use super::{FallbackManager, PacketContext};
use crate::server::{ServerError, Slot};
use slipstream_core::cli::{get_legacy_support, get_obfuscation_key, get_xor_data, get_xor_label};
use slipstream_dns::{decode_query_with_domains, xor_qname_prefix, DecodeQueryError};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_incoming_packet_ex, picoquic_quic_t, slipstream_disable_ack_delay,
};
use slipstream_ffi::socket_addr_to_storage;
use slipstream_ffi::take_stateless_packet_for_cid;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

enum DecodeSlotOutcome {
    Slot(Slot),
    DnsOnly,
    Drop,
}

pub(crate) async fn handle_packet(
    slots: &mut Vec<Slot>,
    packet: &[u8],
    peer: SocketAddr,
    context: &PacketContext<'_>,
    fallback_mgr: &mut Option<FallbackManager>,
) -> Result<(), ServerError> {
    if let Some(manager) = fallback_mgr.as_mut() {
        if manager.is_active_fallback_peer(peer) {
            manager.forward_existing(packet, peer).await;
            return Ok(());
        }
    }

    match decode_slot(
        packet,
        peer,
        context.domains,
        get_obfuscation_key(),
        context.quic,
        context.current_time,
        context.local_addr_storage,
    )? {
        DecodeSlotOutcome::Slot(slot) => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
            slots.push(slot);
        }
        DecodeSlotOutcome::DnsOnly => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
        }
        DecodeSlotOutcome::Drop => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.handle_non_dns(packet, peer).await;
            }
        }
    }

    Ok(())
}

fn decode_slot(
    packet: &[u8],
    peer: SocketAddr,
    domains: &[&str],
    xor_key: u8,
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &slipstream_ffi::SockaddrStorage,
) -> Result<DecodeSlotOutcome, ServerError> {
    // Strict Mode Logic:
    // If we are in XOR-Label mode, we MUST unmask first.
    // If we are in Plain mode, we MUST decode directly.
    // If legacy_support is ON, we try both.

    let mut decoded_query: Option<slipstream_dns::DecodedQuery> = None;
    let use_xor_label = xor_key != 0 && get_xor_label();
    let mut label_was_xored = false;

    // 1. Try XOR Label decoding if enabled
    if use_xor_label {
        let mut attempt_packet = packet.to_vec();
        for domain in domains {
            xor_qname_prefix(&mut attempt_packet, domain, xor_key);
            if let Ok(res) = decode_query_with_domains(&attempt_packet, domains) {
                tracing::debug!("Successfully unmasked packet for domain: {}", domain);
                decoded_query = Some(res);
                label_was_xored = true;
                break;
            }
            // Revert for next domain attempt
            xor_qname_prefix(&mut attempt_packet, domain, xor_key);
        }
    }

    // 2. Try Plain decoding if (Legacy is ON) OR (XOR Label is OFF) OR (XOR Label failed but we want to fallback)
    // Actually, if XOR Label is required and failed, we might only want to fallback if legacy is on.
    if decoded_query.is_none() && (!use_xor_label || get_legacy_support()) {
        if let Ok(res) = decode_query_with_domains(packet, domains) {
            decoded_query = Some(res);
        }
    }

    let final_result = if let Some(q) = decoded_query {
        Ok(q)
    } else {
        // If we failed to decode, just return a generic error to trigger Drop/Fallback
        // (decode_query_with_domains returns errors on failure)
        decode_query_with_domains(packet, domains)
    };

    match final_result {
        Ok(query) => Ok(process_query(
            query,
            peer,
            xor_key,
            quic,
            current_time,
            local_addr_storage,
            label_was_xored,
        )),
        Err(DecodeQueryError::Drop) => Ok(DecodeSlotOutcome::Drop),
        Err(DecodeQueryError::Reply {
            id,
            rd,
            cd,
            question,
            rcode,
        }) => {
            let Some(question) = question else {
                // Treat empty-question queries (QDCOUNT=0) as non-DNS for fallback.
                return Ok(DecodeSlotOutcome::Drop);
            };
            Ok(DecodeSlotOutcome::Slot(Slot {
                peer,
                id,
                rd,
                cd,
                question,
                rcode: Some(rcode),
                cnx: std::ptr::null_mut(),
                path_id: -1,
                payload_override: None,
                xor_mode: false,
                label_xor_mode: false,
            }))
        }
    }
}

fn process_query(
    query: slipstream_dns::DecodedQuery,
    peer: SocketAddr,
    xor_key: u8,
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &slipstream_ffi::SockaddrStorage,
    label_was_xored: bool,
) -> DecodeSlotOutcome {
    let try_process = |payload: Vec<u8>,
                       is_xor_mode: bool|
     -> Option<(Slot, *mut picoquic_cnx_t, libc::c_int)> {
        let mut peer_storage = hash_peer_to_dummy_storage(peer);
        let mut local_storage = unsafe { std::ptr::read(local_addr_storage) };
        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = -1;

        let ret = unsafe {
            picoquic_incoming_packet_ex(
                quic,
                payload.as_ptr() as *mut u8,
                payload.len(),
                &mut peer_storage as *mut _ as *mut libc::sockaddr,
                &mut local_storage as *mut _ as *mut libc::sockaddr,
                0,
                0,
                &mut first_cnx,
                &mut first_path,
                current_time,
            )
        };
        if ret < 0 {
            return None;
        }

        if first_cnx.is_null() {
            if let Some(resp_payload) = unsafe { take_stateless_packet_for_cid(quic, &payload) } {
                if !resp_payload.is_empty() {
                    return Some((
                        Slot {
                            peer,
                            id: query.id,
                            rd: query.rd,
                            cd: query.cd,
                            question: query.question.clone(),
                            rcode: None,
                            cnx: std::ptr::null_mut(),
                            path_id: -1,
                            payload_override: Some(resp_payload),
                            xor_mode: is_xor_mode,
                            label_xor_mode: label_was_xored,
                        },
                        std::ptr::null_mut(),
                        -1,
                    ));
                }
            }
            return None;
        }

        Some((
            Slot {
                peer,
                id: query.id,
                rd: query.rd,
                cd: query.cd,
                question: query.question.clone(),
                rcode: None,
                cnx: first_cnx,
                path_id: first_path,
                payload_override: None,
                xor_mode: is_xor_mode,
                label_xor_mode: label_was_xored,
            },
            first_cnx,
            first_path,
        ))
    };

    // Process Payload
    let use_xor_data = xor_key != 0 && get_xor_data();

    // 1. Try with XOR Data if enabled
    if use_xor_data {
        let mut masked_payload = query.payload.clone();
        for b in &mut masked_payload {
            *b ^= xor_key;
        }
        if let Some((slot, cnx, _)) = try_process(masked_payload, true) {
            if !cnx.is_null() {
                unsafe {
                    slipstream_disable_ack_delay(cnx);
                }
            }
            return DecodeSlotOutcome::Slot(slot);
        }
    }

    // 2. Try plain (Fallback or Default)
    // If we are strict XOR-Data mode, only try plain if legacy is supported.
    if !use_xor_data || get_legacy_support() {
        if let Some((slot, cnx, _)) = try_process(query.payload, false) {
            if !cnx.is_null() {
                unsafe {
                    slipstream_disable_ack_delay(cnx);
                }
            }
            return DecodeSlotOutcome::Slot(slot);
        }
    }

    DecodeSlotOutcome::DnsOnly
}

fn hash_peer_to_dummy_storage(peer: SocketAddr) -> slipstream_ffi::SockaddrStorage {
    // Map the real peer address to a deterministic dummy address in 2001:db8::/32.
    // This ensures picoquic sees a stable address for the handshake while still
    // allowing distinct paths for multipath (different hashes for different resolvers).
    // We hash ONLY the IP and use a fixed port to mask DNS source port randomization.
    let mut hasher = DefaultHasher::new();
    peer.ip().hash(&mut hasher);
    let hash = hasher.finish();
    let addr = Ipv6Addr::new(
        0x2001,
        0xdb8,
        0,
        0,
        (hash >> 48) as u16,
        (hash >> 32) as u16,
        (hash >> 16) as u16,
        hash as u16,
    );
    let dummy_peer = SocketAddr::new(IpAddr::V6(addr), 12345);
    socket_addr_to_storage(dummy_peer)
}
