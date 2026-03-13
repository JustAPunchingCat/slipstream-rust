use super::{FallbackManager, PacketContext};
use crate::server::{ServerError, Slot};
use slipstream_core::cli::{get_legacy_support, get_obfs_data, get_obfs_key, get_obfs_label};
use slipstream_dns::{decode_query_with_domains, shift_qname_prefix, DecodeQueryError};
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
        get_obfs_key(),
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
    obfs_key: u8,
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &slipstream_ffi::SockaddrStorage,
) -> Result<DecodeSlotOutcome, ServerError> {
    // Reliability Logic:
    // We may have multiple candidates:
    // 1. Obfuscated Label (if enabled)
    // 2. Plain Label (if enabled or legacy support is active)
    //
    // To ensure reliability, we shouldn't just check if the label decodes to DNS;
    // we must also check if the payload decrypts to a valid QUIC packet.
    // We try the configured high-security mode first.

    let use_obfs_label = obfs_key != 0 && get_obfs_label();
    let try_legacy = !use_obfs_label || get_legacy_support();

    let mut best_result = DecodeSlotOutcome::Drop;

    // 1. Try Obfuscated Label decoding
    if use_obfs_label {
        let mut attempt_packet = packet.to_vec();
        for domain in domains {
            shift_qname_prefix(&mut attempt_packet, domain, obfs_key, false); // unshift
            if let Ok(res) = decode_query_with_domains(&attempt_packet, domains) {
                tracing::debug!("Successfully unmasked packet for domain: {}", domain);
                let outcome = process_query(
                    res,
                    peer,
                    obfs_key,
                    quic,
                    current_time,
                    local_addr_storage,
                    true, // label_was_obfs
                );
                if let DecodeSlotOutcome::Slot(_) = outcome {
                    return Ok(outcome);
                }
                // If we found valid DNS but invalid QUIC, store as fallback
                if let DecodeSlotOutcome::DnsOnly = outcome {
                    best_result = DecodeSlotOutcome::DnsOnly;
                }
                break;
            }
            // Revert for next domain attempt
            shift_qname_prefix(&mut attempt_packet, domain, obfs_key, true); // reshift back
        }
    }

    // 2. Try Plain decoding
    if try_legacy {
        if let Ok(res) = decode_query_with_domains(packet, domains) {
            let outcome = process_query(
                res,
                peer,
                obfs_key,
                quic,
                current_time,
                local_addr_storage,
                false, // label_was_obfs
            );
            if let DecodeSlotOutcome::Slot(_) = outcome {
                return Ok(outcome);
            }
            // If plain decoding found DNS but not QUIC, it overrides previous DnsOnly
            // because standard DNS is more likely than a collision on Obfs.
            if let DecodeSlotOutcome::DnsOnly = outcome {
                best_result = DecodeSlotOutcome::DnsOnly;
            }
        }
    }

    // 3. Fallback check: if we failed to find any valid Slot, but found DNS structure,
    //    we might want to send a DNS error reply (e.g. for probing tools).
    //    However, `process_query` usually handles successful DNS decode.
    //    If we are here, it means we didn't return a Slot.
    //    We need to check if `decode_query` failed entirely (Drop/Fallback) or
    //    if it failed with a DNS error (Reply).
    //    Since we called `decode_query_with_domains` inside the blocks, we need
    //    to recover the error if `best_result` is not DnsOnly.

    if let DecodeSlotOutcome::DnsOnly = best_result {
        return Ok(DecodeSlotOutcome::DnsOnly);
    }

    // If we really found nothing, just try plain decode one last time to see if we should
    // generate a formatted DNS error reply (like Refused or FormatError) instead of Drop.
    match decode_query_with_domains(packet, domains) {
        Ok(_) => Ok(DecodeSlotOutcome::DnsOnly), // Should have been caught above, but safe fallback
        Err(DecodeQueryError::Drop) => Ok(DecodeSlotOutcome::Drop),
        Err(DecodeQueryError::Reply {
            id,
            rd,
            cd,
            question,
            rcode,
        }) => {
            let Some(question) = question else {
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
                data_obfs_mode: false,
                label_obfs_mode: false,
            }))
        }
    }
}

fn process_query(
    query: slipstream_dns::DecodedQuery,
    peer: SocketAddr,
    obfs_key: u8,
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &slipstream_ffi::SockaddrStorage,
    label_was_obfs: bool,
) -> DecodeSlotOutcome {
    let try_process = |payload: Vec<u8>,
                       is_data_obfs_mode: bool|
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
                            data_obfs_mode: is_data_obfs_mode,
                            label_obfs_mode: label_was_obfs,
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
                data_obfs_mode: is_data_obfs_mode,
                label_obfs_mode: label_was_obfs,
            },
            first_cnx,
            first_path,
        ))
    };

    // Process Payload
    let use_data_obfs = obfs_key != 0 && get_obfs_data();

    // 1. Try with Obfuscated Data if enabled
    if use_data_obfs {
        let mut masked_payload = query.payload.clone();
        for b in &mut masked_payload {
            *b = b.wrapping_sub(obfs_key); // unshift data
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
    // If we are in strict Obfs-Data mode, only try plain if legacy is supported.
    if !use_data_obfs || get_legacy_support() {
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
