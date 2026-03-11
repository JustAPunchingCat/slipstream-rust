use super::{FallbackManager, PacketContext};
use crate::server::{ServerError, Slot};
use slipstream_core::cli::get_obfuscation_key;
use slipstream_dns::{decode_query_with_domains, DecodeQueryError};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_incoming_packet_ex, picoquic_quic_t, slipstream_disable_ack_delay,
};
use slipstream_ffi::take_stateless_packet_for_cid;
use slipstream_ffi::socket_addr_to_storage;
use std::net::SocketAddr;

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
    match decode_query_with_domains(packet, domains) {
        Ok(query) => {
            let try_process = |payload: Vec<u8>,
                                   is_xor_mode: bool|
             -> Option<(Slot, *mut picoquic_cnx_t, libc::c_int)> {
                let mut peer_storage = socket_addr_to_storage(peer);
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
                    if let Some(resp_payload) =
                        unsafe { take_stateless_packet_for_cid(quic, &payload) }
                    {
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
                    },
                    first_cnx,
                    first_path,
                ))
            };

            // 1. Try with XOR (if enabled)
            if xor_key != 0 {
                let mut masked_payload = query.payload.clone();
                for b in &mut masked_payload {
                    *b ^= xor_key;
                }
                if let Some((slot, cnx, _)) = try_process(masked_payload, true) {
                    if !cnx.is_null() {
                        unsafe { slipstream_disable_ack_delay(cnx) };
                    }
                    return Ok(DecodeSlotOutcome::Slot(slot));
                }
            }

            // 2. Try plain (fallback)
            // If xor_key was 0, this is the only attempt.
            // If xor_key != 0 but failed, we try this to support legacy clients.
            if let Some((slot, cnx, _)) = try_process(query.payload, false) {
                if !cnx.is_null() {
                    unsafe { slipstream_disable_ack_delay(cnx) };
                }
                return Ok(DecodeSlotOutcome::Slot(slot));
            }

            Ok(DecodeSlotOutcome::DnsOnly)
        }
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
            }))
        }
    }
}
