use crate::base32;
use crate::dots;

use crate::name::{encode_name, extract_subdomain_multi, parse_name};
use crate::types::{
    DecodeQueryError, DecodedQuery, DnsError, QueryParams, Rcode, ResponseParams, EDNS_UDP_PAYLOAD,
    RR_OPT, RR_TXT,
};
use crate::wire::{
    parse_header, parse_question, parse_question_for_reply, read_u16, read_u32, write_u16,
    write_u32,
};

pub fn decode_query(
    packet: &[u8],
    domain: &str,
    xor_key: Option<u8>,
) -> Result<DecodedQuery, DecodeQueryError> {
    decode_query_with_domains(packet, &[domain], xor_key)
}

pub fn decode_query_with_domains(
    packet: &[u8],
    domains: &[&str],
    xor_key: Option<u8>,
) -> Result<DecodedQuery, DecodeQueryError> {
    let maybe_unmasked_packet;
    let packet_to_process = if let Some(key) = xor_key {
        let mut buf = packet.to_vec();
        for i in 0..std::cmp::min(buf.len(), 16) {
            buf[i] ^= key;
        }
        maybe_unmasked_packet = buf;
        &maybe_unmasked_packet
    } else {
        packet
    };

    let header = match parse_header(packet_to_process) {
        Some(header) => header,
        None => return Err(DecodeQueryError::Drop),
    };

    let rd = header.rd;
    let cd = header.cd;

    if header.is_response {
        let question = parse_question_for_reply(packet_to_process, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    if header.qdcount != 1 {
        let question = parse_question_for_reply(packet_to_process, header.qdcount, header.offset)?;
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question,
            rcode: Rcode::FormatError,
        });
    }

    let question = match parse_question(packet_to_process, header.offset) {
        Ok((question, _)) => question,
        Err(_) => return Err(DecodeQueryError::Drop),
    };

    if question.qtype != RR_TXT {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let subdomain_raw = match extract_subdomain_multi(&question.name, domains) {
        Ok(subdomain_raw) => subdomain_raw,
        Err(rcode) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode,
            })
        }
    };

    let undotted = dots::undotify(&subdomain_raw);
    if undotted.is_empty() {
        return Err(DecodeQueryError::Reply {
            id: header.id,
            rd,
            cd,
            question: Some(question),
            rcode: Rcode::NameError,
        });
    }

    let payload = match base32::decode(&undotted) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(DecodeQueryError::Reply {
                id: header.id,
                rd,
                cd,
                question: Some(question),
                rcode: Rcode::ServerFailure,
            })
        }
    };

    Ok(DecodedQuery {
        id: header.id,
        rd,
        cd,
        question,
        payload,
    })
}

pub fn encode_query(params: &QueryParams<'_>, xor_key: Option<u8>) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(256);
    let mut flags = 0u16;
    if !params.is_query {
        flags |= 0x8000;
    }
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, params.qdcount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    if params.qdcount > 0 {
        encode_name(params.qname, &mut out)?;
        write_u16(&mut out, params.qtype);
        write_u16(&mut out, params.qclass);
    }

    encode_opt_record(&mut out)?;

    if let Some(key) = xor_key {
        for i in 0..std::cmp::min(out.len(), 16) {
            out[i] ^= key;
        }
    }

    Ok(out)
}

pub fn encode_response(params: &ResponseParams<'_>, xor_key: Option<u8>) -> Result<Vec<u8>, DnsError> {
    let payload_len = params.payload.map(|payload| payload.len()).unwrap_or(0);

    let mut rcode = params.rcode.unwrap_or(if payload_len > 0 {
        Rcode::Ok
    } else {
        Rcode::NameError
    });

    let mut ancount = 0u16;
    if payload_len > 0 && rcode == Rcode::Ok {
        ancount = 1;
    } else if params.rcode.is_some() {
        rcode = params.rcode.unwrap_or(Rcode::Ok);
    }

    let mut out = Vec::with_capacity(256);
    let mut flags = 0x8000 | 0x0400;
    if params.rd {
        flags |= 0x0100;
    }
    if params.cd {
        flags |= 0x0010;
    }
    flags |= rcode.to_u8() as u16;

    write_u16(&mut out, params.id);
    write_u16(&mut out, flags);
    write_u16(&mut out, 1);
    write_u16(&mut out, ancount);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);

    encode_name(&params.question.name, &mut out)?;
    write_u16(&mut out, params.question.qtype);
    write_u16(&mut out, params.question.qclass);

    if ancount == 1 {
        out.extend_from_slice(&[0xC0, 0x0C]);
        write_u16(&mut out, params.question.qtype);
        write_u16(&mut out, params.question.qclass);
        write_u32(&mut out, 60);
        let chunk_count = payload_len.div_ceil(255);
        let rdata_len = payload_len + chunk_count;
        if rdata_len > u16::MAX as usize {
            return Err(DnsError::new("payload too long"));
        }
        write_u16(&mut out, rdata_len as u16);
        if let Some(payload) = params.payload {
            let mut remaining = payload_len;
            let mut cursor = 0;
            while remaining > 0 {
                let chunk_len = remaining.min(255);
                out.push(chunk_len as u8);
                out.extend_from_slice(&payload[cursor..cursor + chunk_len]);
                cursor += chunk_len;
                remaining -= chunk_len;
            }
        }
    }

    encode_opt_record(&mut out)?;

    if let Some(key) = xor_key {
        for i in 0..std::cmp::min(out.len(), 16) {
            out[i] ^= key;
        }
    }

    Ok(out)
}

pub fn decode_response(packet: &[u8], xor_key: Option<u8>) -> Option<Vec<u8>> {
    let maybe_unmasked_packet;
    let packet_to_process = if let Some(key) = xor_key {
        let mut buf = packet.to_vec();
        for i in 0..std::cmp::min(buf.len(), 16) {
            buf[i] ^= key;
        }
        maybe_unmasked_packet = buf;
        &maybe_unmasked_packet
    } else {
        packet
    };

    let header = parse_header(packet_to_process)?;
    if !header.is_response {
        return None;
    }
    let rcode = header.rcode?;
    if rcode != Rcode::Ok {
        return None;
    }
    if header.ancount != 1 {
        return None;
    }

    let mut offset = header.offset;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_name(packet_to_process, offset).ok()?;
        offset = new_offset;
        if offset + 4 > packet_to_process.len() {
            return None;
        }
        offset += 4;
    }

    let (_, new_offset) = parse_name(packet_to_process, offset).ok()?;
    offset = new_offset;
    if offset + 10 > packet_to_process.len() {
        return None;
    }
    let qtype = read_u16(packet_to_process, offset)?;
    offset += 2;
    let _qclass = read_u16(packet_to_process, offset)?;
    offset += 2;
    let _ttl = read_u32(packet_to_process, offset)?;
    offset += 4;
    let rdlen = read_u16(packet_to_process, offset)? as usize;
    offset += 2;
    if offset + rdlen > packet_to_process.len() || rdlen < 1 {
        return None;
    }
    if qtype != RR_TXT {
        return None;
    }

    let mut remaining = rdlen;
    let mut cursor = offset;
    let mut out = Vec::with_capacity(rdlen);
    while remaining > 0 {
        let txt_len = packet_to_process[cursor] as usize;
        cursor += 1;
        remaining -= 1;
        if txt_len > remaining {
            return None;
        }
        out.extend_from_slice(&packet_to_process[cursor..cursor + txt_len]);
        cursor += txt_len;
        remaining -= txt_len;
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

pub fn is_response(packet: &[u8], xor_key: Option<u8>) -> bool {
    if packet.len() < 12 {
        return false;
    }
    let mut header_bytes = [0u8; 12];
    header_bytes.copy_from_slice(&packet[..12]);
    if let Some(key) = xor_key {
        for b in &mut header_bytes {
            *b ^= key;
        }
    }
    parse_header(&header_bytes)
        .map(|header| header.is_response)
        .unwrap_or(false)
}

fn encode_opt_record(out: &mut Vec<u8>) -> Result<(), DnsError> {
    out.push(0);
    write_u16(out, RR_OPT);
    write_u16(out, EDNS_UDP_PAYLOAD);
    write_u32(out, 0);
    write_u16(out, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::encode_response;
    use crate::types::{Question, ResponseParams, CLASS_IN, RR_TXT};

    #[test]
    fn encode_response_rejects_large_payload() {
        let question = Question {
            name: "a.test.com.".to_string(),
            qtype: RR_TXT,
            qclass: CLASS_IN,
        };
        let payload = vec![0u8; u16::MAX as usize];
        let params = ResponseParams {
            id: 0x1234,
            rd: false,
            cd: false,
            question: &question,
            payload: Some(&payload),
            rcode: None,
        };
        assert!(encode_response(&params, Some(0xFA)).is_err());
    }
}
