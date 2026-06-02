//! SNMP sysDescr assertion (v2c).
//!
//! A management station GETs sysDescr.0 and the switch responds with its
//! description string, which carries the model and firmware a passive sensor
//! reads. BER-encoded over UDP 161. Synthesis owns every length field.

use std::net::Ipv4Addr;

use super::eth::udp_frame;

const SNMP_PORT: u16 = 161;
// 1.3.6.1.2.1.1.1.0 (sysDescr.0): first two arcs fold to 0x2b, the rest follow.
const SYSDESCR_OID: [u8; 8] = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut b = vec![tag];
    b.extend_from_slice(&ber_len(value.len()));
    b.extend_from_slice(value);
    b
}

/// A minimal, non-negative BER INTEGER.
fn int(v: u32) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 3 && bytes[start] == 0 {
        start += 1;
    }
    let mut val = bytes[start..].to_vec();
    if val[0] & 0x80 != 0 {
        val.insert(0, 0); // keep it positive
    }
    tlv(0x02, &val)
}

fn message(community: &str, pdu_tag: u8, request_id: u32, varbind: &[u8]) -> Vec<u8> {
    let mut pdu_body = Vec::new();
    pdu_body.extend_from_slice(&int(request_id));
    pdu_body.extend_from_slice(&int(0)); // error-status
    pdu_body.extend_from_slice(&int(0)); // error-index
    pdu_body.extend_from_slice(&tlv(0x30, varbind)); // varbind list
    let pdu = tlv(pdu_tag, &pdu_body);

    let mut msg = Vec::new();
    msg.extend_from_slice(&int(1)); // version: v2c
    msg.extend_from_slice(&tlv(0x04, community.as_bytes())); // community
    msg.extend_from_slice(&pdu);
    tlv(0x30, &msg)
}

/// GET sysDescr.0.
pub fn get_request(community: &str, request_id: u32) -> Vec<u8> {
    let mut vb = Vec::new();
    vb.extend_from_slice(&tlv(0x06, &SYSDESCR_OID));
    vb.extend_from_slice(&tlv(0x05, &[])); // NULL value
    let varbind = tlv(0x30, &vb);
    message(community, 0xA0, request_id, &varbind)
}

/// The response binding sysDescr.0 to the description string.
pub fn get_response(community: &str, request_id: u32, sys_descr: &str) -> Vec<u8> {
    let mut vb = Vec::new();
    vb.extend_from_slice(&tlv(0x06, &SYSDESCR_OID));
    vb.extend_from_slice(&tlv(0x04, sys_descr.as_bytes())); // OCTET STRING value
    let varbind = tlv(0x30, &vb);
    message(community, 0xA2, request_id, &varbind)
}

/// The (request, response) frames of an SNMP sysDescr fetch.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    mgr_mac: [u8; 6],
    sw_mac: [u8; 6],
    mgr_ip: Ipv4Addr,
    sw_ip: Ipv4Addr,
    mgr_port: u16,
    community: &str,
    request_id: u32,
    sys_descr: &str,
) -> (Vec<u8>, Vec<u8>) {
    let req = get_request(community, request_id);
    let resp = get_response(community, request_id, sys_descr);
    let rf = udp_frame(mgr_mac, sw_mac, mgr_ip, sw_ip, mgr_port, SNMP_PORT, &req);
    let pf = udp_frame(sw_mac, mgr_mac, sw_ip, mgr_ip, SNMP_PORT, mgr_port, &resp);
    (rf, pf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_lengths_short_and_long() {
        assert_eq!(ber_len(5), vec![5]);
        assert_eq!(ber_len(200), vec![0x81, 200]);
        assert_eq!(ber_len(300), vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn response_is_a_sequence_carrying_the_descr() {
        let resp = get_response("public", 0x1234, "Cisco IOS Software, IE3000");
        assert_eq!(resp[0], 0x30, "top-level SEQUENCE");
        // The description bytes appear verbatim in the encoding.
        let needle = b"Cisco IOS Software, IE3000";
        assert!(
            resp.windows(needle.len()).any(|w| w == needle),
            "sysDescr present in the response"
        );
    }
}
