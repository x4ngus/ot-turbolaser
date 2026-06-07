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
// 1.3.6.1.2.1.1.2.0 (sysObjectID.0).
const SYSOBJECTID_OID: [u8; 8] = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00];

/// Default firmware-version OID: ENTITY-MIB entPhysicalFirmwareRev
/// (1.3.6.1.2.1.47.1.1.1.1.9) at entPhysicalIndex 1. Bound to the device's
/// firmware string in the GetResponse so a passive sensor reads an explicit
/// firmware-version varbind (the firmware detection event), not free text.
pub const DEFAULT_FIRMWARE_OID: &str = "1.3.6.1.2.1.47.1.1.1.1.9.1";

/// Encode a dotted OID string into BER OID content bytes (no tag/length). The
/// first two arcs fold to `40*a + b`; later arcs use base-128 with the
/// continuation bit. None if the string is not a valid OID.
pub fn encode_oid(s: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = s
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 {
        return None;
    }
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut group = [0u8; 10];
        let mut n = 0;
        let mut v = arc;
        group[n] = (v & 0x7f) as u8;
        n += 1;
        v >>= 7;
        while v > 0 {
            group[n] = (v & 0x7f) as u8 | 0x80;
            n += 1;
            v >>= 7;
        }
        for i in (0..n).rev() {
            out.push(group[i]);
        }
    }
    Some(out)
}

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

/// One varbind SEQUENCE: an OID name and a value TLV.
fn varbind(name_oid: &[u8], value: &[u8]) -> Vec<u8> {
    let mut vb = Vec::new();
    vb.extend_from_slice(&tlv(0x06, name_oid));
    vb.extend_from_slice(value);
    tlv(0x30, &vb)
}

/// GET sysDescr.0, sysObjectID.0, and (when set) the firmware OID.
pub fn get_request(community: &str, request_id: u32, firmware_oid: Option<&str>) -> Vec<u8> {
    let mut varbinds = Vec::new();
    varbinds.extend_from_slice(&varbind(&SYSDESCR_OID, &tlv(0x05, &[])));
    varbinds.extend_from_slice(&varbind(&SYSOBJECTID_OID, &tlv(0x05, &[])));
    if let Some(oid) = firmware_oid.and_then(encode_oid) {
        varbinds.extend_from_slice(&varbind(&oid, &tlv(0x05, &[])));
    }
    message(community, 0xA0, request_id, &varbinds)
}

/// The response binding sysDescr.0 to the description string, sysObjectID.0 to
/// the device's enterprise OID when known (the field passive sensors key CVE
/// attribution on), and the firmware OID to the firmware string when both are set
/// (the explicit firmware detection event). A varbind is emitted only when its
/// value is present, so an unset firmware leaves the response byte-identical to
/// the two-varbind form.
pub fn get_response(
    community: &str,
    request_id: u32,
    sys_descr: &str,
    sys_object_id: Option<&str>,
    firmware_oid: Option<&str>,
    firmware: Option<&str>,
) -> Vec<u8> {
    let mut varbinds = Vec::new();
    varbinds.extend_from_slice(&varbind(&SYSDESCR_OID, &tlv(0x04, sys_descr.as_bytes())));
    if let Some(oid) = sys_object_id.and_then(encode_oid) {
        varbinds.extend_from_slice(&varbind(&SYSOBJECTID_OID, &tlv(0x06, &oid)));
    }
    if let (Some(oid), Some(fw)) = (firmware_oid.and_then(encode_oid), firmware) {
        varbinds.extend_from_slice(&varbind(&oid, &tlv(0x04, fw.as_bytes())));
    }
    message(community, 0xA2, request_id, &varbinds)
}

/// The (request, response) frames of an SNMP fetch of sysDescr.0, sysObjectID.0,
/// and, when `firmware_oid`/`firmware` are set, the firmware-version OID.
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
    sys_object_id: Option<&str>,
    firmware_oid: Option<&str>,
    firmware: Option<&str>,
) -> (Vec<u8>, Vec<u8>) {
    let req = get_request(community, request_id, firmware_oid);
    let resp = get_response(
        community,
        request_id,
        sys_descr,
        sys_object_id,
        firmware_oid,
        firmware,
    );
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
        let resp = get_response(
            "public",
            0x1234,
            "Cisco IOS Software, IE3000",
            None,
            None,
            None,
        );
        assert_eq!(resp[0], 0x30, "top-level SEQUENCE");
        // The description bytes appear verbatim in the encoding.
        let needle = b"Cisco IOS Software, IE3000";
        assert!(
            resp.windows(needle.len()).any(|w| w == needle),
            "sysDescr present in the response"
        );
    }

    #[test]
    fn encode_oid_known_vectors() {
        // sysObjectID.0 itself.
        assert_eq!(
            encode_oid("1.3.6.1.2.1.1.2.0").unwrap(),
            vec![0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00]
        );
        // Moxa enterprise arc 8691 spans two base-128 groups (0xC3 0x73).
        let moxa = encode_oid("1.3.6.1.4.1.8691.7.50").unwrap();
        assert_eq!(&moxa[0..5], &[0x2b, 0x06, 0x01, 0x04, 0x01]);
        assert!(moxa.windows(2).any(|w| w == [0xC3, 0x73]), "8691 encoded");
        assert!(encode_oid("not.an.oid").is_none());
    }

    #[test]
    fn response_binds_sysobjectid_when_known() {
        let resp = get_response(
            "public",
            1,
            "Moxa EDS-405A",
            Some("1.3.6.1.4.1.8691.7.50"),
            None,
            None,
        );
        // The sysObjectID name OID and an OBJECT IDENTIFIER value (tag 0x06) are
        // both present.
        assert!(
            resp.windows(SYSOBJECTID_OID.len())
                .any(|w| w == SYSOBJECTID_OID),
            "sysObjectID.0 name present"
        );
        assert!(
            resp.windows(2).any(|w| w == [0xC3, 0x73]),
            "enterprise OID value present"
        );
    }

    #[test]
    fn firmware_varbind_present_when_set_and_backcompat_when_not() {
        let resp = get_response(
            "public",
            7,
            "Fortinet FortiGate",
            Some("1.3.6.1.4.1.12356.101.1.1000"),
            Some(DEFAULT_FIRMWARE_OID),
            Some("6.0.4"),
        );
        let fw_oid = encode_oid(DEFAULT_FIRMWARE_OID).unwrap();
        assert!(
            resp.windows(fw_oid.len()).any(|w| w == fw_oid.as_slice()),
            "firmware OID present"
        );
        assert!(
            resp.windows(5).any(|w| w == b"6.0.4"),
            "firmware string bound as the firmware varbind"
        );
        // No firmware value -> byte-identical to the legacy two-varbind response.
        let with_none = get_response(
            "public",
            9,
            "Hirschmann",
            Some("1.3.6.1.4.1.248"),
            None,
            None,
        );
        let oid_but_no_value = get_response(
            "public",
            9,
            "Hirschmann",
            Some("1.3.6.1.4.1.248"),
            Some(DEFAULT_FIRMWARE_OID),
            None,
        );
        assert_eq!(with_none, oid_but_no_value);
    }
}
