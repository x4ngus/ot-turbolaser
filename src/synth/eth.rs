//! Whole-frame synthesis primitives.
//!
//! Each builder assembles a complete Ethernet + IPv4 + L4 frame around a
//! payload, sets every length field, and recomputes checksums by reusing the
//! frame parser. Because synthesis owns the whole packet, variable-length
//! payloads need no length-cascade handling: the length fields are ours to set.
//! This is the same code path the reload mutators already produce tshark-clean
//! output through.

use std::net::Ipv4Addr;

use crate::proto::frame::{parse_layout, recompute_checksums};

pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Common IPv4 header for a synthesized unicast frame: version/IHL, DSCP, total
/// length, id, flags, TTL, protocol, zero checksum, src, dst.
fn ipv4_header(total_len: usize, proto: u8, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut h = Vec::with_capacity(20);
    h.extend_from_slice(&[0x45, 0x00]);
    h.extend_from_slice(&(total_len as u16).to_be_bytes());
    h.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // id, flags=DF
    h.extend_from_slice(&[0x40, proto]); // ttl 64, protocol
    h.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    h
}

fn ethernet_header(src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(14);
    h.extend_from_slice(&dst_mac);
    h.extend_from_slice(&src_mac);
    h.extend_from_slice(&ethertype.to_be_bytes());
    h
}

fn finish(mut buf: Vec<u8>) -> Vec<u8> {
    if let Some(l) = parse_layout(&buf) {
        recompute_checksums(&mut buf, &l);
    }
    buf
}

/// Ethernet + IPv4 + UDP, checksums filled.
#[allow(clippy::too_many_arguments)]
pub fn udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let mut b = ethernet_header(src_mac, dst_mac, ETHERTYPE_IPV4);
    b.extend_from_slice(&ipv4_header(ip_total, 17, src, dst));
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&(udp_len as u16).to_be_bytes());
    b.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    b.extend_from_slice(payload);
    finish(b)
}

/// Ethernet + IPv4 + TCP, a single PSH+ACK segment, checksums filled. seq/ack
/// let a caller pair a request and its reply into a coherent exchange.
#[allow(clippy::too_many_arguments)]
pub fn tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let ip_total = 20 + tcp_len;
    let mut b = ethernet_header(src_mac, dst_mac, ETHERTYPE_IPV4);
    b.extend_from_slice(&ipv4_header(ip_total, 6, src, dst));
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&ack.to_be_bytes());
    b.extend_from_slice(&[0x50, 0x18]); // data offset 5 words, flags PSH+ACK
    b.extend_from_slice(&[0x20, 0x00]); // window
    b.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    b.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    b.extend_from_slice(payload);
    finish(b)
}

/// A bare Ethernet II frame for non-IP L2 protocols such as LLDP. No checksum:
/// the captured frame carries no FCS.
pub fn l2_frame(src_mac: [u8; 6], dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = ethernet_header(src_mac, dst_mac, ethertype);
    b.extend_from_slice(payload);
    b
}

/// An IEEE 802.3 frame with an LLC/SNAP header, for protocols like CDP that ride
/// SNAP rather than Ethernet II. The length field is the LLC+SNAP+payload size.
pub fn snap_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    oui: [u8; 3],
    protocol_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&dst_mac);
    b.extend_from_slice(&src_mac);
    // 802.3 length: LLC (3) + SNAP (5) + payload.
    let len = 3 + 5 + payload.len();
    b.extend_from_slice(&(len as u16).to_be_bytes());
    // LLC: DSAP=AA SSAP=AA control=03 (unnumbered information).
    b.extend_from_slice(&[0xAA, 0xAA, 0x03]);
    // SNAP: OUI + protocol id.
    b.extend_from_slice(&oui);
    b.extend_from_slice(&protocol_id.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    #[test]
    fn udp_frame_is_valid_and_parses() {
        let f = udp_frame(
            [0, 0x90, 0xE8, 1, 2, 3],
            [0xff; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            161,
            b"snmp-payload",
        );
        let l = parse_layout(&f).unwrap();
        assert_eq!(l.l4_kind, L4Kind::Udp);
        assert!(checksums_valid(&f, &l));
        assert_eq!(&f[l.payload..l.end], b"snmp-payload");
    }

    #[test]
    fn tcp_frame_is_valid_and_parses() {
        let f = tcp_frame(
            [0, 0, 0xBC, 1, 2, 3],
            [0, 0, 0xBC, 4, 5, 6],
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 9),
            50000,
            44818,
            1,
            1,
            b"enip",
        );
        let l = parse_layout(&f).unwrap();
        assert_eq!(l.l4_kind, L4Kind::Tcp);
        assert!(checksums_valid(&f, &l));
        assert_eq!(&f[l.payload..l.end], b"enip");
    }

    #[test]
    fn l2_and_snap_frames_carry_payload() {
        let lldp = l2_frame(
            [0, 0, 0xBC, 1, 2, 3],
            [0x01, 0x80, 0xC2, 0, 0, 0x0E],
            0x88CC,
            b"tlv",
        );
        assert_eq!(u16::from_be_bytes([lldp[12], lldp[13]]), 0x88CC);
        assert_eq!(&lldp[14..], b"tlv");

        let cdp = snap_frame(
            [0, 0, 0x0C, 1, 2, 3],
            [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC],
            [0x00, 0x00, 0x0C],
            0x2000,
            b"cdp",
        );
        // LLC/SNAP header then payload.
        assert_eq!(&cdp[14..17], &[0xAA, 0xAA, 0x03]);
        assert_eq!(&cdp[17..20], &[0x00, 0x00, 0x0C]);
        assert_eq!(&cdp[22..], b"cdp");
    }
}
