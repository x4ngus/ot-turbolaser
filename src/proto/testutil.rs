//! Frame builders for tests: assemble Ethernet + IPv4 + TCP/UDP around a
//! payload, with correct checksums.

use super::frame;

pub fn build_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x08, 0x00];
    let l4 = 20 + payload.len();
    let ip_total = 20 + l4;
    b.extend_from_slice(&[0x45, 0x00]);
    b.extend_from_slice(&(ip_total as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 6, 0, 0]);
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq, ack
    b.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]); // dataoff 5, PSH+ACK, win, csum, urg
    b.extend_from_slice(payload);
    let l = frame::parse_layout(&b).unwrap();
    frame::recompute_checksums(&mut b, &l);
    b
}

pub fn build_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x08, 0x00];
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    b.extend_from_slice(&[0x45, 0x00]);
    b.extend_from_slice(&(ip_total as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&(udp_len as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]); // checksum placeholder
    b.extend_from_slice(payload);
    let l = frame::parse_layout(&b).unwrap();
    frame::recompute_checksums(&mut b, &l);
    b
}
