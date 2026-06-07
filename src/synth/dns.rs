//! DNS A-record synthesis.
//!
//! A hostname completes an asset's picture: with MAC<->IP already unioned from
//! ARP, a DNS A-record adds IP<->name, so the sensor shows a recognisable label
//! (e.g. `LINE-01-PLC`) next to the device. This builds the minimal exchange a
//! passive observer binds from: a client query for the name and the resolver's
//! answer carrying the IP. Both ride `eth::udp_frame` (UDP/53), which fills the
//! IPv4/UDP lengths and checksums. No DHCP (a tell); DNS only. The FQDN domain
//! is a future attribute, so names are single-label today.

use std::net::Ipv4Addr;

use super::eth::udp_frame;

const DNS_PORT: u16 = 53;

/// Encode a name as DNS QNAME labels: each label length-prefixed, terminated by
/// the zero-length root label. Over-long labels are clamped to 63 bytes.
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
    out
}

/// A standard (recursion-desired) A-record query payload for `hostname`.
fn query_payload(qid: u16, hostname: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&qid.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ancount, nscount, arcount = 0
    p.extend_from_slice(&encode_name(hostname));
    p.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    p.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    p
}

/// An A-record response payload: echoes the question, then one answer RR mapping
/// the name to `answer_ip` (name via a compression pointer to the question).
fn response_payload(qid: u16, hostname: &str, answer_ip: Ipv4Addr) -> Vec<u8> {
    let qname = encode_name(hostname);
    let mut p = Vec::new();
    p.extend_from_slice(&qid.to_be_bytes());
    p.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: response, RD, RA, NOERROR
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    p.extend_from_slice(&1u16.to_be_bytes()); // ancount
    p.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount = 0
                                        // Question section.
    p.extend_from_slice(&qname);
    p.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    p.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
                                              // Answer RR: name = pointer to the question name at offset 12 (after header).
    p.extend_from_slice(&0xC00Cu16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // type A
    p.extend_from_slice(&1u16.to_be_bytes()); // class IN
    p.extend_from_slice(&300u32.to_be_bytes()); // TTL 300s
    p.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    p.extend_from_slice(&answer_ip.octets()); // rdata = the IP
    p
}

/// The query frame: client (ephemeral) -> resolver:53.
#[allow(clippy::too_many_arguments)]
pub fn query(
    client_mac: [u8; 6],
    resolver_mac: [u8; 6],
    client_ip: Ipv4Addr,
    resolver_ip: Ipv4Addr,
    client_port: u16,
    qid: u16,
    hostname: &str,
) -> Vec<u8> {
    udp_frame(
        client_mac,
        resolver_mac,
        client_ip,
        resolver_ip,
        client_port,
        DNS_PORT,
        &query_payload(qid, hostname),
    )
}

/// The response frame: resolver:53 -> client (ephemeral), answering `answer_ip`.
#[allow(clippy::too_many_arguments)]
pub fn response(
    resolver_mac: [u8; 6],
    client_mac: [u8; 6],
    resolver_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    client_port: u16,
    qid: u16,
    hostname: &str,
    answer_ip: Ipv4Addr,
) -> Vec<u8> {
    udp_frame(
        resolver_mac,
        client_mac,
        resolver_ip,
        client_ip,
        DNS_PORT,
        client_port,
        &response_payload(qid, hostname, answer_ip),
    )
}

/// The query+response pair that binds hostname<->IP for a passive observer.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    client_mac: [u8; 6],
    resolver_mac: [u8; 6],
    client_ip: Ipv4Addr,
    resolver_ip: Ipv4Addr,
    client_port: u16,
    qid: u16,
    hostname: &str,
    answer_ip: Ipv4Addr,
) -> (Vec<u8>, Vec<u8>) {
    (
        query(
            client_mac,
            resolver_mac,
            client_ip,
            resolver_ip,
            client_port,
            qid,
            hostname,
        ),
        response(
            resolver_mac,
            client_mac,
            resolver_ip,
            client_ip,
            client_port,
            qid,
            hostname,
            answer_ip,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    const CM: [u8; 6] = [0x00, 0x14, 0x22, 1, 2, 3];
    const RM: [u8; 6] = [0x00, 0x21, 0xc1, 4, 5, 6];

    fn udp_payload(frame: &[u8]) -> &[u8] {
        let l = parse_layout(frame).expect("parses");
        assert_eq!(l.l4_kind, L4Kind::Udp, "DNS is UDP");
        &frame[l.l4 + 8..]
    }

    fn ports(frame: &[u8]) -> (u16, u16) {
        let l = parse_layout(frame).unwrap();
        (
            u16::from_be_bytes([frame[l.l4], frame[l.l4 + 1]]),
            u16::from_be_bytes([frame[l.l4 + 2], frame[l.l4 + 3]]),
        )
    }

    #[test]
    fn query_and_response_parse_with_valid_checksums() {
        let cip = Ipv4Addr::new(10, 0, 0, 250);
        let rip = Ipv4Addr::new(10, 0, 0, 1);
        let aip = Ipv4Addr::new(10, 0, 0, 5);
        let (q, r) = exchange(CM, RM, cip, rip, 50000, 0x1234, "LINE-01-PLC", aip);
        for f in [&q, &r] {
            let l = parse_layout(f).expect("frame parses");
            assert_eq!(l.l4_kind, L4Kind::Udp);
            assert!(checksums_valid(f, &l), "IPv4/UDP checksums valid");
        }
        assert_eq!(ports(&q).1, 53, "query goes to :53");
        assert_eq!(ports(&r).0, 53, "response comes from :53");
        assert_eq!(
            ports(&q).0,
            ports(&r).1,
            "response returns to the query port"
        );
    }

    #[test]
    fn response_answers_the_ip_and_echoes_the_qid() {
        let aip = Ipv4Addr::new(10, 9, 9, 42);
        let r = response(
            RM,
            CM,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 250),
            50000,
            0xABCD,
            "CELL-02-S7-01",
            aip,
        );
        let p = udp_payload(&r);
        assert_eq!(&p[0..2], &0xABCDu16.to_be_bytes(), "qid echoed");
        assert_eq!(u16::from_be_bytes([p[6], p[7]]), 1, "one answer RR");
        // The A record's RDATA is the last 4 payload bytes = the device IP.
        assert_eq!(&p[p.len() - 4..], &aip.octets(), "A record answers the IP");
    }

    #[test]
    fn qname_encodes_labels() {
        assert_eq!(
            encode_name("LINE-01-PLC"),
            {
                let mut v = vec![11u8];
                v.extend_from_slice(b"LINE-01-PLC");
                v.push(0);
                v
            },
            "single label, length-prefixed, root-terminated"
        );
        // A dotted name splits into labels.
        assert_eq!(encode_name("a.bc"), vec![1, b'a', 2, b'b', b'c', 0]);
    }
}
