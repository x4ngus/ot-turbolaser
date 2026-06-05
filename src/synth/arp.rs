//! ARP resolution.
//!
//! A passive sensor (Dragos) binds MAC to IP from an ARP response, the canonical
//! L2/L3 resolution, not from the Ethernet header of an arbitrary L3 frame (in a
//! routed network that source MAC could be a router, not the address owner). So
//! every asset we want fused into one entry needs an ARP presence. The form the
//! sensor associates from is a solicited reply: a host asks "who has <ip>?" and
//! the owner answers "<ip> is at <mac>" unicast to the asker. The reference OT
//! capture the sensor binds from carries only these solicited request/reply
//! exchanges and no unsolicited gratuitous announcements, so `resolve` pairs a
//! request with its unicast reply. Every ARP frame is padded to the 60-byte
//! Ethernet minimum (a 42-byte runt is rejected). ARP carries no checksum.

use std::net::Ipv4Addr;

use super::eth::l2_frame;

const ETHERTYPE_ARP: u16 = 0x0806;
const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const ZERO_MAC: [u8; 6] = [0; 6];
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;

/// Assemble an Ethernet + ARP frame with the given operation and addresses.
fn arp(
    eth_dst: [u8; 6],
    oper: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    p.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    p.push(6); // hlen
    p.push(4); // plen
    p.extend_from_slice(&oper.to_be_bytes());
    p.extend_from_slice(&sender_mac);
    p.extend_from_slice(&sender_ip.octets());
    p.extend_from_slice(&target_mac);
    p.extend_from_slice(&target_ip.octets());
    let mut f = l2_frame(sender_mac, eth_dst, ETHERTYPE_ARP, &p);
    // Pad to the 60-byte Ethernet minimum. A bare ARP is 42 bytes; real ARP on
    // the wire is always padded to 60 (a NIC pads short frames). A passive sensor
    // that treats ARP as the authoritative MAC<->IP association source can reject
    // an undersized runt, so without this the association never forms.
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

/// An ARP request: "who has `target_ip`? tell `sender_ip`", broadcast. The
/// sender's MAC and IP bind it at the sensor.
pub fn request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    arp(
        BROADCAST, OP_REQUEST, sender_mac, sender_ip, ZERO_MAC, target_ip,
    )
}

/// An ARP reply: "`sender_ip` is at `sender_mac`", unicast to the requester. The
/// sender's MAC and IP bind it at the sensor.
pub fn reply(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    arp(
        target_mac, OP_REPLY, sender_mac, sender_ip, target_mac, target_ip,
    )
}

/// A resolution exchange that binds both hosts: `requester` asks for `owner_ip`,
/// `owner` answers from `owner_mac`. Returns the (request, reply) frames.
pub fn resolve(
    requester_mac: [u8; 6],
    requester_ip: Ipv4Addr,
    owner_mac: [u8; 6],
    owner_ip: Ipv4Addr,
) -> (Vec<u8>, Vec<u8>) {
    (
        request(requester_mac, requester_ip, owner_ip),
        reply(owner_mac, owner_ip, requester_mac, requester_ip),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oper(f: &[u8]) -> u16 {
        u16::from_be_bytes([f[14 + 6], f[14 + 7]])
    }

    #[test]
    fn request_binds_sender_and_is_broadcast() {
        let f = request(
            [0x02, 0, 0, 1, 2, 3],
            Ipv4Addr::new(10, 1, 0, 250),
            Ipv4Addr::new(10, 1, 0, 5),
        );
        assert_eq!(&f[0..6], &BROADCAST, "request is broadcast");
        assert_eq!(&f[6..12], &[0x02, 0, 0, 1, 2, 3], "eth src is the sender");
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ETHERTYPE_ARP);
        assert_eq!(oper(&f), OP_REQUEST);
        assert_eq!(&f[14 + 8..14 + 14], &[0x02, 0, 0, 1, 2, 3], "SHA = sender");
        assert_eq!(&f[14 + 14..14 + 18], &[10, 1, 0, 250], "SPA = sender ip");
        assert_eq!(&f[14 + 18..14 + 24], &ZERO_MAC, "THA zero in a request");
        assert_eq!(&f[14 + 24..14 + 28], &[10, 1, 0, 5], "TPA = target ip");
        assert_eq!(f.len(), 60, "padded to the Ethernet minimum, never a runt");
    }

    #[test]
    fn reply_binds_owner_and_is_unicast() {
        let owner = [0x00, 0x0e, 0x8c, 1, 2, 3];
        let requester = [0x02, 0, 0, 9, 9, 9];
        let f = reply(
            owner,
            Ipv4Addr::new(10, 1, 0, 5),
            requester,
            Ipv4Addr::new(10, 1, 0, 250),
        );
        assert_eq!(&f[0..6], &requester, "reply is unicast to the requester");
        assert_eq!(&f[6..12], &owner, "eth src is the owner");
        assert_eq!(oper(&f), OP_REPLY);
        assert_eq!(&f[14 + 8..14 + 14], &owner, "SHA = owner mac");
        assert_eq!(&f[14 + 14..14 + 18], &[10, 1, 0, 5], "SPA = owner ip");
    }

    #[test]
    fn resolve_pairs_request_then_reply() {
        let (req, rep) = resolve(
            [0x02, 0, 0, 0, 0, 1],
            Ipv4Addr::new(10, 0, 0, 250),
            [0x00, 0x0e, 0x8c, 4, 5, 6],
            Ipv4Addr::new(10, 0, 0, 5),
        );
        assert_eq!(oper(&req), OP_REQUEST);
        assert_eq!(oper(&rep), OP_REPLY);
        // The reply's sender protocol address is the owner the request asked for.
        assert_eq!(&rep[14 + 14..14 + 18], &[10, 0, 0, 5]);
        assert_eq!(&req[14 + 24..14 + 28], &[10, 0, 0, 5]);
    }
}
