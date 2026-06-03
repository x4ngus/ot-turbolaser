//! Gratuitous ARP announcement.
//!
//! A device announces its own IPv4 address bound to its MAC, so a passive
//! sensor fuses the device into a single asset (one MAC and one IP) rather than
//! recording a MAC-only and an IP-only entry. ARP carries no checksum.

use std::net::Ipv4Addr;

use super::eth::l2_frame;

const ETHERTYPE_ARP: u16 = 0x0806;
const BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// A gratuitous ARP reply: sender and target protocol address both `ip`, sent
/// from `mac` to broadcast. The standard way a host announces its own binding.
pub fn gratuitous(mac: [u8; 6], ip: Ipv4Addr) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    p.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    p.push(6); // hlen
    p.push(4); // plen
    p.extend_from_slice(&2u16.to_be_bytes()); // oper: reply
    p.extend_from_slice(&mac); // sender hardware address
    p.extend_from_slice(&ip.octets()); // sender protocol address
    p.extend_from_slice(&mac); // target hardware address (own, gratuitous)
    p.extend_from_slice(&ip.octets()); // target protocol address (own, gratuitous)
    l2_frame(mac, BROADCAST, ETHERTYPE_ARP, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gratuitous_arp_announces_binding() {
        let f = gratuitous([0x00, 0x0e, 0x8c, 1, 2, 3], Ipv4Addr::new(10, 1, 0, 5));
        assert_eq!(&f[0..6], &[0xff; 6], "broadcast destination");
        assert_eq!(&f[6..12], &[0x00, 0x0e, 0x8c, 1, 2, 3], "sender MAC");
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ETHERTYPE_ARP);
        assert_eq!(u16::from_be_bytes([f[14 + 6], f[14 + 7]]), 2, "ARP reply");
        // Sender and target protocol addresses both the announced IP.
        assert_eq!(&f[14 + 14..14 + 18], &[10, 1, 0, 5]);
        assert_eq!(&f[14 + 24..14 + 28], &[10, 1, 0, 5]);
    }
}
