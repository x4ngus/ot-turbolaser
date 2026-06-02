//! Topology-preserving L3 remap.
//!
//! Moves every host to a fresh random RFC1918 subnet while preserving the
//! conversation graph and intra-subnet structure: hosts that shared a subnet
//! stay together, host offsets are kept, and the same original address always
//! maps to the same new address. The sensor sees genuine-looking conversations
//! that simply moved to new addresses, not a scramble.
//!
//! IPv4 only. Multicast, broadcast, loopback, and 0.0.0.0 are left untouched.

use crate::pcapio::Capture;
use crate::proto::frame::{self, L3Kind, ParsedFrame};
use ipnet::Ipv4Net;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;

const RFC1918_10_BASE: u32 = 0x0A00_0000; // 10.0.0.0
const DEFAULT_PREFIX: u8 = 24;

/// What the remap did, for the round manifest and logs.
pub struct RemapSummary {
    pub host_count: usize,
    pub subnets: Vec<(String, String)>,
}

/// Parse CIDR hint strings, dropping any that do not parse.
pub fn parse_hints(hints: &[String]) -> Vec<Ipv4Net> {
    hints
        .iter()
        .filter_map(|s| Ipv4Net::from_str(s).ok())
        .collect()
}

/// Unicast, non-loopback, non-reserved: the addresses we relocate.
fn is_remappable(addr: u32) -> bool {
    let o0 = (addr >> 24) as u8;
    o0 != 0 && o0 != 127 && o0 < 224
}

fn mask_for(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// The (prefix, network) group an address belongs to: a matching hint if any,
/// otherwise its /24.
fn group_of(addr: u32, hints: &[Ipv4Net]) -> (u8, u32) {
    let ip = Ipv4Addr::from(addr);
    for h in hints {
        if h.prefix_len() >= 8 && h.contains(&ip) {
            let p = h.prefix_len();
            return (p, addr & mask_for(p));
        }
    }
    (DEFAULT_PREFIX, addr & mask_for(DEFAULT_PREFIX))
}

/// The subnet an address belongs to, as an `Ipv4Net`. Shared by the remap and
/// by zone grouping so the two always agree on subnet boundaries.
pub(crate) fn subnet_of(addr: Ipv4Addr, hints: &[Ipv4Net]) -> Ipv4Net {
    let (p, net) = group_of(u32::from(addr), hints);
    Ipv4Net::new(Ipv4Addr::from(net), p).expect("prefix from group_of is valid")
}

/// A fresh `/prefix` network in 10/8 that does not overlap any in `existing`.
/// Reuses the per-run remap's non-overlap logic so fabricated zones and the
/// bulk-capture remap never collide.
pub(crate) fn fresh_subnet(prefix: u8, existing: &[Ipv4Net], rng: &mut ChaCha8Rng) -> Ipv4Net {
    let assigned: Vec<(u32, u8)> = existing
        .iter()
        .map(|n| (u32::from(n.network()), n.prefix_len()))
        .collect();
    let p = prefix.clamp(8, 30);
    let net = pick_new_net(p, rng, &assigned);
    Ipv4Net::new(Ipv4Addr::from(net), p).expect("valid prefix")
}

/// Remap every host in the capture in place, recomputing checksums on changed
/// frames. Deterministic for a given capture and seed.
pub fn remap_capture(cap: &mut Capture, hints: &[Ipv4Net], seed: u64) -> RemapSummary {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // 1. Enumerate distinct remappable hosts and their groups.
    let mut seen = HashSet::new();
    let mut group_by_host: HashMap<u32, (u8, u32)> = HashMap::new();
    for p in &cap.packets {
        let Some(l) = frame::parse_layout(&p.data) else {
            continue;
        };
        if l.l3_kind != L3Kind::Ipv4 {
            continue;
        }
        for off in [l.l3 + 12, l.l3 + 16] {
            let addr = u32::from_be_bytes([
                p.data[off],
                p.data[off + 1],
                p.data[off + 2],
                p.data[off + 3],
            ]);
            if is_remappable(addr) && seen.insert(addr) {
                group_by_host.insert(addr, group_of(addr, hints));
            }
        }
    }

    // 2. Assign each old group a fresh, non-overlapping new network in 10/8.
    let mut groups: Vec<(u8, u32)> = group_by_host.values().copied().collect();
    groups.sort_unstable();
    groups.dedup();
    let mut new_net_of: HashMap<(u8, u32), u32> = HashMap::new();
    let mut assigned: Vec<(u32, u8)> = Vec::new();
    for g in &groups {
        let new_net = pick_new_net(g.0, &mut rng, &assigned);
        assigned.push((new_net, g.0));
        new_net_of.insert(*g, new_net);
    }

    // 3. Build the host bijection, preserving the host offset within the subnet.
    let mut map: HashMap<u32, u32> = HashMap::new();
    for (&host, g) in &group_by_host {
        let new_net = new_net_of[g];
        let host_part = host & !mask_for(g.0);
        map.insert(host, new_net | host_part);
    }

    // 4. Rewrite each packet's src and dst, then fix checksums if changed.
    for p in &mut cap.packets {
        let Some(mut f) = ParsedFrame::parse(&mut p.data) else {
            continue;
        };
        let mut changed = false;
        if let Some(s) = f.ipv4_src() {
            if let Some(&ns) = map.get(&u32::from_be_bytes(s)) {
                f.set_ipv4_src(Ipv4Addr::from(ns).octets());
                changed = true;
            }
        }
        if let Some(d) = f.ipv4_dst() {
            if let Some(&nd) = map.get(&u32::from_be_bytes(d)) {
                f.set_ipv4_dst(Ipv4Addr::from(nd).octets());
                changed = true;
            }
        }
        if changed {
            f.recompute_checksums();
        }
    }

    let subnets = groups
        .iter()
        .map(|g| {
            let nn = new_net_of[g];
            (
                format!("{}/{}", Ipv4Addr::from(g.1), g.0),
                format!("{}/{}", Ipv4Addr::from(nn), g.0),
            )
        })
        .collect();
    RemapSummary {
        host_count: map.len(),
        subnets,
    }
}

/// Pick a random network of the given prefix within 10/8 that does not overlap
/// any already assigned network.
fn pick_new_net(prefix: u8, rng: &mut ChaCha8Rng, assigned: &[(u32, u8)]) -> u32 {
    let prefix = prefix.clamp(8, 30);
    let host_bits = 32 - prefix as u32;
    let count: u64 = 1 << (prefix as u32 - 8);
    for _ in 0..256 {
        let idx = rng.gen_range(0..count) as u32;
        let net = RFC1918_10_BASE | (idx << host_bits);
        if !overlaps(net, prefix, assigned) {
            return net;
        }
    }
    for idx in 0..count as u32 {
        let net = RFC1918_10_BASE | (idx << host_bits);
        if !overlaps(net, prefix, assigned) {
            return net;
        }
    }
    RFC1918_10_BASE
}

fn overlaps(net: u32, prefix: u8, assigned: &[(u32, u8)]) -> bool {
    let lo = net as u64;
    let hi = lo + (1u64 << (32 - prefix as u32));
    assigned.iter().any(|&(n2, p2)| {
        let lo2 = n2 as u64;
        let hi2 = lo2 + (1u64 << (32 - p2 as u32));
        lo < hi2 && lo2 < hi
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapio::{Capture, OwnedPacket};
    use pcap_file::pcap::PcapHeader;
    use std::time::Duration;

    fn udp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x08, 0x00];
        let udp_len = 8 + 4;
        let ip_total = 20 + udp_len;
        b.extend_from_slice(&[0x45, 0x00]);
        b.extend_from_slice(&(ip_total as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
        b.extend_from_slice(&src);
        b.extend_from_slice(&dst);
        b.extend_from_slice(&[0x10, 0x00, 0x4e, 0x20]); // ports 4096 -> 20000
        b.extend_from_slice(&(udp_len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0]); // udp csum placeholder
        b.extend_from_slice(&[1, 2, 3, 4]);
        let l = frame::parse_layout(&b).unwrap();
        frame::recompute_checksums(&mut b, &l);
        b
    }

    fn cap_from(pairs: &[([u8; 4], [u8; 4])]) -> Capture {
        let packets = pairs
            .iter()
            .map(|(s, d)| OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: 0,
                data: udp(*s, *d),
            })
            .collect();
        Capture {
            header: PcapHeader::default(),
            packets,
        }
    }

    fn addrs(data: &[u8]) -> ([u8; 4], [u8; 4]) {
        let l = frame::parse_layout(data).unwrap();
        let s = [
            data[l.l3 + 12],
            data[l.l3 + 13],
            data[l.l3 + 14],
            data[l.l3 + 15],
        ];
        let d = [
            data[l.l3 + 16],
            data[l.l3 + 17],
            data[l.l3 + 18],
            data[l.l3 + 19],
        ];
        (s, d)
    }

    #[test]
    fn preserves_conversations_subnets_and_validity() {
        let mut cap = cap_from(&[
            ([192, 168, 10, 5], [192, 168, 10, 9]),
            ([192, 168, 10, 9], [192, 168, 10, 5]),
            ([10, 5, 5, 2], [10, 5, 5, 3]),
        ]);
        remap_capture(&mut cap, &[], 7);

        let (s0, d0) = addrs(&cap.packets[0].data);
        let (s1, d1) = addrs(&cap.packets[1].data);
        let (s2, d2) = addrs(&cap.packets[2].data);

        // Addresses actually changed.
        assert_ne!(s0, [192, 168, 10, 5]);
        // Conversation preserved: packet 0 and packet 1 are the same pair reversed.
        assert_eq!(s0, d1);
        assert_eq!(d0, s1);
        // Coherent subnet: the two .10.x hosts share a new /24 (top 3 octets equal).
        assert_eq!(s0[..3], d0[..3]);
        // Host offsets preserved within the subnet.
        assert_eq!(s0[3], 5);
        assert_eq!(d0[3], 9);
        // The second subnet (10.5.5.x) is distinct from the first.
        assert_ne!(s2[..3], s0[..3]);
        assert_eq!(s2[3], 2);
        assert_eq!(d2[3], 3);

        // Checksums valid on every packet.
        for p in &cap.packets {
            let l = frame::parse_layout(&p.data).unwrap();
            assert!(frame::checksums_valid(&p.data, &l));
        }
    }

    #[test]
    fn deterministic_for_same_seed() {
        let a = {
            let mut c = cap_from(&[([192, 168, 1, 1], [192, 168, 1, 2])]);
            remap_capture(&mut c, &[], 99);
            c.packets[0].data.clone()
        };
        let b = {
            let mut c = cap_from(&[([192, 168, 1, 1], [192, 168, 1, 2])]);
            remap_capture(&mut c, &[], 99);
            c.packets[0].data.clone()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn multicast_and_broadcast_left_alone() {
        let mut cap = cap_from(&[([192, 168, 1, 10], [239, 255, 0, 1])]);
        remap_capture(&mut cap, &[], 3);
        let (s, d) = addrs(&cap.packets[0].data);
        assert_ne!(s, [192, 168, 1, 10], "unicast source should move");
        assert_eq!(d, [239, 255, 0, 1], "multicast destination must not move");
    }
}
