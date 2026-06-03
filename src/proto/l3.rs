//! Topology-preserving L3 remap.
//!
//! Moves every host to a fresh random RFC1918 subnet while preserving the
//! conversation graph and intra-subnet structure: hosts that shared a subnet
//! stay together, host offsets are kept, and the same original address always
//! maps to the same new address. The sensor sees genuine-looking conversations
//! that simply moved to new addresses, not a scramble.
//!
//! IPv4 only. Multicast, broadcast, loopback, and 0.0.0.0 are left untouched.

use crate::config::ZoneAffinity;
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

    // 4. Rewrite each packet's addresses through the bijection.
    apply_host_map(cap, &map);

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

/// Rewrite every packet's src/dst IPv4 through `map` (old u32 -> new u32) and
/// recompute checksums on changed frames. Shared by the random remap and the
/// into-zones remap.
pub fn apply_host_map(cap: &mut Capture, map: &HashMap<u32, u32>) {
    for p in &mut cap.packets {
        let Some(mut f) = ParsedFrame::parse(&mut p.data) else {
            continue;
        };
        if f.is_ipv4() {
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
        } else {
            // ARP carries IPv4 addresses too; remap them so the sender/target
            // protocol addresses never leak an original (possibly public) IP.
            let l3 = f.layout.l3;
            remap_arp_addrs(f.buf, l3, map);
        }
    }
}

/// Rewrite the sender/target protocol (IPv4) addresses of an ARP frame through
/// the host map. MACs are left intact, matching the IP-only remap. A no-op for
/// non-ARP or non-IPv4-over-Ethernet frames.
fn remap_arp_addrs(buf: &mut [u8], l3: usize, map: &HashMap<u32, u32>) {
    if l3 < 2 || buf.len() < l3 + 28 {
        return;
    }
    let ethertype = u16::from_be_bytes([buf[l3 - 2], buf[l3 - 1]]);
    if ethertype != 0x0806 {
        return;
    }
    let htype = u16::from_be_bytes([buf[l3], buf[l3 + 1]]);
    let ptype = u16::from_be_bytes([buf[l3 + 2], buf[l3 + 3]]);
    if htype != 1 || ptype != 0x0800 || buf[l3 + 4] != 6 || buf[l3 + 5] != 4 {
        return;
    }
    // Sender protocol address at +14, target protocol address at +24.
    for off in [l3 + 14, l3 + 24] {
        let cur = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if let Some(&nv) = map.get(&cur) {
            buf[off..off + 4].copy_from_slice(&nv.to_be_bytes());
        }
    }
}

/// A fabricated ledger zone a replayed capture can be mapped into.
pub struct ZoneTarget {
    pub net: Ipv4Net,
    pub vendor: Option<String>,
    pub purdue_level: u8,
    pub protocol: Option<String>,
    /// Fabricated device IPs already in this zone; never reused for a remapped
    /// capture host.
    pub reserved: HashSet<Ipv4Addr>,
}

/// A distinct host-group from the capture, with the vendor/protocol/level the
/// engine inferred from MAC OUIs and observed ports.
pub struct CaptureGroup {
    pub net: Ipv4Net,
    pub purdue_level: u8,
    pub vendor: Option<String>,
    pub protocol: Option<String>,
    pub hosts: Vec<Ipv4Addr>,
}

/// Map an OT service port to the protocol tag used on ledger device records, so
/// a capture's observed traffic can be matched to a vendor zone. None for
/// non-OT ports.
pub(crate) fn ot_protocol_for_port(port: u16) -> Option<&'static str> {
    match port {
        502 => Some("modbus"),
        2222 | 44818 => Some("enip"),
        102 => Some("s7"),
        161 | 162 => Some("switch_snmp"),
        20000 => Some("dnp3"),
        _ => None,
    }
}

/// Remap a capture's hosts into the fabricated ledger zones by vendor/protocol
/// affinity, preserving conversations and host offsets. Deterministic for a
/// given (capture, zones, seed) so the same capture lands on the same in-zone
/// addresses every run. Returns the old-group -> zone mapping summary.
pub fn remap_capture_into_zones(
    cap: &mut Capture,
    groups: &[CaptureGroup],
    zones: &[ZoneTarget],
    affinity: ZoneAffinity,
    seed: u64,
) -> RemapSummary {
    if zones.is_empty() {
        return RemapSummary {
            host_count: 0,
            subnets: Vec::new(),
        };
    }
    // Per-zone taken addresses, seeded from the reserved fabricated-device IPs.
    let mut taken: Vec<HashSet<Ipv4Addr>> = zones.iter().map(|z| z.reserved.clone()).collect();
    let mut map: HashMap<u32, u32> = HashMap::new();
    let mut subnets: Vec<(String, String)> = Vec::new();

    // Deterministic processing order by network address.
    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_unstable_by_key(|&i| u32::from(groups[i].net.network()));

    for &gi in &order {
        let g = &groups[gi];
        let ranked = rank_zones(g, zones, affinity, seed);
        let host_mask = !mask_for(g.net.prefix_len());
        let mut hosts = g.hosts.clone();
        hosts.sort_unstable();
        let mut placed_zone: Option<usize> = None;
        for host in hosts {
            let off = u32::from(host) & host_mask;
            let mut done = false;
            for &zi in &ranked {
                if let Some(newip) = place_in_zone(&zones[zi].net, &mut taken[zi], off) {
                    map.insert(u32::from(host), u32::from(newip));
                    placed_zone.get_or_insert(zi);
                    done = true;
                    break;
                }
            }
            if !done {
                log::warn!("remap: all fabricated zones full; capture host {host} left unmapped");
            }
        }
        if let Some(zi) = placed_zone {
            subnets.push((g.net.to_string(), zones[zi].net.to_string()));
        }
    }

    apply_host_map(cap, &map);
    RemapSummary {
        host_count: map.len(),
        subnets,
    }
}

/// Zones ranked best-first for a capture group: higher affinity score, then
/// more remaining room, then a deterministic per-(group,zone,seed) tiebreak.
fn rank_zones(
    g: &CaptureGroup,
    zones: &[ZoneTarget],
    affinity: ZoneAffinity,
    seed: u64,
) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..zones.len()).collect();
    idx.sort_by(|&a, &b| {
        let (za, zb) = (&zones[a], &zones[b]);
        affinity_score(g, zb, affinity)
            .cmp(&affinity_score(g, za, affinity))
            .then_with(|| zone_room(zb).cmp(&zone_room(za)))
            .then_with(|| tiebreak(seed, g.net, za.net).cmp(&tiebreak(seed, g.net, zb.net)))
    });
    idx
}

fn affinity_score(g: &CaptureGroup, z: &ZoneTarget, affinity: ZoneAffinity) -> i32 {
    let vendor_match = matches!((&g.vendor, &z.vendor), (Some(a), Some(b)) if a == b);
    let proto_match = matches!((&g.protocol, &z.protocol), (Some(a), Some(b)) if a == b);
    let level_match = g.purdue_level == z.purdue_level;
    match affinity {
        ZoneAffinity::Off => 0,
        ZoneAffinity::Vendor => i32::from(vendor_match) * 3,
        ZoneAffinity::Protocol => i32::from(proto_match) * 2,
        ZoneAffinity::Both => {
            i32::from(vendor_match) * 4 + i32::from(proto_match) * 2 + i32::from(level_match)
        }
    }
}

/// Usable host capacity of a zone minus its reserved device IPs.
fn zone_room(z: &ZoneTarget) -> usize {
    let p = z.net.prefix_len();
    let cap = if p >= 31 {
        0
    } else {
        (1usize << (32 - p as usize)).saturating_sub(2)
    };
    cap.saturating_sub(z.reserved.len())
}

/// Place a host in a zone, preferring its original in-subnet offset, else the
/// next free host. Updates `taken`. None when the zone is full.
fn place_in_zone(
    net: &Ipv4Net,
    taken: &mut HashSet<Ipv4Addr>,
    desired_off: u32,
) -> Option<Ipv4Addr> {
    let host_mask = !mask_for(net.prefix_len());
    let want = Ipv4Addr::from(u32::from(net.network()) | (desired_off & host_mask));
    if is_usable_host(net, want) && taken.insert(want) {
        return Some(want);
    }
    // Otherwise take the next free host (insert returns true only when newly
    // claimed, so this stops at and reserves the first available address).
    net.hosts().find(|&ip| taken.insert(ip))
}

fn is_usable_host(net: &Ipv4Net, ip: Ipv4Addr) -> bool {
    net.contains(&ip) && ip != net.network() && ip != net.broadcast()
}

/// Deterministic tiebreak hash for zone selection (splitmix64 of the seed and
/// the two network addresses), so placement is stable per (capture, session).
fn tiebreak(seed: u64, group: Ipv4Net, zone: Ipv4Net) -> u64 {
    let mut x = seed
        ^ u64::from(u32::from(group.network())).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ u64::from(u32::from(zone.network()));
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
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

    fn zt(
        cidr: &str,
        vendor: Option<&str>,
        level: u8,
        proto: Option<&str>,
        reserved: &[&str],
    ) -> ZoneTarget {
        ZoneTarget {
            net: cidr.parse().unwrap(),
            vendor: vendor.map(String::from),
            purdue_level: level,
            protocol: proto.map(String::from),
            reserved: reserved.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn cg(
        cidr: &str,
        vendor: Option<&str>,
        level: u8,
        proto: Option<&str>,
        hosts: &[&str],
    ) -> CaptureGroup {
        CaptureGroup {
            net: cidr.parse().unwrap(),
            purdue_level: level,
            vendor: vendor.map(String::from),
            protocol: proto.map(String::from),
            hosts: hosts.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn into_zones_places_by_vendor_preserves_convo_and_is_stable() {
        let mk = || {
            cap_from(&[
                ([192, 168, 10, 5], [192, 168, 10, 9]),
                ([192, 168, 10, 9], [192, 168, 10, 5]),
            ])
        };
        let groups = vec![cg(
            "192.168.10.0/24",
            Some("Rockwell Automation"),
            1,
            Some("enip"),
            &["192.168.10.5", "192.168.10.9"],
        )];
        let zones = vec![
            zt("10.50.0.0/24", Some("Siemens AG"), 1, Some("s7"), &[]),
            zt(
                "10.60.0.0/24",
                Some("Rockwell Automation"),
                1,
                Some("enip"),
                &[],
            ),
        ];

        let mut a = mk();
        let sum = remap_capture_into_zones(&mut a, &groups, &zones, ZoneAffinity::Both, 0x1234);
        assert_eq!(sum.host_count, 2);

        let (s0, d0) = addrs(&a.packets[0].data);
        let (s1, d1) = addrs(&a.packets[1].data);
        // Both hosts landed in the Rockwell zone, offsets preserved.
        assert_eq!(s0[..3], [10, 60, 0], "vendor-matched zone");
        assert_eq!(s0[3], 5);
        assert_eq!(d0[3], 9);
        // Conversation preserved (packet 1 is the reverse pair).
        assert_eq!(s0, d1);
        assert_eq!(d0, s1);

        // Deterministic across runs with the same seed.
        let mut b = mk();
        remap_capture_into_zones(&mut b, &groups, &zones, ZoneAffinity::Both, 0x1234);
        assert_eq!(
            a.packets[0].data, b.packets[0].data,
            "stable per (capture, seed)"
        );

        for p in &a.packets {
            let l = frame::parse_layout(&p.data).unwrap();
            assert!(frame::checksums_valid(&p.data, &l));
        }
    }

    #[test]
    fn into_zones_skips_reserved_device_ips() {
        let mut cap = cap_from(&[([192, 168, 1, 5], [192, 168, 1, 6])]);
        let groups = vec![cg(
            "192.168.1.0/24",
            Some("ACME"),
            1,
            None,
            &["192.168.1.5", "192.168.1.6"],
        )];
        // The zone already holds a fabricated device at .5; the capture's .5
        // host must be placed elsewhere.
        let zones = vec![zt("10.70.0.0/24", Some("ACME"), 1, None, &["10.70.0.5"])];
        remap_capture_into_zones(&mut cap, &groups, &zones, ZoneAffinity::Both, 7);
        let (s0, d0) = addrs(&cap.packets[0].data);
        assert_eq!(s0[..3], [10, 70, 0]);
        assert_ne!(s0, [10, 70, 0, 5], "reserved device IP not reused");
        assert_ne!(d0, [10, 70, 0, 5]);
        assert_ne!(s0, d0, "distinct hosts get distinct IPs");
    }

    #[test]
    fn into_zones_uses_protocol_when_vendor_unknown() {
        let mut cap = cap_from(&[([172, 16, 0, 2], [172, 16, 0, 3])]);
        let groups = vec![cg(
            "172.16.0.0/24",
            None,
            1,
            Some("modbus"),
            &["172.16.0.2", "172.16.0.3"],
        )];
        let zones = vec![
            zt(
                "10.10.0.0/24",
                Some("GE Fanuc Automation"),
                1,
                Some("enip"),
                &[],
            ),
            zt(
                "10.20.0.0/24",
                Some("Schneider Electric"),
                1,
                Some("modbus"),
                &[],
            ),
        ];
        remap_capture_into_zones(&mut cap, &groups, &zones, ZoneAffinity::Both, 99);
        let (s0, _d0) = addrs(&cap.packets[0].data);
        assert_eq!(
            s0[..3],
            [10, 20, 0],
            "modbus group lands in the modbus zone"
        );
    }

    #[test]
    fn apply_host_map_remaps_arp_protocol_addresses_not_macs() {
        // Ethernet + ARP reply: SHA 00:0e:8c:.., SPA 192.168.1.5, TPA 192.168.1.1.
        let mut data = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // dst mac
        data.extend_from_slice(&[0x00, 0x0e, 0x8c, 0x11, 0x22, 0x33]); // src mac
        data.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
        data.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]); // htype/ptype/hlen/plen/oper
        data.extend_from_slice(&[0x00, 0x0e, 0x8c, 0x11, 0x22, 0x33]); // SHA
        data.extend_from_slice(&[192, 168, 1, 5]); // SPA
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // THA
        data.extend_from_slice(&[192, 168, 1, 1]); // TPA
        let mut cap = Capture {
            header: PcapHeader::default(),
            packets: vec![OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: data.len() as u32,
                data,
            }],
        };
        let mut map = HashMap::new();
        map.insert(
            u32::from(Ipv4Addr::new(192, 168, 1, 5)),
            u32::from(Ipv4Addr::new(10, 9, 0, 5)),
        );
        map.insert(
            u32::from(Ipv4Addr::new(192, 168, 1, 1)),
            u32::from(Ipv4Addr::new(10, 9, 0, 1)),
        );
        apply_host_map(&mut cap, &map);
        let d = &cap.packets[0].data;
        assert_eq!(
            &d[22..28],
            &[0x00, 0x0e, 0x8c, 0x11, 0x22, 0x33],
            "sender MAC untouched"
        );
        assert_eq!(
            &d[28..32],
            &[10, 9, 0, 5],
            "sender protocol address remapped"
        );
        assert_eq!(
            &d[38..42],
            &[10, 9, 0, 1],
            "target protocol address remapped"
        );
    }
}
