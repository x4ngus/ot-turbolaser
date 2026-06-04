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

/// Public unicast IPv4: a routable address that must never reach the wire
/// un-remapped. The shared definition for the remap output guard and the
/// run-loop leak backstop.
pub(crate) fn is_public_unicast(a: Ipv4Addr) -> bool {
    let o0 = a.octets()[0];
    let unicast = o0 != 0 && o0 != 127 && o0 < 224;
    unicast && !a.is_private() && !a.is_loopback() && !a.is_link_local()
}

/// True if `buf` is an IPv4-over-Ethernet ARP frame (htype 1, ptype 0x0800,
/// 6-byte MAC, 4-byte IP), the only ARP shape carrying IPv4 addresses we remap.
pub(crate) fn is_arp_ipv4(buf: &[u8], l3: usize) -> bool {
    l3 >= 2
        && buf.len() >= l3 + 28
        && u16::from_be_bytes([buf[l3 - 2], buf[l3 - 1]]) == 0x0806
        && u16::from_be_bytes([buf[l3], buf[l3 + 1]]) == 1
        && u16::from_be_bytes([buf[l3 + 2], buf[l3 + 3]]) == 0x0800
        && buf[l3 + 4] == 6
        && buf[l3 + 5] == 4
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
pub fn remap_capture(
    cap: &mut Capture,
    hints: &[Ipv4Net],
    seed: u64,
    remap_mac: bool,
) -> RemapSummary {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // 1. Enumerate distinct remappable hosts and their groups, from IPv4 headers
    // and from IPv4 ARP, so an ARP-only host is relocated too.
    let mut seen = HashSet::new();
    let mut group_by_host: HashMap<u32, (u8, u32)> = HashMap::new();
    for p in &cap.packets {
        let Some(l) = frame::parse_layout(&p.data) else {
            continue;
        };
        let offs: [usize; 2] = if l.l3_kind == L3Kind::Ipv4 {
            [l.l3 + 12, l.l3 + 16]
        } else if is_arp_ipv4(&p.data, l.l3) {
            [l.l3 + 14, l.l3 + 24]
        } else {
            continue;
        };
        for off in offs {
            if off + 4 > p.data.len() {
                continue;
            }
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

    // 4. Rewrite each packet's addresses (and MACs) through the bijection, then
    // drop any frame that would still carry a real or public address. No MAC
    // overrides here: every host gets its stable per-host MAC.
    apply_host_map(cap, &map, &HashMap::new(), seed, remap_mac);
    let dropped = drop_unsafe_frames(cap);
    if dropped > 0 {
        log::warn!(
            "remap: dropped {dropped} unsafe frame(s) (IPv6, truncated, or unmapped-public)"
        );
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

/// Rewrite every packet's src/dst IPv4 through `map` (old u32 -> new u32),
/// recompute checksums on changed frames, and (when `remap_mac`) give each
/// remapped host a stable per-host MAC so the sensor fuses MAC<->IP into one
/// asset. Shared by the random remap and the into-zones remap.
pub fn apply_host_map(
    cap: &mut Capture,
    map: &HashMap<u32, u32>,
    mac_map: &HashMap<u32, [u8; 6]>,
    seed: u64,
    remap_mac: bool,
) {
    for p in &mut cap.packets {
        let Some(mut f) = ParsedFrame::parse(&mut p.data) else {
            continue;
        };
        if f.is_ipv4() {
            let mut new_src: Option<u32> = None;
            let mut new_dst: Option<u32> = None;
            if let Some(s) = f.ipv4_src() {
                if let Some(&ns) = map.get(&u32::from_be_bytes(s)) {
                    f.set_ipv4_src(Ipv4Addr::from(ns).octets());
                    new_src = Some(ns);
                }
            }
            if let Some(d) = f.ipv4_dst() {
                if let Some(&nd) = map.get(&u32::from_be_bytes(d)) {
                    f.set_ipv4_dst(Ipv4Addr::from(nd).octets());
                    new_dst = Some(nd);
                }
            }
            if new_src.is_some() || new_dst.is_some() {
                f.recompute_checksums();
            }
            if remap_mac {
                if let Some(ns) = new_src {
                    f.set_src_mac(mac_for(mac_map, seed, ns));
                }
                // Rewrite the destination MAC only for a unicast peer we
                // remapped; leave broadcast/multicast destination MACs intact.
                if let Some(nd) = new_dst {
                    if f.buf[0] & 0x01 == 0 {
                        f.set_dst_mac(mac_for(mac_map, seed, nd));
                    }
                }
            }
        } else {
            // ARP carries IPv4 addresses too; remap them (and the hardware
            // addresses) so the sender/target never leak an original IP or MAC.
            let l3 = f.layout.l3;
            remap_arp_addrs(f.buf, l3, map, mac_map, seed, remap_mac);
        }
    }
}

/// The MAC for a remapped new IP: an explicit override (a fabricated device's
/// real vendor MAC, for a host riding it) if present, else the host's stable
/// per-host MAC.
fn mac_for(mac_map: &HashMap<u32, [u8; 6]>, seed: u64, new_ip: u32) -> [u8; 6] {
    mac_map
        .get(&new_ip)
        .copied()
        .unwrap_or_else(|| stable_mac(seed, new_ip))
}

/// Rewrite an ARP frame's sender/target protocol (IPv4) addresses through the
/// host map. When `remap_mac`, also rewrite the sender hardware address (and the
/// Ethernet source) to the sender's stable MAC, and the target hardware address
/// (and Ethernet destination) of a reply, so L2 and L3 agree. A no-op for
/// non-IPv4-over-Ethernet ARP.
fn remap_arp_addrs(
    buf: &mut [u8],
    l3: usize,
    map: &HashMap<u32, u32>,
    mac_map: &HashMap<u32, [u8; 6]>,
    seed: u64,
    remap_mac: bool,
) {
    if !is_arp_ipv4(buf, l3) {
        return;
    }
    // Sender protocol +14, target protocol +24; sender hardware +8, target +18.
    let spa = u32::from_be_bytes([buf[l3 + 14], buf[l3 + 15], buf[l3 + 16], buf[l3 + 17]]);
    if let Some(&nspa) = map.get(&spa) {
        buf[l3 + 14..l3 + 18].copy_from_slice(&nspa.to_be_bytes());
        if remap_mac {
            let mac = mac_for(mac_map, seed, nspa);
            buf[l3 + 8..l3 + 14].copy_from_slice(&mac); // sender hardware address
            buf[6..12].copy_from_slice(&mac); // Ethernet source matches the sender
        }
    }
    let tpa = u32::from_be_bytes([buf[l3 + 24], buf[l3 + 25], buf[l3 + 26], buf[l3 + 27]]);
    if let Some(&ntpa) = map.get(&tpa) {
        buf[l3 + 24..l3 + 28].copy_from_slice(&ntpa.to_be_bytes());
        if remap_mac {
            // The target hardware address is zero in a request and a real MAC in
            // a reply; rewrite only a real one, and match the Ethernet dest.
            let tha = &buf[l3 + 18..l3 + 24];
            let is_zero = tha.iter().all(|&b| b == 0);
            let is_bcast = tha.iter().all(|&b| b == 0xff);
            if !is_zero && !is_bcast {
                let mac = mac_for(mac_map, seed, ntpa);
                buf[l3 + 18..l3 + 24].copy_from_slice(&mac);
                buf[0..6].copy_from_slice(&mac);
            }
        }
    }
}

/// Fail-closed output guard. After the remap, keep a frame only if it cannot put
/// a real or public address on the wire: an IPv4 packet that is not snaplen
/// truncated and whose src and dst are both non-public, a handled IPv4 ARP whose
/// protocol addresses are both non-public, or a pure L2 frame with no IP. IPv6
/// and other unhandled L3 are never remapped, so they are dropped. Returns the
/// number of frames dropped.
pub(crate) fn drop_unsafe_frames(cap: &mut Capture) -> usize {
    let before = cap.packets.len();
    cap.packets.retain(|p| frame_is_safe(&p.data));
    before - cap.packets.len()
}

fn frame_is_safe(buf: &[u8]) -> bool {
    let Some(l) = frame::parse_layout(buf) else {
        return false;
    };
    match l.l3_kind {
        L3Kind::Ipv4 => {
            if buf.len() < l.l3 + 20 {
                return false;
            }
            // Truncated IPv4 (declared length exceeds captured bytes) cannot be
            // re-checksummed coherently, so drop it rather than emit a bad frame.
            let ip_total = u16::from_be_bytes([buf[l.l3 + 2], buf[l.l3 + 3]]) as usize;
            if l.l3 + ip_total > buf.len() {
                return false;
            }
            let src = Ipv4Addr::new(
                buf[l.l3 + 12],
                buf[l.l3 + 13],
                buf[l.l3 + 14],
                buf[l.l3 + 15],
            );
            let dst = Ipv4Addr::new(
                buf[l.l3 + 16],
                buf[l.l3 + 17],
                buf[l.l3 + 18],
                buf[l.l3 + 19],
            );
            !is_public_unicast(src) && !is_public_unicast(dst)
        }
        L3Kind::Other => {
            if l.l3 < 2 {
                return false;
            }
            match u16::from_be_bytes([buf[l.l3 - 2], buf[l.l3 - 1]]) {
                0x86dd => false, // IPv6 is never remapped; drop so no real addr leaks
                0x0806 => {
                    if !is_arp_ipv4(buf, l.l3) {
                        return true; // non-IPv4 ARP carries no IPv4 address to leak
                    }
                    let spa = Ipv4Addr::new(
                        buf[l.l3 + 14],
                        buf[l.l3 + 15],
                        buf[l.l3 + 16],
                        buf[l.l3 + 17],
                    );
                    let tpa = Ipv4Addr::new(
                        buf[l.l3 + 24],
                        buf[l.l3 + 25],
                        buf[l.l3 + 26],
                        buf[l.l3 + 27],
                    );
                    !is_public_unicast(spa) && !is_public_unicast(tpa)
                }
                _ => true, // pure L2 (STP/LLDP/CDP/LACP/...) carries no IP address
            }
        }
    }
}

/// True if a raw frame carries a routable address (public IPv4 unicast, a
/// non-local IPv6 address, or a public ARP protocol address). The run-loop
/// remap-off backstop uses this; it fails closed (returns true) on anything it
/// cannot parse and prove safe.
pub(crate) fn carries_public_address(buf: &[u8]) -> bool {
    let Some(l) = frame::parse_layout(buf) else {
        return true;
    };
    match l.l3_kind {
        L3Kind::Ipv4 => {
            if buf.len() < l.l3 + 20 {
                return true;
            }
            let src = Ipv4Addr::new(
                buf[l.l3 + 12],
                buf[l.l3 + 13],
                buf[l.l3 + 14],
                buf[l.l3 + 15],
            );
            let dst = Ipv4Addr::new(
                buf[l.l3 + 16],
                buf[l.l3 + 17],
                buf[l.l3 + 18],
                buf[l.l3 + 19],
            );
            is_public_unicast(src) || is_public_unicast(dst)
        }
        L3Kind::Other => {
            if l.l3 < 2 {
                return true;
            }
            match u16::from_be_bytes([buf[l.l3 - 2], buf[l.l3 - 1]]) {
                0x86dd => ipv6_carries_routable(buf, l.l3),
                0x0806 => {
                    if !is_arp_ipv4(buf, l.l3) {
                        return false;
                    }
                    let spa = Ipv4Addr::new(
                        buf[l.l3 + 14],
                        buf[l.l3 + 15],
                        buf[l.l3 + 16],
                        buf[l.l3 + 17],
                    );
                    let tpa = Ipv4Addr::new(
                        buf[l.l3 + 24],
                        buf[l.l3 + 25],
                        buf[l.l3 + 26],
                        buf[l.l3 + 27],
                    );
                    is_public_unicast(spa) || is_public_unicast(tpa)
                }
                _ => false, // pure L2, no IP to leak
            }
        }
    }
}

/// True if an IPv6 frame carries a non-link-local, non-multicast, non-zero
/// address (so a real/global address would reach the wire). Fails closed.
fn ipv6_carries_routable(buf: &[u8], l3: usize) -> bool {
    if buf.len() < l3 + 40 {
        return true;
    }
    let routable = |o: usize| {
        let link_local = buf[o] == 0xfe && (buf[o + 1] & 0xc0) == 0x80;
        let multicast = buf[o] == 0xff;
        let unspecified = buf[o..o + 16].iter().all(|&x| x == 0);
        !link_local && !multicast && !unspecified
    };
    routable(l3 + 8) || routable(l3 + 24)
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

/// A capture host registered as a new stable asset during reconciliation, for
/// the caller (the engine) to persist in the ledger.
pub struct NewCaptureAsset {
    pub origin: Ipv4Addr,
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub vendor: Option<String>,
    pub protocol: Option<String>,
    pub purdue_level: u8,
    pub subnet_cidr: String,
}

/// Reconcile a capture's hosts into the fabricated zones under a fixed total
/// asset budget (fill-then-map), in deterministic host order. A host whose origin
/// IP is already registered reuses its stable asset. Otherwise, while the budget
/// allows, the host fills spare zone capacity as a new stable asset (its own
/// offset-preserving IP and stable MAC); once the budget is spent it rides an
/// existing fabricated device (that device's IP and real vendor MAC). So the wire
/// never grows past the plan and never carries an un-remapped address. Applies
/// the remap (with `device_macs` overriding the MAC for hosts that ride a
/// fabricated device) and drops any unsafe frame. Returns the summary and the new
/// assets the caller must register. Deterministic for a given (capture, zones,
/// seed, registry).
#[allow(clippy::too_many_arguments)]
pub fn reconcile_capture_into_zones(
    cap: &mut Capture,
    groups: &[CaptureGroup],
    zones: &[ZoneTarget],
    affinity: ZoneAffinity,
    seed: u64,
    remap_mac: bool,
    registered: &HashMap<u32, u32>,
    device_macs: &HashMap<u32, [u8; 6]>,
    mut budget: usize,
) -> (RemapSummary, Vec<NewCaptureAsset>) {
    if zones.is_empty() {
        return (
            RemapSummary {
                host_count: 0,
                subnets: Vec::new(),
            },
            Vec::new(),
        );
    }
    // Taken IPs: reserved fabricated-device IPs across all zones plus the IPs of
    // already-registered capture hosts, so a fresh placement never collides.
    let mut taken: HashSet<Ipv4Addr> = zones
        .iter()
        .flat_map(|z| z.reserved.iter().copied())
        .collect();
    for &nv in registered.values() {
        taken.insert(Ipv4Addr::from(nv));
    }
    let mut map: HashMap<u32, u32> = HashMap::new();
    let mut new_assets: Vec<NewCaptureAsset> = Vec::new();
    let mut subnets: Vec<(String, String)> = Vec::new();

    let mut order: Vec<usize> = (0..groups.len()).collect();
    order.sort_unstable_by_key(|&i| u32::from(groups[i].net.network()));
    for &gi in &order {
        let g = &groups[gi];
        let ranked = rank_zones(g, zones, affinity, seed);
        let Some(&zi) = ranked.first() else { continue };
        let z = &zones[zi];
        let mut hosts = g.hosts.clone();
        hosts.sort_unstable();
        let mut placed_zone: Option<usize> = None;
        for host in hosts {
            let hu = u32::from(host);
            if let Some(&nv) = registered.get(&hu) {
                map.insert(hu, nv); // reuse the host's existing stable asset
                placed_zone.get_or_insert(zi);
                continue;
            }
            if budget > 0 {
                if let Some(newip) = place_in_zone(&z.net, &mut taken, hu) {
                    let nu = u32::from(newip);
                    map.insert(hu, nu);
                    new_assets.push(NewCaptureAsset {
                        origin: host,
                        ip: newip,
                        mac: stable_mac(seed, nu),
                        vendor: z.vendor.clone(),
                        protocol: z.protocol.clone(),
                        purdue_level: z.purdue_level,
                        subnet_cidr: z.net.to_string(),
                    });
                    budget -= 1;
                    placed_zone.get_or_insert(zi);
                    continue;
                }
            }
            // Budget spent (or zone full): ride an existing fabricated device so
            // nothing new appears and no original address is left unmapped.
            if let Some(t) = force_map_target(zones, zi) {
                map.insert(hu, u32::from(t));
                placed_zone.get_or_insert(zi);
            }
        }
        if let Some(zi) = placed_zone {
            subnets.push((g.net.to_string(), zones[zi].net.to_string()));
        }
    }

    apply_host_map(cap, &map, device_macs, seed, remap_mac);
    let dropped = drop_unsafe_frames(cap);
    if dropped > 0 {
        log::warn!(
            "remap: dropped {dropped} unsafe frame(s) (IPv6, truncated, or unmapped-public)"
        );
    }
    (
        RemapSummary {
            host_count: map.len(),
            subnets,
        },
        new_assets,
    )
}

/// A force-map target: the lowest reserved (fabricated device) IP in the
/// preferred zone, else the lowest reserved IP in any zone. None only when no
/// zone holds a fabricated device.
fn force_map_target(zones: &[ZoneTarget], prefer: usize) -> Option<Ipv4Addr> {
    zones
        .get(prefer)
        .and_then(|z| z.reserved.iter().min().copied())
        .or_else(|| zones.iter().flat_map(|z| z.reserved.iter().copied()).min())
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
    splitmix64(
        seed ^ u64::from(u32::from(group.network())).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ u64::from(u32::from(zone.network())),
    )
}

/// splitmix64 finalizer (the published mixing constants). Used for stable
/// per-host MACs and zone tiebreaks.
fn splitmix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// A stable, locally-administered unicast MAC for a remapped host, derived from
/// the session seed and the host's new IP. Deterministic per (seed, ip) so a
/// host keeps one MAC every run and distinct hosts get distinct MACs. Not
/// vendor-matched: octet 0 is forced locally-administered (bit 1 set) and
/// unicast (bit 0 clear), so it never collides with a real vendor OUI.
pub(crate) fn stable_mac(seed: u64, ip: u32) -> [u8; 6] {
    let h = splitmix64(seed ^ u64::from(ip).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let b = h.to_be_bytes();
    [(b[0] & 0xFC) | 0x02, b[1], b[2], b[3], b[4], b[5]]
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
        remap_capture(&mut cap, &[], 7, true);

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
            remap_capture(&mut c, &[], 99, true);
            c.packets[0].data.clone()
        };
        let b = {
            let mut c = cap_from(&[([192, 168, 1, 1], [192, 168, 1, 2])]);
            remap_capture(&mut c, &[], 99, true);
            c.packets[0].data.clone()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn multicast_and_broadcast_left_alone() {
        let mut cap = cap_from(&[([192, 168, 1, 10], [239, 255, 0, 1])]);
        remap_capture(&mut cap, &[], 3, true);
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
    fn reconcile_places_by_vendor_preserves_convo_and_is_stable() {
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
        let reg = HashMap::new();
        let macs = HashMap::new();

        let mut a = mk();
        let (sum, new_assets) = reconcile_capture_into_zones(
            &mut a,
            &groups,
            &zones,
            ZoneAffinity::Both,
            0x1234,
            true,
            &reg,
            &macs,
            100,
        );
        assert_eq!(sum.host_count, 2);
        assert_eq!(new_assets.len(), 2, "two hosts registered as new assets");

        let (s0, d0) = addrs(&a.packets[0].data);
        let (s1, d1) = addrs(&a.packets[1].data);
        assert_eq!(s0[..3], [10, 60, 0], "vendor-matched zone");
        assert_eq!(s0[3], 5);
        assert_eq!(d0[3], 9);
        assert_eq!(s0, d1);
        assert_eq!(d0, s1);

        // Deterministic across runs with the same seed and registry.
        let mut b = mk();
        reconcile_capture_into_zones(
            &mut b,
            &groups,
            &zones,
            ZoneAffinity::Both,
            0x1234,
            true,
            &reg,
            &macs,
            100,
        );
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
    fn reconcile_skips_reserved_device_ips() {
        let mut cap = cap_from(&[([192, 168, 1, 5], [192, 168, 1, 6])]);
        let groups = vec![cg(
            "192.168.1.0/24",
            Some("ACME"),
            1,
            None,
            &["192.168.1.5", "192.168.1.6"],
        )];
        let zones = vec![zt("10.70.0.0/24", Some("ACME"), 1, None, &["10.70.0.5"])];
        reconcile_capture_into_zones(
            &mut cap,
            &groups,
            &zones,
            ZoneAffinity::Both,
            7,
            true,
            &HashMap::new(),
            &HashMap::new(),
            100,
        );
        let (s0, d0) = addrs(&cap.packets[0].data);
        assert_eq!(s0[..3], [10, 70, 0]);
        assert_ne!(s0, [10, 70, 0, 5], "reserved device IP not reused");
        assert_ne!(d0, [10, 70, 0, 5]);
        assert_ne!(s0, d0, "distinct hosts get distinct IPs");
    }

    #[test]
    fn reconcile_uses_protocol_when_vendor_unknown() {
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
        reconcile_capture_into_zones(
            &mut cap,
            &groups,
            &zones,
            ZoneAffinity::Both,
            99,
            true,
            &HashMap::new(),
            &HashMap::new(),
            100,
        );
        let (s0, _d0) = addrs(&cap.packets[0].data);
        assert_eq!(
            s0[..3],
            [10, 20, 0],
            "modbus group lands in the modbus zone"
        );
    }

    #[test]
    fn reconcile_force_maps_onto_device_with_vendor_mac_when_budget_zero() {
        let mut cap = cap_from(&[([192, 168, 1, 5], [192, 168, 1, 6])]);
        let groups = vec![cg(
            "192.168.1.0/24",
            Some("ACME"),
            1,
            None,
            &["192.168.1.5", "192.168.1.6"],
        )];
        // The zone holds one fabricated device at 10.70.0.5 with a vendor MAC.
        let zones = vec![zt("10.70.0.0/24", Some("ACME"), 1, None, &["10.70.0.5"])];
        let dev_ip = u32::from(Ipv4Addr::new(10, 70, 0, 5));
        let dev_mac = [0x00, 0x0e, 0x8c, 0x12, 0x34, 0x56];
        let mut macs = HashMap::new();
        macs.insert(dev_ip, dev_mac);
        // Budget 0: no new assets; surplus hosts ride the device.
        let (_sum, new_assets) = reconcile_capture_into_zones(
            &mut cap,
            &groups,
            &zones,
            ZoneAffinity::Both,
            7,
            true,
            &HashMap::new(),
            &macs,
            0,
        );
        assert!(
            new_assets.is_empty(),
            "no new assets when the budget is zero"
        );
        let (s0, _d0) = addrs(&cap.packets[0].data);
        assert_eq!(
            s0,
            [10, 70, 0, 5],
            "surplus host rides the fabricated device"
        );
        assert_eq!(
            &cap.packets[0].data[6..12],
            &dev_mac,
            "and carries the device's vendor MAC, not a stable LAA MAC"
        );
    }

    #[test]
    fn reconcile_reuses_registered_origin() {
        let mut cap = cap_from(&[([192, 168, 1, 5], [192, 168, 1, 6])]);
        let groups = vec![cg(
            "192.168.1.0/24",
            Some("ACME"),
            1,
            None,
            &["192.168.1.5", "192.168.1.6"],
        )];
        let zones = vec![zt("10.70.0.0/24", Some("ACME"), 1, None, &[])];
        // .5 is already a registered asset at 10.70.0.50.
        let mut reg = HashMap::new();
        reg.insert(
            u32::from(Ipv4Addr::new(192, 168, 1, 5)),
            u32::from(Ipv4Addr::new(10, 70, 0, 50)),
        );
        let (_sum, new_assets) = reconcile_capture_into_zones(
            &mut cap,
            &groups,
            &zones,
            ZoneAffinity::Both,
            7,
            true,
            &reg,
            &HashMap::new(),
            100,
        );
        let (s0, _d0) = addrs(&cap.packets[0].data);
        assert_eq!(
            s0,
            [10, 70, 0, 50],
            "registered origin reuses its stable IP"
        );
        assert_eq!(new_assets.len(), 1, "only the unregistered host is new");
        assert_eq!(new_assets[0].origin, Ipv4Addr::new(192, 168, 1, 6));
    }

    #[test]
    fn apply_host_map_remaps_arp_addresses_and_macs() {
        // Ethernet + ARP reply: SHA 00:0e:8c:.., SPA 192.168.1.5, TPA 192.168.1.1.
        let mut data = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // dst mac (broadcast)
        data.extend_from_slice(&[0x00, 0x0e, 0x8c, 0x11, 0x22, 0x33]); // src mac
        data.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
        data.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02]); // htype/ptype/hlen/plen/oper=reply
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
        let new_spa = u32::from(Ipv4Addr::new(10, 9, 0, 5));
        let new_tpa = u32::from(Ipv4Addr::new(10, 9, 0, 1));
        let mut map = HashMap::new();
        map.insert(u32::from(Ipv4Addr::new(192, 168, 1, 5)), new_spa);
        map.insert(u32::from(Ipv4Addr::new(192, 168, 1, 1)), new_tpa);
        let seed: u64 = 42;
        apply_host_map(&mut cap, &map, &HashMap::new(), seed, true);
        let d = &cap.packets[0].data;
        let sender_mac = stable_mac(seed, new_spa);
        let target_mac = stable_mac(seed, new_tpa);
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
        assert_eq!(&d[22..28], &sender_mac, "sender hardware address rewritten");
        assert_eq!(&d[6..12], &sender_mac, "Ethernet source matches the sender");
        assert_eq!(
            &d[32..38],
            &target_mac,
            "target hardware address rewritten (reply)"
        );
        assert_eq!(
            &d[0..6],
            &target_mac,
            "Ethernet dest matches the target (reply)"
        );
    }

    #[test]
    fn stable_mac_is_laa_unicast_and_deterministic() {
        let a = stable_mac(7, u32::from(Ipv4Addr::new(10, 1, 2, 3)));
        let b = stable_mac(7, u32::from(Ipv4Addr::new(10, 1, 2, 3)));
        let c = stable_mac(7, u32::from(Ipv4Addr::new(10, 1, 2, 4)));
        assert_eq!(a, b, "same (seed, ip) yields the same MAC");
        assert_ne!(a, c, "different IPs yield different MACs");
        assert_eq!(a[0] & 0x01, 0, "unicast (group bit clear)");
        assert_eq!(a[0] & 0x02, 0x02, "locally administered (LAA bit set)");
    }

    #[test]
    fn apply_host_map_rewrites_ipv4_macs_and_preserves_broadcast_dst() {
        // Unicast src->dst: both MACs become stable LAA, IP checksums stay valid.
        let mut uni = cap_from(&[([192, 168, 5, 10], [192, 168, 5, 20])]);
        let seed: u64 = 13;
        // Capture the post-remap new IPs by running the full remap, then re-derive
        // MAC expectations from those IPs.
        remap_capture(&mut uni, &[], seed, true);
        let (s, d) = addrs(&uni.packets[0].data);
        let new_src = u32::from_be_bytes(s);
        let new_dst = u32::from_be_bytes(d);
        assert_eq!(
            &uni.packets[0].data[6..12],
            &stable_mac(seed, new_src),
            "src MAC is the sender's stable MAC"
        );
        assert_eq!(
            &uni.packets[0].data[0..6],
            &stable_mac(seed, new_dst),
            "dst MAC is the peer's stable MAC"
        );
        let l = frame::parse_layout(&uni.packets[0].data).unwrap();
        assert!(frame::checksums_valid(&uni.packets[0].data, &l));

        // A multicast IP destination keeps its (multicast) destination MAC.
        let mut mc = Capture {
            header: PcapHeader::default(),
            packets: vec![OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: 0,
                data: {
                    let mut b = vec![0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]; // multicast dst mac
                    b.extend_from_slice(&[0x52, 0x54, 0, 0, 0, 9]); // src mac
                    b.extend_from_slice(&[0x08, 0x00]);
                    b.extend_from_slice(&[0x45, 0x00, 0x00, 0x1c, 0, 0, 0x40, 0, 0x40, 17, 0, 0]);
                    b.extend_from_slice(&[192, 168, 9, 9]); // src
                    b.extend_from_slice(&[239, 1, 2, 3]); // multicast dst
                    b.extend_from_slice(&[0x10, 0x00, 0x4e, 0x20, 0x00, 0x08, 0x00, 0x00]);
                    let l = frame::parse_layout(&b).unwrap();
                    frame::recompute_checksums(&mut b, &l);
                    b
                },
            }],
        };
        remap_capture(&mut mc, &[], seed, true);
        assert_eq!(
            &mc.packets[0].data[0..6],
            &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            "multicast destination MAC preserved"
        );
    }

    #[test]
    fn drop_unsafe_frames_drops_ipv6_and_keeps_clean_ipv4() {
        // One clean private IPv4 UDP frame plus one IPv6 frame (ethertype 0x86dd).
        let ipv4 = udp([10, 0, 0, 1], [10, 0, 0, 2]);
        let mut ipv6 = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x86, 0xdd];
        ipv6.extend(std::iter::repeat_n(0u8, 40)); // minimal IPv6 header, addresses 0
        ipv6[14] = 0x60; // version 6
        ipv6[22] = 0x20; // a global-ish src first byte (2000::/3)
        let mut cap = Capture {
            header: PcapHeader::default(),
            packets: vec![
                OwnedPacket {
                    ts: Duration::new(1, 0),
                    orig_len: 0,
                    data: ipv4,
                },
                OwnedPacket {
                    ts: Duration::new(1, 0),
                    orig_len: 0,
                    data: ipv6,
                },
            ],
        };
        let dropped = drop_unsafe_frames(&mut cap);
        assert_eq!(dropped, 1, "the IPv6 frame is dropped");
        assert_eq!(cap.packets.len(), 1, "the clean IPv4 frame is kept");
    }

    #[test]
    fn remap_capture_relocates_arp_only_hosts() {
        // An ARP request whose sender IP appears in no IPv4 header must still be
        // relocated out of its original (public) range.
        let mut data = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
        data.extend_from_slice(&[0x08, 0x06]); // ARP
        data.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]); // request
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // SHA
        data.extend_from_slice(&[203, 0, 113, 7]); // SPA (public)
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // THA (zero, request)
        data.extend_from_slice(&[203, 0, 113, 9]); // TPA (public)
        let mut cap = Capture {
            header: PcapHeader::default(),
            packets: vec![OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: data.len() as u32,
                data,
            }],
        };
        let sum = remap_capture(&mut cap, &[], 5, true);
        assert!(sum.host_count >= 1, "ARP hosts are enumerated and remapped");
        // The frame survives (private after remap) and no longer carries the
        // public sender/target protocol addresses.
        assert_eq!(cap.packets.len(), 1, "the ARP frame is kept, not dropped");
        let d = &cap.packets[0].data;
        let spa = Ipv4Addr::new(d[28], d[29], d[30], d[31]);
        let tpa = Ipv4Addr::new(d[38], d[39], d[40], d[41]);
        assert!(
            !is_public_unicast(spa),
            "sender protocol address remapped private"
        );
        assert!(
            !is_public_unicast(tpa),
            "target protocol address remapped private"
        );
    }

    #[test]
    fn carries_public_address_flags_public_ipv4_ipv6_and_arp() {
        // Private IPv4: safe.
        assert!(!carries_public_address(&udp([10, 0, 0, 1], [10, 0, 0, 2])));
        // Public IPv4 destination: flagged.
        assert!(carries_public_address(&udp([10, 0, 0, 1], [8, 8, 8, 8])));
        // IPv6 with a global source: flagged.
        let mut ipv6 = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x86, 0xdd];
        ipv6.extend(std::iter::repeat_n(0u8, 40));
        ipv6[14] = 0x60;
        ipv6[22] = 0x20; // src starts 2000::/3 (global)
        assert!(carries_public_address(&ipv6));
        // ARP with a public sender protocol address: flagged.
        let mut arp = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        arp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
        arp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        arp.extend_from_slice(&[198, 51, 100, 5]); // SPA (public)
        arp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        arp.extend_from_slice(&[192, 168, 0, 1]);
        assert!(carries_public_address(&arp));
        // Unparseable buffer: fail closed.
        assert!(carries_public_address(&[0u8; 4]));
    }
}
