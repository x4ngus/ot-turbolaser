//! The OT communication graph: who resolves whom by ARP.
//!
//! A passive sensor forms the MAC<->IP union from an authoritative ARP
//! *is-at reply* -- an asset answering "my IP is at my MAC" (sender fields of an
//! `oper=2` frame) -- NOT from a `who-has` request's sender, and not from an
//! L3/L7 source MAC (which in a routed network could be a forwarder). The
//! v0.2.21 field export was the controlled proof: every asset broadcast its own
//! who-has request, yet the only assets that unioned were the per-zone `.250`
//! engineering stations -- the sole emitters of an `is-at` reply (every device
//! and host that only requested, or only served an OT session, stayed split).
//!
//! So every asset we want fused must be the OWNER of a resolution: a peer asks
//! for it, and it answers `is-at`. The solicitation must look organic. A single
//! host broadcasting `who-has` for a whole subnet is an ARP-scan signature the
//! sensor suppresses (it cost the pre-v0.2.14 station model its bindings); an
//! abstract every-node-resolves-the-next ring regressed to zero under the
//! pre-flood, pre-global-MAC conditions of v0.2.14. The faithful pattern -- and
//! the 4SICS GeekLounge reference capture's -- is a few hosts each resolving the
//! *few* peers they actually talk to (one geeklounge client re-resolved a single
//! peer 730 times; servers replied and never scanned).
//!
//! This module models that: each zone is partitioned into small **control
//! cells**, mirroring an OT line/cell with a local controller. The cell master
//! resolves its members (they answer and bind); one member resolves the master
//! (it answers and binds). Every asset is the owner of at least one edge -- so it
//! is bound from its first burst, never on a late window -- while no requester
//! resolves more than `CELL_SIZE - 1` distinct owners, so there is no scanner.
//! The zone engineering station (`.250`) leads the first cell: the supervisory
//! client that polls a handful of field devices.
//!
//! The graph is pure (a function of the sealed ledger plus the session seed), so
//! it requires no re-plan and is unit-tested without a wire.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::ledger::{DeviceRecord, Session, SubnetRecord};
use crate::proto::l3;

/// Assets per control cell: a local master plus up to `CELL_SIZE - 1` members.
/// The master's `who-has` fan-out is therefore bounded at `CELL_SIZE - 1`, well
/// under any ARP-scan threshold, while the cell stays the size of a plausible OT
/// line (a controller and the few field devices on it).
pub const CELL_SIZE: usize = 6;

/// One asset as the graph sees it: a stable IP bound to a stable MAC. Both a
/// fabricated [`crate::ledger::DeviceRecord`] and a
/// [`crate::ledger::CaptureHostRecord`] reduce to this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
}

/// A directed resolution: `requester` broadcasts `who-has` for `owner`; `owner`
/// answers `is-at` and binds at the sensor. The engine renders it with
/// [`crate::synth::arp::resolve`] (broadcast request + unicast reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub requester: Node,
    pub owner: Node,
}

/// The engineering-station address within a subnet (network + 250, clamped to
/// the last usable host so it never lands outside a small subnet). This is the
/// per-zone supervisory client: it leads the first control cell and is the OT
/// session client in [`crate::simulate::engine`]. One stable client per zone, so
/// its MAC is never multi-homed across zones (which a sensor cannot fuse).
pub fn station_addr(subnet_cidr: &str) -> Ipv4Addr {
    subnet_cidr
        .parse::<Ipv4Net>()
        .ok()
        .map(station_addr_net)
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 250))
}

/// The engineering-station address for an already-parsed subnet, so callers that
/// hold an [`Ipv4Net`] (host allocation) can reserve the slot without a string
/// round-trip. See [`station_addr`] for the semantics.
pub fn station_addr_net(n: Ipv4Net) -> Ipv4Addr {
    let host_bits = 32 - u32::from(n.prefix_len());
    let last_usable = if host_bits >= 1 {
        (1u32 << host_bits).saturating_sub(2)
    } else {
        0
    };
    let offset = 250.min(last_usable);
    Ipv4Addr::from(u32::from(n.network()) + offset)
}

/// The zone-edge firewall/gateway address within a subnet (network + 1, the
/// conventional default gateway). It hosts the per-zone DNS resolver and is a
/// real ledger asset, so it unions like any other host and reads as the conduit
/// all the zone's traffic routes through.
pub fn firewall_addr(subnet_cidr: &str) -> Ipv4Addr {
    subnet_cidr
        .parse::<Ipv4Net>()
        .ok()
        .map(|n| Ipv4Addr::from(u32::from(n.network()).saturating_add(1)))
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
}

/// A north-south crossing: a supervisory client in a higher Purdue zone reaching
/// a CVE-bearing device in an adjacent lower zone, forwarded by a conduit. The
/// engine renders it with the conduit MAC as the L2 forwarder (the client MAC)
/// and the north client's IP, so a sensor sees north<->south traffic crossing the
/// conduit and does not bind either IP to the conduit MAC (an L3 source MAC could
/// be a router). It carries no ARP, so it never touches the union gate or
/// multi-homes a MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crossing {
    /// The supervisory client's IP (the higher zone's station).
    pub north_ip: Ipv4Addr,
    /// The field server in the adjacent lower zone (its real IP and MAC).
    pub south_ip: Ipv4Addr,
    pub south_mac: [u8; 6],
    /// The L2 forwarder the sensor sees on the crossing: the zone-edge router or
    /// firewall, else a switch, else the north station.
    pub conduit_mac: [u8; 6],
}

/// Enumerate bounded north-south crossings across adjacent Purdue zones. Each
/// zone at level L+1 (north) pairs with one deterministically chosen zone at
/// level L (south) and reaches up to `max_per_pair` of its lowest-IP CVE-bearing
/// devices, forwarded by a conduit (the zone-edge router/firewall, else a switch,
/// else the north station). Bounded, never a mesh, so the wire carries no scan.
/// Pure (a function of the ledger and seed), so adjacency and bounding are
/// unit-tested without a wire.
pub fn north_south_crossings(ledger: &Session, seed: u64, max_per_pair: usize) -> Vec<Crossing> {
    if max_per_pair == 0 {
        return Vec::new();
    }
    let mut by_level: BTreeMap<u8, Vec<&SubnetRecord>> = BTreeMap::new();
    for s in &ledger.subnets {
        by_level.entry(s.purdue_level).or_default().push(s);
    }
    for v in by_level.values_mut() {
        v.sort_by(|a, b| a.cidr.cmp(&b.cidr));
    }
    // South servers: a zone's CVE-bearing field devices (not the conduit infra
    // itself), sorted by IP so the lowest are picked.
    let mut servers_by_zone: BTreeMap<&str, Vec<(Ipv4Addr, [u8; 6])>> = BTreeMap::new();
    for d in &ledger.devices {
        if d.cves.is_empty() || matches!(d.asset_type.as_deref(), Some("Firewall") | Some("Router"))
        {
            continue;
        }
        if let Ok(ip) = d.ip.parse::<Ipv4Addr>() {
            servers_by_zone
                .entry(d.subnet_cidr.as_str())
                .or_default()
                .push((ip, l3::parse_mac(&d.mac)));
        }
    }
    for v in servers_by_zone.values_mut() {
        v.sort_by_key(|(ip, _)| u32::from(*ip));
    }

    let mut out = Vec::new();
    for (&level, north_zones) in &by_level {
        let Some(south_level) = level.checked_sub(1) else {
            continue;
        };
        let Some(south_zones) = by_level.get(&south_level) else {
            continue;
        };
        if south_zones.is_empty() {
            continue;
        }
        for north in north_zones {
            let south = south_zones[det_index(seed, &north.cidr, south_zones.len())];
            let Some(servers) = servers_by_zone.get(south.cidr.as_str()) else {
                continue;
            };
            if servers.is_empty() {
                continue;
            }
            let north_ip = station_addr(&north.cidr);
            let station_mac = l3::stable_mac(seed, u32::from(north_ip));
            let conduit_mac = pick_conduit_mac(ledger, &north.cidr, &south.cidr, station_mac);
            for &(south_ip, south_mac) in servers.iter().take(max_per_pair) {
                out.push(Crossing {
                    north_ip,
                    south_ip,
                    south_mac,
                    conduit_mac,
                });
            }
        }
    }
    out
}

/// The conduit MAC for a zone pair: the zone-edge router or firewall in either
/// zone, else a switch, else the north station MAC. So a plant always shows
/// north-south traffic, using a real conduit device when one exists.
fn pick_conduit_mac(
    ledger: &Session,
    north_cidr: &str,
    south_cidr: &str,
    station: [u8; 6],
) -> [u8; 6] {
    let in_pair = |d: &&DeviceRecord| d.subnet_cidr == north_cidr || d.subnet_cidr == south_cidr;
    for class in ["Router", "Firewall", "Switch"] {
        if let Some(d) = ledger
            .devices
            .iter()
            .filter(in_pair)
            .find(|d| d.asset_type.as_deref() == Some(class))
        {
            return l3::parse_mac(&d.mac);
        }
    }
    station
}

/// A small deterministic index into a slice of length `len`, from the seed and a
/// key string (FNV-1a style), so a north zone always picks the same south zone.
fn det_index(seed: u64, key: &str, len: usize) -> usize {
    if len <= 1 {
        return 0;
    }
    let mut h = seed ^ 0xCBF2_9CE4_8422_2325;
    for b in key.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    (h % len as u64) as usize
}

/// Build the per-zone ARP communication graph as a flat edge list. Every real
/// asset (fabricated device or capture host) appears as the OWNER of at least
/// one edge, so it answers `is-at` and unions its MAC<->IP; no requester resolves
/// more than `CELL_SIZE - 1` distinct owners, so the wire carries no scan. The
/// owner's MAC is the asset's stored MAC -- the same one its L3/L7 traffic
/// sources -- so the sensor never sees two MACs for one IP. The synthetic zone
/// station's MAC is derived the same way the engine's OT-session client MAC is
/// (`stable_mac(seed, station_ip)`), so ARP and the session agree byte-for-byte.
pub fn arp_edges(ledger: &Session, seed: u64) -> Vec<Edge> {
    // Group every asset by its OWN recorded subnet in a single pass. Keying on
    // the asset (not on `ledger.subnets`) means no asset is silently dropped if
    // its zone is absent from the subnet list, and the cost is O(assets) rather
    // than O(zones x assets). A BTreeMap keeps zone order deterministic so a host
    // re-binds in the same cell every burst.
    let mut by_zone: BTreeMap<&str, Vec<Node>> = BTreeMap::new();
    let devices = ledger
        .devices
        .iter()
        .map(|d| (&d.ip, &d.mac, &d.subnet_cidr));
    let hosts = ledger
        .capture_hosts
        .iter()
        .map(|h| (&h.ip, &h.mac, &h.subnet_cidr));
    for (ip, mac, cidr) in devices.chain(hosts) {
        if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            by_zone.entry(cidr.as_str()).or_default().push(Node {
                ip,
                mac: l3::parse_mac(mac),
            });
        }
    }

    let mut edges = Vec::new();
    for (cidr, mut reals) in by_zone {
        // Sort by IP so cell membership is stable across runs.
        reals.sort_by_key(|n| u32::from(n.ip));

        // The station leads cell 0 as the supervisory client, unless a real asset
        // already occupies its address (a duplicate node would split it).
        let station_ip = station_addr(cidr);
        let mut nodes: Vec<Node> = Vec::with_capacity(reals.len() + 1);
        if !reals.iter().any(|n| n.ip == station_ip) {
            nodes.push(Node {
                ip: station_ip,
                mac: l3::stable_mac(seed, u32::from(station_ip)),
            });
        }
        nodes.extend(reals);

        // A lone asset sitting on the station address would be the only node and
        // have no peer to solicit its is-at, so it would never bind. Give it a
        // synthetic requester one address below so it is still resolved.
        if nodes.len() == 1 {
            let alt = Ipv4Addr::from(u32::from(station_ip).saturating_sub(1));
            if alt != nodes[0].ip {
                nodes.insert(
                    0,
                    Node {
                        ip: alt,
                        mac: l3::stable_mac(seed, u32::from(alt)),
                    },
                );
            }
        }

        // Partition into cells; bind every node within its cell.
        for cell in cells_no_orphan(&nodes, CELL_SIZE) {
            let master = cell[0];
            // The master polls each member: it asks, the member answers is-at and
            // binds. (A server answering and never scanning is the faithful OT
            // shape -- geeklounge's PLCs reply and never send who-has.)
            for &member in &cell[1..] {
                edges.push(Edge {
                    requester: master,
                    owner: member,
                });
            }
            // The master binds too: its first member resolves it once.
            if let Some(&first) = cell.get(1) {
                edges.push(Edge {
                    requester: first,
                    owner: master,
                });
            }
        }
    }
    edges
}

/// Split `nodes` into consecutive cells of `size`, never leaving a size-1 tail
/// (a lone node would have no peer to bind it): a trailing single is merged back
/// by shrinking the prior cell to `size - 1`. Assumes `size >= 2`.
fn cells_no_orphan(nodes: &[Node], size: usize) -> Vec<&[Node]> {
    let n = nodes.len();
    if n == 0 {
        return Vec::new();
    }
    if n <= size {
        return vec![nodes];
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let remaining = n - i;
        // If taking a full cell would strand exactly one node, take one fewer so
        // the final cell is a pair rather than an orphan.
        let take = if remaining > size && remaining - size == 1 {
            size - 1
        } else {
            size.min(remaining)
        };
        out.push(&nodes[i..i + take]);
        i += take;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{CaptureHostRecord, DeviceRecord, SubnetRecord};
    use std::collections::{HashMap, HashSet};

    fn sess(seed: u64) -> Session {
        Session::new(seed, 0)
    }

    fn add_zone(s: &mut Session, cidr: &str) {
        s.subnets.push(SubnetRecord {
            cidr: cidr.into(),
            zone_name: "Z".into(),
            purdue_level: 1,
            vendor: None,
            ..Default::default()
        });
    }

    fn dev(ip: &str, cidr: &str) -> DeviceRecord {
        DeviceRecord {
            ip: ip.into(),
            mac: "00:00:bc:00:00:01".into(),
            vendor: "Rockwell Automation".into(),
            model: "1756-L61".into(),
            firmware: "20.011".into(),
            protocol: "enip".into(),
            cves: vec![],
            subnet_cidr: cidr.into(),
            hostname: None,
            asset_type: None,
        }
    }

    fn host(ip: &str, cidr: &str) -> CaptureHostRecord {
        CaptureHostRecord {
            origin_ip: ip.into(),
            ip: ip.into(),
            mac: "02:00:00:11:22:33".into(),
            vendor: None,
            protocol: None,
            purdue_level: 0,
            subnet_cidr: cidr.into(),
            hostname: None,
            asset_type: None,
        }
    }

    /// The cardinal invariant: every real asset is the OWNER of at least one
    /// edge, so it emits an is-at reply and unions. This is exactly what v0.2.21
    /// failed -- only the station replied, so only the station unioned.
    #[test]
    fn every_asset_is_an_is_at_owner() {
        let cidr = "10.0.0.0/24";
        let mut s = sess(42);
        add_zone(&mut s, cidr);
        for i in 1..=40u8 {
            if i % 3 == 0 {
                s.devices.push(dev(&format!("10.0.0.{i}"), cidr));
            } else {
                s.capture_hosts.push(host(&format!("10.0.0.{i}"), cidr));
            }
        }
        let edges = arp_edges(&s, s.seed);
        let owners: HashSet<Ipv4Addr> = edges.iter().map(|e| e.owner.ip).collect();
        for i in 1..=40u8 {
            let ip: Ipv4Addr = format!("10.0.0.{i}").parse().unwrap();
            assert!(owners.contains(&ip), "asset {ip} never owns an is-at reply");
        }
        // The station binds too (it replies when its first member asks).
        assert!(owners.contains(&station_addr(cidr)), "station never binds");
    }

    /// No requester resolves more than CELL_SIZE-1 distinct owners: the wire
    /// never shows one host sweeping the subnet (the scan signature that has
    /// suppressed association in every prior iteration).
    #[test]
    fn no_requester_scans_the_subnet() {
        let cidr = "10.1.0.0/24";
        let mut s = sess(7);
        add_zone(&mut s, cidr);
        for i in 1..=60u8 {
            s.capture_hosts.push(host(&format!("10.1.0.{i}"), cidr));
        }
        let edges = arp_edges(&s, s.seed);
        // Fan-out is a per-node property; key by requester IP (1:1 with MAC in
        // production, where stable_mac is per-IP -- the test helper reuses one MAC).
        let mut fanout: HashMap<Ipv4Addr, HashSet<Ipv4Addr>> = HashMap::new();
        for e in &edges {
            fanout.entry(e.requester.ip).or_default().insert(e.owner.ip);
        }
        for (ip, owners) in fanout {
            assert!(
                owners.len() < CELL_SIZE,
                "requester {ip} resolves {} owners (> {})",
                owners.len(),
                CELL_SIZE - 1
            );
        }
    }

    /// The owner MAC is the asset's stored MAC (what its L3/L7 traffic sources),
    /// and it is globally administered (the v0.2.13 lesson: a passive sensor
    /// ignores locally-administered MACs for association).
    #[test]
    fn owner_mac_is_stored_and_global() {
        let cidr = "10.2.0.0/24";
        let mut s = sess(1);
        add_zone(&mut s, cidr);
        s.capture_hosts.push(host("10.2.0.5", cidr));
        let edges = arp_edges(&s, s.seed);
        let owner = edges
            .iter()
            .find(|e| e.owner.ip == "10.2.0.5".parse::<Ipv4Addr>().unwrap())
            .unwrap();
        assert_eq!(
            owner.owner.mac,
            [0x02, 0x00, 0x00, 0x11, 0x22, 0x33],
            "uses the stored MAC"
        );
        // Station MAC is global (LAA bit clear) since stable_mac clears it.
        let st = edges
            .iter()
            .find(|e| e.owner.ip == station_addr(cidr))
            .unwrap();
        assert_eq!(
            st.owner.mac[0] & 0x02,
            0,
            "station MAC is globally administered"
        );
    }

    /// Determinism: same ledger + seed yields the same graph (a host re-binds in
    /// the same cell every burst, never a moving target the sensor can't fuse).
    #[test]
    fn graph_is_deterministic() {
        let cidr = "10.3.0.0/24";
        let mut s = sess(99);
        add_zone(&mut s, cidr);
        for i in 1..=25u8 {
            s.capture_hosts.push(host(&format!("10.3.0.{i}"), cidr));
        }
        assert_eq!(arp_edges(&s, s.seed), arp_edges(&s, s.seed));
    }

    /// A trailing single node is never stranded: it is merged into a pair so it
    /// always has a peer to bind it.
    #[test]
    fn no_orphan_cell() {
        // 13 nodes, size 6 -> [6,?]: 13 = 6 + 7, and 7 > 6 with 7-6==1 would
        // strand one, so the split is 6,5,2 (every cell >= 2).
        let nodes: Vec<Node> = (0..13)
            .map(|i| Node {
                ip: Ipv4Addr::from(i as u32),
                mac: [0; 6],
            })
            .collect();
        for cell in cells_no_orphan(&nodes, 6) {
            assert!(
                cell.len() >= 2,
                "cell of size {} strands a node",
                cell.len()
            );
        }
    }

    /// A zone with a single asset sitting on the station address still binds: it
    /// gets a synthetic requester one below, so it is solicited and unions.
    #[test]
    fn lone_asset_on_station_address_still_binds() {
        let cidr = "10.5.0.0/24";
        let mut s = sess(3);
        add_zone(&mut s, cidr);
        s.capture_hosts.push(host("10.5.0.250", cidr)); // sits on the station addr
        let edges = arp_edges(&s, s.seed);
        let lone: Ipv4Addr = "10.5.0.250".parse().unwrap();
        assert!(
            edges.iter().any(|e| e.owner.ip == lone),
            "the lone .250 asset must be solicited and bind: {edges:?}"
        );
    }

    /// An asset whose zone is absent from `ledger.subnets` is still bound: the
    /// graph keys on the asset's own subnet, not the subnet list.
    #[test]
    fn asset_binds_even_if_zone_not_in_subnet_list() {
        let cidr = "10.6.0.0/24";
        let mut s = sess(5);
        // Note: NO add_zone -- subnets stays empty on purpose.
        s.capture_hosts.push(host("10.6.0.7", cidr));
        s.capture_hosts.push(host("10.6.0.8", cidr));
        let owners: HashSet<Ipv4Addr> = arp_edges(&s, s.seed).iter().map(|e| e.owner.ip).collect();
        assert!(owners.contains(&"10.6.0.7".parse().unwrap()));
        assert!(owners.contains(&"10.6.0.8".parse().unwrap()));
    }

    fn zoned(s: &mut Session, cidr: &str, level: u8) {
        s.subnets.push(SubnetRecord {
            cidr: cidr.into(),
            zone_name: "Z".into(),
            purdue_level: level,
            vendor: None,
            ..Default::default()
        });
    }

    fn cve_dev(ip: &str, cidr: &str) -> DeviceRecord {
        let mut d = dev(ip, cidr);
        d.cves = vec!["CVE-0000-0000".into()];
        d.asset_type = Some("Controller".into());
        d
    }

    fn infra(ip: &str, cidr: &str, class: &str, mac: &str) -> DeviceRecord {
        let mut d = dev(ip, cidr);
        d.mac = mac.into();
        d.protocol = "switch_snmp".into();
        d.cves = vec!["CVE-0000-0001".into()];
        d.asset_type = Some(class.into());
        d
    }

    #[test]
    fn north_south_pairs_are_adjacent_only() {
        let mut s = sess(11);
        zoned(&mut s, "10.1.0.0/24", 1);
        zoned(&mut s, "10.2.0.0/24", 2);
        zoned(&mut s, "10.3.0.0/24", 3);
        s.devices.push(cve_dev("10.1.0.5", "10.1.0.0/24"));
        s.devices.push(cve_dev("10.1.0.6", "10.1.0.0/24"));
        s.devices.push(cve_dev("10.2.0.5", "10.2.0.0/24"));
        s.devices.push(cve_dev("10.2.0.6", "10.2.0.0/24"));
        s.devices.push(cve_dev("10.3.0.5", "10.3.0.0/24"));
        let xs = north_south_crossings(&s, s.seed, 2);
        assert!(!xs.is_empty(), "adjacent zones yield crossings");
        for c in &xs {
            let n = c.north_ip.octets()[1];
            let so = c.south_ip.octets()[1];
            // North is exactly one Purdue level above south (2->1 or 3->2), never
            // the non-adjacent 3->1.
            assert!(
                (n == 2 && so == 1) || (n == 3 && so == 2),
                "crossing {n}->{so} is not adjacent"
            );
        }
        assert!(
            xs.iter()
                .any(|c| c.north_ip.octets()[1] == 2 && c.south_ip.octets()[1] == 1),
            "the 2->1 pair is represented"
        );
        assert!(
            xs.iter()
                .any(|c| c.north_ip.octets()[1] == 3 && c.south_ip.octets()[1] == 2),
            "the 3->2 pair is represented"
        );
    }

    #[test]
    fn crossings_are_bounded_and_deterministic() {
        let mut s = sess(7);
        zoned(&mut s, "10.1.0.0/24", 1);
        zoned(&mut s, "10.2.0.0/24", 2);
        for i in 1..=20u8 {
            s.devices
                .push(cve_dev(&format!("10.1.0.{i}"), "10.1.0.0/24"));
        }
        s.devices.push(cve_dev("10.2.0.5", "10.2.0.0/24"));
        // One north zone reaching one south zone, capped at max_per_pair even with
        // 20 candidate servers: never a mesh.
        assert_eq!(north_south_crossings(&s, s.seed, 3).len(), 3);
        assert_eq!(
            north_south_crossings(&s, s.seed, 3),
            north_south_crossings(&s, s.seed, 3),
            "deterministic"
        );
    }

    #[test]
    fn conduit_prefers_router_then_firewall_then_switch_then_station() {
        let mut s = sess(5);
        zoned(&mut s, "10.1.0.0/24", 1);
        zoned(&mut s, "10.2.0.0/24", 2);
        s.devices.push(cve_dev("10.1.0.5", "10.1.0.0/24")); // south server
        let sw = infra("10.2.0.20", "10.2.0.0/24", "Switch", "00:90:e8:00:00:20");
        let fw = infra("10.2.0.1", "10.2.0.0/24", "Firewall", "00:09:0f:00:00:01");
        let rt = infra("10.2.0.30", "10.2.0.0/24", "Router", "00:00:0c:00:00:30");
        s.devices.push(sw.clone());
        s.devices.push(fw.clone());
        s.devices.push(rt.clone());
        let station_mac = l3::stable_mac(s.seed, u32::from(station_addr("10.2.0.0/24")));

        assert_eq!(
            north_south_crossings(&s, s.seed, 1)[0].conduit_mac,
            l3::parse_mac(&rt.mac),
            "router preferred"
        );
        s.devices
            .retain(|d| d.asset_type.as_deref() != Some("Router"));
        assert_eq!(
            north_south_crossings(&s, s.seed, 1)[0].conduit_mac,
            l3::parse_mac(&fw.mac),
            "firewall is next"
        );
        s.devices
            .retain(|d| d.asset_type.as_deref() != Some("Firewall"));
        assert_eq!(
            north_south_crossings(&s, s.seed, 1)[0].conduit_mac,
            l3::parse_mac(&sw.mac),
            "switch is next"
        );
        s.devices
            .retain(|d| d.asset_type.as_deref() != Some("Switch"));
        assert_eq!(
            north_south_crossings(&s, s.seed, 1)[0].conduit_mac,
            station_mac,
            "the station MAC is the last resort, so a pair is never skipped"
        );
    }
}
