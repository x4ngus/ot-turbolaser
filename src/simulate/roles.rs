//! The OT communication graph: who resolves whom by ARP.
//!
//! A passive sensor (Dragos) forms the MAC<->IP union from an authoritative ARP
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

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::ledger::Session;
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
        .map(|n| {
            let host_bits = 32 - u32::from(n.prefix_len());
            let last_usable = if host_bits >= 1 {
                (1u32 << host_bits).saturating_sub(2)
            } else {
                0
            };
            let offset = 250.min(last_usable);
            Ipv4Addr::from(u32::from(n.network()) + offset)
        })
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 250))
}

/// Parse a colon-separated MAC string into bytes, zero-filling any missing or
/// malformed group, so a stored ledger MAC always yields six bytes.
fn parse_mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, part) in s.split(':').enumerate().take(6) {
        m[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    m
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
    let mut edges = Vec::new();
    // Walk zones in ledger order for determinism. A capture host or device is
    // placed in the zone whose CIDR it records.
    for subnet in &ledger.subnets {
        let cidr = subnet.cidr.as_str();
        let mut nodes: Vec<Node> = Vec::new();

        // Real assets in this zone, sorted by IP so cell membership is stable
        // across runs (a host re-binds in the same cell every burst).
        let mut reals: Vec<Node> = ledger
            .devices
            .iter()
            .filter(|d| d.subnet_cidr == subnet.cidr)
            .filter_map(|d| {
                d.ip.parse::<Ipv4Addr>().ok().map(|ip| Node {
                    ip,
                    mac: parse_mac(&d.mac),
                })
            })
            .chain(
                ledger
                    .capture_hosts
                    .iter()
                    .filter(|h| h.subnet_cidr == subnet.cidr)
                    .filter_map(|h| {
                        h.ip.parse::<Ipv4Addr>().ok().map(|ip| Node {
                            ip,
                            mac: parse_mac(&h.mac),
                        })
                    }),
            )
            .collect();
        reals.sort_by_key(|n| u32::from(n.ip));

        if reals.is_empty() {
            continue; // an empty zone has nothing to discover
        }

        // The station leads cell 0 as the supervisory client, unless a real
        // asset already occupies its address (then that asset plays the role and
        // a duplicate node would split it).
        let station_ip = station_addr(cidr);
        if !reals.iter().any(|n| n.ip == station_ip) {
            nodes.push(Node {
                ip: station_ip,
                mac: l3::stable_mac(seed, u32::from(station_ip)),
            });
        }
        nodes.extend(reals);

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
                owners.len() <= CELL_SIZE - 1,
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
}
