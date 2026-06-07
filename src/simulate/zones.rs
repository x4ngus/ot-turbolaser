//! Zone model and naming, plus green-laser read-only zone derivation.
//!
//! A zone is a subnet grouped from the conversation graph, named after its
//! Purdue/62443 level and dominant vendor. Red laser fabricates zones into the
//! ledger; green laser derives them from a real capture's actual addresses and
//! MAC OUIs without changing anything.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::oui::OuiDb;
use crate::pcapio::Capture;
use crate::proto::frame::{parse_layout, L3Kind};
use crate::proto::l3;

#[derive(Debug, Clone)]
pub struct Zone {
    pub cidr: Ipv4Net,
    pub name: String,
    pub purdue_level: u8,
    pub vendor: Option<String>,
    pub device_ips: Vec<Ipv4Addr>,
}

/// Human label for a Purdue/62443 level.
pub fn purdue_label(level: u8) -> &'static str {
    match level {
        0 => "Field I/O",
        1 => "Basic Control",
        2 => "Supervisory",
        3 => "Operations",
        4 => "Enterprise",
        _ => "Network",
    }
}

/// Coarse Purdue level from a vendor name: switch vendors sit at the conduit
/// boundary (2), known controller vendors at basic control (1), the rest at
/// operations (3). A heuristic, used only to label derived zones.
pub fn infer_level(vendor: Option<&str>) -> u8 {
    let Some(v) = vendor else { return 3 };
    const SWITCH: [&str; 5] = ["Cisco", "Hirschmann", "Moxa", "Belden", "Westermo"];
    const CONTROLLER: [&str; 8] = [
        "Siemens",
        "Rockwell",
        "Schneider",
        "GE",
        "ABB",
        "Beckhoff",
        "WAGO",
        "Phoenix",
    ];
    if SWITCH.iter().any(|s| v.contains(s)) {
        2
    } else if CONTROLLER.iter().any(|s| v.contains(s)) {
        1
    } else {
        3
    }
}

/// A short product-family token from a model string, e.g. "SIMATIC" from
/// "SIMATIC S7-1200 CPU 1212C". Used to flavour fabricated zone names.
pub fn family_of(model: &str) -> String {
    model.split_whitespace().next().unwrap_or("").to_string()
}

/// Build a zone name from vendor, optional product family, Purdue level, and a
/// per-vendor area index, e.g. "Siemens AG SIMATIC Basic Control Area 1".
pub fn name_zone(vendor: Option<&str>, family: Option<&str>, level: u8, idx: usize) -> String {
    let mut parts = vec![vendor.unwrap_or("ICS").to_string()];
    if let Some(f) = family {
        if !f.is_empty() {
            parts.push(f.to_string());
        }
    }
    parts.push(purdue_label(level).to_string());
    format!("{} Area {}", parts.join(" "), idx + 1)
}

/// Unicast, non-loopback, non-multicast: a host worth grouping into a zone.
fn is_unicast(addr: Ipv4Addr) -> bool {
    let o0 = addr.octets()[0];
    o0 != 0 && o0 != 127 && o0 < 224
}

/// Derive zones from a capture's actual addresses and MAC OUIs. Read-only: this
/// is green laser's view of the real world. A host's vendor is taken from the
/// OUI of the source MAC on frames it sends.
pub fn derive_zones(cap: &Capture, hints: &[Ipv4Net], oui: &OuiDb) -> Vec<Zone> {
    let mut host_mac: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    let mut seen: HashMap<Ipv4Addr, ()> = HashMap::new();
    let note = |ip: Ipv4Addr, hosts: &mut Vec<Ipv4Addr>, seen: &mut HashMap<Ipv4Addr, ()>| {
        if is_unicast(ip) && seen.insert(ip, ()).is_none() {
            hosts.push(ip);
        }
    };

    for p in &cap.packets {
        let Some(l) = parse_layout(&p.data) else {
            continue;
        };
        if l.l3_kind == L3Kind::Ipv4 && p.data.len() >= l.l3 + 20 {
            let src = Ipv4Addr::new(
                p.data[l.l3 + 12],
                p.data[l.l3 + 13],
                p.data[l.l3 + 14],
                p.data[l.l3 + 15],
            );
            let dst = Ipv4Addr::new(
                p.data[l.l3 + 16],
                p.data[l.l3 + 17],
                p.data[l.l3 + 18],
                p.data[l.l3 + 19],
            );
            if is_unicast(src) && p.data.len() >= 12 {
                let mac = [
                    p.data[6], p.data[7], p.data[8], p.data[9], p.data[10], p.data[11],
                ];
                host_mac.entry(src).or_insert(mac);
            }
            note(src, &mut hosts, &mut seen);
            note(dst, &mut hosts, &mut seen);
        } else if l3::is_arp_ipv4(&p.data, l.l3) {
            // ARP binds a sender IP to its hardware address; group ARP-only hosts
            // too so they land in a zone and are remapped like any other host.
            let spa = Ipv4Addr::new(
                p.data[l.l3 + 14],
                p.data[l.l3 + 15],
                p.data[l.l3 + 16],
                p.data[l.l3 + 17],
            );
            let tpa = Ipv4Addr::new(
                p.data[l.l3 + 24],
                p.data[l.l3 + 25],
                p.data[l.l3 + 26],
                p.data[l.l3 + 27],
            );
            if is_unicast(spa) {
                let sha = [
                    p.data[l.l3 + 8],
                    p.data[l.l3 + 9],
                    p.data[l.l3 + 10],
                    p.data[l.l3 + 11],
                    p.data[l.l3 + 12],
                    p.data[l.l3 + 13],
                ];
                host_mac.entry(spa).or_insert(sha);
            }
            note(spa, &mut hosts, &mut seen);
            note(tpa, &mut hosts, &mut seen);
        }
    }

    // Group hosts by subnet, ordered by network address for stable output.
    let mut by_subnet: HashMap<Ipv4Net, Vec<Ipv4Addr>> = HashMap::new();
    for h in hosts {
        by_subnet
            .entry(l3::subnet_of(h, hints))
            .or_default()
            .push(h);
    }
    let mut subs: Vec<Ipv4Net> = by_subnet.keys().copied().collect();
    subs.sort_by_key(|n| u32::from(n.network()));

    subs.into_iter()
        .enumerate()
        .map(|(idx, net)| {
            let mut ips = by_subnet.remove(&net).unwrap_or_default();
            ips.sort();
            let mut votes: HashMap<&str, usize> = HashMap::new();
            for ip in &ips {
                if let Some(mac) = host_mac.get(ip) {
                    if let Some(v) = oui.vendor(*mac) {
                        *votes.entry(v).or_default() += 1;
                    }
                }
            }
            let vendor = votes
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(v, _)| v.to_string());
            let level = infer_level(vendor.as_deref());
            let name = name_zone(vendor.as_deref(), None, level, idx);
            Zone {
                cidr: net,
                name,
                purdue_level: level,
                vendor,
                device_ips: ips,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapio::{Capture, OwnedPacket};
    use pcap_file::pcap::PcapHeader;
    use std::time::Duration;

    #[test]
    fn names_reflect_vendor_family_and_level() {
        assert_eq!(
            name_zone(Some("Siemens AG"), Some("SIMATIC"), 1, 0),
            "Siemens AG SIMATIC Basic Control Area 1"
        );
        assert_eq!(name_zone(None, None, 2, 1), "ICS Supervisory Area 2");
        assert_eq!(infer_level(Some("Cisco Systems")), 2);
        assert_eq!(infer_level(Some("Siemens AG")), 1);
        assert_eq!(infer_level(None), 3);
        assert_eq!(family_of("SIMATIC S7-1200 CPU 1212C"), "SIMATIC");
    }

    // Ethernet + IPv4 + UDP frame with a chosen source MAC and addresses.
    fn frame(src_mac: [u8; 6], src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac
        b.extend_from_slice(&src_mac);
        b.extend_from_slice(&[0x08, 0x00]);
        let udp_len = 8 + 2;
        let ip_total = 20 + udp_len;
        b.extend_from_slice(&[0x45, 0x00]);
        b.extend_from_slice(&(ip_total as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
        b.extend_from_slice(&src);
        b.extend_from_slice(&dst);
        b.extend_from_slice(&[0x10, 0x00, 0x4e, 0x20]);
        b.extend_from_slice(&(udp_len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0xAA, 0xBB]);
        let l = parse_layout(&b).unwrap();
        crate::proto::frame::recompute_checksums(&mut b, &l);
        b
    }

    fn cap_of(frames: Vec<Vec<u8>>) -> Capture {
        Capture {
            header: PcapHeader::default(),
            packets: frames
                .into_iter()
                .map(|data| OwnedPacket {
                    ts: Duration::new(1, 0),
                    orig_len: 0,
                    data,
                })
                .collect(),
        }
    }

    #[test]
    fn derive_groups_subnets_and_names_vendor_from_oui() {
        // Two Rockwell hosts (OUI 00:00:BC) in 192.168.10.0/24 and one Siemens
        // host (00:0E:8C) in 192.168.20.0/24.
        let cap = cap_of(vec![
            frame(
                [0x00, 0x00, 0xBC, 0, 0, 1],
                [192, 168, 10, 5],
                [192, 168, 10, 9],
            ),
            frame(
                [0x00, 0x00, 0xBC, 0, 0, 2],
                [192, 168, 10, 9],
                [192, 168, 10, 5],
            ),
            frame(
                [0x00, 0x0E, 0x8C, 0, 0, 1],
                [192, 168, 20, 7],
                [192, 168, 10, 5],
            ),
        ]);
        let oui = OuiDb::embedded();
        let zones = derive_zones(&cap, &[], &oui);
        assert_eq!(zones.len(), 2, "two /24 zones");
        let z10 = zones
            .iter()
            .find(|z| z.cidr.to_string() == "192.168.10.0/24")
            .unwrap();
        assert_eq!(z10.vendor.as_deref(), Some("Rockwell Automation"));
        assert_eq!(z10.purdue_level, 1);
        assert!(z10.name.contains("Rockwell Automation"));
        assert_eq!(z10.device_ips.len(), 2);
        let z20 = zones
            .iter()
            .find(|z| z.cidr.to_string() == "192.168.20.0/24")
            .unwrap();
        assert_eq!(z20.vendor.as_deref(), Some("Siemens AG"));
    }
}
