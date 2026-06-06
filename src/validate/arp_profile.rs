//! ARP/role profile oracle.
//!
//! Parses an emitted burst pcap and measures it against the shape of real OT ARP
//! -- the 4SICS GeekLounge reference capture a passive sensor unions cleanly:
//! solicited request/reply pairs, unicast replies padded to 60 bytes, no
//! gratuitous announcements, organically distributed (no host sweeps the
//! subnet), and every asset present as an `is-at` replier. A profile outside
//! these bands is exactly the regression that sank earlier iterations (the
//! subnet-scanning station of pre-v0.2.14, the LAA MACs of pre-v0.2.13, the
//! 42-byte runts of v0.2.9), so this doubles as a CI gate.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use crate::pcapio::Capture;

const ETHERTYPE_ARP: u16 = 0x0806;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;
const ETH_MIN: usize = 60;
/// ARP header is 28 bytes after the 14-byte Ethernet header.
const ARP_END: usize = 14 + 28;

/// A measured profile of the ARP frames in a capture.
#[derive(Debug, Default, Clone)]
pub struct ArpProfile {
    pub requests: usize,
    pub replies: usize,
    /// Frames whose sender and target protocol address are equal (an unsolicited
    /// gratuitous announcement); the reference capture has none.
    pub gratuitous: usize,
    /// ARP frames shorter than the 60-byte Ethernet minimum (rejected as runts).
    pub runts: usize,
    /// `is-at` replies whose sender hardware address is locally administered
    /// (LAA bit set); a passive sensor ignores these for association.
    pub locally_administered: usize,
    /// The greatest number of DISTINCT targets any single source MAC asks for: a
    /// host resolving the whole subnet is the ARP-scan signature the sensor
    /// suppresses. Bounded by the control-cell fan-out.
    pub max_fanout: usize,
    /// The source IP (SPA) of the busiest requester, for the report.
    pub busiest_requester: Option<Ipv4Addr>,
    /// Every protocol address that emitted an `is-at` reply: the assets that
    /// declare their own MAC<->IP and therefore union.
    pub repliers: HashSet<Ipv4Addr>,
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn ipv4(b: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
}

/// Measure the ARP traffic in `cap`.
pub fn analyze(cap: &Capture) -> ArpProfile {
    let mut p = ArpProfile::default();
    // Distinct who-has targets per requester MAC, plus that requester's SPA for
    // a readable report.
    let mut fanout: HashMap<[u8; 6], (HashSet<Ipv4Addr>, Ipv4Addr)> = HashMap::new();

    for pkt in &cap.packets {
        let d = &pkt.data;
        if d.len() < ARP_END || be16(d, 12) != ETHERTYPE_ARP {
            continue;
        }
        let oper = be16(d, 20);
        let sha = [d[22], d[23], d[24], d[25], d[26], d[27]];
        let spa = ipv4(d, 28);
        let tpa = ipv4(d, 38);
        if spa == tpa {
            p.gratuitous += 1;
        }
        if d.len() < ETH_MIN {
            p.runts += 1;
        }
        match oper {
            OP_REQUEST => {
                p.requests += 1;
                let src = [d[6], d[7], d[8], d[9], d[10], d[11]];
                let entry = fanout.entry(src).or_insert_with(|| (HashSet::new(), spa));
                entry.0.insert(tpa);
            }
            OP_REPLY => {
                p.replies += 1;
                p.repliers.insert(spa);
                if sha[0] & 0x02 != 0 {
                    p.locally_administered += 1;
                }
            }
            _ => {}
        }
    }

    if let Some((mac_set, spa)) = fanout.values().max_by_key(|(set, _)| set.len()) {
        let _ = mac_set;
        p.busiest_requester = Some(*spa);
    }
    p.max_fanout = fanout.values().map(|(set, _)| set.len()).max().unwrap_or(0);
    p
}

/// A single failed band, for a readable report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation(pub String);

impl ArpProfile {
    /// Assert the profile is within the reference bands and that every expected
    /// owner emitted an `is-at` reply. Returns the violations (empty = pass).
    /// `max_fanout` is the scanner threshold (the control-cell fan-out cap).
    pub fn check(&self, expected_owners: &HashSet<Ipv4Addr>, max_fanout: usize) -> Vec<Violation> {
        let mut v = Vec::new();
        if self.gratuitous != 0 {
            v.push(Violation(format!(
                "{} gratuitous ARP frame(s); the reference capture has none",
                self.gratuitous
            )));
        }
        if self.runts != 0 {
            v.push(Violation(format!(
                "{} ARP frame(s) under the 60-byte minimum (runts a sensor rejects)",
                self.runts
            )));
        }
        if self.locally_administered != 0 {
            v.push(Violation(format!(
                "{} is-at reply(ies) with a locally-administered MAC (a sensor ignores these for association)",
                self.locally_administered
            )));
        }
        if self.max_fanout > max_fanout {
            v.push(Violation(format!(
                "a requester resolves {} distinct targets (> {}): an ARP-scan signature the sensor suppresses",
                self.max_fanout, max_fanout
            )));
        }
        let missing: Vec<Ipv4Addr> = expected_owners
            .iter()
            .filter(|ip| !self.repliers.contains(ip))
            .copied()
            .collect();
        if !missing.is_empty() {
            v.push(Violation(format!(
                "{} planned asset(s) never emit an is-at reply, so they cannot union (e.g. {})",
                missing.len(),
                missing
                    .iter()
                    .take(5)
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{CaptureHostRecord, Session, SubnetRecord};
    use crate::simulate::roles;
    use crate::synth::{self, arp};

    /// Render the engine's ARP graph for a ledger into a capture, the same way
    /// `build_assertions` does, so the gate runs over realistic frames.
    fn render(ledger: &Session) -> Capture {
        let mut frames = Vec::new();
        for e in roles::arp_edges(ledger, ledger.seed) {
            let (req, rep) = arp::resolve(e.requester.mac, e.requester.ip, e.owner.mac, e.owner.ip);
            frames.push(req);
            frames.push(rep);
        }
        synth::to_capture(frames)
    }

    fn ledger_with(cidr: &str, n: u8) -> Session {
        let mut s = Session::new(1234, 0);
        s.subnets.push(SubnetRecord {
            cidr: cidr.into(),
            zone_name: "Z".into(),
            purdue_level: 1,
            vendor: None,
        });
        for i in 1..=n {
            // Distinct, globally-administered MAC per host (as stable_mac yields).
            let mac = format!("00:0e:8c:00:00:{i:02x}");
            s.capture_hosts.push(CaptureHostRecord {
                origin_ip: format!("10.7.0.{i}"),
                ip: format!("10.7.0.{i}"),
                mac,
                vendor: None,
                protocol: None,
                purdue_level: 0,
                subnet_cidr: cidr.into(),
            });
        }
        s
    }

    #[test]
    fn emitted_burst_matches_the_reference_bands() {
        let cidr = "10.7.0.0/24";
        let s = ledger_with(cidr, 50);
        let cap = render(&s);
        let prof = analyze(&cap);

        // Solicited pairs only: a reply for every request, none gratuitous, none
        // runts, none locally administered.
        assert!(prof.requests > 0 && prof.replies > 0);
        assert_eq!(prof.gratuitous, 0);
        assert_eq!(prof.runts, 0, "every ARP frame is padded to 60 bytes");
        assert_eq!(prof.locally_administered, 0, "all is-at MACs are global");
        assert!(
            prof.max_fanout <= roles::CELL_SIZE - 1,
            "no requester sweeps the subnet (fan-out {})",
            prof.max_fanout
        );

        // The cardinal gate: every planned asset is an is-at replier.
        let expected: HashSet<Ipv4Addr> = roles::arp_edges(&s, s.seed)
            .iter()
            .map(|e| e.owner.ip)
            .collect();
        let violations = prof.check(&expected, roles::CELL_SIZE - 1);
        assert!(violations.is_empty(), "profile violations: {violations:?}");
    }

    #[test]
    fn a_subnet_sweep_is_flagged() {
        // One source MAC asks for many distinct targets: the scan signature.
        let mut frames = Vec::new();
        let scanner = [0x00, 0x0e, 0x8c, 1, 1, 1];
        for i in 1..=30u8 {
            frames.push(arp::request(
                scanner,
                Ipv4Addr::new(10, 7, 0, 250),
                Ipv4Addr::new(10, 7, 0, i),
            ));
        }
        let prof = analyze(&synth::to_capture(frames));
        let violations = prof.check(&HashSet::new(), roles::CELL_SIZE - 1);
        assert!(
            violations.iter().any(|v| v.0.contains("ARP-scan")),
            "a subnet sweep must be flagged: {violations:?}"
        );
    }
}
