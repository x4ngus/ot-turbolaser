//! External-threat host promotion (the threat-hunting feature).
//!
//! Rather than synthesize attacker traffic, red laser promotes a genuine host
//! from the replayed capture to a threat actor: its IP is remapped to an
//! external (non-RFC1918) network and its MAC to a desktop-class OUI harvested
//! from the same capture, while its real conversations are preserved. The
//! sensor then sees a believable external actor talking into the OT subnet.
//!
//! Promotions are sparse and rate-limited: at most one every 24 hours, enforced
//! by a hard floor regardless of the configured interval.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use rand::Rng;

use crate::ledger::PromotedHost;
use crate::oui::OuiDb;
use crate::pcapio::Capture;
use crate::proto::frame::{parse_layout, L3Kind, ParsedFrame};

/// The hard minimum between promotions. A config may widen the interval but
/// never make threats more frequent than once a day.
pub const THREAT_FLOOR_SECS: u64 = 86_400;

/// A fallback desktop OUI (VMware) if the capture has no non-OT source MAC to
/// harvest.
const FALLBACK_DESKTOP_OUI: [u8; 3] = [0x00, 0x50, 0x56];

/// Wall-clock scheduler for promotions. Anchors on the last promotion time and
/// draws the next interval in [min, max], with the 24h floor applied. Evaluated
/// each loop iteration; it survives restarts via the ledger's last_threat time.
pub struct ThreatScheduler {
    min: u64,
    max: u64,
    next_due: u64,
}

impl ThreatScheduler {
    pub fn new(
        min_interval: u64,
        max_interval: u64,
        last_threat: Option<u64>,
        now: u64,
        rng: &mut impl Rng,
    ) -> Self {
        let min = min_interval.max(THREAT_FLOOR_SECS);
        let max = max_interval.max(min);
        let mut s = Self {
            min,
            max,
            next_due: 0,
        };
        s.schedule(last_threat.unwrap_or(now), rng);
        s
    }

    fn schedule(&mut self, anchor: u64, rng: &mut impl Rng) {
        let span = self.max - self.min;
        let draw = if span == 0 {
            0
        } else {
            rng.gen_range(0..=span)
        };
        self.next_due = anchor.saturating_add(self.min + draw);
    }

    pub fn due(&self, now: u64) -> bool {
        now >= self.next_due
    }

    pub fn reschedule(&mut self, now: u64, rng: &mut impl Rng) {
        self.schedule(now, rng);
    }
}

fn is_unicast(addr: Ipv4Addr) -> bool {
    let o0 = addr.octets()[0];
    o0 != 0 && o0 != 127 && o0 < 224
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Pick an external address from the first usable configured range. Asserts the
/// candidate is genuinely public at the point of use, independent of config
/// validation, so a misconfigured range can never inject an RFC1918 "attacker".
fn pick_external(cidrs: &[String], rng: &mut impl Rng) -> Option<Ipv4Addr> {
    for c in cidrs {
        if let Ok(net) = c.parse::<Ipv4Net>() {
            let hosts: Vec<Ipv4Addr> = net
                .hosts()
                .filter(|ip| is_public_unicast(*ip))
                .take(1024)
                .collect();
            if !hosts.is_empty() {
                return Some(hosts[rng.gen_range(0..hosts.len())]);
            }
        }
    }
    None
}

/// Unicast and not private/loopback/link-local: a believable external source.
fn is_public_unicast(ip: Ipv4Addr) -> bool {
    let o0 = ip.octets()[0];
    o0 != 0 && o0 != 127 && o0 < 224 && !ip.is_private() && !ip.is_link_local()
}

/// Promote one genuine internal host in `cap` to an external threat actor,
/// rewriting its IP to an external address and its source MAC to a harvested
/// desktop OUI, in place. Returns the promotion record, or None if there is no
/// internal host or no usable external range.
pub fn promote_host(
    cap: &mut Capture,
    external_cidrs: &[String],
    oui: &OuiDb,
    now: u64,
    rng: &mut impl Rng,
) -> Option<PromotedHost> {
    let mut hosts: Vec<Ipv4Addr> = Vec::new();
    let mut seen_hosts = HashSet::new();
    let mut desktop_ouis: Vec<[u8; 3]> = Vec::new();
    let mut seen_ouis = HashSet::new();

    for p in &cap.packets {
        let Some(l) = parse_layout(&p.data) else {
            continue;
        };
        if l.l3_kind != L3Kind::Ipv4 || p.data.len() < l.l3 + 20 {
            continue;
        }
        let src = Ipv4Addr::new(
            p.data[l.l3 + 12],
            p.data[l.l3 + 13],
            p.data[l.l3 + 14],
            p.data[l.l3 + 15],
        );
        if src.is_private() && is_unicast(src) && seen_hosts.insert(src) {
            hosts.push(src);
        }
        if p.data.len() >= 12 {
            let prefix = [p.data[6], p.data[7], p.data[8]];
            // A "desktop" OUI is one our OT-vendor table does not recognise.
            if oui.vendor_of_prefix(prefix).is_none() && seen_ouis.insert(prefix) {
                desktop_ouis.push(prefix);
            }
        }
    }

    if hosts.is_empty() {
        return None;
    }
    let host = hosts[rng.gen_range(0..hosts.len())];
    let external = pick_external(external_cidrs, rng)?;
    let oui3 = if desktop_ouis.is_empty() {
        FALLBACK_DESKTOP_OUI
    } else {
        desktop_ouis[rng.gen_range(0..desktop_ouis.len())]
    };
    let mac = [oui3[0], oui3[1], oui3[2], rng.gen(), rng.gen(), rng.gen()];

    let host_octets = host.octets();
    for p in &mut cap.packets {
        let Some(mut f) = ParsedFrame::parse(&mut p.data) else {
            continue;
        };
        let mut changed = false;
        if f.ipv4_src() == Some(host_octets) {
            f.set_ipv4_src(external.octets());
            f.set_src_mac(mac);
            changed = true;
        }
        if f.ipv4_dst() == Some(host_octets) {
            f.set_ipv4_dst(external.octets());
            changed = true;
        }
        if changed {
            f.recompute_checksums();
        }
    }

    Some(PromotedHost {
        original_ip: host.to_string(),
        external_ip: external.to_string(),
        mac: fmt_mac(mac),
        promoted_unix: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapio::{Capture, OwnedPacket};
    use crate::proto::frame::{self, checksums_valid};
    use pcap_file::pcap::PcapHeader;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::time::Duration;

    fn frame(src_mac: [u8; 6], src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0, 0, 1]); // dst mac
        b.extend_from_slice(&src_mac);
        b.extend_from_slice(&[0x08, 0x00]);
        let udp_len = 8 + 2;
        let ip_total = 20 + udp_len;
        b.extend_from_slice(&[0x45, 0x00]);
        b.extend_from_slice(&(ip_total as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
        b.extend_from_slice(&src);
        b.extend_from_slice(&dst);
        b.extend_from_slice(&[0x13, 0x88, 0x01, 0xf6]);
        b.extend_from_slice(&(udp_len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0xAB, 0xCD]);
        let l = parse_layout(&b).unwrap();
        frame::recompute_checksums(&mut b, &l);
        b
    }

    fn cap_of(frames: Vec<Vec<u8>>) -> Capture {
        Capture {
            header: PcapHeader::default(),
            packets: frames
                .into_iter()
                .map(|data| OwnedPacket {
                    ts: Duration::new(1, 0),
                    orig_len: data.len() as u32,
                    data,
                })
                .collect(),
        }
    }

    #[test]
    fn scheduler_respects_floor_and_window() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        // A configured 1-minute interval is clamped up to the 24h floor.
        let s = ThreatScheduler::new(60, 120, Some(1_000), 0, &mut rng);
        assert!(!s.due(1_000));
        assert!(
            !s.due(1_000 + THREAT_FLOOR_SECS - 1),
            "floor not yet reached"
        );
        assert!(s.due(1_000 + THREAT_FLOOR_SECS + 10));

        // A days-to-weeks window stays within bounds.
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let s = ThreatScheduler::new(172_800, 1_209_600, Some(0), 0, &mut rng);
        assert!(!s.due(172_800 - 1));
        assert!(s.due(1_209_600 + 1));
    }

    #[test]
    fn promotion_moves_one_host_external_and_keeps_others() {
        // Host A uses an unknown (desktop) OUI; host B is a Siemens PLC.
        let a_mac = [0x3c, 0x5a, 0xb4, 0, 0, 1]; // not in the OUI table
        let b_mac = [0x00, 0x0e, 0x8c, 0, 0, 2]; // Siemens
        let cap_base = || {
            cap_of(vec![
                frame(a_mac, [192, 168, 10, 5], [192, 168, 10, 9]),
                frame(b_mac, [192, 168, 10, 9], [192, 168, 10, 5]),
            ])
        };
        let oui = OuiDb::embedded();
        // Seed chosen so the promoted host is the desktop host A.
        let mut promoted_a = None;
        for seed in 0..16u64 {
            let mut cap = cap_base();
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let rec = promote_host(&mut cap, &["203.0.113.0/24".into()], &oui, 5_000, &mut rng)
                .expect("a host is promotable");
            assert!(rec.external_ip.starts_with("203.0.113."));
            // Every frame still has valid checksums.
            for p in &cap.packets {
                let l = parse_layout(&p.data).unwrap();
                assert!(checksums_valid(&p.data, &l));
            }
            if rec.original_ip == "192.168.10.5" {
                promoted_a = Some(cap);
            }
        }
        // When host A is promoted, its frames carry the external src and a
        // desktop OUI; host B's frames are untouched.
        let cap = promoted_a.expect("host A promoted under some seed");
        let l0 = parse_layout(&cap.packets[0].data).unwrap();
        let src0 = [
            cap.packets[0].data[l0.l3 + 12],
            cap.packets[0].data[l0.l3 + 13],
            cap.packets[0].data[l0.l3 + 14],
            cap.packets[0].data[l0.l3 + 15],
        ];
        assert_eq!(src0[0..3], [203, 0, 113], "host A now external");
        let src_oui = [
            cap.packets[0].data[6],
            cap.packets[0].data[7],
            cap.packets[0].data[8],
        ];
        assert!(
            oui.vendor_of_prefix(src_oui).is_none(),
            "promoted host carries a desktop-class (non-OT) OUI"
        );
        // Packet 1 was sent by host B to host A; B's src stays internal.
        let src1 = [
            cap.packets[1].data[l0.l3 + 12],
            cap.packets[1].data[l0.l3 + 13],
        ];
        assert_eq!(src1, [192, 168], "host B unchanged as a sender");
    }
}
