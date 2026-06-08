//! The scenario engine: walks a playbook and renders each phase's events to
//! attack frames.
//!
//! Held as an `Option<ScenarioEngine>` inside the red-laser `SimulatorEngine`.
//! Each announce burst, [`ScenarioEngine::phase_frames`] renders the current
//! phase's events (resolved against the sealed plant ledger) and advances the
//! timeline once the phase's events are spent and its dwell elapses. A long
//! event sequence spreads across bursts under the per-burst frame cap. On
//! exhaustion a one-shot campaign holds the final (impact) phase; a loop restarts.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::config::{Campaign, IocFidelity, TargetCfg};
use crate::ledger::{DeviceRecord, Session};
use crate::proto::l3;
use crate::simulate::roles;
use crate::synth::ioc::C2Target;
use crate::synth::{iec104, ioc, modbus_write, parse_version, s7_control, s7_szl, tristation};
use crate::vuln::VulnDb;

use super::playbook::{DeviceRef, EmitKind, Event, Phase, Playbook};

pub struct ScenarioEngine {
    name: String,
    playbook: Playbook,
    external_cidrs: Vec<String>,
    c2_domains: Vec<String>,
    c2_ips: Vec<String>,
    fidelity: IocFidelity,
    campaign: Campaign,
    max_frames_per_burst: usize,
    seed: u64,
    phase_idx: usize,
    event_cursor: usize,
    bursts_in_phase: u64,
}

impl ScenarioEngine {
    /// Load the scenario's playbook from its pack and build the engine. `seed` is
    /// the session seed, so the attacker-station MACs match the plant's.
    pub fn load(target: &TargetCfg, seed: u64) -> Result<Self, String> {
        let playbook = Playbook::load(&target.pack_dir.join(&target.playbook))?;
        Ok(Self {
            name: target.name.clone(),
            playbook,
            external_cidrs: target.actors.external_cidrs.clone(),
            c2_domains: target.actors.c2_domains.clone(),
            c2_ips: target.actors.c2_ips.clone(),
            fidelity: target.ioc_fidelity,
            campaign: target.campaign,
            max_frames_per_burst: target.max_frames_per_burst.max(1),
            seed,
            phase_idx: 0,
            event_cursor: 0,
            bursts_in_phase: 0,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn current_phase(&self) -> &Phase {
        // phase_idx is always in range: the playbook is non-empty (enforced at
        // parse) and `advance` clamps to the last phase or wraps.
        &self.playbook.phases[self.phase_idx]
    }

    /// The current phase id, e.g. "manipulation".
    pub fn phase_id(&self) -> &str {
        &self.current_phase().id
    }

    /// The current phase's human label (its name, or its id).
    pub fn phase_label(&self) -> String {
        let p = self.current_phase();
        p.name.clone().unwrap_or_else(|| p.id.clone())
    }

    /// The current phase's ATT&CK-for-ICS technique ids.
    pub fn techniques(&self) -> Vec<String> {
        self.current_phase().techniques.clone()
    }

    /// Render this burst's attack frames and advance the timeline. Called once per
    /// identity-announce burst, so dwell and pacing are measured in bursts.
    pub fn phase_frames(&mut self, ledger: &Session, vuln: &VulnDb, nonce: u64) -> Vec<Vec<u8>> {
        let events_len = self.current_phase().events.len();
        let dwell = self.current_phase().dwell_runs.max(1);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        // Emit from the cursor, bounded by the per-burst frame cap so a long
        // sequence spreads across successive bursts instead of one microburst.
        while self.event_cursor < events_len {
            let ev = &self.playbook.phases[self.phase_idx].events[self.event_cursor];
            let ev_frames = self.render_event(
                ev,
                ledger,
                vuln,
                nonce.wrapping_add(self.event_cursor as u64),
            );
            if !frames.is_empty() && frames.len() + ev_frames.len() > self.max_frames_per_burst {
                break;
            }
            frames.extend(ev_frames);
            self.event_cursor += 1;
        }
        self.bursts_in_phase += 1;
        if self.event_cursor >= events_len && self.bursts_in_phase >= dwell {
            self.advance();
        }
        frames
    }

    fn advance(&mut self) {
        self.event_cursor = 0;
        self.bursts_in_phase = 0;
        let last = self.playbook.phases.len() - 1;
        if self.phase_idx < last {
            self.phase_idx += 1;
        } else if self.campaign == Campaign::Loop {
            self.phase_idx = 0;
        }
        // Oneshot at the last phase: hold here and keep re-emitting the impact.
    }

    /// Render one event to frames, resolving its target against the plant. An
    /// event whose target cannot be resolved is skipped (returns no frames), so a
    /// misauthored playbook degrades rather than panics.
    fn render_event(
        &self,
        ev: &Event,
        ledger: &Session,
        vuln: &VulnDb,
        nonce: u64,
    ) -> Vec<Vec<u8>> {
        let port = 49152 + (nonce % 16384) as u16;
        // Most actions run as the zone engineering station against the target
        // device; `on_target` resolves both endpoints once so each arm is just
        // its synth call. The `c` (client/station) and `d` (device) endpoints are
        // (ip, mac) pairs.
        match ev.emit {
            EmitKind::S7Read => self.on_target(ledger, &ev.target, |dev, cip, cmac, dip, dmac| {
                let order = vuln
                    .by_model(&dev.model)
                    .and_then(|p| p.s7_order_number.clone())
                    .unwrap_or_else(|| dev.model.clone());
                let (maj, min) = parse_version(&dev.firmware);
                s7_szl::exchange(cmac, dmac, cip, dip, port, &order, maj, min)
            }),
            EmitKind::S7ProgramDownload => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    let block = ev
                        .block_id
                        .clone()
                        .unwrap_or_else(|| "_0800001P".to_string());
                    let payload =
                        payload_bytes(ev.payload_hex.as_deref(), b"\x70\x70\x01\x02\x03\x04");
                    s7_control::program_download(cmac, dmac, cip, dip, port, &block, &payload)
                })
            }
            EmitKind::S7Write => self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                s7_control::write_db_word(
                    cmac,
                    dmac,
                    cip,
                    dip,
                    port,
                    ev.db.unwrap_or(1),
                    ev.offset.unwrap_or(0),
                    ev.value.unwrap_or(0),
                )
            }),
            EmitKind::S7Stop => self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                s7_control::plc_stop(cmac, dmac, cip, dip, port)
            }),
            EmitKind::ModbusWrite => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    modbus_write::write_single_register(
                        cmac,
                        dmac,
                        cip,
                        dip,
                        port,
                        ev.unit.unwrap_or(1),
                        ev.register.unwrap_or(0),
                        ev.value.unwrap_or(0),
                    )
                })
            }
            EmitKind::TristationStatus => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    tristation::get_cp_status(cmac, dmac, cip, dip, port)
                })
            }
            EmitKind::TristationDownload => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    let payload =
                        payload_bytes(ev.payload_hex.as_deref(), b"imain.bin\x00inject.bin");
                    tristation::program_download(
                        cmac,
                        dmac,
                        cip,
                        dip,
                        port,
                        &payload,
                        ev.chunk.unwrap_or(8),
                    )
                })
            }
            EmitKind::Iec104Interrogation => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    iec104::interrogation(cmac, dmac, cip, dip, port, ev.common_addr.unwrap_or(1))
                })
            }
            EmitKind::Iec104Command => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    iec104::single_command(
                        cmac,
                        dmac,
                        cip,
                        dip,
                        port,
                        ev.common_addr.unwrap_or(1),
                        ev.ioa.unwrap_or(1),
                        ev.close.unwrap_or(false),
                    )
                })
            }
            EmitKind::Wiper => self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                let share = ev
                    .share
                    .clone()
                    .unwrap_or_else(|| format!("\\\\{dip}\\ADMIN$\\update.dll"));
                ioc::smb_share_write(cmac, dmac, cip, dip, port, &share)
            }),
            EmitKind::MoxaBrick => {
                self.on_target(ledger, &ev.target, |_d, cip, cmac, dip, dmac| {
                    let fw = payload_bytes(ev.payload_hex.as_deref(), b"\xde\xad\xbe\xef");
                    ioc::moxa_brick(cmac, dmac, cip, dip, port, &fw)
                })
            }
            EmitKind::RemoteAccess => {
                self.on_target(ledger, &ev.target, |dev, _cip, _cmac, hip, hmac| {
                    // External actor -> the host, forwarded by the zone gateway; the
                    // station source is unused here.
                    let gw = self.gateway_mac(ledger, &dev.subnet_cidr);
                    ioc::remote_access(
                        gw,
                        self.external_ip(),
                        hmac,
                        hip,
                        port,
                        ev.port.unwrap_or(5938),
                    )
                })
            }
            EmitKind::C2Beacon => {
                // The infected host is the target, else the first device.
                let host = resolve(ledger, &ev.target).or_else(|| ledger.devices.first());
                let Some(host) = host else { return Vec::new() };
                let Some((hip, hmac)) = endpoint(host) else {
                    return Vec::new();
                };
                let (rip, rmac) = self.resolver(ledger, &host.subnet_cidr);
                let gw = self.gateway_mac(ledger, &host.subnet_cidr);
                let c2 = C2Target {
                    domain: &self.c2_domain(ev),
                    ip: self.c2_ip(ev),
                    port: ev.port.unwrap_or(80),
                };
                ioc::c2_beacon(hmac, hip, rmac, rip, gw, &c2, port, nonce as u16)
            }
        }
    }

    /// Resolve the event's target, derive the engineering-station source and the
    /// device endpoint once, and run `f(dev, client_ip, client_mac, dev_ip,
    /// dev_mac)`. An unresolved target or unparseable endpoint yields no frames,
    /// so a misauthored playbook degrades rather than panics.
    fn on_target<F>(&self, ledger: &Session, t: &Option<DeviceRef>, f: F) -> Vec<Vec<u8>>
    where
        F: FnOnce(&DeviceRecord, Ipv4Addr, [u8; 6], Ipv4Addr, [u8; 6]) -> Vec<Vec<u8>>,
    {
        let Some(dev) = resolve(ledger, t) else {
            return Vec::new();
        };
        let Some((dip, dmac)) = endpoint(dev) else {
            return Vec::new();
        };
        let (cip, cmac) = self.station(dev);
        f(dev, cip, cmac, dip, dmac)
    }

    /// The zone engineering station that sources an OT action: `.250` with a
    /// seed-stable MAC, matching the identity burst's station so a sensor sees
    /// one consistent operator endpoint.
    fn station(&self, dev: &DeviceRecord) -> (Ipv4Addr, [u8; 6]) {
        let ip = roles::station_addr(&dev.subnet_cidr);
        (ip, l3::stable_mac(self.seed, u32::from(ip)))
    }

    /// The zone's DNS resolver (its firewall at `.1`), for a C2 lookup.
    fn resolver(&self, ledger: &Session, cidr: &str) -> (Ipv4Addr, [u8; 6]) {
        self.firewall(ledger, cidr).unwrap_or_else(|| {
            let ip = roles::firewall_addr(cidr);
            (ip, l3::stable_mac(self.seed, u32::from(ip)))
        })
    }

    /// The L2 next hop for routable (external/C2) traffic: the zone firewall's MAC.
    fn gateway_mac(&self, ledger: &Session, cidr: &str) -> [u8; 6] {
        self.firewall(ledger, cidr)
            .map(|(_, mac)| mac)
            .unwrap_or_else(|| l3::stable_mac(self.seed, u32::from(roles::firewall_addr(cidr))))
    }

    fn firewall(&self, ledger: &Session, cidr: &str) -> Option<(Ipv4Addr, [u8; 6])> {
        ledger
            .devices
            .iter()
            .find(|d| d.subnet_cidr == cidr && d.asset_type.as_deref() == Some("Firewall"))
            .and_then(endpoint)
    }

    fn c2_domain(&self, ev: &Event) -> String {
        if self.fidelity == IocFidelity::Standin {
            return "beacon.example".to_string();
        }
        ev.domain
            .clone()
            .or_else(|| self.c2_domains.first().cloned())
            .unwrap_or_else(|| "beacon.example".to_string())
    }

    fn c2_ip(&self, ev: &Event) -> Ipv4Addr {
        if self.fidelity == IocFidelity::Standin {
            return Ipv4Addr::new(203, 0, 113, 10);
        }
        ev.ip
            .as_deref()
            .and_then(|s| s.parse().ok())
            .or_else(|| self.c2_ips.first().and_then(|s| s.parse().ok()))
            .unwrap_or(Ipv4Addr::new(203, 0, 113, 10))
    }

    fn external_ip(&self) -> Ipv4Addr {
        if self.fidelity == IocFidelity::Standin {
            return Ipv4Addr::new(198, 51, 100, 10);
        }
        self.external_cidrs
            .first()
            .and_then(|c| first_host(c))
            .unwrap_or(Ipv4Addr::new(198, 51, 100, 10))
    }
}

/// First match wins, checked ip -> model -> asset_type.
fn resolve<'a>(ledger: &'a Session, t: &Option<DeviceRef>) -> Option<&'a DeviceRecord> {
    let t = t.as_ref()?;
    if let Some(ip) = &t.ip {
        if let Some(d) = ledger.devices.iter().find(|d| &d.ip == ip) {
            return Some(d);
        }
    }
    if let Some(m) = &t.model {
        if let Some(d) = ledger.devices.iter().find(|d| &d.model == m) {
            return Some(d);
        }
    }
    if let Some(at) = &t.asset_type {
        if let Some(d) = ledger
            .devices
            .iter()
            .find(|d| d.asset_type.as_deref() == Some(at.as_str()))
        {
            return Some(d);
        }
    }
    None
}

/// A device's (IP, MAC), or None if its ledger strings do not parse.
fn endpoint(dev: &DeviceRecord) -> Option<(Ipv4Addr, [u8; 6])> {
    Some((dev.ip.parse().ok()?, l3::parse_mac(&dev.mac)))
}

/// The .10 host of a CIDR, a believable external source within a documented range.
fn first_host(cidr: &str) -> Option<Ipv4Addr> {
    cidr.parse::<Ipv4Net>().ok().and_then(|n| n.hosts().nth(9))
}

/// Decode a hex string to bytes, falling back to `default` when absent or empty.
fn payload_bytes(hex: Option<&str>, default: &[u8]) -> Vec<u8> {
    let Some(h) = hex else {
        return default.to_vec();
    };
    let digits: Vec<u8> = h
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect();
    if digits.len() < 2 {
        return default.to_vec();
    }
    digits
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| c[0] << 4 | c[1])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{DeviceRecord, SubnetRecord};

    fn ledger_with_s7() -> Session {
        let mut s = Session::new(1337, 0);
        s.add_subnet(SubnetRecord {
            cidr: "10.20.10.0/24".into(),
            zone_name: "L1".into(),
            purdue_level: 1,
            vendor: Some("Siemens AG".into()),
            domain: None,
        });
        s.add_device(DeviceRecord {
            ip: "10.20.10.11".into(),
            mac: "00:0e:8c:11:22:33".into(),
            vendor: "Siemens AG".into(),
            model: "SIMATIC S7-300 CPU 315-2 PN/DP".into(),
            firmware: "V3.2.12".into(),
            protocol: "s7".into(),
            cves: vec!["CVE-2016-9159".into()],
            subnet_cidr: "10.20.10.0/24".into(),
            hostname: None,
            asset_type: Some("Controller".into()),
        });
        s.add_device(DeviceRecord {
            ip: "10.20.10.1".into(),
            mac: "00:09:0f:aa:bb:cc".into(),
            vendor: "Fortinet".into(),
            model: "FortiGate 100E".into(),
            firmware: "6.0.4".into(),
            protocol: "switch_snmp".into(),
            cves: vec![],
            subnet_cidr: "10.20.10.0/24".into(),
            hostname: None,
            asset_type: Some("Firewall".into()),
        });
        s
    }

    fn engine(yaml: &str) -> ScenarioEngine {
        ScenarioEngine {
            name: "test".into(),
            playbook: Playbook::parse(yaml).unwrap(),
            external_cidrs: vec!["198.51.100.0/24".into()],
            c2_domains: vec!["www.mypremierfutbol.com".into()],
            c2_ips: vec!["203.0.113.7".into()],
            fidelity: IocFidelity::Real,
            campaign: Campaign::Oneshot,
            max_frames_per_burst: 256,
            seed: 1337,
            phase_idx: 0,
            event_cursor: 0,
            bursts_in_phase: 0,
        }
    }

    #[test]
    fn renders_s7_write_against_the_pinned_cpu() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        let mut e = engine(
            "phases:\n  - id: sabotage\n    events:\n      - { emit: s7_write, target: { ip: 10.20.10.11 }, db: 1, offset: 0, value: 1410 }\n",
        );
        let frames = e.phase_frames(&led, &vuln, 0);
        assert!(!frames.is_empty(), "the write rendered frames");
        // The rogue value 1410 is on the wire, sourced from the .250 station.
        let value_present = frames.iter().any(|f| {
            let l = crate::proto::frame::parse_layout(f).unwrap();
            f[l.payload..l.end]
                .windows(2)
                .any(|w| w == 1410u16.to_be_bytes())
        });
        assert!(value_present, "rogue setpoint 1410 emitted");
    }

    #[test]
    fn timeline_advances_then_holds_on_oneshot() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        let mut e = engine(
            "phases:\n  - id: recon\n    dwell_runs: 2\n    events:\n      - { emit: s7_read, target: { ip: 10.20.10.11 } }\n  - id: impact\n    events:\n      - { emit: s7_stop, target: { ip: 10.20.10.11 } }\n",
        );
        assert_eq!(e.phase_id(), "recon");
        e.phase_frames(&led, &vuln, 0); // burst 1: events done, dwell 1/2
        assert_eq!(e.phase_id(), "recon", "dwell holds the phase");
        e.phase_frames(&led, &vuln, 1); // burst 2: dwell satisfied -> advance
        assert_eq!(e.phase_id(), "impact");
        e.phase_frames(&led, &vuln, 2); // impact emits, then holds (oneshot)
        assert_eq!(e.phase_id(), "impact", "oneshot holds the final phase");
        let frames = e.phase_frames(&led, &vuln, 3);
        assert!(!frames.is_empty(), "impact keeps emitting while held");
    }

    #[test]
    fn loop_campaign_wraps_to_the_first_phase() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        let mut e = engine(
            "phases:\n  - id: recon\n    events:\n      - { emit: s7_read, target: { ip: 10.20.10.11 } }\n  - id: impact\n    events:\n      - { emit: s7_stop, target: { ip: 10.20.10.11 } }\n",
        );
        e.campaign = Campaign::Loop;
        assert_eq!(e.phase_id(), "recon");
        e.phase_frames(&led, &vuln, 0); // recon spent -> advance
        assert_eq!(e.phase_id(), "impact");
        e.phase_frames(&led, &vuln, 1); // impact spent, last phase -> wrap
        assert_eq!(e.phase_id(), "recon", "loop wraps to the first phase");
    }

    #[test]
    fn long_event_sequence_splits_across_bursts_under_the_cap() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        // Three reads in one phase with a per-burst cap of 1: each event yields
        // several frames, so only one event is consumed per burst and the rest
        // spread across following bursts instead of one microburst.
        let mut e = engine(
            "phases:\n  - id: recon\n    events:\n      - { emit: s7_read, target: { ip: 10.20.10.11 } }\n      - { emit: s7_read, target: { ip: 10.20.10.11 } }\n      - { emit: s7_read, target: { ip: 10.20.10.11 } }\n",
        );
        e.max_frames_per_burst = 1;
        let b0 = e.phase_frames(&led, &vuln, 0);
        assert!(!b0.is_empty(), "the first event still emits");
        assert_eq!(e.event_cursor, 1, "only one event consumed under the cap");
        e.phase_frames(&led, &vuln, 1);
        assert_eq!(e.event_cursor, 2, "the next event lands on the next burst");
    }

    #[test]
    fn unresolved_target_is_skipped_not_panicked() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        let mut e = engine(
            "phases:\n  - id: x\n    events:\n      - { emit: s7_stop, target: { ip: 10.99.99.99 } }\n",
        );
        assert!(
            e.phase_frames(&led, &vuln, 0).is_empty(),
            "no frames, no panic"
        );
    }

    #[test]
    fn standin_fidelity_uses_documentation_c2() {
        let led = ledger_with_s7();
        let vuln = VulnDb::embedded().unwrap();
        let mut e = engine("phases:\n  - id: c2\n    events:\n      - { emit: c2_beacon }\n");
        e.fidelity = IocFidelity::Standin;
        let frames = e.phase_frames(&led, &vuln, 0);
        // No real domain leaks; the documentation stand-in is used instead.
        let leaked = frames.iter().any(|f| {
            let l = crate::proto::frame::parse_layout(f).unwrap();
            f[l.payload..l.end].windows(9).any(|w| w == b"futbol.co")
        });
        assert!(!leaked, "standin fidelity suppresses the real domain");
    }
}
