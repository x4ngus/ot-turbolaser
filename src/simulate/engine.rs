//! The red-laser simulator engine.
//!
//! Holds the loaded session ledger and drives each iteration: fabricate a few
//! more devices (up to the caps), then render a rotating window of devices as
//! genuine protocol-assertion exchanges written to a tmpfs pcap the run loop
//! fires. The ledger persists on change so the world survives restarts.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::config::Config;
use crate::ledger::{self, DeviceRecord, Session};
use crate::pcapio;
use crate::synth::{self, cdp, enip_identity, lldp, modbus_devid, s7_szl, snmp};
use crate::vuln::{DeviceProfile, ProfileProto, VulnDb};

use super::devices::{self, AllocParams};

/// How many new devices to fabricate per iteration until the cap, so the asset
/// set grows gradually like real discovery rather than all at once.
const FABRICATE_BATCH: usize = 16;
/// How many devices to re-announce per iteration, cycling through the ledger, so
/// each identity pcap stays small.
const ANNOUNCE_WINDOW: usize = 256;
/// The fabricated engineering station that issues discovery queries.
const CLIENT_MAC: [u8; 6] = [0x00, 0x50, 0x56, 0x00, 0x00, 0x01];

pub struct SimulatorEngine {
    pub ledger: Session,
    ledger_path: PathBuf,
    shm_dir: PathBuf,
    vuln: VulnDb,
    params: AllocParams,
    identity_every: u64,
    synth_enabled: bool,
    device_identity: bool,
    switch_beacons: bool,
    sim_rng: ChaCha8Rng,
    announce_cursor: usize,
    dirty: bool,
}

impl SimulatorEngine {
    /// Construct from config, loading or creating the session ledger. The
    /// scenario RNG is seeded from the session seed so a run is reproducible.
    pub fn red(cfg: &Config, now_unix: u64) -> Self {
        let vuln = VulnDb::load(&cfg.oui_db.vuln_path);
        let session = Session::load(&cfg.session.path)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                Session::new(cfg.session.seed.unwrap_or_else(rand::random), now_unix)
            });
        let sim_rng = ChaCha8Rng::seed_from_u64(session.seed);
        Self {
            ledger_path: cfg.session.path.clone(),
            shm_dir: cfg.paths.shm_dir.clone(),
            vuln,
            params: AllocParams {
                max_subnets: ledger::effective_subnet_cap(cfg.zones.max_subnets),
                max_devices: ledger::effective_device_cap(cfg.synthesis.max_devices),
                default_prefix: cfg.zones.default_prefix,
            },
            identity_every: cfg.synthesis.identity_every_n_runs.max(1),
            synth_enabled: cfg.synthesis.enabled,
            device_identity: cfg.synthesis.device_identity,
            switch_beacons: cfg.synthesis.switch_beacons,
            sim_rng,
            announce_cursor: 0,
            dirty: false,
            ledger: session,
        }
    }

    pub fn ledger(&self) -> &Session {
        &self.ledger
    }

    /// The persisted session seed, logged so an entropy-seeded run can be pinned.
    pub fn seed(&self) -> u64 {
        self.ledger.seed
    }

    /// Persist the ledger if it changed since the last write.
    fn persist_if_dirty(&mut self) {
        if self.dirty {
            match self.ledger.save_atomic(&self.ledger_path) {
                Ok(()) => self.dirty = false,
                Err(e) => log::warn!("could not persist session ledger: {e}"),
            }
        }
    }

    /// One red-laser iteration: grow the device set within caps, then build the
    /// identity/beacon pcap for this round's announce window. Returns the tmpfs
    /// pcap to fire, or None when there is nothing to announce.
    pub fn red_tick(&mut self, run: u64) -> Option<PathBuf> {
        if !self.synth_enabled {
            return None;
        }
        if self.device_identity {
            let target =
                (self.ledger.device_count() + FABRICATE_BATCH).min(self.params.max_devices);
            if devices::fabricate(
                &mut self.ledger,
                &self.vuln,
                &self.params,
                target,
                &mut self.sim_rng,
            ) > 0
            {
                self.dirty = true;
            }
        }

        let frames = if run.is_multiple_of(self.identity_every) {
            self.build_assertions()
        } else {
            Vec::new()
        };
        self.persist_if_dirty();
        if frames.is_empty() {
            return None;
        }

        std::fs::create_dir_all(&self.shm_dir).ok()?;
        let out = self.shm_dir.join("synth-identity.pcap");
        match pcapio::write(&out, &synth::to_capture(frames)) {
            Ok(()) => Some(out),
            Err(e) => {
                log::warn!("could not write identity pcap: {e}");
                None
            }
        }
    }

    /// Render a rotating window of devices as protocol-assertion frames.
    fn build_assertions(&mut self) -> Vec<Vec<u8>> {
        let n = self.ledger.devices.len();
        if n == 0 || !self.device_identity {
            return Vec::new();
        }
        let switch_beacons = self.switch_beacons;
        let start = self.announce_cursor % n;
        let count = ANNOUNCE_WINDOW.min(n);
        let mut frames = Vec::new();
        for k in 0..count {
            let dev = &self.ledger.devices[(start + k) % n];
            if let Some(profile) = self.vuln.by_model(&dev.model) {
                frames.extend(assertions_for_device(dev, profile, switch_beacons));
            }
        }
        self.announce_cursor = (start + count) % n;
        frames
    }
}

/// The protocol-assertion frames for one device, keyed on its carrier protocol.
fn assertions_for_device(
    dev: &DeviceRecord,
    profile: &DeviceProfile,
    switch_beacons: bool,
) -> Vec<Vec<u8>> {
    let Ok(dev_ip) = dev.ip.parse::<Ipv4Addr>() else {
        return Vec::new();
    };
    let dev_mac = parse_mac(&dev.mac);
    let client_ip = client_addr(&dev.subnet_cidr);
    let client_port = 50000u16;

    match profile.protocol {
        ProfileProto::Enip => {
            let (major, minor) = parse_version(&dev.firmware);
            let id = enip_identity::EnipIdentity {
                vendor_id: profile.enip_vendor_id.unwrap_or(0),
                device_type: profile.enip_device_type.unwrap_or(0),
                product_code: profile.enip_product_code.unwrap_or(0),
                revision_major: major,
                revision_minor: minor,
                serial: u32::from(dev_ip),
                product_name: &dev.model,
            };
            let (a, b) =
                enip_identity::exchange(CLIENT_MAC, dev_mac, client_ip, dev_ip, client_port, &id);
            vec![a, b]
        }
        ProfileProto::Modbus => {
            let id = modbus_devid::ModbusDevId {
                vendor_name: &dev.vendor,
                product_code: &dev.model,
                revision: &dev.firmware,
            };
            let (a, b) =
                modbus_devid::exchange(CLIENT_MAC, dev_mac, client_ip, dev_ip, client_port, 1, &id);
            vec![a, b]
        }
        ProfileProto::S7 => {
            let (major, minor) = parse_version(&dev.firmware);
            let order = profile.s7_order_number.as_deref().unwrap_or(&dev.model);
            let (a, b) = s7_szl::exchange(
                CLIENT_MAC, dev_mac, client_ip, dev_ip, 2000, order, major, minor,
            );
            vec![a, b]
        }
        ProfileProto::SwitchSnmp => {
            let descr = profile
                .sys_descr
                .clone()
                .unwrap_or_else(|| format!("{} {}", dev.vendor, dev.model));
            let mut frames = Vec::new();
            if switch_beacons {
                frames.push(lldp::beacon(dev_mac, &dev.model, &descr));
                frames.push(cdp::beacon(dev_mac, &dev.model, &dev.firmware, &dev.model));
            }
            let (a, b) = snmp::exchange(
                CLIENT_MAC, dev_mac, client_ip, dev_ip, 43210, "public", 0x1234, &descr,
            );
            frames.push(a);
            frames.push(b);
            frames
        }
    }
}

fn parse_mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, part) in s.split(':').enumerate().take(6) {
        m[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    m
}

/// First two integer groups of a firmware string as a major/minor pair.
fn parse_version(fw: &str) -> (u8, u8) {
    let mut groups = fw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0).min(255) as u8);
    (groups.next().unwrap_or(0), groups.next().unwrap_or(0))
}

/// The engineering station address within a subnet (network + 250).
fn client_addr(subnet_cidr: &str) -> Ipv4Addr {
    subnet_cidr
        .parse::<Ipv4Net>()
        .ok()
        .map(|n| Ipv4Addr::from(u32::from(n.network()).wrapping_add(250)))
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 250))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(proto: &str, model: &str, fw: &str) -> DeviceRecord {
        DeviceRecord {
            ip: "10.20.0.5".into(),
            mac: "00:0e:8c:11:22:33".into(),
            vendor: "Siemens AG".into(),
            model: model.into(),
            firmware: fw.into(),
            protocol: proto.into(),
            cves: vec!["CVE-2020-15782".into()],
            subnet_cidr: "10.20.0.0/24".into(),
        }
    }

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("V4.2.1"), (4, 2));
        assert_eq!(parse_version("20.011"), (20, 11));
        assert_eq!(parse_version("07.0.02"), (7, 0));
        assert_eq!(parse_version("none"), (0, 0));
    }

    #[test]
    fn mac_and_client_addr() {
        assert_eq!(
            parse_mac("00:0e:8c:11:22:33"),
            [0x00, 0x0E, 0x8C, 0x11, 0x22, 0x33]
        );
        assert_eq!(client_addr("10.20.0.0/24"), Ipv4Addr::new(10, 20, 0, 250));
    }

    #[test]
    fn enip_device_yields_request_and_reply() {
        let vuln = VulnDb::embedded().unwrap();
        let p = vuln
            .profiles()
            .iter()
            .find(|p| p.protocol == ProfileProto::Enip)
            .unwrap();
        let d = dev("enip", &p.model, &p.firmware);
        let frames = assertions_for_device(&d, p, true);
        assert_eq!(frames.len(), 2, "request and reply");
        for f in &frames {
            assert!(crate::proto::frame::parse_layout(f).is_some());
        }
    }

    #[test]
    fn switch_device_emits_beacons_and_snmp() {
        let vuln = VulnDb::embedded().unwrap();
        let p = vuln
            .profiles()
            .iter()
            .find(|p| p.protocol == ProfileProto::SwitchSnmp)
            .unwrap();
        let d = dev("switch_snmp", &p.model, &p.firmware);
        assert_eq!(
            assertions_for_device(&d, p, true).len(),
            4,
            "lldp + cdp + snmp request/response"
        );
        assert_eq!(
            assertions_for_device(&d, p, false).len(),
            2,
            "beacons off leaves only the snmp exchange"
        );
    }
}
