//! Persistent red-laser session ledger.
//!
//! Tracks the fabricated world across daemon restarts: the named subnet zones,
//! the simulated devices and their assigned IP/MAC/CVE identities, and any hosts
//! promoted to external threat actors. It enforces the two hard caps and
//! preserves unique IP assignment. The file is the ground truth that `zones`,
//! `plan`, and `status` report. `reset` clears it for a fresh feed.
//!
//! Hard caps are constants here, not config: a config may lower them but never
//! raise them, so the guarantee holds even if a config is wrong.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use ipnet::Ipv4Net;

/// No red-laser session ever fabricates more than this many subnet zones. Raised
/// to 16 in v0.3.1 to fit L3 (DCS) operations zones above the 10 L1/L2 zones.
pub const MAX_SUBNETS: usize = 16;
/// No red-laser session ever fabricates more than this many devices.
pub const MAX_DEVICES: usize = 2000;

/// Current ledger schema version. Schema 3 (v0.2.2) added the capture-host
/// registry and the `max_assets` cap; schema 4 (v0.3.1) adds per-asset
/// `hostname` and `asset_type`, and (v0.3.2) the per-zone DNS `domain`. All
/// additive optional fields, so the schema number is unchanged. Older files load
/// via serde defaults; a newer file is refused on load rather than silently
/// misread.
pub const SCHEMA: u32 = 4;

/// Default total wire-asset cap (fabricated devices plus capture-derived assets)
/// when a config does not set one. Sized generously so a typical capture pool's
/// hosts all register as distinct assets and surplus force-mapping (riding an
/// existing device) is rarely reached.
pub const DEFAULT_MAX_ASSETS: usize = 512;

/// Resolve an effective cap from an optional config value: a config can lower a
/// hard cap but never exceed it.
pub fn effective_subnet_cap(configured: Option<usize>) -> usize {
    configured
        .map_or(MAX_SUBNETS, |c| c.min(MAX_SUBNETS))
        .max(1)
}

/// Resolve an effective device cap. See [`effective_subnet_cap`].
pub fn effective_device_cap(configured: Option<usize>) -> usize {
    configured
        .map_or(MAX_DEVICES, |c| c.min(MAX_DEVICES))
        .max(1)
}

/// Resolve the total wire-asset cap (fabricated devices plus capture-derived
/// assets): the config value clamped to the device hard cap, defaulting to
/// [`DEFAULT_MAX_ASSETS`]. Bounds the wire so it never exceeds the plan.
pub fn effective_asset_cap(configured: Option<usize>) -> usize {
    configured
        .map_or(DEFAULT_MAX_ASSETS, |c| c.min(MAX_DEVICES))
        .max(1)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub schema: u32,
    pub created_unix: u64,
    /// Seed that drives all fabrication choices, so a session reproduces.
    pub seed: u64,
    /// Increments each time subnets are reused with fresh zone names.
    #[serde(default)]
    pub cycle: u64,
    #[serde(default)]
    pub subnets: Vec<SubnetRecord>,
    #[serde(default)]
    pub devices: Vec<DeviceRecord>,
    #[serde(default)]
    pub promoted: Vec<PromotedHost>,
    #[serde(default)]
    pub last_threat_unix: Option<u64>,
    /// True when this ledger was committed by `turbolaser plan --commit`. The
    /// daemon replays it verbatim and does not fabricate past it.
    #[serde(default)]
    pub sealed: bool,
    /// Intended fabricated fleet size recorded at commit time. 0 on an
    /// unsealed or legacy (schema 1) ledger.
    #[serde(default)]
    pub target_devices: usize,
    /// Capture-derived assets: real replayed hosts registered as stable assets
    /// inside the planned zones, with their own stable MAC and IP. They fill
    /// spare zone capacity up to the asset cap; surplus capture hosts ride
    /// existing assets instead. Not CVE-bearing; identity is whatever their
    /// replayed traffic carries.
    #[serde(default)]
    pub capture_hosts: Vec<CaptureHostRecord>,
    /// Bumped whenever the capture-host registry grows, so a remap cached against
    /// an earlier registry state is recomputed rather than reused.
    #[serde(default)]
    pub registry_generation: u64,
    /// Total wire-asset cap recorded at commit (fabricated plus capture-derived).
    /// 0 on an unsealed or legacy ledger; resolved from config at runtime.
    #[serde(default)]
    pub max_assets: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetRecord {
    pub cidr: String,
    pub zone_name: String,
    pub purdue_level: u8,
    #[serde(default)]
    pub vendor: Option<String>,
    /// DNS domain this zone belongs to. Several zones share one value so the
    /// sensor correlates assets in different subnets as one site (a cross-zone
    /// network identity) from their shared FQDN suffix. `None` leaves hostnames
    /// single-label. Set at plan time by `assign_domains`.
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub model: String,
    pub firmware: String,
    pub protocol: String,
    pub cves: Vec<String>,
    pub subnet_cidr: String,
    /// DNS hostname the asset resolves to, e.g. "LINE-01-PLC". `None` for the
    /// ~10-20% of assets left unnamed. Bound to the IP by a synthesized A-record.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Coarse asset class for analysis ("Controller", "HMI", "EWS", "Historian",
    /// "Firewall", "Switch", "Server"). `None` on legacy records.
    #[serde(default)]
    pub asset_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedHost {
    pub original_ip: String,
    pub external_ip: String,
    pub mac: String,
    pub promoted_unix: u64,
}

/// A real host observed in a replayed capture, registered as a stable asset so
/// it keeps one IP and MAC across runs and is counted against the plan. Unlike a
/// `DeviceRecord` it carries no fabricated model/firmware/CVE: it is a genuine
/// replayed host, just relocated into a planned zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureHostRecord {
    /// The original capture IP this stable asset stands in for. The engine keys
    /// on it so a repeated capture (or another capture reusing the address) maps
    /// to the same asset every run.
    #[serde(default)]
    pub origin_ip: String,
    pub ip: String,
    pub mac: String,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub purdue_level: u8,
    pub subnet_cidr: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub asset_type: Option<String>,
}

impl Session {
    /// A fresh, empty session.
    pub fn new(seed: u64, now_unix: u64) -> Self {
        Self {
            schema: SCHEMA,
            created_unix: now_unix,
            seed,
            cycle: 0,
            subnets: Vec::new(),
            devices: Vec::new(),
            promoted: Vec::new(),
            last_threat_unix: None,
            sealed: false,
            target_devices: 0,
            capture_hosts: Vec::new(),
            registry_generation: 0,
            max_assets: 0,
        }
    }

    /// Load the ledger if present. `Ok(None)` means no file yet (start fresh).
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut s: Session = serde_json::from_str(&text)
                    .map_err(|e| format!("parsing {}: {e}", path.display()))?;
                if s.schema > SCHEMA {
                    return Err(format!(
                        "session {} has schema {} but this build supports up to {}; refusing to misread it",
                        path.display(),
                        s.schema,
                        SCHEMA
                    ));
                }
                if s.schema < SCHEMA {
                    log::info!(
                        "upgrading session ledger {} from schema {} to {SCHEMA}",
                        path.display(),
                        s.schema
                    );
                    s.schema = SCHEMA;
                }
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    /// Write atomically: temp file, fsync, rename. A reader never sees a
    /// half-written ledger. Mirrors the status heartbeat writer.
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        // Unique temp name per process so a concurrent writer (e.g. `plan
        // --commit` while a daemon is running) cannot clobber our in-flight
        // file before the atomic rename.
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| format!("create {}: {e}", tmp.display()))?;
            f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
            f.write_all(b"\n").map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
        Ok(())
    }

    /// Delete the ledger. Missing is success (already reset).
    pub fn reset(path: &Path) -> Result<(), String> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("removing {}: {e}", path.display())),
        }
    }

    pub fn subnet_count(&self) -> usize {
        self.subnets.len()
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn capture_host_count(&self) -> usize {
        self.capture_hosts.len()
    }

    /// Total distinct wire assets: fabricated devices plus capture-derived hosts.
    /// This is what the plan caps and what the sensor should inventory.
    pub fn total_wire_assets(&self) -> usize {
        self.devices.len() + self.capture_hosts.len()
    }

    /// Register a capture-derived host as a stable asset, deduping by IP and
    /// bounding the total wire-asset count at `cap`. Bumps the registry
    /// generation on a real add so a stale remap cache is invalidated. Returns
    /// false when the cap is reached or the IP is already registered.
    pub fn register_capture_host(&mut self, rec: CaptureHostRecord, cap: usize) -> bool {
        if self.total_wire_assets() >= cap {
            return false;
        }
        if self.capture_hosts.iter().any(|h| h.ip == rec.ip) {
            return false;
        }
        self.capture_hosts.push(rec);
        self.registry_generation += 1;
        true
    }

    /// Per-CIDR fabricated-device counts in one pass, so callers do not re-scan
    /// all devices for each zone. Shared by the status heartbeat and the zone
    /// renderers.
    pub fn device_counts_by_subnet(&self) -> HashMap<&str, usize> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for d in &self.devices {
            *counts.entry(d.subnet_cidr.as_str()).or_default() += 1;
        }
        counts
    }

    /// True when this ledger was committed by `plan --commit` and the daemon
    /// must replay it verbatim without fabricating more devices.
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    pub fn has_subnet(&self, cidr: &str) -> bool {
        self.subnets.iter().any(|s| s.cidr == cidr)
    }

    /// Add a subnet zone if under the hard cap. Returns false if the cap or a
    /// duplicate CIDR blocks it.
    pub fn add_subnet(&mut self, rec: SubnetRecord) -> bool {
        if self.subnets.len() >= MAX_SUBNETS || self.has_subnet(&rec.cidr) {
            return false;
        }
        self.subnets.push(rec);
        true
    }

    /// Add a device if under the hard cap. Returns false when the cap is hit,
    /// the signal to stop fabricating and only re-announce existing devices.
    pub fn add_device(&mut self, rec: DeviceRecord) -> bool {
        if self.devices.len() >= MAX_DEVICES {
            return false;
        }
        self.devices.push(rec);
        true
    }

    /// Every IP already assigned to a device or a registered capture host, for
    /// uniqueness checks. A new device or capture host never collides with one.
    pub fn used_ips(&self) -> HashSet<Ipv4Addr> {
        self.devices
            .iter()
            .map(|d| d.ip.as_str())
            .chain(self.capture_hosts.iter().map(|h| h.ip.as_str()))
            .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
            .collect()
    }

    /// The next unused host IP in `net`, or None if the subnet is exhausted.
    /// Uniqueness is global across the session, so a new device never collides
    /// with one assigned in an earlier cycle or before a restart.
    pub fn next_free_ip(&self, net: Ipv4Net) -> Option<Ipv4Addr> {
        let used = self.used_ips();
        net.hosts().find(|ip| !used.contains(ip))
    }

    /// Reuse the existing subnets under fresh zone names. Called on a cycle
    /// boundary once the subnet cap prevents new zones. `namer` receives the
    /// subnet index and its record (CIDR, vendor, level) and returns the new
    /// zone name. Names are computed first, then assigned, so the namer can read
    /// each record's fields.
    pub fn rename_zones_new_cycle<F>(&mut self, namer: F)
    where
        F: Fn(usize, &SubnetRecord) -> String,
    {
        self.cycle += 1;
        let names: Vec<String> = self
            .subnets
            .iter()
            .enumerate()
            .map(|(i, s)| namer(i, s))
            .collect();
        for (s, name) in self.subnets.iter_mut().zip(names) {
            s.zone_name = name;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dev(ip: &str, cidr: &str) -> DeviceRecord {
        DeviceRecord {
            ip: ip.into(),
            mac: "00:00:bc:00:00:01".into(),
            vendor: "Rockwell Automation".into(),
            model: "1756-L61".into(),
            firmware: "20.011".into(),
            protocol: "enip".into(),
            cves: vec!["CVE-2021-22681".into()],
            subnet_cidr: cidr.into(),
            hostname: None,
            asset_type: None,
        }
    }

    fn subnet(cidr: &str) -> SubnetRecord {
        SubnetRecord {
            cidr: cidr.into(),
            zone_name: "Zone".into(),
            purdue_level: 1,
            vendor: Some("Rockwell Automation".into()),
            ..Default::default()
        }
    }

    fn chost(ip: &str, cidr: &str) -> CaptureHostRecord {
        CaptureHostRecord {
            origin_ip: format!("172.16.0.{}", ip.rsplit('.').next().unwrap_or("1")),
            ip: ip.into(),
            mac: "02:00:00:11:22:33".into(),
            vendor: None,
            protocol: Some("modbus".into()),
            purdue_level: 1,
            subnet_cidr: cidr.into(),
            hostname: None,
            asset_type: None,
        }
    }

    #[test]
    fn device_cap_is_hard() {
        let mut s = Session::new(1, 0);
        for i in 0..MAX_DEVICES {
            assert!(s.add_device(dev(&format!("10.0.0.{}", i % 256), "10.0.0.0/24")));
        }
        assert_eq!(s.device_count(), MAX_DEVICES);
        assert!(!s.add_device(dev("10.9.9.9", "10.0.0.0/24")));
        assert_eq!(s.device_count(), MAX_DEVICES);
    }

    #[test]
    fn subnet_cap_is_hard_and_dedups() {
        let mut s = Session::new(1, 0);
        for i in 0..MAX_SUBNETS {
            assert!(s.add_subnet(subnet(&format!("10.{i}.0.0/24"))));
        }
        assert!(!s.add_subnet(subnet("10.99.0.0/24")));
        // Duplicate CIDR refused even under the cap.
        let mut s2 = Session::new(1, 0);
        assert!(s2.add_subnet(subnet("10.1.0.0/24")));
        assert!(!s2.add_subnet(subnet("10.1.0.0/24")));
    }

    #[test]
    fn next_free_ip_is_unique_and_exhausts() {
        let net = Ipv4Net::from_str("10.0.0.0/30").unwrap(); // 2 usable hosts
        let mut s = Session::new(1, 0);
        let a = s.next_free_ip(net).unwrap();
        s.add_device(dev(&a.to_string(), "10.0.0.0/30"));
        let b = s.next_free_ip(net).unwrap();
        assert_ne!(a, b);
        s.add_device(dev(&b.to_string(), "10.0.0.0/30"));
        assert_eq!(s.next_free_ip(net), None, "subnet exhausted");
    }

    #[test]
    fn save_load_roundtrip_preserves_uniqueness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let net = Ipv4Net::from_str("10.5.0.0/24").unwrap();
        let mut s = Session::new(0xABCD, 100);
        let ip = s.next_free_ip(net).unwrap();
        s.add_device(dev(&ip.to_string(), "10.5.0.0/24"));
        s.save_atomic(&path).unwrap();

        let loaded = Session::load(&path).unwrap().unwrap();
        assert_eq!(loaded.seed, 0xABCD);
        assert_eq!(loaded.device_count(), 1);
        // The assigned IP is still skipped after reload.
        assert!(loaded.used_ips().contains(&ip));
        assert_ne!(loaded.next_free_ip(net).unwrap(), ip);
    }

    #[test]
    fn load_missing_is_none_and_reset_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        assert!(Session::load(&path).unwrap().is_none());
        Session::reset(&path).unwrap(); // missing is fine
        Session::new(1, 0).save_atomic(&path).unwrap();
        assert!(Session::load(&path).unwrap().is_some());
        Session::reset(&path).unwrap();
        assert!(Session::load(&path).unwrap().is_none());
    }

    #[test]
    fn rename_cycle_bumps_and_renames() {
        let mut s = Session::new(1, 0);
        s.add_subnet(subnet("10.1.0.0/24"));
        s.add_subnet(subnet("10.2.0.0/24"));
        s.rename_zones_new_cycle(|i, rec| format!("cycle1-zone{i}-{}", rec.cidr));
        assert_eq!(s.cycle, 1);
        assert_eq!(s.subnets[0].zone_name, "cycle1-zone0-10.1.0.0/24");
        assert_eq!(s.subnets[1].zone_name, "cycle1-zone1-10.2.0.0/24");
    }

    #[test]
    fn new_session_is_current_schema_and_unsealed() {
        let s = Session::new(1, 0);
        assert_eq!(s.schema, SCHEMA);
        assert!(!s.is_sealed());
        assert_eq!(s.target_devices, 0);
    }

    #[test]
    fn schema_1_file_loads_with_seal_defaults_and_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        // A schema-1 ledger as v0.2.0 wrote it: no sealed/target_devices keys.
        let legacy = r#"{"schema":1,"created_unix":100,"seed":4660,"cycle":0,
            "subnets":[],"devices":[],"promoted":[],"last_threat_unix":null}"#;
        std::fs::write(&path, legacy).unwrap();
        let loaded = Session::load(&path).unwrap().unwrap();
        assert!(!loaded.sealed, "legacy ledger is unsealed");
        assert_eq!(loaded.target_devices, 0);
        assert_eq!(loaded.seed, 4660);
        assert_eq!(loaded.schema, SCHEMA, "schema upgraded on load");
    }

    #[test]
    fn newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let future =
            r#"{"schema":99,"created_unix":0,"seed":1,"subnets":[],"devices":[],"promoted":[]}"#;
        std::fs::write(&path, future).unwrap();
        assert!(Session::load(&path).is_err(), "a newer schema is refused");
    }

    #[test]
    fn sealed_roundtrips_through_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let mut s = Session::new(7, 0);
        s.sealed = true;
        s.target_devices = 64;
        s.save_atomic(&path).unwrap();
        let loaded = Session::load(&path).unwrap().unwrap();
        assert!(loaded.is_sealed());
        assert_eq!(loaded.target_devices, 64);
    }

    #[test]
    fn register_capture_host_dedups_and_honours_cap() {
        let mut s = Session::new(1, 0);
        // Cap of 2 total wire assets; one fabricated device already present.
        s.add_device(dev("10.0.0.5", "10.0.0.0/24"));
        assert!(s.register_capture_host(chost("10.0.0.6", "10.0.0.0/24"), 2));
        assert_eq!(s.total_wire_assets(), 2);
        let gen = s.registry_generation;
        // Cap reached: further registration refused, generation unchanged.
        assert!(!s.register_capture_host(chost("10.0.0.7", "10.0.0.0/24"), 2));
        assert_eq!(s.registry_generation, gen);
        // Dedup by IP even under a larger cap.
        assert!(!s.register_capture_host(chost("10.0.0.6", "10.0.0.0/24"), 10));
        assert_eq!(s.capture_host_count(), 1);
    }

    #[test]
    fn used_ips_unions_devices_and_capture_hosts() {
        let mut s = Session::new(1, 0);
        s.add_device(dev("10.0.0.5", "10.0.0.0/24"));
        s.register_capture_host(chost("10.0.0.6", "10.0.0.0/24"), 100);
        let used = s.used_ips();
        assert!(used.contains(&"10.0.0.5".parse().unwrap()));
        assert!(used.contains(&"10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn effective_asset_cap_defaults_and_clamps() {
        assert_eq!(effective_asset_cap(None), DEFAULT_MAX_ASSETS);
        assert_eq!(effective_asset_cap(Some(128)), 128);
        assert_eq!(effective_asset_cap(Some(99_999)), MAX_DEVICES);
        assert_eq!(effective_asset_cap(Some(0)), 1);
    }

    #[test]
    fn schema_2_loads_with_empty_registry_and_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        // A schema-2 ledger as v0.2.1 wrote it: sealed/target_devices, no registry.
        let legacy = r#"{"schema":2,"created_unix":100,"seed":4660,"cycle":0,
            "subnets":[],"devices":[],"promoted":[],"last_threat_unix":null,
            "sealed":true,"target_devices":64}"#;
        std::fs::write(&path, legacy).unwrap();
        let loaded = Session::load(&path).unwrap().unwrap();
        assert_eq!(loaded.schema, SCHEMA, "schema upgraded to current on load");
        assert!(loaded.capture_hosts.is_empty(), "registry defaults empty");
        assert_eq!(loaded.registry_generation, 0);
        assert_eq!(loaded.max_assets, 0, "legacy max_assets defaults to 0");
        assert!(loaded.sealed);
        assert_eq!(loaded.target_devices, 64);
    }

    #[test]
    fn schema_3_loads_with_default_hostname_and_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        // A schema-3 ledger as v0.3.0 wrote it: a device with no hostname/asset_type.
        let legacy = r#"{"schema":3,"created_unix":100,"seed":4660,"cycle":0,
            "subnets":[],"devices":[{"ip":"10.0.0.5","mac":"00:00:bc:00:00:01",
            "vendor":"Rockwell Automation","model":"1756-L61","firmware":"20.011",
            "protocol":"enip","cves":[],"subnet_cidr":"10.0.0.0/24"}],
            "promoted":[],"last_threat_unix":null,"sealed":true,"target_devices":1,
            "capture_hosts":[],"registry_generation":0,"max_assets":512}"#;
        std::fs::write(&path, legacy).unwrap();
        let loaded = Session::load(&path).unwrap().unwrap();
        assert_eq!(loaded.schema, SCHEMA, "schema upgraded to 4 on load");
        assert_eq!(loaded.device_count(), 1);
        assert_eq!(
            loaded.devices[0].hostname, None,
            "hostname defaults to None"
        );
        assert_eq!(
            loaded.devices[0].asset_type, None,
            "asset_type defaults to None"
        );
    }
}
