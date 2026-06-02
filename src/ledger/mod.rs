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
use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

use ipnet::Ipv4Net;

/// No red-laser session ever fabricates more than this many subnet zones.
pub const MAX_SUBNETS: usize = 10;
/// No red-laser session ever fabricates more than this many devices.
pub const MAX_DEVICES: usize = 2000;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetRecord {
    pub cidr: String,
    pub zone_name: String,
    pub purdue_level: u8,
    #[serde(default)]
    pub vendor: Option<String>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedHost {
    pub original_ip: String,
    pub external_ip: String,
    pub mac: String,
    pub promoted_unix: u64,
}

impl Session {
    /// A fresh, empty session.
    pub fn new(seed: u64, now_unix: u64) -> Self {
        Self {
            schema: 1,
            created_unix: now_unix,
            seed,
            cycle: 0,
            subnets: Vec::new(),
            devices: Vec::new(),
            promoted: Vec::new(),
            last_threat_unix: None,
        }
    }

    /// Load the ledger if present. `Ok(None)` means no file yet (start fresh).
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| format!("parsing {}: {e}", path.display())),
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
        let tmp = path.with_extension("tmp");
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

    /// Every IP already assigned to a device, for uniqueness checks.
    pub fn used_ips(&self) -> HashSet<Ipv4Addr> {
        self.devices
            .iter()
            .filter_map(|d| d.ip.parse::<Ipv4Addr>().ok())
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
    /// subnet index and its CIDR and returns the new zone name.
    pub fn rename_zones_new_cycle<F>(&mut self, namer: F)
    where
        F: Fn(usize, &str) -> String,
    {
        self.cycle += 1;
        for (i, s) in self.subnets.iter_mut().enumerate() {
            s.zone_name = namer(i, &s.cidr);
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
        }
    }

    fn subnet(cidr: &str) -> SubnetRecord {
        SubnetRecord {
            cidr: cidr.into(),
            zone_name: "Zone".into(),
            purdue_level: 1,
            vendor: Some("Rockwell Automation".into()),
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
        s.rename_zones_new_cycle(|i, cidr| format!("cycle1-zone{i}-{cidr}"));
        assert_eq!(s.cycle, 1);
        assert_eq!(s.subnets[0].zone_name, "cycle1-zone0-10.1.0.0/24");
        assert_eq!(s.subnets[1].zone_name, "cycle1-zone1-10.2.0.0/24");
    }
}
