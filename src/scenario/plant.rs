//! Pinning a scenario's plant into a sealed ledger.
//!
//! The generic fabricator places vendors by RNG and cannot pin exact
//! models/IPs. A scenario instead declares its plant -- the real attack's
//! equipment -- and this builds a *sealed* [`Session`] from that spec, reusing
//! [`devices::assign_domains`] and [`devices::enrich_plant`] for the supporting
//! cast (firewall, HMI, EWS, DNS). Because the session is sealed, the existing
//! identity synthesis renders it verbatim, so no engine change is needed.
//!
//! A device may name a `model` present in the (overlaid) vuln DB, in which case
//! it inherits that profile's CVE-bearing identity and asserts it on the wire;
//! or it may be identity-only (a Triconex SIS, an IEC-104 RTU, a serial
//! converter) that the playbook drives but that carries no read-identity.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::Deserialize;

use crate::config::TargetCfg;
use crate::ledger::{DeviceRecord, Session, SubnetRecord};
use crate::oui::{self, OuiDb};
use crate::proto::l3;
use crate::simulate::devices;
use crate::vuln::{ProfileProto, VulnDb};

/// A scenario plant: zones, the devices pinned into them, the DNS domains, and
/// whether to layer the generic supporting cast on top.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantSpec {
    pub zones: Vec<ZoneSpec>,
    #[serde(default)]
    pub devices: Vec<DeviceSpec>,
    /// DNS domains for the plant. Empty falls back to the config's `dns.domains`.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Add each zone's bill of materials (firewall/HMI/EWS/historian) around the
    /// pinned devices. On by default; turn off for a fully explicit plant.
    #[serde(default = "default_true")]
    pub enrich: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneSpec {
    pub cidr: String,
    pub name: String,
    pub purdue_level: u8,
    #[serde(default)]
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSpec {
    /// Zone CIDR this device sits in (must match a declared zone).
    pub zone: String,
    /// Profile model to resolve from the vuln DB for CVE-bearing kit. When unset
    /// the device is identity-only (vendor/protocol below describe it).
    #[serde(default)]
    pub model: Option<String>,
    /// Explicit host IP; otherwise the next free address in the zone.
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    /// Asset class label, e.g. "Controller", "SIS", "RTU", "Converter", "HMI".
    #[serde(default)]
    pub asset_type: Option<String>,
    // Identity-only fields, used when `model` is unset.
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub firmware: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
}

fn default_true() -> bool {
    true
}

impl PlantSpec {
    /// Parse a plant spec from YAML text.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_norway::from_str(text).map_err(|e| format!("parsing plant spec: {e}"))
    }

    /// Read and parse a plant spec file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading plant {}: {e}", path.display()))?;
        Self::parse(&text)
    }
}

/// A believable, stable MAC for a pinned device: a vendor OUI (the profile's, the
/// spec vendor's via the OUI DB, or the IT pool) with per-IP low bytes -- the
/// same construction the bill of materials uses, so the plant reads consistently.
fn pinned_mac(
    oui_db: &OuiDb,
    vendor: &str,
    profile_oui: Option<[u8; 3]>,
    seed: u64,
    ip: Ipv4Addr,
) -> [u8; 6] {
    let salt = u64::from(u32::from(ip));
    let low = l3::stable_mac(seed, u32::from(ip));
    let prefix = profile_oui
        .or_else(|| oui_db.oui_for_vendor(vendor, salt))
        .unwrap_or_else(|| oui::it_pool_oui(salt));
    [prefix[0], prefix[1], prefix[2], low[3], low[4], low[5]]
}

/// The default asset label for a CVE profile's carrier protocol.
fn label_for_proto(p: ProfileProto) -> &'static str {
    if p == ProfileProto::SwitchSnmp {
        "Switch"
    } else {
        "Controller"
    }
}

/// Build a sealed ledger from a plant spec. `fallback_domains` (the config's
/// `dns.domains`) is used when the spec declares none. The result is sealed and
/// tagged with `scenario`, so the daemon replays it verbatim and the mismatch
/// guard keeps it apart from a generic ledger.
pub fn build_sealed_session(
    spec: &PlantSpec,
    vuln: &VulnDb,
    oui_db: &OuiDb,
    seed: u64,
    now_unix: u64,
    scenario: &str,
    fallback_domains: &[String],
) -> Result<Session, String> {
    let mut s = Session::new(seed, now_unix);

    for z in &spec.zones {
        let _: Ipv4Net = z
            .cidr
            .parse()
            .map_err(|_| format!("zone cidr {:?} is not a valid CIDR", z.cidr))?;
        let rec = SubnetRecord {
            cidr: z.cidr.clone(),
            zone_name: z.name.clone(),
            purdue_level: z.purdue_level,
            vendor: z.vendor.clone(),
            domain: None,
        };
        if !s.add_subnet(rec) {
            return Err(format!("could not add zone {} (duplicate or cap)", z.cidr));
        }
    }

    // Pin each device, tracking explicit hostnames to re-apply after enrich
    // (which would otherwise rename the named share).
    let mut explicit_names: Vec<(String, String)> = Vec::new();
    for d in &spec.devices {
        if !s.has_subnet(&d.zone) {
            return Err(format!("device references undeclared zone {}", d.zone));
        }
        let ip = match &d.ip {
            Some(ip) => ip
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("device ip {ip:?} is not valid"))?,
            None => {
                // Auto-assign the next free host, skipping network+1: enrich_plant
                // reserves that slot for the zone firewall/DNS resolver, so an
                // ip-less device must not land on it (the generic fabricator skips
                // it the same way). The zone was already validated as a CIDR when
                // its subnet was added, so this re-parse cannot realistically fail.
                let net: Ipv4Net = d
                    .zone
                    .parse()
                    .map_err(|_| format!("device zone {:?} is not a valid CIDR", d.zone))?;
                devices::next_free_in(net, &s.used_ips())
                    .ok_or_else(|| format!("zone {} is exhausted", d.zone))?
            }
        };

        // A model that resolves to a profile makes a CVE-bearing device that
        // asserts its identity on the wire; any other device (a descriptive
        // model, or none) is pinned identity-only -- it binds via ARP/DNS and is
        // driven by the playbook (a SIS, an RTU, an HMI, a serial converter). The
        // two cases differ only in where the identity fields come from.
        let profile = d.model.as_ref().and_then(|m| vuln.by_model(m).cloned());
        let (vendor, model, firmware, protocol, cves, oui, asset_type) = match &profile {
            Some(p) => (
                p.vendor.clone(),
                p.model.clone(),
                p.firmware.clone(),
                p.protocol.as_str().to_string(),
                p.cves.clone(),
                p.oui_prefix(),
                d.asset_type
                    .clone()
                    .unwrap_or_else(|| label_for_proto(p.protocol).to_string()),
            ),
            None => (
                d.vendor.clone().unwrap_or_default(),
                d.model
                    .clone()
                    .or_else(|| d.asset_type.clone())
                    .unwrap_or_else(|| "Device".to_string()),
                d.firmware.clone().unwrap_or_else(|| "1.0".to_string()),
                d.protocol.clone().unwrap_or_else(|| "none".to_string()),
                Vec::new(),
                None,
                d.asset_type
                    .clone()
                    .unwrap_or_else(|| "Controller".to_string()),
            ),
        };
        let rec = DeviceRecord {
            ip: ip.to_string(),
            mac: l3::fmt_mac(pinned_mac(oui_db, &vendor, oui, seed, ip)),
            vendor,
            model,
            firmware,
            protocol,
            cves,
            subnet_cidr: d.zone.clone(),
            hostname: d.hostname.clone(),
            asset_type: Some(asset_type),
        };
        if let Some(h) = &d.hostname {
            explicit_names.push((ip.to_string(), h.clone()));
        }
        if !s.add_device(rec) {
            return Err(format!("could not pin device at {ip} (device cap)"));
        }
    }

    let domains: Vec<String> = if spec.domains.is_empty() {
        fallback_domains.to_vec()
    } else {
        spec.domains.clone()
    };
    devices::assign_domains(&mut s, &domains, seed);
    if spec.enrich {
        devices::enrich_plant(&mut s, vuln, oui_db, seed);
    }
    // Re-assert spec-given hostnames, which enrich may have overwritten.
    for (ip, name) in explicit_names {
        if let Some(dev) = s.devices.iter_mut().find(|d| d.ip == ip) {
            dev.hostname = Some(name);
        }
    }

    s.sealed = true;
    s.target_devices = s.device_count();
    s.scenario = Some(scenario.to_string());
    Ok(s)
}

/// Load a scenario pack's plant spec and pin it into a sealed session. The single
/// path both `plan --scenario` and the daemon's first-run plant build go through.
pub fn pin_from_pack(
    target: &TargetCfg,
    vuln: &VulnDb,
    oui_db: &OuiDb,
    seed: u64,
    now_unix: u64,
    fallback_domains: &[String],
) -> Result<Session, String> {
    let spec = PlantSpec::load(&target.pack_dir.join(&target.plant))?;
    build_sealed_session(
        &spec,
        vuln,
        oui_db,
        seed,
        now_unix,
        &target.name,
        fallback_domains,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_yaml() -> &'static str {
        "zones:
  - { cidr: 10.20.10.0/24, name: 'Cascade Protection (L1)', purdue_level: 1, vendor: 'Siemens AG' }
devices:
  - { zone: 10.20.10.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.20.10.11, hostname: A87-CPU }
  - { zone: 10.20.10.0/24, asset_type: SIS, vendor: 'Schneider Electric', protocol: tristation, ip: 10.20.10.20 }
enrich: true
"
    }

    #[test]
    fn builds_a_sealed_scenario_ledger_with_pinned_kit() {
        let spec = PlantSpec::parse(spec_yaml()).expect("spec parses");
        let vuln = VulnDb::embedded().unwrap();
        let oui = OuiDb::embedded();
        let s = build_sealed_session(
            &spec,
            &vuln,
            &oui,
            1337,
            100,
            "stuxnet",
            &["plant.example".into()],
        )
        .expect("builds");

        assert!(s.is_sealed(), "scenario ledger is sealed");
        assert_eq!(s.scenario.as_deref(), Some("stuxnet"));
        // The S7-300 is pinned at its IP with the profile's CVE.
        let cpu = s
            .devices
            .iter()
            .find(|d| d.ip == "10.20.10.11")
            .expect("s7 pinned");
        assert_eq!(cpu.model, "SIMATIC S7-300 CPU 315-2 PN/DP");
        assert!(
            cpu.cves.iter().any(|c| c == "CVE-2016-9159"),
            "carries the CVE"
        );
        assert_eq!(
            cpu.hostname.as_deref(),
            Some("A87-CPU"),
            "explicit hostname kept"
        );
        // The identity-only SIS is pinned with no CVE.
        let sis = s
            .devices
            .iter()
            .find(|d| d.ip == "10.20.10.20")
            .expect("sis pinned");
        assert_eq!(sis.asset_type.as_deref(), Some("SIS"));
        assert!(sis.cves.is_empty(), "identity-only device has no CVE");
        // enrich added the zone's firewall at .1.
        assert!(
            s.devices
                .iter()
                .any(|d| d.ip == "10.20.10.1" && d.asset_type.as_deref() == Some("Firewall")),
            "enrich added the BOM firewall"
        );
    }

    #[test]
    fn unresolved_model_is_pinned_identity_only() {
        // A descriptive model that is not a CVE profile is fine: the device is
        // pinned identity-only (a SIS/RTU/HMI the playbook drives), keeping its
        // label, rather than being rejected.
        let yaml = "zones:\n  - { cidr: 10.0.0.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.0.0.0/24, model: 'Custom RTU 560', ip: 10.0.0.50, asset_type: RTU, protocol: iec104 }\nenrich: false\n";
        let spec = PlantSpec::parse(yaml).unwrap();
        let vuln = VulnDb::embedded().unwrap();
        let s = build_sealed_session(&spec, &vuln, &OuiDb::embedded(), 1, 0, "x", &[]).unwrap();
        let dev = s.devices.iter().find(|d| d.ip == "10.0.0.50").unwrap();
        assert_eq!(dev.model, "Custom RTU 560", "descriptive model kept");
        assert!(dev.cves.is_empty(), "an unresolved model is identity-only");
        assert_eq!(dev.asset_type.as_deref(), Some("RTU"));
    }

    #[test]
    fn auto_assigned_device_skips_the_firewall_slot() {
        // A device that omits `ip:` under enrich must not land on network+1 (.1),
        // which enrich reserves for the zone firewall and DNS resolver. Regression
        // for the auto-assign-vs-firewall collision: before the fix the device
        // took .1 and that zone lost its firewall.
        let yaml = "zones:\n  - { cidr: 10.20.10.0/24, name: Z, purdue_level: 1, vendor: 'Siemens AG' }\ndevices:\n  - { zone: 10.20.10.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP' }\nenrich: true\n";
        let spec = PlantSpec::parse(yaml).unwrap();
        let vuln = VulnDb::embedded().unwrap();
        let s = build_sealed_session(
            &spec,
            &vuln,
            &OuiDb::embedded(),
            1337,
            0,
            "x",
            &["plant.example".into()],
        )
        .unwrap();
        // The firewall still owns the gateway slot.
        let fw = s
            .devices
            .iter()
            .find(|d| d.ip == "10.20.10.1")
            .expect("enrich kept the firewall at .1");
        assert_eq!(fw.asset_type.as_deref(), Some("Firewall"));
        // The auto-assigned CPU sits elsewhere, not on the gateway slot.
        let cpu = s
            .devices
            .iter()
            .find(|d| d.model == "SIMATIC S7-300 CPU 315-2 PN/DP")
            .expect("cpu pinned");
        assert_ne!(
            cpu.ip, "10.20.10.1",
            "auto-assign skipped the firewall slot"
        );
    }
}
