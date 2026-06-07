//! Per-zone bill of materials and recognisable OT hostnames.
//!
//! A real control zone is more than its PLCs: it carries a managed switch, an
//! operator HMI, an engineering workstation, and a zone-edge firewall; an
//! operations (Purdue L3 / DCS) zone is mostly servers and operator stations.
//! This module names those asset classes, the believable mix per Purdue level,
//! and the area-line-device hostnames an OT engineer recognises. It is pure (no
//! I/O, no RNG) so the fabrication and the unit tests share one source of truth.

/// A coarse asset class, stored on the ledger record and shown in analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    Controller,
    Switch,
    Router,
    Hmi,
    EngWorkstation,
    Historian,
    Firewall,
    Server,
}

impl AssetType {
    /// Stable label persisted on the ledger record (`DeviceRecord.asset_type`).
    pub fn label(self) -> &'static str {
        match self {
            AssetType::Controller => "Controller",
            AssetType::Switch => "Switch",
            AssetType::Router => "Router",
            AssetType::Hmi => "HMI",
            AssetType::EngWorkstation => "EWS",
            AssetType::Historian => "Historian",
            AssetType::Firewall => "Firewall",
            AssetType::Server => "Server",
        }
    }

    /// Short token used inside a hostname.
    pub fn host_token(self) -> &'static str {
        match self {
            AssetType::Controller => "PLC",
            AssetType::Switch => "SW",
            AssetType::Router => "RTR",
            AssetType::Hmi => "HMI",
            AssetType::EngWorkstation => "EWS",
            AssetType::Historian => "HIST",
            AssetType::Firewall => "FW",
            AssetType::Server => "SRV",
        }
    }

    /// CVE-bearing by construction? Controllers and switches carry CVEs from the
    /// fabricated core; the zone-edge firewall and router carry them too (v0.3.2)
    /// via an SNMP profile with an explicit firmware OID. HMIs, workstations,
    /// historians, and servers stay identity-only.
    pub fn cve_bearing(self) -> bool {
        matches!(
            self,
            AssetType::Controller | AssetType::Switch | AssetType::Router | AssetType::Firewall
        )
    }
}

/// One line of a zone's bill of materials: a class and how many of it.
pub type BomEntry = (AssetType, usize);

/// The non-controller core a zone should carry, by Purdue level. L1/L2 control
/// zones get a switch + HMI + engineering workstation + a zone-edge firewall
/// (L2 also a historian); L3 operations zones are server-heavy (a DCS: OPC /
/// domain / application servers and operator workstations behind a firewall).
/// Controllers are fabricated separately to hit the planned fleet size, so they
/// are not listed here.
pub fn bom_for(purdue_level: u8) -> Vec<BomEntry> {
    match purdue_level {
        1 => vec![
            (AssetType::Firewall, 1),
            (AssetType::Switch, 1),
            (AssetType::Hmi, 1),
            (AssetType::EngWorkstation, 1),
        ],
        2 => vec![
            (AssetType::Firewall, 1),
            (AssetType::Switch, 1),
            (AssetType::Hmi, 1),
            (AssetType::EngWorkstation, 1),
            (AssetType::Historian, 1),
        ],
        // L3 (operations / DCS): mostly servers + operator stations, with a
        // zone-edge router to the levels below it.
        3 => vec![
            (AssetType::Firewall, 1),
            (AssetType::Router, 1),
            (AssetType::Switch, 1),
            (AssetType::Historian, 1),
            (AssetType::Server, 4),
            (AssetType::EngWorkstation, 2),
        ],
        _ => vec![(AssetType::Firewall, 1)],
    }
}

/// The per-vendor area prefix and controller token, so a controller name reads
/// the way that vendor's installs usually do.
fn vendor_style(vendor: Option<&str>) -> (&'static str, &'static str) {
    match vendor.unwrap_or("") {
        v if v.contains("Rockwell") => ("LINE", "PLC"),
        v if v.contains("Siemens") => ("CELL", "S7"),
        v if v.contains("Schneider") => ("LINE", "M340"),
        v if v.contains("GE") => ("LINE", "RX3i"),
        v if v.contains("ABB") => ("LINE", "AC500"),
        _ => ("LINE", "PLC"),
    }
}

/// A recognisable, deterministic OT hostname: `<AREA>-<nn>-<TOKEN>-<nn>` for a
/// controller (e.g. `LINE-01-PLC-02`, `CELL-03-S7-01`), or `<TOKEN>-<nn>-<nn>`
/// for infrastructure and servers (`HMI-01-01`, `FW-04`, `HIST-02`, `SRV-05-03`).
/// When `domain` is set the name is a fully-qualified `<host>.<domain>` (e.g.
/// `LINE-01-PLC-02.plant.corp.example`); several zones share one domain so the
/// sensor reads a cross-zone site identity from the suffix. 1-based indices.
pub fn hostname_for(
    vendor: Option<&str>,
    asset_type: AssetType,
    area_idx: usize,
    dev_idx: usize,
    domain: Option<&str>,
) -> String {
    let area = area_idx + 1;
    let dev = dev_idx + 1;
    let host = match asset_type {
        AssetType::Controller => {
            let (prefix, token) = vendor_style(vendor);
            format!("{prefix}-{area:02}-{token}-{dev:02}")
        }
        // One firewall and historian per zone read cleaner without a device index.
        AssetType::Firewall => format!("FW-{area:02}"),
        AssetType::Historian => format!("HIST-{area:02}"),
        other => format!("{}-{area:02}-{dev:02}", other.host_token()),
    };
    match domain {
        Some(d) if !d.is_empty() => format!("{host}.{d}"),
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_have_a_firewall_and_expected_shape() {
        for lvl in [1u8, 2, 3] {
            let bom = bom_for(lvl);
            assert!(
                bom.iter()
                    .any(|(t, n)| *t == AssetType::Firewall && *n >= 1),
                "level {lvl} has a zone-edge firewall"
            );
        }
        // L3 is server-heavy; L1/L2 are not.
        let servers = |lvl| {
            bom_for(lvl)
                .iter()
                .find(|(t, _)| *t == AssetType::Server)
                .map(|(_, n)| *n)
                .unwrap_or(0)
        };
        assert!(servers(3) >= 4, "L3 DCS is server-heavy");
        assert_eq!(servers(1), 0, "L1 has no servers");
    }

    #[test]
    fn infrastructure_is_cve_bearing_hosts_are_not() {
        for t in [
            AssetType::Controller,
            AssetType::Switch,
            AssetType::Router,
            AssetType::Firewall,
        ] {
            assert!(t.cve_bearing(), "{} carries CVEs", t.label());
        }
        for t in [
            AssetType::Hmi,
            AssetType::EngWorkstation,
            AssetType::Historian,
            AssetType::Server,
        ] {
            assert!(!t.cve_bearing(), "{} is identity-only", t.label());
        }
    }

    #[test]
    fn hostnames_follow_vendor_conventions() {
        let rk = hostname_for(
            Some("Rockwell Automation"),
            AssetType::Controller,
            0,
            1,
            None,
        );
        assert_eq!(rk, "LINE-01-PLC-02");
        let sm = hostname_for(Some("Siemens AG"), AssetType::Controller, 2, 0, None);
        assert_eq!(sm, "CELL-03-S7-01");
        assert_eq!(hostname_for(None, AssetType::Firewall, 3, 0, None), "FW-04");
        assert_eq!(
            hostname_for(None, AssetType::Historian, 1, 0, None),
            "HIST-02"
        );
        assert_eq!(hostname_for(None, AssetType::Hmi, 0, 0, None), "HMI-01-01");
        assert_eq!(
            hostname_for(None, AssetType::Server, 4, 2, None),
            "SRV-05-03"
        );
    }

    #[test]
    fn a_domain_makes_the_name_an_fqdn() {
        let fqdn = hostname_for(
            Some("Rockwell Automation"),
            AssetType::Controller,
            0,
            1,
            Some("plant.corp.example"),
        );
        assert_eq!(fqdn, "LINE-01-PLC-02.plant.corp.example");
        // An empty domain is treated as no domain (single-label).
        assert_eq!(
            hostname_for(None, AssetType::Firewall, 3, 0, Some("")),
            "FW-04"
        );
    }

    #[test]
    fn hostnames_are_deterministic() {
        let a = hostname_for(Some("ABB"), AssetType::Controller, 1, 1, None);
        let b = hostname_for(Some("ABB"), AssetType::Controller, 1, 1, None);
        assert_eq!(a, b);
        assert_eq!(a, "LINE-02-AC500-02");
    }
}
