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
            AssetType::Hmi => "HMI",
            AssetType::EngWorkstation => "EWS",
            AssetType::Historian => "HIST",
            AssetType::Firewall => "FW",
            AssetType::Server => "SRV",
        }
    }

    /// CVE-bearing by construction? Only controllers and switches carry CVEs in
    /// v0.3.1, so the vulnerable share stays ~the fabricated controller fleet.
    /// (Flipping a class to CVE-bearing later is a one-line change here.)
    pub fn cve_bearing(self) -> bool {
        matches!(self, AssetType::Controller | AssetType::Switch)
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
        // L3 (operations / DCS): mostly servers + operator stations.
        3 => vec![
            (AssetType::Firewall, 1),
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
/// No domain suffix yet (the FQDN domain is a future attribute). 1-based indices.
pub fn hostname_for(
    vendor: Option<&str>,
    asset_type: AssetType,
    area_idx: usize,
    dev_idx: usize,
) -> String {
    let area = area_idx + 1;
    let dev = dev_idx + 1;
    match asset_type {
        AssetType::Controller => {
            let (prefix, token) = vendor_style(vendor);
            format!("{prefix}-{area:02}-{token}-{dev:02}")
        }
        // One firewall and historian per zone read cleaner without a device index.
        AssetType::Firewall => format!("FW-{area:02}"),
        AssetType::Historian => format!("HIST-{area:02}"),
        other => format!("{}-{area:02}-{dev:02}", other.host_token()),
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
    fn only_controllers_and_switches_are_cve_bearing() {
        assert!(AssetType::Controller.cve_bearing());
        assert!(AssetType::Switch.cve_bearing());
        for t in [
            AssetType::Hmi,
            AssetType::EngWorkstation,
            AssetType::Historian,
            AssetType::Firewall,
            AssetType::Server,
        ] {
            assert!(!t.cve_bearing(), "{} is identity-only", t.label());
        }
    }

    #[test]
    fn hostnames_follow_vendor_conventions() {
        let rk = hostname_for(Some("Rockwell Automation"), AssetType::Controller, 0, 1);
        assert_eq!(rk, "LINE-01-PLC-02");
        let sm = hostname_for(Some("Siemens AG"), AssetType::Controller, 2, 0);
        assert_eq!(sm, "CELL-03-S7-01");
        assert_eq!(hostname_for(None, AssetType::Firewall, 3, 0), "FW-04");
        assert_eq!(hostname_for(None, AssetType::Historian, 1, 0), "HIST-02");
        assert_eq!(hostname_for(None, AssetType::Hmi, 0, 0), "HMI-01-01");
        assert_eq!(hostname_for(None, AssetType::Server, 4, 2), "SRV-05-03");
    }

    #[test]
    fn hostnames_are_deterministic() {
        let a = hostname_for(Some("ABB"), AssetType::Controller, 1, 1);
        let b = hostname_for(Some("ABB"), AssetType::Controller, 1, 1);
        assert_eq!(a, b);
        assert_eq!(a, "LINE-02-AC500-02");
    }
}
