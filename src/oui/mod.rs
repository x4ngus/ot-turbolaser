//! Vendor identification from a MAC OUI.
//!
//! Maps the 24-bit OUI (the first three MAC octets) to a vendor name. A curated
//! ICS-vendor subset is embedded in the binary so the appliance stays
//! self-contained; an on-disk CSV at the configured path overrides it. Used by
//! green laser to name zones from real captures and by red laser to label
//! fabricated devices and harvest desktop OUIs for threat promotion.

use std::collections::HashMap;
use std::path::Path;

const EMBEDDED: &str = include_str!("../../data/oui.csv");

#[derive(Debug, Clone, Default)]
pub struct OuiDb {
    map: HashMap<[u8; 3], String>,
    by_vendor: HashMap<String, Vec<[u8; 3]>>,
}

/// Common IT/PC/server vendor OUIs for the generic hosts and workstations that
/// surround the control devices in an OT network. Real, globally-administered
/// prefixes; also present in the CSV so they resolve back to a vendor name.
const IT_POOL: [[u8; 3]; 7] = [
    [0x00, 0x14, 0x22], // Dell
    [0x00, 0x1F, 0x29], // HP
    [0x00, 0x1B, 0x21], // Intel
    [0x00, 0x50, 0x56], // VMware
    [0x00, 0xD0, 0xC9], // Advantech
    [0x00, 0x25, 0x90], // Super Micro
    [0x00, 0x21, 0xCC], // Lenovo
];

/// A deterministic IT-vendor OUI for a generic host, keyed by `salt` (its IP),
/// so background hosts read as believable PCs/servers rather than unknown OUIs.
pub fn it_pool_oui(salt: u64) -> [u8; 3] {
    IT_POOL[(salt as usize) % IT_POOL.len()]
}

impl OuiDb {
    /// Parse the embedded curated subset. Always succeeds.
    pub fn embedded() -> Self {
        Self::parse(EMBEDDED)
    }

    /// Load from an on-disk CSV if present, else fall back to the embedded set.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(_) => Self::embedded(),
        }
    }

    /// Vendor for a MAC, looked up by its OUI prefix.
    pub fn vendor(&self, mac: [u8; 6]) -> Option<&str> {
        self.map.get(&[mac[0], mac[1], mac[2]]).map(|s| s.as_str())
    }

    /// Vendor for a bare OUI prefix.
    pub fn vendor_of_prefix(&self, prefix: [u8; 3]) -> Option<&str> {
        self.map.get(&prefix).map(|s| s.as_str())
    }

    /// A representative OUI for a vendor name (exact match), used to stamp a real
    /// vendor prefix on a fabricated asset's MAC. When a vendor has several
    /// registered OUIs, `salt` (e.g. the asset's IP) picks one deterministically,
    /// so a vendor's assets spread across its real prefixes yet each is stable.
    pub fn oui_for_vendor(&self, vendor: &str, salt: u64) -> Option<[u8; 3]> {
        let prefixes = self.by_vendor.get(vendor)?;
        prefixes
            .get((salt as usize) % prefixes.len().max(1))
            .copied()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        let mut by_vendor: HashMap<String, Vec<[u8; 3]>> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((prefix, vendor)) = line.split_once(',') else {
                continue;
            };
            let vendor = vendor.trim();
            if vendor.is_empty() {
                continue;
            }
            if let Some(bytes) = parse_prefix(prefix.trim()) {
                map.insert(bytes, vendor.to_string());
                by_vendor.entry(vendor.to_string()).or_default().push(bytes);
            }
        }
        // Sort each vendor's prefixes so `oui_for_vendor` is deterministic
        // regardless of CSV order or hash iteration.
        for prefixes in by_vendor.values_mut() {
            prefixes.sort_unstable();
            prefixes.dedup();
        }
        Self { map, by_vendor }
    }
}

/// Parse "0000BC", "00:00:BC", or "00-00-BC" into three bytes.
fn parse_prefix(s: &str) -> Option<[u8; 3]> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 6 {
        return None;
    }
    Some([
        u8::from_str_radix(&cleaned[0..2], 16).ok()?,
        u8::from_str_radix(&cleaned[2..4], 16).ok()?,
        u8::from_str_radix(&cleaned[4..6], 16).ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_loads_known_vendors() {
        let db = OuiDb::embedded();
        assert!(!db.is_empty());
        // Rockwell/Allen-Bradley legacy prefix.
        assert_eq!(
            db.vendor([0x00, 0x00, 0xBC, 1, 2, 3]),
            Some("Rockwell Automation")
        );
        // Siemens.
        assert_eq!(db.vendor([0x00, 0x0E, 0x8C, 9, 9, 9]), Some("Siemens AG"));
    }

    #[test]
    fn unknown_prefix_is_none() {
        let db = OuiDb::embedded();
        assert_eq!(db.vendor([0xDE, 0xAD, 0xBE, 0, 0, 0]), None);
    }

    #[test]
    fn parses_separated_and_bare_prefixes() {
        assert_eq!(parse_prefix("00:00:BC"), Some([0, 0, 0xBC]));
        assert_eq!(parse_prefix("00-00-bc"), Some([0, 0, 0xBC]));
        assert_eq!(parse_prefix("0000BC"), Some([0, 0, 0xBC]));
        assert_eq!(parse_prefix("00:00"), None);
        assert_eq!(parse_prefix("zzzzzz"), None);
    }

    #[test]
    fn on_disk_missing_falls_back_to_embedded() {
        let db = OuiDb::load(Path::new("/nonexistent/oui.csv"));
        assert!(!db.is_empty());
    }

    #[test]
    fn oui_for_vendor_round_trips_and_is_deterministic() {
        let db = OuiDb::embedded();
        // ABB was the v0.3.0 gap; it must now resolve both ways.
        let abb = db.oui_for_vendor("ABB", 0).expect("ABB has an OUI");
        assert_eq!(db.vendor_of_prefix(abb), Some("ABB"));
        // A multi-OUI vendor: every pick still belongs to that vendor, and the
        // pick is stable for a given salt.
        for salt in 0..6u64 {
            let p = db.oui_for_vendor("Siemens AG", salt).unwrap();
            assert_eq!(db.vendor_of_prefix(p), Some("Siemens AG"));
        }
        assert_eq!(
            db.oui_for_vendor("Siemens AG", 7),
            db.oui_for_vendor("Siemens AG", 7)
        );
        assert!(db.oui_for_vendor("No Such Vendor", 0).is_none());
    }

    #[test]
    fn it_pool_is_global_and_resolvable() {
        let db = OuiDb::embedded();
        for salt in 0..14u64 {
            let oui = it_pool_oui(salt);
            assert_eq!(oui[0] & 0x02, 0, "IT OUI is globally administered");
            assert!(
                db.vendor_of_prefix(oui).is_some(),
                "IT-pool OUI {oui:?} resolves to a vendor"
            );
        }
    }
}
