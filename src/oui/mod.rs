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

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
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
            }
        }
        Self { map }
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
}
