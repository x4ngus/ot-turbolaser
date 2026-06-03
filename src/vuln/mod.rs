//! Vulnerable device profiles: the CVE-bearing identities red laser fabricates.
//!
//! A profile pairs a real vendor/model/firmware with the CVE ids that firmware
//! is known vulnerable to, plus the protocol-specific identity fields a passive
//! sensor dissects. The synth builders render a profile into a genuine protocol
//! assertion (query and response, or SNMP fetch) so the sensor's CVE match rests
//! on a coherent transaction. A curated starter set is embedded; an on-disk TOML
//! at the configured path overrides it.

use serde::Deserialize;
use std::path::Path;

const EMBEDDED: &str = include_str!("../../data/vuln_profiles.toml");

/// Which protocol assertion carries this profile's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProto {
    Enip,
    Modbus,
    S7,
    SwitchSnmp,
}

impl ProfileProto {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileProto::Enip => "enip",
            ProfileProto::Modbus => "modbus",
            ProfileProto::S7 => "s7",
            ProfileProto::SwitchSnmp => "switch_snmp",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    pub vendor: String,
    pub model: String,
    pub firmware: String,
    pub protocol: ProfileProto,
    #[serde(default)]
    pub purdue_level: u8,
    /// Representative vendor OUI, e.g. "00:0E:8C". Low bytes are randomised per
    /// device so assets in a zone are distinct.
    #[serde(default)]
    pub oui: Option<String>,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub enip_vendor_id: Option<u16>,
    #[serde(default)]
    pub enip_device_type: Option<u16>,
    #[serde(default)]
    pub enip_product_code: Option<u16>,
    /// Exact CIP ProductName a sensor fingerprints, when it differs from
    /// `model` (e.g. "1756-L61/B LOGIX5561"). Falls back to `model`.
    #[serde(default)]
    pub enip_product_name: Option<String>,
    /// S7 module order number (MLFB) carried in the SZL module-identification
    /// response, e.g. "6ES7 212-1AE40-0XB0".
    #[serde(default)]
    pub s7_order_number: Option<String>,
    #[serde(default)]
    pub sys_descr: Option<String>,
    /// SNMP sysObjectID.0 (an enterprise OID like "1.3.6.1.4.1.8691.7.50") that
    /// passive sensors key CVE attribution on. Emitted alongside sysDescr.
    #[serde(default)]
    pub sys_object_id: Option<String>,
    /// Modbus device-identification object overrides (objects 0x00/0x01/0x02).
    /// Each falls back to vendor/model/firmware when unset.
    #[serde(default)]
    pub modbus_vendor_name: Option<String>,
    #[serde(default)]
    pub modbus_product_code: Option<String>,
    #[serde(default)]
    pub modbus_revision: Option<String>,
}

impl DeviceProfile {
    /// The OUI as three bytes, if set and well formed.
    pub fn oui_prefix(&self) -> Option<[u8; 3]> {
        let s = self.oui.as_deref()?;
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
}

#[derive(Debug, Clone, Deserialize)]
struct ProfileFile {
    #[serde(default)]
    profile: Vec<DeviceProfile>,
}

#[derive(Debug, Clone, Default)]
pub struct VulnDb {
    profiles: Vec<DeviceProfile>,
}

impl VulnDb {
    /// Parse the embedded curated set. Errors only if the bundled file is
    /// malformed, which a unit test guards against.
    pub fn embedded() -> Result<Self, String> {
        Self::parse(EMBEDDED)
    }

    /// Load an on-disk TOML if present and valid, else fall back to embedded.
    pub fn load(path: &Path) -> Self {
        let from_disk = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| Self::parse(&t).ok());
        from_disk
            .or_else(|| Self::embedded().ok())
            .unwrap_or_default()
    }

    fn parse(text: &str) -> Result<Self, String> {
        let f: ProfileFile = toml::from_str(text).map_err(|e| e.to_string())?;
        Ok(Self {
            profiles: f.profile,
        })
    }

    pub fn profiles(&self) -> &[DeviceProfile] {
        &self.profiles
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Profiles whose identity is carried by a given protocol assertion.
    pub fn by_protocol(&self, p: ProfileProto) -> impl Iterator<Item = &DeviceProfile> {
        self.profiles.iter().filter(move |d| d.protocol == p)
    }

    /// Pick a profile by index, wrapping. Callers drive `n` from the seeded
    /// session RNG so selection is reproducible.
    pub fn pick(&self, n: usize) -> Option<&DeviceProfile> {
        if self.profiles.is_empty() {
            None
        } else {
            self.profiles.get(n % self.profiles.len())
        }
    }

    /// The profile for a given model, to recover encoding fields from a ledger
    /// device record when re-announcing it.
    pub fn by_model(&self, model: &str) -> Option<&DeviceProfile> {
        self.profiles.iter().find(|p| p.model == model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_parses_and_is_well_formed() {
        let db = VulnDb::embedded().expect("bundled vuln_profiles.toml must parse");
        assert!(db.len() >= 8, "expected a curated starter set");
        for p in db.profiles() {
            assert!(!p.vendor.is_empty());
            assert!(!p.model.is_empty());
            assert!(!p.firmware.is_empty());
            assert!(!p.cves.is_empty(), "{} has no CVE", p.model);
            for c in &p.cves {
                assert!(c.starts_with("CVE-"), "malformed CVE id {c}");
            }
        }
    }

    #[test]
    fn known_profiles_present() {
        let db = VulnDb::embedded().unwrap();
        let has = |cve: &str| {
            db.profiles()
                .iter()
                .any(|p| p.cves.iter().any(|c| c == cve))
        };
        assert!(has("CVE-2020-15782"), "Siemens S7-1200");
        assert!(has("CVE-2021-22681"), "Rockwell Logix");
        assert!(has("CVE-2018-7811"), "Schneider M340");
    }

    #[test]
    fn protocol_filter_and_oui_parse() {
        let db = VulnDb::embedded().unwrap();
        assert!(db.by_protocol(ProfileProto::S7).count() >= 1);
        assert!(db.by_protocol(ProfileProto::SwitchSnmp).count() >= 2);
        let s7 = db.by_protocol(ProfileProto::S7).next().unwrap();
        assert_eq!(s7.oui_prefix(), Some([0x00, 0x0E, 0x8C]));
    }

    #[test]
    fn pick_wraps_and_load_falls_back() {
        let db = VulnDb::embedded().unwrap();
        let n = db.len();
        assert_eq!(
            db.pick(0).unwrap().model,
            db.pick(n).unwrap().model,
            "pick wraps"
        );
        // Missing file falls back to embedded.
        let fb = VulnDb::load(Path::new("/nonexistent/vuln_profiles.toml"));
        assert_eq!(fb.len(), n);
    }
}
