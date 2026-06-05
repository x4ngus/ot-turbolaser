//! Replay configuration: the schema everything else keys off.
//!
//! Rate and gap use a flat shape (a `kind` enum plus optional parameter
//! fields) rather than serde's internally tagged enums, which parse
//! inconsistently across YAML libraries. Semantic checks live in
//! [`Config::validate`], so a config that parses is also coherent.

use ipnet::Ipv4Net;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Replay NIC on the isolated bridge. Also the mirror source port.
    pub iface: String,
    #[serde(default)]
    pub mode: Mode,
    /// Green-laser master seed. Ignored in red laser, which uses entropy.
    #[serde(default)]
    pub seed: Option<u64>,
    pub paths: Paths,
    #[serde(default)]
    pub l3: L3Cfg,
    pub rate: RateCfg,
    pub gap: GapCfg,
    #[serde(default)]
    pub weights: Weights,
    #[serde(default)]
    pub watchdog: Watchdog,
    #[serde(default)]
    pub net: NetCfg,
    #[serde(default = "default_no_pcaps_retry")]
    pub no_pcaps_retry_secs: u64,
    // v0.2 red/green laser content layer. All optional so existing configs and
    // green laser are unaffected.
    #[serde(default)]
    pub zones: ZonesCfg,
    #[serde(default)]
    pub synthesis: SynthesisCfg,
    #[serde(default)]
    pub threats: ThreatsCfg,
    #[serde(default)]
    pub session: SessionCfg,
    #[serde(default)]
    pub oui_db: OuiDbCfg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum Mode {
    #[default]
    #[serde(rename = "red_laser", alias = "variety", alias = "red")]
    RedLaser,
    #[serde(rename = "green_laser", alias = "baseline", alias = "green")]
    GreenLaser,
}

impl Mode {
    /// Canonical config and status string for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::RedLaser => "red_laser",
            Mode::GreenLaser => "green_laser",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    pub pool: PathBuf,
    pub variants: PathBuf,
    pub shm_dir: PathBuf,
    pub status_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L3Cfg {
    /// Apply the coherent L3 remap per run in red-laser mode.
    #[serde(default = "default_true")]
    pub remap: bool,
    /// Rewrite Ethernet and ARP MAC addresses alongside IPv4 so each remapped
    /// host has a stable, coherent MAC<->IP binding the sensor fuses into one
    /// asset. On by default; only the red-laser remap honours it.
    #[serde(default = "default_true")]
    pub remap_mac: bool,
    /// Deprecated and unused as of v0.2.1: the in-process remap is mandatory in
    /// red laser, and a capture that cannot be remapped is skipped, never
    /// replayed raw. Retained so existing configs still parse; to be removed.
    #[serde(default)]
    pub fallback: L3Fallback,
    /// Optional CIDR hints for grouping hosts into subnets.
    #[serde(default)]
    pub subnets: Vec<String>,
    /// How replayed pcap hosts are mapped onto the fabricated zones: by vendor
    /// and/or protocol affinity, or `off` for size-ordered placement only.
    #[serde(default)]
    pub zone_affinity: ZoneAffinity,
    /// Hard ceiling on capture size to remap. A larger capture is skipped, never
    /// replayed raw. Default 2 GiB.
    #[serde(default = "default_max_remap_bytes")]
    pub max_remap_bytes: u64,
    /// What to do with a capture over the tmpfs budget but under
    /// `max_remap_bytes`: remap it to a disk temp dir, or skip it.
    #[serde(default)]
    pub on_oversize: OversizePolicy,
    /// Backstop: when the remap is off, refuse to send a capture that still
    /// carries a public (non-RFC1918) source address. On by default.
    #[serde(default = "default_true")]
    pub guard_public_sources: bool,
    /// Drop any frame whose on-wire length exceeds this before replay. An
    /// oversized capture frame (a TSO/GSO segment captured before NIC
    /// segmentation) otherwise makes tcpreplay abort the whole run with EMSGSIZE.
    /// Default 1514 (standard Ethernet); raise to ~9014 only on a jumbo bridge.
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    /// Replay the capture's own broadcast ARP. Off by default: the synth burst
    /// supplies controlled, rotating MAC<->IP bindings, so replaying a capture's
    /// ARP on top only floods a passive sensor (ARP was over 90% of frames in the
    /// field). Turn on only to study raw ARP behaviour.
    #[serde(default)]
    pub replay_capture_arp: bool,
}

impl Default for L3Cfg {
    fn default() -> Self {
        Self {
            remap: true,
            remap_mac: true,
            fallback: L3Fallback::default(),
            subnets: Vec::new(),
            zone_affinity: ZoneAffinity::default(),
            max_remap_bytes: default_max_remap_bytes(),
            on_oversize: OversizePolicy::default(),
            guard_public_sources: true,
            max_frame_bytes: default_max_frame_bytes(),
            replay_capture_arp: false,
        }
    }
}

/// What the remap does with a capture too large for the tmpfs budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OversizePolicy {
    /// Remap to a disk temp dir beside the source capture (default).
    #[default]
    RemapToDisk,
    /// Skip the capture entirely.
    Skip,
}

/// How the red-laser remap places a replayed capture's hosts into the
/// fabricated ledger zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ZoneAffinity {
    /// Vendor first, then protocol, then Purdue level, then size.
    #[default]
    Both,
    /// Vendor match only, else size-ordered.
    Vendor,
    /// Protocol match only, else size-ordered.
    Protocol,
    /// Size-ordered placement, ignore vendor/protocol.
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum L3Fallback {
    #[default]
    None,
    Tcprewrite,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCfg {
    pub model: RateModel,
    pub multiplier: Option<f64>,
    pub pps: Option<f64>,
    pub pps_multi: Option<u32>,
    pub mbps: Option<f64>,
    /// Per-run fixed Mbps band. With `model: mbps`, when both bounds are set each
    /// run draws one fixed rate uniformly in [mbps_min, mbps_max]: the wire holds
    /// a steady rate within a run and fluctuates run to run, matching a busy
    /// operational link. Takes precedence over a bare `mbps`.
    pub mbps_min: Option<f64>,
    pub mbps_max: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RateModel {
    #[default]
    Original,
    Multiplier,
    Pps,
    Mbps,
    Topspeed,
}

impl RateCfg {
    pub fn validate(&self) -> Result<(), String> {
        match self.model {
            RateModel::Original | RateModel::Topspeed => Ok(()),
            RateModel::Multiplier => require_positive("rate.multiplier", self.multiplier).map(drop),
            RateModel::Pps => require_positive("rate.pps", self.pps).map(drop),
            RateModel::Mbps => match (self.mbps_min, self.mbps_max) {
                (Some(lo), Some(hi)) => {
                    require_positive("rate.mbps_min", Some(lo))?;
                    require_positive("rate.mbps_max", Some(hi))?;
                    if hi < lo {
                        return Err("rate.mbps_max must be >= rate.mbps_min".into());
                    }
                    Ok(())
                }
                (None, None) => require_positive("rate.mbps", self.mbps).map(drop),
                _ => Err("rate.mbps band needs both mbps_min and mbps_max".into()),
            },
        }
    }

    /// The fixed Mbps value to use for a non-banded mbps config: the bare `mbps`,
    /// or the band midpoint when only a band is set. Used by [`to_args`]; the run
    /// loop instead samples the band per run via [`to_args_for_run`].
    fn mbps_value(&self) -> f64 {
        self.mbps
            .unwrap_or_else(|| match (self.mbps_min, self.mbps_max) {
                (Some(lo), Some(hi)) => (lo + hi) / 2.0,
                _ => 0.0,
            })
    }

    /// Build the tcpreplay rate flags. Call [`RateCfg::validate`] first; the
    /// required parameter is guaranteed present once validation passes.
    pub fn to_args(&self) -> Vec<String> {
        match self.model {
            RateModel::Original => Vec::new(),
            RateModel::Topspeed => vec!["--topspeed".to_string()],
            RateModel::Multiplier => vec![format!("--multiplier={}", self.multiplier.unwrap())],
            RateModel::Pps => {
                let mut v = vec![format!("--pps={}", self.pps.unwrap())];
                if let Some(m) = self.pps_multi {
                    v.push(format!("--pps-multi={m}"));
                }
                v
            }
            RateModel::Mbps => vec![format!("--mbps={}", self.mbps_value())],
        }
    }

    /// Rate flags for one run. For a banded mbps model each run draws its own
    /// fixed rate in [mbps_min, mbps_max] (so the wire fluctuates run to run);
    /// every other model is identical to [`to_args`] and consumes no entropy.
    pub fn to_args_for_run(&self, rng: &mut impl rand::Rng) -> Vec<String> {
        if self.model == RateModel::Mbps {
            if let (Some(lo), Some(hi)) = (self.mbps_min, self.mbps_max) {
                if hi >= lo {
                    return vec![format!("--mbps={}", rng.gen_range(lo..=hi))];
                }
            }
        }
        self.to_args()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapCfg {
    pub dist: GapDist,
    pub mean_secs: Option<f64>,
    pub min_secs: Option<f64>,
    pub max_secs: Option<f64>,
    pub stddev_secs: Option<f64>,
    pub lower_secs: Option<f64>,
    pub upper_secs: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GapDist {
    #[default]
    ExpPoisson,
    TruncNormal,
}

impl GapCfg {
    pub fn validate(&self) -> Result<(), String> {
        match self.dist {
            GapDist::ExpPoisson => {
                let mean = require_positive("gap.mean_secs", self.mean_secs)?;
                let _ = mean;
                if let (Some(lo), Some(hi)) = (self.min_secs, self.max_secs) {
                    if lo < 0.0 {
                        return Err("gap.min_secs must be >= 0".into());
                    }
                    if lo >= hi {
                        return Err("gap.min_secs must be < gap.max_secs".into());
                    }
                }
                Ok(())
            }
            GapDist::TruncNormal => {
                require_positive("gap.mean_secs", self.mean_secs)?;
                require_positive("gap.stddev_secs", self.stddev_secs)?;
                let lo = self
                    .lower_secs
                    .ok_or_else(|| "gap.lower_secs required for trunc_normal".to_string())?;
                let hi = self
                    .upper_secs
                    .ok_or_else(|| "gap.upper_secs required for trunc_normal".to_string())?;
                if lo < 0.0 {
                    return Err("gap.lower_secs must be >= 0".into());
                }
                if lo >= hi {
                    return Err("gap.lower_secs must be < gap.upper_secs".into());
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    #[serde(default = "default_weight")]
    pub default: f64,
    #[serde(default)]
    pub globs: Vec<GlobWeight>,
    #[serde(default)]
    pub files: HashMap<String, f64>,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            default: default_weight(),
            globs: Vec::new(),
            files: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobWeight {
    pub pattern: String,
    pub weight: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watchdog {
    #[serde(default = "default_poll")]
    pub poll_secs: u64,
    #[serde(default = "default_flatline")]
    pub flatline_secs: u64,
}

impl Default for Watchdog {
    fn default() -> Self {
        Self {
            poll_secs: default_poll(),
            flatline_secs: default_flatline(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetCfg {
    #[serde(default)]
    pub mirror: MirrorMode,
    #[serde(default = "default_bridge")]
    pub bridge: String,
    #[serde(default = "default_sensor_port")]
    pub sensor_port: String,
}

impl Default for NetCfg {
    fn default() -> Self {
        Self {
            mirror: MirrorMode::default(),
            bridge: default_bridge(),
            sensor_port: default_sensor_port(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MirrorMode {
    #[default]
    Tc,
    Ovs,
}

/// Red-laser zone fabrication. The hard caps live in the ledger; config can
/// lower them but never raise them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZonesCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cap on distinct subnet zones. Clamped to the ledger hard cap of 10.
    #[serde(default)]
    pub max_subnets: Option<usize>,
    /// Prefix length for fabricated zone subnets.
    #[serde(default = "default_zone_prefix")]
    pub default_prefix: u8,
}

impl Default for ZonesCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            max_subnets: None,
            default_prefix: default_zone_prefix(),
        }
    }
}

/// Red-laser packet synthesis: device-identity assertions and switch beacons.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynthesisCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub switch_beacons: bool,
    #[serde(default = "default_true")]
    pub device_identity: bool,
    /// Re-announce device identity every Nth run. 1 means every run.
    #[serde(default = "default_identity_every")]
    pub identity_every_n_runs: u64,
    /// Re-label zones with fresh names every Nth run once an unsealed session is
    /// saturated, so a long-running feed keeps evolving. 0 disables (default).
    /// Sealed (committed-plan) sessions never cycle.
    #[serde(default)]
    pub cycle_every_n_runs: u64,
    /// Cap on fabricated devices. Clamped to the ledger hard cap of 2000.
    #[serde(default)]
    pub max_devices: Option<usize>,
    /// Intended fabricated fleet size. `plan --commit` fabricates exactly this
    /// many devices and seals the ledger; the daemon does not grow past it.
    /// Clamped to the device cap. A bare `plan` preview uses it unless
    /// `--devices` overrides.
    #[serde(default = "default_target_devices")]
    pub target_devices: usize,
    /// Total wire-asset cap: fabricated devices plus capture-derived assets.
    /// Replayed capture hosts fill spare zone capacity up to this; surplus rides
    /// existing assets, so the wire never exceeds the plan. Clamped to the device
    /// hard cap; defaults to 256.
    #[serde(default)]
    pub max_assets: Option<usize>,
}

impl Default for SynthesisCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            switch_beacons: true,
            device_identity: true,
            identity_every_n_runs: default_identity_every(),
            cycle_every_n_runs: 0,
            max_devices: None,
            target_devices: default_target_devices(),
            max_assets: None,
        }
    }
}

/// External-threat host promotion. Sparse and rate-limited; a 24h floor between
/// promotions is enforced in code regardless of the interval set here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatsCfg {
    /// On by default under red laser; never fires under green laser.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threat_min")]
    pub min_interval_secs: u64,
    #[serde(default = "default_threat_max")]
    pub max_interval_secs: u64,
    /// Non-RFC1918 source ranges a promoted host appears to come from. The
    /// defaults are documentation ranges (non-RFC1918, so the external-source
    /// anomaly still fires); set ranges your threat-intel feeds flag to also
    /// exercise geo and reputation enrichment.
    #[serde(default = "default_external_cidrs")]
    pub external_cidrs: Vec<String>,
}

impl Default for ThreatsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_secs: default_threat_min(),
            max_interval_secs: default_threat_max(),
            external_cidrs: default_external_cidrs(),
        }
    }
}

/// Persistent red-laser session ledger.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCfg {
    #[serde(default = "default_session_path")]
    pub path: PathBuf,
    /// Seed that makes a red-laser session reproducible. Entropy if unset, and
    /// the drawn seed is then persisted in the ledger.
    #[serde(default)]
    pub seed: Option<u64>,
}

impl Default for SessionCfg {
    fn default() -> Self {
        Self {
            path: default_session_path(),
            seed: None,
        }
    }
}

/// Paths to the OUI and vulnerable-profile databases. Both are embedded in the
/// binary; an on-disk file at these paths overrides the embedded set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuiDbCfg {
    #[serde(default = "default_oui_path")]
    pub path: PathBuf,
    #[serde(default = "default_vuln_path")]
    pub vuln_path: PathBuf,
}

impl Default for OuiDbCfg {
    fn default() -> Self {
        Self {
            path: default_oui_path(),
            vuln_path: default_vuln_path(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.iface.trim().is_empty() {
            return Err("iface must not be empty".into());
        }
        if self.mode == Mode::RedLaser && self.seed.is_some() {
            log::warn!(
                "top-level 'seed' is ignored in red_laser; set session.seed for a reproducible red-laser session"
            );
        }
        // Red laser is plan==wire: every replayed host is remapped into the
        // fabricated plant. With the remap off, captures would replay raw and
        // their original (often private 192.168) addresses would reach the
        // sensor, since the public-source backstop only blocks routable
        // addresses. Refuse the combination rather than leak non-plan addresses.
        if self.mode == Mode::RedLaser && !self.l3.remap {
            return Err(
                "red_laser requires l3.remap = true (plan==wire); use green_laser for raw replay"
                    .into(),
            );
        }
        for (name, p) in [
            ("pool", &self.paths.pool),
            ("variants", &self.paths.variants),
            ("shm_dir", &self.paths.shm_dir),
            ("status_file", &self.paths.status_file),
        ] {
            if !p.is_absolute() {
                return Err(format!("paths.{name} must be absolute: {}", p.display()));
            }
        }
        self.rate.validate()?;
        self.gap.validate()?;
        if !self.weights.default.is_finite() || self.weights.default < 0.0 {
            return Err("weights.default must be a finite value >= 0".into());
        }
        for g in &self.weights.globs {
            if !g.weight.is_finite() || g.weight < 0.0 {
                return Err(format!(
                    "weight for glob {} must be a finite value >= 0",
                    g.pattern
                ));
            }
        }
        for (f, w) in &self.weights.files {
            if !w.is_finite() || *w < 0.0 {
                return Err(format!("weight for file {f} must be a finite value >= 0"));
            }
        }
        if matches!(self.zones.max_subnets, Some(0)) {
            return Err("zones.max_subnets must be > 0".into());
        }
        if !(8..=30).contains(&self.zones.default_prefix) {
            return Err("zones.default_prefix must be between 8 and 30".into());
        }
        if matches!(self.synthesis.max_devices, Some(0)) {
            return Err("synthesis.max_devices must be > 0".into());
        }
        if self.synthesis.identity_every_n_runs == 0 {
            return Err("synthesis.identity_every_n_runs must be > 0".into());
        }
        if self.synthesis.target_devices == 0 {
            return Err("synthesis.target_devices must be > 0".into());
        }
        if matches!(self.synthesis.max_assets, Some(0)) {
            return Err("synthesis.max_assets must be > 0".into());
        }
        if self.threats.min_interval_secs > self.threats.max_interval_secs {
            return Err("threats.min_interval_secs must be <= threats.max_interval_secs".into());
        }
        for c in &self.threats.external_cidrs {
            let net = Ipv4Net::from_str(c)
                .map_err(|_| format!("threats.external_cidrs entry {c} is not a valid CIDR"))?;
            let n = net.network();
            let o0 = n.octets()[0];
            let public_unicast = o0 != 0
                && o0 != 127
                && o0 < 224
                && !n.is_private()
                && !n.is_loopback()
                && !n.is_link_local();
            if !public_unicast {
                return Err(format!(
                    "threats.external_cidrs entry {c} must be a public unicast range (not RFC1918, loopback, link-local, or multicast)"
                ));
            }
        }
        for (name, p) in [
            ("session.path", &self.session.path),
            ("oui_db.path", &self.oui_db.path),
            ("oui_db.vuln_path", &self.oui_db.vuln_path),
        ] {
            if !p.is_absolute() {
                return Err(format!("{name} must be absolute: {}", p.display()));
            }
        }
        Ok(())
    }
}

/// Read, parse, and validate a config file.
pub fn load(path: &Path) -> Result<Config, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let cfg: Config =
        serde_norway::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    cfg.validate()?;
    Ok(cfg)
}

fn require_positive(name: &str, v: Option<f64>) -> Result<f64, String> {
    match v {
        Some(x) if x > 0.0 => Ok(x),
        Some(_) => Err(format!("{name} must be > 0")),
        None => Err(format!("{name} is required")),
    }
}

fn default_true() -> bool {
    true
}
fn default_weight() -> f64 {
    1.0
}
fn default_no_pcaps_retry() -> u64 {
    30
}
fn default_poll() -> u64 {
    2
}
fn default_flatline() -> u64 {
    10
}
fn default_bridge() -> String {
    "tlbr0".into()
}
fn default_sensor_port() -> String {
    "sens0".into()
}
fn default_zone_prefix() -> u8 {
    24
}
fn default_identity_every() -> u64 {
    1
}
fn default_target_devices() -> usize {
    64
}
fn default_max_frame_bytes() -> usize {
    // Standard Ethernet: 14-byte header + 1500 MTU. Frames over this abort a
    // tcpreplay run with EMSGSIZE, so they are dropped before replay.
    1514
}
fn default_max_remap_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}
fn default_threat_min() -> u64 {
    172_800 // 2 days
}
fn default_threat_max() -> u64 {
    1_209_600 // 14 days
}
fn default_external_cidrs() -> Vec<String> {
    // Documentation ranges (RFC 5737): non-RFC1918 so the external-source
    // anomaly fires, without baking in attribution to real networks. Operators
    // set ranges their threat-intel flags to also exercise geo enrichment.
    vec!["198.51.100.0/24".into(), "203.0.113.0/24".into()]
}
fn default_session_path() -> PathBuf {
    PathBuf::from("/var/lib/ot-turbolaser/session.json")
}
fn default_oui_path() -> PathBuf {
    PathBuf::from("/opt/replay/data/oui.csv")
}
fn default_vuln_path() -> PathBuf {
    PathBuf::from("/opt/replay/data/vuln_profiles.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(model: RateModel, mult: Option<f64>, pps: Option<f64>, mbps: Option<f64>) -> RateCfg {
        RateCfg {
            model,
            multiplier: mult,
            pps,
            pps_multi: None,
            mbps,
            mbps_min: None,
            mbps_max: None,
        }
    }

    #[test]
    fn rate_args_per_model() {
        assert_eq!(
            rate(RateModel::Original, None, None, None).to_args(),
            Vec::<String>::new()
        );
        assert_eq!(
            rate(RateModel::Topspeed, None, None, None).to_args(),
            vec!["--topspeed"]
        );
        assert_eq!(
            rate(RateModel::Multiplier, Some(2.5), None, None).to_args(),
            vec!["--multiplier=2.5"]
        );
        assert_eq!(
            rate(RateModel::Pps, None, Some(200.0), None).to_args(),
            vec!["--pps=200"]
        );
        assert_eq!(
            rate(RateModel::Mbps, None, None, Some(10.0)).to_args(),
            vec!["--mbps=10"]
        );
    }

    #[test]
    fn rate_validate_requires_param() {
        assert!(rate(RateModel::Multiplier, None, None, None)
            .validate()
            .is_err());
        assert!(rate(RateModel::Multiplier, Some(1.0), None, None)
            .validate()
            .is_ok());
        assert!(rate(RateModel::Pps, None, None, None).validate().is_err());
        assert!(rate(RateModel::Original, None, None, None)
            .validate()
            .is_ok());
    }

    #[test]
    fn mbps_band_validates_and_samples_in_range() {
        use rand::SeedableRng;
        let mut banded = rate(RateModel::Mbps, None, None, None);
        banded.mbps_min = Some(9.0);
        banded.mbps_max = Some(11.0);
        assert!(banded.validate().is_ok(), "a full band validates");
        // A bare midpoint when no rng is sampled.
        assert_eq!(banded.to_args(), vec!["--mbps=10"]);
        // Every sampled run rate stays inside the band.
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        for _ in 0..256 {
            let args = banded.to_args_for_run(&mut rng);
            let v: f64 = args[0].strip_prefix("--mbps=").unwrap().parse().unwrap();
            assert!((9.0..=11.0).contains(&v), "sampled rate {v} in band");
        }
        // Half a band is rejected; a non-mbps model never consumes entropy.
        let mut half = rate(RateModel::Mbps, None, None, None);
        half.mbps_min = Some(9.0);
        assert!(half.validate().is_err(), "half a band is rejected");
        assert_eq!(
            rate(RateModel::Original, None, None, None).to_args_for_run(&mut rng),
            Vec::<String>::new()
        );
    }

    fn gap(dist: GapDist) -> GapCfg {
        GapCfg {
            dist,
            mean_secs: Some(5.0),
            min_secs: Some(0.5),
            max_secs: Some(60.0),
            stddev_secs: Some(3.0),
            lower_secs: Some(1.0),
            upper_secs: Some(30.0),
        }
    }

    #[test]
    fn shipped_example_config_parses_and_validates() {
        // Guards against a deny_unknown_fields break: the shipped config must
        // parse and validate against the current schema (incl. the v0.2.1 keys).
        let cfg = load(std::path::Path::new("conf/replay.yaml"))
            .expect("shipped conf/replay.yaml must parse and validate");
        assert_eq!(cfg.mode, Mode::RedLaser);
        assert_eq!(cfg.l3.zone_affinity, ZoneAffinity::Both);
        assert!(cfg.l3.guard_public_sources);
        assert!(
            !cfg.l3.replay_capture_arp,
            "capture ARP is thinned by default"
        );
        assert_eq!(cfg.synthesis.target_devices, 64);
        assert_eq!(cfg.session.seed, Some(1337));
    }

    #[test]
    fn red_laser_requires_remap_green_does_not() {
        let yaml = "iface: tl0
mode: red_laser
paths:
  pool: /opt/pool
  variants: /opt/variants
  shm_dir: /dev/shm/x
  status_file: /run/x.json
l3:
  remap: false
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 5.0
";
        let cfg: Config = serde_norway::from_str(yaml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.contains("red_laser requires l3.remap"),
            "red laser with remap off is refused: {err}"
        );
        // Green laser legitimately replays raw, guarded by the public backstop.
        let green: Config =
            serde_norway::from_str(&yaml.replace("red_laser", "green_laser")).unwrap();
        assert!(green.validate().is_ok(), "green laser may replay raw");
    }

    #[test]
    fn gap_validate_bounds() {
        assert!(gap(GapDist::ExpPoisson).validate().is_ok());
        assert!(gap(GapDist::TruncNormal).validate().is_ok());

        let mut bad = gap(GapDist::TruncNormal);
        bad.stddev_secs = Some(0.0);
        assert!(bad.validate().is_err());

        let mut inverted = gap(GapDist::TruncNormal);
        inverted.lower_secs = Some(30.0);
        inverted.upper_secs = Some(1.0);
        assert!(inverted.validate().is_err());

        let mut no_mean = gap(GapDist::ExpPoisson);
        no_mean.mean_secs = None;
        assert!(no_mean.validate().is_err());
    }
}
