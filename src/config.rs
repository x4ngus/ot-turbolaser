//! Replay configuration: the schema everything else keys off.
//!
//! Rate and gap use a flat shape (a `kind` enum plus optional parameter
//! fields) rather than serde's internally tagged enums, which parse
//! inconsistently across YAML libraries. Semantic checks live in
//! [`Config::validate`], so a config that parses is also coherent.

use ipnet::Ipv4Net;
use serde::Deserialize;
use serde_norway::Value;
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
    pub dns: DnsCfg,
    #[serde(default)]
    pub north_south: NorthSouthCfg,
    #[serde(default)]
    pub threats: ThreatsCfg,
    #[serde(default)]
    pub session: SessionCfg,
    #[serde(default)]
    pub oui_db: OuiDbCfg,
    // v0.4 target layer. Present only when a scenario pack is loaded; absent is
    // plain red laser, so existing configs and green laser are unaffected.
    #[serde(default)]
    pub target: Option<TargetCfg>,
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
            RateModel::Pps => {
                require_positive("rate.pps", self.pps)?;
                // pps_multi is optional, but an explicit 0 emits `--pps-multi=0`,
                // which tcpreplay rejects. Catch it at config load.
                if self.pps_multi == Some(0) {
                    return Err("rate.pps_multi must be > 0".into());
                }
                Ok(())
            }
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

impl MirrorMode {
    /// Canonical string passed to the net scripts and shown by net-show.
    pub fn as_str(self) -> &'static str {
        match self {
            MirrorMode::Tc => "tc",
            MirrorMode::Ovs => "ovs",
        }
    }
}

/// Red-laser zone fabrication. The hard caps live in the ledger; config can
/// lower them but never raise them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZonesCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cap on distinct subnet zones. Clamped to the ledger hard cap of 16.
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
    /// Re-announce device identity every Nth run. 1 means every run. The wall
    /// clock cadence below is the primary throttle; this is a secondary gate.
    #[serde(default = "default_identity_every")]
    pub identity_every_n_runs: u64,
    /// Minimum seconds between identity bursts, so the plant reads as periodic
    /// discovery rather than a scan storm. Each burst opens fresh client-side
    /// connections (new ephemeral ports), so a sensor sees distinct, parseable
    /// scans it can attribute, instead of one identical conversation it folds and
    /// never re-reads. Default 25s.
    #[serde(default = "default_announce_interval")]
    pub announce_interval_secs: u64,
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
    /// hard cap; defaults to 512 (ledger::DEFAULT_MAX_ASSETS).
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
            announce_interval_secs: default_announce_interval(),
            cycle_every_n_runs: 0,
            max_devices: None,
            target_devices: default_target_devices(),
            max_assets: None,
        }
    }
}

/// Shared DNS domain identity. Fabricated zones are tagged with a domain (most
/// share the first, so the identity spans zones), and the existing DNS A-records
/// resolve fully-qualified `<host>.<domain>` names a sensor correlates by suffix.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCfg {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Site domains. Most zones take the first (the shared plant domain); the rest
    /// cycle the remainder. Empty leaves hostnames single-label.
    #[serde(default = "default_dns_domains")]
    pub domains: Vec<String>,
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            domains: default_dns_domains(),
        }
    }
}

/// North-south conduit traffic: bounded cross-zone OT sessions between adjacent
/// Purdue zones, forwarded by a conduit (the zone firewall, else a switch, else
/// the station). Off by default so the baseline stays intra-zone until opted in.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NorthSouthCfg {
    #[serde(default)]
    pub enabled: bool,
    /// Bounded flows per adjacent zone pair, so the wire carries no scan.
    #[serde(default = "default_ns_per_pair")]
    pub max_flows_per_pair: usize,
    /// Emit the crossings every Nth run.
    #[serde(default = "default_ns_cadence")]
    pub cadence_runs: u64,
}

impl Default for NorthSouthCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            max_flows_per_pair: default_ns_per_pair(),
            cadence_runs: default_ns_cadence(),
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

/// Active target-scenario overlay. A scenario pack under `conf/targets/<name>/`
/// pins a specific real-world attack: its YAML merges over the base config, its
/// `profiles.toml` overlays the CVE database, its `plant` spec is fabricated as a
/// sealed ledger, and its `playbook` drives the phased attack emission. Absent is
/// generic red laser. Built by [`load_with_scenario`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCfg {
    /// Scenario identifier, e.g. "stuxnet". Matches the pack directory name.
    pub name: String,
    /// One-line human description, shown by `turbolaser targets`.
    #[serde(default)]
    pub description: Option<String>,
    /// CVE-profile pack, relative to the pack dir. Overlays the embedded DB.
    #[serde(default = "default_profiles_file")]
    pub profiles: PathBuf,
    /// Phased attack playbook, relative to the pack dir.
    #[serde(default = "default_playbook_file")]
    pub playbook: PathBuf,
    /// Plant spec (exact zones and devices), relative to the pack dir.
    #[serde(default = "default_plant_file")]
    pub plant: PathBuf,
    /// One-shot campaign (hold the final impact) or loop (restart the timeline).
    #[serde(default)]
    pub campaign: Campaign,
    /// Cap on attack-action frames appended to a single burst, so a long
    /// sequence (an S7 download, an IEC-104 sweep) spreads across announces
    /// instead of arriving as one microburst the sensor drops.
    #[serde(default = "default_max_frames_per_burst")]
    pub max_frames_per_burst: usize,
    /// Emit the real published network indicators, or documentation stand-ins.
    #[serde(default)]
    pub ioc_fidelity: IocFidelity,
    /// Threat-actor network identity (external ranges, C2, artifacts) the
    /// playbook's IOC events draw on.
    #[serde(default)]
    pub actors: ActorsCfg,
    /// Absolute pack directory, filled by the loader (never from YAML), so the
    /// plant, playbook, and profile loaders resolve their relative paths.
    #[serde(skip)]
    pub pack_dir: PathBuf,
}

/// Whether a scenario timeline runs once or repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Campaign {
    /// Run the phases once, then hold the final (impact) phase.
    #[default]
    Oneshot,
    /// Restart from the first phase after the last.
    Loop,
}

/// How literal the emitted network indicators are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IocFidelity {
    /// Emit the real published indicators (domains/IPs/artifacts) from the pack.
    #[default]
    Real,
    /// Swap every network indicator for an RFC-5737 documentation stand-in.
    Standin,
}

/// Threat-actor network identity for a scenario. All optional; the playbook's
/// IOC events reference these.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ActorsCfg {
    /// Non-RFC1918 source ranges the actor appears to operate from.
    #[serde(default)]
    pub external_cidrs: Vec<String>,
    /// C2 domains resolved or queried during the campaign.
    #[serde(default)]
    pub c2_domains: Vec<String>,
    /// C2 IPv4 addresses contacted during the campaign.
    #[serde(default)]
    pub c2_ips: Vec<String>,
    /// Named artifacts (filenames, hashes) surfaced as host-level IOCs.
    #[serde(default)]
    pub artifacts: Vec<String>,
}

fn default_profiles_file() -> PathBuf {
    PathBuf::from("profiles.toml")
}
fn default_playbook_file() -> PathBuf {
    PathBuf::from("playbook.yaml")
}
fn default_plant_file() -> PathBuf {
    PathBuf::from("plant.yaml")
}
fn default_max_frames_per_burst() -> usize {
    64
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
        if self.dns.enabled {
            for d in &self.dns.domains {
                if d.trim().is_empty() || d.contains(char::is_whitespace) {
                    return Err(format!("dns.domains entry {d:?} is not a valid domain"));
                }
            }
        }
        if self.north_south.enabled {
            if self.north_south.cadence_runs == 0 {
                return Err("north_south.cadence_runs must be > 0".into());
            }
            if self.north_south.max_flows_per_pair == 0 {
                return Err("north_south.max_flows_per_pair must be > 0".into());
            }
        }
        // Timing knobs must be positive: a zero interval would spin a loop or fire
        // bursts with no delay. Some are also guarded at runtime, but rejecting a
        // zero here makes `check` fail fast with a named field instead.
        if self.watchdog.poll_secs == 0 {
            return Err("watchdog.poll_secs must be > 0".into());
        }
        if self.watchdog.flatline_secs == 0 {
            return Err("watchdog.flatline_secs must be > 0".into());
        }
        if self.no_pcaps_retry_secs == 0 {
            return Err("no_pcaps_retry_secs must be > 0".into());
        }
        if self.synthesis.enabled && self.synthesis.announce_interval_secs == 0 {
            return Err("synthesis.announce_interval_secs must be > 0".into());
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
        if let Some(t) = &self.target {
            // A scenario overlays red laser: it reuses the fabrication, remap, and
            // identity machinery. Refuse a scenario that tried to switch the mode
            // or disable the remap, with a message that names the scenario rather
            // than leaving the generic red-laser invariant to fire confusingly.
            if self.mode != Mode::RedLaser {
                return Err(format!(
                    "target scenario {:?} requires mode red_laser (it overlays red laser)",
                    t.name
                ));
            }
            if !self.l3.remap {
                return Err(format!(
                    "target scenario {:?} requires l3.remap = true (red laser is plan==wire)",
                    t.name
                ));
            }
            if t.name.trim().is_empty() {
                return Err("target.name must not be empty".into());
            }
            if t.max_frames_per_burst == 0 {
                return Err("target.max_frames_per_burst must be > 0".into());
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

/// Read and validate a config, optionally overlaying a named target scenario.
///
/// With `scenario = None` this is byte-identical to [`load`] (the plain
/// red/green-laser path). With a name, the pack at
/// `<config_dir>/targets/<name>/scenario.yaml` is deep-merged over the base
/// config (maps recurse; scalars and sequences replace), then the merged whole
/// is deserialized and validated, so `deny_unknown_fields` still holds across
/// the combined document. The absolute pack directory is recorded on the
/// resulting `target` block so the plant, playbook, and profile loaders resolve
/// their relative paths.
pub fn load_with_scenario(base: &Path, scenario: Option<&str>) -> Result<Config, String> {
    let Some(name) = scenario else {
        return load(base);
    };
    // The name indexes a directory, so reject anything that could escape it.
    if name.trim().is_empty() || name.contains(['/', '\\', '.']) {
        return Err(format!(
            "invalid scenario name {name:?} (use a bare slug like 'stuxnet')"
        ));
    }
    let base_text =
        std::fs::read_to_string(base).map_err(|e| format!("reading {}: {e}", base.display()))?;
    let pack_dir = base
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("targets")
        .join(name);
    let scenario_path = pack_dir.join("scenario.yaml");
    let scen_text = std::fs::read_to_string(&scenario_path)
        .map_err(|e| format!("reading scenario {}: {e}", scenario_path.display()))?;

    let mut merged: Value = serde_norway::from_str(&base_text)
        .map_err(|e| format!("parsing {}: {e}", base.display()))?;
    let overlay: Value = serde_norway::from_str(&scen_text)
        .map_err(|e| format!("parsing {}: {e}", scenario_path.display()))?;
    deep_merge(&mut merged, overlay);

    let mut cfg: Config = serde_norway::from_value(merged)
        .map_err(|e| format!("merging scenario {name} over {}: {e}", base.display()))?;
    match cfg.target.as_mut() {
        Some(t) => {
            // Canonicalise so the recorded dir is absolute regardless of how the
            // base config path was given. The scenario.yaml was just read from
            // this dir, so it exists; a canonicalize failure is an unusual deploy
            // (permissions, a symlink loop), so surface it rather than silently
            // falling back to a CWD-relative path the plant/playbook loaders would
            // then resolve against an unexpected directory.
            t.pack_dir = std::fs::canonicalize(&pack_dir).unwrap_or_else(|e| {
                log::warn!(
                    "could not canonicalize pack dir {}: {e}; using it as given (relative to the working dir)",
                    pack_dir.display()
                );
                pack_dir
            });
        }
        None => {
            return Err(format!(
                "scenario {name} did not set a `target:` block in {}",
                scenario_path.display()
            ));
        }
    }
    cfg.validate()?;
    Ok(cfg)
}

/// Deep-merge `overlay` onto `base`: where both sides are mappings, merge keys
/// recursively; otherwise (a scalar, a sequence, or a type change) the overlay
/// replaces the base wholesale. So a scenario overrides a list (e.g.
/// `dns.domains`, `threats.external_cidrs`) entirely rather than appending to it.
fn deep_merge(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Mapping(over) => {
            if let Some(map) = base.as_mapping_mut() {
                for (k, ov) in over {
                    match map.entry(k) {
                        serde_norway::mapping::Entry::Occupied(mut e) => {
                            deep_merge(e.get_mut(), ov)
                        }
                        serde_norway::mapping::Entry::Vacant(e) => {
                            e.insert(ov);
                        }
                    }
                }
            } else {
                *base = Value::Mapping(over);
            }
        }
        other => *base = other,
    }
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
fn default_announce_interval() -> u64 {
    25
}
fn default_target_devices() -> usize {
    64
}
fn default_dns_domains() -> Vec<String> {
    vec!["plant.corp.example".into(), "dmz.corp.example".into()]
}
fn default_ns_per_pair() -> usize {
    2
}
fn default_ns_cadence() -> u64 {
    2
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
    fn pps_multi_zero_is_rejected() {
        let mut r = rate(RateModel::Pps, None, Some(100.0), None);
        assert!(r.validate().is_ok(), "no pps_multi is fine");
        r.pps_multi = Some(0);
        assert!(
            r.validate().unwrap_err().contains("pps_multi"),
            "an explicit pps_multi of 0 is rejected"
        );
        r.pps_multi = Some(2);
        assert!(r.validate().is_ok(), "a positive pps_multi validates");
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
    fn zero_timing_fields_are_rejected() {
        // Load the valid shipped config, mutate one timing knob to 0, re-validate.
        let validate_with = |mutate: fn(&mut Config)| {
            let mut c = load(std::path::Path::new("conf/replay.yaml")).unwrap();
            mutate(&mut c);
            c.validate()
        };
        assert!(validate_with(|c| c.watchdog.poll_secs = 0)
            .unwrap_err()
            .contains("watchdog.poll_secs"));
        assert!(validate_with(|c| c.watchdog.flatline_secs = 0)
            .unwrap_err()
            .contains("watchdog.flatline_secs"));
        assert!(validate_with(|c| c.no_pcaps_retry_secs = 0)
            .unwrap_err()
            .contains("no_pcaps_retry_secs"));
        assert!(validate_with(|c| c.synthesis.announce_interval_secs = 0)
            .unwrap_err()
            .contains("announce_interval_secs"));
        // A disabled synthesis block does not require a positive announce interval.
        assert!(
            validate_with(|c| {
                c.synthesis.enabled = false;
                c.synthesis.announce_interval_secs = 0;
            })
            .is_ok(),
            "announce interval is irrelevant when synthesis is disabled"
        );
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

    #[test]
    fn deep_merge_overrides_scalars_and_replaces_sequences() {
        let mut base: Value =
            serde_norway::from_str("a: 1\nb:\n  c: 2\n  d: 3\nlist: [1, 2, 3]\n").unwrap();
        let over: Value = serde_norway::from_str("a: 9\nb:\n  c: 20\nlist: [7]\ne: 5\n").unwrap();
        deep_merge(&mut base, over);
        let m = base.as_mapping().unwrap();
        assert_eq!(m.get("a").unwrap().as_u64(), Some(9), "scalar overridden");
        let b = m.get("b").unwrap().as_mapping().unwrap();
        assert_eq!(b.get("c").unwrap().as_u64(), Some(20), "nested overridden");
        assert_eq!(b.get("d").unwrap().as_u64(), Some(3), "untouched key kept");
        let list = m.get("list").unwrap().as_sequence().unwrap();
        assert_eq!(list.len(), 1, "sequence replaced, not concatenated");
        assert_eq!(m.get("e").unwrap().as_u64(), Some(5), "new key added");
    }

    #[test]
    fn unknown_target_field_is_rejected() {
        // deny_unknown_fields on TargetCfg guards against a typo'd scenario key.
        let yaml = "iface: tl0
mode: red_laser
paths:
  pool: /a
  variants: /b
  shm_dir: /c
  status_file: /d
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
target:
  name: x
  bogus_field: 1
";
        let r: Result<Config, _> = serde_norway::from_str(yaml);
        assert!(r.is_err(), "an unknown field under target must be rejected");
    }

    #[test]
    fn scenario_overlay_merges_and_records_pack_dir() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf");
        std::fs::create_dir_all(&conf_dir).unwrap();
        let base = conf_dir.join("replay.yaml");
        std::fs::copy("conf/replay.yaml", &base).unwrap();
        let pack = conf_dir.join("targets").join("demo");
        std::fs::create_dir_all(&pack).unwrap();
        let mut f = std::fs::File::create(pack.join("scenario.yaml")).unwrap();
        write!(
            f,
            "synthesis:\n  target_devices: 8\ntarget:\n  name: demo\n  actors:\n    c2_domains: [\"evil.example\"]\n"
        )
        .unwrap();

        let cfg = load_with_scenario(&base, Some("demo")).expect("overlay loads");
        assert_eq!(
            cfg.synthesis.target_devices, 8,
            "scenario overrode the base"
        );
        let t = cfg.target.expect("target present after overlay");
        assert_eq!(t.name, "demo");
        assert_eq!(t.actors.c2_domains, vec!["evil.example".to_string()]);
        assert!(
            t.pack_dir.ends_with("targets/demo"),
            "pack dir recorded: {:?}",
            t.pack_dir
        );

        // No scenario is byte-identical to load(): plain red laser, no target.
        let plain = load_with_scenario(&base, None).expect("plain load");
        assert!(
            plain.target.is_none(),
            "no scenario means no target overlay"
        );
    }

    #[test]
    fn scenario_without_target_block_is_an_error() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf");
        std::fs::create_dir_all(&conf_dir).unwrap();
        let base = conf_dir.join("replay.yaml");
        std::fs::copy("conf/replay.yaml", &base).unwrap();
        let pack = conf_dir.join("targets").join("nodecl");
        std::fs::create_dir_all(&pack).unwrap();
        // Overrides a value but never declares `target:`.
        let mut f = std::fs::File::create(pack.join("scenario.yaml")).unwrap();
        write!(f, "synthesis:\n  target_devices: 4\n").unwrap();
        let err = load_with_scenario(&base, Some("nodecl")).unwrap_err();
        assert!(err.contains("did not set a `target:` block"), "{err}");
    }

    #[test]
    fn invalid_scenario_names_are_rejected() {
        let base = std::path::Path::new("conf/replay.yaml");
        for bad in ["../escape", "a/b", "with.dot", ""] {
            assert!(
                load_with_scenario(base, Some(bad)).is_err(),
                "name {bad:?} must be rejected"
            );
        }
    }
}
