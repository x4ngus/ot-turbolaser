//! Replay configuration: the schema everything else keys off.
//!
//! Rate and gap use a flat shape (a `kind` enum plus optional parameter
//! fields) rather than serde's internally tagged enums, which parse
//! inconsistently across YAML libraries. Semantic checks live in
//! [`Config::validate`], so a config that parses is also coherent.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Replay NIC on the isolated bridge. Also the mirror source port.
    pub iface: String,
    #[serde(default)]
    pub mode: Mode,
    /// Baseline master seed. Ignored in variety, which uses entropy.
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Variety,
    Baseline,
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
    /// Apply the coherent L3 remap per run in variety mode.
    #[serde(default = "default_true")]
    pub remap: bool,
    /// Optional cheap-tier fallback when the in-process remap is off.
    #[serde(default)]
    pub fallback: L3Fallback,
    /// Optional CIDR hints for grouping hosts into subnets.
    #[serde(default)]
    pub subnets: Vec<String>,
}

impl Default for L3Cfg {
    fn default() -> Self {
        Self {
            remap: true,
            fallback: L3Fallback::default(),
            subnets: Vec::new(),
        }
    }
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
            RateModel::Mbps => require_positive("rate.mbps", self.mbps).map(drop),
        }
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
            RateModel::Mbps => vec![format!("--mbps={}", self.mbps.unwrap())],
        }
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

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.iface.trim().is_empty() {
            return Err("iface must not be empty".into());
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
        if self.weights.default < 0.0 {
            return Err("weights.default must be >= 0".into());
        }
        for g in &self.weights.globs {
            if g.weight < 0.0 {
                return Err(format!("weight for glob {} must be >= 0", g.pattern));
            }
        }
        for (f, w) in &self.weights.files {
            if *w < 0.0 {
                return Err(format!("weight for file {f} must be >= 0"));
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
