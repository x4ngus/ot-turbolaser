//! Inter-run gap sampling. Two distributions: exponential (a Poisson process,
//! the most effective at avoiding periodicity) and truncated normal.

use crate::config::{GapCfg, GapDist};
use rand::Rng;
use rand_distr::{Distribution, Exp, Normal};

/// Sample one inter-run gap in seconds. Assumes the config has been validated,
/// so the required parameters are present, but falls back defensively.
pub fn sample_gap(cfg: &GapCfg, rng: &mut impl Rng) -> f64 {
    match cfg.dist {
        GapDist::ExpPoisson => {
            let mean = cfg.mean_secs.unwrap_or(1.0).max(1e-9);
            let exp = Exp::new(1.0 / mean).unwrap_or_else(|_| Exp::new(1.0).unwrap());
            let mut v = exp.sample(rng);
            if let Some(lo) = cfg.min_secs {
                v = v.max(lo);
            }
            if let Some(hi) = cfg.max_secs {
                v = v.min(hi);
            }
            v
        }
        GapDist::TruncNormal => {
            let mean = cfg.mean_secs.unwrap_or(1.0);
            let sd = cfg.stddev_secs.unwrap_or(1.0).max(1e-9);
            let lo = cfg.lower_secs.unwrap_or(0.0);
            let hi = cfg.upper_secs.unwrap_or(f64::MAX);
            let normal = Normal::new(mean, sd).unwrap_or_else(|_| Normal::new(mean, 1.0).unwrap());
            // Rejection sampling with a finite cap; clamp as the fallback so a
            // pathological config can never loop forever.
            let mut v = normal.sample(rng);
            for _ in 0..64 {
                if (lo..=hi).contains(&v) {
                    break;
                }
                v = normal.sample(rng);
            }
            v.clamp(lo, hi)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn exp(mean: f64, min: Option<f64>, max: Option<f64>) -> GapCfg {
        GapCfg {
            dist: GapDist::ExpPoisson,
            mean_secs: Some(mean),
            min_secs: min,
            max_secs: max,
            stddev_secs: None,
            lower_secs: None,
            upper_secs: None,
        }
    }

    fn trunc(mean: f64, sd: f64, lo: f64, hi: f64) -> GapCfg {
        GapCfg {
            dist: GapDist::TruncNormal,
            mean_secs: Some(mean),
            min_secs: None,
            max_secs: None,
            stddev_secs: Some(sd),
            lower_secs: Some(lo),
            upper_secs: Some(hi),
        }
    }

    #[test]
    fn exponential_mean_is_close() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let cfg = exp(5.0, None, None);
        let n = 20_000;
        let sum: f64 = (0..n).map(|_| sample_gap(&cfg, &mut rng)).sum();
        let mean = sum / n as f64;
        assert!((mean - 5.0).abs() < 0.3, "exp mean {mean} not near 5.0");
    }

    #[test]
    fn exponential_respects_bounds() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let cfg = exp(5.0, Some(1.0), Some(8.0));
        for _ in 0..10_000 {
            let v = sample_gap(&cfg, &mut rng);
            assert!((1.0..=8.0).contains(&v), "exp sample {v} out of bounds");
        }
    }

    #[test]
    fn truncated_normal_stays_in_bounds() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let cfg = trunc(8.0, 3.0, 1.0, 30.0);
        for _ in 0..10_000 {
            let v = sample_gap(&cfg, &mut rng);
            assert!((1.0..=30.0).contains(&v), "trunc sample {v} out of bounds");
        }
    }
}
