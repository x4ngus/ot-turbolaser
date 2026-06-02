//! Seed handling.
//!
//! Green laser derives every per-run seed from a fixed master with SplitMix64,
//! so the whole sequence (file order, gaps, L3 remap) reproduces across restarts.
//! Red laser draws the master from OS entropy, so each daemon start differs; the
//! master and every per-run seed are logged so an interesting run can be
//! reproduced by pinning the seed in green-laser mode.

use crate::config::Mode;

pub const DEFAULT_GREEN_SEED: u64 = 0x00C0_FFEE_0BAD_F00D;

/// One SplitMix64 step. Cheap, well-distributed mixing of master and counter.
pub fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Resolve the master seed for a run. Green laser uses the configured seed (or a
/// fixed default); red laser ignores the config and uses entropy.
pub fn master_seed(mode: Mode, configured: Option<u64>) -> u64 {
    match mode {
        Mode::GreenLaser => configured.unwrap_or(DEFAULT_GREEN_SEED),
        Mode::RedLaser => rand::random(),
    }
}

/// The per-run seed for iteration `run`, used for the L3 remap. Deterministic
/// given the master, which is what makes green laser reproducible.
pub fn run_seed(master: u64, run: u64) -> u64 {
    splitmix64(master ^ run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_master_is_stable() {
        assert_eq!(master_seed(Mode::GreenLaser, Some(42)), 42);
        assert_eq!(master_seed(Mode::GreenLaser, None), DEFAULT_GREEN_SEED);
    }

    #[test]
    fn run_seeds_are_distinct_and_reproducible() {
        let m = 12345;
        let s0 = run_seed(m, 0);
        let s1 = run_seed(m, 1);
        assert_ne!(s0, s1);
        assert_eq!(s0, run_seed(m, 0), "same master and run reproduce the seed");
    }
}
