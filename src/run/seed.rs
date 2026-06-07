//! Seed handling.
//!
//! Green laser uses a fixed master seed (configured, or a default), so the whole
//! per-run sequence reproduces across restarts: capture order and inter-run gaps
//! are both drawn from a single master-seeded RNG. Red laser draws the master
//! from OS entropy; its fabricated world is instead reproduced from the session
//! seed persisted in the ledger, and the per-run L3 remap keys on that session
//! seed (reported as `l3_seed` in the heartbeat).

use crate::config::Mode;

pub const DEFAULT_GREEN_SEED: u64 = 0x00C0_FFEE_0BAD_F00D;

/// Resolve the master seed for a run. Green laser uses the configured seed (or a
/// fixed default); red laser ignores the config and uses entropy.
pub fn master_seed(mode: Mode, configured: Option<u64>) -> u64 {
    match mode {
        Mode::GreenLaser => configured.unwrap_or(DEFAULT_GREEN_SEED),
        Mode::RedLaser => rand::random(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_master_is_stable() {
        assert_eq!(master_seed(Mode::GreenLaser, Some(42)), 42);
        assert_eq!(master_seed(Mode::GreenLaser, None), DEFAULT_GREEN_SEED);
    }
}
