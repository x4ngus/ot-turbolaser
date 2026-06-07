//! Seeded, capture-wide consistent identifier remapping.
//!
//! The same `(domain, original)` always maps to the same new value across a
//! whole capture, and the mapping is reproducible from the seed. Mappings are
//! injective within a domain where the value space allows it, so two distinct
//! assets do not collapse into one identity.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Domain {
    ModbusUnitId,
    EnipVendor,
    EnipDeviceType,
    EnipProductCode,
    EnipSerial,
    S7ModuleId,
    S7Serial,
    Dnp3Addr,
}

pub struct SeededMapper {
    rng: ChaCha8Rng,
    fwd: HashMap<(Domain, u64), u64>,
    used: HashMap<Domain, HashSet<u64>>,
}

impl SeededMapper {
    pub fn from_seed(seed: u64) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            fwd: HashMap::new(),
            used: HashMap::new(),
        }
    }

    /// Map `orig` to a new value in `[lo, hi]`, consistent across the capture.
    /// Avoids collisions within the domain where the range allows, so the
    /// remap stays injective.
    pub fn map_range(&mut self, domain: Domain, orig: u64, lo: u64, hi: u64) -> u64 {
        if let Some(&v) = self.fwd.get(&(domain, orig)) {
            return v;
        }
        let v = self.draw_unused(domain, lo, hi);
        self.fwd.insert((domain, orig), v);
        self.used.entry(domain).or_default().insert(v);
        v
    }

    fn draw_unused(&mut self, domain: Domain, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        let used = self.used.entry(domain).or_default();
        // Bounded retries to avoid collisions; if the space is nearly full we
        // accept whatever we drew rather than loop forever.
        let mut candidate = self.rng.gen_range(lo..=hi);
        for _ in 0..64 {
            if !used.contains(&candidate) {
                break;
            }
            candidate = self.rng.gen_range(lo..=hi);
        }
        candidate
    }

    pub fn map_u8(&mut self, domain: Domain, orig: u8) -> u8 {
        self.map_range(domain, orig as u64, 0, 0xff) as u8
    }

    pub fn map_u16(&mut self, domain: Domain, orig: u16) -> u16 {
        self.map_range(domain, orig as u64, 0, 0xffff) as u16
    }

    pub fn map_u32(&mut self, domain: Domain, orig: u32) -> u32 {
        self.map_range(domain, orig as u64, 0, 0xffff_ffff) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_within_capture() {
        let mut m = SeededMapper::from_seed(42);
        let a = m.map_u16(Domain::EnipVendor, 7);
        let b = m.map_u16(Domain::EnipVendor, 7);
        assert_eq!(a, b, "same input must map to the same output");
    }

    #[test]
    fn deterministic_across_runs() {
        let mut m1 = SeededMapper::from_seed(1234);
        let mut m2 = SeededMapper::from_seed(1234);
        for orig in [1u32, 99, 7, 7, 256, 1] {
            assert_eq!(
                m1.map_u32(Domain::EnipSerial, orig),
                m2.map_u32(Domain::EnipSerial, orig)
            );
        }
    }

    #[test]
    fn injective_within_domain() {
        let mut m = SeededMapper::from_seed(9);
        let mut seen = std::collections::HashSet::new();
        // 200 distinct origs into the 0..=255 space should stay distinct.
        for orig in 0u8..200 {
            let v = m.map_u8(Domain::ModbusUnitId, orig);
            assert!(seen.insert(v), "collision on remapped unit id {v}");
        }
    }

    #[test]
    fn domains_are_independent() {
        let mut m = SeededMapper::from_seed(5);
        // Same orig in different domains may differ; both must be stable.
        let a1 = m.map_u16(Domain::S7ModuleId, 10);
        let b1 = m.map_u16(Domain::Dnp3Addr, 10);
        assert_eq!(a1, m.map_u16(Domain::S7ModuleId, 10));
        assert_eq!(b1, m.map_u16(Domain::Dnp3Addr, 10));
    }
}
