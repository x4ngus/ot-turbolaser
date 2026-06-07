//! Weighted file selection. Weight precedence: an exact file entry (by name or
//! full path), then the first matching glob, then the default. Weight 0
//! excludes a file.

use crate::config::Weights;
use glob::Pattern;
use rand::Rng;
use std::path::{Path, PathBuf};

pub fn weight_for(path: &Path, w: &Weights) -> f64 {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let full = path.to_string_lossy();
    if let Some(&x) = w.files.get(name) {
        return x;
    }
    if let Some(&x) = w.files.get(full.as_ref()) {
        return x;
    }
    for g in &w.globs {
        if let Ok(pat) = Pattern::new(&g.pattern) {
            if pat.matches(name) || pat.matches(&full) {
                return g.weight;
            }
        }
    }
    w.default
}

/// Pick a file weighted by its resolved weight. Returns None if the list is
/// empty or every file is excluded (total weight 0).
pub fn weighted_pick<'a>(
    files: &'a [PathBuf],
    w: &Weights,
    rng: &mut impl Rng,
) -> Option<&'a PathBuf> {
    if files.is_empty() {
        return None;
    }
    let weights: Vec<f64> = files.iter().map(|f| weight_for(f, w).max(0.0)).collect();
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return None;
    }
    let mut pick = rng.gen_range(0.0..total);
    for (f, wt) in files.iter().zip(weights.iter()) {
        if pick < *wt {
            return Some(f);
        }
        pick -= *wt;
    }
    files.last()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobWeight;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::collections::HashMap;

    fn weights() -> Weights {
        let mut files = HashMap::new();
        files.insert("noisy.pcap".to_string(), 0.0);
        files.insert("vip.pcap".to_string(), 5.0);
        Weights {
            default: 1.0,
            globs: vec![GlobWeight {
                pattern: "*modbus*".to_string(),
                weight: 3.0,
            }],
            files,
        }
    }

    #[test]
    fn precedence_exact_then_glob_then_default() {
        let w = weights();
        assert_eq!(weight_for(Path::new("/p/vip.pcap"), &w), 5.0);
        assert_eq!(weight_for(Path::new("/p/noisy.pcap"), &w), 0.0);
        assert_eq!(weight_for(Path::new("/p/site_modbus_1.pcap"), &w), 3.0);
        assert_eq!(weight_for(Path::new("/p/other.pcap"), &w), 1.0);
    }

    #[test]
    fn excluded_file_never_picked() {
        let w = weights();
        let files = vec![PathBuf::from("noisy.pcap")];
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        assert!(weighted_pick(&files, &w, &mut rng).is_none());
    }

    #[test]
    fn weighting_roughly_matches_proportions() {
        let w = Weights {
            default: 1.0,
            globs: vec![GlobWeight {
                pattern: "*heavy*".to_string(),
                weight: 3.0,
            }],
            files: HashMap::new(),
        };
        let files = vec![PathBuf::from("heavy.pcap"), PathBuf::from("light.pcap")];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut heavy = 0;
        let n = 20_000;
        for _ in 0..n {
            if weighted_pick(&files, &w, &mut rng).unwrap() == &files[0] {
                heavy += 1;
            }
        }
        let frac = heavy as f64 / n as f64;
        // Expect about 3/4.
        assert!(
            (frac - 0.75).abs() < 0.03,
            "heavy fraction {frac} not near 0.75"
        );
    }
}
