//! Per-round manifest sidecar (TOML) and the out-dir index (JSON), so an
//! operator can see what each forged round contains.

use super::pipeline::RoundResult;
use crate::pcapio::Capture;
use crate::proto::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Serialize)]
pub struct Manifest {
    pub source: String,
    pub seed: u64,
    pub seed_hex: String,
    pub mode: String,
    pub frames: usize,
    pub duration_secs: f64,
    pub mutations: Vec<MutationEntry>,
    pub l3: Vec<L3Entry>,
}

#[derive(Serialize)]
pub struct MutationEntry {
    pub protocol: String,
    pub field: String,
    pub original: u64,
    pub new: u64,
}

#[derive(Serialize)]
pub struct L3Entry {
    pub old: String,
    pub new: String,
}

fn proto_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Modbus => "modbus",
        Protocol::Enip => "enip",
        Protocol::S7 => "s7",
        Protocol::Dnp3 => "dnp3",
    }
}

pub fn build(source: &str, seed: u64, mode: &str, cap: &Capture, result: &RoundResult) -> Manifest {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for p in &cap.packets {
        let t = p.ts.as_secs_f64();
        lo = lo.min(t);
        hi = hi.max(t);
    }
    let duration_secs = if lo.is_finite() && hi.is_finite() {
        (hi - lo).max(0.0)
    } else {
        0.0
    };

    // Mutations repeat per packet; collapse to the unique identifier rewrites.
    let mut seen = BTreeSet::new();
    let mut mutations = Vec::new();
    for m in &result.mutations {
        let pname = proto_name(m.protocol).to_string();
        if seen.insert((pname.clone(), m.field.clone(), m.original, m.new)) {
            mutations.push(MutationEntry {
                protocol: pname,
                field: m.field.clone(),
                original: m.original,
                new: m.new,
            });
        }
    }

    let l3 = result
        .l3
        .as_ref()
        .map(|s| {
            s.subnets
                .iter()
                .map(|(o, n)| L3Entry {
                    old: o.clone(),
                    new: n.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    Manifest {
        source: source.into(),
        seed,
        seed_hex: format!("{seed:x}"),
        mode: mode.into(),
        frames: result.frames,
        duration_secs,
        mutations,
        l3,
    }
}

pub fn write(path: &Path, m: &Manifest) -> Result<(), String> {
    let toml = toml::to_string_pretty(m).map_err(|e| e.to_string())?;
    std::fs::write(path, toml).map_err(|e| format!("{}: {e}", path.display()))
}

#[derive(Serialize, Deserialize)]
pub struct IndexEntry {
    pub file: String,
    pub seed: u64,
    pub frames: usize,
    pub mutations: usize,
}

/// Load the existing index so repeated reloads into one dir accumulate.
pub fn load_index(dir: &Path) -> Vec<IndexEntry> {
    std::fs::read_to_string(dir.join("index.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn write_index(dir: &Path, entries: &[IndexEntry]) -> Result<(), String> {
    let p = dir.join("index.json");
    let json = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
    std::fs::write(&p, json).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapio::{Capture, OwnedPacket};
    use crate::proto::MutationReport;
    use crate::reload::pipeline::RoundResult;
    use pcap_file::pcap::PcapHeader;
    use std::time::Duration;

    fn cap_with_ts(secs: &[u64]) -> Capture {
        Capture {
            header: PcapHeader::default(),
            packets: secs
                .iter()
                .map(|&s| OwnedPacket {
                    ts: Duration::new(s, 0),
                    orig_len: 0,
                    data: vec![0u8; 14],
                })
                .collect(),
        }
    }

    #[test]
    fn build_dedups_mutations_and_computes_duration() {
        let cap = cap_with_ts(&[1, 5]); // 4-second span
        let m = MutationReport {
            protocol: Protocol::Modbus,
            field: "unit_id".into(),
            original: 1,
            new: 9,
        };
        let result = RoundResult {
            mutations: vec![m.clone(), m.clone(), m], // the same rewrite, repeated
            l3: None,
            frames: 2,
        };
        let man = build("modbus", 0x10, "red_laser", &cap, &result);
        assert_eq!(man.duration_secs, 4.0);
        assert_eq!(
            man.mutations.len(),
            1,
            "repeated identical rewrites collapse"
        );
        assert_eq!(man.seed_hex, "10");
        assert_eq!(man.frames, 2);
    }

    #[test]
    fn build_zero_duration_for_empty_capture() {
        let cap = cap_with_ts(&[]);
        let result = RoundResult {
            mutations: vec![],
            l3: None,
            frames: 0,
        };
        let man = build("x", 0, "red_laser", &cap, &result);
        assert_eq!(
            man.duration_secs, 0.0,
            "no packets means zero span, not infinity"
        );
    }

    #[test]
    fn index_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            IndexEntry {
                file: "a.pcap".into(),
                seed: 1,
                frames: 10,
                mutations: 2,
            },
            IndexEntry {
                file: "b.pcap".into(),
                seed: 2,
                frames: 20,
                mutations: 0,
            },
        ];
        write_index(dir.path(), &entries).unwrap();
        let loaded = load_index(dir.path());
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].file, "a.pcap");
        assert_eq!(loaded[1].seed, 2);
        // A missing index loads as empty, not an error.
        let empty = tempfile::tempdir().unwrap();
        assert!(load_index(empty.path()).is_empty());
    }
}
