//! The heartbeat file at /run/ot-turbolaser/status.json.
//!
//! Written atomically: serialize, write a temp file, fsync, rename over the
//! real path. A reader never sees a half-written file.

use serde::Serialize;
use std::io::{self, Write};
use std::path::Path;

#[derive(Serialize, Debug)]
pub struct Status {
    pub schema: u32,
    pub pid: u32,
    pub state: String,
    /// Deprecated duplicate of `laser`, kept for one release. Carries the
    /// canonical `red_laser`/`green_laser` value, not the old `variety`/`baseline`.
    pub mode: String,
    pub laser: String,
    pub iface: String,
    pub run: u64,
    pub current_file: Option<String>,
    pub l3_seed: Option<u64>,
    pub rate_model: String,
    pub last_run_packets: Option<u64>,
    pub total_tx_packets: Option<u64>,
    pub next_gap_secs: Option<f64>,
    pub last_error: Option<String>,
    pub updated_unix: u64,
    pub started_unix: u64,
}

pub fn write_atomic(path: &Path, status: &Status) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let json = serde_json::to_string_pretty(status).map_err(io::Error::other)?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
