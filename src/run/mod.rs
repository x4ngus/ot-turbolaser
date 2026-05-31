//! The replay daemon loop. `turbolaser run` calls [`run`].
//!
//! Each iteration: rescan captures, weighted-pick one, in variety mode remap
//! its L3 addresses into tmpfs with a fresh seed, fire it once with tcpreplay
//! at the configured rate, write the heartbeat, sleep a sampled gap, repeat.
//! Fail safe: missing captures sleep and retry, never crash-loop. The watchdog
//! lands in a later phase.

mod gap;
mod replay;
mod seed;
mod selection;
mod signal;
pub mod status;

use crate::cli::RunArgs;
use crate::config::{self, Config, Mode};
use crate::proto::l3;
use ipnet::Ipv4Net;
use log::{error, info, warn};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use status::Status;

/// Skip the L3 remap for captures larger than this, to bound tmpfs use.
const MAX_SHM_BYTES: u64 = 256 * 1024 * 1024;

pub fn run(args: &RunArgs) -> i32 {
    init_logger();
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("config: {e}");
            return 1;
        }
    };

    let master = seed::master_seed(cfg.mode, cfg.seed);
    let hints = l3::parse_hints(&cfg.l3.subnets);
    let mut loop_rng = ChaCha8Rng::seed_from_u64(master);
    info!(
        "turbolaser starting: iface={} mode={:?} seed_master={:#018x}",
        cfg.iface, cfg.mode, master
    );

    let shutdown = signal::install_shutdown();
    let started = now_unix();
    let mut run_counter: u64 = 0;

    let mut s = base_status(&cfg, started, 0);
    s.state = "starting".into();
    write(&cfg, &mut s);

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let files = scan_pcaps(&cfg);
        let chosen = match selection::weighted_pick(&files, &cfg.weights, &mut loop_rng) {
            Some(p) => p.clone(),
            None => {
                warn!(
                    "no selectable captures in {} or {}, sleeping {}s",
                    cfg.paths.pool.display(),
                    cfg.paths.variants.display(),
                    cfg.no_pcaps_retry_secs
                );
                let mut s = base_status(&cfg, started, run_counter);
                s.state = "idle_no_pcaps".into();
                write(&cfg, &mut s);
                signal::interruptible_sleep(cfg.no_pcaps_retry_secs as f64, &shutdown);
                continue;
            }
        };

        let run_seed = seed::run_seed(master, run_counter);

        // Variety mode relocates L3 addresses per run into tmpfs. Baseline
        // keeps the asset set fixed and replays the capture as-is.
        let mut remapped: Option<PathBuf> = None;
        let mut l3_seed_used: Option<u64> = None;
        if cfg.mode == Mode::Variety && cfg.l3.remap {
            match remap_to_shm(&cfg, &chosen, &hints, run_seed) {
                Ok(p) => {
                    remapped = Some(p);
                    l3_seed_used = Some(run_seed);
                }
                Err(e) => warn!("L3 remap failed ({e}); replaying original"),
            }
        }
        let file_to_send: &Path = remapped.as_deref().unwrap_or(chosen.as_path());

        info!(
            "run={run_counter} file={} rate={:?} run_seed={:#018x}",
            chosen.display(),
            cfg.rate.model,
            run_seed
        );

        let mut s = base_status(&cfg, started, run_counter);
        s.state = "replaying".into();
        s.current_file = Some(chosen.display().to_string());
        s.l3_seed = l3_seed_used;
        write(&cfg, &mut s);

        match replay::run_once(&cfg.iface, file_to_send, &cfg.rate.to_args()) {
            Ok(res) if res.success => {
                info!("run={run_counter} done: {}", res.detail);
                s.last_run_packets = res.packets;
            }
            Ok(res) => {
                error!("run={run_counter} tcpreplay failed: {}", res.detail);
                s.last_error = Some(res.detail);
            }
            Err(e) => {
                error!("run={run_counter} could not launch tcpreplay: {e}");
                s.last_error = Some(e.to_string());
            }
        }

        if let Some(p) = &remapped {
            let _ = std::fs::remove_file(p);
        }

        if args.once {
            break;
        }

        let secs = gap::sample_gap(&cfg.gap, &mut loop_rng);
        info!("run={run_counter} inter-run gap {secs:.3}s");
        s.state = "gap".into();
        s.next_gap_secs = Some(secs);
        write(&cfg, &mut s);
        signal::interruptible_sleep(secs, &shutdown);

        run_counter += 1;
    }

    let mut s = base_status(&cfg, started, run_counter);
    s.state = "stopping".into();
    write(&cfg, &mut s);
    info!("turbolaser stopped");
    0
}

fn remap_to_shm(cfg: &Config, src: &Path, hints: &[Ipv4Net], seed: u64) -> Result<PathBuf, String> {
    let meta = std::fs::metadata(src).map_err(|e| format!("stat {}: {e}", src.display()))?;
    if meta.len() > MAX_SHM_BYTES {
        return Err(format!(
            "capture is {} bytes, over the {MAX_SHM_BYTES} byte tmpfs cap",
            meta.len()
        ));
    }
    std::fs::create_dir_all(&cfg.paths.shm_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.paths.shm_dir.display()))?;
    let mut cap = crate::pcapio::read(src)?;
    let summary = l3::remap_capture(&mut cap, hints, seed);
    let stem = src
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    let out = cfg.paths.shm_dir.join(format!("{stem}.remap.pcap"));
    crate::pcapio::write(&out, &cap)?;
    log::debug!(
        "L3 remap: {} hosts across {} subnets -> {}",
        summary.host_count,
        summary.subnets.len(),
        out.display()
    );
    Ok(out)
}

fn init_logger() {
    let env = env_logger::Env::default().default_filter_or("info");
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_secs()
        .try_init();
}

fn write(cfg: &Config, s: &mut Status) {
    s.updated_unix = now_unix();
    s.total_tx_packets = read_tx_packets(&cfg.iface);
    if let Err(e) = status::write_atomic(&cfg.paths.status_file, s) {
        warn!("could not write status file: {e}");
    }
}

fn base_status(cfg: &Config, started: u64, run: u64) -> Status {
    Status {
        schema: 1,
        pid: std::process::id(),
        state: String::new(),
        mode: format!("{:?}", cfg.mode).to_lowercase(),
        iface: cfg.iface.clone(),
        run,
        current_file: None,
        l3_seed: None,
        rate_model: format!("{:?}", cfg.rate.model).to_lowercase(),
        last_run_packets: None,
        total_tx_packets: None,
        next_gap_secs: None,
        last_error: None,
        updated_unix: 0,
        started_unix: started,
    }
}

fn scan_pcaps(cfg: &Config) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [&cfg.paths.variants, &cfg.paths.pool] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                match p.extension().and_then(|s| s.to_str()) {
                    Some(ext)
                        if ext.eq_ignore_ascii_case("pcap")
                            || ext.eq_ignore_ascii_case("pcapng") =>
                    {
                        out.push(p)
                    }
                    _ => {}
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn read_tx_packets(iface: &str) -> Option<u64> {
    let path = format!("/sys/class/net/{iface}/statistics/tx_packets");
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
