//! The replay daemon loop. `turbolaser run` calls [`run`].
//!
//! Minimal for now: scan for a capture, fire it once with tcpreplay at the
//! configured rate, write the heartbeat, sleep, repeat. The coherent L3 remap,
//! weighted selection, gap sampling, and the watchdog arrive in later phases.
//! Fail safe: missing captures cause a sleep-and-retry, never a crash-loop.

mod replay;
mod signal;
pub mod status;

use crate::cli::RunArgs;
use crate::config::{self, Config};
use log::{error, info, warn};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use status::Status;

pub fn run(args: &RunArgs) -> i32 {
    init_logger();
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("config: {e}");
            return 1;
        }
    };
    info!("turbolaser starting: iface={} mode={:?}", cfg.iface, cfg.mode);

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
        if files.is_empty() {
            warn!(
                "no captures in {} or {}, sleeping {}s",
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

        // Phase 2: pick the first capture. Weighted selection arrives in Phase 5.
        let chosen = files[0].clone();
        let rate_args = cfg.rate.to_args();
        info!(
            "run={} file={} rate={:?}",
            run_counter,
            chosen.display(),
            cfg.rate.model
        );

        let mut s = base_status(&cfg, started, run_counter);
        s.state = "replaying".into();
        s.current_file = Some(chosen.display().to_string());
        write(&cfg, &mut s);

        match replay::run_once(&cfg.iface, &chosen, &rate_args) {
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

        if args.once {
            break;
        }

        // Phase 2: fixed inter-run gap. Distribution sampling arrives in Phase 5.
        let gap = 1.0_f64;
        s.state = "gap".into();
        s.next_gap_secs = Some(gap);
        write(&cfg, &mut s);
        signal::interruptible_sleep(gap, &shutdown);

        run_counter += 1;
    }

    let mut s = base_status(&cfg, started, run_counter);
    s.state = "stopping".into();
    write(&cfg, &mut s);
    info!("turbolaser stopped");
    0
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
                    Some(ext) if ext.eq_ignore_ascii_case("pcap") || ext.eq_ignore_ascii_case("pcapng") => {
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
