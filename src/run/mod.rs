//! The replay daemon loop. `turbolaser run` calls [`run`].
//!
//! Each iteration: rescan captures and weighted-pick one. In red-laser mode,
//! remap its L3 into tmpfs, optionally promote a host to an external threat
//! actor, fire the capture, then fire a second short burst of synthesized
//! device-identity and switch assertions. Green laser replays the capture as-is
//! and derives zones for the heartbeat. Either way write the heartbeat and sleep
//! a sampled gap. Fail safe: missing captures sleep and retry, never crash-loop;
//! the tx watchdog guards each send.

mod gap;
mod replay;
mod seed;
mod selection;
mod signal;
pub mod status;
mod watchdog;

use crate::cli::RunArgs;
use crate::config::{self, Config, Mode};
use crate::ledger;
use crate::oui::OuiDb;
use crate::proto::l3;
use crate::simulate::engine::SimulatorEngine;
use crate::simulate::zones;
use ipnet::Ipv4Net;
use log::{error, info, warn};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use status::{Status, StatusZone};

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
        "turbolaser starting: iface={} mode={} seed_master={:#018x}",
        cfg.iface,
        cfg.mode.as_str(),
        master
    );

    let shutdown = signal::install_shutdown();
    let watchdog = watchdog::Watchdog::spawn(
        cfg.iface.clone(),
        cfg.watchdog.poll_secs,
        cfg.watchdog.flatline_secs,
        shutdown.clone(),
    );
    let started = now_unix();
    let mut run_counter: u64 = 0;

    // Red laser drives a persistent simulator (zones, devices, identity
    // assertions). Green laser only reads the OUI table to label derived zones.
    let mut engine = match cfg.mode {
        Mode::RedLaser => {
            let e = SimulatorEngine::red(&cfg, started);
            info!(
                "red laser session: seed={:#018x} devices={} zones={}",
                e.seed(),
                e.ledger().device_count(),
                e.ledger().subnet_count()
            );
            Some(e)
        }
        Mode::GreenLaser => None,
    };
    let oui = OuiDb::load(&cfg.oui_db.path);

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

        // Red laser relocates L3 addresses per run into tmpfs. Green laser
        // keeps the asset set fixed and replays the capture as-is.
        let mut remapped: Option<PathBuf> = None;
        let mut l3_seed_used: Option<u64> = None;
        if cfg.mode == Mode::RedLaser && cfg.l3.remap {
            if let Some(e) = engine.as_ref() {
                match e.remap_into_session(&cfg, &chosen, &hints) {
                    Ok(p) => {
                        remapped = Some(p);
                        l3_seed_used = Some(e.seed());
                    }
                    Err(err) => {
                        // Fail closed: never replay the original addresses (which
                        // may be public). Skip this capture and try again.
                        warn!(
                            "run={run_counter} L3 remap failed ({err}); skipping capture to avoid emitting un-remapped addresses"
                        );
                        let mut s = base_status(&cfg, started, run_counter);
                        s.state = "skipped_remap_failed".into();
                        s.last_error = Some(err);
                        write(&cfg, &mut s);
                        let secs = gap::sample_gap(&cfg.gap, &mut loop_rng);
                        signal::interruptible_sleep(secs, &shutdown);
                        run_counter += 1;
                        continue;
                    }
                }
            }
        }
        let file_to_send: &Path = remapped.as_deref().unwrap_or(chosen.as_path());

        // Red laser: an infrequent (<=1/24h) external-threat promotion of a
        // genuine host in this capture, replacing the file to send when it fires.
        let mut promoted: Option<PathBuf> = None;
        if let Some(e) = engine.as_mut() {
            promoted = e.maybe_promote(file_to_send, now_unix());
        }
        let file_to_send: &Path = promoted.as_deref().unwrap_or(file_to_send);

        // Backstop: with the remap off, never emit a capture that still carries a
        // public source address. The promoted file is exempt; its external
        // source is the deliberate threat injection.
        if cfg.mode == Mode::RedLaser
            && cfg.l3.guard_public_sources
            && remapped.is_none()
            && promoted.is_none()
            && has_public_source(file_to_send)
        {
            warn!(
                "run={run_counter} {} carries a public source and remap is off; skipping",
                chosen.display()
            );
            let mut s = base_status(&cfg, started, run_counter);
            s.state = "skipped_public_source".into();
            write(&cfg, &mut s);
            let secs = gap::sample_gap(&cfg.gap, &mut loop_rng);
            signal::interruptible_sleep(secs, &shutdown);
            run_counter += 1;
            continue;
        }

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
        apply_sim_status(&mut s, &cfg, engine.as_ref(), &chosen, &oui, &hints);
        write(&cfg, &mut s);

        match replay::run_once(&cfg.iface, file_to_send, &cfg.rate.to_args(), &watchdog) {
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

        // The remapped capture is a cache entry kept for reuse across runs (the
        // engine bounds the cache). Only the one-shot promoted file is removed.
        if let Some(p) = &promoted {
            let _ = std::fs::remove_file(p);
        }

        // Red laser: fabricate and fire device identities and switch beacons as
        // a second short burst on the same wire, then refresh the heartbeat.
        if let Some(e) = engine.as_mut() {
            if let Some(p) = e.red_tick(run_counter) {
                match replay::run_once(&cfg.iface, &p, &cfg.rate.to_args(), &watchdog) {
                    Ok(res) if res.success => {
                        info!("run={run_counter} identities sent: {}", res.detail)
                    }
                    Ok(res) => warn!("run={run_counter} identity replay failed: {}", res.detail),
                    Err(err) => warn!("run={run_counter} identity replay error: {err}"),
                }
                let _ = std::fs::remove_file(&p);
            }
        }
        if engine.is_some() {
            apply_sim_status(&mut s, &cfg, engine.as_ref(), &chosen, &oui, &hints);
            write(&cfg, &mut s);
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
        schema: 2,
        pid: std::process::id(),
        state: String::new(),
        mode: cfg.mode.as_str().to_string(),
        laser: cfg.mode.as_str().to_string(),
        iface: cfg.iface.clone(),
        run,
        current_file: None,
        l3_seed: None,
        rate_model: format!("{:?}", cfg.rate.model).to_lowercase(),
        last_run_packets: None,
        total_tx_packets: None,
        next_gap_secs: None,
        last_error: None,
        zone_count: 0,
        device_count: 0,
        device_cap: 0,
        subnet_cap: 0,
        cycle: 0,
        last_threat_unix: None,
        zones: Vec::new(),
        updated_unix: 0,
        started_unix: started,
    }
}

/// Fill the zone and session fields of the heartbeat. Red laser reports its
/// ledger; green laser reports zones derived from the current capture.
fn apply_sim_status(
    s: &mut Status,
    cfg: &Config,
    engine: Option<&SimulatorEngine>,
    chosen: &Path,
    oui: &OuiDb,
    hints: &[Ipv4Net],
) {
    s.device_cap = ledger::effective_device_cap(cfg.synthesis.max_devices);
    s.subnet_cap = ledger::effective_subnet_cap(cfg.zones.max_subnets);
    match cfg.mode {
        Mode::RedLaser => {
            if let Some(e) = engine {
                let led = e.ledger();
                s.device_count = led.device_count();
                s.cycle = led.cycle;
                s.last_threat_unix = led.last_threat_unix;
                // Count devices per subnet in one O(devices) pass rather than
                // re-scanning every device for each zone.
                let mut counts: std::collections::HashMap<&str, usize> =
                    std::collections::HashMap::new();
                for d in &led.devices {
                    *counts.entry(d.subnet_cidr.as_str()).or_default() += 1;
                }
                s.zones = led
                    .subnets
                    .iter()
                    .map(|z| StatusZone {
                        cidr: z.cidr.clone(),
                        name: z.zone_name.clone(),
                        purdue_level: z.purdue_level,
                        devices: counts.get(z.cidr.as_str()).copied().unwrap_or(0),
                    })
                    .collect();
                s.zone_count = s.zones.len();
            }
        }
        Mode::GreenLaser => {
            if let Ok(cap) = crate::pcapio::read(chosen) {
                s.zones = zones::derive_zones(&cap, hints, oui)
                    .iter()
                    .map(|z| StatusZone {
                        cidr: z.cidr.to_string(),
                        name: z.name.clone(),
                        purdue_level: z.purdue_level,
                        devices: z.device_ips.len(),
                    })
                    .collect();
                s.zone_count = s.zones.len();
            }
        }
    }
}

pub(crate) fn scan_pcaps(cfg: &Config) -> Vec<PathBuf> {
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

/// True if any IPv4 source address in the capture is a public (non-RFC1918,
/// non-loopback, non-link-local) unicast address. Used as a leak backstop when
/// the remap is disabled.
fn has_public_source(path: &Path) -> bool {
    use crate::proto::frame::{parse_layout, L3Kind};
    let Ok(cap) = crate::pcapio::read(path) else {
        return false;
    };
    cap.packets.iter().any(|p| {
        let Some(l) = parse_layout(&p.data) else {
            return false;
        };
        if l.l3_kind != L3Kind::Ipv4 || p.data.len() < l.l3 + 16 {
            return false;
        }
        let src = std::net::Ipv4Addr::new(
            p.data[l.l3 + 12],
            p.data[l.l3 + 13],
            p.data[l.l3 + 14],
            p.data[l.l3 + 15],
        );
        let o0 = src.octets()[0];
        let unicast = o0 != 0 && o0 != 127 && o0 < 224;
        unicast && !src.is_private() && !src.is_loopback() && !src.is_link_local()
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
