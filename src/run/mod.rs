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
    let cfg = match config::load_with_scenario(&args.config, args.scenario.as_deref()) {
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
    let started = crate::now_unix();
    let mut run_counter: u64 = 0;
    // Carried across iterations: the last completed run's packet count (so the
    // heartbeat is never null once a run finishes) and the tx-rate sampler (so
    // pps reflects the last real send rate, not a zero sampled between sends).
    let mut last_packets: Option<u64> = None;
    let mut pps_state = PpsState::new();

    // Red laser drives a persistent simulator (zones, devices, identity
    // assertions). Green laser only reads the OUI table to label derived zones.
    let mut engine = match cfg.mode {
        Mode::RedLaser => match SimulatorEngine::red(&cfg, started) {
            Ok(e) => {
                let scn = e
                    .scenario_name()
                    .map(|n| format!(" scenario={n}"))
                    .unwrap_or_default();
                info!(
                    "red laser session: seed={:#018x} devices={} zones={}{scn}",
                    e.seed(),
                    e.ledger().device_count(),
                    e.ledger().subnet_count()
                );
                Some(e)
            }
            Err(err) => {
                error!("red laser: {err}");
                return 1;
            }
        },
        Mode::GreenLaser => None,
    };
    let oui = OuiDb::load(&cfg.oui_db.path);

    let mut s = base_status(&cfg, started, 0, last_packets);
    s.state = "starting".into();
    write(&cfg, &mut s, &mut pps_state);

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
                let mut s = base_status(&cfg, started, run_counter, last_packets);
                s.state = "idle_no_pcaps".into();
                write(&cfg, &mut s, &mut pps_state);
                signal::interruptible_sleep(cfg.no_pcaps_retry_secs as f64, &shutdown);
                continue;
            }
        };

        // Red laser relocates L3 addresses per run into tmpfs. Green laser
        // keeps the asset set fixed and replays the capture as-is.
        let mut remapped: Option<PathBuf> = None;
        let mut l3_seed_used: Option<u64> = None;
        if cfg.mode == Mode::RedLaser && cfg.l3.remap {
            if let Some(e) = engine.as_mut() {
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
                        let mut s = base_status(&cfg, started, run_counter, last_packets);
                        s.state = "skipped_remap_failed".into();
                        s.last_error = Some(err);
                        write(&cfg, &mut s, &mut pps_state);
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
            promoted = e.maybe_promote(file_to_send, crate::now_unix());
        }
        let file_to_send: &Path = promoted.as_deref().unwrap_or(file_to_send);

        // Backstop: with the remap off, never emit a capture that still carries a
        // public source address. The promoted file is exempt; its external
        // source is the deliberate threat injection.
        if cfg.mode == Mode::RedLaser
            && cfg.l3.guard_public_sources
            && remapped.is_none()
            && promoted.is_none()
            && has_public_source(file_to_send, cfg.l3.max_remap_bytes)
        {
            warn!(
                "run={run_counter} {} carries a public source and remap is off; skipping",
                chosen.display()
            );
            let mut s = base_status(&cfg, started, run_counter, last_packets);
            s.state = "skipped_public_source".into();
            write(&cfg, &mut s, &mut pps_state);
            let secs = gap::sample_gap(&cfg.gap, &mut loop_rng);
            signal::interruptible_sleep(secs, &shutdown);
            run_counter += 1;
            continue;
        }

        info!(
            "run={run_counter} file={} rate={:?}",
            chosen.display(),
            cfg.rate.model
        );

        let mut s = base_status(&cfg, started, run_counter, last_packets);
        s.state = "replaying".into();
        s.current_file = Some(chosen.display().to_string());
        s.l3_seed = l3_seed_used;
        apply_sim_status(&mut s, &cfg, engine.as_ref(), &chosen, &oui, &hints);
        write(&cfg, &mut s, &mut pps_state);

        // The capture replays at this run's sampled rate; a banded mbps model
        // draws a fresh one per run so the wire fluctuates. The identity burst is
        // not sent at this rate (see below): it is self-paced by its own frame
        // timestamps, so the ARP bindings do not arrive as a microburst the
        // sensor drops before it can form the associations.
        let rate_args = cfg.rate.to_args_for_run(&mut loop_rng);

        match replay::run_once(&cfg.iface, file_to_send, &rate_args, &watchdog) {
            Ok(res) if res.success => {
                info!("run={run_counter} done: {}", res.detail);
                // Carry the count forward only on a successful parse, so a parse
                // miss keeps the last known value rather than nulling it.
                if res.packets.is_some() {
                    last_packets = res.packets;
                }
                s.last_run_packets = last_packets;
                // Record the achieved rate from tcpreplay's own stats; the
                // heartbeat reports it (held until the next run updates it).
                pps_state.record(res.pps, res.mbps);
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
        // a second short burst on the same wire, then refresh the heartbeat. The
        // burst is replayed at its own frame timing (empty rate args, so
        // tcpreplay honours the pcap timestamps spaced a millisecond apart)
        // rather than the capture's line rate, so the ARP resolutions arrive
        // paced over the burst instead of as one microburst the sensor drops.
        if let Some(e) = engine.as_mut() {
            if let Some(p) = e.red_tick(run_counter, crate::now_unix()) {
                match replay::run_once(&cfg.iface, &p, &[], &watchdog) {
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
            write(&cfg, &mut s, &mut pps_state);
        }

        if args.once {
            break;
        }

        let secs = gap::sample_gap(&cfg.gap, &mut loop_rng);
        info!("run={run_counter} inter-run gap {secs:.3}s");
        s.state = "gap".into();
        s.next_gap_secs = Some(secs);
        write(&cfg, &mut s, &mut pps_state);
        signal::interruptible_sleep(secs, &shutdown);

        run_counter += 1;
    }

    let mut s = base_status(&cfg, started, run_counter, last_packets);
    s.state = "stopping".into();
    write(&cfg, &mut s, &mut pps_state);
    info!("turbolaser stopped");
    0
}

fn init_logger() {
    let env = env_logger::Env::default().default_filter_or("info");
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_secs()
        .try_init();
}

fn write(cfg: &Config, s: &mut Status, rates: &mut PpsState) {
    s.updated_unix = crate::now_unix();
    s.total_tx_packets = crate::netinfo::sysfs_stat(&cfg.iface, "tx_packets");
    s.pps = rates.pps;
    s.mbps = rates.mbps;
    if let Err(e) = status::write_atomic(&cfg.paths.status_file, s) {
        warn!("could not write status file: {e}");
    }
}

/// The last completed run's achieved rate, taken from tcpreplay's own per-run
/// stats. The heartbeat is written several times per run (before the send, after
/// it, during the gap), and a NIC-counter rate sampled at whole-second
/// resolution rounds a sub-second run to zero. Sourcing the rate from the run
/// and holding the last positive reading keeps `pewpew` showing the real send
/// rate while replay is healthy, rather than a misleading zero.
struct PpsState {
    pps: Option<f64>,
    mbps: Option<f64>,
}

impl PpsState {
    fn new() -> Self {
        Self {
            pps: None,
            mbps: None,
        }
    }

    /// Record a completed run's measured rate, keeping the last positive reading
    /// so a parse miss or a zero-packet run does not blank the display.
    fn record(&mut self, pps: Option<f64>, mbps: Option<f64>) {
        if let Some(p) = pps {
            if p > 0.0 {
                self.pps = Some(p);
            }
        }
        if let Some(m) = mbps {
            if m > 0.0 {
                self.mbps = Some(m);
            }
        }
    }
}

fn base_status(cfg: &Config, started: u64, run: u64, last_packets: Option<u64>) -> Status {
    Status {
        schema: 4,
        pid: std::process::id(),
        state: String::new(),
        laser: cfg.mode.as_str().to_string(),
        iface: cfg.iface.clone(),
        run,
        current_file: None,
        l3_seed: None,
        rate_model: format!("{:?}", cfg.rate.model).to_lowercase(),
        last_run_packets: last_packets,
        total_tx_packets: None,
        pps: None,
        mbps: None,
        next_gap_secs: None,
        last_error: None,
        zone_count: 0,
        device_count: 0,
        device_cap: 0,
        subnet_cap: 0,
        capture_host_count: 0,
        total_wire_assets: 0,
        max_assets: 0,
        target_devices: 0,
        sealed: false,
        cycle: 0,
        last_threat_unix: None,
        zones: Vec::new(),
        scenario: None,
        phase: None,
        technique_ids: Vec::new(),
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
    s.max_assets = ledger::effective_asset_cap(cfg.synthesis.max_assets);
    match cfg.mode {
        Mode::RedLaser => {
            if let Some(e) = engine {
                let led = e.ledger();
                s.device_count = led.device_count();
                s.capture_host_count = led.capture_host_count();
                s.total_wire_assets = led.total_wire_assets();
                s.target_devices = led.target_devices;
                s.sealed = led.is_sealed();
                s.cycle = led.cycle;
                s.last_threat_unix = led.last_threat_unix;
                // Per-subnet device counts in one pass (shared ledger helper).
                let counts = led.device_counts_by_subnet();
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
                // Under a target scenario, surface the active attack and phase,
                // and label the laser `target:<name>` so `pewpew` reads clearly.
                s.scenario = e.scenario_name().map(String::from);
                s.phase = e.scenario_phase_label();
                s.technique_ids = e.scenario_techniques();
                if let Some(name) = e.scenario_name() {
                    s.laser = format!("target:{name}");
                }
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

/// True if any frame in the capture carries a routable address (public IPv4
/// unicast, a non-local IPv6 address, or a public ARP protocol address). The
/// leak backstop used when the remap is disabled. Fails closed (returns true) on
/// a file too large to inspect, an unreadable file, or any frame it cannot parse
/// and prove safe, so an inspection failure never lets a capture through.
fn has_public_source(path: &Path, max_bytes: u64) -> bool {
    match std::fs::metadata(path) {
        Ok(m) if m.len() > max_bytes => return true,
        Ok(_) => {}
        Err(_) => return true,
    }
    let Ok(cap) = crate::pcapio::read(path) else {
        return true;
    };
    cap.packets
        .iter()
        .any(|p| l3::carries_public_address(&p.data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_public_source_fails_closed_on_unreadable_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        // A non-pcap file cannot be inspected, so treat it as a leak.
        let bad = dir.path().join("garbage.pcap");
        std::fs::write(&bad, b"not a pcap").unwrap();
        assert!(
            has_public_source(&bad, u64::MAX),
            "unreadable capture fails closed"
        );
        // A file over the byte ceiling is never read, so fail closed.
        let big = dir.path().join("big.pcap");
        std::fs::write(&big, vec![0u8; 1024]).unwrap();
        assert!(has_public_source(&big, 16), "oversize capture fails closed");
        // A missing file fails closed too.
        assert!(has_public_source(&dir.path().join("nope.pcap"), u64::MAX));
    }

    #[test]
    fn scan_pcaps_filters_extensions_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["a.pcap", "b.pcapng", "c.txt", "d.PCAP"] {
            std::fs::write(dir.path().join(n), b"x").unwrap();
        }
        let mut cfg = config::load(std::path::Path::new("conf/replay.yaml")).unwrap();
        // Point both scan dirs at the same tempdir so dedup is exercised.
        cfg.paths.variants = dir.path().to_path_buf();
        cfg.paths.pool = dir.path().to_path_buf();
        let names: Vec<String> = scan_pcaps(&cfg)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"a.pcap".to_string()));
        assert!(names.contains(&"b.pcapng".to_string()));
        assert!(
            names.contains(&"d.PCAP".to_string()),
            "case-insensitive ext"
        );
        assert!(!names.contains(&"c.txt".to_string()), "non-pcap excluded");
        assert_eq!(names.len(), 3, "deduped across variants and pool");
    }

    #[test]
    fn status_serializes_without_mode_and_with_new_fields() {
        let cfg = config::load(std::path::Path::new("conf/replay.yaml")).unwrap();
        let s = base_status(&cfg, 100, 5, Some(42));
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("\"mode\""), "deprecated mode field is gone");
        assert!(json.contains("\"laser\""));
        assert!(json.contains("\"schema\":4"));
        for key in [
            "pps",
            "mbps",
            "capture_host_count",
            "total_wire_assets",
            "max_assets",
            "target_devices",
            "sealed",
            "scenario",
            "phase",
            "technique_ids",
        ] {
            assert!(json.contains(&format!("\"{key}\"")), "field {key} present");
        }
        // last_run_packets is seeded from the carried-forward value.
        assert!(json.contains("\"last_run_packets\":42"), "carried forward");
    }

    #[test]
    fn pps_state_holds_last_positive_rate_across_runs() {
        let mut st = PpsState::new();
        assert_eq!(st.pps, None, "no rate before any run");
        st.record(Some(2500.0), Some(10.0));
        assert_eq!(st.pps, Some(2500.0));
        assert_eq!(st.mbps, Some(10.0));
        // A run that reported no rate (parse miss, zero-packet) keeps the last.
        st.record(None, None);
        assert_eq!(st.pps, Some(2500.0), "missing rate holds the last reading");
        assert_eq!(st.mbps, Some(10.0));
        // A zero reading is ignored; a fresh positive run updates the display.
        st.record(Some(0.0), Some(0.0));
        assert_eq!(
            st.pps,
            Some(2500.0),
            "a zero rate does not blank the display"
        );
        st.record(Some(3000.0), Some(11.0));
        assert_eq!(st.pps, Some(3000.0));
        assert_eq!(st.mbps, Some(11.0));
    }

    #[test]
    fn green_laser_run_sequence_reproduces_from_master() {
        use crate::config::{GapCfg, GapDist, Weights};
        let master = seed::master_seed(Mode::GreenLaser, Some(0xABCD));
        let files: Vec<PathBuf> = ["a.pcap", "b.pcap", "c.pcap"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let weights = Weights::default();
        let gapcfg = GapCfg {
            dist: GapDist::ExpPoisson,
            mean_secs: Some(5.0),
            min_secs: Some(0.5),
            max_secs: Some(60.0),
            stddev_secs: None,
            lower_secs: None,
            upper_secs: None,
        };
        // The whole green-laser per-run sequence (capture order + gaps) is drawn
        // from one master-seeded RNG, so it reproduces across restarts.
        let run = || {
            let mut rng = ChaCha8Rng::seed_from_u64(master);
            let mut seq = Vec::new();
            for _ in 0..8 {
                let pick = selection::weighted_pick(&files, &weights, &mut rng).cloned();
                let gap = gap::sample_gap(&gapcfg, &mut rng);
                seq.push((pick, gap.to_bits()));
            }
            seq
        };
        assert_eq!(
            run(),
            run(),
            "green laser reproduces its capture-order and gap sequence from the master"
        );
    }
}
