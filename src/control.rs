//! Operator control: up, down, pewpew, and the net-setup/net-teardown hooks
//! the systemd unit calls.
//!
//! The unit owns network setup so reboots and service restarts are
//! self-contained. `up`/`down` simply drive systemctl; `net-setup`/
//! `net-teardown` read the config and run the shell helpers; `pewpew` reads the
//! heartbeat file and reports health via the exit code (`status` is a deprecated
//! alias).

use crate::cli::{NetArgs, StatusArgs};
use crate::config::{self, MirrorMode};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn up(args: &NetArgs) -> i32 {
    if let Err(e) = config::load(&args.config) {
        eprintln!("config: {e}");
        return 2;
    }
    println!("enabling and starting ot-turbolaser");
    run_systemctl(&["enable", "--now", "ot-turbolaser"])
}

pub fn down(_args: &NetArgs) -> i32 {
    println!("stopping and disabling ot-turbolaser");
    run_systemctl(&["disable", "--now", "ot-turbolaser"])
}

fn run_systemctl(args: &[&str]) -> i32 {
    match Command::new("systemctl").args(args).status() {
        Ok(s) if s.success() => 0,
        Ok(s) => {
            eprintln!("systemctl {} failed: {s}", args.join(" "));
            s.code().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("could not run systemctl ({e}).");
            eprintln!("On the appliance run as root. For dev without systemd, run");
            eprintln!("  turbolaser net-setup --config <cfg> && turbolaser run --config <cfg>");
            1
        }
    }
}

pub fn net_setup(args: &NetArgs) -> i32 {
    run_net_script("net-setup.sh", &args.config)
}

pub fn net_teardown(args: &NetArgs) -> i32 {
    run_net_script("net-teardown.sh", &args.config)
}

fn run_net_script(name: &str, config: &Path) -> i32 {
    let cfg = match config::load(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let script = match resolve_script(name) {
        Some(p) => p,
        None => {
            eprintln!("could not find {name} in /opt/replay/scripts or ./scripts");
            return 2;
        }
    };
    let mode = match cfg.net.mirror {
        MirrorMode::Tc => "tc",
        MirrorMode::Ovs => "ovs",
    };
    let status = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg(mode)
        .arg("--bridge")
        .arg(&cfg.net.bridge)
        .arg("--replay-port")
        .arg(&cfg.iface)
        .arg("--sensor-port")
        .arg(&cfg.net.sensor_port)
        .status();
    match status {
        Ok(s) if s.success() => 0,
        Ok(s) => {
            eprintln!("{name} exited with {s}");
            s.code().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("could not run {name}: {e}");
            1
        }
    }
}

/// Find a helper script. Prefers the installed location, then locations
/// relative to the running binary, then the current directory for dev use.
fn resolve_script(name: &str) -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/opt/replay/scripts").join(name)];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("scripts").join(name));
            if let Some(up) = dir.parent() {
                candidates.push(up.join("scripts").join(name));
            }
        }
    }
    candidates.push(PathBuf::from("scripts").join(name));
    candidates.into_iter().find(|p| p.is_file())
}

pub fn pewpew(args: &StatusArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let path = &cfg.paths.status_file;
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "no status at {} ({e}); is the daemon running?",
                path.display()
            );
            return 2;
        }
    };
    if args.json {
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    }
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bad status json: {e}");
            return 2;
        }
    };
    let state = v.get("state").and_then(|s| s.as_str()).unwrap_or("unknown");
    if !args.json {
        render_pewpew(&v, state);
    }
    match state {
        "replaying" | "gap" | "starting" => 0,
        "idle_no_pcaps" => 3,
        // The skipped_* states (a capture deliberately not sent) and the clean
        // stopping state are healthy, not failures.
        "skipped_remap_failed" | "skipped_public_source" | "stopping" => 0,
        _ => 1,
    }
}

/// The human readout: a header, the wire-footprint-vs-plan group (red laser),
/// the zone list, and the throughput-and-runtime group.
fn render_pewpew(v: &serde_json::Value, state: &str) {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str());
    let u = |k: &str| v.get(k).and_then(|x| x.as_u64());
    let f = |k: &str| v.get(k).and_then(|x| x.as_f64());
    let laser = s("laser").unwrap_or("?");
    let iface = s("iface").unwrap_or("?");
    println!("turbolaser pewpew  [{state}]  {laser} on {iface}");

    if laser == "red_laser" {
        let device_count = u("device_count").unwrap_or(0);
        let capture = u("capture_host_count").unwrap_or(0);
        let total = u("total_wire_assets").unwrap_or(0);
        let max_assets = u("max_assets").unwrap_or(0);
        let target = u("target_devices").unwrap_or(0);
        let sealed = v.get("sealed").and_then(|x| x.as_bool()).unwrap_or(false);
        println!("  -- wire footprint vs plan --");
        println!(
            "    assets        : {total} / {max_assets}  ({device_count} fabricated, {capture} capture-derived)"
        );
        if target > 0 {
            println!("    planned fleet : {target} fabricated  (sealed: {sealed})");
        }
        println!(
            "    zones         : {} / {}",
            u("zone_count").unwrap_or(0),
            u("subnet_cap").unwrap_or(0)
        );
        // The wire must never exceed the plan, and a sealed fleet must match its
        // target; either divergence is drift.
        let drift = (max_assets > 0 && total > max_assets)
            || (sealed && target > 0 && device_count != target);
        println!(
            "    drift         : {}",
            if drift {
                "DRIFT (wire diverges from plan)"
            } else {
                "none"
            }
        );
        if let Some(c) = u("cycle").filter(|&c| c > 0) {
            println!("    cycle         : {c}");
        }
        if let Some(t) = u("last_threat_unix") {
            println!("    last threat   : {t}");
        }
    }

    if let Some(zs) = v.get("zones").and_then(|x| x.as_array()) {
        if !zs.is_empty() {
            println!("  -- zones --");
            for z in zs {
                let c = z.get("cidr").and_then(|x| x.as_str()).unwrap_or("?");
                let n = z.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                let d = z.get("devices").and_then(|x| x.as_u64()).unwrap_or(0);
                println!("    {c:<18} {n} ({d} devices)");
            }
        }
    }

    println!("  -- throughput & runtime --");
    println!("    run           : {}", u("run").unwrap_or(0));
    if let Some(cf) = s("current_file") {
        println!("    current file  : {cf}");
    }
    println!("    last packets  : {}", opt_u(v, "last_run_packets"));
    println!("    tx packets    : {}", opt_u(v, "total_tx_packets"));
    println!(
        "    packets/sec   : {}",
        f("pps")
            .map(|p| format!("{p:.0}"))
            .unwrap_or_else(|| "null".into())
    );
    println!(
        "    throughput    : {}",
        f("mbps")
            .map(|m| format!("{m:.1} Mbps"))
            .unwrap_or_else(|| "null".into())
    );
    if let Some(g) = f("next_gap_secs") {
        println!("    next gap      : {g:.1}s");
    }
    let updated = u("updated_unix").unwrap_or(0);
    let started = u("started_unix").unwrap_or(0);
    if started > 0 && updated >= started {
        println!("    uptime        : {}s", updated - started);
    }
    println!("    updated_unix  : {updated}");
    if let Some(err) = s("last_error") {
        println!("    last_error    : {err}");
    }
}

/// A u64 status field as a string, or "null" when absent.
fn opt_u(v: &serde_json::Value, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "null".into())
}
