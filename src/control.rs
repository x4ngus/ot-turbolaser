//! Operator control: up, down, status, and the net-setup/net-teardown hooks
//! the systemd unit calls.
//!
//! The unit owns network setup so reboots and service restarts are
//! self-contained. `up`/`down` simply drive systemctl; `net-setup`/
//! `net-teardown` read the config and run the shell helpers; `status` reads the
//! heartbeat file and reports health via the exit code.

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

pub fn status(args: &StatusArgs) -> i32 {
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
        let field = |k: &str| -> String {
            match v.get(k) {
                Some(x) => match x.as_str() {
                    Some(t) => t.to_string(),
                    None => x.to_string(),
                },
                None => "null".into(),
            }
        };
        println!("state:        {state}");
        println!("mode:         {}", field("mode"));
        println!("laser:        {}", field("laser"));
        println!("iface:        {}", field("iface"));
        println!("run:          {}", field("run"));
        println!("current_file: {}", field("current_file"));
        println!("tx_packets:   {}", field("total_tx_packets"));
        println!("last_packets: {}", field("last_run_packets"));
        let zone_count = v.get("zone_count").and_then(|x| x.as_u64()).unwrap_or(0);
        let device_count = v.get("device_count").and_then(|x| x.as_u64()).unwrap_or(0);
        if zone_count > 0 || device_count > 0 {
            println!("zones:        {}", field("zone_count"));
            if device_count > 0 || v.get("device_cap").and_then(|x| x.as_u64()).unwrap_or(0) > 0 {
                println!(
                    "devices:      {} / {}",
                    field("device_count"),
                    field("device_cap")
                );
                println!("subnet cap:   {}", field("subnet_cap"));
            }
            if v.get("cycle").and_then(|x| x.as_u64()).unwrap_or(0) > 0 {
                println!("cycle:        {}", field("cycle"));
            }
            if let Some(t) = v.get("last_threat_unix").and_then(|x| x.as_u64()) {
                println!("last_threat:  {t}");
            }
            if let Some(zs) = v.get("zones").and_then(|x| x.as_array()) {
                for z in zs {
                    let c = z.get("cidr").and_then(|x| x.as_str()).unwrap_or("?");
                    let n = z.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    let d = z.get("devices").and_then(|x| x.as_u64()).unwrap_or(0);
                    println!("  {c:<18} {n} ({d} devices)");
                }
            }
        }
        println!("updated_unix: {}", field("updated_unix"));
        if let Some(err) = v.get("last_error").and_then(|x| x.as_str()) {
            println!("last_error:   {err}");
        }
    }
    match state {
        "replaying" | "gap" | "starting" => 0,
        "idle_no_pcaps" => 3,
        _ => 1,
    }
}
