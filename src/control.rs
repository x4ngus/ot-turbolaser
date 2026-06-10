//! Operator control: up, down, pewpew, and the net-setup/net-teardown hooks
//! the systemd unit calls.
//!
//! The unit owns network setup so reboots and service restarts are
//! self-contained. `up`/`down` simply drive systemctl; `net-setup`/
//! `net-teardown` read the config and run the shell helpers; `pewpew` reads the
//! heartbeat file and reports health via the exit code (`status` is a deprecated
//! alias).

use crate::cli::{FireArgs, NetArgs, NetShowArgs, StatusArgs};
use crate::config::{self, MirrorMode};
use crate::ledger::Session;
use crate::netinfo::{self, Datapath};
use crate::scenario::guard_ledger_scenario;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn up(args: &FireArgs) -> i32 {
    match &args.scenario {
        // Run a scenario as the daemon via the templated unit. Pre-flight the pack
        // first so a missing or broken pack fails clearly here instead of the unit
        // crash-looping (the templated unit's StartLimit then trips, but catching
        // it up front is friendlier).
        Some(name) => {
            let cfg = match config::load_with_scenario(&args.config, Some(name)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("scenario {name}: {e}");
                    return 2;
                }
            };
            if let Err(e) = crate::scenario::preflight(&cfg) {
                eprintln!("scenario {name}: {e}");
                return 2;
            }
            let unit = format!("ot-turbolaser@{name}");
            println!("enabling and starting {unit}");
            run_systemctl(&["enable", "--now", &unit])
        }
        None => {
            let cfg = match config::load(&args.config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config: {e}");
                    return 2;
                }
            };
            // Refuse to fire the generic unit over a committed scenario plant: the
            // generic `run` refuses the scenario-tagged ledger and, with
            // Restart=always, would crash-loop. Point at the remedy instead.
            if let Ok(Some(s)) = Session::load(&cfg.session.path) {
                if let Err(e) = guard_ledger_scenario(s.scenario.as_deref(), None) {
                    eprintln!("refusing to fire generic red laser: {e}");
                    eprintln!("  to run that scenario:  turbolaser fire --scenario <name>");
                    return 2;
                }
            }
            println!("enabling and starting ot-turbolaser");
            run_systemctl(&["enable", "--now", "ot-turbolaser"])
        }
    }
}

pub fn down(args: &FireArgs) -> i32 {
    match &args.scenario {
        Some(name) => {
            let unit = format!("ot-turbolaser@{name}");
            println!("stopping and disabling {unit}");
            run_systemctl(&["disable", "--now", &unit])
        }
        None => {
            println!("stopping and disabling ot-turbolaser");
            run_systemctl(&["disable", "--now", "ot-turbolaser"])
        }
    }
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

/// `turbolaser net-show`: qualify the live datapath. Reads the kernel's own link
/// state and counters (not the daemon's self-report) and confirms frames egress
/// the replay port and reach the sensor port through the SPAN mirror, so one call
/// localises a "sensor sees nothing" fault between the appliance, the
/// bridge/mirror, and the sensor. Read-only.
pub fn net_show(args: &NetShowArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let replay = cfg.iface.clone();
    let bridge = cfg.net.bridge.clone();
    let sensor = cfg.net.sensor_port.clone();
    let mode = match cfg.net.mirror {
        MirrorMode::Tc => "tc",
        MirrorMode::Ovs => "ovs",
    };

    let replay_exists = netinfo::iface_exists(&replay);
    let sensor_exists = netinfo::iface_exists(&sensor);
    let bridge_exists = netinfo::iface_exists(&bridge) || ovs_bridge_exists(&bridge);
    let members = bridge_member_list(mode, &bridge);
    let bridge_physical_member = members.iter().find(|m| netinfo::is_physical(m)).cloned();
    let mirror_present = detect_mirror(mode, &replay, &sensor);

    // The live probe is the decisive check: sample both counters across a window
    // and see whether frames actually move to the sensor right now.
    let (tx_delta, rx_delta) = if args.probe_secs > 0 && replay_exists && sensor_exists {
        let tx0 = netinfo::sysfs_stat(&replay, "tx_packets");
        let rx0 = netinfo::sysfs_stat(&sensor, "rx_packets");
        std::thread::sleep(std::time::Duration::from_secs(args.probe_secs));
        let tx1 = netinfo::sysfs_stat(&replay, "tx_packets");
        let rx1 = netinfo::sysfs_stat(&sensor, "rx_packets");
        (counter_delta(tx0, tx1), counter_delta(rx0, rx1))
    } else {
        (None, None)
    };

    let d = Datapath {
        mirror_mode: mode.to_string(),
        replay: replay.clone(),
        bridge: bridge.clone(),
        sensor: sensor.clone(),
        replay_exists,
        replay_up: replay_exists && netinfo::link_up(&replay),
        replay_master: netinfo::master(&replay),
        bridge_exists,
        bridge_physical_member,
        sensor_exists,
        sensor_up: sensor_exists && netinfo::link_up(&sensor),
        sensor_promisc: netinfo::promisc(&sensor).unwrap_or(false),
        mirror_present,
        tx_delta,
        rx_delta,
    };
    let (health, findings) = netinfo::assess(&d);

    if args.json {
        let f: Vec<serde_json::Value> = findings
            .iter()
            .map(|x| {
                serde_json::json!({
                    "severity": format!("{:?}", x.severity).to_lowercase(),
                    "message": x.message,
                    "remedy": x.remedy,
                })
            })
            .collect();
        let out = serde_json::json!({
            "health": format!("{health:?}").to_lowercase(),
            "exit_code": health.exit_code(),
            "mirror_mode": d.mirror_mode,
            "replay": { "iface": d.replay, "exists": d.replay_exists, "up": d.replay_up,
                        "master": d.replay_master, "mtu": netinfo::mtu(&replay),
                        "tx_packets": netinfo::sysfs_stat(&replay, "tx_packets"),
                        "tx_dropped": netinfo::sysfs_stat(&replay, "tx_dropped"),
                        "tx_delta": d.tx_delta },
            "bridge": { "iface": d.bridge, "exists": d.bridge_exists,
                        "members": members, "physical_member": d.bridge_physical_member },
            "sensor": { "iface": d.sensor, "exists": d.sensor_exists, "up": d.sensor_up,
                        "promisc": d.sensor_promisc,
                        "rx_packets": netinfo::sysfs_stat(&sensor, "rx_packets"),
                        "rx_dropped": netinfo::sysfs_stat(&sensor, "rx_dropped"),
                        "rx_delta": d.rx_delta },
            "mirror_present": d.mirror_present,
            "findings": f,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        render_net_show(&cfg, &d, &members, &health, &findings, args.probe_secs);
    }
    health.exit_code()
}

/// The bridge's member ports: sysfs `brif` for a Linux bridge, `ovs-vsctl
/// list-ports` for OVS.
fn bridge_member_list(mode: &str, bridge: &str) -> Vec<String> {
    if mode == "ovs" {
        run_capture("ovs-vsctl", &["list-ports", bridge])
            .map(|s| {
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        netinfo::bridge_members(bridge)
    }
}

fn ovs_bridge_exists(bridge: &str) -> bool {
    run_capture("ovs-vsctl", &["list-br"])
        .map(|s| s.lines().any(|l| l.trim() == bridge))
        .unwrap_or(false)
}

/// Is a mirror/span from the replay port to the sensor port installed? tc parses
/// the mirred action on the replay port's clsact filters; OVS matches the sensor
/// port's uuid against the mirrors' output ports.
fn detect_mirror(mode: &str, replay: &str, sensor: &str) -> bool {
    if mode == "ovs" {
        let Some(uuid) = run_capture("ovs-vsctl", &["get", "port", sensor, "_uuid"]) else {
            return false;
        };
        let uuid = uuid.trim();
        if uuid.is_empty() {
            return false;
        }
        run_capture(
            "ovs-vsctl",
            &[
                "--format=csv",
                "--no-headings",
                "--columns=output_port",
                "list",
                "mirror",
            ],
        )
        .map(|s| s.contains(uuid))
        .unwrap_or(false)
    } else {
        // A tc-mirred mirror to the sensor shows on the replay port's egress (and
        // ingress) clsact filters as a "mirred ... to device <sensor>" action.
        let mut combined = String::new();
        for dir in ["egress", "ingress"] {
            if let Some(s) = run_capture("tc", &["filter", "show", "dev", replay, dir]) {
                combined.push_str(&s);
            }
        }
        combined.contains("mirred") && combined.contains(sensor)
    }
}

/// Run a read-only command and return its stdout, or None if the binary is
/// missing or it failed.
fn run_capture(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Delta between two counter samples, saturating (a counter reset reads as 0).
fn counter_delta(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(b.saturating_sub(a)),
        _ => None,
    }
}

fn render_net_show(
    cfg: &config::Config,
    d: &Datapath,
    members: &[String],
    health: &netinfo::Health,
    findings: &[netinfo::Finding],
    probe_secs: u64,
) {
    let onoff = |b: bool| if b { "up" } else { "DOWN" };
    println!(
        "turbolaser net-show  [{}]  ({} mirror)",
        format!("{health:?}").to_lowercase(),
        d.mirror_mode
    );

    println!("  -- replay port (tcpreplay TX, mirror source) --");
    println!(
        "    iface         : {} ({})",
        d.replay,
        if d.replay_exists {
            onoff(d.replay_up)
        } else {
            "MISSING"
        }
    );
    println!(
        "    bridge master : {}",
        d.replay_master.as_deref().unwrap_or("none")
    );
    if let Some(mtu) = netinfo::mtu(&d.replay) {
        println!("    mtu           : {mtu}");
    }
    println!(
        "    tx packets    : {}  (dropped {})",
        opt(netinfo::sysfs_stat(&d.replay, "tx_packets")),
        opt(netinfo::sysfs_stat(&d.replay, "tx_dropped"))
    );

    println!("  -- isolated bridge --");
    println!(
        "    iface         : {} ({})",
        d.bridge,
        if d.bridge_exists {
            "present"
        } else {
            "MISSING"
        }
    );
    println!(
        "    members       : {}",
        if members.is_empty() {
            "none".into()
        } else {
            members.join(", ")
        }
    );
    if let Some(m) = &d.bridge_physical_member {
        println!("    BREACH        : physical member {m} on the isolated bridge");
    }

    println!("  -- sensor port (mirror destination) --");
    println!(
        "    iface         : {} ({})",
        d.sensor,
        if d.sensor_exists {
            onoff(d.sensor_up)
        } else {
            "MISSING"
        }
    );
    println!(
        "    promiscuous   : {}",
        if d.sensor_promisc { "on" } else { "OFF" }
    );
    println!(
        "    rx packets    : {}  (dropped {})",
        opt(netinfo::sysfs_stat(&d.sensor, "rx_packets")),
        opt(netinfo::sysfs_stat(&d.sensor, "rx_dropped"))
    );

    println!("  -- mirror --");
    println!(
        "    span present  : {}",
        if d.mirror_present { "yes" } else { "NO" }
    );

    if probe_secs > 0 {
        println!("  -- live probe ({probe_secs}s) --");
        println!("    replay tx     : +{} frame(s)", opt(d.tx_delta));
        println!("    sensor rx     : +{} frame(s)", opt(d.rx_delta));
        println!(
            "    flowing       : {}",
            match (d.tx_delta, d.rx_delta) {
                (Some(tx), Some(rx)) if tx > 0 && rx > 0 => "yes (frames reach the sensor)",
                (Some(0), _) => "no tx (daemon idle/in a gap/stopped)",
                (Some(_), Some(0)) => "TX but NO RX (mirror/bridge not delivering)",
                _ => "unknown",
            }
        );
    } else {
        println!("  -- live probe skipped (--probe-secs 0) --");
    }

    // Fold in the daemon's heartbeat so net-show is the single triage surface.
    if let Ok(text) = std::fs::read_to_string(&cfg.paths.status_file) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
            println!("  -- daemon heartbeat --");
            println!(
                "    state         : {}",
                s("state").unwrap_or_else(|| "?".into())
            );
            if let Some(pps) = v.get("pps").and_then(|x| x.as_f64()) {
                println!("    packets/sec   : {pps:.0}");
            }
            if let Some(err) = s("last_error") {
                println!("    last_error    : {err}");
            }
        }
    }

    println!("  -- findings --");
    if findings.is_empty() {
        println!("    none: the datapath is healthy");
    } else {
        for f in findings {
            println!(
                "    [{}] {}",
                format!("{:?}", f.severity).to_lowercase(),
                f.message
            );
            if let Some(r) = &f.remedy {
                println!("        -> {r}");
            }
        }
    }
}

fn opt(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
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

    // Under a target scenario the laser reads `target:<name>`; show the active
    // attack, its current phase, and the ATT&CK-for-ICS techniques in play.
    if let Some(scenario) = s("scenario") {
        println!("  -- target scenario --");
        println!("    scenario      : {scenario}");
        println!("    phase         : {}", s("phase").unwrap_or("?"));
        if let Some(tids) = v.get("technique_ids").and_then(|x| x.as_array()) {
            let ids: Vec<&str> = tids.iter().filter_map(|t| t.as_str()).collect();
            if !ids.is_empty() {
                println!("    att&ck (ics)  : {}", ids.join(" "));
            }
        }
    }

    // The wire-footprint group applies to the whole red-laser family; a scenario
    // is reported by the dedicated `scenario` field rather than parsing `laser`.
    if laser == "red_laser" || s("scenario").is_some() {
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
    // pewpew reports the daemon's own counters; net-show qualifies that those
    // frames actually reach the sensor through the mirror.
    println!("  (datapath triage: turbolaser net-show)");
}

/// A u64 status field as a string, or "null" when absent.
fn opt_u(v: &serde_json::Value, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "null".into())
}
