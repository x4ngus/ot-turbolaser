//! Operator control: up, down, pewpew, and the net-setup/net-teardown hooks
//! the systemd unit calls.
//!
//! The unit owns network setup so reboots and service restarts are
//! self-contained. `up`/`down` simply drive systemctl; `net-setup`/
//! `net-teardown` read the config and run the shell helpers; `pewpew` reads the
//! heartbeat file and reports health via the exit code (`status` is a deprecated
//! alias).

use crate::cli::{FireArgs, NetArgs, NetShowArgs, StatusArgs};
use crate::config;
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
                    return crate::EX_CONFIG;
                }
            };
            if let Err(e) = crate::scenario::preflight(&cfg) {
                eprintln!("scenario {name}: {e}");
                return crate::EX_CONFIG;
            }
            // The unit's net-setup ExecStartPre needs the replay and sensor ports
            // to already exist (net-setup.sh exits 4 otherwise); catch a missing
            // one here so `fire` names it instead of leaving the operator with
            // systemctl's opaque "control process exited with error code".
            if let Err(e) = preflight_datapath(&cfg) {
                eprintln!("{e}");
                return crate::EX_CONFIG;
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
                    return crate::EX_CONFIG;
                }
            };
            // Refuse to fire the generic unit over a committed scenario plant: the
            // generic `run` refuses the scenario-tagged ledger and, with
            // Restart=always, would crash-loop. Point at the remedy instead.
            if let Ok(Some(s)) = Session::load(&cfg.session.path) {
                if let Err(e) = guard_ledger_scenario(s.scenario.as_deref(), None) {
                    eprintln!("refusing to fire generic red laser: {e}");
                    eprintln!("  to run that scenario:  turbolaser fire --scenario <name>");
                    return crate::EX_CONFIG;
                }
            }
            // Same datapath pre-flight as the scenario path: the generic unit's
            // net-setup ExecStartPre fails the same way on a missing port.
            if let Err(e) = preflight_datapath(&cfg) {
                eprintln!("{e}");
                return crate::EX_CONFIG;
            }
            println!("enabling and starting ot-turbolaser");
            run_systemctl(&["enable", "--now", "ot-turbolaser"])
        }
    }
}

/// Confirm `fire` can bring the unit up over this host's datapath. The replay
/// port (the daemon's TX) must exist; a missing one is named here rather than left
/// as systemctl's opaque "the control process exited with error code" when
/// net-setup's ExecStartPre fails. A missing *sensor* port is not an error: on a
/// hypervisor (Proxmox) the sensor tap lives on the host, so it is absent in this
/// container, net-setup no-ops, and the host owns the mirror (see
/// [`run_net_script`] and docs/proxmox.md).
///
/// Gated on `/sys/class/net`: [`netinfo::iface_exists`] reads sysfs, so off a Linux
/// host (a dev mac) every interface reads absent. Skipping there keeps `fire`
/// falling through to `run_systemctl`'s "no systemd" dev hint rather than a false
/// abort; on the appliance sysfs is present and the check runs. The classification
/// and message logic live in pure helpers so they are unit-tested without real
/// interfaces.
fn preflight_datapath(cfg: &config::Config) -> Result<(), String> {
    if !Path::new("/sys/class/net").is_dir() {
        return Ok(());
    }
    match datapath_kind(&cfg.iface, &cfg.net.sensor_port, netinfo::iface_exists) {
        // Both ports present (self-contained), or only the host-side sensor absent
        // (hypervisor-provided): fire proceeds. net-setup builds the local mirror in
        // the first case and no-ops in the second.
        DatapathKind::SelfContained | DatapathKind::HypervisorProvided => Ok(()),
        // The replay port is missing: the daemon cannot transmit. Name it and the
        // remedy instead of letting the unit fail opaquely.
        DatapathKind::Unprovisioned => Err(datapath_missing_msg(&missing_datapath_ifaces(
            &cfg.iface,
            &cfg.net.sensor_port,
            netinfo::iface_exists,
        ))),
    }
}

/// The configured ports the `exists` predicate reports absent, as (role, name)
/// pairs in (replay, sensor) order. Split from the live sysfs probe so the message
/// is unit-tested with a fake predicate.
fn missing_datapath_ifaces<'a>(
    replay: &'a str,
    sensor: &'a str,
    exists: impl Fn(&str) -> bool,
) -> Vec<(&'static str, &'a str)> {
    let mut missing = Vec::new();
    if !exists(replay) {
        missing.push(("replay port (iface)", replay));
    }
    if !exists(sensor) {
        missing.push(("sensor port (net.sensor_port)", sensor));
    }
    missing
}

/// Which deployment regime the configured datapath implies, decided from which
/// ports exist on this host. The sensor port is the signal: on a self-contained
/// host `turbolaser net-provision` creates both the replay and sensor ports, so
/// both exist; on a hypervisor (Proxmox) the sensor tap lives on the host, so it is
/// absent in this container and net-setup must no-op rather than try (and fail with
/// exit 4) to build a local mirror. "Ports already exist" alone cannot tell the two
/// apart, since net-provision makes them exist in the self-contained case too.
#[derive(Debug, PartialEq, Eq)]
enum DatapathKind {
    /// Replay and sensor ports both present: build the isolated bridge + mirror here.
    SelfContained,
    /// Replay present, sensor absent: the hypervisor/host provides the datapath and
    /// owns the mirror (Proxmox). net-setup is a no-op in this container.
    HypervisorProvided,
    /// Replay port absent: the daemon cannot transmit. A non-retryable error.
    Unprovisioned,
}

/// Classify the datapath from the two configured port names. Split from the live
/// sysfs probe so it is unit-tested with a fake predicate.
fn datapath_kind(replay: &str, sensor: &str, exists: impl Fn(&str) -> bool) -> DatapathKind {
    if !exists(replay) {
        DatapathKind::Unprovisioned
    } else if !exists(sensor) {
        DatapathKind::HypervisorProvided
    } else {
        DatapathKind::SelfContained
    }
}

/// The fail-fast message for missing datapath ports. Mirrors net-setup.sh's
/// guidance: the ports must be provisioned first and are not created by net-setup,
/// and (per the hard isolation invariant) the replay port must be a virtual link,
/// never a physical uplink.
fn datapath_missing_msg(missing: &[(&str, &str)]) -> String {
    use std::fmt::Write;
    let listed = missing
        .iter()
        .map(|(role, name)| format!("{role} '{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut m = String::new();
    let _ = write!(m, "datapath interface(s) not found: {listed}");
    m.push_str(
        "\n  net-setup does not create these. On a self-contained host run\
         \n  `turbolaser net-provision` to create the isolated veth pair, or point iface\
         \n  and net.sensor_port at interfaces this host already has (a veth or tap pair,\
         \n  never a physical uplink; on Proxmox the hypervisor provides them, see\
         \n  docs/proxmox.md). Then re-run `turbolaser fire`.",
    );
    m
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

/// `turbolaser net-provision`: create the isolated replay+sensor veth pair a
/// self-contained host needs before net-setup/`fire` can run. The port names come
/// from the config so they always match what the daemon and net-setup use. The
/// script refuses to touch a physical NIC, keeping the isolation invariant. On
/// Proxmox the hypervisor provides these ports, so this is not used there.
pub fn net_provision(args: &NetArgs) -> i32 {
    // Honor the same --scenario overlay the daemon uses, so a pack that overlays
    // iface/net.* provisions the ports it will actually transmit on (SP-8).
    let cfg = match config::load_with_scenario(&args.config, args.scenario.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return crate::EX_CONFIG;
        }
    };
    run_helper(
        "net-provision.sh",
        &[
            "--replay-port",
            &cfg.iface,
            "--sensor-port",
            &cfg.net.sensor_port,
        ],
    )
}

pub fn net_setup(args: &NetArgs) -> i32 {
    run_net_script("net-setup.sh", &args.config, args.scenario.as_deref())
}

pub fn net_teardown(args: &NetArgs) -> i32 {
    run_net_script("net-teardown.sh", &args.config, args.scenario.as_deref())
}

fn run_net_script(name: &str, config: &Path, scenario: Option<&str>) -> i32 {
    // Honor the same --scenario overlay as `run`, so net-setup/net-teardown build
    // and tear down the bridge/mirror on the ports the overlaid config names (SP-8).
    let cfg = match config::load_with_scenario(config, scenario) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return crate::EX_CONFIG;
        }
    };
    let is_setup = name == "net-setup.sh";
    // Auto-detect the deployment so the unit's net-setup/net-teardown is a clean
    // no-op on a hypervisor (Proxmox), where the host owns the mirror and the sensor
    // port is outside this container. Only meaningful where sysfs is present; off a
    // Linux host (a dev mac) fall through and let the script run/refuse as before.
    if Path::new("/sys/class/net").is_dir() {
        match datapath_kind(&cfg.iface, &cfg.net.sensor_port, netinfo::iface_exists) {
            DatapathKind::HypervisorProvided => {
                println!(
                    "sensor port '{}' absent on this host: the hypervisor/host provides the \
                     datapath and owns the mirror, skipping {} (see docs/proxmox.md)",
                    cfg.net.sensor_port,
                    if is_setup {
                        "net-setup"
                    } else {
                        "net-teardown"
                    }
                );
                return 0;
            }
            DatapathKind::Unprovisioned if is_setup => {
                // Replay port missing: the daemon cannot transmit. Non-retryable so
                // the unit fails clean instead of crash-looping on a doomed start.
                eprintln!(
                    "{}",
                    datapath_missing_msg(&missing_datapath_ifaces(
                        &cfg.iface,
                        &cfg.net.sensor_port,
                        netinfo::iface_exists,
                    ))
                );
                return crate::EX_CONFIG;
            }
            // Teardown with nothing provisioned: there is nothing to undo.
            DatapathKind::Unprovisioned => return 0,
            DatapathKind::SelfContained => {}
        }
    }
    let script = match resolve_script(name) {
        Some(p) => p,
        None => {
            eprintln!("could not find {name} in /opt/replay/scripts or ./scripts");
            return crate::EX_CONFIG;
        }
    };
    let mode = cfg.net.mirror.as_str();
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
            // net-setup.sh exit 4 is "interface not found": a non-retryable config
            // error, not a transient fault. Remap it so the unit fails clean.
            match s.code() {
                Some(4) if is_setup => crate::EX_CONFIG,
                Some(c) => c,
                None => 1,
            }
        }
        Err(e) => {
            eprintln!("could not run {name}: {e}");
            1
        }
    }
}

/// Resolve and run a helper script with explicit args, mapping its exit to ours.
/// Unlike [`run_net_script`] this passes the caller's args verbatim (net-provision
/// takes only the two port names, not the bridge/mirror flags net-setup needs).
fn run_helper(name: &str, args: &[&str]) -> i32 {
    let script = match resolve_script(name) {
        Some(p) => p,
        None => {
            eprintln!("could not find {name} in /opt/replay/scripts or ./scripts");
            return 2;
        }
    };
    match Command::new("bash").arg(&script).args(args).status() {
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
            return crate::EX_CONFIG;
        }
    };
    let replay = cfg.iface.clone();
    let bridge = cfg.net.bridge.clone();
    let sensor = cfg.net.sensor_port.clone();
    let mode = cfg.net.mirror.as_str();

    let replay_exists = netinfo::iface_exists(&replay);
    let sensor_exists = netinfo::iface_exists(&sensor);
    let bridge_exists = netinfo::iface_exists(&bridge) || ovs_bridge_exists(&bridge);
    let members = bridge_member_list(mode, &bridge);
    let bridge_physical_member = members.iter().find(|m| netinfo::is_physical(m)).cloned();
    let mirror_present = detect_mirror(mode, &replay, &sensor);

    // The live probe is the decisive check: sample tx/rx across a window and see
    // whether frames actually move to the sensor right now. The post-window
    // sample is also the counter we display, so each is read only once.
    let probe = args.probe_secs > 0 && replay_exists && sensor_exists;
    let (tx0, rx0) = if probe {
        (
            netinfo::sysfs_stat(&replay, "tx_packets"),
            netinfo::sysfs_stat(&sensor, "rx_packets"),
        )
    } else {
        (None, None)
    };
    if probe {
        std::thread::sleep(std::time::Duration::from_secs(args.probe_secs));
    }
    let replay_tx_packets = netinfo::sysfs_stat(&replay, "tx_packets");
    let sensor_rx_packets = netinfo::sysfs_stat(&sensor, "rx_packets");
    let (tx_delta, rx_delta) = if probe {
        (
            counter_delta(tx0, replay_tx_packets),
            counter_delta(rx0, sensor_rx_packets),
        )
    } else {
        (None, None)
    };

    // Gather the snapshot once; both renderers read from it, so the readout shows
    // the same instant the verdict was computed on.
    let d = Datapath {
        mirror_mode: mode.to_string(),
        replay: replay.clone(),
        bridge: bridge.clone(),
        sensor: sensor.clone(),
        replay_exists,
        replay_up: replay_exists && netinfo::link_up(&replay),
        replay_master: netinfo::master(&replay),
        replay_mtu: netinfo::mtu(&replay),
        bridge_exists,
        bridge_physical_member,
        sensor_exists,
        sensor_up: sensor_exists && netinfo::link_up(&sensor),
        sensor_promisc: netinfo::promisc(&sensor).unwrap_or(false),
        mirror_present,
        replay_tx_packets,
        replay_tx_dropped: netinfo::sysfs_stat(&replay, "tx_dropped"),
        sensor_rx_packets,
        sensor_rx_dropped: netinfo::sysfs_stat(&sensor, "rx_dropped"),
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
                        "master": d.replay_master, "mtu": d.replay_mtu,
                        "tx_packets": d.replay_tx_packets, "tx_dropped": d.replay_tx_dropped,
                        "tx_delta": d.tx_delta },
            "bridge": { "iface": d.bridge, "exists": d.bridge_exists,
                        "members": members, "physical_member": d.bridge_physical_member },
            "sensor": { "iface": d.sensor, "exists": d.sensor_exists, "up": d.sensor_up,
                        "promisc": d.sensor_promisc,
                        "rx_packets": d.sensor_rx_packets, "rx_dropped": d.sensor_rx_dropped,
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
    let iface_state = |exists: bool, up: bool| {
        if !exists {
            "MISSING"
        } else if up {
            "up"
        } else {
            "DOWN"
        }
    };
    println!(
        "turbolaser net-show  [{}]  ({} mirror)",
        format!("{health:?}").to_lowercase(),
        d.mirror_mode
    );

    println!("  -- replay port (tcpreplay TX, mirror source) --");
    println!(
        "    iface         : {} ({})",
        d.replay,
        iface_state(d.replay_exists, d.replay_up)
    );
    println!(
        "    bridge master : {}",
        d.replay_master.as_deref().unwrap_or("none")
    );
    if let Some(mtu) = d.replay_mtu {
        println!("    mtu           : {mtu}");
    }
    println!(
        "    tx packets    : {}  (dropped {})",
        opt(d.replay_tx_packets),
        opt(d.replay_tx_dropped)
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
        iface_state(d.sensor_exists, d.sensor_up)
    );
    println!(
        "    promiscuous   : {}",
        if d.sensor_promisc { "on" } else { "OFF" }
    );
    println!(
        "    rx packets    : {}  (dropped {})",
        opt(d.sensor_rx_packets),
        opt(d.sensor_rx_dropped)
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
            return crate::EX_CONFIG;
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

#[cfg(test)]
mod tests {
    use super::{datapath_kind, datapath_missing_msg, missing_datapath_ifaces, DatapathKind};

    #[test]
    fn both_ports_present_is_self_contained() {
        // net-provision made both ends of the veth pair: build the local mirror.
        assert_eq!(
            datapath_kind("tl0", "sens0", |_| true),
            DatapathKind::SelfContained
        );
    }

    #[test]
    fn replay_present_sensor_absent_is_hypervisor() {
        // Proxmox: eth1 is in the container, the sensor tap is on the host. net-setup
        // must no-op here rather than exit 4 looking for sens0.
        assert_eq!(
            datapath_kind("eth1", "sens0", |i| i == "eth1"),
            DatapathKind::HypervisorProvided
        );
    }

    #[test]
    fn replay_absent_is_unprovisioned() {
        // No replay port: the daemon cannot transmit, regardless of the sensor.
        assert_eq!(
            datapath_kind("tl0", "sens0", |i| i == "sens0"),
            DatapathKind::Unprovisioned
        );
        assert_eq!(
            datapath_kind("tl0", "sens0", |_| false),
            DatapathKind::Unprovisioned
        );
    }

    #[test]
    fn both_ports_present_yields_nothing_missing() {
        let missing = missing_datapath_ifaces("tl0", "sens0", |_| true);
        assert!(missing.is_empty(), "both present => fire proceeds");
    }

    #[test]
    fn absent_replay_port_is_reported() {
        // Only the replay port is missing; the sensor exists.
        let missing = missing_datapath_ifaces("tl0", "sens0", |i| i == "sens0");
        assert_eq!(missing, vec![("replay port (iface)", "tl0")]);
    }

    #[test]
    fn absent_sensor_port_is_reported() {
        let missing = missing_datapath_ifaces("tl0", "sens0", |i| i == "tl0");
        assert_eq!(missing, vec![("sensor port (net.sensor_port)", "sens0")]);
    }

    #[test]
    fn both_absent_reported_replay_first() {
        // The appliance regime that triggered the bug: neither port provisioned.
        let missing = missing_datapath_ifaces("tl0", "sens0", |_| false);
        assert_eq!(
            missing,
            vec![
                ("replay port (iface)", "tl0"),
                ("sensor port (net.sensor_port)", "sens0"),
            ],
            "both listed, replay before sensor"
        );
    }

    #[test]
    fn message_names_the_ifaces_and_the_remedy() {
        let missing = missing_datapath_ifaces("tl0", "sens0", |_| false);
        let msg = datapath_missing_msg(&missing);
        // Names both offending interfaces and their config keys.
        assert!(msg.contains("tl0") && msg.contains("sens0"), "names ifaces");
        assert!(msg.contains("iface") && msg.contains("net.sensor_port"));
        // Mirrors net-setup.sh's guidance and the isolation invariant.
        assert!(
            msg.contains("net-setup does not create these"),
            "states they are not auto-created: {msg}"
        );
        assert!(
            msg.contains("veth or tap") && msg.contains("never a physical uplink"),
            "points at provisioning a virtual, isolated pair: {msg}"
        );
        // Names the helper that fixes it and the retry command.
        assert!(
            msg.contains("turbolaser net-provision"),
            "names the provisioning command: {msg}"
        );
        assert!(msg.contains("turbolaser fire"), "names the retry command");
    }
}
