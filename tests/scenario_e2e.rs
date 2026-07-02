//! End-to-end: a scenario daemon builds its pinned plant and appends the
//! playbook's attack frames to the identity burst.
//!
//! Drives the real `config::load_with_scenario` -> `SimulatorEngine::red` ->
//! `red_tick` path against a temp scenario pack, then inspects the emitted burst
//! pcap for the scenario's control-plane signature.

use std::fs;
use std::path::Path;

use ot_turbolaser::config;
use ot_turbolaser::oui::OuiDb;
use ot_turbolaser::pcapio;
use ot_turbolaser::scenario::{engine, plant, playbook};
use ot_turbolaser::simulate::engine::SimulatorEngine;
use ot_turbolaser::vuln::VulnDb;

fn write(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::write(path, body).unwrap();
}

/// True if any packet in the capture contains `needle` in its bytes.
fn capture_contains(path: &Path, needle: &[u8]) -> bool {
    let cap = pcapio::read(path).expect("burst pcap reads");
    cap.packets
        .iter()
        .any(|p| p.data.windows(needle.len()).any(|w| w == needle))
}

#[test]
fn scenario_run_pins_plant_and_emits_attack_frames() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");

    // A minimal but valid appliance config with all paths under the tempdir.
    write(
        &conf,
        &format!(
            "iface: tl0
mode: red_laser
paths:
  pool: {root}/pool
  variants: {root}/variants
  shm_dir: {root}/shm
  status_file: {root}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
session:
  path: {root}/session.json
",
            root = root.display()
        ),
    );

    let pack = root.join("conf").join("targets").join("teststx");
    // Stand-in IOC fidelity so the test never puts a real indicator on the wire.
    write(
        &pack.join("scenario.yaml"),
        "target:
  name: teststx
  description: integration scenario
  ioc_fidelity: standin
",
    );
    // Pin an S7 CPU (an embedded CVE profile) and a Modbus dosing controller.
    write(
        &pack.join("plant.yaml"),
        "zones:
  - { cidr: 10.20.10.0/24, name: 'Control L1', purdue_level: 1, vendor: 'Siemens AG' }
devices:
  - { zone: 10.20.10.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.20.10.11 }
  - { zone: 10.20.10.0/24, model: 'Modicon M340 BMXP342020', ip: 10.20.10.12 }
enrich: true
",
    );
    // One phase that stops the PLC and writes a rogue Modbus setpoint.
    write(
        &pack.join("playbook.yaml"),
        "phases:
  - id: impact
    name: Sabotage
    techniques: [T0837, T0836]
    events:
      - { emit: s7_stop, target: { ip: 10.20.10.11 } }
      - { emit: modbus_write, target: { ip: 10.20.10.12 }, register: 100, value: 11100 }
",
    );
    write(&pack.join("profiles.toml"), "");

    let cfg = config::load_with_scenario(&conf, Some("teststx")).expect("scenario config loads");
    assert!(cfg.target.is_some(), "target overlay active");

    let mut engine = SimulatorEngine::red(&cfg, 1_000).expect("scenario engine builds");
    assert_eq!(engine.scenario_name(), Some("teststx"));
    // The plant is pinned and sealed with the scenario tag.
    assert_eq!(engine.ledger().scenario.as_deref(), Some("teststx"));
    assert!(
        engine
            .ledger()
            .devices
            .iter()
            .any(|d| d.ip == "10.20.10.11"),
        "the S7 CPU is pinned"
    );

    // The first announce burst carries the identity assertions plus the attack
    // actions appended after them.
    let burst = engine.red_tick(0, 1_000).expect("a burst is produced");
    assert!(
        capture_contains(&burst, b"P_PROGRAM"),
        "the S7 PLC-STOP control action is on the wire"
    );
    // The rogue Modbus setpoint value 11100 (0x2B5C) rides a write register.
    assert!(
        capture_contains(&burst, &11100u16.to_be_bytes()),
        "the rogue Modbus setpoint is on the wire"
    );
}

#[test]
fn generic_run_refuses_a_scenario_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");
    write(
        &conf,
        &format!(
            "iface: tl0
mode: red_laser
paths:
  pool: {root}/pool
  variants: {root}/variants
  shm_dir: {root}/shm
  status_file: {root}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
session:
  path: {root}/session.json
",
            root = root.display()
        ),
    );
    let pack = root.join("conf").join("targets").join("teststx");
    write(&pack.join("scenario.yaml"), "target:\n  name: teststx\n");
    write(
        &pack.join("plant.yaml"),
        "zones:\n  - { cidr: 10.20.10.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.20.10.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.20.10.11 }\n",
    );
    write(
        &pack.join("playbook.yaml"),
        "phases:\n  - id: x\n    events: []\n",
    );
    write(&pack.join("profiles.toml"), "");

    // Build and persist the scenario plant.
    let scen_cfg = config::load_with_scenario(&conf, Some("teststx")).unwrap();
    SimulatorEngine::red(&scen_cfg, 0).expect("scenario plant persists");

    // A generic daemon (no --scenario) must refuse the scenario-tagged ledger.
    let generic_cfg = config::load_with_scenario(&conf, None).unwrap();
    let err = match SimulatorEngine::red(&generic_cfg, 0) {
        Ok(_) => panic!("a generic run must refuse the scenario-tagged ledger"),
        Err(e) => e,
    };
    assert!(err.contains("belongs to scenario"), "guard fired: {err}");
}

/// Every shipped scenario pack must merge, parse, pin a non-empty sealed plant,
/// and have a playbook whose explicit target IPs all exist in that plant. Guards
/// against a typo'd pack shipping broken.
#[test]
fn all_shipped_packs_are_internally_consistent() {
    let base = Path::new("conf/replay.yaml");
    for name in [
        "stuxnet",
        "triton",
        "oldsmar",
        "ukraine2015",
        "incontroller",
    ] {
        let cfg = config::load_with_scenario(base, Some(name))
            .unwrap_or_else(|e| panic!("{name} config: {e}"));
        let t = cfg.target.as_ref().expect("target present");

        let pb = playbook::Playbook::load(&t.pack_dir.join(&t.playbook))
            .unwrap_or_else(|e| panic!("{name} playbook: {e}"));
        assert!(!pb.phases.is_empty(), "{name} has phases");

        let spec = plant::PlantSpec::load(&t.pack_dir.join(&t.plant))
            .unwrap_or_else(|e| panic!("{name} plant: {e}"));
        let vuln = VulnDb::load_overlay(&t.pack_dir.join(&t.profiles));
        let s = plant::build_sealed_session(
            &spec,
            &vuln,
            &OuiDb::embedded(),
            1337,
            0,
            name,
            &cfg.dns.domains,
        )
        .unwrap_or_else(|e| panic!("{name} plant build: {e}"));
        assert!(
            s.is_sealed() && s.device_count() > 0,
            "{name} pins a sealed plant"
        );
        assert_eq!(s.scenario.as_deref(), Some(name));

        // Every playbook event that names an explicit ip must hit a pinned device.
        for ph in &pb.phases {
            for ev in &ph.events {
                if let Some(ip) = ev.target.as_ref().and_then(|d| d.ip.as_ref()) {
                    assert!(
                        s.devices.iter().any(|d| &d.ip == ip),
                        "{name}/{}: event targets ip {ip} which is not in the plant",
                        ph.id
                    );
                }
            }
        }

        // Drive the real playbook against the pinned plant and confirm the
        // scenario's signature control-plane PDU lands on the wire.
        let mut eng = engine::ScenarioEngine::load(t, s.seed)
            .unwrap_or_else(|e| panic!("{name} engine: {e}"));
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for n in 0..40u64 {
            frames.extend(eng.phase_frames(&s, &vuln, n));
        }
        let has = |needle: &[u8]| {
            frames
                .iter()
                .any(|f| f.windows(needle.len()).any(|w| w == needle))
        };
        let (label, signature): (&str, &[u8]) = match name {
            "stuxnet" => ("S7 PLC-STOP", b"P_PROGRAM"),
            "triton" => ("TriStation implant", b"imain"), // chunked into 6-byte download packets
            "oldsmar" => ("Modbus setpoint 11100", &[0x2b, 0x5c]), // 11100 big-endian
            "ukraine2015" => ("KillDisk share write", b"ADMIN$"),
            "incontroller" => ("Modbus setpoint 11100", &[0x2b, 0x5c]), // Schneider CODECALL write
            other => panic!("unexpected pack {other}"),
        };
        assert!(
            has(signature),
            "{name}: {label} signature not found on the wire"
        );
    }
}

/// Per-pack, per-event: every playbook event target resolves against the pinned
/// plant, checked with the same ip -> model -> asset_type logic the engine uses,
/// not just explicit-ip targets. `build_validated_plant` loads and validates the
/// playbook, pins the plant, then runs `validate_targets`, so a pack with any
/// orphaned target - a stray model or asset_type as well as an ip - fails here
/// rather than shipping green and emitting nothing for that event (SP-5). Pairs
/// with the negative `orphaned_playbook_target_is_rejected_at_preflight` below.
#[test]
fn every_shipped_pack_event_target_resolves() {
    let base = Path::new("conf/replay.yaml");
    for name in [
        "oldsmar",
        "stuxnet",
        "triton",
        "ukraine2015",
        "incontroller",
    ] {
        let cfg = config::load_with_scenario(base, Some(name))
            .unwrap_or_else(|e| panic!("{name} config: {e}"));
        let t = cfg.target.as_ref().expect("target present");
        let oui = OuiDb::embedded();
        ot_turbolaser::scenario::build_validated_plant(&cfg, t, &oui, 1337, 0)
            .unwrap_or_else(|e| panic!("{name}: every event target must resolve: {e}"));
    }
}

/// The pre-flight fidelity report (CAP-1) lists each event's resolved target and a
/// non-zero per-pass frame total, plus the IOC summary, so an operator sees what
/// will hit the wire before firing.
#[test]
fn fidelity_report_lists_resolved_targets_and_counts() {
    let base = Path::new("conf/replay.yaml");
    let cfg = config::load_with_scenario(base, Some("stuxnet")).expect("stuxnet loads");
    let report = ot_turbolaser::scenario::fidelity_report(&cfg)
        .expect("report builds")
        .expect("scenario present");
    assert!(
        report.contains("10.10.20.11") && report.contains("SIMATIC S7-417 CPU"),
        "names a resolved target ip and model: {report}"
    );
    assert!(
        report.contains("total attack frames per full pass:")
            && !report.contains("total attack frames per full pass: 0"),
        "reports a non-zero frame total: {report}"
    );
    assert!(
        report.contains("ioc fidelity") && report.contains("mypremierfutbol"),
        "reports the IOC summary including the C2 domain: {report}"
    );
    // A generic (no-target) config has no report.
    let generic = config::load_with_scenario(base, None).expect("generic loads");
    assert!(
        ot_turbolaser::scenario::fidelity_report(&generic)
            .expect("ok")
            .is_none(),
        "a generic config produces no fidelity report"
    );
}

/// `registry::discover` finds the five installed packs, sorted, each complete.
#[test]
fn discover_lists_the_shipped_packs() {
    let dir = ot_turbolaser::scenario::registry::targets_dir_for(Path::new("conf/replay.yaml"));
    let found = ot_turbolaser::scenario::registry::discover(&dir);
    let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "incontroller",
            "oldsmar",
            "stuxnet",
            "triton",
            "ukraine2015"
        ],
        "all five shipped packs, sorted"
    );
    for s in &found {
        assert!(
            s.has_playbook && s.has_plant && s.has_profiles,
            "{} ships a complete pack",
            s.name
        );
    }
}

/// Each shipped pack builds through the real daemon path (`SimulatorEngine::red`):
/// it pins and persists a sealed, scenario-tagged plant and renders a burst.
/// Complements the internal-consistency test by exercising session persistence
/// and the engine load, with all writable paths redirected into a tempdir.
#[test]
fn all_shipped_packs_build_through_the_daemon() {
    let base = Path::new("conf/replay.yaml");
    for name in [
        "stuxnet",
        "triton",
        "oldsmar",
        "ukraine2015",
        "incontroller",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut cfg =
            config::load_with_scenario(base, Some(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        // Never touch /var/lib or /dev/shm from a test.
        cfg.session.path = root.join("session.json");
        cfg.paths.shm_dir = root.join("shm");
        cfg.paths.status_file = root.join("status.json");

        let mut eng =
            SimulatorEngine::red(&cfg, 1_000).unwrap_or_else(|e| panic!("{name} red: {e}"));
        assert_eq!(eng.scenario_name(), Some(name));
        assert_eq!(eng.ledger().scenario.as_deref(), Some(name));
        assert!(
            eng.ledger().is_sealed() && eng.ledger().device_count() > 0,
            "{name} pins a sealed, non-empty plant"
        );
        assert!(
            cfg.session.path.is_file(),
            "{name} persisted its plant for the daemon to replay"
        );
        let burst = eng.red_tick(0, 1_000).expect("a burst is produced");
        assert!(
            pcapio::read(&burst)
                .map(|c| !c.packets.is_empty())
                .unwrap_or(false),
            "{name} emitted a non-empty identity+attack burst"
        );
    }
}

/// A pack with a broken playbook is rejected at pre-flight (`scenario::preflight`,
/// the path `check`/`plan`/`fire` run), not only when the daemon first starts.
#[test]
fn broken_playbook_is_rejected_at_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");
    write(
        &conf,
        &format!(
            "iface: tl0
mode: red_laser
paths:
  pool: {root}/pool
  variants: {root}/variants
  shm_dir: {root}/shm
  status_file: {root}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
session:
  path: {root}/session.json
",
            root = root.display()
        ),
    );
    let pack = root.join("conf").join("targets").join("bad");
    write(&pack.join("scenario.yaml"), "target:\n  name: bad\n");
    write(
        &pack.join("plant.yaml"),
        "zones:\n  - { cidr: 10.0.0.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.0.0.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.0.0.11 }\n",
    );
    // An unknown emit kind makes the playbook fail to parse.
    write(
        &pack.join("playbook.yaml"),
        "phases:\n  - id: x\n    events:\n      - { emit: not_a_real_emit }\n",
    );
    write(&pack.join("profiles.toml"), "");

    let cfg = config::load_with_scenario(&conf, Some("bad")).expect("config merges");
    let err = ot_turbolaser::scenario::preflight(&cfg).expect_err("broken playbook is rejected");
    assert!(
        err.contains("playbook"),
        "pre-flight names the playbook: {err}"
    );
}

/// A pack whose playbook targets a device absent from the plant is rejected at
/// pre-flight, not silently skipped (zero frames) at run time. This is the exact
/// gap that let a whole impact phase emit nothing while `check` reported OK.
#[test]
fn orphaned_playbook_target_is_rejected_at_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");
    write(
        &conf,
        &format!(
            "iface: tl0
mode: red_laser
paths:
  pool: {root}/pool
  variants: {root}/variants
  shm_dir: {root}/shm
  status_file: {root}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
session:
  path: {root}/session.json
",
            root = root.display()
        ),
    );
    let pack = root.join("conf").join("targets").join("orphan");
    write(&pack.join("scenario.yaml"), "target:\n  name: orphan\n");
    write(
        &pack.join("plant.yaml"),
        "zones:\n  - { cidr: 10.0.0.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.0.0.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.0.0.11 }\n",
    );
    // The impact phase stops a PLC in a subnet the plant never pins, so the target
    // resolves to no device.
    write(
        &pack.join("playbook.yaml"),
        "phases:\n  - id: impact\n    events:\n      - { emit: s7_stop, target: { ip: 192.0.2.99 } }\n",
    );
    write(&pack.join("profiles.toml"), "");

    let cfg = config::load_with_scenario(&conf, Some("orphan")).expect("config merges");
    let err = ot_turbolaser::scenario::preflight(&cfg).expect_err("orphaned target is rejected");
    assert!(
        err.contains("192.0.2.99"),
        "pre-flight names the unresolved target: {err}"
    );
}

/// A minimal valid red-laser base config under `root`, for preflight tests that
/// then drop a scenario pack under `<root>/conf/targets/<name>`.
fn base_conf(root: &Path) -> String {
    format!(
        "iface: tl0
mode: red_laser
paths:
  pool: {root}/pool
  variants: {root}/variants
  shm_dir: {root}/shm
  status_file: {root}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 1.0
session:
  path: {root}/session.json
",
        root = root.display()
    )
}

/// A declared, non-empty profiles.toml that does not parse is fatal at pre-flight,
/// not a silent fall-back to the embedded set: otherwise a plant model defined only
/// in that overlay would degrade to identity-only (CVE-less) while `check` reports
/// OK (SP-10).
#[test]
fn malformed_profiles_toml_is_fatal_at_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");
    write(&conf, &base_conf(root));
    let pack = root.join("conf").join("targets").join("badprof");
    write(&pack.join("scenario.yaml"), "target:\n  name: badprof\n");
    write(
        &pack.join("plant.yaml"),
        "zones:\n  - { cidr: 10.0.0.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.0.0.0/24, model: 'SIMATIC S7-300 CPU 315-2 PN/DP', ip: 10.0.0.11 }\n",
    );
    write(
        &pack.join("playbook.yaml"),
        "phases:\n  - id: recon\n    events:\n      - { emit: s7_read, target: { ip: 10.0.0.11 } }\n",
    );
    write(&pack.join("profiles.toml"), "not = valid toml [[[\n");

    let cfg = config::load_with_scenario(&conf, Some("badprof")).expect("config merges");
    let err = ot_turbolaser::scenario::preflight(&cfg).expect_err("malformed profiles is fatal");
    assert!(
        err.contains("malformed"),
        "pre-flight names the malformed profiles: {err}"
    );
}

/// A plant device that names a `model` (setting no identity-only fields) which
/// resolves to no CVE profile is flagged at pre-flight - a typo or a model the
/// profiles.toml forgot to define (SP-10). A genuinely identity-only device
/// (protocol/vendor set) with a descriptive model stays exempt.
#[test]
fn unresolved_cve_model_without_identity_fields_is_flagged_at_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let conf = root.join("conf").join("replay.yaml");
    write(&conf, &base_conf(root));
    let pack = root.join("conf").join("targets").join("typo");
    write(&pack.join("scenario.yaml"), "target:\n  name: typo\n");
    write(
        &pack.join("plant.yaml"),
        "zones:\n  - { cidr: 10.0.0.0/24, name: Z, purdue_level: 1 }\ndevices:\n  - { zone: 10.0.0.0/24, model: 'SIMATIC S7-317 TYPO', ip: 10.0.0.11 }\n",
    );
    write(
        &pack.join("playbook.yaml"),
        "phases:\n  - id: recon\n    events:\n      - { emit: s7_read, target: { ip: 10.0.0.11 } }\n",
    );
    write(&pack.join("profiles.toml"), "");

    let cfg = config::load_with_scenario(&conf, Some("typo")).expect("config merges");
    let err = ot_turbolaser::scenario::preflight(&cfg)
        .expect_err("an unresolved CVE-expecting model is flagged");
    assert!(
        err.contains("SIMATIC S7-317 TYPO"),
        "pre-flight names the unresolved model: {err}"
    );
}
