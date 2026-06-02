//! End-to-end of the red-laser engine short of tcpreplay: build it from a
//! config, run one tick, and confirm it fabricates devices, persists the
//! ledger, and emits an identity pcap tshark dissects with no malformed frames.

use std::path::Path;
use std::process::Command;

use ot_turbolaser::ledger::Session;
use ot_turbolaser::pcapio;
use ot_turbolaser::reload::pipeline::tshark_available;
use ot_turbolaser::simulate::engine::SimulatorEngine;

fn tshark(path: &Path, args: &[&str]) -> String {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(args)
        .output()
        .expect("run tshark");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn red_tick_fabricates_and_emits_dissectable_identities() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = format!(
        "iface: tl0
mode: red_laser
paths:
  pool: {base}/pool
  variants: {base}/variants
  shm_dir: {shm}
  status_file: {base}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 5.0
session:
  path: {session}
  seed: 1337
synthesis:
  identity_every_n_runs: 1
",
        base = dir.path().display(),
        shm = shm.display(),
        session = session.display(),
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).expect("config loads");

    let mut engine = SimulatorEngine::red(&cfg, 0);
    let pcap = engine
        .red_tick(0)
        .expect("first tick should fabricate and emit identities");

    // Devices were fabricated and the ledger persisted.
    assert!(engine.ledger().device_count() > 0);
    let persisted = Session::load(&session)
        .unwrap()
        .expect("ledger persisted to disk");
    assert_eq!(persisted.device_count(), engine.ledger().device_count());
    assert!(persisted.subnet_count() >= 1);

    // The emitted pcap is non-empty and re-readable.
    let cap = pcapio::read(&pcap).unwrap();
    assert!(!cap.packets.is_empty(), "identity pcap has frames");

    if !tshark_available() {
        eprintln!("tshark not found; skipping dissector validation");
        return;
    }
    let malformed = tshark(
        &pcap,
        &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
    );
    assert!(
        malformed.trim().is_empty(),
        "no malformed frames: {malformed}"
    );

    // At least one OT identity protocol dissects in the emitted burst.
    let any = ["enip", "mbtcp", "s7comm", "snmp"].iter().any(|p| {
        !tshark(&pcap, &["-Y", p, "-T", "fields", "-e", "frame.number"])
            .trim()
            .is_empty()
    });
    assert!(any, "an OT identity assertion should dissect");
}
