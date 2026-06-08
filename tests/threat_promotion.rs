//! End-to-end of external-threat host promotion: build the engine from a
//! config, force a due promotion against a capture with internal hosts, and
//! confirm a genuine host is re-originated externally, recorded in the ledger,
//! and the emitted pcap is clean.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use ot_turbolaser::proto::frame::parse_layout;
use ot_turbolaser::reload::pipeline::tshark_available;
use ot_turbolaser::simulate::engine::SimulatorEngine;
use ot_turbolaser::synth::eth::udp_frame;
use pcap_file::pcap::PcapHeader;

fn internal_capture() -> Capture {
    let a = udp_frame(
        [0x3c, 0x5a, 0xb4, 0, 0, 1], // desktop-class OUI
        [0x00, 0x0e, 0x8c, 0, 0, 2],
        Ipv4Addr::new(192, 168, 10, 5),
        Ipv4Addr::new(192, 168, 10, 9),
        1000,
        502,
        b"req",
    );
    let b = udp_frame(
        [0x00, 0x0e, 0x8c, 0, 0, 2],
        [0x3c, 0x5a, 0xb4, 0, 0, 1],
        Ipv4Addr::new(192, 168, 10, 9),
        Ipv4Addr::new(192, 168, 10, 5),
        502,
        1000,
        b"resp",
    );
    Capture {
        header: PcapHeader::default(),
        packets: [a, b]
            .into_iter()
            .map(|data| OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: data.len() as u32,
                data,
            })
            .collect(),
    }
}

#[test]
fn due_promotion_reoriginates_a_host_externally() {
    let dir = tempfile::tempdir().unwrap();
    let pool_pcap = dir.path().join("chatter.pcap");
    pcapio::write(&pool_pcap, &internal_capture()).unwrap();

    let yaml = format!(
        "iface: tl0
mode: red_laser
paths:
  pool: {base}/pool
  variants: {base}/variants
  shm_dir: {base}/shm
  status_file: {base}/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 5.0
session:
  path: {base}/session.json
  seed: 1337
threats:
  enabled: true
  external_cidrs: [\"203.0.113.0/24\"]
",
        base = dir.path().display(),
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    // Constructed at t=0; a promotion is never due before the 24h floor.
    let mut engine = SimulatorEngine::red(&cfg, 0).expect("red laser builds");
    assert!(
        engine.maybe_promote(&pool_pcap, 1).is_none(),
        "no promotion within the 24h floor"
    );

    // Far in the future, a promotion is due.
    let pcap = engine
        .maybe_promote(&pool_pcap, 2_000_000)
        .expect("a promotion is due well past the window");

    assert_eq!(engine.ledger().promoted.len(), 1, "promotion recorded");
    assert_eq!(engine.ledger().last_threat_unix, Some(2_000_000));
    let rec = &engine.ledger().promoted[0];
    assert!(rec.external_ip.starts_with("203.0.113."));
    assert!(rec.original_ip.starts_with("192.168.10."));

    // The emitted capture carries the external source address.
    let cap = pcapio::read(&pcap).unwrap();
    let has_external = cap.packets.iter().any(|p| {
        parse_layout(&p.data)
            .map(|l| p.data[l.l3 + 12] == 203)
            .unwrap_or(false)
    });
    assert!(
        has_external,
        "a frame now originates from the external range"
    );

    if tshark_available() {
        let malformed = tshark(
            &pcap,
            &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
        );
        assert!(malformed.trim().is_empty(), "no malformed frames");
    }
}

fn tshark(path: &Path, args: &[&str]) -> String {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(args)
        .output()
        .expect("run tshark");
    String::from_utf8_lossy(&out.stdout).into_owned()
}
