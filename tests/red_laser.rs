//! End-to-end of the red-laser engine short of tcpreplay: build it from a
//! config, run one tick, and confirm it fabricates devices, persists the
//! ledger, and emits an identity pcap tshark dissects with no malformed frames.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ot_turbolaser::ledger::{Session, SubnetRecord};
use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use ot_turbolaser::reload::pipeline::tshark_available;
use ot_turbolaser::simulate::engine::SimulatorEngine;
use ot_turbolaser::synth::eth;
use pcap_file::pcap::PcapHeader;

/// A minimal config for engine tests, with the given extra `synthesis:` lines.
fn cfg_yaml(dir: &Path, shm: &Path, session: &Path, synthesis: &str) -> String {
    format!(
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
{synthesis}
",
        base = dir.display(),
        shm = shm.display(),
        session = session.display(),
    )
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

#[test]
fn unsealed_saturated_session_cycles_zone_names() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    // Tiny fleet so the world saturates in one tick; cycle every run.
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  cycle_every_n_runs: 1\n  max_devices: 3",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0); // fabricates up to the cap; nothing to cycle yet
    assert_eq!(engine.ledger().cycle, 0, "no cycle while still fabricating");
    let before: Vec<String> = engine
        .ledger()
        .subnets
        .iter()
        .map(|s| s.zone_name.clone())
        .collect();

    engine.red_tick(1); // saturated (added == 0) at the cadence -> cycle
    assert_eq!(
        engine.ledger().cycle,
        1,
        "saturated unsealed session cycles"
    );
    let after: Vec<String> = engine
        .ledger()
        .subnets
        .iter()
        .map(|s| s.zone_name.clone())
        .collect();
    assert_ne!(before, after, "zone names are refreshed on a cycle");
}

#[test]
fn sealed_session_never_cycles() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    // A committed (sealed) ledger with one zone.
    let mut sealed = Session::new(1337, 0);
    sealed.add_subnet(SubnetRecord {
        cidr: "10.50.0.0/24".into(),
        zone_name: "L1 ABB Basic Control Area 1".into(),
        purdue_level: 1,
        vendor: Some("ABB".into()),
    });
    sealed.sealed = true;
    sealed.save_atomic(&session).unwrap();

    let yaml = cfg_yaml(dir.path(), &shm, &session, "  cycle_every_n_runs: 1");
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    let before = engine.ledger().subnets[0].zone_name.clone();
    engine.red_tick(1);
    engine.red_tick(2);
    assert_eq!(engine.ledger().cycle, 0, "sealed session never cycles");
    assert_eq!(
        engine.ledger().subnets[0].zone_name,
        before,
        "sealed zone names are stable"
    );
}

#[test]
fn remap_into_session_caches_and_reuses() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(dir.path(), &shm, &session, "  identity_every_n_runs: 1");
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0); // fabricate zones so the remap uses the into-zones path

    // A tiny capture with one remappable conversation.
    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = pool.join("sample.pcap");
    let frame = eth::udp_frame(
        [0x00, 0x00, 0xBC, 1, 2, 3],
        [0x00, 0x00, 0xBC, 4, 5, 6],
        Ipv4Addr::new(192, 168, 1, 5),
        Ipv4Addr::new(192, 168, 1, 9),
        50000,
        44818,
        b"x",
    );
    let cap = Capture {
        header: PcapHeader::default(),
        packets: vec![OwnedPacket {
            ts: Duration::new(1, 0),
            orig_len: frame.len() as u32,
            data: frame,
        }],
    };
    pcapio::write(&src, &cap).unwrap();

    let p1 = engine.remap_into_session(&cfg, &src, &[]).unwrap();
    assert!(p1.is_file(), "remap output written");
    // Corrupt the cache file: a cache hit must reuse it, not recompute it.
    std::fs::write(&p1, b"SENTINEL").unwrap();
    let p2 = engine.remap_into_session(&cfg, &src, &[]).unwrap();
    assert_eq!(p1, p2, "same cache path for identical (capture, seed)");
    assert_eq!(
        std::fs::read(&p2).unwrap(),
        b"SENTINEL",
        "cache was reused, not rewritten"
    );
}

/// Build a tiny capture of `n` distinct src hosts in 192.168.{base}.0/24 all
/// talking to one peer, written to `pool/<name>`.
fn write_capture(pool: &Path, name: &str, base: u8, hosts: u8) -> std::path::PathBuf {
    let mut packets = Vec::new();
    for i in 1..=hosts {
        let frame = eth::udp_frame(
            [0x00, 0x00, 0xBC, 1, 2, i],
            [0x00, 0x00, 0xBC, 9, 9, 9],
            Ipv4Addr::new(192, 168, base, i),
            Ipv4Addr::new(192, 168, base, 200),
            50000,
            44818,
            b"x",
        );
        packets.push(OwnedPacket {
            ts: Duration::new(1, 0),
            orig_len: frame.len() as u32,
            data: frame,
        });
    }
    let cap = Capture {
        header: PcapHeader::default(),
        packets,
    };
    let p = pool.join(name);
    pcapio::write(&p, &cap).unwrap();
    p
}

#[test]
fn reconcile_caps_assets_and_never_leaves_original_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    // Small fleet and a small total asset cap so the capture overflows it.
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_devices: 4\n  max_assets: 8",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0); // fabricate the small fleet and its zones

    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = write_capture(&pool, "many.pcap", 50, 30); // 31 distinct hosts

    let out = engine.remap_into_session(&cfg, &src, &[]).unwrap();
    let remapped = pcapio::read(&out).unwrap();
    assert!(!remapped.packets.is_empty(), "frames survive the remap");
    // Every address is inside a fabricated 10/8 zone; no original 192.168 leaks.
    for p in &remapped.packets {
        let s = [p.data[26], p.data[27], p.data[28], p.data[29]];
        let d = [p.data[30], p.data[31], p.data[32], p.data[33]];
        assert_eq!(s[0], 10, "src remapped into a fabricated zone: {s:?}");
        assert_eq!(d[0], 10, "dst remapped into a fabricated zone: {d:?}");
    }
    // The total wire-asset count never exceeds the plan cap.
    assert!(
        engine.ledger().total_wire_assets() <= 8,
        "total assets capped at the plan: {}",
        engine.ledger().total_wire_assets()
    );
    assert!(
        engine.ledger().capture_host_count() > 0,
        "some capture hosts were registered"
    );
    // The registry persisted to disk.
    let persisted = Session::load(&session).unwrap().unwrap();
    assert_eq!(
        persisted.capture_host_count(),
        engine.ledger().capture_host_count()
    );
}

#[test]
fn reconcile_registers_same_origins_regardless_of_capture_order() {
    let run = |swap: bool| -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let shm = dir.path().join("shm");
        let session = dir.path().join("session.json");
        let yaml = cfg_yaml(
            dir.path(),
            &shm,
            &session,
            "  identity_every_n_runs: 1\n  max_assets: 128",
        );
        let cfg_path = dir.path().join("replay.yaml");
        std::fs::write(&cfg_path, yaml).unwrap();
        let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();
        let mut engine = SimulatorEngine::red(&cfg, 0);
        engine.red_tick(0);
        let pool = dir.path().join("pool");
        std::fs::create_dir_all(&pool).unwrap();
        let a = write_capture(&pool, "a.pcap", 10, 3);
        let b = write_capture(&pool, "b.pcap", 20, 3);
        let (first, second) = if swap { (&b, &a) } else { (&a, &b) };
        engine.remap_into_session(&cfg, first, &[]).unwrap();
        engine.remap_into_session(&cfg, second, &[]).unwrap();
        let mut origins: Vec<String> = engine
            .ledger()
            .capture_hosts
            .iter()
            .map(|h| h.origin_ip.clone())
            .collect();
        origins.sort();
        origins
    };
    let normal = run(false);
    assert_eq!(
        normal,
        run(true),
        "the same origins register regardless of capture order"
    );
    assert!(
        !normal.is_empty(),
        "distinct hosts register under a generous cap"
    );
}

/// First-principles wire check: feed the red-laser remap a capture that mixes OT
/// conversations with the exact junk that leaked in the field (a foreign-MAC LLDP
/// frame, an IPv6 frame, an oversize frame, a broadcast ARP) and confirm the wire
/// carries only planned, coherent frames: every address in a fabricated 10/8
/// zone, every source MAC locally administered (no foreign OUI), nothing over the
/// MTU, no L2 or IPv6 chatter. tshark then confirms the surviving bytes dissect
/// clean. This is the plan==wire and unionised-asset guarantee on real output.
#[test]
fn wire_carries_only_planned_coherent_frames() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_devices: 8\n  max_assets: 64",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0); // fabricate the plant so the into-zones remap runs

    let foreign = [0x00, 0x1c, 0x06]; // a real vendor OUI (not locally administered)
    let udp = |sm: [u8; 6], s: Ipv4Addr, d: Ipv4Addr, dport: u16, pay: &[u8]| {
        let data = eth::udp_frame(sm, [0x00, 0x1c, 0x06, 9, 9, 9], s, d, 50000, dport, pay);
        OwnedPacket {
            ts: Duration::new(1, 0),
            orig_len: data.len() as u32,
            data,
        }
    };
    let raw = |d: Vec<u8>| OwnedPacket {
        ts: Duration::new(1, 0),
        orig_len: d.len() as u32,
        data: d,
    };
    let mut lldp = vec![
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0xe0, 0x62, 0x01, 0x02, 0x03, 0x88, 0xcc,
    ];
    lldp.extend(std::iter::repeat_n(0u8, 46));
    let mut ipv6 = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x86, 0xdd];
    ipv6.extend(std::iter::repeat_n(0u8, 40));
    ipv6[14] = 0x60;
    ipv6[22] = 0x20;
    let mut arp = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1c, 0x06, 9, 9, 9, 0x08, 0x06,
    ];
    arp.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]);
    arp.extend_from_slice(&[0x00, 0x1c, 0x06, 9, 9, 9]);
    arp.extend_from_slice(&[192, 168, 50, 30]);
    arp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    arp.extend_from_slice(&[192, 168, 50, 31]);

    let cap = Capture {
        header: PcapHeader::default(),
        packets: vec![
            udp(
                [0x00, 0x1c, 0x06, 1, 1, 1],
                Ipv4Addr::new(192, 168, 50, 10),
                Ipv4Addr::new(192, 168, 50, 20),
                50001,
                b"poll",
            ),
            udp(
                [0x00, 0x1c, 0x06, 2, 2, 2],
                Ipv4Addr::new(192, 168, 50, 11),
                Ipv4Addr::new(192, 168, 50, 21),
                50002,
                b"resp",
            ),
            raw(lldp),
            raw(ipv6),
            // Oversize (TSO-style) frame: remapped but dropped before the wire.
            udp(
                [0x00, 0x1c, 0x06, 4, 4, 4],
                Ipv4Addr::new(192, 168, 50, 40),
                Ipv4Addr::new(192, 168, 50, 41),
                50001,
                &[0u8; 2000],
            ),
            raw(arp),
        ],
    };
    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = pool.join("mixed.pcap");
    pcapio::write(&src, &cap).unwrap();

    let out = engine.remap_into_session(&cfg, &src, &[]).unwrap();
    let remapped = pcapio::read(&out).unwrap();

    // Only the two coherent conversations and the ARP survive; LLDP, IPv6, and the
    // oversize frame are dropped.
    assert_eq!(
        remapped.packets.len(),
        3,
        "only plan-coherent frames remain"
    );
    for p in &remapped.packets {
        let d = &p.data;
        assert!(d.len() <= 1514, "no frame exceeds the MTU");
        let ethertype = u16::from_be_bytes([d[12], d[13]]);
        assert_ne!(ethertype, 0x86dd, "no IPv6 on the wire");
        assert_ne!(ethertype, 0x88cc, "no LLDP/L2 chatter on the wire");
        // Source MAC is locally administered (a stable plan MAC), never a foreign
        // OUI carried over from the capture.
        assert_eq!(d[6] & 0x02, 0x02, "source MAC is locally administered");
        assert_ne!(&d[6..9], &foreign[..], "no foreign source OUI on the wire");
        match ethertype {
            0x0800 => {
                assert_eq!(d[26], 10, "IPv4 source in a planned 10/8 zone");
                assert_eq!(d[30], 10, "IPv4 destination in a planned 10/8 zone");
            }
            0x0806 => {
                assert_eq!(d[28], 10, "ARP sender in a planned 10/8 zone");
                assert_eq!(d[38], 10, "ARP target in a planned 10/8 zone");
            }
            other => panic!("unexpected ethertype {other:#06x} on the wire"),
        }
    }

    // tshark confirms the surviving bytes dissect with no malformed frames.
    if tshark_available() {
        let malformed = tshark(
            &out,
            &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
        );
        assert!(
            malformed.trim().is_empty(),
            "no malformed frames: {malformed}"
        );
    }
}
