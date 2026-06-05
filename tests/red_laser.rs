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

/// Parse a colon-separated MAC string to bytes (test helper).
fn parse_mac6(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, part) in s.split(':').enumerate().take(6) {
        m[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    m
}

/// One ARP frame's salient fields: (eth_dst, opcode, sender_mac, sender_ip).
type ArpView = ([u8; 6], u16, [u8; 6], [u8; 4]);

/// The ARP frames in a capture, as (eth_dst, opcode, sender_mac, sender_ip).
fn arp_frames(cap: &Capture) -> Vec<ArpView> {
    cap.packets
        .iter()
        .filter(|p| p.data.len() >= 42 && u16::from_be_bytes([p.data[12], p.data[13]]) == 0x0806)
        .map(|p| {
            let mut dst = [0u8; 6];
            dst.copy_from_slice(&p.data[0..6]);
            let oper = u16::from_be_bytes([p.data[20], p.data[21]]);
            let mut sha = [0u8; 6];
            sha.copy_from_slice(&p.data[22..28]);
            let spa = [p.data[28], p.data[29], p.data[30], p.data[31]];
            (dst, oper, sha, spa)
        })
        .collect()
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
        .red_tick(0, 0)
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
    engine.red_tick(0, 0); // fabricates up to the cap; nothing to cycle yet
    assert_eq!(engine.ledger().cycle, 0, "no cycle while still fabricating");
    let before: Vec<String> = engine
        .ledger()
        .subnets
        .iter()
        .map(|s| s.zone_name.clone())
        .collect();

    engine.red_tick(1, 60); // saturated (added == 0) at the cadence -> cycle
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
    engine.red_tick(1, 60);
    engine.red_tick(2, 120);
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
    engine.red_tick(0, 0); // fabricate zones so the remap uses the into-zones path

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

#[test]
fn startup_purges_stale_remap_cache() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    // A stale cache file an earlier binary might have left (reused verbatim on a
    // hit). Engine startup must purge it so a poisoned remap never outlives the
    // binary that wrote it.
    let cache = shm.join("remap-cache");
    std::fs::create_dir_all(&cache).unwrap();
    let stale = cache.join("v2.00000000deadbeef.g0.b.0.0.old.pcap");
    std::fs::write(&stale, b"poison").unwrap();

    let yaml = cfg_yaml(dir.path(), &shm, &session, "  identity_every_n_runs: 1");
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let _engine = SimulatorEngine::red(&cfg, 0);
    assert!(
        !stale.exists(),
        "a stale remap-cache file is purged on engine startup"
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
    engine.red_tick(0, 0); // fabricate the small fleet and its zones

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
        engine.red_tick(0, 0);
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

/// The remap rewrites L3 headers but not payloads, so a discovery frame (NBNS,
/// DHCP, DNS, SSDP) embeds the original host address in its payload even after
/// the header is remapped, and a sensor reads it as a phantom asset on the
/// original address. This is the 4SICS field leak (192.168.10.131 surfacing as a
/// bound asset). Confirm no original address survives the remap anywhere.
#[test]
fn remap_drops_payload_embedded_original_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_assets: 64",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();
    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0, 0); // fabricate the plant so the into-zones remap runs

    let owned = |data: Vec<u8>| OwnedPacket {
        ts: Duration::new(1, 0),
        orig_len: data.len() as u32,
        data,
    };
    // An OT conversation enumerates .5 and .9 (so both become remap map keys),
    // plus a NBNS-style broadcast from .5 whose payload embeds .9's original IP.
    let conv = eth::udp_frame(
        [0x00, 0x00, 0xbc, 1, 1, 1],
        [0x00, 0x00, 0xbc, 2, 2, 2],
        Ipv4Addr::new(192, 168, 50, 5),
        Ipv4Addr::new(192, 168, 50, 9),
        50001,
        502,
        b"poll",
    );
    let mut nbns = eth::udp_frame(
        [0x00, 0x00, 0xbc, 1, 1, 1],
        [0xff; 6],
        Ipv4Addr::new(192, 168, 50, 5),
        Ipv4Addr::new(255, 255, 255, 255),
        137,
        137,
        b"NAME",
    );
    nbns.extend_from_slice(&[192, 168, 50, 9]); // original peer IP embedded in payload
    let cap = Capture {
        header: PcapHeader::default(),
        packets: vec![owned(conv), owned(nbns)],
    };
    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = pool.join("nbns.pcap");
    pcapio::write(&src, &cap).unwrap();

    let out = engine.remap_into_session(&cfg, &src, &[]).unwrap();
    let remapped = pcapio::read(&out).unwrap();
    for p in &remapped.packets {
        for orig in [[192u8, 168, 50, 5], [192, 168, 50, 9]] {
            assert!(
                !p.data.windows(4).any(|w| w == orig),
                "original address {orig:?} leaked into the wire (header or payload)"
            );
        }
    }
}

/// First-principles wire check: feed the red-laser remap a capture that mixes OT
/// conversations with the exact junk that leaked in the field (a foreign-MAC LLDP
/// frame, an IPv6 frame, an oversize frame, a broadcast ARP) and confirm the wire
/// carries only planned, coherent frames: every address in a fabricated 10/8
/// zone, every source MAC globally administered (a stable plan MAC, no foreign
/// OUI), nothing over the MTU, no L2 or IPv6 chatter. tshark then confirms the
/// surviving bytes dissect
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
    engine.red_tick(0, 0); // fabricate the plant so the into-zones remap runs

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

    // Only the two coherent OT conversations survive. LLDP, IPv6, and the
    // oversize frame are dropped as incoherent or over-MTU; the capture's own
    // broadcast ARP is thinned (the synth burst supplies controlled bindings).
    assert_eq!(
        remapped.packets.len(),
        2,
        "only plan-coherent OT frames remain"
    );
    for p in &remapped.packets {
        let d = &p.data;
        assert!(d.len() <= 1514, "no frame exceeds the MTU");
        let ethertype = u16::from_be_bytes([d[12], d[13]]);
        assert_ne!(ethertype, 0x86dd, "no IPv6 on the wire");
        assert_ne!(ethertype, 0x88cc, "no LLDP/L2 chatter on the wire");
        assert_ne!(ethertype, 0x0806, "capture ARP is thinned, not replayed");
        // Source MAC is globally administered (a stable plan MAC), never a
        // foreign OUI carried over from the capture. Globally administered
        // matters: a passive sensor ignores LAA MACs for asset association, so an
        // LAA source MAC would never bind MAC<->IP.
        assert_eq!(
            d[6] & 0x02,
            0x00,
            "source MAC is globally administered (the sensor ignores LAA MACs)"
        );
        assert_ne!(&d[6..9], &foreign[..], "no foreign source OUI on the wire");
        assert_eq!(ethertype, 0x0800, "only IPv4 OT traffic on the wire");
        assert_eq!(d[26], 10, "IPv4 source in a planned 10/8 zone");
        assert_eq!(d[30], 10, "IPv4 destination in a planned 10/8 zone");
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

/// Every asset (device and capture host) must be bound MAC<->IP by a SOLICITED
/// UNICAST ARP reply: the zone engineering station asks "who has the asset IP?"
/// and the asset answers "ip is at mac" (oper=2, SHA=mac, SPA=ip) unicast to the
/// station. The sensor associates MAC<->IP from such a solicited reply, not from
/// a gratuitous broadcast (the reference OT capture it binds from carries only
/// solicited unicast replies, zero gratuitous). Every ARP frame must be padded
/// to the 60-byte Ethernet minimum (a 42-byte runt is rejected). Regression
/// guard for the binding collapse (IP-only assets), the runt-ARP a sensor would
/// not trust, and the gratuitous-broadcast form the sensor did not associate.
#[test]
fn synth_burst_binds_every_asset_via_solicited_unicast_arp_replies() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_devices: 8\n  max_assets: 256",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0, 0); // fabricate the fleet and zones

    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = write_capture(&pool, "many.pcap", 60, 60); // 61 hosts in one /24
    engine.remap_into_session(&cfg, &src, &[]).unwrap();
    let hosts = engine.ledger().capture_host_count();
    assert!(hosts > 40, "many capture hosts registered: {hosts}");

    let pcap = engine.red_tick(1, 60).expect("identity burst");
    let cap = pcapio::read(&pcap).unwrap();
    const BROADCAST: [u8; 6] = [0xff; 6];
    let is_arp = |d: &[u8]| d.len() >= 42 && u16::from_be_bytes([d[12], d[13]]) == 0x0806;
    // ARP opcode at offset 20-21 (after the 14-byte Ethernet header).
    let oper = |d: &[u8]| u16::from_be_bytes([d[20], d[21]]);
    let arp: Vec<&OwnedPacket> = cap.packets.iter().filter(|p| is_arp(&p.data)).collect();
    assert!(!arp.is_empty(), "the burst carries ARP");

    // Every ARP reply is unicast to the requester, never a gratuitous broadcast.
    // A broadcast reply is the form the sensor would not associate MAC<->IP from.
    for p in arp.iter().filter(|p| oper(&p.data) == 2) {
        assert_ne!(
            &p.data[0..6],
            &BROADCAST,
            "ARP reply is unicast, not a gratuitous broadcast"
        );
    }

    // The set of bindings the replies carry: (sender MAC, sender IP) of each
    // reply, i.e. "this IP is at this MAC". Sender hardware addr at ARP offset 8
    // (frame 22-28), sender protocol addr at ARP offset 14 (frame 28-32).
    let bound: std::collections::HashSet<([u8; 6], [u8; 4])> = arp
        .iter()
        .filter(|p| oper(&p.data) == 2)
        .map(|p| {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&p.data[22..28]);
            let ip = [p.data[28], p.data[29], p.data[30], p.data[31]];
            (mac, ip)
        })
        .collect();

    // Every asset is bound by one of those solicited replies.
    let assets = engine
        .ledger()
        .devices
        .iter()
        .map(|d| (d.mac.clone(), d.ip.clone()))
        .chain(
            engine
                .ledger()
                .capture_hosts
                .iter()
                .map(|h| (h.mac.clone(), h.ip.clone())),
        );
    let mut checked = 0;
    for (mac, ip) in assets {
        let m = parse_mac6(&mac);
        let a: Ipv4Addr = ip.parse().expect("asset ip parses");
        assert!(
            bound.contains(&(m, a.octets())),
            "asset {ip} / {mac} is bound by a solicited unicast ARP reply"
        );
        checked += 1;
    }
    assert!(checked > 40, "checked a real fleet of assets: {checked}");

    // Every ARP frame is padded to the 60-byte Ethernet minimum, never a runt.
    for p in &arp {
        assert!(
            p.data.len() >= 60,
            "ARP frame padded to 60 bytes, not a {}-byte runt",
            p.data.len()
        );
    }
    let total = cap.packets.len();
    assert!(
        total - arp.len() >= engine.ledger().device_count(),
        "OT protocol sessions ride alongside the bindings: {total} total, {} arp",
        arp.len()
    );
}

/// With a large capture-host fleet the ARP must rotate through a bounded window
/// per burst, not resolve every host at once. Resolving the whole fleet in one
/// burst is a multi-thousand-frame ARP microburst that chokes the replay and
/// overruns the sensor (so few associations form and the capture is starved):
/// the v0.2.11 field defect. Over a few rotations every host is still bound.
#[test]
fn capture_host_arp_rotates_through_a_window_and_covers_all() {
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_devices: 8\n  max_assets: 512",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0, 0); // fabricate the fleet and zones

    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    // ~200 hosts in one /24, well over the per-burst ARP window.
    let src = write_capture(&pool, "many.pcap", 60, 200);
    engine.remap_into_session(&cfg, &src, &[]).unwrap();
    let hosts = engine.ledger().capture_host_count();
    assert!(hosts > 150, "a large host fleet: {hosts}");

    // Resolve over several bursts, advancing the wall clock past the cadence gate
    // each time, and collect every binding the replies carry.
    let mut bound: std::collections::HashSet<([u8; 6], [u8; 4])> = std::collections::HashSet::new();
    let mut max_replies_in_a_burst = 0usize;
    for i in 1..=8u64 {
        let pcap = engine.red_tick(i, i * 60).expect("burst");
        let cap = pcapio::read(&pcap).unwrap();
        let replies: Vec<_> = arp_frames(&cap)
            .into_iter()
            .filter(|(_, op, _, _)| *op == 2)
            .collect();
        max_replies_in_a_burst = max_replies_in_a_burst.max(replies.len());
        for (_, _, sha, spa) in replies {
            bound.insert((sha, spa));
        }
        let _ = std::fs::remove_file(&pcap);
    }

    // No single burst resolves the whole fleet: the per-burst ARP stays well
    // below the host count (the anti-flood property the window guarantees).
    assert!(
        max_replies_in_a_burst < hosts,
        "a burst never resolves the whole fleet at once: {max_replies_in_a_burst} replies vs {hosts} hosts"
    );

    // Every capture host is bound within a few rotations.
    for h in &engine.ledger().capture_hosts {
        let m = parse_mac6(&h.mac);
        let a: Ipv4Addr = h.ip.parse().expect("host ip parses");
        assert!(
            bound.contains(&(m, a.octets())),
            "capture host {} / {} is bound over the rotations",
            h.ip,
            h.mac
        );
    }
}

/// The ARP must be peer-to-peer: within a subnet each host resolves a single
/// peer, so no host probes many addresses. A single station broadcasting
/// "who-has" for the whole subnet (drawing a flood of replies at itself) is an
/// ARP-scan / cache-poisoning signature a security sensor will not associate
/// MAC<->IP from. That was the field defect: only the stations bound; every host
/// the station scanned stayed split. Regression guard: no requester probes more
/// than a couple of distinct IPs across a full ring rotation.
#[test]
fn arp_is_peer_to_peer_no_single_host_scans_the_subnet() {
    use std::collections::{HashMap, HashSet};
    let dir = tempfile::tempdir().unwrap();
    let shm = dir.path().join("shm");
    let session = dir.path().join("session.json");
    let yaml = cfg_yaml(
        dir.path(),
        &shm,
        &session,
        "  identity_every_n_runs: 1\n  max_devices: 8\n  max_assets: 512",
    );
    let cfg_path = dir.path().join("replay.yaml");
    std::fs::write(&cfg_path, yaml).unwrap();
    let cfg = ot_turbolaser::config::load(&cfg_path).unwrap();

    let mut engine = SimulatorEngine::red(&cfg, 0);
    engine.red_tick(0, 0);
    let pool = dir.path().join("pool");
    std::fs::create_dir_all(&pool).unwrap();
    let src = write_capture(&pool, "many.pcap", 60, 200); // ~200 hosts in one /24
    engine.remap_into_session(&cfg, &src, &[]).unwrap();
    assert!(
        engine.ledger().capture_host_count() > 150,
        "a large host fleet"
    );

    // Across enough bursts to cover a full rotation, count the distinct target
    // IPs each requester probes. ARP request: sender MAC (SHA) at frame 22-28,
    // target protocol address (TPA) at 38-42.
    let mut asked: HashMap<[u8; 6], HashSet<[u8; 4]>> = HashMap::new();
    for i in 1..=6u64 {
        let pcap = engine.red_tick(i, i * 60).expect("burst");
        let cap = pcapio::read(&pcap).unwrap();
        for p in &cap.packets {
            let d = &p.data;
            if d.len() >= 42
                && u16::from_be_bytes([d[12], d[13]]) == 0x0806
                && u16::from_be_bytes([d[20], d[21]]) == 1
            {
                let mut sha = [0u8; 6];
                sha.copy_from_slice(&d[22..28]);
                asked
                    .entry(sha)
                    .or_default()
                    .insert([d[38], d[39], d[40], d[41]]);
            }
        }
        let _ = std::fs::remove_file(&pcap);
    }
    assert!(!asked.is_empty(), "ARP requests were emitted");
    let max_probed = asked.values().map(|s| s.len()).max().unwrap_or(0);
    assert!(
        max_probed <= 2,
        "no host ARP-scans the subnet: the busiest requester probed {max_probed} IPs (a ring probes 1; a station-hub would probe the whole window)"
    );
}
