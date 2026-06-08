//! Validate the scenario attack frames against tshark, the authoritative
//! dissector. Each scenario's playbook is rendered against its pinned plant and
//! the resulting frames must dissect as the intended control-plane protocol with
//! no malformed frames -- the byte-identical result a tcpreplay-and-capture on a
//! veth would produce (this host has no veth/tcpreplay, so it reads the pcap
//! directly). Skips if tshark is absent.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ot_turbolaser::config;
use ot_turbolaser::oui::OuiDb;
use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use ot_turbolaser::reload::pipeline::tshark_available;
use ot_turbolaser::scenario::{engine::ScenarioEngine, plant};
use ot_turbolaser::vuln::VulnDb;
use pcap_file::pcap::PcapHeader;

fn to_cap(frames: Vec<Vec<u8>>) -> Capture {
    Capture {
        header: PcapHeader::default(),
        packets: frames
            .into_iter()
            .enumerate()
            .map(|(i, data)| OwnedPacket {
                ts: Duration::new(i as u64 + 1, 0),
                orig_len: data.len() as u32,
                data,
            })
            .collect(),
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

/// True if any frame matches the display filter.
fn dissects(path: &Path, filter: &str) -> bool {
    !tshark(path, &["-Y", filter, "-T", "fields", "-e", "frame.number"])
        .trim()
        .is_empty()
}

fn malformed(path: &Path) -> String {
    tshark(
        path,
        &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
    )
}

/// Render every attack frame a scenario's playbook produces against its pinned
/// plant, walking the whole timeline.
fn scenario_frames(name: &str) -> Vec<Vec<u8>> {
    let base = Path::new("conf/replay.yaml");
    let cfg = config::load_with_scenario(base, Some(name)).expect("scenario config loads");
    let t = cfg.target.as_ref().expect("target present");
    let vuln = VulnDb::load_overlay(&t.pack_dir.join(&t.profiles));
    let session = plant::pin_from_pack(t, &vuln, &OuiDb::embedded(), 1337, 0, &cfg.dns.domains)
        .expect("plant pins");
    let mut eng = ScenarioEngine::load(t, session.seed).expect("engine loads");
    let mut frames = Vec::new();
    for n in 0..60u64 {
        frames.extend(eng.phase_frames(&session, &vuln, n));
    }
    frames
}

fn write_pcap(dir: &Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(format!("{name}.pcap"));
    pcapio::write(&path, &to_cap(scenario_frames(name))).unwrap();
    path
}

/// Dump each scenario's attack frames to `$TMPDIR/ot-scenarios/<name>.pcap` for
/// manual Wireshark inspection. Run on demand:
/// `cargo test --test scenario_tshark -- --ignored --nocapture`.
#[test]
#[ignore]
fn dump_scenario_pcaps() {
    let dir = std::env::temp_dir().join("ot-scenarios");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["stuxnet", "triton", "oldsmar", "ukraine2015"] {
        let p = write_pcap(&dir, name);
        eprintln!("wrote {}", p.display());
    }
}

#[test]
fn scenario_attack_frames_dissect_in_tshark() {
    if !tshark_available() {
        eprintln!("tshark not found; skipping scenario dissector validation");
        return;
    }
    let dir = tempfile::tempdir().unwrap();

    // Print each scenario's protocol hierarchy for visibility (run with
    // --nocapture), then assert the key control-plane protocol dissects cleanly.
    for name in ["stuxnet", "triton", "oldsmar", "ukraine2015"] {
        let p = write_pcap(dir.path(), name);
        eprintln!(
            "\n==== {name} protocol hierarchy ====\n{}",
            tshark(&p, &["-q", "-z", "io,phs"])
        );
        let m = malformed(&p);
        assert!(
            m.trim().is_empty(),
            "{name}: tshark found malformed frames: {m}"
        );
    }

    // Stuxnet: S7comm program-download / write / stop, on established sessions.
    let p = dir.path().join("stuxnet.pcap");
    assert!(dissects(&p, "s7comm"), "Stuxnet S7comm must dissect");
    assert!(
        dissects(&p, "tcp.flags.syn==1 && tcp.flags.ack==0"),
        "Stuxnet S7 actions open a TCP handshake"
    );
    assert!(
        dissects(&p, "cotp.type==0x0e"),
        "S7 COTP connection request present"
    );

    // Oldsmar: Modbus write of the NaOH dose setpoint (function code 6).
    let p = dir.path().join("oldsmar.pcap");
    assert!(dissects(&p, "mbtcp"), "Oldsmar Modbus/TCP must dissect");
    assert!(
        dissects(&p, "modbus.func_code==6"),
        "Oldsmar emits a Write Single Register"
    );

    // Triton: TriStation is proprietary (no Wireshark dissector); a sensor keys
    // it by port, so verify the UDP/1502 transport is present and clean.
    let p = dir.path().join("triton.pcap");
    assert!(
        dissects(&p, "udp.port==1502"),
        "Triton rides TriStation UDP/1502"
    );

    // Ukraine: IEC 60870-5-104 control + the real BlackEnergy C2 on the wire.
    let p = dir.path().join("ukraine2015.pcap");
    assert!(
        dissects(&p, "104apci"),
        "Ukraine IEC 60870-5-104 must dissect"
    );
    assert!(
        dissects(&p, "ip.addr==5.149.254.114"),
        "the real published BlackEnergy3 C2 address reaches the wire"
    );
}
