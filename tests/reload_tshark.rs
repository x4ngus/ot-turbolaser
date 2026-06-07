//! End-to-end: forge a round and have tshark (the Wireshark dissector, the
//! authoritative oracle) confirm it is well-formed. Skips if tshark is absent.

use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use ot_turbolaser::proto::{crc, frame, mutators};
use ot_turbolaser::reload::pipeline::{
    forge_round, tshark_available, validate_pcap, ReloadOptions,
};
use pcap_file::pcap::PcapHeader;
use std::process::Command;
use std::time::Duration;

fn build_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x08, 0x00];
    let ip_total = 20 + 20 + payload.len();
    b.extend_from_slice(&[0x45, 0x00]);
    b.extend_from_slice(&(ip_total as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 6, 0, 0]);
    b.extend_from_slice(&src);
    b.extend_from_slice(&dst);
    b.extend_from_slice(&sport.to_be_bytes());
    b.extend_from_slice(&dport.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    b.extend_from_slice(payload);
    let l = frame::parse_layout(&b).unwrap();
    frame::recompute_checksums(&mut b, &l);
    b
}

fn modbus_payload(unit: u8) -> Vec<u8> {
    vec![0, 1, 0, 0, 0, 6, unit, 3, 0, 0, 0, 10]
}

fn dnp3_payload(dest: u16, src: u16) -> Vec<u8> {
    // A complete link frame: header + one data block (transport byte plus a
    // minimal application response) so the dissector sees a whole PDU.
    let user = [0xC0u8, 0xC1, 0x81, 0x00, 0x00]; // transport, app ctrl, RESPONSE, IIN
    let len = 5 + user.len() as u8; // CTRL + DEST + SRC + user data
    let mut h = vec![0x05, 0x64, len, 0x44];
    h.extend_from_slice(&dest.to_le_bytes());
    h.extend_from_slice(&src.to_le_bytes());
    let hcrc = crc::dnp3(&h[0..8]);
    h.extend_from_slice(&hcrc.to_le_bytes());
    h.extend_from_slice(&user);
    let bcrc = crc::dnp3(&user);
    h.extend_from_slice(&bcrc.to_le_bytes());
    h
}

#[test]
fn forged_output_is_tshark_clean() {
    let p0 = build_tcp(
        [192, 168, 10, 5],
        [192, 168, 10, 9],
        5000,
        502,
        &modbus_payload(9),
    );
    let p1 = build_tcp(
        [192, 168, 10, 9],
        [192, 168, 10, 5],
        40000,
        20000,
        &dnp3_payload(10, 1),
    );
    let src = Capture {
        header: PcapHeader::default(),
        packets: vec![
            OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: p0.len() as u32,
                data: p0,
            },
            OwnedPacket {
                ts: Duration::new(2, 0),
                orig_len: p1.len() as u32,
                data: p1,
            },
        ],
    };

    let opts = ReloadOptions {
        remap_l3: true,
        hints: Vec::new(),
        mutators: mutators::all(),
    };
    let (cap, result) = forge_round(&src, 0x00C0_FFEE, &opts);
    assert!(!result.mutations.is_empty(), "mutators should fire");
    assert!(result.l3.is_some(), "L3 should be remapped");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("round.pcap");
    pcapio::write(&path, &cap).unwrap();

    if !tshark_available() {
        eprintln!("tshark not found; skipping dissector validation");
        return;
    }

    validate_pcap(&path).expect("tshark should find no malformed frames or bad checksums");

    // Confirm the protocols still dissect and the identifiers actually changed.
    let modbus_unit = tshark(
        &path,
        &["-Y", "mbtcp", "-T", "fields", "-e", "mbtcp.unit_id"],
    );
    assert!(!modbus_unit.trim().is_empty(), "modbus should dissect");
    assert_ne!(modbus_unit.trim(), "9", "unit id should be remapped");

    let dnp3_fields = tshark(
        &path,
        &[
            "-Y", "dnp3", "-T", "fields", "-e", "dnp3.dst", "-e", "dnp3.src",
        ],
    );
    assert!(
        !dnp3_fields.trim().is_empty(),
        "dnp3 should dissect with a valid header CRC"
    );
}

fn tshark(path: &std::path::Path, extra: &[&str]) -> String {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(extra)
        .output()
        .expect("run tshark");
    String::from_utf8_lossy(&out.stdout).into_owned()
}
