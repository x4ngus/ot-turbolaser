//! Validate the synthesized protocol assertions against tshark, the
//! authoritative dissector. Each builder must produce frames that dissect as
//! the intended protocol, carry the identifying strings a sensor reads, and
//! contain no malformed frames. Skips if tshark is absent.

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use ot_turbolaser::reload::pipeline::tshark_available;
use ot_turbolaser::synth::{cdp, enip_identity, lldp, modbus_devid, s7_szl, snmp};
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

fn dissects(path: &Path, proto: &str) -> bool {
    !tshark(path, &["-Y", proto, "-T", "fields", "-e", "frame.number"])
        .trim()
        .is_empty()
}

fn verbose(path: &Path, proto: &str) -> String {
    tshark(path, &["-Y", proto, "-V"])
}

#[test]
fn synthesized_assertions_dissect_in_tshark() {
    let mac = |b: u8| [0x02, 0x00, 0x00, 0x00, 0x00, b];
    let mut frames = Vec::new();

    // ENIP List Identity exchange.
    let id = enip_identity::EnipIdentity {
        vendor_id: 1,
        device_type: 14,
        product_code: 54,
        revision_major: 20,
        revision_minor: 11,
        serial: 0x1234_5678,
        product_name: "1756-L61/B LOGIX5561",
    };
    let (a, b) = enip_identity::exchange(
        mac(1),
        mac(2),
        Ipv4Addr::new(10, 0, 0, 50),
        Ipv4Addr::new(10, 0, 0, 9),
        50000,
        &id,
    );
    frames.push(a);
    frames.push(b);

    // Modbus Read Device Identification exchange.
    let (a, b) = modbus_devid::exchange(
        mac(3),
        mac(4),
        Ipv4Addr::new(10, 0, 1, 50),
        Ipv4Addr::new(10, 0, 1, 9),
        40000,
        1,
        &modbus_devid::ModbusDevId {
            vendor_name: "Schneider Electric",
            product_code: "BMXP342020",
            revision: "V2.60",
        },
    );
    frames.push(a);
    frames.push(b);

    // SNMP sysDescr fetch.
    let (a, b) = snmp::exchange(
        mac(5),
        mac(6),
        Ipv4Addr::new(10, 0, 2, 50),
        Ipv4Addr::new(10, 0, 2, 9),
        43210,
        "public",
        0x1234,
        "Moxa EDS-405A Series Managed Ethernet Switch, firmware V3.4",
        Some("1.3.6.1.4.1.8691.7.50"),
    );
    frames.push(a);
    frames.push(b);

    // S7comm SZL module-identification exchange.
    let (a, b) = s7_szl::exchange(
        mac(9),
        mac(10),
        Ipv4Addr::new(10, 0, 3, 50),
        Ipv4Addr::new(10, 0, 3, 9),
        2000,
        "6ES7 212-1AE40-0XB0",
        4,
        2,
    );
    frames.push(a);
    frames.push(b);

    // LLDP and CDP switch beacons.
    frames.push(lldp::beacon(
        mac(7),
        Ipv4Addr::new(10, 0, 4, 9),
        "sw-cell-1",
        "Hirschmann RSP20 HiOS-2A Rel. 07.0.02",
    ));
    frames.push(cdp::beacon(
        mac(8),
        Ipv4Addr::new(10, 0, 4, 9),
        "IE3000-cell-1",
        "15.2(4)EA",
        "cisco IE-3000-8TC",
    ));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("synth.pcap");
    pcapio::write(&path, &to_cap(frames)).unwrap();

    if !tshark_available() {
        eprintln!("tshark not found; skipping dissector validation");
        return;
    }

    // No frame may be malformed.
    let malformed = tshark(
        &path,
        &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
    );
    assert!(
        malformed.trim().is_empty(),
        "tshark found malformed frames: {malformed}"
    );

    // Each protocol dissects and carries its identifying string.
    assert!(dissects(&path, "enip"), "ENIP must dissect");
    assert!(
        verbose(&path, "enip").contains("LOGIX5561"),
        "ENIP product name must be present"
    );

    assert!(dissects(&path, "mbtcp"), "Modbus/TCP must dissect");
    assert!(
        verbose(&path, "mbtcp").contains("Schneider Electric"),
        "Modbus vendor name must be present"
    );

    assert!(dissects(&path, "snmp"), "SNMP must dissect");
    assert!(
        verbose(&path, "snmp").contains("Moxa EDS-405A"),
        "SNMP sysDescr must be present"
    );

    assert!(dissects(&path, "lldp"), "LLDP must dissect");
    assert!(
        verbose(&path, "lldp").contains("Hirschmann RSP20"),
        "LLDP system description must be present"
    );

    assert!(dissects(&path, "cdp"), "CDP must dissect");
    assert!(
        verbose(&path, "cdp").contains("IE3000-cell-1"),
        "CDP device id must be present"
    );

    assert!(dissects(&path, "s7comm"), "S7comm must dissect");
    assert!(
        verbose(&path, "s7comm").contains("6ES7 212"),
        "S7 module order number must be present"
    );
}
