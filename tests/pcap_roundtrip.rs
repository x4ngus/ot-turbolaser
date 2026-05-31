//! pcap read/write must round-trip packets and timestamps byte-for-byte.

use ot_turbolaser::pcapio::{self, Capture, OwnedPacket};
use pcap_file::pcap::PcapHeader;
use std::time::Duration;

#[test]
fn pcap_write_then_read_is_identical() {
    let packets = vec![
        OwnedPacket {
            ts: Duration::new(1_700_000_000, 123_000),
            orig_len: 8,
            data: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04],
        },
        OwnedPacket {
            ts: Duration::new(1_700_000_001, 456_000),
            orig_len: 4,
            data: vec![0xaa, 0xbb, 0xcc, 0xdd],
        },
    ];
    let cap = Capture {
        header: PcapHeader::default(),
        packets,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rt.pcap");
    pcapio::write(&path, &cap).expect("write");

    let back = pcapio::read(&path).expect("read");
    assert_eq!(back.packets.len(), 2);
    for (a, b) in cap.packets.iter().zip(back.packets.iter()) {
        assert_eq!(a.data, b.data, "packet bytes must round-trip");
        assert_eq!(a.ts, b.ts, "timestamps must round-trip");
        assert_eq!(a.orig_len, b.orig_len);
    }
}
