//! Minimal pcap read and write that preserves per-packet timestamps and the
//! capture's link layer. Wraps pcap-file. Classic pcap only for now.

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter};
use std::fs::File;
use std::path::Path;
use std::time::Duration;

pub struct OwnedPacket {
    pub ts: Duration,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

pub struct Capture {
    pub header: PcapHeader,
    pub packets: Vec<OwnedPacket>,
}

pub fn read(path: &Path) -> Result<Capture, String> {
    let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut rdr =
        PcapReader::new(file).map_err(|e| format!("pcap header {}: {e}", path.display()))?;
    let header = rdr.header();
    let mut packets = Vec::new();
    while let Some(next) = rdr.next_packet() {
        let pkt = next.map_err(|e| format!("pcap packet in {}: {e}", path.display()))?;
        packets.push(OwnedPacket {
            ts: pkt.timestamp,
            orig_len: pkt.orig_len,
            data: pkt.data.into_owned(),
        });
    }
    Ok(Capture { header, packets })
}

pub fn write(path: &Path, cap: &Capture) -> Result<(), String> {
    let file = File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    // Always emit a canonical classic Ethernet, microsecond-resolution header
    // rather than echoing the source. Some source captures carry non-canonical
    // link-type bits (FCS or pseudo-header flags) that tcpreplay rejects at load
    // ("unsupported DLT type: Ethernet (0x1)") even though Wireshark tolerates
    // them; a clean header keeps every file we emit replayable. Per-packet
    // timestamps live on the packets, so they are unaffected.
    let mut wtr = PcapWriter::with_header(file, PcapHeader::default())
        .map_err(|e| format!("pcap write {}: {e}", path.display()))?;
    for p in &cap.packets {
        let pkt = PcapPacket::new(p.ts, p.orig_len, &p.data);
        wtr.write_packet(&pkt)
            .map_err(|e| format!("pcap write {}: {e}", path.display()))?;
    }
    Ok(())
}
