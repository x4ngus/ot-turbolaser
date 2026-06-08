//! Packet synthesis: whole-frame builders that render device identities and
//! switch beacons as genuine protocol assertions.
//!
//! Each device builder emits a full query and its response so a sensor's CVE
//! match rests on a coherent transaction, not an orphan reply. Switch beacons
//! (LLDP, CDP, SNMP) announce a network device sitting between zones. Frames are
//! assembled into a `Capture` and fired with tcpreplay like any pcap.

pub mod arp;
pub mod cdp;
pub mod dns;
pub mod enip_identity;
pub mod eth;
pub mod iec104;
pub mod ioc;
pub mod lldp;
pub mod modbus_devid;
pub mod modbus_write;
pub mod s7_common;
pub mod s7_control;
pub mod s7_szl;
pub mod session;
pub mod snmp;
pub mod tristation;

use std::time::Duration;

use pcap_file::pcap::PcapHeader;

use crate::pcapio::{Capture, OwnedPacket};

/// First two integer groups of a firmware string as a major/minor pair, e.g.
/// "V4.2.1" -> (4, 2). The version a protocol identity assertion carries.
pub fn parse_version(fw: &str) -> (u8, u8) {
    let mut groups = fw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0).min(255) as u8);
    (groups.next().unwrap_or(0), groups.next().unwrap_or(0))
}

/// Collect synthesized frames into a Capture for tmpfs write and replay. Frames
/// are stamped a millisecond apart so tcpreplay paces them in order.
pub fn to_capture(frames: Vec<Vec<u8>>) -> Capture {
    Capture {
        header: PcapHeader::default(),
        packets: frames
            .into_iter()
            .enumerate()
            .map(|(i, data)| OwnedPacket {
                ts: Duration::from_millis(i as u64),
                orig_len: data.len() as u32,
                data,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("V4.2.1"), (4, 2));
        assert_eq!(parse_version("20.011"), (20, 11));
        assert_eq!(parse_version("07.0.02"), (7, 0));
        assert_eq!(parse_version("none"), (0, 0));
    }
}
