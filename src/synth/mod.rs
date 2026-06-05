//! Packet synthesis: whole-frame builders that render device identities and
//! switch beacons as genuine protocol assertions.
//!
//! Each device builder emits a full query and its response so a sensor's CVE
//! match rests on a coherent transaction, not an orphan reply. Switch beacons
//! (LLDP, CDP, SNMP) announce a network device sitting between zones. Frames are
//! assembled into a `Capture` and fired with tcpreplay like any pcap.

pub mod arp;
pub mod cdp;
pub mod enip_identity;
pub mod eth;
pub mod lldp;
pub mod modbus_devid;
pub mod s7_szl;
pub mod session;
pub mod snmp;

use std::time::Duration;

use pcap_file::pcap::PcapHeader;

use crate::pcapio::{Capture, OwnedPacket};

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
