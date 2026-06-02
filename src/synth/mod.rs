//! Packet synthesis: whole-frame builders that render device identities and
//! switch beacons as genuine protocol assertions.
//!
//! Each device builder emits a full query and its response so a sensor's CVE
//! match rests on a coherent transaction, not an orphan reply. Switch beacons
//! (LLDP, CDP, SNMP) announce a network device sitting between zones. Frames are
//! assembled into a `Capture` and fired with tcpreplay like any pcap.

pub mod cdp;
pub mod enip_identity;
pub mod eth;
pub mod lldp;
pub mod modbus_devid;
pub mod s7_szl;
pub mod snmp;
