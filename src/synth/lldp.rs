//! LLDP switch beacon.
//!
//! Announces a managed switch sitting between zones, carrying its chassis MAC,
//! a port id, a TTL, and the System Name and System Description a sensor reads.
//! LLDP is an announcement, not a request/response, so a single frame is the
//! whole assertion.

use super::eth::l2_frame;

const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];
const ETHERTYPE_LLDP: u16 = 0x88CC;

/// One LLDP TLV: a 7-bit type and 9-bit length packed into two bytes.
fn tlv(t: u8, value: &[u8]) -> Vec<u8> {
    let header = ((t as u16) << 9) | (value.len() as u16 & 0x01ff);
    let mut b = header.to_be_bytes().to_vec();
    b.extend_from_slice(value);
    b
}

/// Build an LLDP beacon frame for a switch.
pub fn beacon(switch_mac: [u8; 6], system_name: &str, system_descr: &str) -> Vec<u8> {
    let mut p = Vec::new();
    // Chassis ID (1): subtype 4 = MAC address.
    let mut chassis = vec![4u8];
    chassis.extend_from_slice(&switch_mac);
    p.extend_from_slice(&tlv(1, &chassis));
    // Port ID (2): subtype 7 = locally assigned.
    let mut port = vec![7u8];
    port.extend_from_slice(b"1");
    p.extend_from_slice(&tlv(2, &port));
    // Time To Live (3): 120 seconds.
    p.extend_from_slice(&tlv(3, &120u16.to_be_bytes()));
    // System Name (5) and System Description (6).
    p.extend_from_slice(&tlv(5, system_name.as_bytes()));
    p.extend_from_slice(&tlv(6, system_descr.as_bytes()));
    // End of LLDPDU (0).
    p.extend_from_slice(&tlv(0, &[]));
    l2_frame(switch_mac, LLDP_MULTICAST, ETHERTYPE_LLDP, &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_has_lldp_ethertype_and_mandatory_tlvs() {
        let f = beacon(
            [0x00, 0x80, 0x63, 1, 2, 3],
            "sw-cell-1",
            "Hirschmann RSP20 HiOS",
        );
        assert_eq!(&f[0..6], &LLDP_MULTICAST);
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ETHERTYPE_LLDP);
        // First TLV is Chassis ID (type 1) with the MAC.
        let h = u16::from_be_bytes([f[14], f[15]]);
        assert_eq!(h >> 9, 1, "chassis id tlv");
        assert!(f.windows(9).any(|w| w == b"sw-cell-1"));
    }
}
