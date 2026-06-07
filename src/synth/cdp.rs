//! CDP switch beacon.
//!
//! Like LLDP, an announcement of a managed switch conduit, carrying Device ID,
//! Software Version, and Platform. CDP rides an 802.3 LLC/SNAP frame rather than
//! Ethernet II, with its own checksum over the CDP message.

use std::net::Ipv4Addr;

use super::eth::snap_frame;

const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC];
const SNAP_OUI_CISCO: [u8; 3] = [0x00, 0x00, 0x0C];
const CDP_PROTOCOL_ID: u16 = 0x2000;

/// One CDP TLV: type and length (length covers the 4-byte header) then value.
fn tlv(t: u16, value: &[u8]) -> Vec<u8> {
    let mut b = t.to_be_bytes().to_vec();
    b.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    b.extend_from_slice(value);
    b
}

/// CDP Addresses TLV (0x0002) value carrying a single IPv4 address, so a sensor
/// binds the switch's management IP to its CDP identity.
fn addresses(ip: Ipv4Addr) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_be_bytes()); // number of addresses
    v.push(1); // protocol type: NLPID
    v.push(1); // protocol length
    v.push(0xCC); // protocol: IP
    v.extend_from_slice(&4u16.to_be_bytes()); // address length
    v.extend_from_slice(&ip.octets());
    v
}

/// CDP checksum over the CDP message. Like the internet checksum, but with
/// Cisco's odd-length quirk: a trailing odd byte whose high bit is set is
/// sign-extended (added as 0xFF00 | byte) rather than left-shifted, matching
/// what a strict CDP dissector validates. For ASCII trailing bytes the two
/// agree.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        let b = data[i];
        if (b as i8) < 0 {
            sum += 0xFF00 | b as u32; // sign-extend a negative trailing byte
        } else {
            sum += (b as u32) << 8;
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a CDP beacon frame for a switch.
pub fn beacon(
    switch_mac: [u8; 6],
    mgmt_ip: Ipv4Addr,
    device_id: &str,
    software_version: &str,
    platform: &str,
) -> Vec<u8> {
    let mut tlvs = Vec::new();
    tlvs.extend_from_slice(&tlv(0x0001, device_id.as_bytes())); // Device ID
    tlvs.extend_from_slice(&tlv(0x0002, &addresses(mgmt_ip))); // Addresses
    tlvs.extend_from_slice(&tlv(0x0005, software_version.as_bytes())); // Software version
    tlvs.extend_from_slice(&tlv(0x0006, platform.as_bytes())); // Platform

    let mut pdu = Vec::new();
    pdu.push(2); // version
    pdu.push(180); // TTL seconds
    pdu.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pdu.extend_from_slice(&tlvs);
    let ck = checksum(&pdu);
    pdu[2] = (ck >> 8) as u8;
    pdu[3] = (ck & 0xff) as u8;

    snap_frame(
        switch_mac,
        CDP_MULTICAST,
        SNAP_OUI_CISCO,
        CDP_PROTOCOL_ID,
        &pdu,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_has_snap_header_and_tlvs() {
        let f = beacon(
            [0x00, 0x1B, 0x0C, 1, 2, 3],
            Ipv4Addr::new(10, 3, 0, 9),
            "IE3000-1",
            "15.2(4)EA",
            "cisco IE-3000-8TC",
        );
        assert_eq!(&f[0..6], &CDP_MULTICAST);
        // LLC/SNAP with Cisco OUI and CDP protocol id.
        assert_eq!(&f[14..17], &[0xAA, 0xAA, 0x03]);
        assert_eq!(&f[17..20], &SNAP_OUI_CISCO);
        assert_eq!(u16::from_be_bytes([f[20], f[21]]), CDP_PROTOCOL_ID);
        assert!(f.windows(8).any(|w| w == b"IE3000-1"));
        // Addresses TLV carries the management IPv4.
        assert!(
            f.windows(4).any(|w| w == [10, 3, 0, 9]),
            "management IP present"
        );
    }
}
