//! EtherNet/IP List Identity assertion.
//!
//! Builds the request a discovery tool sends and the reply a device returns,
//! carrying the CIP Identity object (vendor id, device type, product code,
//! revision, serial, product name). The byte layout is the inverse of what the
//! reload ENIP mutator reads, so that reader doubles as a round-trip oracle.

use std::net::Ipv4Addr;

use super::eth::tcp_frame;

const ENIP_PORT: u16 = 44818;
const CMD_LIST_IDENTITY: u16 = 0x0063;
const ITEM_CIP_IDENTITY: u16 = 0x000C;

/// The identity values a device advertises. Strings are length-prefixed in the
/// wire format; the builder sets the lengths.
pub struct EnipIdentity<'a> {
    pub vendor_id: u16,
    pub device_type: u16,
    pub product_code: u16,
    pub revision_major: u8,
    pub revision_minor: u8,
    pub serial: u32,
    pub product_name: &'a str,
}

/// A 24-byte ENIP encapsulation header wrapping `body`.
fn encap(command: u16, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(24 + body.len());
    p.extend_from_slice(&command.to_le_bytes());
    p.extend_from_slice(&(body.len() as u16).to_le_bytes());
    p.extend_from_slice(&[0; 4]); // session handle
    p.extend_from_slice(&[0; 4]); // status
    p.extend_from_slice(&[0; 8]); // sender context
    p.extend_from_slice(&[0; 4]); // options
    p.extend_from_slice(body);
    p
}

/// The List Identity request payload (no body).
pub fn list_identity_request() -> Vec<u8> {
    encap(CMD_LIST_IDENTITY, &[])
}

/// The List Identity reply payload carrying one CIP Identity item.
pub fn list_identity_reply(id: &EnipIdentity) -> Vec<u8> {
    let name = id.product_name.as_bytes();
    let mut obj = Vec::new();
    obj.extend_from_slice(&1u16.to_le_bytes()); // protocol version
    obj.extend_from_slice(&[0; 16]); // socket address
    obj.extend_from_slice(&id.vendor_id.to_le_bytes()); // @18
    obj.extend_from_slice(&id.device_type.to_le_bytes()); // @20
    obj.extend_from_slice(&id.product_code.to_le_bytes()); // @22
    obj.push(id.revision_major); // @24
    obj.push(id.revision_minor); // @25
    obj.extend_from_slice(&0u16.to_le_bytes()); // status @26
    obj.extend_from_slice(&id.serial.to_le_bytes()); // @28
    obj.push(name.len() as u8); // @32 product name length
    obj.extend_from_slice(name); // @33
    obj.push(0); // state

    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes()); // item count
    body.extend_from_slice(&ITEM_CIP_IDENTITY.to_le_bytes());
    body.extend_from_slice(&(obj.len() as u16).to_le_bytes());
    body.extend_from_slice(&obj);
    encap(CMD_LIST_IDENTITY, &body)
}

/// The (request, reply) frames of a device's identity exchange: the discovery
/// tool queries from an ephemeral port, the device replies from 44818.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    tool_mac: [u8; 6],
    dev_mac: [u8; 6],
    tool_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    tool_port: u16,
    id: &EnipIdentity,
) -> (Vec<u8>, Vec<u8>) {
    let req = list_identity_request();
    let reply = list_identity_reply(id);
    let req_frame = tcp_frame(
        tool_mac, dev_mac, tool_ip, dev_ip, tool_port, ENIP_PORT, 1, 1, &req,
    );
    let reply_frame = tcp_frame(
        dev_mac,
        tool_mac,
        dev_ip,
        tool_ip,
        ENIP_PORT,
        tool_port,
        1,
        1 + req.len() as u32,
        &reply,
    );
    (req_frame, reply_frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::ParsedFrame;
    use crate::proto::mutators::enip::Enip;
    use crate::proto::OtMutator;

    #[test]
    fn reply_round_trips_through_the_reader() {
        let id = EnipIdentity {
            vendor_id: 1,
            device_type: 14,
            product_code: 54,
            revision_major: 20,
            revision_minor: 11,
            serial: 0x1234_5678,
            product_name: "1756-L61/B LOGIX5561",
        };
        let (_req, mut reply) = exchange(
            [0, 0, 0xBC, 1, 1, 1],
            [0, 0, 0xBC, 2, 2, 2],
            Ipv4Addr::new(10, 0, 0, 50),
            Ipv4Addr::new(10, 0, 0, 9),
            50000,
            &id,
        );
        let f = ParsedFrame::parse(&mut reply).unwrap();
        // The reload ENIP reader recognises our reply as a List Identity.
        assert!(
            Enip.matches(&f),
            "reader must recognise the synthesized reply"
        );
        // And the vendor id we wrote is at the offset the reader reads.
        let p = f.payload();
        let data = 26 + 4; // item count + item header
        let vendor = u16::from_le_bytes([p[data + 18], p[data + 19]]);
        assert_eq!(vendor, 1);
        let devtype = u16::from_le_bytes([p[data + 20], p[data + 21]]);
        assert_eq!(devtype, 14);
    }

    #[test]
    fn request_is_a_bare_list_identity() {
        let req = list_identity_request();
        assert_eq!(req.len(), 24);
        assert_eq!(u16::from_le_bytes([req[0], req[1]]), CMD_LIST_IDENTITY);
        assert_eq!(u16::from_le_bytes([req[2], req[3]]), 0, "empty body");
    }
}
