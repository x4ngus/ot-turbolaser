//! Modbus Read Device Identification (function 0x2B / MEI 0x0E) assertion.
//!
//! The request asks for the basic identification objects; the response carries
//! VendorName (object 0x00), ProductCode (0x01), and MajorMinorRevision (0x02),
//! the strings a passive sensor reads to identify a Modbus device.

use std::net::Ipv4Addr;

use super::eth::tcp_frame;

const MODBUS_PORT: u16 = 502;
const FUNC_MEI: u8 = 0x2B;
const MEI_DEVICE_ID: u8 = 0x0E;

/// Wrap a PDU in an MBAP header. The length field counts the unit id plus PDU.
fn mbap(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x0001u16.to_be_bytes()); // transaction id
    b.extend_from_slice(&0x0000u16.to_be_bytes()); // protocol id
    b.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    b.push(unit);
    b.extend_from_slice(pdu);
    b
}

/// Request the basic device identification (read device id code 1, object 0).
pub fn read_device_id_request(unit: u8) -> Vec<u8> {
    mbap(unit, &[FUNC_MEI, MEI_DEVICE_ID, 0x01, 0x00])
}

pub struct ModbusDevId<'a> {
    pub vendor_name: &'a str,
    pub product_code: &'a str,
    pub revision: &'a str,
}

/// The response carrying the three basic identification objects.
pub fn read_device_id_response(unit: u8, id: &ModbusDevId) -> Vec<u8> {
    let mut pdu = vec![
        FUNC_MEI,
        MEI_DEVICE_ID,
        0x01, // read device id code: basic
        0x01, // conformity level: basic identification
        0x00, // more follows: no
        0x00, // next object id
        0x03, // number of objects
    ];
    for (oid, val) in [
        (0u8, id.vendor_name),
        (1, id.product_code),
        (2, id.revision),
    ] {
        pdu.push(oid);
        pdu.push(val.len() as u8);
        pdu.extend_from_slice(val.as_bytes());
    }
    mbap(unit, &pdu)
}

/// The (request, response) frames of a device identification exchange.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    tool_mac: [u8; 6],
    dev_mac: [u8; 6],
    tool_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    tool_port: u16,
    unit: u8,
    id: &ModbusDevId,
) -> (Vec<u8>, Vec<u8>) {
    let req = read_device_id_request(unit);
    let resp = read_device_id_response(unit, id);
    let rf = tcp_frame(
        tool_mac,
        dev_mac,
        tool_ip,
        dev_ip,
        tool_port,
        MODBUS_PORT,
        1,
        1,
        &req,
    );
    let pf = tcp_frame(
        dev_mac,
        tool_mac,
        dev_ip,
        tool_ip,
        MODBUS_PORT,
        tool_port,
        1,
        1 + req.len() as u32,
        &resp,
    );
    (rf, pf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::parse_layout;

    #[test]
    fn response_structure_is_well_formed() {
        let id = ModbusDevId {
            vendor_name: "Schneider Electric",
            product_code: "BMXP342020",
            revision: "V2.60",
        };
        let frame = exchange(
            [0; 6],
            [0; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            40000,
            0x01,
            &id,
        )
        .1;
        // The MBAP length field matches the trailing bytes.
        let l = parse_layout(&frame).unwrap();
        let pdu = &frame[l.payload..l.end];
        let mbap_len = u16::from_be_bytes([pdu[4], pdu[5]]) as usize;
        assert_eq!(mbap_len, pdu.len() - 6, "MBAP length counts unit + PDU");
        assert_eq!(pdu[7], FUNC_MEI);
        assert_eq!(pdu[8], MEI_DEVICE_ID);
        assert_eq!(pdu[13], 0x03, "three objects");
    }
}
