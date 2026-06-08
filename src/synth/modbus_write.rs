//! Modbus register-write assertions.
//!
//! Where [`super::modbus_devid`] reads a device's identity, this renders the
//! *manipulation* a setpoint-tampering attack performs: Write Single Register
//! (FC 0x06) and Write Multiple Registers (FC 0x10). The Oldsmar incident is the
//! canonical case -- an operator-facing setpoint (sodium-hydroxide dose) driven
//! from a safe value to a dangerous one. Each is a complete TCP session so a
//! stateful sensor parses it on an established connection.

use std::net::Ipv4Addr;

use super::modbus_devid::mbap;
use super::session;

const MODBUS_PORT: u16 = 502;
const FUNC_WRITE_SINGLE: u8 = 0x06;
const FUNC_WRITE_MULTIPLE: u8 = 0x10;

fn write_single_request(unit: u8, addr: u16, value: u16) -> Vec<u8> {
    let mut pdu = vec![FUNC_WRITE_SINGLE];
    pdu.extend_from_slice(&addr.to_be_bytes());
    pdu.extend_from_slice(&value.to_be_bytes());
    mbap(unit, &pdu)
}

fn write_multiple_request(unit: u8, addr: u16, values: &[u16]) -> Vec<u8> {
    let mut pdu = vec![FUNC_WRITE_MULTIPLE];
    pdu.extend_from_slice(&addr.to_be_bytes());
    pdu.extend_from_slice(&(values.len() as u16).to_be_bytes());
    pdu.push((values.len() * 2) as u8); // byte count
    for v in values {
        pdu.extend_from_slice(&v.to_be_bytes());
    }
    mbap(unit, &pdu)
}

/// FC 0x06 / 0x10 responses echo the address and the value/quantity.
fn write_single_response(unit: u8, addr: u16, value: u16) -> Vec<u8> {
    write_single_request(unit, addr, value)
}

fn write_multiple_response(unit: u8, addr: u16, count: u16) -> Vec<u8> {
    let mut pdu = vec![FUNC_WRITE_MULTIPLE];
    pdu.extend_from_slice(&addr.to_be_bytes());
    pdu.extend_from_slice(&count.to_be_bytes());
    mbap(unit, &pdu)
}

/// A full Write Single Register (FC 0x06) exchange.
#[allow(clippy::too_many_arguments)]
pub fn write_single_register(
    client_mac: [u8; 6],
    dev_mac: [u8; 6],
    client_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    client_port: u16,
    unit: u8,
    addr: u16,
    value: u16,
) -> Vec<Vec<u8>> {
    session::request_response(
        client_mac,
        dev_mac,
        client_ip,
        dev_ip,
        client_port,
        MODBUS_PORT,
        &write_single_request(unit, addr, value),
        &write_single_response(unit, addr, value),
    )
}

/// A full Write Multiple Registers (FC 0x10) exchange.
#[allow(clippy::too_many_arguments)]
pub fn write_multiple_registers(
    client_mac: [u8; 6],
    dev_mac: [u8; 6],
    client_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    client_port: u16,
    unit: u8,
    addr: u16,
    values: &[u16],
) -> Vec<Vec<u8>> {
    session::request_response(
        client_mac,
        dev_mac,
        client_ip,
        dev_ip,
        client_port,
        MODBUS_PORT,
        &write_multiple_request(unit, addr, values),
        &write_multiple_response(unit, addr, values.len() as u16),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn assert_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    #[test]
    fn write_single_carries_function_and_value() {
        // The Oldsmar setpoint excursion: NaOH register driven to 11100 ppm.
        let frames = write_single_register(
            [0; 6],
            [0; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            40000,
            1,
            0x0064, // setpoint register
            11100,
        );
        assert_clean(&frames);
        // Request is the client's data segment (index 3 after the handshake).
        let l = parse_layout(&frames[3]).unwrap();
        let pdu = &frames[3][l.payload..l.end];
        assert_eq!(pdu[7], FUNC_WRITE_SINGLE, "FC 0x06");
        assert_eq!(u16::from_be_bytes([pdu[10], pdu[11]]), 11100, "the value");
    }

    #[test]
    fn write_multiple_byte_count_matches() {
        let frames = write_multiple_registers(
            [0; 6],
            [0; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            40001,
            1,
            0x0064,
            &[11100, 0],
        );
        assert_clean(&frames);
        let l = parse_layout(&frames[3]).unwrap();
        let pdu = &frames[3][l.payload..l.end];
        assert_eq!(pdu[7], FUNC_WRITE_MULTIPLE, "FC 0x10");
        assert_eq!(u16::from_be_bytes([pdu[10], pdu[11]]), 2, "quantity");
        assert_eq!(pdu[12], 4, "byte count = 2 registers * 2");
    }
}
