//! EtherNet/IP CIP explicit-messaging assertions (connected, TCP/44818).
//!
//! Complements [`super::enip_identity`] (the connectionless UDP List Identity
//! recon) with the connected explicit-messaging path an attacker uses to read and
//! write a controller's attributes: RegisterSession, then a `SendRRData` carrying
//! a CIP request in the Common Packet Format. Get_Attribute_Single reads the
//! identity object (recon); Set_Attribute_Single writes an attribute (the
//! manipulation, e.g. INCONTROLLER's Schneider/CODESYS module). ENIP encapsulation
//! and CIP are the open ODVA encoding, so they decode in the enip/cip dissectors.

use std::net::Ipv4Addr;

use super::session::TcpSession;

const ENIP_PORT: u16 = 44818;
const CMD_REGISTER_SESSION: u16 = 0x0065;
const CMD_SEND_RR_DATA: u16 = 0x006F;
const ITEM_NULL_ADDRESS: u16 = 0x0000;
const ITEM_UNCONNECTED_DATA: u16 = 0x00B2;

// CIP service codes; the reply sets the high bit (service | 0x80).
const SVC_GET_ATTR_SINGLE: u8 = 0x0E;
const SVC_SET_ATTR_SINGLE: u8 = 0x10;

/// A 24-byte ENIP encapsulation header wrapping `body`, with an explicit session
/// handle (non-zero on an established session).
fn encap(command: u16, session: u32, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(24 + body.len());
    p.extend_from_slice(&command.to_le_bytes());
    p.extend_from_slice(&(body.len() as u16).to_le_bytes());
    p.extend_from_slice(&session.to_le_bytes());
    p.extend_from_slice(&[0; 4]); // status
    p.extend_from_slice(&[0; 8]); // sender context
    p.extend_from_slice(&[0; 4]); // options
    p.extend_from_slice(body);
    p
}

/// The RegisterSession body: protocol version 1, options 0.
fn register_body() -> Vec<u8> {
    vec![0x01, 0x00, 0x00, 0x00]
}

/// Wrap a CIP request/response in a `SendRRData` command: interface handle 0,
/// timeout 0, then a CPF item list (a null address item and an unconnected data
/// item carrying the CIP message).
fn send_rr_data(session: u32, cip: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // interface handle
    body.extend_from_slice(&0u16.to_le_bytes()); // timeout
    body.extend_from_slice(&2u16.to_le_bytes()); // CPF item count
    body.extend_from_slice(&ITEM_NULL_ADDRESS.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // null address item length
    body.extend_from_slice(&ITEM_UNCONNECTED_DATA.to_le_bytes());
    body.extend_from_slice(&(cip.len() as u16).to_le_bytes());
    body.extend_from_slice(cip);
    encap(CMD_SEND_RR_DATA, session, &body)
}

/// An EPATH to the given class/instance/attribute (three 8-bit logical segments),
/// as the padded byte sequence a CIP request request-path carries.
fn epath(class: u8, instance: u8, attribute: u8) -> Vec<u8> {
    vec![0x20, class, 0x24, instance, 0x30, attribute]
}

/// A CIP request: service, request-path size in 16-bit words, the path, then any
/// service data.
fn cip_request(service: u8, path: &[u8], data: &[u8]) -> Vec<u8> {
    let mut r = vec![service, (path.len() / 2) as u8];
    r.extend_from_slice(path);
    r.extend_from_slice(data);
    r
}

/// A CIP success response: reply service (request | 0x80), reserved 0, general
/// status 0 (success), additional status size 0, then any response data.
fn cip_response(service: u8, data: &[u8]) -> Vec<u8> {
    let mut r = vec![service | 0x80, 0x00, 0x00, 0x00];
    r.extend_from_slice(data);
    r
}

/// RegisterSession, then one SendRRData request/response, then close. Shared by
/// the read and write actions; `req`/`resp` are the CIP messages.
fn cip_exchange(
    client_mac: [u8; 6],
    dev_mac: [u8; 6],
    client_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    client_port: u16,
    req: &[u8],
    resp: &[u8],
) -> Vec<Vec<u8>> {
    const SESSION: u32 = 0x0000_1A2B; // handle the server "assigns" at RegisterSession
    let mut s = TcpSession::new(
        client_mac,
        dev_mac,
        client_ip,
        dev_ip,
        client_port,
        ENIP_PORT,
    );
    s.open();
    s.client_says(&encap(CMD_REGISTER_SESSION, 0, &register_body()));
    s.server_says(&encap(CMD_REGISTER_SESSION, SESSION, &register_body()));
    s.client_says(&send_rr_data(SESSION, req));
    s.server_says(&send_rr_data(SESSION, resp));
    s.close();
    s.into_frames()
}

/// A CIP Get_Attribute_Single read of the Identity object (class 1) attribute 1,
/// the connected-session recon an ENIP scanner runs.
pub fn get_attribute(
    client_mac: [u8; 6],
    dev_mac: [u8; 6],
    client_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    client_port: u16,
) -> Vec<Vec<u8>> {
    let req = cip_request(SVC_GET_ATTR_SINGLE, &epath(0x01, 0x01, 0x01), &[]);
    let resp = cip_response(SVC_GET_ATTR_SINGLE, &1u16.to_le_bytes());
    cip_exchange(
        client_mac,
        dev_mac,
        client_ip,
        dev_ip,
        client_port,
        &req,
        &resp,
    )
}

/// A CIP Set_Attribute_Single write to an assembly-object attribute (the
/// manipulation): `attribute` on class 4 instance 1, carrying the 16-bit `value`.
pub fn set_attribute(
    client_mac: [u8; 6],
    dev_mac: [u8; 6],
    client_ip: Ipv4Addr,
    dev_ip: Ipv4Addr,
    client_port: u16,
    attribute: u8,
    value: u16,
) -> Vec<Vec<u8>> {
    let req = cip_request(
        SVC_SET_ATTR_SINGLE,
        &epath(0x04, 0x01, attribute),
        &value.to_le_bytes(),
    );
    let resp = cip_response(SVC_SET_ATTR_SINGLE, &[]);
    cip_exchange(
        client_mac,
        dev_mac,
        client_ip,
        dev_ip,
        client_port,
        &req,
        &resp,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn endpoints() -> ([u8; 6], [u8; 6], Ipv4Addr, Ipv4Addr) {
        (
            [0x02, 0, 0, 0, 0, 1],
            [0x00, 0x00, 0xBC, 1, 2, 3],
            Ipv4Addr::new(10, 70, 10, 250),
            Ipv4Addr::new(10, 70, 10, 12),
        )
    }

    fn assert_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    /// True if a data segment carries an ENIP command with the given code.
    fn carries_command(frames: &[Vec<u8>], command: u16) -> bool {
        frames.iter().any(|f| {
            let Some(l) = parse_layout(f) else {
                return false;
            };
            let p = &f[l.payload..l.end];
            p.len() >= 2 && u16::from_le_bytes([p[0], p[1]]) == command
        })
    }

    #[test]
    fn get_attribute_registers_then_reads() {
        let (cm, dm, ci, di) = endpoints();
        let frames = get_attribute(cm, dm, ci, di, 50000);
        assert_clean(&frames);
        assert!(
            carries_command(&frames, CMD_REGISTER_SESSION),
            "RegisterSession"
        );
        assert!(carries_command(&frames, CMD_SEND_RR_DATA), "SendRRData");
    }

    #[test]
    fn set_attribute_carries_the_write_value() {
        let (cm, dm, ci, di) = endpoints();
        let frames = set_attribute(cm, dm, ci, di, 50001, 3, 0x2B5C);
        assert_clean(&frames);
        let present = frames.iter().any(|f| {
            let l = parse_layout(f).unwrap();
            f[l.payload..l.end]
                .windows(2)
                .any(|w| w == 0x2B5Cu16.to_le_bytes())
        });
        assert!(present, "the rogue write value is on the wire");
    }
}
