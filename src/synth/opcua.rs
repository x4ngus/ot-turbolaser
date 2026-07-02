//! OPC-UA binary-protocol assertion (opc.tcp, TCP/4840).
//!
//! OPC-UA is the supervisory protocol INCONTROLLER/PIPEDREAM's OPC-UA module
//! speaks to browse and write server nodes. The connection opens with a
//! HELLO/ACKNOWLEDGE handshake that negotiates buffer sizes before any secure
//! channel; a passive sensor fingerprints an OPC-UA server from exactly that
//! exchange. We emit the handshake (which the Wireshark `opcua` dissector decodes
//! from the message-type header) as the server's identity assertion; the secure
//! channel and typed service calls that would follow are deferred (their
//! encrypted-or-signed framing is not needed to place an OPC-UA endpoint on the
//! wire).

use std::net::Ipv4Addr;

use super::session::TcpSession;

const OPCUA_PORT: u16 = 4840;

/// An OPC-UA message: 3-byte type, 1-byte chunk marker ('F' = final), 4-byte LE
/// message size (including this 8-byte header), then the body.
fn message(mtype: &[u8; 3], body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut m = Vec::with_capacity(8 + body.len());
    m.extend_from_slice(mtype);
    m.push(b'F');
    m.extend_from_slice(&size.to_le_bytes());
    m.extend_from_slice(body);
    m
}

/// An OPC-UA string: a signed 32-bit LE length prefix then the UTF-8 bytes.
fn opcua_string(s: &str) -> Vec<u8> {
    let mut v = (s.len() as i32).to_le_bytes().to_vec();
    v.extend_from_slice(s.as_bytes());
    v
}

/// The five buffer-negotiation u32s HELLO and ACKNOWLEDGE share: protocol version,
/// receive and send buffer sizes, max message size (0 = unlimited), max chunk
/// count (0 = unlimited).
fn buffers(body: &mut Vec<u8>) {
    for v in [0u32, 65535, 65535, 0, 0] {
        body.extend_from_slice(&v.to_le_bytes());
    }
}

/// The client HELLO, advertising the endpoint URL it is connecting to.
fn hello(url: &str) -> Vec<u8> {
    let mut b = Vec::new();
    buffers(&mut b);
    b.extend_from_slice(&opcua_string(url));
    message(b"HEL", &b)
}

/// The server ACKNOWLEDGE (no endpoint URL).
fn acknowledge() -> Vec<u8> {
    let mut b = Vec::new();
    buffers(&mut b);
    message(b"ACK", &b)
}

/// The client-connects-to-OPC-UA-server handshake: TCP open, HELLO, ACKNOWLEDGE,
/// close. The recon that places an OPC-UA endpoint on the wire.
pub fn read(
    client_mac: [u8; 6],
    srv_mac: [u8; 6],
    client_ip: Ipv4Addr,
    srv_ip: Ipv4Addr,
    client_port: u16,
) -> Vec<Vec<u8>> {
    let url = format!("opc.tcp://{srv_ip}:{OPCUA_PORT}");
    let mut s = TcpSession::new(
        client_mac,
        srv_mac,
        client_ip,
        srv_ip,
        client_port,
        OPCUA_PORT,
    );
    s.open();
    s.client_says(&hello(&url));
    s.server_says(&acknowledge());
    s.close();
    s.into_frames()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    #[test]
    fn handshake_is_clean_and_carries_hel_ack() {
        let frames = read(
            [0x02, 0, 0, 0, 0, 1],
            [0x00, 0x0c, 0x29, 1, 2, 3],
            Ipv4Addr::new(10, 70, 20, 250),
            Ipv4Addr::new(10, 70, 20, 30),
            50000,
        );
        for f in &frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
        let has = |tag: &[u8]| {
            frames.iter().any(|f| {
                let l = parse_layout(f).unwrap();
                f[l.payload..l.end].starts_with(tag)
            })
        };
        assert!(has(b"HEL"), "client HELLO present");
        assert!(has(b"ACK"), "server ACKNOWLEDGE present");
    }
}
