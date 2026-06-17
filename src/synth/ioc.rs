//! Indicator-of-compromise injectors.
//!
//! The non-OT artifacts a scenario surfaces around its control-plane actions: a
//! C2 beacon (DNS lookup of the actor's domain, then a contact to its address),
//! an external remote-access session (TeamViewer/VPN), a wiper's network-share
//! write (KillDisk), and a serial-converter firmware overwrite (the Moxa brick).
//! Each is generic and driven by the playbook's actor/IOC fields, so a scenario
//! supplies the real published indicators as data.
//!
//! These reproduce the sensor-visible signature (the domain/address on the wire,
//! the protocol and port), not working malware: no payload here executes or
//! completes a transfer; the frames are replayed to a mirror on the isolated
//! bridge.

use std::net::Ipv4Addr;

use super::dns;
use super::eth::udp_frame;
use super::session::TcpSession;

/// A command-and-control endpoint.
pub struct C2Target<'a> {
    pub domain: &'a str,
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// A C2 beacon: resolve the actor's domain, then open a short HTTP contact to
/// its address (carrying the domain in the Host header). `gateway_mac` is the
/// L2 next hop for the routable C2 address.
#[allow(clippy::too_many_arguments)]
pub fn c2_beacon(
    host_mac: [u8; 6],
    host_ip: Ipv4Addr,
    resolver_mac: [u8; 6],
    resolver_ip: Ipv4Addr,
    gateway_mac: [u8; 6],
    c2: &C2Target,
    client_port: u16,
    qid: u16,
) -> Vec<Vec<u8>> {
    let mut frames = vec![
        dns::query(
            host_mac,
            resolver_mac,
            host_ip,
            resolver_ip,
            client_port,
            qid,
            c2.domain,
        ),
        dns::response(
            resolver_mac,
            host_mac,
            resolver_ip,
            host_ip,
            client_port,
            qid,
            c2.domain,
            c2.ip,
        ),
    ];
    let mut s = TcpSession::new(
        host_mac,
        gateway_mac,
        host_ip,
        c2.ip,
        client_port.wrapping_add(1) | 0xc000,
        c2.port,
    );
    s.open();
    s.client_says(
        format!(
            "GET /ping HTTP/1.1\r\nHost: {}\r\nUser-Agent: \r\n\r\n",
            c2.domain
        )
        .as_bytes(),
    );
    s.server_says(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    s.close();
    frames.extend(s.into_frames());
    frames
}

/// An inbound remote-access session from an external host to an internal box
/// (TeamViewer TCP/5938, a VPN port, etc.). `gateway_mac` is the L2 next hop the
/// external source arrives via.
#[allow(clippy::too_many_arguments)]
pub fn remote_access(
    gateway_mac: [u8; 6],
    external_ip: Ipv4Addr,
    host_mac: [u8; 6],
    host_ip: Ipv4Addr,
    external_port: u16,
    access_port: u16,
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(
        gateway_mac,
        host_mac,
        external_ip,
        host_ip,
        external_port,
        access_port,
    );
    s.open();
    s.client_says(b"\x17\x24\x00\x00remote-control-init");
    s.server_says(b"\x17\x24\x00\x00remote-control-ack");
    s.client_says(b"\x17\x24\x00\x00session-active");
    s.close();
    s.into_frames()
}

/// A wiper's write to a network share over SMB2/TCP-445 (the KillDisk staging
/// signature). Models the SMB2 WRITE to the named share; no payload executes.
#[allow(clippy::too_many_arguments)]
pub fn smb_share_write(
    client_mac: [u8; 6],
    server_mac: [u8; 6],
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    client_port: u16,
    share: &str,
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        client_port,
        445,
    );
    s.open();
    s.client_says(&smb2_write(share));
    s.server_says(&smb2_write_response(share.len() as u32));
    s.close();
    s.into_frames()
}

const SMB2_WRITE: u16 = 0x0009;
const SMB2_FLAGS_RESPONSE: u32 = 0x0000_0001;

/// A 64-byte SMB2 sync header.
fn smb2_header(command: u16, flags: u32, message_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xfe, b'S', b'M', b'B']); // ProtocolId
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize (header)
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status (SUCCESS)
    h.extend_from_slice(&command.to_le_bytes()); // Command
    h.extend_from_slice(&1u16.to_le_bytes()); // Credit request/response
    h.extend_from_slice(&flags.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved (ProcessId)
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// A valid SMB2 WRITE request whose buffer carries the target share path, so the
/// wiper's destination is on the wire and the smb2 dissector parses it cleanly.
fn smb2_write(share: &str) -> Vec<u8> {
    let data = share.as_bytes();
    let mut smb = smb2_header(SMB2_WRITE, 0, 1);
    smb.extend_from_slice(&49u16.to_le_bytes()); // StructureSize (WRITE request)
    smb.extend_from_slice(&(64u16 + 48).to_le_bytes()); // DataOffset (header + fixed)
    smb.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Length
    smb.extend_from_slice(&0u64.to_le_bytes()); // Offset
    smb.extend_from_slice(&[0xff; 16]); // FileId
    smb.extend_from_slice(&0u32.to_le_bytes()); // Channel
    smb.extend_from_slice(&0u32.to_le_bytes()); // RemainingBytes
    smb.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    smb.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb.extend_from_slice(data); // the write buffer
    nbss(&smb)
}

/// A valid SMB2 WRITE response acknowledging `count` bytes written.
fn smb2_write_response(count: u32) -> Vec<u8> {
    let mut smb = smb2_header(SMB2_WRITE, SMB2_FLAGS_RESPONSE, 1);
    smb.extend_from_slice(&17u16.to_le_bytes()); // StructureSize (WRITE response)
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb.extend_from_slice(&count.to_le_bytes()); // Count
    smb.extend_from_slice(&0u32.to_le_bytes()); // Remaining
    smb.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    smb.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    nbss(&smb)
}

/// Wrap an SMB payload in a NetBIOS Session Service header (type 0, 3-byte len).
fn nbss(smb: &[u8]) -> Vec<u8> {
    let mut b = vec![0x00];
    let len = smb.len();
    b.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    b.extend_from_slice(smb);
    b
}

/// A firmware overwrite to a Moxa NPort serial-to-Ethernet converter over its
/// UDP admin port (4800) -- the device-bricking step. Reproduces the write
/// opcode and a chunk on the wire; no firmware is transferred.
#[allow(clippy::too_many_arguments)]
pub fn moxa_brick(
    client_mac: [u8; 6],
    conv_mac: [u8; 6],
    client_ip: Ipv4Addr,
    conv_ip: Ipv4Addr,
    client_port: u16,
    firmware_chunk: &[u8],
) -> Vec<Vec<u8>> {
    const MOXA_ADMIN_PORT: u16 = 4800;
    // Opcode 0x19 = "write firmware" in the Moxa admin protocol (modeled), then
    // a length and the chunk.
    let mut body = vec![0x19, 0x00];
    body.extend_from_slice(&(firmware_chunk.len() as u16).to_le_bytes());
    body.extend_from_slice(firmware_chunk);
    let req = udp_frame(
        client_mac,
        conv_mac,
        client_ip,
        conv_ip,
        client_port,
        MOXA_ADMIN_PORT,
        &body,
    );
    let ack = udp_frame(
        conv_mac,
        client_mac,
        conv_ip,
        client_ip,
        MOXA_ADMIN_PORT,
        client_port,
        &[0x19, 0x80, 0x00, 0x00], // write accepted
    );
    vec![req, ack]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    fn payload_contains(frames: &[Vec<u8>], needle: &[u8]) -> bool {
        frames.iter().any(|f| {
            let l = parse_layout(f).unwrap();
            f[l.payload..l.end]
                .windows(needle.len())
                .any(|w| w == needle)
        })
    }

    #[test]
    fn c2_beacon_resolves_and_contacts_the_domain() {
        let c2 = C2Target {
            domain: "www.mypremierfutbol.com",
            ip: Ipv4Addr::new(203, 0, 113, 7),
            port: 80,
        };
        let frames = c2_beacon(
            [0x02, 0, 0, 0, 0, 1],
            Ipv4Addr::new(10, 0, 0, 5),
            [0x02, 0, 0, 0, 0, 2],
            Ipv4Addr::new(10, 0, 0, 1),
            [0x02, 0, 0, 0, 0, 0xfe],
            &c2,
            50000,
            0x1234,
        );
        clean(&frames);
        // The domain rides both the DNS query and the HTTP Host header.
        assert!(
            payload_contains(&frames, b"mypremierfutbol"),
            "domain on wire"
        );
        // The C2 address is the destination of the TCP beacon.
        let to_c2 = frames.iter().any(|f| {
            let l = parse_layout(f).unwrap();
            l.l4_kind == L4Kind::Tcp && f[l.l3 + 16..l.l3 + 20] == [203, 0, 113, 7]
        });
        assert!(to_c2, "beacon reaches the C2 address");
    }

    #[test]
    fn remote_access_session_targets_the_access_port() {
        let frames = remote_access(
            [0x02, 0, 0, 0, 0, 0xfe],
            Ipv4Addr::new(198, 51, 100, 23),
            [0x02, 0, 0, 0, 0, 9],
            Ipv4Addr::new(10, 0, 0, 9),
            44321,
            5938,
        );
        clean(&frames);
        let l = parse_layout(&frames[0]).unwrap();
        assert_eq!(
            u16::from_be_bytes([frames[0][l.l4 + 2], frames[0][l.l4 + 3]]),
            5938,
            "SYN to the TeamViewer port"
        );
    }

    #[test]
    fn smb_write_carries_smb2_magic_and_write_command() {
        let frames = smb_share_write(
            [0; 6],
            [0; 6],
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Addr::new(10, 0, 0, 4),
            50001,
            "\\\\10.0.0.4\\ADMIN$\\kill.dll",
        );
        clean(&frames);
        assert!(payload_contains(&frames, b"\xfeSMB"), "SMB2 magic present");
        assert!(payload_contains(&frames, b"ADMIN$"), "the share path");
    }

    #[test]
    fn moxa_brick_writes_firmware_over_udp_4800() {
        let frames = moxa_brick(
            [0; 6],
            [0; 6],
            Ipv4Addr::new(10, 30, 0, 250),
            Ipv4Addr::new(10, 30, 0, 60),
            50002,
            b"\xde\xad\xbe\xef",
        );
        clean(&frames);
        let l = parse_layout(&frames[0]).unwrap();
        assert_eq!(l.l4_kind, L4Kind::Udp, "Moxa admin is UDP");
        assert_eq!(
            u16::from_be_bytes([frames[0][l.l4 + 2], frames[0][l.l4 + 3]]),
            4800,
            "to the Moxa admin port"
        );
        assert_eq!(frames[0][l.payload], 0x19, "write-firmware opcode");
    }
}
