//! IEC 60870-5-101 command assertions (serial telecontrol, tunneled over TCP).
//!
//! The serial sibling of IEC-104: the same ASDU layer (interrogation, single/
//! double command) wrapped in FT1.2 link frames rather than the -104 APCI. Modern
//! substations tunnel -101 over TCP through a terminal server, which is the form a
//! passive sensor sees, so we carry it over a fixed TCP port. The ASDU is reused
//! verbatim from [`super::iec104`]; only the link framing differs (a `0x68 L L
//! 0x68` variable frame with a trailing 8-bit arithmetic checksum and `0x16` end).
//!
//! IEC-101 is not registered on a well-known TCP port, so a sensor (and a
//! dissector) keys it by the terminal-server port; tests decode it with
//! `-d tcp.port==<port>,iec60870_101`.

use std::net::Ipv4Addr;

use super::iec104::asdu;
use super::session::TcpSession;

/// The terminal-server TCP port carrying tunneled IEC-101, next to -104's 2404.
const IEC101_PORT: u16 = 2405;

// ASDU type identifiers (identical to -104).
const TID_SINGLE_CMD: u8 = 45; // C_SC_NA_1
const TID_INTERROGATION: u8 = 100; // C_IC_NA_1

// Causes of transmission.
const COT_ACT: u8 = 6;
const COT_ACTCON: u8 = 7;

/// Quality-of-interrogation: station (global) interrogation.
const QOI_STATION: u8 = 20;

// FT1.2 control field octets (DIR/PRM/FCB/FCV/func). A primary user-data frame
// with confirm, and a secondary confirm-ACK.
const CTRL_SEND: u8 = 0x73;
const CTRL_CONFIRM: u8 = 0x00;

/// An FT1.2 variable-length link frame around `asdu`: `0x68 L L 0x68`, control,
/// 1-byte link address, the ASDU, an 8-bit arithmetic checksum over
/// control+address+ASDU, and the `0x16` end byte. `L` is the length of
/// control+address+ASDU.
fn ft12(ctrl: u8, link_addr: u8, asdu: &[u8]) -> Vec<u8> {
    let l = (2 + asdu.len()) as u8; // control (1) + link addr (1) + asdu
    let mut b = vec![0x68, l, l, 0x68, ctrl, link_addr];
    b.extend_from_slice(asdu);
    let sum = std::iter::once(ctrl)
        .chain(std::iter::once(link_addr))
        .chain(asdu.iter().copied())
        .fold(0u8, |a, x| a.wrapping_add(x));
    b.push(sum);
    b.push(0x16);
    b
}

/// A station-interrogation (C_IC_NA_1) exchange: the recon a control center runs
/// to enumerate an RTU's points. `common_addr` doubles as the FT1.2 link address.
pub fn interrogation(
    client_mac: [u8; 6],
    rtu_mac: [u8; 6],
    client_ip: Ipv4Addr,
    rtu_ip: Ipv4Addr,
    client_port: u16,
    common_addr: u16,
) -> Vec<Vec<u8>> {
    let addr = common_addr as u8;
    let mut s = TcpSession::new(
        client_mac,
        rtu_mac,
        client_ip,
        rtu_ip,
        client_port,
        IEC101_PORT,
    );
    s.open();
    s.client_says(&ft12(
        CTRL_SEND,
        addr,
        &asdu(TID_INTERROGATION, COT_ACT, common_addr, 0, &[QOI_STATION]),
    ));
    s.server_says(&ft12(
        CTRL_CONFIRM,
        addr,
        &asdu(
            TID_INTERROGATION,
            COT_ACTCON,
            common_addr,
            0,
            &[QOI_STATION],
        ),
    ));
    s.close();
    s.into_frames()
}

/// A single-command (C_SC_NA_1) exchange: the breaker open/close over -101.
/// `close` true issues the close (SCS=1), false the open.
#[allow(clippy::too_many_arguments)]
pub fn single_command(
    client_mac: [u8; 6],
    rtu_mac: [u8; 6],
    client_ip: Ipv4Addr,
    rtu_ip: Ipv4Addr,
    client_port: u16,
    common_addr: u16,
    ioa: u32,
    close: bool,
) -> Vec<Vec<u8>> {
    let addr = common_addr as u8;
    let sco = u8::from(close);
    let mut s = TcpSession::new(
        client_mac,
        rtu_mac,
        client_ip,
        rtu_ip,
        client_port,
        IEC101_PORT,
    );
    s.open();
    s.client_says(&ft12(
        CTRL_SEND,
        addr,
        &asdu(TID_SINGLE_CMD, COT_ACT, common_addr, ioa, &[sco]),
    ));
    s.server_says(&ft12(
        CTRL_CONFIRM,
        addr,
        &asdu(TID_SINGLE_CMD, COT_ACTCON, common_addr, ioa, &[sco]),
    ));
    s.close();
    s.into_frames()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn endpoints() -> ([u8; 6], [u8; 6], Ipv4Addr, Ipv4Addr) {
        (
            [0x02, 0, 0, 0, 0, 1],
            [0x00, 0x80, 0x63, 1, 2, 3],
            Ipv4Addr::new(10, 70, 10, 250),
            Ipv4Addr::new(10, 70, 10, 21),
        )
    }

    fn assert_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    /// True if a data segment is a well-formed FT1.2 variable frame carrying the
    /// given ASDU type id, with a self-consistent checksum.
    fn carries_ft12(frames: &[Vec<u8>], type_id: u8) -> bool {
        frames.iter().any(|f| {
            let Some(l) = parse_layout(f) else {
                return false;
            };
            let p = &f[l.payload..l.end];
            if p.len() < 8 || p[0] != 0x68 || p[3] != 0x68 || *p.last().unwrap() != 0x16 {
                return false;
            }
            let len = p[1] as usize;
            // 0x68 L L 0x68 [len bytes] checksum 0x16
            if p.len() != 4 + len + 2 {
                return false;
            }
            let body = &p[4..4 + len];
            let sum = body.iter().fold(0u8, |a, x| a.wrapping_add(*x));
            if sum != p[4 + len] {
                return false;
            }
            // body = control + link addr + ASDU; the ASDU type id is body[2].
            body.get(2) == Some(&type_id)
        })
    }

    #[test]
    fn interrogation_is_a_clean_ft12_frame() {
        let (cm, rm, ci, ri) = endpoints();
        let frames = interrogation(cm, rm, ci, ri, 50000, 1);
        assert_clean(&frames);
        assert!(
            carries_ft12(&frames, TID_INTERROGATION),
            "C_IC_NA_1 in a checksum-valid FT1.2 frame"
        );
    }

    #[test]
    fn single_command_carries_the_breaker_command() {
        let (cm, rm, ci, ri) = endpoints();
        let frames = single_command(cm, rm, ci, ri, 50001, 1, 0x0001, false);
        assert_clean(&frames);
        assert!(carries_ft12(&frames, TID_SINGLE_CMD), "C_SC_NA_1 present");
    }
}
