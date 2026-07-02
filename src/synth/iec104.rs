//! IEC 60870-5-104 command assertions.
//!
//! The grid-control protocol behind the 2015 Ukraine attack: an operator-station
//! client opens the data link (STARTDT), interrogates an RTU, then issues
//! single/double commands -- the breaker-open messages that dropped the load.
//! Carried over TCP/2404. APCI (the I/S/U frame envelope) and the ASDU are the
//! open IEC standard, so these decode in the iec60870 dissector verbatim.

use std::net::Ipv4Addr;

use super::session::TcpSession;

const IEC104_PORT: u16 = 2404;

/// U-format control field functions (with the low two bits set).
const STARTDT_ACT: u8 = 0x07;
const STARTDT_CON: u8 = 0x0b;

/// ASDU type identifiers.
const TID_SINGLE_CMD: u8 = 45; // C_SC_NA_1
const TID_DOUBLE_CMD: u8 = 46; // C_DC_NA_1
const TID_INTERROGATION: u8 = 100; // C_IC_NA_1

/// Causes of transmission.
const COT_ACT: u8 = 6;
const COT_ACTCON: u8 = 7;
const COT_ACTTERM: u8 = 10;

/// Quality-of-interrogation: station (global) interrogation.
const QOI_STATION: u8 = 20;

/// A U-format (unnumbered control) APDU: STARTDT/STOPDT/TESTFR.
fn u_frame(func: u8) -> Vec<u8> {
    vec![0x68, 0x04, func, 0x00, 0x00, 0x00]
}

/// An I-format (information) APDU carrying an ASDU, with send/receive sequence
/// numbers in the four control octets (each shifted left one bit, little-endian).
fn i_frame(ns: u16, nr: u16, asdu: &[u8]) -> Vec<u8> {
    let len = 4 + asdu.len();
    let mut b = vec![0x68, len as u8];
    b.extend_from_slice(&(ns << 1).to_le_bytes());
    b.extend_from_slice(&(nr << 1).to_le_bytes());
    b.extend_from_slice(asdu);
    b
}

/// An S-format (supervisory) APDU acknowledging received I-frames up to `nr`.
fn s_frame(nr: u16) -> Vec<u8> {
    let mut b = vec![0x68, 0x04, 0x01, 0x00];
    b.extend_from_slice(&(nr << 1).to_le_bytes());
    b
}

/// One ASDU with a single, non-sequence information object. Shared with
/// [`super::iec101`], which wraps the same ASDU in an FT1.2 link frame rather than
/// an APCI (the ASDU layer is identical across IEC 60870-5-101 and -104).
pub(crate) fn asdu(type_id: u8, cot: u8, common_addr: u16, ioa: u32, elements: &[u8]) -> Vec<u8> {
    let mut a = vec![
        type_id, // type identification
        0x01,    // variable structure qualifier: SQ=0, 1 object
        cot,     // cause of transmission
        0x00,    // originator address
    ];
    a.extend_from_slice(&common_addr.to_le_bytes());
    // Information object address: 3 bytes, little-endian.
    a.push((ioa & 0xff) as u8);
    a.push(((ioa >> 8) & 0xff) as u8);
    a.push(((ioa >> 16) & 0xff) as u8);
    a.extend_from_slice(elements);
    a
}

/// Open the link with a STARTDT handshake.
fn start_link(s: &mut TcpSession) {
    s.open();
    s.client_says(&u_frame(STARTDT_ACT));
    s.server_says(&u_frame(STARTDT_CON));
}

/// A full single-command (C_SC_NA_1) exchange: the breaker open/close that
/// actuates a switch. `close` true issues the close (SCS=1), false the open.
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
    // SCO: bit0 = single command state (1 close / 0 open), execute (not select).
    let sco = u8::from(close);
    let mut s = TcpSession::new(
        client_mac,
        rtu_mac,
        client_ip,
        rtu_ip,
        client_port,
        IEC104_PORT,
    );
    start_link(&mut s);
    s.client_says(&i_frame(
        0,
        0,
        &asdu(TID_SINGLE_CMD, COT_ACT, common_addr, ioa, &[sco]),
    ));
    s.server_says(&i_frame(
        0,
        1,
        &asdu(TID_SINGLE_CMD, COT_ACTCON, common_addr, ioa, &[sco]),
    ));
    s.server_says(&i_frame(
        1,
        1,
        &asdu(TID_SINGLE_CMD, COT_ACTTERM, common_addr, ioa, &[sco]),
    ));
    s.client_says(&s_frame(2));
    s.close();
    s.into_frames()
}

/// A full double-command (C_DC_NA_1) exchange. `state` is the 2-bit DCS value
/// (1 = off/open, 2 = on/close).
#[allow(clippy::too_many_arguments)]
pub fn double_command(
    client_mac: [u8; 6],
    rtu_mac: [u8; 6],
    client_ip: Ipv4Addr,
    rtu_ip: Ipv4Addr,
    client_port: u16,
    common_addr: u16,
    ioa: u32,
    state: u8,
) -> Vec<Vec<u8>> {
    let dco = state & 0x03;
    let mut s = TcpSession::new(
        client_mac,
        rtu_mac,
        client_ip,
        rtu_ip,
        client_port,
        IEC104_PORT,
    );
    start_link(&mut s);
    s.client_says(&i_frame(
        0,
        0,
        &asdu(TID_DOUBLE_CMD, COT_ACT, common_addr, ioa, &[dco]),
    ));
    s.server_says(&i_frame(
        0,
        1,
        &asdu(TID_DOUBLE_CMD, COT_ACTCON, common_addr, ioa, &[dco]),
    ));
    s.client_says(&s_frame(1));
    s.close();
    s.into_frames()
}

/// A full station-interrogation (C_IC_NA_1) exchange: the recon a SCADA hijack
/// runs to enumerate the RTU's points before commanding them.
#[allow(clippy::too_many_arguments)]
pub fn interrogation(
    client_mac: [u8; 6],
    rtu_mac: [u8; 6],
    client_ip: Ipv4Addr,
    rtu_ip: Ipv4Addr,
    client_port: u16,
    common_addr: u16,
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(
        client_mac,
        rtu_mac,
        client_ip,
        rtu_ip,
        client_port,
        IEC104_PORT,
    );
    start_link(&mut s);
    s.client_says(&i_frame(
        0,
        0,
        &asdu(TID_INTERROGATION, COT_ACT, common_addr, 0, &[QOI_STATION]),
    ));
    s.server_says(&i_frame(
        0,
        1,
        &asdu(
            TID_INTERROGATION,
            COT_ACTCON,
            common_addr,
            0,
            &[QOI_STATION],
        ),
    ));
    s.server_says(&i_frame(
        1,
        1,
        &asdu(
            TID_INTERROGATION,
            COT_ACTTERM,
            common_addr,
            0,
            &[QOI_STATION],
        ),
    ));
    s.client_says(&s_frame(2));
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
            Ipv4Addr::new(10, 30, 0, 250),
            Ipv4Addr::new(10, 30, 0, 9),
        )
    }

    fn assert_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    /// True if some data segment's payload starts with the IEC-104 0x68 start
    /// byte and contains the given ASDU type id.
    fn carries_type(frames: &[Vec<u8>], type_id: u8) -> bool {
        frames.iter().any(|f| {
            let Some(l) = parse_layout(f) else {
                return false;
            };
            let pdu = &f[l.payload..l.end];
            !pdu.is_empty() && pdu[0] == 0x68 && pdu.contains(&type_id)
        })
    }

    #[test]
    fn single_command_opens_link_and_carries_breaker_command() {
        let (cm, rm, ci, ri) = endpoints();
        let frames = single_command(cm, rm, ci, ri, 50010, 1, 0x0001, false);
        assert_clean(&frames);
        // STARTDT act is the first client data segment after the handshake.
        let l = parse_layout(&frames[3]).unwrap();
        let pdu = &frames[3][l.payload..l.end];
        assert_eq!(
            pdu,
            &[0x68, 0x04, STARTDT_ACT, 0x00, 0x00, 0x00],
            "STARTDT act"
        );
        assert!(carries_type(&frames, TID_SINGLE_CMD), "C_SC_NA_1 present");
    }

    #[test]
    fn interrogation_carries_station_qoi() {
        let (cm, rm, ci, ri) = endpoints();
        let frames = interrogation(cm, rm, ci, ri, 50011, 1);
        assert_clean(&frames);
        assert!(
            carries_type(&frames, TID_INTERROGATION),
            "C_IC_NA_1 present"
        );
        let qoi_present = frames.iter().any(|f| {
            let l = parse_layout(f).unwrap();
            let pdu = &f[l.payload..l.end];
            pdu.first() == Some(&0x68) && pdu.last() == Some(&QOI_STATION)
        });
        assert!(qoi_present, "station QOI 20 on the wire");
    }

    #[test]
    fn double_command_is_clean() {
        let (cm, rm, ci, ri) = endpoints();
        let frames = double_command(cm, rm, ci, ri, 50012, 1, 0x0002, 1);
        assert_clean(&frames);
        assert!(carries_type(&frames, TID_DOUBLE_CMD), "C_DC_NA_1 present");
    }
}
