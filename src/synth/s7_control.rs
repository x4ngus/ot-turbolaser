//! S7comm control and program-download assertions.
//!
//! Where [`super::s7_szl`] reads a CPU's identity, this module renders the
//! *control-plane* actions a Stuxnet-class attack performs once it owns the
//! engineering path: a PLC STOP, a block program-download sequence (Request
//! Download / Download Block / Download Ended), and a Write-Var that drops a
//! rogue value into a data block (the sabotage signature -- e.g. forcing a
//! drive's frequency setpoint). Each is emitted as a complete S7 session
//! (handshake, COTP connect, SetupCommunication, the action, teardown) on the
//! shared framing in [`super::s7_common`], so a stateful sensor parses it on an
//! established connection.
//!
//! These reproduce the sensor-visible signature -- the S7 ROSCTR job function
//! codes (0x1A/0x1B/0x1C download, 0x29 stop, 0x05 write) and the block
//! descriptors -- not a bit-exact controller transfer.

use std::net::Ipv4Addr;

use super::s7_common::{
    cotp_cc, cotp_cr, s7_setup_request, s7_setup_response, tpkt_cotp, S7_PORT,
};
use super::session::TcpSession;

const ROSCTR_JOB: u8 = 0x01;
const ROSCTR_ACK_DATA: u8 = 0x03;

/// S7 function codes carried in a job parameter.
const FN_WRITE_VAR: u8 = 0x05;
const FN_PLC_STOP: u8 = 0x29;
const FN_REQUEST_DOWNLOAD: u8 = 0x1a;
const FN_DOWNLOAD_BLOCK: u8 = 0x1b;
const FN_DOWNLOAD_ENDED: u8 = 0x1c;

/// Build an S7 job message (ROSCTR 0x01) from a parameter and data block, framed
/// in TPKT + COTP.
fn s7_job(param: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s7 = vec![0x32, ROSCTR_JOB, 0x00, 0x00, 0x00, 0x00];
    s7.extend_from_slice(&(param.len() as u16).to_be_bytes());
    s7.extend_from_slice(&(data.len() as u16).to_be_bytes());
    s7.extend_from_slice(param);
    s7.extend_from_slice(data);
    tpkt_cotp(&s7)
}

/// Build an S7 ack_data message (ROSCTR 0x03) -- the PLC's reply, which carries
/// two error bytes after the length fields.
fn s7_ack_data(param: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s7 = vec![0x32, ROSCTR_ACK_DATA, 0x00, 0x00, 0x00, 0x00];
    s7.extend_from_slice(&(param.len() as u16).to_be_bytes());
    s7.extend_from_slice(&(data.len() as u16).to_be_bytes());
    s7.extend_from_slice(&[0x00, 0x00]); // error class / error code: success
    s7.extend_from_slice(param);
    s7.extend_from_slice(data);
    tpkt_cotp(&s7)
}

/// A 9-byte S7 block identifier like "_0800001P": leading '_', a two-ASCII block
/// type code, a five-ASCII block number, and the destination filesystem letter.
fn block_descriptor(block_id: &str) -> Vec<u8> {
    let mut b = [b'_', b'0', b'8', b'0', b'0', b'0', b'0', b'1', b'P'];
    for (dst, src) in b.iter_mut().zip(block_id.bytes()) {
        *dst = src;
    }
    b.to_vec()
}

/// Open an S7 session and run the given request/response exchanges after the
/// SetupCommunication negotiation, returning the full frame sequence.
fn s7_session(
    client_mac: [u8; 6],
    plc_mac: [u8; 6],
    client_ip: Ipv4Addr,
    plc_ip: Ipv4Addr,
    client_port: u16,
    exchanges: &[(Vec<u8>, Vec<u8>)],
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(client_mac, plc_mac, client_ip, plc_ip, client_port, S7_PORT);
    s.open();
    s.client_says(&cotp_cr());
    s.server_says(&cotp_cc());
    s.client_says(&s7_setup_request());
    s.server_says(&s7_setup_response());
    for (req, resp) in exchanges {
        s.client_says(req);
        s.server_says(resp);
    }
    s.close();
    s.into_frames()
}

/// Request to STOP the PLC (ROSCTR job, PI service function 0x29 "P_PROGRAM").
fn plc_stop_request() -> Vec<u8> {
    let mut param = vec![FN_PLC_STOP, 0x00, 0x00, 0x00, 0x00, 0x00];
    param.push(0x09); // length of the PI service name
    param.extend_from_slice(b"P_PROGRAM");
    s7_job(&param, &[])
}

fn plc_stop_response() -> Vec<u8> {
    s7_ack_data(&[FN_PLC_STOP], &[])
}

/// A Write-Var request that drops a 16-bit value into a data block: the sabotage
/// signature (e.g. forcing a drive frequency setpoint to a destructive value).
fn write_db_word_request(db: u16, byte_offset: u16, value: u16) -> Vec<u8> {
    let bit_addr = u32::from(byte_offset) * 8;
    let param = [
        FN_WRITE_VAR,
        0x01, // item count
        0x12, // var spec
        0x0a, // length of address spec following
        0x10, // syntax id: S7ANY
        0x04, // transport size: WORD
        0x00,
        0x01, // number of elements: 1
        (db >> 8) as u8,
        (db & 0xff) as u8, // DB number
        0x84, // area: data block (DB)
        ((bit_addr >> 16) & 0xff) as u8,
        ((bit_addr >> 8) & 0xff) as u8,
        (bit_addr & 0xff) as u8,
    ];
    let data = [
        0x00, // reserved
        0x04, // transport size: byte/word/dword (length in bits)
        0x00,
        0x10, // length: 16 bits
        (value >> 8) as u8,
        (value & 0xff) as u8,
    ];
    s7_job(&param, &data)
}

fn write_var_response() -> Vec<u8> {
    // Param echoes function + item count; data carries one per-item return code.
    s7_ack_data(&[FN_WRITE_VAR, 0x01], &[0xff])
}

fn request_download(block_id: &str) -> Vec<u8> {
    let desc = block_descriptor(block_id);
    let mut param = vec![FN_REQUEST_DOWNLOAD, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    param.push(desc.len() as u8);
    param.extend_from_slice(&desc);
    param.push(0x01); // length-string marker
    param.extend_from_slice(b"000420"); // load-memory length (ASCII)
    param.extend_from_slice(b"000260"); // MC7 code length (ASCII)
    s7_job(&param, &[])
}

fn request_download_ack() -> Vec<u8> {
    s7_ack_data(&[FN_REQUEST_DOWNLOAD], &[])
}

fn download_block(block_id: &str, mc7: &[u8]) -> Vec<u8> {
    let desc = block_descriptor(block_id);
    let mut param = vec![FN_DOWNLOAD_BLOCK, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    param.push(desc.len() as u8);
    param.extend_from_slice(&desc);
    s7_job(&param, mc7)
}

fn download_block_ack(mc7: &[u8]) -> Vec<u8> {
    // The PLC echoes the block bytes back in the ack as it stores them.
    s7_ack_data(&[FN_DOWNLOAD_BLOCK, 0x00], mc7)
}

fn download_ended(block_id: &str) -> Vec<u8> {
    let desc = block_descriptor(block_id);
    let mut param = vec![FN_DOWNLOAD_ENDED, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    param.push(desc.len() as u8);
    param.extend_from_slice(&desc);
    s7_job(&param, &[])
}

fn download_ended_ack() -> Vec<u8> {
    s7_ack_data(&[FN_DOWNLOAD_ENDED], &[])
}

/// A full PLC STOP exchange.
#[allow(clippy::too_many_arguments)]
pub fn plc_stop(
    client_mac: [u8; 6],
    plc_mac: [u8; 6],
    client_ip: Ipv4Addr,
    plc_ip: Ipv4Addr,
    client_port: u16,
) -> Vec<Vec<u8>> {
    s7_session(
        client_mac,
        plc_mac,
        client_ip,
        plc_ip,
        client_port,
        &[(plc_stop_request(), plc_stop_response())],
    )
}

/// A full Write-Var sabotage exchange writing `value` into DB `db` at
/// `byte_offset`.
#[allow(clippy::too_many_arguments)]
pub fn write_db_word(
    client_mac: [u8; 6],
    plc_mac: [u8; 6],
    client_ip: Ipv4Addr,
    plc_ip: Ipv4Addr,
    client_port: u16,
    db: u16,
    byte_offset: u16,
    value: u16,
) -> Vec<Vec<u8>> {
    s7_session(
        client_mac,
        plc_mac,
        client_ip,
        plc_ip,
        client_port,
        &[(write_db_word_request(db, byte_offset, value), write_var_response())],
    )
}

/// A full block program-download sequence: Request Download, one Download Block
/// carrying the implant bytes, then Download Ended.
#[allow(clippy::too_many_arguments)]
pub fn program_download(
    client_mac: [u8; 6],
    plc_mac: [u8; 6],
    client_ip: Ipv4Addr,
    plc_ip: Ipv4Addr,
    client_port: u16,
    block_id: &str,
    mc7: &[u8],
) -> Vec<Vec<u8>> {
    s7_session(
        client_mac,
        plc_mac,
        client_ip,
        plc_ip,
        client_port,
        &[
            (request_download(block_id), request_download_ack()),
            (download_block(block_id, mc7), download_block_ack(mc7)),
            (download_ended(block_id), download_ended_ack()),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn endpoints() -> ([u8; 6], [u8; 6], Ipv4Addr, Ipv4Addr) {
        (
            [0x02, 0, 0, 0, 0, 1],
            [0x00, 0x0e, 0x8c, 1, 2, 3],
            Ipv4Addr::new(10, 20, 0, 250),
            Ipv4Addr::new(10, 20, 0, 11),
        )
    }

    /// Every frame in a session parses as TCP/102 and checksums clean.
    fn assert_session_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("frame parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp, "S7 is TCP");
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    /// The S7 protocol id and the given ROSCTR function byte appear in some
    /// server/client data segment of the session.
    fn carries_function(frames: &[Vec<u8>], func: u8) -> bool {
        frames.iter().any(|f| {
            let Some(l) = parse_layout(f) else {
                return false;
            };
            let pdu = &f[l.payload..l.end];
            // TPKT(4) + COTP(3) then S7: protocol id 0x32 at pdu[7], and the
            // function byte sits in the parameter just past the 10-byte job
            // header (pdu[7+10] = pdu[17]).
            pdu.len() > 17 && pdu[7] == 0x32 && pdu.contains(&func)
        })
    }

    #[test]
    fn plc_stop_is_clean_and_carries_stop_function() {
        let (cm, pm, ci, pi) = endpoints();
        let frames = plc_stop(cm, pm, ci, pi, 50001);
        assert_session_clean(&frames);
        assert!(carries_function(&frames, FN_PLC_STOP), "0x29 PLC stop present");
    }

    #[test]
    fn write_db_word_is_clean_and_carries_value() {
        let (cm, pm, ci, pi) = endpoints();
        // 1410 Hz rogue setpoint, the Stuxnet over-speed value.
        let frames = write_db_word(cm, pm, ci, pi, 50002, 1, 0, 1410);
        assert_session_clean(&frames);
        assert!(carries_function(&frames, FN_WRITE_VAR), "0x05 write var");
        let value_present = frames.iter().any(|f| {
            let l = parse_layout(f).unwrap();
            f[l.payload..l.end].windows(2).any(|w| w == 1410u16.to_be_bytes())
        });
        assert!(value_present, "the rogue value 1410 is on the wire");
    }

    #[test]
    fn program_download_runs_three_download_functions() {
        let (cm, pm, ci, pi) = endpoints();
        let frames = program_download(cm, pm, ci, pi, 50003, "_0800001P", b"\x70\x70\x01\x02");
        assert_session_clean(&frames);
        assert!(carries_function(&frames, FN_REQUEST_DOWNLOAD), "0x1A");
        assert!(carries_function(&frames, FN_DOWNLOAD_BLOCK), "0x1B");
        assert!(carries_function(&frames, FN_DOWNLOAD_ENDED), "0x1C");
    }
}
