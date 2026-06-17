//! S7comm SZL module-identification assertion.
//!
//! A client reads SZL-ID 0x0011 (module identification) and the PLC responds
//! with the module order number (MLFB) and version, the identity a passive
//! sensor reads to recognise a Siemens S7 CPU and match its CVEs. Carried over
//! TPKT + COTP + S7 userdata on port 102.
//!
//! A real S7 conversation is stateful: TCP handshake, then a COTP Connection
//! Request/Confirm, then an S7 SetupCommunication exchange, and only then the
//! function calls (here the SZL read). A sensor that tracks COTP/S7 session
//! state will not attribute identity from a bare DT segment with no connection
//! set up, so [`exchange`] emits the whole sequence.

use std::net::Ipv4Addr;

use super::s7_common::{cotp_cc, cotp_cr, s7_setup_request, s7_setup_response, tpkt_cotp, S7_PORT};
use super::session::TcpSession;

/// The Read SZL request for module identification (SZL-ID 0x0011, index 0). The
/// byte layout is fixed: userdata, CPU function group, read-SZL subfunction.
pub fn read_szl_request() -> Vec<u8> {
    let mut s7 = vec![
        0x32, 0x07, 0x00, 0x00, 0x00, 0x00, // protocol, userdata, reserved, pdu ref
        0x00, 0x08, // parameter length 8
        0x00, 0x08, // data length 8
    ];
    // Userdata parameter: head, len, method=request, type/funcgroup=req+cpu,
    // subfunction=read SZL, sequence.
    s7.extend_from_slice(&[0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00]);
    // Data: return code 0xFF, transport octet-string, length 4, SZL-ID 0x0011,
    // SZL-Index 0x0000.
    s7.extend_from_slice(&[0xff, 0x09, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00]);
    tpkt_cotp(&s7)
}

/// The Read SZL response carrying one module-identification record: the order
/// number (MLFB, 20 bytes) and a two-byte version.
pub fn read_szl_response(order_number: &str, version_major: u8, version_minor: u8) -> Vec<u8> {
    // SZL 0x0011 record: index, MLFB (20 bytes, space padded), BGTyp, two
    // version words.
    let mut mlfb = [b' '; 20];
    for (dst, src) in mlfb.iter_mut().zip(order_number.bytes()) {
        *dst = src;
    }
    let mut record = Vec::new();
    record.extend_from_slice(&0x0001u16.to_be_bytes()); // record index
    record.extend_from_slice(&mlfb);
    record.extend_from_slice(&0x0000u16.to_be_bytes()); // BGTyp
    record.extend_from_slice(&[version_major, version_minor]); // Ausbg1 (version)
    record.extend_from_slice(&0x0000u16.to_be_bytes()); // Ausbg2

    let mut szl = Vec::new();
    szl.extend_from_slice(&0x0011u16.to_be_bytes()); // SZL-ID
    szl.extend_from_slice(&0x0000u16.to_be_bytes()); // SZL-Index
    szl.extend_from_slice(&(record.len() as u16).to_be_bytes()); // partial list length
    szl.extend_from_slice(&0x0001u16.to_be_bytes()); // partial list count
    szl.extend_from_slice(&record);

    let mut data = vec![0xff, 0x09]; // return code success, transport octet string
    data.extend_from_slice(&(szl.len() as u16).to_be_bytes());
    data.extend_from_slice(&szl);

    let param: [u8; 12] = [
        0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut s7 = vec![0x32, 0x07, 0x00, 0x00, 0x00, 0x00];
    s7.extend_from_slice(&(param.len() as u16).to_be_bytes());
    s7.extend_from_slice(&(data.len() as u16).to_be_bytes());
    s7.extend_from_slice(&param);
    s7.extend_from_slice(&data);
    tpkt_cotp(&s7)
}

/// The frames of an SZL module-identification read as a complete S7 session:
/// TCP handshake, COTP connection request/confirm, S7 SetupCommunication, the
/// SZL read request and response, then a graceful teardown. A stateful sensor
/// only attributes the module identity on an established S7 connection.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    client_mac: [u8; 6],
    plc_mac: [u8; 6],
    client_ip: Ipv4Addr,
    plc_ip: Ipv4Addr,
    client_port: u16,
    order_number: &str,
    version_major: u8,
    version_minor: u8,
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(client_mac, plc_mac, client_ip, plc_ip, client_port, S7_PORT);
    s.open();
    s.client_says(&cotp_cr());
    s.server_says(&cotp_cc());
    s.client_says(&s7_setup_request());
    s.server_says(&s7_setup_response());
    s.client_says(&read_szl_request());
    s.server_says(&read_szl_response(
        order_number,
        version_major,
        version_minor,
    ));
    s.close();
    s.into_frames()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpkt_length_matches_contents() {
        let req = read_szl_request();
        let tpkt_len = u16::from_be_bytes([req[2], req[3]]) as usize;
        assert_eq!(tpkt_len, req.len(), "TPKT length covers the whole message");
        // TPKT (4) + COTP (3): S7 protocol id 0x32 at index 7, ROSCTR at 8.
        assert_eq!(req[7], 0x32, "S7 protocol id");
        assert_eq!(req[8], 0x07, "ROSCTR userdata");

        let resp = read_szl_response("6ES7 212-1AE40-0XB0", 4, 2);
        let tpkt_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(tpkt_len, resp.len());
        // The order number is present verbatim.
        assert!(resp.windows(8).any(|w| w == b"6ES7 212"));
    }
}
