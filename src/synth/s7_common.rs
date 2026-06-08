//! Shared S7comm framing.
//!
//! TPKT (RFC 1006) + ISO 8073 COTP plus the COTP connection and S7
//! SetupCommunication exchange every S7 session opens with. The SZL identity
//! read ([`super::s7_szl`]) and the control/program-download assertions
//! ([`super::s7_control`]) build their function calls on top of this, so a
//! stateful sensor only attributes them on an established S7 connection.

/// S7comm well-known TCP port (ISO-on-TCP).
pub const S7_PORT: u16 = 102;

/// COTP data header (DT, EOT).
pub const COTP_DT: [u8; 3] = [0x02, 0xf0, 0x80];

/// Prepend a TPKT (RFC 1006) header whose length field covers the whole record.
pub fn tpkt(cotp: &[u8]) -> Vec<u8> {
    let total = 4 + cotp.len();
    let mut b = vec![0x03, 0x00, (total >> 8) as u8, (total & 0xff) as u8];
    b.extend_from_slice(cotp);
    b
}

/// Wrap an S7 message (header + parameter + data) in TPKT + COTP DT.
pub fn tpkt_cotp(s7: &[u8]) -> Vec<u8> {
    let mut cotp = COTP_DT.to_vec();
    cotp.extend_from_slice(s7);
    tpkt(&cotp)
}

/// COTP Connection Request: class 0, our source reference, a TPDU-size and
/// src/dst TSAP (rack 0, slot 2). What opens an S7 connection after the TCP
/// handshake.
pub fn cotp_cr() -> Vec<u8> {
    tpkt(&[
        0x11, 0xe0, // LI=17, PDU type CR
        0x00, 0x00, // destination reference (unknown)
        0x00, 0x01, // source reference
        0x00, // class 0
        0xc0, 0x01, 0x0a, // parameter: TPDU size = 1024
        0xc1, 0x02, 0x01, 0x00, // parameter: source TSAP
        0xc2, 0x02, 0x01, 0x02, // parameter: destination TSAP (rack 0, slot 2)
    ])
}

/// COTP Connection Confirm: the PLC's answer to the CR.
pub fn cotp_cc() -> Vec<u8> {
    tpkt(&[
        0x11, 0xd0, // LI=17, PDU type CC
        0x00, 0x01, // destination reference (our source ref)
        0x00, 0x02, // source reference (the PLC's)
        0x00, // class 0
        0xc0, 0x01, 0x0a, // parameter: TPDU size = 1024
        0xc1, 0x02, 0x01, 0x02, // parameter: source TSAP
        0xc2, 0x02, 0x01, 0x00, // parameter: destination TSAP
    ])
}

/// S7 SetupCommunication request (ROSCTR job, function 0xF0): negotiate AMQ and
/// PDU length. Sent right after the COTP connection is confirmed.
pub fn s7_setup_request() -> Vec<u8> {
    tpkt_cotp(&[
        0x32, 0x01, 0x00, 0x00, 0x00, 0x00, // job header, pdu ref 0
        0x00, 0x08, // parameter length 8
        0x00, 0x00, // data length 0
        0xf0, 0x00, // function: setup communication
        0x00, 0x01, // max AMQ calling
        0x00, 0x01, // max AMQ called
        0x01, 0xe0, // PDU length 480
    ])
}

/// S7 SetupCommunication response (ROSCTR ack_data).
pub fn s7_setup_response() -> Vec<u8> {
    tpkt_cotp(&[
        0x32, 0x03, 0x00, 0x00, 0x00, 0x00, // ack_data header, pdu ref 0
        0x00, 0x08, // parameter length 8
        0x00, 0x00, // data length 0
        0x00, 0x00, // error class / error code
        0xf0, 0x00, // function: setup communication
        0x00, 0x01, // max AMQ calling
        0x00, 0x01, // max AMQ called
        0x00, 0xf0, // PDU length 240
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpkt_length_covers_record() {
        let f = s7_setup_request();
        let len = u16::from_be_bytes([f[2], f[3]]) as usize;
        assert_eq!(len, f.len(), "TPKT length covers the whole message");
        assert_eq!(f[7], 0x32, "S7 protocol id after TPKT(4)+COTP(3)");
        assert_eq!(f[8], 0x01, "ROSCTR job");
    }

    #[test]
    fn connection_request_carries_cotp_cr() {
        let f = cotp_cr();
        assert_eq!(f[5], 0xe0, "COTP CR PDU type");
    }
}
