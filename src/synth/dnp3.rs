//! DNP3 (IEEE 1815) control assertions.
//!
//! The SCADA-to-outstation protocol common in electric and water utilities, and
//! one of the protocol modules in the INCONTROLLER/PIPEDREAM toolkit. A master
//! runs an integrity poll to enumerate an outstation, then issues a
//! SELECT-then-OPERATE control-relay-output block to actuate a point (a breaker
//! trip). Carried over TCP/20000. The data-link layer (start `0x05 0x64`, length,
//! control, dest, src, header CRC, then user data in 16-byte CRC-trailed blocks)
//! is what the reload DNP3 mutator walks, so its layout is a dissector-valid
//! reference; the application layer is the open IEEE-1815 encoding.

use std::net::Ipv4Addr;

use super::session::TcpSession;
use crate::proto::crc;

const DNP3_PORT: u16 = 20000;
const START: [u8; 2] = [0x05, 0x64];

// Data-link control octets (DIR|PRM|FCB|FCV|func). Unconfirmed user data (func 4)
// is the carrier for application requests/responses; DIR=1 is master->outstation,
// DIR=0 is outstation->master.
const CTRL_MASTER: u8 = 0xC4;
const CTRL_OUTSTATION: u8 = 0x44;

// Application function codes.
const APP_READ: u8 = 0x01;
const APP_SELECT: u8 = 0x03;
const APP_OPERATE: u8 = 0x04;
const APP_RESPONSE: u8 = 0x81;

/// Assemble a DNP3 data-link frame around `user`: start bytes, LEN (CTRL + DEST +
/// SRC + user, i.e. 5 + user.len()), control, dest, src (little-endian), the
/// header CRC over those first 8 octets, then the user data split into 16-byte
/// blocks each trailed by its own CRC. Exactly the framing the reload mutator
/// parses, so it dissects.
fn link_frame(ctrl: u8, dest: u16, src: u16, user: &[u8]) -> Vec<u8> {
    let mut b = vec![START[0], START[1], (5 + user.len()) as u8, ctrl];
    b.extend_from_slice(&dest.to_le_bytes());
    b.extend_from_slice(&src.to_le_bytes());
    let hcrc = crc::dnp3(&b[0..8]);
    b.extend_from_slice(&hcrc.to_le_bytes());
    for chunk in user.chunks(16) {
        b.extend_from_slice(chunk);
        b.extend_from_slice(&crc::dnp3(chunk).to_le_bytes());
    }
    b
}

/// The application layer of an integrity poll: transport header (FIR|FIN|seq),
/// application control (FIR|FIN|seq), READ, and a class-object header per class
/// (groups 60 var 1..4, qualifier 0x06 = all objects). This is the master's
/// enumerate-everything recon poll.
fn integrity_poll_user() -> Vec<u8> {
    let mut u = vec![0xC0, 0xC0, APP_READ];
    for var in [0x02u8, 0x03, 0x04, 0x01] {
        u.extend_from_slice(&[0x3C, var, 0x06]); // group 60, class object, qual 0x06
    }
    u
}

/// A control-relay-output block (group 12 var 1) request body for one point: the
/// object header (group 12 var 1, qualifier 0x17 = 1-octet count and index) plus
/// the CROB. `trip` selects the trip/latch-off control code, else latch-on.
fn crob_user(func: u8, seq: u8, index: u8, trip: bool) -> Vec<u8> {
    let app_ctrl = 0xC0 | (seq & 0x0f);
    // CROB: control code, count, on-time (LE32), off-time (LE32), status.
    let control_code = if trip { 0x81 } else { 0x41 };
    let mut crob = vec![control_code, 0x01];
    crob.extend_from_slice(&100u32.to_le_bytes()); // on-time ms
    crob.extend_from_slice(&0u32.to_le_bytes()); // off-time ms
    crob.push(0x00); // status: request
    let mut u = vec![app_ctrl, func, 0x0C, 0x01, 0x17, 0x01, index];
    u.extend_from_slice(&crob);
    // Prepend the transport header.
    let mut out = vec![0xC0];
    out.append(&mut u);
    out
}

/// The application layer of a null response: RESPONSE with cleared internal
/// indications (IIN1, IIN2).
fn response_user(seq: u8) -> Vec<u8> {
    vec![0xC0, 0xC0 | (seq & 0x0f), APP_RESPONSE, 0x00, 0x00]
}

/// A full integrity poll: the master reads every class from the outstation
/// (recon). `common_addr` is the outstation's link address; the master uses
/// `common_addr + 1000` so the two never collide.
#[allow(clippy::too_many_arguments)]
pub fn integrity_poll(
    master_mac: [u8; 6],
    out_mac: [u8; 6],
    master_ip: Ipv4Addr,
    out_ip: Ipv4Addr,
    master_port: u16,
    common_addr: u16,
) -> Vec<Vec<u8>> {
    let master = common_addr.wrapping_add(1000);
    let mut s = TcpSession::new(
        master_mac,
        out_mac,
        master_ip,
        out_ip,
        master_port,
        DNP3_PORT,
    );
    s.open();
    s.client_says(&link_frame(
        CTRL_MASTER,
        common_addr,
        master,
        &integrity_poll_user(),
    ));
    s.server_says(&link_frame(
        CTRL_OUTSTATION,
        master,
        common_addr,
        &response_user(0),
    ));
    s.close();
    s.into_frames()
}

/// A full SELECT-then-OPERATE control: the master selects a control point on the
/// outstation, the outstation echoes it, the master operates it, the outstation
/// confirms. `trip` opens (trips) the point, else latches it on. This is the
/// PIPEDREAM-style breaker actuation.
#[allow(clippy::too_many_arguments)]
pub fn operate(
    master_mac: [u8; 6],
    out_mac: [u8; 6],
    master_ip: Ipv4Addr,
    out_ip: Ipv4Addr,
    master_port: u16,
    common_addr: u16,
    index: u8,
    trip: bool,
) -> Vec<Vec<u8>> {
    let master = common_addr.wrapping_add(1000);
    let mut s = TcpSession::new(
        master_mac,
        out_mac,
        master_ip,
        out_ip,
        master_port,
        DNP3_PORT,
    );
    s.open();
    // SELECT (seq 0), outstation echo, OPERATE (seq 1), outstation confirm.
    s.client_says(&link_frame(
        CTRL_MASTER,
        common_addr,
        master,
        &crob_user(APP_SELECT, 0, index, trip),
    ));
    s.server_says(&link_frame(
        CTRL_OUTSTATION,
        master,
        common_addr,
        &response_user(0),
    ));
    s.client_says(&link_frame(
        CTRL_MASTER,
        common_addr,
        master,
        &crob_user(APP_OPERATE, 1, index, trip),
    ));
    s.server_says(&link_frame(
        CTRL_OUTSTATION,
        master,
        common_addr,
        &response_user(1),
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
            Ipv4Addr::new(10, 70, 10, 20),
        )
    }

    fn assert_clean(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(f, &l), "checksums valid");
        }
    }

    /// A data segment whose DNP3 link header CRC is self-consistent and whose user
    /// blocks carry the expected application function.
    fn carries_link_with_app(frames: &[Vec<u8>], app_func: u8) -> bool {
        frames.iter().any(|f| {
            let Some(l) = parse_layout(f) else {
                return false;
            };
            let p = &f[l.payload..l.end];
            if p.len() < 12 || p[0] != START[0] || p[1] != START[1] {
                return false;
            }
            // Header CRC self-consistent.
            if u16::from_le_bytes([p[8], p[9]]) != crc::dnp3(&p[0..8]) {
                return false;
            }
            // First user block starts at 10: transport(1) + app ctrl(1) + func.
            p.get(12) == Some(&app_func)
        })
    }

    #[test]
    fn integrity_poll_is_clean_and_reads() {
        let (mm, om, mi, oi) = endpoints();
        let frames = integrity_poll(mm, om, mi, oi, 50000, 5);
        assert_clean(&frames);
        assert!(
            carries_link_with_app(&frames, APP_READ),
            "the poll carries a READ over a CRC-valid link frame"
        );
    }

    #[test]
    fn operate_selects_then_operates() {
        let (mm, om, mi, oi) = endpoints();
        let frames = operate(mm, om, mi, oi, 50001, 5, 3, true);
        assert_clean(&frames);
        assert!(carries_link_with_app(&frames, APP_SELECT), "SELECT present");
        assert!(
            carries_link_with_app(&frames, APP_OPERATE),
            "OPERATE present"
        );
    }
}
