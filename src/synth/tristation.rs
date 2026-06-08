//! TriStation (Schneider Triconex) assertions.
//!
//! The protocol behind TRITON/TRISIS: the engineering-workstation link to a
//! Triconex safety controller, over UDP/1502. This renders the recon and
//! implant-delivery a TRITON-class attack runs -- a CP-status poll, then an
//! allocate + multi-packet program download that drops the controller payload,
//! then a set-program-state.
//!
//! TriStation is proprietary and undocumented at the byte level. These messages
//! reproduce the *sensor-visible signature* -- UDP/1502, the message-type
//! discriminator, and the multi-packet download burst that public analyses
//! (FireEye, Nozomi) describe -- not a bit-exact TriStation transfer. The exact
//! TS command codes should be confirmed against published TS_cnames analysis
//! when authoring a scenario pack.

use std::net::Ipv4Addr;

use super::eth::udp_frame;

const TRISTATION_PORT: u16 = 1502;

// Message-type codes (modeled; see the module note).
const TS_GET_CP_STATUS: u16 = 0x0005;
const TS_CP_STATUS_RESP: u16 = 0x0105;
const TS_ALLOCATE_PROGRAM: u16 = 0x0003;
const TS_ALLOCATE_RESP: u16 = 0x0103;
const TS_PROGRAM_DOWNLOAD: u16 = 0x000e;
const TS_DOWNLOAD_RESP: u16 = 0x010e;
const TS_SET_PROGRAM_STATE: u16 = 0x000d;
const TS_SET_STATE_RESP: u16 = 0x010d;

/// A TriStation message: type, length, body, trailing 16-bit sum.
fn ts_message(msg_type: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&msg_type.to_le_bytes());
    m.extend_from_slice(&(body.len() as u16).to_le_bytes());
    m.extend_from_slice(body);
    let sum = m.iter().fold(0u16, |a, &b| a.wrapping_add(u16::from(b)));
    m.extend_from_slice(&sum.to_le_bytes());
    m
}

/// The engineering-workstation <-> controller link. UDP/1502 is connectionless,
/// so a request is one datagram and the reply another.
struct Link {
    ews_mac: [u8; 6],
    tricon_mac: [u8; 6],
    ews_ip: Ipv4Addr,
    tricon_ip: Ipv4Addr,
    ews_port: u16,
}

impl Link {
    fn request(&self, msg: &[u8]) -> Vec<u8> {
        udp_frame(
            self.ews_mac,
            self.tricon_mac,
            self.ews_ip,
            self.tricon_ip,
            self.ews_port,
            TRISTATION_PORT,
            msg,
        )
    }
    fn reply(&self, msg: &[u8]) -> Vec<u8> {
        udp_frame(
            self.tricon_mac,
            self.ews_mac,
            self.tricon_ip,
            self.ews_ip,
            TRISTATION_PORT,
            self.ews_port,
            msg,
        )
    }
}

/// A control-processor status poll and its reply -- the recon step.
#[allow(clippy::too_many_arguments)]
pub fn get_cp_status(
    ews_mac: [u8; 6],
    tricon_mac: [u8; 6],
    ews_ip: Ipv4Addr,
    tricon_ip: Ipv4Addr,
    ews_port: u16,
) -> Vec<Vec<u8>> {
    let l = Link {
        ews_mac,
        tricon_mac,
        ews_ip,
        tricon_ip,
        ews_port,
    };
    vec![
        l.request(&ts_message(TS_GET_CP_STATUS, &[])),
        // Reply: keyswitch in PROGRAM, the state that lets a download proceed.
        l.reply(&ts_message(TS_CP_STATUS_RESP, &[0x00, 0x10])),
    ]
}

/// The implant delivery: allocate a program, download `payload` in `chunk`-byte
/// packets, then set the program state to run. The multi-packet download burst
/// on UDP/1502 is the TRITON signature.
#[allow(clippy::too_many_arguments)]
pub fn program_download(
    ews_mac: [u8; 6],
    tricon_mac: [u8; 6],
    ews_ip: Ipv4Addr,
    tricon_ip: Ipv4Addr,
    ews_port: u16,
    payload: &[u8],
    chunk: usize,
) -> Vec<Vec<u8>> {
    let l = Link {
        ews_mac,
        tricon_mac,
        ews_ip,
        tricon_ip,
        ews_port,
    };
    let chunk = chunk.max(1);
    let mut frames = vec![
        l.request(&ts_message(TS_ALLOCATE_PROGRAM, &(payload.len() as u32).to_le_bytes())),
        l.reply(&ts_message(TS_ALLOCATE_RESP, &[0x00])),
    ];
    for (i, c) in payload.chunks(chunk).enumerate() {
        let mut body = (i as u16).to_le_bytes().to_vec();
        body.extend_from_slice(c);
        frames.push(l.request(&ts_message(TS_PROGRAM_DOWNLOAD, &body)));
        frames.push(l.reply(&ts_message(TS_DOWNLOAD_RESP, &[0x00])));
    }
    frames.push(l.request(&ts_message(TS_SET_PROGRAM_STATE, &[0x01]))); // run
    frames.push(l.reply(&ts_message(TS_SET_STATE_RESP, &[0x00])));
    frames
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn endpoints() -> ([u8; 6], [u8; 6], Ipv4Addr, Ipv4Addr) {
        (
            [0x02, 0, 0, 0, 0, 1],
            [0x00, 0xa0, 0x45, 1, 2, 3],
            Ipv4Addr::new(10, 40, 0, 250),
            Ipv4Addr::new(10, 40, 0, 8),
        )
    }

    fn dst_port(f: &[u8]) -> u16 {
        let l = parse_layout(f).unwrap();
        u16::from_be_bytes([f[l.l4 + 2], f[l.l4 + 3]])
    }
    fn src_port(f: &[u8]) -> u16 {
        let l = parse_layout(f).unwrap();
        u16::from_be_bytes([f[l.l4], f[l.l4 + 1]])
    }

    fn assert_clean_udp(frames: &[Vec<u8>]) {
        for f in frames {
            let l = parse_layout(f).expect("parses");
            assert_eq!(l.l4_kind, L4Kind::Udp, "TriStation is UDP");
            assert!(checksums_valid(f, &l), "checksums valid");
            // Every datagram touches port 1502 on one side.
            assert!(
                dst_port(f) == TRISTATION_PORT || src_port(f) == TRISTATION_PORT,
                "on UDP/1502"
            );
        }
    }

    #[test]
    fn cp_status_poll_is_clean_udp_1502() {
        let (em, tm, ei, ti) = endpoints();
        let frames = get_cp_status(em, tm, ei, ti, 51000);
        assert_eq!(frames.len(), 2, "request + reply");
        assert_clean_udp(&frames);
        assert_eq!(dst_port(&frames[0]), TRISTATION_PORT, "request to 1502");
    }

    #[test]
    fn program_download_emits_a_multi_packet_burst() {
        let (em, tm, ei, ti) = endpoints();
        // 5 bytes in 2-byte chunks => 3 download packets, each with a reply.
        let frames = program_download(em, tm, ei, ti, 51001, b"\x01\x02\x03\x04\x05", 2);
        assert_clean_udp(&frames);
        // allocate(2) + 3 download exchanges(6) + set-state(2) = 10 frames.
        assert_eq!(frames.len(), 10, "allocate + 3 chunks + set-state");
        // The download type id appears in the request bodies.
        let downloads = frames
            .iter()
            .filter(|f| {
                let l = parse_layout(f).unwrap();
                f[l.payload..].starts_with(&TS_PROGRAM_DOWNLOAD.to_le_bytes())
            })
            .count();
        assert_eq!(downloads, 3, "three download packets");
    }
}
