//! S7comm mutator. Remaps the COTP called and calling TSAP values in the
//! connection request and confirm. The called TSAP encodes the target PLC rack
//! and slot, the addressing identity a sensor keys on. Two-byte fixed-width
//! values, so the COTP, TPKT, and S7 length fields are untouched.
//!
//! Deeper SZL module and serial identity mutation is a planned extension; it
//! needs a reference capture to implement safely and is out of scope for v1.

use crate::proto::frame::{L4Kind, ParsedFrame};
use crate::proto::mapper::{Domain, SeededMapper};
use crate::proto::{MutationReport, OtMutator, Protocol};

const S7_PORT: u16 = 102;
const COTP_CR: u8 = 0xE0;
const COTP_CC: u8 = 0xD0;
const PARAM_CALLING_TSAP: u8 = 0xC1;
const PARAM_CALLED_TSAP: u8 = 0xC2;

pub struct S7;

impl OtMutator for S7 {
    fn protocol(&self) -> Protocol {
        Protocol::S7
    }

    fn matches(&self, f: &ParsedFrame) -> bool {
        if f.l4_kind() != L4Kind::Tcp {
            return false;
        }
        let on_port = f.src_port() == Some(S7_PORT) || f.dst_port() == Some(S7_PORT);
        let p = f.payload();
        // TPKT version 3 marks the RFC1006 / S7 stack.
        on_port && p.len() >= 6 && p[0] == 0x03
    }

    fn mutate(&self, f: &mut ParsedFrame, mapper: &mut SeededMapper) -> Vec<MutationReport> {
        let p = f.payload_mut();
        if p.len() < 7 || p[0] != 0x03 {
            return Vec::new();
        }
        let cotp_len = p[4] as usize; // COTP header length, excluding this octet
        let pdu_type = p[5];
        let mut reports = Vec::new();
        if pdu_type != COTP_CR && pdu_type != COTP_CC {
            return reports; // only connection setup carries TSAPs
        }
        // CR/CC fixed part: len(1) type(1) dst_ref(2) src_ref(2) class(1), then
        // variable parameters starting at offset 11.
        let cotp_end = (5 + cotp_len).min(p.len());
        let mut k = 11;
        while k + 2 <= cotp_end {
            let code = p[k];
            let plen = p[k + 1] as usize;
            let val = k + 2;
            if val + plen > cotp_end {
                break;
            }
            if (code == PARAM_CALLED_TSAP || code == PARAM_CALLING_TSAP) && plen == 2 {
                let (domain, field) = if code == PARAM_CALLED_TSAP {
                    (Domain::S7ModuleId, "called_tsap")
                } else {
                    (Domain::S7Serial, "calling_tsap")
                };
                let orig = u16::from_be_bytes([p[val], p[val + 1]]);
                let new = mapper.map_u16(domain, orig);
                if new != orig {
                    p[val..val + 2].copy_from_slice(&new.to_be_bytes());
                    reports.push(MutationReport {
                        protocol: Protocol::S7,
                        field: field.into(),
                        original: orig as u64,
                        new: new as u64,
                    });
                }
            }
            k = val + plen;
        }
        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{self, ParsedFrame};
    use crate::proto::testutil::build_tcp;

    // TPKT + COTP connection request with calling TSAP 0x0100 and called TSAP
    // 0x0102 (rack 0, slot 2).
    fn cotp_cr() -> Vec<u8> {
        let cotp = [
            0x11, // COTP length (17 bytes follow)
            COTP_CR,
            0x00,
            0x00, // pdu type, dst ref
            0x00,
            0x01,
            0x00, // src ref, class
            PARAM_CALLING_TSAP,
            0x02,
            0x01,
            0x00, // calling TSAP 0x0100
            PARAM_CALLED_TSAP,
            0x02,
            0x01,
            0x02, // called TSAP 0x0102
            0xC0,
            0x01,
            0x0a, // TPDU size param
        ];
        let mut p = vec![0x03, 0x00];
        let total = 4 + cotp.len();
        p.extend_from_slice(&(total as u16).to_be_bytes()); // TPKT length
        p.extend_from_slice(&cotp);
        p
    }

    #[test]
    fn mutates_tsaps_fixed_width() {
        let payload = cotp_cr();
        let mut frame = build_tcp([10, 0, 0, 1], [10, 0, 0, 9], 50000, 102, &payload);
        let before_len = frame.len();
        let mut mapper = SeededMapper::from_seed(3);
        let reports = {
            let mut f = ParsedFrame::parse(&mut frame).unwrap();
            assert!(S7.matches(&f));
            let r = S7.mutate(&mut f, &mut mapper);
            f.recompute_checksums();
            r
        };
        assert_eq!(frame.len(), before_len);
        assert_eq!(reports.len(), 2, "calling and called TSAP");
        let l = frame::parse_layout(&frame).unwrap();
        // called TSAP sits at payload offset 4 + 11 + 2 = 17.
        let called = u16::from_be_bytes([frame[l.payload + 17], frame[l.payload + 18]]);
        assert_ne!(called, 0x0102);
        assert!(frame::checksums_valid(&frame, &l));
    }
}
