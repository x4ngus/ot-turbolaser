//! DNP3 mutator. Remaps the data link layer source and destination addresses,
//! the per-device identity, and recomputes the header block CRC. Addresses are
//! fixed-width (two bytes each), so the LEN field and the user-data block CRCs
//! stay valid; only the header CRC and the L3/L4 checksums change. Walks
//! multiple link frames packed into one TCP segment.

use crate::proto::crc;
use crate::proto::frame::{L4Kind, ParsedFrame};
use crate::proto::mapper::{Domain, SeededMapper};
use crate::proto::{MutationReport, OtMutator, Protocol};

const DNP3_PORT: u16 = 20000;
const START: [u8; 2] = [0x05, 0x64];

pub struct Dnp3;

impl OtMutator for Dnp3 {
    fn protocol(&self) -> Protocol {
        Protocol::Dnp3
    }

    fn matches(&self, f: &ParsedFrame) -> bool {
        if !matches!(f.l4_kind(), L4Kind::Tcp | L4Kind::Udp) {
            return false;
        }
        let on_port = f.src_port() == Some(DNP3_PORT) || f.dst_port() == Some(DNP3_PORT);
        let p = f.payload();
        on_port && p.len() >= 10 && p[0] == START[0] && p[1] == START[1]
    }

    fn mutate(&self, f: &mut ParsedFrame, mapper: &mut SeededMapper) -> Vec<MutationReport> {
        let p = f.payload_mut();
        let mut reports = Vec::new();
        let mut o = 0;
        while o + 10 <= p.len() {
            if p[o] != START[0] || p[o + 1] != START[1] {
                break;
            }
            let len = p[o + 2] as usize;
            if len < 5 {
                break; // LEN counts CTRL + DEST + SRC at minimum
            }
            // DEST at o+4, SRC at o+6, both little-endian.
            let dest = u16::from_le_bytes([p[o + 4], p[o + 5]]);
            let ndest = mapper.map_u16(Domain::Dnp3Addr, dest);
            if ndest != dest {
                p[o + 4..o + 6].copy_from_slice(&ndest.to_le_bytes());
                reports.push(report("dst", dest, ndest));
            }
            let src = u16::from_le_bytes([p[o + 6], p[o + 7]]);
            let nsrc = mapper.map_u16(Domain::Dnp3Addr, src);
            if nsrc != src {
                p[o + 6..o + 8].copy_from_slice(&nsrc.to_le_bytes());
                reports.push(report("src", src, nsrc));
            }
            // Recompute the header block CRC over the 8 bytes before it.
            let header_crc = crc::dnp3(&p[o..o + 8]);
            p[o + 8..o + 10].copy_from_slice(&header_crc.to_le_bytes());

            // Advance past this frame: 10-byte header plus the data section,
            // which is the user data split into 16-byte blocks each trailed by
            // a 2-byte CRC. User data is left untouched, so its CRCs stay valid.
            let user = len - 5;
            let blocks = user.div_ceil(16);
            o += 10 + user + 2 * blocks;
        }
        reports
    }
}

fn report(field: &str, original: u16, new: u16) -> MutationReport {
    MutationReport {
        protocol: Protocol::Dnp3,
        field: field.into(),
        original: original as u64,
        new: new as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{self, ParsedFrame};
    use crate::proto::testutil::build_tcp;

    fn dnp3_header(dest: u16, src: u16) -> Vec<u8> {
        let mut h = vec![0x05, 0x64, 0x05, 0xC4];
        h.extend_from_slice(&dest.to_le_bytes());
        h.extend_from_slice(&src.to_le_bytes());
        let c = crc::dnp3(&h[0..8]);
        h.extend_from_slice(&c.to_le_bytes());
        h
    }

    #[test]
    fn mutates_addresses_and_fixes_header_crc() {
        let payload = dnp3_header(4, 1);
        let mut frame = build_tcp([10, 0, 0, 1], [10, 0, 0, 9], 40000, 20000, &payload);
        let before_len = frame.len();
        let mut mapper = SeededMapper::from_seed(4);
        let reports = {
            let mut f = ParsedFrame::parse(&mut frame).unwrap();
            assert!(Dnp3.matches(&f));
            let r = Dnp3.mutate(&mut f, &mut mapper);
            f.recompute_checksums();
            r
        };
        assert_eq!(frame.len(), before_len);
        assert_eq!(reports.len(), 2, "src and dst");
        let l = frame::parse_layout(&frame).unwrap();
        let h = &frame[l.payload..l.payload + 10];
        let dest = u16::from_le_bytes([h[4], h[5]]);
        let src = u16::from_le_bytes([h[6], h[7]]);
        assert_ne!(dest, 4);
        assert_ne!(src, 1);
        // The recomputed header CRC must be self-consistent.
        let stored = u16::from_le_bytes([h[8], h[9]]);
        assert_eq!(stored, crc::dnp3(&h[0..8]));
        assert!(frame::checksums_valid(&frame, &l));
    }
}
