//! Modbus/TCP mutator. Remaps the MBAP unit identifier, the per-slave asset id,
//! consistently across the capture. Walks pipelined ADUs within a segment.
//! Fixed width (one byte), so the MBAP length field is untouched.

use crate::proto::frame::{L4Kind, ParsedFrame};
use crate::proto::mapper::{Domain, SeededMapper};
use crate::proto::{MutationReport, OtMutator, Protocol};

const MODBUS_PORT: u16 = 502;

pub struct Modbus;

impl OtMutator for Modbus {
    fn protocol(&self) -> Protocol {
        Protocol::Modbus
    }

    fn matches(&self, f: &ParsedFrame) -> bool {
        if f.l4_kind() != L4Kind::Tcp {
            return false;
        }
        let on_port = f.src_port() == Some(MODBUS_PORT) || f.dst_port() == Some(MODBUS_PORT);
        let p = f.payload();
        // MBAP: txn(2) proto(2)=0 len(2) unit(1) func(1). Protocol id is always 0.
        on_port && p.len() >= 8 && p[2] == 0 && p[3] == 0
    }

    fn mutate(&self, f: &mut ParsedFrame, mapper: &mut SeededMapper) -> Vec<MutationReport> {
        let p = f.payload_mut();
        let mut reports = Vec::new();
        let mut off = 0;
        while off + 7 <= p.len() {
            // Stop if this does not look like another MBAP header.
            if p[off + 2] != 0 || p[off + 3] != 0 {
                break;
            }
            let len = u16::from_be_bytes([p[off + 4], p[off + 5]]) as usize;
            if len == 0 {
                break;
            }
            let unit_at = off + 6;
            let orig = p[unit_at];
            let new = mapper.map_u8(Domain::ModbusUnitId, orig);
            if new != orig {
                p[unit_at] = new;
                reports.push(MutationReport {
                    protocol: Protocol::Modbus,
                    field: "unit_id".into(),
                    original: orig as u64,
                    new: new as u64,
                });
            }
            // MBAP header is 6 bytes (txn+proto+len) plus `len` bytes (unit+pdu).
            off += 6 + len;
        }
        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{self, ParsedFrame};
    use crate::proto::testutil::build_tcp;

    fn modbus_adu(unit: u8) -> Vec<u8> {
        // txn 0x0001, proto 0x0000, len 0x0006, unit, FC 0x03, addr 0, qty 10
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, unit, 0x03, 0x00, 0x00, 0x00, 0x0a,
        ]
    }

    #[test]
    fn mutates_unit_id_fixed_width() {
        let mut frame = build_tcp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 502, &modbus_adu(5));
        let before_len = frame.len();
        let mut mapper = SeededMapper::from_seed(1);
        let reports = {
            let mut f = ParsedFrame::parse(&mut frame).unwrap();
            assert!(Modbus.matches(&f));
            let r = Modbus.mutate(&mut f, &mut mapper);
            f.recompute_checksums();
            r
        };
        assert_eq!(frame.len(), before_len, "length must not change");
        assert_eq!(reports.len(), 1);
        let l = frame::parse_layout(&frame).unwrap();
        let new_unit = frame[l.payload + 6];
        assert_ne!(new_unit, 5);
        assert_eq!(reports[0].original, 5);
        assert_eq!(reports[0].new, new_unit as u64);
        assert!(frame::checksums_valid(&frame, &l));
    }
}
