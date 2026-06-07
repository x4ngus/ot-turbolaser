//! EtherNet/IP and CIP mutator. In a List Identity reply it maps the CIP
//! Identity (vendor id, device type, product code) onto a real, advisory-sourced
//! vulnerable profile, so a forged variant keeps a coherent, CVE-matchable
//! identity rather than the random scramble earlier builds produced (which
//! matched no advisory). The serial stays a benign per-seed remap. All edits are
//! fixed-width little-endian numerics, so no length field changes; the product
//! name string is left untouched to avoid cascading length edits.

use crate::proto::frame::{L4Kind, ParsedFrame};
use crate::proto::mapper::{Domain, SeededMapper};
use crate::proto::{MutationReport, OtMutator, Protocol};
use crate::vuln::{ProfileProto, VulnDb};

const ENIP_PORTS: [u16; 2] = [44818, 2222];
const CMD_LIST_IDENTITY: u16 = 0x0063;
const ITEM_CIP_IDENTITY: u16 = 0x000C;

/// A real CIP Identity (vendor, device type, product code) the mutator maps a
/// List Identity reply onto, so the reply attributes to a known CVE.
#[derive(Clone, Copy)]
struct EnipId {
    vendor: u16,
    device_type: u16,
    product_code: u16,
}

#[derive(Default)]
pub struct Enip {
    identities: Vec<EnipId>,
}

impl Enip {
    /// Build with the embedded curated CIP identities. Reload runs offline with
    /// no config, so the embedded set is the canonical CVE-bearing source. With
    /// no profiles the identity is left unchanged (never scrambled).
    pub fn new() -> Self {
        let identities = VulnDb::embedded()
            .ok()
            .map(|db| {
                db.by_protocol(ProfileProto::Enip)
                    .filter_map(|p| {
                        Some(EnipId {
                            vendor: p.enip_vendor_id?,
                            device_type: p.enip_device_type?,
                            product_code: p.enip_product_code?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { identities }
    }
}

impl OtMutator for Enip {
    fn protocol(&self) -> Protocol {
        Protocol::Enip
    }

    fn matches(&self, f: &ParsedFrame) -> bool {
        if !matches!(f.l4_kind(), L4Kind::Tcp | L4Kind::Udp) {
            return false;
        }
        let on_port = f.src_port().is_some_and(|p| ENIP_PORTS.contains(&p))
            || f.dst_port().is_some_and(|p| ENIP_PORTS.contains(&p));
        let p = f.payload();
        // ENIP encapsulation header is 24 bytes; command is the first field.
        on_port && p.len() >= 26 && u16::from_le_bytes([p[0], p[1]]) == CMD_LIST_IDENTITY
    }

    fn mutate(&self, f: &mut ParsedFrame, mapper: &mut SeededMapper) -> Vec<MutationReport> {
        let ids = &self.identities;
        let p = f.payload_mut();
        if p.len() < 26 || u16::from_le_bytes([p[0], p[1]]) != CMD_LIST_IDENTITY {
            return Vec::new();
        }
        let item_count = u16::from_le_bytes([p[24], p[25]]) as usize;
        let mut reports = Vec::new();
        let mut off = 26;
        for _ in 0..item_count {
            if off + 4 > p.len() {
                break;
            }
            let item_type = u16::from_le_bytes([p[off], p[off + 1]]);
            let item_len = u16::from_le_bytes([p[off + 2], p[off + 3]]) as usize;
            let data = off + 4;
            if item_type == ITEM_CIP_IDENTITY && data + 32 <= p.len() {
                // Identity object: vendor@18, devtype@20, prodcode@22, serial@28.
                // Map vendor/devtype/prodcode onto one real vulnerable profile,
                // chosen deterministically per original vendor, so the reply still
                // attributes to a known CVE. The serial is not a CVE key, so it
                // stays a benign per-seed remap for variant uniqueness.
                if !ids.is_empty() {
                    let orig_vendor = u16::from_le_bytes([p[data + 18], p[data + 19]]);
                    let idx = mapper.map_u16(Domain::EnipVendor, orig_vendor) as usize % ids.len();
                    let id = ids[idx];
                    set_u16_le(p, data + 18, id.vendor, "vendor_id", &mut reports);
                    set_u16_le(p, data + 20, id.device_type, "device_type", &mut reports);
                    set_u16_le(p, data + 22, id.product_code, "product_code", &mut reports);
                }
                remap_u32_le(
                    p,
                    data + 28,
                    Domain::EnipSerial,
                    "serial",
                    mapper,
                    &mut reports,
                );
            }
            off = data + item_len;
        }
        reports
    }
}

/// Write a fixed value into a little-endian u16 field, recording the change.
fn set_u16_le(p: &mut [u8], at: usize, new: u16, field: &str, reports: &mut Vec<MutationReport>) {
    if at + 2 > p.len() {
        return;
    }
    let orig = u16::from_le_bytes([p[at], p[at + 1]]);
    if new != orig {
        p[at..at + 2].copy_from_slice(&new.to_le_bytes());
        reports.push(MutationReport {
            protocol: Protocol::Enip,
            field: field.into(),
            original: orig as u64,
            new: new as u64,
        });
    }
}

fn remap_u32_le(
    p: &mut [u8],
    at: usize,
    dom: Domain,
    field: &str,
    mapper: &mut SeededMapper,
    reports: &mut Vec<MutationReport>,
) {
    if at + 4 > p.len() {
        return;
    }
    let orig = u32::from_le_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
    let new = mapper.map_u32(dom, orig);
    if new != orig {
        p[at..at + 4].copy_from_slice(&new.to_le_bytes());
        reports.push(MutationReport {
            protocol: Protocol::Enip,
            field: field.into(),
            original: orig as u64,
            new: new as u64,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{self, ParsedFrame};
    use crate::proto::testutil::build_tcp;

    // Minimal List Identity reply: 24-byte encap header (command 0x63), item
    // count 1, one CIP identity item with vendor/devtype/prodcode/serial.
    fn list_identity_reply() -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&CMD_LIST_IDENTITY.to_le_bytes()); // command
        let body_len: u16 = 2 + 4 + 34; // item count + item header + item data
        p.extend_from_slice(&body_len.to_le_bytes()); // length
        p.extend_from_slice(&[0; 4]); // session
        p.extend_from_slice(&[0; 4]); // status
        p.extend_from_slice(&[0; 8]); // sender context
        p.extend_from_slice(&[0; 4]); // options
        p.extend_from_slice(&1u16.to_le_bytes()); // item count
        p.extend_from_slice(&ITEM_CIP_IDENTITY.to_le_bytes()); // item type
        p.extend_from_slice(&34u16.to_le_bytes()); // item length
                                                   // identity object (34 bytes)
        p.extend_from_slice(&1u16.to_le_bytes()); // protocol version
        p.extend_from_slice(&[0; 16]); // socket address
        p.extend_from_slice(&7u16.to_le_bytes()); // vendor id = 7
        p.extend_from_slice(&12u16.to_le_bytes()); // device type
        p.extend_from_slice(&5u16.to_le_bytes()); // product code
        p.extend_from_slice(&[1, 2]); // revision
        p.extend_from_slice(&[0, 0]); // status
        p.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // serial
        p.extend_from_slice(&[0]); // product name length 0
        p.extend_from_slice(&[0]); // state
        p
    }

    #[test]
    fn maps_identity_onto_a_real_vulnerable_profile() {
        let enip = Enip::new();
        let payload = list_identity_reply();
        let mut frame = build_tcp([10, 0, 0, 1], [10, 0, 0, 9], 50000, 44818, &payload);
        let before_len = frame.len();
        let mut mapper = SeededMapper::from_seed(2);
        {
            let mut f = ParsedFrame::parse(&mut frame).unwrap();
            assert!(enip.matches(&f));
            enip.mutate(&mut f, &mut mapper);
            f.recompute_checksums();
        }
        assert_eq!(frame.len(), before_len, "fixed-width: no length change");
        let l = frame::parse_layout(&frame).unwrap();
        let data = l.payload + 26 + 4;
        let vendor = u16::from_le_bytes([frame[data + 18], frame[data + 19]]);
        let devtype = u16::from_le_bytes([frame[data + 20], frame[data + 21]]);
        let prodcode = u16::from_le_bytes([frame[data + 22], frame[data + 23]]);
        // The mutated identity is a real, CVE-bearing ENIP profile, not random.
        let vuln = VulnDb::embedded().unwrap();
        let real = vuln.by_protocol(ProfileProto::Enip).any(|p| {
            p.enip_vendor_id == Some(vendor)
                && p.enip_device_type == Some(devtype)
                && p.enip_product_code == Some(prodcode)
        });
        assert!(
            real,
            "identity maps onto a real profile (vendor={vendor} devtype={devtype} prodcode={prodcode})"
        );
        assert!(frame::checksums_valid(&frame, &l));
    }
}
