//! The reload forge pipeline: clone the source, optionally remap L3, dispatch
//! each frame to the first matching mutator, recompute checksums, and report
//! what changed. Deterministic: same source and seed yield byte-identical out.

use crate::pcapio::{Capture, OwnedPacket};
use crate::proto::frame::ParsedFrame;
use crate::proto::l3::{self, RemapSummary};
use crate::proto::mapper::SeededMapper;
use crate::proto::{MutationReport, OtMutator};
use ipnet::Ipv4Net;
use std::path::Path;
use std::process::Command;

pub struct ReloadOptions {
    pub remap_l3: bool,
    pub hints: Vec<Ipv4Net>,
    pub mutators: Vec<Box<dyn OtMutator>>,
}

pub struct RoundResult {
    pub mutations: Vec<MutationReport>,
    pub l3: Option<RemapSummary>,
    pub frames: usize,
}

/// Forge one round. The source capture is not modified.
pub fn forge_round(src: &Capture, seed: u64, opts: &ReloadOptions) -> (Capture, RoundResult) {
    let mut cap = Capture {
        header: src.header,
        packets: src
            .packets
            .iter()
            .map(|p| OwnedPacket {
                ts: p.ts,
                orig_len: p.orig_len,
                data: p.data.clone(),
            })
            .collect(),
    };
    let mut mapper = SeededMapper::from_seed(seed);
    let l3 = if opts.remap_l3 {
        Some(l3::remap_capture(&mut cap, &opts.hints, seed, true))
    } else {
        None
    };

    let mut mutations = Vec::new();
    for p in &mut cap.packets {
        let Some(mut f) = ParsedFrame::parse(&mut p.data) else {
            continue;
        };
        for m in &opts.mutators {
            if m.matches(&f) {
                let rs = m.mutate(&mut f, &mut mapper);
                if !rs.is_empty() {
                    f.recompute_checksums();
                    mutations.extend(rs);
                }
                break;
            }
        }
    }
    let frames = cap.packets.len();
    (
        cap,
        RoundResult {
            mutations,
            l3,
            frames,
        },
    )
}

pub fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Validate a forged round with tshark: no malformed frames and no bad
/// checksums. tshark is the Wireshark dissector, the authoritative oracle for
/// whether a passive sensor will accept the traffic.
pub fn validate_pcap(path: &Path) -> Result<(), String> {
    let malformed = tshark_query(
        path,
        &["-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
    )?;
    if !malformed.trim().is_empty() {
        return Err(format!(
            "malformed frames: {}",
            malformed.split_whitespace().collect::<Vec<_>>().join(",")
        ));
    }
    let bad = tshark_query(
        path,
        &[
            "-o", "ip.check_checksum:TRUE",
            "-o", "tcp.check_checksum:TRUE",
            "-o", "udp.check_checksum:TRUE",
            "-Y",
            "ip.checksum.status==\"Bad\" || tcp.checksum.status==\"Bad\" || udp.checksum.status==\"Bad\"",
            "-T", "fields", "-e", "frame.number",
        ],
    )?;
    if !bad.trim().is_empty() {
        return Err(format!(
            "bad checksums in frames: {}",
            bad.split_whitespace().collect::<Vec<_>>().join(",")
        ));
    }
    Ok(())
}

fn tshark_query(path: &Path, extra: &[&str]) -> Result<String, String> {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(extra)
        .output()
        .map_err(|e| format!("run tshark: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tshark exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
