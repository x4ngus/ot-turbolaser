//! `turbolaser reload`: forge variant pcaps (the rounds) from a source capture.
//!
//! Each round i uses seed_base + i, so a family is reproducible. Output is a
//! pcap plus a TOML manifest describing the mutations and L3 remap, with an
//! index.json roster for the out dir.

pub mod manifest;
pub mod pipeline;

use crate::cli::{ModeSel, ProtoSel, ReloadArgs};
use crate::pcapio;
use crate::proto::{mutators, Protocol};
use log::{error, info, warn};

pub fn reload(args: &ReloadArgs) -> i32 {
    init_logger();

    let seed_base = match parse_seed(args.seed_base.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            error!("bad --seed-base: {e}");
            return 2;
        }
    };

    let src = match pcapio::read(&args.input) {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return 1;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&args.out_dir) {
        error!("mkdir {}: {e}", args.out_dir.display());
        return 1;
    }

    let proto = proto_filter(args.proto);
    let mode = match args.mode {
        ModeSel::RedLaser => "red_laser",
        ModeSel::GreenLaser => "green_laser",
    };
    let validate = args.validate;
    if validate && !pipeline::tshark_available() {
        warn!("tshark not found; skipping --validate");
    }
    let stem = args
        .input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture")
        .to_string();

    let mut index = manifest::load_index(&args.out_dir);
    let mut ok = true;

    for i in 0..args.count {
        let seed = seed_base.wrapping_add(i as u64);
        let opts = pipeline::ReloadOptions {
            remap_l3: args.remap_l3,
            hints: Vec::new(),
            mutators: mutators::for_protocol(proto),
        };
        let (cap, result) = pipeline::forge_round(&src, seed, &opts);

        let base = format!("{stem}__v{:04}__seed-{:x}", i + 1, seed);
        let pcap_path = args.out_dir.join(format!("{base}.pcap"));
        if let Err(e) = pcapio::write(&pcap_path, &cap) {
            error!("write {}: {e}", pcap_path.display());
            ok = false;
            continue;
        }

        let man = manifest::build(&stem, seed, mode, &cap, &result);
        let muts = man.mutations.len();
        if let Err(e) = manifest::write(&args.out_dir.join(format!("{base}.toml")), &man) {
            warn!("manifest for {base}: {e}");
        }
        info!(
            "forged {base}.pcap: {} frames, {} unique mutations{}",
            result.frames,
            muts,
            if result.l3.is_some() {
                ", L3 remapped"
            } else {
                ""
            }
        );

        if validate && pipeline::tshark_available() {
            match pipeline::validate_pcap(&pcap_path) {
                Ok(()) => info!("  tshark: clean"),
                Err(e) => {
                    error!("  tshark validation failed: {e}");
                    ok = false;
                }
            }
        }

        index.push(manifest::IndexEntry {
            file: format!("{base}.pcap"),
            seed,
            frames: result.frames,
            mutations: muts,
        });
    }

    if let Err(e) = manifest::write_index(&args.out_dir, &index) {
        warn!("index.json: {e}");
    }

    if ok {
        0
    } else {
        1
    }
}

fn proto_filter(sel: ProtoSel) -> Option<Protocol> {
    match sel {
        ProtoSel::Auto => None,
        ProtoSel::Modbus => Some(Protocol::Modbus),
        ProtoSel::Enip => Some(Protocol::Enip),
        ProtoSel::S7 => Some(Protocol::S7),
        ProtoSel::Dnp3 => Some(Protocol::Dnp3),
    }
}

fn parse_seed(s: Option<&str>) -> Result<u64, String> {
    match s {
        None => Ok(0),
        Some(t) => {
            let t = t.trim();
            if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
            } else {
                t.parse::<u64>().map_err(|e| e.to_string())
            }
        }
    }
}

fn init_logger() {
    let env = env_logger::Env::default().default_filter_or("info");
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_secs()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ModeSel, ProtoSel, ReloadArgs};
    use crate::pcapio::{self, Capture, OwnedPacket};
    use pcap_file::pcap::PcapHeader;
    use std::time::Duration;

    #[test]
    fn parses_hex_and_decimal_seeds() {
        assert_eq!(parse_seed(None).unwrap(), 0);
        assert_eq!(parse_seed(Some("255")).unwrap(), 255);
        assert_eq!(parse_seed(Some("0xff")).unwrap(), 255);
        assert_eq!(parse_seed(Some("0xC0FFEE")).unwrap(), 0xC0FFEE);
        assert!(parse_seed(Some("nope")).is_err());
    }

    #[test]
    fn proto_filter_maps_each_selector() {
        assert_eq!(proto_filter(ProtoSel::Auto), None);
        assert_eq!(proto_filter(ProtoSel::Modbus), Some(Protocol::Modbus));
        assert_eq!(proto_filter(ProtoSel::Enip), Some(Protocol::Enip));
        assert_eq!(proto_filter(ProtoSel::S7), Some(Protocol::S7));
        assert_eq!(proto_filter(ProtoSel::Dnp3), Some(Protocol::Dnp3));
    }

    fn tiny_capture() -> Capture {
        // A benign non-IP frame; reload only needs a readable capture to forge.
        let mut frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x88, 0xcc,
        ];
        frame.extend(std::iter::repeat_n(0u8, 46));
        Capture {
            header: PcapHeader::default(),
            packets: vec![OwnedPacket {
                ts: Duration::new(1, 0),
                orig_len: frame.len() as u32,
                data: frame,
            }],
        }
    }

    #[test]
    fn reload_forges_rounds_and_writes_manifest_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("modbus.pcap");
        pcapio::write(&input, &tiny_capture()).unwrap();
        let out = dir.path().join("variants");
        let args = ReloadArgs {
            input,
            out_dir: out.clone(),
            proto: ProtoSel::Auto,
            seed_base: Some("0x10".into()),
            count: 2,
            mode: ModeSel::RedLaser,
            remap_l3: false,
            validate: false,
        };
        assert_eq!(reload(&args), 0);
        assert!(out.join("modbus__v0001__seed-10.pcap").exists());
        assert!(out.join("modbus__v0002__seed-11.pcap").exists());
        assert!(out.join("modbus__v0001__seed-10.toml").exists());
        assert_eq!(
            manifest::load_index(&out).len(),
            2,
            "index lists both rounds"
        );
    }

    #[test]
    fn reload_on_unreadable_input_fails_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("garbage.pcap");
        std::fs::write(&input, b"not a pcap at all").unwrap();
        let args = ReloadArgs {
            input,
            out_dir: dir.path().join("out"),
            proto: ProtoSel::Auto,
            seed_base: None,
            count: 1,
            mode: ModeSel::RedLaser,
            remap_l3: false,
            validate: false,
        };
        assert_eq!(reload(&args), 1, "an unreadable input fails cleanly");
    }
}
