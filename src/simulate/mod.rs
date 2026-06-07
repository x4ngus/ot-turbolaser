//! The red/green laser content layer.
//!
//! Zones, device fabrication, and the operator commands that expose them:
//! `zones` (show the current map), `reset` (clear the session for a fresh
//! feed), and `plan` (preview what red laser would fabricate, no traffic). The
//! run-loop engine that emits this world lands in a later milestone; the pieces
//! here are pure and CLI-driven.

pub mod bom;
pub mod devices;
pub mod engine;
pub mod roles;
pub mod zones;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::cli::{PlanArgs, ResetArgs, ZonesArgs};
use crate::config::{self, Config, Mode};
use crate::ledger::{self, Session};
use crate::oui::OuiDb;
use crate::pcapio::Capture;
use crate::proto::l3;
use crate::vuln::VulnDb;

/// `turbolaser zones`: show the current zone map. Green laser derives it from
/// the configured captures on demand; red laser reads the session ledger.
pub fn cmd_zones(args: &ZonesArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    match cfg.mode {
        Mode::GreenLaser => {
            let Some(cap) = read_some_captures(&cfg) else {
                eprintln!(
                    "no captures in {} or {}",
                    cfg.paths.variants.display(),
                    cfg.paths.pool.display()
                );
                return 2;
            };
            let hints = l3::parse_hints(&cfg.l3.subnets);
            let oui = OuiDb::load(&cfg.oui_db.path);
            render_green(&zones::derive_zones(&cap, &hints, &oui), args.json);
            0
        }
        Mode::RedLaser => match Session::load(&cfg.session.path) {
            Ok(Some(s)) => {
                render_session(&s, args.json);
                0
            }
            Ok(None) => {
                if args.json {
                    println!(
                        "{{\"laser\":\"red_laser\",\"zones\":[],\"note\":\"no session yet\"}}"
                    );
                } else {
                    println!(
                        "no red-laser session yet at {}. Run the daemon or `turbolaser plan`.",
                        cfg.session.path.display()
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("session: {e}");
                2
            }
        },
    }
}

/// `turbolaser reset`: clear the red-laser session ledger for a fresh feed.
pub fn cmd_reset(args: &ResetArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let existed = matches!(Session::load(&cfg.session.path), Ok(Some(_)));
    match Session::reset(&cfg.session.path) {
        Ok(()) => {
            if existed {
                println!(
                    "cleared red-laser session at {}",
                    cfg.session.path.display()
                );
            } else {
                println!("no session to clear at {}", cfg.session.path.display());
            }
            0
        }
        Err(e) => {
            eprintln!("reset: {e}");
            1
        }
    }
}

/// `turbolaser plan`: preview the fabricated zone and device map without
/// sending any traffic. Shares the allocator with the run loop, so it matches
/// what red laser will emit for the same seed.
pub fn cmd_plan(args: &PlanArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let vuln = VulnDb::load(&cfg.oui_db.vuln_path);
    if vuln.is_empty() {
        eprintln!("no vulnerable-device profiles available");
        return 1;
    }
    let seed = cfg.session.seed.unwrap_or_else(rand::random);
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let params = devices::AllocParams {
        max_subnets: ledger::effective_subnet_cap(cfg.zones.max_subnets),
        max_devices: ledger::effective_device_cap(cfg.synthesis.max_devices),
        default_prefix: cfg.zones.default_prefix,
    };
    let target = args.devices.unwrap_or(cfg.synthesis.target_devices);
    let mut s = Session::new(seed, now_unix());
    // Fabricate the L1/L2 control zones (capped at 10, the field-zone budget),
    // then add a few L3 operations (DCS) zones in the headroom above them.
    let fab_params = devices::AllocParams {
        max_subnets: params.max_subnets.min(10),
        ..params
    };
    let added = devices::fabricate(&mut s, &vuln, &fab_params, target, &mut rng);
    devices::create_l3_zones(&mut s, &params, 3, &mut rng);
    // Tag each zone with a shared DNS domain before naming, so hostnames seal as
    // fully-qualified `<host>.<domain>` and the sensor reads a cross-zone site
    // identity from the suffix.
    if cfg.dns.enabled {
        devices::assign_domains(&mut s, &cfg.dns.domains, seed);
    }
    // Add the supporting cast (firewall at .1, HMI, engineering station,
    // historian, servers) and DNS hostnames off the same seed, then record the
    // full fabricated count so a sealed plan's drift check (device_count ==
    // target_devices) accounts for the BOM. The BOM is identity-only, so the
    // CVE-bearing set stays the controllers.
    let oui = OuiDb::load(&cfg.oui_db.path);
    devices::enrich_plant(&mut s, &vuln, &oui, seed);
    s.target_devices = s.device_count();
    s.max_assets = ledger::effective_asset_cap(cfg.synthesis.max_assets);

    // --commit persists this fabricated session as the authoritative ledger the
    // daemon replays verbatim. A bare `plan` only previews.
    if args.commit {
        match Session::load(&cfg.session.path) {
            Ok(Some(_)) if !args.force => {
                eprintln!(
                    "refusing to overwrite existing session at {}; pass --force or run 'turbolaser reset' first",
                    cfg.session.path.display()
                );
                return 2;
            }
            Err(e) => {
                eprintln!("session: {e}");
                return 2;
            }
            _ => {}
        }
        s.sealed = true;
        if let Err(e) = s.save_atomic(&cfg.session.path) {
            eprintln!("commit: {e}");
            return 1;
        }
        if args.json {
            render_session(&s, true);
        } else {
            println!(
                "committed plan: seed={seed:#018x}, {added} device(s) across {} zone(s) -> {}",
                s.subnet_count(),
                cfg.session.path.display()
            );
            render_session(&s, false);
        }
        return 0;
    }

    if args.json {
        render_session(&s, true);
    } else {
        println!(
            "plan (preview, no traffic): seed={seed:#018x}, fabricated {added} device(s) across {} zone(s)",
            s.subnet_count()
        );
        render_session(&s, false);
        if cfg.north_south.enabled {
            let flows =
                roles::north_south_crossings(&s, seed, cfg.north_south.max_flows_per_pair).len();
            println!("north-south: {flows} conduit flow(s) across adjacent Purdue zones");
        }
        println!("sample devices:");
        for d in s.devices.iter().take(12) {
            println!(
                "  {:<15} {:<22} {:<30} {:<10} [{}]",
                d.ip,
                d.vendor,
                d.model,
                d.firmware,
                d.cves.join(",")
            );
        }
        if s.devices.len() > 12 {
            println!("  ... and {} more", s.devices.len() - 12);
        }
        println!(
            "(preview only; re-run with --commit to write {})",
            cfg.session.path.display()
        );
    }
    0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read and merge a bounded slice of the configured captures, for green-laser
/// on-demand zone derivation.
fn read_some_captures(cfg: &Config) -> Option<Capture> {
    const MAX_FILES: usize = 16;
    const MAX_PACKETS: usize = 500_000;
    let files = crate::run::scan_pcaps(cfg);
    let mut merged: Option<Capture> = None;
    for path in files.into_iter().take(MAX_FILES) {
        let cap = match crate::pcapio::read(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match &mut merged {
            None => merged = Some(cap),
            Some(m) => {
                for p in cap.packets {
                    if m.packets.len() >= MAX_PACKETS {
                        break;
                    }
                    m.packets.push(p);
                }
            }
        }
        if merged
            .as_ref()
            .is_some_and(|m| m.packets.len() >= MAX_PACKETS)
        {
            break;
        }
    }
    merged
}

fn render_green(zones: &[zones::Zone], json: bool) {
    if json {
        let arr: Vec<_> = zones
            .iter()
            .map(|z| {
                serde_json::json!({
                    "cidr": z.cidr.to_string(),
                    "name": z.name,
                    "purdue_level": z.purdue_level,
                    "vendor": z.vendor,
                    "devices": z.device_ips.len(),
                })
            })
            .collect();
        let v = serde_json::json!({"laser": "green_laser", "zones": arr});
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    if zones.is_empty() {
        println!("no zones derived from the captures");
        return;
    }
    println!(
        "green laser: {} zone(s) derived from actual captures",
        zones.len()
    );
    for z in zones {
        println!(
            "  {:<18} L{} {:<32} {:>4} devices  {}",
            z.cidr.to_string(),
            z.purdue_level,
            z.name,
            z.device_ips.len(),
            z.vendor.as_deref().unwrap_or("-")
        );
    }
}

fn render_session(s: &Session, json: bool) {
    // One O(devices) pass for per-zone counts, not a re-scan per zone.
    let counts = s.device_counts_by_subnet();
    let count = |cidr: &str| counts.get(cidr).copied().unwrap_or(0);
    if json {
        let arr: Vec<_> = s
            .subnets
            .iter()
            .map(|z| {
                serde_json::json!({
                    "cidr": z.cidr,
                    "name": z.zone_name,
                    "purdue_level": z.purdue_level,
                    "vendor": z.vendor,
                    "domain": z.domain,
                    "devices": count(&z.cidr),
                })
            })
            .collect();
        let v = serde_json::json!({
            "laser": "red_laser",
            "cycle": s.cycle,
            "device_count": s.device_count(),
            "subnet_count": s.subnet_count(),
            "zones": arr,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return;
    }
    println!(
        "red-laser session: {} zone(s), {} device(s), cycle {}",
        s.subnet_count(),
        s.device_count(),
        s.cycle
    );
    for z in &s.subnets {
        println!(
            "  {:<18} L{} {:<34} {:>4} devices  {:<20} {}",
            z.cidr,
            z.purdue_level,
            z.zone_name,
            count(&z.cidr),
            z.vendor.as_deref().unwrap_or("-"),
            z.domain.as_deref().unwrap_or("-")
        );
    }
}
