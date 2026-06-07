//! Post-deploy validation oracles for the MAC<->IP union.
//!
//! Two checks, one command. `arp_profile` measures the emitted burst against the
//! shape of real OT ARP (the gate that keeps the wire from regressing toward a
//! scan or a runt); `sensor_csv` scores a sensor export for how many planned
//! assets actually unioned. Together they turn "did the union work?" from a
//! squint at a CSV into a one-command answer.

pub mod arp_profile;
pub mod sensor_csv;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::cli::VerifyArgs;
use crate::config;
use crate::ledger::Session;
use crate::pcapio;
use crate::simulate::roles;

/// `turbolaser verify`: profile an emitted burst pcap against the reference ARP
/// bands and/or score a passive-sensor export for union-rate against the plan. Exits
/// non-zero if the ARP profile violates a band (a CI/CD-friendly gate) or an
/// input cannot be read; the CSV report is informational.
pub fn cmd_verify(args: &VerifyArgs) -> i32 {
    let cfg = match config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return 2;
        }
    };
    let ledger = match Session::load(&cfg.session.path) {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!(
                "no session ledger at {}; run `turbolaser plan --commit` first",
                cfg.session.path.display()
            );
            return 2;
        }
        Err(e) => {
            eprintln!("session: {e}");
            return 2;
        }
    };

    let mut failed = false;
    let mut did_something = false;

    // Profile a pcap: the one named, else the engine's last synth burst.
    let pcap = args.pcap.clone().or_else(|| {
        let p = cfg.paths.shm_dir.join("synth-identity.pcap");
        p.exists().then_some(p)
    });
    if let Some(path) = pcap {
        did_something = true;
        match pcapio::read(&path) {
            Ok(cap) => {
                let prof = arp_profile::analyze(&cap);
                let expected: HashSet<Ipv4Addr> = roles::arp_edges(&ledger, ledger.seed)
                    .iter()
                    .map(|e| e.owner.ip)
                    .collect();
                let violations = prof.check(&expected, roles::CELL_SIZE - 1);
                failed |= !violations.is_empty();
                print_arp(&path, &prof, &violations, args.json);
            }
            Err(e) => {
                eprintln!("pcap {}: {e}", path.display());
                failed = true;
            }
        }
    }

    // Score a sensor export against the plan.
    if let Some(path) = &args.csv {
        did_something = true;
        match std::fs::read_to_string(path) {
            Ok(text) => match sensor_csv::analyze(&text, &ledger) {
                Ok(rep) => print_union(path, &rep, args.json),
                Err(e) => {
                    eprintln!("csv {}: {e}", path.display());
                    failed = true;
                }
            },
            Err(e) => {
                eprintln!("reading {}: {e}", path.display());
                failed = true;
            }
        }
    }

    if !did_something {
        eprintln!(
            "nothing to verify: pass --csv <export> to score a sensor export, or --pcap <file> \
             (or run the daemon so a synth burst exists at {}/synth-identity.pcap)",
            cfg.paths.shm_dir.display()
        );
        return 2;
    }
    i32::from(failed)
}

fn print_arp(path: &Path, p: &arp_profile::ArpProfile, v: &[arp_profile::Violation], json: bool) {
    if json {
        let val = serde_json::json!({
            "pcap": path.display().to_string(),
            "requests": p.requests,
            "replies": p.replies,
            "gratuitous": p.gratuitous,
            "runts": p.runts,
            "locally_administered": p.locally_administered,
            "max_fanout": p.max_fanout,
            "repliers": p.repliers.len(),
            "violations": v.iter().map(|x| &x.0).collect::<Vec<_>>(),
            "pass": v.is_empty(),
        });
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        return;
    }
    println!("ARP profile of {}", path.display());
    println!(
        "  requests {}  replies {}  is-at repliers {}",
        p.requests,
        p.replies,
        p.repliers.len()
    );
    println!(
        "  gratuitous {}  runts {}  locally-administered {}  max fan-out {}",
        p.gratuitous, p.runts, p.locally_administered, p.max_fanout
    );
    if v.is_empty() {
        println!("  PASS: within the reference OT ARP bands");
    } else {
        println!("  FAIL:");
        for x in v {
            println!("    - {}", x.0);
        }
    }
}

fn print_union(path: &Path, r: &sensor_csv::UnionReport, json: bool) {
    if json {
        let val = serde_json::json!({
            "csv": path.display().to_string(),
            "total_records": r.total_records,
            "unioned": r.unioned,
            "ip_only": r.ip_only,
            "mac_only": r.mac_only,
            "neither": r.neither,
            "planned": r.planned,
            "planned_unioned": r.planned_unioned,
            "union_rate": r.union_rate(),
            "planned_named": r.planned_named,
            "planned_named_resolved": r.planned_named_resolved,
            "hostname_coverage": r.hostname_coverage(),
            "stragglers": r.stragglers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        return;
    }
    println!("Union report from {}", path.display());
    println!(
        "  records: {} total  ({} unioned, {} ip-only, {} mac-only, {} addressless)",
        r.total_records, r.unioned, r.ip_only, r.mac_only, r.neither
    );
    println!(
        "  plan:    {} / {} planned assets unioned  =  {:.1}% union-rate",
        r.planned_unioned,
        r.planned,
        r.union_rate() * 100.0
    );
    if r.planned_named > 0 {
        println!(
            "  names:   {} / {} named devices resolved  =  {:.1}% hostname coverage",
            r.planned_named_resolved,
            r.planned_named,
            r.hostname_coverage() * 100.0
        );
    }
    if !r.stragglers.is_empty() {
        let shown: Vec<String> = r
            .stragglers
            .iter()
            .take(15)
            .map(|ip| ip.to_string())
            .collect();
        let more = r.stragglers.len().saturating_sub(shown.len());
        println!(
            "  still split: {}{}",
            shown.join(", "),
            if more > 0 {
                format!(", +{more} more")
            } else {
                String::new()
            }
        );
    }
}
