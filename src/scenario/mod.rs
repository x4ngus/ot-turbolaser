//! The target-scenario framework.
//!
//! A scenario is a drop-in data pack under `conf/targets/<name>/` that pins a
//! specific real-world OT attack on top of red laser: its YAML merges over the
//! base config (see [`crate::config::load_with_scenario`]), its `profiles.toml`
//! overlays the CVE database, its `plant` spec is fabricated as a sealed ledger,
//! and its `playbook` drives the phased attack emission. Loading no scenario
//! leaves red laser's generic behaviour unchanged.
//!
//! This module owns discovery ([`registry`]); plant pinning, the playbook
//! timeline, and the engine overlay land in sibling submodules.

pub mod engine;
pub mod plant;
pub mod playbook;
pub mod registry;

/// Error if a loaded ledger's scenario tag does not match the active scenario,
/// so a generic daemon never re-announces a scenario plant and a scenario run
/// never replays a generic ledger. A stale `session.json` is caught loudly with
/// a remedy rather than silently misread.
pub fn guard_ledger_scenario(ledger: Option<&str>, active: Option<&str>) -> Result<(), String> {
    if ledger == active {
        return Ok(());
    }
    let show = |o: Option<&str>| o.unwrap_or("<generic>").to_string();
    Err(format!(
        "session ledger belongs to scenario {} but the active config is {}; run `turbolaser reset` (matching --scenario) for a fresh plant",
        show(ledger),
        show(active),
    ))
}

/// `turbolaser targets`: list the installed scenario packs.
pub fn cmd_targets(args: &crate::cli::TargetsArgs) -> i32 {
    let dir = registry::targets_dir_for(&args.config);
    let found = registry::discover(&dir);
    if args.json {
        match serde_json::to_string_pretty(&found) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("targets: {e}");
                1
            }
        }
    } else {
        if found.is_empty() {
            println!("no target scenarios installed in {}", dir.display());
            return 0;
        }
        println!("target scenarios in {} ({}):", dir.display(), found.len());
        for s in &found {
            let desc = s.description.as_deref().unwrap_or("");
            println!("  {:<14} {desc}", s.name);
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::guard_ledger_scenario;

    #[test]
    fn guard_matches_and_mismatches() {
        assert!(
            guard_ledger_scenario(None, None).is_ok(),
            "generic vs generic"
        );
        assert!(guard_ledger_scenario(Some("stuxnet"), Some("stuxnet")).is_ok());
        assert!(
            guard_ledger_scenario(Some("stuxnet"), None).is_err(),
            "scenario vs generic"
        );
        assert!(
            guard_ledger_scenario(None, Some("triton")).is_err(),
            "generic vs scenario"
        );
        assert!(
            guard_ledger_scenario(Some("stuxnet"), Some("triton")).is_err(),
            "wrong scenario"
        );
    }
}
