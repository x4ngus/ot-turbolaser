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

/// Validate a scenario pack end to end without committing or sending traffic:
/// overlay its CVE profiles, build (and discard) its sealed plant, and load its
/// playbook. Returns the first error, so `check`/`plan` reject a broken pack at
/// pre-flight instead of letting the daemon discover it only at its first start.
/// A config with no `target:` is a generic run and validates trivially.
pub fn preflight(cfg: &crate::config::Config) -> Result<(), String> {
    let Some(t) = cfg.target.as_ref() else {
        return Ok(());
    };
    // Embedded OUI and a fixed seed keep pre-flight self-contained: it checks the
    // pack's structure (zones, devices, profiles, playbook), not the eventual
    // wire identities, so it must not depend on the configured OUI file existing
    // or on any particular seed.
    // A malformed profiles.toml is not fatal (load_overlay keeps the embedded set
    // and only logs it), but a silent drop hides a typo'd CVE profile from the
    // operator. Surface it loudly at pre-flight so `check`/`plan`/`fire` report it.
    let profiles_path = t.pack_dir.join(&t.profiles);
    if let Ok(text) = std::fs::read_to_string(&profiles_path) {
        if !text.trim().is_empty() {
            if let Err(e) = toml::from_str::<toml::Value>(&text) {
                eprintln!(
                    "warning: scenario profiles {} is malformed and will be ignored (the embedded CVE set is used instead): {e}",
                    profiles_path.display()
                );
            }
        }
    }
    let vuln = crate::vuln::VulnDb::load_overlay(&profiles_path);
    let oui = crate::oui::OuiDb::embedded();
    let seed = cfg.session.seed.unwrap_or(0);
    plant::pin_from_pack(t, &vuln, &oui, seed, 0, &cfg.dns.domains)?;
    engine::ScenarioEngine::load(t, seed)?;
    Ok(())
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
            // Distinguish "the targets dir is missing" (the packaging symptom: the
            // installer did not lay it down, or --config points at the wrong tree)
            // from "the dir is present but holds no packs".
            if dir.is_dir() {
                println!(
                    "no target scenarios in {} (directory present but empty)",
                    dir.display()
                );
            } else {
                println!(
                    "no targets directory at {}; scenario packs install under <config-dir>/targets -- re-run scripts/install.sh, or point --config at the installed conf",
                    dir.display()
                );
            }
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
