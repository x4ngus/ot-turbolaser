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

/// Build a scenario's sealed plant from its pack and validate its playbook in one
/// sequence: overlay the pack's CVE profiles, load (validate) the playbook, then
/// pin the plant into a sealed [`Session`]. The single definition that `plan`
/// (which keeps the session to commit) and [`preflight`] (which discards it) both
/// use, so the validation order lives in one place rather than being copied per
/// caller. The daemon's first-run build in `SimulatorEngine::red` shares the same
/// `pin_from_pack`/`ScenarioEngine::load` pieces but owns its own load-or-build
/// and persistence lifecycle.
pub fn build_validated_plant(
    cfg: &crate::config::Config,
    target: &crate::config::TargetCfg,
    oui: &crate::oui::OuiDb,
    seed: u64,
    now_unix: u64,
) -> Result<crate::ledger::Session, String> {
    let vuln = crate::vuln::VulnDb::load_overlay(&target.pack_dir.join(&target.profiles));
    if vuln.is_empty() {
        return Err("no vulnerable-device profiles available".into());
    }
    let engine = engine::ScenarioEngine::load(target, seed)?; // validate the playbook
    let session = plant::pin_from_pack(target, &vuln, oui, seed, now_unix, &cfg.dns.domains)?;
    // Cross-check the playbook's targets against the pinned plant, so a target that
    // names no plant device is rejected here rather than silently skipped (zero
    // frames) at run time, defeating the scenario the operator meant to fire.
    engine.validate_targets(&session)?;
    Ok(session)
}

/// Validate a scenario pack end to end without committing or sending traffic, so
/// `check`/`plan`/`fire` reject a broken pack at pre-flight instead of letting the
/// daemon discover it only at its first start. A config with no `target:` is a
/// generic run and validates trivially.
pub fn preflight(cfg: &crate::config::Config) -> Result<(), String> {
    let Some(t) = cfg.target.as_ref() else {
        return Ok(());
    };
    // A declared, non-empty profiles.toml that does not parse is FATAL here (SP-10).
    // `load_overlay` only logs it and falls back to the embedded set, so a plant
    // model defined only in that overlay (e.g. stuxnet's SIMATIC S7-417 CPU) would
    // silently pin identity-only: CVE-less, protocol-none, the literal model string
    // on the wire instead of the real MLFB. An operator must not fire that; make
    // the malformed overlay stop pre-flight rather than degrade quietly.
    let profiles_path = t.pack_dir.join(&t.profiles);
    if let Ok(text) = std::fs::read_to_string(&profiles_path) {
        if !text.trim().is_empty() {
            if let Err(e) = toml::from_str::<toml::Value>(&text) {
                return Err(format!(
                    "scenario profiles {} is malformed: {e}; fix it or remove it (a CVE-bearing plant device would otherwise silently degrade to identity-only)",
                    profiles_path.display()
                ));
            }
        }
    }
    // Flag a plant device that names a `model` expecting a CVE profile (it sets none
    // of the identity-only descriptive fields protocol/vendor/firmware) yet resolves
    // to no profile in the overlaid DB (SP-10). That is an author error: a typo, or a
    // model the profiles.toml was meant to define but does not. A genuinely
    // identity-only device (a SIS/RTU/HMI that sets protocol/vendor) is exempt, since
    // an unresolved descriptive model is intentional there.
    let vuln = crate::vuln::VulnDb::load_overlay(&profiles_path);
    let spec = plant::PlantSpec::load(&t.pack_dir.join(&t.plant))?;
    for d in &spec.devices {
        if let Some(m) = &d.model {
            let identity_only = d.protocol.is_some() || d.vendor.is_some() || d.firmware.is_some();
            if !identity_only && vuln.by_model(m).is_none() {
                return Err(format!(
                    "scenario plant model {m:?} resolves to no CVE profile and declares no identity-only fields (protocol/vendor/firmware); define it in {} or mark it identity-only",
                    profiles_path.display()
                ));
            }
        }
    }
    // Embedded OUI and a fixed seed keep pre-flight self-contained: it checks the
    // pack's structure, not the eventual wire identities, so it must not depend on
    // the configured OUI file or any particular seed.
    let oui = crate::oui::OuiDb::embedded();
    let seed = cfg.session.seed.unwrap_or(0);
    build_validated_plant(cfg, t, &oui, seed, 0).map(|_| ())
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
