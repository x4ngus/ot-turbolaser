//! Scenario discovery.
//!
//! A scenario pack is an immediate subdirectory of the targets dir that contains
//! a `scenario.yaml`. Discovery is pure filesystem plus a shallow parse of each
//! `scenario.yaml` for its declared name/description, so `turbolaser targets`
//! can list packs without building a full merged config. Adding a scenario is a
//! drop-in: a new directory, no code change.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_norway::Value;

/// One discovered scenario pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScenarioInfo {
    /// Pack directory name (the `--scenario` argument).
    pub name: String,
    /// `target.name` declared inside scenario.yaml, if present.
    pub declared_name: Option<String>,
    /// `target.description` declared inside scenario.yaml, if present.
    pub description: Option<String>,
    pub dir: PathBuf,
    pub has_profiles: bool,
    pub has_playbook: bool,
    pub has_plant: bool,
}

/// The targets dir for a base config path: `<config_dir>/targets`.
pub fn targets_dir_for(base_config: &Path) -> PathBuf {
    base_config
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("targets")
}

/// Discover scenario packs under `targets_dir`: each immediate subdirectory that
/// holds a `scenario.yaml`, sorted by name. A missing or unreadable targets dir
/// yields an empty list -- no scenarios installed is not an error.
pub fn discover(targets_dir: &Path) -> Vec<ScenarioInfo> {
    let Ok(rd) = std::fs::read_dir(targets_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let scenario_yaml = dir.join("scenario.yaml");
        if !scenario_yaml.is_file() {
            continue;
        }
        let Some(name) = dir.file_name().and_then(|n| n.to_str()).map(String::from) else {
            continue;
        };
        // A `_`-prefixed dir (e.g. the authoring `_template`) is documentation, not
        // a runnable pack. The installer skips it; discovery does too, so it never
        // appears in `turbolaser targets` or as a selectable `--scenario`.
        if name.starts_with('_') {
            continue;
        }
        let (declared_name, description) = shallow_meta(&scenario_yaml);
        out.push(ScenarioInfo {
            name,
            declared_name,
            description,
            has_profiles: dir.join("profiles.toml").is_file(),
            has_playbook: dir.join("playbook.yaml").is_file(),
            has_plant: dir.join("plant.yaml").is_file(),
            dir,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Pull `target.name` and `target.description` from a scenario.yaml without a
/// full config merge. Best effort: any read or parse miss yields `(None, None)`.
fn shallow_meta(scenario_yaml: &Path) -> (Option<String>, Option<String>) {
    let Ok(text) = std::fs::read_to_string(scenario_yaml) else {
        return (None, None);
    };
    let Ok(val) = serde_norway::from_str::<Value>(&text) else {
        return (None, None);
    };
    let target = val.get("target");
    let pick = |k: &str| {
        target
            .and_then(|t| t.get(k))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    (pick("name"), pick("description"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_packs_with_scenario_yaml_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let targets = dir.path().join("targets");
        for (name, body) in [
            (
                "zebra",
                "target:\n  name: zebra\n  description: last alphabetically\n",
            ),
            ("alpha", "target:\n  name: alpha\n  description: first\n"),
        ] {
            let p = targets.join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("scenario.yaml"), body).unwrap();
            std::fs::write(p.join("profiles.toml"), "").unwrap();
        }
        // A directory without scenario.yaml is not a pack.
        std::fs::create_dir_all(targets.join("notapack")).unwrap();
        // A `_`-prefixed dir (the authoring template) is documentation, not a pack.
        let tmpl = targets.join("_template");
        std::fs::create_dir_all(&tmpl).unwrap();
        std::fs::write(tmpl.join("scenario.yaml"), "target:\n  name: _template\n").unwrap();

        let found = discover(&targets);
        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["alpha", "zebra"],
            "sorted; junk and _-prefixed dirs skipped"
        );
        assert_eq!(found[0].declared_name.as_deref(), Some("alpha"));
        assert_eq!(found[0].description.as_deref(), Some("first"));
        assert!(found[0].has_profiles);
        assert!(!found[0].has_playbook);
    }

    #[test]
    fn discover_missing_dir_is_empty_not_error() {
        assert!(discover(Path::new("/nonexistent/targets")).is_empty());
    }
}
