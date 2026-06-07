//! The shipped sample config must always parse and validate.

use std::path::Path;

#[test]
fn sample_config_parses_and_validates() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/replay.yaml");
    let cfg = ot_turbolaser::config::load(&p)
        .unwrap_or_else(|e| panic!("sample config should load and validate: {e}"));
    assert_eq!(cfg.iface, "tl0");
    assert_eq!(cfg.mode, ot_turbolaser::config::Mode::RedLaser);
}

fn write(dir: &tempfile::TempDir, name: &str, yaml: &str) -> std::path::PathBuf {
    use std::io::Write;
    let path = dir.path().join(name);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(yaml.as_bytes())
        .unwrap();
    path
}

const BASE: &str = "iface: tl0
mode: red_laser
paths:
  pool: /opt/replay/pcaps/pool
  variants: /opt/replay/pcaps/variants
  shm_dir: /dev/shm/ot-turbolaser
  status_file: /run/ot-turbolaser/status.json
rate:
  model: original
gap:
  dist: exp_poisson
  mean_secs: 5.0
";

#[test]
fn v02_sections_parse_with_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = format!(
        "{BASE}zones:\n  max_subnets: 8\n  default_prefix: 24\nthreats:\n  external_cidrs: [\"198.51.100.0/24\"]\nsession:\n  seed: 42\n"
    );
    let cfg = ot_turbolaser::config::load(&write(&dir, "ok.yaml", &yaml))
        .expect("v0.2 sections should load and validate");
    assert_eq!(cfg.zones.max_subnets, Some(8));
    assert_eq!(cfg.session.seed, Some(42));
    assert!(cfg.synthesis.enabled, "synthesis defaults on");
}

#[test]
fn rfc1918_external_cidr_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = format!("{BASE}threats:\n  external_cidrs: [\"10.0.0.0/8\"]\n");
    assert!(
        ot_turbolaser::config::load(&write(&dir, "bad.yaml", &yaml)).is_err(),
        "an RFC1918 external range must be rejected"
    );
}

#[test]
fn unknown_field_still_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = format!("{BASE}zones:\n  bogus_key: 1\n");
    assert!(
        ot_turbolaser::config::load(&write(&dir, "typo.yaml", &yaml)).is_err(),
        "deny_unknown_fields must still reject typos"
    );
}
