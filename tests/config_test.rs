//! The shipped sample config must always parse and validate.

use std::path::Path;

#[test]
fn sample_config_parses_and_validates() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf/replay.yaml");
    let cfg = ot_turbolaser::config::load(&p)
        .unwrap_or_else(|e| panic!("sample config should load and validate: {e}"));
    assert_eq!(cfg.iface, "tl0");
    assert_eq!(cfg.mode, ot_turbolaser::config::Mode::Variety);
}
