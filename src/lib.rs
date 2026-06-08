//! ot-turbolaser: a headless ICS/OT pcap replay appliance.
//!
//! The binary is a thin shell over this library. Each subcommand has an
//! entrypoint here so the logic stays unit testable. See [`cli`] for the
//! command surface and the README for the architecture.

pub mod cli;
pub mod config;
pub mod control;
pub mod ledger;
pub mod oui;
pub mod pcapio;
pub mod proto;
pub mod reload;
pub mod run;
pub mod scenario;
pub mod simulate;
pub mod synth;
pub mod threat;
pub mod validate;
pub mod vuln;

use cli::{Cli, Command};

/// Dispatch a parsed CLI to the matching subcommand. Returns a process exit
/// code: 0 on success, non-zero on error.
pub fn dispatch(cli: Cli) -> i32 {
    match cli.command {
        Command::Run(a) => run::run(&a),
        Command::Check(a) => check(&a),
        Command::Zones(a) => simulate::cmd_zones(&a),
        Command::Reset(a) => simulate::cmd_reset(&a),
        Command::Plan(a) => simulate::cmd_plan(&a),
        Command::Reload(a) => reload::reload(&a),
        Command::Up(a) => control::up(&a),
        Command::Down(a) => control::down(&a),
        Command::Pewpew(a) => control::pewpew(&a),
        Command::Status(a) => control::pewpew(&a),
        Command::NetSetup(a) => control::net_setup(&a),
        Command::NetTeardown(a) => control::net_teardown(&a),
        Command::Verify(a) => validate::cmd_verify(&a),
        Command::Targets(a) => scenario::cmd_targets(&a),
    }
}

fn check(a: &cli::CheckArgs) -> i32 {
    match config::load_with_scenario(&a.config, a.scenario.as_deref()) {
        Ok(cfg) => {
            let scenario = cfg
                .target
                .as_ref()
                .map(|t| format!(" scenario={}", t.name))
                .unwrap_or_default();
            println!(
                "config OK: iface={} mode={}{scenario} rate={:?} gap={:?}",
                cfg.iface,
                cfg.mode.as_str(),
                cfg.rate.model,
                cfg.gap.dist
            );
            0
        }
        Err(e) => {
            eprintln!("config error: {e}");
            1
        }
    }
}
