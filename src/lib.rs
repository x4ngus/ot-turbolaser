//! ot-turbolaser: a headless ICS/OT pcap replay appliance.
//!
//! The binary is a thin shell over this library. Each subcommand has an
//! entrypoint here so the logic stays unit testable. See [`cli`] for the
//! command surface and the README for the architecture.

pub mod cli;

use cli::{Cli, Command};

/// Dispatch a parsed CLI to the matching subcommand. Returns a process exit
/// code: 0 on success, non-zero on error.
pub fn dispatch(cli: Cli) -> i32 {
    match cli.command {
        Command::Run(_) => not_yet("run"),
        Command::Reload(_) => not_yet("reload"),
        Command::Up(_) => not_yet("up"),
        Command::Down(_) => not_yet("down"),
        Command::Status(_) => not_yet("status"),
        Command::Check(_) => not_yet("check"),
    }
}

fn not_yet(what: &str) -> i32 {
    eprintln!("{what}: not yet implemented");
    1
}
