//! Command line surface for the turbolaser binary.
//!
//! The gun metaphor maps onto the subcommands. `run` fires packets at the
//! sensor. `reload` hand-loads the rounds, the variant pcaps, ahead of time.
//! `up`, `down`, and `status` operate the appliance.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Default config path on an installed appliance.
pub const DEFAULT_CONFIG: &str = "/opt/replay/conf/replay.yaml";

#[derive(Parser, Debug)]
#[command(
    name = "turbolaser",
    version,
    about = "Headless ICS/OT pcap replay appliance"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the replay daemon loop (fire).
    Run(RunArgs),
    /// Forge variant pcaps from a source capture (reload the magazine).
    Reload(ReloadArgs),
    /// Enable and start the appliance service (the unit sets up the mirror).
    Up(NetArgs),
    /// Stop and disable the appliance service (the unit tears down the mirror).
    Down(NetArgs),
    /// Print the live fire-control readout from the heartbeat file (pew pew).
    Pewpew(StatusArgs),
    /// Deprecated alias for `pewpew`, kept for one release.
    #[command(hide = true)]
    Status(StatusArgs),
    /// Validate a config file without replaying.
    Check(CheckArgs),
    /// Show the current zone map (green derives from captures, red reads the ledger).
    Zones(ZonesArgs),
    /// Clear the red-laser session ledger for a fresh feed.
    Reset(ResetArgs),
    /// Preview the fabricated zone and device map without sending traffic.
    Plan(PlanArgs),
    /// Set up the bridge and mirror from config. Used by the systemd unit.
    NetSetup(NetArgs),
    /// Tear down the bridge and mirror from config. Used by the systemd unit.
    NetTeardown(NetArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Path to the replay config.
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Run a single replay iteration then exit. For testing.
    #[arg(long)]
    pub once: bool,
}

#[derive(Args, Debug)]
pub struct ReloadArgs {
    /// Source capture to reload from.
    #[arg(long = "in", value_name = "PCAP")]
    pub input: PathBuf,
    /// Directory to write the forged rounds into.
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,
    /// Which protocol mutator to apply.
    #[arg(long, value_enum, default_value_t = ProtoSel::Auto)]
    pub proto: ProtoSel,
    /// Base seed, hex (0x...) or decimal. Round i uses seed_base + i.
    #[arg(long, value_name = "SEED")]
    pub seed_base: Option<String>,
    /// Number of rounds to forge.
    #[arg(long, default_value_t = 1)]
    pub count: u32,
    /// Mutation mode.
    #[arg(long, value_enum, default_value_t = ModeSel::RedLaser)]
    pub mode: ModeSel,
    /// Also remap L3 with topology-preserving random subnets.
    #[arg(long)]
    pub remap_l3: bool,
    /// Validate each forged round with tshark after writing.
    #[arg(long)]
    pub validate: bool,
}

#[derive(Args, Debug)]
pub struct NetArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
}

#[derive(Args, Debug)]
pub struct ZonesArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ResetArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
    /// Intended fleet size to fabricate. Defaults to synthesis.target_devices.
    #[arg(long)]
    pub devices: Option<usize>,
    /// Persist the fabricated session as the authoritative ledger the daemon
    /// replays verbatim. Without this, `plan` only previews.
    #[arg(long, visible_alias = "write")]
    pub commit: bool,
    /// Overwrite an existing committed ledger (with --commit).
    #[arg(long)]
    pub force: bool,
    /// Explicit preview only; never write. Mutually exclusive with --commit.
    #[arg(long, conflicts_with = "commit")]
    pub dry_run: bool,
}

/// Protocol selector for reload. `auto` dispatches by sniffing each frame.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lowercase")]
pub enum ProtoSel {
    Auto,
    Modbus,
    Enip,
    S7,
    Dnp3,
}

/// Randomisation mode shared by run and reload.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "snake_case")]
pub enum ModeSel {
    RedLaser,
    GreenLaser,
}
