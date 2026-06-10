//! Command line surface for the turbolaser binary.
//!
//! The fire-control metaphor maps onto the subcommands. `fire` (alias `up`)
//! brings the appliance online and `halt` (alias `down`) stands it down; in
//! between, the systemd unit runs `run`, the replay daemon loop. `reload`
//! hand-loads the rounds, the variant pcaps, ahead of time, and `pewpew` prints
//! the live fire-control readout.

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
    /// Run the replay daemon loop. The systemd unit invokes this; operators use
    /// `fire` and `halt`.
    Run(RunArgs),
    /// Forge variant pcaps from a source capture (reload the magazine).
    Reload(ReloadArgs),
    /// Bring the appliance online: enable and start the service, which sets up
    /// the mirror. Alias: fire.
    #[command(visible_alias = "fire")]
    Up(FireArgs),
    /// Take the appliance offline: stop and disable the service, which tears down
    /// the mirror. With --scenario, stops the templated unit. Alias: halt.
    #[command(visible_alias = "halt")]
    Down(FireArgs),
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
    /// Qualify the live datapath: confirm frames egress the replay port and reach
    /// the sensor port through the SPAN mirror. Triage for "the sensor sees nothing".
    NetShow(NetShowArgs),
    /// Validate the MAC<->IP union: profile the emitted ARP burst against the
    /// reference OT bands and/or score a passive-sensor asset export against the plan.
    Verify(VerifyArgs),
    /// List the installed target scenarios (the red-laser attack packs).
    Targets(TargetsArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Path to the replay config.
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Run a single replay iteration then exit. For testing.
    #[arg(long)]
    pub once: bool,
    /// Load a target scenario (a pack under the config's `targets/` dir),
    /// overlaying its attack on red laser. Omit for the generic plant.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
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
pub struct NetShowArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
    /// Sample the replay-tx and sensor-rx counters over this many seconds to show
    /// frames are flowing right now. 0 skips the live probe (static checks only).
    #[arg(long, default_value_t = 2)]
    pub probe_secs: u64,
}

#[derive(Args, Debug)]
pub struct FireArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Run a target scenario as the daemon via the templated unit
    /// (`ot-turbolaser@<name>`) instead of the generic service. Omit for generic
    /// red laser.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
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
    /// Validate the config with a target scenario overlaid.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
}

#[derive(Args, Debug)]
pub struct ZonesArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
    /// Show the map for a target scenario's plant.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
}

#[derive(Args, Debug)]
pub struct TargetsArgs {
    /// Path to the replay config; its sibling `targets/` dir is scanned.
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
    /// Resolve the session path with a target scenario overlaid.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
}

#[derive(Args, Debug)]
pub struct PlanArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
    /// Preview (or commit) a target scenario's pinned plant instead of the
    /// generic fabricated one.
    #[arg(long, value_name = "NAME")]
    pub scenario: Option<String>,
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

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(long, default_value = "/opt/replay/conf/replay.yaml")]
    pub config: PathBuf,
    /// A passive-sensor CSV asset export to score for MAC<->IP union-rate vs the plan.
    #[arg(long, value_name = "CSV")]
    pub csv: Option<PathBuf>,
    /// An emitted burst pcap to profile against the reference ARP bands. If
    /// omitted, the daemon's synth burst at <shm_dir>/synth-identity.pcap is used.
    #[arg(long, value_name = "PCAP")]
    pub pcap: Option<PathBuf>,
    /// Emit raw JSON instead of a human summary.
    #[arg(long)]
    pub json: bool,
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
