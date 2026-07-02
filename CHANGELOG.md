# Changelog

All notable changes to ot-turbolaser are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

Backport of the two HIGH defects found in the 0.4.1 scenario-framework review. Both
are latent in 0.4.0; they will ship in the next stable release (0.4.1). The stable
tag is held for now (these also land on the develop 0.4.1 line as 0.4.1-beta.2).

### Fixed
- **Orphaned playbook target no longer emits zero frames silently (SP-1).** A
  playbook `target` naming no plant device now fails pre-flight instead of rendering
  nothing while the daemon looked healthy. `build_validated_plant` cross-checks every
  event target against the pinned plant (`ScenarioEngine::validate_targets`); a
  `c2_beacon` may omit its target, every other event must name one that resolves.
- **Non-default `PREFIX` install no longer sits idle forever (SP-2).** `install.sh`
  templates `conf/replay.yaml` to the install `PREFIX` so `paths.pool` and
  `paths.variants` point inside the install tree, not the never-created
  `/opt/replay/pcaps/*`. The default `/opt/replay` install is unchanged.

## [0.4.0] - 2026-07-02

First stable 0.4.0, then hardened for prime time. The headline 0.4.0 additions
(target scenarios, datapath provisioning/triage, Proxmox out-of-the-box) are in
the Baseline note below; this revision folds in a structured audit pass: one
correctness fix, defensive hardening, config fail-fast, dead-code removal, and a
custom-PREFIX install fix.

### Fixed
- **Unique MACs across the fabricated fleet.** Red-laser device fabrication now
  derives each MAC deterministically from its (already unique) IP via the shared
  `stable_mac` helper and enforces uniqueness with a used-MAC set, so no two
  fabricated assets can share a MAC (which would emit conflicting ARP `is-at`
  replies the sensor must never see). Because MAC generation no longer draws from
  the fabrication RNG, a given `session.seed` now produces a different but stable
  plant layout; committed/sealed ledgers replay verbatim and are unaffected.
- **Saturating arithmetic in cycle zone-naming** (`simulate::engine`) so a very
  long-lived unsealed feed can never overflow the area number and repeat names.

### Added
- **`turbolaser check` rejects zero timing/rate knobs** at config load instead of
  letting them fail (or spin) at runtime: `watchdog.poll_secs`,
  `watchdog.flatline_secs`, `no_pcaps_retry_secs`, `synthesis.announce_interval_secs`
  (when synthesis is enabled), and `rate.pps_multi`.

### Changed
- **`install.sh` templates the systemd units and the optional hardening drop-in to
  the install `PREFIX`.** A deploy under a non-default `PREFIX` now gets working
  `ExecStart`/`ExecStartPre` paths and a matching `$PREFIX/systemd/hardening.conf`;
  the default `/opt/replay` install is byte-for-byte unchanged.
- Documentation corrections: the L1/L2 zone-cap comment (10 zones are a subset of
  the 16-zone hard cap), the `synthesis.max_assets` default (512), the `AGENTS.md`
  hard-cap note (16 subnet zones), and the README quickstart config path.

### Removed
- **Deprecated `l3.fallback` config key and its `L3Fallback` enum**, unused since
  v0.2.1. A config that still sets `l3.fallback:` is now rejected by the strict
  schema (`deny_unknown_fields`); delete the line (no shipped config used it).

### Baseline (0.4.0, 2026-06-17)

First stable 0.4.0 release. Promotes the 0.4.0-beta ladder (beta.1–beta.5),
validated on a live Proxmox appliance feeding a Dragos sensor, to stable with no
code changes over beta.5 — only the version string and this entry. The per-beta
sections below carry the detailed history; the headline additions over 0.3.2:

- **Target scenario framework.** Drop-in attack packs under `conf/targets/<name>/`
  pin a specific real-world OT attack on top of red laser: a YAML overlay, a CVE
  profile overlay, a sealed plant, and a phased playbook. `turbolaser targets`
  lists them; `--scenario <name>` (and `ot-turbolaser@<name>.service`) runs one,
  guarded so a generic daemon never replays a scenario ledger and vice versa.
- **Datapath provisioning and triage.** `turbolaser net-provision` creates the
  isolated replay+sensor veth pair a self-contained host needs; `net-setup`
  auto-detects self-contained vs hypervisor and no-ops where the host owns the
  mirror (Proxmox works out of the box, no systemd drop-in); `turbolaser net-show`
  qualifies the live datapath for "the sensor sees nothing" faults.
- **Robust SPAN delivery.** `scripts/net-setup.sh` floods bridge members so unicast
  reaches the sensor even past `PACKET_QDISC_BYPASS` (the split-assets fix).
- **Fail clean, not crash-loop.** Non-retryable config/state errors exit 78
  (`EX_CONFIG`) uniformly; both systemd units stop on it (`RestartPreventExitStatus`)
  with `StartLimit` as the backstop, leaving a bad config `failed` with its remedy.

## [0.4.0-beta.5] - 2026-06-17

Make the Proxmox deployment work out of the box and stop non-retryable errors from
crash-looping under systemd. A fresh appliance whose unit ran `net-setup` in the
container hit `scripts/net-setup.sh` exit 4 ("interface 'sens0' not found") because
on Proxmox the host provides the ports and owns the mirror; with `Restart=always`
and no `StartLimit`/`RestartPreventExitStatus`, the unit looped the same error
forever. The only workaround was a manual `systemctl edit` drop-in.

### Added
- **`conf/replay.proxmox.yaml.example`**: a ready-made profile for the hypervisor
  layout (`iface: eth1`, host-side `bridge`/`sensor_port`), so the in-container
  `net-setup` auto-no-ops and the host runs the mirror (see `docs/proxmox.md`).

### Changed
- **`net-setup`/`net-teardown` auto-detect the deployment.** When the configured
  `sensor_port` is absent on this host — the hypervisor (Proxmox) provides the ports
  and runs the mirror on the host — net-setup no-ops cleanly (exit 0) instead of
  exiting 4. No `systemctl edit` drop-in is needed; a stock config just works on
  Proxmox. `fire`'s datapath pre-flight is hypervisor-aware to match (a missing
  sensor port is no longer an error; only a missing replay port is). The signal is
  the sensor port because a self-contained host's `net-provision` makes both ports
  exist, so "ports exist" alone cannot tell the regimes apart.
- **`scripts/net-setup.sh` applies the robust L2 fix by default.** Its `tc` mode now
  sets `learning off flood on` on every bridge-member port, so a monitoring span
  delivers unicast to the sensor even when tcpreplay transmits with
  `PACKET_QDISC_BYPASS` (which skips the egress qdisc and the tc-mirred mirror). This
  is the in-script equivalent of the manual `bridge link set` step the Proxmox guide
  documented for the "broadcast but not unicast / split assets" symptom.
- **Non-retryable config/state errors exit `78` (`EX_CONFIG`), uniformly.** A bad
  config, a missing replay port, a scenario/ledger mismatch, or a corrupt ledger now
  exit 78 across every subcommand (`run`, `check`, `fire`, `net-setup`, `zones`,
  `reset`, `plan`, `verify`, …) instead of the previous mix of 1/2. Transient faults
  (missing captures, a failed send) keep the daemon's in-loop sleep-and-retry.
- **systemd units fail clean instead of crash-looping.** Both units set
  `RestartPreventExitStatus=78`, and the plain `ot-turbolaser.service` gains
  `StartLimitIntervalSec=60`/`StartLimitBurst=5` (matching the templated unit). A
  config/scenario error now leaves the unit `failed` with its one-line remedy in the
  journal rather than scrolling forever.
- **`docs/proxmox.md`**: the manual `ExecStartPre=` drop-in step is gone (net-setup
  auto-no-ops); notes that `net-setup.sh` now applies flood-on; adds a `pct exec`
  PATH note (use the absolute `/opt/replay/bin/turbolaser` for non-login shells).

## [0.4.0-beta.4] - 2026-06-11

Operator ergonomics for the datapath interfaces, after a fresh-appliance
`fire --scenario triton` failed with only systemd's opaque "the control process
exited with error code". The cause was the unit's `net-setup` ExecStartPre exiting
because the replay and sensor ports did not exist, and nothing created them.

### Added
- **`turbolaser net-provision`** (and `scripts/net-provision.sh`): create the
  isolated replay+sensor veth pair a self-contained host needs before `net-setup`
  and `fire` can run. Names come from the config (`iface` / `net.sensor_port`) so
  they always match the daemon. Idempotent, refuses to touch a physical NIC (the
  isolation invariant holds), and `--undo` removes the pair. Not used on Proxmox,
  where the hypervisor provides the ports. `install.sh` ships the script and names
  the step in its next-steps output; `just provision` and the README "Deployment
  topology" section (with the raw `ip link` equivalent) document it.

### Changed
- **`fire` pre-flights the datapath ports.** Both `fire` and `fire --scenario`
  now confirm the configured replay (`iface`) and sensor (`net.sensor_port`) ports
  exist before enabling the unit, and fail fast (exit 2) naming the missing
  interface and the remedy (`turbolaser net-provision`), instead of letting
  `net-setup`'s ExecStartPre fail under systemd with no actionable hint. The check
  is gated on `/sys/class/net`, so a non-Linux dev host still falls through to the
  existing "no systemd" guidance rather than a false abort.

## [0.4.0-beta.3] - 2026-06-10

Internal cleanups from a quality pass over the beta work. No behaviour change.

### Changed
- `net-show` gathers the interface counters once into its snapshot and both the
  human and JSON renderers read from it, instead of re-opening `/sys` per output
  line; the readout now reflects the same instant the verdict was computed on.
- Pack validation is centralised in one `scenario::build_validated_plant`
  sequence that `plan` and `check`/`fire` (via `preflight`) share, so they cannot
  drift on what a valid pack is.
- Added `MirrorMode::as_str()` (matching `Mode::as_str()`) in place of two inline
  match arms; the plant hostname re-qualification is a single pass.
- `install.sh` system integration (PATH symlink, systemd units, `/var/lib`) is now
  gated by an explicit `OT_INSTALL_SYSTEM` flag (default on) rather than inferred
  from `PREFIX`, so a real install under a non-default prefix is not silently left
  non-functional; the install-layout smoke test sets `OT_INSTALL_SYSTEM=0`.

## [0.4.0-beta.2] - 2026-06-10

A content-fidelity fix on top of beta.1.

### Fixed
- **Stuxnet S7-417 order number corrected to a real Siemens MLFB.** The pinned
  `s7_order_number` was `6ES7 417-4XT07-0AB0`, whose `4XT07` middle group is not a
  valid Siemens 417 hardware-revision code, so a passive sensor fingerprinting the
  SZL module-identification order number against a Siemens catalog would not match
  a real part. Replaced with the genuine S7-400H CPU 417-4H MLFB
  `6ES7 417-4HT14-0AB0`, and the firmware corrected from `V5.2.0` to `V4.5.4` (the
  real V4.5.x track for that MLFB; the prior value did not match the part). The
  417 (cascade protection) is the system the Stuxnet "417 code" warhead targeted.
  Read via `s7_szl::exchange`; no code change.

## [0.4.0-beta.1] - 2026-06-10

First beta of the 0.4.0 line. The alpha shipped the target-scenario framework but
the scenarios did not load on an installed appliance; this beta makes them load,
adds the regression test that would have caught it, makes a broken pack fail safe
instead of crash-looping, and adds a runtime datapath-triage command. No new
scenarios or emit kinds (deferred to later 0.4.x betas); the four shipped packs
keep `ioc_fidelity: real`.

### Fixed
- **Target scenarios now ship with the appliance (the headline bug).**
  `install.sh` laid down the binary, config, and data DBs but never copied
  `conf/targets/`, and the packs have no embedded fallback, so on a real install
  `run --scenario`/`targets`/`check --scenario` all failed and
  `ot-turbolaser@<name>` crash-looped. The installer now copies every pack
  (`scenario.yaml`/`playbook.yaml`/`plant.yaml`/`profiles.toml`) into
  `<prefix>/conf/targets/`, honouring the same `.example` no-clobber convention as
  the config, and skipping `_`-prefixed dirs (the authoring `_template`). It also
  ships `veth-replay-check.sh`. CI passed through the alpha because the tests load
  the repo-relative `conf/`, never the installed tree.

### Added
- **`install-smoke.sh` + a CI step** that installs into a sandbox `PREFIX` and
  asserts the four packs are present and load through the real binary
  (`targets` lists 4, `check --scenario <name>` exits 0). This is the regression
  guard the source-tree tests cannot provide. `install.sh` now honours an
  overridable `PREFIX` and skips system integration (PATH symlink, systemd units,
  `/var/lib`) for a non-default prefix, so the smoke test is hermetic and rootless.
- **`turbolaser net-show`**: a read-only, single-call datapath triage. It
  qualifies that frames actually egress the replay port and reach the sensor port
  through the SPAN mirror (live tx/rx delta probe), checks the bridge, mirror, and
  promiscuity, cross-checks the heartbeat, and exits non-zero naming the specific
  defect with a remedy. Closes the gap that `pewpew` (daemon-reported counters
  only) cannot see, after a live-demo failure where the sensor had no ingest and
  there was no fast way to localise the fault between appliance, bridge, and sensor.
- **Pre-flight validation of the whole pack.** `check --scenario` and
  `plan --scenario` now load the plant, playbook, and profiles, so a broken pack is
  rejected at pre-flight instead of at the daemon's first start.

### Changed
- **A broken scenario no longer self-destructs.** `ot-turbolaser@.service` gains
  `StartLimitIntervalSec`/`StartLimitBurst` so a genuinely broken pack lands in
  `failed` instead of crash-looping every `RestartSec`, plus an `ExecStartPre`
  that fails early with a clear message if the named pack is not installed.
- **A corrupt `session.json` is recoverable again.** The daemon warns and rebuilds
  a fresh plant rather than refusing to start; only the deliberate
  scenario-mismatch guard (a ledger that parsed cleanly but belongs to a different
  scenario) stays fatal.
- **Proxmox docs** gain a `net-show`-first triage path and a host-by-host tcpdump
  runbook (turbolaser CT, Proxmox host, sensor VM) with a fault-localisation
  decision tree.
- Stabilisation hardening: a strict `payload_hex` decoder (rejects odd-length or
  malformed hex instead of silently shifting bytes), plant-integrity checks
  (duplicate-IP rejection, hostname re-qualification), a loud warning when a pack's
  `profiles.toml` is malformed, `fire --scenario`, and clearer `targets` output
  when the targets dir is missing versus empty.
- Content fidelity: the four packs' CVEs, firmware, order numbers, and indicators
  were re-verified against their cited advisories (the Ukraine breaker-open is
  correctly mapped to ATT&CK T0855 Unauthorized Command Message). The Stuxnet
  S7-417 order number needed a follow-up correction to a real Siemens MLFB; see
  the beta.2 entry above.

## [0.4.0-alpha.2] - 2026-06-08

Second alpha of the 0.4.0 line: hardening from a full code review of the scenario
framework. No behaviour change to the shipped scenarios or to generic red laser;
all fixes close latent edges a hand-authored pack or an unusual deploy could hit.

### Added
- **Templated systemd unit** `ot-turbolaser@.service` to run a target scenario as
  the daemon (`systemctl start ot-turbolaser@stuxnet`). The stock unit and
  `fire`/`halt` still run generic red laser; `docs/targets.md` now documents the
  difference and warns that committing a scenario plant and then `fire`-ing the
  stock unit crash-loops.

### Fixed
- **Oversized synth frames no longer abort the replay.** A misauthored scenario
  `payload_hex` (Moxa brick, S7 download, TriStation) could build a frame over the
  link MTU; the synth burst now drops such frames with a warning, the same guard
  the remap path already applied to replayed captures, instead of failing the
  whole tcpreplay run with EMSGSIZE.
- **Auto-assigned pinned devices skip the firewall slot.** A plant device that
  omits `ip:` under `enrich: true` no longer lands on network+1 (the gateway slot
  enrich reserves for the zone firewall/DNS resolver), which previously left that
  zone with no firewall. It now uses the same gateway-skipping allocator as the
  generic fabricator.
- **Modbus FC16 clamps to 123 registers** so the single-byte PDU byte-count can
  never truncate or disagree with the register payload.

### Changed
- **Status heartbeat note:** the heartbeat `schema` moved 3 -> 4 in alpha.1 with
  the additive `scenario`, `phase`, and `technique_ids` fields. The in-tree reader
  (`pewpew`) is field-tolerant; an external consumer keyed on `schema == 3` must
  accept 4.
- CI now requires tshark for the scenario dissector gate (`OT_REQUIRE_TSHARK`), so
  a lost dissector fails the build instead of skipping the gate. Added tests for
  the Modbus clamp, the auto-IP firewall slot, looped-campaign phase wrap, and the
  per-burst frame-cap split.

## [0.4.0-alpha.1] - 2026-06-08

First pre-release (alpha) of the 0.4.0 line, for validation on the isolated
bridge before promotion to stable.

A modular **target scenario** layer for red laser: load a documented real-world
OT attack and the appliance pins that attack's plant and drives a phased attack
timeline onto the isolated bridge, so a passive sensor sees the incident unfold.

### Added
- **`target` scenario framework.** A scenario is a drop-in data pack under
  `targets/<name>/` (`scenario.yaml` + `plant.yaml` + `playbook.yaml` +
  `profiles.toml`). Its YAML deep-merges over the base config; its profiles
  overlay the embedded CVE database; its plant is pinned into a sealed,
  scenario-tagged ledger; its playbook drives the attack. Adding a scenario is
  pure data, with no code change. Activated with `--scenario <name>` on `run`,
  `plan`, `check`, `zones`, and `reset`; no scenario leaves red laser unchanged.
- **Four scenarios.** `stuxnet` (Siemens S7 / Natanz centrifuges),
  `triton` (Schneider Triconex SIS), `oldsmar` (water-treatment NaOH setpoint),
  and `ukraine2015` (BlackEnergy / IEC-104 grid), each with a real BOM, real
  CVEs, ATT&CK-for-ICS-phased timelines, and the published indicators.
- **Control-plane emitters.** New synth builders for the attack actions a passive
  sensor fingerprints: S7 program-download / write-var / PLC-STOP, Modbus
  write-register (FC6/FC16), **TriStation** (UDP/1502), **IEC 60870-5-104**
  (TCP/2404), and IOC injectors (C2 beacon, remote access, KillDisk share write,
  Moxa firmware brick).
- **`turbolaser targets`** lists the installed scenarios.
- **Status & readout.** The heartbeat (schema 4) and `pewpew` surface the active
  scenario, its current phase, and the ATT&CK-for-ICS technique ids in play.

### Notes
- Scenario traffic carries real published indicators by default (`ioc_fidelity:
  real`) and must run only on the isolated bridge; set `ioc_fidelity: standin`
  for documentation-range stand-ins. Indicator strings live in pack data, never
  the binary. See `docs/targets.md`.
- A scenario daemon refuses to replay a generic ledger and vice versa, so a
  stale session never bleeds one mode into the other.

## [0.3.2] - 2026-06-07

### Added
- North-south conduit traffic across adjacent Purdue zones, switch/router/
  firewall SNMP firmware CVEs, and shared cross-zone DNS domain identity.

## [0.3.1] - 2026-06-07

Initial open-source release. ot-turbolaser fabricates a believable OT/ICS network
and replays it onto an isolated mirror so a passive sensor discovers a coherent
asset inventory: every asset fused to one MAC, IP, vendor, and name.

### Added
- **Full asset identity (MAC ↔ IP ↔ DNS).** Assets bind MAC↔IP from an
  authoritative ARP `is-at` reply, solicited by an organically-distributed
  control-cell graph (no subnet scan). Each carries a real vendor OUI and
  resolves a recognisable hostname (`LINE-01-PLC`, `CELL-02-S7`, …) via a
  per-zone DNS resolver.
- **Believable plant.** A per-zone bill of materials (controllers, a managed
  switch, an HMI, an engineering workstation, and a zone-edge firewall at `.1`)
  plus Purdue L3 operations (DCS) zones of historians, OPC/domain/application
  servers, and operator stations.
- **CVE attribution.** ~10% of assets (the real-model controllers) carry
  advisory-sourced CVEs, delivered as genuine OT protocol exchanges
  (EtherNet/IP, Modbus, S7comm, SNMP).
- **`turbolaser verify`.** A self-contained post-deploy oracle: profiles the
  emitted ARP against a reference band and scores a sensor's CSV export for
  MAC↔IP union-rate and hostname coverage against the sealed plan.
- **Operator surface.** `plan` / `fire` / `halt` / `pewpew` / `reload` /
  `zones` / `verify`, an isolated bridge with a SPAN mirror, weighted capture
  selection, inter-run gap distributions, a tx watchdog, a JSON status
  heartbeat, and systemd + Proxmox deployment.

### Notes
- No DHCP is ever synthesized: it is not an OT protocol and would be a tell.
- Replay runs only on an isolated segment with no route to a production network.
