# Changelog

All notable changes to ot-turbolaser are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

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
