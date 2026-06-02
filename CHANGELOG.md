# Changelog

All notable changes to ot-turbolaser are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.2.0] - 2026-06-02

Takes the PoC to a usable prototype for ICS simulated security testing. Adds a
content layer (red laser only) that fabricates realistic ICS network structure
on top of the existing replay engine, plus operator tooling.

### Changed
- Renamed the two operating modes to codify their intent: `variety` is now
  `red_laser` (adversarial) and `baseline` is now `green_laser` (accurate). The
  old names still parse as config aliases. The status heartbeat gains a `laser`
  field and bumps its schema to 2; the `mode` field is retained as a deprecated
  duplicate for one release.

### Added
- Red laser: subnet-grouped zones with Purdue/62443-aware naming, managed
  switches as inter-zone conduits, simulated devices carrying real CVE-bearing
  firmware identities delivered as genuine protocol assertions (EtherNet/IP,
  Modbus 0x2B/0x0E, S7comm SZL, LLDP/CDP/SNMP), and sparse external-threat host
  promotion (rate-limited to one per 24 hours).
- Green laser: read-only zone derivation from actual capture addresses and OUIs.
- Persistent session ledger with hard caps (10 subnet zones, 2000 devices) and
  unique IP assignment preserved across restarts.
- New subcommands: `zones`, `reset`, `plan`. Zone and session stats in `status`.
- Bundled OUI and vulnerable-device-profile databases (embedded, on-disk
  override).
- GitHub Actions CI (fmt, clippy, build, test) and this changelog.

## [0.1.0]

Initial PoC. Headless Rust appliance that replays ICS/OT pcaps onto an isolated
bridge via tcpreplay, with topology-preserving L3 remap, four offline protocol
mutators (Modbus, EtherNet/IP, S7comm, DNP3), weighted capture selection,
inter-run gap distributions, a tx watchdog, a JSON status heartbeat, and systemd
plus Proxmox LXC deployment.
