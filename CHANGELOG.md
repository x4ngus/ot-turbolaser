# Changelog

All notable changes to ot-turbolaser are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.2.1] - 2026-06-03

Fixes the v0.2.0 production-trial drift between the planned world and what the
daemon actually replays, so the downstream sensor's asset inventory matches the
design.

### Changed
- `turbolaser plan --commit` (alias `--write`) now persists the fabricated
  session as the authoritative ledger the daemon replays verbatim; a sealed
  ledger is not grown past its planned fleet. Bare `plan` still only previews.
  `--force` overwrites an existing ledger; `--dry-run` is an explicit preview.
- The red-laser L3 remap is seeded from the persistent session seed instead of a
  per-run seed, so a capture maps to the same addresses every run rather than
  scattering across fresh random subnets each iteration.
- Replayed pcap hosts are remapped into the fabricated control-system zones by
  vendor and protocol affinity (`l3.zone_affinity`), so a Modbus conversation
  lands in a Modicon zone and the zones hold real device relationships instead
  of the bulk traffic piling into a generic catch-all.
- `session.seed` is the single red-laser reproducibility knob; the top-level
  `seed` is ignored in red laser and now warns if set. `synthesis.target_devices`
  sets the committed fleet size.
- Ledger schema bumped to 2 (adds `sealed`, `target_devices`); schema-1 files
  load unchanged and a newer schema is refused.

### Added
- Gratuitous ARP announcements per synthesized device, plus LLDP/CDP management
  address TLVs, so a passive sensor fuses each device into one MAC+IP asset
  rather than separate MAC-only and IP-only entries.
- SNMP responses bind sysObjectID.0 (the enterprise OID) alongside sysDescr.0,
  the field passive sensors key switch CVE attribution on. New profile fields:
  `enip_product_name`, `sys_object_id`, `modbus_vendor_name/product_code/revision`.
- `l3.max_remap_bytes`, `l3.on_oversize` (remap_to_disk | skip), and
  `l3.guard_public_sources` to keep oversize or un-remapped captures from
  leaking original (possibly public) addresses to the sensor.

### Fixed
- A failed or oversize L3 remap no longer falls back to replaying the original
  capture with its un-remapped (possibly public) addresses; the capture is
  skipped instead.
- ARP frames in replayed captures are now remapped, so they no longer leak the
  original sender/target IPs even when the IPv4 remap succeeds.
- Devices whose model is absent from the vuln DB are announced with a generic
  identity (logged once) instead of being silently dropped.
- Device fabrication builds its used-IP set once (was O(devices^2) per batch);
  the ledger temp file is now per-process so `plan --commit` cannot race a
  running daemon.
- Zone cycle renewal is wired and reachable (issue #2): an unsealed, saturated
  feed re-labels its zones every `synthesis.cycle_every_n_runs` runs (0/off by
  default); sealed plans never cycle. It was previously dead code with `cycle`
  stuck at 0.
- The deterministic remap is cached and reused across runs (issue #3): a repeated
  pick of the same capture skips the re-read and recompute. The cache is
  byte-bounded on tmpfs.
- Red-laser status counts devices per zone in a single pass instead of
  O(zones x devices) each heartbeat (issue #4).
- `l3.fallback` is deprecated and ignored, retained so existing configs parse.

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
