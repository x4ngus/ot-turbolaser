# AGENTS.md

Context for future sessions working on ot-turbolaser. Read this before changing
the architecture.

## What this is

A headless, modular ICS/OT PCAP replay appliance. A Rust daemon (the turbolaser)
continuously replays industrial protocol captures with randomised, genuine
looking L3 identifiers and randomised timing onto an isolated virtual bridge with
no uplink. A host-side SPAN mirror copies the replay port to a passive sensor's
monitor port. The purpose is to drive a passive OT monitoring sensor with varied,
non-trivially-periodic traffic to exercise parsers and detections, or to produce
a baseline. Primary deployment is a Proxmox LXC container, secondary a minimal
Linux VM.

## Locked decisions

- Whole toolset is Rust. No Python, no scapy, anywhere.
- One crate, one binary `turbolaser`, over a shared library. Subcommands:
  `run` (the daemon loop), `reload` (forge variant pcaps), `up`, `down`,
  `status`, `check`.
- `reload` replaces the originally planned Python+scapy baker. The gun metaphor
  ties naming to function: `run` fires, `reload` hand-loads the rounds.
- Default mirror is tc clsact/mirred. An OVS helper is also provided.
- Base image is Debian 12. Ship a static musl binary.
- Replay rate defaults to original capture timing. Multiplier, pps, mbps, and
  topspeed are also selectable.
- Inter-run gap distributions: exponential/Poisson and truncated normal only.
- Red laser per-run randomisation is L3 only and topology preserving. No MAC, no
  L4. The cheap tier is an in-process coherent remapper, not tcprewrite.
  tcprewrite is kept only as an optional fallback.
- Observability: structured logs to stderr (journald ingests them) plus a JSON
  heartbeat at /run/ot-turbolaser/status.json.
- License is MIT.

## Hard invariants

- Never bridge to a production or uplinked network. net-setup must refuse to
  attach the bridge to a physical NIC and warn loudly.
- No payload-layer mutation in the hot path. Only the L3 coherent remap runs per
  run. All payload identity mutation happens offline in `reload`.
- Mutations are fixed-width. No field changes byte length, so upper-layer length
  fields never need recomputation. Only the protocol CRC (DNP3) and the L3/L4
  checksums change.
- Fail safe. If no pcaps are present, sleep and retry, never crash-loop. systemd
  Restart=always plus the tx watchdog cover the rest.
- Variants must stay internally consistent so the sensor never sees malformed
  traffic. Validate forged rounds with tshark.

## License hygiene

No Rust dissector for these OT protocols is permissively licensed. rmodbus
(Apache), the ENIP/CIP client crates, s7-comm (non-standard license),
stepfunc/dnp3 (non-commercial), and Suricata's parsers (GPLv2) may be read as
references only. Never vendor them. Implement mutators from public protocol
specs. See LICENSES.md.

## Prose and comments

Plain and direct. No em-dashes. No filler.

## Build and test

```
cargo build
cargo test
cargo fmt
cargo clippy
turbolaser check --config conf/replay.yaml
turbolaser reload --in <pcap> --out-dir variants/ --count 4 --validate
```

The live replay path (tcpreplay), the mirror (tc/ovs), the watchdog reads from
/sys, and systemd are validated on target, not in CI. The reload pipeline and
all pure logic are unit testable, and tshark validates forged output anywhere
tshark is installed.
