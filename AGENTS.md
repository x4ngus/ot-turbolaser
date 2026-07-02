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
  `status`, `check`, `zones`, `plan`, `reset`.
- `reload` replaces the originally planned Python+scapy baker. The gun metaphor
  ties naming to function: `run` fires, `reload` hand-loads the rounds.
- Default mirror is tc clsact/mirred. An OVS helper is also provided.
- Base image is Debian 12. Ship a static musl binary.
- Replay rate defaults to original capture timing. Multiplier, pps, mbps, and
  topspeed are also selectable.
- Inter-run gap distributions: exponential/Poisson and truncated normal only.
- Red laser per-run randomisation of the replayed chatter is L3 only and
  topology preserving, via the in-process coherent remapper (tcprewrite is kept
  only as an optional fallback). On top of that, red laser synthesizes
  device-identity and switch-beacon assertions and occasionally promotes a host
  to an external threat actor; those paths build or rewrite whole frames,
  including MACs, and are fired as separate bursts, never edits to the replayed
  capture's payloads.
- Observability: structured logs to stderr (journald ingests them) plus a JSON
  heartbeat at /run/ot-turbolaser/status.json.
- License is MIT.
- v0.2 red/green laser: `variety`/`baseline` are renamed to `red_laser`/
  `green_laser` (old names still parse as aliases). Green laser is read-only and
  derives zones from real captures; red laser owns the content layer.
- New content is synthesized whole in Rust as genuine protocol assertions
  (query plus response, or an SNMP fetch), never lone packets, so a CVE match
  rests on a coherent transaction. CVE identities come from a curated,
  advisory-sourced profile database. The OUI and profile databases are embedded
  with on-disk overrides.
- A persistent session ledger at /var/lib/ot-turbolaser enforces the hard caps
  and preserves unique IP assignment across restarts. `reset` clears it.
- External threats are genuine-host promotion (IP and MAC rewrite of a real
  host), sparse and rate-limited. Never synthesize real exploit payloads.

## Hard invariants

- Never bridge to a production or uplinked network. net-setup must refuse to
  attach the bridge to a physical NIC and warn loudly.
- The replayed-capture path stays fixed-width: the reload mutators change no
  field's byte length, so upper-layer lengths never move, and only the DNP3 CRC
  and the L3/L4 checksums change. Red laser does not edit a replayed capture's
  payloads in the hot path: device identities and switch beacons are synthesized
  whole (the lengths are ours to set) and fired as a separate burst, and threat
  promotion only rewrites a selected host's L3 and MAC and recomputes checksums.
- Hard caps (16 subnet zones, 2000 devices) live in ledger constants; config may
  lower but never raise them. Fabrication packs at most 10 of the zones as L1/L2
  control zones, leaving headroom for L3 (DCS) operations zones. External-threat
  promotion is sparse, at most one per 24h (a floor enforced regardless of config).
- Synthesized and promoted traffic is data-plane payload on the isolated bridge
  only. External source addresses are bytes, not routes; keep the bridge
  isolated (net-setup refuses a physical NIC).
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
