<p align="center">
  <img src="docs/hero.png" alt="ot-turbolaser firing OT protocol traffic at a passive monitoring sensor" width="100%">
</p>

# ot-turbolaser

A headless ICS/OT pcap replay appliance. It puts a believable industrial network
on the wire downrange to a passive monitoring sensor, all on an isolated segment
with no route to anything real. Use it to exercise protocol parsers and detections, 
or to practice building OT baselines, without ever touching a production network.

It replays OT pcaps continuously with fresh genuine-looking addresses and timing. 
In red laser mode it overlays a simulated plant: Complete with Purdue-levelled zones 
of controllers, HMIs, engineering stations, servers, and conduit firewalls, each
with a real vendor MAC, a resolvable hostname, and (for the controllers) real
CVEs.

## Safety

**This appliance must never bridge to a production or uplinked network**. 
Turbolaser is built to feed a passive sensor on an isolated segment with no route 
off the box. The network setup script refuses to attach the bridge to a physical NIC, 
and warns loudly. Read the warning. Do not override it on a live network.

## How it works

- The replay port sits on an isolated Linux bridge with no uplink. tcpreplay
  sends each capture's original MACs, so a port mirror copies the replay port to
  the sensor's (promiscuous) monitor port. A `tc` (clsact/mirred) helper and an
  Open vSwitch helper are provided.
- Replayed addresses are rewritten to a fresh internal network, but conversations
  are preserved (the same hosts keep talking), and the mapping is stable per
  session, so a capture replays to the same addresses every run.
- Device identity payloads (Modbus unit id, EtherNet/IP and CIP identity,
  S7comm SZL, DNP3 link addresses) are pre-baked offline for simulated control
  traffic and directional awareness.

## Red laser and green laser

Two modes are available:

- **red_laser**: adversarial. Fabricates a believable ICS plant for the sensor.
- **green_laser**: accurate. It replays a captured baseline and derives zones
  from the capture's real addresses and OUIs, with no fabrication.

The red-laser schematics:

- **Zones** grouped by subnet on the Purdue/IEC-62443 model, named by dominant
  vendor (e.g. "Siemens SIMATIC Basic Control Area 1"). Each control zone carries
  a bill of materials: controllers, a managed switch, an HMI, an engineering
  workstation, and a zone-edge firewall at `.1`. L3 operations (DCS) zones add
  historians, OPC/domain/application servers, and operator stations.
- **Full identity per asset (MAC ↔ IP ↔ DNS)** each device binds MAC & IP from 
  authoritative ARP `is-at` replies, carries a real vendor OUI, and resolves a
  recognisable hostname (`LINE-01-PLC`, `CELL-02-S7`) via a per-zone DNS resolver.
- **CVEs** inserted using controller firmware, advisory-sourced and delivered as
  complete OT protocol sessions (EtherNet/IP, Modbus, S7comm, SNMP).
- **Replayed capture traffic** is mapped into the matching vendor zone, so the
  subnets hold real device relationships, not just made up identities. The
  mapping drops any frame whose payload still embeds an original address, so a
  real host never surfaces on the sensor.
- **Rare external-threat injections**: a real host is promoted to an external
  address, at most once a day. This is part of a suite of threat hunt scenarios
  being continuously built into the application.

### Target scenarios

A **target scenario** aims red laser at one documented real-world attack. Loading
one pins that attack's plant (its actual controllers, firmware, and CVEs) and
fires the documented attack downrange as a phased, ATT&CK-for-ICS timeline, so the
sensor watches the incident unfold. Four scenarios ship:

- `stuxnet`: Siemens S7 centrifuge sabotage (S7 program download, rogue drive frequency, PLC stop).
- `triton`: Schneider Triconex SIS attack over TriStation.
- `oldsmar`: water-treatment setpoint excursion (a Modbus dose change from 100 to 11,100 ppm).
- `ukraine2015`: BlackEnergy / IEC-104 grid attack (breaker-open commands, then KillDisk).

Scenarios are drop-in data packs under `targets/`; adding one is data, not code.

```
turbolaser targets                       # list installed scenarios
turbolaser plan --scenario stuxnet       # preview the pinned plant (no traffic)
turbolaser run  --scenario stuxnet       # fire the attack timeline downrange
```

No `--scenario` is the generic red laser above. Scenario traffic carries real
published indicators, so it stays on the isolated bridge. See
[docs/targets.md](docs/targets.md) for containment and authoring a pack.

### Plan it, then fire

Design the simulation and lock it in, so the sensor sees the same networks every
run:

- `turbolaser reset` clears the ledger for a fresh plant layout.
- `turbolaser plan` previews the fabricated zones, devices, and CVE assignments.
- `turbolaser plan --commit` fabricates the zones from your plan and writes it
  to a ledger. Turbolaser then simulated those plant networks faithfully.
- `turbolaser zones` shows the current map (green derives it from the captures;
  red reads the ledger).
- `turbolaser pewpew` reports the wire footprint against the plan, the zone list,
  throughput, and the last threat injection (`status` is a deprecated alias).

The plant, CVE profiles, external ranges, and zone affinity are all configurable; 
see the comments in `conf/replay.yaml`. The bundled OUI and vulnerable-profile 
databases can be overridden on disk to suit your testing scenario.

## Quickstart

The appliance is a single static Rust binary. `bootstrap` installs the tcpreplay
and iproute2 tools it drives.

```
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
just bootstrap        # build, install the binary, the unit, and a default config
# drop captures into the pool, then forge a magazine of rounds:
just reload n=16
```

For red laser operations review/approve `conf/replay.yaml`, then commit the plan:

```
turbolaser plan --config conf/replay.yaml --commit
```

Then bring it online:

```
just fire             # set up the isolated bridge and mirror, start the service
just pewpew
```

Without `just`, the steps are `scripts/bootstrap.sh`,
`turbolaser reload --in <pcap> --out-dir <variants> --count 16`,
`turbolaser plan --commit`, `turbolaser fire`, and `turbolaser pewpew`.

To roll out a new version later, run `just deploy` (or
`cargo build --release && sudo scripts/install.sh`). It builds, installs the
binary to the service's own path, and restarts a running service onto the new
binary in one step, so an upgrade never depends on remembering to reinstall to
the right path or restart by hand.

For a Proxmox deployment, see the [Proxmox guide](docs/proxmox.md).

## Commands

Every subcommand takes `--config <path>` (default `/opt/replay/conf/replay.yaml`).
`fire`/`halt` are the operator commands; `up`/`down` remain as aliases. The
red-laser commands (`run`, `plan`, `check`, `zones`, `reset`) also take
`--scenario <name>` to load a target scenario; see
[docs/targets.md](docs/targets.md).

| Command | What it does |
| --- | --- |
| `turbolaser fire` (alias `up`) | Bring the appliance online: enable and start the service, which sets up the isolated bridge and the port mirror. |
| `turbolaser halt` (alias `down`) | Take the appliance offline: stop and disable the service, which tears down the mirror. |
| `turbolaser plan` | Preview the fabricated zones, devices, and CVE assignments without sending traffic (red laser). `--devices N` overrides the fleet size, `--json` emits raw. |
| `turbolaser plan --commit` | Fabricate the plant from `session.seed` and seal it as the ledger the daemon replays verbatim. `--write` is an alias, `--force` overwrites an existing ledger, `--dry-run` previews only. |
| `turbolaser pewpew` (alias `status`) | Live fire-control readout: wire footprint vs plan, the zone list, throughput (pps and Mbps), and the last threat injection. `--json` emits raw. |
| `turbolaser zones` | Show the current zone map: red reads the sealed ledger, green derives it from the captures. `--json` emits raw. |
| `turbolaser targets` | List the installed target scenarios (the red-laser attack packs). `--json` emits raw. |
| `turbolaser verify` | Post-deploy check. Profiles the synth burst against the reference OT ARP bands (no scan, runts, or LAA; every planned asset emits an `is-at`); `--csv <export>` scores a passive-sensor asset export for MAC<->IP union-rate and hostname coverage vs the plan, listing stragglers. `--pcap <file>` profiles a capture; `--json` emits raw. |
| `turbolaser reload --in <pcap> --out-dir <dir>` | Forge variant pcaps (the rounds) with payload-identity mutations. `--count N` rounds, `--proto`, `--seed-base`, `--remap-l3`, `--validate` (tshark-check each round). |
| `turbolaser reset` | Clear the red-laser session ledger for a fresh plant. |
| `turbolaser check` | Validate a config file without replaying. |
| `turbolaser run` | The replay daemon loop itself. The systemd unit runs this; operators use `fire`/`halt`. `--once` does a single iteration (for testing). |
| `turbolaser net-provision` | Create the isolated replay+sensor veth pair (named from `iface`/`net.sensor_port`) on a self-contained host, so net-setup and `fire` find the ports they need. Refuses a physical NIC. One-time, before the first `fire`. Not used on Proxmox (the hypervisor provides the ports). |
| `turbolaser net-setup` / `net-teardown` | Low-level bridge and mirror setup/teardown from config. The unit calls these, and `fire`/`halt` wrap them. |
| `turbolaser net-show` | Datapath triage: confirms frames egress the replay port and reach the sensor port through the SPAN mirror (live tx/rx probe), beyond `pewpew`'s daemon counters. First stop for "the sensor sees nothing". `--probe-secs N`, `--json`. |

## Sourcing captures

Captures are not shipped with this repo and are gitignored. Good public sources of
ICS/OT traffic include the 4SICS Geek Lounge lab pcaps, the automayt/ICS-pcap
collection, and the iTrust SWaT and WADI datasets. Drop captures into the pool
directory set in `conf/replay.yaml`, then use `reload` to produce
payload-identity variants in the variants directory.

## Configuration

See `conf/replay.yaml` for an annotated sample: interface, mode, rate model, gap
distribution, per-file weights, the session seed, the red-laser plant, and paths.
In red laser, `session.seed` is the one knob that makes the plant repeatable.
Validate a config without replaying with `turbolaser check --config <path>`.

## Deployment topology

The appliance needs two interfaces on an isolated segment:

- the replay port (`iface` in the config, default `tl0`), where tcpreplay
  transmits and which the mirror copies from, and
- the sensor monitor port (`net.sensor_port`, default `sens0`), set promiscuous,
  which receives the mirrored copy and feeds the sensor.

`net-setup.sh` builds an isolated bridge with no uplink, enslaves the replay port,
and mirrors its egress to the sensor port (tc clsact/mirred by default, or Open
vSwitch). It refuses to put a physical NIC on the bridge, so the isolated segment
can never reach a production or uplinked network.

Those two interfaces must exist before `fire`: net-setup does not create them, it
only bridges and mirrors them, and exits non-zero (so `fire` aborts) if either is
missing. How they come to exist depends on the layout:

1. Self-contained container or VM with two virtual interfaces for the replay and
   sensor ports. Create them once with the helper, which reads the names from the
   config so they always match the daemon and net-setup:

   ```
   turbolaser net-provision        # creates the isolated veth pair iface <-> net.sensor_port
   turbolaser fire                 # net-setup then bridges + mirrors them
   ```

   The helper refuses to touch a physical NIC (the replay port must be virtual).
   The raw equivalent, if you prefer to provision by hand (substitute your
   configured names; the pair names MUST match `iface` and `net.sensor_port`):

   ```
   ip link add tl0 type veth peer name sens0   # tl0 = iface, sens0 = net.sensor_port
   ip link set tl0 up
   ip link set sens0 up promisc on
   ```

   Undo with `turbolaser net-provision --undo` (or `ip link del tl0`).

   On a single host the pair already links the replay port to the sensor port, so
   the bridge and mirror `fire` adds are what give the replay port its isolated,
   no-uplink segment. If the sensor sees frames twice, enable port isolation as in
   the Proxmox guide's "Duplicate broadcast frames" note.

2. Host-side mirror, where the replay port is the container's veth and the sensor
   port is a dedicated NIC cabled to the sensor. The hypervisor (or the host)
   provides both ports and the mirror runs on the host, so net-provision and the
   unit's net-setup are not used inside the appliance. If your sensor port is a
   physical NIC, do not run net-provision (it only creates virtual interfaces and
   refuses a real one); provision only the replay port as a veth, as in layout 1.

## Running in a Proxmox LXC

For the full walkthrough, see [docs/proxmox.md](docs/proxmox.md).

## Verifying on the sensor

- With a capture replaying, run `tshark -i <sensor_port>` and confirm the sensor
  receives unicast frames, not just broadcast and multicast. Watch the mirror
  counters with `tc -s filter show dev <iface> egress`.
- Read `/run/ot-turbolaser/status.json` and `journalctl -u ot-turbolaser` for the
  state, the per-run timing, and the zone and device counts.
- In red laser, confirm the replayed hosts land in the fabricated control-system
  zones and stay put across runs (the mapping is stable for the session). In green
  laser, the baseline is fixed and only the timing varies.

## Build from source

Requires a recent stable Rust toolchain.

```
cargo build --release
```

For the appliance, build a static binary against musl on a Linux host:

```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## License

MIT. See `LICENSE`. Third-party crate licenses and the protocol references used
while implementing the mutators are listed in `LICENSES.md`.
