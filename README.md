<p align="center">
  <img src="docs/hero.png" alt="ot-turbolaser firing OT protocol traffic at a passive monitoring sensor" width="100%">
</p>

# ot-turbolaser

A headless ICS/OT pcap replay appliance. It puts a believable industrial network
on the wire, downrange to a passive monitoring sensor, on an isolated segment with
no route to anything real. Use it to exercise protocol parsers and detections, or
to build a baseline, without ever touching a production network.

It replays OT captures continuously with fresh but genuine-looking addresses and
timing. In red laser mode it also overlays a designed plant of zones and
CVE-bearing devices for the sensor to inventory.

## Safety

This appliance must never bridge to a production or uplinked network. It is built
to feed a passive sensor on an isolated segment with no route off the box. The
network setup script refuses to attach the bridge to a physical NIC, and warns
loudly. Read the warning. Do not override it on a live network.

## How it works

- The replay port sits on an isolated Linux bridge with no uplink.
- tcpreplay sends each capture's original MAC addresses, and a plain bridge will
  not forward that traffic to the sensor. So a port mirror is mandatory: the host
  copies the replay port to the sensor's monitor port, which runs in promiscuous
  mode. A tc (clsact/mirred) helper and an Open vSwitch helper are both provided;
  tc is the default.
- The replayed addresses are rewritten to a fresh internal network, but the
  conversations are preserved: the same hosts keep talking to the same hosts, so
  the sensor sees genuine-looking traffic. The mapping is stable for a session, so
  a capture replays to the same addresses every run.
- Payload-level device identity (Modbus unit id, EtherNet/IP and CIP identity,
  S7comm SZL, DNP3 link addresses) is pre-baked offline by `reload` into variant
  pcaps, never mutated in the hot path.

## Red laser and green laser

Two modes:

- **red_laser** is the adversarial mode. On top of the replayed chatter it
  fabricates a believable ICS plant and feeds it to the sensor.
- **green_laser** is the accurate mode. It replays a fixed, reproducible baseline
  and derives zones read-only from the capture's real addresses and MAC OUIs, with
  no fabrication.

The former names `variety` and `baseline` still parse as aliases.

In red laser the fabricated plant includes:

- Named zones grouped by subnet, following the Purdue/IEC-62443 model and the
  dominant vendor OUI (for example "Siemens SIMATIC Basic Control Area 1"), with
  managed switches as the conduits between zones.
- Devices carrying real, advisory-sourced vendor/model/firmware identities that
  trigger CVE matches, delivered as genuine protocol assertions (EtherNet/IP List
  Identity, Modbus 0x2B/0x0E, S7comm SZL, and LLDP/CDP/SNMP for switches) plus a
  gratuitous ARP, so each device fingerprints as a single asset and each detection
  rests on a coherent transaction.
- Replayed capture traffic mapped into the matching vendor zone, so the
  control-system subnets hold real device relationships, not just the synthetic
  identities.
- Rare external-threat injections: a real host is occasionally re-originated from
  an external address with a desktop MAC, at most once a day.

A persistent session ledger holds the plant, bounds it to at most 10 zones and
2000 devices, keeps IP assignments unique, and survives restarts. It is the ground
truth you can diff against the sensor.

### Plan it, then fire

Design the plant once and lock it in, so the sensor sees the same network every
run:

- `turbolaser plan` previews the fabricated zones, devices, and CVE assignments
  without sending traffic.
- `turbolaser plan --commit` fabricates the plant from your `session.seed` and
  writes it to a sealed ledger. The daemon then replays that sealed plant
  verbatim, with no drift between what you planned and what the sensor sees.
- `turbolaser zones` shows the current map (green derives it from the captures;
  red reads the ledger).
- `turbolaser reset` clears the ledger for a fresh plant.
- `turbolaser status` reports the zone list, the device count against the cap, and
  the last threat injection.

Pin `session.seed` in the config so plan and run agree. The plant, CVE profiles,
external ranges, and zone affinity are all configurable; see the comments in
`conf/replay.yaml`. The bundled OUI and vulnerable-profile databases can be
overridden on disk.

## Quickstart

The appliance is a single static Rust binary; `bootstrap` installs the tcpreplay
and iproute2 tools it drives.

```
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
just bootstrap        # build, install the binary, the unit, and a default config
# drop captures into the pool, then forge a magazine of rounds:
just reload n=16
```

For red laser, pin `session.seed` in `conf/replay.yaml`, then commit the plant so
the sensor sees the same network every run:

```
turbolaser plan --config conf/replay.yaml --commit
```

Then bring it online:

```
just up               # set up the isolated bridge and mirror, start the service
just status
```

Without `just`, the steps are `scripts/bootstrap.sh`,
`turbolaser reload --in <pcap> --out-dir <variants> --count 16`,
`turbolaser plan --commit`, `turbolaser up`, and `turbolaser status`.

For a Proxmox deployment, start with the
[Proxmox quick start](docs/proxmox-quickstart.md).

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

Two common layouts:

1. Self-contained container or VM with two virtual interfaces (veth or tap) for
   the replay and sensor ports, with the sensor cabled or bridged to the
   appliance's sensor port. net-setup runs inside the appliance.
2. Host-side mirror, where the replay port is the container's veth and the sensor
   port is a dedicated NIC cabled to the sensor. net-setup runs on the host
   against those ports.

## Running in a Proxmox LXC

For the short copy-and-paste path, see the
[Proxmox quick start](docs/proxmox-quickstart.md). For the complete end-to-end
walkthrough on a Dell R740, including CT template selection, host and guest
network settings, and the host-side SPAN mirror, see
[docs/proxmox-getting-started.md](docs/proxmox-getting-started.md).

Use a privileged container (the daemon needs `CAP_NET_RAW` and `CAP_NET_ADMIN` for
raw transmit and for `ip`/`tc`). Give the container two NICs on an isolated Linux
bridge that has no uplink, mapped to the replay and sensor ports. A minimal Debian
12 container idles well under 256 MB.

```
# on the appliance (container), as root:
scripts/bootstrap.sh                 # tcpreplay + iproute2 (add --ovs for OVS)
cargo build --release                # or copy in a prebuilt static binary
sudo scripts/install.sh              # lays out /opt/replay, installs the unit
# edit /opt/replay/conf/replay.yaml: iface, net.sensor_port, mode, session.seed
turbolaser reload --in /opt/replay/pcaps/pool/<cap>.pcap \
    --out-dir /opt/replay/pcaps/variants --count 16
turbolaser plan --config /opt/replay/conf/replay.yaml --commit   # red laser: seal the plant
turbolaser up
turbolaser status
```

## Verifying on the sensor

- After `turbolaser up`, confirm the topology print and that net-setup refuses a
  physical NIC if you point it at one.
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
