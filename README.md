<p align="center">
  <img src="docs/hero.png" alt="ot-turbolaser firing OT protocol traffic at a passive monitoring sensor" width="100%">
</p>

# ot-turbolaser

A headless ICS/OT PCAP replay appliance. It continuously replays industrial
protocol captures with randomised but genuine-looking network identifiers and
timing, emitting frames onto an isolated virtual bridge. A host-side SPAN mirror
copies that traffic to a passive monitoring sensor, so you can exercise protocol 
parsers and detections or build a baseline without touching a production network.

## Safety

This appliance must never bridge to a production or uplinked network. It is built
to feed a passive sensor on an isolated segment with no route off the box. The
network setup script refuses to attach the bridge to a physical NIC and warns
loudly. Read the warning. Do not override it on a live network.

## How it works

- One replay NIC sits on an isolated Linux bridge with no uplink.
- tcpreplay re-emits each capture's original MAC addresses, so a plain bridge
  will not forward that unicast traffic to the sensor. A port mirror is therefore
  mandatory, not optional. The host mirrors the replay port to the sensor's
  monitor port, which runs promiscuous. Both a tc clsact/mirred helper and an
  Open vSwitch helper are provided. tc-mirred is the default.
- Topology-preserving remap: fresh random subnets each run, but the same hosts
  keep talking to the same hosts, so the sensor sees genuine looking
  conversations. The expensive tier, payload-layer asset identity (Modbus unit
  id, EtherNet/IP and CIP identity, S7comm module and SZL identity, DNP3 link
  addresses), is pre-baked offline by `reload` into variant pcaps and never
  mutated in the hot path.
- Two modes. `variety` randomises aggressively every run to exercise parsers and
  detections. `baseline` fixes the seed and the asset set, so the addresses stay
  put, and changes only the replay timing and how long it pauses between runs.

## Quickstart

The appliance is a single static Rust binary. There is no Python or scapy at
runtime.

```
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
just bootstrap        # build, install the binary, the unit, and a default config
# drop captures into the pool, then forge a magazine of rounds:
just reload n=16
just up               # set up the isolated bridge and mirror, start the service
just status
```

Without `just`, the same steps are `scripts/bootstrap.sh`,
`turbolaser reload --in <pcap> --out-dir <variants> --count 16`,
`turbolaser up`, and `turbolaser status`.

## Sourcing captures

Captures are not shipped with this repo and are gitignored. Good public sources
of ICS/OT traffic include the 4SICS Geek Lounge lab pcaps, the automayt/ICS-pcap
collection, and the iTrust SWaT and WADI datasets. Drop captures into the pool
directory configured in `conf/replay.yaml`, then use `reload` to produce
payload-identity variants in the variants directory.

## Configuration

See `conf/replay.yaml` for an annotated sample: interface, mode, rate model, gap
distribution, per-file weights, seed handling, and paths. Validate a config
without replaying with `turbolaser check --config <path>`.

## Deployment topology

The appliance needs two interfaces on an isolated segment:

- the replay port (`iface` in the config, default `tl0`), where tcpreplay
  transmits and which the mirror copies from, and
- the sensor monitor port (`net.sensor_port`, default `sens0`), set promiscuous,
  which receives the mirrored copy and feeds the sensor.

`net-setup.sh` builds an isolated bridge with no uplink, enslaves the replay
port, and mirrors its egress to the sensor port (tc clsact/mirred by default, or
Open vSwitch). It refuses to put a physical NIC on the bridge, so the isolated
segment can never reach a production or uplinked network.

Two common layouts:

1. Self-contained container or VM with two virtual interfaces (veth or tap) for
   the replay and sensor ports, with the sensor cabled or bridged to the
   appliance's sensor port. net-setup runs inside the appliance.
2. Host-side mirror, where the replay port is the container's veth and the
   sensor port is a dedicated NIC cabled to the sensor. net-setup runs on the
   host against those ports.

## Running in a Proxmox LXC

Use a privileged container (the daemon needs `CAP_NET_RAW` and `CAP_NET_ADMIN`
for raw transmit and for `ip`/`tc`). Give the container two NICs on an isolated
Linux bridge that has no uplink, mapped to the replay and sensor ports. A minimal
Debian 12 container idles well under 256 MB.

```
# on the appliance (container), as root:
scripts/bootstrap.sh                 # tcpreplay + iproute2 (add --ovs for OVS)
cargo build --release                # or copy in a prebuilt static binary
sudo scripts/install.sh              # lays out /opt/replay, installs the unit
# edit /opt/replay/conf/replay.yaml: iface, net.sensor_port, mode
turbolaser reload --in /opt/replay/pcaps/pool/<cap>.pcap \
    --out-dir /opt/replay/pcaps/variants --count 16
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
  per-run seed, the pause between runs, and state.
- In variety mode, confirm replayed IPs occupy fresh random subnets each run
  while conversations stay intact and MACs are unchanged. In baseline mode, IPs
  are stable across runs and only timing varies.

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
