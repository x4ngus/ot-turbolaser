# ot-turbolaser

A headless ICS/OT PCAP replay appliance. It continuously replays industrial
protocol captures with randomised but genuine-looking network identifiers and
timing, emitting frames onto an isolated virtual bridge. A host-side SPAN mirror
copies that traffic to a passive monitoring sensor, for example a Dragos Platform
sensor, so you can exercise protocol parsers and detections or build a traffic
baseline without touching a production network.

The name is the metaphor for how it works. The daemon is the turbolaser: `run`
fires packets at the sensor. `reload` hand-loads the rounds, the variant pcaps,
ahead of time. In firearms terms reload fits twice, since it means both loading
the weapon and manufacturing your own ammunition.

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
- Randomisation is tiered. The cheap per-run tier rewrites L3 addresses with a
  topology-preserving remap: fresh random subnets each run, but the same hosts
  keep talking to the same hosts, so the sensor sees genuine looking
  conversations. The expensive tier, payload-layer asset identity (Modbus unit
  id, EtherNet/IP and CIP identity, S7comm module and SZL identity, DNP3 link
  addresses), is pre-baked offline by `reload` into variant pcaps and never
  mutated in the hot path.
- Two modes. `variety` randomises aggressively every run to exercise parsers and
  detections. `baseline` fixes the seed and the asset set and varies only timing
  and the inter-run gap.

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
