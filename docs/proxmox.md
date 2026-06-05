# ot-turbolaser on Proxmox VE

Put a believable OT network on the wire for a passive sensor to watch, on an
isolated segment with no route to anything real. This guide has a quick
copy-and-paste path first, then a full reference (Dell R740 layout, a Dragos
sensor VM, the host SPAN mirror, OVS, and troubleshooting).

You design the fake plant once, lock it in with `plan --commit`, then fire. The
sensor sees the same planned network every run, with the addresses, zones, and
CVE-bearing devices you chose. No surprises, no drift.

Substitute your own IDs. This guide uses container `910`, sensor VM `200`, and
isolated bridge `vmbr9`.

## What you are building

```
  turbolaser CT 910  --fire-->  vmbr9 (isolated, no uplink)
                                  |
                                  +-- host mirror -->  sensor VM 200
```

Two rules keep it safe:

- The lab bridge `vmbr9` has no physical port, so replayed traffic can never
  leave the host.
- The traffic uses fake (remapped) addresses and MACs, never real ones. A
  capture that cannot be safely remapped is skipped, never sent raw.

---

# Quick start

## 1. Build the firing lane (isolated bridge)

On the Proxmox host, add `vmbr9` to `/etc/network/interfaces`:

```
auto vmbr9
iface vmbr9 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
#ot-turbolaser isolated lab segment, no uplink
```

Apply it without a reboot (PVE 8 uses ifupdown2):

```
ifreload -a
ip -br link show vmbr9
```

## 2. Create the emitter (container)

The daemon sends raw frames, so it needs a privileged container. It gets two
ports: `eth0` for internet during setup, `eth1` as the replay port on the
isolated bridge.

```
pveam update
pveam download local debian-12-standard_12.7-1_amd64.tar.zst

pct create 910 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname turbolaser \
  --cores 2 --memory 2048 --swap 512 \
  --rootfs local-lvm:8 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr9,ip=manual \
  --unprivileged 0 \
  --onboot 1

pct start 910
```

Use whatever current `debian-12-standard` version `pveam available` lists. You
can lower the memory to 512 MB after the build; the daemon idles light. `eth1`
has no IP; the replay segment is layer 2 only.

## 3. Charge it (build and install)

```
pct enter 910

apt-get update && apt-get install -y --no-install-recommends git
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
./scripts/bootstrap.sh --build --tests
. "$HOME/.cargo/env"

cargo install just            # the recipe runner used below (just deploy, etc.)
cargo build --release
./scripts/install.sh
```

`bootstrap.sh --build` installs the tcpreplay suite, iproute2, and the Rust
toolchain; `--tests` adds tshark for `reload --validate`. A minimal Debian
container has no `just`, and `apt` only ships it on Debian 13+, so install it
from the toolchain you just set up with `cargo install just` (it lands in
`~/.cargo/bin`, already on PATH). The recipes are optional sugar; every one maps
to a plain command, so you can skip `just` entirely and run those directly.
`install.sh` puts the binary at `/opt/replay/bin/turbolaser` (the path the
systemd unit runs), links it onto PATH, installs the systemd unit, and creates
the pcap folders.

To upgrade later, pull and run `cargo build --release && ./scripts/install.sh`
(or `just deploy`; both run as root in the container, so no `sudo` is needed, and
a minimal LXC may not even have it). The installer writes the new binary to that same
`/opt/replay/bin/turbolaser` path and, if the service is already running,
restarts it onto the new binary. Do not copy the binary to `/usr/local/bin` by
hand: that path is a symlink to the service binary, and overwriting it leaves the
running daemon on the old code.

## 4. Set the targeting solution (configure)

Edit `/opt/replay/conf/replay.yaml`. You only need three lines:

```
iface: eth1                  # the replay port on vmbr9
mode: red_laser              # the adversarial content layer

session:
  seed: 1337                 # pin any number; this makes the plant repeatable
```

That `seed` is the important one: it is the single setting that makes your fake
plant come out the same every time. The other red-laser options have safe
defaults (see the comments in the shipped config). Two worth knowing:

- `synthesis.max_assets` (default 512) bounds the total assets on the wire
  (fabricated devices plus the replayed capture hosts that fill spare zone
  capacity); surplus hosts ride existing assets, so the sensor's asset count
  stays bounded and equal to the plan.
- `l3.remap_mac` (default true) rewrites each host's MAC alongside its IP, so
  every asset has one coherent MAC and IP the sensor fuses into a single entry.

The mirror is set up on the host, not the container, so tell the unit to skip
its own network setup:

```
systemctl edit ot-turbolaser
```

Add these lines, save, and exit:

```
[Service]
ExecStartPre=
ExecStopPost=
```

Check the config is valid:

```
turbolaser check --config /opt/replay/conf/replay.yaml
```

## 5. Load the magazine (captures)

Put OT captures in the pool. From the host:

```
pct push 910 /path/to/modbus.pcap /opt/replay/pcaps/pool/modbus.pcap
```

Drop in as many as you like; the turbolaser picks from them at random. Optionally
forge payload-identity variants ahead of time (see the reference below).

## 6. Commit the firing solution (the key step)

Fabricate the plant once and lock it into a sealed plan. The daemon then replays
exactly that plant, every run.

```
turbolaser reset --config /opt/replay/conf/replay.yaml
turbolaser plan  --config /opt/replay/conf/replay.yaml --commit
turbolaser zones --config /opt/replay/conf/replay.yaml
```

`plan --commit` builds the zones and devices from your `seed` and writes them to
a sealed file the daemon follows. `zones` prints the control-system zones, their
vendors, and the device counts: this is exactly what your sensor will inventory.
To change the plant, edit the `seed` (or the device count), then `reset` and
`plan --commit` again; add `--force` to overwrite in one go.

Tip: copy these zone subnets into your sensor's zone or asset rules now, so the
sensor groups the assets the way you planned.

## 7. Aim downrange (host mirror)

The sensor is a separate VM, so the mirror is set on the host. Give the sensor a
monitor port on the lab bridge first:

```
qm set 200 --net1 virtio,bridge=vmbr9
```

Find the exact port names with both guests running:

```
ip -br link | grep -E 'veth910|tap200'
```

Set up the mirror (idempotent, safe to re-run):

```
REPLAY=veth910i1
SENSOR=tap200i1

ip link set "$SENSOR" up
ip link set "$SENSOR" promisc on
tc qdisc show dev "$REPLAY" | grep -q clsact || tc qdisc add dev "$REPLAY" clsact
tc filter del dev "$REPLAY" ingress 2>/dev/null || true
tc filter add dev "$REPLAY" ingress matchall \
    action mirred egress mirror dev "$SENSOR"
```

The ingress direction matters: a veth delivers the peer's transmit as ingress on
the other end, so the container's replayed frames arrive on `veth910i1` ingress.
Inside the sensor VM, set that new port as a monitoring interface in promiscuous
mode (the exact step is sensor-specific).

## 8. Open fire and confirm hits

```
turbolaser fire          # alias for `turbolaser up`; `halt` (or `down`) stands down
turbolaser pewpew
journalctl -u ot-turbolaser -f
```

Confirm the rounds are landing:

```
# on the host: this counter climbs while a capture replays
tc -s filter show dev veth910i1 ingress

# inside the sensor VM: OT traffic on fake internal addresses
tshark -i net1 -c 20
```

Within a short while the sensor should inventory the same zones and devices you
saw in step 6, including the CVE-bearing devices.

---

# Full reference

## How the pieces fit (Dell R740 with an existing production SPAN)

```
  Dell R740 / Proxmox VE 8
  +----------------------------------------------------------------------+
  |  ot-turbolaser CT 910               Dragos sensor VM 200             |
  |  +--------------------+             +------------------------------+  |
  |  | turbolaser run     |             | net0  mgmt   -> vmbr0        |  |
  |  |  eth0 mgmt -> vmbr0 |             | net2  prod SPAN -> vmbr3 -- NIC3 -- physical SPAN (separate)
  |  |  eth1 replay-> vmbr9|             | net1  lab monitor -> vmbr9  |  |
  |  +---------+----------+             +--------------+---------------+  |
  |            | host veth910i1                       | host tap200i1    |
  |        vmbr9 (isolated, no physical port)         |                  |
  |            +-------- host tc-mirred mirror -------+                  |
  +----------------------------------------------------------------------+
```

A port mirror is mandatory: tcpreplay re-emits each capture's MAC addresses and
the replay contains both endpoints, so a plain bridge learns both MACs on the
replay port and never forwards their unicast to the sensor. The NIC3 production
SPAN keeps its own bridge (`vmbr3`) and a separate sensor NIC; never bridge the
two. Because the sensor is a VM in a different namespace from the CT, the mirror
is configured on the host, not inside the CT.

## Container sizing and capabilities

`--memory 2048` is for the build (the release profile uses link-time
optimization, which is memory hungry). Lower the container to 256-512 MB after
the binary is built. The daemon needs `CAP_NET_RAW` and `CAP_NET_ADMIN` for raw
transmit and for `ip`/`tc`; the simplest way to keep those in LXC is a privileged
container (`--unprivileged 0`).

## Low-memory build alternative

Build a static musl binary on another machine and copy it in:

```
# on a build host with Rust
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
pct push 910 target/x86_64-unknown-linux-musl/release/turbolaser /opt/replay/bin/turbolaser
```

## Forge variants (optional, offline)

Pre-bake payload-identity variants from a source capture so the feed carries
varied but coherent device identities (EtherNet/IP identities map onto real,
CVE-bearing profiles; addresses and MACs are remapped):

```
turbolaser reload \
  --in /opt/replay/pcaps/pool/modbus.pcap \
  --out-dir /opt/replay/pcaps/variants \
  --count 16 --remap-l3 --validate
```

Each round is written with a `.toml` manifest and an `index.json` roster.
`--validate` runs tshark as the dissector oracle.

## Persistent host mirror (survives reboots and guest restarts)

Save the step-7 `tc` block as `/usr/local/sbin/ot-mirror.sh` (with
`#!/usr/bin/env bash` and `set -euo pipefail`), make it executable, then install
a host unit that runs after the guests come up:

```
cat >/etc/systemd/system/ot-turbolaser-mirror.service <<'EOF'
[Unit]
Description=ot-turbolaser host SPAN mirror
After=pve-guests.service
Wants=pve-guests.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ot-mirror.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ot-turbolaser-mirror.service
```

The repo's `scripts/net-setup.sh` does the same and adds both directions:

```
./net-setup.sh --mode tc --bridge vmbr9 --replay-port veth910i1 --sensor-port tap200i1
```

## Open vSwitch alternative

If `vmbr9` is an OVS bridge, add both guest ports to it and create an OVS mirror
instead of the `tc` filter:

```
ovs-vsctl -- --id=@p get Port veth910i1 \
          -- --id=@s get Port tap200i1 \
          -- --id=@m create Mirror name=tl-span \
                select-src-port=@p select-dst-port=@p output-port=@s \
          -- set Bridge vmbr9 mirrors=@m
```

## Verify on the Dragos sensor

- On the host, confirm the mirror carries frames; the counter climbs while a
  capture replays:

  ```
  tc -s filter show dev veth910i1 ingress
  ```

- In the sensor VM, confirm it receives unicast OT traffic, not just broadcast
  and multicast:

  ```
  tshark -i net1 -c 20
  ```

  You should see Modbus, DNP3, S7comm, or EtherNet/IP, with source and
  destination addresses in the fabricated internal subnets. Every source MAC and
  IP must belong to a planned zone: no original capture addresses, no foreign
  vendor MACs, and no broadcast-domain chatter from the source network. The
  appliance drops any frame it cannot make fully plan-coherent before replay.

- In the CT, `turbolaser pewpew` shows the live readout. Check that:
  - `drift` is `none` (the wire matches the sealed plan),
  - `last packets` is non-null and `packets/sec` is live during a replay,
  - the assets line stays at or under the plan cap (fabricated + capture-derived).

  The default rate is a fixed Mbps band (`rate.model: mbps`, `mbps_min`/
  `mbps_max` in `conf/replay.yaml`): each run replays at one fixed rate sampled
  in the band, so the sensor sees a sustained ~10 Mbps that fluctuates run to
  run rather than the captures' own (sparse) timing. Widen the band or raise the
  gap for a burstier profile; on a jumbo bridge raise `l3.max_frame_bytes`.

- In Dragos, confirm the assets categorise by vendor (no MAC-only or IP-only
  fragments), every asset carries a matching MAC and IP, the asset count matches
  the plan, and CVEs attribute to the fabricated devices. The zones should match
  the subnets `turbolaser zones` printed, with nothing in an RFC1918 or External
  catch-all.

## Safety and troubleshooting

- **Isolation.** `vmbr9` must keep `bridge-ports none`. Never add a physical NIC
  to it, and never bridge it to a production network. Keep the NIC3 production
  SPAN on its own bridge.
- **The sensor sees nothing.** Check the mirror counter. If it is zero, you
  likely mirrored the wrong port; re-check names with `ip -br link` after both
  guests are up (they change with CTID and VMID), and confirm the ingress
  direction on the container veth.
- **The plant looks different from the plan.** Make sure `session.seed` is set
  and that you ran `plan --commit` (not just `plan`). Re-run `turbolaser zones`
  to confirm what is committed, and `turbolaser pewpew` to check `drift`.
- **A capture is skipped in the logs.** By design, the turbolaser skips any
  capture it cannot safely rewrite (oversize, or one that would leak a real
  address) rather than putting real addresses on the wire. Drop in another
  capture, or shrink the oversized one.
- **Throughput is low or a run sends zero packets.** `journalctl -u
  ot-turbolaser | grep done:` may show `Unable to process unsupported DLT type`
  or `Message too long (errno = 90)` on older builds: the first is a source pcap
  with a non-canonical link-type header, the second an oversized (TSO/jumbo)
  frame, and either makes tcpreplay abort that run. The appliance now normalizes
  every replayed pcap to canonical Ethernet and drops frames over
  `l3.max_frame_bytes`, so both are handled. If the sensor still sees a low rate,
  confirm `rate.model: mbps` with a `mbps_min`/`mbps_max` band (not `original`,
  which paces to the captures' own slow timing) and that the `gap` is short.
- **Service fails with `226/NAMESPACE`.** The shipped unit is LXC-safe. On an
  older unit, add a drop-in disabling the filesystem hardening
  (`ProtectSystem=no`, `ProtectHome=no`, `ProtectKernelTunables=no`,
  `ProtectKernelModules=no`, `ProtectControlGroups=no`, `ReadWritePaths=`), then
  `systemctl daemon-reload && systemctl reset-failed ot-turbolaser && systemctl
  restart ot-turbolaser`.
- **Raw socket denied.** Use a privileged container (`--unprivileged 0`). If a
  restrictive AppArmor profile blocks raw networking, as a last resort set
  `lxc.apparmor.profile: unconfined` in `/etc/pve/lxc/910.conf` and weigh the
  trade-off.
- **Build killed for memory.** Raise container memory or swap, or build a static
  musl binary elsewhere and `pct push` it in.
- **Duplicate broadcast frames.** With both guest ports on `vmbr9`, the bridge
  may flood broadcast/multicast to the sensor on top of the mirror. Enable port
  isolation on both ports: `bridge link set dev veth910i1 isolated on` and the
  same for `tap200i1`.
- **AF_PACKET and tc.** The mirror relies on the container's raw transmit
  traversing the host veth so the ingress hook can copy it (the default). If a
  future tcpreplay sets `PACKET_QDISC_BYPASS`, switch to the OVS mirror, which
  copies in the datapath regardless.
