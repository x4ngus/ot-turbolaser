# Getting started on Proxmox VE (Dell R740)

A complete, end to end walkthrough: build an isolated lab segment on a Proxmox
host, run ot-turbolaser in an LXC container, and feed varied OT traffic to a
Dragos sensor VM. It covers the CT template, the host and guest network settings
for a Dell R740 whose sensor already receives production SPAN on NIC3, and
building the application for its first run.

Substitute your own IDs and interface names. This guide uses:

- Proxmox VE 8 (Debian 12 based) on a Dell R740
- `vmbr0`: management bridge with uplink (already present)
- `vmbr9`: a new isolated lab bridge, no uplink (we create it)
- NIC3 and `vmbr3`: the existing production SPAN path to the sensor (left alone)
- CT `910`: the ot-turbolaser appliance
- VM `200`: the Dragos sensor

## How the pieces fit

```
  Dell R740 / Proxmox VE 8
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                        │
  │  ot-turbolaser CT 910               Dragos sensor VM 200               │
  │  ┌────────────────────┐             ┌──────────────────────────────┐  │
  │  │ turbolaser run     │             │ net0  mgmt   -> vmbr0         │  │
  │  │  eth0 mgmt -> vmbr0 │             │ net2  prod SPAN -> vmbr3 ── NIC3 ── physical SPAN (separate)
  │  │  eth1 replay-> vmbr9│             │ net1  lab monitor -> vmbr9   │  │
  │  └─────────┬──────────┘             └──────────────┬───────────────┘  │
  │            │ host veth910i1                        │ host tap200i1     │
  │        vmbr9 (isolated, no physical port)          │                   │
  │            └──────── host tc-mirred mirror ────────┘                   │
  │              (CT transmit is ingress on veth910i1,                     │
  │               copied out tap200i1 into the sensor)                     │
  └──────────────────────────────────────────────────────────────────────┘
```

Two facts drive this layout:

- tcpreplay re-emits each capture's original MAC addresses, and the replay
  contains both endpoints, so a plain bridge learns both MACs on the replay port
  and then sends their unicast back to that same port, never to the sensor. A
  port mirror is therefore mandatory.
- The replay segment must never touch a physical uplink. `vmbr9` has no bridge
  port, so the lab traffic cannot leave the host. The NIC3 production SPAN keeps
  its own bridge and feeds a separate sensor NIC. We never bridge the two.

Because the sensor is a VM in a different network namespace from the CT, the
mirror is configured on the Proxmox host, not inside the CT. The CT just runs the
replay daemon.

## 1. Host: create the isolated lab bridge

Add `vmbr9` to `/etc/network/interfaces` on the Proxmox host. It has no bridge
port, so it carries no uplink.

```
auto vmbr9
iface vmbr9 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
#ot-turbolaser isolated lab segment, no uplink
```

Apply it without rebooting (PVE 8 uses ifupdown2):

```
ifreload -a
ip -br link show vmbr9
```

If you run Open vSwitch ("vSwitch") bridges instead, create an OVS bridge with no
port and see the OVS note in step 8.

## 2. Host: download the CT template

```
pveam update
pveam available --section system | grep debian-12
pveam download local debian-12-standard_12.7-1_amd64.tar.zst
```

Use whatever current `debian-12-standard` version `pveam available` lists. Debian
12 is the supported base. It keeps tcpreplay and the toolchain simple.

## 3. Host: create the ot-turbolaser CT

The daemon transmits raw frames and runs `tc`, so it needs `CAP_NET_RAW` and
`CAP_NET_ADMIN`. The simplest way to keep those in an LXC container is a
privileged container (`--unprivileged 0`).

The CT has two NICs: `eth0` on the management bridge for internet during setup,
and `eth1` on the isolated lab bridge as the replay port.

```
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

Notes:

- `--memory 2048` is for the build. The release profile uses link time
  optimization, which is memory hungry. You can lower the container to 256 to 512
  MB after the binary is built, since the daemon idles well under 256 MB. If the
  build is killed for memory, raise memory or swap, or build elsewhere (step 4).
- `eth1` has no IP. The replay segment is layer 2 only.

## 4. CT: get the repo and build

Enter the container and build. `bootstrap.sh --build` installs the tcpreplay
suite, iproute2, and the Rust toolchain. `--tests` adds tshark for
`reload --validate`.

```
pct enter 910

apt-get update && apt-get install -y --no-install-recommends git
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
./scripts/bootstrap.sh --build --tests
. "$HOME/.cargo/env"

cargo build --release
cargo test                 # optional, confirms the build is healthy
./scripts/install.sh       # lays out /opt/replay, installs the unit, links onto PATH
```

`install.sh` copies the binary to `/opt/replay/bin/turbolaser`, links it to
`/usr/local/bin`, installs the systemd unit, and creates the pcap directories.

Low-memory alternative: build a static binary on another machine and copy it in.

```
# on a build host with Rust
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# copy into the CT
pct push 910 target/x86_64-unknown-linux-musl/release/turbolaser /opt/replay/bin/turbolaser
```

## 5. CT: configure the daemon

Edit `/opt/replay/conf/replay.yaml`. The only required change is the replay
interface.

```
iface: eth1            # the lab NIC on vmbr9
mode: variety          # or baseline
```

The mirror is set up on the host (step 8), not by the container, so tell the
unit to skip its built in network setup. Add a drop in override:

```
systemctl edit ot-turbolaser
```

In the editor, add:

```
[Service]
ExecStartPre=
ExecStopPost=
```

Empty assignments clear the host-side setup hooks. The unit will then only run
`turbolaser run`.

Validate the config:

```
turbolaser check --config /opt/replay/conf/replay.yaml
```

## 6. CT: add captures and forge variants

Source ICS/OT captures (see the main README for sources such as the
automayt/ICS-pcap collection). Place them in the pool, then forge variants. From
the host you can push files in:

```
# on the host
pct push 910 /path/to/modbus.pcap /opt/replay/pcaps/pool/modbus.pcap
```

Then in the CT, forge a magazine of variants with payload identity mutation and a
fresh topology preserving L3 remap, validated by tshark:

```
turbolaser reload \
  --in /opt/replay/pcaps/pool/modbus.pcap \
  --out-dir /opt/replay/pcaps/variants \
  --count 16 --remap-l3 --validate
```

Each round is written with a `.toml` manifest describing what changed, plus an
`index.json` roster.

## 7. VM: add the sensor lab monitor NIC

Give the Dragos sensor VM a dedicated monitor NIC on the isolated lab bridge.
This is separate from its production SPAN NIC on `vmbr3`/NIC3.

```
qm set 200 --net1 virtio,bridge=vmbr9
```

Then, inside the sensor, configure that interface as a monitoring interface in
promiscuous mode. The exact step is sensor specific; see your Dragos sensor
documentation for assigning a monitoring interface.

## 8. Host: set up the mirror

This is the core of the topology. The CT's transmit on `eth1` appears on the host
as ingress on the container's veth (`veth910i1`, where `910` is the CTID and `1`
is the index of `net1`). We mirror that ingress out the sensor VM's tap
(`tap200i1`), which delivers it into the sensor.

Find the exact names once both guests are running:

```
ip -br link | grep -E 'veth910|tap200'
```

Set up the mirror with `tc`. This is idempotent and safe to re-run:

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
The repo's `scripts/net-setup.sh` does the same thing and adds both directions, so
you can also copy it to the host and run:

```
./net-setup.sh --mode tc --bridge vmbr9 --replay-port veth910i1 --sensor-port tap200i1
```

Make it survive reboots and guest restarts with a host unit that runs after the
guests come up. Save the `tc` block above as `/usr/local/sbin/ot-mirror.sh`
(with `set -euo pipefail` and `#!/usr/bin/env bash`), make it executable, then:

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

Open vSwitch alternative: if `vmbr9` is an OVS bridge, add both guest ports to it
and create an OVS mirror instead of the `tc` filter:

```
ovs-vsctl -- --id=@p get Port veth910i1 \
          -- --id=@s get Port tap200i1 \
          -- --id=@m create Mirror name=tl-span \
                select-src-port=@p select-dst-port=@p output-port=@s \
          -- set Bridge vmbr9 mirrors=@m
```

## 9. First run

Start the appliance in the CT:

```
turbolaser up        # enable and start the service (host mirror already running)
turbolaser status
journalctl -u ot-turbolaser -f
```

You should see per-run lines with the chosen capture, the rate model, and the run
seed, then inter-run gaps.

## 10. Verify on the sensor

- On the host, confirm the mirror is carrying frames. The action packet counter
  should climb while a capture replays:

  ```
  tc -s filter show dev veth910i1 ingress
  ```

- Inside the sensor VM, confirm it receives unicast OT traffic, not just
  broadcast and multicast:

  ```
  tshark -i net1 -c 20
  ```

  You should see Modbus, DNP3, S7comm, or EtherNet/IP depending on the capture,
  with source and destination addresses in the fresh random subnets.

- Back in the CT, `turbolaser status` shows the live state, the current capture,
  the per-run seed, and the tx packet count. `cat /run/ot-turbolaser/status.json`
  gives the raw heartbeat.

## 11. Safety and troubleshooting

- Isolation. `vmbr9` must have `bridge-ports none`. Never add a physical NIC to
  it. The lab traffic uses foreign, randomised MACs and IPs and must never reach a
  production network. Keep the NIC3 production SPAN on its own bridge.
- The sensor sees nothing. Check the mirror counters in step 10. If they are zero,
  confirm you mirrored the correct veth and tap and used the ingress direction on
  the container veth. Confirm the names with `ip -br link` after both guests are
  up, since they change with CTID and VMID.
- AF_PACKET and tc. The mirror relies on the container's raw transmit traversing
  the host veth so the ingress hook can copy it. This is the default. If a future
  tcpreplay build sets `PACKET_QDISC_BYPASS`, switch to the OVS mirror, which
  copies in the datapath regardless.
- Service fails with `226/NAMESPACE` ("Failed to set up mount namespacing"). The
  unit's filesystem hardening needs a mount namespace, which a container cannot
  set up. The shipped unit is already LXC safe. If you are on an older unit, add a
  drop-in that disables it:
  `mkdir -p /etc/systemd/system/ot-turbolaser.service.d` then write
  `[Service]` with `ProtectSystem=no`, `ProtectHome=no`, `ProtectKernelTunables=no`,
  `ProtectKernelModules=no`, `ProtectControlGroups=no`, and `ReadWritePaths=`, then
  `systemctl daemon-reload && systemctl reset-failed ot-turbolaser &&
  systemctl restart ot-turbolaser`.
- Raw socket denied in the CT. Use a privileged container. If a restrictive
  AppArmor profile blocks raw networking, as a last resort set
  `lxc.apparmor.profile: unconfined` in `/etc/pve/lxc/910.conf` and weigh the
  security trade-off.
- Build killed for memory. The release build uses link time optimization. Raise
  the container memory or swap for the build, or build a static musl binary
  elsewhere and `pct push` it in (step 4).
- Duplicate broadcast frames. With both guest ports on `vmbr9`, the bridge may
  also flood broadcast and multicast to the sensor on top of the mirror. To make
  the sensor see only mirrored frames, enable port isolation on both ports:
  `bridge link set dev veth910i1 isolated on` and the same for `tap200i1`.
```
