# ot-turbolaser quick start: Proxmox VE (v0.2.1)

Bring the turbolaser online and put a believable OT network on the wire for your
sensor to watch. This is the short, copy-and-paste path for Proxmox VE 8. For the
full background and every option, see
[proxmox-getting-started.md](proxmox-getting-started.md).

New in v0.2.1: you design the fake plant once, lock it in, then fire. The sensor
then sees the same planned network every time, with the addresses, zones, and
CVE-bearing devices you chose. No surprises, no drift.

## What you are building

A self-contained firing lane on one Proxmox host: the turbolaser runs in a small
container, replays OT captures onto an isolated bridge with no uplink, and a host
mirror copies that traffic into your sensor VM.

```
  turbolaser CT 910  ──fire──>  vmbr9 (isolated, no uplink)
                                  │
                                  └── host mirror ──>  sensor VM 200
```

Two rules keep it safe:

- The lab bridge `vmbr9` has no physical port, so replayed traffic can never
  leave the host.
- The traffic uses fake (randomized) addresses, never real ones.

Substitute your own IDs. This guide uses container `910`, sensor VM `200`, and
isolated bridge `vmbr9`.

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

Apply it without a reboot:

```
ifreload -a
ip -br link show vmbr9
```

## 2. Create the emitter (container)

The daemon sends raw frames, so it needs a privileged container. It gets two
network ports: `eth0` for internet during setup, `eth1` as the replay port on the
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

Use whatever current `debian-12-standard` version `pveam available` lists. You can
lower the memory to 512 MB after the build; the daemon idles light.

## 3. Charge it (build and install)

Enter the container and build:

```
pct enter 910

apt-get update && apt-get install -y --no-install-recommends git
git clone https://github.com/x4ngus/ot-turbolaser
cd ot-turbolaser
./scripts/bootstrap.sh --build --tests
. "$HOME/.cargo/env"

cargo build --release
./scripts/install.sh
```

`install.sh` puts the binary at `/opt/replay/bin/turbolaser`, adds it to your
PATH, installs the service, and creates the pcap folders.

## 4. Set the targeting solution (configure)

Edit `/opt/replay/conf/replay.yaml`. You only need to change three lines:

```
iface: eth1                  # the replay port on vmbr9
mode: red_laser              # the adversarial content layer

session:
  seed: 1337                 # pin any number you like; this makes the plant repeatable
```

That `seed` is the important one. It is the single setting that makes your fake
plant come out the same every time. Pick a number and keep it.

The rest of the new v0.2.1 options have safe defaults, so you can leave them out.
They live under `l3:` and `synthesis:` if you want to tune them later (see the
comments in the shipped config).

The mirror is set up on the host, not the container, so tell the service to skip
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

Drop in as many as you like. The turbolaser picks from them at random.

## 6. Commit the firing solution (the key v0.2.1 step)

This is the new step that makes the trial repeatable. You fabricate the fake
plant once and lock it into a sealed plan. The daemon then replays exactly that
plant, every run.

Inside the container:

```
turbolaser reset --config /opt/replay/conf/replay.yaml
turbolaser plan  --config /opt/replay/conf/replay.yaml --commit
```

`plan --commit` builds the zones and devices from your `seed` and writes them to
a sealed file the daemon will follow. Look at what you committed:

```
turbolaser zones --config /opt/replay/conf/replay.yaml
```

You will see the control-system zones, their vendors, and the device counts. This
is exactly what your sensor will inventory. If you want a different plant, change
the `seed` (or the device count), then run `reset` and `plan --commit` again. To
overwrite an existing plan in one go, add `--force`.

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

Set up the mirror (safe to re-run):

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

Inside the sensor VM, set that new port as a monitoring interface in promiscuous
mode. The exact step depends on your sensor; check its documentation.

## 8. Open fire and confirm hits

Start the turbolaser:

```
turbolaser up
turbolaser status
journalctl -u ot-turbolaser -f
```

Confirm the rounds are landing:

```
# on the host: this counter should climb while a capture replays
tc -s filter show dev veth910i1 ingress

# inside the sensor VM: you should see OT traffic on fake internal addresses
tshark -i net1 -c 20
```

Within a short while the sensor should inventory the same zones and devices you
saw in step 6, including the CVE-bearing devices.

## Quick troubleshooting

- The sensor sees nothing. Check the mirror counter in step 8. If it is zero, you
  likely mirrored the wrong port. Re-check the names with `ip -br link` after both
  guests are up.
- The plant looks different from the plan. Make sure `session.seed` is set in the
  config, and that you ran `plan --commit` (not just `plan`). Re-run `turbolaser
  zones` to confirm what is committed.
- A capture is skipped in the logs. By design, the turbolaser skips any capture it
  cannot safely rewrite rather than putting real addresses on the wire. Drop in
  another capture, or shrink the oversized one.
- The build runs out of memory. Raise the container memory or swap for the build,
  or build a static binary elsewhere and copy it in (see the full guide).
- Raw socket denied. Use a privileged container (`--unprivileged 0`, as above).

## Safety

The lab bridge `vmbr9` must keep `bridge-ports none`. Never add a physical NIC to
it, and never bridge it to a production network. The replayed traffic uses fake
addresses and is for your isolated sensor test only.
