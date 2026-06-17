#!/usr/bin/env bash
# net-provision.sh: create the isolated replay+sensor veth pair the appliance's
# datapath rides on, for a self-contained single-host deployment (bare metal or a
# minimal VM: README "Deployment topology" mode 1). This is the missing first step
# before `turbolaser net-setup`/`fire`: net-setup expects the replay port
# (replay.yaml `iface`) and the sensor port (`net.sensor_port`) to already exist
# and exits non-zero if they do not. This creates them as the two ends of one veth
# pair, so the daemon's replayed traffic reaches the sensor monitor port.
#
# NOT for Proxmox/ESXi: there the hypervisor provides the ports and the mirror runs
# on the host (see docs/proxmox.md), so this is not used. NOT for a physical sensor
# NIC: this only creates virtual interfaces and refuses to touch a real NIC; if the
# sensor port is a physical link to the sensor, provision only the replay port (see
# README "Deployment topology").
#
# Idempotent. Linux only (veth is a Linux construct). Run as root (NET_ADMIN).
set -euo pipefail

REPLAY=tl0
SENSOR=sens0
UNDO=0

usage() {
    cat >&2 <<EOF
usage: net-provision.sh [--replay-port IF] [--sensor-port IF] [--undo]
  --replay-port  daemon tcpreplay TX interface (replay.yaml iface; default tl0)
  --sensor-port  sensor monitor interface (net.sensor_port; default sens0)
  --undo         delete the veth pair instead of creating it
Creates an isolated veth pair <replay-port> <-> <sensor-port>. net-setup then
builds the bridge and mirror on top. Refuses to touch a physical NIC.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --replay-port) REPLAY="${2:?}"; shift 2 ;;
        --sensor-port) SENSOR="${2:?}"; shift 2 ;;
        --undo) UNDO=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ "$(uname -s)" == Linux ]] || { echo "Linux only: veth is a Linux construct" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "run as root: creating a veth pair needs NET_ADMIN" >&2; exit 1; }
command -v ip >/dev/null || { echo "missing tool: ip (install iproute2)" >&2; exit 1; }

# A physical NIC has a /sys/class/net/<if>/device symlink into the PCI or USB tree.
# Virtual interfaces (veth, tap, bridge, dummy) do not. Same test net-setup uses.
is_physical() {
    local ifc="$1" dev real
    dev="/sys/class/net/${ifc}/device"
    [[ -e "$dev" ]] || return 1
    real="$(readlink -f "$dev" 2>/dev/null || true)"
    case "$real" in
        */pci*|*/usb*) return 0 ;;
        *) return 1 ;;
    esac
}
iface_exists() { ip link show "$1" >/dev/null 2>&1; }

# Never clobber, delete, or bridge a real NIC (the hard isolation invariant): the
# replay port must be virtual, and a physical sensor NIC is provisioned by cabling,
# not here. Checked on both the create and the --undo path.
for role_ifc in "replay port:$REPLAY" "sensor port:$SENSOR"; do
    role="${role_ifc%%:*}"
    ifc="${role_ifc##*:}"
    if is_physical "$ifc"; then
        {
            echo "REFUSING: $role '$ifc' is a physical NIC."
            echo "  net-provision only creates virtual veth interfaces and never touches a"
            echo "  real NIC. The replay port must be virtual; if the sensor port is a"
            echo "  physical link to the sensor, create only the replay port (see README"
            echo "  'Deployment topology')."
        } >&2
        exit 3
    fi
done

if [[ "$UNDO" == 1 ]]; then
    # Deleting either end removes the whole veth pair.
    ip link del "$REPLAY" 2>/dev/null || ip link del "$SENSOR" 2>/dev/null || true
    echo "removed veth pair $REPLAY <-> $SENSOR (if present)"
    exit 0
fi

rep_exists=0
sen_exists=0
iface_exists "$REPLAY" && rep_exists=1
iface_exists "$SENSOR" && sen_exists=1

if [[ "$rep_exists" == 1 && "$sen_exists" == 1 ]]; then
    echo "veth pair already present: $REPLAY <-> $SENSOR (nothing to create)"
elif [[ "$rep_exists" == 1 || "$sen_exists" == 1 ]]; then
    present="$REPLAY"
    [[ "$rep_exists" == 1 ]] || present="$SENSOR"
    {
        echo "ERROR: '$present' already exists but its pair does not."
        echo "  Refusing to create a half-pair over an existing interface. Remove it"
        echo "  first (net-provision --undo, or: ip link del '$present'), then re-run."
    } >&2
    exit 4
else
    ip link add "$REPLAY" type veth peer name "$SENSOR"
    echo "created veth pair $REPLAY <-> $SENSOR"
fi

ip link set "$REPLAY" up
ip link set "$SENSOR" up
# The sensor port is a monitor: promiscuous so it captures frames not addressed to
# it. net-setup sets this too; doing it here makes the pair usable on its own.
ip link set "$SENSOR" promisc on

cat <<EOF
provisioned isolated datapath:
  replay port:  $REPLAY  (tcpreplay TX; net-setup bridges this, mirror source)
  sensor port:  $SENSOR  (promiscuous; mirror destination / monitor)

next:  turbolaser fire             (sets up the bridge + mirror, starts the daemon)
undo:  ip link del $REPLAY    (removes the pair; or: net-provision --undo)
EOF
