#!/usr/bin/env bash
# net-setup.sh: create an isolated bridge and mirror the replay port to the
# sensor monitor port. Idempotent. Refuses to attach a physical uplink.
#
# The replay port carries tcpreplay output and is the mirror source. The sensor
# port is the mirror destination, set promiscuous, never bridged for forwarding.
# A plain bridge will not forward the captures' original unicast MACs, so the
# mirror is the mechanism, not an optimisation.
set -euo pipefail

MODE=tc
BRIDGE=tlbr0
REPLAY=tl0
SENSOR=sens0

usage() {
    cat >&2 <<EOF
usage: net-setup.sh [--mode tc|ovs] [--bridge NAME] [--replay-port IF] [--sensor-port IF]
  --mode         mirror mechanism: tc (clsact/mirred, default) or ovs
  --bridge       isolated bridge name (default tlbr0)
  --replay-port  tcpreplay TX interface, joined to the bridge (default tl0)
  --sensor-port  sensor monitor interface, mirror destination (default sens0)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:?}"; shift 2 ;;
        --bridge) BRIDGE="${2:?}"; shift 2 ;;
        --replay-port) REPLAY="${2:?}"; shift 2 ;;
        --sensor-port) SENSOR="${2:?}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

case "$MODE" in
    tc|ovs) ;;
    *) echo "unknown --mode: $MODE (want tc or ovs)" >&2; exit 2 ;;
esac

# A physical NIC has a /sys/class/net/<if>/device symlink into the PCI or USB
# tree. Virtual interfaces (veth, tap, bridge, dummy) do not.
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

# Hard refusal: the replay port joins the bridge, so it must never be a real NIC
# that could bridge the isolated segment to a production or uplinked network.
if is_physical "$REPLAY"; then
    {
        echo "REFUSING: replay port '$REPLAY' is a physical NIC."
        echo "  This appliance must never bridge to a production or uplinked network."
        echo "  The replay port must be a virtual interface (veth or tap) on an isolated segment."
    } >&2
    exit 3
fi

# The sensor port is a mirror destination, not bridged, so it may legitimately
# be a dedicated physical link to the sensor. Warn loudly so the operator
# confirms it is not a production uplink.
if is_physical "$SENSOR"; then
    {
        echo "WARNING: sensor port '$SENSOR' is a physical NIC."
        echo "  It will be set promiscuous as a mirror DESTINATION only and never bridged."
        echo "  Ensure it is a dedicated, isolated link to the sensor, not a production uplink."
    } >&2
fi

for ifc in "$REPLAY" "$SENSOR"; do
    iface_exists "$ifc" || { echo "ERROR: interface '$ifc' not found" >&2; exit 4; }
done

setup_tc() {
    # Refuse if the bridge already enslaves a physical NIC (a pre-existing uplink).
    if [[ -d "/sys/class/net/${BRIDGE}/brif" ]]; then
        for member in "/sys/class/net/${BRIDGE}/brif/"*; do
            [[ -e "$member" ]] || continue
            local m; m="$(basename "$member")"
            if is_physical "$m"; then
                echo "REFUSING: bridge '$BRIDGE' already has a physical member '$m'." >&2
                exit 3
            fi
        done
    fi

    iface_exists "$BRIDGE" || ip link add name "$BRIDGE" type bridge
    ip link set "$BRIDGE" up
    ip link set "$REPLAY" master "$BRIDGE"
    ip link set "$REPLAY" up
    ip link set "$SENSOR" up
    ip link set "$SENSOR" promisc on

    # clsact carries both the egress and ingress mirror filters.
    tc qdisc show dev "$REPLAY" | grep -q clsact || tc qdisc add dev "$REPLAY" clsact
    # Replace any filters we set previously so re-running is idempotent.
    tc filter del dev "$REPLAY" egress 2>/dev/null || true
    tc filter del dev "$REPLAY" ingress 2>/dev/null || true
    # Egress mirrors tcpreplay TX to the sensor. Ingress is for completeness.
    tc filter add dev "$REPLAY" egress matchall \
        action mirred egress mirror dev "$SENSOR"
    tc filter add dev "$REPLAY" ingress matchall \
        action mirred egress mirror dev "$SENSOR"

    # Robust L2 delivery on top of the mirror: disable MAC learning and flood on
    # every port that is a member of the bridge. This is a monitoring span, not a
    # production switch, so flooding is correct and on an isolated segment cannot
    # storm. It survives tcpreplay transmitting with PACKET_QDISC_BYPASS (which
    # skips the egress qdisc and the tc-mirred mirror with it), because flooding is
    # plain L2 below the qdisc. It also fixes the learning-switch failure where the
    # bridge learns each fabricated MAC on the replay port and forwards unicast back
    # there instead of to the sensor (the "broadcast but not unicast" symptom). Only
    # applies to ports actually enslaved to $BRIDGE: in the self-contained model only
    # the replay port is a member (the sensor receives via the mirror), while on a
    # Proxmox host both the replay veth and the sensor tap are members of vmbr9.
    for port in "$REPLAY" "$SENSOR"; do
        if [[ -d "/sys/class/net/${BRIDGE}/brif/${port}" ]]; then
            bridge link set dev "$port" learning off flood on || true
        fi
    done
}

setup_ovs() {
    # Refuse if the OVS bridge already enslaves a physical member that is not our
    # designated sensor port (a pre-existing uplink), mirroring the tc path. The
    # replay port is already required to be virtual by the global check above; a
    # physical sensor port is the one allowed exception (mirror destination).
    if ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
        local port
        while read -r port; do
            [[ -n "$port" ]] || continue
            [[ "$port" == "$REPLAY" || "$port" == "$SENSOR" ]] && continue
            if is_physical "$port"; then
                echo "REFUSING: OVS bridge '$BRIDGE' already has a physical member '$port'." >&2
                exit 3
            fi
        done < <(ovs-vsctl list-ports "$BRIDGE" 2>/dev/null || true)
    fi

    ovs-vsctl --may-exist add-br "$BRIDGE"
    ovs-vsctl --may-exist add-port "$BRIDGE" "$REPLAY"
    ovs-vsctl --may-exist add-port "$BRIDGE" "$SENSOR"
    ip link set "$SENSOR" up
    ip link set "$SENSOR" promisc on
    ovs-vsctl --if-exists clear Bridge "$BRIDGE" mirrors
    ovs-vsctl \
        -- --id=@p get Port "$REPLAY" \
        -- --id=@s get Port "$SENSOR" \
        -- --id=@m create Mirror name=tl-span \
              select-src-port=@p select-dst-port=@p output-port=@s \
        -- set Bridge "$BRIDGE" mirrors=@m
}

if [[ "$MODE" == tc ]]; then
    setup_tc
else
    setup_ovs
fi

cat <<EOF
topology:
  mode:    $MODE
  bridge:  $BRIDGE  (isolated, no uplink)
  replay:  $REPLAY  (tcpreplay TX, mirror source)
  sensor:  $SENSOR  (promiscuous, mirror destination)

  [tcpreplay] --tx--> $REPLAY ==egress mirror==> $SENSOR --> sensor
                       |
                    <$BRIDGE> isolated, no uplink
EOF
