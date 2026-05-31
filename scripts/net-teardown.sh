#!/usr/bin/env bash
# net-teardown.sh: remove the mirror and the isolated bridge. Idempotent and
# fail-safe: missing objects are not an error.
set -euo pipefail

MODE=tc
BRIDGE=tlbr0
REPLAY=tl0
SENSOR=sens0

usage() {
    cat >&2 <<EOF
usage: net-teardown.sh [--mode tc|ovs] [--bridge NAME] [--replay-port IF] [--sensor-port IF]
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

if [[ "$MODE" == ovs ]]; then
    ovs-vsctl --if-exists clear Bridge "$BRIDGE" mirrors 2>/dev/null || true
    ovs-vsctl --if-exists del-br "$BRIDGE" 2>/dev/null || true
    ip link set "$SENSOR" promisc off 2>/dev/null || true
else
    tc qdisc del dev "$REPLAY" clsact 2>/dev/null || true
    ip link set "$REPLAY" nomaster 2>/dev/null || true
    ip link set "$SENSOR" promisc off 2>/dev/null || true
    ip link set "$BRIDGE" down 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
fi

echo "teardown complete (mode=$MODE bridge=$BRIDGE)"
