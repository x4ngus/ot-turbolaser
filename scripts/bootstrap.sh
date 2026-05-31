#!/usr/bin/env bash
# bootstrap.sh: install runtime dependencies on Debian 12. Run as root.
#
#   --ovs     also install Open vSwitch (only if you use the OVS mirror)
#   --tests   also install tshark (for `reload --validate` and the test suite)
#   --build   also install the Rust toolchain (build host only)
#
# The appliance itself needs only the tcpreplay suite and iproute2. There is no
# Python or scapy.
set -euo pipefail

WITH_OVS=0
WITH_TESTS=0
WITH_BUILD=0
for a in "$@"; do
    case "$a" in
        --ovs) WITH_OVS=1 ;;
        --tests) WITH_TESTS=1 ;;
        --build) WITH_BUILD=1 ;;
        *) echo "unknown flag: $a" >&2; exit 2 ;;
    esac
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
# tcpreplay provides tcpreplay and tcprewrite; iproute2 provides ip and tc.
apt-get install -y --no-install-recommends tcpreplay iproute2

if [[ $WITH_OVS -eq 1 ]]; then
    apt-get install -y --no-install-recommends openvswitch-switch
fi
if [[ $WITH_TESTS -eq 1 ]]; then
    apt-get install -y --no-install-recommends tshark
fi
if [[ $WITH_BUILD -eq 1 ]]; then
    apt-get install -y --no-install-recommends curl ca-certificates build-essential
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    echo "rust installed; for a static appliance binary add:"
    echo "  rustup target add x86_64-unknown-linux-musl"
fi

echo "bootstrap complete (ovs=$WITH_OVS tests=$WITH_TESTS build=$WITH_BUILD)"
