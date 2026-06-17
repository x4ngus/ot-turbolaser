#!/usr/bin/env bash
# veth-replay-check.sh: validate the target-scenario emission end to end on a
# real Linux wire. Creates a veth pair -- the appliance's replay port and the
# sensor monitor port -- fires each scenario's burst pcap with tcpreplay (the
# same tool and flags the daemon uses), then dissects what the sensor captures
# off the wire with tshark, asserting the attack protocol decodes with no
# malformed frames. This is the composition the appliance runs in the field.
#
# Linux only (veth is a Linux construct); run as root (veth and tcpreplay need
# NET_ADMIN). Needs tcpreplay, tshark, ip, tcpdump.
set -euo pipefail

REPLAY=tlrep0       # replay port (tcpreplay --intf1), the daemon's iface
SENSOR=tlrep1       # sensor monitor port (capture), the veth peer
PCAP_DIR=""

usage() {
    cat >&2 <<EOF
usage: sudo scripts/veth-replay-check.sh [--pcap-dir DIR]
  --pcap-dir DIR   directory of <scenario>.pcap burst captures to replay. If
                   omitted, they are generated via the scenario dump test
                   (needs cargo and the source tree).
Validates stuxnet, triton, oldsmar, ukraine2015.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pcap-dir) PCAP_DIR="${2:?--pcap-dir needs a directory}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
    esac
done

[ "$(uname -s)" = Linux ] || { echo "Linux only: veth is a Linux construct" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root: veth and tcpreplay need NET_ADMIN" >&2; exit 1; }
for t in tcpreplay tshark ip tcpdump; do
    command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done

# Generate the scenario burst pcaps if a directory was not supplied.
if [ -z "$PCAP_DIR" ]; then
    PCAP_DIR="${TMPDIR:-/tmp}/ot-scenarios"
    echo "generating scenario pcaps into $PCAP_DIR ..."
    cargo test --release --test scenario_tshark dump_scenario_pcaps -- --ignored --nocapture >/dev/null
fi

cleanup() { ip link del "$REPLAY" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip link add "$REPLAY" type veth peer name "$SENSOR"
ip link set "$REPLAY" up
ip link set "$SENSOR" up promisc on

# Per-scenario signature: the control-plane protocol the sensor must dissect off
# the wire. TriStation is proprietary (no Wireshark dissector), so it is keyed by
# its UDP/1502 transport, exactly as a passive sensor keys it.
sig_stuxnet='s7comm'
sig_triton='udp.port==1502'
sig_oldsmar='modbus.func_code==6'
sig_ukraine2015='104apci || ip.addr==5.149.254.114'

rc=0
for name in stuxnet triton oldsmar ukraine2015; do
    src="$PCAP_DIR/$name.pcap"
    [ -f "$src" ] || { echo "SKIP $name (no $src)"; continue; }
    cap="$(mktemp /tmp/ot-cap.XXXXXX.pcap)"

    # Capture inbound on the sensor port, then fire the burst on the replay port
    # with the daemon's own tcpreplay invocation. The daemon paces the burst by
    # the pcap's own timestamps; --topspeed just makes the test quick.
    tcpdump -i "$SENSOR" -Q in -w "$cap" >/dev/null 2>&1 &
    cpid=$!
    sleep 0.5
    tcpreplay --intf1="$REPLAY" --preload-pcap --loop=1 --topspeed "$src" >/dev/null 2>&1
    sleep 0.5
    kill "$cpid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true

    sig_var="sig_${name}"
    sig="${!sig_var}"
    malformed="$(tshark -r "$cap" -Y _ws.malformed -T fields -e frame.number 2>/dev/null | tr -d '[:space:]')"
    seen="$(tshark -r "$cap" -Y "$sig" -T fields -e frame.number 2>/dev/null | head -1)"
    count="$(tshark -r "$cap" -T fields -e frame.number 2>/dev/null | grep -c .)"
    rm -f "$cap"

    if [ -n "$malformed" ]; then
        echo "FAIL $name: malformed frames captured off the wire (frames $malformed)"
        rc=1
    elif [ -z "$seen" ]; then
        echo "FAIL $name: '$sig' not dissected off the wire ($count frames captured)"
        rc=1
    else
        echo "PASS $name: $count frames off the wire, '$sig' dissects, none malformed"
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "OK: every scenario validated on the wire"
else
    echo "FAILURES above"
fi
exit "$rc"
