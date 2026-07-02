#!/usr/bin/env bash
# install-smoke.sh: prove the installed runtime tree can actually load the target
# scenarios. The unit and integration tests run against the repo-relative conf/
# dir, so they never catch a packaging gap (the v0.4.0-alpha bug: install.sh did
# not ship conf/targets/, so every `--scenario` failed on a real appliance while
# CI stayed green). This installs into a sandbox PREFIX and asserts the packs are
# present and loadable through the real binary. Run after `cargo build --release`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PREFIX="$(mktemp -d "${TMPDIR:-/tmp}/tl-smoke.XXXXXX")"
cleanup() { rm -rf "$PREFIX"; }
trap cleanup EXIT

echo "install-smoke: laying the tree into $PREFIX"
# OT_INSTALL_SYSTEM=0: lay only the runtime tree, no PATH symlink / systemd units /
# /var/lib, so the smoke test is hermetic and needs no root.
PREFIX="$PREFIX" OT_INSTALL_SYSTEM=0 scripts/install.sh >/dev/null

BIN="$PREFIX/bin/turbolaser"
CFG="$PREFIX/conf/replay.yaml"
fail=0

# The five shipped packs must be on disk under the installed conf/targets.
for name in stuxnet triton oldsmar ukraine2015 incontroller; do
    if [[ -f "$PREFIX/conf/targets/$name/scenario.yaml" ]]; then
        echo "  ok: $name/scenario.yaml installed"
    else
        echo "  FAIL: $name/scenario.yaml missing from the installed tree" >&2
        fail=1
    fi
done

# The installed config's pcap paths must be templated to THIS PREFIX. A verbatim
# copy leaves them at /opt/replay/pcaps/*, which a non-default install never
# creates, so scan_pcaps finds nothing and the daemon idles forever while systemd
# still sees the unit as up.
if grep -q "$PREFIX/pcaps/pool" "$CFG" && grep -q "$PREFIX/pcaps/variants" "$CFG"; then
    echo "  ok: replay.yaml pcap paths templated to the install PREFIX"
else
    echo "  FAIL: replay.yaml pcap paths not templated to $PREFIX" >&2
    grep -nE "pool:|variants:" "$CFG" >&2 || true
    fail=1
fi
if grep -q "/opt/replay/pcaps" "$CFG"; then
    echo "  FAIL: replay.yaml still references /opt/replay/pcaps under a non-default PREFIX" >&2
    fail=1
fi

# `targets` must discover all five through the installed config's sibling dir.
count="$("$BIN" targets --config "$CFG" --json | grep -c '"name":' || true)"
if [[ "$count" == 5 ]]; then
    echo "  ok: turbolaser targets lists 5 scenarios"
else
    echo "  FAIL: turbolaser targets listed $count scenarios, expected 5" >&2
    "$BIN" targets --config "$CFG" || true
    fail=1
fi

# Every pack must merge + validate through the real loader from the installed
# layout (this is the exact path that failed on the alpha appliance).
for name in stuxnet triton oldsmar ukraine2015 incontroller; do
    if "$BIN" check --config "$CFG" --scenario "$name" >/dev/null 2>&1; then
        echo "  ok: check --scenario $name exits 0"
    else
        echo "  FAIL: check --scenario $name failed from the installed tree" >&2
        "$BIN" check --config "$CFG" --scenario "$name" || true
        fail=1
    fi
done

if [[ "$fail" == 0 ]]; then
    echo "install-smoke: PASS (scenarios load from the installed tree)"
else
    echo "install-smoke: FAIL" >&2
    exit 1
fi
