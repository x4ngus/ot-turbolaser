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
PREFIX="$PREFIX" scripts/install.sh >/dev/null

BIN="$PREFIX/bin/turbolaser"
CFG="$PREFIX/conf/replay.yaml"
fail=0

# The four shipped packs must be on disk under the installed conf/targets.
for name in stuxnet triton oldsmar ukraine2015; do
    if [[ -f "$PREFIX/conf/targets/$name/scenario.yaml" ]]; then
        echo "  ok: $name/scenario.yaml installed"
    else
        echo "  FAIL: $name/scenario.yaml missing from the installed tree" >&2
        fail=1
    fi
done

# `targets` must discover all four through the installed config's sibling dir.
count="$("$BIN" targets --config "$CFG" --json | grep -c '"name":' || true)"
if [[ "$count" == 4 ]]; then
    echo "  ok: turbolaser targets lists 4 scenarios"
else
    echo "  FAIL: turbolaser targets listed $count scenarios, expected 4" >&2
    "$BIN" targets --config "$CFG" || true
    fail=1
fi

# Every pack must merge + validate through the real loader from the installed
# layout (this is the exact path that failed on the alpha appliance).
for name in stuxnet triton oldsmar ukraine2015; do
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
