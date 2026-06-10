#!/usr/bin/env bash
# install.sh: lay the runtime tree under /opt/replay and install the systemd
# unit. Idempotent. Does not enable the service: edit the config and place
# captures first, then run `turbolaser up`. Run as root (the justfile uses sudo).
#
# PREFIX is overridable (PREFIX=/tmp/tl-test scripts/install.sh) so the
# install-layout smoke test can lay the tree into a sandbox; defaults to the
# appliance path the systemd unit runs.
set -euo pipefail

PREFIX="${PREFIX:-/opt/replay}"

BIN_SRC=""
for c in \
    target/x86_64-unknown-linux-musl/release/turbolaser \
    target/release/turbolaser; do
    if [[ -x "$c" ]]; then
        BIN_SRC="$c"
        break
    fi
done
[[ -n "$BIN_SRC" ]] || {
    echo "no release binary found; build first: cargo build --release" >&2
    exit 1
}

install -d "$PREFIX/bin" "$PREFIX/conf" "$PREFIX/conf/targets" "$PREFIX/scripts" \
    "$PREFIX/data" "$PREFIX/pcaps/pool" "$PREFIX/pcaps/variants"
install -m 0755 "$BIN_SRC" "$PREFIX/bin/turbolaser"
install -m 0755 scripts/net-setup.sh scripts/net-teardown.sh "$PREFIX/scripts/"
# veth-replay-check.sh validates scenario emission on a real wire; ship it so the
# operator can run the on-wire dissector check from the installed tree.
[[ -f scripts/veth-replay-check.sh ]] && \
    install -m 0755 scripts/veth-replay-check.sh "$PREFIX/scripts/"

# Bundled OUI and vulnerable-profile databases. The binary embeds these; the
# on-disk copies are optional overrides the operator can edit. Never clobber an
# edited override: install the sample alongside instead.
for d in oui.csv vuln_profiles.toml; do
    if [[ -f "$PREFIX/data/$d" ]]; then
        install -m 0644 "data/$d" "$PREFIX/data/$d.example"
    else
        install -m 0644 "data/$d" "$PREFIX/data/$d"
    fi
done

# Never clobber an edited config: install the sample alongside instead.
if [[ -f "$PREFIX/conf/replay.yaml" ]]; then
    install -m 0644 conf/replay.yaml "$PREFIX/conf/replay.yaml.example"
    echo "kept existing config; new sample at $PREFIX/conf/replay.yaml.example"
else
    install -m 0644 conf/replay.yaml "$PREFIX/conf/replay.yaml"
fi

# Target-scenario packs. The binary does NOT embed these (unlike the OUI and
# vuln databases), so the daemon reads them from <conf>/targets/<name>/ at run
# time: not shipping them here is a total loss of `--scenario`. Copy each pack's
# four files with the same .example no-clobber convention as the config, so an
# operator-edited pack is preserved across upgrades. A `_`-prefixed dir (e.g. the
# authoring `_template`) is documentation, not a runnable pack, so skip it.
PACKS=0
if [[ -d conf/targets ]]; then
    for src in conf/targets/*/; do
        [[ -d "$src" ]] || continue
        name="$(basename "$src")"
        [[ "$name" == _* ]] && continue
        dst="$PREFIX/conf/targets/$name"
        install -d "$dst"
        for f in scenario.yaml playbook.yaml plant.yaml profiles.toml; do
            [[ -f "$src$f" ]] || continue
            if [[ -f "$dst/$f" ]]; then
                install -m 0644 "$src$f" "$dst/$f.example"
            else
                install -m 0644 "$src$f" "$dst/$f"
            fi
        done
        PACKS=$((PACKS + 1))
    done
fi

# A sandbox install (PREFIX overridden, e.g. the install-layout smoke test) lays
# only the runtime tree under PREFIX. The global PATH symlink and the systemd
# units are real-appliance integration into system paths, skipped unless we are
# installing to the default prefix, so the smoke test stays hermetic and rootless.
SYSTEM_INTEGRATION=0
[[ "$PREFIX" == /opt/replay ]] && SYSTEM_INTEGRATION=1

if [[ "$SYSTEM_INTEGRATION" == 1 ]]; then
    # The persistent session-ledger dir. On the appliance the systemd unit's
    # StateDirectory=ot-turbolaser also creates it; this covers a non-systemd dev run.
    install -d /var/lib/ot-turbolaser
    ln -sf "$PREFIX/bin/turbolaser" /usr/local/bin/turbolaser
fi

RESTARTED=0
if [[ "$SYSTEM_INTEGRATION" == 1 && -d /etc/systemd/system ]]; then
    install -m 0644 systemd/ot-turbolaser.service /etc/systemd/system/ot-turbolaser.service
    # Templated unit for running a target scenario as the daemon
    # (systemctl start ot-turbolaser@stuxnet); the plain unit runs generic red laser.
    install -m 0644 systemd/ot-turbolaser@.service /etc/systemd/system/ot-turbolaser@.service
    systemctl daemon-reload || true
    # On an upgrade of a running appliance, roll the daemon onto the freshly
    # installed binary so the operator never has to restart by hand. A stale
    # running binary (a plain start, not restart, after an upgrade) was a
    # recurring deploy trap. A fresh install is left stopped: configure first,
    # then fire.
    if systemctl is-active --quiet ot-turbolaser; then
        systemctl restart ot-turbolaser
        RESTARTED=1
    fi
fi

VERSION="$("$PREFIX/bin/turbolaser" --version 2>/dev/null || echo unknown)"
if [[ "$RESTARTED" == 1 ]]; then
    cat <<EOF
upgraded $PREFIX -> $VERSION
the running service was restarted onto the new binary.
verify:  turbolaser pewpew
EOF
else
    cat <<EOF
installed to $PREFIX ($VERSION); $PACKS target scenario(s) under $PREFIX/conf/targets
next:
  1. edit $PREFIX/conf/replay.yaml (iface, net.sensor_port, mode)
  2. drop captures into $PREFIX/pcaps/pool
     and forge variants:  turbolaser reload --in <pcap> --out-dir $PREFIX/pcaps/variants --count 16
  3. bring it up:  turbolaser fire   (or: systemctl enable --now ot-turbolaser)
  scenarios:  turbolaser targets   then   systemctl start ot-turbolaser@<name>
EOF
fi
