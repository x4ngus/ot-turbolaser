#!/usr/bin/env bash
# install.sh: lay the runtime tree under /opt/replay and install the systemd
# unit. Idempotent. Does not enable the service: edit the config and place
# captures first, then run `turbolaser up`. Run as root (the justfile uses sudo).
set -euo pipefail

PREFIX=/opt/replay

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

install -d "$PREFIX/bin" "$PREFIX/conf" "$PREFIX/scripts" "$PREFIX/data" \
    "$PREFIX/pcaps/pool" "$PREFIX/pcaps/variants" /var/lib/ot-turbolaser
install -m 0755 "$BIN_SRC" "$PREFIX/bin/turbolaser"
install -m 0755 scripts/net-setup.sh scripts/net-teardown.sh "$PREFIX/scripts/"

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

ln -sf "$PREFIX/bin/turbolaser" /usr/local/bin/turbolaser

if [[ -d /etc/systemd/system ]]; then
    install -m 0644 systemd/ot-turbolaser.service /etc/systemd/system/ot-turbolaser.service
    systemctl daemon-reload || true
fi

cat <<EOF
installed to $PREFIX
next:
  1. edit $PREFIX/conf/replay.yaml (iface, net.sensor_port, mode)
  2. drop captures into $PREFIX/pcaps/pool
     and forge variants:  turbolaser reload --in <pcap> --out-dir $PREFIX/pcaps/variants --count 16
  3. bring it up:  turbolaser up   (or: systemctl enable --now ot-turbolaser)
EOF
