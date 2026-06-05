# ot-turbolaser operator automation. Run `just` to list recipes.
# Recipes assume the binary is installed on PATH (see `just bootstrap`).

set shell := ["bash", "-uc"]

# List recipes.
default:
    @just --list

# First-time install: build release and lay down the binary, unit, and default
# config (needs root; uses sudo only when not already root, so a root LXC with
# no sudo still works). Leaves the service stopped so you configure first.
bootstrap:
    cargo build --release
    if [ "$(id -u)" = 0 ]; then scripts/install.sh; else sudo scripts/install.sh; fi

# Roll out a new version in one step: build, install to the service's own path,
# and (if the service is already running) restart it onto the new binary. This
# is the upgrade path; no manual binary-copy or restart needed.
deploy:
    cargo build --release
    if [ "$(id -u)" = 0 ]; then scripts/install.sh; else sudo scripts/install.sh; fi
    turbolaser --version

# Validate the installed config.
check:
    turbolaser check --config /opt/replay/conf/replay.yaml

# Forge n rounds from every capture in the pool into the variants dir.
reload pool="/opt/replay/pcaps/pool" variants="/opt/replay/pcaps/variants" n="8":
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    mkdir -p "{{variants}}"
    found=0
    for f in "{{pool}}"/*.pcap "{{pool}}"/*.pcapng; do
        found=1
        echo "reloading $f"
        turbolaser reload --in "$f" --out-dir "{{variants}}" --count {{n}} --validate
    done
    [[ $found -eq 1 ]] || echo "no captures in {{pool}}"

# Bring the appliance online (enable + start; the unit sets up the mirror).
# `just up` is an alias.
fire:
    turbolaser fire
up:
    turbolaser fire

# Show the live fire-control readout (pew pew). `status` is a deprecated alias.
pewpew:
    turbolaser pewpew

# Take the appliance offline (stop + disable; the unit tears down the mirror).
# `just down` is an alias.
halt:
    turbolaser halt
down:
    turbolaser halt
