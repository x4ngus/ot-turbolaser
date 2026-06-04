# ot-turbolaser operator automation. Run `just` to list recipes.
# Recipes assume the binary is installed on PATH (see `just bootstrap`).

set shell := ["bash", "-uc"]

# List recipes.
default:
    @just --list

# Build release and install the binary, unit, and default config (needs sudo).
bootstrap:
    cargo build --release
    sudo scripts/install.sh

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

# Bring the appliance up (enable + start; the unit sets up the mirror).
up:
    turbolaser up

# Show the live fire-control readout (pew pew). `status` is a deprecated alias.
pewpew:
    turbolaser pewpew

# Take the appliance down (stop + disable; the unit tears down the mirror).
down:
    turbolaser down
