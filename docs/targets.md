# Target scenarios

A **target scenario** aims red laser at a specific, documented real-world OT
attack. Loading one pins the attack's plant (the real equipment, with real CVEs)
and drives a phased attack timeline onto the isolated bridge, so a passive OT
sensor sees the incident unfold. Loading no scenario leaves red laser's generic
plant behaviour unchanged.

Four scenarios ship:

| Scenario | Attack | Signature on the wire |
|---|---|---|
| `stuxnet` | Siemens S7 / Natanz centrifuges (2010) | S7 program download, rogue VFD frequency write, PLC STOP |
| `triton` | Schneider Triconex SIS / petrochemical (2017) | TriStation (UDP/1502) status + program download |
| `oldsmar` | Water-treatment NaOH setpoint (2021) | Modbus write of the dose setpoint 100 → 11,100 ppm |
| `ukraine2015` | BlackEnergy / IEC-104 grid (2015) | IEC-104 interrogation + breaker-open commands, KillDisk, Moxa brick |

```
turbolaser targets                          # list installed scenarios
turbolaser check   --scenario stuxnet       # validate the merged config
turbolaser plan    --scenario stuxnet       # preview the pinned plant (no traffic)
turbolaser plan    --scenario stuxnet --commit   # seal the plant for the daemon
turbolaser run     --scenario stuxnet       # the daemon (builds the plant if uncommitted)
turbolaser pewpew  --config <cfg>           # readout shows the scenario + current phase
```

Without `--scenario`, every command is the generic red laser it always was.

### Running a scenario as the daemon

`fire --scenario <name>` runs a scenario as the persistent service (it starts the
templated unit `ot-turbolaser@<name>` and pre-flights the pack first, so a missing
or broken pack fails clearly instead of crash-looping):

```
turbolaser fire --scenario stuxnet        # start the stuxnet scenario daemon
turbolaser halt --scenario stuxnet        # stop it
```

Equivalently, drive the templated unit directly:

```
systemctl start ot-turbolaser@stuxnet
systemctl stop  ot-turbolaser@stuxnet
```

A plain `fire` (no `--scenario`) runs **generic** red laser. If a scenario plant
is committed, a plain `fire` refuses to start (the generic `run` would reject the
scenario-tagged ledger and, with `Restart=always`, crash-loop) and points you at
`fire --scenario <name>`; or run `turbolaser reset` to return the plant to generic
first. The templated unit also rate-limits restarts (`StartLimitBurst`), so a
genuinely broken pack lands in `failed` rather than looping forever.

### Upgrading from v0.3.x

A v0.3.x appliance has a committed **generic** session ledger. v0.4.0 adds the
scenario tag, so before running a scenario for the first time, clear the generic
plant for that scenario: `turbolaser reset --scenario <name>` (or run a generic
`reset`). The daemon also rebuilds a fresh plant automatically if the ledger is
unreadable, so a stale `session.json` no longer blocks startup.

## Containment (read this)

Scenario packs carry **real published indicators** (C2 domains, artifact names,
CVEs) by default (`ioc_fidelity: real`). These are emitted **only onto the
appliance's isolated bridge**, replayed to a mirror port for a passive sensor --
no connection completes and nothing executes. Even so:

- **Run scenarios only on the isolated test bridge**, never a production or
  internet-reachable segment.
- Set **`ioc_fidelity: standin`** in a pack's `scenario.yaml` to swap every
  network indicator for an RFC-5737 documentation stand-in, for labs that want
  zero real attribution on the wire.
- Indicator strings and hashes live in **pack data files, never compiled into
  the binary**, so the appliance binary stays clean.
- Under `ioc_fidelity: real` the network indicators are the real published ones:
  the Ukraine pack ships the documented BlackEnergy3 C2 address (5.149.254.114);
  the Stuxnet pack ships the real C2 domains (the Symantec dossier published no
  literal C2 IP -- the servers were sinkholed in 2010). Raw routable C2 addresses
  therefore do reach the bridge, so keep it isolated, and confirm a pack's
  indicators against its cited advisory before relying on it.

## Anatomy of a pack

A scenario is a drop-in directory under `<config-dir>/targets/<name>/`:

```
targets/<name>/
  scenario.yaml    # the target: block (+ any base-config overrides)
  plant.yaml       # the pinned zones and devices
  playbook.yaml    # the phased attack timeline
  profiles.toml    # scenario-specific CVE profiles (overlaid on the embedded set)
```

Adding a scenario is pure data: drop in a new directory, no code change.

### Authoring a new pack

Start from the annotated template, then validate as you go:

```
cp -r conf/targets/_template conf/targets/<name>     # a bare slug, no dots
# edit scenario.yaml (set name: <name>), plant.yaml, playbook.yaml, profiles.toml
turbolaser check --config conf/replay.yaml --scenario <name>   # merge + pre-flight the whole pack
turbolaser plan  --config conf/replay.yaml --scenario <name>   # preview the pinned plant (no traffic)
```

`check` and `plan` load the plant, playbook, and profiles, so a typo (an unknown
`emit`, a malformed `payload_hex`, a duplicate device IP, a device in an undeclared
zone) is reported here, not at the daemon's first start. The `_template` directory
is `_`-prefixed, so the installer and `turbolaser targets` skip it: it is the
starting point, never a runnable scenario.

### scenario.yaml

`scenario.yaml` deep-merges over the base config (maps merge; scalars and lists
replace). It must declare a `target:` block:

```yaml
target:
  name: stuxnet                 # must match the directory name
  description: ...              # shown by `turbolaser targets`
  campaign: oneshot             # oneshot (hold the final phase) | loop (restart)
  ioc_fidelity: real            # real | standin
  max_frames_per_burst: 64      # cap on attack frames appended per identity burst
  actors:
    external_cidrs: ["198.51.100.0/24"]
    c2_domains: ["www.example-c2.com"]
    c2_ips: ["203.0.113.7"]
    artifacts: ["implant.dll"]
# Any base-config key may be overridden too, e.g.:
dns:
  domains: ["fep.natanz.example"]
```

`profiles`, `playbook`, and `plant` default to the filenames above; set them only
to use different names.

### plant.yaml

Pins the exact plant. A device whose `model` matches a CVE profile (embedded or
in `profiles.toml`) becomes CVE-bearing and asserts its identity on the wire; any
other device is identity-only (it binds via ARP/DNS and is driven by the
playbook). `enrich: true` adds the generic supporting cast (zone firewall, HMI,
EWS, historian) around the pinned kit.

```yaml
zones:
  - { cidr: 10.10.10.0/24, name: "Centrifuge Drive Control", purdue_level: 1, vendor: "Siemens AG" }
devices:
  - { zone: 10.10.10.0/24, model: "SIMATIC S7-300 CPU 315-2 PN/DP", ip: 10.10.10.11, hostname: A21-DRIVE-1 }
  - { zone: 10.10.10.0/24, asset_type: SIS, vendor: "Schneider Electric", protocol: tristation, ip: 10.10.10.20 }
enrich: true
```

### playbook.yaml

An ordered list of phases. Each phase advances once its events are emitted and
its `dwell_runs` (in announce bursts) elapses.

```yaml
phases:
  - id: sabotage
    name: "Rogue VFD frequency"
    techniques: [T0836, T0855, T0831]   # ATT&CK-for-ICS technique ids
    dwell_runs: 4
    events:
      - { emit: s7_write, target: { ip: 10.10.10.11 }, db: 8, offset: 0, value: 1410 }
```

An event's `target` selects a plant device by `ip`, `model`, or `asset_type`
(first match wins). Available `emit` kinds:

| emit | protocol | key params |
|---|---|---|
| `s7_read` | S7comm /102 | `target` |
| `s7_program_download` | S7comm /102 | `target`, `block_id`, `payload_hex` |
| `s7_write` | S7comm /102 | `target`, `db`, `offset`, `value` |
| `s7_stop` | S7comm /102 | `target` |
| `modbus_write` | Modbus /502 | `target`, `register`, `value`, `unit` |
| `tristation_status` | TriStation /1502 | `target` |
| `tristation_download` | TriStation /1502 | `target`, `payload_hex`, `chunk` |
| `iec104_interrogation` | IEC-104 /2404 | `target`, `common_addr` |
| `iec104_command` | IEC-104 /2404 | `target`, `common_addr`, `ioa`, `close` |
| `c2_beacon` | DNS + TCP | `domain`, `ip`, `port` (else `actors`) |
| `remote_access` | TCP | `target`, `port` |
| `wiper` | SMB2 /445 | `target`, `share` |
| `moxa_brick` | UDP /4800 | `target`, `payload_hex` |

Where an emit accepts `payload_hex`, it is a bare hex string (e.g. `7070010203`);
non-hex characters are ignored. A payload large enough to push a frame over the
link MTU is dropped from that burst with a warning, so a mis-sized pack value
never aborts the replay run.

A new protocol emitter is a `synth` module plus an `EmitKind` arm; the framework,
config, status, and CLI need no change to gain a new scenario.

## Notes

- A scenario ledger is tagged with its name; the daemon refuses to replay a
  scenario plant generically (or a generic plant under `--scenario`). Run
  `turbolaser reset --scenario <name>` to clear it.
- The TriStation emitter models the sensor-visible signature (UDP/1502 + the
  download burst); the protocol is proprietary and undocumented at the byte
  level. IEC-104 and the S7/Modbus emitters follow their open specifications and
  decode in the standard dissectors.
- Verify each scenario's CVEs, firmware, and indicators against the primary
  advisory (e.g. ICSA-16-348-05, SEVD-2017-347-01, CISA AA21-042A, CISA
  IR-ALERT-H-16-056-01) before relying on a pack.
- The status heartbeat (`/run/ot-turbolaser/status.json`) is `schema: 4` under a
  scenario, adding `scenario`, `phase`, and `technique_ids` (additive over the
  generic `schema: 3` fields). `pewpew` is field-tolerant; an external consumer
  keyed on `schema == 3` must accept 4.
- Use `turbolaser net-show` to confirm the scenario's frames actually reach the
  sensor through the mirror (it reads the kernel's own counters, beyond `pewpew`).
