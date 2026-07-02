# ot-turbolaser 0.4.1 sprint roadmap

Scope, backlog, and exit criteria for the 0.4.1 development ladder. This file is the
sprint's source of truth; keep it current as items land.

## Where 0.4.1 starts

`0.4.1-beta.1` is a consolidation build. `develop` had fallen behind: it was still at
`0.4.0-beta.4` while `main` shipped stable 0.4.0 (target scenarios, datapath
provisioning/triage, Proxmox out-of-the-box) and then the 0.4.0 audit hardening
(unique fabricated MACs, config fail-fast, saturating zone-naming, `l3.fallback`
removal, PREFIX-aware install, the `EX_CONFIG`=78 exit contract). `main` was a clean
functional superset of `develop`, so the consolidation merges `main` into the develop
line and the tree is byte-identical to 0.4.0 stable. It builds clean and the full test
suite passes (216 unit tests plus every integration suite, one root/tcpreplay-gated
test ignored).

The attack-scenario framework therefore already shipped in 0.4.0. 0.4.1 does not add it;
0.4.1 hardens it against silent misfire and extends its authoring/verification story.

## Sprint goal

Take the scenario framework from "ships and dissects" to "cannot silently mis-fire on a
real appliance." Concretely, by 0.4.1 stable:

1. Every pre-flight (`check`/`plan`/`fire`) rejects a pack that would emit the wrong
   traffic or no traffic, instead of the daemon looking healthy while the sensor sees
   nothing.
2. A non-default `PREFIX` install works end to end.
3. The test suite proves per-event fidelity for every shipped pack, not just one
   signature per pack.

## Review basis

Backlog below is seeded from an adversarial review of the scenario framework and the
0.4.0 hardening: five dimension reviewers (scenario core, plant/playbook, registry/packs,
hardening correctness, integration wiring), each finding verified by an independent
skeptic, then a completeness-critic pass. 11 findings confirmed (0 refuted) plus 3 from
the critic. Severities below are the post-verification (corrected) severities.

Both P1 items are latent in shipped 0.4.0 as well, not only the develop line. If a 0.4.0
patch is wanted, SP-1 and SP-2 are the candidates to backport.

## Backlog

### P1 - silent-misfire blockers (both DONE in 0.4.1-beta.2)

- **SP-1 [high] [DONE 0.4.1-beta.2] Orphaned playbook target emits zero frames, silently.**
  `src/scenario/mod.rs:53`, resolution in `src/scenario/engine.rs` (`resolve` is
  first-match; an unresolved `DeviceRef` returns an empty frame vec and the event is
  skipped while the cursor advances). `build_validated_plant` validates the playbook and
  pins the plant as two independent steps and never cross-checks that each event's
  `target` resolves to a pinned device. A playbook that names an ip/model/asset_type
  absent from the plant passes `turbolaser check` ("config OK") and then emits nothing
  for that event or whole phase, so the intended detection never reaches the sensor. The
  shipped test `unresolved_target_is_skipped_not_panicked` documents the skip.
  *Fix:* in `build_validated_plant`, after pinning, assert every event `target` (when
  `Some`) resolves against the sealed session using the same ip -> model -> asset_type
  logic the engine uses; return `Err` naming any phase/event that resolves to nothing.
  Exempt `C2Beacon`'s `None`-target fallback to `devices.first()`.
  *Acceptance:* negative test (pack with an orphaned target is rejected at pre-flight)
  plus SP-5's positive per-pack test.
  *Landed 0.4.1-beta.2:* `ScenarioEngine::validate_targets` called from
  `build_validated_plant`; three unit tests plus the
  `orphaned_playbook_target_is_rejected_at_preflight` e2e test.

- **SP-2 [high] [DONE 0.4.1-beta.2] `conf/replay.yaml` is not PREFIX-templated, so a non-default install
  idles forever.** `scripts/install.sh:65`. The installer templates the systemd units and
  `hardening.conf` with `sed s#/opt/replay#${PREFIX}#g` but copies `conf/replay.yaml`
  verbatim. `paths.pool`/`paths.variants` stay pinned at `/opt/replay/pcaps/*` (required
  fields, absolute so `validate()` passes), which the installer never creates under a
  non-default `PREFIX`. `scan_pcaps` silently drops the missing dirs, `weighted_pick`
  returns `None`, the run loop sets `idle_no_pcaps` and sleeps forever, and `fire`/systemd
  see the unit as "up" (exit 3 idle, not a failure). The install hint does not mention the
  pcap paths.
  *Fix:* template `conf/replay.yaml` (both the fresh-install and `.example` branches)
  through the same `PREFIX` `sed`, or make `paths.pool`/`variants` default relative to the
  config dir.
  *Acceptance:* extend the install-layout smoke test to run under `PREFIX=/tmp/tl-test`
  and assert `paths.pool`/`variants` in the installed config point inside `PREFIX`.
  *Landed 0.4.1-beta.2:* `install.sh` templates `conf/replay.yaml` to `PREFIX` (both
  branches); `install-smoke.sh` asserts the installed config's pcap paths resolve
  inside `PREFIX`.

### P2 - correctness (latent / author footguns)

- **SP-3 [medium] Pinned `.250` device collides with the engineering-station slot.**
  `src/scenario/plant.rs:243`. `build_sealed_session` guards only the firewall slot
  (`network+1`) with a warn; the station slot (`roles::station_addr`, `network+250`
  clamped) is unguarded. The engine sources every OT action from the station address with
  a seed-derived `stable_mac`, so a device pinned at `.250` puts two MACs on one IP that
  the sensor cannot fuse. No shipped pack hits it (all pin low hosts).
  *Fix:* mirror the firewall guard for `roles::station_addr(&d.zone)`.

- **SP-4 [medium] Auto-assigned device collides with the station in small subnets.**
  `src/scenario/plant.rs:178`. `devices::next_free_in` reserves only the gateway, not the
  station slot; in a small zone (e.g. `/30`, where `station_addr` clamps to `network+2`)
  an ip-less device is placed on the station slot, reproducing SP-3 with no operator
  action. Shipped packs use `/24` with explicit ips, so latent.
  *Fix:* also exclude `roles::station_addr(net)` in `next_free_in` (or the plant caller).

- **SP-5 [medium] No test asserts per-event target resolution for shipped packs.**
  `tests/scenario_e2e.rs:238`. E2E asserts one signature per pack, so an orphaned target
  in a multi-event phase (e.g. stuxnet's S7-417 `s7_read`/`s7_stop` at `10.10.20.11`, or
  either ukraine RTU breaker command) ships green. Pairs with SP-1.
  *Fix:* per-pack test that loads plant + playbook and asserts every event target resolves;
  plus a negative test that pre-flight rejects an unresolved target.

### P3 - hardening, safety, and coverage

- **SP-6 [low] One oversized event bypasses `max_frames_per_burst`.**
  `src/scenario/engine.rs:112`. The per-burst cap is checked only between events, so the
  first event of a burst is emitted whole. `payload_hex` has no length bound, so a large
  `tristation_download` with `chunk: 1` builds an unbounded single microburst.
  *Fix:* bound `payload_hex` at load, or clamp `ev_frames` to the remaining burst budget.

- **SP-7 [low] Pack path fields escape the pack dir.** `src/config.rs:643`.
  `TargetCfg.plant`/`.playbook`/`.profiles` are `PathBuf`s joined onto `pack_dir`; an
  absolute or `../` value escapes the sandbox (file reads only; third-party packs only).
  *Fix:* reject `is_absolute()` or any `ParentDir` component in `validate()`, mirroring the
  scenario-name guard.

- **SP-8 [low] Scenario overlay can redefine `iface`/`net.*`.** `src/config.rs:845`.
  `net-setup` runs on the base config while the daemon runs the overlaid config; a pack
  that overlays `iface`/`net.*` desyncs the mirror from the tx port. Shipped packs do not.
  *Fix:* reject `iface`/`net.*` overrides in a target overlay, or have `net-setup` honor
  the same `--scenario` overlay.

- **SP-9 [low] Missing-pack `ExecStartPre` exits 1, not 78.** `systemd/ot-turbolaser@.service:22`.
  So a missing pack crash-loops to the StartLimit instead of failing clean on the first hit
  like the rest of the `EX_CONFIG`=78 lifecycle.
  *Fix:* exit 78 from the guard.

- **SP-10 [low] Unparseable pack `profiles.toml` degrades a CVE device silently.**
  `src/vuln/mod.rs:145`. `load_overlay` warns and falls back to the embedded set; a plant
  model defined only in the pack overlay (e.g. stuxnet's `SIMATIC S7-417 CPU`) then pins
  identity-only, protocol-none, CVE-less, and the SZL carries the literal model string
  instead of the real MLFB. `preflight` warns but does not fail.
  *Fix:* treat a declared-but-unparseable `profiles.toml` as fatal in pre-flight; flag a
  plant `model` that fails to resolve to a profile yet is not clearly identity-only.

- **SP-11 [low] MAC-uniqueness is enforced only inside `fabricate()`.**
  `src/simulate/devices.rs:78`. BOM (`bom_mac`) and capture-host MACs are unchecked, so the
  "no two assets ever share a MAC" claim in the commit/doc is statistical, not enforced
  (birthday-bounded, not reached at supported scale).
  *Fix:* thread the `used_macs` set through `enrich_plant` and capture-host registration,
  or soften the claim to "unique across the fabricated core fleet."

- **SP-12 [low] No full-plant MAC-uniqueness test.** `src/simulate/devices.rs:554`.
  The new test exercises only `fabricate()`. A BOM-MAC regression would pass CI.
  *Fix:* assert a MAC `HashSet` equals device count after `enrich_plant`, mirroring the
  existing IP-uniqueness assertion.

- **SP-13 [low] stuxnet C2 domain never asserted on the wire.** `tests/scenario_tshark.rs:126`.
  ukraine2015's real C2 IP is asserted; stuxnet ships `ioc_fidelity: real` with a
  domain-only IOC that no scenario-level test checks reaches the frames.
  *Fix:* assert the beacon domain (or its DNS query) in stuxnet frames, paralleling the
  ukraine2015 `ip.addr` check.

### Capability track (finish 0.4.1 features)

- **CAP-1 Pre-flight fidelity report.** `turbolaser check --scenario X` prints resolved
  targets, per-phase frame counts, and an IOC summary so an operator sees what will hit the
  wire before firing. Directly closes SP-1/SP-5 ergonomically.
- **CAP-2 Scenario authoring lint + docs.** A `turbolaser targets --validate <pack>` lint
  (target resolution, reserved gateway/station slots, path-field constraints, payload
  bounds) and a `docs/targets.md` section documenting the resolution and reserved-slot
  rules. Turns SP-1/SP-3/SP-4/SP-6/SP-7 into pack-author guardrails.
- **CAP-3 (stretch) New scenario content.** Additional pack(s) and/or richer playbook event
  types, scope TBD by product; gated on the P1/P2 guardrails landing first.

## Definition of done for 0.4.1 stable

- All P1 and P2 items closed; every P3 item either fixed or explicitly deferred with a
  one-line rationale in this file.
- Every shipped pack has a per-event target-resolution test and a tshark wire-signature
  assertion for its primary IOC.
- A non-default `PREFIX` install is validated end to end in CI.
- CHANGELOG carries a 0.4.1 entry; the beta ladder is promoted to rc, then to 0.4.1 stable
  on `main`, per the release cadence (main = stable, develop = pre-release ladder).

## Working state

- Consolidation branch: `claude/v0.4.1-beta.1` (this build), tagged `v0.4.1-beta.1`
  locally. It should become the new `develop` tip once reviewed.
