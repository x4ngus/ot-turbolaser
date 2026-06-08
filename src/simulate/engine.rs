//! The red-laser simulator engine.
//!
//! Holds the loaded session ledger and drives each iteration: fabricate a few
//! more devices (up to the caps), then build the identity burst -- an ARP
//! `is-at` reply that unions every asset MAC<->IP (see [`super::roles`]) plus the
//! fabricated devices' OT sessions carrying their model and CVEs -- written to a
//! tmpfs pcap the run loop fires. The ledger persists on change so the world
//! survives restarts.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::config::{Config, OversizePolicy, ZoneAffinity};
use crate::ledger::{self, CaptureHostRecord, DeviceRecord, Session};
use crate::oui::OuiDb;
use crate::pcapio::{self, Capture};
use crate::proto::frame::{parse_layout, L3Kind, L4Kind};
use crate::proto::l3;
use crate::scenario::engine::ScenarioEngine;
use crate::scenario::{guard_ledger_scenario, plant};
use crate::synth::{self, arp, cdp, dns, enip_identity, lldp, modbus_devid, s7_szl, snmp};
use crate::threat::{self, ThreatScheduler};
use crate::vuln::{DeviceProfile, ProfileProto, VulnDb};

use super::devices::{self, AllocParams};
use super::roles;
use super::zones;

/// How many new devices to fabricate per iteration until the cap, so the asset
/// set grows gradually like real discovery rather than all at once.
const FABRICATE_BATCH: usize = 16;
/// Emit switch beacons (LLDP/CDP) only every Nth identity burst. Real beacons
/// are periodic (tens of seconds), so emitting them every sub-second tick is
/// both unrealistic and a needless share of the wire; spacing them keeps OT
/// protocol traffic dominant in the sensor's packet-type histogram.
const BEACON_EVERY: u64 = 8;
/// Skip the L3 remap for captures larger than this, to bound tmpfs use.
const MAX_SHM_BYTES: u64 = 256 * 1024 * 1024;
/// Remap cache format version, embedded in the cache filename. Bump it whenever
/// the remap output changes so an upgrade invalidates every stale cached pcap
/// rather than replaying old content under an unchanged key. v2: plan-coherence
/// drop, canonical Ethernet header, and the over-MTU drop (v0.2.3). v3: capture
/// ARP thinned out of the remap (v0.2.5), and a defensive bump past any cache an
/// intermediate build wrote with a weaker (public-only) leak guard.
const REMAP_CACHE_VERSION: u32 = 3;

pub struct SimulatorEngine {
    pub ledger: Session,
    ledger_path: PathBuf,
    shm_dir: PathBuf,
    vuln: VulnDb,
    oui: OuiDb,
    params: AllocParams,
    identity_every: u64,
    /// Cycle (re-label zones) every Nth run when unsealed and saturated; 0 off.
    cycle_every: u64,
    synth_enabled: bool,
    device_identity: bool,
    switch_beacons: bool,
    /// North-south conduit traffic across adjacent Purdue zones.
    ns_enabled: bool,
    ns_cadence: u64,
    ns_max_per_pair: usize,
    /// True when the loaded ledger was committed by `plan --commit`: do not
    /// fabricate past it, just re-announce the sealed fleet.
    sealed: bool,
    threats_enabled: bool,
    external_cidrs: Vec<String>,
    scheduler: ThreatScheduler,
    sim_rng: ChaCha8Rng,
    /// Minimum seconds between identity bursts (periodic discovery cadence).
    announce_interval_secs: u64,
    /// Wall-clock time of the last identity burst, for the cadence gate.
    last_announce_unix: Option<u64>,
    /// Count of identity bursts so far, used as the per-scan nonce that varies
    /// each device's ephemeral client port (and thus its TCP ISN), so every burst
    /// is a fresh, separately parseable connection rather than an identical one
    /// the sensor folds and never re-reads.
    announce_count: u64,
    /// Models already warned about missing from the vuln DB, so the warning
    /// logs once rather than on every announce.
    warned_models: HashSet<String>,
    /// Running size estimate per remap cache dir, so a cache miss only walks the
    /// directory on first use or when the estimate crosses the budget, not every
    /// time.
    remap_cache_bytes: HashMap<PathBuf, u64>,
    dirty: bool,
    /// The active target-scenario overlay, present only under `--scenario`. Its
    /// playbook appends attack-action frames to each identity burst.
    scenario: Option<ScenarioEngine>,
}

impl SimulatorEngine {
    /// Construct from config, loading or creating the session ledger. The
    /// scenario RNG is seeded from the session seed so a run is reproducible.
    pub fn red(cfg: &Config, now_unix: u64) -> Result<Self, String> {
        // Purge the remap cache on startup. A cache hit is reused verbatim, so a
        // stale or poisoned entry an earlier binary wrote (for example one from a
        // build whose leak guard only blocked public addresses) must never
        // outlive the binary that produced it. The cache is a performance
        // optimisation, not correctness state, so dropping it is always safe.
        purge_remap_cache(&cfg.paths.shm_dir);
        // A scenario overlays the embedded CVE DB with its pack profiles so the
        // pinned plant's kit resolves; a generic run uses the configured DB.
        let vuln = match &cfg.target {
            Some(t) => VulnDb::load_overlay(&t.pack_dir.join(&t.profiles)),
            None => VulnDb::load(&cfg.oui_db.vuln_path),
        };
        let oui = OuiDb::load(&cfg.oui_db.path);
        let active = cfg.target.as_ref().map(|t| t.name.as_str());
        let session = match Session::load(&cfg.session.path)? {
            Some(s) => {
                // Never replay a scenario ledger generically, or a generic ledger
                // under a scenario.
                guard_ledger_scenario(s.scenario.as_deref(), active)?;
                s
            }
            None => match &cfg.target {
                // A scenario daemon with no committed plan builds (and persists)
                // the sealed plant from the pack, so `run --scenario X` works
                // without a prior `plan --scenario --commit`.
                Some(t) => {
                    let seed = cfg.session.seed.unwrap_or_else(rand::random);
                    let mut p =
                        plant::pin_from_pack(t, &vuln, &oui, seed, now_unix, &cfg.dns.domains)?;
                    p.max_assets = ledger::effective_asset_cap(cfg.synthesis.max_assets);
                    if let Err(e) = p.save_atomic(&cfg.session.path) {
                        log::warn!("could not persist scenario plant: {e}");
                    }
                    p
                }
                None => Session::new(cfg.session.seed.unwrap_or_else(rand::random), now_unix),
            },
        };
        let scenario = match &cfg.target {
            Some(t) => Some(ScenarioEngine::load(t, session.seed)?),
            None => None,
        };
        let sealed = session.sealed;
        let mut sim_rng = ChaCha8Rng::seed_from_u64(session.seed);
        let scheduler = ThreatScheduler::new(
            cfg.threats.min_interval_secs,
            cfg.threats.max_interval_secs,
            session.last_threat_unix,
            now_unix,
            &mut sim_rng,
        );
        Ok(Self {
            ledger_path: cfg.session.path.clone(),
            shm_dir: cfg.paths.shm_dir.clone(),
            vuln,
            oui,
            params: AllocParams {
                max_subnets: ledger::effective_subnet_cap(cfg.zones.max_subnets),
                max_devices: ledger::effective_device_cap(cfg.synthesis.max_devices),
                default_prefix: cfg.zones.default_prefix,
            },
            identity_every: cfg.synthesis.identity_every_n_runs.max(1),
            cycle_every: cfg.synthesis.cycle_every_n_runs,
            synth_enabled: cfg.synthesis.enabled,
            device_identity: cfg.synthesis.device_identity,
            switch_beacons: cfg.synthesis.switch_beacons,
            ns_enabled: cfg.north_south.enabled,
            ns_cadence: cfg.north_south.cadence_runs.max(1),
            ns_max_per_pair: cfg.north_south.max_flows_per_pair,
            sealed,
            threats_enabled: cfg.threats.enabled,
            external_cidrs: cfg.threats.external_cidrs.clone(),
            scheduler,
            sim_rng,
            announce_interval_secs: cfg.synthesis.announce_interval_secs,
            last_announce_unix: None,
            announce_count: 0,
            warned_models: HashSet::new(),
            remap_cache_bytes: HashMap::new(),
            dirty: false,
            scenario,
            ledger: session,
        })
    }

    pub fn ledger(&self) -> &Session {
        &self.ledger
    }

    /// The persisted session seed, logged so an entropy-seeded run can be pinned.
    pub fn seed(&self) -> u64 {
        self.ledger.seed
    }

    /// The active scenario's name, if any (startup log and heartbeat).
    pub fn scenario_name(&self) -> Option<&str> {
        self.scenario.as_ref().map(|s| s.name())
    }

    /// The active scenario's current phase label, if any.
    pub fn scenario_phase_label(&self) -> Option<String> {
        self.scenario.as_ref().map(|s| s.phase_label())
    }

    /// The active scenario's current phase id, if any.
    pub fn scenario_phase_id(&self) -> Option<String> {
        self.scenario.as_ref().map(|s| s.phase_id().to_string())
    }

    /// The active scenario's current ATT&CK-for-ICS technique ids.
    pub fn scenario_techniques(&self) -> Vec<String> {
        self.scenario
            .as_ref()
            .map(|s| s.techniques())
            .unwrap_or_default()
    }

    /// Remap a capture's hosts into the fabricated ledger zones and return the
    /// remapped pcap path. Capture hosts are reconciled into the plan: a known
    /// host reuses its stable asset, a new host fills spare zone capacity as a
    /// registered asset while the total stays under the asset cap, and surplus
    /// hosts ride existing fabricated devices, so the wire never exceeds the plan
    /// and never carries an un-remapped address. With no fabricated zones yet it
    /// falls back to the legacy seeded random remap.
    ///
    /// The result is cached, keyed on the capture, session seed, affinity, and
    /// the registry generation, so a repeat of the same capture reuses the cached
    /// pcap once the registry has stabilised; while the registry is still filling
    /// the generation changes and the remap is recomputed. The cache is
    /// byte-bounded.
    pub fn remap_into_session(
        &mut self,
        cfg: &Config,
        src: &Path,
        hints: &[Ipv4Net],
    ) -> Result<PathBuf, String> {
        let meta = std::fs::metadata(src).map_err(|e| format!("stat {}: {e}", src.display()))?;
        let size = meta.len();
        if size > cfg.l3.max_remap_bytes {
            return Err(format!(
                "capture is {size} bytes, over the {} byte remap ceiling",
                cfg.l3.max_remap_bytes
            ));
        }
        let to_disk = size > MAX_SHM_BYTES;
        if to_disk && cfg.l3.on_oversize == OversizePolicy::Skip {
            return Err(format!(
                "capture is {size} bytes, over the {MAX_SHM_BYTES} byte tmpfs budget (on_oversize=skip)"
            ));
        }
        // Remap cache layering, in one place so the moving parts are legible:
        //   1. location: tmpfs (`remap-cache`) normally, or a disk-spill dir
        //      beside the source for oversize captures, so the tmpfs budget holds.
        //   2. filename key: cache-format version + session seed + affinity +
        //      source mtime/size/stem + registry generation. A hit means the same
        //      capture, plan, and registry already produced this exact remap.
        //   3. registry generation bumps while the asset registry is still
        //      filling, so the remap recomputes until the plan stabilises, then
        //      reuses; the version invalidates every entry on an upgrade.
        //   4. size bound: an LRU eviction (oldest first, never the just-written
        //      file) keeps each dir under its byte budget, driven by a running
        //      estimate so a hit does not re-walk the directory.
        let cache_dir = if to_disk {
            src.parent()
                .map(|d| d.join(".turbolaser-remap"))
                .unwrap_or_else(|| self.shm_dir.clone())
        } else {
            self.shm_dir.join("remap-cache")
        };
        let stem = src
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("capture")
            .to_string();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let aff = match cfg.l3.zone_affinity {
            ZoneAffinity::Both => 'b',
            ZoneAffinity::Vendor => 'v',
            ZoneAffinity::Protocol => 'p',
            ZoneAffinity::Off => 'o',
        };
        let seed = self.ledger.seed;
        let cache_path = |generation: u64| {
            cache_dir.join(format!(
                "v{REMAP_CACHE_VERSION}.{seed:016x}.g{generation}.{aff}.{mtime}.{size}.{stem}.pcap"
            ))
        };
        // Cache hit at the current generation: identical (capture, seed,
        // affinity, registry) already remapped.
        let out = cache_path(self.ledger.registry_generation);
        if out.is_file() {
            return Ok(out);
        }

        let mut cap = pcapio::read(src)?;
        let zones = self.zone_targets();
        if zones.is_empty() {
            // No fabricated zones yet (first run, before fabrication): the legacy
            // seeded random remap, still safe (it drops any unsafe frame).
            l3::remap_capture(&mut cap, hints, seed, cfg.l3.remap_mac);
        } else {
            let groups = self.capture_groups(&cap, hints);
            let cap_assets = ledger::effective_asset_cap(cfg.synthesis.max_assets);
            let registered = self.registered_origins();
            let device_macs = self.device_mac_map();
            let budget = cap_assets.saturating_sub(self.ledger.total_wire_assets());
            let ctx = l3::ReconcileCtx {
                zones: &zones,
                affinity: cfg.l3.zone_affinity,
                seed,
                remap_mac: cfg.l3.remap_mac,
                registered: &registered,
                device_macs: &device_macs,
                budget,
            };
            let (_summary, new_assets) = l3::reconcile_capture_into_zones(&mut cap, &groups, &ctx);
            for a in new_assets {
                let rec = CaptureHostRecord {
                    origin_ip: a.origin.to_string(),
                    ip: a.ip.to_string(),
                    mac: l3::fmt_mac(a.mac),
                    vendor: a.vendor,
                    protocol: a.protocol,
                    purdue_level: a.purdue_level,
                    subnet_cidr: a.subnet_cidr,
                    hostname: None,
                    asset_type: None,
                };
                if self.ledger.register_capture_host(rec, cap_assets) {
                    self.dirty = true;
                }
            }
            self.persist_if_dirty();
        }
        // Drop frames over the link MTU so one oversized capture frame cannot
        // abort the tcpreplay run (EMSGSIZE) and send zero packets.
        let oversize = l3::drop_oversize_frames(&mut cap, cfg.l3.max_frame_bytes);
        if oversize > 0 {
            log::warn!(
                "remap: dropped {oversize} frame(s) over {} bytes from {}",
                cfg.l3.max_frame_bytes,
                src.display()
            );
        }
        // Thin the capture's own broadcast ARP unless explicitly asked to keep
        // it: the synth burst already supplies controlled MAC<->IP bindings, so
        // replaying capture ARP only floods the sensor. This keeps the wire an OT
        // protocol feed rather than an ARP broadcast.
        if !cfg.l3.replay_capture_arp {
            let arp = l3::drop_arp_frames(&mut cap);
            if arp > 0 {
                log::info!(
                    "remap: thinned {arp} capture ARP frame(s) from {}",
                    src.display()
                );
            }
        }
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("mkdir {}: {e}", cache_dir.display()))?;
        // Write under the (possibly advanced) generation so the next identical
        // pick reuses this file once the registry has settled.
        let out = cache_path(self.ledger.registry_generation);
        pcapio::write(&out, &cap)?;
        // The tmpfs cache is bounded by the shm budget; the disk-spill dir can
        // hold multi-gigabyte oversize remaps, so it gets its own larger bound
        // (two max-size remaps) rather than the tmpfs budget.
        let budget = if to_disk {
            cfg.l3.max_remap_bytes.saturating_mul(2)
        } else {
            MAX_SHM_BYTES
        };
        // Only walk the cache dir on first use or when the running estimate
        // crosses the budget; otherwise just add the byte count of what we wrote.
        let written = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        let projected = match self.remap_cache_bytes.get(&cache_dir) {
            Some(prev) => prev.saturating_add(written),
            None => dir_total_bytes(&cache_dir),
        };
        let total = if projected > budget {
            evict_remap_cache(&cache_dir, &out, budget)
        } else {
            projected
        };
        self.remap_cache_bytes.insert(cache_dir.clone(), total);
        if to_disk {
            log::info!(
                "remap disk-spill cache {} now {total} bytes (budget {budget})",
                cache_dir.display()
            );
        }
        Ok(out)
    }

    /// Origin IP (u32) -> assigned in-zone IP (u32) for every registered capture
    /// host: the lookup that keeps a host on the same asset every run.
    fn registered_origins(&self) -> HashMap<u32, u32> {
        self.ledger
            .capture_hosts
            .iter()
            .filter_map(|h| {
                let o = h.origin_ip.parse::<Ipv4Addr>().ok()?;
                let n = h.ip.parse::<Ipv4Addr>().ok()?;
                Some((u32::from(o), u32::from(n)))
            })
            .collect()
    }

    /// Fabricated device IP (u32) -> its real vendor MAC, so a surplus capture
    /// host that rides a device carries that device's MAC, not a stable LAA MAC.
    fn device_mac_map(&self) -> HashMap<u32, [u8; 6]> {
        self.ledger
            .devices
            .iter()
            .filter_map(|d| {
                let ip = d.ip.parse::<Ipv4Addr>().ok()?;
                Some((u32::from(ip), l3::parse_mac(&d.mac)))
            })
            .collect()
    }

    /// Per-zone remap targets from the ledger: each zone's CIDR, vendor, level,
    /// dominant device protocol, and the device IPs reserved within it.
    fn zone_targets(&self) -> Vec<l3::ZoneTarget> {
        self.ledger
            .subnets
            .iter()
            .filter_map(|s| {
                let net = s.cidr.parse::<Ipv4Net>().ok()?;
                let reserved: HashSet<Ipv4Addr> = self
                    .ledger
                    .devices
                    .iter()
                    .filter(|d| d.subnet_cidr == s.cidr)
                    .filter_map(|d| d.ip.parse::<Ipv4Addr>().ok())
                    .collect();
                let protocol = self
                    .ledger
                    .devices
                    .iter()
                    .find(|d| d.subnet_cidr == s.cidr)
                    .map(|d| d.protocol.clone());
                Some(l3::ZoneTarget {
                    net,
                    vendor: s.vendor.clone(),
                    purdue_level: s.purdue_level,
                    protocol,
                    reserved,
                })
            })
            .collect()
    }

    /// Classify the capture's host-groups by vendor (MAC OUI majority, reusing
    /// green-laser zone derivation) and dominant OT protocol (observed ports).
    fn capture_groups(&self, cap: &Capture, hints: &[Ipv4Net]) -> Vec<l3::CaptureGroup> {
        let proto = dominant_protocol_by_group(cap, hints);
        zones::derive_zones(cap, hints, &self.oui)
            .into_iter()
            .map(|z| l3::CaptureGroup {
                protocol: proto.get(&z.cidr).cloned(),
                net: z.cidr,
                purdue_level: z.purdue_level,
                vendor: z.vendor,
                hosts: z.device_ips,
            })
            .collect()
    }

    /// Persist the ledger if it changed since the last write.
    fn persist_if_dirty(&mut self) {
        if self.dirty {
            match self.ledger.save_atomic(&self.ledger_path) {
                Ok(()) => self.dirty = false,
                Err(e) => log::warn!("could not persist session ledger: {e}"),
            }
        }
    }

    /// One red-laser iteration: grow the device set within caps, then build the
    /// identity/beacon pcap for this round's announce window. `now` is the current
    /// unix time, for the periodic-discovery cadence. Returns the tmpfs pcap to
    /// fire, or None when there is nothing to announce this tick.
    pub fn red_tick(&mut self, run: u64, now: u64) -> Option<PathBuf> {
        if !self.synth_enabled {
            return None;
        }
        let mut added = 0;
        if self.device_identity && !self.sealed {
            let target =
                (self.ledger.device_count() + FABRICATE_BATCH).min(self.params.max_devices);
            added = devices::fabricate(
                &mut self.ledger,
                &self.vuln,
                &self.params,
                target,
                &mut self.sim_rng,
            );
            if added > 0 {
                self.dirty = true;
            }
        }

        // Once an unsealed feed is saturated (nothing new fabricated this tick),
        // refresh the zone names on a cadence so a long-running world keeps
        // evolving. Sealed (committed-plan) sessions stay frozen.
        if !self.sealed
            && self.cycle_every > 0
            && run > 0
            && run.is_multiple_of(self.cycle_every)
            && added == 0
            && self.ledger.subnet_count() > 0
        {
            let cycle_next = self.ledger.cycle + 1;
            self.ledger.rename_zones_new_cycle(|idx, s| {
                zones::name_zone(
                    s.vendor.as_deref(),
                    None,
                    s.purdue_level,
                    idx + cycle_next as usize * ledger::MAX_SUBNETS,
                )
            });
            self.dirty = true;
        }

        // Announce on a wall-clock cadence so the plant reads as periodic
        // discovery, not a scan storm. Each burst increments the nonce so every
        // device opens a fresh client connection (new ephemeral port and ISN),
        // giving the sensor a distinct, parseable scan to attribute rather than
        // one identical conversation it folds and never re-reads.
        let cadence_due = match self.last_announce_unix {
            Some(t) => now.saturating_sub(t) >= self.announce_interval_secs,
            None => true,
        };
        let frames = if run.is_multiple_of(self.identity_every) && cadence_due {
            self.last_announce_unix = Some(now);
            let nonce = self.announce_count;
            self.announce_count = self.announce_count.wrapping_add(1);
            let mut frames = self.build_assertions(run, nonce);
            // ARP is-at and the device identities come first (the MAC<->IP union
            // gate); a scenario's attack-action frames are appended after, so they
            // never perturb the associations the sensor forms this burst.
            if let Some(scenario) = self.scenario.as_mut() {
                let attack = scenario.phase_frames(&self.ledger, &self.vuln, nonce);
                frames.extend(attack);
            }
            frames
        } else {
            Vec::new()
        };
        self.persist_if_dirty();
        if frames.is_empty() {
            return None;
        }

        if let Err(e) = std::fs::create_dir_all(&self.shm_dir) {
            log::warn!("could not create shm dir {}: {e}", self.shm_dir.display());
            return None;
        }
        let out = self.shm_dir.join("synth-identity.pcap");
        match pcapio::write(&out, &synth::to_capture(frames)) {
            Ok(()) => Some(out),
            Err(e) => {
                log::warn!("could not write identity pcap: {e}");
                None
            }
        }
    }

    /// If an external-threat promotion is due, promote a genuine host in `file`
    /// to an external actor and return a tmpfs pcap to replay in its place.
    /// Sparse and rate-limited; the promotion is logged loudly and recorded in
    /// the ledger. Returns None when no promotion is due or possible.
    pub fn maybe_promote(&mut self, file: &Path, now: u64) -> Option<PathBuf> {
        if !self.threats_enabled || !self.scheduler.due(now) {
            return None;
        }
        let mut cap = match pcapio::read(file) {
            Ok(c) => c,
            Err(e) => {
                // Reschedule even on a read failure, so a persistently unreadable
                // candidate does not retry every iteration once the timer is due.
                self.scheduler.reschedule(now, &mut self.sim_rng);
                log::warn!("threat promotion: could not read {}: {e}", file.display());
                return None;
            }
        };
        let record = threat::promote_host(
            &mut cap,
            &self.external_cidrs,
            &self.oui,
            now,
            &mut self.sim_rng,
        );
        // Reschedule regardless, so a capture with no promotable host does not
        // retry every iteration.
        self.scheduler.reschedule(now, &mut self.sim_rng);
        let record = record?;
        if let Err(e) = std::fs::create_dir_all(&self.shm_dir) {
            log::warn!("could not create shm dir {}: {e}", self.shm_dir.display());
            return None;
        }
        let out = self.shm_dir.join("threat-promoted.pcap");
        if let Err(e) = pcapio::write(&out, &cap) {
            log::warn!("could not write threat pcap: {e}");
            return None;
        }
        log::warn!(
            "THREAT INJECTION: promoted host {} to external {} (mac {})",
            record.original_ip,
            record.external_ip,
            record.mac
        );
        self.ledger.promoted.push(record);
        self.ledger.last_threat_unix = Some(now);
        self.dirty = true;
        self.persist_if_dirty();
        Some(out)
    }

    /// Emit the identity burst the run loop fires as a paced pcap: first the ARP
    /// resolutions that union every asset's MAC<->IP, then the fabricated
    /// devices' OT sessions that carry their model and CVEs.
    ///
    /// THE UNION. A passive sensor forms the MAC<->IP union from an
    /// authoritative ARP `is-at` REPLY -- an asset answering "my IP is at my MAC"
    /// (the sender fields of an `oper=2` frame) -- not from a `who-has` request's
    /// sender, and not from an L3/L7 frame's source MAC. The v0.2.21 field export
    /// was the controlled proof: every asset broadcast its own who-has request,
    /// yet the ONLY assets that unioned were the per-zone `.250` stations -- the
    /// sole emitters of an is-at reply. So every asset must be the OWNER of a
    /// resolution. The `roles` graph arranges that as small control cells (a
    /// local master polls a few members, which answer and bind; one member
    /// resolves the master, which answers and binds), so the solicitation is
    /// organically distributed -- never the one-host subnet sweep the sensor
    /// suppresses as a scan, which cost every prior iteration its bindings.
    ///
    /// THE IDENTITY. Each fabricated device additionally answers its zone station
    /// as an OT server (`assert_identity`), so the sensor parses its model/CVEs
    /// and tracks it as an endpoint -- a second authoritative signal beyond the
    /// is-at reply. Capture hosts carry no synthetic session (a generic one was
    /// parsed into separate, address-less phantom assets in v0.2.20); they bind
    /// by their is-at reply alone. `nonce` (the burst counter) varies each client
    /// ephemeral port so every burst is a fresh, separately parseable connection.
    fn build_assertions(&mut self, run: u64, nonce: u64) -> Vec<Vec<u8>> {
        if !self.device_identity {
            return Vec::new();
        }
        let seed = self.ledger.seed;
        // Beacons are periodic, so emit them only every Nth burst, keeping OT
        // protocol traffic the dominant packet type the sensor sees.
        let switch_beacons = self.switch_beacons && run.is_multiple_of(BEACON_EVERY);
        let mut frames = Vec::new();

        // Union every asset (device and capture host) MAC<->IP via the
        // authoritative is-at reply it emits as the OWNER of a cell resolution.
        // Emitted first, so the binding is on the wire before the asset's OT
        // session or any replayed background L3 that could otherwise let the
        // sensor classify its MAC as a forwarder and split it.
        for e in roles::arp_edges(&self.ledger, seed) {
            let (req, rep) = arp::resolve(e.requester.mac, e.requester.ip, e.owner.mac, e.owner.ip);
            frames.push(req);
            frames.push(rep);
        }

        // Sustain each fabricated device's parsed OT identity (model + CVEs) as
        // the server answering its zone station, so the sensor reads its CVEs and
        // tracks it as an OT endpoint. Capture hosts get no synthetic session.
        let mut missing: Vec<String> = Vec::new();
        {
            let devices = &self.ledger.devices;
            let vuln = &self.vuln;
            // Each zone's engineering-station identity, derived once per zone
            // rather than re-parsing the CIDR for every device in it.
            let mut station: HashMap<&str, (Ipv4Addr, [u8; 6])> = HashMap::new();
            for dev in devices {
                // Identity-only assets (HMI/EWS/firewall/historian/server) carry
                // no CVE and no OT session: they bind via their ARP is-at reply and
                // are named by DNS below. Only a CVE-bearing device asserts an OT
                // identity, whose whole purpose is to deliver the model->CVE match.
                if dev.cves.is_empty() {
                    continue;
                }
                // Own the profile so a missing-model fallback and the vuln borrow
                // do not tangle; a device is never silently dropped.
                let profile = match vuln.by_model(&dev.model) {
                    Some(p) => p.clone(),
                    None => {
                        missing.push(dev.model.clone());
                        fallback_profile(dev)
                    }
                };
                if let Ok(dev_ip) = dev.ip.parse::<Ipv4Addr>() {
                    let dev_mac = l3::parse_mac(&dev.mac);
                    let (client_ip, client_mac) =
                        *station.entry(dev.subnet_cidr.as_str()).or_insert_with(|| {
                            let ip = roles::station_addr(&dev.subnet_cidr);
                            (ip, l3::stable_mac(seed, u32::from(ip)))
                        });
                    frames.extend(assert_identity(
                        dev_mac,
                        dev_ip,
                        client_ip,
                        client_mac,
                        &profile,
                        switch_beacons,
                        nonce,
                    ));
                }
            }
        }
        for model in missing {
            if self.warned_models.insert(model.clone()) {
                log::warn!("no vuln profile for model {model:?}; announcing a generic identity");
            }
        }

        // DNS: each zone's firewall (.1) answers an A-record for the zone's named
        // devices, binding hostname<->IP. MAC<->IP is already unioned by the ARP
        // above, so this completes the MAC<->IP<->DNS picture. Plain UDP/53, so it
        // cannot affect the ARP shape the sensor associates from. Names cover the
        // ~85% of core devices assigned at plan time; the rest stay unnamed.
        let resolvers: HashMap<&str, (Ipv4Addr, [u8; 6])> = self
            .ledger
            .devices
            .iter()
            .filter(|d| d.asset_type.as_deref() == Some("Firewall"))
            .filter_map(|d| {
                let ip = d.ip.parse::<Ipv4Addr>().ok()?;
                Some((d.subnet_cidr.as_str(), (ip, l3::parse_mac(&d.mac))))
            })
            .collect();
        for dev in &self.ledger.devices {
            let Some(hostname) = dev.hostname.as_deref() else {
                continue;
            };
            let Some(&(rip, rmac)) = resolvers.get(dev.subnet_cidr.as_str()) else {
                continue;
            };
            let Ok(dip) = dev.ip.parse::<Ipv4Addr>() else {
                continue;
            };
            if dip == rip {
                continue; // the resolver does not query itself
            }
            let dmac = l3::parse_mac(&dev.mac);
            let port = ephemeral_port(nonce, dip);
            let qid = (nonce ^ u64::from(u32::from(dip))) as u16;
            let (q, r) = dns::exchange(dmac, rmac, dip, rip, port, qid, hostname, dip);
            frames.push(q);
            frames.push(r);
        }

        // North-south conduit traffic: a supervisory client in a higher zone polls
        // a CVE-bearing device in an adjacent lower zone, forwarded by a conduit
        // whose MAC is the L2 source the sensor sees (so neither endpoint IP binds
        // to it). Bounded and on a cadence; rendered by the same OT-session builder
        // as an identity, never ARP, so the union gate is untouched.
        if self.ns_enabled && run.is_multiple_of(self.ns_cadence) {
            let by_ip: HashMap<Ipv4Addr, &DeviceRecord> = self
                .ledger
                .devices
                .iter()
                .filter_map(|d| d.ip.parse::<Ipv4Addr>().ok().map(|ip| (ip, d)))
                .collect();
            for c in roles::north_south_crossings(&self.ledger, seed, self.ns_max_per_pair) {
                let Some(dev) = by_ip.get(&c.south_ip) else {
                    continue;
                };
                let profile = match self.vuln.by_model(&dev.model) {
                    Some(p) => p.clone(),
                    None => fallback_profile(dev),
                };
                // The south device is the server; the conduit MAC forwards the
                // north client's poll (client_ip = north, client_mac = conduit).
                frames.extend(assert_identity(
                    c.south_mac,
                    c.south_ip,
                    c.north_ip,
                    c.conduit_mac,
                    &profile,
                    false,
                    nonce,
                ));
            }
        }
        frames
    }
}

/// The protocol-assertion frames for one asset (a fabricated device or a capture
/// host), keyed on the profile's carrier protocol. Driven entirely by the
/// `profile` (its model/firmware/vendor and protocol-specific fields), so the
/// same builder serves the CVE-bearing fabricated fleet and the generic-identity
/// capture hosts: the asset is the session SERVER, answering its per-zone
/// engineering station, which is what makes the sensor track it as an OT endpoint
/// and union its MAC<->IP. A bare host seen only in replayed background traffic
/// never unions; a parsed OT session is the lever (the fabricated devices and the
/// CDP/LLDP-speaking switches prove it). The caller passes the zone's stable
/// engineering-station identity (`client_ip`/`client_mac`), one client per zone
/// so its MAC is never multi-homed across zones (which a sensor cannot fuse).
/// `nonce` (the burst counter) varies the client ephemeral port per scan so each
/// burst is a fresh connection the sensor parses anew.
fn assert_identity(
    mac: [u8; 6],
    ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    client_mac: [u8; 6],
    profile: &DeviceProfile,
    switch_beacons: bool,
    nonce: u64,
) -> Vec<Vec<u8>> {
    let client_port = ephemeral_port(nonce, ip);

    let mut frames: Vec<Vec<u8>> = Vec::new();

    match profile.protocol {
        ProfileProto::Enip => {
            let (major, minor) = synth::parse_version(&profile.firmware);
            let product_name = profile
                .enip_product_name
                .as_deref()
                .unwrap_or(&profile.model);
            let id = enip_identity::EnipIdentity {
                vendor_id: profile.enip_vendor_id.unwrap_or(0),
                device_type: profile.enip_device_type.unwrap_or(0),
                product_code: profile.enip_product_code.unwrap_or(0),
                revision_major: major,
                revision_minor: minor,
                serial: u32::from(ip),
                product_name: clamp_str(product_name, 255),
            };
            let (a, b) = enip_identity::exchange(client_mac, mac, client_ip, ip, client_port, &id);
            frames.push(a);
            frames.push(b);
        }
        ProfileProto::Modbus => {
            let id = modbus_devid::ModbusDevId {
                vendor_name: clamp_str(
                    profile
                        .modbus_vendor_name
                        .as_deref()
                        .unwrap_or(&profile.vendor),
                    255,
                ),
                product_code: clamp_str(
                    profile
                        .modbus_product_code
                        .as_deref()
                        .unwrap_or(&profile.model),
                    255,
                ),
                revision: clamp_str(
                    profile
                        .modbus_revision
                        .as_deref()
                        .unwrap_or(&profile.firmware),
                    255,
                ),
            };
            frames.extend(modbus_devid::exchange(
                client_mac,
                mac,
                client_ip,
                ip,
                client_port,
                1,
                &id,
            ));
        }
        ProfileProto::S7 => {
            let (major, minor) = synth::parse_version(&profile.firmware);
            let order = profile.s7_order_number.as_deref().unwrap_or(&profile.model);
            frames.extend(s7_szl::exchange(
                client_mac,
                mac,
                client_ip,
                ip,
                client_port,
                order,
                major,
                minor,
            ));
        }
        ProfileProto::SwitchSnmp => {
            let descr = profile
                .sys_descr
                .clone()
                .unwrap_or_else(|| format!("{} {}", profile.vendor, profile.model));
            // Switches send LLDP and CDP on the beacon cadence (realistic switch
            // colour; on a multi-MAC chassis these are also what the sensor uses
            // to merge the MACs into one asset). A zone-edge firewall or router
            // emits no such discovery beacons, so suppress them for those classes.
            // The MAC<->IP union comes from the every-burst SNMP session plus the
            // ARP request in build_assertions.
            let infra = matches!(
                profile.asset_class.as_deref(),
                Some("Firewall") | Some("Router")
            );
            if switch_beacons && !infra {
                frames.push(lldp::beacon(
                    mac,
                    ip,
                    clamp_str(&profile.model, 511),
                    clamp_str(&descr, 511),
                ));
                frames.push(cdp::beacon(
                    mac,
                    ip,
                    &profile.model,
                    &profile.firmware,
                    &profile.model,
                ));
            }
            // Bind an explicit firmware-version OID when a firmware string is
            // present, so the sensor reads a firmware detection event rather than
            // scraping sysDescr. A profile may override the default OID.
            let firmware_oid = (!profile.firmware.is_empty()).then(|| {
                profile
                    .firmware_oid
                    .as_deref()
                    .unwrap_or(snmp::DEFAULT_FIRMWARE_OID)
            });
            let firmware = (!profile.firmware.is_empty()).then_some(profile.firmware.as_str());
            let request_id = 0x1000u32.wrapping_add(nonce as u32 & 0x0fff);
            let (a, b) = snmp::exchange(
                client_mac,
                mac,
                client_ip,
                ip,
                client_port,
                "public",
                request_id,
                &descr,
                profile.sys_object_id.as_deref(),
                firmware_oid,
                firmware,
            );
            frames.push(a);
            frames.push(b);
        }
    }
    frames
}

/// A fresh ephemeral client port in the IANA dynamic range (49152-65535), varied
/// per burst (`nonce`) and per device, so every scan is a distinct 4-tuple a
/// sensor treats as a new conversation to parse, instead of the same connection
/// re-opening forever (which it folds into one record and never re-reads).
fn ephemeral_port(nonce: u64, dev_ip: Ipv4Addr) -> u16 {
    let h = nonce.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ u64::from(u32::from(dev_ip)).wrapping_mul(0x2545_F491_4F6C_DD1D);
    49152 + (h % 16384) as u16
}

/// Truncate a string to at most `max` bytes at a char boundary, so a builder's
/// fixed-width length field can never disagree with the bytes that follow.
fn clamp_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A generic profile recovered from a ledger device whose model is no longer in
/// the vuln DB, so it still announces a coherent (if unspecific) identity.
fn fallback_profile(dev: &DeviceRecord) -> DeviceProfile {
    DeviceProfile {
        vendor: dev.vendor.clone(),
        model: dev.model.clone(),
        firmware: dev.firmware.clone(),
        protocol: proto_from_str(&dev.protocol),
        purdue_level: 0,
        oui: None,
        cves: dev.cves.clone(),
        enip_vendor_id: None,
        enip_device_type: None,
        enip_product_code: None,
        enip_product_name: None,
        s7_order_number: None,
        sys_descr: None,
        sys_object_id: None,
        firmware_oid: None,
        asset_class: None,
        modbus_vendor_name: None,
        modbus_product_code: None,
        modbus_revision: None,
    }
}

fn proto_from_str(s: &str) -> ProfileProto {
    match s {
        "modbus" => ProfileProto::Modbus,
        "s7" => ProfileProto::S7,
        "switch_snmp" => ProfileProto::SwitchSnmp,
        _ => ProfileProto::Enip,
    }
}

/// Remove the tmpfs remap-cache directory and its contents. Called on engine
/// startup so a cached remap an earlier binary wrote (reused verbatim on a hit)
/// can never outlive the binary that produced it. Best effort.
fn purge_remap_cache(shm_dir: &Path) {
    let dir = shm_dir.join("remap-cache");
    if dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            log::warn!("could not purge remap cache {}: {e}", dir.display());
        }
    }
}

/// Total size in bytes of the regular files directly in `dir`. 0 if unreadable.
fn dir_total_bytes(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Indices to evict, oldest first, to bring `total` within `budget`, never
/// evicting `keep_idx`. Pure, so the policy is unit-tested without a filesystem.
fn plan_evictions(
    entries: &[(u64, std::time::SystemTime)],
    total: u64,
    budget: u64,
    keep_idx: usize,
) -> Vec<usize> {
    if total <= budget {
        return Vec::new();
    }
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].1); // oldest first
    let mut remaining = total;
    let mut evict = Vec::new();
    for i in order {
        if remaining <= budget {
            break;
        }
        if i == keep_idx {
            continue;
        }
        remaining -= entries[i].0;
        evict.push(i);
    }
    evict
}

/// Bound a remap cache directory: evict oldest entries (never the one just
/// written) until the total size is within `budget`. Returns the resulting
/// total. Reads the directory once; the per-miss check that decides whether to
/// call this at all is the engine's running size estimate.
fn evict_remap_cache(dir: &Path, keep: &Path, budget: u64) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut meta: Vec<(u64, std::time::SystemTime)> = Vec::new();
    let mut total = 0u64;
    let mut keep_idx = usize::MAX;
    for e in rd.flatten() {
        let Ok(m) = e.metadata() else {
            continue;
        };
        if !m.is_file() {
            continue;
        }
        let path = e.path();
        if path == keep {
            keep_idx = paths.len();
        }
        total += m.len();
        meta.push((m.len(), m.modified().unwrap_or(std::time::UNIX_EPOCH)));
        paths.push(path);
    }
    for i in plan_evictions(&meta, total, budget, keep_idx) {
        if std::fs::remove_file(&paths[i]).is_ok() {
            total -= meta[i].0;
        }
    }
    total
}

/// Dominant OT protocol per capture host-group, voted from observed service
/// ports, so e.g. a Modbus conversation is mapped into a Modicon zone.
fn dominant_protocol_by_group(cap: &Capture, hints: &[Ipv4Net]) -> HashMap<Ipv4Net, String> {
    let mut votes: HashMap<Ipv4Net, HashMap<&'static str, usize>> = HashMap::new();
    for p in &cap.packets {
        let Some(l) = parse_layout(&p.data) else {
            continue;
        };
        if l.l3_kind != L3Kind::Ipv4 || l.l4_kind == L4Kind::Other || p.data.len() < l.l4 + 4 {
            continue;
        }
        let sport = u16::from_be_bytes([p.data[l.l4], p.data[l.l4 + 1]]);
        let dport = u16::from_be_bytes([p.data[l.l4 + 2], p.data[l.l4 + 3]]);
        let Some(proto) =
            l3::ot_protocol_for_port(dport).or_else(|| l3::ot_protocol_for_port(sport))
        else {
            continue;
        };
        if p.data.len() < l.l3 + 20 {
            continue;
        }
        let src = Ipv4Addr::new(
            p.data[l.l3 + 12],
            p.data[l.l3 + 13],
            p.data[l.l3 + 14],
            p.data[l.l3 + 15],
        );
        let dst = Ipv4Addr::new(
            p.data[l.l3 + 16],
            p.data[l.l3 + 17],
            p.data[l.l3 + 18],
            p.data[l.l3 + 19],
        );
        for h in [src, dst] {
            *votes
                .entry(l3::subnet_of(h, hints))
                .or_default()
                .entry(proto)
                .or_default() += 1;
        }
    }
    votes
        .into_iter()
        .filter_map(|(g, m)| {
            m.into_iter()
                .max_by_key(|&(_, c)| c)
                .map(|(proto, _)| (g, proto.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(proto: &str, model: &str, fw: &str) -> DeviceRecord {
        DeviceRecord {
            ip: "10.20.0.5".into(),
            mac: "00:0e:8c:11:22:33".into(),
            vendor: "Siemens AG".into(),
            model: model.into(),
            firmware: fw.into(),
            protocol: proto.into(),
            cves: vec!["CVE-2020-15782".into()],
            subnet_cidr: "10.20.0.0/24".into(),
            hostname: None,
            asset_type: None,
        }
    }

    /// Render a device's identity through the profile-driven builder (a test shim
    /// for the old per-device entry point; the engine now calls assert_identity
    /// directly for both fabricated devices and capture hosts).
    fn identity_for(
        d: &DeviceRecord,
        p: &DeviceProfile,
        switch_beacons: bool,
        seed: u64,
        nonce: u64,
    ) -> Vec<Vec<u8>> {
        let client_ip = roles::station_addr(&d.subnet_cidr);
        let client_mac = l3::stable_mac(seed, u32::from(client_ip));
        assert_identity(
            l3::parse_mac(&d.mac),
            d.ip.parse().unwrap(),
            client_ip,
            client_mac,
            p,
            switch_beacons,
            nonce,
        )
    }

    #[test]
    fn mac_and_station_addr() {
        assert_eq!(
            l3::parse_mac("00:0e:8c:11:22:33"),
            [0x00, 0x0E, 0x8C, 0x11, 0x22, 0x33]
        );
        assert_eq!(
            roles::station_addr("10.20.0.0/24"),
            Ipv4Addr::new(10, 20, 0, 250)
        );
    }

    #[test]
    fn enip_device_yields_request_and_reply() {
        let vuln = VulnDb::embedded().unwrap();
        let p = vuln
            .profiles()
            .iter()
            .find(|p| p.protocol == ProfileProto::Enip)
            .unwrap();
        let d = dev("enip", &p.model, &p.firmware);
        let frames = identity_for(&d, p, true, 1337, 0);
        assert_eq!(frames.len(), 2, "List Identity request + reply over UDP");
        // List Identity is UDP/44818 (ethertype 0x0800); the device binds from
        // the connectionless reply, which a sensor reads without a session.
        assert_eq!(u16::from_be_bytes([frames[0][12], frames[0][13]]), 0x0800);
        assert_eq!(
            crate::proto::frame::parse_layout(&frames[0])
                .unwrap()
                .l4_kind,
            crate::proto::frame::L4Kind::Udp,
            "ENIP discovery is over UDP"
        );
        for f in &frames {
            assert!(crate::proto::frame::parse_layout(f).is_some());
        }
    }

    #[test]
    fn switch_device_emits_beacons_and_snmp() {
        let vuln = VulnDb::embedded().unwrap();
        let p = vuln
            .profiles()
            .iter()
            .find(|p| p.protocol == ProfileProto::SwitchSnmp)
            .unwrap();
        let d = dev("switch_snmp", &p.model, &p.firmware);
        // The switch branch emits LLDP + CDP on the beacon cadence plus the SNMP
        // fetch; the MAC<->IP binding ARP is added per asset in build_assertions.
        assert_eq!(
            identity_for(&d, p, true, 1337, 0).len(),
            4,
            "lldp + cdp + snmp request/response"
        );
        assert_eq!(
            identity_for(&d, p, false, 1337, 0).len(),
            2,
            "beacons off leaves the snmp exchange"
        );
    }

    #[test]
    fn ephemeral_port_varies_per_burst_and_device() {
        let a = Ipv4Addr::new(10, 0, 0, 5);
        let b = Ipv4Addr::new(10, 0, 0, 6);
        assert!(
            (49152..=65535).contains(&ephemeral_port(0, a)),
            "in the IANA dynamic range"
        );
        assert_ne!(
            ephemeral_port(0, a),
            ephemeral_port(1, a),
            "a new burst uses a new ephemeral port for the same device"
        );
        assert_ne!(
            ephemeral_port(0, a),
            ephemeral_port(0, b),
            "distinct devices use distinct ports within a burst"
        );
    }

    #[test]
    fn successive_scans_are_distinct_connections() {
        let vuln = VulnDb::embedded().unwrap();
        let p = vuln
            .profiles()
            .iter()
            .find(|p| p.protocol == ProfileProto::Modbus)
            .unwrap();
        let d = dev("modbus", &p.model, &p.firmware);
        // Two bursts (nonce 0 and 1) must differ on the wire, so a sensor sees a
        // fresh connection each scan rather than one it folds and never re-reads.
        let burst0 = identity_for(&d, p, false, 1337, 0);
        let burst1 = identity_for(&d, p, false, 1337, 1);
        assert_ne!(
            burst0, burst1,
            "successive scans are distinct connections (fresh port and ISN)"
        );
    }

    #[test]
    fn plan_evictions_removes_oldest_until_within_budget_and_keeps_keep() {
        use std::time::{Duration, UNIX_EPOCH};
        let at = |s| UNIX_EPOCH + Duration::from_secs(s);
        // Four 10-byte files, ages 1..4 (index 0 oldest); keep is the oldest.
        let entries = vec![(10, at(1)), (10, at(2)), (10, at(3)), (10, at(4))];
        let evict = plan_evictions(&entries, 40, 25, 0);
        // Drop oldest non-keep until <= 25: idx 1 then idx 2 (total 20).
        assert_eq!(evict, vec![1, 2]);
        assert!(
            !evict.contains(&0),
            "the just-written file is never evicted"
        );
        // Under budget evicts nothing.
        assert!(plan_evictions(&entries, 20, 25, 0).is_empty());
    }
}
