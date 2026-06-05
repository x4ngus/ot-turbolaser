//! The red-laser simulator engine.
//!
//! Holds the loaded session ledger and drives each iteration: fabricate a few
//! more devices (up to the caps), then render a rotating window of devices as
//! genuine protocol-assertion exchanges written to a tmpfs pcap the run loop
//! fires. The ledger persists on change so the world survives restarts.

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
use crate::synth::{self, arp, cdp, enip_identity, lldp, modbus_devid, s7_szl, snmp};
use crate::threat::{self, ThreatScheduler};
use crate::vuln::{DeviceProfile, ProfileProto, VulnDb};

use super::devices::{self, AllocParams};
use super::zones;

/// How many new devices to fabricate per iteration until the cap, so the asset
/// set grows gradually like real discovery rather than all at once.
const FABRICATE_BATCH: usize = 16;
/// How many devices to re-announce per iteration, cycling through the ledger, so
/// each identity pcap stays small.
const ANNOUNCE_WINDOW: usize = 256;
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
    /// True when the loaded ledger was committed by `plan --commit`: do not
    /// fabricate past it, just re-announce the sealed fleet.
    sealed: bool,
    threats_enabled: bool,
    external_cidrs: Vec<String>,
    scheduler: ThreatScheduler,
    sim_rng: ChaCha8Rng,
    announce_cursor: usize,
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
}

impl SimulatorEngine {
    /// Construct from config, loading or creating the session ledger. The
    /// scenario RNG is seeded from the session seed so a run is reproducible.
    pub fn red(cfg: &Config, now_unix: u64) -> Self {
        // Purge the remap cache on startup. A cache hit is reused verbatim, so a
        // stale or poisoned entry an earlier binary wrote (for example one from a
        // build whose leak guard only blocked public addresses) must never
        // outlive the binary that produced it. The cache is a performance
        // optimisation, not correctness state, so dropping it is always safe.
        purge_remap_cache(&cfg.paths.shm_dir);
        let vuln = VulnDb::load(&cfg.oui_db.vuln_path);
        let oui = OuiDb::load(&cfg.oui_db.path);
        let session = Session::load(&cfg.session.path)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                Session::new(cfg.session.seed.unwrap_or_else(rand::random), now_unix)
            });
        let sealed = session.sealed;
        let mut sim_rng = ChaCha8Rng::seed_from_u64(session.seed);
        let scheduler = ThreatScheduler::new(
            cfg.threats.min_interval_secs,
            cfg.threats.max_interval_secs,
            session.last_threat_unix,
            now_unix,
            &mut sim_rng,
        );
        Self {
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
            sealed,
            threats_enabled: cfg.threats.enabled,
            external_cidrs: cfg.threats.external_cidrs.clone(),
            scheduler,
            sim_rng,
            announce_cursor: 0,
            announce_interval_secs: cfg.synthesis.announce_interval_secs,
            last_announce_unix: None,
            announce_count: 0,
            warned_models: HashSet::new(),
            remap_cache_bytes: HashMap::new(),
            dirty: false,
            ledger: session,
        }
    }

    pub fn ledger(&self) -> &Session {
        &self.ledger
    }

    /// The persisted session seed, logged so an entropy-seeded run can be pinned.
    pub fn seed(&self) -> u64 {
        self.ledger.seed
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
                    mac: fmt_mac(a.mac),
                    vendor: a.vendor,
                    protocol: a.protocol,
                    purdue_level: a.purdue_level,
                    subnet_cidr: a.subnet_cidr,
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
                Some((u32::from(ip), parse_mac(&d.mac)))
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
            self.build_assertions(run, nonce)
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

    /// Render a window of devices as an ARP resolution (so the sensor binds the
    /// device MAC<->IP, which it does not infer from L3 frame Ethernet headers)
    /// followed by the protocol-assertion session; `nonce` varies the client
    /// ephemeral port (and ISN) so each burst is a fresh, separately parseable
    /// connection. Every capture host is resolved the same way. Switch beacons
    /// fire only on a cadence. Each ARP exchange is one conversation at the
    /// sensor (request + reply bind both ends), so this binds every asset without
    /// being an ARP broadcast in the record histogram.
    fn build_assertions(&mut self, run: u64, nonce: u64) -> Vec<Vec<u8>> {
        let n = self.ledger.devices.len();
        if n == 0 || !self.device_identity {
            return Vec::new();
        }
        // Beacons are periodic, so emit them only every Nth burst, keeping OT
        // protocol traffic the dominant packet type the sensor sees.
        let switch_beacons = self.switch_beacons && run.is_multiple_of(BEACON_EVERY);
        let seed = self.ledger.seed;
        let start = self.announce_cursor % n;
        let count = ANNOUNCE_WINDOW.min(n);
        let mut frames = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let devices = &self.ledger.devices;
            let vuln = &self.vuln;
            for k in 0..count {
                let dev = &devices[(start + k) % n];
                // Bind the device MAC<->IP with a gratuitous ARP response,
                // broadcast: "dev_ip is at dev_mac". The sensor associates
                // MAC<->IP ONLY from an ARP response (the source MAC of an L3
                // frame is untrusted, it could be a router), and this unsolicited
                // broadcast announcement is the form it associates from most
                // reliably on a SPAN.
                if let Ok(dev_ip) = dev.ip.parse::<Ipv4Addr>() {
                    frames.push(arp::gratuitous(parse_mac(&dev.mac), dev_ip));
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
                frames.extend(assertions_for_device(
                    dev,
                    &profile,
                    switch_beacons,
                    seed,
                    nonce,
                ));
            }
        }
        for model in missing {
            if self.warned_models.insert(model.clone()) {
                log::warn!("no vuln profile for model {model:?}; announcing a generic identity");
            }
        }
        // Bind every capture host the same way, a gratuitous ARP response
        // announcing "ip is at mac". Its replayed L3 traffic does not bind it (the
        // sensor does not infer MAC<->IP from L3 frame Ethernet headers), so
        // without this ARP it stays IP-only.
        for h in &self.ledger.capture_hosts {
            if let Ok(ip) = h.ip.parse::<Ipv4Addr>() {
                frames.push(arp::gratuitous(parse_mac(&h.mac), ip));
            }
        }
        self.announce_cursor = (start + count) % n;
        frames
    }
}

/// The protocol-assertion frames for one device, keyed on its carrier protocol.
/// `seed` derives the per-zone engineering-station MAC so the querying client is
/// a distinct, coherent asset in each zone rather than one MAC multi-homed across
/// every zone (which a sensor cannot fuse, and which polluted attribution).
/// `nonce` (the burst counter) varies the client ephemeral port per scan so each
/// burst is a fresh connection the sensor parses anew, instead of one identical
/// 4-tuple it folds into a single conversation and never re-reads (which left the
/// device unattributed and surfacing only as an L2/MAC-only asset).
fn assertions_for_device(
    dev: &DeviceRecord,
    profile: &DeviceProfile,
    switch_beacons: bool,
    seed: u64,
    nonce: u64,
) -> Vec<Vec<u8>> {
    let Ok(dev_ip) = dev.ip.parse::<Ipv4Addr>() else {
        return Vec::new();
    };
    let dev_mac = parse_mac(&dev.mac);
    let client_ip = client_addr(&dev.subnet_cidr);
    // A stable per-zone engineering-station MAC, not one global CLIENT_MAC across
    // all zones: a multi-homed MAC is unbindable and pollutes the asset model.
    let client_mac = l3::stable_mac(seed, u32::from(client_ip));
    // A fresh ephemeral client port per scan, so each connection is a distinct
    // 4-tuple (one ephemeral port per connection, like a real client).
    let client_port = ephemeral_port(nonce, dev_ip);

    let mut frames: Vec<Vec<u8>> = Vec::new();

    match profile.protocol {
        ProfileProto::Enip => {
            let (major, minor) = parse_version(&dev.firmware);
            let product_name = profile.enip_product_name.as_deref().unwrap_or(&dev.model);
            let id = enip_identity::EnipIdentity {
                vendor_id: profile.enip_vendor_id.unwrap_or(0),
                device_type: profile.enip_device_type.unwrap_or(0),
                product_code: profile.enip_product_code.unwrap_or(0),
                revision_major: major,
                revision_minor: minor,
                serial: u32::from(dev_ip),
                product_name: clamp_str(product_name, 255),
            };
            let (a, b) =
                enip_identity::exchange(client_mac, dev_mac, client_ip, dev_ip, client_port, &id);
            frames.push(a);
            frames.push(b);
        }
        ProfileProto::Modbus => {
            let id = modbus_devid::ModbusDevId {
                vendor_name: clamp_str(
                    profile.modbus_vendor_name.as_deref().unwrap_or(&dev.vendor),
                    255,
                ),
                product_code: clamp_str(
                    profile.modbus_product_code.as_deref().unwrap_or(&dev.model),
                    255,
                ),
                revision: clamp_str(
                    profile.modbus_revision.as_deref().unwrap_or(&dev.firmware),
                    255,
                ),
            };
            frames.extend(modbus_devid::exchange(
                client_mac,
                dev_mac,
                client_ip,
                dev_ip,
                client_port,
                1,
                &id,
            ));
        }
        ProfileProto::S7 => {
            let (major, minor) = parse_version(&dev.firmware);
            let order = profile.s7_order_number.as_deref().unwrap_or(&dev.model);
            frames.extend(s7_szl::exchange(
                client_mac,
                dev_mac,
                client_ip,
                dev_ip,
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
                .unwrap_or_else(|| format!("{} {}", dev.vendor, dev.model));
            // Switches send LLDP and CDP on the beacon cadence (realistic switch
            // colour; on a multi-MAC chassis these are also what the sensor uses
            // to merge the MACs into one asset). MAC<->IP binding still comes from
            // the ARP response emitted for every asset in build_assertions.
            if switch_beacons {
                frames.push(lldp::beacon(
                    dev_mac,
                    dev_ip,
                    clamp_str(&dev.model, 511),
                    clamp_str(&descr, 511),
                ));
                frames.push(cdp::beacon(
                    dev_mac,
                    dev_ip,
                    &dev.model,
                    &dev.firmware,
                    &dev.model,
                ));
            }
            let request_id = 0x1000u32.wrapping_add(nonce as u32 & 0x0fff);
            let (a, b) = snmp::exchange(
                client_mac,
                dev_mac,
                client_ip,
                dev_ip,
                client_port,
                "public",
                request_id,
                &descr,
                profile.sys_object_id.as_deref(),
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

fn parse_mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, part) in s.split(':').enumerate().take(6) {
        m[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    m
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// First two integer groups of a firmware string as a major/minor pair.
fn parse_version(fw: &str) -> (u8, u8) {
    let mut groups = fw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().unwrap_or(0).min(255) as u8);
    (groups.next().unwrap_or(0), groups.next().unwrap_or(0))
}

/// The engineering station address within a subnet (network + 250, clamped to
/// the last usable host so it never lands outside a small subnet).
fn client_addr(subnet_cidr: &str) -> Ipv4Addr {
    subnet_cidr
        .parse::<Ipv4Net>()
        .ok()
        .map(|n| {
            let host_bits = 32 - u32::from(n.prefix_len());
            let last_usable = if host_bits >= 1 {
                (1u32 << host_bits).saturating_sub(2)
            } else {
                0
            };
            let offset = 250.min(last_usable);
            Ipv4Addr::from(u32::from(n.network()) + offset)
        })
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 250))
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
        }
    }

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("V4.2.1"), (4, 2));
        assert_eq!(parse_version("20.011"), (20, 11));
        assert_eq!(parse_version("07.0.02"), (7, 0));
        assert_eq!(parse_version("none"), (0, 0));
    }

    #[test]
    fn mac_and_client_addr() {
        assert_eq!(
            parse_mac("00:0e:8c:11:22:33"),
            [0x00, 0x0E, 0x8C, 0x11, 0x22, 0x33]
        );
        assert_eq!(client_addr("10.20.0.0/24"), Ipv4Addr::new(10, 20, 0, 250));
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
        let frames = assertions_for_device(&d, p, true, 1337, 0);
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
            assertions_for_device(&d, p, true, 1337, 0).len(),
            4,
            "lldp + cdp + snmp request/response"
        );
        assert_eq!(
            assertions_for_device(&d, p, false, 1337, 0).len(),
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
        let burst0 = assertions_for_device(&d, p, false, 1337, 0);
        let burst1 = assertions_for_device(&d, p, false, 1337, 1);
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
