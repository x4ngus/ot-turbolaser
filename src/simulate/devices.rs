//! Device fabrication: fill zones with simulated, CVE-bearing devices.
//!
//! Pure and deterministic given the session seed. The `plan` dry-run and the
//! red-laser run loop share this allocator, so a preview matches what the
//! daemon will fabricate. Hard caps live in the ledger; `AllocParams` only
//! lowers them.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::ledger::{DeviceRecord, Session, SubnetRecord};
use crate::oui::{self, OuiDb};
use crate::proto::l3;
use crate::vuln::{DeviceProfile, ProfileProto, VulnDb};

use super::bom::{self, AssetType};
use super::zones::{family_of, name_zone};

#[derive(Clone, Copy)]
pub struct AllocParams {
    pub max_subnets: usize,
    pub max_devices: usize,
    pub default_prefix: u8,
}

/// Fabricate zones and devices into the session until it holds `target` devices
/// (bounded by the device cap). Returns the number of devices added.
pub fn fabricate(
    session: &mut Session,
    vuln: &VulnDb,
    params: &AllocParams,
    target: usize,
    rng: &mut ChaCha8Rng,
) -> usize {
    if vuln.is_empty() {
        return 0;
    }
    let target = target.min(params.max_devices);
    // Build the used-IP set once and update it as we go, so fabrication is
    // O(devices) rather than rebuilding the whole set on every IP probe.
    let mut used: HashSet<Ipv4Addr> = session.used_ips();
    let mut added = 0;
    while session.device_count() < target {
        let Some(cidr) = choose_or_create_subnet(session, vuln, params, &used, rng) else {
            break; // nothing has room and no new zone can be created
        };
        let Ok(net) = cidr.parse::<Ipv4Net>() else {
            break;
        };
        let Some(ip) = next_free_in(net, &used) else {
            continue; // picked subnet filled up; retry selection
        };
        let zone_vendor = session
            .subnets
            .iter()
            .find(|s| s.cidr == cidr)
            .and_then(|s| s.vendor.clone());
        let profile = pick_profile(vuln, zone_vendor.as_deref(), rng);
        let mac = make_mac(profile, rng);
        let rec = DeviceRecord {
            ip: ip.to_string(),
            mac: l3::fmt_mac(mac),
            vendor: profile.vendor.clone(),
            model: profile.model.clone(),
            firmware: profile.firmware.clone(),
            protocol: profile.protocol.as_str().to_string(),
            cves: profile.cves.clone(),
            subnet_cidr: cidr,
            hostname: None,
            asset_type: Some(asset_label_for_proto(profile.protocol).into()),
        };
        if !session.add_device(rec) {
            break; // device hard cap reached
        }
        used.insert(ip);
        added += 1;
    }
    added
}

/// The next host in `net` not already in `used`, skipping network+1 which is
/// reserved for the zone-edge firewall gateway (added by `enrich_plant`). Pure
/// helper so fabrication keeps one growing set instead of rebuilding it.
fn next_free_in(net: Ipv4Net, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    let gateway = Ipv4Addr::from(u32::from(net.network()).saturating_add(1));
    net.hosts().find(|ip| *ip != gateway && !used.contains(ip))
}

/// A subnet CIDR with a free host, creating a new zone when there is room and
/// either nothing has space or to add variety. None when all subnets are full
/// and the subnet cap blocks new zones.
fn choose_or_create_subnet(
    session: &mut Session,
    vuln: &VulnDb,
    params: &AllocParams,
    used: &HashSet<Ipv4Addr>,
    rng: &mut ChaCha8Rng,
) -> Option<String> {
    let cidrs: Vec<String> = session.subnets.iter().map(|s| s.cidr.clone()).collect();
    let with_room: Vec<String> = cidrs
        .into_iter()
        .filter(|c| {
            c.parse::<Ipv4Net>()
                .ok()
                .and_then(|n| next_free_in(n, used))
                .is_some()
        })
        .collect();

    let can_create = session.subnet_count() < params.max_subnets;
    // Force a new zone until every carrier protocol has one, so the plant covers
    // enip/modbus/s7/switch_snmp rather than whatever vendors random picks seeded.
    // After coverage, the existing variety logic applies.
    let need_coverage =
        session.subnet_count() < protocols_present(vuln).len().min(params.max_subnets);
    let create = can_create && (need_coverage || with_room.is_empty() || rng.gen_bool(0.15));
    if create {
        if let Some(cidr) = create_zone(session, vuln, params, rng) {
            return Some(cidr);
        }
    }
    if with_room.is_empty() {
        None
    } else {
        Some(with_room[rng.gen_range(0..with_room.len())].clone())
    }
}

/// A core fabrication profile: a controller or switch, not a BOM-placed
/// firewall/router (those are tagged with `asset_class` and reached only by the
/// bill of materials in `enrich_plant`, never by core zone/device fabrication).
fn is_core(p: &DeviceProfile) -> bool {
    p.asset_class.is_none()
}

/// The distinct carrier protocols present among the core profiles, in a fixed
/// order, so zone creation can cycle them and guarantee every protocol is
/// represented. Infrastructure (firewall/router) profiles are excluded so they
/// never seed a core zone.
fn protocols_present(vuln: &VulnDb) -> Vec<ProfileProto> {
    [
        ProfileProto::Enip,
        ProfileProto::Modbus,
        ProfileProto::S7,
        ProfileProto::SwitchSnmp,
    ]
    .into_iter()
    .filter(|&p| vuln.by_protocol(p).any(is_core))
    .collect()
}

fn create_zone(
    session: &mut Session,
    vuln: &VulnDb,
    params: &AllocParams,
    rng: &mut ChaCha8Rng,
) -> Option<String> {
    let existing: Vec<Ipv4Net> = session
        .subnets
        .iter()
        .filter_map(|s| s.cidr.parse().ok())
        .collect();
    let net = l3::fresh_subnet(params.default_prefix, &existing, rng);
    // Cycle the zone's carrier protocol by zone index so the plant covers every
    // protocol, then pick a vendor within that protocol for variety.
    let protos = protocols_present(vuln);
    if protos.is_empty() {
        return None;
    }
    let proto = protos[session.subnet_count() % protos.len()];
    let candidates: Vec<&DeviceProfile> = vuln.by_protocol(proto).filter(|p| is_core(p)).collect();
    if candidates.is_empty() {
        return None;
    }
    let profile = candidates[rng.gen_range(0..candidates.len())];
    let idx = session.subnet_count();
    let name = name_zone(
        Some(&profile.vendor),
        Some(&family_of(&profile.model)),
        profile.purdue_level,
        idx,
    );
    let rec = SubnetRecord {
        cidr: net.to_string(),
        zone_name: name,
        purdue_level: profile.purdue_level,
        vendor: Some(profile.vendor.clone()),
        domain: None,
    };
    session.add_subnet(rec).then(|| net.to_string())
}

/// Create up to `count` Purdue L3 (operations / DCS) zones above the L1/L2
/// control zones, bounded by the subnet cap. These hold servers and operator
/// stations, not controllers, so the plant shows a distributed control system
/// over the field zones. The zones are created empty here; `enrich_plant` fills
/// each from the L3 bill of materials (historian, OPC/domain/app servers,
/// operator workstations, a firewall). Deterministic given the rng.
pub fn create_l3_zones(
    session: &mut Session,
    params: &AllocParams,
    count: usize,
    rng: &mut ChaCha8Rng,
) {
    // Server-room makers, so the zone label and BOM OUIs read believably.
    const L3_VENDORS: [&str; 3] = ["VMware", "Dell", "Hewlett Packard"];
    for _ in 0..count {
        if session.subnet_count() >= params.max_subnets {
            break;
        }
        let existing: Vec<Ipv4Net> = session
            .subnets
            .iter()
            .filter_map(|s| s.cidr.parse().ok())
            .collect();
        let net = l3::fresh_subnet(params.default_prefix, &existing, rng);
        let idx = session.subnet_count();
        let vendor = L3_VENDORS[idx % L3_VENDORS.len()];
        let name = name_zone(Some(vendor), None, 3, idx);
        let rec = SubnetRecord {
            cidr: net.to_string(),
            zone_name: name,
            purdue_level: 3,
            vendor: Some(vendor.to_string()),
            domain: None,
        };
        session.add_subnet(rec);
    }
}

/// Prefer a core profile matching the zone vendor; fall back to any core profile.
/// Infrastructure (firewall/router) profiles are excluded: they are placed by the
/// bill of materials, not fabricated into the core fleet.
fn pick_profile<'a>(
    vuln: &'a VulnDb,
    vendor: Option<&str>,
    rng: &mut ChaCha8Rng,
) -> &'a DeviceProfile {
    let core: Vec<&DeviceProfile> = vuln.profiles().iter().filter(|p| is_core(p)).collect();
    if let Some(v) = vendor {
        let matches: Vec<&DeviceProfile> = core.iter().copied().filter(|p| p.vendor == v).collect();
        if !matches.is_empty() {
            return matches[rng.gen_range(0..matches.len())];
        }
    }
    core[rng.gen_range(0..core.len())]
}

/// A MAC from the profile's vendor OUI plus random low bytes, so devices in a
/// zone are distinct assets while keeping the vendor-identifying prefix. With no
/// vendor OUI, fall back to a globally-administered unicast OUI (not a
/// locally-administered one): a passive sensor ignores LAA MACs for
/// asset association, so an LAA address would never bind MAC<->IP and the device
/// would stay MAC-less.
fn make_mac(profile: &DeviceProfile, rng: &mut ChaCha8Rng) -> [u8; 6] {
    match profile.oui_prefix() {
        Some(oui) => [oui[0], oui[1], oui[2], rng.gen(), rng.gen(), rng.gen()],
        None => {
            // Globally administered (0x02 clear), unicast (0x01 clear).
            let b0 = rng.gen::<u8>() & 0xFC;
            [b0, rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()]
        }
    }
}

/// The asset-class label for a fabricated, CVE-bearing device: switches speak
/// SNMP, everything else is a controller.
fn asset_label_for_proto(p: ProfileProto) -> &'static str {
    if p == ProfileProto::SwitchSnmp {
        AssetType::Switch.label()
    } else {
        AssetType::Controller.label()
    }
}

/// The asset class of an existing record, for choosing its hostname style.
fn asset_type_of(dev: &DeviceRecord) -> AssetType {
    match dev.asset_type.as_deref() {
        Some("Switch") => AssetType::Switch,
        Some("Router") => AssetType::Router,
        Some("HMI") => AssetType::Hmi,
        Some("EWS") => AssetType::EngWorkstation,
        Some("Historian") => AssetType::Historian,
        Some("Firewall") => AssetType::Firewall,
        Some("Server") => AssetType::Server,
        _ => AssetType::Controller,
    }
}

/// A vendor name to brand a BOM asset class so its OUI resolves to a believable
/// maker. Controllers/switches come from vuln profiles, not here.
fn bom_vendor(asset_type: AssetType) -> &'static str {
    match asset_type {
        AssetType::Firewall => "Fortinet",
        AssetType::Switch => "Cisco Systems",
        AssetType::Router => "Cisco Systems",
        AssetType::Hmi => "Advantech",
        AssetType::EngWorkstation => "Dell",
        AssetType::Historian => "Hewlett Packard",
        AssetType::Server => "VMware",
        AssetType::Controller => "",
    }
}

/// A believable model string for a BOM asset class.
fn bom_model(asset_type: AssetType) -> &'static str {
    match asset_type {
        AssetType::Firewall => "FortiGate 40F",
        AssetType::Switch => "Catalyst IE-3300",
        AssetType::Router => "ISR 4321",
        AssetType::Hmi => "WebOP-2070T",
        AssetType::EngWorkstation => "OptiPlex 7090",
        AssetType::Historian => "ProLiant DL360",
        AssetType::Server => "ESXi Host",
        AssetType::Controller => "",
    }
}

fn ip_u32(s: &str) -> u32 {
    s.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0)
}

/// Whether a core device is DNS-named: ~85% deterministic by (seed, ip), so the
/// named subset is stable across runs and the sensor's hostname coverage holds.
fn is_named(seed: u64, ip: u32) -> bool {
    let h = (seed ^ u64::from(ip).wrapping_mul(0x9E37_79B9_7F4A_7C15)).rotate_left(31);
    (h % 100) < 85
}

/// A deterministic vuln profile for a BOM infrastructure class ("Firewall" or
/// "Router"), chosen by the profile's `asset_class` so a zone's firewall/router
/// carries a real CVE-bearing SNMP identity (sysDescr + sysObjectID + firmware
/// OID). None when the DB has no such profile, so fabrication falls back to an
/// identity-only generic record. Indexed by (seed, ip) so the choice is stable.
fn infra_profile<'a>(
    vuln: &'a VulnDb,
    class: &str,
    seed: u64,
    ip: u32,
) -> Option<&'a DeviceProfile> {
    let matches: Vec<&DeviceProfile> = vuln
        .profiles()
        .iter()
        .filter(|p| p.asset_class.as_deref() == Some(class))
        .collect();
    if matches.is_empty() {
        return None;
    }
    let h = (seed ^ u64::from(ip).wrapping_mul(0x0100_0000_01B3)).rotate_left(17) as usize;
    Some(matches[h % matches.len()])
}

/// A believable, stable MAC for a BOM asset: the class vendor's OUI (or the IT
/// pool when the vendor has none registered) with low bytes derived per-IP.
fn bom_mac(oui: &OuiDb, vendor: &str, seed: u64, ip: u32) -> [u8; 6] {
    let salt = u64::from(ip);
    let prefix = oui
        .oui_for_vendor(vendor, salt)
        .unwrap_or_else(|| oui::it_pool_oui(salt));
    let low = l3::stable_mac(seed, ip);
    [prefix[0], prefix[1], prefix[2], low[3], low[4], low[5]]
}

/// Tag each zone with a DNS domain so the plant reads as one site spanning zones.
/// Most zones share the primary domain (a single cross-zone identity a sensor
/// correlates from the FQDN suffix); a minority take a secondary for variety.
/// Deterministic from the seed and zone index (no RNG draw, so it does not
/// perturb fabrication), run at plan time before `enrich_plant` so the names are
/// sealed as FQDNs. No-op when `domains` is empty (DNS stays single-label).
pub fn assign_domains(session: &mut Session, domains: &[String], seed: u64) {
    if domains.is_empty() {
        return;
    }
    for (i, sn) in session.subnets.iter_mut().enumerate() {
        let h = (seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).rotate_left(29);
        let domain = if domains.len() == 1 || (h % 100) < 75 {
            domains[0].clone()
        } else {
            domains[1 + (i % (domains.len() - 1))].clone()
        };
        sn.domain = Some(domain);
    }
}

/// After controllers are fabricated, name ~85% of the core devices and add each
/// zone's bill of materials -- a zone-edge firewall at .1 plus HMI / engineering
/// workstation / historian / server / router identities by Purdue level. The
/// firewall and router carry a real CVE-bearing SNMP identity (from a vuln
/// profile tagged with their asset class); the rest are identity-only (they bind
/// via their ARP is-at reply and are named by DNS, not by an OT session).
/// Deterministic from the seed. Run at plan time so the supporting cast and the
/// names are sealed into the ledger the daemon replays verbatim.
pub fn enrich_plant(session: &mut Session, vuln: &VulnDb, oui: &OuiDb, seed: u64) {
    let zones: Vec<(usize, String, u8, Option<String>)> = session
        .subnets
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.cidr.clone(), s.purdue_level, s.domain.clone()))
        .collect();

    // 1) Name ~85% of the fabricated core devices, per zone in IP order so a
    //    device's hostname index is stable.
    for (zi, cidr, _lvl, domain) in &zones {
        let mut idxs: Vec<usize> = session
            .devices
            .iter()
            .enumerate()
            .filter(|(_, d)| &d.subnet_cidr == cidr)
            .map(|(i, _)| i)
            .collect();
        idxs.sort_by_key(|&i| ip_u32(&session.devices[i].ip));
        for (n, &di) in idxs.iter().enumerate() {
            if is_named(seed, ip_u32(&session.devices[di].ip)) {
                let vendor = session.devices[di].vendor.clone();
                let at = asset_type_of(&session.devices[di]);
                session.devices[di].hostname = Some(bom::hostname_for(
                    Some(&vendor),
                    at,
                    *zi,
                    n,
                    domain.as_deref(),
                ));
            }
        }
    }

    // 2) Add each zone's BOM as identity-only assets (the firewall claims the
    //    reserved .1; the rest take the next free host).
    let mut used: HashSet<Ipv4Addr> = session.used_ips();
    for (zi, cidr, lvl, domain) in &zones {
        let Ok(net) = cidr.parse::<Ipv4Net>() else {
            continue;
        };
        for (atype, count) in bom::bom_for(*lvl) {
            for n in 0..count {
                let ip = if atype == AssetType::Firewall {
                    super::roles::firewall_addr(cidr)
                } else {
                    match next_free_in(net, &used) {
                        Some(ip) => ip,
                        None => break,
                    }
                };
                if used.contains(&ip) {
                    continue;
                }
                // A CVE-bearing infrastructure class (firewall/router) takes a real
                // SNMP profile so it carries CVEs and a firmware identity; every
                // other class is identity-only (named by DNS, bound by ARP).
                let cve_profile = atype
                    .cve_bearing()
                    .then(|| infra_profile(vuln, atype.label(), seed, u32::from(ip)))
                    .flatten();
                let (vendor, model, firmware, protocol, cves) = match cve_profile {
                    Some(p) => (
                        p.vendor.clone(),
                        p.model.clone(),
                        p.firmware.clone(),
                        p.protocol.as_str().to_string(),
                        p.cves.clone(),
                    ),
                    None => (
                        bom_vendor(atype).to_string(),
                        bom_model(atype).to_string(),
                        "1.0".to_string(),
                        "none".to_string(),
                        Vec::new(),
                    ),
                };
                let mac = bom_mac(oui, &vendor, seed, u32::from(ip));
                let rec = DeviceRecord {
                    ip: ip.to_string(),
                    mac: l3::fmt_mac(mac),
                    vendor: vendor.clone(),
                    model,
                    firmware,
                    protocol,
                    cves,
                    subnet_cidr: cidr.clone(),
                    // Name the same ~85% share as the core devices, so overall DNS
                    // coverage lands in the 80-90% band (not every asset has a name).
                    hostname: is_named(seed, u32::from(ip)).then(|| {
                        bom::hostname_for(Some(&vendor), atype, *zi, n, domain.as_deref())
                    }),
                    asset_type: Some(atype.label().to_string()),
                };
                if session.add_device(rec) {
                    used.insert(ip);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Session;
    use rand::SeedableRng;
    use std::collections::HashSet;

    fn db() -> VulnDb {
        VulnDb::embedded().unwrap()
    }

    #[test]
    fn respects_caps_and_unique_ips() {
        let params = AllocParams {
            max_subnets: 4,
            max_devices: 50,
            default_prefix: 24,
        };
        let mut s = Session::new(123, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let added = fabricate(&mut s, &db(), &params, 50, &mut rng);
        assert_eq!(added, 50);
        assert_eq!(s.device_count(), 50);
        assert!(s.subnet_count() >= 1 && s.subnet_count() <= 4);
        let ips: HashSet<&String> = s.devices.iter().map(|d| &d.ip).collect();
        assert_eq!(ips.len(), s.devices.len(), "IPs are unique");
        for d in &s.devices {
            assert!(!d.cves.is_empty(), "{} carries a CVE", d.model);
            assert!(s.subnets.iter().any(|z| z.cidr == d.subnet_cidr));
        }
    }

    #[test]
    fn device_cap_bounds_the_target() {
        let params = AllocParams {
            max_subnets: 10,
            max_devices: 5,
            default_prefix: 24,
        };
        let mut s = Session::new(1, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let added = fabricate(&mut s, &db(), &params, 1000, &mut rng);
        assert_eq!(added, 5, "the device cap bounds an over-large target");
    }

    #[test]
    fn fabrication_covers_all_protocols() {
        let params = AllocParams {
            max_subnets: 10,
            max_devices: 64,
            default_prefix: 24,
        };
        let mut s = Session::new(1337, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(1337);
        fabricate(&mut s, &db(), &params, 64, &mut rng);
        let protos: HashSet<&str> = s.devices.iter().map(|d| d.protocol.as_str()).collect();
        for p in ["enip", "modbus", "s7", "switch_snmp"] {
            assert!(
                protos.contains(p),
                "a 64-device fleet covers {p}: {protos:?}"
            );
        }
    }

    #[test]
    fn deterministic_for_same_seed() {
        let params = AllocParams {
            max_subnets: 5,
            max_devices: 30,
            default_prefix: 24,
        };
        let run = || {
            let mut s = Session::new(7, 0);
            let mut rng = ChaCha8Rng::seed_from_u64(7);
            fabricate(&mut s, &db(), &params, 30, &mut rng);
            s.devices
                .iter()
                .map(|d| (d.ip.clone(), d.model.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn enrich_adds_bom_firewall_and_names_most_devices() {
        let params = AllocParams {
            max_subnets: 10,
            max_devices: 300,
            default_prefix: 24,
        };
        let mut s = Session::new(2024, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(2024);
        let controllers = fabricate(&mut s, &db(), &params, 64, &mut rng);
        let cve_before = s.devices.iter().filter(|d| !d.cves.is_empty()).count();

        enrich_plant(&mut s, &db(), &OuiDb::embedded(), 2024);

        // Every zone has a firewall at .1, plus an HMI and an engineering station.
        for sn in &s.subnets {
            let net: Ipv4Net = sn.cidr.parse().unwrap();
            let gw = Ipv4Addr::from(u32::from(net.network()) + 1).to_string();
            assert!(
                s.devices
                    .iter()
                    .any(|d| d.ip == gw && d.asset_type.as_deref() == Some("Firewall")),
                "zone {} has a firewall at .1",
                sn.cidr
            );
            for t in ["HMI", "EWS"] {
                assert!(
                    s.devices
                        .iter()
                        .any(|d| d.subnet_cidr == sn.cidr && d.asset_type.as_deref() == Some(t)),
                    "zone {} has a {t}",
                    sn.cidr
                );
            }
        }
        // Before the BOM, the CVE-bearing set is exactly the fabricated core.
        assert_eq!(
            cve_before, controllers,
            "the fabricated core carries the CVEs"
        );
        // The zone-edge firewall is now CVE-bearing (a real SNMP identity); the
        // operator-facing classes (HMI/EWS/historian/server) stay identity-only.
        let firewalls: Vec<&DeviceRecord> = s
            .devices
            .iter()
            .filter(|d| d.asset_type.as_deref() == Some("Firewall"))
            .collect();
        assert!(!firewalls.is_empty());
        assert!(
            firewalls
                .iter()
                .all(|d| !d.cves.is_empty() && d.protocol == "switch_snmp"),
            "every zone firewall carries a CVE over SNMP"
        );
        let cve_after = s.devices.iter().filter(|d| !d.cves.is_empty()).count();
        assert!(cve_after > cve_before, "the BOM firewalls/routers add CVEs");
        for d in &s.devices {
            if matches!(
                d.asset_type.as_deref(),
                Some("HMI") | Some("EWS") | Some("Historian") | Some("Server")
            ) {
                assert!(d.cves.is_empty(), "{} is identity-only", d.ip);
            }
        }
        // Most core assets are named (BOM all named, controllers ~85%).
        let named = s.devices.iter().filter(|d| d.hostname.is_some()).count();
        assert!(
            named * 10 > s.devices.len() * 6,
            "most assets are DNS-named: {named}/{}",
            s.devices.len()
        );
        // IPs stay unique once the BOM is in.
        let ips: HashSet<&String> = s.devices.iter().map(|d| &d.ip).collect();
        assert_eq!(ips.len(), s.devices.len(), "IPs unique including the BOM");
    }

    #[test]
    fn l3_zones_are_server_identity_only() {
        let params = AllocParams {
            max_subnets: 16,
            max_devices: 400,
            default_prefix: 24,
        };
        let mut s = Session::new(99, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        fabricate(
            &mut s,
            &db(),
            &AllocParams {
                max_subnets: 10,
                ..params
            },
            64,
            &mut rng,
        );
        create_l3_zones(&mut s, &params, 3, &mut rng);
        enrich_plant(&mut s, &db(), &OuiDb::embedded(), 99);

        let l3: HashSet<String> = s
            .subnets
            .iter()
            .filter(|z| z.purdue_level == 3)
            .map(|z| z.cidr.clone())
            .collect();
        assert_eq!(l3.len(), 3, "three L3 (DCS) zones created");
        assert!(s.subnet_count() <= 16, "within the raised subnet cap");

        let l3_devs: Vec<&DeviceRecord> = s
            .devices
            .iter()
            .filter(|d| l3.contains(&d.subnet_cidr))
            .collect();
        assert!(!l3_devs.is_empty(), "L3 zones are populated by the BOM");
        for d in &l3_devs {
            assert_ne!(
                d.asset_type.as_deref(),
                Some("Controller"),
                "L3 zones hold servers/hosts, not controllers"
            );
            // The zone-edge firewall and router carry CVEs; servers and operator
            // stations are identity-only.
            match d.asset_type.as_deref() {
                Some("Firewall") | Some("Router") => {
                    assert!(!d.cves.is_empty(), "L3 {} carries a CVE", d.ip)
                }
                _ => assert!(d.cves.is_empty(), "L3 asset {} is identity-only", d.ip),
            }
        }
        assert!(
            l3_devs
                .iter()
                .any(|d| d.asset_type.as_deref() == Some("Server")),
            "an L3 DCS zone is server-heavy"
        );
    }
}
