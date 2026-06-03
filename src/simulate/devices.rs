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
use crate::proto::l3;
use crate::vuln::{DeviceProfile, VulnDb};

use super::zones::{family_of, name_zone};

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
            mac: fmt_mac(mac),
            vendor: profile.vendor.clone(),
            model: profile.model.clone(),
            firmware: profile.firmware.clone(),
            protocol: profile.protocol.as_str().to_string(),
            cves: profile.cves.clone(),
            subnet_cidr: cidr,
        };
        if !session.add_device(rec) {
            break; // device hard cap reached
        }
        used.insert(ip);
        added += 1;
    }
    added
}

/// The next host in `net` not already in `used`. Pure helper so fabrication
/// keeps one growing set instead of rebuilding it on every probe.
fn next_free_in(net: Ipv4Net, used: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    net.hosts().find(|ip| !used.contains(ip))
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
    let create = can_create && (with_room.is_empty() || rng.gen_bool(0.15));
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
    let profile = vuln.pick(rng.gen_range(0..vuln.len()))?;
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
    };
    session.add_subnet(rec).then(|| net.to_string())
}

/// Prefer a profile matching the zone vendor; fall back to any profile.
fn pick_profile<'a>(
    vuln: &'a VulnDb,
    vendor: Option<&str>,
    rng: &mut ChaCha8Rng,
) -> &'a DeviceProfile {
    if let Some(v) = vendor {
        let matches: Vec<&DeviceProfile> =
            vuln.profiles().iter().filter(|p| p.vendor == v).collect();
        if !matches.is_empty() {
            return matches[rng.gen_range(0..matches.len())];
        }
    }
    vuln.pick(rng.gen_range(0..vuln.len()))
        .expect("vuln db is non-empty here")
}

/// A MAC from the profile's vendor OUI plus random low bytes, so devices in a
/// zone are distinct assets while keeping the vendor-identifying prefix.
fn make_mac(profile: &DeviceProfile, rng: &mut ChaCha8Rng) -> [u8; 6] {
    let oui = profile.oui_prefix().unwrap_or([0x02, 0x00, 0x00]);
    [oui[0], oui[1], oui[2], rng.gen(), rng.gen(), rng.gen()]
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
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
}
