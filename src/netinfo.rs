//! Read-only network-datapath inspection for `net-show`.
//!
//! `pewpew` reports the daemon's own view (tx_packets it counted off the replay
//! port). That cannot tell an operator whether frames actually *egress* the
//! replay port and *arrive* at the sensor port through the SPAN mirror. This
//! module reads the kernel's own counters and link state from `/sys/class/net`
//! and turns a snapshot into a verdict, so a single `net-show` call localises a
//! "sensor sees nothing" fault between the appliance, the bridge/mirror, and the
//! sensor. Everything here is read-only: sysfs reads plus, in the caller, a few
//! read-only `tc`/`ovs-vsctl` queries for the mirror.

use std::path::Path;

/// Read a `/sys/class/net/<iface>/statistics/<name>` counter (tx_packets,
/// rx_packets, tx_dropped, ...). None if the interface or counter is absent.
pub fn sysfs_stat(iface: &str, name: &str) -> Option<u64> {
    read_u64(&format!("/sys/class/net/{iface}/statistics/{name}"))
}

/// True if the interface exists (has a `/sys/class/net/<iface>` entry).
pub fn iface_exists(iface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{iface}")).exists()
}

/// The interface MTU, if present.
pub fn mtu(iface: &str) -> Option<u64> {
    read_u64(&format!("/sys/class/net/{iface}/mtu"))
}

/// operstate string ("up", "down", "unknown"). veth/tap often read "unknown"
/// even when usable, so callers pair this with [`carrier`].
pub fn operstate(iface: &str) -> Option<String> {
    read_trimmed(&format!("/sys/class/net/{iface}/operstate"))
}

/// Carrier present (link layer up). None if the file is unreadable (e.g. the
/// interface is administratively down).
pub fn carrier(iface: &str) -> Option<bool> {
    read_u64(&format!("/sys/class/net/{iface}/carrier")).map(|v| v != 0)
}

/// A usable link: operstate "up", or carrier present (covers veth/tap that
/// report operstate "unknown" while still carrying frames).
pub fn link_up(iface: &str) -> bool {
    matches!(operstate(iface).as_deref(), Some("up")) || carrier(iface).unwrap_or(false)
}

/// The bridge this interface is enslaved to, via the `master` symlink, if any.
pub fn master(iface: &str) -> Option<String> {
    std::fs::read_link(format!("/sys/class/net/{iface}/master"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Promiscuous mode, parsed from the `flags` bitfield (IFF_PROMISC = 0x100).
pub fn promisc(iface: &str) -> Option<bool> {
    read_trimmed(&format!("/sys/class/net/{iface}/flags"))
        .and_then(|s| {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u64::from_str_radix(s, 16).ok()
        })
        .map(|flags| flags & 0x100 != 0)
}

/// The bridge's member interfaces, from `/sys/class/net/<bridge>/brif/`.
pub fn bridge_members(bridge: &str) -> Vec<String> {
    let dir = format!("/sys/class/net/{bridge}/brif");
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// True if the interface is a physical NIC (has a `device` link into the PCI or
/// USB tree), mirroring net-setup's isolation check. A physical member of the
/// isolated bridge is an isolation breach.
pub fn is_physical(iface: &str) -> bool {
    match std::fs::read_link(format!("/sys/class/net/{iface}/device")) {
        Ok(p) => {
            let s = p.to_string_lossy();
            s.contains("/pci") || s.contains("/usb")
        }
        Err(_) => false,
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_u64(path: &str) -> Option<u64> {
    read_trimmed(path).and_then(|s| s.parse().ok())
}

/// A snapshot of the datapath, gathered by `net-show` and turned into a verdict.
/// Kept separate from the gathering so the decision table is unit-testable
/// without a live bridge.
#[derive(Debug, Clone)]
pub struct Datapath {
    pub mirror_mode: String,
    pub replay: String,
    pub bridge: String,
    pub sensor: String,
    pub replay_exists: bool,
    pub replay_up: bool,
    /// The bridge the replay port is enslaved to (tc mode), if any.
    pub replay_master: Option<String>,
    pub bridge_exists: bool,
    /// A physical member of the isolated bridge: an isolation breach.
    pub bridge_physical_member: Option<String>,
    pub sensor_exists: bool,
    pub sensor_up: bool,
    pub sensor_promisc: bool,
    /// A mirror/span from the replay port to the sensor port was found.
    pub mirror_present: bool,
    /// Counter deltas over the probe window. None when no probe was run.
    pub tx_delta: Option<u64>,
    pub rx_delta: Option<u64>,
}

/// Overall datapath health. The exit code follows the `pewpew`/`verify`
/// convention: 0 healthy, 1 degraded (works but something is off), 2 broken
/// (frames cannot reach the sensor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Degraded,
    Broken,
}

impl Health {
    pub fn exit_code(&self) -> i32 {
        match self {
            Health::Healthy => 0,
            Health::Degraded => 1,
            Health::Broken => 2,
        }
    }
}

/// One finding about the datapath: a severity, a human line, and (optionally) a
/// remedy hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Health,
    pub message: String,
    pub remedy: Option<String>,
}

/// Reduce a [`Datapath`] snapshot to a health verdict and an ordered list of
/// findings. Pure: no I/O, so the decision table is fully unit-tested.
pub fn assess(d: &Datapath) -> (Health, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut worst = Health::Healthy;
    let mut note = |sev: Health, message: String, remedy: Option<String>| {
        if sev == Health::Broken {
            worst = Health::Broken;
        } else if sev == Health::Degraded && worst == Health::Healthy {
            worst = Health::Degraded;
        }
        findings.push(Finding {
            severity: sev,
            message,
            remedy,
        });
    };

    // Isolation invariant first: a physical NIC on the isolated bridge is the one
    // thing that must never happen, regardless of replay health.
    if let Some(m) = &d.bridge_physical_member {
        note(
            Health::Broken,
            format!(
                "ISOLATION BREACH: bridge {} has physical member {m}",
                d.bridge
            ),
            Some("remove the physical NIC from the isolated bridge immediately".into()),
        );
    }

    if !d.replay_exists {
        note(
            Health::Broken,
            format!("replay port {} does not exist", d.replay),
            Some("check `iface` in the config and that net-setup ran".into()),
        );
        // Without a replay port nothing else is meaningful.
        return (worst, findings);
    }
    if !d.replay_up {
        note(
            Health::Broken,
            format!("replay port {} is down", d.replay),
            Some(format!("ip link set {} up", d.replay)),
        );
    }
    if !d.bridge_exists {
        note(
            Health::Broken,
            format!("bridge {} does not exist", d.bridge),
            Some("run net-setup to create the isolated bridge and mirror".into()),
        );
    } else if d.mirror_mode == "tc" && d.replay_master.as_deref() != Some(d.bridge.as_str()) {
        note(
            Health::Degraded,
            format!(
                "replay port {} is not enslaved to bridge {} (master={})",
                d.replay,
                d.bridge,
                d.replay_master.as_deref().unwrap_or("none")
            ),
            Some(format!("ip link set {} master {}", d.replay, d.bridge)),
        );
    }
    if !d.sensor_exists {
        note(
            Health::Broken,
            format!("sensor port {} does not exist", d.sensor),
            Some("check `net.sensor_port` in the config".into()),
        );
    } else {
        if !d.sensor_up {
            note(
                Health::Broken,
                format!("sensor port {} is down", d.sensor),
                Some(format!("ip link set {} up", d.sensor)),
            );
        }
        if !d.sensor_promisc {
            note(
                Health::Degraded,
                format!(
                    "sensor port {} is not promiscuous; mirrored frames are dropped",
                    d.sensor
                ),
                Some(format!("ip link set {} promisc on", d.sensor)),
            );
        }
    }
    if !d.mirror_present {
        note(
            Health::Broken,
            format!(
                "no mirror from {} to {} found ({} mode)",
                d.replay, d.sensor, d.mirror_mode
            ),
            Some("re-run net-setup to install the SPAN mirror".into()),
        );
    }

    // The live probe is the decisive signal: did frames actually flow to the
    // sensor during the window?
    if let (Some(tx), Some(rx)) = (d.tx_delta, d.rx_delta) {
        if tx == 0 {
            note(
                Health::Degraded,
                "no frames left the replay port during the probe (daemon idle, in a gap, or stopped)".into(),
                Some("confirm the daemon is replaying: turbolaser pewpew".into()),
            );
        } else if rx == 0 {
            // The exact demo failure: the daemon is emitting but nothing reaches
            // the sensor port.
            note(
                Health::Broken,
                format!("{tx} frame(s) egressed {} but 0 reached {}: the mirror/bridge is not delivering", d.replay, d.sensor),
                Some("tcpreplay may use PACKET_QDISC_BYPASS (skips the tc mirror); switch the bridge to flood mode (`bridge link set dev <port> learning off flood on` on both ports) or use the OVS mirror".into()),
            );
        }
    }

    (worst, findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Datapath {
        Datapath {
            mirror_mode: "tc".into(),
            replay: "tl0".into(),
            bridge: "tlbr0".into(),
            sensor: "sens0".into(),
            replay_exists: true,
            replay_up: true,
            replay_master: Some("tlbr0".into()),
            bridge_exists: true,
            bridge_physical_member: None,
            sensor_exists: true,
            sensor_up: true,
            sensor_promisc: true,
            mirror_present: true,
            tx_delta: Some(1200),
            rx_delta: Some(1200),
        }
    }

    #[test]
    fn a_flowing_datapath_is_healthy() {
        let (h, f) = assess(&healthy());
        assert_eq!(h, Health::Healthy, "{f:?}");
        assert_eq!(h.exit_code(), 0);
    }

    #[test]
    fn tx_flowing_but_no_rx_is_broken_with_the_mirror_remedy() {
        // The live-demo failure: the daemon emits but nothing reaches the sensor.
        let mut d = healthy();
        d.rx_delta = Some(0);
        let (h, f) = assess(&d);
        assert_eq!(h, Health::Broken);
        assert!(
            f.iter().any(|x| x.severity == Health::Broken
                && x.message.contains("0 reached")
                && x.remedy.as_deref().unwrap_or("").contains("flood")),
            "names the datapath fault and the flood/OVS remedy: {f:?}"
        );
    }

    #[test]
    fn idle_replay_is_degraded_not_broken() {
        let mut d = healthy();
        d.tx_delta = Some(0);
        d.rx_delta = Some(0);
        let (h, _) = assess(&d);
        assert_eq!(
            h,
            Health::Degraded,
            "an idle daemon is not a datapath fault"
        );
    }

    #[test]
    fn missing_mirror_is_broken() {
        let mut d = healthy();
        d.mirror_present = false;
        assert_eq!(assess(&d).0, Health::Broken);
    }

    #[test]
    fn sensor_not_promisc_is_degraded() {
        let mut d = healthy();
        d.sensor_promisc = false;
        assert_eq!(assess(&d).0, Health::Degraded);
    }

    #[test]
    fn physical_bridge_member_is_an_isolation_breach() {
        let mut d = healthy();
        d.bridge_physical_member = Some("eth0".into());
        let (h, f) = assess(&d);
        assert_eq!(h, Health::Broken);
        assert!(f.iter().any(|x| x.message.contains("ISOLATION BREACH")));
    }

    #[test]
    fn missing_replay_port_short_circuits() {
        let mut d = healthy();
        d.replay_exists = false;
        let (h, f) = assess(&d);
        assert_eq!(h, Health::Broken);
        // No spurious sensor/mirror findings once the replay port is absent.
        assert_eq!(f.len(), 1, "{f:?}");
    }
}
