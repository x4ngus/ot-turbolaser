//! Passive-sensor CSV union oracle.
//!
//! Parses a passive sensor's asset export and scores it against the sealed plan:
//! how many planned assets the sensor fused into one MAC<->IP record (the union),
//! how many are still split (an IP-only ghost plus a MAC-only record), and how
//! many of the named devices the sensor resolved a hostname for. The post-deploy
//! health check that productized the manual analysis behind v0.3.0 -- the one
//! that found only 11 of 743 records unioned under v0.2.21.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::ledger::Session;

/// The union scorecard for one export against one plan.
#[derive(Debug, Clone, Default)]
pub struct UnionReport {
    /// Total asset records in the export.
    pub total_records: usize,
    /// Records carrying both an IP and a MAC (a formed union).
    pub unioned: usize,
    pub ip_only: usize,
    pub mac_only: usize,
    pub neither: usize,
    /// Planned assets (fabricated devices + capture hosts) in the ledger.
    pub planned: usize,
    /// Planned assets whose IP appears in a unioned record.
    pub planned_unioned: usize,
    /// Planned IPs not yet unioned (the work remaining), capped for the report.
    pub stragglers: Vec<Ipv4Addr>,
    /// Planned devices assigned a hostname in the ledger.
    pub planned_named: usize,
    /// Of those, how many the sensor resolved a hostname for (name bound to IP).
    pub planned_named_resolved: usize,
}

impl UnionReport {
    /// Fraction of planned assets that have unioned, in [0, 1]. The headline.
    pub fn union_rate(&self) -> f64 {
        if self.planned == 0 {
            0.0
        } else {
            self.planned_unioned as f64 / self.planned as f64
        }
    }

    /// Fraction of named planned devices whose hostname the sensor resolved (the
    /// MAC<->IP<->DNS completion rate), in [0, 1].
    pub fn hostname_coverage(&self) -> f64 {
        if self.planned_named == 0 {
            0.0
        } else {
            self.planned_named_resolved as f64 / self.planned_named as f64
        }
    }
}

/// Split one CSV record into fields, honouring RFC-4180 double-quoting (a quoted
/// field may contain commas; "" is a literal quote). Returns owned fields.
fn parse_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut field = String::new();
    let mut record: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => record.push(std::mem::take(&mut field)),
            '\n' | '\r' if !in_quotes => {
                // End the record on a newline; tolerate CRLF and blank lines.
                if !field.is_empty() || !record.is_empty() {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// Tokens in an address field: a sensor may list several space/comma-separated
/// addresses in one cell. Empty tokens are dropped.
fn tokens(field: &str) -> impl Iterator<Item = &str> {
    field
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Score `csv_text` against the planned assets in `ledger`.
pub fn analyze(csv_text: &str, ledger: &Session) -> Result<UnionReport, String> {
    let records = parse_records(csv_text);
    let mut rows = records.into_iter();
    let header = rows.next().ok_or("empty CSV (no header row)")?;
    let col = |name: &str| header.iter().position(|h| h == name);
    let ip_col = col("addresses.ip").ok_or("CSV has no 'addresses.ip' column")?;
    let mac_col = col("addresses.mac").ok_or("CSV has no 'addresses.mac' column")?;
    // Hostname column is optional: not every export carries one.
    let host_col = col("addresses.hostname");

    let mut r = UnionReport::default();
    let mut unioned_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut named_ips: HashSet<Ipv4Addr> = HashSet::new();
    for row in rows {
        let ip_field = row.get(ip_col).map(String::as_str).unwrap_or("");
        let mac_field = row.get(mac_col).map(String::as_str).unwrap_or("");
        let has_ip = tokens(ip_field).next().is_some();
        let has_mac = tokens(mac_field).next().is_some();
        r.total_records += 1;
        match (has_ip, has_mac) {
            (true, true) => {
                r.unioned += 1;
                for t in tokens(ip_field) {
                    if let Ok(ip) = t.parse::<Ipv4Addr>() {
                        unioned_ips.insert(ip);
                    }
                }
            }
            (true, false) => r.ip_only += 1,
            (false, true) => r.mac_only += 1,
            (false, false) => r.neither += 1,
        }
        // Record the IPs the sensor has resolved a hostname for.
        if has_ip {
            let named = host_col
                .and_then(|hc| row.get(hc))
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if named {
                for t in tokens(ip_field) {
                    if let Ok(ip) = t.parse::<Ipv4Addr>() {
                        named_ips.insert(ip);
                    }
                }
            }
        }
    }

    // Cross-reference the plan: a planned asset has unioned iff its IP shows up
    // in a record that also carries a MAC.
    let planned: Vec<Ipv4Addr> = ledger
        .devices
        .iter()
        .map(|d| d.ip.as_str())
        .chain(ledger.capture_hosts.iter().map(|h| h.ip.as_str()))
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .collect();
    r.planned = planned.len();
    for ip in planned {
        if unioned_ips.contains(&ip) {
            r.planned_unioned += 1;
        } else if r.stragglers.len() < 50 {
            r.stragglers.push(ip);
        }
    }

    // Hostname coverage: of the devices the plan named, how many did the sensor
    // resolve a hostname for? (Capture hosts are unnamed by design.)
    for d in &ledger.devices {
        if d.hostname.is_some() {
            r.planned_named += 1;
            if let Ok(ip) = d.ip.parse::<Ipv4Addr>() {
                if named_ips.contains(&ip) {
                    r.planned_named_resolved += 1;
                }
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{CaptureHostRecord, DeviceRecord, Session};

    fn dev(ip: &str) -> DeviceRecord {
        DeviceRecord {
            ip: ip.into(),
            mac: "00:0e:8c:11:22:33".into(),
            vendor: "Siemens".into(),
            model: "S7".into(),
            firmware: "1".into(),
            protocol: "s7".into(),
            cves: vec![],
            subnet_cidr: "10.0.0.0/24".into(),
            hostname: None,
            asset_type: None,
        }
    }
    fn host(ip: &str) -> CaptureHostRecord {
        CaptureHostRecord {
            origin_ip: ip.into(),
            ip: ip.into(),
            mac: "00:0e:8c:44:55:66".into(),
            vendor: None,
            protocol: None,
            purdue_level: 0,
            subnet_cidr: "10.0.0.0/24".into(),
            hostname: None,
            asset_type: None,
        }
    }

    #[test]
    fn scores_union_rate_and_lists_stragglers() {
        // Header mirrors the real export's columns of interest.
        let csv = "id,addresses.ip,addresses.mac,zone.name\n\
                   1,10.0.0.5,00:0e:8c:11:22:33,Siemens\n\
                   2,10.0.0.6,,Siemens\n\
                   3,,AA:BB:CC:DD:EE:FF,External Network\n\
                   4,10.0.0.7,00:0e:8c:44:55:66,Siemens\n";
        let mut s = Session::new(1, 0);
        s.devices.push(dev("10.0.0.5")); // unioned
        s.devices.push(dev("10.0.0.6")); // ip-only -> straggler
        s.capture_hosts.push(host("10.0.0.7")); // unioned

        let r = analyze(csv, &s).unwrap();
        assert_eq!(r.total_records, 4);
        assert_eq!(r.unioned, 2);
        assert_eq!(r.ip_only, 1);
        assert_eq!(r.mac_only, 1);
        assert_eq!(r.planned, 3);
        assert_eq!(r.planned_unioned, 2);
        assert_eq!(r.stragglers, vec!["10.0.0.6".parse::<Ipv4Addr>().unwrap()]);
        assert!((r.union_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn handles_quoted_fields_with_commas() {
        // The 'tags' column carries commas inside quotes; the IP/MAC columns must
        // still line up.
        let csv = "id,tags,addresses.ip,addresses.mac\n\
                   1,\"Controller, PLC, OT\",10.0.0.5,00:0e:8c:11:22:33\n";
        let mut s = Session::new(1, 0);
        s.devices.push(dev("10.0.0.5"));
        let r = analyze(csv, &s).unwrap();
        assert_eq!(r.unioned, 1);
        assert_eq!(r.planned_unioned, 1);
    }

    #[test]
    fn scores_hostname_coverage() {
        // Two named planned devices; the export carries a hostname for one.
        let csv = "addresses.ip,addresses.mac,addresses.hostname\n\
                   10.0.0.5,00:0e:8c:11:22:33,LINE-01-PLC-01\n\
                   10.0.0.6,00:0e:8c:11:22:34,\n";
        let mut s = Session::new(1, 0);
        let mut a = dev("10.0.0.5");
        a.hostname = Some("LINE-01-PLC-01".into());
        let mut b = dev("10.0.0.6");
        b.hostname = Some("LINE-01-PLC-02".into());
        s.devices.push(a);
        s.devices.push(b);
        s.devices.push(dev("10.0.0.7")); // unnamed planned device, not counted

        let r = analyze(csv, &s).unwrap();
        assert_eq!(r.planned_named, 2, "two named planned devices");
        assert_eq!(r.planned_named_resolved, 1, "sensor resolved one name");
        assert!((r.hostname_coverage() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn hostname_coverage_zero_when_column_absent() {
        // An export without a hostname column -> coverage 0, no error.
        let csv = "addresses.ip,addresses.mac\n10.0.0.5,00:0e:8c:11:22:33\n";
        let mut s = Session::new(1, 0);
        let mut a = dev("10.0.0.5");
        a.hostname = Some("LINE-01-PLC-01".into());
        s.devices.push(a);
        let r = analyze(csv, &s).unwrap();
        assert_eq!(r.planned_named, 1);
        assert_eq!(r.planned_named_resolved, 0);
        assert_eq!(r.hostname_coverage(), 0.0);
    }

    #[test]
    fn missing_columns_are_an_error() {
        let csv = "id,name\n1,foo\n";
        assert!(analyze(csv, &Session::new(1, 0)).is_err());
    }
}
