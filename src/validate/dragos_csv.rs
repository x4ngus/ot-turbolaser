//! Dragos CSV union oracle.
//!
//! Parses a Dragos asset export and scores it against the sealed plan: how many
//! planned assets the sensor has fused into one MAC<->IP record (the union), and
//! which are still split (an IP-only ghost in its OT zone plus a MAC-only record
//! in "External Network"). This is the post-deploy health check that productizes
//! the manual analysis behind v0.3.0 -- the one that found only 11 of 743 records
//! unioned under v0.2.21, all of them the per-zone stations.

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

/// Tokens in an address field: Dragos may list several space/comma-separated
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

    let mut r = UnionReport::default();
    let mut unioned_ips: HashSet<Ipv4Addr> = HashSet::new();
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
    fn missing_columns_are_an_error() {
        let csv = "id,name\n1,foo\n";
        assert!(analyze(csv, &Session::new(1, 0)).is_err());
    }
}
