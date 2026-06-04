//! Spawn a single-shot tcpreplay run, watched by the tx watchdog, and
//! summarise the result. The orchestrator owns the loop, so each run is one
//! `--loop=1` invocation that can use a different capture, seed, and rate.

use super::watchdog::Watchdog;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub struct ReplayResult {
    pub success: bool,
    pub packets: Option<u64>,
    /// Achieved rate for this run, parsed from tcpreplay's own stats. Reported in
    /// the heartbeat so the operator sees the real send rate rather than a value
    /// derived from a whole-second NIC counter that rounds sub-second runs to 0.
    pub pps: Option<f64>,
    pub mbps: Option<f64>,
    pub detail: String,
}

pub fn run_once(
    iface: &str,
    pcap: &Path,
    rate_args: &[String],
    watchdog: &Watchdog,
) -> std::io::Result<ReplayResult> {
    let mut child = Command::new("tcpreplay")
        .arg(format!("--intf1={iface}"))
        .arg("--preload-pcap")
        .arg("--loop=1")
        .arg("--stats=1")
        .args(rate_args)
        .arg(pcap)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    watchdog.begin();
    let mut killed = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if watchdog.tripped() && !killed {
            let _ = child.kill();
            killed = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    watchdog.end();

    let mut text = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut text);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut text);
    }

    let summary = summarize(&text, status.code());
    let (pps, mbps) = parse_rate(&text);
    Ok(ReplayResult {
        success: status.success() && !killed,
        packets: parse_packets(&text),
        pps,
        mbps,
        detail: if killed {
            format!("watchdog killed stalled replay; {summary}")
        } else {
            summary
        },
    })
}

/// tcpreplay prints a final "Actual: <n> packets ..." line with --stats.
fn parse_packets(text: &str) -> Option<u64> {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Actual:") {
            for tok in rest.split_whitespace() {
                if let Ok(n) = tok.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Achieved (pps, Mbps) from tcpreplay's final
/// "Actual: <n> packets (<b> bytes) sent in <t> seconds" line. tcpreplay's own
/// timing is sub-second accurate, unlike the whole-second NIC counter, so a fast
/// run reports a real rate instead of zero. Best effort: returns (None, None)
/// when the line or any of count/bytes/duration is missing.
fn parse_rate(text: &str) -> (Option<f64>, Option<f64>) {
    let Some(line) = text.lines().find(|l| l.trim_start().starts_with("Actual:")) else {
        return (None, None);
    };
    let toks: Vec<&str> = line.split_whitespace().collect();
    let packets = toks
        .iter()
        .position(|t| *t == "Actual:")
        .and_then(|i| toks.get(i + 1))
        .and_then(|t| t.parse::<u64>().ok());
    let bytes = toks
        .iter()
        .find_map(|t| t.strip_prefix('(').and_then(|s| s.parse::<u64>().ok()));
    let secs = toks
        .iter()
        .position(|t| *t == "in")
        .and_then(|i| toks.get(i + 1))
        .and_then(|t| t.parse::<f64>().ok());
    match (packets, bytes, secs) {
        (Some(p), Some(b), Some(s)) if s > 0.0 => {
            (Some(p as f64 / s), Some(b as f64 * 8.0 / s / 1_000_000.0))
        }
        _ => (None, None),
    }
}

fn summarize(text: &str, code: Option<i32>) -> String {
    let last = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    match code {
        Some(c) => format!("exit={c} {last}"),
        None => format!("signal-terminated {last}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actual_packet_count() {
        let text = "some preamble\nActual: 1234 packets (98765 bytes) sent in 1.00 seconds\n";
        assert_eq!(parse_packets(text), Some(1234));
    }

    #[test]
    fn no_count_when_absent() {
        assert_eq!(parse_packets("nothing here"), None);
    }

    #[test]
    fn parses_rate_from_actual_line() {
        // 1250000 bytes in 1.0s = 10.0 Mbps; 2500 packets in 1.0s = 2500 pps.
        let text = "File Cache is enabled\nActual: 2500 packets (1250000 bytes) sent in 1.00 seconds\nRated: ...\n";
        let (pps, mbps) = parse_rate(text);
        assert_eq!(pps, Some(2500.0));
        assert_eq!(mbps, Some(10.0));
    }

    #[test]
    fn no_rate_when_line_absent_or_zero_duration() {
        assert_eq!(parse_rate("nothing here"), (None, None));
        // A zero duration cannot yield a rate.
        let z = "Actual: 5 packets (300 bytes) sent in 0.00 seconds\n";
        assert_eq!(parse_rate(z), (None, None));
    }
}
