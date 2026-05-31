//! Spawn a single-shot tcpreplay run and summarise the result.
//!
//! The orchestrator owns the loop, so each run is one `--loop=1` invocation
//! that can use a different capture, seed, and rate.

use std::path::Path;
use std::process::Command;

pub struct ReplayResult {
    pub success: bool,
    pub packets: Option<u64>,
    pub detail: String,
}

pub fn run_once(iface: &str, pcap: &Path, rate_args: &[String]) -> std::io::Result<ReplayResult> {
    let mut cmd = Command::new("tcpreplay");
    cmd.arg(format!("--intf1={iface}"))
        .arg("--preload-pcap")
        .arg("--loop=1")
        .arg("--stats=1");
    for a in rate_args {
        cmd.arg(a);
    }
    cmd.arg(pcap);

    let out = cmd.output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));

    Ok(ReplayResult {
        success: out.status.success(),
        packets: parse_packets(&text),
        detail: summarize(&text, out.status.code()),
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
}
