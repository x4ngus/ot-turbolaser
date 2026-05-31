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
    Ok(ReplayResult {
        success: status.success() && !killed,
        packets: parse_packets(&text),
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
