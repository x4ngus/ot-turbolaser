//! tx-counter watchdog. While a replay is active, it polls the interface's
//! tx_packets counter. If the counter is flat for longer than the configured
//! window, it trips a flag so the stalled tcpreplay child can be killed and the
//! loop can move on. A flat counter during an inter-run gap is expected and
//! never trips, because the watchdog only watches while a send is active.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct Shared {
    active: AtomicBool,
    tripped: AtomicBool,
    stop: AtomicBool,
}

pub struct Watchdog {
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    pub fn spawn(
        iface: String,
        poll_secs: u64,
        flatline_secs: u64,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let shared = Arc::new(Shared {
            active: AtomicBool::new(false),
            tripped: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });
        let s = Arc::clone(&shared);
        let poll_secs = poll_secs.max(1);
        let flatline_secs = flatline_secs.max(1);
        let poll = Duration::from_secs(poll_secs);
        let handle = thread::spawn(move || {
            let mut last: Option<u64> = None;
            let mut stall: u64 = 0;
            loop {
                thread::sleep(poll);
                if s.stop.load(Ordering::Relaxed) || shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if !s.active.load(Ordering::Relaxed) {
                    last = None;
                    stall = 0;
                    continue;
                }
                step(&mut last, &mut stall, read_tx_packets(&iface), poll_secs);
                if stall >= flatline_secs {
                    s.tripped.store(true, Ordering::Relaxed);
                }
            }
        });
        Watchdog {
            shared,
            handle: Some(handle),
        }
    }

    /// Mark the start of an active send. Clears any prior trip.
    pub fn begin(&self) {
        self.shared.tripped.store(false, Ordering::Relaxed);
        self.shared.active.store(true, Ordering::Relaxed);
    }

    /// Mark the end of a send. The counter may now sit flat without tripping.
    pub fn end(&self) {
        self.shared.active.store(false, Ordering::Relaxed);
    }

    pub fn tripped(&self) -> bool {
        self.shared.tripped.load(Ordering::Relaxed)
    }

    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Update the flatline state from one reading. Extracted so the decision is
/// unit testable without a real interface.
fn step(last: &mut Option<u64>, stall: &mut u64, tx: Option<u64>, poll_secs: u64) {
    match (tx, *last) {
        (Some(now), Some(prev)) if now == prev => *stall += poll_secs,
        (Some(now), _) => {
            *last = Some(now);
            *stall = 0;
        }
        (None, _) => {} // cannot read the counter, do not trip on that alone
    }
}

fn read_tx_packets(iface: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/tx_packets"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stall_after(readings: &[Option<u64>], poll_secs: u64) -> u64 {
        let mut last = None;
        let mut stall = 0;
        for &tx in readings {
            step(&mut last, &mut stall, tx, poll_secs);
        }
        stall
    }

    #[test]
    fn flat_counter_accumulates_stall() {
        // Same value four polls in a row: three increments after the first.
        let stall = stall_after(&[Some(100), Some(100), Some(100), Some(100)], 2);
        assert_eq!(stall, 6);
    }

    #[test]
    fn progress_resets_stall() {
        let stall = stall_after(&[Some(100), Some(100), Some(150), Some(150)], 2);
        assert_eq!(stall, 2, "stall resets when the counter advances");
    }

    #[test]
    fn unreadable_counter_does_not_accumulate() {
        let stall = stall_after(&[Some(100), None, None, Some(100)], 2);
        assert_eq!(stall, 2);
    }
}
