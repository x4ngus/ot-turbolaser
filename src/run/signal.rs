//! SIGTERM and SIGINT handling. systemd sends SIGTERM on stop; the loop and
//! [`interruptible_sleep`] observe the shared flag and exit cleanly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub fn install_shutdown() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&flag));
    }
    flag
}

/// Sleep for `secs`, waking early if shutdown is requested. Sleeps in small
/// slices so a SIGTERM during a long gap is honoured promptly.
pub fn interruptible_sleep(secs: f64, shutdown: &AtomicBool) {
    if secs <= 0.0 {
        return;
    }
    let total = Duration::from_secs_f64(secs);
    let slice = Duration::from_millis(200);
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let step = slice.min(total - elapsed);
        std::thread::sleep(step);
        elapsed += step;
    }
}
