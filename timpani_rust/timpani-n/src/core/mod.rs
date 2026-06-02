/*
 * SPDX-FileCopyrightText: Copyright 2026 LG Electronics Inc.
 * SPDX-License-Identifier: MIT
 */

//! Core BPF management and utilities
//!
//! This module handles BPF program management, event processing, and time
//! calibration. It is the Rust port of the C `trace_bpf.c` implementation.
//!
//! BPF uses CLOCK_MONOTONIC for timestamps, but we need CLOCK_REALTIME for
//! absolute time references. This module calibrates the offset between these
//! two clocks to enable accurate timestamp conversion.
//!
//! Note: The actual BPF C programs (`*.bpf.c`) are kept in a separate `bpf/`
//! folder and compiled as-is (not ported to Rust).
//!
//!

pub mod bpf_events;
pub mod bpf_manager;

pub use bpf_events::{SchedstatEvent, SigwaitEvent};
pub use bpf_manager::{BpfManager, SchedstatCallback, SigwaitCallback};

use std::sync::atomic::{AtomicI64, Ordering};
use tracing::{debug, info};

use crate::error::{TimpaniError, TimpaniResult};

/// BPF time offset (CLOCK_MONOTONIC → CLOCK_REALTIME conversion)
/// Stored as nanoseconds to add to BPF monotonic timestamps
static BPF_KTIME_OFFSET: AtomicI64 = AtomicI64::new(0);

/// Number of calibration samples to take
const CALIBRATION_SAMPLES: usize = 20;

/// Calibrate BPF time offset by finding the offset between
/// CLOCK_MONOTONIC (used by BPF) and CLOCK_REALTIME.
///
/// This function takes multiple samples and uses the one with the smallest
/// delta (fastest measurement) to minimize timing jitter and context switch impact.
///
/// # Returns
/// - `Ok(())` on successful calibration
/// - `Err(TimpaniError::Io)` if clock_gettime fails
pub fn calibrate_time_offset() -> TimpaniResult<()> {
    let mut best_delta = u64::MAX;
    let mut best_offset: i64 = 0;

    for i in 1..=CALIBRATION_SAMPLES {
        // Get timestamps
        // print!("Calibration attempt {}: \n", i);
        let t1 = get_realtime_ns()?;
        let t2 = get_monotonic_ns()?;
        let t3 = get_realtime_ns()?;

        let delta = t3 - t1;
        let ts = (t3 + t1) / 2; // Midpoint = best estimate of "now"

        if delta < best_delta {
            best_delta = delta;
            best_offset = ts as i64 - t2 as i64;

            debug!(
                "BPF ktime calibration attempt {}: t1={}.{:09}, t2={}.{:09}, t3={}.{:09}",
                i,
                t1 / 1_000_000_000,
                t1 % 1_000_000_000,
                t2 / 1_000_000_000,
                t2 % 1_000_000_000,
                t3 / 1_000_000_000,
                t3 % 1_000_000_000
            );
            debug!(
                "Attempt {}: delta={} ns, bpf_ktime_off={} ns",
                i, delta, best_offset
            );
        }
    }

    BPF_KTIME_OFFSET.store(best_offset, Ordering::Relaxed);

    info!(
        "BPF time offset calibrated: {} ns (best delta: {} ns)",
        best_offset, best_delta
    );

    Ok(())
}

/// Convert BPF monotonic timestamp to realtime timestamp
///
/// # Arguments
/// * `bpf_ts` - BPF timestamp in nanoseconds (CLOCK_MONOTONIC)
///
/// # Returns
/// Realtime timestamp in nanoseconds (CLOCK_REALTIME)
#[inline]
pub fn bpf_ktime_to_realtime(bpf_ts: u64) -> u64 {
    let offset = BPF_KTIME_OFFSET.load(Ordering::Relaxed);
    (bpf_ts as i64 + offset) as u64
}

/// Get current CLOCK_REALTIME in nanoseconds
fn get_realtime_ns() -> TimpaniResult<u64> {
    let ts = unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) != 0 {
            return Err(TimpaniError::Io);
        }
        ts
    };
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// Get current CLOCK_MONOTONIC in nanoseconds
fn get_monotonic_ns() -> TimpaniResult<u64> {
    let ts = unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return Err(TimpaniError::Io);
        }
        ts
    };
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibration_completes() {
        // Should complete without error
        assert!(calibrate_time_offset().is_ok());
    }

    #[test]
    fn test_offset_is_set() {
        calibrate_time_offset().unwrap();
        let offset = BPF_KTIME_OFFSET.load(Ordering::Relaxed);
        // Offset should be non-zero after calibration
        assert_ne!(offset, 0);
    }

    #[test]
    fn test_conversion_produces_valid_timestamp() {
        calibrate_time_offset().unwrap();

        let rt = get_realtime_ns().unwrap();
        let mono = get_monotonic_ns().unwrap();
        let bpf_rt = bpf_ktime_to_realtime(mono);

        // Converted time should be close to actual realtime (within 1ms)
        let diff = (rt as i64 - bpf_rt as i64).abs();
        assert!(
            diff < 1_000_000,
            "Converted time differs from realtime by {} ns (> 1ms)",
            diff
        );
    }

    #[test]
    fn test_get_realtime_ns() {
        let rt = get_realtime_ns().unwrap();
        // Should be a reasonable timestamp (after year 2000)
        assert!(rt > 946_684_800_000_000_000); // Jan 1, 2000 in ns
    }

    #[test]
    fn test_get_monotonic_ns() {
        let mono1 = get_monotonic_ns().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let mono2 = get_monotonic_ns().unwrap();
        // Monotonic should increase
        assert!(mono2 > mono1);
    }

    #[test]
    fn test_multiple_calibrations() {
        // Should be safe to calibrate multiple times
        assert!(calibrate_time_offset().is_ok());
        let offset1 = BPF_KTIME_OFFSET.load(Ordering::Relaxed);

        assert!(calibrate_time_offset().is_ok());
        let offset2 = BPF_KTIME_OFFSET.load(Ordering::Relaxed);

        // Offsets should be very close (within 1ms)
        let diff = (offset1 - offset2).abs();
        assert!(
            diff < 1_000_000,
            "Calibration offsets differ by {} ns",
            diff
        );
    }
}

// ── RT main loop ──────────────────────────────────────────────────────────────
//
// Ports `start_timers` + `timer_expired_handler` + `epoll_loop` from core.c.
//
// Design vs C:
//   C spawns one real OS thread per timer fire (SIGEV_THREAD).  Here each
//   task gets a single long-lived tokio task that drives a tokio interval.
//   The interval fires at the configured period; the task sends SIGNO_TT and
//   loops.  This avoids per-fire thread allocation while delivering the same
//   signal at each period boundary.
//
//   Process-death monitoring (epoll on pidfds) is not yet implemented; the
//   timer task self-terminates on ESRCH from pidfd_send_signal instead.

use std::os::fd::AsFd;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{trace, warn};

use crate::context::{HyperperiodManager, SyncStartTime};
use crate::sched::send_tt_signal_pidfd;
use crate::task::TimeTrigger;

/// Delay before the first timer fire when no sync barrier is used.
/// Mirrors `TT_TIMER_INCREMENT_NS = 5 ms` from `timetrigger.h`.
const TIMER_START_DELAY: Duration = Duration::from_millis(5);

// ── Handle ────────────────────────────────────────────────────────────────────

/// Handle to a running RT loop.  Drop or call [`stop`][RtLoopHandle::stop] to
/// cancel all timer tasks and wait for them to exit cleanly.
pub struct RtLoopHandle {
    /// Token used to cancel only the RT loop tasks (child of the main token).
    cancel: CancellationToken,
    /// All spawned tasks (one per task + one hyperperiod cycle task).
    tasks: JoinSet<()>,
}

impl RtLoopHandle {
    /// Cancel all tasks and await their exit.
    ///
    /// Called on workload change (before re-initializing with a new schedule)
    /// and at shutdown.  The caller must be inside a tokio async context.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        while self.tasks.join_next().await.is_some() {}
    }
}

// ── Start time ────────────────────────────────────────────────────────────────

/// Compute the absolute [`tokio::time::Instant`] at which all task timers
/// should fire their **first** tick.
///
/// When a sync barrier was used (`sync_start` is `Some`), the barrier's
/// CLOCK_REALTIME timestamp is converted to a monotonic `Instant` so all
/// nodes in the workload start their timers at the same wall-clock moment.
///
/// When no barrier was used, timers start [`TIMER_START_DELAY`] from now —
/// a small slack to ensure the first fire is always in the future.
///
/// Mirrors the `starttimer_ts` calculation in `core.c: start_timers()`.
pub fn compute_start_at(sync_start: Option<&SyncStartTime>) -> Instant {
    match sync_start {
        Some(s) => {
            // Convert the barrier's CLOCK_REALTIME timestamp to a tokio Instant.
            // Strategy: measure both clocks at the same moment, compute the delta
            // to the sync timestamp, then offset from Instant::now().
            let sync_realtime_ns = s.sec as u64 * 1_000_000_000 + s.nsec as u32 as u64;
            let now_monotonic = Instant::now();
            let now_realtime_ns = {
                let mut ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                // SAFETY: clock_gettime with a valid clock-id and pointer is safe.
                unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
                ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
            };
            let delta_ns = sync_realtime_ns as i64 - now_realtime_ns as i64;
            if delta_ns > 0 {
                now_monotonic + Duration::from_nanos(delta_ns as u64)
            } else {
                // Barrier start is in the past (clock skew or late join).
                // Fall back to TIMER_START_DELAY so the first fire is still future.
                warn!(
                    past_us = (-delta_ns) / 1_000,
                    delay_ms = TIMER_START_DELAY.as_millis(),
                    "SyncTimer start is in the past — using now + delay"
                );
                now_monotonic + TIMER_START_DELAY
            }
        }
        None => Instant::now() + TIMER_START_DELAY,
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Spawn timer tasks for every entry in `tt_list`, plus a hyperperiod cycle task.
///
/// Each timer task fires at `start_at`, then every `task.period_us` µs,
/// sending `SIGNO_TT` via the task's pidfd.  If the process has died (ESRCH),
/// the timer task stops itself.
///
/// The hyperperiod cycle task fires once per `hp_manager.hyperperiod_us`,
/// advancing the cycle counter and logging statistics every 100 cycles.
///
/// All tasks are children of `parent_cancel`; calling
/// [`RtLoopHandle::stop`] cancels them without touching the rest of the
/// application.
///
/// Mirrors `start_timers()` + the SIGEV_THREAD callback in `core.c`.
pub fn start_rt_loop(
    tt_list: Vec<TimeTrigger>,
    start_at: Instant,
    parent_cancel: &CancellationToken,
    hp_manager: HyperperiodManager,
) -> RtLoopHandle {
    // Child token: cancel() here stops only the RT loop; the parent's cancel()
    // propagates down automatically (child is cancelled when parent is).
    let cancel = parent_cancel.child_token();
    let mut tasks = JoinSet::new();

    info!(
        task_count = tt_list.len(),
        start_delay_ms = {
            let now = Instant::now();
            if start_at > now {
                (start_at - now).as_millis()
            } else {
                0
            }
        },
        "Starting RT loop"
    );

    for trigger in tt_list {
        let c = cancel.clone();
        tasks.spawn(run_task_timer(trigger, start_at, c));
    }

    let hp_us = hp_manager.hyperperiod_us;
    if hp_us > 0 {
        let c = cancel.clone();
        tasks.spawn(run_hyperperiod(hp_manager, start_at, c));
    } else {
        warn!("Hyperperiod is 0 — cycle task not started");
    }

    RtLoopHandle { cancel, tasks }
}

// ── Timer task ────────────────────────────────────────────────────────────────

/// Per-task timer loop.  Fires at `start_at`, then every `period_us` µs.
///
/// On each tick:
/// 1. Optionally sleep `release_time_us` (task-local release offset).
/// 2. Send `SIGNO_TT` via `pidfd_send_signal`.
/// 3. If ESRCH (process dead): log and exit.
///
/// Mirrors `timer_expired_handler` + `SIGEV_THREAD` callback in `core.c`.
async fn run_task_timer(mut trigger: TimeTrigger, start_at: Instant, cancel: CancellationToken) {
    let period = Duration::from_micros(trigger.info.period_us as u64);
    if period.is_zero() {
        warn!(name = %trigger.info.name, "Task period is 0 — skipping timer");
        return;
    }

    // MissedTickBehavior::Skip: if a tick is delayed past the next deadline,
    // skip the missed tick and resume from the next scheduled time.
    // Matches POSIX timer coalescing behaviour (overrun count is discarded).
    let mut interval = interval_at(start_at, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!(
        name      = %trigger.info.name,
        pid       = %trigger.pid,
        period_us = trigger.info.period_us,
        "Task timer started"
    );

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(name = %trigger.info.name, "Task timer cancelled");
                break;
            }
            _ = interval.tick() => {
                let fire_time = std::time::Instant::now();

                // Release offset: sleep before sending the activation signal.
                // Mirrors the clock_nanosleep call in timer_expired_handler.
                let release = Duration::from_micros(trigger.info.release_time_us as u64);
                if !release.is_zero() {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(release) => {}
                    }
                }

                match send_tt_signal_pidfd(trigger.pidfd.as_fd()) {
                    Ok(()) => {
                        trace!(
                            name = %trigger.info.name,
                            pid  = %trigger.pid,
                            "SIGNO_TT sent"
                        );
                        trigger.prev_timer = Some(fire_time);
                    }
                    Err(crate::error::TimpaniError::Signal) => {
                        // ESRCH: task process has exited.  Stop its timer.
                        // Recovery (restart or fault report) is a future TODO.
                        info!(
                            name = %trigger.info.name,
                            pid  = %trigger.pid,
                            "Task process is dead — stopping its timer"
                        );
                        break;
                    }
                    Err(e) => {
                        warn!(
                            name  = %trigger.info.name,
                            pid   = %trigger.pid,
                            error = ?e,
                            "SIGNO_TT send failed — will retry next tick"
                        );
                    }
                }
            }
        }
    }

    debug!(name = %trigger.info.name, "Task timer task exited");
}

// ── Hyperperiod cycle task ────────────────────────────────────────────────────

/// Hyperperiod cycle task.  Fires once per `hyperperiod_us`, advancing the
/// cycle counter and logging statistics every 100 cycles.
///
/// The first fire is at `start_at + hyperperiod_us` (after the first full
/// hyperperiod completes), matching `start_hyperperiod_timer` in `hyperperiod.c`.
///
/// Owns `hp_manager`; no shared state needed while BPF miss-detection is not
/// yet wired in.
async fn run_hyperperiod(
    mut hp_manager: HyperperiodManager,
    start_at: Instant,
    cancel: CancellationToken,
) {
    let period = Duration::from_micros(hp_manager.hyperperiod_us);
    // First fire after one complete hyperperiod, not at start_at itself.
    let first_tick = start_at + period;
    let mut interval = interval_at(first_tick, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!(
        workload_id  = %hp_manager.workload_id,
        hyperperiod_us = hp_manager.hyperperiod_us,
        "Hyperperiod cycle task started"
    );

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                hp_manager.on_cycle_complete();
            }
        }
    }

    // Log final statistics on exit.
    if hp_manager.completed_cycles > 0 {
        hp_manager.log_statistics();
    }
    debug!("Hyperperiod cycle task exited");
}

// ── RT loop tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod rt_tests {
    use super::*;
    use crate::context::HyperperiodManager;

    // ── compute_start_at ──────────────────────────────────────────────────────

    #[test]
    fn start_at_no_sync_is_in_future() {
        let t = compute_start_at(None);
        assert!(
            t > Instant::now(),
            "start_at should be slightly in the future"
        );
    }

    #[test]
    fn start_at_no_sync_has_correct_delay() {
        let before = Instant::now();
        let t = compute_start_at(None);
        let after = Instant::now();
        // t should be roughly TIMER_START_DELAY from the call time
        let delay = t - before;
        let elapsed = after - before;
        assert!(delay >= TIMER_START_DELAY - Duration::from_millis(1));
        assert!(delay <= TIMER_START_DELAY + elapsed + Duration::from_millis(1));
    }

    #[test]
    fn start_at_past_sync_falls_back_to_delay() {
        // A SyncStartTime 10 seconds in the past should fall back to now + delay.
        let realtime_ns = {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        };
        let ten_secs_ago_ns = realtime_ns.saturating_sub(10 * 1_000_000_000);
        let sync = SyncStartTime {
            sec: (ten_secs_ago_ns / 1_000_000_000) as i64,
            nsec: (ten_secs_ago_ns % 1_000_000_000) as i32,
        };
        let before = Instant::now();
        let t = compute_start_at(Some(&sync));
        assert!(t > before, "past sync should fall back to a future instant");
    }

    // ── HyperperiodManager ────────────────────────────────────────────────────

    #[test]
    fn hp_manager_init() {
        let hp = HyperperiodManager::init("wl-001", 10_000, 4);
        assert_eq!(hp.workload_id, "wl-001");
        assert_eq!(hp.hyperperiod_us, 10_000);
        assert_eq!(hp.tasks_in_hyperperiod, 4);
        assert_eq!(hp.completed_cycles, 0);
        assert_eq!(hp.total_deadline_misses, 0);
    }

    #[test]
    fn hp_manager_cycle_advances_counters() {
        let mut hp = HyperperiodManager::init("wl-001", 10_000, 2);
        hp.on_cycle_complete();
        assert_eq!(hp.completed_cycles, 1);
        assert_eq!(hp.current_cycle, 1);
    }

    #[test]
    fn hp_manager_cycle_resets_cycle_misses() {
        let mut hp = HyperperiodManager::init("wl-001", 10_000, 2);
        hp.record_deadline_miss();
        hp.record_deadline_miss();
        assert_eq!(hp.total_deadline_misses, 2);
        assert_eq!(hp.cycle_deadline_misses, 2);
        hp.on_cycle_complete();
        assert_eq!(hp.total_deadline_misses, 2); // total preserved
        assert_eq!(hp.cycle_deadline_misses, 0); // per-cycle reset
    }

    #[test]
    fn hp_manager_miss_rate_zero_when_no_cycles() {
        let hp = HyperperiodManager::init("wl-001", 10_000, 1);
        // Calling log_statistics with 0 cycles should not panic (division by zero guard)
        hp.log_statistics();
    }

    // ── start_rt_loop / stop ──────────────────────────────────────────────────

    #[tokio::test]
    async fn start_rt_loop_with_empty_task_list_starts_and_stops() {
        let cancel = CancellationToken::new();
        let hp = HyperperiodManager::init("wl-test", 0, 0); // hp_us=0 → no cycle task
        let start_at = compute_start_at(None);
        let handle = start_rt_loop(vec![], start_at, &cancel, hp);
        // No tasks spawned → JoinSet is empty; stop() should return immediately.
        handle.stop().await;
    }

    #[tokio::test]
    async fn parent_cancel_stops_rt_loop() {
        let parent = CancellationToken::new();
        let hp = HyperperiodManager::init("wl-test", 1_000_000, 0);
        let start_at = compute_start_at(None);
        let handle = start_rt_loop(vec![], start_at, &parent, hp);
        parent.cancel(); // cancel parent → child token also cancelled
        handle.stop().await; // should not hang
    }
}
