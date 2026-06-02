/*
 * SPDX-FileCopyrightText: Copyright 2026 LG Electronics Inc.
 * SPDX-License-Identifier: MIT
 */

//! BPF program management and ring buffer handling
//!
//! This module is the Rust port of trace_bpf.c, handling:
//! - Loading and attaching BPF programs (sigwait, schedstat)
//! - Ring buffer event polling in dedicated threads
//! - PID filtering for targeted monitoring
//! - Graceful degradation when BPF is unavailable
//!
//! The BPF programs themselves (*.bpf.c) are compiled at build time
//! into Rust skeleton modules via libbpf-cargo.

#[cfg(feature = "bpf")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

#[cfg(feature = "bpf")]
use std::mem::MaybeUninit;

#[cfg(feature = "bpf")]
use libbpf_rs::{MapCore, OpenObject, RingBufferBuilder};

#[cfg(feature = "bpf")]
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

#[cfg(feature = "bpf")]
use tracing::{debug, error, info, warn};

use crate::error::{TimpaniError, TimpaniResult};

#[cfg(feature = "bpf")]
use super::bpf_events::{SchedstatEvent, SigwaitEvent};

/// Ring buffer poll timeout in milliseconds
#[cfg(feature = "bpf")]
const RB_TIMEOUT_MS: std::time::Duration = std::time::Duration::from_millis(100);

// ── Mock Trait for PID Filtering (testable without root) ──────────────────────

/// Trait for PID filter map operations - allows mocking in tests
#[cfg(feature = "bpf")]
pub trait PidFilterMap: Send + Sync {
    fn update_pid(&self, pid: i32) -> TimpaniResult<()>;
    fn delete_pid(&self, pid: i32) -> TimpaniResult<()>;
}

/// Mock implementation for testing without BPF permissions
#[cfg(all(feature = "bpf", test))]
pub struct MockPidFilterMap {
    pub pids: std::sync::Mutex<std::collections::HashSet<i32>>,
    pub should_fail: std::sync::atomic::AtomicBool,
}

#[cfg(all(feature = "bpf", test))]
impl MockPidFilterMap {
    pub fn new() -> Self {
        Self {
            pids: std::sync::Mutex::new(std::collections::HashSet::new()),
            should_fail: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn set_should_fail(&self, fail: bool) {
        self.should_fail
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn contains(&self, pid: i32) -> bool {
        self.pids.lock().unwrap().contains(&pid)
    }

    pub fn len(&self) -> usize {
        self.pids.lock().unwrap().len()
    }
}

#[cfg(all(feature = "bpf", test))]
impl PidFilterMap for MockPidFilterMap {
    fn update_pid(&self, pid: i32) -> TimpaniResult<()> {
        if self.should_fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(TimpaniError::Bpf);
        }
        self.pids.lock().unwrap().insert(pid);
        Ok(())
    }

    fn delete_pid(&self, pid: i32) -> TimpaniResult<()> {
        if self.should_fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(TimpaniError::Bpf);
        }
        self.pids.lock().unwrap().remove(&pid);
        Ok(())
    }
}

/// Type alias for sigwait event callback
pub type SigwaitCallback = Arc<dyn Fn(SigwaitEvent) + Send + Sync>;

/// Type alias for schedstat event callback
pub type SchedstatCallback = Arc<dyn Fn(SchedstatEvent) + Send + Sync>;

// Include generated BPF skeletons when BPF feature is enabled
#[cfg(feature = "bpf")]
mod sigwait_skel {
    include!(concat!(env!("OUT_DIR"), "/sigwait.skel.rs"));
}

#[cfg(all(feature = "bpf", feature = "plot"))]
mod schedstat_skel {
    include!(concat!(env!("OUT_DIR"), "/schedstat.skel.rs"));
}

/// BPF Manager - Handles lifecycle of BPF programs and ring buffers
#[derive(Debug)]
pub struct BpfManager {
    #[cfg(feature = "bpf")]
    sigwait_state: Option<SigwaitState>,

    #[cfg(all(feature = "bpf", feature = "plot"))]
    schedstat_state: Option<SchedstatState>,
}

#[cfg(feature = "bpf")]
struct SigwaitState {
    _skel: sigwait_skel::SigwaitSkel<'static>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    need_exit: Arc<AtomicBool>,
}

#[cfg(feature = "bpf")]
impl std::fmt::Debug for SigwaitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigwaitState")
            .field("thread_handle", &self.thread_handle.is_some())
            .field("need_exit", &self.need_exit)
            .finish()
    }
}

#[cfg(all(feature = "bpf", feature = "plot"))]
struct SchedstatState {
    _skel: schedstat_skel::SchedstatSkel<'static>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    need_exit: Arc<AtomicBool>,
}

#[cfg(all(feature = "bpf", feature = "plot"))]
impl std::fmt::Debug for SchedstatState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedstatState")
            .field("thread_handle", &self.thread_handle.is_some())
            .field("need_exit", &self.need_exit)
            .finish()
    }
}

impl BpfManager {
    /// Create a new BPF manager (does not start programs yet)
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "bpf")]
            sigwait_state: None,
            #[cfg(all(feature = "bpf", feature = "plot"))]
            schedstat_state: None,
        }
    }

    /// Initialize and start BPF monitoring
    ///
    /// This loads, attaches, and starts polling threads for BPF programs.
    /// Implements graceful degradation: if BPF initialization fails, it logs
    /// a warning and returns success to allow the application to continue.
    pub fn bpf_on(
        &mut self,
        sigwait_cb: SigwaitCallback,
        #[allow(unused_variables)] schedstat_cb: SchedstatCallback,
    ) -> TimpaniResult<()> {
        #[cfg(not(feature = "bpf"))]
        {
            info!("BPF support not compiled in, continuing without BPF monitoring");
            return Ok(());
        }

        #[cfg(feature = "bpf")]
        {
            info!("Initializing BPF monitoring...");

            // Start sigwait BPF (core functionality)
            match self.start_sigwait_bpf(sigwait_cb) {
                Ok(()) => {
                    info!("Successfully initialized sigwait BPF monitoring");
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize BPF tracepoints: {} - continuing without BPF monitoring",
                        e
                    );
                    info!("This is normal on kernels without required tracepoint support");
                    return Ok(()); // Graceful degradation
                }
            }

            // Start schedstat BPF (optional, for plot feature)
            #[cfg(feature = "plot")]
            {
                match self.start_schedstat_bpf(schedstat_cb) {
                    Ok(()) => {
                        info!("Successfully initialized schedstat BPF monitoring");
                    }
                    Err(e) => {
                        warn!(
                            "Failed to initialize BPF schedstat monitoring: {} - continuing without schedstat",
                            e
                        );
                        // Don't fail completely, sigwait BPF is more important
                    }
                }
            }

            Ok(())
        }
    }

    /// Stop BPF monitoring and cleanup resources
    pub fn bpf_off(&mut self) {
        #[cfg(feature = "bpf")]
        {
            if let Some(mut state) = self.sigwait_state.take() {
                info!("Stopping sigwait BPF monitoring...");
                state.need_exit.store(true, Ordering::Relaxed);
                if let Some(handle) = state.thread_handle.take() {
                    let _ = handle.join();
                }
            }

            #[cfg(feature = "plot")]
            {
                if let Some(mut state) = self.schedstat_state.take() {
                    info!("Stopping schedstat BPF monitoring...");
                    state.need_exit.store(true, Ordering::Relaxed);
                    if let Some(handle) = state.thread_handle.take() {
                        let _ = handle.join();
                    }
                }
            }
        }
    }

    /// Add a PID to the BPF filter maps
    pub fn add_pid(&self, pid: i32) -> TimpaniResult<()> {
        #[cfg(not(feature = "bpf"))]
        {
            let _ = pid;
            Ok(()) // No-op when BPF is disabled
        }

        #[cfg(feature = "bpf")]
        {
            // Check if sigwait BPF feature is initialized
            if self.sigwait_state.is_none() {
                // BPF not available, return success for graceful degradation
                return Ok(());
            }

            let value: u8 = 1;
            let key_bytes = pid.to_ne_bytes();
            let value_bytes = [value];

            // Add to sigwait filter map
            if let Some(ref state) = self.sigwait_state {
                let map = &state._skel.maps.pid_filter_map;
                if let Err(e) = map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY) {
                    warn!("Failed to add PID {} to sigwait pid_filter_map: {}", pid, e);
                    return Ok(()); // Don't fail the application
                }
            }

            // Add to schedstat filter map (if enabled)
            #[cfg(feature = "plot")]
            {
                if let Some(ref state) = self.schedstat_state {
                    let map = &state._skel.maps.pid_filter_map;
                    if let Err(e) = map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY) {
                        warn!(
                            "Failed to add PID {} to schedstat pid_filter_map: {}",
                            pid, e
                        );
                    }
                }
            }

            debug!("Added PID {} to BPF filter maps", pid);
            Ok(())
        }
    }

    /// Remove a PID from the BPF filter maps
    pub fn del_pid(&self, pid: i32) -> TimpaniResult<()> {
        #[cfg(not(feature = "bpf"))]
        {
            let _ = pid;
            Ok(()) // No-op when BPF is disabled
        }

        #[cfg(feature = "bpf")]
        {
            // Check if sigwait BPF feature is initialized
            if self.sigwait_state.is_none() {
                // BPF not available, return success for graceful degradation
                return Ok(());
            }

            let key_bytes = pid.to_ne_bytes();

            // Delete from sigwait filter map
            if let Some(ref state) = self.sigwait_state {
                let map = &state._skel.maps.pid_filter_map;
                if let Err(e) = map.delete(&key_bytes) {
                    warn!(
                        "Failed to delete PID {} from sigwait pid_filter_map: {}",
                        pid, e
                    );
                    return Ok(()); // Don't fail the application
                }
            }

            // Delete from schedstat filter map (if enabled)
            #[cfg(feature = "plot")]
            {
                if let Some(ref state) = self.schedstat_state {
                    let map = &state._skel.maps.pid_filter_map;
                    if let Err(e) = map.delete(&key_bytes) {
                        warn!(
                            "Failed to delete PID {} from schedstat pid_filter_map: {}",
                            pid, e
                        );
                    }
                }
            }

            debug!("Removed PID {} from BPF filter maps", pid);
            Ok(())
        }
    }

    #[cfg(feature = "bpf")]
    fn start_sigwait_bpf(&mut self, callback: SigwaitCallback) -> TimpaniResult<()> {
        use sigwait_skel::*;

        info!("Initializing sigwait BPF tracepoints...");

        // Open and load BPF skeleton
        // Use Box::leak to get a 'static reference to the open_object
        let skel_builder = SigwaitSkelBuilder::default();
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));
        let open_skel = skel_builder.open(open_object).map_err(|e| {
            error!("Failed to open sigwait BPF skeleton: {}", e);
            TimpaniError::Bpf
        })?;

        let mut skel = open_skel.load().map_err(|e| {
            error!("Failed to load sigwait BPF programs: {}", e);
            TimpaniError::Bpf
        })?;

        // Attach BPF programs to tracepoints
        skel.attach().map_err(|e| {
            error!("Failed to attach sigwait BPF programs: {}", e);
            TimpaniError::Bpf
        })?;

        // Build ring buffer with callback
        let rb_map = &skel.maps.buffer;
        let mut rb_builder = RingBufferBuilder::new();

        rb_builder
            .add(rb_map, move |data: &[u8]| {
                if let Some(event) = SigwaitEvent::from_bytes(data) {
                    callback(event);
                } else {
                    error!("Failed to parse sigwait event from ring buffer");
                }
                0 // Return 0 for success
            })
            .map_err(|e| {
                error!("Failed to add sigwait ring buffer: {}", e);
                TimpaniError::Bpf
            })?;

        let rb = rb_builder.build().map_err(|e| {
            error!("Failed to build sigwait ring buffer: {}", e);
            TimpaniError::Bpf
        })?;

        // Spawn polling thread
        let need_exit = Arc::new(AtomicBool::new(false));
        let need_exit_clone = need_exit.clone();

        let rb = Arc::new(Mutex::new(rb));
        let thread_handle = std::thread::spawn(move || {
            while !need_exit_clone.load(Ordering::Relaxed) {
                if let Ok(rb_guard) = rb.lock() {
                    match rb_guard.poll(RB_TIMEOUT_MS) {
                        Ok(_) => {}
                        Err(e) if matches!(e.kind(), libbpf_rs::ErrorKind::Interrupted) => {}
                        Err(e) => {
                            error!("Error polling sigwait ring buffer: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        self.sigwait_state = Some(SigwaitState {
            _skel: skel,
            thread_handle: Some(thread_handle),
            need_exit,
        });

        Ok(())
    }

    #[cfg(all(feature = "bpf", feature = "plot"))]
    fn start_schedstat_bpf(&mut self, callback: SchedstatCallback) -> TimpaniResult<()> {
        use schedstat_skel::*;

        info!("Initializing schedstat BPF tracepoints...");

        // Open and load BPF skeleton
        // Use Box::leak to get a 'static reference to the open_object
        let skel_builder = SchedstatSkelBuilder::default();
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));
        let open_skel = skel_builder.open(open_object).map_err(|e| {
            error!("Failed to open schedstat BPF skeleton: {}", e);
            TimpaniError::Bpf
        })?;

        let mut skel = open_skel.load().map_err(|e| {
            error!("Failed to load schedstat BPF programs: {}", e);
            TimpaniError::Bpf
        })?;

        // Attach BPF programs to tracepoints
        skel.attach().map_err(|e| {
            error!("Failed to attach schedstat BPF programs: {}", e);
            TimpaniError::Bpf
        })?;

        // Build ring buffer with callback
        let rb_map = &skel.maps.buffer;
        let mut rb_builder = RingBufferBuilder::new();

        rb_builder
            .add(rb_map, move |data: &[u8]| {
                if let Some(event) = SchedstatEvent::from_bytes(data) {
                    callback(event);
                } else {
                    error!("Failed to parse schedstat event from ring buffer");
                }
                0 // Return 0 for success
            })
            .map_err(|e| {
                error!("Failed to add schedstat ring buffer: {}", e);
                TimpaniError::Bpf
            })?;

        let rb = rb_builder.build().map_err(|e| {
            error!("Failed to build schedstat ring buffer: {}", e);
            TimpaniError::Bpf
        })?;

        // Spawn polling thread
        let need_exit = Arc::new(AtomicBool::new(false));
        let need_exit_clone = need_exit.clone();

        let rb = Arc::new(Mutex::new(rb));
        let thread_handle = std::thread::spawn(move || {
            while !need_exit_clone.load(Ordering::Relaxed) {
                if let Ok(rb_guard) = rb.lock() {
                    match rb_guard.poll(RB_TIMEOUT_MS) {
                        Ok(_) => {}
                        Err(e) if matches!(e.kind(), libbpf_rs::ErrorKind::Interrupted) => {}
                        Err(e) => {
                            error!("Error polling schedstat ring buffer: {}", e);
                            break;
                        }
                    }
                }
            }
        });

        self.schedstat_state = Some(SchedstatState {
            _skel: skel,
            thread_handle: Some(thread_handle),
            need_exit,
        });

        Ok(())
    }
}

impl Default for BpfManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        self.bpf_off();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_bpf_manager_creation() {
        let manager = BpfManager::new();
        // Should create without error
        drop(manager);
    }

    #[test]
    fn test_bpf_manager_default_trait() {
        let manager = BpfManager::default();
        drop(manager);
    }

    #[test]
    fn test_bpf_manager_add_del_pid_without_start() {
        let manager = BpfManager::new();
        // Should not fail even if BPF is not started (graceful degradation)
        assert!(manager.add_pid(1234).is_ok());
        assert!(manager.del_pid(1234).is_ok());
    }

    #[test]
    fn test_bpf_manager_multiple_pid_operations() {
        let manager = BpfManager::new();
        // Add multiple PIDs
        for pid in 1000..1010 {
            assert!(manager.add_pid(pid).is_ok());
        }
        // Delete multiple PIDs
        for pid in 1000..1010 {
            assert!(manager.del_pid(pid).is_ok());
        }
    }

    #[test]
    fn test_bpf_manager_bpf_off_without_start() {
        let mut manager = BpfManager::new();
        // Should not panic when calling bpf_off without bpf_on
        manager.bpf_off();
    }

    #[test]
    fn test_bpf_manager_drop_cleanup() {
        let manager = BpfManager::new();
        // Drop should call bpf_off automatically
        drop(manager);
    }

    #[test]
    fn test_bpf_on_graceful_degradation() {
        let mut manager = BpfManager::new();

        let sigwait_counter = Arc::new(AtomicU32::new(0));
        let schedstat_counter = Arc::new(AtomicU32::new(0));

        let sigwait_cnt = sigwait_counter.clone();
        let sigwait_cb: SigwaitCallback = Arc::new(move |_event| {
            sigwait_cnt.fetch_add(1, Ordering::Relaxed);
        });

        let schedstat_cnt = schedstat_counter.clone();
        let schedstat_cb: SchedstatCallback = Arc::new(move |_event| {
            schedstat_cnt.fetch_add(1, Ordering::Relaxed);
        });

        // BPF will fail to load without root, but should return Ok due to graceful degradation
        let result = manager.bpf_on(sigwait_cb, schedstat_cb);
        assert!(
            result.is_ok(),
            "bpf_on should succeed with graceful degradation"
        );
    }

    #[test]
    fn test_bpf_manager_lifecycle() {
        let mut manager = BpfManager::new();

        let counter = Arc::new(AtomicU32::new(0));
        let cnt = counter.clone();
        let sigwait_cb: SigwaitCallback = Arc::new(move |_event| {
            cnt.fetch_add(1, Ordering::Relaxed);
        });

        let cnt2 = Arc::new(AtomicU32::new(0));
        let cnt2_clone = cnt2.clone();
        let schedstat_cb: SchedstatCallback = Arc::new(move |_event| {
            cnt2_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Start BPF
        let _ = manager.bpf_on(sigwait_cb.clone(), schedstat_cb.clone());

        // Add some PIDs
        let _ = manager.add_pid(1234);
        let _ = manager.add_pid(5678);

        // Stop BPF
        manager.bpf_off();

        // Should be able to start again
        let _ = manager.bpf_on(sigwait_cb, schedstat_cb);

        // Cleanup
        manager.bpf_off();
    }

    #[test]
    fn test_bpf_manager_callbacks_created() {
        use super::super::bpf_events::{SchedstatEvent, SigwaitEvent};

        let sigwait_counter = Arc::new(AtomicU32::new(0));
        let sigwait_cnt = sigwait_counter.clone();
        let sigwait_cb: SigwaitCallback = Arc::new(move |event: SigwaitEvent| {
            assert!(event.pid > 0 || event.pid == 0);
            sigwait_cnt.fetch_add(1, Ordering::Relaxed);
        });

        let schedstat_counter = Arc::new(AtomicU32::new(0));
        let schedstat_cnt = schedstat_counter.clone();
        let schedstat_cb: SchedstatCallback = Arc::new(move |event: SchedstatEvent| {
            assert!(event.cpu >= 0);
            schedstat_cnt.fetch_add(1, Ordering::Relaxed);
        });

        // Create dummy events to test callbacks
        let dummy_sigwait = SigwaitEvent {
            pid: 1234,
            tgid: 1234,
            timestamp: 1000000,
            enter: 1,
        };
        sigwait_cb(dummy_sigwait);
        assert_eq!(sigwait_counter.load(Ordering::Relaxed), 1);

        let dummy_schedstat = SchedstatEvent {
            pid: 1234,
            cpu: 0,
            ts_wakeup: 1000,
            ts_start: 2000,
            ts_stop: 3000,
        };
        schedstat_cb(dummy_schedstat);
        assert_eq!(schedstat_counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_bpf_manager_add_pid_zero() {
        let manager = BpfManager::new();
        // PID 0 is a valid PID (scheduler), should not fail
        assert!(manager.add_pid(0).is_ok());
        assert!(manager.del_pid(0).is_ok());
    }

    #[test]
    fn test_bpf_manager_add_pid_negative() {
        let manager = BpfManager::new();
        // Negative PIDs should be handled gracefully
        assert!(manager.add_pid(-1).is_ok());
        assert!(manager.del_pid(-1).is_ok());
    }

    #[test]
    fn test_bpf_manager_repeated_operations() {
        let manager = BpfManager::new();
        // Add same PID multiple times
        assert!(manager.add_pid(9999).is_ok());
        assert!(manager.add_pid(9999).is_ok());
        // Delete same PID multiple times
        assert!(manager.del_pid(9999).is_ok());
        assert!(manager.del_pid(9999).is_ok());
    }

    #[test]
    fn test_callback_type_aliases() {
        use super::super::bpf_events::{SchedstatEvent, SigwaitEvent};

        // Test that type aliases work correctly
        let _sigwait: SigwaitCallback = Arc::new(|_: SigwaitEvent| {});
        let _schedstat: SchedstatCallback = Arc::new(|_: SchedstatEvent| {});
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_bpf_timeout_constant() {
        // Verify the timeout is reasonable
        assert_eq!(RB_TIMEOUT_MS.as_millis(), 100);
    }

    // ── Tests with Mock PID Filter Map ────────────────────────────────────────

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_basic() {
        let mock = MockPidFilterMap::new();

        // Test current process PID
        let test_pid = std::process::id() as i32;

        // Add PID
        assert!(mock.update_pid(test_pid).is_ok());
        assert!(mock.contains(test_pid));
        assert_eq!(mock.len(), 1);

        // Add more PIDs
        assert!(mock.update_pid(test_pid + 1).is_ok());
        assert!(mock.update_pid(test_pid + 2).is_ok());
        assert_eq!(mock.len(), 3);

        // Delete PID
        assert!(mock.delete_pid(test_pid).is_ok());
        assert!(!mock.contains(test_pid));
        assert_eq!(mock.len(), 2);
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_failure_mode() {
        let mock = MockPidFilterMap::new();
        let test_pid = std::process::id() as i32;

        // Normal operation
        assert!(mock.update_pid(test_pid).is_ok());

        // Enable failure mode
        mock.set_should_fail(true);
        assert!(mock.update_pid(test_pid + 1).is_err());
        assert!(mock.delete_pid(test_pid).is_err());

        // Disable failure mode
        mock.set_should_fail(false);
        assert!(mock.delete_pid(test_pid).is_ok());
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_with_process_pid() {
        let mock = MockPidFilterMap::new();

        // Use actual process PIDs for realistic testing
        let self_pid = std::process::id() as i32;
        let parent_pid = unsafe { libc::getppid() };

        // Add both PIDs
        assert!(mock.update_pid(self_pid).is_ok());
        assert!(mock.update_pid(parent_pid).is_ok());

        assert!(mock.contains(self_pid));
        assert!(mock.contains(parent_pid));

        // Verify isolation
        assert!(!mock.contains(self_pid + 99999));
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_thread_safety() {
        use std::thread;

        let mock = Arc::new(MockPidFilterMap::new());
        let test_pid_base = std::process::id() as i32;

        let mut handles = vec![];

        // Spawn multiple threads adding PIDs
        for i in 0..10 {
            let mock_clone = Arc::clone(&mock);
            let pid = test_pid_base + i;
            handles.push(thread::spawn(move || {
                mock_clone.update_pid(pid).unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(mock.len(), 10);
    }

    #[test]
    fn test_bpf_manager_with_self_pid() {
        let manager = BpfManager::new();
        let self_pid = std::process::id() as i32;

        // Use actual process PID
        assert!(manager.add_pid(self_pid).is_ok());
        assert!(manager.del_pid(self_pid).is_ok());

        // Use parent PID
        let parent_pid = unsafe { libc::getppid() };
        assert!(manager.add_pid(parent_pid).is_ok());
        assert!(manager.del_pid(parent_pid).is_ok());
    }

    #[test]
    fn test_bpf_manager_pid_lifecycle_with_callbacks() {
        let mut manager = BpfManager::new();
        let self_pid = std::process::id() as i32;

        // Create callbacks that track invocations
        let sigwait_pids = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sigwait_pids_clone = sigwait_pids.clone();
        let sigwait_cb: SigwaitCallback = Arc::new(move |event| {
            sigwait_pids_clone.lock().unwrap().push(event.pid);
        });

        let schedstat_pids = Arc::new(std::sync::Mutex::new(Vec::new()));
        let schedstat_pids_clone = schedstat_pids.clone();
        let schedstat_cb: SchedstatCallback = Arc::new(move |event| {
            schedstat_pids_clone.lock().unwrap().push(event.pid);
        });

        // Start BPF (will gracefully degrade without root)
        let _ = manager.bpf_on(sigwait_cb, schedstat_cb);

        // Add self PID
        assert!(manager.add_pid(self_pid).is_ok());

        // Add parent PID
        let ppid = unsafe { libc::getppid() };
        assert!(manager.add_pid(ppid).is_ok());

        // Delete both
        assert!(manager.del_pid(self_pid).is_ok());
        assert!(manager.del_pid(ppid).is_ok());

        // Cleanup
        manager.bpf_off();
    }

    #[test]
    fn test_bpf_events_creation_with_process_data() {
        use super::super::bpf_events::{SchedstatEvent, SigwaitEvent};

        let self_pid = std::process::id() as i32;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Create realistic sigwait event
        let sigwait = SigwaitEvent {
            pid: self_pid,
            tgid: self_pid,
            timestamp,
            enter: 1,
        };

        assert_eq!(sigwait.pid, self_pid);
        assert_eq!(sigwait.tgid, self_pid);
        assert!(sigwait.timestamp > 0);

        // Create realistic schedstat event
        let schedstat = SchedstatEvent {
            pid: self_pid,
            cpu: 0,
            ts_wakeup: timestamp,
            ts_start: timestamp + 1000,
            ts_stop: timestamp + 2000,
        };

        assert_eq!(schedstat.pid, self_pid);
        assert!(schedstat.ts_start > schedstat.ts_wakeup);
        assert!(schedstat.ts_stop > schedstat.ts_start);
    }

    #[test]
    fn test_bpf_manager_concurrent_operations() {
        use std::thread;

        let manager = Arc::new(BpfManager::new());
        let base_pid = std::process::id() as i32;

        let mut handles = vec![];

        // Concurrent add operations
        for i in 0..5 {
            let mgr = Arc::clone(&manager);
            let pid = base_pid + i;
            handles.push(thread::spawn(move || {
                mgr.add_pid(pid).unwrap();
            }));
        }

        // Concurrent del operations
        for i in 5..10 {
            let mgr = Arc::clone(&manager);
            let pid = base_pid + i;
            handles.push(thread::spawn(move || {
                mgr.add_pid(pid).unwrap();
                mgr.del_pid(pid).unwrap();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_pid_filter_map_trait_coverage() {
        let mock = MockPidFilterMap::new();

        // Test the trait methods directly
        let pid1 = 1000;
        let pid2 = 2000;
        let pid3 = 3000;

        // Test update_pid via trait
        assert!(PidFilterMap::update_pid(&mock, pid1).is_ok());
        assert!(PidFilterMap::update_pid(&mock, pid2).is_ok());
        assert!(PidFilterMap::update_pid(&mock, pid3).is_ok());

        assert!(mock.contains(pid1));
        assert!(mock.contains(pid2));
        assert!(mock.contains(pid3));

        // Test delete_pid via trait
        assert!(PidFilterMap::delete_pid(&mock, pid2).is_ok());
        assert!(!mock.contains(pid2));
        assert!(mock.contains(pid1));
        assert!(mock.contains(pid3));
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_edge_cases() {
        let mock = MockPidFilterMap::new();

        // Test with PID 0 (kernel/scheduler)
        assert!(mock.update_pid(0).is_ok());
        assert!(mock.contains(0));

        // Test with PID 1 (init)
        assert!(mock.update_pid(1).is_ok());
        assert!(mock.contains(1));

        // Test with negative PID (should still work as it's just a key)
        assert!(mock.update_pid(-1).is_ok());
        assert!(mock.contains(-1));

        // Test with max i32
        assert!(mock.update_pid(i32::MAX).is_ok());
        assert!(mock.contains(i32::MAX));

        // Test with min i32
        assert!(mock.update_pid(i32::MIN).is_ok());
        assert!(mock.contains(i32::MIN));

        // Verify all PIDs are in the map
        assert_eq!(mock.len(), 5);

        // Delete all
        assert!(mock.delete_pid(0).is_ok());
        assert!(mock.delete_pid(1).is_ok());
        assert!(mock.delete_pid(-1).is_ok());
        assert!(mock.delete_pid(i32::MAX).is_ok());
        assert!(mock.delete_pid(i32::MIN).is_ok());

        assert_eq!(mock.len(), 0);
    }

    #[cfg(feature = "bpf")]
    #[test]
    fn test_mock_pid_filter_map_duplicate_operations() {
        let mock = MockPidFilterMap::new();
        let test_pid = 12345;

        // Add same PID multiple times
        assert!(mock.update_pid(test_pid).is_ok());
        assert!(mock.update_pid(test_pid).is_ok());
        assert!(mock.update_pid(test_pid).is_ok());

        // Should still only have one entry (HashSet behavior)
        assert_eq!(mock.len(), 1);
        assert!(mock.contains(test_pid));

        // Delete once should remove it
        assert!(mock.delete_pid(test_pid).is_ok());
        assert!(!mock.contains(test_pid));
        assert_eq!(mock.len(), 0);

        // Delete again should still succeed (no-op)
        assert!(mock.delete_pid(test_pid).is_ok());
    }
}
