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
                    if let Err(e) = map.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)
                    {
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

        rb_builder.add(rb_map, move |data: &[u8]| {
            if let Some(event) = SigwaitEvent::from_bytes(data) {
                callback(event);
            } else {
                error!("Failed to parse sigwait event from ring buffer");
            }
            0 // Return 0 for success
        }).map_err(|e| {
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

        rb_builder.add(rb_map, move |data: &[u8]| {
            if let Some(event) = SchedstatEvent::from_bytes(data) {
                callback(event);
            } else {
                error!("Failed to parse schedstat event from ring buffer");
            }
            0 // Return 0 for success
        }).map_err(|e| {
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

    #[test]
    fn test_bpf_manager_creation() {
        let manager = BpfManager::new();
        // Should create without error
        drop(manager);
    }

    #[test]
    fn test_bpf_manager_add_del_pid_without_start() {
        let manager = BpfManager::new();
        // Should not fail even if BPF is not started (graceful degradation)
        assert!(manager.add_pid(1234).is_ok());
        assert!(manager.del_pid(1234).is_ok());
    }
}
