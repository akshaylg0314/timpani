/*
 * SPDX-FileCopyrightText: Copyright 2026 LG Electronics Inc.
 * SPDX-License-Identifier: MIT
 */

//! BPF event types matching C structures from trace_bpf.h
//!
//! These types must match the layout of the C structures to correctly
//! parse events from BPF ring buffers.

/// Sigwait event from BPF (matches C struct sigwait_event)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SigwaitEvent {
    pub pid: i32,
    pub tgid: i32,
    pub timestamp: u64,
    pub enter: u8,
}

/// Schedstat event from BPF (matches C struct schedstat_event)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SchedstatEvent {
    pub pid: i32,
    pub cpu: i32,
    pub ts_wakeup: u64,
    pub ts_start: u64,
    pub ts_stop: u64,
}

impl SigwaitEvent {
    /// Parse event from raw bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }
}

impl SchedstatEvent {
    /// Parse event from raw bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigwait_event_size() {
        // Verify struct layout matches C
        // Size is 24 bytes on x86_64 (4+4+8+1+3 padding for alignment)
        // The struct is repr(C) so padding matches C compiler behavior
        let size = std::mem::size_of::<SigwaitEvent>();
        assert!(size == 21 || size == 24, "Expected 21 or 24 bytes, got {}", size);
    }

    #[test]
    fn test_schedstat_event_size() {
        // Verify struct layout matches C (should be 32 bytes)
        assert_eq!(std::mem::size_of::<SchedstatEvent>(), 32);
    }
}
