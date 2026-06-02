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
        assert!(
            size == 21 || size == 24,
            "Expected 21 or 24 bytes, got {}",
            size
        );
    }

    #[test]
    fn test_schedstat_event_size() {
        // Verify struct layout matches C (should be 32 bytes)
        assert_eq!(std::mem::size_of::<SchedstatEvent>(), 32);
    }

    #[test]
    fn test_sigwait_event_from_bytes_valid() {
        // Create raw bytes representing a SigwaitEvent
        let mut data = vec![0u8; 24];
        // pid = 1234 (little endian)
        data[0..4].copy_from_slice(&1234i32.to_le_bytes());
        // tgid = 5678
        data[4..8].copy_from_slice(&5678i32.to_le_bytes());
        // timestamp = 123456789
        data[8..16].copy_from_slice(&123456789u64.to_le_bytes());
        // enter = 1
        data[16] = 1;

        let event = SigwaitEvent::from_bytes(&data).expect("Failed to parse event");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.tgid, 5678);
        assert_eq!(event.timestamp, 123456789);
        assert_eq!(event.enter, 1);
    }

    #[test]
    fn test_sigwait_event_from_bytes_insufficient_data() {
        // Provide insufficient bytes
        let data = vec![0u8; 10];
        let result = SigwaitEvent::from_bytes(&data);
        assert!(result.is_none(), "Should return None for insufficient data");
    }

    #[test]
    fn test_schedstat_event_from_bytes_valid() {
        // Create raw bytes representing a SchedstatEvent
        let mut data = vec![0u8; 32];
        // pid = 9999
        data[0..4].copy_from_slice(&9999i32.to_le_bytes());
        // cpu = 3
        data[4..8].copy_from_slice(&3i32.to_le_bytes());
        // ts_wakeup = 1000
        data[8..16].copy_from_slice(&1000u64.to_le_bytes());
        // ts_start = 2000
        data[16..24].copy_from_slice(&2000u64.to_le_bytes());
        // ts_stop = 3000
        data[24..32].copy_from_slice(&3000u64.to_le_bytes());

        let event = SchedstatEvent::from_bytes(&data).expect("Failed to parse event");
        assert_eq!(event.pid, 9999);
        assert_eq!(event.cpu, 3);
        assert_eq!(event.ts_wakeup, 1000);
        assert_eq!(event.ts_start, 2000);
        assert_eq!(event.ts_stop, 3000);
    }

    #[test]
    fn test_schedstat_event_from_bytes_insufficient_data() {
        // Provide insufficient bytes
        let data = vec![0u8; 20];
        let result = SchedstatEvent::from_bytes(&data);
        assert!(result.is_none(), "Should return None for insufficient data");
    }

    #[test]
    fn test_sigwait_event_enter_exit_values() {
        // Test enter=0 (exit)
        let mut data = vec![0u8; 24];
        data[16] = 0; // enter = 0
        let event = SigwaitEvent::from_bytes(&data).unwrap();
        assert_eq!(event.enter, 0);

        // Test enter=1 (enter)
        data[16] = 1;
        let event = SigwaitEvent::from_bytes(&data).unwrap();
        assert_eq!(event.enter, 1);
    }
}
