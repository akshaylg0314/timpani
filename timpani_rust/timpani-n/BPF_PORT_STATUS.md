## BPF Integration for Timpani-N (Rust)

This document describes the BPF integration that has been ported from the C implementation.

### Summary

The BPF monitoring system has been successfully ported to Rust with the following components:

1. **BPF Event Types** (`src/core/bpf_events.rs`)
   - `SigwaitEvent` - Matches C struct for sigwait enter/exit events
   - `SchedstatEvent` - Matches C struct for scheduler statistics

2. **BPF Manager** (`src/core/bpf_manager.rs`)
   - Manages lifecycle of BPF programs (sigwait and optionally schedstat)
   - Loads and attaches BPF programs using libbpf-rs skeletons
   - Spawns dedicated polling threads for ring buffer events
   - Provides PID filtering via BPF maps
   - Implements graceful degradation when BPF is unavailable

3. **Context Integration** (`src/context/mod.rs`)
   - Added `BpfManager` field to `Context`
   - `init_bpf_monitoring()` method to start BPF after schedule is received
   - Cleanup in `cleanup()` method to stop BPF monitoring

4. **Build System** (`build.rs`, `Cargo.toml`)
   - BPF programs compiled via libbpf-cargo at build time
   - Feature flags: `bpf` (default on), `plot` (default off)
   - Generated Rust skeletons included at compile time

### Status: ✅ COMPLETE

All compilation issues have been resolved. The implementation successfully:
- Uses libbpf-rs v0.24.8 skeleton API correctly
- Handles lifetime requirements with `Box::leak` for `'static` references
- Imports necessary traits (`OpenSkel`, `Skel`, `SkelBuilder`)
- Compiles cleanly without errors

### Implementation Details

**Skeleton API Pattern:**
```rust
// Open object needs 'static lifetime for skeleton
let open_object: &'static mut MaybeUninit<OpenObject> =
    Box::leak(Box::new(MaybeUninit::uninit()));

// Build and load skeleton
let skel_builder = SigwaitSkelBuilder::default();
let open_skel = skel_builder.open(open_object)?;
let mut skel = open_skel.load()?;
skel.attach()?;
```

**Key Implementation Choices:**
1. **Box::leak for lifetimes** - BPF skeleton requires `'static` lifetime, so we use `Box::leak` to create a leaked allocation that lives for the program duration
2. **Ring buffer in Arc<Mutex>** - Polling thread needs shared access to ring buffer
3. **Graceful degradation** - If BPF init fails, log warning and continue (matches C behavior)
4. **No cleanup of leaked memory** - Acceptable since BPF lives for program lifetime

### Testing

Build and test with:
```bash
cd timpani_rust
cargo build -p timpani-n  # With BPF (default)
cargo build -p timpani-n --no-default-features  # Without BPF
cargo build -p timpani-n --features plot  # With plot feature
```

### Next Steps

1. Test BPF program loading and attachment with a live kernel
2. Verify ring buffer event callbacks work correctly
3. Add task PID registration when tasks are initialized
4. Implement deadline miss detection logic in sigwait callback
5. Add plot file writing for schedstat events (when plot feature is enabled)
- Arc/Mutex for thread-safe ring buffer sharing
- Type-safe event parsing from raw bytes
- Graceful degradation via Result types instead of return codes

All BPF C programs (`*.bpf.c`) remain unchanged and are compiled as-is at build time.
