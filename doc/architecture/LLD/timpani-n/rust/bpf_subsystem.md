# BPF Subsystem - Low Level Design

## 1. Module Overview

The BPF subsystem provides kernel-level monitoring for real-time task scheduling through eBPF tracepoints. It consists of two core modules:

| Module | Purpose |
|--------|---------|
| `bpf_events.rs` | Event type definitions matching C BPF struct layouts |
| `bpf_manager.rs` | BPF program lifecycle, ring buffer polling, PID filtering |

---

## 2. Architecture

```mermaid
flowchart TB
    subgraph Kernel["Linux Kernel Space"]
        TP1[sigwait tracepoint]
        TP2[sched_stat tracepoint]
        RB1[(Ring Buffer)]
        RB2[(Ring Buffer)]
        PM1[(pid_filter_map)]
        PM2[(pid_filter_map)]

        TP1 --> RB1
        TP2 --> RB2
        PM1 -.->|filter| TP1
        PM2 -.->|filter| TP2
    end

    subgraph UserSpace["User Space (Rust)"]
        BM[BpfManager]
        PT1[Polling Thread 1]
        PT2[Polling Thread 2]
        CB1[SigwaitCallback]
        CB2[SchedstatCallback]

        BM -->|spawns| PT1
        BM -->|spawns| PT2
        PT1 -->|invokes| CB1
        PT2 -->|invokes| CB2
    end

    RB1 -->|poll| PT1
    RB2 -->|poll| PT2
    BM -->|add_pid/del_pid| PM1
    BM -->|add_pid/del_pid| PM2
```

---

## 3. Class Diagram

```mermaid
classDiagram
    class SigwaitEvent {
        <<repr(C)>>
        +i32 pid
        +i32 tgid
        +u64 timestamp
        +u8 enter
        +from_bytes(data: &[u8]) Option~SigwaitEvent~
    }

    class SchedstatEvent {
        <<repr(C)>>
        +i32 pid
        +i32 cpu
        +u64 ts_wakeup
        +u64 ts_start
        +u64 ts_stop
        +from_bytes(data: &[u8]) Option~SchedstatEvent~
    }

    class BpfManager {
        -Option~SigwaitState~ sigwait_state
        -Option~SchedstatState~ schedstat_state
        +new() BpfManager
        +bpf_on(sigwait_cb, schedstat_cb) TimpaniResult
        +bpf_off()
        +add_pid(pid: i32) TimpaniResult
        +del_pid(pid: i32) TimpaniResult
        -start_sigwait_bpf(callback) TimpaniResult
        -start_schedstat_bpf(callback) TimpaniResult
    }

    class SigwaitState {
        -SigwaitSkel skel
        -Option~JoinHandle~ thread_handle
        -Arc~AtomicBool~ need_exit
    }

    class SchedstatState {
        -SchedstatSkel skel
        -Option~JoinHandle~ thread_handle
        -Arc~AtomicBool~ need_exit
    }

    class PidFilterMap {
        <<trait>>
        +update_pid(pid: i32) TimpaniResult
        +delete_pid(pid: i32) TimpaniResult
    }

    BpfManager *-- SigwaitState : contains
    BpfManager *-- SchedstatState : contains
    SigwaitState ..> SigwaitEvent : produces
    SchedstatState ..> SchedstatEvent : produces
```

---

## 4. Event Structures

### 4.1 SigwaitEvent

Captures `sigwait` system call enter/exit events for deadline monitoring.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | i32 | Process ID |
| `tgid` | i32 | Thread Group ID |
| `timestamp` | u64 | Kernel timestamp (ns) |
| `enter` | u8 | 1 = enter, 0 = exit |

**Size**: 24 bytes (with padding)

### 4.2 SchedstatEvent

Captures scheduler statistics for execution time analysis.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | i32 | Process ID |
| `cpu` | i32 | CPU core number |
| `ts_wakeup` | u64 | Wakeup timestamp |
| `ts_start` | u64 | Execution start timestamp |
| `ts_stop` | u64 | Execution stop timestamp |

**Size**: 32 bytes

---

## 5. BpfManager State Machine

```mermaid
stateDiagram-v2
    [*] --> Uninitialized: new()
    Uninitialized --> Running: bpf_on() success
    Uninitialized --> Uninitialized: bpf_on() fail (graceful)
    Running --> Uninitialized: bpf_off()
    Running --> [*]: drop()
    Uninitialized --> [*]: drop()

    state Running {
        [*] --> Polling
        Polling --> Polling: ring buffer events
        Polling --> Stopping: need_exit=true
        Stopping --> [*]: thread join
    }
```

---

## 6. Functional Flow

### 6.1 Initialization Sequence

```mermaid
sequenceDiagram
    participant Ctx as Context
    participant BM as BpfManager
    participant Skel as BPF Skeleton
    participant RB as RingBuffer
    participant Thread as Poll Thread

    Ctx->>BM: bpf_on(sigwait_cb, schedstat_cb)
    BM->>BM: start_sigwait_bpf()
    BM->>Skel: SigwaitSkelBuilder::default()
    BM->>Skel: open(open_object)
    BM->>Skel: load()
    BM->>Skel: attach()
    BM->>RB: RingBufferBuilder::new()
    BM->>RB: add(map, callback)
    BM->>RB: build()
    BM->>Thread: spawn(poll_loop)
    BM-->>Ctx: Ok(())
```

### 6.2 Event Processing

```mermaid
sequenceDiagram
    participant K as Kernel Tracepoint
    participant RB as Ring Buffer
    participant PT as Poll Thread
    participant CB as Callback
    participant App as Application

    K->>RB: submit event
    loop Every 100ms
        PT->>RB: poll(timeout)
        RB-->>PT: event data
        PT->>CB: callback(data)
        CB->>CB: from_bytes(data)
        CB->>App: process event
    end
```

### 6.3 PID Filtering

```mermaid
sequenceDiagram
    participant Task as Task Manager
    participant BM as BpfManager
    participant Map as pid_filter_map
    participant BPF as BPF Program

    Task->>BM: add_pid(1234)
    BM->>Map: update(key=1234, value=1)
    Note over BPF: Only events with<br/>pid in map are<br/>submitted to ring buffer

    Task->>BM: del_pid(1234)
    BM->>Map: delete(key=1234)
```

---

## 7. Feature Flags

| Feature | Effect |
|---------|--------|
| `bpf` (default) | Enables sigwait BPF monitoring |
| `plot` | Enables schedstat BPF monitoring |

Conditional compilation:

```rust
#[cfg(feature = "bpf")]           // sigwait core
#[cfg(all(feature = "bpf", feature = "plot"))]  // schedstat
```

---

## 8. Memory Model

```mermaid
flowchart LR
    subgraph Static["'static Lifetime"]
        OO[OpenObject via Box::leak]
    end

    subgraph Arc["Arc Shared"]
        NE[AtomicBool need_exit]
        RB[Mutex RingBuffer]
    end

    subgraph Owned["BpfManager Owned"]
        SK[Skeleton]
        TH[Thread Handle]
    end

    OO --> SK
    NE --> TH
    RB --> TH
```

**Key Design Decision**: `Box::leak` creates `'static` lifetime for `OpenObject` required by libbpf-rs skeleton API. Memory is intentionally leaked as BPF runs for program lifetime.

---

## 9. Error Handling

| Scenario | Behavior |
|----------|----------|
| BPF load fails | Log warning, return `Ok(())` (graceful degradation) |
| Ring buffer poll error | Log error, break poll loop |
| PID map update fails | Log warning, return `Ok(())` |
| Schedstat fails but sigwait works | Continue with sigwait only |

---

## 10. Thread Safety

| Component | Protection |
|-----------|------------|
| Ring buffer | `Arc<Mutex<RingBuffer>>` |
| Exit flag | `Arc<AtomicBool>` with `Ordering::Relaxed` |
| Callbacks | `Arc<dyn Fn() + Send + Sync>` |
| PID maps | Protected by BPF map atomic operations |
