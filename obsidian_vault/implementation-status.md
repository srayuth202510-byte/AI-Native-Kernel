# Implementation Status

This note tracks the current state of the repository as implemented in code, not only the target architecture described in `docs/ai_native_kernel_plan_v2.html`.

## Current Baseline

- Workspace crates exist for:
  - `kernel-companion`
  - `agent-scheduler`
  - `intent-bus`
  - `context-memory`
  - `compute-scheduler`
  - `capability-security`
- Unit tests have been added to the core prototype crates.
- The runtime graph is composed in `crates/kernel-companion/src/lib.rs`.

## Implemented Now

### kernel-companion

- Builds the in-process runtime graph.
- Owns LSM attachment state through `LsmAttachment`.
- Starts:
  - intent routing loop
  - supervisor monitoring loop
- Publishes a boot event to the intent bus.

### agent-scheduler

- Stores `AgentControlBlock` records in-memory.
- Supports:
  - spawn
  - pause
  - resume
  - terminate
  - fail
  - structured intent routing into context memory
  - capability grant flow
- Emits `AgentEvent` notifications via `broadcast`.

### intent-bus

- Broadcast-based intent distribution.
- Supports filters and subscribers.
- Exposes an async processing loop through a future-returning trait method.

### context-memory

- Hot, warm, and cold stores are implemented as in-memory maps.
- Eviction moves data from hot -> warm -> cold.
- No persistent backend is active yet.

### compute-scheduler

- Exposes a simple weighted cost model.
- Chooses the lowest-scoring compute target from a candidate list.
- Weights are updated with a simple adaptive smoothing step.

### capability-security

- Capability tokens exist with:
  - `id`
  - `scope`
  - `capabilities`
  - `expires_at`
- Policy engine is fail-closed.
- Policy decisions are constrained by an allowlist.
- Audit entries are recorded for:
  - `issued`
  - `allowed`
  - `denied`

## Not Implemented Yet

- Real eBPF userspace loader and production attachment flow
- Persistent warm/cold context storage via RocksDB or NVMe
- Real WORM audit backend
- Real syscall mediation path from kernel hook -> policy engine
- Integration test suite across crates in `tests/`
- Benchmark and fuzz harnesses

## Validation Status

- The repository has meaningful unit tests in several crates.
- Full validation is still blocked by the current shell environment if `cargo` / `rustc` are missing.
- Before calling this baseline stable, run:

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace -- -D warnings
rtk cargo test --workspace
```

## Recommended Next Step

Raise the bar from "refactored prototype" to "validated prototype":

1. run the workspace checks in a Rust-enabled environment
2. fix remaining compile or clippy issues
3. add cross-crate integration tests for `kernel-companion -> intent-bus -> agent-scheduler`
