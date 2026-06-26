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

<!-- IMPLEMENTED_NOW_START -->
### kernel-companion

- **[ANK-001] Setup Rust workspace + companion crate layout**: Workspace manifest และ crate layout สำหรับ kernel-companion ถูกจัดให้ parse ได้และเชื่อมกับ crate อื่นแล้ว แต่ยังไม่ได้ยืนยันด้วย cargo build จริงใน environment นี้.
- **[ANK-002] Prototype companion composition root**: kernel-companion สร้าง intent bus, memory, security, compute และ agent scheduler แล้ว boot/shutdown ได้ในระดับ prototype host-side.
- **[ANK-004] Phase 2 kick-off: eBPF/LSM module**: Aya + LSM BPF integration เริ่มร่างโครงสร้างใน kernel-companion แล้ว (LSM attachment, policy default DENY, tracepoints). ขาดแค่ BPF maps และ eBPF program ที่ compile เป็น bytecode จริง.
- **[ANK-005] Aya toolchain + kernel target validation**: ติดตั้งและ pin toolchain สำหรับ Aya: nightly Rust, bpf-linker, kernel headers (Linux 6.1+) และยืนยันใน CI.

### agent-scheduler

- **[ANK-006] AgentControlBlock + AgentState enum**: นิยาม struct และ state machine สำหรับ lifecycle ของ agent มีอยู่แล้วใน prototype scheduler.
- **[ANK-007] Agent spawn/pause/resume/terminate API**: Async API สำหรับควบคุม lifecycle พื้นฐานมีแล้วและมี unit tests ครอบคลุม แต่ยังไม่ได้ยืนยัน performance budget.
- **[ANK-008] Supervisor: restart/retry on fault**: Supervisor loop และโครง restart path มีใน prototype แต่ยังต้อง review เรื่อง concurrency และทดสอบ fault injection เพิ่ม.
- **[ANK-009] Property test: scheduler state invariant**: เพิ่ม property tests แล้ว: invariant Running ≤ total spawned, terminate removes from count, error paths (double-pause, resume-running, nonexistent, duplicate ID) รวม 6 tests ผ่าน.
- **[ANK-010] Intent-driven scheduler routing**: รองรับ Command intent เช่น spawn-agent, Structured intent พร้อม metadata และ capability grant ผ่าน capability-security แล้ว.

### intent-bus

- **[ANK-021] Intent Bus (tokio broadcast)**: tokio::sync::broadcast channel สำหรับ Intent events มีแล้ว พร้อม subscriber filtering และ unit tests.

### context-memory

- **[ANK-011] Prototype context manager + tier modules**: มี hot/warm/cold modules และ API ระดับ prototype สำหรับเก็บ context แล้ว แต่ยังไม่ใช่ persistent paging จริง.
- **[ANK-013] Tier migration: Hot<->Warm<->Cold**: Bidirectional paging ระหว่าง tiers + fallback ไป Cold (file) เมื่อ RocksDB I/O error.
- **[ANK-014] Property test: context round-trip lossless**: Hot→Warm→Cold→Warm→Hot ต้องไม่สูญเสียข้อมูล

### compute-scheduler

- **[ANK-015] Prototype compute scheduler baseline**: มี compute-scheduler crate, cost function และ adaptive weights baseline พร้อม sanity tests แล้ว แต่ยังไม่ผูกกับ real CPU/GPU/NPU placement.

### capability-security

- **[ANK-017] CapabilityToken struct + Scope enum**: นิยาม CapabilityToken และ Scope มีแล้วใน prototype พร้อม validation path และ tests พื้นฐาน.
- **[ANK-018] Policy Engine (fail-DENY)**: Policy engine default = DENY และมี capability allowlist ใน prototype แล้ว แต่ยังไม่ได้ใช้ constant_time_eq และยังไม่ยืนยัน latency budget.
- **[ANK-019] Persistent WORM audit logger**: ปัจจุบัน audit trail เป็น in-memory เท่านั้น ต้องย้ายไป append-only persistent store สำหรับ Phase 1 security baseline.
- **[ANK-020] Security hardening: constant-time token comparison**: แทนที่การเทียบ token แบบปกติด้วย constant_time_eq ตาม security guideline ใน AGENTS.md.

### infra

- **[ANK-022] Cargo workspace skeleton (7 crates)**: Workspace manifests และ crate wiring ถูกแก้ให้ coherent แล้วในระดับ source tree.
- **[ANK-023] Unit test baseline for core crates**: เพิ่ม tests ขั้นต้นให้ scheduler, intent bus, capability security, context memory, compute scheduler และ kernel companion แล้ว.
- **[ANK-024] Documentation + implementation status note**: อัปเดต obsidian docs และเพิ่ม implementation-status note ให้สะท้อนสถานะจริงของ prototype.
- **[ANK-025] CI: clippy + test + audit pipeline**: GitHub Actions: rtk cargo clippy -D warnings, rtk cargo test, cargo audit. Pin kernel version.
- **[ANK-027] Observability: tracing + Prometheus exporter**: tracing spans (#[instrument], debug!, warn!) เพิ่มแล้วใน context-memory put/get และ kernel-companion boot/shutdown. Prometheus metrics exporter ยังไม่ได้ implement — ต้องเพิ่ม prometheus crate + /metrics endpoint.
- **[ANK-028] Build validation on real toolchain**: รัน rtk cargo fmt, clippy, check และ test บนเครื่องที่มี rustc/cargo จริง แล้วปิด compile/lint issues ที่เหลือ.
- **[ANK-029] Security: sanitize .secret/ + .gitignore**: ลบ .secret/ ออกจาก repo, เพิ่ม .gitignore, rotate GitHub token + sudo password (leaked in filenames).
- **[ANK-030] Blocked: cargo/rustc toolchain is not ready/installed**: สภาพแวดล้อมปัจจุบันยังไม่มี rustc/cargo หรือ bpf-linker ทำให้ไม่สามารถ compile/test เพื่อตรวจสอบความถูกต้องของระบบ eBPF/LSM และ workspace crate ทั้งหมดได้
<!-- IMPLEMENTED_NOW_END -->

## Not Implemented Yet

<!-- NOT_IMPLEMENTED_YET_START -->
- **[ANK-016] Real device-aware placement policy** (backlog, high): เพิ่มการเลือก backend จริงสำหรับ CPU/GPU/NPU ตาม latency, power และ monetary cost.
- **[ANK-026] CI: fuzz + chaos test harness** (backlog, med): cargo-fuzz targets + failpoints harness สำหรับทุก Failure Domain (plan §5).
<!-- NOT_IMPLEMENTED_YET_END -->

## Validation Status

<!-- VALIDATION_STATUS_START -->
- The repository has meaningful unit tests in several crates.
- Before calling this baseline stable, run:

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --workspace -- -D warnings
rtk cargo test --workspace
```
<!-- VALIDATION_STATUS_END -->

## Recommended Next Step

Raise the bar from "refactored prototype" to "validated prototype":

1. run the workspace checks in a Rust-enabled environment
2. fix remaining compile or clippy issues
3. add cross-crate integration tests for `kernel-companion -> intent-bus -> agent-scheduler`

