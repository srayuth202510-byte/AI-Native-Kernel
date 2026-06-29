# Implementation Status

This note tracks the current repository state as implemented and locally validated in this workspace, not only the target architecture described in `docs/ai_native_kernel_plan_v2.html`.

Last verified: 2026-06-29

## Current Baseline

- Workspace crates exist for:
  - `kernel-companion`
  - `agent-scheduler`
  - `intent-bus`
  - `context-memory`
  - `compute-scheduler`
  - `capability-security`
  - `immune-system`
- The runtime graph is composed in `crates/kernel-companion/src/lib.rs`.
- The repository currently builds and tests successfully on the local pinned toolchain exposed by `scripts/use-local-toolchain.sh`.

## Implemented Now

<!-- IMPLEMENTED_NOW_START -->
### kernel-companion

- **[ANK-001] Setup Rust workspace + companion crate layout**: Workspace manifests และ crate layout ของ companion/co-crates coherent แล้ว และ validate ได้ด้วย local toolchain ใน workspace ปัจจุบัน.
- **[ANK-002] Prototype companion composition root**: kernel-companion ประกอบ intent bus, memory, security, compute, immune system, metrics server และ agent scheduler เป็น runtime เดียวกันได้แล้วในระดับ host-side prototype.
- **[ANK-003] Real eBPF syscall tracer (Aya)**: Aya loader, tracepoint attach path, และ prebuilt eBPF objects มีแล้ว; tracer รองรับ real attach และ simulation fallback แต่ real privileged attach ยังไม่ได้ re-validate ในรอบนี้.
- **[ANK-004] Phase 2 kick-off: eBPF/LSM module**: LSM policy engine, syscall allowlist profiles, tracer integration, PID deny propagation, และ companion-side enforcement flow มีแล้วใน host-side prototype.
- **[ANK-005] Aya toolchain + kernel target validation**: Toolchain pinning, prebuilt BPF objects, และ CI wiring มีแล้ว; local pinned toolchain ถูกยืนยันว่า compile/check/test ได้ใน workspace ปัจจุบัน แต่ privileged kernel attach path ยังต้องยืนยันบน host จริง.
- **[ANK-041] Production default: disable eBPF simulation fallback**: เสร็จแล้ว — default `enable_fallback = false` ใน config/default.toml และ code; dev สามารถเปิดผ่าน ANK_EBPF_ENABLE_FALLBACK=true หรือ --no-bpf-fallback=false
- **[ANK-042] NLP Intent Parser**: Lightweight intent classifier ใน kernel-companion ใช้ cosine similarity บน djb2 word-hash embeddings (128 dims) เพื่อจำแนก Intent จากภาษาธรรมชาติ.
- **[ANK-049] Config System (default.toml) + LSM Profiles + Runtime Switching**: Config struct พร้อม serde deserialize จาก config/default.toml, env override (ANK_*). รองรับ LSM profile switching ขณะรัน (kernel-companion) และ CLI toggle.
- **[ANK-050] eBPF Runtime Allowlist Expansion + Security Hardenings**: eBPF runtime allowlist ขยายพร้อม syscall profiles; EPERM macro ใน BPF program; real LSM eBPF security hooks; fail-closed enforcement path.
- **[ANK-052] ank-cli (UDS CLI) + ank-tui (TUI Dashboard)**: ank-cli: bidirectional UDS communication รองรับ spawn-agent, status, list-quarantine, set-threshold, set-lsm-profile, device-aware placement. ank-tui: real-time dashboard ด้วย ratatui + crossterm แสดง system stats.
- **[ANK-053] UDS Auth Hardening (Peer Credential + Socket Permission)**: Peer credential check ผ่าน nix::sys::socket::getsockopt (PeerCredentials) เพื่อ verify UID/GID; socket permission hardening (0o700); admin command separation.

### agent-scheduler

- **[ANK-006] AgentControlBlock + AgentState enum**: นิยาม struct และ state machine สำหรับ lifecycle ของ agent มีแล้ว พร้อม unit coverage.
- **[ANK-007] Agent spawn/pause/resume/terminate API**: Async API สำหรับควบคุม lifecycle มีแล้วและผ่าน unit, integration, และ perf-budget tests.
- **[ANK-008] Supervisor: restart/retry on fault**: Supervisor loop และ restart/retry path มีแล้ว และผ่าน chaos/integration tests; ยังควร review concurrency เพิ่มเมื่อขยายสเกล.
- **[ANK-009] Property test: scheduler state invariant**: เพิ่ม property tests แล้ว: invariant Running ≤ total spawned, terminate removes from count, error paths (double-pause, resume-running, nonexistent, duplicate ID) รวม 6 tests ผ่าน.
- **[ANK-010] Intent-driven scheduler routing**: รองรับ Command intent เช่น spawn-agent, Structured intent พร้อม metadata และ capability grant ผ่าน capability-security แล้ว.

### intent-bus

- **[ANK-021] Intent Bus (tokio broadcast)**: tokio::sync::broadcast channel สำหรับ Intent events มีแล้ว พร้อม subscriber filtering และ unit/integration tests.

### context-memory

- **[ANK-011] Prototype context manager + tier modules**: มี hot/warm/cold/VRAM tiers และ paging API ใช้งานได้จริง พร้อมการทดสอบ round-trip และ eviction.
- **[ANK-012] Warm tier (NVMe): RocksDB store**: RocksDB WarmStore implement แล้วด้วย feature flag `rocksdb-warm`. Default CI ใช้ in-memory (ไม่ต้อง NVMe). เปิดใช้ด้วย --features context-memory/rocksdb-warm. Snappy compression เปิดแล้ว. Cold→Warm load < 50ms ยังไม่ได้วัด benchmark จริง.
- **[ANK-013] Tier migration: Hot<->Warm<->Cold**: Bidirectional paging ระหว่าง tiers + fallback ไป Cold (file) เมื่อ RocksDB I/O error.
- **[ANK-014] Property test: context round-trip lossless**: Hot→Warm→Cold→Warm→Hot ต้องไม่สูญเสียข้อมูล
- **[ANK-043] P2P Context Mesh with real TCP networking**: Gossip-based P2P mesh ใน context-memory ใช้ tokio TCP (TcpListener/TcpStream) พร้อม NodeInfo, capability advertisement, gossip heartbeat, และ KV sync.
- **[ANK-044] P2P Trust Model + Conflict Resolution + Distributed Sync**: Trust scoring (100-0), conflict resolution สำหรับ records ที่ conflict, distributed context sync/fetch ผ่าน P2P mesh พร้อม fail-closed LSM gating เมื่อ mesh ล้มเหลว.
- **[ANK-055] RocksDB Warm Tier Persistent Configurable Path**: WarmStore รองรับ configurable RocksDB path (new_with_path); startup key scanning; persistent storage ผ่าน feature flag rocksdb-warm. เปิดใช้ด้วย --features context-memory/rocksdb-warm.

### compute-scheduler

- **[ANK-015] Prototype compute scheduler baseline**: มี compute-scheduler crate, cost function, adaptive weights และ target scoring พร้อม tests แล้ว.
- **[ANK-016] Real device-aware placement policy**: เพิ่มการเลือก backend จริงสำหรับ CPU/GPU/NPU ตาม latency, power และ monetary cost.
- **[ANK-045] llama.cpp + ONNX Runtime Integration**: InferenceRuntime enum (LlamaCpp/OnnxRuntime/TensorRtLlm) ใน compute-scheduler พร้อม mock execution model สำหรับ CPU/NPU/GPU placement decision.
- **[ANK-046] GPU/NPU Hardware Detection + Phase 2 Placement Policy**: HardwareProber ใช้ sysinfo + nvml-wrapper เพื่อสแกน CPU/GPU/NPU จริง; PlacementPolicy รองรับ WorkloadClass (KernelLogic/SmallLlm/LargeLlm/VectorIndexing) พร้อม async event flow.

### capability-security

- **[ANK-017] CapabilityToken struct + Scope enum**: นิยาม CapabilityToken และ Scope มีแล้วใน prototype พร้อม validation path และ tests พื้นฐาน.
- **[ANK-018] Policy Engine (fail-DENY)**: Policy engine default = DENY, capability allowlist, และ token validation/decision paths มีแล้ว; constant_time_eq ถูกใช้งานแล้ว.
- **[ANK-019] Persistent WORM audit logger**: Audit trail เป็น file-backed append-only log พร้อม hash chaining แล้ว; ยังควร harden เรื่อง fail-closed ordering ของ revoke path เพิ่ม.
- **[ANK-020] Security hardening: constant-time token comparison**: แทนที่การเทียบ token แบบปกติด้วย constant_time_eq ตาม security guideline ใน AGENTS.md.
- **[ANK-047] Automatic Capability Revoke + Expiry + Rate Limiting**: revoke_token() พร้อม callback propagation ไปยัง allowed_pids; token expiry check ในทุก decision path; rate-limited token issuance (max_issue_rate ปรับได้).
- **[ANK-048] Security Metrics / Prometheus Counters**: SecurityMetrics struct พร้อม Prometheus counters: tokens_issued_total, token_validation_failures_total, policy_decisions_total (allow/deny labels), audit_entries_total. ลงทะเบียนกับ global registry.
- **[ANK-054] Cryptographic Audit Log Validation**: Hash chain validation สำหรับ WORM audit log; cryptographic verification ของ log integrity; CLI integration สำหรับ log validation commands.

### immune-system

- **[ANK-031] Immune System: Macrophage Agent (GC)**: Macrophage Agent สำหรับ garbage collection: ตรวจ Intent หมดอายุ, sweep stale entries, รายงาน stats. 4 tests ผ่าน.
- **[ANK-032] Immune System: T-Cell Agent (Threat Detection)**: T-Cell Agent สำหรับ anomaly detection: ติดตาม syscall rate per PID, detect spikes, quarantine/kill threats. 4 tests ผ่าน.
- **[ANK-033] Immune System: B-Cell Agent (Pattern Learning)**: B-Cell Agent สำหรับเรียนรู้ attack patterns จาก T-Cell reports และสร้าง Antibody Rules (LSM policy). 3 tests ผ่าน.
- **[ANK-034] Immune System: Cytokine Signal (Critical Broadcast)**: Cytokine Signal สำหรับ broadcast ข้อความวิกฤต (Emergency/Critical/Warning/Info) ไปยัง Agents ทุกตัวผ่าน IntentBus. 3 tests ผ่าน.
- **[ANK-051] Closed-Loop Immune System Feedback + T-Cell Enhancements**: T-Cell ส่ง threat report ผ่าน IntentBus → B-Cell อ่านและสร้าง AntibodyRules (LSM policy) โดยอัตโนมัติ; T-Cell เพิ่ม anomaly_score, syscall_history, dynamic thresholds, quarantine expiry.

### infra

- **[ANK-022] Cargo workspace skeleton (7 crates)**: Workspace structure ครบและ crate wiring coherent แล้ว พร้อมการ validate ผ่าน local toolchain.
- **[ANK-023] Unit test baseline for core crates**: มี unit, integration, chaos, perf-budget, pipeline และ doc tests ครอบคลุม crate หลักของ workspace.
- **[ANK-024] Documentation + implementation status note**: อัปเดต README, board/tasks, และ implementation-status note ให้สะท้อนสถานะที่ตรวจยืนยันได้ของ workspace.
- **[ANK-025] CI: clippy + test + audit pipeline**: GitHub Actions มี fmt, clippy, tests, release build และ cargo audit.
- **[ANK-026] CI: fuzz + chaos test harness**: cargo-fuzz targets + failpoints harness สำหรับทุก Failure Domain (plan §5).
- **[ANK-027] Observability: tracing + Prometheus exporter**: มี tracing instrumentation และ Prometheus metrics HTTP server แล้ว.
- **[ANK-028] Build validation on real toolchain**: ยืนยัน local toolchain แล้วด้วย cargo fmt/check/clippy/test ใน workspace ปัจจุบัน.
- **[ANK-029] Security: sanitize .secret/ + .gitignore**: ลบ .secret/ ออกจาก repo, เพิ่ม .gitignore, rotate GitHub token + sudo password (leaked in filenames).
- **[ANK-030] Local toolchain bootstrap + workspace validation**: ใช้ scripts/use-local-toolchain.sh เพื่อ expose rustc/cargo แล้ว และยืนยันว่า workspace fmt/check/clippy/test ผ่านใน environment ปัจจุบัน.
- **[ANK-035] Security: upgrade protobuf 2.28 → 3.7 (RUSTSEC-2024-0437)**: อัปเดต prometheus 0.13 → 0.14 เพื่อแก้ vulnerability ใน protobuf 2.28.0 (RUSTSEC-2024-0437). cargo audit clean.
- **[ANK-036] Security: cargo-vet initialized + passing**: ติดตั้ง cargo-vet, รัน cargo vet init, ยืนยัน supply chain audit ผ่าน (149 exempted).
- **[ANK-038] Timeout hardening for external I/O paths**: ครอบ tokio::time::timeout ให้ external calls ที่ยังเหลือ เช่น Qdrant, TCP peer connect/accept/read paths และ network-facing endpoints ให้ตรงกับ AGENTS.md.
- **[ANK-039] CI-equivalent clippy validation (--all-targets --all-features)**: ผ่านแล้ว — cargo clippy --all-targets --all-features clean (0 errors, 0 lint warnings). เหลือแค่ info log จาก prebuilt eBPF objects.
- **[ANK-056] Cross-Crate Pipeline Integration Tests**: 11 cross-crate integration tests ครอบคลุม end-to-end pipeline: intent → scheduler → capability → LSM decision → audit log, พร้อม fault injection สำหรับทุก Failure Domain.
<!-- IMPLEMENTED_NOW_END -->

## Not Implemented Yet

<!-- NOT_IMPLEMENTED_YET_START -->
- **[ANK-037] Privileged eBPF/LSM validation with fallback disabled** (todo, critical): ยืนยัน real attach/enforcement บน host ที่มี kernel prerequisites ครบ และรันด้วย --no-bpf-fallback เพื่อพิสูจน์ fail-closed production path.
- **[ANK-040] Run ignored Qdrant-backed tests against reachable endpoint** (todo, med): รัน cargo test -p context-memory --lib -- --ignored หรือ scripts/run-qdrant-tests.sh กับ QDRANT_URL จริงเพื่อยืนยัน semantic store path.
<!-- NOT_IMPLEMENTED_YET_END -->

## Validation Status

<!-- VALIDATION_STATUS_START -->
- Re-validate with the pinned local toolchain from `scripts/use-local-toolchain.sh` when the environment changes.
- Recommended verification commands:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo test --workspace
```
<!-- VALIDATION_STATUS_END -->

## Recommended Next Step

Raise the bar from "validated host-side prototype" to "production-ready security baseline":

1. re-run privileged eBPF/LSM validation on a host with kernel prerequisites and fallback disabled
2. close the remaining timeout gaps on external I/O paths
3. verify the CI-equivalent lint path with `cargo clippy --all-targets --all-features -- -D warnings`
4. run the ignored Qdrant-backed tests against a reachable endpoint
