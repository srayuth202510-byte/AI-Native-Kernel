# Implementation Status

This note tracks the current repository state as implemented and locally validated in this workspace, not only the target architecture described in `docs/ai_native_kernel_plan_v2.html`.

Last verified: 2026-07-10 — **516 tests pass** (4 ignored, Qdrant-backed — now also run against a real Qdrant in CI), clippy clean, cargo audit clean. Hardening backlog H1–H8 complete (see §"Hardening Round 2026-07-10"); H1/H2/H3/H8 + H6/H7 validated end-to-end.

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
- **[ANK-037] Privileged eBPF/LSM validation with fallback disabled**: ยืนยัน real attach/enforcement บน host ที่มี kernel prerequisites ครบ และรันด้วย --no-bpf-fallback เพื่อพิสูจน์ fail-closed production path.
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
- **[ANK-040] Run ignored Qdrant-backed tests against reachable endpoint**: รัน cargo test -p context-memory --lib -- --ignored หรือ scripts/run-qdrant-tests.sh กับ QDRANT_URL จริงเพื่อยืนยัน semantic store path.
- **[ANK-043] P2P Context Mesh with real TCP networking**: Gossip-based P2P mesh ใน context-memory ใช้ tokio TCP (TcpListener/TcpStream) พร้อม NodeInfo, capability advertisement, gossip heartbeat, และ KV sync.
- **[ANK-044] P2P Trust Model + Conflict Resolution + Distributed Sync**: Trust scoring (100-0), conflict resolution สำหรับ records ที่ conflict, distributed context sync/fetch ผ่าน P2P mesh พร้อม fail-closed LSM gating เมื่อ mesh ล้มเหลว.
- **[ANK-055] RocksDB Warm Tier Persistent Configurable Path**: WarmStore รองรับ configurable RocksDB path (new_with_path); startup key scanning; persistent storage ผ่าน feature flag rocksdb-warm. เปิดใช้ด้วย --features context-memory/rocksdb-warm.
- **[ANK-058] KV Cache Paging & Eviction Model for VRAM Tier**: พัฒนาโครงสร้างข้อมูล KvCachePage สำหรับจัดเก็บ key/value tensors และจัดระบบ Paging สลับหน่วยความจำของหน้าบริบทย้ายเข้า-ออกระหว่าง RAM (Hot) และ VRAM (Vram) เพื่อความเสถียรของ Multi-tenant GPU.

### compute-scheduler

- **[ANK-015] Prototype compute scheduler baseline**: มี compute-scheduler crate, cost function, adaptive weights และ target scoring พร้อม tests แล้ว.
- **[ANK-016] Real device-aware placement policy**: เพิ่มการเลือก backend จริงสำหรับ CPU/GPU/NPU ตาม latency, power และ monetary cost.
- **[ANK-045] llama.cpp + ONNX Runtime Integration**: InferenceRuntime enum (LlamaCpp/OnnxRuntime/TensorRtLlm) ใน compute-scheduler พร้อม mock execution model สำหรับ CPU/NPU/GPU placement decision.
- **[ANK-046] GPU/NPU Hardware Detection + Phase 2 Placement Policy**: HardwareProber ใช้ sysinfo + nvml-wrapper เพื่อสแกน CPU/GPU/NPU จริง; PlacementPolicy รองรับ WorkloadClass (KernelLogic/SmallLlm/LargeLlm/VectorIndexing) พร้อม async event flow.
- **[ANK-057] llama.cpp + ONNX Runtime Dynamic FFI Linkers**: พัฒนาระบบโหลดสัญลักษณ์ไลบรารีภายนอกแบบไดนามิก (Dynamic FFI loader via dlopen/dlsym) สำหรับ ONNX Runtime และ llama.cpp เพื่อความยืดหยุ่นในการ Compile และตัด Dependencies ส่วนเกิน.
- **[ANK-059] Multi-tenant GPU VRAM Budget Manager & Circuit Breaker**: ออกแบบ GpuVramManager ในการจอง ตรวจสอบ และจำกัดการใช้ VRAM ของแต่ละ Agent โดยมีการตัดการทำงานของระบบ Circuit Breaker เมื่อปริมาณ VRAM เกินค่าขีดจำกัดความปลอดภัย (เช่น 90.0%) เพื่อป้องกัน GPU OOM.

### capability-security

- **[ANK-017] CapabilityToken struct + Scope enum**: นิยาม CapabilityToken และ Scope มีแล้วใน prototype พร้อม validation path และ tests พื้นฐาน.
- **[ANK-018] Policy Engine (fail-DENY)**: Policy engine default = DENY, capability allowlist, และ token validation/decision paths มีแล้ว; constant_time_eq ถูกใช้งานแล้ว.
- **[ANK-019] Persistent WORM audit logger**: Audit trail เป็น file-backed append-only log พร้อม hash chaining แล้ว; ยังควร harden เรื่อง fail-closed ordering ของ revoke path เพิ่ม.
- **[ANK-020] Security hardening: constant-time token comparison**: แทนที่การเทียบ token แบบปกติด้วย constant_time_eq ตาม security guideline ใน AGENTS.md.
- **[ANK-047] Automatic Capability Revoke + Expiry + Rate Limiting**: revoke_token() พร้อม callback propagation ไปยัง blocked_pids (global default-allow LSM hook, deny เฉพาะ PID ที่ถูกบล็อก); token expiry check ในทุก decision path; rate-limited token issuance (max_issue_rate ปรับได้).
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

### Hardening Round 2026-07-09

- **Panic-path elimination**: กำจัด `unwrap()`/`expect()` ทั้งหมดใน production code — engine constructors คืน `Result<Self, EngineError>` ผ่าน [[build_http_client]], lock poisoning กู้ด้วย `PoisonError::into_inner`, metrics registration มี isolated-registry fallback.
- **Audit logger rewrite** ([[audit-record]]): tail-read O(1) แทนการอ่าน+parse ทั้งไฟล์ (57.8ms → 81µs บน grant_capability, -99.87%); persistent write handle + writer lock แก้ hash chain fork และบรรทัดปนกันจาก concurrent writers; ซ่อมบรรทัดครึ่งท่อนจาก mid-write crash ตอนเปิดไฟล์.
- **TCell hot path** ([[observe_syscall]]): `RwLock<HashMap>` → DashMap (per-shard lock) + `Arc<str>` (1 alloc/event) — ~136ns/event sequential, ~71ns/event ที่ 8-way concurrency (~14M events/s).
- **Constant-time token equality**: `CapabilityToken` ใช้ manual `PartialEq` ผ่าน `constant_time_eq` กับ secret (เดิม derive เทียบ short-circuit = timing side channel).
- **Property tests (14)**: zero-trust invariants ([[policy-decision]]), cost monotonicity ([[choose_best]]), priority-queue ordering.
- **Chaos tests (+6)**: concurrent audit hash chain, restart tail recovery, partial-line repair, unwritable path, TCell concurrent quarantine, intent-bus slow-subscriber overflow.
- **Fuzz repair + expansion**: fuzz manifest เดิมไม่มี [[bin]] และใช้ workspace deps ทั้งที่ไม่อยู่ใน workspace — targets ไม่เคยถูก compile; ซ่อมแล้ว + async calls รันจริงผ่าน runtime + เพิ่ม 3 targets ใหม่ (audit_entry, config_toml, uds_command) รวมเป็น 7.
- **CVE**: crossbeam-epoch 0.9.18 → 0.9.20 (RUSTSEC-2026-0204).
- **Benchmarks**: เพิ่ม immune_bench (crate สุดท้ายที่ยังไม่มี bench); ทุก bench เขียน audit log ลง temp path (เดิมสะสม 2.9GB ใน crate dirs — ลบแล้ว).

### Hardening Round 2026-07-10 — Security Backlog H1–H6

ที่มา: commit `d728095d` ต้องกลับ LSM PID gate เป็น block-list (default-ALLOW) เพื่อไม่ให้ host ค้าง ซึ่งขัดหลัก fail-DENY — backlog นี้ย้าย trust boundary ลงชั้นที่ปลอมไม่ได้จริง ครบทั้ง host (H1–H5) และ network (H6). แผนเต็มดู `docs/ai_native_kernel_plan_v2.html` §9.1.

- **[H1] cgroup-scoped allow-list** — LSM gate เช็ค cgroup v2 id: host world ปล่อยผ่าน, agent cgroup ที่ลงทะเบียนเป็น **default-DENY** เว้นแต่ PID อยู่ใน allow-list; quarantine (`blocked_pids`) ชนะทุกกรณี. Opt-in `lsm.agent_cgroup_path`, fail-closed ตอน boot. **✅ validated end-to-end บน kernel 7.0.0-27** (`scripts/validate-ebpf-attach.sh`: unauthorized process ใน cgroup โดน `-EPERM`, host ไม่กระทบ).
- **[H2] unforgeable process identity** — allow-list ผูกกับ `(PID, start_time)` (`/proc/<pid>/stat` field 22 == `task->group_leader->start_boottime` ใน BPF) กัน PID reuse; `allow_pid` fail closed เมื่ออ่าน `/proc` ไม่ได้. **✅ validated end-to-end** (`tests/privileged_h1_h2.rs`: authorize flow จริง — allow path ผ่าน, deny path บล็อก).
- **[H3] intent → scope compiler** — `kernel-companion/src/scope.rs`: compile token caps (grant) + intent metadata (narrow เท่านั้น) → operation-class flags + path prefix, push ลง BPF maps ก่อน agent เริ่มงาน; kernel บังคับ path ด้วย `bpf_d_path`. **✅ validated end-to-end** (in-scope allow / out-of-scope deny / exec deny). BPF gotchas: hook ต้องใช้ `BPF_PROG(...)`, buffer ของ `bpf_d_path` ต้อง zero-init.
- **[H4] real-time revocation** — TCell quarantine/kill เขียน `blocked_pids` map แบบ synchronous ก่อน audit/broadcast (`apply_immune_revocation`) แล้วเพิกถอน token ปิดหน้าต่างที่ agent ยิง syscall ต่อได้ระหว่างรอ token expiry. **✅ unit-tested** (simulation); ยังไม่ทดสอบภายใต้ syscall load จริง.
- **[H5] VRAM tier lossless migration** — `compute-scheduler/src/gpu_pool.rs`: `migrate_to_cpu` ทำ DtoH copy จริงรักษาข้อมูล (เดิม free ทิ้ง = data loss) + เพิ่ม `migrate_to_gpu` คู่กัน HtoD. **✅ simulation round-trip**; real-GPU byte-for-byte test พร้อมรัน รอเครื่อง CUDA/ROCm.
- **[H6] P2P mesh mutual auth + integrity** — `context-memory/src/mesh_auth.rs`: HMAC-SHA256 (pre-shared key ต่อ mesh) + replay guard (timestamp window + nonce dedup) ทุกข้อความ; companion fail closed ถ้าเปิด mesh โดยไม่ตั้ง `p2p_mesh_key_hex`. **✅ validated** (E2E TCP loopback: matching-key เชื่อมได้/wrong-key ถูกปฏิเสธ).
- **[H7] P2P mesh confidentiality (mTLS)** — `context-memory/src/mesh_tls.rs`: เข้ารหัสสายด้วย TLS 1.3 โดยไม่ต้องมี PKI — derive cert/key แบบ deterministic จาก PSK เดียวกับ H6 (SHA256 seed → Ed25519 → rcgen self-signed) แล้ว pin peer cert ด้วย rustls custom verifier; wrap TLS ใน `start_listener`/`connect_to_peer`. **✅ validated** (E2E: matching-PSK handshake ผ่าน, wrong-PSK ถูกปฏิเสธที่ชั้น TLS ก่อนถึง HMAC). Operator ยังจัดการ secret เดียว (`p2p_mesh_key_hex`).
- **[H8] capability-scoped skill manifests** — `kernel-companion/src/skill.rs`: skill.md-style manifest (TOML frontmatter, `+++`) ประกาศ routing (`description`) + placement (`model`/`compute`) + capability scope (`[capabilities]`) ในไฟล์เดียว; `to_intent()` แปลง `allow` เป็น H3 narrow-only (skill ลดสิทธิ์ token ได้อย่างเดียว); `SkillRegistry` โหลด+route. ต่อ `authorize_process_token_with_scope` (H3) โดยไม่มี enforcement code ใหม่. **✅ validated end-to-end บน kernel 7.0.0-27** — agent จาก skill file-only เปิด in-scope ได้ / out-of-scope + exec โดนปฏิเสธตามที่ manifest ประกาศ. "ความถนัด = kernel-enforced least-privilege".
<!-- IMPLEMENTED_NOW_END -->

## Not Implemented Yet

<!-- NOT_IMPLEMENTED_YET_START -->

<!-- NOT_IMPLEMENTED_YET_END -->

## Validation Status

<!-- VALIDATION_STATUS_START -->
- Re-validate with the pinned local toolchain from `scripts/use-local-toolchain.sh` when the environment changes.
- Recommended verification commands:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
./scripts/run-all-tests.sh
cargo bench --bench scheduler_bench --bench security_bench --bench compute_bench --bench memory_bench --bench intent_bus_bench --bench companion_bench -- --quick
./scripts/run-warm-bench.sh
```
<!-- VALIDATION_STATUS_END -->

## Recommended Next Step

Hardening backlog H1–H6 is complete; two validations remain gated on hardware this workspace lacks, plus follow-on security work:

1. **H4 under real syscall load** — drive TCell past its threshold on a privileged host and confirm the kernel cut lands within budget (currently unit-tested logic only).
2. **H5 on a real GPU** — run `validate_real_gpu_migrate_round_trip_preserves_bytes` on a CUDA/ROCm host (test is written, skips without a runtime).
3. verify latency performance regularly against the benchmarks budget on production targets.
