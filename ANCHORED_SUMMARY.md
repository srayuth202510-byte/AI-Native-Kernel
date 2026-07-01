# Anchored Summary — AI-Native Kernel

> Last updated: Thu Jul 02 2026

## Project State

Located at `/home/lokis/Documents/AI-Native-Kernel` — Rust workspace implementing an AI-Native OS Kernel with Hybrid-Companion architecture alongside Linux.

### Current Phase: Phase 2 — AI Runtime & Accelerators (nearly complete)

---

## Implemented Modules (crates)

### `compute-scheduler/` — **COMPLETE (all 86 tests passing)**

Main scheduling + hardware abstraction crate. **20 source modules.**

| Module | Status | Lines | Key Contents |
|--------|--------|-------|--------------|
| `engine.rs` | ✅ Done | ~350 | `AiEngine` enum (LLaMA, TensorRT, ONNX, VLLM, Cloud, MPS, NPU), trait dispatch + fallback chaining |
| `npu.rs` | ✅ Done | ~400 | Phase 2 NPU backends: **Intel OpenVINO**, **Qualcomm QNN/HTP**, **AMD XDNA**, **Samsung ENN**, **MediaPipe**; profiles → compute profiles, mock inference |
| `cuda_ffi.rs` | ✅ Done | ~120 | Real CUDA FFI via `libloading`: `libcuda.so` symbol resolution (`cuMemAlloc`, `cuMemFree`, `cuMemGetInfo`, `cuMemcpyHtoD`, `cuMemcpyDtoH`) |
| `rocm_ffi.rs` | ✅ Done | ~110 | Real ROCm FFI via `libloading`: `librocm-core.so` / `libamdhip64.so` symbol resolution (`hipMalloc`, `hipFree`, `hipMemGetInfo`, `hipMemcpy`) |
| `gpu_pool.rs` | ✅ Done | ~500 | GpuMemoryPool with oversubscription: allocate, deallocate, swap-out/swap-in (host RAM), auto-swap LRU eviction, `is_swapped`/`is_allocated`/`block_ids_for_agent`/`used_bytes_for_agent` helpers. Supports simulated + real CUDA/ROCm modes. |
| `gpu_oom.rs` | ✅ Done | ~320 | `GpuOomKiller`: priority-based VRAM OOM handler. Two-step strategy: (1) swap out lower-priority agent blocks, (2) kill lowest-priority agents if still OOM. Tracks `OomAction::SwappedOut` / `OomAction::Killed`. |
| `budget.rs` | ✅ Done | ~250 | `GpuBudgetController`: per-agent budgets, priority-aware preemption, pressure detection, `agent_ids()` |
| `vram_manager.rs` | ✅ Done | ~120 | High-level VRAM reservation, circuit breaker |
| `placement.rs` | ✅ Done | ~280 | Model placement logic: compute profile matching, hardware requirement checks, runtime selection (CPU/GPU/NPU) |
| `cost.rs` | ✅ Done | ~100 | Cost function: `score = w1·latency⁻¹ + w2·power⁻¹ + w3·cost⁻¹` |
| `weights.rs` | ✅ Done | ~120 | EWMA adaptive weight tuning, mode presets (throughput/battery/latency/cost) |
| `hardware.rs` | ✅ Done | ~60 | Hardware topology detection |
| `observer.rs` | ✅ Done | ~150 | System observer: battery events, GPU memory pressure, weight updates |
| `batching.rs` | ✅ Done | ~100 | Request batching and flush on timeout |
| `cloud.rs` | ✅ Done | ~200 | Cloud engine fallback with retry, jitter, health checks |
| `llama.rs` | ✅ Done | ~80 | llama.cpp engine bindings (stub) |
| `onnx.rs` | ✅ Done | ~70 | ONNX Runtime bindings (stub) |
| `vllm.rs` | ✅ Done | ~90 | vLLM engine bindings (stub) |
| `mps.rs` | ✅ Done | ~70 | Apple MPS engine bindings (stub) |
| `lib.rs` | ✅ Done | ~60 | Crate root: `resolve_engine`/`resolve_engine_with_fallback`, sub-module exports |

### Other Crates (Phase 1)

- `kernel-companion/` — eBPF/LSM hook layer via Aya (Phase 1 scaffold)
- `agent-scheduler/` — Agent lifecycle control blocks, priority queues
- `context-memory/` — Hot/Warm/Cold paging (RAM → RocksDB → disk)
- `capability-security/` — Zero-Trust capability tokens, WORM audit
- `intent-bus/` — Intent capture and event loop

---

## Recent Work (this session)

1. **Intel OpenVINO NPU backend** — Added OpenVINO profile runtime, driver patterns, Intel VPU hardware detection in `npu.rs`
2. **Qualcomm QNN/HTP NPU backend** — Added Qualcomm Hexagon/HTP profile, DSP driver patterns in `npu.rs`
3. **Real CUDA/ROCm FFI via libloading** — `cuda_ffi.rs` and `rocm_ffi.rs` dynamically load `libcuda.so`/`librocm-core.so` at runtime and resolve real symbols (`cuMemAlloc`, `cuMemFree`, `hipMalloc`, etc.). `gpu_pool.rs` calls these in non-simulated mode. Fallback to simulator when library unavailable.
4. **GPU memory oversubscription + host swap** — `gpu_pool.rs` extended with `swap_out`/`swap_in` (host RAM backup), `allocate_with_auto_swap` (LRU eviction), `is_swapped` tracking, and `block_ids_for_agent`/`used_bytes_for_agent` for the OOM killer.
5. **GPU OOM killer with priority-based preemption** — `gpu_oom.rs`: `GpuOomKiller` allocates VRAM with two-step OOM handling: (1) swap out lower-priority agent blocks automatically, (2) if swap insufficient, kill lowest-priority agents. Returns `OomAllocationResult { actions: Vec<OomAction> }` with `SwappedOut`/`Killed` records.

---

## Test Results

**All 86 compute-scheduler tests pass** across all 20 modules:
- 5 gpu_oom tests (swap/kill/resolve/priority)
- 8 gpu_pool tests (allocate/deallocate/swap/auto-swap/LRU)
- 6 budget tests (register/preempt/pressure/agent_ids/unregister)
- 7 engine tests (all engine variants, mock fallback, batch, health check)
- 4 placement tests (CPU/GPU/NPU, hardware reqs, runtime selection)
- 3 cost function tests
- 3 weights tests
- 5 npu tests (OpenVINO, QNN, XDNA, ENN, MediaPipe)
- 5 cuda_ffi + rocm_ffi tests (availability checks)
- 3+ observer tests
- 3 cloud tests
- 2 batching tests
- Plus integration tests and misc cross-module tests

**4 integration tests** (all_target_types_scorable, identical_profiles_choose_one, no_candidates_returns_error, weight_update_diverges_scores) also pass.

---

## Key Dependencies Added

```toml
libloading = { version = "0.8", optional = true }  # Dynamic CUDA/ROCm FFI
```

---

## Pending Work (Phase 2 remaining)

- [ ] Phase 2 NPU <-> agent-scheduler integration tests
- [ ] e2e pipeline: Intent → Compute → Agent → GPU memory
- [ ] Performance benchmarking (Criterion benches)
- [ ] Property-based tests (proptest) for OOM/scheduler invariants
