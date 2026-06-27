# SKILL.md - AI-Native Kernel Development Skill

> พยากรณ์เอกสารแผน: `docs/ai_native_kernel_plan_v2.html`
> มาตรฐานโค้ด / conventions: `AGENTS.md`

## Trigger Words

- `build`, `compile`, `lint`, `test`, `fuzz`, `bench`, `deploy`
- `ebpf`, `aya`, `syscall`, `trace`, `lsm`, `hook`
- `agent`, `scheduler`, `spawn`, `priority`, `lifecycle`, `supervisor`
- `context`, `paging`, `hot`, `warm`, `cold`, `vram`, `nvme`, `rocksdb`
- `compute`, `cost`, `gpu`, `npu`, `cuda`, `tensorrt`, `onnx`, `llama`
- `capability`, `token`, `policy`, `zero-trust`, `audit`, `worm`
- `intent`, `bus`, `event`, `loop`
- `crypto`, `sign`, `encrypt`, `hash`, `ed25519`, `aes-gcm`, `sha256`
- `observability`, `metrics`, `tracing`, `otel`, `prometheus`
- `release`, `version`, `changelog`

## Core Workflow

### 1. Start Development

```bash
rtk cargo check                           # Quick type check first
rtk cargo build --release                 # Full build
rtk cargo clippy -- -D warnings           # Lint
rtk cargo test                            # Run tests
```

### 2. Code Changes Checklist

Before any commit:
1. `rtk cargo fmt --all -- --check` - formatting
2. `rtk cargo clippy -- -D warnings` - zero warnings
3. `rtk cargo test` - all tests pass


### 3. Common Tasks

#### Add new module
```
1. Create crates/<crate>/src/<module>.rs with #[cfg(test)] mod tests
2. Add mod declaration in crates/<crate>/src/lib.rs
3. Add module-specific error type using thiserror
4. Write tests in same file
5. Run: rtk cargo test -p <crate> <module>
```

#### Add eBPF program (Aya)
```
1. Write eBPF program in crates/kernel-companion/src/ebpf/<name>.rs
2. Compile to BPF bytecode (BPF target)
3. Load from userspace via Aya API
4. Attach to tracepoint/kprobe/LSM hook
5. Add timeout wrapper on attach/load operations
6. Test with mock kernel + real kernel in CI (pin version)
```

#### Add Agent lifecycle state
```
1. Extend AgentState enum in agent-scheduler/src/block.rs
2. Add state transition logic in supervisor.rs (guarded by enum)
3. Add property test: state invariant must hold (Running+Ready+Waiting == active)
4. Add chaos test: fault injection on new state must not crash system
5. Update performance budget metric if new state affects spawn/switch latency
```

#### Add Capability Token scope
```
1. Extend Scope enum in capability-security/src/token.rs
2. Implement policy decision logic in policy.rs
3. Default = DENY on parse error / unrecognized scope
4. Add constant_time_eq for token comparison
5. Write audit log entry (ALLOW/DENY + reason)
6. Property test: expired tokens always rejected
```

#### Add Context tier migration
```
1. Implement migration in context-memory/src/<tier>.rs
2. Add timeout on I/O (NVMe, VRAM load)
3. Property test: round-trip Hot→Warm→Cold→Warm→Hot must be lossless
4. Add tracing span for latency measurement (compare vs Performance Budget)
5. Fallback to next tier on I/O error (circuit breaker)
```

#### Add Compute target
```
1. Implement target adapter in compute-scheduler/src/<target>.rs
2. Add to Decision Matrix in plan §3 Module 3
3. Run via Compute Scheduler with timeout (GPU inference: 60s, NPU: 30s)
4. Add circuit breaker: disable backend on OOM/driver hang, fallback to CPU
5. Benchmark: record actual latency/power/cost for EWMA weight update
```

## Security Patterns

### Never do this
```rust
// ❌ unwrap() in library code
let agent = agents.get(&id).unwrap();

// ❌ Logging secrets or PII
tracing::info!("Token: {:?}", token.token_id);

// ❌ Timing-dependent comparison
if token_a.token_id == token_b.token_id { ... }

// ❌ Missing timeout on external call (eBPF, GPU, NVMe)
let result = ebpf_program.run(input).await?;

// ❌ Policy Engine fails open on error
match policy.decide(&req) {
    Ok(allow) => allow,
    Err(_) => true,  // WRONG - default must be DENY
}

// ❌ Using raw String for secrets
let api_key = "sk-...";  // Use secrecy::SecretString
```

### Always do this
```rust
// ✅ Proper error propagation
let agent = agents.get(&id)
    .ok_or_else(|| SchedulerError::AgentNotFound { id })?;

// ✅ Sanitized logging (hash the token_id, don't log raw)
tracing::info!(
    agent_id = %agent.id,
    token_hash = %sha256_short(&token.token_id),
    "Capability check",
);

// ✅ Constant-time comparison
if constant_time_eq(&token_a.token_id, &token_b.token_id) { ... }

// ✅ Timeout on all external calls
tokio::time::timeout(
    Duration::from_millis(1),
    policy.decide(&req)
).await??;

// ✅ Policy Engine fails DENY (fail-closed)
match policy.decide(&req) {
    Ok(allow) => allow,
    Err(e) => {
        tracing::error!(error = %e, "Policy error - failing DENY");
        false
    }
}

// ✅ Secrets wrapped in SecretString
let api_key: SecretString = std::env::var("API_KEY")?.into();
```

## File Organization Rules

### Module file structure
```rust
// crates/<crate>/src/<module>.rs

// 1. Imports
use crate::capability::CapabilityToken;
use thiserror::Error;

// 2. Public types
#[derive(Debug, Clone)]
pub struct AgentControlBlock { ... }

// 3. Error type (one per module)
#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("Agent {id} not found")]
    AgentNotFound { id: u64 },
}

// 4. Public API
pub async fn spawn_agent(...) -> Result<AgentControlBlock, SchedulerError> { ... }

// 5. Private helpers
fn compute_priority(...) -> u8 { ... }

// 6. Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_agent() { ... }
}
```

## Dependency Management

### Adding new crates
```bash
cargo add <crate_name>

```

### Approved crates (security vetted)
- `tokio` - async runtime
- `tracing` - structured logging
- `thiserror` - error handling
- `anyhow` - application errors
- `serde` / `serde_json` - serialization
- `aya` - eBPF programs (userspace + kernel)
- `rocksdb` - embedded KV store (Warm context)
- `rusqlite` - audit log (WORM, Phase 1)
- `prometheus` / `metrics` - metrics export
- `proptest` / `quickcheck` - property testing
- `rstest` - parameterized testing
- `ed25519-dalek` - signing (capability tokens)
- `aes-gcm` - encryption
- `sha2` - hashing
- `secrecy` - secret handling
- `zeroize` - memory zeroing
- `constant_time_eq` - constant-time comparison
- `uuid` - agent/token IDs

### Phase 2+ crates (deferred)
- `llama-cpp` - LLM inference (CPU/NPU)
- `tensorrt` / `cudarc` - GPU inference
- `ort` (ONNX Runtime) - NPU inference

## Testing Strategy

| Layer | Tool | Target |
|-------|------|--------|
| Unit | `#[cfg(test)]`, `rstest` | > 85% per module |
| Property | `proptest`, `quickcheck` | 100% of public invariants |
| Integration | `tokio::test`, mock eBPF/LSM | all happy + error paths |
| Fuzz | `cargo-fuzz`, AFL | all parsers/decoders |
| Chaos | `failpoints`, custom harness | all Failure Domains (plan §5) |

### Key Property Test Invariants
1. **Agent Scheduler:** Running + Ready + Waiting == total active agents
2. **Capability Token:** expired tokens always rejected
3. **Context Memory:** Hot→Warm→Cold→Warm→Hot round-trip is lossless
4. **Cost Function:** selected target is global minimum for given weights

## Release Process

```bash
# 1. Update version in workspace Cargo.toml
# 2. Run full quality suite
rtk cargo clippy -- -D warnings
rtk cargo test

cargo audit

# 3. Build release
rtk cargo build --release

# 4. Tag
git tag -a v<version> -m "Release <version>"
git push origin v<version>
```

## Emergency Procedures

### eBPF program load failure (kernel version mismatch)
```rust
// Fail-open for syscalls + block new agents + alert
match aya::Bpf::load(code) {
    Ok(prog) => prog,
    Err(e) => {
        tracing::error!(error = %e, "eBPF load failed - entering Safe Mode");
        safe_mode::enter().await;  // block spawns, allow existing agents, alert
        return Err(KernelError::EbpfLoadFailed);
    }
}
```

### GPU OOM / Compute backend failure
```rust
// Circuit breaker + fallback to CPU
match gpu.infer(&batch).await {
    Ok(out) => out,
    Err(ComputeError::Oom) => {
        tracing::warn!("GPU OOM - circuit breaker opening");
        gpu_circuit_breaker.open();
        cpu.infer(&batch).await?  // fallback
    }
    Err(e) => return Err(e.into()),
}
```

### Context store corruption (RocksDB I/O error)
```rust
// Fallback to Cold (file) tier + queue repair
match warm_store.get(&ctx_id).await {
    Ok(ctx) => ctx,
    Err(ContextError::Io(e)) => {
        tracing::warn!(ctx_id = %ctx_id, "Warm store I/O - fallback to Cold");
        repair_queue.push(ctx_id).await;
        cold_store.get(&ctx_id).await?
    }
    Err(e) => return Err(e.into()),
}
```

### Policy Engine unreachable
```rust
// Fail-DENY (default closed)
match policy.decide(&req).await {
    Ok(decision) => decision,
    Err(e) => {
        tracing::error!(error = %e, "Policy unreachable - DENY");
        audit::log_deny(&req, "policy_unreachable").await;
        false
    }
}
```

## Performance Benchmarks

Target metrics (measured in `benches/` via Criterion):
- Agent spawn: **P99 < 500 µs** (Phase 1: 10 agents; Phase 2: 1000+)
- Agent ↔ Agent context switch: **P99 < 50 µs**
- Syscall decision (LSM policy): **P99 < 1 ms**
- Context load Cold→Warm (NVMe): **P99 < 50 ms**
- Context load Warm→Hot (RAM): **P99 < 10 ms**
- eBPF tracer overhead: **< 3% CPU**
- GPU inference: timeout **60 s** (circuit breaker on OOM)
- NPU inference: timeout **30 s**

## Phase Context

**Phase 1 (MVP) - current focus:**
- eBPF syscall tracer (read-only) on Linux x86_64
- Agent runtime (max 10 concurrent)
- Capability/LSM policy engine + WORM audit log
- Context Memory 2-tier (RAM + NVMe)
- See `docs/ai_native_kernel_plan_v2.html` §1.1 (scope) and §10 (success criteria)

**Phase 2+:** VRAM paging, Adaptive Compute Scheduler (GPU/NPU), Semantic FS, Distributed OS
