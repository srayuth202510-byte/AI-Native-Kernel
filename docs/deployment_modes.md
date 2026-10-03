# Deployment Modes: Simulation vs Privileged

AI-Native Kernel operates in two distinct modes depending on kernel capabilities and privileges available at runtime. Understanding the difference is critical for development, testing, and production deployment.

---

## Mode Comparison

| Aspect | **Simulation Mode** (Default) | **Privileged Mode** (Production) |
|--------|------------------------------|----------------------------------|
| **eBPF/LSM Attach** | Userspace simulation — no kernel hooks | Real kernel attach via BPF LSM |
| **Syscall Interception** | Logged only, decisions made in userspace | Kernel-enforced ALLOW/DENY |
| **LSM Policy Decision** | Evaluated in companion daemon | Evaluated in kernel (fail-closed) |
| **Capability Tokens** | Tracked in daemon, revoked on expiry | Enforced at kernel via `blocked_pids` map |
| **Root Required** | No | Yes (or `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`) |
| **Kernel Requirements** | Linux 5.19+ | Linux 5.19+ with BTF (`/sys/kernel/btf/vmlinux`) |
| **Security Guarantees** | **Best-effort** — agent can bypass by not using UDS | **Strong** — kernel enforces default-DENY |
| **Use Case** | Development, CI, testing, demos | Production, security-critical workloads |

---

## How Mode Is Selected

The companion daemon runs **automated pre-flight diagnostics** at startup (`capability_detect::KernelCapabilityDetector::diagnose()`) and selects the recommended mode:

```rust
// crates/kernel-companion/src/capability_detect.rs
pub enum DeploymentMode {
    Real,        // Full kernel enforcement
    Simulation,  // Userspace fallback
}
```

### Decision Logic

1. **Check BTF**: `/sys/kernel/btf/vmlinux` readable?
2. **Check LSM**: `/sys/kernel/security/lsm` contains `bpf`?
3. **Check Privileges**: Can we `bpf(BPF_PROG_LOAD, ...)` and attach LSM?
4. **Check Headers**: `bpf/bpf_helpers.h` available for compilation?

If **all pass** → `DeploymentMode::Real`  
If **any fail** → `DeploymentMode::Simulation` (with detailed remediation logs)

---

## Running in Simulation Mode

**Default behavior** — no special flags needed:

```bash
# Just run the companion
./scripts/run.sh companion

# Or explicitly enable fallback
ANK_EBPF_ENABLE_FALLBACK=true ./scripts/run.sh companion
```

### What Works in Simulation

- Intent Bus routing and agent scheduling
- Context Memory paging (Hot/Warm/Cold/VRAM)
- Compute Scheduler placement decisions
- Capability token issuance/validation/revocation (userspace)
- Audit logging (WORM hash chain)
- Immune System (T/B/Macrophage agents)
- P2P Mesh context replication
- Semantic Guard / Extraction Detector (data-plane)
- AI Gateway proxy with policy enforcement

### What Does NOT Work in Simulation

- **Kernel-enforced syscall blocking** — agents can make syscalls directly
- **LSM hook decisions** — policy evaluated after-the-fact in userspace
- **PID-based revocation at kernel level** — relies on agent cooperating via UDS
- **cgroup-scoped default-DENY** (Hardening H1) — not enforced by kernel

> **Security Implication**: In simulation mode, a compromised agent that bypasses the UDS/API can execute arbitrary syscalls. Use only for development/testing.

---

## Running in Privileged Mode

### Prerequisites

```bash
# Verify host readiness
./scripts/check-ebpf-prereqs.sh

# Must pass all checks:
#   ✓ BTF: /sys/kernel/btf/vmlinux
#   ✓ LSM: bpf in /sys/kernel/security/lsm
#   ✓ Headers: bpf/bpf_helpers.h
#   ✓ Tools: clang, bpftool, libbpf-dev
#   ✓ Privileges: CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON (or root)
```

### Start Daemon with Real Enforcement

```bash
# Disable fallback explicitly (fail-closed)
ANK_EBPF_ENABLE_FALLBACK=false ./scripts/run.sh companion

# Or in config/default.toml:
[ebpf]
enable_fallback = false
```

### Verify Real Attach

```bash
# In another terminal - validate real kernel attach
sudo ./scripts/validate-ebpf-attach.sh

# Expected: PASS with metrics showing:
#   ank_ebpf_active_mode{mode="real"} 1
#   ank_lsm_active_mode{mode="real"} 1
```

### Run Privileged Integration Tests

```bash
# These tests REQUIRE real kernel attach
sudo ./run-privileged.sh cargo test -p kernel-companion --test privileged_h1_h2
sudo ./run-privileged.sh cargo test -p kernel-companion --test e2e_pipeline
```

---

## CI/CD Pipeline: Two Lanes

The project uses **two separate validation lanes**:

### Lane 1: CI (GitHub Actions `ci.yml`)
- Runs on **any** runner (no special privileges)
- Builds all crates, runs unit/integration tests in **simulation mode**
- Checks: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo audit`
- **Gate for PR merge**

### Lane 2: eBPF Validation (GitHub Actions `ebpf-validation.yml`)
- **Manual trigger only** — runs on self-hosted runner with labels:
  ```
  ["self-hosted", "linux", "x64", "ebpf-validation"]
  ```
- Requires provisioned host per `host_provisioning.md`
- Runs: `./scripts/run-full-validation-suite.sh`
- Validates real eBPF/LSM attach, warm-store benchmarks, full test suite
- **Gate for release tagging**

---

## Configuration Reference

### config/default.toml

```toml
[ebpf]
# Enable simulation fallback when kernel attach fails
# true  = Simulation Mode (default, no root needed)
# false = Privileged Mode (fail-closed, requires root/caps)
enable_fallback = true

[kernel_companion]
# UDS socket for external clients
uds_socket_path = "/tmp/ank-companion.sock"
# Metrics server address
metrics_server_addr = "127.0.0.1:9090"
# Intent bus channel capacity
intent_bus_capacity = 1024
# Monitoring channel capacity for supervisor
monitoring_channel_capacity = 100

[lsm]
# Active LSM profile: "strict" | "runtime" | "dev"
active_profile = "runtime"
# Agent cgroup path for Hardening H1 (default-DENY scope)
# If set, daemon creates/registers cgroup and fails boot if unavailable
# agent_cgroup_path = "/sys/fs/cgroup/ank-agents"

[agent_scheduler]
max_agents = 100
local_node_id = "node-local"
supervisor_interval_ms = 5000
max_restart_attempts = 3
distributed_enabled = false
remote_overload_threshold_percent = 75
min_remote_trust_score = 60
max_remote_candidates = 3

[context_memory]
hot_capacity = 256
warm_capacity = 1024
warm_store_path = "/tmp/ank-warm-store"

[capability_security]
audit_log_path = "/tmp/ank-audit.log"
max_issue_rate = 100

[compute_scheduler]
default_mode = "throughput"  # "throughput" | "battery" | "cost"

[immune_system]
rate_threshold = 100
deny_threshold = 0.7
kill_threshold = 0.9
tcell_check_interval_ms = 1000
quarantine_duration_secs = 300
# UID -> tenant_id mapping for tenant-keyed T-Cell (ANK-065)
# uid_to_tenant = { 1000 = "tenant-a", 1001 = "tenant-b" }

[retry_telemetry]
retry_max_attempts = 3
retry_initial_backoff_ms = 100
retry_backoff_multiplier = 2.0
retry_max_backoff_ms = 10000
retry_timeout_ms = 5000
retry_use_jitter = true
metric_cache_ttl_ms = 300000
telemetry_snapshot_ttl_ms = 60000
audit_log_ttl_ms = 86400000
intent_metadata_ttl_ms = 300000
cleanup_interval_ms = 60000
telemetry_publish_interval_ms = 10000
include_timestamps = true
auto_cleanup = true
```

### Environment Variable Overrides

All config values can be overridden via `ANK_*` environment variables (see `running.md` for full table).

Key mode-related overrides:

```bash
# Force simulation mode
ANK_EBPF_ENABLE_FALLBACK=true

# Force privileged mode (will fail boot if prerequisites missing)
ANK_EBPF_ENABLE_FALLBACK=false

# Switch LSM profile at runtime (via ank-cli)
# cargo run --release --bin ank-cli -- set-lsm-profile strict
```

---

## Development Workflow

### Daily Development (Simulation Mode)

```bash
# 1. Make changes
# 2. Fast type check
rtk cargo check

# 3. Run unit tests (simulation)
rtk cargo test --lib

# 4. Run integration tests (simulation)
rtk cargo test --test '*'

# 5. Format and lint
rtk cargo fmt --all -- --check
rtk cargo clippy -- -D warnings
```

### Pre-Release Validation (Privileged Mode)

```bash
# On provisioned host (see host_provisioning.md)
./scripts/run-full-validation-suite.sh

# Or step by step:
./scripts/check-ebpf-prereqs.sh
./scripts/run.sh validate-ebpf
./scripts/run.sh validate-warm-bench
rtk cargo test --workspace
rtk cargo bench --workspace
```

---

## Decision Matrix

| Scenario | Recommended Mode |
|----------|-----------------|
| Local development (laptop, no root) | Simulation |
| CI pipeline (GitHub Actions) | Simulation |
| Integration testing with mock services | Simulation |
| Security audit / penetration testing | Privileged |
| Staging environment | Privileged |
| Production deployment | Privileged |
| Demo / hackathon (no GPU/NPU) | Simulation |
| Benchmarking syscall latency | Privileged |

---

## Troubleshooting

| Symptom | Mode | Fix |
|---------|------|-----|
| `enable_fallback = false` but daemon starts in simulation | Privileged | Check `./scripts/check-ebpf-prereqs.sh` output; daemon logs show which check failed |
| `ank_ebpf_active_mode{mode="real"} 0` in metrics | Privileged | Verify BTF, LSM, and capabilities; check `dmesg` for BPF verifier errors |
| Tests pass in CI but fail in privileged validation | Both | Tests using simulation-specific mocks; check `#[cfg(test)]` vs real eBPF paths |
| `Permission denied` on eBPF attach | Privileged | Run as root or grant `CAP_BPF CAP_SYS_ADMIN CAP_PERFMON` |
| LSM hook not appearing in `/sys/kernel/security/lsm` | Privileged | Kernel config: `CONFIG_BPF_LSM=y`, `CONFIG_SECURITY_BPF=y` |

---

## Security Checklist for Production

- [ ] Running in **Privileged Mode** (`enable_fallback = false`)
- [ ] `validate-ebpf-attach.sh` passes on target host
- [ ] LSM profile set to `strict` or `runtime` (not `dev`)
- [ ] Agent cgroup configured (`lsm.agent_cgroup_path`) for Hardening H1
- [ ] Audit log path on persistent storage (not `/tmp`)
- [ ] WORM audit verification enabled (`ank-cli verify-audit` in monitoring)
- [ ] Capability token TTL configured appropriately
- [ ] Immune system thresholds tuned for workload (not defaults)
- [ ] P2P mesh TLS enabled (`mesh_tls` module) for multi-node
- [ ] Monitoring alerts configured for `ank_ebpf_active_mode{mode="simulation"}` (should be 0)

---

## Related Documents

- [Running the AI-Native Kernel](running.md) — operational guide
- [eBPF Prerequisites](ebpf_prereqs.md) — kernel-level setup details
- [Host Provisioning](host_provisioning.md) — provisioning validation hosts
- [Architecture Plan](ai_native_kernel_plan_v2.html) — full design (sections 2, 5, 9, 10)
- [Hardening Backlog](ai_native_kernel_plan_v2.html#section-9) — H1–H8 tracking