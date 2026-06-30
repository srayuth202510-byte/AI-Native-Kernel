# Running the AI-Native Kernel

## Prerequisites

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | x86-64 / aarch64, 4 cores | 16+ cores |
| RAM | 8 GB | 64+ GB |
| Disk | 10 GB free | 100+ GB (NVMe) |
| GPU/NPU | (optional) | NVIDIA GPU / Intel NPU |

### Software

- **OS**: Linux 5.19+ (for BPF LSM support) — Ubuntu 22.04+, Debian 12+, Fedora 37+
- **Rust**: nightly toolchain (see `rust-toolchain.toml` — currently `nightly-2026-06-25`)
- **eBPF**: See [ebpf_prereqs.md](ebpf_prereqs.md) for full eBPF/LSM setup

Quick check:

```bash
./scripts/run.sh prereqs
./scripts/run.sh install-prereqs   # Debian/Ubuntu only
./scripts/run.sh validate-ebpf     # Privileged host validation for real attach
```

---

## Building

```bash
# Build everything (release)
./scripts/run.sh build

# Or with RocksDB warm store
cargo build --release --features context-memory/rocksdb-warm
```

Binaries produced:
- `target/release/kernel-companion` — the daemon
- `target/release/ank-cli` — CLI management tool
- `target/release/ank-tui` — terminal dashboard

---

## Single-Node Mode

### 1. Start the Daemon

```bash
# Default config (config/default.toml)
./scripts/run.sh companion

# Custom config
./scripts/run.sh companion -- -c /path/to/config.toml

# With eBPF simulation fallback (no root required)
ANK_EBPF_ENABLE_FALLBACK=true ./scripts/run.sh companion
```

The daemon loads config from `config/default.toml`, applies environment variable overrides (`ANK_*`), then boots all subsystems:

1. Config loader → parses TOML + env + CLI
2. Tracing init → structured logging via `tracing`
3. eBPF/LSM attach → hooks syscalls (falls back to simulation if `enable_fallback = true`)
4. Unix Domain Socket → listens at `uds_socket_path` for external intents
5. Intent Bus → starts the tokio broadcast event loop
6. Agent Scheduler → agent lifecycle + supervisor background task
7. Immune System → TCell, BCell, Macrophage background agents
8. Context Memory → Hot/Warm paging (P2P if enabled)
9. Compute Scheduler → CPU/GPU placement engine
10. Capability Security → WORM audit logger
11. Metrics server → Prometheus at `metrics_server_addr`
12. Ctrl+C handler → graceful shutdown

### 2. Verify Status

```bash
# In another terminal:
cargo run --release --bin ank-cli -- status
```

Expected output:

```
Agent Status: 0 running, 0 quarantined, 0 terminated
LSM Profile: runtime
Syscalls Traced: 127
Audit Entries: 0
Uptime: 5s
```

### 3. Spawn a Test Agent

```bash
cargo run --release --bin ank-cli -- spawn-agent \
  '{"agent_name":"hello-agent","description":"test agent"}'
```

### 4. Monitor via TUI

```bash
cargo run --release --bin ank-tui --
```

Press `q` or `Ctrl+C` to quit.

### 5. Shutdown

Press `Ctrl+C` in the daemon terminal. The companion performs a graceful shutdown:

- Drains in-flight intents
- Persists warm store
- Detaches eBPF/LSM hooks
- Flushes audit log
- Closes UDS socket

---

## Multi-Node Cluster Mode

### Overview

```
┌────────────────────────┐     Intent Bus Bridge (TCP)     ┌────────────────────────┐
│      node-alpha        │◄──────────────────────────────►│       node-beta        │
│  (compute-optimized)   │                                  │  (memory-optimized)    │
│  10.0.1.10:9091        │                                  │  10.0.1.20:9092        │
│  hot=1024 warm=8192    │                                  │  hot=2048 warm=65536    │
│  LSM=runtime           │                                  │  LSM=dev                │
└───────┬────────────────┘                                  └────────┬───────────────┘
        │                                                           │
        │                    P2P Gossip Mesh                        │
        │              (context memory replication)                 │
        └──────────────────────────┬────────────────────────────────┘
                                   │
                        ┌──────────▼──────────┐
                        │      node-gamma      │
                        │   (edge / secure)    │
                        │   10.0.1.30:9093     │
                        │   hot=128 warm=512   │
                        │   LSM=strict         │
                        └──────────────────────┘
```

### Cluster Configuration

Use `config/cluster.example.toml` as a starting point:

```bash
export ANK_CONFIG_PATH=config/cluster.example.toml
```

Each node overrides its identity and port via environment variables or a wrapper script.

### Start Each Node

**Terminal 1 — node-alpha:**

```bash
export ANK_NODE_ID=node-alpha
export ANK_METRICS_ADDR=0.0.0.0:9090
export ANK_HOT_CAPACITY=1024
export ANK_WARM_CAPACITY=8192
export ANK_LSM_PROFILE=runtime
./scripts/run.sh companion -- -c config/cluster.example.toml
```

**Terminal 2 — node-beta:**

```bash
export ANK_NODE_ID=node-beta
export ANK_METRICS_ADDR=0.0.0.0:9090
export ANK_HOT_CAPACITY=2048
export ANK_WARM_CAPACITY=65536
export ANK_LSM_PROFILE=dev
export ANK_INTENT_BUS_CAPACITY=4096
./scripts/run.sh companion -- -c config/cluster.example.toml
```

**Terminal 3 — node-gamma:**

```bash
export ANK_NODE_ID=node-gamma
export ANK_METRICS_ADDR=0.0.0.0:9090
export ANK_MAX_AGENTS=50
export ANK_HOT_CAPACITY=128
export ANK_WARM_CAPACITY=512
export ANK_LSM_PROFILE=strict
./scripts/run.sh companion -- -c config/cluster.example.toml
```

> **Note**: Each node on the same machine needs unique ports. The example config uses sequential ports (9091/9092/9093 for P2P, 9191/9192/9193 for bridge). On separate machines, reuse the same ports.

### What Happens in a Cluster

1. **P2P Context Sync** — Context Memory entries gossip across nodes. When `node-alpha` writes a hot context entry, `node-beta` and `node-gamma` eventually receive it via the gossip mesh (conflict resolution: trust score > version > node ID).

2. **Distributed Scheduling** — When `node-alpha` reaches 75% agent capacity (per `remote_overload_threshold_percent`), the scheduler considers remote nodes filtered by trust score >= 60. It ranks candidates by load, trust, and capability match before spawning the agent remotely.

3. **Intent Bridge** — Cross-node intent delegation uses TCP. `node-alpha` can send an intent to `node-beta` via the bridge peer definition `node-beta@10.0.1.20:9192`. Responses are routed back through the bridge.

4. **Unified Monitoring** — Each node exposes Prometheus metrics at its `metrics_server_addr`. A central Prometheus server can scrape all nodes.

---

## CLI Reference (`ank-cli`)

```bash
# General help
cargo run --release --bin ank-cli --

# Subcommands
cargo run --release --bin ank-cli -- status                          # System status
cargo run --release --bin ank-cli -- spawn-agent '<json>'            # Spawn an AI agent
cargo run --release --bin ank-cli -- list-quarantine                 # List quarantined PIDs
cargo run --release --bin ank-cli -- set-threshold <rate> <deny>     # Tune immune thresholds
cargo run --release --bin ank-cli -- set-lsm-profile <profile>       # Switch LSM profile live
cargo run --release --bin ank-cli -- verify-audit                    # Verify WORM audit integrity
cargo run --release --bin ank-cli -- place <json>                    # Placement query
```

### spawn-agent JSON Schema

```json
{
  "agent_name": "my-agent",
  "description": "what this agent does",
  "capabilities": ["vision", "nlp"],
  "compute_profile": "throughput",
  "memory_pages": 64,
  "timeout_secs": 300
}
```

---

## Environment Variables

| Variable | Corresponding Config | Default |
|----------|---------------------|---------|
| `ANK_CONFIG_PATH` | Config file path | `config/default.toml` |
| `ANK_LOG_LEVEL` | `general.log_level` | `info` |
| `ANK_UDS_SOCKET_PATH` | `kernel_companion.uds_socket_path` | `/tmp/ank-companion.sock` |
| `ANK_INTENT_BUS_CAPACITY` | `kernel_companion.intent_bus_capacity` | `1024` |
| `ANK_METRICS_ADDR` | `kernel_companion.metrics_server_addr` | `127.0.0.1:9090` |
| `ANK_MAX_AGENTS` | `agent_scheduler.max_agents` | `100` |
| `ANK_NODE_ID` | `agent_scheduler.local_node_id` | `node-local` |
| `ANK_HOT_CAPACITY` | `context_memory.hot_capacity` | `256` |
| `ANK_WARM_CAPACITY` | `context_memory.warm_capacity` | `1024` |
| `ANK_WARM_STORE_PATH` | `context_memory.warm_store_path` | `/tmp/ank-warm-store` |
| `ANK_AUDIT_LOG_PATH` | `capability_security.audit_log_path` | `/tmp/ank-audit.log` |
| `ANK_LSM_PROFILE` | `lsm.active_profile` | `runtime` |
| `ANK_EBPF_ENABLE_FALLBACK` | enables eBPF fallback | `false` |
| `ANK_RETRY_MAX_ATTEMPTS` | `retry_telemetry.retry_max_attempts` | `3` |
| `ANK_RETRY_INITIAL_BACKOFF_MS` | `retry_telemetry.retry_initial_backoff_ms` | `100` |
| `ANK_RETRY_BACKOFF_MULTIPLIER` | `retry_telemetry.retry_backoff_multiplier` | `2.0` |
| `ANK_RETRY_MAX_BACKOFF_MS` | `retry_telemetry.retry_max_backoff_ms` | `10000` |
| `ANK_RETRY_TIMEOUT_MS` | `retry_telemetry.retry_timeout_ms` | `5000` |
| `ANK_RETRY_USE_JITTER` | `retry_telemetry.retry_use_jitter` | `true` |
| `ANK_METRIC_CACHE_TTL_MS` | `retry_telemetry.metric_cache_ttl_ms` | `300000` |
| `ANK_TELEMETRY_SNAPSHOT_TTL_MS` | `retry_telemetry.telemetry_snapshot_ttl_ms` | `60000` |
| `ANK_AUDIT_LOG_TTL_MS` | `retry_telemetry.audit_log_ttl_ms` | `86400000` |
| `ANK_INTENT_METADATA_TTL_MS` | `retry_telemetry.intent_metadata_ttl_ms` | `300000` |
| `ANK_CLEANUP_INTERVAL_MS` | `retry_telemetry.cleanup_interval_ms` | `60000` |

---

## Common Operations

### Switch LSM Profile at Runtime

```bash
cargo run --release --bin ank-cli -- set-lsm-profile strict
```

Available profiles: `strict` (4 syscalls), `runtime` (67 syscalls), `dev` (75 syscalls).

### Check Quarantined Processes

```bash
cargo run --release --bin ank-cli -- list-quarantine
```

### Verify Audit Log Integrity

```bash
cargo run --release --bin ank-cli -- verify-audit
```

This checks the WORM (Write Once Read Many) audit log for tampering by validating the hash chain.

### Benchmark Warm Recovery

```bash
./scripts/run.sh validate-warm-bench
```

This includes a preflight check, a `--no-run` compile step, and the persistent warm-store reopen benchmark that measures Cold→Warm recovery time.
If `bindgen` cannot find `libclang`, set `LIBCLANG_PATH` or provide a host LLVM/libclang toolchain first.

### Validate P2P Mesh

```bash
./scripts/run.sh validate-p2p
```

This runs the distributed context mesh tests in `crates/context-memory/src/p2p_mesh.rs`.

### Run with eBPF Simulation (No Root)

```bash
ANK_EBPF_ENABLE_FALLBACK=true ./scripts/run.sh companion
```

The legacy alias `ANK_EARLY_BPF=true` is still accepted for compatibility.

Or in the config:

```toml
[ebpf]
enable_fallback = true
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `No such file or directory` for UDS socket | Parent dir missing | Create `/tmp/` or set `ANK_UDS_SOCKET_PATH` |
| `Permission denied` on eBPF attach | Missing capabilities | Run as root, or add `CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON` |
| `Connection refused` on bridge peer | Node not started or wrong port | Verify bridge peer address/port match `bridge_listen_addr` on remote |
| Agent fails to spawn | LSM profile too restrictive | Switch to `runtime` or `dev` profile |
| High latency on remote agent spawn | Network timeout | Increase `bridge_connect_timeout_ms` / `bridge_request_timeout_ms` |
| Warm store RocksDB lock error | Two instances sharing path | Set unique `warm_store_path` per node |

---

## See Also

- [Architecture Plan](ai_native_kernel_plan_v2.html) — full design document
- [eBPF Prerequisites](ebpf_prereqs.md) — kernel-level setup details
- [Task Board](board.html) — implementation progress
- [config/cluster.example.toml](../config/cluster.example.toml) — example cluster config
