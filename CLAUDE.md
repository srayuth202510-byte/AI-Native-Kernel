> พยากรณ์เอกสารแผน: `docs/ai_native_kernel_plan_v2.html`

## Project Overview

AI-Native Kernel — Operating System Kernel สำหรับยุค AI ที่ทำงานแบบ **Hybrid-Companion** กับ Linux Kernel โดยใช้ <span>eBPF</span> และ <strong>LSM</strong> ดักจับ syscall และควบคุม AI Agents ผ่านระบบ Zero-Trust

- **Language:** Rust (Edition 2024)
- **Runtime:** Tokio async runtime (multi-threaded)
- **Kernel Interface:** eBPF (via Aya) + LSM Hooks
- **State:** Context Paging Memory (RAM → NVMe/RocksDB → VRAM in Phase 2)
- **AI Compute:** llama.cpp (CPU/NPU), TensorRT-LLM (GPU), ONNX Runtime (NPU)
- **Security:** Zero-Trust Capability Tokens, WORM Audit Logger
- **Observability:** tracing + OpenTelemetry + Prometheus metrics

## Architecture

```
User / AI Application
    │  Intent (NL or structured)
    ▼
Intent Bus (tokio::sync::broadcast)
    │
    ▼
Agent Scheduler (tokio::runtime) ── Capability & Security Manager (LSM Policy Engine)
    │                                  │
    ├── Context Memory Manager ─────────┤  (Hot/Warm/Cold paging)
    │                                  │
    ▼                                  ▼
Compute Scheduler (CPU/GPU/NPU)    Audit Logger (WORM)
    │
    ▼
Linux Kernel (eBPF/LSM Hooks via Aya)
    │
    ▼
Hardware (CPU / GPU / NPU / NVMe)
```

> แผนภาพเต็ม: ดู `docs/ai_native_kernel_plan_v2.html` หัวข้อ 2

## Project Structure

```
ai-native-kernel/
├── Cargo.toml                 # Workspace manifest
├── crates/
│   ├── kernel-companion/      # eBPF/LSM hook layer (Aya)
│   │   ├── src/
│   │   │   ├── main.rs        # Companion daemon bootstrap
│   │   │   ├── ebpf/          # eBPF programs (Aya)
│   │   │   └── lsm/           # LSM policy decision point
│   │   └── Cargo.toml
│   ├── agent-scheduler/       # Agent lifecycle + priority + isolation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── block.rs       # AgentControlBlock, AgentState
│   │       ├── priority.rs    # Priority queue (Eco/Batch)
│   │       └── supervisor.rs  # Restart/retry on fault
│   ├── context-memory/        # Hot/Warm/Cold paging manager
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── hot.rs         # RAM layer (Vec<f32>)
│   │       ├── warm.rs        # NVMe layer (RocksDB)
│   │       └── cold.rs        # Disk file fallback
│   ├── compute-scheduler/     # Cost function + adaptive weights
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── cost.rs        # Cost = w1·Lat + w2·Pow + w3·Cost
│   │       └── weights.rs     # EWMA adaptive weights
│   ├── capability-security/   # CapabilityToken + LSM policy + audit
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── token.rs       # CapabilityToken, Scope
│   │       ├── policy.rs      # Policy decision point (fail-DENY)
│   │       └── audit.rs       # WORM audit logger
│   └── intent-bus/            # Intent capture + event loop
│       └── src/lib.rs
├── tests/
│   ├── integration/           # End-to-end pipeline tests
│   ├── fuzz/                  # cargo-fuzz targets
│   └── fixtures/              # Shared test data
├── benches/                   # Criterion benchmarks
└── config/
    └── default.toml
```

## Coding Conventions

### Rust Style

- **Rust 2024 edition** - use latest stable features
- Follow `rustfmt` default style (run `rtk cargo fmt` before commit)
- Use `rtk cargo clippy` - zero warnings allowed in CI
- Prefer `thiserror` for domain errors, `anyhow` for application-level errors
- **Never use `unwrap()` in library code** - use proper error propagation with `?`
- Use `#[must_use]` on functions returning important values
- Prefer `Arc<T>` for shared immutable state, `Arc<RwLock<T>>` for mutable shared state
- Use `tokio::select!` for concurrent operations, not `futures::join!` unless truly parallel

### Naming

- `snake_case` for functions, variables, and modules
- `PascalCase` for types, traits, and enums
- `SCREAMING_SNAKE_CASE` for constants
- Module names: singular (e.g., `agent`, `context`, not `agents`)
- Error types: `XxxError` (e.g., `SchedulerError`, `ContextError`, `CapabilityError`)

### Error Handling

- Define domain errors in each module using `thiserror::Error`
- Chain errors: `map_err(|e| MyError::Context { source: e.into() })?`
- Log at `error!` level before returning error in service layer
- Never panic in production code paths - use `catch_unwind` for boundary points

### Async Patterns

- All I/O must be async (tokio runtime)
- Use `tokio::spawn` for fire-and-forget background tasks
- Use `tokio::sync::broadcast` for Intent Bus event broadcasting
- Use `tokio::sync::mpsc` for channel communication
- **Always use `tokio::time::timeout` for external calls** (eBPF, NVMe, GPU, NPU, network)
- Never block on async code (`block_on` only in tests/benchmarks)

### Security-First Rules

- **No raw strings for secrets** - use `secrecy::SecretString` or `zeroize::Zeroize`
- **No logging of PII/keys** - sanitize before writing to structured logs
- **Use `constant_time_eq`** for all comparison of sensitive data (tokens, hashes)
- **No `unsafe`** without explicit review and justification in comments

- **Policy Engine default = DENY** (fail-closed for security decisions)

## Build & Quality Commands

```bash
# Build
rtk cargo build --release          # Production build
rtk cargo check                    # Quick type check

# Lint & Format
rtk cargo clippy -- -D warnings    # Zero warnings
rtk cargo fmt --all -- --check     # Format check

# Test
rtk cargo test                     # Unit + integration tests
rtk cargo test --test '*'          # Integration tests only
cargo fuzz run <target>            # Fuzz testing (see tests/fuzz/)

# Audit

cargo audit                        # Security vulnerability scan
```

## Testing Requirements

- Unit tests: `#[cfg(test)]` in same file, integration tests in `tests/`
- Property tests: use `proptest` / `quickcheck` for invariants (scheduler, capability, cost function)
- Fuzz tests: use `cargo-fuzz` for all parsers/decoders
- Chaos tests: every Failure Domain (see plan §5) must have a fault injection test
- Test error paths, not just happy paths
- Use `rstest` for parameterized tests
- Test fixtures in `tests/fixtures/` for shared test data

**Coverage targets:** unit > 85% per module; fuzz corpus > 10M inputs with zero panics

## Git Conventions

- **Branch naming:** `feat/`, `fix/`, `chore/`, `docs/`
- **Commit messages:** `<type>: <description>` (e.g., `feat: implement eBPF syscall tracer`)
- Never commit secrets, keys, or PII
- Pre-commit hook runs `cargo fmt --all -- --check` automatically; fix with `cargo fmt --all` if it fails
- Run `rtk cargo clippy` and `rtk cargo test` before pushing
- PR description must reference issue/task number

## Performance Budget

See `docs/ai_native_kernel_plan_v2.html` §3 (per-module) and §10 (MVP success criteria).

Key targets:
- Agent spawn latency: **P99 < 500 µs**
- Agent ↔ Agent context switch: **P99 < 50 µs**
- Syscall decision (LSM policy): **P99 < 1 ms**
- eBPF tracer overhead: **< 3% CPU**
- Concurrent agents (Phase 1): **10**, (Phase 2+): **1,000+**

## Security Checklist (Every PR)

- [ ] No `unwrap()` in non-test code
- [ ] No secrets/keys in code or logs
- [ ] Error types defined and propagated correctly

- [ ] `unsafe` block justified (if any)
- [ ] `timeout()` applied to all external calls
- [ ] Structured logging with PII sanitized
- [ ] Policy Engine fails closed (DENY) on error
- [ ] Audit log entry written for every security decision (ALLOW/DENY)
<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->
