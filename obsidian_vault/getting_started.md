# Getting Started

This guide will help you set up and start working with the AI-Native Kernel project.

## Current State First

Before treating this repository as runnable, check the current implementation status in `obsidian_vault/implementation-status.md`.

The codebase currently provides a prototype runtime graph and unit-testable crate boundaries, but some design targets in the long-form plan are not implemented yet.

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Rust**: stable toolchain with Edition 2024 support
- **Kernel**: 5.4+ (for eBPF support)
- **Build Tools**: cargo, rustc, make

### Development Tools

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Optional hardware tools for future GPU/NPU work
sudo apt-get update
sudo apt-get install intel-gpu-tools
```

## Project Setup

### 1. Clone the Repository

```bash
cd /path/to
git clone https://github.com/srayuth202510-byte/AI-Native-Kernel.git

cd AI-Native-Kernel
```

### 2. Initialize Cargo Workspace

All components are managed as a single workspace. Run the following to initialize:

```bash
# Check if Rust toolchain is installed
cargo --version
rustc --version

# Generate workspace lockfile if needed
cargo generate-lockfile || true

# Verify workspace metadata
cargo metadata --no-deps
```

### 3. Environment Configuration

The current prototype does not require a full `.env` file to run unit tests. Start with the toolchain first, then add runtime settings only if you extend the daemon.

```bash
export RUST_LOG=info
```

### 4. Build the Project

```bash
# Quick type check
rtk cargo check

# Build for development
rtk cargo build

# Build for production
rtk cargo build --release

# All crates in the workspace
rtk cargo build --workspace
```

## Running the Prototype Companion

The current `kernel-companion` binary runs the prototype runtime graph and simulated LSM attachment flow.

### Start the Companion

```bash
cargo run -p kernel-companion
```

### Current Limitation

- There is no production health endpoint yet.
- The current daemon waits for `Ctrl+C` and shuts down cleanly.
- The eBPF path is still a stub.

## Testing the System

### Unit Tests

Run unit tests for individual components:

```bash
rtk cargo test -p agent-scheduler
rtk cargo test -p intent-bus
rtk cargo test -p capability-security
```

### Integration Tests

Run full integration tests:

```bash
rtk cargo test --workspace
```

## Working with Components

### kernel-companion

Start by reading:

- `crates/kernel-companion/src/lib.rs`
- `crates/kernel-companion/src/lsm.rs`
- `crates/kernel-companion/src/main.rs`

Those files describe the current prototype composition flow more accurately than the long-term design examples.

### agent-scheduler

The agent scheduler manages AI agent lifecycle and priorities.

#### Agent Control Block

```rust
#[derive(Debug, Clone)]
pub struct AgentControlBlock {
    pub id: u64,
    pub state: AgentState,
    pub priority: Priority,
    pub context_ptr: usize,
    pub capabilities: Vec<CapabilityToken>,
    pub restart_attempts: u32,
    pub last_restart: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentState {
    Creating,
    Running,
    Paused,
    Terminating,
    Failed,
    Restarting,
}
```

#### Priority System

The agent scheduler supports four priority levels:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    Eco,        // Energy-efficient, low priority
    Batch,      // Batch processing, medium priority  
    Interactive, // Interactive tasks, high priority
    RealTime,   // Real-time tasks, highest priority
}
```

### intent-bus

The intent bus handles user/AI application communication.

#### Intent Types

```rust
#[derive(Debug, Clone)]
pub enum IntentType {
    NaturalLanguage, // Natural language commands
    Structured,     // Structured data
    Command,        // Direct commands
    Event,          // Events from the system
    Interrupt,      // Interrupt signals
}
```

#### Intent Processing

```rust
pub async fn process_intent(&self, intent: Intent) {
    // Match on intent type for specialized handling
    match intent.intent_type {
        IntentType::NaturalLanguage => {
            let parsed = parse_natural_language(&intent.payload).await;
            // Route to appropriate agent
        }
        IntentType::Structured => {
            let structured = deserialize_structured(&intent.payload);
            // Process structured data
        }
        // ... other types
    }
}
```

## Development Workflow

### 1. Component Development

When adding a new component or modifying an existing one:

1. **Security First**: Ensure zero-trust principles are followed
2. **Async Design**: All I/O must be async with proper timeouts
3. **Error Handling**: Define domain errors and propagate them correctly
4. **Testing**: Write unit tests for the new functionality
5. **Integration**: Test with other components

### 2. Code Quality

Use the project's linting and formatting tools:

```bash
# Format code
rtk cargo fmt

# Check for warnings
rtk cargo clippy

# Run tests
rtk cargo test
```

### 3. Version Control

Follow the project's Git conventions:

- **Branch naming**: `feat/`, `fix/`, `chore/`, `docs/`
- **Commit messages**: Use conventional commits
- **Pull requests**: Reference issue/task numbers

## Configuration Files

### main.toml

```toml
[ai_kernel]
# Core settings
security_mode = "strict"
audit_enabled = true
worker_threads = 4

[hardware]
# Hardware detection and configuration
gpu_enabled = true
npu_enabled = true
nvme_enabled = true

[memory]
# Memory layer configuration
hot_memory_mb = 1024
warm_memory_gb = 100
cold_storage_tb = 10

[performance]
# Performance tuning
async_buffer_size = 1000
timeout_ms = 5000
batch_size = 100
```

## Monitoring and Observability

### Metrics

The system exposes metrics via Prometheus:

```rust
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub active_agents: u64,
    pub intent_processed: u64,
    pub policy_decisions: u64,
    pub memory_utilization: f64,
    pub cpu_utilization: f64,
}
```

### Logging

Structured logging with sanitization:

```rust
// Sanitize before logging
fn sanitize_log_entry(&self, entry: LogEntry) -> SanitizedLogEntry {
    let mut sanitized = entry;
    sanitized.sanitize_sensitive_data();
    return sanitized;
}
```

## Troubleshooting

### Common Issues

1. **No eBPF programs loading**
   - Check kernel version: `uname -r`
   - Verify eBPF kernel support: `grep CONFIG_BPF /proc/config.gz`
   - Ensure proper capabilities: `capsh --print`

2. **Deadlocks in async code**
   - Avoid holding locks across await points
   - Use `tokio::select!` for concurrent operations
   - Ensure proper ordering when acquiring multiple locks

3. **Memory issues**
   - Monitor hot memory usage: `AI_KERNEL_HOT_MEMORY_MB`
   - Check for memory leaks with `valgrind`
   - Ensure proper cleanup in drop handlers

4. **Component not communicating**
   - Verify channel sizes and buffer management
   - Check for backpressure handling
   - Ensure proper error propagation

### Debug Commands

```bash
# Check component status
cargo run --bin debug-components

# View live logs
tail -f /var/log/ai_kernel.log

# System health check
curl -X GET http://localhost:8080/health

# Component metrics scrape
curl http://localhost:8080/metrics
```

## Project Structure

```
AI-Native-Kernel/
├── Cargo.toml                    # Workspace manifest
├── crates/                      # All components
│   ├── kernel-companion/        # eBPF/LSM layer
│   ├── agent-scheduler/         # Agent management
│   ├── intent-bus/              # Intent communication
│   ├── context-memory/          # Memory paging
│   ├── compute-scheduler/       # Compute allocation
│   └── capability-security/     # Security layer
├── tests/                       # Test suites
│   ├── agent-scheduler/         # Agent scheduler tests
│   ├── intent-bus/              # Intent bus tests
│   ├── capability-security/     # Security tests
│   ├── context-memory/          # Memory tests
│   ├── compute-scheduler/       # Compute tests
│   └── integration/             # E2E tests
├── obsidian_vault/              # Documentation (this)
├── docs/                        # Architecture docs
├── benches/                     # Performance benchmarks
└── config/                      # Configuration files
```

## Next Steps

1. **Read** `AGENTS.md` for detailed coding conventions
2. **Build** the project: `rtk cargo build --release`
3. **Run tests**: `rtk cargo test -- --list`
4. **Explore components** in the `crates/` directory
5. **Contribute** by adding tests or fixing bugs

The AI-Native Kernel is a complex system, but following these guidelines will help ensure consistent, high-quality code. Good luck!

---

**Need Help?**  
- Check the [GitHub Issues](https://github.com/srayuth202510-byte/AI-Native-Kernel/issues)
- Ask questions in the project discussions
- Review the component documentation in `obsidian_vault/`
