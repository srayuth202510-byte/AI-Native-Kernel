# Getting Started

This guide will help you set up and start working with the AI-Native Kernel project.

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ recommended)
- **Rust**: 1.72.0+ (Rust 2024 Edition)
- **Kernel**: 5.4+ (for eBPF support)
- **Build Tools**: cargo, rustc, make

### Development Tools

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Intel Graphics Drivers (for NPU support)
sudo apt-get update
sudo apt-get install intel-gpu-tools

# Install NVIDIA Drivers (for GPU support)
sudo ubuntu-drone nvidia-driver install

# Install ROCm (for AMD GPU/NPU support)
sudo apt-get install amdgpu-dkms
```

## Project Setup

### 1. Clone the Repository

```bash
cd /path/to
git clone https://github.com/srayuth202510-byte/AI-Native-Kernel.git

cd AI-Native-Kernel
cp .env.example .env
```

### 2. Initialize Cargo Workspace

All components are managed as a single workspace. Run the following to initialize:

```bash
# Check if Rust toolchain is installed
cargo --version

# Initialize workspace if needed
cargo generate-lockfile

# Check for common issues
cargo vet
```

### 3. Environment Configuration

The project uses environment variables for configuration. Create a `.env` file:

```bash
# Core Configuration
cARGO_INCREMENTAL=1
CARGO_TARGET_RELEASE_OPTIMIZATION=true

# Security
AI_KERNEL_SECURITY_MODE=strict
AI_KERNEL_AUDIT_ENABLED=true

# Compute Hardware
AI_KERNEL_GPU_ENABLED=true
AI_KERNEL_NPU_ENABLED=true

# Memory Configuration
AI_KERNEL_HOT_MEMORY_MB=1024
AI_KERNEL_WARM_MEMORY_GB=100
AI_KERNEL_COLD_STORAGE_TB=10

# Logging
RUST_LOG=info
AI_KERNEL_LOG_FORMAT=json

# Performance
AI_KERNEL_WORKER_THREADS=4
AI_KERNEL_ASYNC_BUFFER_SIZE=1000
```

### 4. Build the Project

```bash
# Quick format and type check
rtk cargo check

# Build for development
rtk cargo build

# Build for production
rtk cargo build --release

# All crates in the workspace
rtk cargo build --workspace
```

## Running the Companion Daemon

The kernel companion daemon is the main entry point for eBPF/LSM integration.

### Start the Companion

```bash
# From the project root
cargo run --bin companion-daemon

# Or run as a background service
systemd-run --user --section="[Service]" \
    --pty --working-directory=/path/to/AI-Native-Kernel \
    --setenv=RUST_LOG=info \
    --setenv=AI_KERNEL_SECURITY_MODE=strict \
    --setenv=AI_KERNEL_AUDIT_ENABLED=true \
    --user=$USER \
    --group=$USER \
    --no-block \
    --same-user \
    --ambient-capabilities=all \
    --exec /path/to/AI-Native-Kernel/target/release/companion-daemon \
    -- --listen 0.0.0.0:8080
```

### Verify Running

```bash
# Check if companion is running
ps aux | grep companion-daemon

# Check logs
journalctl -u companion-daemon -f --no-pager

# Health check
curl -X GET http://localhost:8080/health
```

## Testing the System

### Unit Tests

Run unit tests for individual components:

```bash
# Agent Scheduler tests
cd crates/agent-scheduler
rtk cargo test

# Intent Bus tests
cd crates/intent-bus
rtk cargo test

# Individual test modules
cd crates/context-memory
rtk cargo test --test integration_tests
```

### Integration Tests

Run full integration tests:

```bash
# From project root
cd /path/to/AI-Native-Kernel
cargo test --test integration_tests

# Fuzz tests (requires cargo-fuzz)
cargo fuzz run all

# Performance benchmarks
cargo bench
```

### Local Development Testing

Create a simple test scenario:

```rust
use tokio::sync::{broadcast, mpsc};
use std::time::Duration;

#[tokio::test]
async fn test_basic_workflow() {
    // Initialize components
    let intent_bus = IntentBus::new(100);
    let memory = ContextMemoryManager::new();
    let scheduler = AgentScheduler::new(intent_bus, memory);
    
    // Create an agent
    let agent = AgentControlBlock::new(1);
    agent.state = AgentState::Creating;
    
    // Spawn the agent
    assert!(scheduler.spawn_agent(agent).await.is_ok());
    
    // Verify it's running
    let agent = scheduler.get_agent(1).await.unwrap();
    assert_eq!(agent.state, AgentState::Creating);
    
    // Send an intent
    let intent = Intent::new(
        "test_intent".to_string(),
        IntentType::Command,
        "test_payload".to_string(),
    );
    intent_bus.publish(intent).await;
    
    // Verify intent was processed
    let mut subscriber = intent_bus.subscribe().await;
    let received = subscriber.receive().await.unwrap();
    assert_eq!(received.id, "test_intent");
}
```

## Working with Components

### kernel-companion

The eBPF/LSM layer is the lowest-level component. It intercepts syscalls and enforces policies.

#### eBPF Programs

The eBPF programs are in `crates/kernel-companion/src/ebpf/`:

```bash
# View eBPF code
cat crates/kernel-companion/src/ebpf/mod.rs

# Compile eBPF programs
cd crates/kernel-companion
cargo build --release --target x86_64-unknown-linux-musl
```

#### LSM Hooks

The LSM (Linux Security Modules) hooks are in `crates/kernel-companion/src/lsm/`:

```rust
// Example LSM hook implementation
#[lsm]
fn ai_lsm_security_hook(hook: &str, ctx: &mut LsmContext) -> Result<(), LsmError> {
    // Check capability tokens
    let token = validate_token_from_context(ctx)?;
    
    // Enforce policies
    if !policy_engine.check_permission(token, hook) {
        return Err(LsmError::PermissionDenied);
    }
    
    // Log the decision
    audit_logger.log_decision(token.id, hook, Decision::Allow);
    
    Ok(())
}
```

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