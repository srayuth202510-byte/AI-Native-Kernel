# AI-Native Kernel - Component Documentation

## Overview

The AI-Native Kernel is a hybrid companion to the Linux kernel that provides AI-specific capabilities through eBPF and LSM hooks. This Obsidian vault documents each component's architecture, implementation, and integration patterns.

## Architecture Overview

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

## Quick Links

- [Components Overview](components/README.md)
- [Getting Started](getting_started.md)
- [Security Architecture](security/README.md)
- [Async Patterns](async-patterns.md)
- [Error Handling](error-handling.md)
- [Testing](testing/README.md)

## Components

### kernel-companion

The eBPF/LSM layer that intercepts and controls syscalls.

- **Files**: `crates/kernel-companion/src/`
- **Key Features**: Context paging, policy enforcement, audit logging
- **Integration**: Works directly with Linux kernel hooks

**See**: `kernel-companion/` directory

### agent-scheduler

Manages AI agent lifecycle, priorities, and isolation.

- **Files**: `crates/agent-scheduler/src/`
- **Key Features**: AgentControlBlock, priority queues, auto-restart
- **Integration**: Connected to Intent Bus for communication

**See**: `agent-scheduler/` directory

### intent-bus

Event-driven communication for user/AI intents.

- **Files**: `crates/intent-bus/src/`
- **Key Features**: Intent processing, filtering, broadcasting
- **Integration**: Core communication layer for the system

**See**: `intent-bus/` directory

### context-memory

Hot/Warm/Cold memory paging manager.

- **Files**: `crates/context-memory/src/`
- **Key Features**: RAM (hot) → NVMe (warm) → VRAM (cold)
- **Integration**: Used by Agent Scheduler for context storage

**See**: `context-memory/` directory

### compute-scheduler

CPU/GPU/NPU allocation and optimization.

- **Files**: `crates/compute-scheduler/src/`
- **Key Features**: Cost function, adaptive weights, hardware optimization
- **Integration**: Powers Agent Compute Scheduler

**See**: `compute-scheduler/` directory

### capability-security

Zero-trust capability tokens and policy engine.

- **Files**: `crates/capability-security/src/`
- **Key Features**: Token validation, LSM policies, audit trails
- **Integration**: Security layer for all components

**See**: `capability-security/` directory

## Development Workflow

### 1. Component Development

Each component follows the same pattern:

```rust
#![deny(unsafe_code)]
use tokio::sync::{RwLock, mpsc, broadcast};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ComponentName {
    // State management with Arc<RwLock> for shared access
    state: Arc<RwLock<ComponentState>>,
    // Async channels for communication
    tx: mpsc::Sender<Message>,
    rx: Arc<RwLock<mpsc::Receiver<Message>>>,
}

impl ComponentName {
    pub fn new() -> Self {
        // Initialize with proper error handling
    }
    
    pub async fn process(&self, input: InputType) -> Result<OutputType, ComponentError> {
        // Use tokio::select! for concurrent operations
        // Always use tokio::time::timeout for external calls
    }
}
```

### 2. Security Principles

**Fail-Closed by Default**: Every security decision defaults to DENY unless explicitly allowed.

**Zero-Trust Tokens**: All interactions use capability tokens with:
- Scope validation (process/thread/global)
- Expiration timestamps
- Auditable access logs

**No Secrets in Code**: Use `secrecy::SecretString` for sensitive data.

### 3. Async Patterns

**Always Async**: Every I/O operation must be async.

**Channel Usage**:
- `broadcast::Sender` for Intent Bus communication
- `mpsc::Sender` for fire-and-forget background tasks
- `RwLock` for shared read/write access

**Timeouts**: All external calls must use `tokio::time::timeout`.

### 4. Error Handling

**Domain Errors**: Each module defines its own error type.

**Error Propagation**: Use `?` for proper error chaining.

**Logging**: Log at `error!` level before returning errors in service layer.

## Testing Strategy

### Unit Tests

Each component has comprehensive unit tests:

```rust
#[tokio::test]
async fn test_component_specific_scenario() {
    let component = ComponentName::new();
    let input = TestInput::default();
    
    let result = component.process(input).await;
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap().field, expected_value);
}
```

### Integration Tests

Verify end-to-end workflows:

```rust
#[tokio::test]
async fn test_agent_workflow() {
    let intent_bus = IntentBus::new(100);
    let memory = ContextMemory::new();
    let scheduler = AgentScheduler::new(intent_bus, memory);
    
    // Spawn agent
    let agent = AgentControlBlock::new(1);
    scheduler.spawn_agent(agent).await.unwrap();
    
    // Send intent
    let intent = Intent::new(...);
    intent_bus.publish(intent).await;
    
    // Verify processing
    // ...
}
```

### Performance Testing

Benchmarks are in `benches/`:

```bash
# Agent spawn latency
cargo criterion agent_spawn_latency

# Context switch performance
cargo criterion context_switch

# eBPF overhead
cargo criterion ebpf_overhead
```

## Build Commands

See `AGENTS.md` for full build and quality commands:

```bash
rtk cargo build --release          # Production build
rtk cargo clippy -- -D warnings    # Zero warnings
rtk cargo fmt --all -- --check     # Format check
rtk cargo test                     # All tests
```

## Development Checklist

### Before Committing

- [ ] Run `rtk cargo clippy -- -D warnings` (zero warnings required)
- [ ] Run `rtk cargo fmt --all -- --check` (format check)
- [ ] Run `rtk cargo test` (all tests pass)
- [ ] No `unwrap()` in non-test code
- [ ] Error types defined and propagated correctly
- [ ] Audit log entry written for security decisions
- [ ] New crate added with `cargo vet` approved

### Per Component

**kernel-companion**:
- [ ] eBPF programs compile without warnings
- [ ] LSM hooks are properly attached
- [ ] Policy decision logging is comprehensive

**agent-scheduler**:
- [ ] Agent lifecycle (create, pause, resume, terminate)
- [ ] Priority queue algorithms are correct
- [ ] Supervision and auto-restart mechanisms

**intent-bus**:
- [ ] Intent filtering works correctly
- [ ] Broadcast channels handle backpressure
- [ ] All intent types are supported

**context-memory**:
- [ ] Hot/Warm/Cold paging is efficient
- [ ] RocksDB integration for NVMe layer
- [ ] Eviction policies are optimal

**compute-scheduler**:
- [ ] Cost function is accurate
- [ ] Hardware detection works
- [ ] Load balancing is effective

**capability-security**:
- [ ] Token validation is secure
- [ ] Policy enforcement is strict
- [ ] Audit trails are unmodifiable

## next Steps

1. **Read** `AGENTS.md` for detailed coding conventions
2. **Explore** component implementations in `crates/`
3. **Run tests** to verify understanding
4. **Build** the project with `rtk cargo build --release`
5. **Document** your work in this vault

## Community

- **Issues**: Report bugs in GitHub
- **Discussions**: Ask questions in project discussions
- **Contributing**: Follow branch naming conventions (`feat/`, `fix/`, etc.)
- **Commits**: Use conventional commit messages

---

*This documentation is auto-generated and kept in sync with the code.*

GitHub: https://github.com/srayuth202510-byte/AI-Native-Kernel