# Components Overview

This directory contains documentation for each component of the AI-Native Kernel.

## Current Implementation Caveat

Some examples in this directory describe the target architecture rather than the exact code that exists today. For the current prototype state, cross-check:

- `obsidian_vault/implementation-status.md`
- `crates/kernel-companion/src/lib.rs`
- `crates/agent-scheduler/src/lib.rs`
- `crates/capability-security/src/lib.rs`

## Component Dependencies

Each component uses Tokio async runtime and follows zero-trust security principles:

```rust
use tokio::sync::{RwLock, mpsc, broadcast};
use std::sync::Arc;
```

## Build Commands

```bash
# Individual component builds
cd crates/kernel-companion && rtk cargo build

# Component-specific tests
cd crates/agent-scheduler && rtk cargo test

# Generate documentation with rustdoc
cd crates/intent-bus && rtk cargo doc --open
```

## Integration Patterns

### Component Communication

Components communicate through:

1. **Intent Bus** - High-level events and intents
2. **Channels** - Low-level message passing
3. **Shared State** - Arc<RwLock> for data coordination

### State Management

```rust
// Component A
let state_a = Arc::new(RwLock::new(state_data));
let (tx_a, rx_a) = mpsc::channel(100);

// Component B
let shared_state = Arc::new(RwLock::new(state_data));
let (tx_b, rx_b) = mpsc::channel(100);

// Shared access
let read_guard = shared_state.read().await;
let data = read_guard.value.clone();
```

## Security Considerations

### Capability Token Flow

1. **Token Creation**: `CapabilityToken::new(...)`
2. **Validation**: `CapabilitySecurityManager::validate(...)`
3. **Audit**: Decisions recorded by `CapabilitySecurityManager` through `AuditLogger`

### Error Handling

```rust
pub async fn secure_operation(&self) -> Result<(), SecurityError> {
    // Validate capabilities
    let token = self.validate_token().await
        .map_err(|e| SecurityError::TokenValidationFailed { source: e })?;
    
    // Log attempt
    self.audit_log.log_access(token.id, "operation").await
        .map_err(|e| SecurityError::AuditLogWriteFailed { source: e })?;
    
    // Perform operation
    self.perform_operation().await
}
```

## Testing Strategy

Each component follows the same testing pattern:

1. **Unit Tests**: `#[tokio::test]` in component files
2. **Integration Tests**: `tests/` directory per component
3. **Property Tests**: `proptest` for invariants
4. **Fuzz Tests**: `cargo-fuzz` for parsers/decoders

### Example Unit Test

```rust
#[tokio::test]
async fn test_component_operations() {
    let component = ComponentName::new();
    let input = TestInput::default();
    
    // Test successful path
    let result = component.process(input).await;
    assert!(result.is_ok());
    
    // Test error paths
    let invalid_input = InvalidInput::new();
    let result = component.process(invalid_input).await;
    assert!(result.is_err());
}
```

## Performance Considerations

### Resource Management

```rust
// Limit concurrent operations
let (tx, rx) = mpsc::channel(1000);

// Add timeout for external operations
let result = tokio::time::timeout(
    Duration::from_secs(5),
    self.external_call()
).await;
```

### Memory Efficiency

```rust
// Use Arc for shared read-only references
let shared_data = Arc::new(DataStructure);

// Use RwLock for shared mutable access  
let mut data = shared_data.write().await;
data.modify();
```

## CLI Interface

Each component may expose CLI for debugging:

```bash
# Component-specific commands
cargo run --bin component-name -- --help

# Debugging utilities
cargo run --bin debug-component -- --monitor
```

## Observability

### Metrics

Components expose metrics via Prometheus:

```rust
#[derive(Debug, Clone)]
pub struct Metrics {
    pub operations_count: u64,
    pub error_count: u64,
    pub processing_time_ms: u64,
}

impl Metrics {
    pub fn record_success(&mut self, duration: Duration) {
        self.operations_count += 1;
        self.processing_time_ms += duration.as_millis() as u64;
    }
    
    pub fn record_error(&mut self) {
        self.error_count += 1;
    }
}
```

### Logging

Structured logging with sanitization:

```rust
use tracing::info;

#[tracing::instrument(skip(data))]
pub async fn process_data(&self, data: &SanitizedData) {
    info!(component = "component_name", operation = "process", data_size = data.len());
    // ... processing logic
}
```

## Migration Guide

### From v1.0 to v2.0

Changes in API:

1. **Async Everywhere**: All I/O operations are now async
2. **New Error Types**: Each component has its own error type
3. **Updated Channels**: Use `tokio::sync` instead of `futures`
4. **Security Enhancements**: Zero-trust tokens are now required for all operations

```rust
// Old way
let result = component.sync_method(input);

// New way
let result = component.async_method(input).await;
```

## Troubleshooting

### Common Issues

1. **Deadlocks**: Avoid holding RwLocks across await points
2. **Channel Overflow**: Use proper buffer sizes for mpsc channels
3. **Resource Exhaustion**: Implement proper cleanup in drop handlers
4. **Race Conditions**: Use atomic operations for shared counters

```rust
// Avoid deadlocks
pub async fn process(&self) {
    // BAD: Hold lock across await
    let mut lock = self.lock.write().await;
    tokio::time::sleep(Duration::from_millis(100)).await; // AWAITING WITH LOCK HELD
    lock.do_something();
    
    // GOOD: Release lock before awaiting
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    // ... continue with lock
}
```

## Future Enhancements

Planned features for v2.0:

- **gRPC Integration**: External service communication
- **Distributed Tracing**: OpenTelemetry integration
- **Hot Reload**: Update components without restart
- **Clustering**: Multi-node coordination
- **Export/Import**: Backup and migration utilities

This vault will be updated as the project evolves.

---

**Maintainer**: AI-Native Kernel Team
**Last Updated**: 2026-06-26
**Version**: prototype-refactor
