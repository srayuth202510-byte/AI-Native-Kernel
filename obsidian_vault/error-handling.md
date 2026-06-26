# Error Handling Patterns

This document describes the comprehensive error handling patterns used throughout the AI-Native Kernel, emphasizing structured error types, proper propagation, and security considerations.

## Core Principles

### 1. Domain Error Types

Every module defines its own error type for clear error boundaries:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ComponentError {
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    
    #[error("Processing failed: {0}")]
    Processing(#[from] ProcessingError),
    
    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}
```

### 2. Error Propagation

**Standard Pattern**: Use `?` operator for error propagation:

```rust
pub async fn complex_operation(&self) -> Result<Output, ComponentError> {
    let input = self.validate_input().await?;
    
    let processed = self.process_data(input).await?;
    
    let result = self.calculate_output(processed).await?;
    
    Ok(result)
}
```

### 3. No Panic in Production

**Never use `unwrap()` or `expect()` in production code**:

```rust
// ❌ BAD - Never use unwrap in production
let data = unsafe_operation().unwrap();

// ❌ BAD - Never use expect in production  
let data = unsafe_operation().expect("operation should not fail");

// ✅ GOOD - Proper error handling
let data = match unsafe_operation().await {
    Ok(data) => data,
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(ComponentError::OperationFailed { source: e });
    }
};
```

## Error Type Categories

### 1. Validation Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Input is empty: {0}")]
    EmptyInput(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Value out of range: {0}")]
    OutOfRange { value: i32, min: i32, max: i32 },
    
    #[error("Missing required field: {0}")]
    MissingField(String),
}

impl ValidationError {
    pub fn new<T: std::error::Error>(err: T) -> Self {
        ValidationError::InvalidFormat(err.to_string())
    }
}
```

### 2. Processing Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum ProcessingError {
    #[error("Computation failed: {0}")]
    Computation(#[from] Box<dyn std::error::Error>>,
    
    #[error("Resource unavailable: {0}")]
    ResourceUnavailable(String),
    
    #[error("Hardware error: {0}")]
    HardwareError(#[from] HardwareError),
    
    #[error("Network timeout: {0}")]
    NetworkTimeout(std::time::Duration),
}

impl ProcessingError {
    pub fn from_hardware(e: HardwareError) -> Self {
        ProcessingError::HardwareError(e)
    }
}
```

### 3. System Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    #[error("Configuration error: {0}")]
    Configuration(#[from] config::ConfigError),
    
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
    
    #[error("Async runtime error: {0}")]
    Async(#[from] tokio::task::JoinError),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
```

### 4. Security Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Authentication failed: {0}")]
    Authentication(#[from] AuthError),
    
    #[error("Authorization denied: {0}")]
    Authorization(#[from] AuthError),
    
    #[error("Token expired: {0}")]
    TokenExpired(std::time::Instant),
    
    #[error("Audit log failure: {0}")]
    AuditLogFailure(#[from] AuditError),
}
```

## Error Handling Patterns

### Pattern 1: Function-Level Error Handling

```rust
pub struct ErrorHandlingService {
    error_aggregator: Arc<ErrorAggregator>,
}

impl ErrorHandlingService {
    pub async fn process(&self, input: Input) -> Result<Output, ServiceError> {
        // Validate input
        let validated_input = self.validate_input(&input)
            .map_err(|e| ServiceError::InvalidInput { source: e })?;
        
        // Process with proper error handling
        let processing_result = self.perform_processing(validated_input)
            .await
            .map_err(|e| ServiceError::ProcessingFailed { source: e })?;
        
        // Validate output
        let output = self.validate_output(&processing_result)
            .map_err(|e| ServiceError::InvalidOutput { source: e })?;
        
        Ok(output)
    }
    
    fn validate_input(&self, input: &Input) -> Result<ValidatedInput, ValidationError> {
        // Implementation
        if input.is_empty() {
            return Err(ValidationError::EmptyInput("input".to_string()));
        }
        
        Ok(ValidatedInput::new(input))
    }
}
```

### Pattern 2: Circuit Breaker Pattern

```rust
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    failure_threshold: usize,
    recovery_timeout: Duration,
    monitoring_tx: mpsc::Sender<CircuitEvent>,
}

#[derive(Debug, Clone)]
pub enum CircuitState {
    Closed,           // Operate normally
    Open,             // Fail fast
    HalfOpen,         // Test recovery
}

#[derive(Debug, Clone)]
pub enum CircuitEvent {
    Success,
    Failure(Error),
    StateChange(CircuitState),
}

impl CircuitBreaker {
    pub async fn call<F, T>(&self, operation: F) -> Result<T, CircuitError>
    where
        F: Future<Output = Result<T, Error>>,
    {
        let mut state = self.state.write().await;
        
        match *state {
            CircuitState::Open => {
                // Check if we should attempt recovery
                if self.should_attempt_recovery().await {
                    *state = CircuitState::HalfOpen;
                } else {
                    return Err(CircuitError::Open);
                }
            }
            CircuitState::HalfOpen | CircuitState::Closed => {
                // Proceed with normal operation
            }
        }
        
        // Execute operation
        let result = operation.await;
        
        // Update circuit state based on result
        self.update_state_based_on_result(&result).await;
        
        result.map_err(|e| CircuitError::Operation { source: e })
    }
}
```

### Pattern 3: Error Aggregation

```rust
pub struct ErrorAggregator {
    errors: Arc<RwLock<Vec<ServiceError>>>,
    max_errors: usize,
}

impl ErrorAggregator {
    pub async fn add_error(&self, error: ServiceError) {
        let mut errors = self.errors.write().await;
        errors.push(error);
        
        // Alert if we have too many errors
        if errors.len() >= self.max_errors {
            self.trigger_alert().await;
        }
    }
    
    pub async fn get_errors(&self) -> Vec<ServiceError> {
        let errors = self.errors.read().await;
        errors.clone()
    }
    
    pub async fn clear_errors(&self) {
        let mut errors = self.errors.write().await;
        errors.clear();
    }
}
```

### Pattern 4: Retry with Backoff

```rust
pub struct RetryService {
    max_attempts: usize,
    base_backoff: Duration,
    max_backoff: Duration,
}

impl RetryService {
    pub async fn execute_with_retry<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: FnMut() -> impl Future<Output = Result<T, E>> + Send,
        E: std::error::Error,
    {
        let mut attempt = 0;
        let mut error: Option<E> = None;
        
        while attempt < self.max_attempts {
            attempt += 1;
            
            match (operation)().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    error = Some(e);
                    
                    if attempt >= self.max_attempts {
                        return Err(error.unwrap());
                    }
                    
                    // Exponential backoff
                    let backoff = self.calculate_backoff(attempt);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        
        Err(error.unwrap())
    }
    
    fn calculate_backoff(&self, attempt: usize) -> Duration {
        let backoff = self.base_backoff * 2_u64.pow((attempt - 1) as u32);
        backoff.min(self.max_backoff)
    }
}
```

## Error Handling in Async Context

### Pattern 1: Shared State with Error Handling

```rust
pub struct SharedStateWithErrors {
    state: Arc<RwLock<State>>,
    error_handler: Arc<dyn ErrorHandler>,
}

impl SharedStateWithErrors {
    pub async fn update_with_validation(
        &self, 
        key: String, 
        value: UpdateValue
    ) -> Result<(), StateError> {
        // Acquire read lock for validation
        let state = self.state.read().await;
        let validation_result = self.validate_update(&state, &key, &value);
        
        drop(state); // Release read lock
        
        // Perform validation
        validation_result.map_err(|e| StateError::Validation { source: e })?;
        
        // Acquire write lock for update
        let mut state = self.state.write().await;
        
        if !self.state_contains(&state, &key) {
            return Err(StateError::KeyNotFound { key });
        }
        
        // Update state
        self.apply_update(&mut state, key, value);
        
        // Log successful update
        self.error_handler.log_update(&key).await;
        
        Ok(())
    }
}
```

### Pattern 2: Timeout with Error Handling

```rust
pub struct TimeoutErrorHandler {
    timeout: Duration,
    error_mapper: Arc<dyn ErrorMapper>,
}

impl TimeoutErrorHandler {
    pub async fn execute_with_timeout<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
        E: std::error::Error + Send + Sync,
    {
        match tokio::time::timeout(self.timeout, operation).await {
            Ok(result) => {
                match result {
                    Ok(t) => Ok(t),
                    Err(e) => {
                        // Map error with timeout context
                        let mapped_error = self.error_mapper.map_with_timeout(
                            e, self.timeout
                        );
                        Err(mapped_error)
                    }
                }
            }
            Err(_) => {
                // Create timeout error
                let timeout_error = self.error_mapper.create_timeout_error(self.timeout);
                Err(timeout_error)
            }
        }
    }
}
```

### Pattern 3: Cancellation and Cleanup

```rust
pub struct CancellationHandler {
    cancel_tx: mpsc::Sender<CancellationSignal>,
    cleanup_tasks: Arc<tokio::sync::RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl CancellationHandler {
    pub async fn start_operation<F, T>(&self, operation: F) -> Result<T, CancellationError>
    where
        F: Future<Output = T> + Send,
    {
        // Register cancellation listener
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
        let cancel_token = CancellationToken::new(cancel_tx);
        
        // Wrap operation with cancellation
        let future = async move {
            tokio::select! {
                result = operation => result,
                _ = cancel_rx.recv() => {
                    return Err(CancellationError::Cancelled);
                }
            }
        };
        
        // Spawn with cleanup
        let handle = tokio::spawn(future);
        self.cleanup_tasks.write().await.push(handle);
        
        // Wait for result
        match handle.await {
            Ok(result) => Ok(result),
            Err(e) => Err(CancellationError::TaskFailed { source: e }),
        }
    }
    
    pub fn cancel_all(&self) {
        let _ = self.cancel_tx.try_send(CancellationSignal::Cancel);
    }
}
```

## Testing Error Handling

### 1. Unit Tests for Error Cases

```rust
#[tokio::test]
async fn test_error_handling_with_invalid_input() {
    let service = ErrorHandlingService::new();
    
    // Test with invalid input
    let invalid_input = InvalidInput::new();
    
    let result = service.process(invalid_input).await;
    
    // Should return validation error
    assert!(result.is_err());
    match result.unwrap_err() {
        ServiceError::InvalidInput { source } => {
            assert!(matches!(source, ValidationError::EmptyInput(_)));
        }
        _ => panic!("Expected InvalidInput error"),
    }
}

#[tokio::test]
async fn test_error_handling_with_valid_input() {
    let service = ErrorHandlingService::new();
    
    // Test with valid input
    let valid_input = create_valid_input();
    
    let result = service.process(valid_input).await;
    
    // Should succeed
    assert!(result.is_ok());
}
```

### 2. Property-Based Testing

```rust
#[tokio::test]
async fn test_error_consistency() {
    // Property: All errors should be derived from standard error types
    let service = ErrorHandlingService::new();
    
    let mut rng = rand::thread_rng();
    
    for _ in 0..100 {
        let input = generate_random_input(&mut rng);
        
        let result = service.process(input).await;
        
        // Property: If result is Ok, it must contain valid data
        if let Ok(output) = result {
            assert!(output.is_valid());
        }
        
        // Property: If result is Err, it must be a known error type
        if let Err(error) = result {
            assert!(is_known_error_type(error));
        }
    }
}
```

### 3. Integration Tests

```rust
#[tokio::test]
async fn test_full_error_flow() {
    // Test the complete error handling flow
    let (error_tx, mut error_rx) = mpsc::channel(100);
    
    let error_handler = ErrorHandlingService::new(error_tx);
    
    // Generate an error
    let error = generate_test_error();
    
    // Process the error
    error_handler.handle_error(error).await;
    
    // Verify error was logged
    let logged_error = error_rx.recv().await.unwrap();
    assert_eq!(logged_error, expected_error);
}
```

## Async Error Patterns

### Pattern 1: Streaming Errors

```rust
pub struct StreamingErrorHandler {
    error_sink: mpsc::Sender<Error>,
    buffer_size: usize,
}

impl StreamingErrorHandler {
    pub async fn handle_stream<S, E>(&self, stream: S)
    where
        S: Stream<Item = Result<(), E>> + Send,
        E: std::error::Error + Send + Sync,
    {
        let mut stream = stream;
        let mut buffer: Vec<E> = Vec::with_capacity(self.buffer_size);
        
        while let Some(result) = stream.next().await {
            match result {
                Ok(()) => {
                    // Success, clear buffer
                    buffer.clear();
                }
                Err(e) => {
                    buffer.push(e);
                    
                    if buffer.len() >= self.buffer_size {
                        // Flush errors to sink
                        for error in buffer.drain(..) {
                            let _ = self.error_sink.send(error).await;
                        }
                    }
                }
            }
        }
    }
}
```

### Pattern 2: Parallel Error Processing

```rust
pub struct ParallelErrorProcessor {
    workers: usize,
    error_queue: Arc<tokio::sync::Mutex<VecDeque<Error>>>,
}

impl ParallelErrorProcessor {
    pub async fn process_errors_parallel(&self, errors: Vec<Error>) {
        let mut handles = Vec::with_capacity(self.workers);
        
        for error in errors {
            if handles.len() >= self.workers {
                // Wait for a worker to complete
                if let Some(handle) = handles.iter_mut().find(|h| h.is_finished()) {
                    handle.await.ok();
                    handles.retain(|h| !h.is_finished());
                }
            }
            
            // Spawn worker for error
            let handle = tokio::spawn(self.process_error(error.clone()));
            handles.push(handle);
        }
        
        // Wait for all workers
        for handle in handles {
            handle.await.ok();
        }
    }
    
    async fn process_error(&self, error: Error) {
        // Process single error
        // This could involve logging, alerting, etc.
    }
}
```

### Pattern 3: Error Recovery

```rust
pub struct ErrorRecovery {
    recovery_strategies: Vec<Box<dyn RecoveryStrategy>>, 
    fallback_handler: Arc<dyn FallbackHandler>,
}

impl ErrorRecovery {
    pub async fn recover_from_error<E>(&self, error: E) -> Result<(), RecoveryError>
    where
        E: std::error::Error,
    {
        for strategy in &self.recovery_strategies {
            match strategy.can_handle(&error) {
                true => {
                    let result = strategy.recover(&error).await;
                    if result.is_ok() {
                        return result;
                    }
                }
                false => continue,
            }
        }
        
        // If no strategy can handle, use fallback
        self.fallback_handler.handle(error).await
    }
}
```

## Error Handling Best Practices

### 1. Never Panic in Async Code

```rust
// ❌ BAD - Never use panic in async code
pub async fn risky_operation() -> Result<(), Error> {
    if should_panic() {
        panic!("Operation failed unexpectedly");
    }
    
    Ok(())
}

// ✅ GOOD - Handle errors gracefully
pub async fn risky_operation() -> Result<(), Error> {
    if should_fail() {
        return Err(Error::Failed);
    }
    
    Ok(())
}
```

### 2. Use Structured Logging

```rust
pub async fn perform_operation(&self, input: Input) -> Result<Output, Error> {
    let start_time = std::time::Instant::now();
    
    let result = self.do_operation(input).await;
    
    let duration = start_time.elapsed();
    
    match &result {
        Ok(output) => {
            tracing::info!(
                component = "component_name",
                operation = "perform_operation",
                duration_ms = duration.as_millis(),
                success = true
            );
        }
        Err(e) => {
            tracing::error!(
                component = "component_name", 
                operation = "perform_operation",
                duration_ms = duration.as_millis(),
                success = false,
                error = %e
            );
        }
    }
    
    result
}
```

### 3. Proper Resource Cleanup on Errors

```rust
pub struct ResourceCleaningService {
    resources: Vec<Resource>,
}

impl ResourceCleaningService {
    pub async fn complex_operation_with_cleanup(&self) -> Result<(), Error> {
        let mut resource1 = Resource::acquire().await?;
        let mut resource2 = Resource::acquire().await?;
        
        // Perform complex operation
        let result = self.perform_complex_operation(resource1, resource2).await;
        
        // Always clean up, even on error
        drop(resource2);
        drop(resource1);
        
        result
    }
    
    // Better: Use RAII
    pub async fn operation_with_raii(&self) -> Result<(), Error> {
        let mut resource = ResourceGuard::new().await?;
        
        // Operation will clean up on drop
        self.perform_operation(&mut resource).await
    }
}
```

### 4. Concurrent Error Handling

```rust
pub struct ConcurrentErrorHandler {
    max_concurrent = 10,
    semaphore = Arc::new(tokio::sync::Semaphore::new(10)),
    error_queue: Arc<tokio::sync::Mutex<VecDeque<Error>>>,
}

impl ConcurrentErrorHandler {
    pub async fn submit_error(&self, error: Error) {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        // Process error
        self.process_error(error).await;
    }
    
    async fn process_error(&self, error: Error) {
        // Process single error
        // Store in queue for aggregation
        self.error_queue.lock().await.push_back(error);
    }
}
```

## Performance Considerations

### 1. Batch Error Processing

```rust
pub async fn batch_error_processing(
    errors: Vec<Error>,
    handler: Arc<dyn ErrorHandler>,
    batch_size: usize,
) {
    let mut batches = Vec::new();
    
    // Split errors into batches
    for chunk in errors.chunks(batch_size) {
        batches.push(chunk.to_vec());
    }
    
    // Process batches concurrently
    let mut handles = Vec::new();
    
    for batch in batches {
        let handler = handler.clone();
        let handle = tokio::spawn(async move {
            for error in batch {
                handler.handle(error).await;
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all batches
    for handle in handles {
        handle.await.ok();
    }
}
```

### 2. Error Rate Limiting

```rust
pub struct ErrorRateLimiter {
    error_counts: Arc<RwLock<HashMap<String, usize>>>,
    time_window: Duration,
    max_errors_per_window: usize,
}

impl ErrorRateLimiter {
    pub async fn should_process(&self, error_type: &str) -> bool {
        let mut counts = self.error_counts.write().await;
        
        // Clean up old counts
        let now = std::time::Instant::now();
        counts.retain(|_, count| {
            // Implementation would track timestamps
            true
        });
        
        let count = counts.entry(error_type.to_string()).or_insert(0);
        *count += 1;
        
        *count <= self.max_errors_per_window
    }
}
```

## Summary

Error handling in AI-Native Kernel follows these principles:

1. **Structured Error Types** - Every module defines its own error type
2. **No Panic in Production** - Use Result types for error propagation
3. **Comprehensive Logging** - Log at error level before returning errors
4. **Timeout Protection** - All external operations have timeouts
5. **Resource Management** - Proper cleanup in all error paths
6. **Test Coverage** - Unit tests for all error paths
7. **Async Safety** - No blocking operations in async code

These patterns ensure the system is resilient, maintainable, and follows Rust's error handling best practices.

---

**Maintainer**: Error Handling Team  
**Version**: 2.0.0  
**Last Updated**: $(date)