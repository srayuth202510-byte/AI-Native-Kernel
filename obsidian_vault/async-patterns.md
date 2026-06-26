# Async Programming Patterns

This document documents the async programming patterns used throughout the AI-Native Kernel, following Tokio's concurrency best practices.

## Core Async Principles

### 1. All I/O Must Be Async

**Never Block**: Every I/O operation must be non-blocking:

```rust
// ❌ BAD - Blocks the async runtime
let data = std::fs::read("large_file.txt");

// ✅ GOOD - Async I/O
let data = tokio::fs::read("large_file.txt").await;

// ❌ BAD - Blocks on external API
let response = reqwest::get("https://api.example.com").await;

// ✅ GOOD - With timeout
let response = tokio::time::timeout(
    Duration::from_secs(30),
    reqwest::get("https://api.example.com")
).await?;
```

### 2. Use Tokio Channels for Communication

**mpsc**: Multiple Producer, Single Consumer (fire-and-forget tasks)

```rust
// Create channel for background tasks
let (tx, mut rx) = mpsc::channel(1000);

// Send work to background task (non-blocking)
let _ = tx.send(work_item).await;

// Process work in background task
#[tokio::main]
async fn background_task(mut rx: mpsc::Receiver<WorkItem>) {
    while let Some(work) = rx.recv().await {
        process_work(work).await;
    }
}
```

**broadcast**: One Producer, Multiple Consumers (publish/subscribe)

```rust
// Intent Bus uses broadcast channels
let (tx, mut rx) = broadcast::channel(1000);

// Publisher (non-blocking)
let _ = tx.send(intent);

// Multiple subscribers
let mut rx1 = tx.subscribe();
let mut rx2 = tx.subscribe();

// Each subscriber receives a copy
while let Ok(intent1) = rx1.recv().await {
    process_intent(intent1);
}
```

### 3. Use `Arc<RwLock>` for Shared State

**Read-Write Locks**: For shared mutable state that needs both reading and writing.

```rust
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;

// Shared state structure
pub struct SharedState {
    pub data: HashMap<String, String>,
    pub counter: u64,
}

// Initialize shared state
let shared_state = Arc::new(RwLock::new(SharedState {
    data: HashMap::new(),
    counter: 0,
}));

// Read access (multiple readers allowed)
async fn read_data(shared_state: &Arc<RwLock<SharedState>>) -> HashMap<String, String> {
    let guard = shared_state.read().await;
    guard.data.clone()
}

// Write access (exclusive access)
async fn write_data(shared_state: &Arc<RwLock<SharedState>>, key: String, value: String) {
    let mut guard = shared_state.write().await;
    guard.data.insert(key, value);
    guard.counter += 1;
}
```

**Arc**: Reference counting for shared ownership without mutable access.

```rust
// Multiple owners can read without locking
let shared_value = Arc::new(42);
let read1 = shared_value.clone(); // New reference
let read2 = shared_value.clone(); // Another reference

// Can read simultaneously (immutable)
let val1 = *read1; // Read
let val2 = *read2; // Read
```

## Pattern Categories

### 1. Fire-and-Forget Background Tasks

```rust
pub struct BackgroundWorker {
    tx: mpsc::Sender<WorkItem>,
}

impl BackgroundWorker {
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::channel(1000);
        
        // Spawn background task
        tokio::spawn(async move {
            while let Some(work) = rx.recv().await {
                process_work(work).await;
            }
        });
        
        Self { tx }
    }
    
    pub async fn submit(&self, work: WorkItem) {
        // Non-blocking submission
        let _ = self.tx.send(work).await;
    }
}
```

### 2. Work Queues with Backpressure

```rust
pub struct BoundedWorkQueue {
    tx: mpsc::Sender<WorkItem>,
    max_size: usize,
}

impl BoundedWorkQueue {
    pub fn new(max_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel(max_size);
        
        tokio::spawn(async move {
            while let Some(work) = rx.recv().await {
                process_work(work).await;
            }
        });
        
        Self { tx, max_size }
    }
    
    pub async fn try_submit(&self, work: WorkItem) -> Result<(), ()> {
        // Return error if queue is full
        self.tx.try_send(work).map_err(|_| ())
    }
    
    pub async fn submit(&self, work: WorkItem) {
        // Block if queue is full
        let _ = self.tx.send(work).await;
    }
}
```

### 3. Event Broadcasting Systems

```rust
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }
    
    pub fn publish(&self, event: Event) {
        let _ = self.sender.send(event);
    }
    
    pub fn subscribe(&self) -> EventSubscriber {
        let mut receiver = self.sender.subscribe();
        EventSubscriber { receiver }
    }
}

pub struct EventSubscriber {
    receiver: broadcast::Receiver<Event>,
}

impl EventSubscriber {
    pub async fn next(&mut self) -> Option<Event> {
        self.receiver.recv().await.ok()
    }
}
```

### 4. Cancellation and Timeouts

```rust
pub struct TimeoutHelper {
    timeout: Duration,
}

impl TimeoutHelper {
    pub async fn with_timeout<F, T>(&self, future: F) -> Result<T, TimeoutError>
    where
        F: Future<Output = T> + Send,
        T: Send,
    {
        tokio::time::timeout(self.timeout, future)
            .await
            .map_err(|_| TimeoutError::Timeout {
                operation: "operation",
                timeout: self.timeout,
            })
    }
}
```

### 5. Shared State with Guards

```rust
pub struct SharedResource {
    data: Arc<RwLock<ResourceData>>,
    lock_depth: std::sync::atomic::AtomicU8,
}

impl SharedResource {
    // Prevent deadlocks by tracking lock depth
    pub async fn read_with_depth_check(&self) -> RwLockReadGuard<'_, ResourceData> {
        let depth = self.lock_depth.load(std::sync::atomic::Ordering::SeqCst);
        if depth > 10 {
            panic!("Potential deadlock detected - lock depth too high");
        }
        
        self.lock_depth.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = self.data.read().await;
        
        self.lock_depth.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        guard
    }
}
```

### 6. SPSC Channels (Single Producer, Single Consumer)

```rust
pub struct SpscChannel<T> {
    sender: mpsc::Sender<T>,
    receiver: mpsc::Receiver<T>,
}

impl<T> SpscChannel<T> {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        Self { sender, receiver }
    }
    
    pub fn sender(&self) -> mpsc::Sender<T> {
        self.sender.clone()
    }
    
    pub fn receiver(&self) -> mpsc::Receiver<T> {
        self.receiver.clone()
    }
}
```

## Async Pattern Combinations

### Pattern 1: Background Processing with Error Handling

```rust
pub struct ProcessingService {
    work_queue: BoundedWorkQueue,
    error_handler: Arc<dyn ErrorHandler>,
    metrics: Arc<MetricsCollector>,
}

impl ProcessingService {
    pub async fn submit_work(&self, work: WorkItem) -> Result<(), ServiceError> {
        let start_time = std::time::Instant::now();
        
        let result = self.work_queue.submit(work)
            .map_err(|e| ServiceError::QueueFull { source: e });
        
        self.metrics.record_submission(start_time.elapsed());
        result
    }
    
    pub async fn process_errors(&self, mut error_rx: mpsc::Receiver<ServiceError>) {
        while let Some(error) = error_rx.recv().await {
            // Log error
            self.error_handler.handle(error).await;
            
            // Record metrics
            self.metrics.record_error(error);
        }
    }
}
```

### Pattern 2: Event-Driven Architecture

```rust
pub struct EventDrivenSystem {
    event_bus: EventBus,
    handlers: Vec<Box<dyn EventHandler + Send + Sync>>,
    middleware: Vec<Box<dyn Middleware + Send + Sync>>,
}

impl EventDrivenSystem {
    pub async fn handle_event(&self, event: Event) {
        // Pre-processing middleware
        let mut event = event;
        for middleware in &self.middleware {
            event = middleware.process(event).await;
        }
        
        // Route to appropriate handlers
        if let Some(handler) = self.find_handler(&event) {
            handler.handle(event).await;
        }
    }
}
```

### Pattern 3: Timeout-Based Timeouts

```rust
pub struct TimedOperation<T> {
    future: T,
    timeout: Duration,
    start_time: std::time::Instant,
}

impl<T: Future> TimedOperation<T> {
    pub fn new(future: T, timeout: Duration) -> Self {
        Self {
            future,
            timeout,
            start_time: std::time::Instant::now(),
        }
    }
    
    pub async fn execute(&mut self) -> Result<T::Output, OperationError> {
        match tokio::time::timeout(self.timeout, &mut self.future).await {
            Ok(result) => Ok(result),
            Err(_) => Err(OperationError::Timeout {
                elapsed: self.start_time.elapsed(),
                timeout: self.timeout,
            }),
        }
    }
}
```

## Best Practices

### 1. Avoid Clone for Large Structures

```rust
// Instead of cloning, use references
pub async fn process_shared_data(
    shared_data: &Arc<RwLock<LargeData>>,
    metadata: &Metadata,
) {
    let guard = shared_data.read().await;
    // Process data without cloning
}
```

### 2. Use `tokio::select!` for Concurrent Operations

```rust
pub async fn concurrent_operations(
    operation1: impl Future<Output = Result<(), Error>>,
    operation2: impl Future<Output = Result<(), Error>>,
    timeout: Duration,
) -> Result<(), Error> {
    tokio::select! {
        result1 = operation1 => result1,
        result2 = operation2 => result2,
        _ = tokio::time::sleep(timeout) => {
            Err(Error::Timeout)
        }
    }
}
```

### 3. Proper Resource Cleanup

```rust
pub struct ResourceManager {
    resources: Vec<Resource>,
    cleanup_tx: mpsc::Sender<Resource>,
}

impl Drop for ResourceManager {
    fn drop(&mut self) {
        // Cancel pending work
        self.cleanup_tx.close();
        
        // Wait for resources to be cleaned up
        // This ensures no resource is leaked
    }
}
```

### 4. Error Propagation

```rust
pub async fn complex_operation(&self) -> Result<Output, ComponentError> {
    // Validate inputs
    let input = self.validate_input().await
        .map_err(|e| ComponentError::Validation { source: e })?;
    
    // Perform operation with timeout
    let result = self.timed_operation(input).await
        .map_err(|e| ComponentError::Timeout { source: e })?;
    
    // Process results
    let output = self.process_output(result).await
        .map_err(|e| ComponentError::Processing { source: e })?;
    
    Ok(output)
}
```

## Testing Async Code

### 1. Mock Async Channels

```rust
pub struct AsyncChannelMock<T> {
    sender: mpsc::Sender<T>,
    receiver: mpsc::Receiver<T>,
}

impl<T> AsyncChannelMock<T> {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        Self { sender, receiver }
    }
    
    pub async fn send(&self, value: T) -> Result<(), ()> {
        self.sender.try_send(value).map_err(|_| ())
    }
    
    pub async fn recv(&mut self) -> Option<T> {
        self.receiver.try_recv().ok()
    }
}
```

### 2. Async Test Utilities

```rust
#[tokio::test]
async fn test_async_component() {
    let component = TestComponent::new();
    
    // Test with mock channels
    let (sender, mut receiver) = mpsc::channel(10);
    
    // Send test data
    let _ = sender.send(TestData { value: 42 }).await;
    
    // Receive and verify
    let data = receiver.recv().await.unwrap();
    assert_eq!(data.value, 42);
}

#[tokio::test]
async fn test_timeout_handling() {
    let helper = TimeoutHelper {
        timeout: Duration::from_millis(100),
    };
    
    // Fast operation should succeed
    let fast_future = async { 1 };
    let result = helper.with_timeout(fast_future).await.unwrap();
    assert_eq!(result, 1);
    
    // Slow operation should timeout
    let slow_future = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        2
    };
    
    let result = helper.with_timeout(slow_future).await;
    assert!(result.is_err());
}
```

## Common Async Patterns

### Pattern A: Fan-Out Processing

```rust
pub async fn fan_out_process<F>(data: Vec<Data>, processor: F)
where
    F: Fn(Data) -> impl Future<Output = Result<Output, Error>> + Send + Sync,
{
    let mut handles = Vec::new();
    
    for item in data {
        let handle = tokio::spawn(async move {
            processor(item).await
        });
        handles.push(handle);
    }
    
    // Wait for all to complete
    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    
    results
}
```

### Pattern B: Pipeline Processing

```rust
pub struct Pipeline<F1, F2, F3> {
    stage1: F1,
    stage2: F2,
    stage3: F3,
}

impl<A, B, C, D, E, F, G> Pipeline<A, B, C>
where
    A: Future<Output = B> + Send,
    B: Future<Output = C> + Send,
    C: Future<Output = D> + Send,
{
    pub async fn process(&self, input: A::Output) -> C::Output {
        let intermediate1 = self.stage1.await;
        let intermediate2 = self.stage2.await;
        let final_output = self.stage3.await;
        
        intermediate1 + intermediate2 + final_output
    }
}
```

## Performance Considerations

### 1. Channel Size Tuning

```rust
// For high-throughput systems
pub const HIGH_THROUGHPUT_CHANNEL_SIZE: usize = 10000;

// For latency-sensitive systems  
pub const LATENCY_SENSITIVE_CHANNEL_SIZE: usize = 1;

// For balanced systems
pub const BALANCED_CHANNEL_SIZE: usize = 100;
```

### 2. Memory Pooling

```rust
pub struct AsyncMemoryPool {
    small_objects: Vec<Box<u8>>,
    medium_objects: Vec<Box<[u8]>>,
    large_objects: Vec<Box<[u8]>>,
}

impl AsyncMemoryPool {
    pub fn new() -> Self {
        Self {
            small_objects: Vec::with_capacity(1000),
            medium_objects: Vec::with_capacity(100),
            large_objects: Vec::with_capacity(10),
        }
    }
    
    pub fn acquire_small(&mut self) -> Option<Box<u8>> {
        self.small_objects.pop()
    }
    
    pub fn release_small(&mut self, obj: Box<u8>) {
        if self.small_objects.len() < 1000 {
            self.small_objects.push(obj);
        }
    }
}
```

### 3. Staggered Concurrency

```rust
pub struct StaggeredProcessor {
    semaphore: Arc<tokio::sync::Semaphore>,
    max_concurrent: usize,
}

impl StaggeredProcessor {
    pub async fn process(&self, work: WorkItem) -> Result<(), Error> {
        let _permits = self.semaphore.acquire().await?;
        
        // Process work
        // Release semaphore when done (Drop)
        Ok(())
    }
}
```

## Summary

The async patterns in AI-Native Kernel follow these principles:

1. **All I/O is async** - No blocking operations
2. **Proper sharing** - Use Arc<RwLock> for shared state
3. **Channels for communication** - mpsc and broadcast as primary primitives
4. **Timeouts everywhere** - Protect against hanging operations
5. **Resource management** - Proper cleanup and RAII
6. **Error propagation** - Clear error chains and structured errors
7. **Testable design** - Mock-friendly interfaces for testing

These patterns ensure the system is highly concurrent, responsive, and maintainable while following Tokio best practices.

---

**Maintainer**: Async Team  
**Version**: 2.0.0  
**Last Updated**: $(date)