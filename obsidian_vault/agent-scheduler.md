# Agent Scheduler Component

The Agent Scheduler is the core component of AI-Native Kernel that manages AI agent lifecycle, priorities, and isolation. This component handles the creation, execution, and lifecycle management of AI agents in a secure, efficient, and scalable manner.

## Current Implementation Note

This document originally described the target design. The current implementation in `crates/agent-scheduler/src/` is narrower and should be treated as the source of truth for the prototype.

- `context_ptr` has been replaced by `context_key: Option<String>`
- the scheduler is composed with `IntentBus`, `ContextMemoryManager`, and `CapabilitySecurityManager`
- structured intents can route payloads into context memory
- capability grants are validated through the security manager before being attached to an agent
- the current scheduler stores agent state in-memory and does not yet execute real agent workloads

## Core Components

### 1. Agent Control Block (AgentControlBlock)

```rust
#[derive(Debug, Clone)]
pub struct AgentControlBlock {
    pub id: u64,
    pub state: AgentState,
    pub priority: Priority,
    pub context_key: Option<String>,
    pub capabilities: Vec<CapabilityToken>,
    pub restart_attempts: u32,
    pub last_restart: std::time::Instant,
}
```

**Purpose**: Stores all runtime state for an AI agent.

**Key Fields**:
- **id**: Unique identifier for the agent
- **state**: Current operational state of the agent
- **priority**: Priority level for scheduling decisions
- **context_key**: Logical key used to resolve agent context in the context memory manager
- **capabilities**: Security tokens defining agent's permissions
- **restart_attempts**: Counter for fault recovery attempts
- **last_restart**: Timestamp for restart tracking

### 2. Agent State (AgentState)

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum AgentState {
    Creating,    // Agent is being initialized
    Running,    // Agent is actively processing
    Paused,     // Agent execution is paused
    Terminating, // Agent is shutting down
    Failed,     // Agent has encountered a fatal error
    Restarting,  // Agent is being restarted after failure
}
```

**State Transition Logic**:

```rust
impl AgentControlBlock {
    pub async fn transition_to(&mut self, new_state: AgentState) {
        // Validate state transitions
        if !self.is_valid_transition(&new_state) {
            log::error!("Invalid state transition from {:?} to {:?}", self.state, new_state);
            return;
        }
        
        // Handle state-specific actions
        match new_state {
            AgentState::Running => self.on_start_running(),
            AgentState::Failed => self.on_fail(),
            AgentState::Restarting => self.on_restart(),
            _ => {}
        }
        
        self.state = new_state;
        log::debug!("Agent {} transitioned to {:?}", self.id, self.state);
    }
    
    fn is_valid_transition(&self, new_state: &AgentState) -> bool {
        match (self.state, new_state) {
            (AgentState::Creating, AgentState::Running) => true,
            (AgentState::Running, AgentState::Paused) => true,
            (AgentState::Running, AgentState::Terminating) => true,
            (AgentState::Failed, AgentState::Restarting) => true,
            (AgentState::Restarting, AgentState::Creating) => true,
            _ => false,
        }
    }
}
```

### 3. Priority System (Priority)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Priority {
    Eco,        // Energy-efficient, lowest priority
    Batch,     // Batch processing, medium priority
    Interactive, // Interactive tasks, high priority
    RealTime,  // Real-time tasks, highest priority
}
```

**Ordering**: `RealTime > Interactive > Batch > Eco`

**Scheduling Algorithms**:

```rust
pub struct PriorityScheduler {
    priority_queues: HashMap<Priority, BinaryHeap<AgentHandle>>,
    current_priorities: Vec<Priority>,
}

impl PriorityScheduler {
    pub fn new() -> Self {
        let mut queues: HashMap<Priority, BinaryHeap<AgentHandle>> = HashMap::new();
        for priority in [Priority::RealTime, Priority::Interactive, Priority::Batch, Priority::Eco] {
            queues.insert(priority, BinaryHeap::new());
        }
        
        Self {
            priority_queues: queues,
            current_priorities: vec![Priority::RealTime, Priority::Interactive, Priority::Batch, Priority::Eco],
        }
    }
    
    pub fn select_next_agent(&mut self) -> Option<AgentHandle> {
        for priority in &self.current_priorities {
            if let Some(queue) = self.priority_queues.get_mut(priority) {
                if !queue.is_empty() {
                    return queue.pop();
                }
            }
        }
        None
    }
}
```

### 4. Supervisor Service (SupervisorService)

```rust
pub struct SupervisorService {
    supervisor: Supervisor,
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
}

impl SupervisorService {
    pub fn new(
        restart_tx: mpsc::Sender<RestartRequest>,
        agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
        max_restarts: u32,
        restart_backoff_ms: u64,
    ) -> Self {
        let supervisor = Supervisor {
            restart_tx,
            restart_rx: Arc::new(RwLock::new(restart_tx.receiver())),
            max_restarts,
            restart_backoff_ms,
        };
        
        Self {
            supervisor,
            agents,
        }
    }
    
    pub async fn monitor_agent(&self, agent: &AgentControlBlock) -> bool {
        match agent.state {
            AgentState::Failed => {
                if agent.restart_attempts < self.supervisor.max_restarts {
                    let backoff = self.calculate_backoff(agent.restart_attempts);
                    tokio::time::sleep(backoff).await;
                    self.supervisor.restart_agent(agent.id, "Agent failed").await
                } else {
                    false
                }
            }
            AgentState::Running => {
                if agent.restart_attempts > 0 {
                    self.reset_restart_counter(agent.id).await;
                }
                true
            }
            _ => false,
        }
    }
}
```

### 5. Intent Bus Integration

```rust
pub struct AgentScheduler {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    intent_bus: Arc<IntentBus>,
    context_memory: Arc<ContextMemoryManager>,
    capability_security: Arc<CapabilitySecurityManager>,
    supervisor_service: Arc<SupervisorService>,
    next_agent_id: Arc<RwLock<u64>>,
    monitoring_tx: broadcast::Sender<AgentEvent>,
}

impl AgentScheduler {
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
        supervisor_service: Arc<SupervisorService>,
    ) -> Self {
        let (monitoring_tx, _) = broadcast::channel(1024);
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            intent_bus,
            context_memory,
            capability_security,
            supervisor_service,
            next_agent_id: Arc::new(RwLock::new(1)),
            monitoring_tx,
        }
    }
    
    pub async fn spawn_agent(&self, agent: AgentControlBlock) -> Result<u64, SchedulerError> {
        let mut agents = self.agents.write().await;
        
        if agents.contains_key(&agent.id) {
            return Err(SchedulerError::new("Agent already exists"));
        }
        
        agents.insert(agent.id, agent.clone());
        
        let _ = self.monitoring_tx.send(AgentEvent::AgentSpawned(agent.clone()));
        
        // Notify intent bus about new agent
        let intent = Intent {
            id: format!("agent_spawn_{}", agent.id),
            intent_type: IntentType::Command,
            payload: format!("spawn agent {}", agent.id),
            priority: IntentPriority::High,
            timestamp: std::time::Instant::now(),
            source: "agent-scheduler".to_string(),
            target: None,
            metadata: HashMap::new(),
        };
        
        self.intent_bus.publish(intent).await?;
        
        Ok(agent.id)
    }
}
```

### 6. Current Prototype Behavior

The current scheduler can:

- allocate agent IDs
- spawn, pause, resume, terminate, and mark agents as failed
- route `Command` intents such as `spawn-agent`
- route `Structured` intents with metadata:
  - `agent_id`
  - `context_key`
- persist intent payloads into `ContextMemoryManager`
- grant validated capability tokens to agents

The current scheduler does not yet:

- drive real agent execution
- schedule compute workloads directly
- persist scheduler state beyond process lifetime

## Event System (AgentEvent)

```rust
#[derive(Debug, Clone)]
pub enum AgentEvent {
    AgentCreated(AgentControlBlock),
    AgentSpawned(AgentControlBlock),
    AgentPaused(AgentControlBlock),
    AgentResumed(AgentControlBlock),
    AgentTerminated(AgentControlBlock),
    AgentFailed(AgentControlBlock),
    AgentRestarted(AgentControlBlock),
    AgentPriorityChanged(u64, Priority),
    AgentContextSwitched(u64, usize),
    AgentCapabilityGranted(u64, CapabilityToken),
    AgentCapabilityRevoked(u64, u64),
}
```

## Key Features

### 1. Lifecycle Management

**Agent Creation**:
- Initialize with default state (Creating)
- Assign priority based on system needs
- Allocate context memory (hot layer)
- Send completion event

**Agent Execution**:
- Transition to Running state
- Schedule based on priority
- Monitor for faults
- Handle interruption/termination

**Agent Fault Recovery**:
- Detect agent failures
- Implement exponential backoff
- Track restart attempts
- Fail after max attempts

### 2. Priority-Based Scheduling

**Static Priority Assignment**:
- RealTime: Emergency AI tasks, lowest latency
- Interactive: User-facing AI interactions
- Batch: Background AI processing
- Eco: Energy-efficient maintenance tasks

**Dynamic Priority Adjustment**:
- Adjust based on system load
- Consider resource availability
- Account for deadlines

### 3. Context Memory Integration

**Hot Memory Layer** (RAM):
- Fast access for running agents
- Limited capacity (system-configured)
- Automatic eviction for new agents

**Warm Memory Layer** (NVMe):
- Medium-speed storage for paused agents
- Larger capacity than hot layer
- Slower access but persistent

**Cold Memory Layer** (VRAM):
- Fallback storage for evicted contexts
- GPU-accelerated access
- Archival storage

### 4. Capability Security Integration

**Token Validation**:
- Verify agent capabilities before execution
- Check scope matches operation requirements
- Ensure tokens haven't expired

**Policy Enforcement**:
- LSM policy engine validation
- Audit logging for all decisions
- Fail-closed security model

### 5. Intent Bus Communication

**Event Broadcasting**:
- Publish agent events for system-wide awareness
- Subscribe to system intents for coordination
- Filter events based on agent capabilities

**Message Passing**:
- Send commands to agents
- Receive agent status updates
- Coordinate between multiple agents

## API Reference

### Main Structs

```rust
pub struct AgentScheduler {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    // ... other fields
}

pub enum AgentState {
    Creating,
    Running,
    Paused,
    Terminating,
    Failed,
    Restarting,
}

pub enum Priority {
    Eco,
    Batch,
    Interactive,
    RealTime,
}
```

### Key Methods

```rust
impl AgentScheduler {
    pub fn new(...) -> Self;
    
    pub async fn spawn_agent(&self, agent: AgentControlBlock) -> Result<(), SchedulerError>;
    
    pub async fn pause_agent(&self, agent_id: u64) -> Result<(), SchedulerError>;
    
    pub async fn resume_agent(&self, agent_id: u64) -> Result<(), SchedulerError>;
    
    pub async fn terminate_agent(&self, agent_id: u64) -> Result<(), SchedulerError>;
    
    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentControlBlock, SchedulerError>;
    
    pub async fn get_running_agents(&self) -> Vec<AgentControlBlock>;
    
    pub async fn get_all_events(&self) -> broadcast::Receiver<AgentEvent>;
}
```

## Configuration

### AgentScheduler Configuration

```rust
pub struct SchedulerConfig {
    pub max_agents: usize,
    pub default_priority: Priority,
    pub max_restarts: u32,
    pub restart_backoff_ms: u64,
    pub enable_monitoring: bool,
    pub intent_bus_capacity: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_agents: 1000,
            default_priority: Priority::Batch,
            max_restarts: 3,
            restart_backoff_ms: 1000,
            enable_monitoring: true,
            intent_bus_capacity: 1000,
        }
    }
}
```

### Metrics

```rust
pub struct SchedulerMetrics {
    pub active_agents: usize,
    pub paused_agents: usize,
    pub failed_agents: usize,
    pub successful_spawns: u64,
    pub failed_spawns: u64,
    pub context_switches: u64,
}
```

## Testing

### Unit Tests

```rust
#[tokio::test]
async fn test_agent_lifecycle() {
    let intent_bus = Arc::new(IntentBus::new(100));
    let context_memory = Arc::new(ContextMemoryManager::new());
    let capability_security = Arc::new(CapabilitySecurityManager::new());
    let supervisor_service = Arc::new(SupervisorService::new(
        mpsc::channel(100).0,
        Arc::new(RwLock::new(HashMap::new())),
        3,
        1000,
    ));
    
    let scheduler = AgentScheduler::new(
        intent_bus.clone(),
        context_memory.clone(),
        capability_security.clone(),
        supervisor_service.clone(),
    );
    
    let agent = AgentControlBlock::new(1);
    agent.state = AgentState::Creating;
    
    assert!(scheduler.spawn_agent(agent).await.is_ok());
    
    let agent = scheduler.get_agent(1).await.unwrap();
    assert_eq!(agent.state, AgentState::Creating);
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_agent_workflow() {
    // Test complete agent workflow:
    // 1. Create agent
    // 2. Spawn agent
    // 3. Send intent to agent
    // 4. Process intent
    // 5. Monitor agent
    // 6. Handle agent failure
    // 7. Recover agent
}
```

## Performance Considerations

### Memory Optimization

```rust
impl AgentScheduler {
    // Use Arc for shared references to reduce memory
    pub fn optimize_memory_usage(&self) {
        // Merge inactive agents
        // Compress context data
        // Use efficient data structures
    }
}
```

### Concurrency Optimization

```rust
impl AgentScheduler {
    // Use fine-grained locks
    // Batch operations
    // Use async channels for work distribution
}
```

### Scalability

```rust
impl AgentScheduler {
    // Partition agents by priority
    // Use sharded data structures
    // Implement load balancing
}
```

## Migration Guide

### From v1.0 to v2.0

**API Changes**:
- AgentControlBlock moved to `agent-scheduler/src/block.rs`
- New SupervisorService for fault handling
- Updated IntentBus integration
- Enhanced priority system

**Configuration Changes**:
- New `SchedulerConfig` structure
- Support for dynamic priority adjustment
- Enhanced monitoring capabilities

```rust
// Old way
let agent = AgentControlBlock::new(1);

// New way
use agent_scheduler::block::AgentControlBlock;
let agent = AgentControlBlock::new(1);
```

## Security Considerations

### Capability Validation

```rust
pub async fn validate_agent_capabilities(
    &self,
    agent_id: u64,
    required_capabilities: &[String]
) -> Result<bool, SecurityError> {
    let agents = self.agents.read().await;
    let agent = agents.get(&agent_id)
        .ok_or(SecurityError::AgentNotFound { id: agent_id })?;
    
    // Check if agent has all required capabilities
    for capability in required_capabilities {
        if !agent.capabilities.iter().any(|token| token.has_capability(capability)) {
            return Ok(false);
        }
    }
    
    Ok(true)
}
```

### Audit Logging

```rust
pub async fn log_agent_event(&self, event: AgentEvent) {
    // Log all agent events for audit purposes
    // Include timestamp, agent id, event type, and relevant context
    self.monitoring_tx.send(event).await;
}
```

## Future Enhancements

### 1. GPU-Accelerated Scheduling

```rust
// Implement priority-based GPU scheduling
pub struct GPUScheduler {
    priority_queue: PriorityQueue<AgentHandle>,
    gpu_memory: Arc<RwLock<GpuMemory>>,
}
```

### 2. Dynamic Priority Adjustment

```rust
pub struct AdaptivePriorityScheduler {
    system_load_monitor: Arc<SystemLoadMonitor>,
    deadline_tracker: Arc<DeadlineTracker>,
    resource_monitor: Arc<ResourceMonitor>,
}
```

### 3. Multi-Agent Coordination

```rust
pub struct AgentCoordinator {
    agent_registry: Arc<AgentRegistry>,
    coordination_bus: Arc<CoordinationBus>,
}
```

## Summary

The AgentScheduler component is the heart of AI-Native Kernel's agent management system. It provides:

1. **Robust Lifecycle Management** - Create, execute, monitor, and recover agents
2. **Intelligent Scheduling** - Priority-based algorithm for optimal resource utilization
3. **Secure Operations** - Integration with capability security and LSM policies
4. **Comprehensive Monitoring** - Event system for system-wide awareness
5. **Scalable Architecture** - Supports thousands of concurrent agents

This component follows the security-first, async-first design principles of the entire AI-Native Kernel project.

---

**Maintainer**: Agent Scheduler Team  
**Version**: 2.0.0  
**Last Updated**: $(date)  
**Read Time**: ~5 minutes
