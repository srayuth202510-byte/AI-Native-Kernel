use tokio::sync::{RwLock, mpsc, broadcast};
use std::sync::Arc;
use std::collections::{HashMap, BinaryHeap};
use priority::Priority;

#[derive(Debug, Clone)]
pub struct AgentControlBlock {
    pub id: u64,
    pub state: AgentState,
    pub priority: Priority,
    pub context_ptr: usize, // Pointer to context memory
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

impl AgentControlBlock {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            state: AgentState::Creating,
            priority: Priority::Batch,
            context_ptr: 0,
            capabilities: Vec::new(),
            restart_attempts: 0,
            last_restart: std::time::Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub id: u64,
    pub scope: Scope,
    pub capabilities: Vec<String>,
    pub expires_at: std::time::Instant,
}

#[derive(Debug, Clone)]
pub enum Scope {
    Process(u32),
    Thread(u32),
    Global,
}

#[derive(Debug, Clone)]
pub struct AgentScheduler {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    priority_queue: Arc<RwLock<BinaryHeap<PriorityAgent>>>,
    capability_manager: Arc<RwLock<CapabilitySecurityManager>>,
    supervisor: Arc<Supervisor>,
    next_agent_id: Arc<RwLock<u64>>,
}

#[derive(Debug, Clone)]
struct PriorityAgent {
    agent: AgentControlBlock,
    priority: Priority,
}

impl Ord for PriorityAgent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for PriorityAgent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PriorityAgent {}

#[derive(Debug, Clone)]
pub struct CapabilitySecurityManager {
    tokens: HashMap<u64, CapabilityToken>,
    policies: HashMap<String, SecurityPolicy>,
}

#[derive(Debug, Clone)]
struct SecurityPolicy {
    pub allowed_capabilities: Vec<String>,
    pub deny_operations: Vec<String>,
    pub audit_enabled: bool,
}

#[derive(Debug)]
struct Supervisor {
    restart_queue: mpsc::Sender<RestartRequest>,
    max_restarts: u32,
    restart_backoff_ms: u64,
}

#[derive(Debug, Clone)]
struct RestartRequest {
    agent_id: u64,
    reason: String,
    timestamp: std::time::Instant,
}