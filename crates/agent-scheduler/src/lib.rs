#![deny(unsafe_code)]

use tokio::sync::{RwLock, mpsc, broadcast};
use std::sync::Arc;
use std::collections::HashMap;

use crate::block::{AgentControlBlock, AgentState, CapabilityToken};
use crate::priority::Priority;

#[derive(Debug, Clone)]
pub struct SchedulerError {
    pub message: String,
}

impl SchedulerError {
    pub fn new(msg: &str) -> Self {
        Self { message: msg.to_string() }
    }
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Debug for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Clone)]
pub struct AgentScheduler {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    intent_bus: Arc<IntentBus>,
    context_memory: Arc<ContextMemoryManager>,
    capability_security: Arc<CapabilitySecurityManager>,
    supervisor_service: Arc<SupervisorService>,
    next_agent_id: Arc<RwLock<u64>>,
    pub monitoring_tx: broadcast::Sender<AgentEvent>,
    pub monitoring_rx: Arc<RwLock<broadcast::Receiver<AgentEvent>>>,
}

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

impl AgentScheduler {
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
        supervisor_service: Arc<SupervisorService>,
    ) -> Self {
        let (monitoring_tx, monitoring_rx) = broadcast::channel(1000);
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            intent_bus,
            context_memory,
            capability_security,
            supervisor_service,
            next_agent_id: Arc::new(RwLock::new(1)),
            monitoring_tx,
            monitoring_rx: Arc::new(RwLock::new(monitoring_rx)),
        }
    }
    
    pub async fn spawn_agent(&self, agent: AgentControlBlock) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        
        if agents.contains_key(&agent.id) {
            return Err(SchedulerError::new("Agent already exists"));
        }
        
        agents.insert(agent.id, agent.clone());
        
        let _ = self.monitoring_tx.send(AgentEvent::AgentSpawned(agent.clone()));
        
        Ok(())
    }
    
    pub async fn pause_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        
        let agent = agents.get_mut(&agent_id)
            .ok_or(SchedulerError::new("Agent not found"))?;
        
        if agent.state != AgentState::Running {
            return Err(SchedulerError::new("Agent not running"));
        }
        
        agent.state = AgentState::Paused;
        
        let _ = self.monitoring_tx.send(AgentEvent::AgentPaused(agent.clone()));
        
        Ok(())
    }
    
    pub async fn resume_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        
        let agent = agents.get_mut(&agent_id)
            .ok_or(SchedulerError::new("Agent not found"))?;
        
        if agent.state != AgentState::Paused {
            return Err(SchedulerError::new("Agent not paused"));
        }
        
        agent.state = AgentState::Running;
        
        let _ = self.monitoring_tx.send(AgentEvent::AgentResumed(agent.clone()));
        
        Ok(())
    }
    
    pub async fn terminate_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        
        let agent = agents.get_mut(&agent_id)
            .ok_or(SchedulerError::new("Agent not found"))?;
        
        agent.state = AgentState::Terminating;
        
        let _ = self.monitoring_tx.send(AgentEvent::AgentTerminated(agent.clone()));
        
        agents.remove(&agent_id);
        
        Ok(())
    }
    
    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentControlBlock, SchedulerError> {
        let agents = self.agents.read().await;
        
        agents.get(&agent_id)
            .cloned()
            .ok_or(SchedulerError::new("Agent not found"))
    }
    
    pub async fn get_running_agents(&self) -> Vec<AgentControlBlock> {
        let agents = self.agents.read().await;
        agents.values()
            .filter(|agent| agent.state == AgentState::Running)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct IntentBus {
    sender: broadcast::Sender<Intent>,
    receiver: Arc<RwLock<broadcast::Receiver<Intent>>>,
    intent_queue: Arc<RwLock<mpsc::UnboundedSender<Intent>>>,
    filters: Arc<RwLock<HashMap<String, IntentFilter>>>,
}

#[derive(Debug, Clone)]
pub struct Intent {
    pub id: String,
    pub intent_type: IntentType,
    pub payload: String,
    pub priority: IntentPriority,
    pub timestamp: std::time::Instant,
    pub source: String,
    pub target: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum IntentType {
    NaturalLanguage,
    Structured,
    Command,
    Event,
    Interrupt,
}

#[derive(Debug, Clone)]
pub enum IntentPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct IntentFilter {
    pub name: String,
    pub conditions: Vec<FilterCondition>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum FilterCondition {
    IntentType(IntentType),
    Priority(IntentPriority),
    SourceContains(String),
    TargetContains(String),
    HasMetadata(String, String),
}

impl IntentBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = broadcast::channel(capacity);
        let (queue_sender, queue_receiver) = mpsc::unbounded_channel();
        
        Self {
            sender,
            receiver: Arc::new(RwLock::new(receiver)),
            intent_queue: Arc::new(RwLock::new(queue_sender)),
            filters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn publish(&self, intent: Intent) {
        let _ = self.sender.send(intent.clone());
        let _ = self.intent_queue.write().await.send(intent);
    }
}

pub trait IntentProcessor {
    async fn process(&self, intent: Intent);
}

#[derive(Debug, Clone)]
pub struct IntentSubscriber {
    _receiver: broadcast::Receiver<Intent>,
}

impl IntentSubscriber {
    pub async fn receive(&mut self) -> Option<Intent> {
        self._receiver.recv().await.ok()
    }
}

pub struct ContextMemoryManager {
    // Hot/Warm/Cold layers
}

pub struct CapabilitySecurityManager {
    // Capability token management
}

pub struct SupervisorService {
    // Supervisor logic
}
