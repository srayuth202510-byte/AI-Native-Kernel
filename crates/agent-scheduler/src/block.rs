use crate::priority::Priority;
use capability_security::CapabilityToken;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentControlBlock {
    pub id: u64,
    pub state: AgentState,
    pub priority: Priority,
    pub context_key: Option<String>,
    pub capabilities: Vec<CapabilityToken>,
    pub restart_attempts: u32,
    pub last_restart: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    Creating,
    Running,
    Paused,
    Terminating,
    Failed,
    Restarting,
}

impl AgentControlBlock {
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            state: AgentState::Creating,
            priority: Priority::Batch,
            context_key: None,
            capabilities: Vec::new(),
            restart_attempts: 0,
            last_restart: Instant::now(),
        }
    }
}
