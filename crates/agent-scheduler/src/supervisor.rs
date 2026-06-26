use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc, broadcast};
use crate::block::{AgentControlBlock, AgentState};

#[derive(Debug, Clone)]
pub struct Supervisor {
    restart_tx: mpsc::Sender<RestartRequest>,
    restart_rx: Arc<RwLock<mpsc::Receiver<RestartRequest>>>,
    max_restarts: u32,
    restart_backoff_ms: u64,
}

#[derive(Debug, Clone)]
struct RestartRequest {
    agent_id: u64,
    reason: String,
    timestamp: std::time::Instant,
}

#[derive(Debug)]
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
        let (restart_tx, restart_rx) = mpsc::channel(100);
        let supervisor = Supervisor {
            restart_tx,
            restart_rx: Arc::new(RwLock::new(restart_rx)),
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
                    let backoff = std::time::Duration::from_millis(
                        self.supervisor.restart_backoff_ms * (2_u64.pow(agent.restart_attempts))
                    );
                    tokio::time::sleep(backoff).await;
                    self.restart_agent(agent.id, "Agent failed").await
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
    
    async fn restart_agent(&self, agent_id: u64, reason: &str) -> bool {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.state = AgentState::Restarting;
            agent.restart_attempts += 1;
            agent.last_restart = std::time::Instant::now();
            
            // Simulate restart logic
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            
            agent.state = AgentState::Creating;
            true
        } else {
            false
        }
    }
    
    async fn reset_restart_counter(&self, agent_id: u64) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.restart_attempts = 0;
        }
    }
    
    pub async fn start_monitoring_loop(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        let agents = self.agents.clone();
        
        loop {
            interval.tick().await;
            let agents_guard = agents.read().await;
            
            for agent in agents_guard.values() {
                let should_monitor = self.monitor_agent(agent).await;
                if !should_monitor {
                    continue;
                }
            }
        }
    }
}