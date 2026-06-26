use crate::block::{AgentControlBlock, AgentState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct SupervisorService {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    max_restarts: u32,
    restart_backoff_ms: u64,
}

impl SupervisorService {
    #[must_use]
    pub fn new(
        agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
        max_restarts: u32,
        restart_backoff_ms: u64,
    ) -> Self {
        Self {
            agents,
            max_restarts,
            restart_backoff_ms,
        }
    }

    pub async fn monitor_agent(&self, agent: &AgentControlBlock) -> bool {
        match agent.state {
            AgentState::Failed => {
                if agent.restart_attempts < self.max_restarts {
                    let attempts = agent.restart_attempts.min(10);
                    let multiplier = 1_u64 << attempts;
                    let backoff = std::time::Duration::from_millis(
                        self.restart_backoff_ms.saturating_mul(multiplier),
                    );
                    tokio::time::sleep(backoff).await;
                    self.restart_agent(agent.id).await
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

    async fn restart_agent(&self, agent_id: u64) -> bool {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.state = AgentState::Restarting;
            agent.restart_attempts = agent.restart_attempts.saturating_add(1);
            agent.last_restart = std::time::Instant::now();

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            agent.state = AgentState::Running;
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

        loop {
            interval.tick().await;

            let snapshot = {
                let agents = self.agents.read().await;
                agents.values().cloned().collect::<Vec<_>>()
            };

            for agent in snapshot {
                let _ = self.monitor_agent(&agent).await;
            }
        }
    }
}
