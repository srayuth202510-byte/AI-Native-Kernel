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
        // Set state to Restarting and increment attempts while holding lock briefly
        {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.state = AgentState::Restarting;
                agent.restart_attempts = agent.restart_attempts.saturating_add(1);
                agent.last_restart = std::time::Instant::now();
            } else {
                return false;
            }
        }

        // Perform the sleep without holding the write lock
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Set state back to Running under a new brief lock acquisition
        {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.state = AgentState::Running;
                true
            } else {
                false
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{AgentControlBlock, AgentState};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_supervisor_restarts_failed_agent() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(1);
        agent.state = AgentState::Failed;
        agents.write().await.insert(1, agent);

        let supervisor = SupervisorService::new(agents.clone(), 3, 1);

        // Retrieve a clone of the agent first to release the read lock immediately
        let agent_to_monitor = {
            let reader = supervisor.agents.read().await;
            reader[&1].clone()
        };

        let restarted = supervisor.monitor_agent(&agent_to_monitor).await;
        assert!(restarted);

        let final_agent = &supervisor.agents.read().await[&1];
        assert_eq!(final_agent.state, AgentState::Running);
        assert_eq!(final_agent.restart_attempts, 1);
    }

    #[tokio::test]
    async fn test_supervisor_gives_up_after_max_restarts() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(2);
        agent.state = AgentState::Failed;
        agent.restart_attempts = 3;
        agents.write().await.insert(2, agent);

        let supervisor = SupervisorService::new(agents.clone(), 3, 1);

        // Retrieve a clone of the agent first to release the read lock immediately
        let agent_to_monitor = {
            let reader = supervisor.agents.read().await;
            reader[&2].clone()
        };

        let restarted = supervisor.monitor_agent(&agent_to_monitor).await;
        assert!(!restarted);

        let final_agent = &supervisor.agents.read().await[&2];
        assert_eq!(final_agent.state, AgentState::Failed);
        assert_eq!(final_agent.restart_attempts, 3);
    }

    #[tokio::test]
    async fn test_supervisor_loop_fault_injection() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(3);
        agent.state = AgentState::Running;
        agents.write().await.insert(3, agent);

        let supervisor = SupervisorService::new(agents.clone(), 5, 1);

        // Spawn supervisor loop in background
        let supervisor_clone = supervisor.clone();
        let loop_handle = tokio::spawn(async move {
            supervisor_clone.start_monitoring_loop().await;
        });

        // Sleep briefly to let loop start and make first tick
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Simulate fault: change running agent to failed (Fault Injection)
        {
            let mut writer = agents.write().await;
            if let Some(a) = writer.get_mut(&3) {
                a.state = AgentState::Failed;
            }
        }

        // Wait for supervisor loop to catch it and restart
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Verify that supervisor has restarted it back to Running
        {
            let reader = agents.read().await;
            let a = &reader[&3];
            assert_eq!(a.state, AgentState::Running);
        }

        // Abort the background supervisor loop
        loop_handle.abort();
    }
}
