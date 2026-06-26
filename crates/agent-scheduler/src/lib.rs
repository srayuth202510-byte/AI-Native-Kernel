#![deny(unsafe_code)]

pub mod block;
pub mod priority;
pub mod supervisor;

use crate::block::{AgentControlBlock, AgentState};
use crate::priority::Priority;
use crate::supervisor::SupervisorService;
use capability_security::CapabilitySecurityManager;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentType};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};

pub use capability_security::{CapabilityToken, Scope};
pub use priority::{PriorityAgent, PriorityQueue};
pub use supervisor::SupervisorService as Supervisor;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("agent already exists")]
    AgentAlreadyExists,
    #[error("agent not found")]
    AgentNotFound,
    #[error("agent is not running")]
    AgentNotRunning,
    #[error("agent is not paused")]
    AgentNotPaused,
    #[error("intent dispatch failed")]
    IntentDispatchFailed,
    #[error("context update failed")]
    ContextUpdateFailed,
    #[error("capability denied")]
    CapabilityDenied,
}

#[derive(Clone)]
pub struct AgentScheduler {
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    next_agent_id: Arc<RwLock<u64>>,
    intent_bus: Arc<IntentBus>,
    context_memory: Arc<ContextMemoryManager>,
    capability_security: Arc<CapabilitySecurityManager>,
    supervisor_service: Arc<SupervisorService>,
    monitoring_tx: broadcast::Sender<AgentEvent>,
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
    AgentContextSwitched(u64, String),
    AgentCapabilityGranted(u64, CapabilityToken),
    AgentCapabilityRevoked(u64, u64),
}

impl AgentScheduler {
    #[must_use]
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
    ) -> Self {
        let agents = Arc::new(RwLock::new(HashMap::new()));
        let supervisor_service = Arc::new(SupervisorService::new(agents.clone(), 3, 100));
        let (monitoring_tx, _) = broadcast::channel(1024);

        Self {
            agents,
            next_agent_id: Arc::new(RwLock::new(1)),
            intent_bus,
            context_memory,
            capability_security,
            supervisor_service,
            monitoring_tx,
        }
    }

    #[must_use]
    pub fn supervisor(&self) -> Arc<SupervisorService> {
        Arc::clone(&self.supervisor_service)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.monitoring_tx.subscribe()
    }

    pub fn intent_bus(&self) -> Arc<IntentBus> {
        Arc::clone(&self.intent_bus)
    }

    #[must_use]
    pub fn context_memory(&self) -> Arc<ContextMemoryManager> {
        Arc::clone(&self.context_memory)
    }

    pub async fn allocate_agent_id(&self) -> u64 {
        let mut next_agent_id = self.next_agent_id.write().await;
        let agent_id = *next_agent_id;
        *next_agent_id = agent_id.saturating_add(1);
        agent_id
    }

    pub async fn spawn_agent(&self, mut agent: AgentControlBlock) -> Result<u64, SchedulerError> {
        if agent.id == 0 {
            agent.id = self.allocate_agent_id().await;
        }

        let mut agents = self.agents.write().await;
        if agents.contains_key(&agent.id) {
            return Err(SchedulerError::AgentAlreadyExists);
        }

        if agent.state == AgentState::Creating {
            agent.state = AgentState::Running;
        }

        let agent_id = agent.id;
        agents.insert(agent_id, agent.clone());
        let _ = self.monitoring_tx.send(AgentEvent::AgentSpawned(agent));
        Ok(agent_id)
    }

    pub async fn submit_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        self.intent_bus
            .publish(intent)
            .await
            .map_err(|_| SchedulerError::IntentDispatchFailed)
    }

    pub async fn route_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        match intent.intent_type {
            IntentType::Command => {
                if intent.payload == "spawn-agent" {
                    let agent_id = self.spawn_agent(AgentControlBlock::new(0)).await?;
                    let agent = self.get_agent(agent_id).await?;
                    let _ = self.monitoring_tx.send(AgentEvent::AgentCreated(agent));
                }
            }
            IntentType::Structured => {
                let Some(agent_id) = intent.metadata.get("agent_id") else {
                    return Ok(());
                };
                let Some(context_key) = intent.metadata.get("context_key") else {
                    return Ok(());
                };

                let agent_id = agent_id
                    .parse::<u64>()
                    .map_err(|_| SchedulerError::ContextUpdateFailed)?;

                let context_key = context_key.clone();
                let payload = intent.payload.clone().into_bytes();
                self.store_context(agent_id, context_key, payload).await?;
            }
            IntentType::NaturalLanguage | IntentType::Event | IntentType::Interrupt => {}
        }
        Ok(())
    }

    pub async fn pause_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;

        if agent.state != AgentState::Running {
            return Err(SchedulerError::AgentNotRunning);
        }

        agent.state = AgentState::Paused;
        let _ = self.monitoring_tx.send(AgentEvent::AgentPaused(agent.clone()));
        Ok(())
    }

    pub async fn resume_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;

        if agent.state != AgentState::Paused {
            return Err(SchedulerError::AgentNotPaused);
        }

        agent.state = AgentState::Running;
        let _ = self.monitoring_tx.send(AgentEvent::AgentResumed(agent.clone()));
        Ok(())
    }

    pub async fn terminate_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let event = {
            let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;
            agent.state = AgentState::Terminating;
            agent.clone()
        };
        agents.remove(&agent_id);
        let _ = self.monitoring_tx.send(AgentEvent::AgentTerminated(event));
        Ok(())
    }

    pub async fn fail_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;
        agent.state = AgentState::Failed;
        let _ = self.monitoring_tx.send(AgentEvent::AgentFailed(agent.clone()));
        Ok(())
    }

    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentControlBlock, SchedulerError> {
        let agents = self.agents.read().await;
        agents.get(&agent_id).cloned().ok_or(SchedulerError::AgentNotFound)
    }

    pub async fn get_running_agents(&self) -> Vec<AgentControlBlock> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|agent| agent.state == AgentState::Running)
            .cloned()
            .collect()
    }

    pub async fn store_context(
        &self,
        agent_id: u64,
        context_key: impl Into<String>,
        value: Vec<u8>,
    ) -> Result<(), SchedulerError> {
        let context_key = context_key.into();
        {
            let agents = self.agents.read().await;
            if !agents.contains_key(&agent_id) {
                return Err(SchedulerError::AgentNotFound);
            }
        }

        self.context_memory.put(context_key.clone(), value);

        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;
        agent.context_key = Some(context_key.clone());
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentContextSwitched(agent_id, context_key));
        Ok(())
    }

    pub async fn grant_capability(
        &self,
        agent_id: u64,
        token: CapabilityToken,
    ) -> Result<(), SchedulerError> {
        {
            let agents = self.agents.read().await;
            if !agents.contains_key(&agent_id) {
                return Err(SchedulerError::AgentNotFound);
            }
        }

        let capability_allowed = token
            .capabilities
            .iter()
            .any(|capability| self.capability_security.authorize_token(&token, capability));

        if !capability_allowed {
            return Err(SchedulerError::CapabilityDenied);
        }

        self.capability_security.issue_token(token.clone());

        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&agent_id).ok_or(SchedulerError::AgentNotFound)?;
        agent.capabilities.push(token.clone());
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentCapabilityGranted(agent_id, token));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{AgentControlBlock, AgentState};
    use crate::{AgentScheduler, SchedulerError};
    use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope};
    use context_memory::ContextMemoryManager;
    use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    fn scheduler() -> AgentScheduler {
        AgentScheduler::new(
            Arc::new(IntentBus::new(8)),
            Arc::new(ContextMemoryManager::new()),
            Arc::new(CapabilitySecurityManager::new()),
        )
    }

    #[tokio::test]
    async fn spawn_pause_resume_and_terminate_agent() {
        let scheduler = scheduler();
        let agent_id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");

        assert_eq!(scheduler.get_running_agents().await.len(), 1);

        scheduler.pause_agent(agent_id).await.expect("pause should succeed");
        assert_eq!(scheduler.get_agent(agent_id).await.unwrap().state, AgentState::Paused);

        scheduler.resume_agent(agent_id).await.expect("resume should succeed");
        assert_eq!(scheduler.get_agent(agent_id).await.unwrap().state, AgentState::Running);

        scheduler.terminate_agent(agent_id).await.expect("terminate should succeed");
        assert!(matches!(
            scheduler.get_agent(agent_id).await,
            Err(SchedulerError::AgentNotFound)
        ));
    }

    #[tokio::test]
    async fn submit_intent_reaches_bus_subscriber() {
        let scheduler = scheduler();
        let mut subscriber = scheduler.intent_bus().subscribe();
        let intent = Intent::new(
            "intent-1",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::High,
            "user",
        );

        scheduler
            .submit_intent(intent.clone())
            .await
            .expect("intent dispatch should succeed");

        let received = timeout(Duration::from_millis(100), subscriber.receive())
            .await
            .expect("receive should not time out")
            .expect("subscriber should receive intent");

        assert_eq!(received.id, intent.id);
        assert_eq!(received.payload, intent.payload);
    }

    #[tokio::test]
    async fn route_command_can_spawn_agent() {
        let scheduler = scheduler();
        let intent = Intent::new(
            "intent-2",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::Medium,
            "system",
        );

        scheduler.route_intent(intent).await.expect("route should succeed");

        assert_eq!(scheduler.get_running_agents().await.len(), 1);
    }

    #[tokio::test]
    async fn route_structured_intent_updates_context() {
        let scheduler = scheduler();
        let agent_id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");

        let mut intent = Intent::new(
            "intent-3",
            IntentType::Structured,
            "payload-data",
            IntentPriority::Low,
            "agent-1",
        );
        intent
            .metadata
            .insert("agent_id".to_string(), agent_id.to_string());
        intent
            .metadata
            .insert("context_key".to_string(), "ctx-1".to_string());

        scheduler.route_intent(intent).await.expect("route should succeed");

        let agent = scheduler.get_agent(agent_id).await.expect("agent should exist");
        assert_eq!(agent.context_key.as_deref(), Some("ctx-1"));
        assert_eq!(
            scheduler.context_memory().get("ctx-1").expect("context should exist"),
            b"payload-data".to_vec()
        );
    }

    #[tokio::test]
    async fn grant_capability_requires_allowed_token() {
        let scheduler = scheduler();
        let agent_id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");
        let token = CapabilityToken::new(
            7,
            Scope::Global,
            vec!["read".to_string()],
            Duration::from_secs(60),
        );

        scheduler
            .grant_capability(agent_id, token.clone())
            .await
            .expect("grant should succeed");

        let agent = scheduler.get_agent(agent_id).await.expect("agent should exist");
        assert_eq!(agent.capabilities.len(), 1);
        assert_eq!(agent.capabilities[0].id, token.id);
    }

    #[tokio::test]
    async fn grant_capability_denies_unapproved_token() {
        let scheduler = scheduler();
        let agent_id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");
        let token = CapabilityToken::new(
            8,
            Scope::Global,
            vec!["write".to_string()],
            Duration::from_secs(60),
        );

        let result = scheduler.grant_capability(agent_id, token).await;
        assert!(matches!(result, Err(SchedulerError::CapabilityDenied)));
    }
}
