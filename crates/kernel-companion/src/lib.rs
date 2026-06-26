#![deny(unsafe_code)]

use agent_scheduler::AgentScheduler;
use capability_security::CapabilitySecurityManager;
use compute_scheduler::ComputeScheduler;
use compute_scheduler::ComputeProfile;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentType};
use std::sync::Arc;

pub mod lsm;

pub use lsm::{attach_lsm_hooks, LsmAttachment, LsmDecision, LsmPolicyEngine};

pub struct KernelCompanion {
    lsm_engine: Arc<LsmPolicyEngine>,
    intent_bus: Arc<IntentBus>,
    context_memory: Arc<ContextMemoryManager>,
    capability_security: Arc<CapabilitySecurityManager>,
    compute_scheduler: Arc<ComputeScheduler>,
    agent_scheduler: Arc<AgentScheduler>,
    attachment: Option<LsmAttachment>,
}

impl KernelCompanion {
    #[must_use]
    pub fn new() -> Self {
        let intent_bus = Arc::new(IntentBus::new(1024));
        let context_memory = Arc::new(ContextMemoryManager::new());
        let capability_security = Arc::new(CapabilitySecurityManager::new());
        let agent_scheduler = Arc::new(AgentScheduler::new(
            Arc::clone(&intent_bus),
            Arc::clone(&context_memory),
            Arc::clone(&capability_security),
        ));

        Self {
            lsm_engine: Arc::new(LsmPolicyEngine::new()),
            intent_bus,
            context_memory,
            capability_security,
            compute_scheduler: Arc::new(ComputeScheduler::new()),
            agent_scheduler,
            attachment: None,
        }
    }

    #[must_use]
    pub fn intent_bus(&self) -> Arc<IntentBus> {
        Arc::clone(&self.intent_bus)
    }

    #[must_use]
    pub fn agent_scheduler(&self) -> Arc<AgentScheduler> {
        Arc::clone(&self.agent_scheduler)
    }

    #[must_use]
    pub fn compute_scheduler(&self) -> Arc<ComputeScheduler> {
        Arc::clone(&self.compute_scheduler)
    }

    pub async fn boot(&mut self) -> anyhow::Result<()> {
        if self.attachment.is_none() {
            self.attachment = Some(attach_lsm_hooks(Arc::clone(&self.lsm_engine))?);
        }

        let _boot_context = self.context_memory();
        let _security = self.capability_security();
        let _warmup_score = self.compute_scheduler.score(ComputeProfile {
            latency_ms: 1.0,
            power_watts: 1.0,
            cost_units: 1.0,
        });

        let scheduler = Arc::clone(&self.agent_scheduler);
        let mut intent_subscriber = self.intent_bus.subscribe();
        let supervisor = scheduler.supervisor();

        let _routing_task = tokio::spawn(async move {
            while let Some(intent) = intent_subscriber.receive().await {
                let _ = scheduler.route_intent(intent).await;
            }
        });

        let _supervisor_task = tokio::spawn(async move {
            supervisor.start_monitoring_loop().await;
        });

        let _ = self
            .intent_bus
            .publish(Intent::new(
                "boot",
                IntentType::Event,
                "kernel-companion boot",
                intent_bus::IntentPriority::Low,
                "kernel-companion",
            ))
            .await;

        Ok(())
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        self.boot().await?;

        tokio::signal::ctrl_c().await?;

        self.shutdown().await;
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        if let Some(attachment) = self.attachment.as_mut() {
            attachment.detach();
        }
        self.attachment = None;
    }

    #[must_use]
    pub fn classify_intent(&self, intent_type: &IntentType) -> &'static str {
        match intent_type {
            IntentType::NaturalLanguage => "interactive",
            IntentType::Structured => "batch",
            IntentType::Command => "interactive",
            IntentType::Event => "eco",
            IntentType::Interrupt => "realtime",
        }
    }

    #[must_use]
    pub fn context_memory(&self) -> Arc<ContextMemoryManager> {
        Arc::clone(&self.context_memory)
    }

    #[must_use]
    pub fn capability_security(&self) -> Arc<CapabilitySecurityManager> {
        Arc::clone(&self.capability_security)
    }

    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attachment
            .as_ref()
            .is_some_and(LsmAttachment::is_attached)
    }
}

impl Default for KernelCompanion {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_intent_returns_expected_queue_class() {
        let companion = KernelCompanion::new();

        assert_eq!(companion.classify_intent(&IntentType::NaturalLanguage), "interactive");
        assert_eq!(companion.classify_intent(&IntentType::Structured), "batch");
        assert_eq!(companion.classify_intent(&IntentType::Interrupt), "realtime");
    }

    #[tokio::test]
    async fn boot_attaches_and_shutdown_detaches() {
        let mut companion = KernelCompanion::new();

        companion.boot().await.expect("boot should succeed");
        assert!(companion.is_attached());

        companion.shutdown().await;
        assert!(!companion.is_attached());
    }
}
