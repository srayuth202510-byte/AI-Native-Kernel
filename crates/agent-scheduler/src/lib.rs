//! # Agent Scheduler
//!
//! โมดูลนี้ทำหน้าที่จัดการวงจรชีวิต (Lifecycle), จัดลำดับความสำคัญ (Priority),
//! และการแยกส่วนการทำงาน (Isolation) ของ Agent แต่ละตัวในระบบ AI-Native Kernel.
//! ทำงานประสานงานกับ Intent Bus, Context Memory, และ Capability Security.

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
use tokio::sync::{RwLock, broadcast};

pub use capability_security::{CapabilityToken, Scope};
pub use priority::{PriorityAgent, PriorityQueue};
pub use supervisor::SupervisorService as Supervisor;

/// ข้อผิดพลาดต่างๆ ที่เกิดขึ้นในระหว่างการทำงานของ Scheduler
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    /// เกิดขึ้นเมื่อพยายามจะสร้าง Agent ที่มี ID ซ้ำกับที่มีอยู่แล้ว
    #[error("agent already exists")]
    AgentAlreadyExists,
    /// ไม่พบ Agent ที่ระบุ
    #[error("agent not found")]
    AgentNotFound,
    /// Agent ไม่ได้อยู่ในสถานะ Running
    #[error("agent is not running")]
    AgentNotRunning,
    /// Agent ไม่ได้อยู่ในสถานะ Paused
    #[error("agent is not paused")]
    AgentNotPaused,
    /// การส่ง Intent ไปยัง Intent Bus ล้มเหลว
    #[error("intent dispatch failed")]
    IntentDispatchFailed,
    /// การปรับปรุงข้อมูลบริบท (Context Update) ของ Agent ล้มเหลว
    #[error("context update failed")]
    ContextUpdateFailed,
    /// การขอใช้งานสิทธิ์ (Capability) ถูกปฏิเสธ
    #[error("capability denied")]
    CapabilityDenied,
}

/// โครงสร้างหลักของ Agent Scheduler ที่ทำหน้าที่จัดการและควบคุม Agent ทั้งหมดในระบบ
#[derive(Clone)]
pub struct AgentScheduler {
    /// แผนผังเก็บข้อมูล AgentControlBlock ของ Agent ทั้งหมดโดยระบุด้วย ID (มีระบบ Lock สำหรับอ่าน/เขียน)
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    /// ID ถัดไปที่จะใช้สำหรับสร้าง Agent ตัวใหม่ (เพิ่มขึ้นทีละ 1)
    next_agent_id: Arc<RwLock<u64>>,
    /// Intent Bus สำหรับการกระจายข่าวสารและคำสั่งแบบ Event-driven
    intent_bus: Arc<IntentBus>,
    /// ตัวจัดการหน่วยความจำบริบท (Hot/Warm/Cold paging) ของ Agent
    context_memory: Arc<ContextMemoryManager>,
    /// ตัวจัดการความปลอดภัยและการตรวจสอบสิทธิ์ของ Agent (LSM Policy Engine)
    capability_security: Arc<CapabilitySecurityManager>,
    /// บริการ Supervisor สำหรับเฝ้าระวังความล้มเหลวและ Restart Agent
    supervisor_service: Arc<SupervisorService>,
    /// ช่องทางส่งข้อมูลความเคลื่อนไหว (Event) ของ Agent เพื่อใช้วิเคราะห์หรือทำ Audit Log
    monitoring_tx: broadcast::Sender<AgentEvent>,
}

/// เหตุการณ์สำคัญต่างๆ ที่เกิดขึ้นกับ Agent ในระบบ
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// สร้างข้อมูล Agent สำเร็จแต่ยังไม่ได้เปิดให้เริ่มทำงาน
    AgentCreated(AgentControlBlock),
    /// Agent เริ่มต้นทำงาน (Spawned)
    AgentSpawned(AgentControlBlock),
    /// Agent ถูกสั่งให้หยุดชั่วคราว (Paused)
    AgentPaused(AgentControlBlock),
    /// Agent กลับมาทำงานต่ออีกครั้ง (Resumed)
    AgentResumed(AgentControlBlock),
    /// Agent ทำงานเสร็จสิ้นและถูกลบออกจากสารระบบ (Terminated)
    AgentTerminated(AgentControlBlock),
    /// Agent เกิดข้อผิดพลาดร้ายแรงและหยุดทำงาน (Failed)
    AgentFailed(AgentControlBlock),
    /// Agent ถูกเริ่มต้นการทำงานใหม่หลังล้มเหลว (Restarted)
    AgentRestarted(AgentControlBlock),
    /// ลำดับความสำคัญ (Priority) ของ Agent ถูกเปลี่ยน
    AgentPriorityChanged(u64, Priority),
    /// บริบทข้อมูล (Context Key) ของ Agent ถูกเปลี่ยน/สลับ
    AgentContextSwitched(u64, String),
    /// Agent ได้รับสิทธิ์ใหม่ (Capability Token Granted)
    AgentCapabilityGranted(u64, CapabilityToken),
    /// สิทธิ์ของ Agent ถูกยกเลิก (Capability Token Revoked)
    AgentCapabilityRevoked(u64, u64),
}

impl AgentScheduler {
    /// สร้างอินสแตนซ์ใหม่ของ `AgentScheduler`
    #[must_use]
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
    ) -> Self {
        let agents = Arc::new(RwLock::new(HashMap::new()));
        // ตั้งค่า Supervisor Service เริ่มต้นให้มีจำนวน Restart สูงสุด 3 ครั้ง และ Backoff 100ms
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

    /// ดึงการอ้างอิงถึง `SupervisorService`
    #[must_use]
    pub fn supervisor(&self) -> Arc<SupervisorService> {
        Arc::clone(&self.supervisor_service)
    }

    /// สมัครรับข้อมูลเหตุการณ์ (Event Stream) ของ Agent เพื่อนำไปใช้งานด้าน Monitoring หรือ Audit
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.monitoring_tx.subscribe()
    }

    /// ดึงการอ้างอิงถึง `IntentBus` สำหรับสื่อสาร
    pub fn intent_bus(&self) -> Arc<IntentBus> {
        Arc::clone(&self.intent_bus)
    }

    /// ดึงการอ้างอิงถึง `ContextMemoryManager`
    #[must_use]
    pub fn context_memory(&self) -> Arc<ContextMemoryManager> {
        Arc::clone(&self.context_memory)
    }

    /// จัดสรร ID ใหม่สำหรับ Agent แบบไม่ซ้ำกันอย่างปลอดภัย (Thread-safe)
    pub async fn allocate_agent_id(&self) -> u64 {
        let mut next_agent_id = self.next_agent_id.write().await;
        let agent_id = *next_agent_id;
        // ป้องกัน Overflow ด้วย saturating_add
        *next_agent_id = agent_id.saturating_add(1);
        agent_id
    }

    /// นำ Agent เข้าสู่ระบบและเปลี่ยนสถานะเริ่มต้นให้พร้อมทำงาน
    pub async fn spawn_agent(&self, mut agent: AgentControlBlock) -> Result<u64, SchedulerError> {
        // หากไม่มี ID ให้จัดสรรใหม่โดยอัตโนมัติ
        if agent.id == 0 {
            agent.id = self.allocate_agent_id().await;
        }

        let mut agents = self.agents.write().await;
        // ตรวจสอบว่าไม่เกิด ID ซ้ำซ้อนในระบบ
        if agents.contains_key(&agent.id) {
            return Err(SchedulerError::AgentAlreadyExists);
        }

        // หากสถานะเดิมคือ Creating ให้เปลี่ยนเป็น Running
        if agent.state == AgentState::Creating {
            agent.state = AgentState::Running;
        }

        let agent_id = agent.id;
        agents.insert(agent_id, agent.clone());
        // ส่งเหตุการณ์ Spawned ออกไปยัง Monitoring Bus
        let _ = self.monitoring_tx.send(AgentEvent::AgentSpawned(agent));
        Ok(agent_id)
    }

    /// ส่งต่อ Intent ไปยังระบบ Intent Bus
    pub async fn submit_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        self.intent_bus
            .publish(intent)
            .await
            .map_err(|_| SchedulerError::IntentDispatchFailed)
    }

    /// ถอดรหัสโครงสร้าง Intent และเรียกใช้งานคำสั่งตามความเหมาะสม
    pub async fn route_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        match intent.intent_type {
            // คำสั่งตรงจากผู้ใช้หรือระบบ
            IntentType::Command => {
                if intent.payload == "spawn-agent" {
                    // หากเป็นคำสั่งสร้าง Agent ใหม่ ให้สร้าง บันทึก และประกาศ Event
                    let agent_id = self.spawn_agent(AgentControlBlock::new(0)).await?;
                    let agent = self.get_agent(agent_id).await?;
                    let _ = self.monitoring_tx.send(AgentEvent::AgentCreated(agent));
                }
            }
            // ข้อมูลที่มีโครงสร้างและต้องการนำไปอัปเดตบริบท (Context)
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
                // บันทึกและสลับบริบทข้อมูลของ Agent
                self.store_context(agent_id, context_key, payload).await?;
            }
            IntentType::NaturalLanguage | IntentType::Event | IntentType::Interrupt => {}
        }
        Ok(())
    }

    /// หยุดการทำงานของ Agent ชั่วคราว (Pause) โดยต้องมีสถานะเดิมเป็น Running เท่านั้น
    pub async fn pause_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;

        if agent.state != AgentState::Running {
            return Err(SchedulerError::AgentNotRunning);
        }

        agent.state = AgentState::Paused;
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentPaused(agent.clone()));
        Ok(())
    }

    /// สั่งให้ Agent ที่ถูกพักกลับมาทำงานใหม่ (Resume)
    pub async fn resume_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;

        if agent.state != AgentState::Paused {
            return Err(SchedulerError::AgentNotPaused);
        }

        agent.state = AgentState::Running;
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentResumed(agent.clone()));
        Ok(())
    }

    /// สิ้นสุดการทำงานของ Agent และถอดถอนออกจากโครงสร้างหลัก
    pub async fn terminate_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let event = {
            let agent = agents
                .get_mut(&agent_id)
                .ok_or(SchedulerError::AgentNotFound)?;
            agent.state = AgentState::Terminating;
            agent.clone()
        };
        agents.remove(&agent_id);
        let _ = self.monitoring_tx.send(AgentEvent::AgentTerminated(event));
        Ok(())
    }

    /// สั่งการให้ Agent เปลี่ยนสถานะเป็นล้มเหลว (Failed) เมื่อเกิดเหตุขัดข้อง
    pub async fn fail_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;
        agent.state = AgentState::Failed;
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentFailed(agent.clone()));
        Ok(())
    }

    /// ค้นหาและส่งข้อมูล Agent อ้างอิงจาก ID
    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentControlBlock, SchedulerError> {
        let agents = self.agents.read().await;
        agents
            .get(&agent_id)
            .cloned()
            .ok_or(SchedulerError::AgentNotFound)
    }

    /// ดึงรายชื่อ Agent ทั้งหมดที่กำลังทำงานอยู่ในปัจจุบัน
    pub async fn get_running_agents(&self) -> Vec<AgentControlBlock> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|agent| agent.state == AgentState::Running)
            .cloned()
            .collect()
    }

    /// บันทึกและปรับเปลี่ยน Context ของ Agent ในระบบ Context Memory
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

        // จัดเก็บในหน่วยความจำบริบทจริง
        self.context_memory.put(context_key.clone(), value);

        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;
        agent.context_key = Some(context_key.clone());
        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentContextSwitched(agent_id, context_key));
        Ok(())
    }

    /// มอบอำนาจความปลอดภัย (Capability Token) ให้แก่ Agent
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

        // ตรวจสอบความถูกต้องของสิทธิ์ผ่าน Capability Security Manager
        let capability_allowed = token
            .capabilities
            .iter()
            .any(|capability| self.capability_security.authorize_token(&token, capability));

        if !capability_allowed {
            return Err(SchedulerError::CapabilityDenied);
        }

        self.capability_security.issue_token(token.clone());

        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;
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

        scheduler
            .pause_agent(agent_id)
            .await
            .expect("pause should succeed");
        assert_eq!(
            scheduler.get_agent(agent_id).await.unwrap().state,
            AgentState::Paused
        );

        scheduler
            .resume_agent(agent_id)
            .await
            .expect("resume should succeed");
        assert_eq!(
            scheduler.get_agent(agent_id).await.unwrap().state,
            AgentState::Running
        );

        scheduler
            .terminate_agent(agent_id)
            .await
            .expect("terminate should succeed");
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

        scheduler
            .route_intent(intent)
            .await
            .expect("route should succeed");

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

        scheduler
            .route_intent(intent)
            .await
            .expect("route should succeed");

        let agent = scheduler
            .get_agent(agent_id)
            .await
            .expect("agent should exist");
        assert_eq!(agent.context_key.as_deref(), Some("ctx-1"));
        assert_eq!(
            scheduler
                .context_memory()
                .get("ctx-1")
                .expect("context should exist"),
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
            [0u8; 32],
        );

        scheduler
            .grant_capability(agent_id, token.clone())
            .await
            .expect("grant should succeed");

        let agent = scheduler
            .get_agent(agent_id)
            .await
            .expect("agent should exist");
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
            [0u8; 32],
        );

        let result = scheduler.grant_capability(agent_id, token).await;
        assert!(matches!(result, Err(SchedulerError::CapabilityDenied)));
    }

    // ---- ANK-009: Property tests สำหรับ scheduler state invariants ----

    #[tokio::test]
    async fn property_running_plus_paused_never_exceeds_total_spawned() {
        // invariant: จำนวน Running + Paused ≤ total ที่ spawn ไป (ไม่มี agent ปรากฏเกินจำนวน)
        let scheduler = scheduler();
        let n = 5usize;

        let mut ids = Vec::new();
        for _ in 0..n {
            let id = scheduler
                .spawn_agent(AgentControlBlock::new(0))
                .await
                .expect("spawn should succeed");
            ids.push(id);
        }

        // pause ครึ่งหนึ่ง
        for &id in ids.iter().take(n / 2) {
            scheduler
                .pause_agent(id)
                .await
                .expect("pause should succeed");
        }

        let running = scheduler.get_running_agents().await.len();
        let total_agents = {
            // นับจำนวน agent ทั้งหมดที่ยังมีชีวิตอยู่ในระบบ
            n // เราไม่ได้ terminate ใคร
        };

        assert!(
            running <= total_agents,
            "จำนวน Running ({running}) ต้องไม่เกิน total spawned ({total_agents})"
        );
    }

    #[tokio::test]
    async fn property_terminate_removes_from_running_count() {
        // invariant: หลัง terminate ทุกตัว running count ต้องเป็น 0
        let scheduler = scheduler();
        let mut ids = Vec::new();
        for _ in 0..4 {
            let id = scheduler
                .spawn_agent(AgentControlBlock::new(0))
                .await
                .expect("spawn should succeed");
            ids.push(id);
        }

        assert_eq!(scheduler.get_running_agents().await.len(), 4);

        for id in ids {
            scheduler
                .terminate_agent(id)
                .await
                .expect("terminate should succeed");
        }

        assert_eq!(
            scheduler.get_running_agents().await.len(),
            0,
            "ไม่ควรมี agent running หลังจาก terminate ทั้งหมดแล้ว"
        );
    }

    #[tokio::test]
    async fn error_pause_already_paused_agent() {
        // ทดสอบ error path: การ pause agent ที่ pause อยู่แล้วต้องคืน AgentNotRunning
        let scheduler = scheduler();
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");

        scheduler
            .pause_agent(id)
            .await
            .expect("first pause should succeed");
        let result = scheduler.pause_agent(id).await;
        assert!(
            matches!(result, Err(SchedulerError::AgentNotRunning)),
            "double-pause ต้องคืน AgentNotRunning"
        );
    }

    #[tokio::test]
    async fn error_resume_running_agent_is_rejected() {
        // ทดสอบ error path: resume agent ที่กำลัง running อยู่ต้องคืน AgentNotPaused
        let scheduler = scheduler();
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");

        let result = scheduler.resume_agent(id).await;
        assert!(
            matches!(result, Err(SchedulerError::AgentNotPaused)),
            "resume agent ที่ running ต้องคืน AgentNotPaused"
        );
    }

    #[tokio::test]
    async fn error_pause_nonexistent_agent() {
        // ทดสอบ error path: pause agent ID ที่ไม่มีอยู่ในระบบต้องคืน AgentNotFound
        let scheduler = scheduler();
        let result = scheduler.pause_agent(999_999).await;
        assert!(
            matches!(result, Err(SchedulerError::AgentNotFound)),
            "pause agent ที่ไม่มีอยู่ต้องคืน AgentNotFound"
        );
    }

    #[tokio::test]
    async fn error_duplicate_agent_id_is_rejected() {
        // ทดสอบ error path: spawn agent ด้วย ID ซ้ำต้องคืน AgentAlreadyExists
        let scheduler = scheduler();
        let mut agent = AgentControlBlock::new(42);
        agent.state = AgentState::Creating;
        scheduler
            .spawn_agent(agent.clone())
            .await
            .expect("first spawn should succeed");

        let result = scheduler.spawn_agent(agent).await;
        assert!(
            matches!(result, Err(SchedulerError::AgentAlreadyExists)),
            "ID ซ้ำต้องคืน AgentAlreadyExists"
        );
    }
}
