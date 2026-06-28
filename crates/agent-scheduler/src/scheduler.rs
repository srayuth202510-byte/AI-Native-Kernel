use crate::block::{AgentControlBlock, AgentState};
use crate::error::SchedulerError;
use crate::priority::{Priority, PriorityAgent, PriorityQueue};
use crate::supervisor::SupervisorService;
use capability_security::{CapabilitySecurityManager, CapabilityToken};
use compute_scheduler::ComputeTarget;
use compute_scheduler::placement::WorkloadClass;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentType};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::task;
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument};

/// ตัวจัดตารางเวลาและการประมวลผลของ Agent (Agent Scheduler)
/// ทำหน้าที่บริหารจัดการสถานะ วงจรชีวิต และการสื่อสารประสานงานของ Agent ทั้งหมดในระบบ
#[derive(Clone)]
pub struct AgentScheduler {
    /// รายการของ Agent ทั้งหมดในระบบ ที่อยู่ภายใต้การสลับล็อกแบบ Read/Write (RwLock) เพื่อความปลอดภัยในการเข้าถึง
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    /// ตัวสร้างไอดี Agent ถัดไป (Auto-increment) ป้องกันด้วย RwLock
    next_agent_id: Arc<RwLock<u64>>,
    /// บัสเจตจำนง (Intent Bus) สำหรับรับส่งคำสั่งและเหตุการณ์ในระบบปฏิบัติการ
    intent_bus: Arc<IntentBus>,
    /// ผู้จัดการหน่วยความจำบริบท (Context Memory Manager) สำหรับสลับหน้าข้อมูล
    context_memory: Arc<ContextMemoryManager>,
    /// ระบบตรวจสอบสิทธิ์และความปลอดภัย (Capability Security Manager)
    capability_security: Arc<CapabilitySecurityManager>,
    /// บริการเฝ้าระวังความล้มเหลว (Supervisor Service) คอยกู้ชีพ Agent
    supervisor_service: Arc<SupervisorService>,
    /// ช่องสัญญาณกระจายข่าวสารประวัติการทำงานของ Agent (Agent Events monitoring)
    monitoring_tx: broadcast::Sender<AgentEvent>,
    /// คิวลำดับความสำคัญสำหรับการจัดตารางการทำงานของ Agent
    run_queue: Arc<RwLock<PriorityQueue>>,
    /// Task handle สำหรับ scheduling loop
    scheduler_task: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Cancellation token สำหรับ scheduler loop
    scheduler_cancel: Arc<tokio::sync::watch::Sender<bool>>,
    /// Time slice configuration per priority level (in microseconds)
    time_slices: [Duration; 4],
}

/// เหตุการณ์การเปลี่ยนแปลงสถานะหรือคุณลักษณะของ Agent ในระบบ
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// มีการสร้างข้อมูล Agent Control Block ชุดใหม่ขึ้นในระบบ
    AgentCreated(AgentControlBlock),
    /// Agent ได้ถูกสตาร์ทและเริ่มทำงาน (Spawned) แล้วจริง
    AgentSpawned(AgentControlBlock),
    /// Agent ถูกสั่งพักการทำงานชั่วคราว (Paused)
    AgentPaused(AgentControlBlock),
    /// Agent ได้รับคำสั่งให้กลับมาประมวลผลต่อ (Resumed)
    AgentResumed(AgentControlBlock),
    /// Agent ถูกสั่งปิดการทำงานและถอนการลงทะเบียน (Terminated)
    AgentTerminated(AgentControlBlock),
    /// Agent เกิดเหตุขัดข้องหรือข้อผิดพลาดภายใน (Failed)
    AgentFailed(AgentControlBlock),
    /// Agent ถูกชุบชีวิตและเริ่มทำงานใหม่โดยระบบ Supervisor (Restarted)
    AgentRestarted(AgentControlBlock),
    /// ลำดับความสำคัญการประมวลผลของ Agent ได้รับการปรับเปลี่ยน
    AgentPriorityChanged(u64, Priority),
    /// ข้อมูลบริบทของ Agent ได้ถูกสลับหน้าหรือโยกย้าย (Context Switched)
    AgentContextSwitched(u64, String),
    /// Agent ได้รับอนุมัติสิทธิ์การเข้าถึงข้อมูลระบบ (Capability Granted)
    AgentCapabilityGranted(u64, CapabilityToken),
    /// Agent ถูกเพิกถอนสิทธิ์ความปลอดภัยในระบบ (Capability Revoked)
    AgentCapabilityRevoked(u64, u64),
}

impl AgentScheduler {
    /// สร้างตัวจัดตารางการทำงานของ Agent ตัวใหม่ พร้อมกำหนดบัสสื่อสาร คลังหน่วยความจำ และระบบรักษาความปลอดภัย
    /// ใช้ค่าเริ่มต้น: max_restarts=3, backoff=100ms, monitoring_capacity=1024
    #[must_use]
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
    ) -> Self {
        Self::with_params(
            intent_bus,
            context_memory,
            capability_security,
            3,
            100,
            1024,
        )
    }

    /// สร้าง AgentScheduler พร้อมกำหนดค่าพารามิเตอร์ต่าง ๆ ตามที่ต้องการ
    #[must_use]
    pub fn with_params(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        capability_security: Arc<CapabilitySecurityManager>,
        max_restarts: u32,
        restart_backoff_ms: u64,
        monitoring_capacity: usize,
    ) -> Self {
        let agents = Arc::new(RwLock::new(HashMap::new()));
        let supervisor_service = Arc::new(SupervisorService::new(
            agents.clone(),
            max_restarts,
            restart_backoff_ms,
        ));
        let (monitoring_tx, _) = broadcast::channel(monitoring_capacity);
        let run_queue = Arc::new(RwLock::new(PriorityQueue::new()));
        let (scheduler_cancel_tx, _) = tokio::sync::watch::channel(false);

        // Time slices per priority: Eco=10ms, Batch=5ms, Interactive=1ms, RealTime=500µs
        let time_slices = [
            Duration::from_millis(10),  // Eco
            Duration::from_millis(5),   // Batch
            Duration::from_millis(1),   // Interactive
            Duration::from_micros(500), // RealTime
        ];

        Self {
            agents,
            next_agent_id: Arc::new(RwLock::new(1)),
            intent_bus,
            context_memory,
            capability_security,
            supervisor_service,
            monitoring_tx,
            run_queue,
            scheduler_task: Arc::new(RwLock::new(None)),
            scheduler_cancel: Arc::new(scheduler_cancel_tx),
            time_slices,
        }
    }

    /// อ้างอิงไปยังบริการผู้ดูแลระบบและรีสตาร์ต Agent (Supervisor Service)
    #[must_use]
    pub fn supervisor(&self) -> Arc<SupervisorService> {
        Arc::clone(&self.supervisor_service)
    }

    /// ลงทะเบียนและติดตามประวัติเหตุการณ์ต่าง ๆ ของ Agent ผ่านช่องรับสัญญาณมอนิเตอร์
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.monitoring_tx.subscribe()
    }

    /// อ้างอิงไปยัง Intent Bus
    pub fn intent_bus(&self) -> Arc<IntentBus> {
        Arc::clone(&self.intent_bus)
    }

    /// อ้างอิงไปยัง Context Memory Manager
    #[must_use]
    pub fn context_memory(&self) -> Arc<ContextMemoryManager> {
        Arc::clone(&self.context_memory)
    }

    /// จองและจัดสรร ID ใหม่ให้แก่ Agent (Thread-safe)
    pub async fn allocate_agent_id(&self) -> u64 {
        let mut next_agent_id = self.next_agent_id.write().await;
        let agent_id = *next_agent_id;
        *next_agent_id = agent_id.saturating_add(1);
        agent_id
    }

    /// สั่งลงทะเบียนและเริ่มต้นรัน Agent ใหม่
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาด `SchedulerError::AgentAlreadyExists` หาก ID ของ Agent ซ้ำในระบบ
    pub async fn spawn_agent(&self, mut agent: AgentControlBlock) -> Result<u64, SchedulerError> {
        if agent.id == 0 {
            agent.id = self.allocate_agent_id().await;
        }

        let mut agents = self.agents.write().await;
        if agents.contains_key(&agent.id) {
            return Err(SchedulerError::AgentAlreadyExists);
        }

        if agent.compute_target.is_some() && agent.state == AgentState::Creating {
            agent.state = AgentState::Running;
        }

        let agent_id = agent.id;
        agents.insert(agent_id, agent.clone());

        if agent.state == AgentState::Running {
            let _ = self.monitoring_tx.send(AgentEvent::AgentSpawned(agent));
        } else {
            let _ = self.monitoring_tx.send(AgentEvent::AgentCreated(agent));
        }
        Ok(agent_id)
    }

    /// ส่งและกระจายข่าวสารเจตจำนง (Intent) ลงสู่ Intent Bus เพื่อให้โมดูลที่รับผิดชอบทำงานต่อ
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาด `SchedulerError::IntentDispatchFailed` หากบัสไม่สามารถเผยแพร่ Intent ได้
    pub async fn submit_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        self.intent_bus
            .publish(intent)
            .await
            .map_err(|_| SchedulerError::IntentDispatchFailed)
    }

    /// หาเส้นทางและจัดการคำสั่งที่ส่งผ่านมาจาก Intent Bus
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากกระบวนการจัดเก็บ context หรือ spawn agent ล้มเหลว
    pub async fn route_intent(&self, intent: Intent) -> Result<(), SchedulerError> {
        match intent.intent_type {
            IntentType::Command => {
                if intent.payload == "spawn-agent" {
                    let workload_str = intent
                        .metadata
                        .get("workload")
                        .map(|s| s.as_str())
                        .unwrap_or("small");
                    let wl = match workload_str {
                        "kernel" => WorkloadClass::KernelLogic,
                        "small" => WorkloadClass::SmallLlm,
                        "large" => WorkloadClass::LargeLlm,
                        "vector" => WorkloadClass::VectorIndexing,
                        _ => WorkloadClass::SmallLlm,
                    };

                    let agent_id = self.allocate_agent_id().await;
                    let agent = AgentControlBlock::new_unplaced(agent_id, wl);

                    self.spawn_agent(agent).await?;

                    let req_payload = serde_json::json!({
                        "action": "PlacementRequest",
                        "agent_id": agent_id,
                        "workload_class": format!("{:?}", wl),
                    })
                    .to_string();

                    let req_intent = Intent::new(
                        uuid::Uuid::new_v4().to_string(),
                        IntentType::Event,
                        req_payload,
                        intent_bus::IntentPriority::High,
                        "agent-scheduler",
                    );
                    let _ = self.intent_bus.publish(req_intent).await;
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
            IntentType::Event => {
                if intent.source == "compute-scheduler" {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                        if data.get("action").and_then(|v| v.as_str()) == Some("PlacementResponse")
                        {
                            let agent_id =
                                data.get("agent_id").and_then(|v| v.as_u64()).unwrap_or(0);
                            let target_str = data
                                .get("compute_target")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Cpu");
                            let target = match target_str {
                                "Cpu" => ComputeTarget::Cpu,
                                "Gpu" => ComputeTarget::Gpu,
                                "Npu" => ComputeTarget::Npu,
                                "Cloud" => ComputeTarget::Cloud,
                                _ => ComputeTarget::Cpu,
                            };

                            let mut agents = self.agents.write().await;
                            if let Some(agent) = agents.get_mut(&agent_id) {
                                agent.compute_target = Some(target);
                                if agent.state == AgentState::Creating {
                                    agent.state = AgentState::Running;
                                    let priority_agent =
                                        PriorityAgent::new(agent_id, agent.priority);
                                    let mut queue = self.run_queue.write().await;
                                    queue.push(priority_agent);
                                    let _ = self
                                        .monitoring_tx
                                        .send(AgentEvent::AgentSpawned(agent.clone()));
                                }
                            }
                        }
                    }
                }
            }
            IntentType::NaturalLanguage | IntentType::Interrupt => {}
        }
        Ok(())
    }

    /// สั่งพักการประมวลผลของ Agent ที่ระบุไว้ชั่วคราว
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent หรือ Agent ไม่ได้อยู่ในสถานะ Running
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

    /// สั่งให้ Agent ที่ระบุกลับมาทำงานต่อ
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent หรือ Agent ไม่ได้ถูกสั่งหยุดทำงานชั่วคราว
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

    /// สั่งปิดการทำงานและถอนรากถอนโคน Agent ออกจากระบบอย่างถาวร
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent ตัวที่ระบุในสารระบบ
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

    /// เปลี่ยนสถานะของ Agent ให้กลายเป็นล้มเหลว (Failed) เพื่อส่งต่อการกู้ชีพให้แก่ระบบ Supervisor
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent ที่ระบุ
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

    /// ค้นหาและดึงสำเนาข้อมูล AgentControlBlock ด้วย ID
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่มี Agent รหัสนี้อยู่ในระบบ
    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentControlBlock, SchedulerError> {
        let agents = self.agents.read().await;
        agents
            .get(&agent_id)
            .cloned()
            .ok_or(SchedulerError::AgentNotFound)
    }

    /// ดึงประวัติข้อมูลควบคุมของ Agent ทั้งหมดที่กำลังทำงานอยู่ในปัจจุบัน
    pub async fn get_running_agents(&self) -> Vec<AgentControlBlock> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|agent| agent.state == AgentState::Running)
            .cloned()
            .collect()
    }

    /// บันทึกและสลับย้ายข้อมูลบริบท (Context) ของ Agent
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent
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

        self.context_memory
            .put_distributed(context_key.clone(), value)
            .await
            .map_err(|_| SchedulerError::ContextUpdateFailed)?;

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

    /// ดำเนินการออกและจัดสรรสิทธิ์ความสามารถ (Capability Token) ให้แก่ Agent
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากการขอสิทธิ์ความปลอดภัยล้มเหลว หรือสิทธิ์ถูกปฏิเสธ
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

        if token.capabilities.is_empty() {
            return Err(SchedulerError::CapabilityDenied);
        }

        let capability_security = Arc::clone(&self.capability_security);
        let token_to_issue = token.clone();
        let grant_result = task::spawn_blocking(move || {
            for capability in &token_to_issue.capabilities {
                let allowed = capability_security
                    .authorize_token(&token_to_issue, capability)
                    .map_err(|_| SchedulerError::CapabilitySecurityFailed)?;
                if !allowed {
                    return Err(SchedulerError::CapabilityDenied);
                }
            }

            capability_security
                .issue_token(token_to_issue)
                .map_err(|_| SchedulerError::CapabilitySecurityFailed)
        })
        .await
        .map_err(|_| SchedulerError::CapabilitySecurityFailed)?;
        grant_result?;

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

    /// เพิ่ม Agent เข้าสู่คิวการทำงาน (Run Queue) ตามลำดับความสำคัญ
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent หรือ Agent ไม่อยู่ในสถานะ Running
    pub async fn enqueue_agent(&self, agent_id: u64) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;

        if agent.state != AgentState::Running {
            return Err(SchedulerError::AgentNotRunning);
        }

        let priority_agent = PriorityAgent::new(agent_id, agent.priority);
        let mut queue = self.run_queue.write().await;
        queue.push(priority_agent);
        Ok(())
    }

    /// นำ Agent ออกจากคิวการทำงาน
    pub async fn dequeue_agent(&self, agent_id: u64) -> bool {
        let mut queue = self.run_queue.write().await;
        // PriorityQueue ไม่มี remove by ID ตรงๆ ต้องสร้างใหม่
        let mut temp = Vec::new();
        let mut found = false;
        while let Some(pa) = queue.pop() {
            if pa.id == agent_id {
                found = true;
            } else {
                temp.push(pa);
            }
        }
        for pa in temp {
            queue.push(pa);
        }
        found
    }

    /// เริ่มต้น Scheduling Loop ที่ทำงานแบบ Time-sliced ตาม Priority
    ///
    /// Scheduling Loop จะ:
    /// 1. ดึง Agent ที่มี Priority สูงสุดจาก Run Queue
    /// 2. รัน Agent เป็นเวลา Time Slice ตาม Priority ของมัน
    /// 3. ถ้า Agent ยัง Running อยู่ ให้ Enqueue กลับเข้า Queue
    /// 4. ทำซ้ำจนกว่าจะได้รับสัญญาณ Cancel
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหาก Scheduler Task กำลังทำงานอยู่แล้ว
    #[instrument(skip(self))]
    pub async fn start_scheduler_loop(&self) -> Result<(), SchedulerError> {
        let mut task_guard = self.scheduler_task.write().await;
        if task_guard.is_some() {
            return Err(SchedulerError::SchedulerAlreadyRunning);
        }

        let agents = Arc::clone(&self.agents);
        let run_queue = Arc::clone(&self.run_queue);
        let context_memory = Arc::clone(&self.context_memory);
        let monitoring_tx = self.monitoring_tx.clone();
        let time_slices = self.time_slices;
        let mut shutdown_rx = self.scheduler_cancel.subscribe();

        let task = tokio::spawn(async move {
            info!("Agent Scheduler Loop started");
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Scheduler loop received shutdown signal");
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_micros(100)) => {
                        // ดึง Agent ถัดไปจากคิว
                        let next_agent = {
                            let mut queue = run_queue.write().await;
                            queue.pop()
                        };

                        if let Some(priority_agent) = next_agent {
                            let agent_id = priority_agent.id;
                            let priority = priority_agent.priority;
                            let time_slice = time_slices[priority as usize];

                            // ตรวจสอบว่า Agent ยังอยู่และ Running
                            let agent_opt = {
                                let agents_read = agents.read().await;
                                agents_read.get(&agent_id).cloned()
                            };

                            if let Some(agent) = agent_opt {
                                if agent.state == AgentState::Running {
                                    // Execute agent time slice
                                    Self::execute_agent_slice(
                                        agent_id,
                                        priority,
                                        time_slice,
                                        Arc::clone(&context_memory),
                                        &monitoring_tx,
                                    ).await;

                                    // Enqueue กลับเข้า Queue ถ้ายัง Running
                                    let still_running = {
                                        let agents_read = agents.read().await;
                                        agents_read.get(&agent_id)
                                            .map(|a| a.state == AgentState::Running)
                                            .unwrap_or(false)
                                    };
                                    if still_running {
                                        let mut queue = run_queue.write().await;
                                        queue.push(priority_agent);
                                    } else {
                                        debug!(agent_id, "Agent no longer running, not re-queued");
                                    }
                                } else {
                                    debug!(agent_id, ?agent.state, "Agent not running, skipped");
                                }
                            } else {
                                debug!(agent_id, "Agent not found, skipped");
                            }
                        }
                    }
                }
            }
            info!("Agent Scheduler Loop stopped");
        });

        *task_guard = Some(task);
        Ok(())
    }

    /// หยุด Scheduling Loop
    pub async fn stop_scheduler_loop(&self) {
        let _ = self.scheduler_cancel.send(true);
        let mut task_guard = self.scheduler_task.write().await;
        if let Some(task) = task_guard.take() {
            let _ = task.await;
        }
    }

    /// Execute a single time slice for an agent
    async fn execute_agent_slice(
        agent_id: u64,
        priority: Priority,
        time_slice: Duration,
        context_memory: Arc<ContextMemoryManager>,
        monitoring_tx: &broadcast::Sender<AgentEvent>,
    ) {
        debug!(
            agent_id,
            ?priority,
            ?time_slice,
            "Executing agent time slice"
        );

        // Simulate agent work - in real implementation this would run the agent's task
        // For now, we just sleep for the time slice duration
        tokio::time::sleep(time_slice).await;

        // Promote context to hot tier if agent has context
        let context_key = format!("agent-{}", agent_id);
        let context_memory_for_blocking = Arc::clone(&context_memory);
        let agents_read = task::spawn_blocking({
            let context_key = context_key.clone();
            move || context_memory_for_blocking.tier_of(&context_key)
        })
        .await
        .ok()
        .flatten();
        if let Some(tier) = agents_read {
            if tier != "hot" {
                let context_memory_for_blocking = Arc::clone(&context_memory);
                let promoted = task::spawn_blocking({
                    let context_key = context_key.clone();
                    move || context_memory_for_blocking.promote(&context_key)
                })
                .await
                .ok()
                .and_then(|result| result.ok())
                .is_some();
                if promoted {
                    let _ =
                        monitoring_tx.send(AgentEvent::AgentContextSwitched(agent_id, context_key));
                }
            }
        }
    }

    /// เปลี่ยน Priority ของ Agent และอัปเดตคิวการทำงาน
    ///
    /// # Errors
    /// ส่งคืนข้อผิดพลาดหากไม่พบ Agent
    pub async fn set_agent_priority(
        &self,
        agent_id: u64,
        priority: Priority,
    ) -> Result<(), SchedulerError> {
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotFound)?;

        let old_priority = agent.priority;
        agent.priority = priority;

        // ถ้า Agent อยู่ใน Run Queue ให้ Dequeue แล้ว Enqueue ใหม่ด้วย Priority ใหม่
        let was_queued = self.dequeue_agent(agent_id).await;
        if was_queued {
            let priority_agent = PriorityAgent::new(agent_id, priority);
            let mut queue = self.run_queue.write().await;
            queue.push(priority_agent);
        }

        let _ = self
            .monitoring_tx
            .send(AgentEvent::AgentPriorityChanged(agent_id, priority));

        debug!(agent_id, old = ?old_priority, new = ?priority, "Agent priority changed");
        Ok(())
    }

    /// ดึงขนาดคิวการทำงานปัจจุบัน
    pub async fn run_queue_len(&self) -> usize {
        let queue = self.run_queue.read().await;
        queue.len()
    }

    /// ตรวจสอบว่า Scheduler Loop กำลังทำงานอยู่หรือไม่
    pub async fn is_scheduler_running(&self) -> bool {
        let task_guard = self.scheduler_task.read().await;
        task_guard.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{AgentControlBlock, AgentState};
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
        let mut subscriber = scheduler.intent_bus().subscribe();

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

        // Wait for PlacementRequest
        let request = timeout(Duration::from_millis(100), subscriber.receive())
            .await
            .expect("should receive PlacementRequest")
            .unwrap();

        assert_eq!(request.intent_type, IntentType::Event);
        let data: serde_json::Value = serde_json::from_str(&request.payload).unwrap();
        assert_eq!(data["action"], "PlacementRequest");
        let agent_id = data["agent_id"].as_u64().unwrap();

        // Simulate PlacementResponse
        let resp_payload = serde_json::json!({
            "action": "PlacementResponse",
            "agent_id": agent_id,
            "compute_target": "Cpu",
        })
        .to_string();

        let resp_intent = Intent::new(
            "resp-1",
            IntentType::Event,
            resp_payload,
            IntentPriority::High,
            "compute-scheduler",
        );

        scheduler
            .route_intent(resp_intent)
            .await
            .expect("routing response should succeed");

        assert_eq!(scheduler.get_running_agents().await.len(), 1);
        let agent = scheduler.get_agent(agent_id).await.unwrap();
        assert_eq!(agent.state, AgentState::Running);
        assert_eq!(agent.compute_target, Some(ComputeTarget::Cpu));
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

    #[tokio::test]
    async fn grant_capability_rejects_mixed_allowed_and_denied_capabilities() {
        let scheduler = scheduler();
        let agent_id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");
        let token = CapabilityToken::new(
            9,
            Scope::Global,
            vec!["read".to_string(), "write".to_string()],
            Duration::from_secs(60),
            [0u8; 32],
        );

        let result = scheduler.grant_capability(agent_id, token).await;
        assert!(matches!(result, Err(SchedulerError::CapabilityDenied)));
    }

    #[tokio::test]
    async fn property_running_plus_paused_never_exceeds_total_spawned() {
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

        for &id in ids.iter().take(n / 2) {
            scheduler
                .pause_agent(id)
                .await
                .expect("pause should succeed");
        }

        let running = scheduler.get_running_agents().await.len();

        assert!(
            running <= n,
            "จำนวน Running ({running}) ต้องไม่เกิน total spawned ({n})"
        );
    }

    #[tokio::test]
    async fn property_terminate_removes_from_running_count() {
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

        assert_eq!(scheduler.get_running_agents().await.len(), 0,);
    }

    #[tokio::test]
    async fn error_pause_already_paused_agent() {
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
        assert!(matches!(result, Err(SchedulerError::AgentNotRunning)),);
    }

    #[tokio::test]
    async fn error_resume_running_agent_is_rejected() {
        let scheduler = scheduler();
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");

        let result = scheduler.resume_agent(id).await;
        assert!(matches!(result, Err(SchedulerError::AgentNotPaused)),);
    }

    #[tokio::test]
    async fn error_pause_nonexistent_agent() {
        let scheduler = scheduler();
        let result = scheduler.pause_agent(999_999).await;
        assert!(matches!(result, Err(SchedulerError::AgentNotFound)),);
    }

    #[tokio::test]
    async fn error_duplicate_agent_id_is_rejected() {
        let scheduler = scheduler();
        let mut agent = AgentControlBlock::new(42);
        agent.state = AgentState::Creating;
        scheduler
            .spawn_agent(agent.clone())
            .await
            .expect("first spawn should succeed");

        let result = scheduler.spawn_agent(agent).await;
        assert!(matches!(result, Err(SchedulerError::AgentAlreadyExists)),);
    }
}
