#![deny(unsafe_code)]

//! โมดูลหลักสำหรับ Kernel Companion
//! ทำหน้าที่เป็นตัวกลางในการเชื่อมต่อระหว่างระบบปฏิบัติการ Linux (ผ่าน LSM/eBPF) และระบบจัดการ AI Agents

use agent_scheduler::AgentScheduler;
use capability_security::CapabilitySecurityManager;
use compute_scheduler::ComputeProfile;
use compute_scheduler::ComputeScheduler;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentType};
use std::sync::Arc;
use tracing::{info, instrument, warn};

pub mod ebpf;
pub mod lsm;

pub use ebpf::{PolicyDecision, SyscallEvent, SyscallTracer, tokio_util_cancel};
pub use lsm::{LsmAttachment, LsmDecision, LsmPolicyEngine, attach_lsm_hooks};

/// โครงสร้างหลักของ KernelCompanion ที่ทำหน้าที่ประสานงานระหว่างส่วนประกอบต่าง ๆ ของระบบ
pub struct KernelCompanion {
    /// ระบบตรวจสอบและตัดสินใจเชิงนโยบายความปลอดภัย LSM (LSM Policy Engine)
    lsm_engine: Arc<LsmPolicyEngine>,
    /// บัสส่งผ่านเจตจำนง (Intent Bus) สำหรับรับส่งเหตุการณ์และคำสั่ง
    intent_bus: Arc<IntentBus>,
    /// ระบบจัดการหน่วยความจำบริบท (Context Memory Manager) สำหรับย้ายหน้าหน่วยความจำ
    context_memory: Arc<ContextMemoryManager>,
    /// ระบบจัดการความปลอดภัยตามสิทธิ์การใช้งาน (Capability & Security Manager)
    capability_security: Arc<CapabilitySecurityManager>,
    /// ตัวจัดการคิวประมวลผล (Compute Scheduler) สำหรับคำนวณและปรับเปลี่ยนน้ำหนักการทำงาน
    compute_scheduler: Arc<ComputeScheduler>,
    /// ตัวจัดตารางการทำงานของ Agent (Agent Scheduler) ควบคุมวงจรชีวิตของ Agent
    agent_scheduler: Arc<AgentScheduler>,
    /// สถานะการเชื่อมต่อกับ LSM Hook ในระบบ Linux Kernel
    attachment: Option<LsmAttachment>,
}

impl KernelCompanion {
    /// สร้างอินสแตนซ์ของ KernelCompanion ใหม่ พร้อมเริ่มต้นการเชื่อมต่อส่วนประกอบต่าง ๆ
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

    /// ดึงการอ้างอิงไปยัง Intent Bus
    #[must_use]
    pub fn intent_bus(&self) -> Arc<IntentBus> {
        Arc::clone(&self.intent_bus)
    }

    /// ดึงการอ้างอิงไปยัง Agent Scheduler
    #[must_use]
    pub fn agent_scheduler(&self) -> Arc<AgentScheduler> {
        Arc::clone(&self.agent_scheduler)
    }

    /// ดึงการอ้างอิงไปยัง Compute Scheduler
    #[must_use]
    pub fn compute_scheduler(&self) -> Arc<ComputeScheduler> {
        Arc::clone(&self.compute_scheduler)
    }

    /// เริ่มต้นการทำงาน (Boot) ของระบบ รวมถึงการแนบ LSM Hook และการสร้าง Task สำหรับรับส่งข่าวสารในระบบ
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากไม่สามารถติดตั้ง LSM Hooks สำเร็จ
    #[instrument(skip(self))]
    pub async fn boot(&mut self) -> anyhow::Result<()> {
        info!("KernelCompanion กำลัง boot");

        // แนบ LSM Hook เข้ากับระบบ Kernel หากยังไม่ได้ดำเนินการ
        if self.attachment.is_none() {
            self.attachment = Some(attach_lsm_hooks(Arc::clone(&self.lsm_engine))?);
            info!("LSM Hooks แนบสำเร็จ");
        }

        // เริ่มต้นใช้งานโมดูลอื่น ๆ
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

        // รัน Task สำหรับดักฟัง Intent Bus และส่งต่อไปยัง Agent Scheduler แบบ異步 (Async)
        let _routing_task = tokio::spawn(async move {
            while let Some(intent) = intent_subscriber.receive().await {
                let _ = scheduler.route_intent(intent).await;
            }
        });

        // รัน Task สำหรับเฝ้าดูแลระบบ (Supervisor Loop) เพื่อคอยตรวจสอบและรีสตาร์ต Agent ในกรณีที่พัง
        let _supervisor_task = tokio::spawn(async move {
            supervisor.start_monitoring_loop().await;
        });

        // ส่งสัญญาณ (Publish) เหตุการณ์การ Boot สำเร็จไปยัง Intent Bus
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

        info!("KernelCompanion boot เสร็จสมบูรณ์");
        Ok(())
    }

    /// รัน Kernel Companion Daemon โดยจะรอรับสัญญาณหยุดทำงาน (Ctrl+C)
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากขั้นตอน Boot ล้มเหลว หรือสัญญาณ Ctrl+C มีปัญหา
    pub async fn run(mut self) -> anyhow::Result<()> {
        self.boot().await?;

        // รอคอยสัญญาณ Ctrl+C จากระบบปฏิบัติการ
        tokio::signal::ctrl_c().await?;

        // เคลียร์ระบบและยกเลิกการแนบ Hook
        self.shutdown().await;
        Ok(())
    }

    /// หยุดการทำงานของ Daemon และถอนการติดตั้ง LSM Hooks ออกจาก Linux Kernel
    #[instrument(skip(self))]
    pub async fn shutdown(&mut self) {
        warn!("KernelCompanion กำลัง shutdown — ถอน LSM hooks");
        if let Some(attachment) = self.attachment.as_mut() {
            attachment.detach();
        }
        self.attachment = None;
        info!("KernelCompanion shutdown เสร็จสมบูรณ์");
    }

    /// จำแนกประเภทความสำคัญของคิวงานประมวลผล (Scheduler Queue Class) จากประเภทของ Intent
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

    /// ดึงการอ้างอิงไปยัง Context Memory Manager
    #[must_use]
    pub fn context_memory(&self) -> Arc<ContextMemoryManager> {
        Arc::clone(&self.context_memory)
    }

    /// ดึงการอ้างอิงไปยัง Capability Security Manager
    #[must_use]
    pub fn capability_security(&self) -> Arc<CapabilitySecurityManager> {
        Arc::clone(&self.capability_security)
    }

    /// ตรวจสอบว่า LSM Hooks ถูกแนบเข้ากับระบบแล้วหรือไม่
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

        assert_eq!(
            companion.classify_intent(&IntentType::NaturalLanguage),
            "interactive"
        );
        assert_eq!(companion.classify_intent(&IntentType::Structured), "batch");
        assert_eq!(
            companion.classify_intent(&IntentType::Interrupt),
            "realtime"
        );
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
