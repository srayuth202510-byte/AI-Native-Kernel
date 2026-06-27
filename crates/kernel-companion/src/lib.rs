#![deny(unsafe_code)]

//! โมดูลหลักสำหรับ Kernel Companion
//! ทำหน้าที่เป็นตัวกลางในการเชื่อมต่อระหว่างระบบปฏิบัติการ Linux (ผ่าน LSM/eBPF) และระบบจัดการ AI Agents

use crate::config::Config;
use agent_scheduler::AgentScheduler;
use capability_security::CapabilitySecurityManager;
use compute_scheduler::ComputeProfile;
use compute_scheduler::ComputeScheduler;
use context_memory::ContextMemoryManager;
use immune_system::{BCellAgent, MacrophageAgent, TCellAgent};
use intent_bus::{Intent, IntentBus, IntentType};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

pub mod config;
pub mod ebpf;
pub mod lsm;
pub mod uds;

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
    /// T-Cell Agent — ตรวจจับ Anomaly (reserved for syscall event feed)
    #[allow(dead_code)]
    tcell: Arc<TCellAgent>,
    /// B-Cell Agent — เรียนรู้และสร้าง Antibody Rules
    bcell: Arc<BCellAgent>,
    /// Macrophage Agent — GC สำหรับ Intent + Context
    macrophage: Arc<MacrophageAgent>,
    /// การตั้งค่าที่ใช้ขณะรัน (kept for reference)
    config: Config,
    /// สถานะการเชื่อมต่อกับ LSM Hook ในระบบ Linux Kernel
    attachment: Option<LsmAttachment>,
    /// ช่องสัญญาณใช้แจ้งให้ background tasks หยุดทำงาน
    shutdown_tx: Option<watch::Sender<bool>>,
    /// handle ของ routing task
    routing_task: Option<JoinHandle<()>>,
    /// handle ของ supervisor task
    supervisor_task: Option<JoinHandle<()>>,
    /// handle ของ immune system antibody sync task
    immune_task: Option<JoinHandle<()>>,
}

impl KernelCompanion {
    /// สร้างอินสแตนซ์ของ KernelCompanion ใหม่ พร้อมเริ่มต้นการเชื่อมต่อส่วนประกอบต่าง ๆ
    /// ใช้ค่าจาก `config/default.toml` หรือค่ามาตรฐานหากไม่มีไฟล์กำหนดค่า
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(&Config::default())
    }

    /// สร้างอินสแตนซ์ของ KernelCompanion ด้วยการตั้งค่าที่กำหนด (Config struct)
    /// ใช้ค่าจาก config/default.toml หรือ CLI/env overrides
    #[must_use]
    pub fn with_config(config: &Config) -> Self {
        let intent_bus = Arc::new(IntentBus::new(config.kernel_companion.intent_bus_capacity));
        let context_memory = Arc::new(ContextMemoryManager::with_capacity(
            config.context_memory.hot_capacity,
            config.context_memory.warm_capacity,
        ));
        let capability_security = Arc::new(CapabilitySecurityManager::new_with_log_path(
            std::path::PathBuf::from(&config.capability_security.audit_log_path),
        ));
        let agent_scheduler = Arc::new(AgentScheduler::with_params(
            Arc::clone(&intent_bus),
            Arc::clone(&context_memory),
            Arc::clone(&capability_security),
            config.agent_scheduler.max_restart_attempts,
            config.agent_scheduler.supervisor_interval_ms,
            config.kernel_companion.monitoring_channel_capacity,
        ));

        let compute_mode: compute_scheduler::weights::SchedulerMode =
            match config.compute_scheduler.default_mode.as_str() {
                "battery" => compute_scheduler::weights::SchedulerMode::Battery,
                "cost" => compute_scheduler::weights::SchedulerMode::Cost,
                _ => compute_scheduler::weights::SchedulerMode::Throughput,
            };
        let weights = compute_scheduler::weights::AdaptiveWeights::from_mode(compute_mode);

        let intent_bus_immune = Arc::clone(&intent_bus);
        let tcell = Arc::new(TCellAgent::new(100, 5));
        let bcell = Arc::new(BCellAgent::new(100));
        let macrophage = Arc::new(MacrophageAgent::new(
            intent_bus_immune,
            Arc::clone(&context_memory),
            config.immune_system.tcell_check_interval_ms,
            config.immune_system.quarantine_duration_secs,
        ));

        Self {
            config: config.clone(),
            lsm_engine: Arc::new(LsmPolicyEngine::new()),
            intent_bus,
            context_memory,
            capability_security,
            compute_scheduler: Arc::new(ComputeScheduler::with_weights(weights)),
            agent_scheduler,
            tcell,
            bcell,
            macrophage,
            attachment: None,
            shutdown_tx: None,
            routing_task: None,
            supervisor_task: None,
            immune_task: None,
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

        if self.shutdown_tx.is_none() {
            let scheduler = Arc::clone(&self.agent_scheduler);
            let mut intent_subscriber = self.intent_bus.subscribe();
            let supervisor = scheduler.supervisor();
            let (shutdown_tx, mut routing_shutdown_rx) = watch::channel(false);
            let supervisor_shutdown_rx = shutdown_tx.subscribe();

            // รัน Task สำหรับดักฟัง Intent Bus และส่งต่อไปยัง Agent Scheduler แบบ Async
            self.routing_task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        intent = intent_subscriber.receive() => {
                            match intent {
                                Some(intent) => {
                                    let _ = scheduler.route_intent(intent).await;
                                }
                                None => break,
                            }
                        }
                        changed = routing_shutdown_rx.changed() => {
                            if changed.is_err() || *routing_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));

            // รัน Task สำหรับเฝ้าดูแลระบบ (Supervisor Loop) เพื่อคอยตรวจสอบและรีสตาร์ต Agent ในกรณีที่พัง
            self.supervisor_task = Some(tokio::spawn(async move {
                supervisor
                    .start_monitoring_loop_until(supervisor_shutdown_rx)
                    .await;
            }));

            // ── Immune System Integration Tasks ──
            let lsm = Arc::clone(&self.lsm_engine);
            let bcell = Arc::clone(&self.bcell);
            let macrophage = Arc::clone(&self.macrophage);
            let immune_shutdown_rx = shutdown_tx.subscribe();
            let immune_interval = std::time::Duration::from_secs(10);

            self.immune_task = Some(tokio::spawn(async move {
                let mut shutdown_rx = immune_shutdown_rx;
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(immune_interval) => {
                            // 1. Drain B-Cell antibodies → push to LSM Policy Engine
                            let antibodies = bcell.take_new_antibodies().await;
                            for ab in &antibodies {
                                lsm.add_blocked_syscall(&ab.blocked_syscall);
                                warn!(
                                    syscall = %ab.blocked_syscall,
                                    confidence = ab.confidence,
                                    "Immune System: applied antibody rule to LSM Policy Engine"
                                );
                            }

                            // 2. Macrophage GC — sweep expired context entries
                            let swept = macrophage.sweep_context().await;
                            if swept > 0 {
                                info!("Immune System: Macrophage cleaned {} expired context entries", swept);
                            }
                        }
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                info!("Immune System task shutting down");
                                break;
                            }
                        }
                    }
                }
            }));

            let cancel = tokio_util_cancel::CancellationToken::new();
            let _ = uds::start_uds_server(
                Arc::clone(&self.intent_bus),
                &self.config.kernel_companion.uds_socket_path,
                cancel,
            )
            .await;

            self.shutdown_tx = Some(shutdown_tx);
        }

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
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        if let Some(task) = self.routing_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.supervisor_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.immune_task.take() {
            let _ = task.await;
        }
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

    #[tokio::test]
    async fn repeated_boot_does_not_duplicate_routing_tasks() {
        let mut companion = KernelCompanion::new();

        companion.boot().await.expect("first boot should succeed");
        companion.boot().await.expect("second boot should succeed");

        companion
            .intent_bus()
            .publish(Intent::new(
                "spawn-once",
                IntentType::Command,
                "spawn-agent",
                intent_bus::IntentPriority::High,
                "test",
            ))
            .await
            .expect("publish should succeed");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            companion.agent_scheduler().get_running_agents().await.len(),
            1
        );

        companion.shutdown().await;
    }
}
