#![deny(unsafe_code)]

//! โมดูลหลักสำหรับ Kernel Companion
//! ทำหน้าที่เป็นตัวกลางในการเชื่อมต่อระหว่างระบบปฏิบัติการ Linux (ผ่าน LSM/eBPF) และระบบจัดการ AI Agents

use crate::config::Config;
use crate::intent_bridge::IntentBridge;
use crate::observability::kernel_metrics;
use crate::retry_telemetry::{RetryAndTelemetryManager, RetryConfig, TelemetryTTLConfig};
use agent_scheduler::{AgentScheduler, DistributedRoutingPolicy, RemoteNodeState};
use capability_security::CapabilitySecurityManager;
use capability_security::Scope;
use capability_security::audit::{AuditEntry, AuditLogger};
use compute_scheduler::placement::{PlacementPolicy, WorkloadClass};
use compute_scheduler::{ComputeProfile, ComputeScheduler, ComputeTarget};
use context_memory::ContextMemoryManager;
use context_memory::p2p_mesh::{NodeTelemetry, P2PMeshManager};
use immune_system::{BCellAgent, MacrophageAgent, TCellAgent, ThreatDecision};
use intent_bus::{Intent, IntentBus, IntentType};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::task;
use tokio::task::JoinHandle;
use tracing::{info, instrument, warn};

/// โมดูล `config` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `config` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod config;
/// โมดูล `ebpf` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `ebpf` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod ebpf;
pub mod intent_bridge;
/// โมดูล `lsm` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `lsm` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod lsm;
/// โมดูล `metrics_server` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `metrics_server` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod metrics_server;
pub mod nlp;
/// โมดูล `observability` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `observability` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod observability;
/// โมดูล `retry_telemetry` จัดการการ retry/backoff และ TTL ของ telemetry
/// โมดูล `retry_telemetry` จัดการการ retry/backoff และ TTL ของ telemetry
pub mod retry_telemetry;
/// โมดูล `uds` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `uds` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod uds;

pub use ebpf::{PolicyDecision, SyscallEvent, SyscallTracer, tokio_util_cancel};
pub use lsm::{LsmAttachment, LsmDecision, LsmPolicyEngine, attach_lsm_hooks};

fn infer_bridge_addr(
    peer_addr: std::net::SocketAddr,
    local_bridge_addr: &str,
) -> Option<std::net::SocketAddr> {
    let bridge_addr = local_bridge_addr.parse::<std::net::SocketAddr>().ok()?;
    Some(std::net::SocketAddr::new(
        peer_addr.ip(),
        bridge_addr.port(),
    ))
}

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
    tcell: Arc<TCellAgent>,
    /// B-Cell Agent — เรียนรู้และสร้าง Antibody Rules
    bcell: Arc<BCellAgent>,
    /// Macrophage Agent — GC สำหรับ Intent + Context
    macrophage: Arc<MacrophageAgent>,
    /// การตั้งค่าที่ใช้ขณะรัน (kept for reference)
    config: Config,
    /// สถานะการเชื่อมต่อกับ LSM Hook ในระบบ Linux Kernel
    attachment: Arc<parking_lot::Mutex<Option<LsmAttachment>>>,
    /// ช่องสัญญาณใช้แจ้งให้ background tasks หยุดทำงาน
    shutdown_tx: Option<watch::Sender<bool>>,
    /// handle ของ routing task
    routing_task: Option<JoinHandle<()>>,
    /// handle ของ supervisor task
    supervisor_task: Option<JoinHandle<()>>,
    /// handle ของ immune system antibody sync task
    immune_task: Option<JoinHandle<()>>,
    /// handle ของ tracer task
    tracer_task: Option<JoinHandle<()>>,
    /// cancellation token ของ tracer task
    tracer_cancel: Option<tokio_util_cancel::CancellationToken>,
    /// handle ของ tcell event receiver task
    tcell_task: Option<JoinHandle<()>>,
    /// handle ของ prometheus metrics server task
    metrics_task: Option<JoinHandle<()>>,
    /// cancellation token ของ metrics server task
    metrics_cancel: Option<tokio_util_cancel::CancellationToken>,
    /// handle ของ compute scheduler routing task
    compute_task: Option<JoinHandle<()>>,
    /// handle ของ network intent bridge listener
    intent_bridge_listener_task: Option<JoinHandle<()>>,
    /// handle ของ network intent bridge forwarder
    intent_bridge_forwarder_task: Option<JoinHandle<()>>,
    /// cancellation token ของ network intent bridge
    intent_bridge_cancel: Option<tokio_util_cancel::CancellationToken>,
    /// shared network intent bridge state
    intent_bridge: Option<Arc<IntentBridge>>,
    /// handle ของ telemetry sync task ระหว่าง p2p mesh กับ scheduler
    telemetry_task: Option<JoinHandle<()>>,
    /// P2P Gossip Mesh manager
    p2p_mesh: Option<Arc<P2PMeshManager>>,
    /// handle ของ P2P mesh listener task
    p2p_listener_task: Option<JoinHandle<()>>,
    /// handle ของ P2P gossip sync loop task
    p2p_gossip_task: Option<JoinHandle<()>>,
    /// ตัวจัดการการตั้งค่าการรีสตาร์ตและการตรวจตรา
    retry_telemetry_manager: Arc<RetryAndTelemetryManager>,
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
        let _ = kernel_metrics();
        let intent_bus = Arc::new(IntentBus::new(config.kernel_companion.intent_bus_capacity));
        let context_memory = Arc::new(ContextMemoryManager::with_vram_path_and_capacity(
            32 * 1024 * 1024,
            config.context_memory.hot_capacity,
            config.context_memory.warm_capacity,
            Some(std::path::PathBuf::from(
                &config.context_memory.warm_store_path,
            )),
        ));
        let capability_security = Arc::new(CapabilitySecurityManager::new_with_log_path_and_rate(
            std::path::PathBuf::from(&config.capability_security.audit_log_path),
            config.capability_security.max_issue_rate,
        ));
        let agent_scheduler = Arc::new(AgentScheduler::with_params(
            Arc::clone(&intent_bus),
            Arc::clone(&context_memory),
            Arc::clone(&capability_security),
            config.agent_scheduler.max_restart_attempts,
            config.retry_telemetry.retry_initial_backoff_ms,
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
        let tcell = Arc::new(TCellAgent::with_kill_threshold(
            config.immune_system.rate_threshold as u64,
            config.immune_system.deny_threshold,
            config.immune_system.kill_threshold,
        ));
        let bcell = Arc::new(BCellAgent::new(100));
        let macrophage = Arc::new(MacrophageAgent::new(
            intent_bus_immune,
            Arc::clone(&context_memory),
            config.immune_system.tcell_check_interval_ms,
            config.immune_system.quarantine_duration_secs,
        ));
        let retry_config = RetryConfig::new(
            config.retry_telemetry.retry_max_attempts,
            config.retry_telemetry.retry_initial_backoff_ms,
            config.retry_telemetry.retry_backoff_multiplier,
            config.retry_telemetry.retry_max_backoff_ms,
            config.retry_telemetry.retry_timeout_ms,
            config.retry_telemetry.retry_use_jitter,
        );
        let telemetry_ttl_config = TelemetryTTLConfig::new(
            config.retry_telemetry.metric_cache_ttl_ms,
            config.retry_telemetry.telemetry_snapshot_ttl_ms,
            config.retry_telemetry.audit_log_ttl_ms,
            config.retry_telemetry.intent_metadata_ttl_ms,
            config.retry_telemetry.cleanup_interval_ms,
            config.retry_telemetry.telemetry_publish_interval_ms,
            config.retry_telemetry.include_timestamps,
            config.retry_telemetry.auto_cleanup,
        );
        let retry_telemetry_manager = Arc::new(RetryAndTelemetryManager::with_configs(
            retry_config,
            telemetry_ttl_config,
        ));

        Self {
            config: config.clone(),
            lsm_engine: Arc::new(LsmPolicyEngine::with_config(&config.lsm)),
            intent_bus,
            context_memory,
            capability_security,
            compute_scheduler: Arc::new(ComputeScheduler::with_weights(weights)),
            agent_scheduler,
            tcell,
            bcell,
            macrophage,
            attachment: Arc::new(parking_lot::Mutex::new(None)),
            shutdown_tx: None,
            routing_task: None,
            supervisor_task: None,
            immune_task: None,
            tracer_task: None,
            tracer_cancel: None,
            tcell_task: None,
            metrics_task: None,
            metrics_cancel: None,
            compute_task: None,
            intent_bridge_listener_task: None,
            intent_bridge_forwarder_task: None,
            intent_bridge_cancel: None,
            intent_bridge: None,
            telemetry_task: None,
            p2p_mesh: None,
            p2p_listener_task: None,
            p2p_gossip_task: None,
            retry_telemetry_manager,
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

    /// ดึงการอ้างอิงไปยัง P2P Gossip Mesh manager
    #[must_use]
    pub fn p2p_mesh(&self) -> Option<Arc<P2PMeshManager>> {
        self.p2p_mesh.clone()
    }

    /// ดึงการอ้างอิงไปยัง Compute Scheduler
    #[must_use]
    pub fn compute_scheduler(&self) -> Arc<ComputeScheduler> {
        Arc::clone(&self.compute_scheduler)
    }

    /// ดึงการอ้างอิงไปยัง RetryAndTelemetry Manager สำหรับการกำหนดค่าและการตรวจสอบ
    #[must_use]
    pub fn retry_telemetry_manager(&self) -> Arc<RetryAndTelemetryManager> {
        Arc::clone(&self.retry_telemetry_manager)
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
        {
            let mut attachment_lock = self.attachment.lock();
            if attachment_lock.is_none() {
                *attachment_lock = Some(attach_lsm_hooks(Arc::clone(&self.lsm_engine))?);
                info!("LSM Hooks แนบสำเร็จ");
            }
        }

        // เริ่มต้นใช้งานโมดูลอื่น ๆ
        let _boot_context = self.context_memory();
        let _security = self.capability_security();
        let _warmup_score = self.compute_scheduler.score(ComputeProfile {
            latency_ms: 1.0,
            power_watts: 1.0,
            cost_units: 1.0,
        });

        self.agent_scheduler
            .configure_routing_policy(DistributedRoutingPolicy {
                local_node_id: self.config.agent_scheduler.local_node_id.clone(),
                remote_enabled: self.config.agent_scheduler.distributed_enabled,
                max_local_agents: self.config.agent_scheduler.max_agents,
                overload_threshold_percent: self
                    .config
                    .agent_scheduler
                    .remote_overload_threshold_percent,
                min_remote_trust: self.config.agent_scheduler.min_remote_trust_score,
                max_candidate_nodes: self.config.agent_scheduler.max_remote_candidates,
            })
            .await;
        for peer in &self.config.intent_bus.bridge_peers {
            self.agent_scheduler
                .upsert_remote_node(RemoteNodeState::new(
                    peer.node_id.clone(),
                    peer.available_agent_slots,
                    peer.trust_score,
                    peer.capabilities.clone(),
                ))
                .await;
        }

        if self.shutdown_tx.is_none() {
            let scheduler = Arc::clone(&self.agent_scheduler);
            let mut intent_subscriber = self.intent_bus.subscribe();
            let supervisor = scheduler.supervisor();
            let (shutdown_tx, mut routing_shutdown_rx) = watch::channel(false);
            let supervisor_shutdown_rx = shutdown_tx.subscribe();

            // ── Register capability revocation callback ──
            {
                let attachment_clone = Arc::clone(&self.attachment);
                self.capability_security.register_revocation_callback(Arc::new(move |token_id, scope| {
                    if let Scope::Process(pid) = scope {
                        if let Some(attachment) = attachment_clone.lock().as_mut() {
                            if let Err(e) = attachment.deny_pid(pid) {
                                tracing::error!("Failed to deny PID {} upon token revocation: {:?}", pid, e);
                            } else {
                                tracing::warn!("LSM: Revoked PID {} from allowed_pids because token {} was revoked", pid, token_id);
                            }
                        }
                    }
                }));
            }

            // ── Spawn periodic capability expiration task ──
            {
                let cap_sec = Arc::clone(&self.capability_security);
                let attachment_for_expiry = Arc::clone(&self.attachment);
                let mut expiry_shutdown_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    let expiry_interval = std::time::Duration::from_millis(500); // Check twice a second
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(expiry_interval) => {
                                // 1. ทำความสะอาด Token ที่หมดอายุ และขยะอื่นๆ ในระบบ
                                cap_sec.garbage_collect();

                                // 2. ดึงรายการ PID ที่ยังได้รับอนุญาตอยู่ใน BPF Map มาเพื่อตรวจสอบ
                                let current_allowed_pids = {
                                    if let Some(attachment) = attachment_for_expiry.lock().as_ref() {
                                        attachment.allowed_pids()
                                    } else {
                                        std::collections::HashSet::new()
                                    }
                                };

                                // 3. สำหรับแต่ละ PID ที่ได้รับอนุญาต ตรวจสอบว่ายังมี Token ที่ใช้งานได้อยู่หรือไม่
                                for pid in current_allowed_pids {
                                    if pid == std::process::id() {
                                        continue;
                                    }

                                    let has_valid_token = cap_sec.has_valid_token_for_pid(pid);

                                    if !has_valid_token {
                                        if let Some(attachment) = attachment_for_expiry.lock().as_mut() {
                                            if let Err(e) = attachment.deny_pid(pid) {
                                                tracing::error!("Failed to deny expired PID {}: {:?}", pid, e);
                                            } else {
                                                tracing::warn!("LSM: Revoked PID {} from allowed_pids due to token expiration/no active tokens", pid);
                                            }
                                        }
                                    }
                                }
                            }
                            changed = expiry_shutdown_rx.changed() => {
                                if changed.is_err() || *expiry_shutdown_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }

            let intent_bus_for_routing = Arc::clone(&self.intent_bus);
            // รัน Task สำหรับดักฟัง Intent Bus และส่งต่อไปยัง Agent Scheduler แบบ Async
            self.routing_task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        intent = intent_subscriber.receive() => {
                            match intent {
                                Some(intent) => {
                                    if intent.intent_type == IntentType::NaturalLanguage {
                                        if let Some(cmd_intent) = nlp::parse_natural_language_intent(&intent) {
                                            let _ = intent_bus_for_routing.publish(cmd_intent).await;
                                        }
                                    }
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

            // ── Syscall Tracer & T-Cell Integration ──
            // เริ่มต้น SyscallTracer เพื่อดักฟัง syscall และส่งต่อให้ TCellAgent
            let (tracer, mut event_rx) = SyscallTracer::new(Arc::clone(&self.lsm_engine));
            let cancel = tokio_util_cancel::CancellationToken::new();
            let enable_fallback = self.config.ebpf.enable_fallback;
            self.tracer_cancel = Some(cancel.clone());
            self.tracer_task = Some(tokio::spawn(async move {
                let _ = tracer.run(cancel, enable_fallback).await;
            }));

            let tcell = Arc::clone(&self.tcell);
            let intent_bus_for_tcell = Arc::clone(&self.intent_bus);
            let audit_logger = AuditLogger::new(std::path::PathBuf::from(
                &self.config.capability_security.audit_log_path,
            ));
            let mut tcell_shutdown_rx = shutdown_tx.subscribe();
            self.tcell_task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some(event) = event_rx.recv() => {
                            let denied = matches!(event.decision, PolicyDecision::Deny);
                            let decision = tcell.observe_syscall(event.pid, &event.syscall_name, denied).await;

                            if decision == ThreatDecision::Quarantine || decision == ThreatDecision::Kill {
                                if decision == ThreatDecision::Quarantine {
                                    tcell.quarantine(event.pid).await;
                                }

                                // Audit logging with full context
                                let reason = format!("{:?}", decision);
                                let anomaly_score = tcell.get_stats(event.pid).await
                                    .map(|s| s.anomaly_score)
                                    .unwrap_or(0.0);
                                let entry = match decision {
                                    ThreatDecision::Kill => AuditEntry::process_killed(
                                        event.pid, event.uid, anomaly_score, &reason,
                                    ),
                                    _ => AuditEntry::process_quarantined(
                                        event.pid, event.uid, anomaly_score, &reason,
                                    ),
                                };
                                let audit_logger = audit_logger.clone();
                                let _ = task::spawn_blocking(move || audit_logger.record(entry)).await;

                                let payload = serde_json::json!({
                                    "pid": event.pid,
                                    "syscall": event.syscall_name,
                                    "decision": reason,
                                    "anomaly_score": anomaly_score,
                                }).to_string();

                                let threat_intent = Intent::new(
                                    uuid::Uuid::new_v4().to_string(),
                                    IntentType::Event,
                                    payload,
                                    intent_bus::IntentPriority::Critical,
                                    "tcell",
                                );
                                let _ = intent_bus_for_tcell.publish(threat_intent).await;
                            }
                        }
                        changed = tcell_shutdown_rx.changed() => {
                            if changed.is_err() || *tcell_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));

            // ── Immune System Integration Tasks ──
            let lsm = Arc::clone(&self.lsm_engine);
            let bcell = Arc::clone(&self.bcell);
            let tcell_for_immune = Arc::clone(&self.tcell);
            let macrophage = Arc::clone(&self.macrophage);
            let mut immune_intent_subscriber = self.intent_bus.subscribe();
            let immune_shutdown_rx = shutdown_tx.subscribe();
            let immune_interval = std::time::Duration::from_secs(10);

            self.immune_task = Some(tokio::spawn(async move {
                let mut shutdown_rx = immune_shutdown_rx;
                loop {
                    tokio::select! {
                        // 1. ดักรับ Threat Event จาก T-Cell เข้าบัส แล้วนำไปป้อนให้ B-Cell เรียนรู้แบบ Closed-loop
                        Some(intent) = immune_intent_subscriber.receive() => {
                            if intent.intent_type == IntentType::Event && intent.source == "tcell" {
                                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                                    if let Some(pid) = data.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) {
                                        let severity = match data.get("decision").and_then(|v| v.as_str()) {
                                            Some("Kill") => 10,
                                            Some("Quarantine") => 8,
                                            _ => 5,
                                        };
                                        if let Some(stats) = tcell_for_immune.get_stats(pid).await {
                                            let syscalls: Vec<String> = stats.syscall_history.into_iter().collect();
                                            if !syscalls.is_empty() {
                                                bcell.learn_threat(syscalls, severity).await;

                                                // สั่งให้ B-Cell สร้าง Antibody ทันทีหลังเรียนรู้
                                                if let Some(antibody) = bcell.generate_antibody().await {
                                                    lsm.add_blocked_syscall(&antibody.blocked_syscall);
                                                    warn!(
                                                        syscall = %antibody.blocked_syscall,
                                                        confidence = antibody.confidence,
                                                        "Immune System: auto-generated and applied antibody rule to LSM Policy Engine"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // 2. งานประจำช่วงเวลา (Periodic Tasks)
                        _ = tokio::time::sleep(immune_interval) => {
                            // Sweep shadow antibodies — promote those that passed observation window
                            let promoted = bcell.sweep_shadow_antibodies().await;
                            for ab in &promoted {
                                lsm.add_blocked_syscall(&ab.blocked_syscall);
                                warn!(
                                    syscall = %ab.blocked_syscall,
                                    confidence = ab.confidence,
                                    "Immune System: shadow antibody promoted to enforce — applied to LSM Policy Engine"
                                );
                            }

                            // ล้างข้อมูลหน้า context ที่หมดอายุ
                            let swept = macrophage.sweep_context().await;
                            if swept > 0 {
                                info!("Immune System: Macrophage cleaned {} expired context entries", swept);
                            }

                            // ปลดกักกัน process ที่หมดอายุของ T-Cell
                            let released = tcell_for_immune.release_expired_quarantine(std::time::Duration::from_secs(300)).await;
                            if !released.is_empty() {
                                info!("Immune System: auto-released {} processes from T-Cell quarantine", released.len());
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

            let compute_scheduler = Arc::clone(&self.compute_scheduler);
            let intent_bus_for_compute = Arc::clone(&self.intent_bus);
            let mut compute_intent_subscriber = self.intent_bus.subscribe();
            let mut compute_shutdown_rx = shutdown_tx.subscribe();
            self.compute_task = Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some(intent) = compute_intent_subscriber.receive() => {
                            if intent.intent_type == IntentType::Event && intent.source == "agent-scheduler" {
                                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                                    if data.get("action").and_then(|v| v.as_str()) == Some("PlacementRequest") {
                                        let agent_id = data.get("agent_id").and_then(|v| v.as_u64()).unwrap_or(0);
                                        let workload_str = data.get("workload_class").and_then(|v| v.as_str()).unwrap_or("SmallLlm");
                                        let wl = match workload_str {
                                            "KernelLogic" => WorkloadClass::KernelLogic,
                                            "SmallLlm" => WorkloadClass::SmallLlm,
                                            "LargeLlm" => WorkloadClass::LargeLlm,
                                            "VectorIndexing" => WorkloadClass::VectorIndexing,
                                            _ => WorkloadClass::SmallLlm,
                                        };

                                        // Scan hardware and place
                                        let policy = PlacementPolicy::new((*compute_scheduler).clone());
                                        let profiles = compute_scheduler.scan_real_hardware();
                                        let target = policy.place(wl, &profiles).unwrap_or(ComputeTarget::Cpu);

                                        // Publish response
                                        let resp_payload = serde_json::json!({
                                            "action": "PlacementResponse",
                                            "agent_id": agent_id,
                                            "compute_target": format!("{:?}", target),
                                        }).to_string();

                                        let resp_intent = Intent::new(
                                            uuid::Uuid::new_v4().to_string(),
                                            IntentType::Event,
                                            resp_payload,
                                            intent_bus::IntentPriority::High,
                                            "compute-scheduler",
                                        );
                                        let _ = intent_bus_for_compute.publish(resp_intent).await;
                                    }
                                }
                            }
                        }
                        changed = compute_shutdown_rx.changed() => {
                            if changed.is_err() || *compute_shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));

            if self.config.intent_bus.bridge_enabled {
                let bridge = Arc::new(IntentBridge::new(
                    self.config.agent_scheduler.local_node_id.clone(),
                    &self.config.intent_bus.bridge_peers,
                    std::time::Duration::from_millis(
                        self.config.intent_bus.bridge_connect_timeout_ms,
                    ),
                    std::time::Duration::from_millis(
                        self.config.intent_bus.bridge_request_timeout_ms,
                    ),
                ));
                let bridge_cancel = tokio_util_cancel::CancellationToken::new();
                let bridge_listener_cancel = bridge_cancel.clone();
                let bridge_forwarder_cancel = bridge_cancel.clone();
                let bridge_listener = Arc::clone(&bridge);
                let bridge_forwarder = Arc::clone(&bridge);
                let bridge_bus_listener = Arc::clone(&self.intent_bus);
                let bridge_bus_forwarder = Arc::clone(&self.intent_bus);
                self.intent_bridge_cancel = Some(bridge_cancel);
                self.intent_bridge = Some(Arc::clone(&bridge));

                match self
                    .config
                    .intent_bus
                    .bridge_listen_addr
                    .parse::<std::net::SocketAddr>()
                {
                    Ok(listen_addr) => {
                        self.intent_bridge_listener_task = Some(tokio::spawn(async move {
                            if let Err(error) = bridge_listener
                                .start_listener(
                                    bridge_bus_listener,
                                    listen_addr,
                                    bridge_listener_cancel,
                                )
                                .await
                            {
                                warn!(?error, "Intent bridge listener failed");
                            }
                        }));
                        self.intent_bridge_forwarder_task = Some(tokio::spawn(async move {
                            if let Err(error) = bridge_forwarder
                                .start_forwarder(bridge_bus_forwarder, bridge_forwarder_cancel)
                                .await
                            {
                                warn!(?error, "Intent bridge forwarder failed");
                            }
                        }));
                    }
                    Err(error) => {
                        warn!(
                            addr = %self.config.intent_bus.bridge_listen_addr,
                            ?error,
                            "Intent bridge disabled due to invalid listen address"
                        );
                    }
                }
            }

            // ── P2P Gossip Mesh Integration ──
            let mut p2p_mgr_opt = None;
            if self.config.context_memory.p2p_enabled {
                if let Ok(addr) = self
                    .config
                    .context_memory
                    .p2p_listen_addr
                    .parse::<std::net::SocketAddr>()
                {
                    let p2p_mgr = Arc::new(P2PMeshManager::new_with_node_config(
                        addr,
                        self.config.agent_scheduler.local_node_id.clone(),
                        Vec::new(),
                    ));
                    let p2p_listener_mgr = Arc::clone(&p2p_mgr);
                    let p2p_gossip_mgr = Arc::clone(&p2p_mgr);

                    self.p2p_listener_task = Some(tokio::spawn(async move {
                        if let Err(e) = p2p_listener_mgr.start_listener().await {
                            warn!("P2P Mesh: listener failed: {}", e);
                        }
                    }));

                    self.p2p_gossip_task = Some(tokio::spawn(async move {
                        p2p_gossip_mgr.start_gossip_loop().await;
                    }));

                    let p2p_bootstrap_mgr = Arc::clone(&p2p_mgr);
                    let bootstrap_nodes = self.config.context_memory.p2p_bootstrap_nodes.clone();
                    tokio::spawn(async move {
                        for node in bootstrap_nodes {
                            if let Ok(peer_addr) = node.parse::<std::net::SocketAddr>() {
                                if let Err(e) =
                                    p2p_bootstrap_mgr.clone().connect_to_peer(peer_addr).await
                                {
                                    warn!(
                                        "P2P Bootstrap: failed to connect to peer {}: {}",
                                        peer_addr, e
                                    );
                                } else {
                                    info!(
                                        "P2P Bootstrap: successfully connected to peer {}",
                                        peer_addr
                                    );
                                }
                            }
                        }
                    });

                    self.p2p_mesh = Some(Arc::clone(&p2p_mgr));
                    self.context_memory.attach_mesh(Arc::clone(&p2p_mgr));
                    p2p_mgr_opt = Some(p2p_mgr);
                    info!("P2P Mesh: initialized on addr {}", addr);
                } else {
                    warn!(
                        "P2P Mesh: invalid listen addr {}",
                        self.config.context_memory.p2p_listen_addr
                    );
                }
            }

            if let Some(p2p_mgr) = self.p2p_mesh.clone() {
                let scheduler = Arc::clone(&self.agent_scheduler);
                let bridge = self.intent_bridge.clone();
                let local_node_id = self.config.agent_scheduler.local_node_id.clone();
                let max_agents = self.config.agent_scheduler.max_agents;
                let local_bridge_listen_addr = self.config.intent_bus.bridge_listen_addr.clone();
                let bridge_addr = if self.config.intent_bus.bridge_enabled {
                    Some(local_bridge_listen_addr.clone())
                } else {
                    None
                };
                let telemetry_interval = std::time::Duration::from_millis(
                    self.config.retry_telemetry.telemetry_publish_interval_ms,
                );
                let mut telemetry_shutdown_rx = shutdown_tx.subscribe();
                self.telemetry_task = Some(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(telemetry_interval) => {
                                let total_agents = scheduler.total_agents().await;
                                let running_agents = scheduler.get_running_agents().await.len();
                                let telemetry = NodeTelemetry {
                                    node_id: local_node_id.clone(),
                                    available_agent_slots: max_agents.saturating_sub(total_agents),
                                    max_agents,
                                    running_agents,
                                    capabilities: Vec::new(),
                                    bridge_addr: bridge_addr.clone(),
                                    timestamp_millis: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .map(|duration| duration.as_millis() as u64)
                                        .unwrap_or(0),
                                };
                                let _ = p2p_mgr.publish_node_telemetry(telemetry).await;

                                let snapshot = p2p_mgr.get_telemetry_snapshot().await;
                                let alive_peers = p2p_mgr.get_alive_peers().await;
                                let active_ids: HashSet<String> = alive_peers
                                    .iter()
                                    .map(|peer| peer.id.clone())
                                    .collect();

                                for peer in alive_peers {
                                    if peer.id == local_node_id {
                                        continue;
                                    }
                                    if let Some(telemetry) = snapshot.get(&peer.id) {
                                        scheduler
                                            .upsert_remote_node(RemoteNodeState::new(
                                                peer.id.clone(),
                                                telemetry.available_agent_slots,
                                                peer.trust_score,
                                                if telemetry.capabilities.is_empty() {
                                                    peer.capabilities.clone()
                                                } else {
                                                    telemetry.capabilities.clone()
                                                },
                                            ))
                                            .await;
                                        if let (Some(bridge), Some(addr)) =
                                            (bridge.as_ref(), telemetry.bridge_addr.as_deref())
                                        {
                                            if let Ok(socket_addr) = addr.parse() {
                                                bridge.upsert_peer(peer.id.clone(), socket_addr).await;
                                            }
                                        } else if let Some(bridge) = bridge.as_ref() {
                                            if let Some(socket_addr) =
                                                infer_bridge_addr(peer.addr, &local_bridge_listen_addr)
                                            {
                                                bridge.upsert_peer(peer.id.clone(), socket_addr).await;
                                            }
                                        }
                                    }
                                }

                                let known_remote_nodes = scheduler.remote_nodes().await;
                                for remote in known_remote_nodes {
                                    if active_ids.contains(&remote.node_id) {
                                        continue;
                                    }
                                    scheduler.remove_remote_node(&remote.node_id).await;
                                    if let Some(bridge) = bridge.as_ref() {
                                        bridge.remove_peer(&remote.node_id).await;
                                    }
                                }
                            }
                            changed = telemetry_shutdown_rx.changed() => {
                                if changed.is_err() || *telemetry_shutdown_rx.borrow() {
                                    break;
                                }
                            }
                        }
                    }
                }));
            }

            let cancel_uds = tokio_util_cancel::CancellationToken::new();
            let _ = uds::start_uds_server(
                Arc::clone(&self.intent_bus),
                Some(Arc::clone(&self.tcell)),
                Some(Arc::clone(&self.lsm_engine)),
                Some(Arc::clone(&self.agent_scheduler)),
                Some(Arc::clone(&self.compute_scheduler)),
                Some(Arc::clone(&self.context_memory)),
                p2p_mgr_opt,
                &self.config.kernel_companion.uds_socket_path,
                cancel_uds,
                Some(Arc::clone(&self.capability_security)),
            )
            .await;

            let metrics_addr = self.config.kernel_companion.metrics_server_addr.clone();
            let cancel_metrics = tokio_util_cancel::CancellationToken::new();
            self.metrics_cancel = Some(cancel_metrics.clone());
            self.metrics_task = Some(tokio::spawn(async move {
                let _ = metrics_server::start_metrics_server(&metrics_addr, cancel_metrics).await;
            }));

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
        if let Some(cancel) = self.tracer_cancel.take() {
            cancel.cancel();
        }
        if let Some(cancel) = self.metrics_cancel.take() {
            cancel.cancel();
        }
        if let Some(cancel) = self.intent_bridge_cancel.take() {
            cancel.cancel();
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
        if let Some(task) = self.compute_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.telemetry_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.intent_bridge_listener_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.intent_bridge_forwarder_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.p2p_listener_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.p2p_gossip_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tracer_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.tcell_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.metrics_task.take() {
            let _ = task.await;
        }
        if let Some(attachment) = self.attachment.lock().as_mut() {
            attachment.detach();
        }
        *self.attachment.lock() = None;
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

    /// ดึงการอ้างอิงไปยัง LSM Policy Engine
    #[must_use]
    pub fn lsm_engine(&self) -> Arc<LsmPolicyEngine> {
        Arc::clone(&self.lsm_engine)
    }

    /// ฟังก์ชัน `authorize_process_token` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `authorize_process_token` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn authorize_process_token(
        &mut self,
        pid: u32,
        token_id: u64,
        secret: &[u8; 32],
        capability: &str,
    ) -> anyhow::Result<bool> {
        let allowed = self.capability_security.validate(
            token_id,
            secret,
            &Scope::Process(pid),
            capability,
        )?;

        if allowed {
            if let Some(salt) = self.agent_scheduler.get_instance_salt_by_token_id(token_id) {
                let active_profile = self.lsm_engine.active_profile_name();
                self.lsm_engine
                    .register_polymorphic_pid(pid, &active_profile, &salt);
            }
        }

        if let Some(attachment) = self.attachment.lock().as_mut() {
            if allowed {
                attachment.allow_pid(pid)?;
            } else {
                attachment.deny_pid(pid)?;
            }
        }

        Ok(allowed)
    }

    #[must_use]
    /// ฟังก์ชัน `is_pid_authorized` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `is_pid_authorized` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn is_pid_authorized(&self, pid: u32) -> bool {
        self.attachment
            .lock()
            .as_ref()
            .is_some_and(|attachment| attachment.allows_pid(pid))
    }

    /// ตรวจสอบว่า LSM Hooks ถูกแนบเข้ากับระบบแล้วหรือไม่
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attachment
            .lock()
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

    #[test]
    fn infer_bridge_addr_reuses_peer_ip_and_local_bridge_port() {
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 9091);
        let derived = infer_bridge_addr(peer_addr, "127.0.0.1:9191").expect("valid bridge addr");
        assert_eq!(
            derived,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 9191)
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
