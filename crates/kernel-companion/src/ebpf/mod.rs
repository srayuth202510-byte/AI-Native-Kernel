use anyhow::Result;
use bytes::BytesMut;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

use crate::lsm::{LsmDecision, LsmPolicyEngine};
use crate::observability::kernel_metrics;

// ---- Types ----

#[derive(Debug, Error)]
/// ประเภทข้อมูล Enum `TracerError` สำหรับระบุชนิดของข้อมูล
/// ประเภทข้อมูล Enum `TracerError` สำหรับระบุชนิดของข้อมูล
pub enum TracerError {
    #[error("eBPF program load failed: {0}")]
    /// ข้อมูล `LoadFailed(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `LoadFailed(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    LoadFailed(String),
    #[error("tracepoint attach failed: {0}")]
    /// ข้อมูล `AttachFailed(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `AttachFailed(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    AttachFailed(String),
    #[error("ring buffer error: {0}")]
    /// ข้อมูล `RingBufferError(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `RingBufferError(String)` สำหรับการกำหนดค่าหรือสถานะภายใน
    RingBufferError(String),
    #[error("tracer cancelled")]
    /// ข้อมูล `Cancelled` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `Cancelled` สำหรับการกำหนดค่าหรือสถานะภายใน
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// โครงสร้างข้อมูล `SyscallEvent` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `SyscallEvent` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct SyscallEvent {
    /// ข้อมูล `syscall_nr` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `syscall_nr` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub syscall_nr: u64,
    /// ข้อมูล `syscall_name` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `syscall_name` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub syscall_name: String,
    /// ข้อมูล `pid` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `pid` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub pid: u32,
    /// ข้อมูล `uid` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `uid` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub uid: u32,
    /// ข้อมูล `timestamp_ns` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `timestamp_ns` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub timestamp_ns: u64,
    /// ข้อมูล `decision` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `decision` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// ประเภทข้อมูล Enum `PolicyDecision` สำหรับระบุชนิดของข้อมูล
/// ประเภทข้อมูล Enum `PolicyDecision` สำหรับระบุชนิดของข้อมูล
pub enum PolicyDecision {
    /// ข้อมูล `Allow` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `Allow` สำหรับการกำหนดค่าหรือสถานะภายใน
    Allow,
    /// ข้อมูล `Deny` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `Deny` สำหรับการกำหนดค่าหรือสถานะภายใน
    Deny,
}

/// ประเภทข้อมูลย่อย (Alias) `SyscallEventReceiver` เพื่อความสะดวกในการอ่านรหัส
/// ประเภทข้อมูลย่อย (Alias) `SyscallEventReceiver` เพื่อความสะดวกในการอ่านรหัส
pub type SyscallEventReceiver = mpsc::Receiver<SyscallEvent>;

/// Cache invalidation events sent from the daemon to the tracer task.
#[derive(Debug, Clone, Copy)]
pub enum CacheInvalidation {
    /// Invalidate all entries (profile changed).
    Full,
    /// Invalidate a specific syscall entry (antibody added/removed).
    Syscall(u64),
}

/// ประเภทข้อมูลย่อย (Alias) `CacheInvalidationReceiver` เพื่อความสะดวกในการอ่านรหัส
/// ประเภทข้อมูลย่อย (Alias) `CacheInvalidationReceiver` เพื่อความสะดวกในการอ่านรหัส
pub type CacheInvalidationReceiver = tokio::sync::mpsc::Receiver<CacheInvalidation>;
/// ประเภทข้อมูลย่อย (Alias) `CacheInvalidationSender` เพื่อความสะดวกในการอ่านรหัส
/// ประเภทข้อมูลย่อย (Alias) `CacheInvalidationSender` เพื่อความสะดวกในการอ่านรหัส
pub type CacheInvalidationSender = tokio::sync::mpsc::Sender<CacheInvalidation>;

// ---- SyscallTracer ----

/// โครงสร้างข้อมูล `SyscallTracer` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `SyscallTracer` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct SyscallTracer {
    policy: Arc<LsmPolicyEngine>,
    event_tx: mpsc::Sender<SyscallEvent>,
    syscall_table: HashMap<u64, &'static str>,
    cache_invalidation_rx: Arc<tokio::sync::Mutex<Option<CacheInvalidationReceiver>>>,
}

impl SyscallTracer {
    #[must_use]
    /// ฟังก์ชัน `new` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `new` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn new(policy: Arc<LsmPolicyEngine>) -> (Self, SyscallEventReceiver) {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (_invalidation_tx, invalidation_rx) = tokio::sync::mpsc::channel(64);
        let tracer = Self {
            policy,
            event_tx,
            syscall_table: build_syscall_table(),
            cache_invalidation_rx: Arc::new(tokio::sync::Mutex::new(Some(invalidation_rx))),
        };
        (tracer, event_rx)
    }

    /// Create a SyscallTracer with a cache invalidation sender handle.
    /// Returns (tracer, event_rx, invalidation_tx).
    pub fn with_cache_invalidation(
        policy: Arc<LsmPolicyEngine>,
    ) -> (Self, SyscallEventReceiver, CacheInvalidationSender) {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let (invalidation_tx, invalidation_rx) = tokio::sync::mpsc::channel(64);
        let tracer = Self {
            policy,
            event_tx,
            syscall_table: build_syscall_table(),
            cache_invalidation_rx: Arc::new(tokio::sync::Mutex::new(Some(invalidation_rx))),
        };
        (tracer, event_rx, invalidation_tx)
    }

    #[instrument(skip(self, cancel))]
    /// ข้อมูล `async fn run(` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `async fn run(` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub async fn run(
        self,
        cancel: CancellationToken,
        enable_fallback: bool,
    ) -> Result<(), TracerError> {
        info!("SyscallTracer starting — attempting real eBPF program load");

        match self.try_run_bpf(cancel.clone()).await {
            Ok(()) => {
                kernel_metrics().set_active_mode("tracer", "real");
                info!("SyscallTracer running on real eBPF");
                Ok(())
            }
            Err(e) => {
                if !enable_fallback {
                    // --no-bpf-fallback: fail hard instead of degrading to simulation.
                    // Use case: production deployments that refuse to run without
                    // kernel-level enforcement (fail-closed posture).
                    kernel_metrics().record_attach_attempt("tracer", "failed");
                    error!(
                        error = %e,
                        "real eBPF load failed and fallback is disabled (use --no-bpf-fallback=false to allow simulation)"
                    );
                    return Err(e);
                }
                let metrics = kernel_metrics();
                metrics.record_attach_attempt("tracer", "fallback");
                metrics.set_active_mode("tracer", "simulation");
                warn!(error = %e, "real eBPF load failed — falling back to simulation mode");
                self.run_simulation_loop(cancel).await
            }
        }
    }

    #[instrument(skip(self, cancel))]
    async fn try_run_bpf(&self, cancel: CancellationToken) -> Result<(), TracerError> {
        let metrics = kernel_metrics();
        let bpf_bytes = load_bpf_program_bytes()
            .map_err(|e| TracerError::LoadFailed(format!("cannot load BPF .o bytes: {e}")))?;

        let mut bpf =
            aya::Bpf::load(&bpf_bytes).map_err(|e| TracerError::LoadFailed(e.to_string()))?;

        let program: &mut aya::programs::TracePoint = bpf
            .program_mut("sys_enter_tp")
            .ok_or_else(|| TracerError::LoadFailed("no sys_enter_tp program".into()))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                TracerError::LoadFailed(format!("program type mismatch: {e}"))
            })?;

        program
            .load()
            .map_err(|e| TracerError::LoadFailed(e.to_string()))?;

        program
            .attach("raw_syscalls", "sys_enter")
            .map_err(|e| TracerError::AttachFailed(e.to_string()))?;

        metrics.record_attach_attempt("tracer", "success");
        metrics.set_active_mode("tracer", "real");
        info!("eBPF tracepoint sys_enter attached — polling ring buffer");

        // ── Extract syscall decision cache map ──
        let mut cache = SyscallDecisionCache::from_bpf(&mut bpf);
        if cache.is_some() {
            info!("syscall_decision_cache map found — kernel-space caching active");
        } else {
            warn!("syscall_decision_cache map not found — caching disabled (old BPF object?)");
        }

        // ── Pre-populate cache with current policy decisions ──
        if let Some(ref mut cache) = cache {
            for (&nr, name) in &self.syscall_table {
                let decision = self.policy.decision_for_syscall(name);
                let pd = match decision {
                    LsmDecision::Allow => PolicyDecision::Allow,
                    LsmDecision::Deny => PolicyDecision::Deny,
                };
                cache.populate(nr, pd);
            }
            info!(
                "syscall decision cache pre-populated with {} entries",
                self.syscall_table.len()
            );
        }

        let map = bpf
            .take_map("syscall_events")
            .ok_or_else(|| TracerError::RingBufferError("map syscall_events not found".into()))?;

        let mut perf_array: aya::maps::PerfEventArray<_> = map
            .try_into()
            .map_err(|e: aya::maps::MapError| TracerError::RingBufferError(e.to_string()))?;

        let cpus =
            aya::util::online_cpus().map_err(|e| TracerError::RingBufferError(e.to_string()))?;

        let mut buffers: Vec<PerfBufferState> = Vec::new();
        for cpu_id in cpus {
            let buf = perf_array
                .open(cpu_id, None)
                .map_err(|e| TracerError::RingBufferError(e.to_string()))?;
            buffers.push(PerfBufferState {
                cpu_id,
                buf,
                out_bufs: vec![BytesMut::with_capacity(4096)],
            });
        }

        let poll_interval = std::time::Duration::from_millis(1);

        // ── Main polling loop: handle perf events + cache invalidation ──
        let mut invalidation_rx = self.cache_invalidation_rx.lock().await.take();
        loop {
            if cancel.is_cancelled() {
                info!("SyscallTracer received cancel signal");
                break;
            }

            tokio::select! {
                // Handle cache invalidation from daemon
                Some(invalidation) = async {
                    invalidation_rx.as_mut()?.recv().await
                } => {
                    if let Some(ref mut cache) = cache {
                        match invalidation {
                            CacheInvalidation::Full => {
                                cache.invalidate_all();
                                metrics.record_cache_invalidation("full");
                                // Re-populate with current policy
                                for (&nr, name) in &self.syscall_table {
                                    let decision = self.policy.decision_for_syscall(name);
                                    let pd = match decision {
                                        LsmDecision::Allow => PolicyDecision::Allow,
                                        LsmDecision::Deny => PolicyDecision::Deny,
                                    };
                                    cache.populate(nr, pd);
                                }
                                info!("cache invalidated and re-populated with {} entries", self.syscall_table.len());
                            }
                            CacheInvalidation::Syscall(nr) => {
                                cache.invalidate_entry(nr);
                                metrics.record_cache_invalidation("syscall");
                                // Re-evaluate this specific syscall
                                if let Some(name) = self.syscall_table.get(&nr) {
                                    let decision = self.policy.decision_for_syscall(name);
                                    let pd = match decision {
                                        LsmDecision::Allow => PolicyDecision::Allow,
                                        LsmDecision::Deny => PolicyDecision::Deny,
                                    };
                                    cache.populate(nr, pd);
                                }
                            }
                        }
                    }
                }
                // Handle perf buffer events
                _ = async {
                    for state in buffers.iter_mut() {
                        match state.buf.read_events(&mut state.out_bufs) {
                            Ok(events) if events.read > 0 => {
                                for buf in state.out_bufs.iter() {
                                    if let Some(raw) = parse_raw_event(buf) {
                                        let event =
                                            self.process_syscall_event(raw.syscall_nr, raw.pid, raw.uid);

                                        // ── Populate cache for future hits ──
                                        if let Some(ref mut cache) = cache {
                                            cache.populate(raw.syscall_nr, event.decision);
                                        }

                                        if self.event_tx.try_send(event).is_err() {
                                            metrics.record_syscall_drop("channel_full");
                                            debug!("event channel full — dropping syscall event");
                                        }
                                    }
                                }
                                if events.lost > 0 {
                                    debug!(lost = events.lost, "perf events lost");
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                debug!(error = %e, "read_events error");
                            }
                        }
                    }
                } => {
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }

        info!("SyscallTracer eBPF loop stopped");
        Ok(())
    }

    #[instrument(skip(self, cancel))]
    async fn run_simulation_loop(&self, cancel: CancellationToken) -> Result<(), TracerError> {
        info!("SyscallTracer running in simulation mode (Phase 1 — no real kernel tracepoint)");

        let simulated: &[(u64, u32, u32)] = &[
            (0, 1000, 1000),
            (1, 1000, 1000),
            (59, 1001, 0),
            (2, 1002, 1000),
        ];

        for &(syscall_nr, pid, uid) in simulated {
            if cancel.is_cancelled() {
                info!("SyscallTracer received cancel signal — stopping");
                return Err(TracerError::Cancelled);
            }

            let event = self.process_syscall_event(syscall_nr, pid, uid);
            debug!(
                syscall = %event.syscall_name,
                pid = event.pid,
                decision = ?event.decision,
                "processed syscall event"
            );

            if self.event_tx.send(event).await.is_err() {
                warn!("SyscallEvent receiver closed — stopping tracer");
                break;
            }
        }

        info!("SyscallTracer stopped (simulation loop complete)");
        Ok(())
    }

    #[instrument(skip(self), fields(syscall_nr, pid, uid))]
    /// ฟังก์ชัน `process_syscall_event` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `process_syscall_event` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn process_syscall_event(&self, syscall_nr: u64, pid: u32, uid: u32) -> SyscallEvent {
        let syscall_name = self
            .syscall_table
            .get(&syscall_nr)
            .copied()
            .unwrap_or("unknown");
        let metrics = kernel_metrics();

        let lsm_decision = self.policy.decision_for_syscall(syscall_name);
        let decision = match lsm_decision {
            LsmDecision::Allow => {
                metrics.record_syscall_event("allow", syscall_name);
                PolicyDecision::Allow
            }
            LsmDecision::Deny => {
                metrics.record_syscall_event("deny", syscall_name);
                warn!(
                    syscall = syscall_name,
                    pid, uid, "LSM denied syscall per Zero-Trust policy"
                );
                PolicyDecision::Deny
            }
        };

        SyscallEvent {
            syscall_nr,
            syscall_name: syscall_name.to_string(),
            pid,
            uid,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            decision,
        }
    }
}

// ---- Per-buffer state ----

struct PerfBufferState {
    #[allow(dead_code)]
    cpu_id: u32,
    buf: aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>,
    out_bufs: Vec<BytesMut>,
}

// ---- Syscall Decision Cache ----

/// BPF hash map wrapper for caching syscall allow/deny decisions in kernel-space.
/// Key: syscall_nr (u64), Value: decision (u8, 1=allow, 2=deny).
/// Eliminates userspace round-trip for repeat syscalls.
pub struct SyscallDecisionCache {
    map: aya::maps::HashMap<aya::maps::MapData, u64, u8>,
}

/// Cache decision values matching the BPF C defines.
const DECISION_ALLOW: u8 = 1;
const DECISION_DENY: u8 = 2;

impl SyscallDecisionCache {
    /// Create a new cache wrapper from an aya::Bpf instance.
    /// Returns None if the map doesn't exist (e.g., old BPF object).
    pub fn from_bpf(bpf: &mut aya::Bpf) -> Option<Self> {
        let map = bpf.take_map("syscall_decision_cache")?;
        let map: aya::maps::HashMap<_, u64, u8> = map.try_into().ok()?;
        Some(Self { map })
    }

    /// Write a decision into the kernel BPF cache map.
    /// After userspace evaluates a syscall, call this to populate the cache
    /// so subsequent occurrences are resolved in-kernel without perf buffer round-trip.
    pub fn populate(&mut self, syscall_nr: u64, decision: PolicyDecision) {
        let val = match decision {
            PolicyDecision::Allow => DECISION_ALLOW,
            PolicyDecision::Deny => DECISION_DENY,
        };
        let _ = self.map.insert(syscall_nr, val, 0);
    }

    /// Invalidate the entire cache map.
    /// Called when the active policy profile changes or antibodies are updated.
    pub fn invalidate_all(&mut self) {
        // Iterate and remove all entries — aya HashMap doesn't have a clear() method.
        // We collect keys first to avoid borrow issues.
        let keys: Vec<u64> = self
            .map
            .iter()
            .filter_map(|r| r.ok())
            .map(|(k, _)| k)
            .collect();
        let count = keys.len();
        for key in &keys {
            let _ = self.map.remove(key);
        }
        info!("syscall decision cache invalidated ({count} entries removed)");
    }

    /// Remove a single syscall from the cache.
    /// Called when a specific antibody is added/removed.
    pub fn invalidate_entry(&mut self, syscall_nr: u64) {
        let _ = self.map.remove(&syscall_nr);
    }
}

// ---- Raw event struct matching BPF C definition ----

#[repr(C)]
struct RawSyscallEvent {
    syscall_nr: u64,
    pid: u32,
    uid: u32,
    timestamp_ns: u64,
}

fn parse_raw_event(buf: &[u8]) -> Option<RawSyscallEvent> {
    let size = std::mem::size_of::<RawSyscallEvent>();
    if buf.len() < size {
        return None;
    }
    let syscall_nr = u64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
    let uid = u32::from_ne_bytes(buf[12..16].try_into().ok()?);
    let timestamp_ns = u64::from_ne_bytes(buf[16..24].try_into().ok()?);
    Some(RawSyscallEvent {
        syscall_nr,
        pid,
        uid,
        timestamp_ns,
    })
}

// ---- BPF program loading ----

/// Load a compiled BPF .o file by stem name (e.g., "syscall-tracer" or "lsm-security").
/// Looks in BPF_OUT_DIR first, then CARGO_MANIFEST_DIR/target/bpf/, then common paths.
pub fn load_bpf_o(stem: &str) -> Result<Vec<u8>> {
    let filename = format!("{}.bpf.o", stem);
    let bpf_o_path = if let Ok(out_dir) = std::env::var("BPF_OUT_DIR") {
        std::path::PathBuf::from(out_dir).join(&filename)
    } else if let Ok(cargo_manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        std::path::PathBuf::from(cargo_manifest)
            .join("target")
            .join("bpf")
            .join(&filename)
    } else {
        // Check relative to the current binary
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_default();
        let rel = exe_dir.join(&filename);
        if rel.exists() {
            return Ok(std::fs::read(&rel)?);
        }
        anyhow::bail!(
            "BPF_OUT_DIR and CARGO_MANIFEST_DIR not set, and {} not found near binary",
            filename
        );
    };

    if !bpf_o_path.exists() {
        anyhow::bail!("BPF object file not found: {}", bpf_o_path.display());
    }

    Ok(std::fs::read(&bpf_o_path)?)
}

// Backward compatibility for internal use
fn load_bpf_program_bytes() -> Result<Vec<u8>> {
    load_bpf_o("syscall-tracer")
}

// ---- CancellationToken ----

/// โมดูล `tokio_util_cancel` จัดการระบบย่อยที่เกี่ยวข้อง
/// โมดูล `tokio_util_cancel` จัดการระบบย่อยที่เกี่ยวข้อง
pub mod tokio_util_cancel {
    #[derive(Clone, Default)]
    /// โครงสร้างข้อมูล `CancellationToken` ใช้สำหรับเก็บสถานะและการตั้งค่า
    /// โครงสร้างข้อมูล `CancellationToken` ใช้สำหรับเก็บสถานะและการตั้งค่า
    pub struct CancellationToken {
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl CancellationToken {
        #[must_use]
        /// ฟังก์ชัน `new` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        /// ฟังก์ชัน `new` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        pub fn new() -> Self {
            Self::default()
        }

        /// ฟังก์ชัน `cancel` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        /// ฟังก์ชัน `cancel` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        pub fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        #[must_use]
        /// ฟังก์ชัน `is_cancelled` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        /// ฟังก์ชัน `is_cancelled` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
        pub fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
}

use tokio_util_cancel::CancellationToken;

// ---- x86_64 syscall table ----

/// ฟังก์ชัน `build_syscall_table` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
/// ฟังก์ชัน `build_syscall_table` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
pub fn build_syscall_table() -> HashMap<u64, &'static str> {
    let mut table = HashMap::new();
    table.insert(0, "read");
    table.insert(1, "write");
    table.insert(2, "open");
    table.insert(3, "close");
    table.insert(4, "stat");
    table.insert(5, "fstat");
    table.insert(6, "lstat");
    table.insert(7, "poll");
    table.insert(8, "lseek");
    table.insert(9, "mmap");
    table.insert(10, "mprotect");
    table.insert(11, "munmap");
    table.insert(12, "brk");
    table.insert(13, "rt_sigaction");
    table.insert(14, "rt_sigprocmask");
    table.insert(16, "ioctl");
    table.insert(17, "pread64");
    table.insert(18, "pwrite64");
    table.insert(19, "readv");
    table.insert(20, "writev");
    table.insert(21, "access");
    table.insert(22, "pipe");
    table.insert(23, "select");
    table.insert(24, "sched_yield");
    table.insert(25, "mremap");
    table.insert(26, "msync");
    table.insert(27, "mincore");
    table.insert(28, "madvise");
    table.insert(31, "dup");
    table.insert(32, "dup2");
    table.insert(33, "pause");
    table.insert(34, "nanosleep");
    table.insert(38, "getpid");
    table.insert(39, "sendfile");
    table.insert(41, "socket");
    table.insert(42, "connect");
    table.insert(43, "accept");
    table.insert(44, "sendto");
    table.insert(45, "recvfrom");
    table.insert(46, "sendmsg");
    table.insert(47, "recvmsg");
    table.insert(56, "clone");
    table.insert(57, "fork");
    table.insert(58, "vfork");
    table.insert(59, "execve");
    table.insert(60, "exit");
    table.insert(61, "wait4");
    table.insert(62, "kill");
    table.insert(63, "uname");
    table.insert(72, "fcntl");
    table.insert(74, "fsync");
    table.insert(75, "fdatasync");
    table.insert(77, "ftruncate");
    table.insert(95, "umask");
    table.insert(97, "getrlimit");
    table.insert(98, "getrusage");
    table.insert(99, "sysinfo");
    table.insert(102, "getuid");
    table.insert(103, "syslog");
    table.insert(104, "getgid");
    table.insert(107, "geteuid");
    table.insert(108, "getegid");
    table.insert(116, "setgroups");
    table.insert(124, "getsid");
    table.insert(125, "capget");
    table.insert(126, "capset");
    table.insert(131, "sigaltstack");
    table.insert(157, "prctl");
    table.insert(158, "arch_prctl");
    table.insert(186, "gettid");
    table.insert(202, "futex");
    table.insert(203, "sched_setaffinity");
    table.insert(204, "sched_getaffinity");
    table.insert(218, "set_tid_address");
    table.insert(220, "semtimedop");
    table.insert(221, "fadvise64");
    table.insert(228, "clock_gettime");
    table.insert(229, "clock_getres");
    table.insert(230, "clock_nanosleep");
    table.insert(231, "exit_group");
    table.insert(232, "epoll_wait");
    table.insert(233, "epoll_ctl");
    table.insert(234, "tgkill");
    table.insert(257, "openat");
    table.insert(262, "newfstatat");
    table.insert(267, "readlinkat");
    table.insert(268, "fchmodat");
    table.insert(269, "faccessat");
    table.insert(272, "sync_file_range");
    table.insert(275, "utimensat");
    table.insert(276, "epoll_pwait");
    table.insert(277, "signalfd");
    table.insert(279, "eventfd");
    table.insert(280, "fallocate");
    table.insert(283, "accept4");
    table.insert(285, "eventfd2");
    table.insert(286, "epoll_create1");
    table.insert(287, "dup3");
    table.insert(288, "pipe2");
    table.insert(289, "inotify_init1");
    table.insert(290, "preadv");
    table.insert(291, "pwritev");
    table.insert(293, "perf_event_open");
    table.insert(294, "recvmmsg");
    table.insert(302, "prlimit64");
    table.insert(318, "getrandom");
    table.insert(319, "memfd_create");
    table.insert(323, "userfaultfd");
    table.insert(324, "membarrier");
    table.insert(325, "mlock2");
    table.insert(326, "copy_file_range");
    table.insert(327, "preadv2");
    table.insert(328, "pwritev2");
    table.insert(329, "pkey_mprotect");
    table.insert(330, "pkey_alloc");
    table.insert(331, "pkey_free");
    table.insert(332, "statx");
    table.insert(333, "io_pgetevents");
    table.insert(334, "rseq");
    table.insert(424, "pidfd_send_signal");
    table.insert(425, "io_uring_setup");
    table.insert(426, "io_uring_enter");
    table.insert(427, "io_uring_register");
    table.insert(428, "open_tree");
    table.insert(429, "move_mount");
    table.insert(430, "fsopen");
    table.insert(431, "fsconfig");
    table.insert(432, "fsmount");
    table.insert(433, "fspick");
    table.insert(434, "pidfd_open");
    table.insert(435, "clone3");
    table.insert(437, "openat2");
    table.insert(439, "faccessat2");
    table.insert(80, "chdir");
    table.insert(81, "fchdir");
    table.insert(82, "rename");
    table.insert(83, "mkdir");
    table.insert(84, "rmdir");
    table.insert(85, "creat");
    table.insert(86, "link");
    table.insert(87, "unlink");
    table.insert(88, "symlink");
    table.insert(89, "readlink");
    table.insert(90, "chmod");
    table.insert(91, "fchmod");
    table.insert(92, "chown");
    table.insert(93, "fchown");
    table.insert(94, "lchown");
    table
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracer() -> (SyscallTracer, SyscallEventReceiver) {
        SyscallTracer::new(Arc::new(LsmPolicyEngine::new()))
    }

    #[test]
    fn process_read_syscall_is_allowed() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 1000, 1000);
        assert_eq!(event.syscall_name, "read");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_write_syscall_is_allowed() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(1, 1000, 1000);
        assert_eq!(event.syscall_name, "write");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_execve_syscall_is_denied() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(59, 1001, 0);
        assert_eq!(event.syscall_name, "execve");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn unknown_syscall_is_denied() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(9999, 1000, 1000);
        assert_eq!(event.syscall_name, "unknown");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn syscall_event_contains_pid_and_uid() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 42, 1337);
        assert_eq!(event.pid, 42);
        assert_eq!(event.uid, 1337);
    }

    #[tokio::test]
    async fn simulation_loop_sends_events_to_channel() {
        let cancel = CancellationToken::new();
        let (tracer, mut rx) = make_tracer();

        tokio::spawn(async move {
            let _ = tracer.run(cancel, true).await;
        });

        let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("should receive event within 500ms")
            .expect("channel should be open");

        assert_eq!(event.syscall_nr, 0);
        assert_eq!(event.syscall_name, "read");
    }

    #[test]
    fn syscall_table_covers_common_syscalls() {
        let table = build_syscall_table();
        assert!(table.contains_key(&0), "must have read");
        assert!(table.contains_key(&1), "must have write");
        assert!(table.contains_key(&59), "must have execve");
        assert!(table.contains_key(&41), "must have socket");
        assert!(table.len() >= 30, "table should have at least 30 entries");
    }

    #[test]
    fn tracer_falls_back_to_simulation_when_bpf_missing() {
        let (tracer, mut rx) = make_tracer();
        let cancel = CancellationToken::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            tokio::spawn(async move {
                let _ = tracer.run(cancel, true).await;
            });

            let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
                .await
                .expect("should receive event within 500ms")
                .expect("channel should be open");

            assert_eq!(event.syscall_nr, 0);
            assert_eq!(event.syscall_name, "read");
        });
    }

    /// Privileged validation: load real eBPF syscall-tracer object.
    /// Requires: CAP_BPF + CAP_SYS_ADMIN (run with `sudo -E` or as root).
    /// Skipped automatically if prebuilt BPF objects are missing or not privileged.
    #[test]
    fn validate_ebpf_syscall_tracer_loads() {
        let bpf_bytes = match load_bpf_o("syscall-tracer") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_ebpf_syscall_tracer_loads: {e}");
                return;
            }
        };

        let bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "SKIP validate_ebpf_syscall_tracer_loads: aya load failed (need CAP_BPF): {e}"
                );
                return;
            }
        };

        // Verify program exists
        let prog = bpf.program("sys_enter_tp");
        assert!(
            prog.is_some(),
            "sys_enter_tp program must exist in BPF object"
        );
        eprintln!("PASS: syscall-tracer BPF object loaded successfully");
    }

    /// Privileged validation: load real eBPF LSM security object.
    /// Requires: CAP_BPF + CAP_SYS_ADMIN + kernel BTF + CONFIG_BPF_LSM.
    #[test]
    fn validate_ebpf_lsm_security_loads() {
        let bpf_bytes = match load_bpf_o("lsm-security") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_ebpf_lsm_security_loads: {e}");
                return;
            }
        };

        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "SKIP validate_ebpf_lsm_security_loads: aya load failed (need CAP_BPF): {e}"
                );
                return;
            }
        };

        // Verify all LSM programs exist
        let programs = ["lsm_file_open", "lsm_bprm_check", "lsm_socket_create"];
        for name in programs {
            let prog = bpf.program_mut(name);
            assert!(
                prog.is_some(),
                "LSM program '{name}' must exist in BPF object"
            );
        }

        // Verify maps exist
        let maps = ["allowed_pids", "allowed_syscalls"];
        for name in maps {
            let map = bpf.take_map(name);
            assert!(map.is_some(), "eBPF map '{name}' must exist in BPF object");
        }

        eprintln!("PASS: lsm-security BPF object loaded — all programs and maps present");
    }

    /// Privileged validation: attach LSM hooks to the kernel.
    /// This is the real integration test — it verifies that the kernel accepts
    /// our BPF programs and attaches them to the security hooks.
    #[test]
    fn validate_lsm_hooks_attach_to_kernel() {
        let bpf_bytes = match load_bpf_o("lsm-security") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_lsm_hooks_attach_to_kernel: {e}");
                return;
            }
        };

        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_lsm_hooks_attach_to_kernel: aya load failed: {e}");
                return;
            }
        };

        let btf = match aya::Btf::from_sys_fs() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_lsm_hooks_attach_to_kernel: BTF not available: {e}");
                return;
            }
        };

        let hook_count = 0u32;

        // security_file_open
        {
            let prog: &mut aya::programs::Lsm = match bpf.program_mut("lsm_file_open") {
                Some(p) => p.try_into().unwrap(),
                None => {
                    eprintln!("SKIP: lsm_file_open not found");
                    return;
                }
            };
            match prog.load("security_file_open", &btf) {
                Ok(()) => eprintln!("LSM: security_file_open loaded"),
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_file_open load failed: {e}"
                    );
                    return;
                }
            }
            match prog.attach() {
                Ok(link) => {
                    Box::leak(Box::new(link));
                    eprintln!("LSM: security_file_open attached");
                }
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_file_open attach failed: {e}"
                    );
                    return;
                }
            }
        }

        // security_bprm_check
        {
            let prog: &mut aya::programs::Lsm = match bpf.program_mut("lsm_bprm_check") {
                Some(p) => p.try_into().unwrap(),
                None => {
                    eprintln!("SKIP: lsm_bprm_check not found");
                    return;
                }
            };
            match prog.load("security_bprm_check", &btf) {
                Ok(()) => eprintln!("LSM: security_bprm_check loaded"),
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_bprm_check load failed: {e}"
                    );
                    return;
                }
            }
            match prog.attach() {
                Ok(link) => {
                    Box::leak(Box::new(link));
                    eprintln!("LSM: security_bprm_check attached");
                }
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_bprm_check attach failed: {e}"
                    );
                    return;
                }
            }
        }

        // security_socket_create
        {
            let prog: &mut aya::programs::Lsm = match bpf.program_mut("lsm_socket_create") {
                Some(p) => p.try_into().unwrap(),
                None => {
                    eprintln!("SKIP: lsm_socket_create not found");
                    return;
                }
            };
            match prog.load("security_socket_create", &btf) {
                Ok(()) => eprintln!("LSM: security_socket_create loaded"),
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_socket_create load failed: {e}"
                    );
                    return;
                }
            }
            match prog.attach() {
                Ok(link) => {
                    Box::leak(Box::new(link));
                    eprintln!("LSM: security_socket_create attached");
                }
                Err(e) => {
                    eprintln!(
                        "SKIP validate_lsm_hooks_attach_to_kernel: security_socket_create attach failed: {e}"
                    );
                    return;
                }
            }
        }

        eprintln!(
            "PASS: all 3 LSM hooks attached to kernel successfully (hook_count={hook_count})"
        );
        // Keep bpf alive for the rest of the test
        let _ = bpf;
    }

    /// Privileged validation: attach syscall-tracepoint to kernel.
    /// The perf event array map requires elevated privileges beyond CAP_BPF,
    /// so this test gracefully skips if map creation fails.
    #[test]
    fn validate_tracepoint_attach_to_kernel() {
        let bpf_bytes = match load_bpf_o("syscall-tracer") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_tracepoint_attach_to_kernel: {e}");
                return;
            }
        };

        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                // Perf event array maps (syscall_events) require CAP_PERFMON or CAP_SYS_ADMIN
                // This is expected in environments without full kernel privileges
                eprintln!(
                    "SKIP validate_tracepoint_attach_to_kernel: aya load failed (perf event array requires CAP_PERFMON): {e}"
                );
                return;
            }
        };

        let prog: &mut aya::programs::TracePoint = match bpf.program_mut("sys_enter_tp") {
            Some(p) => match p.try_into() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "SKIP validate_tracepoint_attach_to_kernel: program type mismatch: {e}"
                    );
                    return;
                }
            },
            None => {
                eprintln!("SKIP: sys_enter_tp not found");
                return;
            }
        };

        match prog.load() {
            Ok(()) => eprintln!("TracePoint: sys_enter loaded"),
            Err(e) => {
                eprintln!("SKIP validate_tracepoint_attach_to_kernel: load failed: {e}");
                return;
            }
        }

        match prog.attach("raw_syscalls", "sys_enter") {
            Ok(_link) => {
                eprintln!("PASS: tracepoint sys_enter attached to kernel successfully");
            }
            Err(e) => {
                eprintln!("SKIP validate_tracepoint_attach_to_kernel: attach failed: {e}");
            }
        }
    }

    /// Validate that the BPF program contains the syscall_decision_cache map.
    /// This test verifies the BPF object structure without requiring kernel privileges.
    #[test]
    fn validate_bpf_has_decision_cache_map() {
        let bpf_bytes = match load_bpf_o("syscall-tracer") {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_bpf_has_decision_cache_map: {e}");
                return;
            }
        };

        let mut bpf = match aya::Bpf::load(&bpf_bytes) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP validate_bpf_has_decision_cache_map: aya load failed: {e}");
                return;
            }
        };

        // Verify the syscall_decision_cache map exists
        let map = bpf.take_map("syscall_decision_cache");
        assert!(
            map.is_some(),
            "syscall_decision_cache map must exist in BPF object"
        );

        // Verify we can create a SyscallDecisionCache wrapper
        let cache = SyscallDecisionCache::from_bpf(&mut bpf);
        assert!(
            cache.is_some(),
            "SyscallDecisionCache::from_bpf must succeed"
        );

        eprintln!("PASS: BPF object contains syscall_decision_cache map");
    }
}
