//! T-Cell Agent — หน่วยพิฆาต (Killer T-Cell)
//!
//! ทำหน้าที่ตรวจจับพฤติกรรมผิดปกติ (Anomaly Detection) ของ Agent และ Process:
//! - ติดตามอัตราการเรียก syscall ของแต่ละ Process
//! - ตรวจจับ rate spike ที่ผิดปกติ (เช่น fork bomb, tight loop)
//! - ตรวจจับ syscall ต้องห้ามที่ถูก deny ซ้ำๆ
//! - ตรวจจับรูปแบบลำดับ syscall ที่น่าสงสัย (Suspicious Syscall Sequence)
//! - สั่ง quarantine หรือ kill process ที่น่าสงสัย

use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

static JITTER_SEED: AtomicU64 = AtomicU64::new(123456789);

fn get_jitter_percentage() -> f64 {
    let old = JITTER_SEED.load(Ordering::Relaxed);
    // Simple LCG PRNG
    let new = old
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    JITTER_SEED.store(new, Ordering::Relaxed);
    // ช่วง -15% ถึง +15%
    let percent = (new % 31) as i32 - 15;
    percent as f64 / 100.0
}

/// ข้อผิดพลาดของ T-Cell Agent
#[derive(Debug, Error)]
pub enum TCellError {
    /// ค่าเกณฑ์การตรวจจับ (threshold) ไม่ถูกต้อง
    #[error("threshold config error: {0}")]
    ConfigError(String),
}

/// ผลการตัดสินใจของ T-Cell
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatDecision {
    /// ไม่พบภัยคุกคาม
    Safe,
    /// พบพฤติกรรมผิดปกติ level ต่ำ — เตือน
    Warn,
    /// พบภัยคุกคามร้ายแรง — สั่ง quarantine
    Quarantine,
    /// พบภัยคุกคามวิกฤต — สั่ง kill
    Kill,
}

/// ข้อมูลสถิติของ Process แต่ละตัว (ภายใน Tenant)
#[derive(Debug, Clone)]
pub struct ProcessStats {
    /// จำนวน syscall ที่เรียกในช่วง 1 วินาทีล่าสุด
    pub syscall_count: u64,
    /// จำนวนครั้งที่ถูก deny
    pub deny_count: u64,
    /// เวลาที่เริ่มต้นนับ
    pub window_start: Instant,
    /// syscall ล่าสุดที่เรียก
    pub last_syscall: Option<Arc<str>>,
    /// คะแนนความผิดปกติสะสม (Anomaly Score)
    pub anomaly_score: f64,
    /// ประวัติการเรียก syscall ล่าสุด 5 รายการ
    pub syscall_history: VecDeque<Arc<str>>,
    /// จำนวนวินาทีติดต่อกันที่ตรวจพบความผิดปกติ (Consecutive violation windows)
    pub consecutive_violations: u32,
}

impl Default for ProcessStats {
    fn default() -> Self {
        Self {
            syscall_count: 0,
            deny_count: 0,
            window_start: Instant::now(),
            last_syscall: None,
            anomaly_score: 0.0,
            syscall_history: VecDeque::with_capacity(5),
            consecutive_violations: 0,
        }
    }
}

/// สถิติรวมของ Tenant (รวมทุก PID ใน Tenant นั้น)
#[derive(Default)]
struct TenantState {
    /// สถิติต่อ PID ภายใน Tenant นี้
    pids: DashMap<u32, ProcessStats>,
    /// PID ที่ถูก quarantine ภายใน Tenant นี้
    quarantined: Arc<RwLock<HashMap<u32, Instant>>>,
}

/// T-Cell Agent ที่ตรวจจับภัยคุกคามแบบ real-time
pub struct TCellAgent {
    /// สถิติของแต่ละ Tenant — ใช้ DashMap เพื่อ lock ราย shard
    tenants: DashMap<String, TenantState>,
    /// จำนวน syscall ต่อวินาทีที่ถือว่าผิดปกติ (base rate)
    rate_threshold: AtomicU64,
    /// จำนวน deny ติดต่อกันที่ถือว่าผิดปกติ
    deny_threshold: AtomicU32,
    /// คะแนน anomaly ที่ถือว่าถึงขีด kill
    kill_threshold: AtomicU32,
    /// สถานะเปิด/ปิดการใช้งาน Immunological Jitter
    jitter_enabled: AtomicBool,
    /// รายชื่อโปรเซสที่ได้รับการยกเว้นจากการ Kill (Exempted processes) — global
    exempt_processes: Arc<RwLock<std::collections::HashSet<String>>>,
    /// รายการ PID ที่ได้รับการยกเว้นจากการ Kill (Exempted PIDs) — global
    exempt_pids: Arc<RwLock<std::collections::HashSet<u32>>>,
    /// จำนวนวินาทีติดต่อกันที่ต้องตรวจพบความผิดปกติก่อนตัดสินใจ Kill
    violation_window_limit: AtomicU32,
    /// ปรับสัดส่วนการตรวจจับ (Sensitivity factor) ต่อ PID — global
    pid_sensitivity_factors: DashMap<u32, f64>,
}

impl TCellAgent {
    /// สร้าง T-Cell ด้วยเกณฑ์ syscall rate และ deny count (kill threshold ดีฟอลต์ = 15)
    #[must_use]
    pub fn new(rate_threshold: u64, deny_threshold: u32) -> Self {
        Self::with_kill_threshold(rate_threshold, deny_threshold, 15)
    }

    /// สร้าง T-Cell พร้อมระบุเกณฑ์ deny สะสมที่จะยกระดับจาก quarantine เป็น kill
    #[must_use]
    pub fn with_kill_threshold(
        rate_threshold: u64,
        deny_threshold: u32,
        kill_threshold: u32,
    ) -> Self {
        Self {
            tenants: DashMap::new(),
            rate_threshold: AtomicU64::new(rate_threshold),
            deny_threshold: AtomicU32::new(deny_threshold),
            kill_threshold: AtomicU32::new(kill_threshold),
            jitter_enabled: AtomicBool::new(true),
            exempt_processes: Arc::new(RwLock::new(
                vec![
                    "systemd".to_string(),
                    "init".to_string(),
                    "kernel-companion".to_string(),
                    "ank-companion".to_string(),
                    "cargo".to_string(),
                    "rustc".to_string(),
                    "bash".to_string(),
                    "sshd".to_string(),
                ]
                .into_iter()
                .collect(),
            )),
            exempt_pids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            violation_window_limit: AtomicU32::new(3),
            pid_sensitivity_factors: DashMap::new(),
        }
    }

    /// กำหนดว่าเปิดใช้งาน Immunological Jitter หรือไม่
    pub fn set_jitter_enabled(&self, enabled: bool) {
        self.jitter_enabled.store(enabled, Ordering::Relaxed);
    }

    /// อัปเดตขีดจำกัดความปลอดภัยของ T-Cell แบบ thread-safe
    pub fn update_thresholds(&self, rate_threshold: u64, deny_threshold: u32, kill_threshold: u32) {
        self.rate_threshold.store(rate_threshold, Ordering::Relaxed);
        self.deny_threshold.store(deny_threshold, Ordering::Relaxed);
        self.kill_threshold.store(kill_threshold, Ordering::Relaxed);
        debug!(
            rate_threshold,
            deny_threshold, kill_threshold, "T-Cell: thresholds updated dynamically"
        );
    }

    /// บันทึก syscall event และตัดสินใจว่ามีภัยคุกคามหรือไม่
    ///
    /// อาร์กิวเมนต์:
    /// - `tenant_id`: รหัสผู้เช่า (เช่น "acme", "globex") — ใช้เป็นมิติหลักของการตรวจจับ
    /// - `pid`: Process ID — ใช้ระบุ process สำหรับ quarantine/kill
    /// - `syscall_name`: ชื่อ syscall ที่เรียก
    /// - `denied`: ว่า syscall นี้ถูกปฏิเสธหรือไม่
    #[instrument(skip(self), fields(tenant = %tenant_id, pid))]
    pub async fn observe_syscall(
        &self,
        tenant_id: &str,
        pid: u32,
        syscall_name: &str,
        denied: bool,
    ) -> ThreatDecision {
        let base_rate = self.rate_threshold.load(Ordering::Relaxed);
        let base_deny = self.deny_threshold.load(Ordering::Relaxed);
        let base_kill = self.kill_threshold.load(Ordering::Relaxed);

        let (mut rate_limit, mut deny_limit, mut kill_limit) =
            if self.jitter_enabled.load(Ordering::Relaxed) {
                let jitter = get_jitter_percentage();
                let rate = if base_rate > 0 {
                    ((base_rate as f64) * (1.0 + jitter)).round() as u64
                } else {
                    0
                };
                let deny = ((base_deny as f64) * (1.0 + jitter)).round().max(1.0) as u32;
                let kill = ((base_kill as f64) * (1.0 + jitter)).round().max(1.0) as u32;
                (rate, deny, kill)
            } else {
                (base_rate, base_deny, base_kill)
            };

        // Apply dynamic sensitivity factor for this PID (Blast Radius Minimization)
        let sensitivity = self
            .pid_sensitivity_factors
            .get(&pid)
            .map(|factor| *factor)
            .unwrap_or(1.0);
        rate_limit = (rate_limit as f64 * sensitivity).round() as u64;
        deny_limit = (deny_limit as f64 * sensitivity).round().max(1.0) as u32;
        kill_limit = (kill_limit as f64 * sensitivity).round().max(1.0) as u32;

        // อัปเดตสถิติภายใต้ shard lock ของ TenantState
        // ห้ามมี await ระหว่างถือ entry guard — คัดลอกค่าที่ต้องใช้ออกมาก่อนปล่อย lock
        let (score, deny_count, syscall_count, total_violations) = {
            // เข้าถึง TenantState ของ tenant นี้
            let tenant_state = self.tenants.entry(tenant_id.to_string()).or_default();
            let mut entry = tenant_state.pids.entry(pid).or_default();

            let now = Instant::now();
            let elapsed = now.duration_since(entry.window_start);

            if elapsed >= Duration::from_secs(1) {
                // Check if previous window constituted a violation
                let prev_violating = entry.deny_count >= deny_limit as u64
                    || (rate_limit > 0 && entry.syscall_count >= rate_limit * 2)
                    || entry.anomaly_score >= kill_limit as f64;

                if prev_violating {
                    entry.consecutive_violations += 1;
                } else {
                    entry.consecutive_violations = 0;
                }
                entry.syscall_count = 0;
                entry.window_start = now;
            }

            // allocate ครั้งเดียวต่อ event แล้วแชร์ผ่าน Arc<str>
            let name: Arc<str> = Arc::from(syscall_name);
            entry.syscall_count += 1;
            entry.last_syscall = Some(Arc::clone(&name));

            // จัดเก็บประวัติ syscall ย้อนหลัง (เก็บสูงสุด 5 รายการ)
            if entry.syscall_history.len() >= 5 {
                entry.syscall_history.pop_front();
            }
            entry.syscall_history.push_back(name);

            if denied {
                entry.deny_count += 1;
            } else {
                entry.deny_count = 0;
            }

            // คำนวณ Anomaly Score แบบไดนามิก
            let mut score = 0.0;

            // 1. ผลกระทบจากปริมาณ syscall (Syscall Rate contribution)
            if rate_limit > 0 {
                score += (entry.syscall_count as f64 / rate_limit as f64) * 4.0;
            }

            // 2. ผลกระทบจากการเรียกปฏิเสธ (Deny count contribution)
            // Capped at deny_limit to prevent unbounded score growth
            let capped_deny = entry.deny_count.min(deny_limit as u64);
            score += capped_deny as f64 * 2.0;

            // 3. ผลกระทบจากลำดับการเรียกที่น่าสงสัย (Suspicious sequence contribution)
            if has_suspicious_sequence(&entry.syscall_history) {
                score += 8.0;
            }

            entry.anomaly_score = score;

            // ตัดสินใจระดับภัยคุกคามโดยอ้างอิงจากเกณฑ์ (Hard limits), Consecutive Violations และ Anomaly Score
            let current_violating = entry.deny_count >= deny_limit as u64
                || (rate_limit > 0 && entry.syscall_count >= rate_limit * 2)
                || score >= kill_limit as f64;

            let total_violations =
                entry.consecutive_violations + if current_violating { 1 } else { 0 };
            (
                score,
                entry.deny_count,
                entry.syscall_count,
                total_violations,
            )
        };

        let violation_limit = self.violation_window_limit.load(Ordering::Relaxed);

        if total_violations >= violation_limit {
            // Check if process is exempted from being terminated (Blast Radius Minimization)
            let is_exempt = {
                let pids = self.exempt_pids.read().await;
                if pids.contains(&pid) {
                    true
                } else {
                    let name_opt = get_process_comm(pid);
                    let exempt = self.exempt_processes.read().await;
                    if let Some(ref name) = name_opt {
                        exempt.contains(name)
                    } else {
                        false
                    }
                }
            };

            if is_exempt {
                warn!(
                    pid,
                    process_name = ?get_process_comm(pid),
                    "T-Cell: critical threat detected, but process is EXEMPTED from killing. Downgrading to WARN."
                );
                return ThreatDecision::Warn;
            }

            warn!(
                pid,
                score = ?score,
                deny_count,
                syscall_count,
                consecutive_violations = total_violations,
                "T-Cell: critical threat detected — Action: KILL"
            );
            return ThreatDecision::Kill;
        }

        if (rate_limit > 0 && syscall_count >= rate_limit) || score >= 8.0 {
            warn!(
                pid,
                score = ?score,
                syscall_count,
                "T-Cell: high syscall rate/anomaly — Action: QUARANTINE"
            );
            return ThreatDecision::Quarantine;
        }

        if deny_count > 0 || score >= 2.0 {
            debug!(
                pid,
                score = ?score,
                deny_count,
                "T-Cell: suspicious syscall/anomaly — Action: WARN"
            );
            return ThreatDecision::Warn;
        }

        ThreatDecision::Safe
    }

    /// สั่ง quarantine process ภายใน Tenant
    pub async fn quarantine(&self, tenant_id: &str, pid: u32) {
        // ห้าม await ขณะถือ DashMap guard: `entry`/`get` จับ shard lock ที่
        // block ฝั่ง OS (parking_lot) — worker ที่ถูก park ค้างใน shard จะ
        // ไม่ได้ poll task ที่ถือ tokio lock อยู่ เกิด deadlock ทั้ง runtime
        // ใต้ load ขนาน จึง clone `Arc` ออกมาก่อนแล้วค่อย await ข้างนอก guard
        // เสมอ (`quarantined` ถูกห่อเป็น `Arc` ไว้เพื่อการนี้โดยเฉพาะ)
        let lock = {
            let tenant_state = self.tenants.entry(tenant_id.to_string()).or_default();
            Arc::clone(&tenant_state.quarantined)
        };
        lock.write().await.insert(pid, Instant::now());
        warn!(tenant = %tenant_id, pid, "T-Cell: process quarantined");
    }

    /// ตรวจสอบว่า process ถูก quarantine หรือไม่ภายใน Tenant
    #[instrument(skip(self))]
    pub async fn is_quarantined(&self, tenant_id: &str, pid: u32) -> bool {
        let lock = self
            .tenants
            .get(tenant_id)
            .map(|s| Arc::clone(&s.quarantined));
        match lock {
            Some(lock) => lock.read().await.contains_key(&pid),
            None => false,
        }
    }

    /// ปลด quarantine ภายใน Tenant
    ///
    /// เช่นเดียวกับ `quarantine`: clone `Arc` ออกจาก DashMap guard ก่อน
    /// await (ดูเหตุผลเรื่อง deadlock ในคอมเมนต์ของ `quarantine`)
    pub async fn release(&self, tenant_id: &str, pid: u32) {
        let lock = self
            .tenants
            .get(tenant_id)
            .map(|s| Arc::clone(&s.quarantined));
        if let Some(lock) = lock {
            lock.write().await.remove(&pid);
            debug!(tenant = %tenant_id, pid, "T-Cell: quarantine released");
        }
    }

    /// ดึงรายการ PID ทั้งหมดที่อยู่ระหว่างการกักกันใน Tenant
    pub async fn get_quarantined_pids(&self, tenant_id: &str) -> Vec<u32> {
        let lock = self
            .tenants
            .get(tenant_id)
            .map(|s| Arc::clone(&s.quarantined));
        match lock {
            Some(lock) => lock.read().await.keys().copied().collect(),
            None => Vec::new(),
        }
    }

    /// ปลดกักกัน process ทั้งหมดที่ถูกกักกันเกินระยะเวลาที่กำหนดใน Tenant (Expired quarantine auto-release)
    pub async fn release_expired_quarantine(
        &self,
        tenant_id: &str,
        duration: Duration,
    ) -> Vec<u32> {
        // clone `Arc` ออกจาก DashMap guard ก่อน await — ดู `quarantine`
        let lock = self
            .tenants
            .get(tenant_id)
            .map(|s| Arc::clone(&s.quarantined));
        if let Some(lock) = lock {
            let mut q = lock.write().await;
            let now = Instant::now();
            let mut expired = Vec::new();

            q.retain(|pid, timestamp| {
                if now.duration_since(*timestamp) >= duration {
                    expired.push(*pid);
                    false // Remove from quarantined map
                } else {
                    true // Keep in quarantined map
                }
            });

            for pid in &expired {
                debug!(tenant = %tenant_id, pid = %pid, "T-Cell: auto-released expired quarantine");
            }
            expired
        } else {
            Vec::new()
        }
    }

    /// ดึงสถิติของ process ใน Tenant
    #[must_use]
    pub fn get_stats(&self, tenant_id: &str, pid: u32) -> Option<ProcessStats> {
        self.tenants
            .get(tenant_id)
            .and_then(|ts| ts.pids.get(&pid).map(|e| e.clone()))
    }

    /// ดึงรายการ tenant_id ทั้งหมด
    #[must_use]
    pub fn tenant_ids(&self) -> Vec<String> {
        self.tenants.iter().map(|e| e.key().clone()).collect()
    }

    /// เพิ่มรายชื่อโปรเซสที่ได้รับการยกเว้นจากการ Kill (Exempt from Kill)
    pub async fn add_exempt_process(&self, name: impl Into<String>) {
        self.exempt_processes.write().await.insert(name.into());
    }

    /// เพิ่ม PID ที่ได้รับการยกเว้นจากการ Kill (Exempt from Kill)
    pub async fn add_exempt_pid(&self, pid: u32) {
        self.exempt_pids.write().await.insert(pid);
    }

    /// กำหนดเกณฑ์จำนวนวินาทีติดต่อกันในการเกิดความผิดปกติก่อนสั่ง Kill
    pub fn set_violation_window_limit(&self, limit: u32) {
        self.violation_window_limit.store(limit, Ordering::Relaxed);
    }

    /// กำหนดค่า Sensitivity Factor สำหรับ PID เจาะจง
    pub fn set_pid_sensitivity_factor(&self, pid: u32, factor: f64) {
        self.pid_sensitivity_factors.insert(pid, factor);
    }
}

fn get_process_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// ตรวจสอบรูปแบบ syscall sequence ย้อนหลังเพื่อดูความน่าจะเป็นในการโจมตีระบบ
fn has_suspicious_sequence(history: &VecDeque<Arc<str>>) -> bool {
    if history.len() < 2 {
        return false;
    }

    // 1. Privilege Escalation signature: setuid/setgid -> execve
    let mut has_setuid = false;
    for s in history {
        let s = s.as_ref();
        if s == "setuid" || s == "setgid" {
            has_setuid = true;
        } else if (s == "execve" || s == "execveat") && has_setuid {
            return true;
        }
    }

    // 2. Process Hijack/Injection signature: ptrace -> memfd_create / process_vm_writev
    let mut has_ptrace = false;
    for s in history {
        let s = s.as_ref();
        if s == "ptrace" {
            has_ptrace = true;
        } else if (s == "memfd_create" || s == "process_vm_writev") && has_ptrace {
            return true;
        }
    }

    // 3. Reverse Shell signature: socket/connect -> dup2/dup3 -> execve
    let mut has_socket = false;
    let mut has_dup = false;
    for s in history {
        let s = s.as_ref();
        if s == "socket" || s == "connect" {
            has_socket = true;
        } else if (s == "dup2" || s == "dup3") && has_socket {
            has_dup = true;
        } else if (s == "execve" || s == "execveat") && has_socket && has_dup {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcell() -> TCellAgent {
        let t = TCellAgent::new(100, 5);
        t.set_jitter_enabled(false);
        t.set_violation_window_limit(1);
        t
    }

    const TEST_TENANT: &str = "test";

    #[tokio::test]
    async fn safe_syscall_returns_safe() {
        let t = make_tcell();
        let d = t.observe_syscall(TEST_TENANT, 1, "read", false).await;
        assert_eq!(d, ThreatDecision::Safe);
    }

    #[tokio::test]
    async fn denied_syscall_returns_warn() {
        let t = make_tcell();
        let d = t.observe_syscall(TEST_TENANT, 1, "execve", true).await;
        assert_eq!(d, ThreatDecision::Warn);
    }

    #[tokio::test]
    async fn quarantine_and_release() {
        let t = make_tcell();
        assert!(!t.is_quarantined(TEST_TENANT, 42).await);
        t.quarantine(TEST_TENANT, 42).await;
        assert!(t.is_quarantined(TEST_TENANT, 42).await);
        t.release(TEST_TENANT, 42).await;
        assert!(!t.is_quarantined(TEST_TENANT, 42).await);
    }

    #[tokio::test]
    async fn stats_are_tracked() {
        let t = make_tcell();
        let _ = t.observe_syscall(TEST_TENANT, 1, "read", false).await;
        let stats = t.get_stats(TEST_TENANT, 1).unwrap();
        assert_eq!(stats.syscall_count, 1);
        assert_eq!(stats.last_syscall.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn dynamic_threshold_update() {
        let t = make_tcell();
        t.update_thresholds(10, 2, 15);
        // rate threshold is now 10. 10 * 2 = 20 is critical limit.
        for _ in 0..20 {
            let _ = t.observe_syscall(TEST_TENANT, 999, "read", false).await;
        }
        let d = t.observe_syscall(TEST_TENANT, 999, "read", false).await;
        assert_eq!(d, ThreatDecision::Kill);
    }

    #[tokio::test]
    async fn test_suspicious_sequence_escalation() {
        let t = make_tcell();
        t.observe_syscall(TEST_TENANT, 1, "setuid", false).await;
        let d = t.observe_syscall(TEST_TENANT, 1, "execve", false).await;
        // setuid -> execve triggers has_suspicious_sequence (+8.0 anomaly score) -> Quarantine
        assert_eq!(d, ThreatDecision::Quarantine);
    }

    #[tokio::test]
    async fn test_suspicious_sequence_reverse_shell() {
        let t = make_tcell();
        t.observe_syscall(TEST_TENANT, 1, "socket", false).await;
        t.observe_syscall(TEST_TENANT, 1, "dup2", false).await;
        let d = t.observe_syscall(TEST_TENANT, 1, "execve", false).await;
        // socket -> dup2 -> execve triggers reverse shell (+8.0 score) -> Quarantine
        assert_eq!(d, ThreatDecision::Quarantine);
    }

    #[tokio::test]
    async fn test_quarantine_expiry() {
        let t = make_tcell();
        t.quarantine(TEST_TENANT, 42).await;
        assert!(t.is_quarantined(TEST_TENANT, 42).await);

        // Wait a tiny bit and check expiry
        let released = t
            .release_expired_quarantine(TEST_TENANT, Duration::from_nanos(1))
            .await;
        assert_eq!(released, vec![42]);
        assert!(!t.is_quarantined(TEST_TENANT, 42).await);
    }

    #[tokio::test]
    async fn test_immunological_jitter() {
        let t = TCellAgent::new(100, 5); // Jitter is enabled by default

        // We will sample jitter multiple times to verify fluctuation
        let percent1 = get_jitter_percentage();
        let percent2 = get_jitter_percentage();
        assert_ne!(
            percent1, percent2,
            "Jitter should produce fluctuating values!"
        );

        let decision = t.observe_syscall(TEST_TENANT, 1, "read", false).await;
        assert_eq!(decision, ThreatDecision::Safe);
    }

    #[tokio::test]
    async fn test_consecutive_violations_required_for_kill() {
        let t = TCellAgent::new(10, 2);
        t.set_jitter_enabled(false);
        t.set_violation_window_limit(3);

        // 1st window violation
        for _ in 0..21 {
            let _ = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        }
        let decision1 = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        assert_ne!(decision1, ThreatDecision::Kill);

        // Advance window
        if let Some(tenant_state) = t.tenants.get(TEST_TENANT) {
            if let Some(mut entry) = tenant_state.pids.get_mut(&101) {
                entry.window_start -= Duration::from_secs(2);
            }
        }

        // 2nd window violation
        for _ in 0..21 {
            let _ = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        }
        let decision2 = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        assert_ne!(decision2, ThreatDecision::Kill);

        // Advance window again
        if let Some(tenant_state) = t.tenants.get(TEST_TENANT) {
            if let Some(mut entry) = tenant_state.pids.get_mut(&101) {
                entry.window_start -= Duration::from_secs(2);
            }
        }

        // 3rd window violation -> should trigger KILL
        for _ in 0..21 {
            let _ = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        }
        let decision3 = t.observe_syscall(TEST_TENANT, 101, "read", false).await;
        assert_eq!(decision3, ThreatDecision::Kill);
    }

    #[tokio::test]
    async fn test_system_process_exemption() {
        let t = TCellAgent::new(10, 2);
        t.set_jitter_enabled(false);
        t.set_violation_window_limit(1);

        let own_pid = std::process::id();
        t.add_exempt_pid(own_pid).await;

        // Generate enough violations to trigger Kill
        for _ in 0..25 {
            let _ = t.observe_syscall(TEST_TENANT, own_pid, "read", false).await;
        }
        let decision = t.observe_syscall(TEST_TENANT, own_pid, "read", false).await;

        // Should be downgraded to Warn instead of Kill because our process is exempted!
        assert_eq!(decision, ThreatDecision::Warn);
    }

    #[tokio::test]
    async fn test_pid_sensitivity_factor() {
        let t = TCellAgent::new(10, 2);
        t.set_jitter_enabled(false);
        t.set_violation_window_limit(1);

        // Set sensitivity factor to 2.0 (double threshold)
        t.set_pid_sensitivity_factor(200, 2.0);

        for _ in 0..30 {
            let _ = t.observe_syscall(TEST_TENANT, 200, "read", false).await;
        }
        let decision1 = t.observe_syscall(TEST_TENANT, 200, "read", false).await;
        assert_ne!(decision1, ThreatDecision::Kill);

        for _ in 0..10 {
            let _ = t.observe_syscall(TEST_TENANT, 200, "read", false).await;
        }
        let decision2 = t.observe_syscall(TEST_TENANT, 200, "read", false).await;
        assert_eq!(decision2, ThreatDecision::Kill);
    }

    #[tokio::test]
    async fn test_multi_tenant_isolation() {
        let t = make_tcell();
        // Use low threshold for test: 5 syscalls/sec triggers quarantine
        t.update_thresholds(5, 5, 10);

        // Tenant A generates high syscall rate
        for _ in 0..6 {
            let _ = t.observe_syscall("tenant_a", 100, "read", false).await;
        }
        let d_a = t.observe_syscall("tenant_a", 100, "read", false).await;
        // Tenant A should be quarantined (exceeds rate limit of 5)
        assert_eq!(d_a, ThreatDecision::Quarantine);

        // Tenant B should be unaffected (different tenant, separate counting)
        for _ in 0..6 {
            let _ = t.observe_syscall("tenant_b", 200, "read", false).await;
        }
        let d_b = t.observe_syscall("tenant_b", 200, "read", false).await;
        // Tenant B also gets quarantined independently (same threshold, separate counting)
        assert_eq!(d_b, ThreatDecision::Quarantine);
    }

    #[tokio::test]
    async fn test_quarantine_per_tenant() {
        let t = make_tcell();
        t.quarantine("tenant_a", 100).await;
        assert!(t.is_quarantined("tenant_a", 100).await);
        // Different tenant should not see the quarantine
        assert!(!t.is_quarantined("tenant_b", 100).await);
        // Different PID in same tenant should not be quarantined
        assert!(!t.is_quarantined("tenant_a", 200).await);
    }
}
