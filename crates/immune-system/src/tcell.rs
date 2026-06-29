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

/// T-Cell Agent — หน่วยพิฆาต (Killer T-Cell)
///
/// ทำหน้าที่ตรวจจับพฤติกรรมผิดปกติ (Anomaly Detection) ของ Agent และ Process:
/// - ติดตามอัตราการเรียก syscall ของแต่ละ Process
/// - ตรวจจับ rate spike ที่ผิดปกติ (เช่น fork bomb, tight loop)
/// - ตรวจจับ syscall ต้องห้ามที่ถูก deny ซ้ำๆ
/// - ตรวจจับรูปแบบลำดับ syscall ที่น่าสงสัย (Suspicious Syscall Sequence)
/// - สั่ง quarantine หรือ kill process ที่น่าสงสัย

#[derive(Debug, Error)]
pub enum TCellError {
    #[error("threshold config error: {0}")]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
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

/// ข้อมูลสถิติของ Process แต่ละตัว
#[derive(Debug, Clone)]
pub struct ProcessStats {
    /// จำนวน syscall ที่เรียกในช่วง 1 วินาทีล่าสุด
    pub syscall_count: u64,
    /// จำนวนครั้งที่ถูก deny
    pub deny_count: u64,
    /// เวลาที่เริ่มต้นนับ
    pub window_start: Instant,
    /// syscall ล่าสุดที่เรียก
    pub last_syscall: Option<String>,
    /// คะแนนความผิดปกติสะสม (Anomaly Score)
    pub anomaly_score: f64,
    /// ประวัติการเรียก syscall ล่าสุด 5 รายการ
    pub syscall_history: VecDeque<String>,
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
        }
    }
}

/// T-Cell Agent ที่ตรวจจับภัยคุกคามแบบ real-time
pub struct TCellAgent {
    /// สถิติของแต่ละ PID
    stats: Arc<RwLock<HashMap<u32, ProcessStats>>>,
    /// จำนวน syscall ต่อวินาทีที่ถือว่าผิดปกติ
    rate_threshold: AtomicU64,
    /// จำนวน deny ติดต่อกันที่ถือว่าผิดปกติ
    deny_threshold: AtomicU32,
    /// คะแนน anomaly ที่ถือว่าถึงขีด kill
    kill_threshold: AtomicU32,
    /// รายการ PID ที่ถูก quarantine แล้ว
    quarantined: Arc<RwLock<HashMap<u32, Instant>>>,
    /// สถานะเปิด/ปิดการใช้งาน Immunological Jitter (ใช้ปิดในการทดสอบเพื่อผลลัพธ์ที่แน่นอน)
    jitter_enabled: AtomicBool,
}

impl TCellAgent {
    #[must_use]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub fn new(rate_threshold: u64, deny_threshold: u32) -> Self {
        Self::with_kill_threshold(rate_threshold, deny_threshold, 15)
    }

    #[must_use]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub fn with_kill_threshold(
        rate_threshold: u64,
        deny_threshold: u32,
        kill_threshold: u32,
    ) -> Self {
        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
            rate_threshold: AtomicU64::new(rate_threshold),
            deny_threshold: AtomicU32::new(deny_threshold),
            kill_threshold: AtomicU32::new(kill_threshold),
            quarantined: Arc::new(RwLock::new(HashMap::new())),
            jitter_enabled: AtomicBool::new(true),
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
    #[instrument(skip(self), fields(pid))]
    pub async fn observe_syscall(
        &self,
        pid: u32,
        syscall_name: &str,
        denied: bool,
    ) -> ThreatDecision {
        let base_rate = self.rate_threshold.load(Ordering::Relaxed);
        let base_deny = self.deny_threshold.load(Ordering::Relaxed);
        let base_kill = self.kill_threshold.load(Ordering::Relaxed);

        let (rate_limit, deny_limit, kill_limit) = if self.jitter_enabled.load(Ordering::Relaxed) {
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

        let mut stats = self.stats.write().await;
        let entry = stats.entry(pid).or_default();

        let now = Instant::now();
        let elapsed = now.duration_since(entry.window_start);

        if elapsed >= Duration::from_secs(1) {
            entry.syscall_count = 0;
            entry.window_start = now;
        }

        entry.syscall_count += 1;
        entry.last_syscall = Some(syscall_name.to_string());

        // จัดเก็บประวัติ syscall ย้อนหลัง (เก็บสูงสุด 5 รายการ)
        if entry.syscall_history.len() >= 5 {
            entry.syscall_history.pop_front();
        }
        entry.syscall_history.push_back(syscall_name.to_string());

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

        // ตัดสินใจระดับภัยคุกคามโดยอ้างอิงจากเกณฑ์ (Hard limits) และ Anomaly Score
        if entry.deny_count >= deny_limit as u64
            || (rate_limit > 0 && entry.syscall_count >= rate_limit * 2)
            || score >= kill_limit as f64
        {
            warn!(
                pid,
                score = ?score,
                deny_count = entry.deny_count,
                syscall_count = entry.syscall_count,
                "T-Cell: critical threat detected — Action: KILL"
            );
            return ThreatDecision::Kill;
        }

        if (rate_limit > 0 && entry.syscall_count >= rate_limit) || score >= 8.0 {
            warn!(
                pid,
                score = ?score,
                syscall_count = entry.syscall_count,
                "T-Cell: high syscall rate/anomaly — Action: QUARANTINE"
            );
            return ThreatDecision::Quarantine;
        }

        if entry.deny_count > 0 || score >= 2.0 {
            debug!(
                pid,
                score = ?score,
                deny_count = entry.deny_count,
                "T-Cell: suspicious syscall/anomaly — Action: WARN"
            );
            return ThreatDecision::Warn;
        }

        ThreatDecision::Safe
    }

    /// สั่ง quarantine process
    pub async fn quarantine(&self, pid: u32) {
        let mut q = self.quarantined.write().await;
        q.insert(pid, Instant::now());
        warn!(pid, "T-Cell: process quarantined");
    }

    /// ตรวจสอบว่า process ถูก quarantine หรือไม่
    #[instrument(skip(self))]
    pub async fn is_quarantined(&self, pid: u32) -> bool {
        self.quarantined.read().await.contains_key(&pid)
    }

    /// ปลด quarantine
    pub async fn release(&self, pid: u32) {
        self.quarantined.write().await.remove(&pid);
        debug!(pid, "T-Cell: quarantine released");
    }

    /// ดึงรายการ PID ทั้งหมดที่อยู่ระหว่างการกักกัน (Quarantined PIDs)
    pub async fn get_quarantined_pids(&self) -> Vec<u32> {
        self.quarantined.read().await.keys().copied().collect()
    }

    /// ปลดกักกัน process ทั้งหมดที่ถูกกักกันเกินระยะเวลาที่กำหนด (Expired quarantine auto-release)
    pub async fn release_expired_quarantine(&self, duration: Duration) -> Vec<u32> {
        let mut q = self.quarantined.write().await;
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
            debug!(pid = %pid, "T-Cell: auto-released expired quarantine");
        }
        expired
    }

    /// ดึงสถิติของ process
    pub async fn get_stats(&self, pid: u32) -> Option<ProcessStats> {
        self.stats.read().await.get(&pid).cloned()
    }
}

/// ตรวจสอบรูปแบบ syscall sequence ย้อนหลังเพื่อดูความน่าจะเป็นในการโจมตีระบบ
fn has_suspicious_sequence(history: &VecDeque<String>) -> bool {
    if history.len() < 2 {
        return false;
    }

    // 1. Privilege Escalation signature: setuid/setgid -> execve
    let mut has_setuid = false;
    for s in history {
        if s == "setuid" || s == "setgid" {
            has_setuid = true;
        } else if (s == "execve" || s == "execveat") && has_setuid {
            return true;
        }
    }

    // 2. Process Hijack/Injection signature: ptrace -> memfd_create / process_vm_writev
    let mut has_ptrace = false;
    for s in history {
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
        t
    }

    #[tokio::test]
    async fn safe_syscall_returns_safe() {
        let t = make_tcell();
        let d = t.observe_syscall(1, "read", false).await;
        assert_eq!(d, ThreatDecision::Safe);
    }

    #[tokio::test]
    async fn denied_syscall_returns_warn() {
        let t = make_tcell();
        let d = t.observe_syscall(1, "execve", true).await;
        assert_eq!(d, ThreatDecision::Warn);
    }

    #[tokio::test]
    async fn quarantine_and_release() {
        let t = make_tcell();
        assert!(!t.is_quarantined(42).await);
        t.quarantine(42).await;
        assert!(t.is_quarantined(42).await);
        t.release(42).await;
        assert!(!t.is_quarantined(42).await);
    }

    #[tokio::test]
    async fn stats_are_tracked() {
        let t = make_tcell();
        let _ = t.observe_syscall(1, "read", false).await;
        let stats = t.get_stats(1).await.unwrap();
        assert_eq!(stats.syscall_count, 1);
        assert_eq!(stats.last_syscall, Some("read".to_string()));
    }

    #[tokio::test]
    async fn dynamic_threshold_update() {
        let t = make_tcell();
        t.update_thresholds(10, 2, 15);
        // rate threshold is now 10. 10 * 2 = 20 is critical limit.
        for _ in 0..20 {
            let _ = t.observe_syscall(1, "read", false).await;
        }
        let d = t.observe_syscall(1, "read", false).await;
        assert_eq!(d, ThreatDecision::Kill);
    }

    #[tokio::test]
    async fn test_suspicious_sequence_escalation() {
        let t = make_tcell();
        t.observe_syscall(1, "setuid", false).await;
        let d = t.observe_syscall(1, "execve", false).await;
        // setuid -> execve triggers has_suspicious_sequence (+8.0 anomaly score) -> Quarantine
        assert_eq!(d, ThreatDecision::Quarantine);
    }

    #[tokio::test]
    async fn test_suspicious_sequence_reverse_shell() {
        let t = make_tcell();
        t.observe_syscall(1, "socket", false).await;
        t.observe_syscall(1, "dup2", false).await;
        let d = t.observe_syscall(1, "execve", false).await;
        // socket -> dup2 -> execve triggers reverse shell (+8.0 score) -> Quarantine
        assert_eq!(d, ThreatDecision::Quarantine);
    }

    #[tokio::test]
    async fn test_quarantine_expiry() {
        let t = make_tcell();
        t.quarantine(42).await;
        assert!(t.is_quarantined(42).await);

        // Wait a tiny bit and check expiry
        let released = t.release_expired_quarantine(Duration::from_nanos(1)).await;
        assert_eq!(released, vec![42]);
        assert!(!t.is_quarantined(42).await);
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

        let decision = t.observe_syscall(1, "read", false).await;
        assert_eq!(decision, ThreatDecision::Safe);
    }
}
