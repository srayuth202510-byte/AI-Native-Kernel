use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

/// T-Cell Agent — หน่วยพิฆาต (Killer T-Cell)
///
/// ทำหน้าที่ตรวจจับพฤติกรรมผิดปกติ (Anomaly Detection) ของ Agent และ Process:
/// - ติดตามอัตราการเรียก syscall ของแต่ละ Process
/// - ตรวจจับ rate spike ที่ผิดปกติ (เช่น fork bomb, tight loop)
/// - ตรวจจับ syscall ต้องห้ามที่ถูก deny ซ้ำๆ
/// - สั่ง quarantine หรือ kill process ที่น่าสงสัย

#[derive(Debug, Error)]
pub enum TCellError {
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
}

impl Default for ProcessStats {
    fn default() -> Self {
        Self {
            syscall_count: 0,
            deny_count: 0,
            window_start: Instant::now(),
            last_syscall: None,
        }
    }
}

/// T-Cell Agent ที่ตรวจจับภัยคุกคามแบบ real-time
pub struct TCellAgent {
    /// สถิติของแต่ละ PID
    stats: Arc<RwLock<HashMap<u32, ProcessStats>>>,
    /// จำนวน syscall ต่อวินาทีที่ถือว่าผิดปกติ
    rate_threshold: u64,
    /// จำนวน deny ติดต่อกันที่ถือว่าผิดปกติ
    deny_threshold: u32,
    /// รายการ PID ที่ถูก quarantine แล้ว
    quarantined: Arc<RwLock<HashMap<u32, Instant>>>,
}

impl TCellAgent {
    #[must_use]
    pub fn new(rate_threshold: u64, deny_threshold: u32) -> Self {
        Self {
            stats: Arc::new(RwLock::new(HashMap::new())),
            rate_threshold,
            deny_threshold,
            quarantined: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// บันทึก syscall event และตัดสินใจว่ามีภัยคุกคามหรือไม่
    #[instrument(skip(self), fields(pid))]
    pub async fn observe_syscall(
        &self,
        pid: u32,
        syscall_name: &str,
        denied: bool,
    ) -> ThreatDecision {
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

        if denied {
            entry.deny_count += 1;
        } else {
            entry.deny_count = 0;
        }

        // ตัดสินใจระดับภัยคุกคาม
        if entry.deny_count >= self.deny_threshold as u64 {
            warn!(
                pid,
                deny_count = entry.deny_count,
                "T-Cell: critical threat — multiple denied syscalls"
            );
            return ThreatDecision::Kill;
        }

        if entry.syscall_count >= self.rate_threshold * 2 {
            warn!(
                pid,
                rate = entry.syscall_count,
                "T-Cell: critical threat — extreme syscall rate"
            );
            return ThreatDecision::Kill;
        }

        if entry.syscall_count >= self.rate_threshold {
            warn!(
                pid,
                rate = entry.syscall_count,
                "T-Cell: high syscall rate — quarantine recommended"
            );
            return ThreatDecision::Quarantine;
        }

        if entry.deny_count > 0 {
            debug!(pid, deny_count = entry.deny_count, "T-Cell: denied syscall");
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

    /// ดึงสถิติของ process
    pub async fn get_stats(&self, pid: u32) -> Option<ProcessStats> {
        self.stats.read().await.get(&pid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcell() -> TCellAgent {
        TCellAgent::new(100, 5)
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
        t.observe_syscall(1, "read", false).await;
        t.observe_syscall(1, "write", false).await;
        let stats = t.get_stats(1).await.unwrap();
        assert_eq!(stats.syscall_count, 2);
        assert_eq!(stats.last_syscall.as_deref(), Some("write"));
    }
}
