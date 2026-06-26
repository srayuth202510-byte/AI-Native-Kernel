use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

/// B-Cell Agent — หน่วยสร้างแอนติบอดี (Antibody Generator)
///
/// ทำหน้าที่เรียนรู้รูปแบบการโจมตีจาก T-Cell threat reports:
/// - วิเคราะห์ syscall patterns ที่ถูก quarantine/killed
/// - สร้าง LSM Policy Rules (แอนติบอดี) ใหม่
/// - จดจำ attack signatures สำหรับการตรวจจับครั้งถัดไป
/// - persist learned rules ลง persistent storage

#[derive(Debug, Error)]
pub enum BCellError {
    #[error("learning failed: {0}")]
    LearningFailed(String),
}

/// Attack pattern ที่เรียนรู้ได้
#[derive(Debug, Clone)]
pub struct AttackPattern {
    /// syscall ที่เป็นส่วนหนึ่งของ attack
    pub syscalls: Vec<String>,
    /// จำนวนครั้งที่เคยเห็น pattern นี้
    pub frequency: u32,
    /// ระดับความรุนแรง (0-10)
    pub severity: u8,
    /// เวลาที่เรียนรู้ pattern นี้
    pub learned_at: Instant,
}

/// LSM Policy Rule ที่ B-Cell สร้างขึ้น
#[derive(Debug, Clone, PartialEq)]
pub struct AntibodyRule {
    /// syscall ที่จะบล็อก
    pub blocked_syscall: String,
    /// เงื่อนไขเพิ่มเติม (เช่น rate limit, PID match)
    pub condition: String,
    /// ระดับความมั่นใจ (0.0-1.0)
    pub confidence: f64,
}

/// B-Cell Agent ที่เรียนรู้ attack patterns และสร้าง antibodies
pub struct BCellAgent {
    /// รูปแบบการโจมตีที่เรียนรู้ไว้
    patterns: Arc<RwLock<VecDeque<AttackPattern>>>,
    /// Antibody Rules ที่สร้างขึ้น
    antibodies: Arc<RwLock<Vec<AntibodyRule>>>,
    /// จำนวน patterns สูงสุดที่เก็บไว้ในหน่วยความจำ
    max_patterns: usize,
}

impl BCellAgent {
    #[must_use]
    pub fn new(max_patterns: usize) -> Self {
        Self {
            patterns: Arc::new(RwLock::new(VecDeque::with_capacity(max_patterns))),
            antibodies: Arc::new(RwLock::new(Vec::new())),
            max_patterns,
        }
    }

    /// เรียนรู้จาก threat report (syscall + severity)
    #[instrument(skip(self))]
    pub async fn learn_threat(&self, syscalls: Vec<String>, severity: u8) {
        let pattern = AttackPattern {
            syscalls,
            frequency: 1,
            severity,
            learned_at: Instant::now(),
        };

        let mut patterns = self.patterns.write().await;
        if patterns.len() >= self.max_patterns {
            patterns.pop_front();
        }
        patterns.push_back(pattern.clone());
        debug!(
            syscalls = ?pattern.syscalls,
            severity = pattern.severity,
            "B-Cell: learned new attack pattern"
        );
    }

    /// สร้าง Antibody Rule จาก patterns ที่เรียนรู้ไว้
    #[instrument(skip(self))]
    pub async fn generate_antibody(&self) -> Option<AntibodyRule> {
        let patterns = self.patterns.read().await;
        let high_severity = patterns.iter().filter(|p| p.severity >= 7);

        let mut syscall_counts = std::collections::HashMap::new();
        for p in high_severity {
            for s in &p.syscalls {
                *syscall_counts.entry(s.clone()).or_insert(0u32) += 1;
            }
        }

        let (syscall, count) = syscall_counts.into_iter().max_by_key(|(_, c)| *c)?;
        if count < 3 {
            return None;
        }

        let antibody = AntibodyRule {
            blocked_syscall: syscall.clone(),
            condition: format!("rate > {}/s", count),
            confidence: (count as f64 / 10.0).min(1.0),
        };

        let mut antibodies = self.antibodies.write().await;
        if !antibodies.iter().any(|a| a.blocked_syscall == antibody.blocked_syscall) {
            antibodies.push(antibody.clone());
            debug!(syscall = %antibody.blocked_syscall, confidence = antibody.confidence, "B-Cell: generated new antibody");
            return Some(antibody);
        }

        None
    }

    /// ดู antibodies ที่สร้างไว้
    pub async fn get_antibodies(&self) -> Vec<AntibodyRule> {
        self.antibodies.read().await.clone()
    }

    /// ดู patterns ที่เรียนรู้ไว้
    pub async fn get_patterns(&self) -> Vec<AttackPattern> {
        self.patterns.read().await.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bcell() -> BCellAgent {
        BCellAgent::new(100)
    }

    #[tokio::test]
    async fn learn_and_generate_antibody() {
        let b = make_bcell();
        for _ in 0..5 {
            b.learn_threat(vec!["execve".into()], 8).await;
        }
        let antibody = b.generate_antibody().await;
        assert!(antibody.is_some());
        assert_eq!(antibody.unwrap().blocked_syscall, "execve");
    }

    #[tokio::test]
    async fn no_antibody_below_threshold() {
        let b = make_bcell();
        b.learn_threat(vec!["read".into()], 8).await;
        let antibody = b.generate_antibody().await;
        assert!(antibody.is_none());
    }

    #[tokio::test]
    async fn patterns_are_stored() {
        let b = make_bcell();
        b.learn_threat(vec!["write".into()], 3).await;
        let patterns = b.get_patterns().await;
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].syscalls, vec!["write".to_string()]);
    }
}
