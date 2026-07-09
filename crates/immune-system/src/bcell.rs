//! B-Cell Agent — หน่วยสร้างแอนติบอดี (Antibody Generator)
//!
//! ทำหน้าที่เรียนรู้รูปแบบการโจมตีจาก T-Cell threat reports:
//! - วิเคราะห์ syscall patterns ที่ถูก quarantine/killed
//! - สร้าง LSM Policy Rules (แอนติบอดี) ใหม่
//! - จดจำ attack signatures สำหรับการตรวจจับครั้งถัดไป
//! - persist learned rules ลง persistent storage

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

/// ข้อผิดพลาดของ B-Cell Agent
#[derive(Debug, Error)]
pub enum BCellError {
    /// การเรียนรู้ pattern จากประวัติ syscall ล้มเหลว
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

/// Shadow Antibody — Antibody ที่อยู่ในโหมดสังเกตการณ์ก่อน enforce
///
/// ใช้สำหรับทดสอบว่า antibody จะทำให้เกิด false positive หรือไม่
/// โดยจะ log เหตุการณ์ที่ควรจะถูก block แต่ยังไม่ block จริง
#[derive(Debug, Clone)]
pub struct ShadowAntibody {
    /// Antibody rule ที่จะ enforce เมื่อผ่าน shadow period
    pub rule: AntibodyRule,
    /// เวลาที่สร้าง shadow antibody
    pub created_at: Instant,
    /// ระยะเวลา observation window
    pub observation_window: Duration,
    /// จำนวนครั้งที่ shadow antibody ได้บันทึกเหตุการณ์ที่ควร block
    pub observed_deny_count: u64,
    /// จำนวนครั้งที่ shadow antibody ได้บันทึกเหตุการณ์ที่ไม่ควร block (false positive)
    pub observed_allow_count: u64,
}

impl ShadowAntibody {
    /// สร้าง ShadowAntibody ใหม่จาก AntibodyRule
    #[must_use]
    pub fn new(rule: AntibodyRule, observation_window: Duration) -> Self {
        Self {
            rule,
            created_at: Instant::now(),
            observation_window,
            observed_deny_count: 0,
            observed_allow_count: 0,
        }
    }

    /// ตรวจสอบว่า shadow period หมดอายุแล้วหรือยัง
    #[must_use]
    pub fn is_observation_complete(&self) -> bool {
        self.created_at.elapsed() >= self.observation_window
    }

    /// ตรวจสอบว่า antibody ควรถูก promote ไป enforce หรือไม่
    /// เงื่อนไข: observation window หมดอายุ AND confidence >= threshold
    #[must_use]
    pub fn should_promote(&self, confidence_threshold: f64) -> bool {
        self.is_observation_complete() && self.rule.confidence >= confidence_threshold
    }

    /// คำนวณ false positive rate (อัตราส่วนของ allow ต่อ total observations)
    #[must_use]
    pub fn false_positive_rate(&self) -> f64 {
        let total = self.observed_deny_count + self.observed_allow_count;
        if total == 0 {
            0.0
        } else {
            self.observed_allow_count as f64 / total as f64
        }
    }

    /// บันทึกเหตุการณ์ที่ shadow antibody ได้สังเกตเห็น
    pub fn record_observation(&mut self, would_block: bool) {
        if would_block {
            self.observed_deny_count += 1;
        } else {
            self.observed_allow_count += 1;
        }
    }
}

/// B-Cell Agent ที่เรียนรู้ attack patterns และสร้าง antibodies
pub struct BCellAgent {
    /// รูปแบบการโจมตีที่เรียนรู้ไว้
    patterns: Arc<RwLock<VecDeque<AttackPattern>>>,
    /// Antibody Rules ที่สร้างขึ้น (enforce mode)
    antibodies: Arc<RwLock<Vec<AntibodyRule>>>,
    /// Shadow Antibodies ที่อยู่ในโหมดสังเกตการณ์
    shadow_antibodies: Arc<RwLock<Vec<ShadowAntibody>>>,
    /// จำนวน patterns สูงสุดที่เก็บไว้ในหน่วยความจำ
    max_patterns: usize,
    /// ระยะเวลา observation window สำหรับ shadow mode
    shadow_observation_window: Duration,
    /// Confidence threshold สำหรับการ promote จาก shadow → enforce
    promote_confidence_threshold: f64,
    /// False positive rate threshold — ถ้า shadow antibody มี FPR สูงกว่านี้จะไม่ promote
    max_false_positive_rate: f64,
}

impl BCellAgent {
    /// สร้าง B-Cell ด้วยค่า shadow mode ดีฟอลต์ (สังเกต 60 วิ, promote เมื่อ confidence ≥ 0.7, FPR ≤ 0.1)
    #[must_use]
    pub fn new(max_patterns: usize) -> Self {
        Self::with_shadow_config(max_patterns, Duration::from_secs(60), 0.7, 0.1)
    }

    /// สร้าง BCellAgent พร้อม shadow mode configuration
    #[must_use]
    pub fn with_shadow_config(
        max_patterns: usize,
        shadow_observation_window: Duration,
        promote_confidence_threshold: f64,
        max_false_positive_rate: f64,
    ) -> Self {
        Self {
            patterns: Arc::new(RwLock::new(VecDeque::with_capacity(max_patterns))),
            antibodies: Arc::new(RwLock::new(Vec::new())),
            shadow_antibodies: Arc::new(RwLock::new(Vec::new())),
            max_patterns,
            shadow_observation_window,
            promote_confidence_threshold,
            max_false_positive_rate,
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
    ///
    /// Antibody ที่สร้างจะเข้าสู่ shadow mode ก่อน เพื่อสังเกตการณ์ว่า
    /// จะทำให้เกิด false positive หรือไม่ ก่อนที่จะ enforce จริง
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

        // ตรวจสอบว่ามี shadow antibody หรือ enforce antibody สำหรับ syscall นี้แล้วหรือยัง
        let shadow = self.shadow_antibodies.read().await;
        let antibodies = self.antibodies.read().await;

        let already_exists = shadow
            .iter()
            .any(|s| s.rule.blocked_syscall == antibody.blocked_syscall)
            || antibodies
                .iter()
                .any(|a| a.blocked_syscall == antibody.blocked_syscall);

        drop(shadow);
        drop(antibodies);

        if !already_exists {
            // สร้าง shadow antibody แทน enforce antibody
            let shadow_ab = ShadowAntibody::new(antibody.clone(), self.shadow_observation_window);
            self.shadow_antibodies.write().await.push(shadow_ab);
            info!(
                syscall = %antibody.blocked_syscall,
                confidence = antibody.confidence,
                observation_window_secs = self.shadow_observation_window.as_secs(),
                "B-Cell: generated shadow antibody — entering observation mode"
            );
            return Some(antibody);
        }

        None
    }

    /// บันทึกเหตุการณ์สำหรับ shadow antibody ที่ตรงกับ syscall
    ///
    /// เมื่อมี syscall เข้ามา ให้เรียก method นี้เพื่อบันทึกว่า
    /// shadow antibody จะ block หรือไม่ (สำหรับคำนวณ false positive rate)
    pub async fn record_shadow_observation(&self, syscall: &str, would_block: bool) {
        let mut shadow = self.shadow_antibodies.write().await;
        for ab in shadow.iter_mut() {
            if ab.rule.blocked_syscall == syscall {
                ab.record_observation(would_block);
                debug!(
                    syscall = %syscall,
                    would_block = would_block,
                    deny_count = ab.observed_deny_count,
                    allow_count = ab.observed_allow_count,
                    "shadow antibody observation recorded"
                );
            }
        }
    }

    /// Sweep shadow antibodies และ promote those ที่ผ่านเงื่อนไข
    ///
    /// เรียกทุกๆ N วินาทีจาก immune_task
    /// Returns: antibodies ที่ถูก promote ไป enforce mode
    pub async fn sweep_shadow_antibodies(&self) -> Vec<AntibodyRule> {
        let mut promoted = Vec::new();
        let mut shadow = self.shadow_antibodies.write().await;
        let mut remaining = Vec::new();

        for ab in shadow.drain(..) {
            if ab.is_observation_complete() {
                let fpr = ab.false_positive_rate();
                if ab.should_promote(self.promote_confidence_threshold)
                    && fpr <= self.max_false_positive_rate
                {
                    info!(
                        syscall = %ab.rule.blocked_syscall,
                        confidence = ab.rule.confidence,
                        fpr = fpr,
                        deny_count = ab.observed_deny_count,
                        allow_count = ab.observed_allow_count,
                        "shadow antibody promoted to enforce mode"
                    );
                    promoted.push(ab.rule);
                } else {
                    warn!(
                        syscall = %ab.rule.blocked_syscall,
                        confidence = ab.rule.confidence,
                        fpr = fpr,
                        reason = if fpr > self.max_false_positive_rate { "high_fpr" } else { "low_confidence" },
                        "shadow antibody rejected — not promoting to enforce"
                    );
                }
            } else {
                remaining.push(ab);
            }
        }

        *shadow = remaining;

        // Add promoted antibodies to enforce mode
        if !promoted.is_empty() {
            let mut antibodies = self.antibodies.write().await;
            antibodies.extend(promoted.clone());
        }

        promoted
    }

    /// ดึง antibodies ที่ enforce mode (ที่บล็อกจริงแล้ว)
    pub async fn get_enforce_antibodies(&self) -> Vec<AntibodyRule> {
        self.antibodies.read().await.clone()
    }

    /// ดึง shadow antibodies ที่กำลังสังเกตการณ์อยู่
    pub async fn get_shadow_antibodies(&self) -> Vec<ShadowAntibody> {
        self.shadow_antibodies.read().await.clone()
    }

    /// บังคับ promote shadow antibody ไป enforce mode (สำหรับ admin override)
    pub async fn force_promote_shadow(&self, syscall: &str) -> Option<AntibodyRule> {
        let mut shadow = self.shadow_antibodies.write().await;
        if let Some(pos) = shadow
            .iter()
            .position(|s| s.rule.blocked_syscall == syscall)
        {
            let ab = shadow.remove(pos);
            info!(
                syscall = %ab.rule.blocked_syscall,
                confidence = ab.rule.confidence,
                "shadow antibody force-promoted to enforce mode"
            );
            let rule = ab.rule;
            self.antibodies.write().await.push(rule.clone());
            Some(rule)
        } else {
            None
        }
    }

    /// ลบ shadow antibody (admin override — reject)
    pub async fn reject_shadow(&self, syscall: &str) -> bool {
        let mut shadow = self.shadow_antibodies.write().await;
        let before = shadow.len();
        shadow.retain(|s| s.rule.blocked_syscall != syscall);
        let removed = before - shadow.len();
        if removed > 0 {
            info!(syscall = %syscall, "shadow antibody rejected by admin");
        }
        removed > 0
    }

    /// ดู antibodies ที่สร้างไว้ (enforce mode)
    pub async fn get_antibodies(&self) -> Vec<AntibodyRule> {
        self.antibodies.read().await.clone()
    }

    /// ดึงและล้าง antibody rules ใหม่ที่ยังไม่ได้ถูกประมวลผล
    ///
    /// **หมายเหตุ**: method นี้ใช้สำหรับ backward compatibility เท่านั้น
    /// ควรใช้ `sweep_shadow_antibodies()` แทนสำหรับ shadow mode flow ใหม่
    pub async fn take_new_antibodies(&self) -> Vec<AntibodyRule> {
        let mut antibodies = self.antibodies.write().await;
        let result = antibodies.clone();
        antibodies.clear();
        result
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

    fn make_bcell_with_shadow() -> BCellAgent {
        BCellAgent::with_shadow_config(100, Duration::from_secs(60), 0.7, 0.1)
    }

    #[tokio::test]
    async fn learn_and_generate_antibody() {
        let b = make_bcell_with_shadow();
        for _ in 0..5 {
            b.learn_threat(vec!["execve".into()], 8).await;
        }
        let antibody = b.generate_antibody().await;
        assert!(antibody.is_some());
        assert_eq!(antibody.unwrap().blocked_syscall, "execve");

        // Antibody should be in shadow mode, not enforce
        let shadows = b.get_shadow_antibodies().await;
        assert_eq!(shadows.len(), 1);
        assert_eq!(shadows[0].rule.blocked_syscall, "execve");

        // No enforce antibodies yet
        let enforce = b.get_enforce_antibodies().await;
        assert!(enforce.is_empty());
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

    #[tokio::test]
    async fn shadow_antibody_promotes_after_observation() {
        let b = BCellAgent::with_shadow_config(
            100,
            Duration::from_millis(100), // 100ms for testing
            0.7,
            0.1,
        );

        // Generate shadow antibody (need count >= 7 for confidence >= 0.7)
        for _ in 0..8 {
            b.learn_threat(vec!["ptrace".into()], 8).await;
        }
        let antibody = b.generate_antibody().await;
        assert!(antibody.is_some(), "antibody should be generated");
        let ab = antibody.unwrap();
        assert!(
            ab.confidence >= 0.7,
            "confidence {} should be >= 0.7",
            ab.confidence
        );

        // Verify shadow antibody exists
        let shadows = b.get_shadow_antibodies().await;
        assert_eq!(shadows.len(), 1, "should have 1 shadow antibody");

        // Record observations (mostly denies = good)
        for _ in 0..10 {
            b.record_shadow_observation("ptrace", true).await;
        }

        // Wait for observation window
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Sweep should promote
        let promoted = b.sweep_shadow_antibodies().await;
        assert_eq!(promoted.len(), 1, "should have 1 promoted antibody");
        assert_eq!(promoted[0].blocked_syscall, "ptrace");

        // Now in enforce mode
        let enforce = b.get_enforce_antibodies().await;
        assert_eq!(enforce.len(), 1, "should have 1 enforce antibody");
        assert_eq!(enforce[0].blocked_syscall, "ptrace");
    }

    #[tokio::test]
    async fn shadow_antibody_rejects_high_fpr() {
        let b = BCellAgent::with_shadow_config(
            100,
            Duration::from_millis(100),
            0.7,
            0.1, // 10% max FPR
        );

        for _ in 0..5 {
            b.learn_threat(vec!["socket".into()], 8).await;
        }
        let antibody = b.generate_antibody().await;
        assert!(antibody.is_some());

        // Record observations (many allows = bad — high FPR)
        for _ in 0..5 {
            b.record_shadow_observation("socket", true).await;
        }
        for _ in 0..50 {
            b.record_shadow_observation("socket", false).await;
        }

        tokio::time::sleep(Duration::from_millis(150)).await;

        let promoted = b.sweep_shadow_antibodies().await;
        assert!(promoted.is_empty(), "should not promote high-FPR antibody");

        let enforce = b.get_enforce_antibodies().await;
        assert!(enforce.is_empty());
    }

    #[tokio::test]
    async fn force_promote_shadow() {
        let b = make_bcell_with_shadow();

        for _ in 0..5 {
            b.learn_threat(vec!["execve".into()], 8).await;
        }
        b.generate_antibody().await;

        let promoted = b.force_promote_shadow("execve").await;
        assert!(promoted.is_some());

        let enforce = b.get_enforce_antibodies().await;
        assert_eq!(enforce.len(), 1);
    }

    #[tokio::test]
    async fn reject_shadow() {
        let b = make_bcell_with_shadow();

        for _ in 0..5 {
            b.learn_threat(vec!["execve".into()], 8).await;
        }
        b.generate_antibody().await;

        let rejected = b.reject_shadow("execve").await;
        assert!(rejected);

        let shadows = b.get_shadow_antibodies().await;
        assert!(shadows.is_empty());
    }
}
