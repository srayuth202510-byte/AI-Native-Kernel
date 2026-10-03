//! ระบบตอบโต้อัตโนมัติ (Phase B) — ลงโทษแบบย้อนกลับได้เมื่อกฎยิง
//!
//! ลำดับความสำคัญที่ล็อกไว้ใน design: **ป้องกันก่อน แจ้งทีหลัง** — action ถูก
//! ประหารก่อน webhook เสมอ ถ้า webhook ล้มยังมี audit entry เป็นหลักฐาน
//! (defense first, notification best-effort)
//!
//! สามเสาหลักกัน automation กลายเป็นอาวุธ:
//! 1. ต้อง opt-in สองชั้น (กฎอยู่ใน allowlist + tenant เปิด flag) ถึงจะทำอะไร
//! 2. ทุก action มีวันหมดอายุหรือทางย้อนกลับที่ประกาศชัด
//! 3. circuit breaker แช่แข็ง automation ทั้งระบบเมื่อเรทผิดปกติ + ร้องเอง

use crate::rules::FiredAlert;
use crate::{Clock, SystemClock};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// ชนิดของการลงโทษ — มีแค่ที่ย้อนกลับได้เท่านั้นถึงจะอยู่ enum นี้ได้
/// (ลบข้อมูล/แบนถาวรไม่มีที่ยืนตรงนี้โดยออกแบบ)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// ระงับ tenant ชั่วคราว (หมดอายุแล้วกลับมาเอง)
    Suspend,
    /// เพิกถอนคีย์ (ติดจน restart/reload — คีย์หลุดต้องไม่กลับมาเอง)
    RevokeKey,
}

impl ActionKind {
    /// ชื่อคงที่สำหรับ metric label และ audit reason
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::RevokeKey => "revoke_key",
        }
    }

    /// reason ที่เขียนลง audit สำหรับ action นี้
    #[must_use]
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::Suspend => "auto_suspended",
            Self::RevokeKey => "auto_key_revoked",
        }
    }
}

/// คำสั่งลงโทษหนึ่งรายการ — executor โง่ ๆ เอาไปประหาร ไม่ต้องรู้บริบทอื่น
#[derive(Debug, Clone)]
pub struct ExecutedAction {
    /// ลงโทษแบบไหน
    pub kind: ActionKind,
    /// ผู้เช่าเป้าหมาย
    pub tenant_id: String,
    /// กฎที่เป็นต้นเหตุ (สืบกลับได้)
    pub rule_id: String,
    /// ระยะเวลาระงับ (ใช้เฉพาะ `Suspend`)
    pub suspend_duration: Duration,
}

/// ผู้ประหาร action — ฝั่ง ai-gateway implement (มี Arc<GatewayCore>)
///
/// รับ owned `ExecutedAction` และคืน boxed future เพื่อให้เป็น `dyn compatible`
/// (ต่างจาก `AlertSink` ที่เป็น generic — ตรงนี้ต้องเก็บใน struct จึงต้อง dyn)
/// กล่องหนึ่งใบต่อ action ไม่ใช่ปัญหาประสิทธิภาพเพราะ action เกิดนาน ๆ ครั้ง
/// ไม่ใช่ทุก request
///
/// คืน `true` ก็ต่อเมื่อลงมือทำจริง — dispatcher ส่ง "auto-action-taken" และ
/// นับ metric เฉพาะกรณีนี้เท่านั้น การข้าม (เช่น tenant ไม่ opt-in) ต้องไม่
/// ทิ้งร่องรอยว่า "ได้ลงโทษแล้ว" นั่นคือการโกหกในห่วงโซ่หลักฐาน
pub trait ActionExecutor: Send + Sync {
    /// ประหาร action หนึ่งรายการ (idempotent ได้ยิ่งดี — เรียกซ้ำต้องไม่พัง)
    /// คืน `true` เมื่อลงมือทำจริง
    fn execute(
        &self,
        action: ExecutedAction,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>;
}

/// circuit breaker ของ automation — นับ action ในหน้าต่าง ถ้าเกิน freeze ทั้งระบบ
///
/// freeze ไม่ถาวร: เมื่อเรทตกต่ำกว่าเกณฑ์ (หน้าต่างเลื่อนพ้น) จะกลับมาทำงานเอง
/// แต่ทุกครั้งที่ "เริ่ม freeze" จะร้อง meta-alert หนึ่งครั้งผ่าน sink ตรง
/// (ไม่ผ่าน engine — จะให้ pipeline ที่กำลังจะตายพึ่งตัวเองไม่ได้)
#[derive(Debug)]
pub struct CircuitBreaker {
    max_per_window: u64,
    window: Duration,
    hits: parking_lot::Mutex<VecDeque<u64>>,
    frozen: AtomicBool,
    clock: Arc<dyn Clock>,
}

impl CircuitBreaker {
    /// สร้าง breaker ด้วยนาฬิกาจริง
    #[must_use]
    pub fn new(max_per_window: u64, window: Duration) -> Self {
        Self::with_clock(max_per_window, window, Arc::new(SystemClock))
    }

    /// สร้าง breaker ด้วยนาฬิกาที่กำหนด (เทสต์ใช้ `ManualClock`)
    #[must_use]
    pub fn with_clock(max_per_window: u64, window: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            max_per_window: max_per_window.max(1),
            window,
            hits: parking_lot::Mutex::new(VecDeque::new()),
            frozen: AtomicBool::new(false),
            clock,
        }
    }

    /// ขอสิทธิ์ประหารหนึ่งครั้ง
    ///
    /// คืน `BreakerDecision::Permit` เมื่อทำได้, `Denied { became_frozen }`
    /// เมื่อถูกแช่แข็ง — `became_frozen=true` แค่ครั้งแรกที่ freeze (edge)
    /// ผู้เรียกใช้ส่ง meta-alert ตรงนั้น ไม่ใช่ทุกครั้งที่โดนปฏิเสธ
    pub fn try_permit(&self) -> BreakerDecision {
        let now = self.clock.now_ms();
        let mut hits = self.hits.lock();
        let cutoff = now.saturating_sub(self.window.as_millis() as u64);
        while hits.front().is_some_and(|t| *t < cutoff) {
            hits.pop_front();
        }
        if (hits.len() as u64) >= self.max_per_window {
            let became_frozen = !self.frozen.swap(true, Ordering::SeqCst);
            return BreakerDecision::Denied { became_frozen };
        }
        self.frozen.store(false, Ordering::SeqCst);
        hits.push_back(now);
        BreakerDecision::Permit
    }

    /// ถูกแช่แข็งอยู่หรือไม่
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    /// เวลาปัจจุบันของ breaker (สำหรับ timestamp ของ synthetic alert)
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }
}

/// ผลการขอสิทธิ์จาก breaker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerDecision {
    /// ทำได้
    Permit,
    /// ถูกแช่แข็ง — `became_frozen` เป็นจริงเฉพาะครั้งแรกที่ freeze
    Denied {
        /// เพิ่ง freeze ครั้งนี้ (ให้ส่ง meta-alert ตรงนี้ครั้งเดียว)
        became_frozen: bool,
    },
}

/// ชุดค่าตอบโต้อัตโนมัติที่ผูกกับ dispatcher
///
/// - `suspend_rules` / `revoke_rules`: allowlist รหัสกฎที่มีสิทธิ์ลงโทษ
///   (default ว่าง = notify-only — ต้องเปิดทีละกฎโดย operator)
/// - ไม่มีกฎใน allowlist = ไม่มี action ใดเกิด ไม่ว่า tenant จะ opt-in หรือไม่
#[derive(Clone)]
pub struct AutoResponse {
    /// ผู้ประหาร (ฝั่ง gateway)
    pub executor: Arc<dyn ActionExecutor>,
    /// breaker กัน automation คลั่ง
    pub breaker: Arc<CircuitBreaker>,
    /// กฎที่อนุญาตให้ suspend
    pub suspend_rules: Vec<String>,
    /// กฎที่อนุญาตให้ revoke key
    pub revoke_rules: Vec<String>,
    /// ระยะเวลาระงับต่อครั้ง
    pub suspend_duration: Duration,
}

impl std::fmt::Debug for AutoResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoResponse")
            .field("suspend_rules", &self.suspend_rules)
            .field("revoke_rules", &self.revoke_rules)
            .field("suspend_duration", &self.suspend_duration)
            .field("frozen", &self.breaker.is_frozen())
            .finish()
    }
}

impl AutoResponse {
    /// action ที่ alert นี้มีสิทธิ์ก่อ (อาจได้ 0–2 รายการ)
    #[must_use]
    pub fn actions_for(&self, alert: &FiredAlert) -> Vec<ExecutedAction> {
        let mut out = Vec::new();
        if self.suspend_rules.iter().any(|r| r == &alert.rule_id) {
            out.push(ExecutedAction {
                kind: ActionKind::Suspend,
                tenant_id: alert.tenant_id.clone(),
                rule_id: alert.rule_id.clone(),
                suspend_duration: self.suspend_duration,
            });
        }
        if self.revoke_rules.iter().any(|r| r == &alert.rule_id) {
            out.push(ExecutedAction {
                kind: ActionKind::RevokeKey,
                tenant_id: alert.tenant_id.clone(),
                rule_id: alert.rule_id.clone(),
                suspend_duration: self.suspend_duration,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ManualClock;

    #[test]
    fn breaker_permits_until_quota_then_freezes_once() {
        let clock = Arc::new(ManualClock::new(0));
        let breaker = CircuitBreaker::with_clock(3, Duration::from_secs(3600), clock.clone());
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        // ครั้งที่ 4 เกินโควตา — freeze พร้อม edge flag
        assert_eq!(
            breaker.try_permit(),
            BreakerDecision::Denied {
                became_frozen: true
            }
        );
        assert!(breaker.is_frozen());
        // ครั้งถัดไปยัง freeze แต่ edge เป็น false (meta-alert ต้องส่งครั้งเดียว)
        assert_eq!(
            breaker.try_permit(),
            BreakerDecision::Denied {
                became_frozen: false
            }
        );
    }

    #[test]
    fn breaker_recovers_when_window_slides() {
        let clock = Arc::new(ManualClock::new(0));
        let breaker = CircuitBreaker::with_clock(2, Duration::from_secs(60), clock.clone());
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        assert!(matches!(
            breaker.try_permit(),
            BreakerDecision::Denied { .. }
        ));
        assert!(breaker.is_frozen());
        // เดินพ้นหน้าต่าง — กลับมาทำงานเอง ไม่ต้องมีคนมากดปุ่ม
        clock.advance(Duration::from_secs(61));
        assert_eq!(breaker.try_permit(), BreakerDecision::Permit);
        assert!(!breaker.is_frozen());
    }

    #[test]
    fn actions_for_respects_allowlists() {
        let clock = Arc::new(ManualClock::new(0));
        struct Noop;
        impl ActionExecutor for Noop {
            fn execute(
                &self,
                _action: ExecutedAction,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>>
            {
                Box::pin(async { true })
            }
        }
        let auto = AutoResponse {
            executor: Arc::new(Noop),
            breaker: Arc::new(CircuitBreaker::with_clock(
                10,
                Duration::from_secs(3600),
                clock,
            )),
            suspend_rules: vec!["extraction-active".to_string()],
            revoke_rules: vec![],
            suspend_duration: Duration::from_secs(1800),
        };
        let alert = FiredAlert {
            rule_id: "extraction-active".to_string(),
            tenant_id: "acme".to_string(),
            severity: crate::Severity::Critical,
            total: 1,
            window_started_ms: 0,
            sample: crate::SecurityEvent::new(
                "acme",
                "extraction",
                "x",
                crate::Severity::Critical,
                "r",
                0,
            ),
        };
        let actions = auto.actions_for(&alert);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, ActionKind::Suspend);

        let other = FiredAlert {
            rule_id: "injection-burst".to_string(),
            ..alert.clone()
        };
        // กฎไม่อยู่ใน allowlist = ไม่มี action แม้ tenant จะ opt-in
        assert!(auto.actions_for(&other).is_empty());
    }

    #[test]
    fn audit_reasons_are_stable() {
        assert_eq!(ActionKind::Suspend.audit_reason(), "auto_suspended");
        assert_eq!(ActionKind::RevokeKey.audit_reason(), "auto_key_revoked");
    }
}
