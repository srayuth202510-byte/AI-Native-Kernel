//! Rules engine — นับเหตุการณ์ในหน้าต่างเวลาแล้วยิง alert
//!
//! ออกแบบให้โง่โดยตั้งใจ: ไม่มี ML, ไม่มี baseline แบบ adaptive — มีแค่
//! "ผลรวมในหน้าต่างถึงเกณฑ์ + พ้น cooldown = ยิง" กฎที่อธิบายไม่ได้คือ alert
//! ที่ operator ไม่กล้า action (ดู design doc §6)
//!
//! นาฬิกาถูกฉีดเข้ามา (`Clock`) เพื่อให้เทสต์เวลาย้อน/เดินหน้าได้โดยไม่ `sleep`
//! จริง — เทสต์ที่ sleep จริงคือเทสต์ที่ flaky

use crate::event::{SecurityEvent, Severity};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// ขอบเขตการนับของกฎ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// นับแยกต่อผู้เช่า (เช่น injection พุ่งของ tenant หนึ่ง)
    PerTenant,
    /// นับรวมทั้งระบบ (เช่น เดาคีย์ — attacker ไม่รู้ tenant)
    Global,
}

/// นาฬิกาสำหรับ engine — production ใช้เวลาจริง เทสต์ใช้เวลาปลอม
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// เวลาปัจจุบันเป็น ms
    fn now_ms(&self) -> u64;
}

/// นาฬิกาเวลาจริง
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// นาฬิกาปลอมสำหรับเทสต์ — เดินหน้าเอง ไม่มี sleep ไม่ flaky
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    /// สร้างนาฬิกาที่เวลาเริ่มต้นกำหนดเองได้
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self {
            now: AtomicU64::new(start_ms),
        }
    }

    /// เดินหน้าเวลา (ห้ามเดินถอยหลัง — เวลาถอยหลังทำให้หน้าต่างนับพังเงียบ ๆ)
    pub fn advance(&self, delta: Duration) {
        self.now
            .fetch_add(delta.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// กฎหนึ่งข้อ: หมวด + ขอบเขต + หน้าต่าง + เกณฑ์ผลรวม + cooldown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// รหัสกฎ เช่น `injection-burst` (ใช้เป็น metric label ได้)
    pub id: String,
    /// หมวดเหตุการณ์ที่นับ (`SecurityEvent.category` ต้องตรงกันพอดี)
    pub category: String,
    /// นับแยก tenant หรือรวมทั้งระบบ
    pub scope: Scope,
    /// ความกว้างหน้าต่างเวลานับย้อนหลัง
    pub window: Duration,
    /// ผลรวม `event.count` ในหน้าต่างที่ทำให้ยิง (>= เกณฑ์นี้)
    pub threshold: u64,
    /// ความรุนแรงของ alert ที่ยิงออกไป
    pub severity: Severity,
    /// หลังยิงแล้วต้องรออย่างน้อยเท่านี้ก่อนยิงเรื่องเดิมซ้ำ (กัน fatigue)
    pub cooldown: Duration,
}

impl AlertRule {
    /// ตรวจความสมเหตุสมผลของกฎ — ให้ fail ตอนโหลด config ไม่ใช่ตอนตี 3
    ///
    /// # Errors
    /// คืน `Err` เมื่อ threshold เป็น 0 (ยิงทุก event = spam) หรือ window/cooldown
    /// เป็น 0 (นิยามไม่ครบ)
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("rule id must not be empty".to_string());
        }
        if self.category.is_empty() {
            return Err("rule category must not be empty".to_string());
        }
        if self.threshold == 0 {
            return Err(format!(
                "rule '{}': threshold 0 fires on every event",
                self.id
            ));
        }
        if self.window.is_zero() {
            return Err(format!("rule '{}': window must not be zero", self.id));
        }
        Ok(())
    }
}

/// alert ที่ยิงออกไปหนึ่งครั้ง พร้อมตัวอย่างเหตุการณ์ที่เป็นฟางเส้นสุดท้าย
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredAlert {
    /// รหัสกฎที่ยิง
    pub rule_id: String,
    /// ผู้เช่าที่เกี่ยวข้อง (`*` สำหรับกฎ Global)
    pub tenant_id: String,
    /// ความรุนแรงตามกฎ
    pub severity: Severity,
    /// ผลรวมในหน้าต่างที่ทำให้ยิง
    pub total: u64,
    /// จุดเริ่มหน้าต่าง (ms)
    pub window_started_ms: u64,
    /// เหตุการณ์ตัวอย่าง (ถือไว้เพื่อแนบหลักฐานใน webhook)
    pub sample: SecurityEvent,
}

/// สถานะนับของ (กฎ, ขอบเขต) หนึ่งชุด
#[derive(Debug, Default)]
struct CounterState {
    /// timestamps (ms) ของ event ในหน้าต่าง เรียงเวลา (push ท้าย, ตัดหัว)
    hits: VecDeque<(u64, u64)>,
    /// เวลาที่ alert เรื่องนี้ยิงครั้งล่าสุด (กันส่งซ้ำ)
    last_fired_ms: Option<u64>,
}

/// Rules engine — เก็บกฎและสถานะนับ ใช้ lock ภายในเพื่อให้ `observe` รับ `&self`
///
/// `observe` ต้องเร็วพอให้เรียกบน request path ได้ (แค่ push/ตัด VecDeque ใต้
/// lock สั้น ๆ) งานหนัก (ส่ง webhook) อยู่นอก engine ใน dispatcher เสมอ
#[derive(Debug)]
pub struct RulesEngine {
    rules: Vec<AlertRule>,
    state: Mutex<HashMap<(usize, String), CounterState>>,
    clock: Arc<dyn Clock>,
}

impl RulesEngine {
    /// สร้าง engine ด้วยนาฬิกาจริง
    ///
    /// # Panics
    /// panic เมื่อกฎไม่ผ่าน `validate` — config ผิดต้องตายตอน boot ไม่ใช่ตอนตี 3
    #[must_use]
    pub fn new(rules: Vec<AlertRule>) -> Self {
        Self::with_clock(rules, Arc::new(SystemClock))
    }

    /// สร้าง engine ด้วยนาฬิกาที่กำหนด (เทสต์ใช้ `ManualClock`)
    ///
    /// # Panics
    /// panic เมื่อกฎไม่ผ่าน `validate`
    #[must_use]
    pub fn with_clock(rules: Vec<AlertRule>, clock: Arc<dyn Clock>) -> Self {
        for r in &rules {
            r.validate().expect("invalid alert rule");
        }
        Self {
            rules,
            state: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// จำนวนกฎ
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// ป้อนเหตุการณ์หนึ่งรายการ — คืน alert ที่ยิง (ปกติคือว่าง)
    ///
    /// รับ `&self` ได้เพราะ state อยู่ใต้ lock ภายใน ผู้เรียกบน request path
    /// ไม่ต้องถือ lock เอง
    pub fn observe(&self, event: &SecurityEvent) -> Vec<FiredAlert> {
        // ใช้เวลาของ engine เอง ไม่ใช่ event.observed_at_ms — นาฬิกาสองเรือน
        // (producer กับ engine) เดินไม่ตรงกันจะทำให้หน้าต่างเพี้ยนเงียบ ๆ
        let now = self.clock.now_ms();
        let mut fired = Vec::new();
        let mut state = self.state.lock();

        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.category != event.category {
                continue;
            }
            let key = match rule.scope {
                Scope::PerTenant => (idx, event.tenant_id.clone()),
                Scope::Global => (idx, String::new()),
            };
            let counter = state.entry(key).or_default();

            // ตัด timestamps ที่หลุดหน้าต่างออกจากหัว (ข้อมูลเรียงเวลาเสมอ)
            let window_ms = rule.window.as_millis() as u64;
            let cutoff = now.saturating_sub(window_ms);
            while counter.hits.front().is_some_and(|(t, _)| *t < cutoff) {
                counter.hits.pop_front();
            }
            counter.hits.push_back((now, event.count));
            let total: u64 = counter.hits.iter().map(|(_, c)| c).sum();

            if total < rule.threshold {
                continue;
            }
            if counter
                .last_fired_ms
                .is_some_and(|last| now.saturating_sub(last) < rule.cooldown.as_millis() as u64)
            {
                continue;
            }
            counter.last_fired_ms = Some(now);
            fired.push(FiredAlert {
                rule_id: rule.id.clone(),
                tenant_id: match rule.scope {
                    Scope::PerTenant => event.tenant_id.clone(),
                    Scope::Global => "*".to_string(),
                },
                severity: rule.severity,
                total,
                window_started_ms: cutoff,
                sample: event.clone(),
            });
        }
        fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(rules: Vec<AlertRule>, clock: ManualClock) -> (RulesEngine, Arc<ManualClock>) {
        let clock = Arc::new(clock);
        (RulesEngine::with_clock(rules, clock.clone()), clock)
    }

    fn burst_rule() -> AlertRule {
        AlertRule {
            id: "injection-burst".to_string(),
            category: "prompt_injection".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(300),
            threshold: 3,
            severity: Severity::High,
            cooldown: Duration::from_secs(300),
        }
    }

    fn ev(tenant: &str, at: u64) -> SecurityEvent {
        let mut e = SecurityEvent::new(
            tenant,
            "prompt_injection",
            "prompt_injection_detected",
            Severity::High,
            "r1",
            at,
        );
        e.observed_at_ms = at;
        e
    }

    #[test]
    fn fires_when_threshold_reached_inside_window() {
        let (eng, clock) = engine(vec![burst_rule()], ManualClock::new(0));
        assert!(eng.observe(&ev("acme", 0)).is_empty());
        assert!(eng.observe(&ev("acme", 0)).is_empty());
        clock.advance(Duration::from_secs(10));
        let fired = eng.observe(&ev("acme", 10_000));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_id, "injection-burst");
        assert_eq!(fired[0].tenant_id, "acme");
        assert_eq!(fired[0].total, 3);
    }

    #[test]
    fn old_hits_expire_out_of_window() {
        let (eng, clock) = engine(vec![burst_rule()], ManualClock::new(0));
        eng.observe(&ev("acme", 0));
        eng.observe(&ev("acme", 0));
        // เดินเลยหน้าต่าง 5 นาที — สอง hit แรกต้องหมดอายุ เหลือ hit เดียวไม่ถึงเกณฑ์
        clock.advance(Duration::from_secs(301));
        assert!(eng.observe(&ev("acme", 301_000)).is_empty());
    }

    #[test]
    fn cooldown_suppresses_repeat_firing() {
        // window กว้างกว่า cooldown มาก เพื่อแยกสองเรื่องออกจากกัน: หลักฐานยัง
        // อยู่ในหน้าต่าง แต่ alert ต้องเงียบจนพ้น cooldown
        let rule = AlertRule {
            window: Duration::from_secs(600),
            cooldown: Duration::from_secs(60),
            ..burst_rule()
        };
        let (eng, clock) = engine(vec![rule], ManualClock::new(0));
        for _ in 0..3 {
            eng.observe(&ev("acme", 0));
        }
        // ยิงครั้งแรกไปแล้ว — hit ที่ 4 ยังเกินเกณฑ์แต่ติด cooldown 60s
        clock.advance(Duration::from_secs(30));
        assert!(eng.observe(&ev("acme", 30_000)).is_empty());
        // พ้น cooldown แล้ว หลักฐานยังอยู่ในหน้าต่าง → ยิงซ้ำได้
        clock.advance(Duration::from_secs(40));
        let fired = eng.observe(&ev("acme", 70_000));
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn tenants_are_counted_independently() {
        let (eng, _) = engine(vec![burst_rule()], ManualClock::new(0));
        eng.observe(&ev("acme", 0));
        eng.observe(&ev("acme", 0));
        // globex มีแค่ 2 hits — ต้องไม่ยิง และต้องไม่ไปรวมกับของ acme
        assert!(eng.observe(&ev("globex", 0)).is_empty());
        assert!(eng.observe(&ev("globex", 0)).is_empty());
    }

    #[test]
    fn global_scope_counts_across_tenants() {
        let rule = AlertRule {
            scope: Scope::Global,
            threshold: 3,
            ..burst_rule()
        };
        let (eng, _) = engine(vec![rule], ManualClock::new(0));
        eng.observe(&ev("acme", 0));
        eng.observe(&ev("globex", 0));
        let fired = eng.observe(&ev("initech", 0));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].tenant_id, "*");
    }

    #[test]
    fn counts_sum_not_events() {
        // A4 (PII volume) นับ redacted_count รวม ไม่ใช่นับจำนวน request
        let rule = AlertRule {
            id: "pii-volume".to_string(),
            category: "pii_exfiltration".to_string(),
            threshold: 100,
            ..burst_rule()
        };
        let (eng, _) = engine(vec![rule], ManualClock::new(0));
        let big = SecurityEvent::new(
            "acme",
            "pii_exfiltration",
            "pii_redacted",
            Severity::High,
            "r1",
            0,
        )
        .with_count(60);
        assert!(eng.observe(&big).is_empty());
        let fired = eng.observe(&big);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].total, 120);
    }

    #[test]
    fn non_matching_category_is_ignored() {
        let (eng, _) = engine(vec![burst_rule()], ManualClock::new(0));
        let other = SecurityEvent::new("acme", "auth", "invalid_api_key", Severity::High, "r1", 0);
        assert!(eng.observe(&other).is_empty());
    }

    #[test]
    fn invalid_rule_rejected_at_construction() {
        assert!(burst_rule().validate().is_ok());
        for bad in [
            AlertRule {
                threshold: 0,
                ..burst_rule()
            },
            AlertRule {
                window: Duration::ZERO,
                ..burst_rule()
            },
            AlertRule {
                id: String::new(),
                ..burst_rule()
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
