//! Watchtower — ระวังภัยชั้น monitoring/alerting ของ AI security
//!
//! แปลง verdict ที่ detector ผลิตอยู่แล้ว (gateway policy, guard, extraction,
//! host plane) ให้เป็นสิ่งที่ operator เห็นและตื่นได้: metrics + alert + webhook
//!
//! ```text
//! SecurityEvent → RulesEngine.observe → [FiredAlert] → Dispatcher → WebhookSink
//!        │                  │
//!        └─ metrics ────────┘
//! ```
//!
//! กฎเหล็กของ crate นี้ (จาก design doc §4):
//! - ส่ง alert นอกเส้นทาง request เสมอ (`try_enqueue` ไม่มีทาง block)
//! - ทุก alert สืบกลับไปหา audit evidence ได้ (`request_id` + `evidence`)
//! - ทิ้ง alert ต้องนับ (`alerts_dropped_total`) — ทิ้งเงียบคือโกหก
//! - default คือ notify-only — auto-action เป็น opt-in ของ operator

#![deny(unsafe_code)]

pub mod dispatch;
pub mod event;
pub mod metrics;
pub mod rules;
pub mod sink;

pub use dispatch::{DEFAULT_QUEUE_CAPACITY, Dispatcher, Enqueue};
pub use event::{SecurityEvent, Severity};
pub use metrics::WatchtowerMetrics;
pub use rules::{AlertRule, Clock, FiredAlert, ManualClock, RulesEngine, Scope, SystemClock};
pub use sink::{AlertPayload, AlertSink, DELIVERY_TIMEOUT, MAX_ATTEMPTS, SinkError, WebhookSink};

use std::time::Duration;

/// กฎเริ่มต้นจาก alert catalog ใน design doc (§5)
///
/// เกณฑ์เป็นค่าเริ่มต้นจากอากาศ — platform team (เจ้าของ threshold) ต้อง tune
/// จาก traffic จริง 2 สัปดาห์แรกในโหมด observe ดู `docs/ai_threat_monitoring_design.md`
#[must_use]
pub fn default_rules() -> Vec<AlertRule> {
    vec![
        // A1: injection พุ่งต่อ tenant
        AlertRule {
            id: "injection-burst".to_string(),
            category: "prompt_injection".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(300),
            threshold: 10,
            severity: Severity::High,
            cooldown: Duration::from_secs(900),
        },
        // A2: extraction ระดับ extracting — ครั้งเดียวก็ตื่น
        AlertRule {
            id: "extraction-active".to_string(),
            category: "extraction".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(3600),
            threshold: 1,
            severity: Severity::Critical,
            cooldown: Duration::from_secs(300),
        },
        // A3: extraction ระดับ alert ต่อเนื่อง
        AlertRule {
            id: "extraction-sustained".to_string(),
            category: "extraction_watch".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(3600),
            threshold: 3,
            severity: Severity::High,
            cooldown: Duration::from_secs(900),
        },
        // A4: PII exfil volume (นับ redacted_count รวม ไม่ใช่นับ request)
        AlertRule {
            id: "pii-exfil-volume".to_string(),
            category: "pii_exfiltration".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(600),
            threshold: 100,
            severity: Severity::High,
            cooldown: Duration::from_secs(900),
        },
        // A5: เดาคีย์ — นับรวมทั้งระบบ (attacker ไม่รู้ tenant)
        AlertRule {
            id: "auth-probing".to_string(),
            category: "auth".to_string(),
            scope: Scope::Global,
            window: Duration::from_secs(300),
            threshold: 20,
            severity: Severity::High,
            cooldown: Duration::from_secs(900),
        },
        // A6: shed พุ่ง (DoS หรือโควตาไม่พอ)
        AlertRule {
            id: "concurrency-shedding".to_string(),
            category: "concurrency".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(300),
            threshold: 50,
            severity: Severity::Warn,
            cooldown: Duration::from_secs(900),
        },
        // A7: tenant ถูกระงับแล้วยังมีคนเรียก
        AlertRule {
            id: "suspended-tenant-traffic".to_string(),
            category: "suspended".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(300),
            threshold: 5,
            severity: Severity::High,
            cooldown: Duration::from_secs(900),
        },
        // A8: host-plane quarantine (source ที่สองมาต่อทีหลัง — กฎรอไว้ก่อน)
        AlertRule {
            id: "host-quarantine".to_string(),
            category: "host".to_string(),
            scope: Scope::PerTenant,
            window: Duration::from_secs(3600),
            threshold: 1,
            severity: Severity::Critical,
            cooldown: Duration::from_secs(300),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_are_valid() {
        let rules = default_rules();
        assert!(!rules.is_empty());
        for r in &rules {
            r.validate().expect("default rule must validate");
        }
    }

    #[test]
    fn extracting_fires_on_first_event() {
        // A2: extracting ครั้งเดียวต้องตื่น — ห้ามมีเกณฑ์นับที่ทำให้ช้า
        let clock = std::sync::Arc::new(ManualClock::new(0));
        let engine = RulesEngine::with_clock(default_rules(), clock);
        let e = SecurityEvent::new(
            "acme",
            "extraction",
            "extracting",
            Severity::Critical,
            "r1",
            0,
        );
        let fired = engine.observe(&e);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_id, "extraction-active");
        assert_eq!(fired[0].severity, Severity::Critical);
    }
}
