//! เหตุการณ์ความปลอดภัย — หน่วยเล็กที่สุดของ pipeline
//!
//! ทุก detector (gateway policy, guard, extraction-det, host plane ในอนาคต)
//! แปลง verdict ของตัวเองเป็น [`SecurityEvent`] แล้วส่งให้ rules engine
//! ตัว event เองไม่รู้ว่าใครส่งมา — engine สนใจแค่ category/severity/tenant
//! กับเวลา นี่คือสัญญาที่ทำให้เพิ่ม source ใหม่ได้โดยไม่แก้ engine

use serde::{Deserialize, Serialize};

/// ระดับความรุนแรงของเหตุการณ์ — เรียงจากเบาไปหนัก ใช้เปรียบเทียบได้
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// ข้อมูลประกอบ ไม่มี action
    Info,
    /// ควรดู ไม่ต้องตื่น
    Warn,
    /// ต้องดูวันนี้
    High,
    /// ตื่นมาดูเดี๋ยวนี้
    Critical,
}

impl Severity {
    /// ชื่อคงที่สำหรับ metric label และ JSON
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// เหตุการณ์ความปลอดภัยหนึ่งรายการ
///
/// ออกแบบให้เล็กและหนีไม่พ้น `Clone` เพราะ rules engine อาจถือ sample ไว้ใน
/// alert ที่ fire ออกไป — ถ้า struct ใหญ่ การ clone ทุก event จะกลายเป็นภาษี
/// บน request path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// ผู้เช่าเจ้าของเหตุการณ์ (`*` สำหรับเหตุการณ์ระดับระบบที่ไม่ผูก tenant)
    pub tenant_id: String,
    /// หมวด เช่น `prompt_injection`, `pii_exfiltration`, `auth`, `concurrency`,
    /// `extraction`, `policy_violation`, `host`
    pub category: String,
    /// เหตุผลแบบเครื่องอ่าน เช่น `prompt_injection_detected`
    pub reason: String,
    /// ความรุนแรงของเหตุการณ์นี้
    pub severity: Severity,
    /// ปริมาณสำหรับกฎแบบผลรวม (เช่น `redacted_count`) — ปกติคือ 1
    pub count: u64,
    /// ตัวชี้หลักฐาน: `request_id` ของ audit entry (สืบกลับไปหา chain ได้)
    pub request_id: String,
    /// หลักฐานเสริมอิสระ เช่น hash ของ chain หรือ rule ids ที่โดน
    pub evidence: String,
    /// เวลาเกิดเหตุเป็น ms นับจาก UNIX epoch (ผู้ผลิตเป็นคนตั้ง)
    pub observed_at_ms: u64,
}

impl SecurityEvent {
    /// สร้าง event ปริมาณ 1 หน่วย — เคสทั่วไปของ deny หนึ่งครั้ง
    #[must_use]
    pub fn new(
        tenant_id: &str,
        category: &str,
        reason: &str,
        severity: Severity,
        request_id: &str,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            category: category.to_string(),
            reason: reason.to_string(),
            severity,
            count: 1,
            request_id: request_id.to_string(),
            evidence: String::new(),
            observed_at_ms,
        }
    }

    /// แนบหลักฐานเสริม (builder style เพื่อไม่ต้องมี constructor ยาวเป็นหางว่าว)
    #[must_use]
    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = evidence.to_string();
        self
    }

    /// กำหนดปริมาณ (เช่น จำนวน PII ที่ redact ใน request เดียว)
    #[must_use]
    pub fn with_count(mut self, count: u64) -> Self {
        self.count = count.max(1);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_matches_escalation() {
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn event_serializes_for_webhook_payload() {
        let e = SecurityEvent::new("acme", "auth", "invalid_api_key", Severity::High, "r1", 7)
            .with_count(3)
            .with_evidence("chain:abc");
        let v: serde_json::Value = serde_json::to_value(&e).expect("event must serialize");
        assert_eq!(v["tenant_id"], "acme");
        assert_eq!(v["severity"], "high");
        assert_eq!(v["count"], 3);
    }

    #[test]
    fn count_zero_is_coerced_to_one() {
        // count=0 จะทำให้กฎผลรวมมองไม่เห็น event นี้เลย — บังคับขั้นต่ำ 1
        // ดีกว่าเงียบหาย
        let e = SecurityEvent::new("t", "c", "r", Severity::Info, "r1", 0).with_count(0);
        assert_eq!(e.count, 1);
    }
}
