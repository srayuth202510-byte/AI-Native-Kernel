//! โมดูลสำหรับ Prometheus Metrics ของระบบ Capability Security
//! ใช้ติดตามสถิติการออกโทเค็น การตัดสินนโยบาย และการบันทึกประวัติ

use prometheus::{IntCounter, IntCounterVec, Opts, Registry};
use std::sync::Arc;

/// ชุด Prometheus Metrics สำหรับ Capability Security Manager
/// เก็บตัวนับสถิติต่างๆ เพื่อใช้สำหรับการ observability และ monitoring
#[derive(Debug)]
pub struct SecurityMetrics {
    /// จำนวนโทเค็นที่ออกทั้งหมดตั้งแต่เริ่มระบบ
    pub tokens_issued_total: IntCounter,
    /// จำนวนการตัดสินใจนโยบาย แยกตาม label decision=allow/deny
    pub policy_decisions_total: IntCounterVec,
    /// จำนวนรายการ audit ที่บันทึกทั้งหมด
    pub audit_entries_total: IntCounter,
    /// จำนวนครั้งที่การยืนยันโทเค็นล้มเหลว
    pub token_validation_failures_total: IntCounter,
}

impl SecurityMetrics {
    /// สร้างและลงทะเบียน SecurityMetrics ใน Prometheus Registry ที่กำหนด
    ///
    /// # Errors
    /// คืน `prometheus::Error` หาก metric ชื่อซ้ำหรือ Registry มีปัญหา
    pub fn register(registry: &Registry) -> Result<Arc<Self>, prometheus::Error> {
        // สร้าง counter สำหรับนับโทเค็นที่ออก
        let tokens_issued_total = IntCounter::with_opts(Opts::new(
            "security_tokens_issued_total",
            "จำนวนโทเค็นความสามารถที่ออกทั้งหมด",
        ))?;

        // สร้าง counter vector สำหรับนับการตัดสินใจนโยบาย แยกตาม decision label
        let policy_decisions_total = IntCounterVec::new(
            Opts::new(
                "security_policy_decisions_total",
                "จำนวนการตัดสินใจนโยบายความปลอดภัย แยกตาม allow/deny",
            ),
            &["decision"],
        )?;

        // สร้าง counter สำหรับนับรายการ audit
        let audit_entries_total = IntCounter::with_opts(Opts::new(
            "security_audit_entries_total",
            "จำนวนรายการ audit log ที่บันทึกทั้งหมด",
        ))?;

        // สร้าง counter สำหรับนับการยืนยันโทเค็นที่ล้มเหลว
        let token_validation_failures_total = IntCounter::with_opts(Opts::new(
            "security_token_validation_failures_total",
            "จำนวนครั้งที่การยืนยันโทเค็นล้มเหลว",
        ))?;

        // ลงทะเบียน metrics ทั้งหมดใน registry
        registry.register(Box::new(tokens_issued_total.clone()))?;
        registry.register(Box::new(policy_decisions_total.clone()))?;
        registry.register(Box::new(audit_entries_total.clone()))?;
        registry.register(Box::new(token_validation_failures_total.clone()))?;

        Ok(Arc::new(Self {
            tokens_issued_total,
            policy_decisions_total,
            audit_entries_total,
            token_validation_failures_total,
        }))
    }
}

/// เรนเดอร์ metrics ทั้งหมดใน Registry ออกมาในรูปแบบ Prometheus text format
///
/// # Errors
/// คืน `prometheus::Error` หากเกิดปัญหาในการรวบรวม metrics
pub fn render_metrics(registry: &Registry) -> Result<String, prometheus::Error> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = registry.gather();
    let mut output = Vec::new();
    encoder
        .encode(&metric_families, &mut output)
        .map_err(|e| prometheus::Error::Msg(e.to_string()))?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn register_succeeds_with_fresh_registry() {
        // ทดสอบว่าการลงทะเบียน metrics ใน registry ใหม่ต้องสำเร็จ
        let registry = Registry::new();
        let result = SecurityMetrics::register(&registry);
        assert!(result.is_ok(), "ควรลงทะเบียน metrics ใน registry ใหม่ได้สำเร็จ");
    }

    #[test]
    fn counter_labels_are_correct() {
        // ทดสอบว่า counter labels allow และ deny ทำงานถูกต้อง
        let registry = Registry::new();
        let metrics = SecurityMetrics::register(&registry).expect("ลงทะเบียนสำเร็จ");

        // เพิ่มค่า counter สำหรับ allow และ deny
        metrics
            .policy_decisions_total
            .with_label_values(&["allow"])
            .inc();
        metrics
            .policy_decisions_total
            .with_label_values(&["allow"])
            .inc();
        metrics
            .policy_decisions_total
            .with_label_values(&["deny"])
            .inc();

        // ตรวจสอบค่า counter ที่บันทึกไว้
        assert_eq!(
            metrics
                .policy_decisions_total
                .with_label_values(&["allow"])
                .get(),
            2,
            "allow counter ควรเป็น 2"
        );
        assert_eq!(
            metrics
                .policy_decisions_total
                .with_label_values(&["deny"])
                .get(),
            1,
            "deny counter ควรเป็น 1"
        );
    }

    #[test]
    fn render_output_contains_metric_names() {
        // ทดสอบว่า render_metrics ผลิต output ที่มีชื่อ metric ถูกต้อง
        let registry = Registry::new();
        let metrics = SecurityMetrics::register(&registry).expect("ลงทะเบียนสำเร็จ");
        metrics.tokens_issued_total.inc();
        metrics.audit_entries_total.inc_by(3);

        let output = render_metrics(&registry).expect("render metrics สำเร็จ");
        assert!(
            output.contains("security_tokens_issued_total"),
            "ผลลัพธ์ควรมีชื่อ metric tokens_issued_total"
        );
        assert!(
            output.contains("security_audit_entries_total"),
            "ผลลัพธ์ควรมีชื่อ metric audit_entries_total"
        );
    }

    #[test]
    fn duplicate_registration_returns_error() {
        // ทดสอบว่าการลงทะเบียน metric ซ้ำใน registry เดิมต้องคืน error
        let registry = Registry::new();
        let _first = SecurityMetrics::register(&registry).expect("ครั้งแรกสำเร็จ");
        let second = SecurityMetrics::register(&registry);
        assert!(
            second.is_err(),
            "การลงทะเบียนซ้ำต้องคืน error"
        );
    }
}
