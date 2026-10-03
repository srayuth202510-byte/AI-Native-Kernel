//! Prometheus metrics ของ watchtower — convention เดียวกับ
//! `capability-security/src/metrics.rs`: struct ถือ counter ไว้, `register`
//! ผูกกับ Registry ที่ผู้เรียกส่งมาให้ (ไม่ใช้ default global — เทสต์สร้างหลาย
//! core ใน process เดียวกัน ชื่อซ้ำบน global registry จะชนกัน)

use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use std::sync::Arc;

/// ชุด metrics ของ monitoring plane
#[derive(Debug)]
pub struct WatchtowerMetrics {
    /// เหตุการณ์ที่ engine รับ แยกตาม tenant × category × severity
    pub events_total: IntCounterVec,
    /// alert ที่ยิง แยกตาม rule × tenant × severity
    pub alerts_fired_total: IntCounterVec,
    /// alert ที่ทิ้งเพราะ queue เต็ม (ทิ้งเงียบโดยไม่มีตัวนับคือการโกหก)
    pub alerts_dropped_total: IntCounter,
    /// pipeline มีชีวิตหรือไม่ (1 = ปกติ, 0 = ตาบอด — ดู A9 ใน design doc)
    pub pipeline_healthy: IntGauge,
    /// โหมดตรวจจับปัจจุบันต่อ tenant (ค่า 1 ที่ label mode ตรงกับสถานะจริง)
    pub detection_mode: IntGaugeVec,
}

impl WatchtowerMetrics {
    /// สร้างและลงทะเบียน metrics ทั้งหมดใน registry ที่กำหนด
    ///
    /// # Errors
    /// คืน `prometheus::Error` เมื่อชื่อซ้ำหรือ registry มีปัญหา
    pub fn register(registry: &Registry) -> Result<Arc<Self>, prometheus::Error> {
        let events_total = IntCounterVec::new(
            Opts::new(
                "watchtower_events_total",
                "security events observed by the rules engine",
            ),
            &["tenant", "category", "severity"],
        )?;
        let alerts_fired_total = IntCounterVec::new(
            Opts::new(
                "watchtower_alerts_fired_total",
                "alerts fired by alert rules",
            ),
            &["rule", "tenant", "severity"],
        )?;
        let alerts_dropped_total = IntCounter::with_opts(Opts::new(
            "watchtower_alerts_dropped_total",
            "alerts dropped because the dispatch queue was full",
        ))?;
        let pipeline_healthy = IntGauge::with_opts(Opts::new(
            "watchtower_pipeline_healthy",
            "1 when the alerting pipeline is alive, 0 when blind",
        ))?;
        let detection_mode = IntGaugeVec::new(
            Opts::new(
                "watchtower_detection_mode",
                "current detection mode per tenant (1 at the active mode)",
            ),
            &["tenant", "mode"],
        )?;

        for m in [
            Box::new(events_total.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(alerts_fired_total.clone()),
            Box::new(alerts_dropped_total.clone()),
            Box::new(pipeline_healthy.clone()),
            Box::new(detection_mode.clone()),
        ] {
            registry.register(m)?;
        }

        Ok(Arc::new(Self {
            events_total,
            alerts_fired_total,
            alerts_dropped_total,
            pipeline_healthy,
            detection_mode,
        }))
    }

    /// เรนเดอร์ registry เป็น Prometheus text format (เสิร์ฟที่ `/metrics`)
    ///
    /// # Errors
    /// คืน `String` เมื่อ encode ล้มเหลว (เกิดยาก แต่ห้าม panic บน request path)
    pub fn render(registry: &Registry) -> Result<String, String> {
        use prometheus::Encoder as _;
        let families = registry.gather();
        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&families, &mut buf)
            .map_err(|e| e.to_string())?;
        String::from_utf8(buf).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_contains_expected_series() {
        let registry = Registry::new();
        let m = WatchtowerMetrics::register(&registry).expect("register");
        m.events_total
            .with_label_values(&["acme", "auth", "high"])
            .inc();
        m.alerts_dropped_total.inc();
        m.pipeline_healthy.set(1);
        m.detection_mode
            .with_label_values(&["acme", "signature"])
            .set(1);

        let text = WatchtowerMetrics::render(&registry).expect("render");
        // prometheus เรียง label ตามตัวอักษร — assert ตามของจริงที่ render
        // ไม่ใช่ตามลำดับที่ประกาศ (ไม่งั้นเทสต์ผูกกับรายละเอียด encoder)
        assert!(
            text.contains(
                "watchtower_events_total{category=\"auth\",severity=\"high\",tenant=\"acme\"} 1"
            ),
            "{text}"
        );
        assert!(text.contains("watchtower_alerts_dropped_total 1"), "{text}");
        assert!(text.contains("watchtower_pipeline_healthy 1"), "{text}");
        assert!(
            text.contains("watchtower_detection_mode{mode=\"signature\",tenant=\"acme\"} 1"),
            "{text}"
        );
    }

    #[test]
    fn two_registries_do_not_collide() {
        // เทสต์สร้างหลาย core ใน process เดียว — ถ้าใช้ global registry จะชน
        // นี่คือเหตุผลที่ register รับ registry เข้ามาแทน
        let a = Registry::new();
        let b = Registry::new();
        WatchtowerMetrics::register(&a).expect("a");
        WatchtowerMetrics::register(&b).expect("b");
    }
}
