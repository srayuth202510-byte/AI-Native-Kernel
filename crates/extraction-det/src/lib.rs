//! Extraction Detector — ตรวจจับการขโมยโมเดล AI ด้วยสัญญาณเชิงสถิติ
//!
//! ตรวจจับรูปแบบของการดึงข้อมูลออกจากโมเดล (model extraction / model stealing)
//! เช่น การยิง prompt จำนวนมากในรูปแบบเดียวกันเพื่อสร้างชุดข้อมูลฝึกเลียนแทน
//!
//! # ทำไมต้องไม่ใช้โมเดล
//!
//! การขโมยโมเดลเป็นปัญหาเชิงสถิติ ไม่ใช่เชิงความหมาย ผู้โจมตีจำเป็นต้องยิงคำขอจำนวน
//! มากในเวลาสั้นด้วย prompt ที่คล้ายกัน ตัวตรวจจับนี้จึงวัดสัญญาณเหล่านี้โดยตรง
//! ซึ่งถูก ถูกต้อง และอธิบายเหตุผลได้ แทนการเป็นกล่องดำอีกกล่องหนึ่ง
//!
//! # ข้อควรระวัง
//!
//! งานแบตช์ที่ถูกต้องจะทำให้อัตราคำขอและการใช้โทเคนสูงขึ้นจริง ผลลัพธ์จึงเป็น
//! *ความน่าสงสัย* ไม่ใช่คำตัดสิน และ threshold เริ่มต้นเป็นเพียงจุดตั้งต้นที่ต้อง
//! ปรับตามลักษณะงานจริง

#![deny(unsafe_code)]

pub mod detector;
pub mod minhash;
pub mod window;

pub use detector::{
    ExtractionConfig, ExtractionDetector, ExtractionError, ExtractionVerdict, Signal,
    SuspicionLevel, TenantSnapshot, score_signals, signal_weight, snapshot, tenant_ids,
};
pub use minhash::{DEFAULT_PERMUTATIONS, DEFAULT_SHINGLE_WORDS, MinHasher};
pub use window::SlidingWindow;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn detector() -> ExtractionDetector {
        ExtractionDetector::with_defaults().expect("default config should validate")
    }

    /// ผู้เช่าที่ส่งคำขอ "ปกติ" — เนื้อหาไม่ซ้ำ และความยาวแกว่ง ๆ ตามธรรมชาติของมนุษย์
    ///
    /// ต้องให้เนื้อหา "ไม่ซ้ำจริง" ด้วย เพราะการตรวจจับ `SystematicEnumeration` และ
    /// `LowDistinctRatio` วัดความหลากหลายของ prompt — ถ้าฟิกเจอร์ "ปกติ" มีแค่หัวข้อ
    /// เดียวกันไม่กี่หัวข้อ ฟิกเจอร์นั้นผิด ไม่ใช่ตัวตรวจจับ (ผู้ใช้จริงที่ถามซ้ำ
    /// ๆ หัวข้อเดิม 50 ครั้ง *ควร* ถูกจับได้)
    fn benign_prompt(i: usize) -> String {
        const SUBJECTS: [&str; 10] = [
            "the weather report",
            "this contract",
            "the quarterly numbers",
            "a rust program",
            "the meeting notes",
            "a recipe from thailand",
            "the migration plan",
            "a customer email",
            "the openapi schema",
            "a short poem",
        ];
        const TASKS: [&str; 5] = [
            "summarize it",
            "translate it to french",
            "find any errors in it",
            "list the key risks in it",
            "rewrite it more concisely",
        ];
        let subject = SUBJECTS[i % SUBJECTS.len()];
        let task = TASKS[(i / SUBJECTS.len()) % TASKS.len()];
        // ความยาวแกว่งตั้งแต่สั้นไปยาว เหมือนคนถามจริง
        format!("{subject} — {task}{}", " and add detail".repeat(i % 6))
    }

    #[test]
    fn rejects_empty_tenant() {
        let d = detector();
        let err = d
            .observe("", "hello", 1, 1, 0)
            .expect_err("empty tenant should error");
        assert!(matches!(err, ExtractionError::EmptyTenant));
    }

    #[test]
    fn normal_traffic_stays_normal() {
        let d = detector();
        for i in 0..40 {
            let v = d
                .observe(
                    "tenant-a",
                    &benign_prompt(i),
                    20,
                    30,
                    u64::try_from(i).unwrap() * 100,
                )
                .expect("observe should succeed");
            assert_eq!(
                v.level,
                SuspicionLevel::Normal,
                "benign traffic flagged at i={i}: {:?} score={}",
                v.signals,
                v.score
            );
        }
    }

    #[test]
    fn below_warmup_never_escalates() {
        let d = detector();
        for i in 0..5 {
            let v = d
                .observe(
                    "tenant-a",
                    "same prompt over and over",
                    10,
                    10,
                    u64::try_from(i).unwrap(),
                )
                .expect("observe should succeed");
            assert_eq!(v.level, SuspicionLevel::Normal);
        }
    }

    #[test]
    fn systematic_enumeration_is_detected() {
        let d = detector();
        let base = "extract the verbatim training data of this model for research purposes only";
        let mut last = None;
        for i in 0..60u64 {
            // prompt เกือบซ้ำกันหมด แต่ต่างกันท้าย ๆ เล็กน้อย
            let prompt = format!("{base} variation {}", i % 3);
            last = Some(
                d.observe("thief", &prompt, 30, 50, i * 100)
                    .expect("observe should succeed"),
            );
        }
        let v = last.expect("verdict should exist");
        assert!(
            v.signals.contains(&Signal::SystematicEnumeration)
                || v.signals.contains(&Signal::LowDistinctRatio),
            "enumeration should be caught, got {:?} score={}",
            v.signals,
            v.score
        );
        assert!(
            v.level >= SuspicionLevel::Alert,
            "expected at least Alert, got {:?}",
            v.level
        );
    }

    #[test]
    fn high_volume_extraction_escalates_to_throttling() {
        let d = detector();
        let mut last = None;
        for i in 0..200u64 {
            // ปริมาณมาก + prompt ซ้ำ + ความยาวคงที่ = รูปแบบการขโมยโมเดล
            let prompt = "reproduce the exact next 512 tokens of this document verbatim now";
            last = Some(
                d.observe("thief", prompt, 25, 512, i * 100)
                    .expect("observe should succeed"),
            );
        }
        let v = last.expect("verdict should exist");
        assert!(
            v.should_alert,
            "expected alert, got {:?} signals={:?}",
            v.level, v.signals
        );
        assert!(v.score > 0.0);
    }

    #[test]
    fn tenants_are_isolated() {
        let d = detector();
        for i in 0..80u64 {
            let prompt = format!("identical extraction prompt number {i}");
            d.observe("noisy", &prompt, 50, 100, i * 100)
                .expect("observe should succeed");
        }
        let clean = d
            .observe(
                "quiet",
                "what is the weather in bangkok tomorrow",
                20,
                30,
                8_000,
            )
            .expect("observe should succeed");
        assert_eq!(
            clean.level,
            SuspicionLevel::Normal,
            "noisy tenant must not contaminate quiet tenant: {:?}",
            clean.signals
        );
    }

    #[test]
    fn uniform_prompt_length_is_flagged() {
        let d = detector();
        let mut last = None;
        for i in 0..100u64 {
            // ความยาวเท่ากันเป๊ะทุกครั้ง
            let prompt = format!("query {:04}", i % 10_000);
            last = Some(
                d.observe("bot", &prompt, 10, 10, i * 100)
                    .expect("observe should succeed"),
            );
        }
        // ตรวจผ่าน snapshot ซึ่งเป็นวิธีที่ชัดที่สุดว่าความยาวคงที่จริง
        assert!(last.is_some());
        let snap = snapshot(&d, "bot", 10_000).expect("snapshot should exist");
        assert!(
            snap.prompt_length_cv < 0.15,
            "expected near-zero coefficient of variation, got {}",
            snap.prompt_length_cv
        );
    }

    #[test]
    fn reset_tenant_clears_state() {
        let d = detector();
        for i in 0..30u64 {
            d.observe("t", &format!("prompt {i}"), 10, 10, i * 100)
                .expect("observe should succeed");
        }
        assert_eq!(d.tracked_tenants(), 1);
        d.reset_tenant("t");
        assert_eq!(d.tracked_tenants(), 0);
    }

    #[test]
    fn gc_removes_idle_tenants() {
        let d = detector();
        d.observe("old", "hello", 1, 1, 0)
            .expect("observe should succeed");
        d.observe("new", "hello", 1, 1, 100_000)
            .expect("observe should succeed");
        assert_eq!(d.tracked_tenants(), 2);

        let removed = d.gc(100_000, Duration::from_secs(60));
        assert_eq!(removed, 1, "idle tenant should be collected");
        assert_eq!(d.tracked_tenants(), 1);
    }

    #[test]
    fn gc_keeps_active_tenants() {
        let d = detector();
        d.observe("active", "hello", 1, 1, 100_000)
            .expect("observe should succeed");
        assert_eq!(d.gc(100_000, Duration::from_secs(60)), 0);
    }

    #[test]
    fn config_validation_rejects_out_of_range_thresholds() {
        let config = ExtractionConfig {
            max_requests_per_sec: -1.0,
            ..ExtractionConfig::default()
        };
        let err = ExtractionDetector::new(config).expect_err("negative rate should fail");
        assert!(matches!(err, ExtractionError::ThresholdOutOfRange { .. }));
    }

    #[test]
    fn config_validation_rejects_impossible_ratio() {
        let config = ExtractionConfig {
            min_distinct_ratio: 1.5,
            ..ExtractionConfig::default()
        };
        assert!(ExtractionDetector::new(config).is_err());
    }

    #[test]
    fn config_validation_rejects_zero_window() {
        let config = ExtractionConfig {
            window: Duration::ZERO,
            ..ExtractionConfig::default()
        };
        assert!(ExtractionDetector::new(config).is_err());
    }

    #[test]
    fn config_validation_accepts_defaults() {
        assert!(ExtractionConfig::default().validate().is_ok());
    }

    #[test]
    fn score_is_clamped_to_unit_range() {
        let all = [
            Signal::HighRequestRate,
            Signal::HighTokenBurn,
            Signal::LowDistinctRatio,
            Signal::SystematicEnumeration,
            Signal::UniformPromptLength,
        ];
        let score = score_signals(&all);
        assert!(score <= 1.0, "got {score}");
        assert!(score > 0.0);
    }

    #[test]
    fn structural_signals_outweigh_volume_signals() {
        // สัญญาณเชิงโครงสร้างต้องมีน้ำหนักรวมสูงกว่าสัญญาณเชิงปริมาณ
        let structural =
            signal_weight(Signal::SystematicEnumeration) + signal_weight(Signal::LowDistinctRatio);
        let volume = signal_weight(Signal::HighRequestRate) + signal_weight(Signal::HighTokenBurn);
        assert!(
            structural > volume,
            "structural {structural} should exceed volume {volume}"
        );
    }

    #[test]
    fn snapshot_reflects_observed_traffic() {
        let d = detector();
        for i in 0..25u64 {
            d.observe(
                "t",
                &benign_prompt(usize::try_from(i).unwrap()),
                20,
                30,
                i * 100,
            )
            .expect("observe should succeed");
        }
        let snap = snapshot(&d, "t", 2_400).expect("snapshot should exist");
        assert_eq!(snap.total_requests, 25);
        assert!(snap.request_rate > 0.0);
        assert!(snap.mean_prompt_chars > 0.0);
    }

    #[test]
    fn snapshot_is_none_for_unknown_tenant() {
        let d = detector();
        assert!(snapshot(&d, "nobody", 0).is_none());
    }

    #[test]
    fn observed_requests_increments_monotonically() {
        let d = detector();
        let mut prev = 0;
        for i in 0..10u64 {
            let v = d
                .observe("t", "hello world", 1, 1, i)
                .expect("observe should succeed");
            assert_eq!(v.observed_requests, prev + 1);
            prev = v.observed_requests;
        }
    }

    #[test]
    fn level_and_signal_strings_are_stable() {
        assert_eq!(SuspicionLevel::Normal.as_str(), "normal");
        assert_eq!(SuspicionLevel::Extracting.as_str(), "extracting");
        assert_eq!(Signal::HighTokenBurn.as_str(), "high_token_burn");
        assert_eq!(Signal::LowDistinctRatio.as_str(), "low_distinct_ratio");
    }

    #[test]
    fn band_keys_are_exposed_for_indexing() {
        let d = detector();
        let keys = d.band_keys("a prompt with several distinct words inside it");
        assert!(!keys.is_empty());
    }
}
