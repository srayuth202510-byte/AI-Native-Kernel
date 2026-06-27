#![deny(unsafe_code)]

/// โมดูลคำนวณต้นทุน/คะแนนของทรัพยากรประมวลผล
pub mod cost;
/// โมดูลเชื่อมต่อเพื่ออ่านข้อมูลฮาร์ดแวร์จริง (CPU/GPU/NPU)
pub mod hardware;
/// โมดูลจัดการนโยบายการจัดสรรอุปกรณ์ (Placement Policy) ตามภาระงาน
pub mod placement;
/// โมดูลจัดการน้ำหนักปรับตัว (Adaptive Weights) ตามสถิติการใช้งานจริง
pub mod weights;
use crate::cost::score_target;
use crate::weights::AdaptiveWeights;
use std::sync::RwLock;
use thiserror::Error;

/// ข้อผิดพลาดจากการคำนวณและการจัดสรรทรัพยากรประมวลผล
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ComputeError {
    /// เกิดขึ้นเมื่อไม่มีฮาร์ดแวร์ประมวลผลที่เหมาะสมให้เลือกใช้งาน
    #[error("no compute target available")]
    NoTargetAvailable,
}

/// ฮาร์ดแวร์เป้าหมายสำหรับการประมวลผล AI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputeTarget {
    /// หน่วยประมวลผลกลาง (CPU)
    Cpu,
    /// หน่วยประมวลผลกราฟิก (GPU)
    Gpu,
    /// หน่วยประมวลผลโครงข่ายประสาทเทียม (NPU)
    Npu,
    /// คลาวด์ หรือ Server ภายนอก
    Cloud,
}

/// โปรไฟล์ข้อมูลประสิทธิภาพและพลังงานของฮาร์ดแวร์แต่ละประเภท
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComputeProfile {
    /// ความหน่วงในการประมวลผล มีหน่วยเป็นมิลลิวินาที (Latency)
    pub latency_ms: f64,
    /// อัตราการใช้พลังงาน มีหน่วยเป็นวัตต์ (Power)
    pub power_watts: f64,
    /// ค่าใช้จ่ายของระบบ มีหน่วยเป็นหน่วยสมมุติ (Cost)
    pub cost_units: f64,
}

/// ตัวจัดตารางเวลาและวิเคราะห์การใช้ทรัพยากรประมวลผล (Compute Scheduler)
/// ทำหน้าที่เลือกฮาร์ดแวร์ประมวลผลที่ดีที่สุดตามฟังก์ชันต้นทุนและตัวแปรปรับตัว (Adaptive Weights)
#[derive(Debug, Clone)]
pub struct ComputeScheduler {
    /// ค่าน้ำหนักปรับตัวที่ใช้ในการคำนวณคะแนนต้นทุน ถูกป้องกันด้วย RwLock เพื่อความปลอดภัยในการทำงานหลายเธรด
    weights: std::sync::Arc<RwLock<AdaptiveWeights>>,
}

impl ComputeScheduler {
    /// สร้างตัวจัดตารางเวลา `ComputeScheduler` ใหม่พร้อมค่าเริ่มต้นค่าน้ำหนักปรับตัว
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: std::sync::Arc::new(RwLock::new(AdaptiveWeights::default())),
        }
    }

    /// สร้าง `ComputeScheduler` โดยกำหนดค่าน้ำหนักปรับตัวเริ่มต้น
    #[must_use]
    pub fn with_weights(weights: AdaptiveWeights) -> Self {
        Self {
            weights: std::sync::Arc::new(RwLock::new(weights)),
        }
    }

    /// คำนวณคะแนนต้นทุนสำหรับโปรไฟล์ประสิทธิภาพฮาร์ดแวร์ที่กำหนด
    /// ยิ่งคะแนนต่ำ หมายถึงฮาร์ดแวร์นั้นมีประสิทธิภาพ/ต้นทุนที่คุ้มค่ากว่าในการทำงาน
    pub fn score(&self, profile: ComputeProfile) -> f64 {
        let weights = self.weights.read().expect("compute weights lock poisoned");
        score_target(profile, &weights)
    }

    /// เลือกฮาร์ดแวร์ประมวลผลที่ดีที่สุด (คะแนนต่ำสุด) จากตัวเลือกที่มีให้ทั้งหมด
    /// คืนค่า `Ok(ComputeTarget)` เมื่อเลือกได้สำเร็จ หรือ `Err(ComputeError)` หากไม่มีตัวเลือกให้เลือก
    pub fn choose_best(
        &self,
        candidates: &[(ComputeTarget, ComputeProfile)],
    ) -> Result<ComputeTarget, ComputeError> {
        candidates
            .iter()
            .min_by(|(_, left), (_, right)| {
                self.score(*left)
                    .partial_cmp(&self.score(*right))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(target, _)| *target)
            .ok_or(ComputeError::NoTargetAvailable)
    }

    /// อัปเดตค่าน้ำหนักปรับตัวด้วยตัวอย่างข้อมูล (Sample) โปรไฟล์ประสิทธิภาพใหม่ล่าสุด
    pub fn update_weights(&self, sample: ComputeProfile) {
        let mut weights = self.weights.write().expect("compute weights lock poisoned");
        weights.observe(sample);
    }
}

impl Default for ComputeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choose_best_prefers_lower_score() {
        // ทดสอบว่าฟังก์ชันเลือกเป้าหมายการประมวลผล เลือกฮาร์ดแวร์ที่ได้คะแนนคำนวณต่ำที่สุด (ดีที่สุด)
        let scheduler = ComputeScheduler::new();
        let candidates = [
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: 10.0,
                    power_watts: 10.0,
                    cost_units: 10.0,
                },
            ),
            (
                ComputeTarget::Gpu,
                ComputeProfile {
                    latency_ms: 1.0,
                    power_watts: 2.0,
                    cost_units: 3.0,
                },
            ),
        ];

        assert_eq!(
            scheduler
                .choose_best(&candidates)
                .expect("candidate should exist"),
            ComputeTarget::Gpu
        );
    }

    #[test]
    fn choose_best_returns_error_when_no_candidates() {
        // ทดสอบว่าคืน error เมื่อไม่มีตัวเลือกฮาร์ดแวร์ใดเลย (NoTargetAvailable)
        let scheduler = ComputeScheduler::new();
        let result = scheduler.choose_best(&[]);
        assert_eq!(result, Err(ComputeError::NoTargetAvailable));
    }

    #[test]
    fn choose_best_single_candidate_always_wins() {
        // ทดสอบว่าหากมีตัวเลือกเดียว ต้องเลือกตัวนั้นเสมอ ไม่ว่าคะแนนจะเป็นเท่าใด
        let scheduler = ComputeScheduler::new();
        let candidates = [(
            ComputeTarget::Npu,
            ComputeProfile {
                latency_ms: 999.0,
                power_watts: 999.0,
                cost_units: 999.0,
            },
        )];
        assert_eq!(
            scheduler
                .choose_best(&candidates)
                .expect("should pick single candidate"),
            ComputeTarget::Npu
        );
    }

    #[test]
    fn score_is_non_negative_for_positive_profiles() {
        // ทดสอบ property: คะแนนจะต้องไม่ติดลบสำหรับโปรไฟล์ที่มีค่าบวกทุกตัว
        let scheduler = ComputeScheduler::new();
        let profiles = [
            ComputeProfile {
                latency_ms: 0.0,
                power_watts: 0.0,
                cost_units: 0.0,
            },
            ComputeProfile {
                latency_ms: 1.0,
                power_watts: 50.0,
                cost_units: 100.0,
            },
            ComputeProfile {
                latency_ms: 500.0,
                power_watts: 300.0,
                cost_units: 1.0,
            },
        ];
        for profile in profiles {
            assert!(
                scheduler.score(profile) >= 0.0,
                "คะแนนต้องไม่ติดลบสำหรับโปรไฟล์ที่มีค่าบวก: {:?}",
                profile
            );
        }
    }

    #[test]
    fn update_weights_converges_toward_sample() {
        // ทดสอบว่า EWMA ค่อยๆ ดึงค่าน้ำหนักเข้าหา normalized sample ตามสัมประสิทธิ์ alpha=0.1
        let scheduler = ComputeScheduler::new();
        let sample = ComputeProfile {
            latency_ms: 100.0,
            power_watts: 10.0,
            cost_units: 1.0,
        };

        let contrast_profile = ComputeProfile {
            latency_ms: 1.0,
            power_watts: 100.0,
            cost_units: 100.0,
        };

        // บันทึก score ก่อนอัปเดต โดยใช้ profile ที่ไม่เหมือน sample เพื่อให้เห็นผลจาก weight shift ชัดเจน
        let score_before = scheduler.score(contrast_profile);
        // อัปเดตน้ำหนักหลายรอบให้มีการเปลี่ยนแปลงมากพอ
        for _ in 0..20 {
            scheduler.update_weights(sample);
        }
        let score_after = scheduler.score(contrast_profile);

        // หลัง update หลายรอบ คะแนนควรเปลี่ยนแปลง (EWMA มีผล)
        assert_ne!(
            (score_before * 1000.0) as i64,
            (score_after * 1000.0) as i64,
            "คะแนนต้องเปลี่ยนหลัง update weights"
        );
    }

    #[test]
    fn update_weights_preserves_normalized_weight_budget() {
        let scheduler = ComputeScheduler::new();
        let sample = ComputeProfile {
            latency_ms: 1000.0,
            power_watts: 10.0,
            cost_units: 1.0,
        };

        for _ in 0..10 {
            scheduler.update_weights(sample);
        }

        let weights = scheduler
            .weights
            .read()
            .expect("compute weights lock poisoned");
        let total = weights.latency + weights.power + weights.cost;

        assert!(
            (total - 1.0).abs() < 1e-9,
            "weights must remain normalized, got {total}"
        );
    }

    #[test]
    fn three_way_comparison_picks_npu_as_cheapest() {
        // ทดสอบการเปรียบเทียบ 3 ทาง: CPU/GPU/NPU โดย NPU มีต้นทุนต่ำสุด
        let scheduler = ComputeScheduler::new();
        let candidates = [
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: 50.0,
                    power_watts: 80.0,
                    cost_units: 20.0,
                },
            ),
            (
                ComputeTarget::Gpu,
                ComputeProfile {
                    latency_ms: 5.0,
                    power_watts: 150.0,
                    cost_units: 50.0,
                },
            ),
            (
                ComputeTarget::Npu,
                ComputeProfile {
                    latency_ms: 2.0,
                    power_watts: 10.0,
                    cost_units: 5.0,
                },
            ),
        ];
        assert_eq!(
            scheduler.choose_best(&candidates).expect("should pick NPU"),
            ComputeTarget::Npu
        );
    }
}
