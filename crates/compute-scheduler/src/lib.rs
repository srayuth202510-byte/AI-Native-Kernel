#![deny(unsafe_code)]

/// โมดูลคำนวณต้นทุน/คะแนนของทรัพยากรประมวลผล
pub mod cost;
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
}
