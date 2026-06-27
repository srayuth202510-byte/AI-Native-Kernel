/// โหมดการจัดตารางเวลาของระบบ เพื่อปรับเปลี่ยนพฤติกรรมตามสภาพแวดล้อม
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// โหมดประหยัดพลังงาน (Edge/Laptop) - ให้น้ำหนักกับการใช้พลังงานต่ำสุด
    Battery,
    /// โหมดประสิทธิภาพสูงสุด (Server) - ให้น้ำหนักกับความเร็ว (Latency ต่ำสุด)
    Throughput,
    /// โหมดประหยัดค่าใช้จ่าย (Cloud) - ให้น้ำหนักกับต้นทุนทางการเงินต่ำสุด
    Cost,
}

/// ค่าน้ำหนักปรับตัว (Adaptive Weights) สำหรับการคำนวณคะแนนประสิทธิภาพทรัพยากร
/// ค่าน้ำหนักเหล่านี้จะถูกอัปเดตแบบเรียลไทม์ตามสถิติการใช้งานที่บันทึกได้จริง
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveWeights {
    /// น้ำหนักของปัจจัยความหน่วง (Latency weight)
    pub latency: f64,
    /// น้ำหนักของปัจจัยการใช้พลังงาน (Power consumption weight)
    pub power: f64,
    /// น้ำหนักของปัจจัยค่าใช้จ่าย (Cost weight)
    pub cost: f64,
}

impl AdaptiveWeights {
    /// สร้างออบเจกต์ `AdaptiveWeights` ใหม่ด้วยน้ำหนักเริ่มต้นแบบกำหนดเอง
    #[must_use]
    pub fn new(latency: f64, power: f64, cost: f64) -> Self {
        Self {
            latency,
            power,
            cost,
        }
    }

    /// สร้างค่าน้ำหนักเริ่มต้นที่ตั้งค่ามาสำหรับโหมดการทำงานที่ระบุ
    #[must_use]
    pub fn from_mode(mode: SchedulerMode) -> Self {
        match mode {
            SchedulerMode::Battery => Self::new(0.1, 0.8, 0.1),
            SchedulerMode::Throughput => Self::new(0.8, 0.1, 0.1),
            SchedulerMode::Cost => Self::new(0.1, 0.1, 0.8),
        }
    }

    /// อัปเดตค่าน้ำหนักปรับตัวปัจจุบันโดยใช้สูตรการคำนวณ Exponential Weighted Moving Average (EWMA)
    /// โดยใช้สัมประสิทธิ์การปรับปรุง (alpha) เท่ากับ 0.1
    pub fn observe(&mut self, sample: crate::ComputeProfile) {
        let alpha = 0.1;
        let total = sample.latency_ms + sample.power_watts + sample.cost_units;
        if total <= f64::EPSILON {
            return;
        }

        let sample_latency = sample.latency_ms / total;
        let sample_power = sample.power_watts / total;
        let sample_cost = sample.cost_units / total;

        self.latency = self.latency * (1.0 - alpha) + sample_latency * alpha;
        self.power = self.power * (1.0 - alpha) + sample_power * alpha;
        self.cost = self.cost * (1.0 - alpha) + sample_cost * alpha;

        let normalized_total = self.latency + self.power + self.cost;
        if normalized_total > f64::EPSILON {
            self.latency /= normalized_total;
            self.power /= normalized_total;
            self.cost /= normalized_total;
        }
    }
}

impl Default for AdaptiveWeights {
    /// กำหนดค่าน้ำหนักเริ่มต้นของระบบ โดยใช้โหมด Throughput เป็นมาตรฐาน (เน้น Latency)
    fn default() -> Self {
        Self::from_mode(SchedulerMode::Throughput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComputeProfile;

    #[test]
    fn mode_presets_sum_to_one() {
        for mode in [
            SchedulerMode::Battery,
            SchedulerMode::Throughput,
            SchedulerMode::Cost,
        ] {
            let weights = AdaptiveWeights::from_mode(mode);
            let total = weights.latency + weights.power + weights.cost;
            assert!((total - 1.0).abs() < 1e-9, "preset must be normalized");
        }
    }

    #[test]
    fn observe_zero_total_sample_is_noop() {
        let mut weights = AdaptiveWeights::default();
        let before = weights;

        weights.observe(ComputeProfile {
            latency_ms: 0.0,
            power_watts: 0.0,
            cost_units: 0.0,
        });

        assert_eq!(weights, before);
    }

    #[test]
    fn observe_moves_weights_toward_sample_distribution() {
        let mut weights = AdaptiveWeights::new(0.8, 0.1, 0.1);
        weights.observe(ComputeProfile {
            latency_ms: 1.0,
            power_watts: 100.0,
            cost_units: 1.0,
        });

        assert!(weights.power > 0.1);
        assert!(weights.latency < 0.8);
        let total = weights.latency + weights.power + weights.cost;
        assert!((total - 1.0).abs() < 1e-9);
    }
}
