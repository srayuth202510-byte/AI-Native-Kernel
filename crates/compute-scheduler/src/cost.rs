use crate::ComputeProfile;
use crate::weights::AdaptiveWeights;

/// คำนวณคะแนนรวมของเป้าหมายการประมวลผล (Compute Target Score)
/// โดยใช้สูตร: `Score = Latency * w_latency + Power * w_power + Cost * w_cost`
/// ยิ่งคะแนนที่ได้มีค่าต่ำ แสดงว่าทรัพยากรนั้นเหมาะสมและคุ้มค่าที่สุดในการใช้งาน
#[must_use]
pub fn score_target(profile: ComputeProfile, weights: &AdaptiveWeights) -> f64 {
    profile.latency_ms * weights.latency
        + profile.power_watts * weights.power
        + profile.cost_units * weights.cost
}
