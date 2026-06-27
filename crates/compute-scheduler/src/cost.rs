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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_target_matches_weighted_sum_formula() {
        let profile = ComputeProfile {
            latency_ms: 10.0,
            power_watts: 20.0,
            cost_units: 30.0,
        };
        let weights = AdaptiveWeights::new(0.2, 0.3, 0.5);

        let score = score_target(profile, &weights);
        assert!((score - 23.0).abs() < 1e-9);
    }

    #[test]
    fn zero_weights_yield_zero_score() {
        let profile = ComputeProfile {
            latency_ms: 10.0,
            power_watts: 20.0,
            cost_units: 30.0,
        };
        let weights = AdaptiveWeights::new(0.0, 0.0, 0.0);

        assert_eq!(score_target(profile, &weights), 0.0);
    }
}
