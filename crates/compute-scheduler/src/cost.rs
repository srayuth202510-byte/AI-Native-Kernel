use crate::weights::AdaptiveWeights;
use crate::ComputeProfile;

#[must_use]
pub fn score_target(profile: ComputeProfile, weights: &AdaptiveWeights) -> f64 {
    profile.latency_ms * weights.latency
        + profile.power_watts * weights.power
        + profile.cost_units * weights.cost
}
