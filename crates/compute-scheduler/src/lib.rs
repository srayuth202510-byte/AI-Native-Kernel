#![deny(unsafe_code)]

pub mod cost;
pub mod weights;

use crate::cost::score_target;
use crate::weights::AdaptiveWeights;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ComputeError {
    #[error("no compute target available")]
    NoTargetAvailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputeTarget {
    Cpu,
    Gpu,
    Npu,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComputeProfile {
    pub latency_ms: f64,
    pub power_watts: f64,
    pub cost_units: f64,
}

#[derive(Debug, Clone)]
pub struct ComputeScheduler {
    weights: std::sync::Arc<RwLock<AdaptiveWeights>>,
}

impl ComputeScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: std::sync::Arc::new(RwLock::new(AdaptiveWeights::default())),
        }
    }

    pub fn score(&self, profile: ComputeProfile) -> f64 {
        let weights = self.weights.read().expect("compute weights lock poisoned");
        score_target(profile, &weights)
    }

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
