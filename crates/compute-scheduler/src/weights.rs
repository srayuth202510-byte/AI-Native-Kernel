#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveWeights {
    pub latency: f64,
    pub power: f64,
    pub cost: f64,
}

impl AdaptiveWeights {
    #[must_use]
    pub fn new(latency: f64, power: f64, cost: f64) -> Self {
        Self {
            latency,
            power,
            cost,
        }
    }

    pub fn observe(&mut self, sample: crate::ComputeProfile) {
        let alpha = 0.1;
        self.latency = self.latency * (1.0 - alpha) + sample.latency_ms * alpha;
        self.power = self.power * (1.0 - alpha) + sample.power_watts * alpha;
        self.cost = self.cost * (1.0 - alpha) + sample.cost_units * alpha;
    }
}

impl Default for AdaptiveWeights {
    fn default() -> Self {
        Self {
            latency: 0.6,
            power: 0.2,
            cost: 0.2,
        }
    }
}
