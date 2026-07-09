//! Property-based tests สำหรับ invariants ของ Cost Function และการเลือกฮาร์ดแวร์
//!
//! Invariants หลัก:
//! 1. Monotonicity — latency/power/cost สูงขึ้น (weights ไม่ติดลบ) คะแนนต้องไม่ลดลง
//! 2. Zero weights → คะแนนเป็นศูนย์เสมอ
//! 3. `choose_best` เลือก candidate ที่คะแนนต่ำสุดเสมอ และ error เมื่อไม่มีตัวเลือก
//! 4. คะแนนไม่ติดลบเมื่อ input ทั้งหมดไม่ติดลบ

use compute_scheduler::cost::score_target;
use compute_scheduler::weights::AdaptiveWeights;
use compute_scheduler::{ComputeProfile, ComputeScheduler, ComputeTarget};
use proptest::prelude::*;

/// ช่วงค่า f64 ที่ finite และไม่ติดลบ สำหรับโปรไฟล์/น้ำหนัก
fn nonneg() -> impl Strategy<Value = f64> {
    0.0f64..1.0e6
}

fn profile_strategy() -> impl Strategy<Value = ComputeProfile> {
    (nonneg(), nonneg(), nonneg()).prop_map(|(latency_ms, power_watts, cost_units)| {
        ComputeProfile {
            latency_ms,
            power_watts,
            cost_units,
        }
    })
}

fn target_strategy() -> impl Strategy<Value = ComputeTarget> {
    prop_oneof![
        Just(ComputeTarget::Cpu),
        Just(ComputeTarget::Gpu),
        Just(ComputeTarget::Npu),
    ]
}

proptest! {
    /// Invariant 1: latency สูงขึ้นโดยตัวแปรอื่นคงที่ → คะแนนต้องไม่ลดลง
    #[test]
    fn score_is_monotonic_in_latency(
        lat_low in nonneg(),
        lat_delta in nonneg(),
        power in nonneg(),
        cost in nonneg(),
        (w1, w2, w3) in (nonneg(), nonneg(), nonneg()),
    ) {
        let weights = AdaptiveWeights::new(w1, w2, w3);
        let low = ComputeProfile { latency_ms: lat_low, power_watts: power, cost_units: cost };
        let high = ComputeProfile { latency_ms: lat_low + lat_delta, power_watts: power, cost_units: cost };

        prop_assert!(score_target(low, &weights) <= score_target(high, &weights));
    }

    /// Invariant 2: weights เป็นศูนย์ทั้งหมด → คะแนนเป็นศูนย์เสมอ
    #[test]
    fn zero_weights_always_give_zero_score(profile in profile_strategy()) {
        let weights = AdaptiveWeights::new(0.0, 0.0, 0.0);
        prop_assert_eq!(score_target(profile, &weights), 0.0);
    }

    /// Invariant 3a: `choose_best` เลือก candidate ที่คะแนนต่ำสุดเสมอ
    #[test]
    fn choose_best_picks_minimum_score(
        candidates in prop::collection::vec((target_strategy(), profile_strategy()), 1..16),
        (w1, w2, w3) in (nonneg(), nonneg(), nonneg()),
    ) {
        let scheduler = ComputeScheduler::with_weights(AdaptiveWeights::new(w1, w2, w3));
        let chosen = scheduler.choose_best(&candidates).expect("non-empty candidates");

        // คะแนนของ target ที่ถูกเลือกต้องไม่เกินคะแนนของ candidate ใด ๆ
        let chosen_score = candidates
            .iter()
            .filter(|(t, _)| *t == chosen)
            .map(|(_, p)| scheduler.score(*p))
            .fold(f64::INFINITY, f64::min);
        for (_, profile) in &candidates {
            prop_assert!(chosen_score <= scheduler.score(*profile));
        }
    }

    /// Invariant 4: คะแนนไม่ติดลบเมื่อ input ไม่ติดลบ
    #[test]
    fn score_is_nonnegative_for_nonnegative_inputs(
        profile in profile_strategy(),
        (w1, w2, w3) in (nonneg(), nonneg(), nonneg()),
    ) {
        let weights = AdaptiveWeights::new(w1, w2, w3);
        prop_assert!(score_target(profile, &weights) >= 0.0);
    }
}

/// Invariant 3b: ไม่มี candidate → ต้องได้ Err (ไม่ panic)
#[test]
fn choose_best_errors_on_empty_candidates() {
    let scheduler = ComputeScheduler::new();
    assert!(scheduler.choose_best(&[]).is_err());
}
