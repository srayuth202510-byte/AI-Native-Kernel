use compute_scheduler::{ComputeError, ComputeProfile, ComputeScheduler, ComputeTarget};

#[test]
fn all_target_types_scorable() {
    let scheduler = ComputeScheduler::new();

    let targets = [
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
        (
            ComputeTarget::Cloud,
            ComputeProfile {
                latency_ms: 100.0,
                power_watts: 5.0,
                cost_units: 200.0,
            },
        ),
    ];

    for (target, profile) in &targets {
        let chosen = scheduler
            .choose_best(&[(*target, *profile)])
            .expect("single candidate should be chosen");
        assert_eq!(
            chosen, *target,
            "{target:?} should be chosen when only candidate"
        );
    }
}

#[test]
fn weight_update_diverges_scores() {
    let scheduler = ComputeScheduler::new();
    let cpu = ComputeProfile {
        latency_ms: 50.0,
        power_watts: 80.0,
        cost_units: 20.0,
    };
    let gpu = ComputeProfile {
        latency_ms: 5.0,
        power_watts: 150.0,
        cost_units: 50.0,
    };

    let score_before = scheduler.score(gpu);

    for _ in 0..100 {
        scheduler.update_weights(cpu);
    }

    let score_after = scheduler.score(gpu);
    assert!(
        (score_before - score_after).abs() > 0.01,
        "scores should diverge after weight updates: before={score_before}, after={score_after}"
    );
}

#[test]
fn no_candidates_returns_error() {
    let scheduler = ComputeScheduler::new();
    let result = scheduler.choose_best(&[]);
    assert_eq!(result, Err(ComputeError::NoTargetAvailable));
}

#[test]
fn identical_profiles_choose_one() {
    let scheduler = ComputeScheduler::new();
    let profile = ComputeProfile {
        latency_ms: 10.0,
        power_watts: 10.0,
        cost_units: 10.0,
    };
    let candidates = [(ComputeTarget::Cpu, profile), (ComputeTarget::Gpu, profile)];

    let result = scheduler.choose_best(&candidates).expect("should pick one");
    assert!(result == ComputeTarget::Cpu || result == ComputeTarget::Gpu);
}
