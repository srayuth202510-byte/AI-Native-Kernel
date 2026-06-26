use compute_scheduler::{ComputeProfile, ComputeScheduler, ComputeTarget};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_score(c: &mut Criterion) {
    let scheduler = ComputeScheduler::new();
    let profile = ComputeProfile {
        latency_ms: 10.0,
        power_watts: 50.0,
        cost_units: 5.0,
    };

    c.bench_function("score", |b| {
        b.iter(|| {
            let score = scheduler.score(black_box(profile));
            black_box(score)
        });
    });
}

fn bench_choose_best_4_candidates(c: &mut Criterion) {
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
        (
            ComputeTarget::Cloud,
            ComputeProfile {
                latency_ms: 100.0,
                power_watts: 5.0,
                cost_units: 200.0,
            },
        ),
    ];

    c.bench_function("choose_best_4", |b| {
        b.iter(|| {
            let best = scheduler.choose_best(black_box(&candidates));
            black_box(best)
        });
    });
}

fn bench_choose_best_10_candidates(c: &mut Criterion) {
    let scheduler = ComputeScheduler::new();
    let candidates: Vec<_> = (0..10)
        .map(|i| {
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: (i as f64) * 10.0,
                    power_watts: (i as f64) * 5.0,
                    cost_units: (i as f64) * 2.0,
                },
            )
        })
        .collect();

    c.bench_function("choose_best_10", |b| {
        b.iter(|| {
            let best = scheduler.choose_best(black_box(&candidates));
            black_box(best)
        });
    });
}

fn bench_update_weights(c: &mut Criterion) {
    let scheduler = ComputeScheduler::new();
    let sample = ComputeProfile {
        latency_ms: 100.0,
        power_watts: 10.0,
        cost_units: 1.0,
    };

    c.bench_function("update_weights", |b| {
        b.iter(|| {
            scheduler.update_weights(black_box(sample));
        });
    });
}

fn bench_score_with_updated_weights(c: &mut Criterion) {
    let scheduler = ComputeScheduler::new();
    let sample = ComputeProfile {
        latency_ms: 100.0,
        power_watts: 10.0,
        cost_units: 1.0,
    };
    for _ in 0..50 {
        scheduler.update_weights(sample);
    }
    let profile = ComputeProfile {
        latency_ms: 10.0,
        power_watts: 50.0,
        cost_units: 5.0,
    };

    c.bench_function("score_after_50_updates", |b| {
        b.iter(|| {
            let score = scheduler.score(black_box(profile));
            black_box(score)
        });
    });
}

criterion_group!(
    benches,
    bench_score,
    bench_choose_best_4_candidates,
    bench_choose_best_10_candidates,
    bench_update_weights,
    bench_score_with_updated_weights,
);
criterion_main!(benches);
