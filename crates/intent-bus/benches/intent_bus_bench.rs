#![allow(missing_docs)]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use intent_bus::{FilterCondition, Intent, IntentBus, IntentFilter, IntentPriority, IntentType};
use tokio::runtime::Runtime;

fn bench_publish_subscribe(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("publish_single_subscriber", |b| {
        b.iter_batched(
            || {
                let bus = IntentBus::new(1024);
                let subscriber = bus.subscribe();
                let intent = Intent::new(
                    "bench-intent",
                    IntentType::Command,
                    "spawn-agent",
                    IntentPriority::High,
                    "bench",
                );
                (bus, subscriber, intent)
            },
            |(bus, mut subscriber, intent)| {
                rt.block_on(async {
                    bus.publish(intent).await.unwrap();
                    let received = subscriber.receive().await;
                    black_box(received)
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_publish_100_intents(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let bus = IntentBus::new(1024);
    let mut subscriber = bus.subscribe();

    c.bench_function("publish_100_sequential", |b| {
        b.iter(|| {
            rt.block_on(async {
                for i in 0..100 {
                    let intent = Intent::new(
                        format!("intent-{i}"),
                        IntentType::Event,
                        "payload",
                        IntentPriority::Low,
                        "bench",
                    );
                    bus.publish(intent).await.unwrap();
                }
                for _ in 0..100 {
                    let _ = subscriber.receive().await;
                }
                black_box(())
            });
        });
    });
}

fn bench_filter_matching(c: &mut Criterion) {
    let filter = IntentFilter {
        name: "bench-filter".to_string(),
        conditions: vec![
            FilterCondition::IntentType(IntentType::Structured),
            FilterCondition::Priority(IntentPriority::Medium),
            FilterCondition::SourceContains("agent".to_string()),
            FilterCondition::TargetContains("worker".to_string()),
            FilterCondition::HasMetadata("ctx".to_string(), "val".to_string()),
        ],
        enabled: true,
    };

    let mut intent = Intent::new(
        "filter-test",
        IntentType::Structured,
        "data",
        IntentPriority::Medium,
        "agent-bench",
    );
    intent.target = Some("worker-1".to_string());
    intent.metadata.insert("ctx".to_string(), "val".to_string());

    c.bench_function("filter_matches_all_conditions", |b| {
        b.iter(|| {
            let result = filter.passes(black_box(&intent));
            black_box(result)
        });
    });
}

fn bench_add_remove_filter(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("add_remove_filter", |b| {
        b.iter_batched(
            || IntentBus::new(8),
            |bus| {
                rt.block_on(async {
                    let filter = IntentFilter {
                        name: "temp".to_string(),
                        conditions: vec![FilterCondition::IntentType(IntentType::Command)],
                        enabled: true,
                    };
                    bus.add_filter(filter).await;
                    bus.remove_filter("temp").await;
                    black_box(())
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_publish_subscribe,
    bench_publish_100_intents,
    bench_filter_matching,
    bench_add_remove_filter,
);
criterion_main!(benches);
