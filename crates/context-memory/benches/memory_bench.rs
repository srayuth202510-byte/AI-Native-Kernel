use context_memory::ContextMemoryManager;
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

fn bench_put_hot(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();
    let mut counter = 0u64;

    c.bench_function("put_hot_1kb", |b| {
        b.iter_batched(
            || {
                counter += 1;
                (format!("key_{counter}"), vec![0u8; 1024])
            },
            |(key, value)| {
                memory.put(black_box(key), black_box(value));
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_get_hot_hit(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();
    memory.put("benchmark-key", vec![0xABu8; 1024]);

    c.bench_function("get_hot_hit", |b| {
        b.iter(|| {
            let result = memory.get(black_box("benchmark-key"));
            black_box(result)
        });
    });
}

fn bench_get_miss(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();

    c.bench_function("get_miss", |b| {
        b.iter(|| {
            let result = memory.get(black_box("nonexistent-key"));
            black_box(result)
        });
    });
}

fn bench_promote(c: &mut Criterion) {
    let memory = ContextMemoryManager::with_capacity(1, 1024);
    memory.put("promote-me", vec![0x42u8; 512]);
    memory.put("evict-other", vec![0xFFu8; 512]);

    c.bench_function("promote_from_warm_to_hot", |b| {
        b.iter(|| {
            memory.promote(black_box("promote-me")).unwrap();
            black_box(())
        });
    });
}

fn bench_demote(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();

    c.bench_function("demote_from_hot_to_warm", |b| {
        b.iter(|| {
            memory.put("demote-me", vec![0x42u8; 512]);
            memory.demote("demote-me").unwrap();
            black_box(())
        });
    });
}

fn bench_tier_of_hit(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();
    memory.put("tier-key", vec![0x01u8; 64]);

    c.bench_function("tier_of_hit", |b| {
        b.iter(|| {
            let result = memory.tier_of(black_box("tier-key"));
            black_box(result)
        });
    });
}

fn bench_eviction_chain(c: &mut Criterion) {
    let memory = ContextMemoryManager::with_capacity(10, 10);
    let mut batch_id = 0u64;

    c.bench_function("eviction_chain_hot_to_cold", |b| {
        b.iter_batched(
            || {
                batch_id += 1;
                (0..30)
                    .map(move |i| format!("evict-key-{batch_id}-{i}"))
                    .collect::<Vec<_>>()
            },
            |keys| {
                for key in keys {
                    memory.put(key, vec![0xBBu8; 256]);
                }
                black_box(())
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_overwrite_existing(c: &mut Criterion) {
    let memory = ContextMemoryManager::new();
    memory.put("overwrite-key", vec![0x00u8; 128]);

    c.bench_function("overwrite_existing", |b| {
        b.iter(|| {
            memory.put(black_box("overwrite-key"), black_box(vec![0xFFu8; 128]));
        });
    });
}

criterion_group!(
    benches,
    bench_put_hot,
    bench_get_hot_hit,
    bench_get_miss,
    bench_promote,
    bench_demote,
    bench_tier_of_hit,
    bench_eviction_chain,
    bench_overwrite_existing,
);
criterion_main!(benches);
