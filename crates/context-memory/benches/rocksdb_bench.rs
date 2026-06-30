#![allow(missing_docs)]
use context_memory::warm::WarmStore;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

#[cfg(feature = "rocksdb-warm")]
fn prepare_persistent_warm_store(path: &std::path::Path) {
    let mut store = WarmStore::new_with_path(path);
    let payload = vec![0u8; 1024];

    for i in 0..5_000 {
        store.insert(format!("preload_{i:05}"), payload.clone());
    }

    drop(store);
}

#[cfg(feature = "rocksdb-warm")]
fn bench_rocksdb_warm_io(c: &mut Criterion) {
    let mut group = c.benchmark_group("RocksDB_WarmStore");
    // ตั้งเวลาวัดที่น้อยลงหน่อย เพราะ RocksDB อาจจะใช้เวลานานถ้ารันเยอะ
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("insert_1kb", |b| {
        let mut store = WarmStore::new();
        let payload = vec![0u8; 1024]; // 1KB payload
        let mut i = 0;
        b.iter(|| {
            let key = format!("key_{}", i);
            store.insert(black_box(key), black_box(payload.clone()));
            i += 1;
        });
    });

    group.bench_function("get_1kb", |b| {
        let mut store = WarmStore::new();
        let payload = vec![0u8; 1024];
        let key = "target_key".to_string();
        store.insert(key.clone(), payload);

        b.iter(|| {
            let _val = store.get(black_box(&key));
        });
    });

    group.bench_function("evict_oldest_1kb", |b| {
        let mut store = WarmStore::new();
        let payload = vec![0u8; 1024];

        // เราเติมค่าลงไปจำนวนหนึ่งก่อน
        for i in 0..1000 {
            store.insert(format!("fill_{}", i), payload.clone());
        }

        b.iter(|| {
            // เมื่อเรา evict มันก็จะดึงตัวเก่าออกไปเรื่อยๆ
            // ในแต่ละรอบของการวัด เราต้องมีค่าให้มัน evict
            // (ถ้าหมดมันจะคืน None แต่เพื่อวัด performance ก็ถือว่าวัด overhead ได้)
            let _val = store.evict_oldest();
        });
    });

    group.finish();
}

#[cfg(feature = "rocksdb-warm")]
fn bench_rocksdb_warm_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("RocksDB_WarmStore_Recovery");
    group.measurement_time(Duration::from_secs(5));

    let path = std::env::temp_dir().join(format!("ank-rocksdb-bench-{}", uuid::Uuid::new_v4()));
    prepare_persistent_warm_store(&path);

    group.bench_function("reopen_and_reconstruct_fifo", |b| {
        b.iter(|| {
            let store = WarmStore::new_with_path(black_box(&path));
            black_box(store.len())
        });
    });

    group.finish();
    let _ = std::fs::remove_dir_all(&path);
}

#[cfg(feature = "rocksdb-warm")]
fn bench_rocksdb_warm_store(c: &mut Criterion) {
    bench_rocksdb_warm_io(c);
    bench_rocksdb_warm_reload(c);
}

criterion_group!(benches, bench_rocksdb_warm_store);
criterion_main!(benches);
