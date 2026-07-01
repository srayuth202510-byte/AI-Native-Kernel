//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
#![allow(missing_docs)]
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use intent_bus::IntentType;
use kernel_companion::KernelCompanion;
use tokio::runtime::Runtime;

fn bench_classify_intent(c: &mut Criterion) {
    let companion = KernelCompanion::new();

    c.bench_function("classify_intent", |b| {
        b.iter(|| {
            let class = companion.classify_intent(black_box(&IntentType::Structured));
            black_box(class)
        });
    });

    c.bench_function("classify_intent_all_types", |b| {
        b.iter(|| {
            for ty in &[
                IntentType::NaturalLanguage,
                IntentType::Structured,
                IntentType::Command,
                IntentType::Event,
                IntentType::Interrupt,
            ] {
                let class = companion.classify_intent(black_box(ty));
                black_box(class);
            }
        });
    });
}

fn bench_new(c: &mut Criterion) {
    c.bench_function("kernel_companion_new", |b| {
        b.iter(|| {
            let companion = KernelCompanion::new();
            black_box(companion)
        });
    });
}

fn bench_boot_shutdown(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Pre-check: verify that boot() can succeed in this environment.
    // In sandboxes without UDS or eBPF privileges, boot() will fail.
    let probe = rt.block_on(async {
        let mut c = KernelCompanion::new();
        c.boot().await
    });
    if let Err(e) = probe {
        eprintln!(
            "SKIP: boot_and_shutdown bench (boot not available: {:?})",
            e
        );
        return;
    }
    // If probe succeeded, the first boot already ran; we need a fresh instance
    // for the actual benchmark, so shut down the probed one isn't needed
    // (it was dropped at end of block_on).

    c.bench_function("boot_and_shutdown", |b| {
        b.iter_batched(
            KernelCompanion::new,
            |mut companion| {
                rt.block_on(async {
                    let _ = companion.boot().await;
                    companion.shutdown().await;
                    black_box(())
                });
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_classify_intent,
    bench_new,
    bench_boot_shutdown,
);
criterion_main!(benches);
