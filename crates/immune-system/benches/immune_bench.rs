//! # การทดสอบประสิทธิภาพ (Benchmarks) สำหรับ Immune System
//!
//! เน้น hot path ของ T-Cell: `observe_syscall` ถูกเรียกทุก syscall event
//! จาก kernel-companion — benchmark concurrent หลาย PID คือตัวชี้วัดหลัก
//! เพราะเป็นจุดที่ per-shard locking (DashMap) ต่างจาก global lock

#![allow(missing_docs)]

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use immune_system::TCellAgent;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// สร้าง T-Cell ที่ threshold สูงพอให้ decision เป็น Safe (วัด hot path ปกติ
/// ไม่ใช่ kill path) และปิด jitter เพื่อผลลัพธ์ที่คงที่
fn bench_tcell() -> TCellAgent {
    let tcell = TCellAgent::new(1_000_000, 10_000);
    tcell.set_jitter_enabled(false);
    tcell
}

fn bench_observe_syscall_single_pid(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let tcell = bench_tcell();

    c.bench_function("observe_syscall_single_pid", |b| {
        b.to_async(&rt).iter(|| async {
            let decision = tcell.observe_syscall(1, black_box("read"), false).await;
            black_box(decision)
        })
    });
}

fn bench_observe_syscall_multi_pid(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let tcell = bench_tcell();
    let mut pid = 0u32;

    c.bench_function("observe_syscall_multi_pid_roundrobin", |b| {
        b.to_async(&rt).iter(|| {
            pid = pid.wrapping_add(1) % 64;
            let tcell = &tcell;
            let pid = pid;
            async move {
                let decision = tcell.observe_syscall(pid, black_box("read"), false).await;
                black_box(decision)
            }
        })
    });
}

/// จุดวัดหลักของ DashMap: 8 tasks ยิง event พร้อมกันคนละ PID (128 events/task
/// = 1,024 events ต่อ iteration) — global lock จะบังคับให้ทั้งหมดต่อคิวกัน
fn bench_observe_syscall_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    const TASKS: u32 = 8;
    const EVENTS_PER_TASK: u32 = 128;

    c.bench_function("observe_syscall_concurrent_8x128", |b| {
        b.iter_batched(
            || Arc::new(bench_tcell()),
            |tcell| {
                rt.block_on(async {
                    let mut handles = Vec::with_capacity(TASKS as usize);
                    for task_id in 0..TASKS {
                        let tcell = Arc::clone(&tcell);
                        handles.push(tokio::spawn(async move {
                            for i in 0..EVENTS_PER_TASK {
                                let denied = i % 17 == 0;
                                let decision = tcell
                                    .observe_syscall(task_id + 1, black_box("read"), denied)
                                    .await;
                                black_box(decision);
                            }
                        }));
                    }
                    for handle in handles {
                        handle.await.unwrap();
                    }
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_get_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let tcell = bench_tcell();
    rt.block_on(async {
        let _ = tcell.observe_syscall(42, "read", false).await;
    });

    c.bench_function("get_stats", |b| {
        b.iter(|| {
            let stats = tcell.get_stats(black_box(42));
            black_box(stats)
        })
    });
}

criterion_group!(
    benches,
    bench_observe_syscall_single_pid,
    bench_observe_syscall_multi_pid,
    bench_observe_syscall_concurrent,
    bench_get_stats,
);
criterion_main!(benches);
