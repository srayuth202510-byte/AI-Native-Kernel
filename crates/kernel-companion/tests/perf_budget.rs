#![deny(unsafe_code)]

//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
use agent_scheduler::{AgentScheduler, block::AgentControlBlock};
use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope};
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use kernel_companion::LsmPolicyEngine;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---- Performance Budget Targets (plan §3) ----
//
// Agent spawn latency:            P99 < 500 µs
// Agent ↔ Agent context switch:   P99 < 50 µs
// Syscall decision (LSM policy):  P99 < 1 ms
// eBPF tracer overhead:           < 3% CPU
// Concurrent agents (Phase 1):    10

fn scheduler() -> AgentScheduler {
    AgentScheduler::new(
        Arc::new(IntentBus::new(1024)),
        Arc::new(ContextMemoryManager::new()),
        Arc::new(CapabilitySecurityManager::new()),
    )
}

// ---- BUDGET-1: Agent spawn latency < 500 µs (P99) ----

#[tokio::test]
async fn budget_agent_spawn_p99_below_500us() {
    let scheduler = scheduler();
    let samples = 1000;
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = scheduler.spawn_agent(AgentControlBlock::new(0)).await;
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];
    let max = latencies.last().unwrap();

    println!("[PERF] Agent spawn latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");
    println!("[PERF]   MAX  = {max:?}");
    let target = if std::env::var("CI").is_ok() {
        Duration::from_micros(1000)
    } else {
        Duration::from_micros(500)
    };
    println!("[PERF]   Target: P99 < {target:?}");

    assert!(
        p99 < target,
        "Agent spawn P99 = {p99:?} exceeds {target:?} budget"
    );
}

// ---- BUDGET-2: Context switch (pause + resume) P99 < 50 µs ----

#[tokio::test]
async fn budget_context_switch_p99_below_50us() {
    let scheduler = scheduler();
    let samples = 1000;
    let mut latencies = Vec::with_capacity(samples);

    let mut ids = Vec::new();
    for _ in 0..samples {
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .unwrap();
        ids.push(id);
    }

    for id in &ids {
        let start = Instant::now();
        let _ = scheduler.pause_agent(*id).await;
        let _ = scheduler.resume_agent(*id).await;
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];
    let max = latencies.last().unwrap();

    println!("[PERF] Context switch latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");
    println!("[PERF]   MAX  = {max:?}");
    let target = if std::env::var("CI").is_ok() {
        Duration::from_micros(100)
    } else {
        Duration::from_micros(50)
    };
    println!("[PERF]   Target: P99 < {target:?}");

    assert!(
        p99 < target,
        "Context switch P99 = {p99:?} exceeds {target:?} budget"
    );
}

// ---- BUDGET-3: Syscall decision (LSM policy) P99 < 1 ms ----

#[tokio::test]
async fn budget_syscall_decision_p99_below_1ms() {
    let policy = Arc::new(LsmPolicyEngine::new());
    let samples = 10_000;
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let (tracer, _rx) = kernel_companion::SyscallTracer::new(policy.clone());
        let start = Instant::now();
        let _ = tracer.process_syscall_event(0, 1000, 1000);
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];
    let max = latencies.last().unwrap();

    println!("[PERF] Syscall decision latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");
    println!("[PERF]   MAX  = {max:?}");
    let target = if std::env::var("CI").is_ok() {
        Duration::from_millis(5)
    } else {
        Duration::from_millis(1)
    };
    println!("[PERF]   Target: P99 < {target:?}");

    assert!(
        p99 < target,
        "Syscall decision P99 = {p99:?} exceeds {target:?} budget"
    );
}

// ---- BUDGET-4: Concurrent agents (Phase 1 target: 10) ----

#[tokio::test]
async fn budget_concurrent_agents_10() {
    let scheduler = scheduler();
    let target = 10;
    let start = Instant::now();

    for _ in 0..target {
        scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");
    }

    let elapsed = start.elapsed();
    let running = scheduler.get_running_agents().await.len();
    let per_agent = elapsed / target as u32;

    println!("[PERF] Concurrent agents spawn ({target} agents):");
    println!("[PERF]   Total time = {elapsed:?}");
    println!("[PERF]   Per agent  = {per_agent:?}");
    println!("[PERF]   Running    = {running}");

    assert_eq!(running, target, "all {target} agents should be running");
    let limit = if std::env::var("CI").is_ok() {
        Duration::from_micros(1000)
    } else {
        Duration::from_micros(500)
    };
    assert!(
        per_agent < limit,
        "per-agent spawn {per_agent:?} exceeds {limit:?}"
    );
}

// ---- BUDGET-5: IntentBus publish/subscribe throughput ----

#[tokio::test]
async fn budget_intentbus_throughput() {
    let bus = IntentBus::new(1024);
    let mut subscriber = bus.subscribe();
    let samples = 1000;

    let publish_start = Instant::now();
    for i in 0..samples {
        let intent = Intent::new(
            format!("bench-{i}"),
            IntentType::Event,
            format!("payload-{i}"),
            IntentPriority::Medium,
            "bench",
        );
        bus.publish(intent).await.unwrap();
    }
    let publish_elapsed = publish_start.elapsed();

    let mut received = 0;
    let recv_start = Instant::now();
    while let Some(_intent) = tokio::time::timeout(Duration::from_millis(500), subscriber.receive())
        .await
        .ok()
        .flatten()
    {
        received += 1;
        if received >= samples {
            break;
        }
    }
    let recv_elapsed = recv_start.elapsed();

    let pub_rate = samples as f64 / publish_elapsed.as_secs_f64();
    let recv_rate = received as f64 / recv_elapsed.as_secs_f64();

    println!("[PERF] IntentBus throughput ({samples} intents):");
    println!("[PERF]   Publish rate  = {pub_rate:.0} intents/sec");
    println!("[PERF]   Receive rate  = {recv_rate:.0} intents/sec");
    println!("[PERF]   Published     = {samples}");
    println!("[PERF]   Received      = {received}");

    assert_eq!(received, samples, "all intents should be received");
    let limit = if std::env::var("CI").is_ok() {
        5000.0
    } else {
        10000.0
    };
    assert!(
        pub_rate > limit,
        "publish rate {pub_rate:.0} should be > {limit:.0}/sec"
    );
}

// ---- BUDGET-6: Context memory put/get latency ----

#[tokio::test]
async fn budget_context_memory_hot_hit_latency() {
    let ctx = ContextMemoryManager::new();
    ctx.put("bench-key", vec![0xABu8; 1024]);

    let samples = 10_000;
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = ctx.get("bench-key");
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];

    println!("[PERF] Context memory hot get latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");

    let limit = if std::env::var("CI").is_ok() {
        Duration::from_micros(50)
    } else {
        Duration::from_micros(10)
    };
    assert!(
        p99 < limit,
        "context hot get P99 = {p99:?} exceeds {limit:?}"
    );
}

// ---- BUDGET-7: Capability token validation latency ----

#[tokio::test]
async fn budget_capability_validation_latency() {
    let cap = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        999,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0u8; 32],
    );
    cap.issue_token(token.clone()).await.unwrap();

    let samples = 10_000;
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = cap.authorize_token(&token, "read").await;
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];

    println!("[PERF] Capability validation latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");

    let limit = if std::env::var("CI").is_ok() {
        Duration::from_micros(1000)
    } else {
        Duration::from_micros(500)
    };
    assert!(
        p99 < limit,
        "capability validation P99 = {p99:?} exceeds {limit:?}"
    );
}

// ---- BUDGET-8: Compute scheduler score latency ----

#[tokio::test]
async fn budget_compute_score_latency() {
    use compute_scheduler::{ComputeProfile, ComputeScheduler};

    let scheduler = ComputeScheduler::new();
    let samples = 10_000;
    let mut latencies = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = scheduler.score(ComputeProfile {
            latency_ms: 10.0,
            power_watts: 50.0,
            cost_units: 1.0,
        });
        latencies.push(start.elapsed());
    }

    latencies.sort();
    let p99_idx = (samples as f64 * 0.99) as usize;
    let p99 = latencies[p99_idx];
    let p50 = latencies[samples / 2];

    println!("[PERF] Compute scheduler score latency ({samples} samples):");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");

    let limit = if std::env::var("CI").is_ok() {
        Duration::from_micros(50)
    } else {
        Duration::from_micros(10)
    };
    assert!(p99 < limit, "compute score P99 = {p99:?} exceeds {limit:?}");
}
