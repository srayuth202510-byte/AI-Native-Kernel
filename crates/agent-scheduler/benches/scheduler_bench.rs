use agent_scheduler::AgentScheduler;
use agent_scheduler::block::AgentControlBlock;
use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope};
use context_memory::ContextMemoryManager;
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use intent_bus::IntentBus;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_spawn_agents(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("spawn_agent", |b| {
        b.iter_batched(
            || {
                AgentScheduler::new(
                    Arc::new(IntentBus::new(1024)),
                    Arc::new(ContextMemoryManager::new()),
                    Arc::new(CapabilitySecurityManager::new()),
                )
            },
            |scheduler| {
                rt.block_on(async {
                    let id = scheduler
                        .spawn_agent(AgentControlBlock::new(0))
                        .await
                        .unwrap();
                    black_box(id)
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_agent_lifecycle(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("agent_lifecycle_spawn_pause_resume_terminate", |b| {
        b.iter_batched(
            || {
                AgentScheduler::new(
                    Arc::new(IntentBus::new(1024)),
                    Arc::new(ContextMemoryManager::new()),
                    Arc::new(CapabilitySecurityManager::new()),
                )
            },
            |scheduler| {
                rt.block_on(async {
                    let id = scheduler
                        .spawn_agent(AgentControlBlock::new(0))
                        .await
                        .unwrap();
                    scheduler.pause_agent(id).await.unwrap();
                    scheduler.resume_agent(id).await.unwrap();
                    scheduler.terminate_agent(id).await.unwrap();
                    black_box(id)
                });
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_get_running_agents(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let scheduler = AgentScheduler::new(
        Arc::new(IntentBus::new(1024)),
        Arc::new(ContextMemoryManager::new()),
        Arc::new(CapabilitySecurityManager::new()),
    );
    rt.block_on(async {
        for _ in 0..100 {
            scheduler
                .spawn_agent(AgentControlBlock::new(0))
                .await
                .unwrap();
        }
    });

    c.bench_function("get_running_agents_100", |b| {
        b.iter(|| {
            rt.block_on(async {
                let agents = scheduler.get_running_agents().await;
                black_box(agents.len())
            })
        });
    });
}

fn bench_grant_capability(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let token = CapabilityToken::new(
        1,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0x42u8; 32],
    );

    c.bench_function("grant_capability", |b| {
        b.iter_batched(
            || {
                let scheduler = AgentScheduler::new(
                    Arc::new(IntentBus::new(1024)),
                    Arc::new(ContextMemoryManager::new()),
                    Arc::new(CapabilitySecurityManager::new()),
                );
                let id = rt
                    .block_on(scheduler.spawn_agent(AgentControlBlock::new(0)))
                    .unwrap();
                (scheduler, id)
            },
            |(scheduler, id)| {
                rt.block_on(async {
                    scheduler.grant_capability(id, token.clone()).await.unwrap();
                    black_box(())
                });
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_spawn_agents,
    bench_agent_lifecycle,
    bench_get_running_agents,
    bench_grant_capability,
);
criterion_main!(benches);
