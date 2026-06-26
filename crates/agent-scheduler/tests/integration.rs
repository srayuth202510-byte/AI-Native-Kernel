use agent_scheduler::block::AgentControlBlock;
use agent_scheduler::AgentScheduler;
use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope};
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn scheduler() -> AgentScheduler {
    AgentScheduler::new(
        Arc::new(IntentBus::new(32)),
        Arc::new(ContextMemoryManager::new()),
        Arc::new(CapabilitySecurityManager::new()),
    )
}

#[tokio::test]
async fn spawn_100_agents_and_verify() {
    let scheduler = scheduler();
    let mut ids = Vec::new();

    for _ in 0..100 {
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .expect("spawn should succeed");
        ids.push(id);
    }

    assert_eq!(scheduler.get_running_agents().await.len(), 100);

    for id in &ids {
        let agent = scheduler.get_agent(*id).await.expect("agent should exist");
        assert_eq!(agent.id, *id);
    }
}

#[tokio::test]
async fn monitoring_stream_receives_events() {
    let scheduler = scheduler();
    let mut events = scheduler.subscribe();

    let id = scheduler
        .spawn_agent(AgentControlBlock::new(42))
        .await
        .expect("spawn should succeed");

    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("should receive event")
        .expect("event should be ok");
    match event {
        agent_scheduler::AgentEvent::AgentSpawned(agent) => {
            assert_eq!(agent.id, 42);
        }
        other => panic!("expected AgentSpawned event, got {other:?}"),
    }

    scheduler.pause_agent(id).await.unwrap();
    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("should receive pause event")
        .expect("event should be ok");
    match event {
        agent_scheduler::AgentEvent::AgentPaused(agent) => {
            assert_eq!(agent.id, 42);
        }
        other => panic!("expected AgentPaused event, got {other:?}"),
    }
}

#[tokio::test]
async fn intent_bus_and_scheduler_interop() {
    let scheduler = scheduler();
    let mut subscriber = scheduler.intent_bus().subscribe();

    let intent = Intent::new(
        "spawn-cmd",
        IntentType::Command,
        "spawn-agent",
        IntentPriority::Critical,
        "integration-test",
    );

    scheduler
        .submit_intent(intent)
        .await
        .expect("intent should be submitted");

    let received = tokio::time::timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("should receive intent")
        .expect("intent should be valid");

    assert_eq!(received.payload, "spawn-agent");
    assert_eq!(received.intent_type, IntentType::Command);
}

#[tokio::test]
async fn grant_capability_then_terminate() {
    let scheduler = scheduler();
    let id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .expect("spawn should succeed");

    let token = CapabilityToken::new(
        100,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0x42u8; 32],
    );

    scheduler
        .grant_capability(id, token)
        .await
        .expect("grant should succeed");

    let agent = scheduler.get_agent(id).await.unwrap();
    assert_eq!(agent.capabilities.len(), 1);

    scheduler.terminate_agent(id).await.unwrap();
    assert!(matches!(
        scheduler.get_agent(id).await,
        Err(agent_scheduler::SchedulerError::AgentNotFound)
    ));
}
