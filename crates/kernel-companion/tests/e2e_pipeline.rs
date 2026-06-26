#![deny(unsafe_code)]

use agent_scheduler::{block::AgentControlBlock, AgentScheduler};
use capability_security::CapabilitySecurityManager;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use kernel_companion::ebpf::tokio_util_cancel::CancellationToken;
use kernel_companion::{SyscallTracer, ebpf::PolicyDecision};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn pipeline() -> (
    IntentBus,
    AgentScheduler,
    Arc<CapabilitySecurityManager>,
    Arc<ContextMemoryManager>,
) {
    let intent_bus = Arc::new(IntentBus::new(1024));
    let context_memory = Arc::new(ContextMemoryManager::new());
    let capability_security = Arc::new(CapabilitySecurityManager::new());
    let agent_scheduler = AgentScheduler::new(
        Arc::clone(&intent_bus),
        Arc::clone(&context_memory),
        Arc::clone(&capability_security),
    );
    (
        Arc::try_unwrap(intent_bus).unwrap_or_else(|arc| (*arc).clone()),
        agent_scheduler,
        capability_security,
        context_memory,
    )
}

// ---- E2E-1: SyscallTracer → Channel (simulation mode) ----

#[tokio::test]
async fn e2e_tracer_delivers_simulated_events() {
    let cancel = CancellationToken::new();
    let (tracer, mut rx) = SyscallTracer::new(Arc::new(kernel_companion::LsmPolicyEngine::new()));

    let handle = tokio::spawn(async move { tracer.run(cancel).await });

    let mut events = Vec::new();
    while let Some(event) = timeout(Duration::from_millis(500), rx.recv())
        .await
        .ok()
        .flatten()
    {
        events.push(event);
    }

    assert_eq!(events.len(), 4, "simulation should produce exactly 4 events");
    assert_eq!(events[0].syscall_name, "read");
    assert_eq!(events[1].syscall_name, "write");
    assert_eq!(events[2].syscall_name, "execve");
    assert_eq!(events[3].syscall_name, "open");

    assert_eq!(events[0].decision, PolicyDecision::Allow);
    assert_eq!(events[1].decision, PolicyDecision::Allow);
    assert_eq!(events[2].decision, PolicyDecision::Deny);
    assert_eq!(events[3].decision, PolicyDecision::Deny);

    handle.await.unwrap().ok();
}

// ---- E2E-2: SyscallTracer → IntentBus → AgentScheduler (full pipeline) ----

#[tokio::test]
async fn e2e_full_pipeline_tracer_to_scheduler() {
    let (intent_bus, agent_scheduler, _cap, _ctx) = pipeline();
    let mut subscriber = intent_bus.subscribe();

    let cancel = CancellationToken::new();
    let (tracer, mut rx) = SyscallTracer::new(Arc::new(kernel_companion::LsmPolicyEngine::new()));

    // 1) Start tracer (simulation mode)
    let tracer_handle = tokio::spawn(async move { tracer.run(cancel).await });

    // 2) Bridge: convert SyscallEvents → Intents and publish to IntentBus
    let bus_arc = Arc::new(intent_bus);
    let bus_for_bridge = Arc::clone(&bus_arc);
    let bridge_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let intent = Intent::new(
                format!("syscall-{}", event.syscall_nr),
                IntentType::Event,
                format!("syscall:{} pid={} uid={}", event.syscall_name, event.pid, event.uid),
                IntentPriority::Medium,
                "ebpf-tracer",
            );
            let _ = bus_for_bridge.publish(intent).await;
        }
    });

    // 3) Receive all 4 intents
    let mut received = Vec::new();
    for _ in 0..4 {
        let intent = timeout(Duration::from_millis(500), subscriber.receive())
            .await
            .expect("timeout waiting for intent")
            .expect("channel closed");
        received.push(intent);
    }

    assert_eq!(received.len(), 4);
    assert!(received[0].payload.contains("read"));
    assert!(received[2].payload.contains("execve"));
    assert_eq!(received[0].source, "ebpf-tracer");

    // 4) Publish a Command intent to spawn agent via pipeline
    let spawn_intent = Intent::new(
        "cmd-1",
        IntentType::Command,
        "spawn-agent",
        IntentPriority::High,
        "e2e-test",
    );
    bus_arc.publish(spawn_intent).await.unwrap();

    // 5) Route through AgentScheduler
    while let Some(intent) = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .ok()
        .flatten()
    {
        let _ = agent_scheduler.route_intent(intent).await;
    }

    // 6) Verify agent was spawned
    let running = agent_scheduler.get_running_agents().await;
    assert_eq!(running.len(), 1, "AgentScheduler should have 1 running agent");

    // Cleanup
    tracer_handle.abort();
    bridge_handle.abort();
}

// ---- E2E-3: Policy enforcement — execve denied, read/write allowed ----

#[tokio::test]
async fn e2e_policy_denies_dangerous_syscalls() {
    let policy = Arc::new(kernel_companion::LsmPolicyEngine::new());
    let (tracer, mut rx) = SyscallTracer::new(policy);

    let cancel = CancellationToken::new();
    tokio::spawn(async move { tracer.run(cancel).await });

    let mut allow_count = 0;
    let mut deny_count = 0;

    while let Some(event) = timeout(Duration::from_millis(500), rx.recv())
        .await
        .ok()
        .flatten()
    {
        match event.decision {
            PolicyDecision::Allow => allow_count += 1,
            PolicyDecision::Deny => deny_count += 1,
        }
    }

    assert_eq!(allow_count, 2, "read + write should be allowed");
    assert_eq!(deny_count, 2, "execve + open should be denied");
}

// ---- E2E-4: Agent spawn via IntentBus → route → verify state ----

#[tokio::test]
async fn e2e_spawn_agent_via_bus() {
    let (intent_bus, scheduler, _, _) = pipeline();

    // Subscribe before publishing — broadcast requires at least one active subscriber
    let mut subscriber = intent_bus.subscribe();

    let intent = Intent::new(
        "spawn-cmd",
        IntentType::Command,
        "spawn-agent",
        IntentPriority::High,
        "system",
    );
    intent_bus.publish(intent).await.unwrap();

    let received = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout")
        .expect("no intent");

    scheduler.route_intent(received).await.unwrap();

    let agents = scheduler.get_running_agents().await;
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].state, agent_scheduler::block::AgentState::Running);
}

// ---- E2E-5: Context update via structured intent ----

#[tokio::test]
async fn e2e_context_update_via_structured_intent() {
    let (intent_bus, scheduler, _, _) = pipeline();

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    // Subscribe before publishing
    let mut subscriber = intent_bus.subscribe();

    let mut intent = Intent::new(
        "ctx-1",
        IntentType::Structured,
        "important-context-data",
        IntentPriority::Low,
        "upstream-agent",
    );
    intent
        .metadata
        .insert("agent_id".to_string(), agent_id.to_string());
    intent
        .metadata
        .insert("context_key".to_string(), "ctx-e2e".to_string());

    intent_bus.publish(intent).await.unwrap();

    let received = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout")
        .expect("no intent");

    scheduler.route_intent(received).await.unwrap();

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.context_key.as_deref(), Some("ctx-e2e"));

    let ctx_value = scheduler
        .context_memory()
        .get("ctx-e2e")
        .expect("context should exist in memory");
    assert_eq!(ctx_value, b"important-context-data".to_vec());
}

// ---- E2E-6: Capability grant through full pipeline ----

#[tokio::test]
async fn e2e_capability_grant_full_pipeline() {
    let (_intent_bus, scheduler, _, _) = pipeline();
    use capability_security::{CapabilityToken, Scope};

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    let token = CapabilityToken::new(
        100,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0u8; 32],
    );

    scheduler
        .grant_capability(agent_id, token.clone())
        .await
        .expect("grant should succeed");

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.capabilities.len(), 1);
    assert_eq!(agent.capabilities[0].id, 100);
}

// ---- E2E-7: Supervisor restarts failed agent ----

#[tokio::test]
async fn e2e_supervisor_recovers_failed_agent() {
    let (_intent_bus, scheduler, _, _) = pipeline();

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    scheduler.fail_agent(agent_id).await.unwrap();

    // Re-read agent AFTER fail to get the current Failed state
    let failed_agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(failed_agent.state, agent_scheduler::block::AgentState::Failed);

    let recovered = scheduler.supervisor().monitor_agent(&failed_agent).await;
    assert!(recovered, "supervisor should recover the agent");

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.state, agent_scheduler::block::AgentState::Running);
}
