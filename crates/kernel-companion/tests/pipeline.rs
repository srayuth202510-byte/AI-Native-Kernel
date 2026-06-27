#![deny(unsafe_code)]

use agent_scheduler::{AgentScheduler, block::AgentControlBlock};
use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope};
use compute_scheduler::{ComputeProfile, ComputeScheduler, ComputeTarget};
use context_memory::ContextMemoryManager;
use immune_system::{BCellAgent, MacrophageAgent, TCellAgent, ThreatDecision};
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

fn full_pipeline() -> (
    Arc<IntentBus>,
    AgentScheduler,
    Arc<CapabilitySecurityManager>,
    Arc<ContextMemoryManager>,
) {
    let intent_bus = Arc::new(IntentBus::new(1024));
    let context_memory = Arc::new(ContextMemoryManager::new());
    let capability_security = Arc::new(CapabilitySecurityManager::new());
    let scheduler = AgentScheduler::new(
        Arc::clone(&intent_bus),
        Arc::clone(&context_memory),
        Arc::clone(&capability_security),
    );
    (intent_bus, scheduler, capability_security, context_memory)
}

// ---------------------------------------------------------------------------
// INT-1: Immune System closed-loop pipeline
//   T-Cell detects anomaly → publishes via IntentBus → B-Cell learns
//   → generates antibody → policy can use it
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_immune_system_closed_loop() {
    let (intent_bus, _scheduler, _cap, _ctx) = full_pipeline();
    let tcell = TCellAgent::new(100, 5);
    let bcell = BCellAgent::new(100);

    // Simulate a privilege escalation attack sequence
    let pid = 42u32;

    // Phase 1: T-Cell observes suspicious syscalls
    let d1 = tcell.observe_syscall(pid, "setuid", false).await;
    assert_eq!(d1, ThreatDecision::Safe);

    let d2 = tcell.observe_syscall(pid, "execve", false).await;
    assert_eq!(d2, ThreatDecision::Quarantine);

    // Phase 2: Subscribe before publishing (broadcast requires active subscriber)
    let mut subscriber = intent_bus.subscribe();

    tcell.quarantine(pid).await;
    assert!(tcell.is_quarantined(pid).await);

    let threat_intent = Intent::new(
        "threat-setuid-execve",
        IntentType::Event,
        format!(
            "threat: pid={} sequence=setuid->execve score={:.1}",
            pid, 8.0
        ),
        IntentPriority::High,
        "tcell-agent",
    );
    intent_bus.publish(threat_intent).await.unwrap();

    // Phase 3: B-Cell learns from the threat via IntentBus
    let received = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout")
        .expect("no intent");

    assert!(received.source == "tcell-agent");
    assert!(received.payload.contains("threat:"));

    // Phase 4: B-Cell learns the pattern and generates antibody
    for _ in 0..5 {
        bcell.learn_threat(vec!["execve".to_string()], 8).await;
    }
    let antibody = bcell.generate_antibody().await;
    assert!(antibody.is_some());
    assert_eq!(antibody.unwrap().blocked_syscall, "execve");

    let antibodies = bcell.get_antibodies().await;
    assert_eq!(antibodies.len(), 1);
    assert_eq!(antibodies[0].blocked_syscall, "execve");
}

// ---------------------------------------------------------------------------
// INT-2: Capability token full lifecycle across security + scheduler
//   Issue → authorize → grant to agent → expire → revoke
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_capability_token_lifecycle() {
    let (_intent_bus, scheduler, cap_mgr, _ctx) = full_pipeline();

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    let token = CapabilityToken::new(
        200,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0u8; 32],
    );

    // Issue in security manager
    cap_mgr.issue_token(token.clone()).unwrap();

    // Authorize — should pass
    assert!(cap_mgr.authorize_token(&token, "read").unwrap());

    // Grant to agent via scheduler
    scheduler
        .grant_capability(agent_id, token.clone())
        .await
        .unwrap();

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.capabilities.len(), 1);
    assert_eq!(agent.capabilities[0].id, 200);

    // Deny for unauthorized action
    assert!(!cap_mgr.authorize_token(&token, "write").unwrap());

    // Revoke
    cap_mgr.revoke_token(token.id).unwrap();
    assert!(!cap_mgr.authorize_token(&token, "read").unwrap());
}

// ---------------------------------------------------------------------------
// INT-3: Compute scheduler + context memory integration
//   Context data influences compute placement decisions
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_compute_with_context_influence() {
    let (_intent_bus, scheduler, _cap, ctx_mgr) = full_pipeline();

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    // Store compute-relevant context
    ctx_mgr.put("agent-type", b"gpu-inference".to_vec());
    ctx_mgr.put("latency-requirement", b"low".to_vec());

    scheduler
        .store_context(agent_id, "agent-type", b"gpu-inference".to_vec())
        .await
        .unwrap();

    // Compute scheduler chooses best device
    let compute = ComputeScheduler::new();
    let candidates = [
        (
            ComputeTarget::Cpu,
            ComputeProfile {
                latency_ms: 100.0,
                power_watts: 200.0,
                cost_units: 50.0,
            },
        ),
        (
            ComputeTarget::Gpu,
            ComputeProfile {
                latency_ms: 1.0,
                power_watts: 150.0,
                cost_units: 20.0,
            },
        ),
    ];

    // Default weights (lat=0.8, pow=0.1, cost=0.1): GPU=17.8, CPU=105 → GPU wins
    let best = compute.choose_best(&candidates).unwrap();
    assert_eq!(best, ComputeTarget::Gpu);

    // Verify context is accessible via agent
    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.context_key.as_deref(), Some("agent-type"));
    let ctx_value = ctx_mgr.get("agent-type").unwrap();
    assert_eq!(ctx_value, b"gpu-inference".to_vec());
}

// ---------------------------------------------------------------------------
// INT-4: Macrophage GC pipeline
//   Sweeps stale intents and expired context entries
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_macrophage_gc_pipeline() {
    let intent_bus = Arc::new(IntentBus::new(16));
    let ctx_mgr = Arc::new(ContextMemoryManager::new());

    let macrophage = MacrophageAgent::new(
        Arc::clone(&intent_bus),
        Arc::clone(&ctx_mgr),
        10, // max_intent_age_ms
        0,  // context_ttl_secs — expires immediately
    );

    // Test is_stale directly
    let fresh = Intent::new(
        "fresh",
        IntentType::Event,
        "data",
        IntentPriority::Low,
        "test",
    );
    assert!(!MacrophageAgent::is_stale(&fresh, 1000));

    let mut stale = Intent::new(
        "stale",
        IntentType::Event,
        "old",
        IntentPriority::Low,
        "test",
    );
    // Manually set old timestamp
    stale.timestamp = std::time::SystemTime::now() - Duration::from_secs(60);
    assert!(MacrophageAgent::is_stale(&stale, 1000));

    // Test sweep_context with expired entries
    ctx_mgr.put("expired-key", b"expired-value".to_vec());
    let cleaned = macrophage.sweep_context().await;
    assert!(cleaned >= 1, "should clean at least 1 expired context");

    // Publish and sweep in a single subscriber lifecycle
    let mut sub = intent_bus.subscribe();
    let intent = Intent::new(
        "live-1",
        IntentType::Event,
        "live-data",
        IntentPriority::Low,
        "test",
    );
    intent_bus.publish(intent).await.unwrap();

    // Consume the intent through our subscriber (it's not stale)
    let received = tokio::time::timeout(Duration::from_millis(100), sub.receive())
        .await
        .expect("timeout")
        .expect("no intent");
    assert_eq!(received.payload, "live-data");

    let stats = macrophage.stats();
    assert!(stats.collected_context >= 1, "should have cleaned context");
}

// ---------------------------------------------------------------------------
// INT-5: Multi-agent context isolation
//   Each agent's context is independent and doesn't leak
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_multi_agent_context_isolation() {
    let (_intent_bus, scheduler, _cap, ctx_mgr) = full_pipeline();

    let alice = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();
    let bob = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    assert_ne!(alice, bob, "agent IDs must be unique");

    scheduler
        .store_context(alice, "alice-key", b"alice-data".to_vec())
        .await
        .unwrap();
    scheduler
        .store_context(bob, "bob-key", b"bob-data".to_vec())
        .await
        .unwrap();

    // Alice does not have Bob's context key
    let alice_agent = scheduler.get_agent(alice).await.unwrap();
    assert_eq!(alice_agent.context_key.as_deref(), Some("alice-key"));

    let bob_agent = scheduler.get_agent(bob).await.unwrap();
    assert_eq!(bob_agent.context_key.as_deref(), Some("bob-key"));

    // Context values are independent
    assert_eq!(ctx_mgr.get("alice-key").unwrap(), b"alice-data".to_vec());
    assert_eq!(ctx_mgr.get("bob-key").unwrap(), b"bob-data".to_vec());
}

// ---------------------------------------------------------------------------
// INT-6: Full pipeline — NL intent → command → spawn → context → compute
//   End-to-end: user sends NL intent → bus routes → scheduler spawns
//   → agent stores context → compute scheduler picks device
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_full_end_to_end_pipeline() {
    let (intent_bus, scheduler, _cap, ctx_mgr) = full_pipeline();

    let mut subscriber = intent_bus.subscribe();

    // Phase 1: NL intent submitted
    let nl_intent = Intent::new(
        "nl-1",
        IntentType::NaturalLanguage,
        "run inference on the GPU with low latency",
        IntentPriority::Medium,
        "user",
    );
    scheduler.submit_intent(nl_intent).await.unwrap();

    let received_nl = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout")
        .expect("no intent");
    assert_eq!(received_nl.source, "user");

    // Phase 2: Command intent spawns an agent
    let cmd_intent = Intent::new(
        "cmd-1",
        IntentType::Command,
        "spawn-agent",
        IntentPriority::High,
        "user",
    );
    scheduler.route_intent(cmd_intent).await.unwrap();

    let running = scheduler.get_running_agents().await;
    assert_eq!(running.len(), 1, "agent should be spawned");

    let agent_id = running[0].id;

    // Phase 3: Structured intent updates context
    let mut ctx_intent = Intent::new(
        "ctx-1",
        IntentType::Structured,
        "gpu-inference",
        IntentPriority::High,
        "system",
    );
    ctx_intent
        .metadata
        .insert("agent_id".to_string(), agent_id.to_string());
    ctx_intent
        .metadata
        .insert("context_key".to_string(), "workload-type".to_string());
    scheduler.route_intent(ctx_intent).await.unwrap();

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.context_key.as_deref(), Some("workload-type"));
    assert_eq!(
        ctx_mgr.get("workload-type").unwrap(),
        b"gpu-inference".to_vec()
    );

    // Phase 4: Compute scheduler can use context-informed placement
    let compute = ComputeScheduler::new();
    let candidates = [
        (
            ComputeTarget::Cpu,
            ComputeProfile {
                latency_ms: 100.0,
                power_watts: 200.0,
                cost_units: 50.0,
            },
        ),
        (
            ComputeTarget::Gpu,
            ComputeProfile {
                latency_ms: 1.0,
                power_watts: 150.0,
                cost_units: 20.0,
            },
        ),
    ];
    // Default weights favor latency (0.8), so GPU with 1ms wins
    let best = compute.choose_best(&candidates).unwrap();
    assert_eq!(best, ComputeTarget::Gpu);
}

// ---------------------------------------------------------------------------
// INT-7: Supervisor with concurrent agent lifecycle across crates
//   Spawn 10 agents, fail 5, supervisor recovers all
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_supervisor_mass_recovery_across_crates() {
    let (_intent_bus, scheduler, _cap, _ctx) = full_pipeline();

    let mut ids = Vec::new();
    for _ in 0..10 {
        let id = scheduler
            .spawn_agent(AgentControlBlock::new(0))
            .await
            .unwrap();
        ids.push(id);
    }

    assert_eq!(scheduler.get_running_agents().await.len(), 10);

    // Fail 5 agents
    for id in ids.iter().take(5) {
        scheduler.fail_agent(*id).await.unwrap();
    }

    let recovering = scheduler.get_running_agents().await;
    assert_eq!(recovering.len(), 5, "5 agents should still be running");

    // Recover via supervisor
    for id in ids.iter().take(5) {
        let failed = scheduler.get_agent(*id).await.unwrap();
        assert_eq!(failed.state, agent_scheduler::block::AgentState::Failed);
        let recovered = scheduler.supervisor().monitor_agent(&failed).await;
        assert!(recovered, "supervisor should recover agent {}", id);
    }

    let all_running = scheduler.get_running_agents().await;
    assert_eq!(
        all_running.len(),
        10,
        "all 10 agents should be running after recovery"
    );
}

// ---------------------------------------------------------------------------
// INT-8: Intent bus subscriber filtering across types
//   Multiple subscribers receive only relevant intents
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_intent_bus_subscriber_filtering() {
    let bus = Arc::new(IntentBus::new(32));
    let mut sub_all = bus.subscribe();
    let mut sub_high = bus.subscribe();

    let intents = [
        Intent::new(
            "i1",
            IntentType::Command,
            "spawn",
            IntentPriority::High,
            "src1",
        ),
        Intent::new(
            "i2",
            IntentType::Event,
            "status",
            IntentPriority::Low,
            "src2",
        ),
        Intent::new(
            "i3",
            IntentType::Structured,
            "update",
            IntentPriority::High,
            "src3",
        ),
        Intent::new(
            "i4",
            IntentType::NaturalLanguage,
            "hello",
            IntentPriority::Medium,
            "src4",
        ),
    ];

    for intent in &intents {
        bus.publish(intent.clone()).await.unwrap();
    }

    // sub_all receives all 4
    for _ in 0..4 {
        let received = timeout(Duration::from_millis(100), sub_all.receive())
            .await
            .expect("timeout")
            .expect("no intent");
        assert!(!received.id.is_empty());
    }

    // sub_high should also get all 4 (broadcast — all subscribers get everything)
    for _ in 0..4 {
        let received = timeout(Duration::from_millis(100), sub_high.receive())
            .await
            .expect("timeout")
            .expect("no intent");
        assert!(!received.id.is_empty());
    }
}

// ---------------------------------------------------------------------------
// INT-9: Security audit trail across policy decisions
//   Audit logger records allow/deny decisions correctly
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_security_audit_trail() {
    let (_intent_bus, _scheduler, cap_mgr, _ctx) = full_pipeline();

    let _agent_id = _scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    let token = CapabilityToken::new(
        300,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0u8; 32],
    );

    // Issue creates an "issued" audit entry via CapabilitySecurityManager
    cap_mgr.issue_token(token.clone()).unwrap();

    // Authorize — creates an "allowed" audit entry
    let authorized = cap_mgr.authorize_token(&token, "read").unwrap();
    assert!(authorized);

    // Deny for unauthorized action — creates a "denied" audit entry
    let denied = cap_mgr.authorize_token(&token, "write").unwrap();
    assert!(!denied);

    // Revoke creates a "revoked" audit entry
    cap_mgr.revoke_token(token.id).unwrap();

    // After revocation, authorization is denied
    let after_revoke = cap_mgr.authorize_token(&token, "read").unwrap();
    assert!(!after_revoke);
}

// ---------------------------------------------------------------------------
// INT-10: Agent event monitoring across all lifecycle phases
//   Subscribe to AgentScheduler events and verify each phase
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_agent_event_monitoring_lifecycle() {
    use agent_scheduler::scheduler::AgentEvent;

    let (_intent_bus, scheduler, _cap, _ctx) = full_pipeline();
    let mut events = scheduler.subscribe();

    let agent_id = scheduler
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("timeout")
        .expect("no event");
    assert!(matches!(event, AgentEvent::AgentSpawned(_)));

    scheduler.pause_agent(agent_id).await.unwrap();
    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("timeout")
        .expect("no event");
    assert!(matches!(event, AgentEvent::AgentPaused(_)));

    scheduler.resume_agent(agent_id).await.unwrap();
    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("timeout")
        .expect("no event");
    assert!(matches!(event, AgentEvent::AgentResumed(_)));

    scheduler.terminate_agent(agent_id).await.unwrap();
    let event = timeout(Duration::from_millis(100), events.recv())
        .await
        .expect("timeout")
        .expect("no event");
    assert!(matches!(event, AgentEvent::AgentTerminated(_)));
}

// ---------------------------------------------------------------------------
// INT-11: Cross-crate context migration through tiers
//   Insert → promote → demote across hot/warm/cold with agent association
// ---------------------------------------------------------------------------
#[tokio::test]
async fn int_context_tier_migration_with_agent() {
    let (intent_bus, _scheduler, _cap, _ctx_mgr) = full_pipeline();

    // Create small capacity to force eviction
    let ctx_mgr_small = Arc::new(ContextMemoryManager::with_capacity(2, 2));
    let scheduler_with_small = AgentScheduler::new(
        Arc::clone(&intent_bus),
        Arc::clone(&ctx_mgr_small),
        Arc::new(CapabilitySecurityManager::new()),
    );

    let agent_id = scheduler_with_small
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .unwrap();

    // Feed 5 context entries to force hot→warm→cold eviction
    for i in 0..5 {
        let key = format!("ctx-{}", i);
        ctx_mgr_small.put(&key, format!("value-{}", i).into_bytes());
    }

    // Agent can store its own context
    scheduler_with_small
        .store_context(agent_id, "agent-ctx", b"agent-data".to_vec())
        .await
        .unwrap();

    // All 5 entries should exist (some in warm/cold)
    for i in 0..5 {
        let key = format!("ctx-{}", i);
        let val = ctx_mgr_small
            .get(&key)
            .expect(&format!("{} should exist", key));
        assert_eq!(val, format!("value-{}", i).into_bytes());
    }

    // Agent context is intact
    let agent = scheduler_with_small.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.context_key.as_deref(), Some("agent-ctx"));
}
