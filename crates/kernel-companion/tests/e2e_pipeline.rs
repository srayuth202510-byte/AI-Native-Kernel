#![deny(unsafe_code)]

//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
use agent_scheduler::{
    AgentScheduler, DistributedRoutingPolicy, RemoteNodeState, block::AgentControlBlock,
    block::AgentState,
};
use capability_security::CapabilitySecurityManager;
use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use kernel_companion::ebpf::tokio_util_cancel::CancellationToken;
use kernel_companion::{SyscallTracer, ebpf::PolicyDecision};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

fn arc_pipeline() -> (
    Arc<IntentBus>,
    Arc<AgentScheduler>,
    Arc<CapabilitySecurityManager>,
    Arc<ContextMemoryManager>,
) {
    let intent_bus = Arc::new(IntentBus::new(1024));
    let context_memory = Arc::new(ContextMemoryManager::new());
    let capability_security = Arc::new(CapabilitySecurityManager::new());
    let agent_scheduler = Arc::new(AgentScheduler::new(
        Arc::clone(&intent_bus),
        Arc::clone(&context_memory),
        Arc::clone(&capability_security),
    ));
    (
        intent_bus,
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

    let handle = tokio::spawn(async move { tracer.run(cancel, true).await });

    let mut events = Vec::new();
    while let Some(event) = timeout(Duration::from_millis(500), rx.recv())
        .await
        .ok()
        .flatten()
    {
        events.push(event);
    }

    assert_eq!(
        events.len(),
        4,
        "simulation should produce exactly 4 events"
    );
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
    let tracer_handle = tokio::spawn(async move { tracer.run(cancel, true).await });

    // 2) Bridge: convert SyscallEvents → Intents and publish to IntentBus
    let bus_arc = Arc::new(intent_bus);
    let bus_for_bridge = Arc::clone(&bus_arc);
    let bridge_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let intent = Intent::new(
                format!("syscall-{}", event.syscall_nr),
                IntentType::Event,
                format!(
                    "syscall:{} pid={} uid={}",
                    event.syscall_name, event.pid, event.uid
                ),
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
        let _ = agent_scheduler.route_intent(intent.clone()).await;

        // If it's a PlacementRequest, publish the response
        if intent.intent_type == IntentType::Event && intent.source == "agent-scheduler" {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                if data.get("action").and_then(|v| v.as_str()) == Some("PlacementRequest") {
                    let agent_id = data.get("agent_id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let resp_payload = serde_json::json!({
                        "action": "PlacementResponse",
                        "agent_id": agent_id,
                        "compute_target": "Cpu",
                    })
                    .to_string();
                    let resp_intent = Intent::new(
                        "resp-e2e",
                        IntentType::Event,
                        resp_payload,
                        IntentPriority::High,
                        "compute-scheduler",
                    );
                    bus_arc.publish(resp_intent).await.unwrap();
                }
            }
        }
    }

    // 6) Verify agent was spawned
    let running = agent_scheduler.get_running_agents().await;
    assert_eq!(
        running.len(),
        1,
        "AgentScheduler should have 1 running agent"
    );

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
    tokio::spawn(async move { tracer.run(cancel, true).await });

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

    // Wait for PlacementRequest
    let req = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout waiting for placement request")
        .expect("no placement request");

    let data: serde_json::Value = serde_json::from_str(&req.payload).unwrap();
    let agent_id = data["agent_id"].as_u64().unwrap();

    // Simulate response
    let resp_payload = serde_json::json!({
        "action": "PlacementResponse",
        "agent_id": agent_id,
        "compute_target": "Cpu",
    })
    .to_string();

    let resp_intent = Intent::new(
        "resp-1",
        IntentType::Event,
        resp_payload,
        IntentPriority::High,
        "compute-scheduler",
    );

    intent_bus.publish(resp_intent).await.unwrap();

    let resp_received = timeout(Duration::from_millis(100), subscriber.receive())
        .await
        .expect("timeout waiting for placement response")
        .expect("no placement response");

    scheduler.route_intent(resp_received).await.unwrap();

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
    assert_eq!(
        failed_agent.state,
        agent_scheduler::block::AgentState::Failed
    );

    let recovered = scheduler.supervisor().monitor_agent(&failed_agent).await;
    assert!(recovered, "supervisor should recover the agent");

    let agent = scheduler.get_agent(agent_id).await.unwrap();
    assert_eq!(agent.state, agent_scheduler::block::AgentState::Running);
}

// ---- E2E-8: Two-node delegated spawn over network bridge ----

#[tokio::test]
async fn e2e_two_node_delegated_spawn() {
    let (bus_a, scheduler_a, _, _) = arc_pipeline();
    let (bus_b, scheduler_b, _, _) = arc_pipeline();

    scheduler_a
        .configure_routing_policy(DistributedRoutingPolicy {
            local_node_id: "node-a".to_string(),
            remote_enabled: true,
            max_local_agents: 1,
            overload_threshold_percent: 100,
            min_remote_trust: 80,
            max_candidate_nodes: 2,
        })
        .await;
    scheduler_b
        .configure_routing_policy(DistributedRoutingPolicy {
            local_node_id: "node-b".to_string(),
            remote_enabled: false,
            max_local_agents: 4,
            overload_threshold_percent: 100,
            min_remote_trust: 80,
            max_candidate_nodes: 2,
        })
        .await;
    scheduler_a
        .upsert_remote_node(RemoteNodeState::new(
            "node-b",
            4,
            100,
            vec!["small".to_string(), "large".to_string()],
        ))
        .await;

    scheduler_a
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .expect("seed local agent should spawn");

    let (bridge_a_io, bridge_b_io) = tokio::io::duplex(8 * 1024);
    let cancel_a_forwarder = CancellationToken::new();
    let cancel_b_listener = CancellationToken::new();
    let cancel_b_router = CancellationToken::new();

    let router_task = tokio::spawn({
        let scheduler_b = Arc::clone(&scheduler_b);
        let bus_b = Arc::clone(&bus_b);
        let cancel = cancel_b_router.clone();
        async move {
            let mut subscriber = bus_b.subscribe();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    maybe_intent = subscriber.receive() => {
                        let Some(intent) = maybe_intent else {
                            break;
                        };

                        scheduler_b.route_intent(intent.clone()).await.unwrap();

                        if intent.intent_type == IntentType::Event && intent.source == "agent-scheduler" {
                            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                                if data.get("action").and_then(|value| value.as_str()) == Some("PlacementRequest") {
                                    let agent_id = data["agent_id"].as_u64().unwrap();
                                    let resp_payload = serde_json::json!({
                                        "action": "PlacementResponse",
                                        "agent_id": agent_id,
                                        "compute_target": "Cpu",
                                    })
                                    .to_string();
                                    bus_b
                                        .publish(Intent::new(
                                            format!("resp-{agent_id}"),
                                            IntentType::Event,
                                            resp_payload,
                                            IntentPriority::High,
                                            "compute-scheduler",
                                        ))
                                        .await
                                        .unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let forwarder_task = tokio::spawn({
        let bus_a = Arc::clone(&bus_a);
        let cancel = cancel_a_forwarder.clone();
        async move {
            let mut subscriber = bus_a.subscribe();
            let (reader, mut writer) = tokio::io::split(bridge_a_io);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    maybe_intent = subscriber.receive() => {
                        let Some(intent) = maybe_intent else {
                            break;
                        };

                        if intent
                            .metadata
                            .get("routing_mode")
                            .map(String::as_str)
                            != Some("delegated")
                        {
                            continue;
                        }

                        let envelope = serde_json::json!({ "intent": intent });
                        let payload = format!("{}\n", envelope);
                        writer.write_all(payload.as_bytes()).await.unwrap();
                        writer.flush().await.unwrap();

                        line.clear();
                        reader.read_line(&mut line).await.unwrap();
                        let ack: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                        assert_eq!(ack["accepted"], true);
                        break;
                    }
                }
            }
        }
    });

    let listener_task = tokio::spawn({
        let bus_b = Arc::clone(&bus_b);
        let cancel = cancel_b_listener.clone();
        async move {
            let (reader, mut writer) = tokio::io::split(bridge_b_io);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    read_result = reader.read_line(&mut line) => {
                        read_result.unwrap();
                        let intent: Intent = serde_json::from_value(
                            serde_json::from_str::<serde_json::Value>(line.trim())
                                .unwrap()["intent"].clone(),
                        ).unwrap();
                        bus_b.publish(intent).await.unwrap();
                        let ack = serde_json::json!({
                            "accepted": true,
                            "node_id": "node-b",
                            "error": null,
                        });
                        writer.write_all(format!("{}\n", ack).as_bytes()).await.unwrap();
                        writer.flush().await.unwrap();
                        break;
                    }
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    scheduler_a
        .route_intent(Intent::new(
            "delegated-spawn",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::Critical,
            "node-a-test",
        ))
        .await
        .expect("delegated route should succeed");

    timeout(Duration::from_secs(2), async {
        loop {
            if scheduler_b.get_running_agents().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node B should eventually spawn delegated agent");

    assert_eq!(
        scheduler_a.get_running_agents().await.len(),
        1,
        "node A should only keep the seed local agent"
    );
    let remote_agents = scheduler_b.get_running_agents().await;
    assert_eq!(remote_agents.len(), 1);
    assert_eq!(remote_agents[0].id, 2);

    cancel_a_forwarder.cancel();
    cancel_b_listener.cancel();
    cancel_b_router.cancel();

    forwarder_task.await.unwrap();
    listener_task.await.unwrap();
    router_task.await.unwrap();
}

// ---- E2E-9: Two-node remote lifecycle management (pause/resume/terminate) ----

#[tokio::test]
async fn e2e_two_node_remote_lifecycle_management() {
    let (bus_a, scheduler_a, _, _) = arc_pipeline();
    let (bus_b, scheduler_b, _, _) = arc_pipeline();

    scheduler_a
        .configure_routing_policy(DistributedRoutingPolicy {
            local_node_id: "node-a".to_string(),
            remote_enabled: true,
            max_local_agents: 1,
            overload_threshold_percent: 100,
            min_remote_trust: 80,
            max_candidate_nodes: 2,
        })
        .await;
    scheduler_b
        .configure_routing_policy(DistributedRoutingPolicy {
            local_node_id: "node-b".to_string(),
            remote_enabled: false,
            max_local_agents: 4,
            overload_threshold_percent: 100,
            min_remote_trust: 80,
            max_candidate_nodes: 2,
        })
        .await;
    scheduler_a
        .upsert_remote_node(RemoteNodeState::new(
            "node-b",
            4,
            100,
            vec!["small".to_string(), "large".to_string()],
        ))
        .await;

    scheduler_a
        .spawn_agent(AgentControlBlock::new(0))
        .await
        .expect("seed local agent should spawn");

    let (bridge_a_io, bridge_b_io) = tokio::io::duplex(8 * 1024);

    let cancel_a_forwarder = CancellationToken::new();
    let cancel_b_listener = CancellationToken::new();
    let cancel_b_router = CancellationToken::new();

    // Router on node B: processes intents published to bus_b
    let router_task = tokio::spawn({
        let scheduler_b = Arc::clone(&scheduler_b);
        let bus_b = Arc::clone(&bus_b);
        let cancel = cancel_b_router.clone();
        async move {
            let mut subscriber = bus_b.subscribe();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    maybe_intent = subscriber.receive() => {
                        let Some(intent) = maybe_intent else {
                            break;
                        };
                        let _ = scheduler_b.route_intent(intent.clone()).await;

                        if intent.intent_type == IntentType::Event && intent.source == "agent-scheduler" {
                            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&intent.payload) {
                                if data.get("action").and_then(|value| value.as_str()) == Some("PlacementRequest") {
                                    let agent_id = data["agent_id"].as_u64().unwrap();
                                    let resp_payload = serde_json::json!({
                                        "action": "PlacementResponse",
                                        "agent_id": agent_id,
                                        "compute_target": "Cpu",
                                    })
                                    .to_string();
                                    bus_b
                                        .publish(Intent::new(
                                            format!("resp-{agent_id}"),
                                            IntentType::Event,
                                            resp_payload,
                                            IntentPriority::High,
                                            "compute-scheduler",
                                        ))
                                        .await
                                        .unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Multi-hop forwarder on node A: forwards all delegated intents over bridge
    let forwarder_task = tokio::spawn({
        let bus_a = Arc::clone(&bus_a);
        let cancel = cancel_a_forwarder.clone();
        async move {
            let mut subscriber = bus_a.subscribe();
            let (reader, mut writer) = tokio::io::split(bridge_a_io);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    maybe_intent = subscriber.receive() => {
                        let Some(intent) = maybe_intent else {
                            break;
                        };

                        if intent
                            .metadata
                            .get("routing_mode")
                            .map(String::as_str)
                            != Some("delegated")
                        {
                            continue;
                        }

                        let envelope = serde_json::json!({ "intent": intent });
                        let payload = format!("{}\n", envelope);
                        writer.write_all(payload.as_bytes()).await.unwrap();
                        writer.flush().await.unwrap();

                        line.clear();
                        reader.read_line(&mut line).await.unwrap();
                        let ack: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                        assert_eq!(ack["accepted"], true);
                    }
                }
            }
        }
    });

    // Listener on node B: receives intents from bridge and publishes to bus_b
    let listener_task = tokio::spawn({
        let bus_b = Arc::clone(&bus_b);
        let cancel = cancel_b_listener.clone();
        async move {
            let (reader, mut writer) = tokio::io::split(bridge_b_io);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                    }
                    read_result = reader.read_line(&mut line) => {
                        read_result.unwrap();
                        let intent: Intent = serde_json::from_value(
                            serde_json::from_str::<serde_json::Value>(line.trim())
                                .unwrap()["intent"].clone(),
                        ).unwrap();
                        bus_b.publish(intent).await.unwrap();
                        let ack = serde_json::json!({
                            "accepted": true,
                            "node_id": "node-b",
                            "error": null,
                        });
                        writer.write_all(format!("{}\n", ack).as_bytes()).await.unwrap();
                        writer.flush().await.unwrap();
                    }
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- Step 1: Delegated spawn ---
    scheduler_a
        .route_intent(Intent::new(
            "delegated-spawn",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::Critical,
            "node-a-test",
        ))
        .await
        .expect("delegated route should succeed");

    timeout(Duration::from_secs(2), async {
        loop {
            if scheduler_b.get_running_agents().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node B should eventually spawn delegated agent");

    assert_eq!(
        scheduler_a.get_running_agents().await.len(),
        1,
        "node A should only keep the seed local agent"
    );
    let remote_agents = scheduler_b.get_running_agents().await;
    assert_eq!(remote_agents.len(), 1);
    let remote_id = remote_agents[0].id;
    assert_eq!(remote_id, 2);

    // --- Step 2: Remote pause ---
    scheduler_a
        .remote_pause_agent(remote_id, "node-b")
        .await
        .expect("remote pause should dispatch");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let paused = scheduler_b
        .get_agent(remote_id)
        .await
        .expect("agent should exist on node B after remote pause");
    assert_eq!(
        paused.state,
        AgentState::Paused,
        "agent should be Paused after remote pause"
    );

    // --- Step 3: Remote resume ---
    scheduler_a
        .remote_resume_agent(remote_id, "node-b")
        .await
        .expect("remote resume should dispatch");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let resumed = scheduler_b
        .get_agent(remote_id)
        .await
        .expect("agent should exist on node B after remote resume");
    assert_eq!(
        resumed.state,
        AgentState::Running,
        "agent should be Running after remote resume"
    );

    // --- Step 4: Remote status ---
    scheduler_a
        .remote_agent_status(remote_id, "node-b")
        .await
        .expect("remote status should dispatch");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let status = scheduler_b
        .get_agent(remote_id)
        .await
        .expect("agent should still exist on node B");
    assert_eq!(
        status.state,
        AgentState::Running,
        "agent should still be Running after status query"
    );

    // --- Step 5: Remote terminate ---
    scheduler_a
        .remote_terminate_agent(remote_id, "node-b")
        .await
        .expect("remote terminate should dispatch");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let terminated = scheduler_b.get_agent(remote_id).await;
    assert!(
        terminated.is_err(),
        "agent should be gone from node B after remote terminate"
    );

    // --- Step 6: node A local agent untouched ---
    assert_eq!(
        scheduler_a.get_running_agents().await.len(),
        1,
        "node A should still have its local seed agent"
    );

    cancel_a_forwarder.cancel();
    cancel_b_listener.cancel();
    cancel_b_router.cancel();

    forwarder_task.await.unwrap();
    listener_task.await.unwrap();
    router_task.await.unwrap();
}
