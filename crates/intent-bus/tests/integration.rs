use intent_bus::{FilterCondition, Intent, IntentBus, IntentFilter, IntentPriority, IntentType};

#[tokio::test]
async fn multiple_subscribers_all_receive() {
    let bus = IntentBus::new(32);
    let mut sub1 = bus.subscribe();
    let mut sub2 = bus.subscribe();

    let intent = Intent::new(
        "multi",
        IntentType::Event,
        "broadcast-test",
        IntentPriority::High,
        "tester",
    );

    bus.publish(intent.clone())
        .await
        .expect("publish should succeed");

    let r1 = sub1.receive().await.expect("sub1 should receive");
    let r2 = sub2.receive().await.expect("sub2 should receive");

    assert_eq!(r1.id, "multi");
    assert_eq!(r2.id, "multi");
    assert_eq!(r1.payload, r2.payload);
}

#[tokio::test]
async fn filters_exclude_unwanted_intents() {
    let bus = IntentBus::new(16);

    bus.add_filter(IntentFilter {
        name: "commands-only".to_string(),
        conditions: vec![FilterCondition::IntentType(IntentType::Command)],
        enabled: true,
    })
    .await;

    let event_intent = Intent::new(
        "evt-1",
        IntentType::Event,
        "heartbeat",
        IntentPriority::Low,
        "system",
    );
    let cmd_intent = Intent::new(
        "cmd-1",
        IntentType::Command,
        "spawn-agent",
        IntentPriority::High,
        "user",
    );

    assert!(
        !bus.passes_filters(&event_intent).await,
        "event should be filtered out"
    );
    assert!(
        bus.passes_filters(&cmd_intent).await,
        "command should pass filter"
    );
}

#[tokio::test]
async fn multiple_filters_and_priority() {
    let bus = IntentBus::new(16);

    bus.add_filter(IntentFilter {
        name: "high-priority".to_string(),
        conditions: vec![FilterCondition::Priority(IntentPriority::High)],
        enabled: true,
    })
    .await;

    bus.add_filter(IntentFilter {
        name: "structured".to_string(),
        conditions: vec![FilterCondition::IntentType(IntentType::Structured)],
        enabled: true,
    })
    .await;

    let ok_intent = Intent::new(
        "ok",
        IntentType::Structured,
        "data",
        IntentPriority::High,
        "agent",
    );
    let fail_intent = Intent::new(
        "fail",
        IntentType::Structured,
        "data",
        IntentPriority::Low,
        "agent",
    );

    assert!(bus.passes_filters(&ok_intent).await);
    assert!(
        !bus.passes_filters(&fail_intent).await,
        "low priority structured should be filtered"
    );
}

#[tokio::test]
async fn disabled_filters_ignored() {
    let bus = IntentBus::new(8);

    bus.add_filter(IntentFilter {
        name: "disabled-filter".to_string(),
        conditions: vec![FilterCondition::IntentType(IntentType::Command)],
        enabled: false,
    })
    .await;

    let intent = Intent::new(
        "evt",
        IntentType::Event,
        "payload",
        IntentPriority::Low,
        "test",
    );
    assert!(
        bus.passes_filters(&intent).await,
        "disabled filter should be ignored"
    );
}

#[tokio::test]
async fn source_target_filters() {
    let bus = IntentBus::new(8);

    bus.add_filter(IntentFilter {
        name: "source-check".to_string(),
        conditions: vec![
            FilterCondition::SourceContains("trusted".to_string()),
            FilterCondition::TargetContains("worker".to_string()),
        ],
        enabled: true,
    })
    .await;

    let mut intent = Intent::new(
        "check",
        IntentType::Command,
        "do-something",
        IntentPriority::Medium,
        "trusted-agent",
    );
    intent.target = Some("worker-pool".to_string());

    assert!(bus.passes_filters(&intent).await);

    intent.source = "malicious-bot".to_string();
    assert!(
        !bus.passes_filters(&intent).await,
        "untrusted source should fail filter"
    );
}
