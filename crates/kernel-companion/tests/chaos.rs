//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
use agent_scheduler::{
    block::{AgentControlBlock, AgentState},
    supervisor::SupervisorService,
};
use capability_security::{
    policy::{PolicyDecision, PolicyEngine},
    token::{CapabilityToken, Scope},
};
use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// -----------------------------------------------------------------------------
// 1. Fuzzing / Chaos Test: Intent Bus (ANK-026)
// ทดสอบยิงข้อมูลแบบสุ่มและพังๆ เข้าไปที่ Intent Bus เพื่อดูว่าระบบเกิด Panic หรือไม่
// -----------------------------------------------------------------------------
proptest! {
    #[test]
    fn fuzz_intent_bus_payloads(payload in ".*") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let bus = IntentBus::new(100);

            // ส่ง Payload ที่เป็น Garbage เข้าไปในระบบ
            let intent = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::NaturalLanguage,
                payload,
                IntentPriority::Medium,
                "fuzzer",
            );

            // ต้องไม่เกิด Panic (Fail-safe)
            let _ = bus.publish(intent).await;
        });
    }
}

// -----------------------------------------------------------------------------
// 2. Chaos Test: Supervisor Mass Failure Recovery (ANK-026)
// จำลองสถานการณ์ที่ Agent จำนวนมากพังทลาย (Failed) พร้อมๆ กัน (เช่น OOM หรือ Node crash)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn chaos_supervisor_recovers_mass_failures() {
    let agents = Arc::new(RwLock::new(HashMap::new()));

    // สร้างสถานการณ์วุ่นวาย: Agent 1,000 ตัวตายพร้อมกันหมด (State = Failed)
    {
        let mut writer = agents.write().await;
        for i in 0..1000 {
            let mut agent = AgentControlBlock::new(i);
            agent.state = AgentState::Failed;
            writer.insert(i, agent);
        }
    }

    let supervisor = SupervisorService::new(agents.clone(), 3, 1, 100);

    // จำลองการทำงานของ Monitor Loop เพื่อพยายามกู้คืนทุกตัว
    let snapshot = {
        let reader = agents.read().await;
        reader.values().cloned().collect::<Vec<_>>()
    };

    // Supervisor ต้องไม่พังระหว่างการกู้ภัย
    let mut tasks = tokio::task::JoinSet::new();
    for agent in snapshot {
        let supervisor = supervisor.clone();
        tasks.spawn(async move { (agent.id, supervisor.monitor_agent(&agent).await) });
    }

    while let Some(joined) = tasks.join_next().await {
        let (agent_id, recovered) = joined.expect("chaos recovery task should join");
        assert!(recovered, "Agent {} failed to recover", agent_id);
    }

    // 検証 (Verify): ตรวจสอบว่าระบบสามารถดึงทุก Agent กลับมาทำงาน (Running) ได้ตามหลัก Fault Tolerance
    let final_state = agents.read().await;
    for i in 0..1000 {
        assert_eq!(
            final_state[&i].state,
            AgentState::Running,
            "Agent {} is not running",
            i
        );
    }
}

// -----------------------------------------------------------------------------
// 3. Fuzzing / Chaos Test: Policy Engine Fail-Closed (ANK-026)
// ทดสอบยิงข้อมูล Token พังๆ และตรวจสอบว่า Policy Engine จะตอบปฏิเสธ (DENY) อย่างปลอดภัย
// -----------------------------------------------------------------------------
proptest! {
    #[test]
    fn fuzz_policy_engine_garbage_token(garbage in "\\PC*") {
        let engine = PolicyEngine::default();

        // จำลองสถานการณ์: มีคนส่ง capability เป็นตัวอักษรขยะเข้ามา
        let token = CapabilityToken::new(
            123,
            Scope::Global,
            vec![garbage.clone()],
            std::time::Duration::from_secs(60),
            [0u8; 32],
        );

        let decision = engine.decision(&token, &Scope::Global, "execute");

        // Zero-Trust: ถ้าระบบเจอสิทธิ์แปลกๆ (Garbage) ที่ไม่ตรงกับ Allowlist ต้องตัดเป็น Deny เสมอ
        prop_assert_eq!(decision, PolicyDecision::Deny, "System failed closed bypass!");
    }
}

// -----------------------------------------------------------------------------
// 4. Chaos Test: T-Cell Concurrent Operations (Failure Domain: Immune System)
// สังเกต syscall จาก 16 tasks พร้อมกัน ระหว่างที่มี task อื่น quarantine/release
// วนอยู่ตลอด — ต้องไม่ panic, ไม่ deadlock และสถานะ quarantine ต้อง consistent
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn chaos_tcell_survives_concurrent_observe_and_quarantine() {
    use immune_system::TCellAgent;

    let tcell = Arc::new(TCellAgent::new(1_000_000, 10_000));
    tcell.set_jitter_enabled(false);

    let mut handles = Vec::new();

    // 16 observer tasks — คนละ PID
    for pid in 1..=16u32 {
        let tcell = Arc::clone(&tcell);
        handles.push(tokio::spawn(async move {
            for i in 0..200u32 {
                let denied = i % 13 == 0;
                let _ = tcell.observe_syscall(pid, "read", denied).await;
            }
        }));
    }

    // 4 chaos tasks — quarantine/release/expire วนแทรกตลอดเวลา
    for offset in 0..4u32 {
        let tcell = Arc::clone(&tcell);
        handles.push(tokio::spawn(async move {
            for round in 0..50u32 {
                let pid = (round % 16) + 1 + offset;
                tcell.quarantine(pid).await;
                tokio::task::yield_now().await;
                tcell.release(pid).await;
                let _ = tcell
                    .release_expired_quarantine(std::time::Duration::from_nanos(1))
                    .await;
            }
        }));
    }

    for handle in handles {
        handle.await.expect("no task may panic under chaos");
    }

    // สถานะสุดท้ายต้อง consistent: ทุก PID ที่รายงานว่าถูกกักกัน ต้องตอบ true จริง
    for pid in tcell.get_quarantined_pids().await {
        assert!(tcell.is_quarantined(pid).await);
    }
    // สถิติของทุก observer PID ต้องครบและไม่เสียหาย
    for pid in 1..=16u32 {
        let stats = tcell.get_stats(pid).expect("stats must exist");
        assert!(stats.syscall_count > 0);
    }
}

// -----------------------------------------------------------------------------
// 5. Chaos Test: Intent Bus Slow Subscriber / Overflow (Failure Domain: Intent Bus)
// จงใจทำให้ subscriber lag จน buffer ล้น (deterministic ไม่พึ่ง timing) แล้ว
// พิสูจน์ว่า: (1) publish ไม่ panic แม้บัสล้น (2) subscriber ที่ lag แล้ว
// ยังรับ intent ที่ publish ต่อจากนั้นได้ ไม่หยุดถาวร
// -----------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_intent_bus_survives_slow_subscriber_overflow() {
    const CAPACITY: usize = 8;
    let bus = IntentBus::new(CAPACITY);
    let mut subscriber = bus.subscribe();

    let publish = |tag: &str, i: u32| {
        let intent = Intent::new(
            format!("chaos-{tag}-{i}"),
            IntentType::Event,
            format!("payload-{i}"),
            IntentPriority::Low,
            "chaos-publisher",
        );
        bus.publish(intent)
    };

    // 1. ยิง intent เกิน capacity หลายเท่าโดยที่ subscriber ยังไม่อ่านเลย
    //    → รับประกันว่า subscriber ต้องเจอ Lagged ในการ recv ครั้งถัดไป
    for i in 0..(CAPACITY as u32 * 4) {
        publish("flood", i).await.expect("publish must not panic");
    }

    // 2. ยิง intent ที่รู้จำนวนแน่นอนต่อจากนั้น (จำนวน = capacity พอดี)
    for i in 0..(CAPACITY as u32) {
        publish("post", i).await.expect("publish must not panic");
    }

    // 3. subscriber ต้อง recover จาก Lagged แล้วอ่าน intent ชุดหลังได้ครบ capacity
    //    (buffer เก็บ intent ล่าสุด capacity ตัว = ชุด "post" ทั้งหมด)
    let mut received = 0u32;
    for _ in 0..CAPACITY {
        match tokio::time::timeout(std::time::Duration::from_secs(1), subscriber.receive()).await {
            Ok(Some(_)) => received += 1,
            Ok(None) => panic!("channel must stay open while the bus is alive"),
            Err(_) => break,
        }
    }

    assert_eq!(
        received, CAPACITY as u32,
        "lagged subscriber must recover and drain the most recent {CAPACITY} intents"
    );
}
