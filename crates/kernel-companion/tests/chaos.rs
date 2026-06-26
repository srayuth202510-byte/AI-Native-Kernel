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

    let supervisor = SupervisorService::new(agents.clone(), 3, 1);

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
