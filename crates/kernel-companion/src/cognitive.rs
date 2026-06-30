#![deny(unsafe_code)]

use crate::nlp;
use intent_bus::{Intent, IntentPriority, IntentType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// แหล่งที่มาสำหรับ Intent ที่เป็น Advisory (คำแนะนำจาก Cognitive Plane)
const ADVISORY_SOURCE: &str = "cognitive-plane";
/// แหล่งที่มาสำหรับ Intent ที่มาจาก Reasoner (ผู้ให้เหตุผล)
const REASONER_SOURCE: &str = "cognitive-reasoner";
/// Metadata key สำหรับระบุโหมดการทำงานของ Cognitive Layer
const META_COGNITIVE_MODE: &str = "cognitive_mode";
/// Metadata key สำหรับผลการตรวจสอบความสอดคล้องของ Reasoner
const META_REASONER_VERDICT: &str = "reasoner_verdict";
/// Metadata key สำหรับคำอธิบายเหตุผลของ Reasoner
const META_REASONER_RATIONALE: &str = "reasoner_rationale";

/// ผลการตัดสินความสอดคล้องของ Intent จาก Reasoner
/// ใช้ในการตรวจสอบว่า Intent ที่ผู้ใช้ส่งมามีความสอดคล้องกับความสามารถของระบบหรือไม่
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonerVerdict {
    /// Intent มีความสอดคล้องและสามารถดำเนินการต่อได้
    Consistent,
    /// Intent ไม่สอดคล้อง ไม่สามารถดำเนินการต่อได้
    Inconsistent,
}

/// ภาพรวมสถานะโลก (World Model Snapshot) ที่ Cognitive Plane ใช้
/// เก็บข้อมูลสถิติที่สังเกตได้ทั้งหมดสำหรับการตัดสินใจ
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModelSnapshot {
    /// จำนวน Intent ทั้งหมดที่ถูกสังเกตการณ์ตั้งแต่เริ่มระบบ
    pub observed_intents_total: u64,
    /// จำนวน Intent แบบภาษาธรรมชาติที่ถูกสังเกตการณ์
    pub natural_language_intents_total: u64,
    /// จำนวนคำสั่งที่ถูกแนะนำจาก Cognitive Planner
    pub suggested_commands_total: u64,
    /// แหล่งที่มาของ Intent ล่าสุดที่ถูกประมวลผล
    pub last_intent_source: Option<String>,
    /// ประเภทภาระงานล่าสุดที่ถูกตรวจพบ
    pub last_workload: Option<String>,
}

/// สถานะภายในของ World Model สำหรับบันทึกประวัติ Intent
#[derive(Debug, Default)]
struct WorldModelState {
    /// จำนวน Intent ทั้งหมดที่ถูกสังเกตการณ์ตั้งแต่เริ่มระบบ
    observed_intents_total: u64,
    /// จำนวน Intent แบบภาษาธรรมชาติ
    natural_language_intents_total: u64,
    /// จำนวนคำสั่งที่ถูกแนะนำ
    suggested_commands_total: u64,
    /// แหล่งที่มาของ Intent ล่าสุด
    last_intent_source: Option<String>,
    /// ประเภทภาระงานล่าสุด
    last_workload: Option<String>,
}

impl WorldModelState {
    /// สร้าง Snapshot ของสถานะปัจจุบันเพื่อนำไปใช้ในการตัดสินใจ
    fn snapshot(&self) -> WorldModelSnapshot {
        WorldModelSnapshot {
            observed_intents_total: self.observed_intents_total,
            natural_language_intents_total: self.natural_language_intents_total,
            suggested_commands_total: self.suggested_commands_total,
            last_intent_source: self.last_intent_source.clone(),
            last_workload: self.last_workload.clone(),
        }
    }
}

/// ผลลัพธ์จากการวางแผนและให้เหตุผลของ Cognitive Control Plane
/// ประกอบด้วย Intent คำแนะนำ (Advisory) และ Intent คำสั่ง (Command) ที่อาจมีหรือไม่มีก็ได้
#[derive(Debug, Clone)]
pub struct CognitiveDecision {
    /// Intent คำแนะนำสำหรับผู้ดูแลระบบ ใช้บันทึกประวัติและแจ้งเตือน
    pub advisory_intent: Intent,
    /// Intent คำสั่งที่ระบบควรดำเนินการต่อ (เช่น spawn-agent)
    pub command_intent: Option<Intent>,
}

/// ศูนย์ควบคุมระดับปัญญา (Cognitive Control Plane)
/// ทำหน้าที่สังเกตการณ์ Intent, วางแผน, และให้เหตุผล
/// ทำงานในโหมด advisory-only (แนะนำเท่านั้น ไม่บังคับ)
#[derive(Debug, Clone, Default)]
pub struct CognitiveControlPlane {
    /// แบบจำลองโลก (World Model) สำหรับบันทึกประวัติและสถิติ
    world_model: Arc<RwLock<WorldModelState>>,
}

impl CognitiveControlPlane {
    /// สร้าง CognitiveControlPlane ใหม่ด้วยค่าเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// สังเกตการณ์ Intent และบันทึกสถิติลงใน World Model
    pub async fn observe_intent(&self, intent: &Intent) {
        let mut model = self.world_model.write().await;
        model.observed_intents_total += 1;
        model.last_intent_source = Some(intent.source.clone());

        if intent.intent_type == IntentType::NaturalLanguage {
            model.natural_language_intents_total += 1;
        }

        if let Some(workload) = intent.metadata.get("workload") {
            model.last_workload = Some(workload.clone());
        }
    }

    /// ดึงภาพรวมสถานะโลก (World Model Snapshot) ปัจจุบัน
    pub async fn snapshot(&self) -> WorldModelSnapshot {
        self.world_model.read().await.snapshot()
    }

    /// วางแผนและให้เหตุผลสำหรับ Intent แบบภาษาธรรมชาติ
    /// คืนค่า `CognitiveDecision` ที่ประกอบด้วย Intent คำแนะนำและ Intent คำสั่ง (ถ้ามี)
    /// หรือคืน `None` หาก Intent ไม่ใช่ภาษาธรรมชาติ
    pub async fn plan_and_reason(&self, intent: &Intent) -> Option<CognitiveDecision> {
        if intent.intent_type != IntentType::NaturalLanguage {
            return None;
        }

        let snapshot = self.snapshot().await;
        let command_intent = nlp::parse_natural_language_intent(intent);

        match command_intent {
            Some(mut command_intent) => {
                let workload = command_intent
                    .metadata
                    .get("workload")
                    .cloned()
                    .unwrap_or_else(|| "small".to_string());
                let rationale = format!(
                    "planner matched workload '{workload}' from source '{}' after observing {} intents",
                    intent.source, snapshot.observed_intents_total
                );

                command_intent.source = REASONER_SOURCE.to_string();
                command_intent.metadata.insert(
                    META_COGNITIVE_MODE.to_string(),
                    "advisory".to_string(),
                );
                command_intent.metadata.insert(
                    META_REASONER_VERDICT.to_string(),
                    "consistent".to_string(),
                );
                command_intent.metadata.insert(
                    META_REASONER_RATIONALE.to_string(),
                    rationale.clone(),
                );
                command_intent.metadata.insert(
                    "payload".to_string(),
                    serde_json::json!({
                        "workload": workload.clone(),
                        "priority": priority_label(intent.priority),
                        "description": intent.payload.clone(),
                    })
                    .to_string(),
                );

                {
                    let mut model = self.world_model.write().await;
                    model.suggested_commands_total += 1;
                    model.last_workload = command_intent.metadata.get("workload").cloned();
                }

                Some(CognitiveDecision {
                    advisory_intent: build_advisory_intent(
                        intent,
                        ReasonerVerdict::Consistent,
                        Some(workload.clone()),
                        rationale,
                        snapshot,
                    ),
                    command_intent: Some(command_intent),
                })
            }
            None => Some(CognitiveDecision {
                advisory_intent: build_advisory_intent(
                    intent,
                    ReasonerVerdict::Inconsistent,
                    None,
                    "planner could not derive a safe workload classification from the natural-language request".to_string(),
                    snapshot,
                ),
                command_intent: None,
            }),
        }
    }
}

/// สร้าง Intent คำแนะนำ (Advisory Intent) สำหรับส่งให้ผู้ดูแลระบบหรือระบบย่อยอื่น
/// ใช้เมื่อ Cognitive Plane ต้องการแจ้งผลการวิเคราะห์โดยไม่ต้องดำเนินการใด ๆ ต่อ
fn build_advisory_intent(
    original_intent: &Intent,
    verdict: ReasonerVerdict,
    workload: Option<String>,
    rationale: String,
    snapshot: WorldModelSnapshot,
) -> Intent {
    let payload = serde_json::json!({
        "action": "CognitiveAdvisory",
        "verdict": verdict,
        "original_intent_id": original_intent.id,
        "source": original_intent.source,
        "suggested_workload": workload,
        "rationale": rationale,
        "world_model": snapshot,
    })
    .to_string();

    Intent::new(
        uuid::Uuid::new_v4().to_string(),
        IntentType::Event,
        payload,
        IntentPriority::High,
        ADVISORY_SOURCE,
    )
}

/// แปลงลำดับความสำคัญของ Intent (IntentPriority) เป็นชื่อป้ายสำหรับภาระงาน
/// ใช้ในการกำหนด Workload Class สำหรับการจัดสรรทรัพยากร
fn priority_label(priority: IntentPriority) -> &'static str {
    match priority {
        IntentPriority::Low => "eco",
        IntentPriority::Medium => "batch",
        IntentPriority::High => "interactive",
        IntentPriority::Critical => "realtime",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ทดสอบว่า Intent แบบภาษาธรรมชาติที่ถูกต้องสร้าง Advisory และ Command Intent ได้สำเร็จ
    #[tokio::test]
    async fn natural_language_intent_generates_advisory_and_command() {
        let plane = CognitiveControlPlane::new();
        let intent = Intent::new(
            "nl-1",
            IntentType::NaturalLanguage,
            "run reasoning model on high speed gpu",
            IntentPriority::High,
            "user",
        );

        plane.observe_intent(&intent).await;
        let decision = plane
            .plan_and_reason(&intent)
            .await
            .expect("natural-language intent should produce a decision");

        let command = decision
            .command_intent
            .expect("expected advisory decision to contain a command");
        assert_eq!(command.payload, "spawn-agent");
        assert_eq!(
            command
                .metadata
                .get(META_COGNITIVE_MODE)
                .map(String::as_str),
            Some("advisory")
        );
        assert_eq!(
            command
                .metadata
                .get(META_REASONER_VERDICT)
                .map(String::as_str),
            Some("consistent")
        );

        let advisory: serde_json::Value = serde_json::from_str(&decision.advisory_intent.payload)
            .expect("advisory payload should be valid JSON");
        assert_eq!(advisory["action"], "CognitiveAdvisory");
        assert_eq!(advisory["verdict"], "consistent");
        assert_eq!(advisory["suggested_workload"], "large");
    }

    /// ทดสอบว่า Intent ขยะ (ไม่มีความหมาย) สร้างเฉพาะ Advisory แบบ Inconsistent โดยไม่มี Command
    #[tokio::test]
    async fn garbage_intent_generates_inconsistent_advisory_only() {
        let plane = CognitiveControlPlane::new();
        let intent = Intent::new(
            "nl-2",
            IntentType::NaturalLanguage,
            "hello world this request has no actionable workload",
            IntentPriority::Low,
            "user",
        );

        let decision = plane
            .plan_and_reason(&intent)
            .await
            .expect("natural-language intent should still produce an advisory");

        assert!(decision.command_intent.is_none());
        let advisory: serde_json::Value = serde_json::from_str(&decision.advisory_intent.payload)
            .expect("advisory payload should be valid JSON");
        assert_eq!(advisory["verdict"], "inconsistent");
    }

    /// ทดสอบว่า World Model บันทึกจำนวน Intent ที่ถูกสังเกตการณ์ได้ถูกต้อง
    #[tokio::test]
    async fn world_model_tracks_observed_intents() {
        let plane = CognitiveControlPlane::new();
        let intent = Intent::new(
            "evt-1",
            IntentType::Event,
            "noop",
            IntentPriority::Low,
            "kernel",
        );

        plane.observe_intent(&intent).await;
        let snapshot = plane.snapshot().await;
        assert_eq!(snapshot.observed_intents_total, 1);
        assert_eq!(snapshot.natural_language_intents_total, 0);
        assert_eq!(snapshot.last_intent_source.as_deref(), Some("kernel"));
    }
}
