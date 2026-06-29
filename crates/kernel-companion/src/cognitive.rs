#![deny(unsafe_code)]

use crate::nlp;
use intent_bus::{Intent, IntentPriority, IntentType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

const ADVISORY_SOURCE: &str = "cognitive-plane";
const REASONER_SOURCE: &str = "cognitive-reasoner";
const META_COGNITIVE_MODE: &str = "cognitive_mode";
const META_REASONER_VERDICT: &str = "reasoner_verdict";
const META_REASONER_RATIONALE: &str = "reasoner_rationale";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonerVerdict {
    Consistent,
    Inconsistent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModelSnapshot {
    pub observed_intents_total: u64,
    pub natural_language_intents_total: u64,
    pub suggested_commands_total: u64,
    pub last_intent_source: Option<String>,
    pub last_workload: Option<String>,
}

#[derive(Debug, Default)]
struct WorldModelState {
    observed_intents_total: u64,
    natural_language_intents_total: u64,
    suggested_commands_total: u64,
    last_intent_source: Option<String>,
    last_workload: Option<String>,
}

impl WorldModelState {
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

#[derive(Debug, Clone)]
pub struct CognitiveDecision {
    pub advisory_intent: Intent,
    pub command_intent: Option<Intent>,
}

#[derive(Debug, Clone, Default)]
pub struct CognitiveControlPlane {
    world_model: Arc<RwLock<WorldModelState>>,
}

impl CognitiveControlPlane {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

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

    pub async fn snapshot(&self) -> WorldModelSnapshot {
        self.world_model.read().await.snapshot()
    }

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
