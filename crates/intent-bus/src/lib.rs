#![deny(unsafe_code)]

use std::future::Future;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub id: String,
    pub intent_type: IntentType,
    pub payload: String,
    pub priority: IntentPriority,
    pub timestamp: std::time::SystemTime,
    pub source: String,
    pub target: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Intent {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        intent_type: IntentType,
        payload: impl Into<String>,
        priority: IntentPriority,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            intent_type,
            payload: payload.into(),
            priority,
            timestamp: std::time::SystemTime::now(),
            source: source.into(),
            target: None,
            metadata: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentType {
    NaturalLanguage,
    Structured,
    Command,
    Event,
    Interrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntentPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct IntentBus {
    sender: broadcast::Sender<Intent>,
    filters: Arc<RwLock<HashMap<String, IntentFilter>>>,
}

#[derive(Debug, Clone)]
pub struct IntentFilter {
    pub name: String,
    pub conditions: Vec<FilterCondition>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum FilterCondition {
    IntentType(IntentType),
    Priority(IntentPriority),
    SourceContains(String),
    TargetContains(String),
    HasMetadata(String, String),
}

#[derive(Debug, Error)]
pub enum IntentBusError {
    #[error("intent bus send failed")]
    SendFailed,
}

impl IntentFilter {
    #[must_use]
    pub fn passes(&self, intent: &Intent) -> bool {
        self.conditions.iter().all(|condition| condition.matches(intent))
    }
}

impl FilterCondition {
    #[must_use]
    pub fn matches(&self, intent: &Intent) -> bool {
        match self {
            Self::IntentType(intent_type) => intent.intent_type == *intent_type,
            Self::Priority(priority) => intent.priority >= *priority,
            Self::SourceContains(pattern) => intent.source.contains(pattern),
            Self::TargetContains(pattern) => intent
                .target
                .as_deref()
                .is_some_and(|target| target.contains(pattern)),
            Self::HasMetadata(key, value) => intent.metadata.get(key) == Some(value),
        }
    }
}

impl IntentBus {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            sender,
            filters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn subscribe(&self) -> IntentSubscriber {
        IntentSubscriber {
            receiver: self.sender.subscribe(),
        }
    }

    pub async fn publish(&self, intent: Intent) -> Result<(), IntentBusError> {
        self.sender
            .send(intent)
            .map(|_| ())
            .map_err(|_| IntentBusError::SendFailed)
    }

    pub async fn add_filter(&self, filter: IntentFilter) {
        let mut filters = self.filters.write().await;
        filters.insert(filter.name.clone(), filter);
    }

    pub async fn remove_filter(&self, name: &str) {
        let mut filters = self.filters.write().await;
        filters.remove(name);
    }

    pub async fn passes_filters(&self, intent: &Intent) -> bool {
        let filters = self.filters.read().await;
        filters
            .values()
            .filter(|filter| filter.enabled)
            .all(|filter| filter.passes(intent))
    }

    pub async fn process_intents(&self, processor: &impl IntentProcessor) {
        let mut receiver = self.sender.subscribe();
        while let Ok(intent) = receiver.recv().await {
            if self.passes_filters(&intent).await {
                processor.process(intent).await;
            }
        }
    }
}

pub trait IntentProcessor {
    fn process(&self, intent: Intent) -> impl Future<Output = ()> + Send;
}

pub struct IntentSubscriber {
    receiver: broadcast::Receiver<Intent>,
}

impl IntentSubscriber {
    pub async fn receive(&mut self) -> Option<Intent> {
        self.receiver.recv().await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_subscriber() {
        let bus = IntentBus::new(8);
        let mut subscriber = bus.subscribe();
        let intent = Intent::new(
            "intent-1",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::High,
            "user",
        );

        bus.publish(intent.clone()).await.expect("publish should succeed");

        let received = subscriber.receive().await.expect("subscriber should receive intent");
        assert_eq!(received.id, intent.id);
        assert_eq!(received.intent_type, intent.intent_type);
        assert_eq!(received.payload, intent.payload);
    }

    #[test]
    fn filter_matches_expected_intent() {
        let mut intent = Intent::new(
            "intent-2",
            IntentType::Structured,
            "payload",
            IntentPriority::Medium,
            "agent-a",
        );
        intent.target = Some("worker-1".to_string());
        intent
            .metadata
            .insert("context_key".to_string(), "ctx-1".to_string());

        let filter = IntentFilter {
            name: "structured".to_string(),
            conditions: vec![
                FilterCondition::IntentType(IntentType::Structured),
                FilterCondition::Priority(IntentPriority::Low),
                FilterCondition::SourceContains("agent".to_string()),
                FilterCondition::TargetContains("worker".to_string()),
                FilterCondition::HasMetadata("context_key".to_string(), "ctx-1".to_string()),
            ],
            enabled: true,
        };

        assert!(filter.passes(&intent));
    }

    #[tokio::test]
    async fn disabled_filter_is_ignored() {
        let bus = IntentBus::new(8);
        let intent = Intent::new(
            "intent-3",
            IntentType::Event,
            "heartbeat",
            IntentPriority::Low,
            "system",
        );

        bus.add_filter(IntentFilter {
            name: "events".to_string(),
            conditions: vec![FilterCondition::IntentType(IntentType::Command)],
            enabled: false,
        })
        .await;

        assert!(bus.passes_filters(&intent).await);
    }
}
