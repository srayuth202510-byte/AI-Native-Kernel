#![deny(unsafe_code)]

use tokio::sync::{broadcast, RwLock, mpsc};
use std::sync::Arc;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Intent {
    pub id: String,
    pub intent_type: IntentType,
    pub payload: String,
    pub priority: IntentPriority,
    pub timestamp: std::time::Instant,
    pub source: String,
    pub target: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum IntentType {
    NaturalLanguage,
    Structured,
    Command,
    Event,
    Interrupt,
}

#[derive(Debug, Clone)]
pub enum IntentPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct IntentBus {
    sender: broadcast::Sender<Intent>,
    receiver: Arc<RwLock<broadcast::Receiver<Intent>>>,
    intent_queue: Arc<RwLock<mpsc::UnboundedSender<Intent>>>,
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

impl IntentBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = broadcast::channel(capacity);
        let (queue_sender, queue_receiver) = mpsc::unbounded_channel();
        
        Self {
            sender,
            receiver: Arc::new(RwLock::new(receiver)),
            intent_queue: Arc::new(RwLock::new(queue_sender)),
            filters: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    pub async fn publish(&self, intent: Intent) {
        let _ = self.sender.send(intent.clone());
        let _ = self.intent_queue.write().await.send(intent);
    }
    
    pub async fn subscribe(&self) -> IntentSubscriber {
        let mut receiver = self.receiver.write().await;
        IntentSubscriber {
            _receiver: receiver.resubscribe(),
        }
    }
    
    pub async fn add_filter(&self, filter: IntentFilter) {
        let mut filters = self.filters.write().await;
        filters.insert(filter.name.clone(), filter);
    }
    
    pub async fn process_intents(&self, processor: &impl IntentProcessor) {
        let mut receiver = self.receiver.write().await;
        while let Ok(intent) = receiver.recv().await {
            if self.passes_filters(&intent).await {
                processor.process(intent).await;
            }
        }
    }
    
    async fn passes_filters(&self, intent: &Intent) -> bool {
        let filters = self.filters.read().await;
        filters.values()
            .filter(|f| f.enabled)
            .all(|filter| filter.passes(intent))
    }
}

pub trait IntentProcessor {
    async fn process(&self, intent: Intent);
}

#[derive(Debug)]
pub struct IntentSubscriber {
    _receiver: broadcast::Receiver<Intent>,
}

impl IntentSubscriber {
    pub async fn receive(&mut self) -> Option<Intent> {
        self._receiver.recv().await.ok()
    }
}