//! เอกสารกำกับโค้ดระดับโมดูล/เครต (เพิ่มอัตโนมัติ)
//! เอกสารกำกับโค้ดระดับโมดูล/เครต (เพิ่มอัตโนมัติ)
#![deny(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{RwLock, broadcast};

use serde::{Deserialize, Serialize};

/// `Intent` คือตัวแทนของเจตจำนงหรือความต้องการที่ส่งเข้ามาในระบบ
/// เพื่อให้ Agent หรือส่วนประกอบอื่น ๆ นำไปประมวลผลต่อ
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// ไอดีเฉพาะสำหรับการอ้างอิง Intent แต่ละตัว
    pub id: String,
    /// ประเภทของ Intent เช่น คำสั่งหรือเหตุการณ์
    pub intent_type: IntentType,
    /// ข้อมูลเนื้อหาของ Intent
    pub payload: String,
    /// ระดับความสำคัญของ Intent (ต่ำ, ปานกลาง, สูง, วิกฤต)
    pub priority: IntentPriority,
    /// เวลาที่สร้าง Intent นี้ขึ้นมา
    pub timestamp: std::time::SystemTime,
    /// แหล่งที่มาของ Intent (เช่น user หรือ agent-a)
    pub source: String,
    /// ปลายทางที่ต้องการส่ง Intent นี้ไปหา (ถ้ามี)
    pub target: Option<String>,
    /// ข้อมูลเพิ่มเติมในรูปแบบ Key-Value
    pub metadata: HashMap<String, String>,
}

impl Intent {
    /// สร้างอินสแตนซ์ใหม่ของ `Intent` โดยตั้งค่าเริ่มต้นและบันทึกเวลาปัจจุบัน
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

/// `IntentType` กำหนดประเภทของเจตจำนง เพื่อจัดสรรให้กับโมดูลประมวลผลที่เหมาะสม
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentType {
    /// เจตจำนงในรูปแบบภาษาธรรมชาติ (เช่น ข้อความดิบจากผู้ใช้)
    NaturalLanguage,
    /// เจตจำนงแบบมีโครงสร้าง (เช่น ข้อมูล JSON หรือ Schema ที่กำหนดไว้)
    Structured,
    /// คำสั่งการทำงานในระบบ
    Command,
    /// เหตุการณ์หรือการแจ้งเตือนภายในระบบ
    Event,
    /// คำสั่งขัดจังหวะการทำงานที่มีลำดับความสำคัญสูง
    Interrupt,
}

/// `IntentPriority` กำหนดระดับความสำคัญในการประมวลผลเจตจำนง
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntentPriority {
    /// ลำดับความสำคัญต่ำ (เช่น งานเบื้องหลังที่รอได้)
    Low,
    /// ลำดับความสำคัญปานกลาง (การทำงานทั่วไป)
    Medium,
    /// ลำดับความสำคัญสูง (ต้องได้รับการตอบสนองอย่างรวดเร็ว)
    High,
    /// ลำดับความสำคัญวิกฤต (ต้องประมวลผลทันที)
    Critical,
}

/// `IntentBus` เป็นระบบส่งผ่านข้อมูลแบบกระจายสัญญาณ (Broadcast Intent Bus)
/// ที่ใช้ประสานการทำงานระหว่าง Agent และระบบย่อยอื่น ๆ แบบ Asynchronous
#[derive(Debug, Clone)]
pub struct IntentBus {
    /// ช่องสัญญาณหลักในการกระจายสัญญาณ Intent ไปยัง Subscriber ทั้งหมด
    sender: broadcast::Sender<Intent>,
    /// รายการตัวกรอง (Filters) ที่ใช้ในการกรอง Intent โดยมี RwLock เพื่อควบคุมการเขียนอ่านแบบเธรดเซฟ
    filters: Arc<RwLock<HashMap<String, IntentFilter>>>,
}

/// `IntentFilter` กำหนดข้อมูลตัวกรองสำหรับคัดแยกประเภท Intent ที่สนใจ
#[derive(Debug, Clone)]
pub struct IntentFilter {
    /// ชื่อของตัวกรองเพื่อใช้ระบุและอ้างอิง
    pub name: String,
    /// รายการเงื่อนไขคัดกรองทั้งหมด ซึ่ง Intent จะต้องผ่านทุกเงื่อนไข (AND)
    pub conditions: Vec<FilterCondition>,
    /// สถานะว่าตัวกรองนี้กำลังเปิดใช้งานอยู่หรือไม่
    pub enabled: bool,
}

/// `FilterCondition` เงื่อนไขแต่ละรูปแบบที่ใช้ตรวจสอบคุณสมบัติของ Intent
#[derive(Debug, Clone)]
pub enum FilterCondition {
    /// ตรวจสอบประเภทของ Intent ให้ตรงกับประเภทที่กำหนด
    IntentType(IntentType),
    /// ตรวจสอบระดับความสำคัญว่าเท่ากับหรือสูงกว่าที่ระบุหรือไม่
    Priority(IntentPriority),
    /// ตรวจสอบว่าแหล่งที่มา (Source) มีข้อความตามที่กำหนดหรือไม่
    SourceContains(String),
    /// ตรวจสอบว่าปลายทาง (Target) มีข้อความตามที่กำหนดหรือไม่
    TargetContains(String),
    /// ตรวจสอบว่ามี Metadata ตาม Key และ Value ที่ระบุหรือไม่
    HasMetadata(String, String),
}

/// ข้อผิดพลาดที่อาจเกิดขึ้นระหว่างการทำงานกับ `IntentBus`
#[derive(Debug, Error)]
pub enum IntentBusError {
    /// เกิดข้อผิดพลาดเมื่อไม่สามารถส่งข้อมูลลงในช่องสัญญาณได้ (เช่น ไม่มี Subscriber รอรับอยู่)
    #[error("intent bus send failed")]
    SendFailed,
}

impl IntentFilter {
    /// ตรวจสอบว่า Intent ที่ส่งเข้ามาผ่านเงื่อนไขคัดกรองทั้งหมดใน Filter นี้หรือไม่
    #[must_use]
    pub fn passes(&self, intent: &Intent) -> bool {
        self.conditions
            .iter()
            .all(|condition| condition.matches(intent))
    }
}

impl FilterCondition {
    /// เปรียบเทียบข้อมูลเงื่อนไขของตัวคัดกรองนี้กับ Intent ที่กำหนด
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
    /// สร้างอินสแตนซ์ของ `IntentBus` ใหม่โดยระบุความจุของช่องสัญญาณ (Capacity)
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            sender,
            filters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// ลงทะเบียนผู้ติดตาม (Subscriber) รายใหม่เพื่อรับข้อมูลจาก IntentBus
    pub fn subscribe(&self) -> IntentSubscriber {
        IntentSubscriber {
            receiver: self.sender.subscribe(),
        }
    }

    /// ส่งและเผยแพร่ Intent เข้าสู่ระบบส่งข้อมูล (Broadcast channel)
    /// คืนค่า `Ok(())` หากส่งสำเร็จ หรือส่งข้อผิดพลาดหากล้มเหลว
    pub async fn publish(&self, intent: Intent) -> Result<(), IntentBusError> {
        self.sender
            .send(intent)
            .map(|_| ())
            .map_err(|_| IntentBusError::SendFailed)
    }

    /// เพิ่มตัวกรองการคัดแยก Intent ใหม่เข้าไปในระบบแบบ Asynchronous
    pub async fn add_filter(&self, filter: IntentFilter) {
        let mut filters = self.filters.write().await;
        filters.insert(filter.name.clone(), filter);
    }

    /// ลบตัวกรองการคัดแยก Intent ออกจากระบบด้วยชื่อของตัวกรอง
    pub async fn remove_filter(&self, name: &str) {
        let mut filters = self.filters.write().await;
        filters.remove(name);
    }

    /// ตรวจสอบว่า Intent นั้น ๆ ผ่านตัวกรองทั้งหมดที่เปิดใช้งานอยู่ในขณะนั้นหรือไม่
    pub async fn passes_filters(&self, intent: &Intent) -> bool {
        let filters = self.filters.read().await;
        filters
            .values()
            .filter(|filter| filter.enabled)
            .all(|filter| filter.passes(intent))
    }

    /// สังเกตการณ์และประมวลผล Intent ในระบบแบบลูปวนซ้ำ โดยจะทำการคัดกรองก่อนส่งให้ `processor` ดำเนินการ
    pub async fn process_intents(&self, processor: &impl IntentProcessor) {
        let mut receiver = self.sender.subscribe();
        while let Ok(intent) = receiver.recv().await {
            if self.passes_filters(&intent).await {
                processor.process(intent).await;
            }
        }
    }
}

/// Interface (Trait) สำหรับการนำ Intent ไปประมวลผลตามตรรกะของระบบ
pub trait IntentProcessor {
    /// ฟังก์ชันประมวลผล Intent แบบ Asynchronous
    fn process(&self, intent: Intent) -> impl Future<Output = ()> + Send;
}

/// โครงสร้างข้อมูลห่อหุ้มฝั่งผู้รับข้อมูลจาก `IntentBus`
pub struct IntentSubscriber {
    /// ช่องทางรับข่าวสาร (Receiver) ของ Tokio Broadcast
    receiver: broadcast::Receiver<Intent>,
}

impl IntentSubscriber {
    /// รอรับและคืนค่า Intent ถัดไปแบบ Asynchronous คืนค่า `None` หากเกิดความล้มเหลวในการส่งผ่านข้อมูล
    pub async fn receive(&mut self) -> Option<Intent> {
        self.receiver.recv().await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct RecordingProcessor {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl IntentProcessor for RecordingProcessor {
        async fn process(&self, intent: Intent) {
            self.seen.lock().await.push(intent.id);
        }
    }

    #[tokio::test]
    async fn publish_reaches_subscriber() {
        // ทดสอบว่าการ Publish ข้อมูลส่งไปถึงผู้ติดตาม (Subscriber) ได้จริง
        let bus = IntentBus::new(8);
        let mut subscriber = bus.subscribe();
        let intent = Intent::new(
            "intent-1",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::High,
            "user",
        );

        bus.publish(intent.clone())
            .await
            .expect("publish should succeed");

        let received = subscriber
            .receive()
            .await
            .expect("subscriber should receive intent");
        assert_eq!(received.id, intent.id);
        assert_eq!(received.intent_type, intent.intent_type);
        assert_eq!(received.payload, intent.payload);
    }

    #[test]
    fn filter_matches_expected_intent() {
        // ทดสอบว่าการตรวจเงื่อนไขตัวกรองทำงานถูกต้องตรงกับเงื่อนไขที่กำหนดทั้งหมด
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
        // ทดสอบว่าตัวกรองที่ไม่ได้เปิดใช้งาน (disabled) จะถูกละเลย/ข้ามไป
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

    #[tokio::test]
    async fn publish_without_subscribers_fails_closed() {
        let bus = IntentBus::new(8);
        let intent = Intent::new(
            "intent-4",
            IntentType::Event,
            "orphan",
            IntentPriority::Low,
            "system",
        );

        assert!(matches!(
            bus.publish(intent).await,
            Err(IntentBusError::SendFailed)
        ));
    }

    #[tokio::test]
    async fn remove_filter_restores_pass_through() {
        let bus = IntentBus::new(8);
        let intent = Intent::new(
            "intent-5",
            IntentType::Event,
            "heartbeat",
            IntentPriority::Low,
            "system",
        );

        bus.add_filter(IntentFilter {
            name: "commands-only".to_string(),
            conditions: vec![FilterCondition::IntentType(IntentType::Command)],
            enabled: true,
        })
        .await;

        assert!(!bus.passes_filters(&intent).await);
        bus.remove_filter("commands-only").await;
        assert!(bus.passes_filters(&intent).await);
    }

    #[tokio::test]
    async fn process_intents_only_for_matching_filters() {
        let bus = IntentBus::new(8);
        let processor = RecordingProcessor::default();

        bus.add_filter(IntentFilter {
            name: "critical-commands".to_string(),
            conditions: vec![
                FilterCondition::IntentType(IntentType::Command),
                FilterCondition::Priority(IntentPriority::Critical),
            ],
            enabled: true,
        })
        .await;

        let worker_bus = bus.clone();
        let worker_processor = processor.clone();
        let handle = tokio::spawn(async move {
            worker_bus.process_intents(&worker_processor).await;
        });
        tokio::task::yield_now().await;

        let ignored = Intent::new(
            "intent-6",
            IntentType::Command,
            "low-priority",
            IntentPriority::Low,
            "user",
        );
        let accepted = Intent::new(
            "intent-7",
            IntentType::Command,
            "critical-op",
            IntentPriority::Critical,
            "user",
        );

        bus.publish(ignored).await.expect("publish should succeed");
        bus.publish(accepted).await.expect("publish should succeed");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();

        let seen = processor.seen.lock().await.clone();
        assert_eq!(seen, vec!["intent-7".to_string()]);
    }
}
