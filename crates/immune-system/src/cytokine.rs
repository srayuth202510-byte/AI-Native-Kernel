use intent_bus::{Intent, IntentBus, IntentPriority, IntentType};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, instrument, warn};

/// Cytokine Signal — สัญญาณเสริมภูมิ (Critical Broadcast)
///
/// ทำหน้าที่ broadcast ข้อความวิกฤตไปยัง Agents ทุกตัว:
/// - Threat detected → broadcast alert
/// - System-wide emergency → mobilize all agents
/// - Escalation levels: Info → Warning → Critical → Emergency
#[derive(Debug, Error)]
pub enum CytokineError {
    /// ส่งสัญญาณเข้า Intent Bus ไม่สำเร็จ
    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),
}

/// ระดับความรุนแรงของ Cytokine Signal
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CytokineLevel {
    /// ข้อมูลทั่วไป ไม่ต้องตอบสนอง
    Info,
    /// สิ่งผิดปกติที่ควรจับตา
    Warning,
    /// ภัยคุกคามที่ต้องตอบสนองทันที
    Critical,
    /// เหตุฉุกเฉินระดับระบบ — ระดมทุก agent
    Emergency,
}

/// Cytokine Signal event
#[derive(Debug, Clone)]
pub struct CytokineEvent {
    /// ระดับความรุนแรงของสัญญาณ
    pub level: CytokineLevel,
    /// ชื่อ component ต้นทางที่ส่งสัญญาณ (เช่น "tcell")
    pub source: String,
    /// ข้อความอธิบายเหตุการณ์
    pub message: String,
    /// เวลาเกิดเหตุการณ์
    pub timestamp: Instant,
    /// รายการ PID ที่ได้รับผลกระทบจากเหตุการณ์นี้
    pub affected_pids: Vec<u32>,
}

impl CytokineEvent {
    /// สร้าง event ใหม่ ณ เวลาปัจจุบัน (ยังไม่ระบุ PID ที่กระทบ)
    #[must_use]
    pub fn new(level: CytokineLevel, source: &str, message: &str) -> Self {
        Self {
            level,
            source: source.to_string(),
            message: message.to_string(),
            timestamp: Instant::now(),
            affected_pids: Vec::new(),
        }
    }
}

/// Cytokine Signal broadcaster
pub struct CytokineSignal {
    intent_bus: Arc<IntentBus>,
    /// ประวัติ Cytokine events ล่าสุด
    history: Vec<CytokineEvent>,
    /// เก็บเฉพาะ N events ล่าสุด
    max_history: usize,
}

impl CytokineSignal {
    /// สร้าง broadcaster ใหม่ ผูกกับ Intent Bus และจำกัดขนาดประวัติ
    #[must_use]
    pub fn new(intent_bus: Arc<IntentBus>, max_history: usize) -> Self {
        Self {
            intent_bus,
            history: Vec::new(),
            max_history,
        }
    }

    /// ส่ง Cytokine Signal ออกอากาศ
    #[instrument(skip(self))]
    pub async fn broadcast(&mut self, event: CytokineEvent) -> crate::Result<()> {
        let priority = match event.level {
            CytokineLevel::Info => IntentPriority::Low,
            CytokineLevel::Warning => IntentPriority::Medium,
            CytokineLevel::Critical => IntentPriority::Critical,
            CytokineLevel::Emergency => IntentPriority::Critical,
        };

        let intent = Intent::new(
            format!("cytokine:{:?}", event.level),
            IntentType::Event,
            &event.message,
            priority,
            &event.source,
        );

        let _ = self.intent_bus.publish(intent).await;

        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(event.clone());

        match event.level {
            CytokineLevel::Emergency => {
                warn!(
                    source = %event.source,
                    message = %event.message,
                    "CYTOKINE EMERGENCY — system-wide alert broadcast"
                );
            }
            CytokineLevel::Critical => {
                warn!(
                    source = %event.source,
                    message = %event.message,
                    "CYTOKINE CRITICAL — mobilizing agents"
                );
            }
            _ => {
                debug!(
                    level = ?event.level,
                    source = %event.source,
                    "cytokine signal broadcast"
                );
            }
        }

        Ok(())
    }

    /// ส่ง Emergency Signal ด้วยความเร็วสูงสุด
    #[instrument(skip(self))]
    pub async fn emergency(&mut self, source: &str, message: &str) -> crate::Result<()> {
        let event = CytokineEvent::new(CytokineLevel::Emergency, source, message);
        self.broadcast(event).await
    }

    /// ดูประวัติ Cytokine events
    #[must_use]
    pub fn history(&self) -> &[CytokineEvent] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn broadcast_and_record() {
        let bus = Arc::new(IntentBus::new(8));
        let mut c = CytokineSignal::new(bus, 10);
        let event = CytokineEvent::new(CytokineLevel::Info, "test", "hello");
        c.broadcast(event).await.unwrap();
        assert_eq!(c.history().len(), 1);
        assert_eq!(c.history()[0].source, "test");
    }

    #[tokio::test]
    async fn emergency_signal() {
        let bus = Arc::new(IntentBus::new(8));
        let mut c = CytokineSignal::new(bus, 10);
        c.emergency("test", "emergency!").await.unwrap();
        assert_eq!(c.history().len(), 1);
        assert_eq!(c.history()[0].level, CytokineLevel::Emergency);
    }

    #[tokio::test]
    async fn history_limit() {
        let bus = Arc::new(IntentBus::new(8));
        let mut c = CytokineSignal::new(bus, 3);
        for i in 0..5 {
            let event = CytokineEvent::new(CytokineLevel::Info, "test", &i.to_string());
            c.broadcast(event).await.unwrap();
        }
        assert_eq!(c.history().len(), 3);
        assert_eq!(c.history()[0].message, "2");
    }
}
