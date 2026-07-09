use context_memory::ContextMemoryManager;
use intent_bus::{Intent, IntentBus};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use tracing::{debug, instrument};

/// Macrophage Agent — หน่วยกวาดล้าง (Garbage Collector)
///
/// ทำหน้าที่ตรวจตราและทำลายข้อมูลที่หมดอายุหรือไม่ใช้แล้ว:
/// - Intent ที่ค้างเก่าใน IntentBus
/// - Context entries ที่หมดอายุใน ContextMemory
/// - Token ที่หมดอายุในระบบ
#[derive(Clone)]
pub struct MacrophageAgent {
    intent_bus: Arc<IntentBus>,
    context_memory: Arc<ContextMemoryManager>,
    /// อายุสูงสุดของ Intent ก่อนถูกกำจัด (ms)
    max_intent_age_ms: u64,
    /// อายุสูงสุดของ Context entry ก่อนถูกกำจัด (s)
    context_ttl_secs: u64,
    /// จำนวน Intent ที่กำจัดได้ในรอบล่าสุด
    pub collected: Arc<std::sync::atomic::AtomicU64>,
    /// จำนวน Context entries ที่กำจัดได้ในรอบล่าสุด
    pub collected_context: Arc<std::sync::atomic::AtomicU64>,
}

impl MacrophageAgent {
    /// สร้าง Macrophage ผูกกับ Intent Bus และ context memory พร้อมกำหนดอายุขยะที่จะเก็บกวาด
    #[must_use]
    pub fn new(
        intent_bus: Arc<IntentBus>,
        context_memory: Arc<ContextMemoryManager>,
        max_intent_age_ms: u64,
        context_ttl_secs: u64,
    ) -> Self {
        Self {
            intent_bus,
            context_memory,
            max_intent_age_ms,
            context_ttl_secs,
            collected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            collected_context: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// ตรวจสอบ Intent ว่าหมดอายุหรือไม่
    #[must_use]
    pub fn is_stale(intent: &Intent, max_age_ms: u64) -> bool {
        intent
            .timestamp
            .elapsed()
            .map(|e| e.as_millis() as u64 > max_age_ms)
            .unwrap_or(false)
    }

    /// ล้าง Intent ที่หมดอายุออกจากระบบ
    #[instrument(skip(self))]
    pub async fn sweep_intents(&self) -> u64 {
        let mut subscriber = self.intent_bus.subscribe();
        let mut stale_count = 0u64;

        while let Some(intent) =
            tokio::time::timeout(Duration::from_millis(10), subscriber.receive())
                .await
                .ok()
                .flatten()
        {
            if Self::is_stale(&intent, self.max_intent_age_ms) {
                debug!(
                    intent_id = %intent.id,
                    age_ms = intent.timestamp.elapsed().map(|e| e.as_millis() as u64).unwrap_or(0),
                    "sweeping stale intent"
                );
                stale_count += 1;
            }
        }

        self.collected
            .fetch_add(stale_count, std::sync::atomic::Ordering::Relaxed);
        stale_count
    }

    /// ล้าง Context entries ที่หมดอายุออกจาก ContextMemory
    #[instrument(skip(self))]
    pub async fn sweep_context(&self) -> u64 {
        let context_memory = Arc::clone(&self.context_memory);
        let ttl = Duration::from_secs(self.context_ttl_secs);
        let count = task::spawn_blocking(move || context_memory.clean_expired(ttl))
            .await
            .unwrap_or(0);
        if count > 0 {
            debug!(count, "Macrophage: cleaned expired context entries");
        }
        self.collected_context
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        count
    }

    /// รายงานสถิติการกวาดล้าง
    #[must_use]
    pub fn stats(&self) -> SweepStats {
        SweepStats {
            collected: self.collected.load(std::sync::atomic::Ordering::Relaxed),
            collected_context: self
                .collected_context
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// สถิติผลการเก็บกวาดรอบล่าสุดของ Macrophage
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepStats {
    /// จำนวน intent เก่าที่ถูกกำจัด
    pub collected: u64,
    /// จำนวน context entries หมดอายุที่ถูกกำจัด
    pub collected_context: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_bus::{IntentPriority, IntentType};
    use std::time::SystemTime;

    fn make_macrophage() -> MacrophageAgent {
        MacrophageAgent::new(
            Arc::new(IntentBus::new(8)),
            Arc::new(ContextMemoryManager::new()),
            1000,
            3600,
        )
    }

    #[test]
    fn stale_intent_detected() {
        let mut intent = Intent::new(
            "old",
            IntentType::Event,
            "data",
            IntentPriority::Low,
            "test",
        );
        intent.timestamp = SystemTime::now() - Duration::from_secs(60);
        assert!(MacrophageAgent::is_stale(&intent, 1000));
    }

    #[test]
    fn fresh_intent_not_stale() {
        let intent = Intent::new(
            "new",
            IntentType::Event,
            "data",
            IntentPriority::Low,
            "test",
        );
        assert!(!MacrophageAgent::is_stale(&intent, 1000));
    }

    #[test]
    fn collected_counter_starts_at_zero() {
        let m = make_macrophage();
        assert_eq!(m.stats().collected, 0);
    }

    #[tokio::test]
    async fn sweep_returns_zero_when_no_stale_intents() {
        let m = make_macrophage();
        let count = m.sweep_intents().await;
        assert_eq!(count, 0);
    }
}
