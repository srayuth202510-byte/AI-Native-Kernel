#![deny(unsafe_code)]

//! ระบบจัดการหน่วยความจำบริบท (Context Memory Manager)
//! รองรับการจัดเก็บข้อมูลแบบลำดับชั้น (Hierarchical Paging) ตั้งแต่ Hot, Warm ไปจนถึง Cold Store

pub mod cold;
pub mod hot;
pub mod warm;

use crate::cold::ColdStore;
use crate::hot::HotStore;
use crate::warm::WarmStore;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, warn};

/// ข้อผิดพลาดที่เกี่ยวข้องกับระบบจัดการหน่วยความจำบริบท
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// ไม่พบหน้าบริบท (Context Page) ที่ต้องการในระบบเก็บข้อมูล
    #[error("context page not found")]
    NotFound,
}

/// ผลลัพธ์แบบ Custom Result สำหรับ Context Memory
pub type Result<T> = core::result::Result<T, ContextError>;

/// ตัวจัดการหน่วยความจำบริบทที่แบ่งลำดับชั้นของข้อมูล (Hot -> Warm -> Cold)
/// เพื่อประสิทธิภาพสูงสุดในการดึงข้อมูลและประหยัดการใช้ RAM
pub struct ContextMemoryManager {
    /// พื้นที่เก็บข้อมูลด่วน (Hot Store) ใน RAM เข้าถึงได้เร็วที่สุด
    hot: Arc<std::sync::RwLock<HotStore>>,
    /// พื้นที่เก็บข้อมูลชั่วคราว (Warm Store) บน RocksDB หรือ NVMe
    warm: Arc<std::sync::RwLock<WarmStore>>,
    /// พื้นที่เก็บข้อมูลถาวร (Cold Store) บนฮาร์ดดิสก์/ไฟล์สำรอง
    cold: Arc<std::sync::RwLock<ColdStore>>,
    /// ขนาดความจุสูงสุดของ Hot Store ก่อนที่จะถูกย้ายไปยัง Warm Store
    hot_capacity: usize,
    /// ขนาดความจุสูงสุดของ Warm Store ก่อนที่จะถูกย้ายไปยัง Cold Store
    warm_capacity: usize,
}

impl ContextMemoryManager {
    /// สร้างอินสแตนซ์ของ ContextMemoryManager พร้อมกำหนดค่าความจุเริ่มต้น (256 hot, 1024 warm)
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(256, 1_024)
    }

    /// สร้าง ContextMemoryManager ด้วยค่าความจุที่กำหนดเอง
    /// เหมาะสำหรับ testing หรือ configuration ที่ต้องการขนาด tier ที่แน่นอน
    #[must_use]
    pub fn with_capacity(hot_capacity: usize, warm_capacity: usize) -> Self {
        Self {
            hot: Arc::new(std::sync::RwLock::new(HotStore::new())),
            warm: Arc::new(std::sync::RwLock::new(WarmStore::new())),
            cold: Arc::new(std::sync::RwLock::new(ColdStore::new())),
            hot_capacity,
            warm_capacity,
        }
    }

    /// บันทึกข้อมูลบริบทลงในระบบเก็บข้อมูล โดยเริ่มจาก Hot Store ก่อน
    /// หากข้อมูลใน Hot Store เกินขนาดความจุ จะย้ายข้อมูลเก่าสุดไปยัง Warm Store
    /// และหากข้อมูลใน Warm Store เกินขนาดความจุ ก็จะย้ายข้อมูลเก่าสุดไปยัง Cold Store
    #[instrument(skip(self, value), fields(key = %key.as_ref(), value_len = value.len()))]
    pub fn put(&self, key: impl Into<String> + AsRef<str>, value: Vec<u8>) {
        let key = key.into();
        debug!(tier = "hot", "บันทึกข้อมูลบริบทลง Hot Store");
        let mut hot = self.hot.write().expect("hot memory lock poisoned");
        hot.insert(key, value);

        // ตรวจสอบขนาดเพื่อย้ายข้อมูล (Evict) ไปยัง Warm Store
        if hot.len() > self.hot_capacity {
            let evicted = hot.evict_oldest();
            drop(hot); // ปลดล็อก hot write lock ก่อนเขียนลง warm store เพื่อป้องกัน deadlock

            if let Some((evicted_key, evicted_value)) = evicted {
                warn!(tier = "warm", key = %evicted_key, "Hot Store เต็ม — ย้ายข้อมูลเก่าลง Warm Store");
                let mut warm = self.warm.write().expect("warm memory lock poisoned");
                warm.insert(evicted_key.clone(), evicted_value);

                // ตรวจสอบขนาดเพื่อย้ายข้อมูล (Evict) ไปยัง Cold Store
                if warm.len() > self.warm_capacity {
                    let spilled = warm.evict_oldest();
                    drop(warm); // ปลดล็อก warm write lock ก่อนเขียนลง cold store เพื่อป้องกัน deadlock

                    if let Some((spilled_key, spilled_value)) = spilled {
                        warn!(tier = "cold", key = %spilled_key, "Warm Store เต็ม — ย้ายข้อมูลเก่าลง Cold Store");
                        self.cold
                            .write()
                            .expect("cold memory lock poisoned")
                            .insert(spilled_key, spilled_value);
                    }
                }
            }
        }
    }

    /// ดึงข้อมูลบริบทจากระบบเก็บข้อมูลตามลำดับชั้น
    /// โดยจะค้นหาใน Hot Store ก่อน หากไม่พบจะค้นหาใน Warm Store และ Cold Store ตามลำดับ
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาด `ContextError::NotFound` หากไม่พบข้อมูลในระดับใดเลย
    #[instrument(skip(self), fields(key = %key))]
    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        // ค้นหาใน Hot Store (RAM)
        if let Some(value) = self.hot.read().expect("hot memory lock poisoned").get(key) {
            debug!(tier = "hot", "พบข้อมูลใน Hot Store");
            return Ok(value);
        }

        // ค้นหาใน Warm Store (RocksDB / NVMe)
        if let Some(value) = self
            .warm
            .read()
            .expect("warm memory lock poisoned")
            .get(key)
        {
            debug!(tier = "warm", "พบข้อมูลใน Warm Store");
            return Ok(value);
        }

        // ค้นหาใน Cold Store (Disk File)
        if let Some(value) = self
            .cold
            .read()
            .expect("cold memory lock poisoned")
            .get(key)
        {
            debug!(tier = "cold", "พบข้อมูลใน Cold Store");
            return Ok(value);
        }

        warn!("ไม่พบข้อมูลบริบทในทุก tier");
        Err(ContextError::NotFound)
    }

    /// ยกระดับ (Promote) ข้อมูลจาก Warm หรือ Cold tier กลับขึ้นสู่ Hot tier
    ///
    /// ค้นหาใน Warm ก่อน ถ้าพบ → ลบออก → insert ใน Hot
    /// ถ้าไม่พบใน Warm → ค้นหาใน Cold → ลบออก → insert ใน Hot
    /// ถ้าข้อมูลอยู่ใน Hot อยู่แล้ว → no-op (คืน Ok)
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ในทุก tier
    #[instrument(skip(self), fields(key = %key))]
    pub fn promote(&self, key: &str) -> Result<()> {
        // ถ้าอยู่ใน Hot อยู่แล้ว — no-op
        if self
            .hot
            .read()
            .expect("hot lock poisoned")
            .get(key)
            .is_some()
        {
            debug!(tier = "hot", "ข้อมูลอยู่ใน Hot อยู่แล้ว — no-op");
            return Ok(());
        }
        // ค้นหาและดึงออกจาก Warm
        let warm_value = self.warm.write().expect("warm lock poisoned").remove(key);
        if let Some(value) = warm_value {
            debug!(tier = "warm->hot", "ยกระดับข้อมูลจาก Warm ขึ้น Hot");
            self.put(key.to_string(), value);
            return Ok(());
        }
        // ค้นหาและดึงออกจาก Cold
        let cold_value = self.cold.write().expect("cold lock poisoned").remove(key);
        if let Some(value) = cold_value {
            debug!(tier = "cold->hot", "ยกระดับข้อมูลจาก Cold ขึ้น Hot");
            self.put(key.to_string(), value);
            return Ok(());
        }
        warn!("promote ล้มเหลว — ไม่พบ key ในทุก tier");
        Err(ContextError::NotFound)
    }

    /// ลดระดับ (Demote) ข้อมูลจาก Hot tier ลงสู่ Warm tier
    ///
    /// ลบออกจาก Hot → insert ใน Warm
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ใน Hot Store
    #[instrument(skip(self), fields(key = %key))]
    pub fn demote(&self, key: &str) -> Result<()> {
        let hot_value = self.hot.write().expect("hot lock poisoned").remove(key);
        if let Some(value) = hot_value {
            debug!(tier = "hot->warm", "ลดระดับข้อมูลจาก Hot ลง Warm");
            self.warm
                .write()
                .expect("warm lock poisoned")
                .insert(key.to_string(), value);
            return Ok(());
        }
        warn!("demote ล้มเหลว — ไม่พบ key ใน Hot Store");
        Err(ContextError::NotFound)
    }

    /// คืนชื่อ tier ที่เก็บข้อมูล key นั้นอยู่ในปัจจุบัน
    /// ใช้สำหรับ debugging, testing และ observability
    ///
    /// คืน `Some("hot")`, `Some("warm")`, `Some("cold")` หรือ `None`
    #[must_use]
    pub fn tier_of(&self, key: &str) -> Option<&'static str> {
        if self
            .hot
            .read()
            .expect("hot lock poisoned")
            .get(key)
            .is_some()
        {
            return Some("hot");
        }
        if self
            .warm
            .read()
            .expect("warm lock poisoned")
            .get(key)
            .is_some()
        {
            return Some("warm");
        }
        if self
            .cold
            .read()
            .expect("cold lock poisoned")
            .get(key)
            .is_some()
        {
            return Some("cold");
        }
        None
    }
}

impl Default for ContextMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_round_trip() {
        let memory = ContextMemoryManager::new();
        memory.put("ctx-1", b"hello".to_vec());

        let value = memory.get("ctx-1").expect("context should exist");
        assert_eq!(value, b"hello".to_vec());
    }

    #[test]
    fn get_returns_not_found_for_missing_key() {
        let memory = ContextMemoryManager::new();
        let result = memory.get("does-not-exist");
        assert_eq!(result, Err(ContextError::NotFound));
    }

    #[test]
    fn overwrite_updates_value_in_hot_store() {
        let memory = ContextMemoryManager::new();
        memory.put("ctx-2", b"original".to_vec());
        memory.put("ctx-2", b"updated".to_vec());

        let value = memory.get("ctx-2").expect("context should exist");
        assert_eq!(value, b"updated".to_vec());
    }

    #[test]
    fn multiple_keys_are_independent() {
        let memory = ContextMemoryManager::new();
        memory.put("key-a", b"alpha".to_vec());
        memory.put("key-b", b"beta".to_vec());
        memory.put("key-c", b"gamma".to_vec());

        assert_eq!(memory.get("key-a").expect("key-a"), b"alpha".to_vec());
        assert_eq!(memory.get("key-b").expect("key-b"), b"beta".to_vec());
        assert_eq!(memory.get("key-c").expect("key-c"), b"gamma".to_vec());
    }

    #[test]
    fn eviction_to_warm_when_hot_capacity_exceeded() {
        let memory = ContextMemoryManager::new();
        let first_key = "evict-target-0".to_string();
        for i in 0..257usize {
            memory.put(format!("evict-target-{i}"), vec![i as u8]);
        }
        let result = memory.get(&first_key);
        assert!(
            result.is_ok(),
            "ข้อมูลที่ถูก evict ควรยังคงดึงได้จาก warm/cold store"
        );
    }

    #[test]
    fn get_empty_byte_slice_is_valid() {
        let memory = ContextMemoryManager::new();
        memory.put("empty-ctx", vec![]);
        let value = memory.get("empty-ctx").expect("empty context should exist");
        assert_eq!(value, Vec::<u8>::new());
    }

    // ---- ANK-013: Tier Migration API tests ----

    #[test]
    fn with_capacity_controls_eviction_boundary() {
        let memory = ContextMemoryManager::with_capacity(2, 1024);
        memory.put("a", b"1".to_vec());
        memory.put("b", b"2".to_vec());
        assert_eq!(memory.tier_of("a"), Some("hot"));
        assert_eq!(memory.tier_of("b"), Some("hot"));
        memory.put("c", b"3".to_vec()); // บังคับ evict "a" ไป warm
        assert_eq!(memory.tier_of("a"), Some("warm"), "a ต้องถูก evict ไป warm");
        assert_eq!(memory.tier_of("b"), Some("hot"));
        assert_eq!(memory.tier_of("c"), Some("hot"));
    }

    #[test]
    fn promote_from_warm_to_hot_succeeds() {
        let memory = ContextMemoryManager::with_capacity(2, 1024);
        memory.put("a", b"alpha".to_vec());
        memory.put("b", b"beta".to_vec());
        memory.put("c", b"gamma".to_vec()); // evict "a" ไป warm
        assert_eq!(memory.tier_of("a"), Some("warm"));

        memory.promote("a").expect("promote Warm→Hot ต้องสำเร็จ");
        assert_eq!(memory.tier_of("a"), Some("hot"), "หลัง promote ต้องอยู่ใน Hot");
        assert_eq!(
            memory.get("a").expect("a ต้องดึงได้หลัง promote"),
            b"alpha".to_vec(),
            "ข้อมูลต้องไม่เปลี่ยนแปลง"
        );
    }

    #[test]
    fn promote_respects_hot_capacity() {
        let memory = ContextMemoryManager::with_capacity(2, 1024);
        memory.put("a", b"alpha".to_vec());
        memory.put("b", b"beta".to_vec());
        memory.put("c", b"gamma".to_vec()); // a -> warm

        memory.promote("a").expect("promote Warm→Hot ต้องสำเร็จ");

        assert_eq!(memory.tier_of("a"), Some("hot"));
        assert_eq!(memory.tier_of("b"), Some("warm"));
        assert_eq!(memory.tier_of("c"), Some("hot"));
    }

    #[test]
    fn demote_from_hot_to_warm_succeeds() {
        let memory = ContextMemoryManager::new();
        memory.put("hotkey", b"data".to_vec());
        assert_eq!(memory.tier_of("hotkey"), Some("hot"));

        memory.demote("hotkey").expect("demote Hot→Warm ต้องสำเร็จ");
        assert_eq!(
            memory.tier_of("hotkey"),
            Some("warm"),
            "หลัง demote ต้องอยู่ใน Warm"
        );
        assert_eq!(
            memory.get("hotkey").expect("ยังดึงได้จาก Warm"),
            b"data".to_vec()
        );
    }

    // ---- ANK-014: Round-trip property tests ----

    #[test]
    fn property_round_trip_hot_to_cold_and_back() {
        let memory = ContextMemoryManager::with_capacity(1, 1);
        memory.put("x", b"payload".to_vec());
        memory.put("y", b"y".to_vec()); // x → warm
        memory.put("z", b"z".to_vec()); // x → cold (warm full)

        assert_eq!(memory.tier_of("x"), Some("cold"), "x ต้องถูก evict ถึง cold");
        let val = memory.get("x").expect("x ต้องดึงได้จาก cold tier");
        assert_eq!(
            val,
            b"payload".to_vec(),
            "ข้อมูลต้องไม่สูญหายระหว่าง tier migration"
        );

        // promote กลับขึ้น hot
        memory.promote("x").expect("promote from cold ต้องสำเร็จ");
        let promoted = memory.get("x").expect("x หลัง promote");
        assert_eq!(promoted, b"payload".to_vec(), "ข้อมูลต้องครบหลัง promote");
    }

    #[test]
    fn promote_nonexistent_returns_not_found() {
        let memory = ContextMemoryManager::new();
        assert_eq!(memory.promote("ghost"), Err(ContextError::NotFound));
    }

    #[test]
    fn demote_nonexistent_returns_not_found() {
        let memory = ContextMemoryManager::new();
        assert_eq!(memory.demote("ghost"), Err(ContextError::NotFound));
    }

    #[test]
    fn tier_of_returns_none_for_missing_key() {
        let memory = ContextMemoryManager::new();
        assert_eq!(memory.tier_of("missing"), None);
    }

    #[test]
    fn promote_already_hot_is_noop() {
        let memory = ContextMemoryManager::new();
        memory.put("k", b"v".to_vec());
        assert_eq!(memory.tier_of("k"), Some("hot"));
        memory.promote("k").expect("promote hot เป็น no-op");
        assert_eq!(memory.tier_of("k"), Some("hot"));
        assert_eq!(memory.get("k").expect("k ยังอยู่"), b"v".to_vec());
    }
}
