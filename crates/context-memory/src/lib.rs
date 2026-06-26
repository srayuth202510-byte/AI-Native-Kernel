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
    /// สร้างอินสแตนซ์ของ ContextMemoryManager พร้อมกำหนดค่าความจุเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self {
            hot: Arc::new(std::sync::RwLock::new(HotStore::new())),
            warm: Arc::new(std::sync::RwLock::new(WarmStore::new())),
            cold: Arc::new(std::sync::RwLock::new(ColdStore::new())),
            hot_capacity: 256,
            warm_capacity: 1_024,
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
        // ทดสอบว่าการดึงข้อมูลด้วย key ที่ไม่เคยบันทึกต้องคืน ContextError::NotFound
        let memory = ContextMemoryManager::new();
        let result = memory.get("does-not-exist");
        assert_eq!(result, Err(ContextError::NotFound));
    }

    #[test]
    fn overwrite_updates_value_in_hot_store() {
        // ทดสอบว่าการ put ครั้งที่สองด้วย key เดิมจะเขียนทับค่าเดิม (upsert semantics)
        let memory = ContextMemoryManager::new();
        memory.put("ctx-2", b"original".to_vec());
        memory.put("ctx-2", b"updated".to_vec());

        let value = memory.get("ctx-2").expect("context should exist");
        assert_eq!(value, b"updated".to_vec());
    }

    #[test]
    fn multiple_keys_are_independent() {
        // ทดสอบว่า key หลายตัวไม่วนกัน แต่ละ key เก็บค่าเป็นอิสระ
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
        // ทดสอบว่าเมื่อเกิน hot_capacity (256) ข้อมูลเก่าจะถูกย้ายไป warm
        // และยังคงดึงข้อมูลได้ผ่าน get()
        let memory = ContextMemoryManager::new();

        // เพิ่มข้อมูลเกินความจุความจุ hot store (257 รายการ)
        let first_key = "evict-target-0".to_string();
        for i in 0..257usize {
            memory.put(format!("evict-target-{i}"), vec![i as u8]);
        }

        // key แรกที่ถูก evict ควรยังคงดึงได้ผ่าน warm/cold store
        let result = memory.get(&first_key);
        assert!(
            result.is_ok(),
            "ข้อมูลที่ถูก evict ควรยังคงดึงได้จาก warm/cold store"
        );
    }

    #[test]
    fn get_empty_byte_slice_is_valid() {
        // ทดสอบว่าการเก็บไบต์เปล่า (empty vec) ยังเป็นม่าใช้และดึงคืนได้ถูกต้อง
        let memory = ContextMemoryManager::new();
        memory.put("empty-ctx", vec![]);

        let value = memory.get("empty-ctx").expect("empty context should exist");
        assert_eq!(value, Vec::<u8>::new());
    }
}
