#![deny(unsafe_code)]

//! ระบบจัดการหน่วยความจำบริบท (Context Memory Manager)
//! รองรับการจัดเก็บข้อมูลแบบลำดับชั้น (Hierarchical Paging) ตั้งแต่ Hot, Warm ไปจนถึง Cold Store

/// Cold tier — ไฟล์บนดิสก์สำหรับข้อมูลที่นานๆ ใช้ที
pub mod cold;
/// Semantic File System — ค้นหาไฟล์เชิงความหมาย
pub mod fs;
/// Hot tier — เก็บใน RAM สำหรับข้อมูลที่ใช้บ่อยที่สุด
pub mod hot;
pub mod indexer;
/// P2P mesh สำหรับ replicate context ข้ามเครื่อง
pub mod p2p_mesh;
/// Vector store + semantic embedding ของ context
pub mod semantic;
/// SWIM failure detector สำหรับตรวจ node ล้มเหลวใน mesh
pub mod swim;
/// VRAM tier — tensor/KV cache บน GPU/NPU
pub mod vram;
/// Warm tier — NVMe (RocksDB ผ่าน feature flag) สำหรับข้อมูลรองจาก Hot
pub mod warm;

use crate::cold::ColdStore;
use crate::hot::HotStore;
use crate::p2p_mesh::P2PMeshManager;
pub use crate::vram::{
    DeviceMemoryBlock, KvCachePage, TensorDevice, TensorDtype, TensorMetadata, TensorStore,
    VramMetrics, VramMetricsSnapshot, VramStore,
};
use crate::warm::WarmStore;
pub use fs::{SemanticFile, SemanticFileSystem};
pub use indexer::{
    FileChange, IncrementalIndexer, IndexManifestEntry, IndexerEvent, ManifestStore,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, instrument, warn};

/// ข้อผิดพลาดที่เกี่ยวข้องกับระบบจัดการหน่วยความจำบริบท
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    /// ไม่พบหน้าบริบท (Context Page) ที่ต้องการในระบบเก็บข้อมูล
    #[error("context page not found")]
    NotFound,
    /// VRAM Store เต็ม ไม่สามารถจัดสรรพื้นที่เพิ่มได้
    #[error("VRAM store is full or above capacity")]
    VramFull,
}

/// ผลลัพธ์แบบ Custom Result สำหรับ Context Memory
pub type Result<T> = core::result::Result<T, ContextError>;

/// ตัวจัดการหน่วยความจำบริบทที่แบ่งลำดับชั้นของข้อมูล (VRAM -> Hot -> Warm -> Cold)
/// เพื่อประสิทธิภาพสูงสุดในการดึงข้อมูลและประหยัดการใช้ RAM
pub struct ContextMemoryManager {
    /// พื้นที่เก็บข้อมูลกราฟิกจำลอง (VRAM Store) สำหรับ GPU/NPU
    vram: Arc<RwLock<VramStore>>,
    /// พื้นที่เก็บข้อมูลด่วน (Hot Store) ใน RAM เข้าถึงได้เร็วที่สุด
    hot: Arc<RwLock<HotStore>>,
    /// พื้นที่เก็บข้อมูลชั่วคราว (Warm Store) บน RocksDB หรือ NVMe
    warm: Arc<RwLock<WarmStore>>,
    /// พื้นที่เก็บข้อมูลถาวร (Cold Store) บนฮาร์ดดิสก์/ไฟล์สำรอง
    cold: Arc<RwLock<ColdStore>>,
    /// ขนาดความจุสูงสุดของ VRAM Store ในหน่วยไบต์
    vram_capacity_bytes: usize,
    /// ขนาดความจุสูงสุดของ Hot Store ก่อนที่จะถูกย้ายไปยัง Warm Store
    hot_capacity: usize,
    /// ขนาดความจุสูงสุดของ Warm Store ก่อนที่จะถูกย้ายไปยัง Cold Store
    warm_capacity: usize,
    /// บันทึกเวลาในการป้อนข้อมูล (สำหรับ GC / TTL-based clean)
    timestamps: RwLock<HashMap<String, Instant>>,
    /// P2P mesh integration สำหรับ distributed context sync/fetch
    mesh: RwLock<Option<Arc<P2PMeshManager>>>,
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
        Self::with_vram_and_capacity(32 * 1024 * 1024, hot_capacity, warm_capacity)
    }

    /// สร้าง ContextMemoryManager ด้วยค่าความจุ VRAM และ RAM/RocksDB ที่กำหนดเอง
    #[must_use]
    pub fn with_vram_and_capacity(
        vram_capacity_bytes: usize,
        hot_capacity: usize,
        warm_capacity: usize,
    ) -> Self {
        Self::with_vram_path_and_capacity(vram_capacity_bytes, hot_capacity, warm_capacity, None)
    }

    /// สร้าง ContextMemoryManager ด้วยค่าความจุ VRAM, RAM/RocksDB และพาธจัดเก็บ NVMe/RocksDB ที่กำหนดเอง
    #[must_use]
    pub fn with_vram_path_and_capacity(
        vram_capacity_bytes: usize,
        hot_capacity: usize,
        warm_capacity: usize,
        warm_store_path: Option<std::path::PathBuf>,
    ) -> Self {
        let warm_store = {
            #[cfg(feature = "rocksdb-warm")]
            {
                if let Some(path) = warm_store_path {
                    WarmStore::new_with_path(path)
                } else {
                    WarmStore::new()
                }
            }
            #[cfg(not(feature = "rocksdb-warm"))]
            {
                let _ = warm_store_path;
                WarmStore::new()
            }
        };

        Self {
            vram: Arc::new(RwLock::new(VramStore::new(vram_capacity_bytes))),
            hot: Arc::new(RwLock::new(HotStore::new())),
            warm: Arc::new(RwLock::new(warm_store)),
            cold: Arc::new(RwLock::new(ColdStore::new())),
            vram_capacity_bytes,
            hot_capacity,
            warm_capacity,
            timestamps: RwLock::new(HashMap::new()),
            mesh: RwLock::new(None),
        }
    }

    /// บันทึกข้อมูลบริบทลงในระบบเก็บข้อมูล โดยเริ่มจาก Hot Store ก่อน
    /// หากข้อมูลใน Hot Store เกินขนาดความจุ จะย้ายข้อมูลเก่าสุดไปยัง Warm Store
    /// และหากข้อมูลใน Warm Store เกินขนาดความจุ ก็จะย้ายข้อมูลเก่าสุดไปยัง Cold Store
    #[instrument(skip(self, value), fields(key = %key.as_ref(), value_len = value.len()))]
    pub fn put(&self, key: impl Into<String> + AsRef<str>, value: Vec<u8>) {
        let key = key.into();
        debug!(tier = "hot", "บันทึกข้อมูลบริบทลง Hot Store");
        let mut hot = self.hot.write();
        let is_new = !hot.contains_key(&key);
        if is_new {
            drop(hot);
            self.timestamps.write().insert(key.clone(), Instant::now());
            hot = self.hot.write();
        }
        hot.insert(key, value);

        // ตรวจสอบขนาดเพื่อย้ายข้อมูล (Evict) ไปยัง Warm Store
        if hot.len() > self.hot_capacity {
            let evicted = hot.evict_oldest();
            drop(hot); // ปลดล็อก hot write lock ก่อนเขียนลง warm store เพื่อป้องกัน deadlock

            if let Some((evicted_key, evicted_value)) = evicted {
                warn!(tier = "warm", key = %evicted_key, "Hot Store เต็ม — ย้ายข้อมูลเก่าลง Warm Store");
                let mut warm = self.warm.write();
                warm.insert(evicted_key.clone(), evicted_value);

                // ตรวจสอบขนาดเพื่อย้ายข้อมูล (Evict) ไปยัง Cold Store
                if warm.len() > self.warm_capacity {
                    let spilled = warm.evict_oldest();
                    drop(warm); // ปลดล็อก warm write lock ก่อนเขียนลง cold store เพื่อป้องกัน deadlock

                    if let Some((spilled_key, spilled_value)) = spilled {
                        warn!(tier = "cold", key = %spilled_key, "Warm Store เต็ม — ย้ายข้อมูลเก่าลง Cold Store");
                        self.cold.write().insert(spilled_key, spilled_value);
                    }
                }
            }
        }
    }

    /// ดึงข้อมูลบริบทจากระบบเก็บข้อมูลตามลำดับชั้น
    /// โดยจะค้นหาใน VRAM Store ก่อน หากไม่พบจะค้นหาใน Hot Store (RAM), Warm Store และ Cold Store ตามลำดับ
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาด `ContextError::NotFound` หากไม่พบข้อมูลในระดับใดเลย
    #[instrument(skip(self), fields(key = %key))]
    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        // ค้นหาใน VRAM Store
        if let Some(value) = self.vram.write().get(key) {
            debug!(tier = "vram", "พบข้อมูลใน VRAM Store");
            return Ok(value);
        }

        // ค้นหาใน Hot Store (RAM)
        if let Some(value) = self.hot.read().get(key) {
            debug!(tier = "hot", "พบข้อมูลใน Hot Store");
            return Ok(value);
        }

        // ค้นหาใน Warm Store (RocksDB / NVMe)
        if let Some(value) = self.warm.read().get(key) {
            debug!(tier = "warm", "พบข้อมูลใน Warm Store");
            return Ok(value);
        }

        // ค้นหาใน Cold Store (Disk File)
        if let Some(value) = self.cold.read().get(key) {
            debug!(tier = "cold", "พบข้อมูลใน Cold Store");
            return Ok(value);
        }

        warn!("ไม่พบข้อมูลบริบทในทุก tier");
        Err(ContextError::NotFound)
    }

    /// ย้าย (Page) ข้อมูลบริบทไปยัง GPU/NPU VRAM Store
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ในทุกระดับ (RAM/Warm/Cold)
    #[instrument(skip(self), fields(key = %key))]
    pub fn page_to_vram(&self, key: &str) -> Result<()> {
        // หากอยู่ใน VRAM อยู่แล้ว — อัปเดต LRU และคืน Ok
        if self.vram.write().get(key).is_some() {
            debug!(tier = "vram", "ข้อมูลอยู่ใน VRAM อยู่แล้ว — no-op");
            return Ok(());
        }

        // ดึงข้อมูลจากระดับอื่น
        let value = self.get(key)?;

        // ลบข้อมูลออกจากระดับอื่นเพื่อป้องกันความซ้ำซ้อน
        self.hot.write().remove(key);
        self.warm.write().remove(key);
        self.cold.write().remove(key);

        // โหลดข้อมูลลง VRAM
        let evicted = self.vram.write().insert(key.to_string(), value);

        // หาก VRAM เต็มจนเกิดการถอดถอน (Evict) ข้อมูลเดิมออกมา ให้คัดถ่ายข้อมูลนั้นลง RAM
        for (evicted_key, evicted_value) in evicted {
            warn!(tier = "ram", key = %evicted_key, "VRAM เต็ม — คัดถ่ายข้อมูลเก่าลง RAM");
            self.put(evicted_key, evicted_value);
        }

        Ok(())
    }

    /// คัดถ่าย (Page/Demote) ข้อมูลบริบทจาก GPU/NPU VRAM Store ลงมายัง RAM
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบข้อมูลใน VRAM Store
    #[instrument(skip(self), fields(key = %key))]
    pub fn page_to_ram(&self, key: &str) -> Result<()> {
        if let Some((value, _meta)) = self.vram.write().remove(key) {
            debug!(tier = "vram->ram", "คัดถ่ายข้อมูลบริบทจาก VRAM ลง RAM");
            self.put(key.to_string(), value);
            Ok(())
        } else {
            warn!("ไม่พบข้อมูลใน VRAM");
            Err(ContextError::NotFound)
        }
    }

    /// ย้ายหน้า KV Cache จากหน่วยความจำหลักระบบไปยัง VRAM ของ GPU/NPU
    /// หาก VRAM เต็ม จะถอดถอนหน้าเก่าที่สุดตามลำดับ LRU กลับลงมายัง RAM และส่งคืนหน้านั้น
    #[instrument(skip(self, page), fields(sequence_id = %page.sequence_id, size = page.size_bytes()))]
    pub fn page_kv_to_vram(&self, page: KvCachePage) -> Result<Option<KvCachePage>> {
        let key = format!("kv_seq_{}", page.sequence_id);
        let value = serde_json::to_vec(&page).map_err(|_| ContextError::NotFound)?;

        // บันทึกเวลา
        self.timestamps.write().insert(key.clone(), Instant::now());

        // ใส่ข้อมูลใน VRAM
        let evicted = self.vram.write().insert(key, value);

        // หากมีการถอดถอนหน้า VRAM เดิมออกมา ให้ย้ายกลับลง RAM (Hot Tier)
        let mut evicted_page = None;
        for (evicted_key, evicted_value) in evicted {
            let page: KvCachePage =
                serde_json::from_slice(&evicted_value).map_err(|_| ContextError::NotFound)?;
            warn!(
                tier = "ram",
                key = %evicted_key,
                "VRAM เต็มในการโหลด KV cache — ถอดถอนหน้าเก่าลง RAM"
            );
            // บันทึกกลับลง Hot Store/RAM
            self.put(evicted_key, evicted_value);
            evicted_page = Some(page);
        }

        Ok(evicted_page)
    }

    /// ดึงหน้า KV Cache จาก VRAM กลับลงมายัง RAM
    #[instrument(skip(self), fields(sequence_id = %sequence_id))]
    pub fn page_kv_to_ram(&self, sequence_id: &str) -> Result<KvCachePage> {
        let key = format!("kv_seq_{}", sequence_id);
        if let Some((value, _meta)) = self.vram.write().remove(&key) {
            let page: KvCachePage =
                serde_json::from_slice(&value).map_err(|_| ContextError::NotFound)?;
            debug!(tier = "vram->ram", sequence_id = %sequence_id, "ดึงหน้า KV Cache กลับลง RAM");
            self.put(key, value);
            Ok(page)
        } else {
            warn!(sequence_id = %sequence_id, "ไม่พบหน้า KV Cache ใน VRAM");
            Err(ContextError::NotFound)
        }
    }

    /// ยกระดับ (Promote) ข้อมูลจาก Warm หรือ Cold tier กลับขึ้นสู่ Hot tier (RAM)
    ///
    /// ค้นหาใน Warm ก่อน ถ้าพบ → ลบออก → insert ใน Hot
    /// ถ้าไม่พบใน Warm → ค้นหาใน Cold → ลบออก → insert ใน Hot
    /// ถ้าข้อมูลอยู่ใน VRAM หรือ Hot อยู่แล้ว → no-op (คืน Ok)
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ในทุก tier
    #[instrument(skip(self), fields(key = %key))]
    pub fn promote(&self, key: &str) -> Result<()> {
        // ถ้าอยู่ใน VRAM หรือ Hot อยู่แล้ว — no-op
        if self.vram.read().contains_key(key) || self.hot.read().get(key).is_some() {
            debug!(tier = "vram/hot", "ข้อมูลอยู่ใน VRAM หรือ Hot อยู่แล้ว — no-op");
            return Ok(());
        }
        // ค้นหาและดึงออกจาก Warm
        let warm_value = self.warm.write().remove(key);
        if let Some(value) = warm_value {
            debug!(tier = "warm->hot", "ยกระดับข้อมูลจาก Warm ขึ้น Hot");
            self.put(key.to_string(), value);
            return Ok(());
        }
        // ค้นหาและดึงออกจาก Cold
        let cold_value = self.cold.write().remove(key);
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
        let hot_value = self.hot.write().remove(key);
        if let Some(value) = hot_value {
            debug!(tier = "hot->warm", "ลดระดับข้อมูลจาก Hot ลง Warm");
            self.warm.write().insert(key.to_string(), value);
            return Ok(());
        }
        warn!("demote ล้มเหลว — ไม่พบ key ใน Hot Store");
        Err(ContextError::NotFound)
    }

    /// คืนชื่อ tier ที่เก็บข้อมูล key นั้นอยู่ในปัจจุบัน
    /// ใช้สำหรับ debugging, testing และ observability
    ///
    /// คืน `Some("vram")`, `Some("hot")`, `Some("warm")`, `Some("cold")` หรือ `None`
    #[must_use]
    pub fn tier_of(&self, key: &str) -> Option<&'static str> {
        if self.vram.read().contains_key(key) {
            return Some("vram");
        }
        if self.hot.read().get(key).is_some() {
            return Some("hot");
        }
        if self.warm.read().get(key).is_some() {
            return Some("warm");
        }
        if self.cold.read().get(key).is_some() {
            return Some("cold");
        }
        None
    }

    /// คืนค่าขนาดความจุ VRAM สูงสุดในหน่วยไบต์
    #[must_use]
    pub fn vram_capacity(&self) -> usize {
        self.vram_capacity_bytes
    }

    /// คืนค่าขนาดพื้นที่ VRAM ที่ถูกใช้งานจริงในปัจจุบัน (ไบต์)
    #[must_use]
    pub fn vram_allocated(&self) -> usize {
        self.vram.read().allocated_bytes()
    }

    // ── Tensor-Aware Paging ──────────────────────────────────────────────

    /// ย้าย (Page) เทนเซอร์จาก RAM ไปยัง VRAM พร้อม metadata shape/dtype/device
    ///
    /// ค้นหาข้อมูลจาก Hot/Warm/Cold ก่อน ถ้าพบจะลบออกจาก tier นั้นและย้ายขึ้น VRAM
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ในทุกระดับ
    /// คืน `ContextError::VramFull` หาก VRAM เต็มและไม่สามารถจัดสรรพื้นที่ได้
    #[instrument(skip(self), fields(key = %key, shape = ?shape, dtype = ?dtype, device = ?device))]
    pub fn page_tensor_to_vram(
        &self,
        key: &str,
        shape: Vec<usize>,
        dtype: TensorDtype,
        device: TensorDevice,
    ) -> Result<Option<TensorMetadata>> {
        // ถ้าอยู่ใน VRAM อยู่แล้ว — อัปเดต metadata และคืน Ok
        if self.vram.read().contains_key(key) {
            if let Some(meta) = self.vram.write().get_metadata_mut(key) {
                meta.shape = shape;
                meta.dtype = dtype;
                meta.device = device;
                meta.size_bytes = meta.shape.iter().product::<usize>() * meta.dtype.size_bytes();
            }
            return Ok(None);
        }

        let value = self.get(key)?;

        // ลบข้อมูลออกจากระดับอื่นเพื่อป้องกันความซ้ำซ้อน
        self.hot.write().remove(key);
        self.warm.write().remove(key);
        self.cold.write().remove(key);

        // สร้าง metadata และบันทึก
        let meta = TensorMetadata::new(shape, dtype, device);
        let evicted =
            self.vram
                .write()
                .insert_with_metadata(key.to_string(), value, Some(meta.clone()));

        // หาก VRAM เต็มจนเกิดการถอดถอน อีวิคต์ลง RAM
        for (evicted_key, evicted_value) in evicted {
            warn!(tier = "ram", key = %evicted_key, "VRAM tensor store เต็ม — คัดถ่ายลง RAM");
            self.put(evicted_key, evicted_value);
        }

        Ok(None)
    }

    /// ดึงเทนเซอร์จาก VRAM กลับลงมายัง RAM
    ///
    /// # Errors
    /// คืน `ContextError::NotFound` หากไม่พบ key ใน VRAM
    pub fn page_tensor_to_ram(&self, key: &str) -> Result<(Vec<u8>, Option<TensorMetadata>)> {
        if let Some((value, meta)) = self.vram.write().remove(key) {
            debug!(tier = "vram->ram", key = %key, "คัดถ่ายเทนเซอร์จาก VRAM ลง RAM");
            self.put(key.to_string(), value.clone());
            Ok((value, meta))
        } else {
            warn!(key = %key, "ไม่พบเทนเซอร์ใน VRAM");
            Err(ContextError::NotFound)
        }
    }

    /// ดู metadata ของเทนเซอร์ใน VRAM (ไม่นับเป็นการ access)
    #[must_use]
    pub fn get_tensor_metadata(&self, key: &str) -> Option<TensorMetadata> {
        self.vram.read().get_metadata(key).cloned()
    }

    /// ดูจำนวนครั้งที่มีการเรียกใช้เทนเซอร์ใน VRAM
    #[must_use]
    pub fn get_tensor_access_count(&self, key: &str) -> u64 {
        self.vram
            .read()
            .get_metadata(key)
            .map(|m| m.access_count)
            .unwrap_or(0)
    }

    /// รายชื่อคีย์ทั้งหมดใน VRAM ที่มี tensor metadata
    #[must_use]
    pub fn list_tensor_keys(&self) -> Vec<String> {
        self.vram
            .read()
            .keys()
            .iter()
            .filter(|k| self.vram.read().get_metadata(k).is_some())
            .map(|k| k.to_string())
            .collect()
    }

    /// อัปเดต device pointer สำหรับเทนเซอร์ใน VRAM
    pub fn update_tensor_device_ptr(&self, key: &str, device_ptr: u64) {
        if let Some(meta) = self.vram.write().get_metadata_mut(key) {
            meta.device_ptr = Some(device_ptr);
        }
    }

    /// ขนาด VRAM ที่ถูกใช้งานโดยเทนเซอร์ทั้งหมด (ไบต์)
    #[must_use]
    pub fn tensor_allocated_bytes(&self) -> usize {
        self.vram.read().allocated_bytes()
    }

    /// ลบข้อมูลบริบทที่หมดอายุ (> ttl) ออกจากทุก tiers (VRAM, Hot, Warm, Cold)
    /// คืนจำนวนข้อมูลที่ถูกลบ
    #[instrument(skip(self), fields(ttl_ms = ttl.as_millis() as u64))]
    pub fn clean_expired(&self, ttl: std::time::Duration) -> u64 {
        let now = Instant::now();
        let timestamps = self.timestamps.read();
        let expired_keys: Vec<String> = timestamps
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        drop(timestamps);

        let count = expired_keys.len() as u64;
        if count == 0 {
            return 0;
        }

        let mut ts = self.timestamps.write();
        for key in &expired_keys {
            ts.remove(key);
            self.vram.write().remove(key);
            self.hot.write().remove(key);
            self.warm.write().remove(key);
            self.cold.write().remove(key);
        }

        debug!(count, "ContextMemory: cleaned expired entries");
        count
    }

    /// เชื่อม P2P mesh เข้ากับ memory manager เพื่อเปิดโหมด distributed
    pub fn attach_mesh(&self, mesh: Arc<P2PMeshManager>) {
        *self.mesh.write() = Some(mesh);
    }

    /// ตัดการเชื่อม mesh — กลับสู่โหมด local-only
    pub fn detach_mesh(&self) {
        *self.mesh.write() = None;
    }

    /// ตรวจว่าขณะนี้เชื่อม mesh อยู่หรือไม่
    #[must_use]
    pub fn mesh_enabled(&self) -> bool {
        self.mesh.read().is_some()
    }

    /// เขียนข้อมูลลง tier ฝั่งเรา แล้ว replicate ไปยังทุก node ใน mesh (ถ้าเชื่อมอยู่)
    pub async fn put_distributed(
        &self,
        key: impl Into<String> + AsRef<str>,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        let key = key.into();
        self.put(key.clone(), value.clone());

        let mesh = self.mesh.read().clone();
        if let Some(mesh) = mesh {
            mesh.sync_record(key, value).await?;
        }

        Ok(())
    }

    /// อ่านข้อมูล — ลอง tier ฝั่งเราก่อน ถ้าไม่พบจึงไปถาม node อื่นใน mesh
    pub async fn get_distributed(&self, key: &str) -> Result<Vec<u8>> {
        if let Ok(value) = self.get(key) {
            return Ok(value);
        }

        let mesh = self.mesh.read().clone();
        if let Some(mesh) = mesh {
            if let Some(value) = mesh.get_cached_record(key).await {
                self.put(key.to_string(), value.clone());
                return Ok(value);
            }

            if let Ok(Some(value)) = mesh.fetch_record(key).await {
                self.put(key.to_string(), value.clone());
                return Ok(value);
            }
        }

        warn!(key, "distributed context fetch failed");
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

    #[test]
    fn vram_paging_round_trip() {
        let memory = ContextMemoryManager::with_vram_and_capacity(100, 2, 2);
        memory.put("a", b"alpha".to_vec()); // 5 bytes
        assert_eq!(memory.tier_of("a"), Some("hot"));

        memory
            .page_to_vram("a")
            .expect("page to VRAM should succeed");
        assert_eq!(memory.tier_of("a"), Some("vram"));
        assert_eq!(memory.get("a").unwrap(), b"alpha".to_vec());

        memory.page_to_ram("a").expect("page to RAM should succeed");
        assert_eq!(memory.tier_of("a"), Some("hot"));
        assert_eq!(memory.get("a").unwrap(), b"alpha".to_vec());
    }

    #[test]
    fn vram_eviction_when_capacity_exceeded() {
        // VRAM capacity is 10 bytes
        let memory = ContextMemoryManager::with_vram_and_capacity(10, 2, 2);
        memory.put("a", b"123456".to_vec()); // 6 bytes
        memory.put("b", b"123456".to_vec()); // 6 bytes

        memory.page_to_vram("a").unwrap();
        assert_eq!(memory.tier_of("a"), Some("vram"));

        // a is 6 bytes. b is 6 bytes. Total = 12 bytes > 10 bytes capacity.
        // Paging b to VRAM will evict a from VRAM to RAM (hot).
        memory.page_to_vram("b").unwrap();
        assert_eq!(memory.tier_of("b"), Some("vram"));
        assert_eq!(memory.tier_of("a"), Some("hot"));

        assert_eq!(memory.get("a").unwrap(), b"123456".to_vec());
        assert_eq!(memory.get("b").unwrap(), b"123456".to_vec());
    }

    #[test]
    fn promote_on_vram_key_is_noop() {
        let memory = ContextMemoryManager::with_vram_and_capacity(100, 2, 2);
        memory.put("a", b"alpha".to_vec());
        memory.page_to_vram("a").unwrap();

        assert_eq!(memory.tier_of("a"), Some("vram"));
        memory.promote("a").expect("promote should be no-op");
        assert_eq!(memory.tier_of("a"), Some("vram"));
    }

    #[test]
    fn page_to_vram_nonexistent_returns_not_found() {
        let memory = ContextMemoryManager::new();
        assert_eq!(memory.page_to_vram("ghost"), Err(ContextError::NotFound));
    }

    #[test]
    fn page_to_ram_nonexistent_returns_not_found() {
        let memory = ContextMemoryManager::new();
        assert_eq!(memory.page_to_ram("ghost"), Err(ContextError::NotFound));
    }

    // ── Tensor-Aware Paging Tests ──────────────────────────────────────

    #[test]
    fn page_tensor_to_vram_and_get_metadata() {
        let memory = ContextMemoryManager::with_vram_and_capacity(1024, 2, 2);
        let data = vec![0u8; 64];
        memory.put("w", data.clone());
        assert_eq!(memory.tier_of("w"), Some("hot"));

        memory
            .page_tensor_to_vram("w", vec![4, 4, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();
        assert_eq!(memory.tier_of("w"), Some("vram"));

        let meta = memory.get_tensor_metadata("w").unwrap();
        assert_eq!(meta.shape, vec![4, 4, 4]);
        assert_eq!(meta.dtype, TensorDtype::F32);
        assert_eq!(meta.device, TensorDevice::Cuda);
        assert_eq!(meta.size_bytes, 4 * 4 * 4 * 4);
    }

    #[test]
    fn page_tensor_to_ram_returns_data_and_metadata() {
        let memory = ContextMemoryManager::with_vram_and_capacity(1024, 2, 2);
        memory.put("t", vec![1, 2, 3, 4]);
        memory
            .page_tensor_to_vram("t", vec![4], TensorDtype::U8, TensorDevice::Cpu)
            .unwrap();

        let (data, meta) = memory.page_tensor_to_ram("t").unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);
        let meta = meta.unwrap();
        assert_eq!(meta.shape, vec![4]);
        assert_eq!(meta.dtype, TensorDtype::U8);
        assert_eq!(memory.tier_of("t"), Some("hot"));
    }

    #[test]
    fn tensor_access_count_increments_on_get() {
        let memory = ContextMemoryManager::with_vram_and_capacity(1024, 2, 2);
        memory.put("freq", vec![0; 32]);
        memory
            .page_tensor_to_vram("freq", vec![8, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();

        // access 3 times via get
        memory.get("freq").unwrap();
        memory.get("freq").unwrap();
        memory.get("freq").unwrap();

        assert_eq!(memory.get_tensor_access_count("freq"), 3);
    }

    #[test]
    fn list_tensor_keys_filters_only_tensors() {
        let memory = ContextMemoryManager::with_vram_and_capacity(1024, 2, 2);
        memory.put("plain", vec![0; 16]);
        memory.put("tensor1", vec![0; 16]);
        memory.put("tensor2", vec![0; 16]);

        memory.page_to_vram("plain").unwrap();
        memory
            .page_tensor_to_vram("tensor1", vec![4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();
        memory
            .page_tensor_to_vram("tensor2", vec![4], TensorDtype::F16, TensorDevice::Rocm)
            .unwrap();

        let tensor_keys = memory.list_tensor_keys();
        assert!(tensor_keys.contains(&"tensor1".to_string()));
        assert!(tensor_keys.contains(&"tensor2".to_string()));
        assert!(!tensor_keys.contains(&"plain".to_string())); // no metadata
    }

    #[test]
    fn update_tensor_device_ptr_changes_metadata() {
        let memory = ContextMemoryManager::with_vram_and_capacity(1024, 2, 2);
        memory.put("ptr-test", vec![0; 64]);
        memory
            .page_tensor_to_vram("ptr-test", vec![4, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();

        memory.update_tensor_device_ptr("ptr-test", 0xDEAD_BEEF);
        let meta = memory.get_tensor_metadata("ptr-test").unwrap();
        assert_eq!(meta.device_ptr, Some(0xDEAD_BEEF));
    }

    #[test]
    fn page_tensor_nonexistent_returns_not_found() {
        let memory = ContextMemoryManager::new();
        let result =
            memory.page_tensor_to_vram("ghost", vec![1], TensorDtype::F32, TensorDevice::Cuda);
        assert_eq!(result, Err(ContextError::NotFound));
    }

    #[test]
    fn page_tensor_eviction_preserves_data() {
        // VRAM capacity = 80 bytes — holds only one 64-byte tensor at a time
        let memory = ContextMemoryManager::with_vram_and_capacity(80, 10, 10);

        let data = vec![0u8; 64];
        memory.put("a", data.clone());
        memory.put("b", data.clone());
        memory.put("c", data.clone());

        // Page "a": 1 entry, 64/80 bytes
        memory
            .page_tensor_to_vram("a", vec![4, 4, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();
        assert_eq!(memory.tier_of("a"), Some("vram"));

        // Page "b": evicts "a" from VRAM (128 > 80), "b" takes its place
        memory
            .page_tensor_to_vram("b", vec![4, 4, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();
        assert_eq!(memory.tier_of("b"), Some("vram"));
        assert_eq!(memory.tier_of("a"), Some("hot")); // evicted to RAM

        // Page "c": evicts "b" from VRAM, "c" takes its place
        memory
            .page_tensor_to_vram("c", vec![4, 4, 4], TensorDtype::F32, TensorDevice::Cuda)
            .unwrap();

        assert_eq!(memory.tier_of("c"), Some("vram"));
        assert_eq!(memory.tier_of("b"), Some("hot")); // evicted to RAM
        assert_eq!(memory.tier_of("a"), Some("hot")); // still in RAM
    }

    #[test]
    fn kv_cache_paging_and_eviction() {
        // Create memory manager with 100 bytes of VRAM capacity
        let memory = ContextMemoryManager::with_vram_and_capacity(100, 2, 2);

        // Create two pages of 60 bytes each (2 * 1 * 1 * 15 * 2 * 1 = 60 bytes)
        let page_a = KvCachePage::new("agent-a".to_string(), 15, 1, 1, 2, 1);
        let page_b = KvCachePage::new("agent-b".to_string(), 15, 1, 1, 2, 1);

        assert_eq!(page_a.size_bytes(), 60);

        // Page A to VRAM
        let evicted = memory.page_kv_to_vram(page_a.clone()).unwrap();
        assert!(evicted.is_none(), "no eviction should occur yet");
        assert_eq!(memory.tier_of("kv_seq_agent-a"), Some("vram"));

        // Page B to VRAM (causes A to evict because 60 + 60 = 120 > 100 capacity)
        let evicted = memory.page_kv_to_vram(page_b.clone()).unwrap();
        assert_eq!(evicted.unwrap().sequence_id, "agent-a");
        assert_eq!(memory.tier_of("kv_seq_agent-b"), Some("vram"));
        assert_eq!(memory.tier_of("kv_seq_agent-a"), Some("hot")); // Evicted to RAM

        // Pull B back from VRAM to RAM
        let page_b_back = memory.page_kv_to_ram("agent-b").unwrap();
        assert_eq!(page_b_back.sequence_id, "agent-b");
        assert_eq!(memory.tier_of("kv_seq_agent-b"), Some("hot"));
    }
}
