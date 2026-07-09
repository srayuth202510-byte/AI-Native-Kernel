use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, instrument, warn};

// ── Tensor Types ──────────────────────────────────────────────────────────

/// ชนิดของข้อมูลใน Tensor (element type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TensorDtype {
    F32,
    F16,
    BF16,
    I8,
    I4,
    I32,
    U8,
}

impl TensorDtype {
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        match self {
            Self::F32 => 4,
            Self::F16 | Self::BF16 => 2,
            Self::I8 | Self::U8 => 1,
            Self::I4 => 1, // packed
            Self::I32 => 4,
        }
    }
}

/// อุปกรณ์ที่เก็บ Tensor อยู่
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TensorDevice {
    /// System RAM (CPU memory)
    Cpu,
    /// NVIDIA GPU (CUDA)
    Cuda,
    /// AMD GPU (ROCm)
    Rocm,
    /// Intel NPU (OpenVINO)
    IntelNpu,
    /// Qualcomm Hexagon NPU (QNN)
    QualcommNpu,
    /// Apple Neural Engine / MPS
    AppleMps,
}

impl TensorDevice {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
            Self::Rocm => "rocm",
            Self::IntelNpu => "intel_npu",
            Self::QualcommNpu => "qnn_npu",
            Self::AppleMps => "apple_mps",
        }
    }
}

/// ข้อมูลเมตาของ Tensor สำหรับติดตามขนาดและตำแหน่งที่ตั้ง
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TensorMetadata {
    /// ขนาดแต่ละมิติของ tensor (shape)
    pub shape: Vec<usize>,
    /// ชนิดข้อมูล (element type)
    pub dtype: TensorDtype,
    /// อุปกรณ์ที่เก็บ tensor
    pub device: TensorDevice,
    /// Device pointer (ที่อยู่หน่วยความจำบน GPU/NPU) เป็น u64 สำหรับ cross-platform
    pub device_ptr: Option<u64>,
    /// ขนาด tensor ในหน่วยไบต์ (ของ raw data)
    pub size_bytes: usize,
    /// จำนวนครั้งที่มีการเรียกใช้ (สำหรับ frequency-aware eviction)
    pub access_count: u64,
}

impl TensorMetadata {
    /// สร้าง TensorMetadata ใหม่
    #[must_use]
    pub fn new(shape: Vec<usize>, dtype: TensorDtype, device: TensorDevice) -> Self {
        let size_bytes = shape.iter().product::<usize>() * dtype.size_bytes();
        Self {
            shape,
            dtype,
            device,
            device_ptr: None,
            size_bytes,
            access_count: 0,
        }
    }

    /// คำนวณจำนวนไบต์ทั้งหมดของ tensor
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.size_bytes
    }

    /// จำนวนมิติ
    #[must_use]
    pub fn ndim(&self) -> usize {
        self.shape.len()
    }

    /// จำนวน elements ทั้งหมด
    #[must_use]
    pub fn num_elements(&self) -> usize {
        self.shape.iter().product()
    }
}

// ── KV Cache Page (existing) ──────────────────────────────────────────────

/// โครงสร้างแทนข้อมูล KV Cache ของโมเดล AI (เช่น LLM)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct KvCachePage {
    pub sequence_id: String,
    pub num_tokens: usize,
    pub num_layers: usize,
    pub num_heads: usize,
    pub head_dim: usize,
    pub element_size_bytes: usize,
    pub data: Vec<u8>,
}

impl KvCachePage {
    #[must_use]
    pub fn new(
        sequence_id: String,
        num_tokens: usize,
        num_layers: usize,
        num_heads: usize,
        head_dim: usize,
        element_size_bytes: usize,
    ) -> Self {
        let size = 2 * num_layers * num_heads * num_tokens * head_dim * element_size_bytes;
        Self {
            sequence_id,
            num_tokens,
            num_layers,
            num_heads,
            head_dim,
            element_size_bytes,
            data: vec![0xABu8; size],
        }
    }

    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

// ── Device Memory Allocations ─────────────────────────────────────────────

/// ตัวแทนบล็อกหน่วยความจำบนอุปกรณ์ (GPU/NPU) ที่มีการจัดสรรจริง
/// ใช้สำหรับติดตามการจัดสรรหน่วยความจำระดับ low-level
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceMemoryBlock {
    /// ID ของบล็อก
    pub id: String,
    /// อุปกรณ์ที่บล็อกอยู่
    pub device: TensorDevice,
    /// ขนาดบล็อกในหน่วยไบต์
    pub size_bytes: usize,
    /// device pointer ของ CUDA/ROCm (ถ้ามี)
    pub device_ptr: Option<u64>,
    /// true ถ้าบล็อกนี้ถูกจัดสรรบนอุปกรณ์จริง (ไม่ใช่ software simulation)
    pub is_pinned: bool,
}

impl DeviceMemoryBlock {
    #[must_use]
    pub fn new(id: String, device: TensorDevice, size_bytes: usize) -> Self {
        Self {
            id,
            device,
            size_bytes,
            device_ptr: None,
            is_pinned: false,
        }
    }
}

// ── VRAM Store (existing) ─────────────────────────────────────────────────

/// Callback ที่เรียกเมื่อมีการถอดถอนข้อมูลจาก VRAM
/// ใช้สำหรับย้ายข้อมูลไปยัง Hot Tier (RAM) ก่อนสูญหาย
pub type OnEvictCallback = Arc<dyn Fn(&str, &[u8], Option<&TensorMetadata>) + Send + Sync>;

/// สถิติการใช้งาน VRAM Store ( getCounts)
#[derive(Debug, Default)]
pub struct VramMetrics {
    pub inserts: AtomicU64,
    pub gets: AtomicU64,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub removes: AtomicU64,
}

impl VramMetrics {
    #[must_use]
    pub fn snapshot(&self) -> VramMetricsSnapshot {
        VramMetricsSnapshot {
            inserts: self.inserts.load(Ordering::Relaxed),
            gets: self.gets.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            removes: self.removes.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot ของสถิติ (Copy-friendly)
#[derive(Debug, Clone, Copy, Default)]
pub struct VramMetricsSnapshot {
    pub inserts: u64,
    pub gets: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub removes: u64,
}

impl VramMetricsSnapshot {
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.gets == 0 {
            0.0
        } else {
            self.hits as f64 / self.gets as f64
        }
    }
}

/// พื้นที่เก็บข้อมูล VRAM สำหรับ GPU/NPU context pages
/// ใช้ LRU eviction แบบ VecDeque (O(1) front removal)
#[derive(Clone)]
pub struct VramStore {
    buffers: HashMap<String, Vec<u8>>,
    /// จัดเก็บ metadata คู่กับข้อมูลแต่ละชิ้น
    metadata: HashMap<String, TensorMetadata>,
    total_capacity: usize,
    allocated_bytes: usize,
    /// LRU access order: back = most recent, front = least recent
    access_order: VecDeque<String>,
    metrics: Arc<VramMetrics>,
    on_evict: Option<OnEvictCallback>,
}

impl std::fmt::Debug for VramStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VramStore")
            .field("total_capacity", &self.total_capacity)
            .field("allocated_bytes", &self.allocated_bytes)
            .field("entries", &self.buffers.len())
            .field("with_metadata", &self.metadata.len())
            .field("metrics", &self.metrics.snapshot())
            .finish()
    }
}

impl VramStore {
    /// สร้าง VramStore ใหม่พร้อมขนาดความจุสูงสุด
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            metadata: HashMap::new(),
            total_capacity: capacity_bytes,
            allocated_bytes: 0,
            access_order: VecDeque::new(),
            metrics: Arc::new(VramMetrics::default()),
            on_evict: None,
        }
    }

    /// สร้าง VramStore พร้อม callback สำหรับย้ายข้อมูลเมื่อถูกถอดถอน
    #[must_use]
    pub fn with_evict_callback(capacity_bytes: usize, on_evict: OnEvictCallback) -> Self {
        Self {
            buffers: HashMap::new(),
            metadata: HashMap::new(),
            total_capacity: capacity_bytes,
            allocated_bytes: 0,
            access_order: VecDeque::new(),
            metrics: Arc::new(VramMetrics::default()),
            on_evict: Some(on_evict),
        }
    }

    /// คืน reference ไปยัง metrics
    #[must_use]
    pub fn metrics(&self) -> &Arc<VramMetrics> {
        &self.metrics
    }

    /// ตรวจสอบว่ามีข้อมูลคีย์นี้อยู่ใน VRAM หรือไม่
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.buffers.contains_key(key)
    }

    /// ดึงข้อมูลจาก VRAM พร้อมอัปเดตสถานะ LRU
    #[instrument(skip(self), fields(key = %key))]
    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        self.metrics.gets.fetch_add(1, Ordering::Relaxed);

        if self.buffers.contains_key(key) {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
            self.touch(key);
            if let Some(ref mut meta) = self.metadata.get_mut(key) {
                meta.access_count = meta.access_count.saturating_add(1);
            }
            debug!(key = key, "VRAM cache hit");
            self.buffers.get(key).cloned()
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            debug!(key = key, "VRAM cache miss");
            None
        }
    }

    /// ดึง metadata ของ key พร้อมอัปเดต access_count
    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&TensorMetadata> {
        self.metadata.get(key)
    }

    /// ดึง mutable reference ไปยัง metadata
    /// ใช้สำหรับอัปเดต device_ptr หรือข้อมูลอื่น ๆ
    #[must_use]
    pub fn get_metadata_mut(&mut self, key: &str) -> Option<&mut TensorMetadata> {
        self.metadata.get_mut(key)
    }

    /// บันทึกข้อมูลบริบทลง VRAM
    /// หาก VRAM เต็ม จะทำการถอดถอน (Evict) ข้อมูล LRU หลายตัวจนกว่าจะมีเนื้อที่เพียงพอ
    /// คืนค่ารายการข้อมูลที่ถูกถอดถอนทั้งหมด
    #[instrument(skip(self, value), fields(key = %key, value_len = value.len()))]
    pub fn insert(&mut self, key: String, value: Vec<u8>) -> Vec<(String, Vec<u8>)> {
        self.insert_with_metadata(key, value, None)
    }

    /// บันทึกข้อมูลพร้อม TensorMetadata
    /// หาก VRAM เต็ม จะทำการถอดถอน (Evict) ข้อมูล LRU หลายตัวจนกว่าจะมีเนื้อที่เพียงพอ
    #[instrument(skip(self, value), fields(key = %key, value_len = value.len()))]
    pub fn insert_with_metadata(
        &mut self,
        key: String,
        value: Vec<u8>,
        tensor_meta: Option<TensorMetadata>,
    ) -> Vec<(String, Vec<u8>)> {
        let value_len = value.len();
        let mut evicted = Vec::new();

        // หักลบขนาดเดิมออกหากคีย์มีอยู่แล้ว
        if let Some(old_val) = self.buffers.remove(&key) {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(old_val.len());
            self.access_order.retain(|k| k != &key);
            self.metadata.remove(&key);
        }

        // ถอดถอน LRU หลายตัวจนกว่าจะมีเนื้อที่เพียงพอ
        while self.allocated_bytes + value_len > self.total_capacity
            && !self.access_order.is_empty()
        {
            let Some(oldest_key) = self.access_order.pop_front() else {
                break;
            };
            if let Some(oldest_val) = self.buffers.remove(&oldest_key) {
                let oldest_meta = self.metadata.remove(&oldest_key);
                self.allocated_bytes = self.allocated_bytes.saturating_sub(oldest_val.len());
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);

                // เรียก callback เพื่อย้ายข้อมูลไป Hot Tier
                if let Some(ref cb) = self.on_evict {
                    cb(&oldest_key, &oldest_val, oldest_meta.as_ref());
                }

                debug!(
                    evicted_key = %oldest_key,
                    evicted_size = oldest_val.len(),
                    remaining_capacity = self.total_capacity - self.allocated_bytes,
                    "VRAM evicted LRU entry"
                );
                evicted.push((oldest_key, oldest_val));
            }
        }

        if let Some(meta) = tensor_meta {
            self.metadata.insert(key.clone(), meta);
        }
        self.allocated_bytes += value_len;
        self.buffers.insert(key.clone(), value);
        self.access_order.push_back(key);
        self.metrics.inserts.fetch_add(1, Ordering::Relaxed);

        evicted
    }

    /// ลบข้อมูลออกจาก VRAM และคืนค่าพื้นที่หน่วยความจำ
    /// คืนค่า (data, metadata_optional)
    pub fn remove(&mut self, key: &str) -> Option<(Vec<u8>, Option<TensorMetadata>)> {
        if let Some(val) = self.buffers.remove(key) {
            let meta = self.metadata.remove(key);
            self.allocated_bytes = self.allocated_bytes.saturating_sub(val.len());
            self.access_order.retain(|k| k != key);
            self.metrics.removes.fetch_add(1, Ordering::Relaxed);
            Some((val, meta))
        } else {
            None
        }
    }

    /// ลบเฉพาะข้อมูลโดยไม่สนใจ metadata (backwards-compatible)
    pub fn remove_data(&mut self, key: &str) -> Option<Vec<u8>> {
        self.remove(key).map(|(data, _)| data)
    }

    /// คืนค่าขนาดพื้นที่จัดเก็บรวม
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.total_capacity
    }

    /// คืนค่าขนาดพื้นที่ใช้งานปัจจุบัน
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    /// คืนค่าพื้นที่ว่างคงเหลือ
    #[must_use]
    pub fn free_bytes(&self) -> usize {
        self.total_capacity.saturating_sub(self.allocated_bytes)
    }

    /// จำนวน entries ที่จัดเก็บอยู่
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// ตรวจสอบว่า VRAM ว่างหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// คืนรายชื่อคีย์ทั้งหมดใน VRAM (ไม่เรียงลำดับ)
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.buffers.keys().map(|s| s.as_str()).collect()
    }

    /// ล้างข้อมูลทั้งหมดออกจาก VRAM
    pub fn clear(&mut self) {
        self.buffers.clear();
        self.metadata.clear();
        self.access_order.clear();
        self.allocated_bytes = 0;
    }

    /// อัปเดตสถานะ LRU: ย้าย key ไปท้าย VecDeque (most recent)
    fn touch(&mut self, key: &str) {
        self.access_order.retain(|k| k != key);
        self.access_order.push_back(key.to_string());
    }
}

// ── TensorStore: high-level tensor paging over VramStore ──────────────────

/// คลาส wrapper รอบ VramStore สำหรับจัดการข้อมูลระดับ Tensor
/// รองรับ shape/dtype awareness, frequency-aware eviction, และ device tracking
#[derive(Clone)]
pub struct TensorStore {
    store: VramStore,
}

impl std::fmt::Debug for TensorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TensorStore")
            .field("store", &self.store)
            .finish()
    }
}

impl TensorStore {
    /// สร้าง TensorStore ใหม่ด้วยความจุที่กำหนด (ไบต์)
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            store: VramStore::new(capacity_bytes),
        }
    }

    /// วาง tensor ลงใน store ด้วย key
    /// shape: [dim1, dim2, ...], dtype: ชนิดข้อมูล
    /// คืนค่ารายการที่ถูก evict
    pub fn put_tensor(
        &mut self,
        key: String,
        data: Vec<u8>,
        shape: Vec<usize>,
        dtype: TensorDtype,
        device: TensorDevice,
    ) -> Vec<(String, Vec<u8>)> {
        let meta = TensorMetadata::new(shape, dtype, device);
        self.store.insert_with_metadata(key, data, Some(meta))
    }

    /// ดึง tensor raw data และ metadata
    pub fn get_tensor(&mut self, key: &str) -> Option<(Vec<u8>, TensorMetadata)> {
        let data = self.store.get(key)?;
        let meta = self.store.get_metadata(key).cloned()?;
        Some((data, meta))
    }

    /// ดึงเฉพาะ metadata (ไม่นับเป็นการ access)
    #[must_use]
    pub fn peek_metadata(&self, key: &str) -> Option<&TensorMetadata> {
        self.store.get_metadata(key)
    }

    /// ลบ tensor พร้อม metadata
    pub fn remove_tensor(&mut self, key: &str) -> Option<(Vec<u8>, Option<TensorMetadata>)> {
        self.store.remove(key)
    }

    /// ตรวจสอบว่ามี tensor นี้หรือไม่
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }

    /// จำนวน tensor ที่จัดเก็บ
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// ว่างหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// ขนาดที่ใช้งาน (ไบต์)
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.store.allocated_bytes()
    }

    /// ความจุทั้งหมด (ไบต์)
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.store.capacity()
    }

    /// พื้นที่ว่าง (ไบต์)
    #[must_use]
    pub fn free_bytes(&self) -> usize {
        self.store.free_bytes()
    }

    /// คืนค่า raw VramStore reference สำหรับ operation พิเศษ
    #[must_use]
    pub fn inner(&self) -> &VramStore {
        &self.store
    }

    /// คืนค่า raw VramStore mutable reference
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut VramStore {
        &mut self.store
    }

    /// ล้างข้อมูลทั้งหมด
    pub fn clear(&mut self) {
        self.store.clear();
    }

    /// Metrics snapshot
    #[must_use]
    pub fn metrics(&self) -> VramMetricsSnapshot {
        self.store.metrics().snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn vram_insert_and_get() {
        let mut vram = VramStore::new(1024);
        vram.insert("ctx-1".into(), vec![1, 2, 3, 4]);
        assert_eq!(vram.get("ctx-1"), Some(vec![1, 2, 3, 4]));
        assert_eq!(vram.allocated_bytes(), 4);
    }

    #[test]
    fn vram_evicts_lru_when_full() {
        let mut vram = VramStore::new(8);
        vram.insert("a".into(), vec![0; 4]);
        vram.insert("b".into(), vec![0; 4]);
        assert_eq!(vram.allocated_bytes(), 8);

        let evicted = vram.insert("c".into(), vec![0; 4]);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, "a");
        assert_eq!(vram.allocated_bytes(), 8);
        assert!(vram.get("a").is_none());
        assert!(vram.get("b").is_some());
        assert!(vram.get("c").is_some());
    }

    #[test]
    fn vram_batch_eviction() {
        let mut vram = VramStore::new(5);
        vram.insert("a".into(), vec![0; 2]);
        vram.insert("b".into(), vec![0; 2]);
        let evicted = vram.insert("c".into(), vec![0; 2]);
        assert!(!evicted.is_empty());
        assert_eq!(vram.allocated_bytes(), 4);
    }

    #[test]
    fn vram_lru_access_order() {
        let mut vram = VramStore::new(8);
        vram.insert("a".into(), vec![0; 4]);
        vram.insert("b".into(), vec![0; 4]);
        vram.get("a");
        let evicted = vram.insert("c".into(), vec![0; 4]);
        assert_eq!(evicted[0].0, "b");
        assert!(vram.get("a").is_some());
        assert!(vram.get("b").is_none());
    }

    #[test]
    fn vram_remove_returns_value() {
        let mut vram = VramStore::new(1024);
        vram.insert("x".into(), vec![10, 20]);
        let removed = vram.remove_data("x");
        assert_eq!(removed, Some(vec![10, 20]));
        assert_eq!(vram.allocated_bytes(), 0);
    }

    #[test]
    fn vram_metrics_tracking() {
        let mut vram = VramStore::new(8);
        vram.insert("a".into(), vec![0; 4]);
        vram.get("a");
        vram.get("a");
        vram.get("missing");

        let m = vram.metrics().snapshot();
        assert_eq!(m.inserts, 1);
        assert_eq!(m.gets, 3);
        assert_eq!(m.hits, 2);
        assert_eq!(m.misses, 1);
        assert!((m.hit_rate() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn vram_evict_callback_called() {
        let evicted_keys = Arc::new(AtomicUsize::new(0));
        let evicted_keys_clone = evicted_keys.clone();

        let mut vram = VramStore::with_evict_callback(
            8,
            Arc::new(
                move |_key: &str, _val: &[u8], _meta: Option<&TensorMetadata>| {
                    evicted_keys_clone.fetch_add(1, AtomicOrdering::Relaxed);
                },
            ),
        );

        vram.insert("a".into(), vec![0; 4]);
        vram.insert("b".into(), vec![0; 4]);
        vram.insert("c".into(), vec![0; 4]);

        assert_eq!(evicted_keys.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn vram_overwrite_same_key() {
        let mut vram = VramStore::new(8);
        vram.insert("a".into(), vec![1, 2]);
        vram.insert("a".into(), vec![3, 4, 5, 6]);
        assert_eq!(vram.get("a"), Some(vec![3, 4, 5, 6]));
        assert_eq!(vram.allocated_bytes(), 4);
    }

    #[test]
    fn vram_clear_resets_state() {
        let mut vram = VramStore::new(1024);
        vram.insert("a".into(), vec![0; 100]);
        vram.insert("b".into(), vec![0; 200]);
        vram.clear();
        assert_eq!(vram.len(), 0);
        assert_eq!(vram.allocated_bytes(), 0);
        assert!(vram.is_empty());
    }

    // ── TensorMetadata & TensorStore Tests ────────────────────────────────

    #[test]
    fn tensor_dtype_size() {
        assert_eq!(TensorDtype::F32.size_bytes(), 4);
        assert_eq!(TensorDtype::F16.size_bytes(), 2);
        assert_eq!(TensorDtype::BF16.size_bytes(), 2);
        assert_eq!(TensorDtype::I8.size_bytes(), 1);
        assert_eq!(TensorDtype::I4.size_bytes(), 1);
        assert_eq!(TensorDtype::I32.size_bytes(), 4);
        assert_eq!(TensorDtype::U8.size_bytes(), 1);
    }

    #[test]
    fn tensor_device_name() {
        assert_eq!(TensorDevice::Cuda.name(), "cuda");
        assert_eq!(TensorDevice::Rocm.name(), "rocm");
        assert_eq!(TensorDevice::IntelNpu.name(), "intel_npu");
    }

    #[test]
    fn tensor_metadata_computes_size() {
        let meta = TensorMetadata::new(vec![2, 3, 224, 224], TensorDtype::F32, TensorDevice::Cuda);
        assert_eq!(meta.size_bytes, 2 * 3 * 224 * 224 * 4);
        assert_eq!(meta.ndim(), 4);
        assert_eq!(meta.num_elements(), 2 * 3 * 224 * 224);
        assert_eq!(meta.access_count, 0);
    }

    #[test]
    fn tensor_store_put_and_get() {
        let mut ts = TensorStore::new(1 << 20);
        let data = vec![0u8; 64];
        ts.put_tensor(
            "w1".into(),
            data.clone(),
            vec![4, 4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );

        let (got_data, got_meta) = ts.get_tensor("w1").unwrap();
        assert_eq!(got_data, data);
        assert_eq!(got_meta.shape, vec![4, 4]);
        assert_eq!(got_meta.dtype, TensorDtype::F32);
        assert_eq!(got_meta.device, TensorDevice::Cuda);
    }

    #[test]
    fn tensor_store_eviction_with_metadata() {
        let mut ts = TensorStore::new(128);
        ts.put_tensor(
            "a".into(),
            vec![0; 64],
            vec![4, 4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );
        ts.put_tensor(
            "b".into(),
            vec![0; 64],
            vec![4, 4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );

        // insert c → evicts a
        let evicted = ts.put_tensor(
            "c".into(),
            vec![0; 64],
            vec![4, 4],
            TensorDtype::F16,
            TensorDevice::Rocm,
        );
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].0, "a");

        assert!(ts.contains("b"));
        assert!(ts.contains("c"));
        assert!(!ts.contains("a"));

        let meta_c = ts.peek_metadata("c").unwrap();
        assert_eq!(meta_c.dtype, TensorDtype::F16);
        assert_eq!(meta_c.device, TensorDevice::Rocm);
    }

    #[test]
    fn tensor_store_access_count_increments() {
        let mut ts = TensorStore::new(1 << 20);
        ts.put_tensor(
            "w1".into(),
            vec![0; 16],
            vec![4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );
        // access 3 times
        ts.get_tensor("w1").unwrap();
        ts.get_tensor("w1").unwrap();
        ts.get_tensor("w1").unwrap();

        let meta = ts.peek_metadata("w1").unwrap();
        assert_eq!(meta.access_count, 3);
    }

    #[test]
    fn tensor_store_remove() {
        let mut ts = TensorStore::new(1 << 20);
        ts.put_tensor(
            "x".into(),
            vec![1, 2, 3],
            vec![3],
            TensorDtype::U8,
            TensorDevice::Cpu,
        );
        let (data, meta) = ts.remove_tensor("x").unwrap();
        assert_eq!(data, vec![1, 2, 3]);
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().dtype, TensorDtype::U8);
        assert!(!ts.contains("x"));
    }

    #[test]
    fn tensor_store_metrics() {
        let mut ts = TensorStore::new(128);
        ts.put_tensor(
            "a".into(),
            vec![0; 64],
            vec![4, 4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );
        ts.put_tensor(
            "b".into(),
            vec![0; 64],
            vec![4, 4],
            TensorDtype::F32,
            TensorDevice::Cuda,
        );

        // miss
        ts.get_tensor("missing");

        let m = ts.metrics();
        assert_eq!(m.inserts, 2);
        assert_eq!(m.gets, 1);
        assert_eq!(m.misses, 1);
    }
}
