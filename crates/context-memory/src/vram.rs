use std::collections::HashMap;

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
            data: vec![0xABu8; size], // simulated initial values
        }
    }

    #[must_use]
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

/// พื้นที่เก็บข้อมูลกราฟิกจำลอง (VRAM Store) สำหรับ GPU/NPU context pages
#[derive(Debug, Clone)]
pub struct VramStore {
    /// ข้อมูลที่จัดเก็บใน VRAM จำลอง
    buffers: HashMap<String, Vec<u8>>,
    /// ขนาดความจุ VRAM สูงสุดในหน่วยไบต์
    total_capacity: usize,
    /// ขนาด VRAM ที่ถูกใช้ไปในปัจจุบัน (ไบต์)
    allocated_bytes: usize,
    /// ลำดับการใช้งานล่าสุด (LRU) สำหรับถอดถอนข้อมูลเมื่อเต็ม
    access_order: Vec<String>,
}

impl VramStore {
    /// สร้างอินสแตนซ์ VramStore ใหม่พร้อมขนาดความจุสูงสุด
    #[must_use]
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            total_capacity: capacity_bytes,
            allocated_bytes: 0,
            access_order: Vec::new(),
        }
    }

    /// ตรวจสอบว่ามีข้อมูลคีย์นี้อยู่ใน VRAM หรือไม่
    pub fn contains_key(&self, key: &str) -> bool {
        self.buffers.contains_key(key)
    }

    /// ดึงข้อมูลจาก VRAM พร้อมอัปเดตสถานะ LRU
    pub fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        if self.buffers.contains_key(key) {
            self.update_access(key);
            self.buffers.get(key).cloned()
        } else {
            None
        }
    }

    /// บันทึกข้อมูลบริบทลง VRAM
    /// หาก VRAM เต็ม จะทำการถอดถอน (Evict) ข้อมูลเก่าที่สุดออก และคืนค่าข้อมูลที่ถูกถอดถอนออกไป
    pub fn insert(&mut self, key: String, value: Vec<u8>) -> Option<(String, Vec<u8>)> {
        let value_len = value.len();

        // หากคีย์เดิมมีอยู่ ให้หักลบขนาดเดิมออกก่อน
        if let Some(old_val) = self.buffers.remove(&key) {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(old_val.len());
            self.access_order.retain(|k| k != &key);
        }

        let mut evicted = None;

        // วนลูปถอดถอนข้อมูลแบบ LRU จนกว่าจะมีเนื้อที่เพียงพอ
        while self.allocated_bytes + value_len > self.total_capacity
            && !self.access_order.is_empty()
        {
            let oldest_key = self.access_order.remove(0);
            if let Some(oldest_val) = self.buffers.remove(&oldest_key) {
                self.allocated_bytes = self.allocated_bytes.saturating_sub(oldest_val.len());
                evicted = Some((oldest_key, oldest_val));
                break; // สำหรับบริบทจำลอง ถอนตัวเดียวออกเพื่อให้มีเนื้อที่
            }
        }

        self.allocated_bytes += value_len;
        self.buffers.insert(key.clone(), value);
        self.access_order.push(key);

        evicted
    }

    /// ลบข้อมูลออกจาก VRAM และคืนค่าพื้นที่หน่วยความจำ
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        if let Some(val) = self.buffers.remove(key) {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(val.len());
            self.access_order.retain(|k| k != key);
            Some(val)
        } else {
            None
        }
    }

    /// คืนค่าขนาดพื้นที่จัดเก็บรวม
    pub fn capacity(&self) -> usize {
        self.total_capacity
    }

    /// คืนค่าขนาดพื้นที่ใช้งานปัจจุบัน
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    /// อัปเดตสถานะ LRU ให้แก่คีย์ที่เพิ่งเรียกใช้
    fn update_access(&mut self, key: &str) {
        self.access_order.retain(|k| k != key);
        self.access_order.push(key.to_string());
    }
}
