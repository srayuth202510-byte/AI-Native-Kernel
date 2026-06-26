use std::collections::{HashMap, VecDeque};

/// โครงสร้างข้อมูลสำหรับเก็บหน้าบริบทแบบชั่วคราว (Warm Store)
///
/// **โหมดปกติ (default)**: จำลองด้วยหน่วยความจำ (HashMap) เหมาะสำหรับ CI และการทดสอบ
///
/// **โหมด RocksDB (`rocksdb-warm` feature)**: ใช้ RocksDB จริงบน NVMe
/// เปิดใช้งานด้วย `cargo build --features context-memory/rocksdb-warm`
/// เป้าหมาย: Cold→Warm load < 50ms P99 (ANK-012)
#[cfg(not(feature = "rocksdb-warm"))]
#[derive(Debug, Default)]
pub struct WarmStore {
    /// ตาราง HashMap สำหรับเก็บคีย์และข้อมูลบริบท (โหมดจำลอง)
    entries: HashMap<String, Vec<u8>>,
    /// คิวสองด้านสำหรับติดตามและจัดการคิวลำดับข้อมูลแบบ FIFO
    order: VecDeque<String>,
}

#[cfg(not(feature = "rocksdb-warm"))]
impl WarmStore {
    /// สร้างอินสแตนซ์ของ WarmStore ใหม่ที่มีค่าเริ่มต้นเป็นค่าว่าง
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ใส่ข้อมูลบริบทลงใน Warm Store
    pub fn insert(&mut self, key: String, value: Vec<u8>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value);
    }

    /// ดึงสำเนาข้อมูลบริบทตามคีย์ที่กำหนด (ถ้ามี)
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }

    /// ส่งคืนจำนวนข้อมูลบริบททั้งหมดที่จัดเก็บอยู่ในปัจจุบัน
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// ตรวจสอบว่า Warm Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// ลบและส่งคืนข้อมูลเก่าที่สุดตามลำดับ FIFO เพื่อย้ายไปยัง Cold Store
    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = self.order.pop_front()?;
        self.entries.remove(&key).map(|value| (key, value))
    }
}

// ---- โหมด RocksDB จริง (feature = "rocksdb-warm") ----
// ANK-012: Warm tier (NVMe): RocksDB store สำหรับ Phase 1 production
#[cfg(feature = "rocksdb-warm")]
pub struct WarmStore {
    /// การเชื่อมต่อกับฐานข้อมูล RocksDB บน NVMe สำหรับ Warm tier จริง
    db: std::sync::Arc<rocksdb::DB>,
    /// คิวติดตามลำดับข้อมูล FIFO สำหรับการ evict ข้อมูลเก่า
    order: std::sync::Mutex<VecDeque<String>>,
    /// นับจำนวนรายการเพื่อประเมิน len() โดยไม่ต้อง scan ทั้ง DB
    count: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "rocksdb-warm")]
impl WarmStore {
    /// สร้าง WarmStore ที่ใช้ RocksDB ในพาธชั่วคราว (สำหรับ testing)
    /// ใน production ควรระบุพาธ NVMe จริงผ่าน config
    #[must_use]
    pub fn new() -> Self {
        let path = std::env::temp_dir().join("ank-warm-store");
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        // เปิดใช้ compression เพื่อประหยัดพื้นที่บน NVMe
        opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
        let db = rocksdb::DB::open(&opts, path).expect("ไม่สามารถเปิด RocksDB warm store ได้");
        Self {
            db: std::sync::Arc::new(db),
            order: std::sync::Mutex::new(VecDeque::new()),
            count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// ใส่ข้อมูลบริบทลงใน RocksDB Warm Store
    pub fn insert(&mut self, key: String, value: Vec<u8>) {
        let is_new = self
            .db
            .get(key.as_bytes())
            .map(|v| v.is_none())
            .unwrap_or(true);
        self.db
            .put(key.as_bytes(), &value)
            .expect("RocksDB put ล้มเหลว");
        if is_new {
            let mut order = self.order.lock().expect("order lock poisoned");
            order.push_back(key);
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// ดึงข้อมูลบริบทจาก RocksDB ตามคีย์ที่กำหนด
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.db.get(key.as_bytes()).ok().flatten()
    }

    /// ส่งคืนจำนวนรายการโดยประมาณ (ใช้ atomic counter)
    #[must_use]
    pub fn len(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// ตรวจสอบว่า Warm Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// ลบและส่งคืนข้อมูลเก่าที่สุดตามลำดับ FIFO เพื่อย้ายไปยัง Cold Store
    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = {
            let mut order = self.order.lock().expect("order lock poisoned");
            order.pop_front()?
        };
        let value = self.db.get(key.as_bytes()).ok().flatten()?;
        self.db.delete(key.as_bytes()).ok();
        self.count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        Some((key, value))
    }
}
