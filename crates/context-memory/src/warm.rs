use std::collections::{HashMap, VecDeque};

/// โครงสร้างข้อมูลสำหรับเก็บหน้าบริบทแบบชั่วคราว (Warm Store) บน NVMe หรือ RocksDB (จำลองด้วยหน่วยความจำ)
/// รองรับการคัดเอาข้อมูลเก่าออกไปยังพื้นที่ระดับ Cold Store เมื่อข้อมูลเกิดการล้น (Spill over)
#[derive(Debug, Default)]
pub struct WarmStore {
    /// ตาราง HashMap สำหรับเก็บคีย์และข้อมูลบริบท
    entries: HashMap<String, Vec<u8>>,
    /// คิวสองด้านสำหรับติดตามและจัดการคิวลำดับข้อมูลแบบ FIFO
    order: VecDeque<String>,
}

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
