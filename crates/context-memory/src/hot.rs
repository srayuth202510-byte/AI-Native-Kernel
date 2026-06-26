use std::collections::{HashMap, VecDeque};

/// โครงสร้างข้อมูลสำหรับเก็บหน้าบริบทแบบด่วน (Hot Store) ในหน่วยความจำหลัก (RAM)
/// โดยใช้ FIFO (First-In, First-Out) เพื่อลบ/ย้ายข้อมูลเก่าสุดออกเมื่อความจุเต็ม
#[derive(Debug, Default)]
pub struct HotStore {
    /// ตาราง HashMap สำหรับเก็บคีย์และบริบท (เก็บในรูปไบต์เวกเตอร์ Vec<u8>)
    entries: HashMap<String, Vec<u8>>,
    /// คิวสองด้าน (Double-ended queue) สำหรับบันทึกลำดับการป้อนข้อมูลเพื่อใช้ในการไล่ข้อมูลเก่า (Eviction)
    order: VecDeque<String>,
}

impl HotStore {
    /// สร้างอินสแตนซ์ของ HotStore ใหม่ที่มีค่าเริ่มต้นเป็นค่าว่าง
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ใส่ข้อมูลบริบทลงใน Hot Store พร้อมทั้งบันทึกลำดับหากเป็นคีย์ใหม่
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

    /// ตรวจสอบว่า Hot Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// ลบและส่งคืนข้อมูลที่เก่าที่สุดตามลำดับ FIFO (ข้อมูลที่เพิ่มเข้ามาแรกสุด)
    /// เพื่อนำไปเก็บในระดับถัดไป (เช่น Warm Store)
    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = self.order.pop_front()?;
        self.entries.remove(&key).map(|value| (key, value))
    }
}
