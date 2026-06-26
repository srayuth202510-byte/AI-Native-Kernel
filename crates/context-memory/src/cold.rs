use std::collections::{HashMap, VecDeque};

/// โครงสร้างข้อมูลสำหรับเก็บหน้าบริบทแบบถาวร (Cold Store) บนดิสก์หรือไฟล์สำรองข้อมูล (จำลองด้วยหน่วยความจำ)
/// เป็นพื้นที่เก็บข้อมูลระดับสุดท้ายที่มีพื้นที่มากที่สุดแต่เข้าถึงช้าที่สุด
#[derive(Debug, Default)]
pub struct ColdStore {
    /// ตาราง HashMap สำหรับเก็บคีย์และข้อมูลบริบท
    entries: HashMap<String, Vec<u8>>,
    /// คิวสองด้านสำหรับติดตามและบันทึกลำดับของข้อมูลบริบทที่บันทึกเข้ามา
    order: VecDeque<String>,
}

impl ColdStore {
    /// สร้างอินสแตนซ์ของ ColdStore ใหม่ที่มีค่าเริ่มต้นเป็นค่าว่าง
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// ใส่ข้อมูลบริบทลงใน Cold Store
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

    /// ตรวจสอบว่า Cold Store ว่างเปล่าหรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
