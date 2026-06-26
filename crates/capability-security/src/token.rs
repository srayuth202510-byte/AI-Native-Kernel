use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

/// โทเค็นแสดงสิทธิ์ความสามารถ (Capability Token) สำหรับระบุสิทธิ์ ขอบเขต และอายุการใช้งานของตัวแทนหรือส่วนประกอบระบบ
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct CapabilityToken {
    /// รหัสระบุเฉพาะตัวของโทเค็นความสามารถ
    pub id: u64,
    /// ขอบเขตการทำงานของโทเค็น (เช่น ระดับโปรเซส เธรด หรือระดับสากล)
    pub scope: Scope,
    /// รายการความสามารถที่ได้รับอนุญาตให้เข้าถึงได้ (เช่น "read", "execute")
    #[zeroize(skip)]
    pub capabilities: Vec<String>,
    /// วันเวลาที่จะหมดอายุการใช้งานของโทเค็นนี้
    #[zeroize(skip)]
    pub expires_at: SystemTime,
    /// รหัสลับสำหรับยืนยันความถูกต้องของโทเค็นนี้ (จะเคลียร์ค่าในหน่วยความจำเมื่อเลิกใช้งานด้วย Zeroize)
    pub secret: [u8; 32],
}

impl CapabilityToken {
    /// สร้างโทเค็นความสามารถใหม่พร้อมทั้งกำหนดอายุการใช้งาน (TTL)
    #[must_use]
    pub fn new(
        id: u64,
        scope: Scope,
        capabilities: Vec<String>,
        ttl: Duration,
        secret: [u8; 32],
    ) -> Self {
        Self {
            id,
            scope,
            capabilities,
            expires_at: SystemTime::now() + ttl,
            secret,
        }
    }

    /// ตรวจสอบว่าโทเค็นนี้ยังมีอายุการใช้งานอยู่หรือไม่ (ยังไม่หมดอายุ)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        SystemTime::now() <= self.expires_at
    }

    /// ตรวจสอบว่าโทเค็นนี้อนุญาตให้ดำเนิน Capability ที่ระบุหรือไม่
    #[must_use]
    pub fn allows(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }
}

/// ขอบเขตในการบังคับใช้สิทธิ์ของโทเค็นความสามารถ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum Scope {
    /// ขอบเขตระดับโปรเซส (Process-level) พร้อมระบุ PID
    Process(u32),
    /// ขอบเขตระดับเธรด (Thread-level) พร้อมระบุ TID
    Thread(u32),
    /// ขอบเขตระดับสากล (Global-level) ครอบคลุมทั่วทั้งระบบ
    Global,
}
