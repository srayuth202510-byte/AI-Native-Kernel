use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

/// โทเค็นแสดงสิทธิ์ความสามารถ (Capability Token) สำหรับระบุสิทธิ์ ขอบเขต และอายุการใช้งานของตัวแทนหรือส่วนประกอบระบบ
#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
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

// เปรียบเทียบ secret ด้วย constant-time เสมอ เพื่อไม่ให้เกิด timing side channel
// (derive(PartialEq) จะเทียบ [u8; 32] แบบ short-circuit ซึ่งขัดกับ security convention)
impl PartialEq for CapabilityToken {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.scope == other.scope
            && self.capabilities == other.capabilities
            && self.expires_at == other.expires_at
            && crate::constant_time_eq(&self.secret, &other.secret)
    }
}

impl Eq for CapabilityToken {}

/// ขอบเขตในการบังคับใช้สิทธิ์ของโทเค็นความสามารถ
#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash, Zeroize, Serialize, Deserialize)]
pub enum Scope {
    /// ขอบเขตระดับโปรเซส (Process-level) พร้อมระบุ PID
    Process(u32),
    /// ขอบเขตระดับเธรด (Thread-level) พร้อมระบุ TID
    Thread(u32),
    /// ขอบเขตระดับสากล (Global-level) ครอบคลุมทั่วทั้งระบบ
    Global,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_token_carries_expected_fields() {
        let secret = [0xAB; 32];
        let token = CapabilityToken::new(
            7,
            Scope::Process(42),
            vec!["read".to_string(), "execute".to_string()],
            Duration::from_secs(30),
            secret,
        );

        assert_eq!(token.id, 7);
        assert_eq!(token.scope, Scope::Process(42));
        assert_eq!(token.secret, secret);
        assert!(token.allows("read"));
        assert!(token.allows("execute"));
    }

    #[test]
    fn token_validity_tracks_expiration() {
        let valid = CapabilityToken::new(
            8,
            Scope::Global,
            vec!["read".to_string()],
            Duration::from_secs(1),
            [0x08; 32],
        );
        assert!(valid.is_valid());

        let expired = CapabilityToken {
            id: 9,
            scope: Scope::Thread(3),
            capabilities: vec!["read".to_string()],
            expires_at: SystemTime::now() - Duration::from_secs(1),
            secret: [0x09; 32],
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn allows_requires_exact_capability_match() {
        let token = CapabilityToken::new(
            10,
            Scope::Global,
            vec!["read".to_string()],
            Duration::from_secs(30),
            [0x10; 32],
        );

        assert!(token.allows("read"));
        assert!(!token.allows("write"));
        assert!(!token.allows("READ"));
    }

    #[test]
    fn token_json_round_trip_preserves_secret_and_scope() {
        let token = CapabilityToken::new(
            11,
            Scope::Thread(99),
            vec!["execute".to_string()],
            Duration::from_secs(30),
            [0x11; 32],
        );

        let json = serde_json::to_string(&token).expect("token serialization should succeed");
        let restored: CapabilityToken =
            serde_json::from_str(&json).expect("token deserialization should succeed");

        assert_eq!(restored.id, token.id);
        assert_eq!(restored.scope, token.scope);
        assert_eq!(restored.capabilities, token.capabilities);
        assert_eq!(restored.secret, token.secret);
    }
}
