#![deny(unsafe_code)]

pub mod audit;
pub mod metrics;
pub mod policy;
pub mod token;

pub use metrics::{SecurityMetrics, render_metrics};

use crate::audit::{AuditEntry, AuditLogger};
use crate::policy::{PolicyDecision, PolicyEngine};
pub use crate::token::{CapabilityToken, Scope};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, CapabilityError>;

/// ข้อผิดพลาดประเภทต่างๆ ที่เกี่ยวข้องกับการตรวจสอบและจัดการสิทธิ์การเข้าถึง (Capability)
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// การยืนยันความถูกต้องของโทเค็นล้มเหลว
    #[error("token validation failed")]
    TokenValidationFailed,
    /// การตัดสินใจตามนโยบายความปลอดภัยปฏิเสธการเข้าถึง
    #[error("policy decision denied")]
    PolicyDecisionDenied,
    /// การบันทึกประวัติการเข้าถึงและการทำงาน (Audit Log) ล้มเหลว
    #[error("audit write failed")]
    AuditWriteFailed,
    /// การขยายขอบเขตการเข้าถึง (Scope Expansion) ล้มเหลว
    #[error("scope expansion failed")]
    ScopeExpansionFailed,
    /// เกิดข้อผิดพลาดเนื่องจากโทเค็นหมดอายุ
    #[error("token expiration error")]
    ExpirationError,
}

/// ตัวจัดการความปลอดภัยอิงความสามารถ (Capability-based Security Manager)
/// ทำหน้าที่ควบคุมสิทธิ์ ออกโทเค็น ตรวจสอบสิทธิ์ และบันทึกประวัติความปลอดภัย
#[derive(Debug)]
pub struct CapabilitySecurityManager {
    /// ตารางเก็บโทเค็นความสามารถทั้งหมด มีการใช้ `RwLock` เพื่อให้สามารถใช้งานข้ามเธรดได้อย่างปลอดภัย
    tokens: RwLock<HashMap<u64, CapabilityToken>>,
    /// กลไกการประเมินนโยบายเพื่อตัดสินใจอนุญาตหรือปฏิเสธสิทธิ์
    policy_engine: PolicyEngine,
    /// ตัวบันทึกประวัติการตรวจสอบการทำงานและความปลอดภัย (Audit Logger)
    audit_logger: AuditLogger,
}

/// ฟังก์ชันเปรียบเทียบข้อมูลไบต์อาร์เรย์ขนาด 32 ไบต์แบบคงเวลา (Constant-time comparison)
/// เพื่อป้องกันการโจมตีประเภท Timing Attack เมื่อทำการเปรียบเทียบข้อมูลลับ (เช่น Token Secret Key)
#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

impl CapabilitySecurityManager {
    /// สร้างตัวจัดการความปลอดภัย `CapabilitySecurityManager` ใหม่ด้วยการตั้งค่าเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::default(),
        }
    }

    /// สร้างตัวจัดการความปลอดภัย `CapabilitySecurityManager` ใหม่พร้อมระบุพาธในการบันทึกไฟล์ประวัติการตรวจสอบ
    #[must_use]
    pub fn new_with_log_path(log_path: std::path::PathBuf) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::new(log_path),
        }
    }

    /// ออกโทเค็นความสามารถ (Capability Token) ใหม่ บันทึกลงในระบบเพื่อใช้งาน และบันทึกประวัติ (Audit Log)
    pub fn issue_token(&self, token: CapabilityToken) -> Result<()> {
        self.audit_logger
            .record(AuditEntry::issued(token.id))
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        self.tokens
            .write()
            .expect("capability tokens lock poisoned")
            .insert(token.id, token);
        Ok(())
    }

    /// ตรวจสอบสิทธิ์ของโทเค็นโดยอ้างอิงกับ Capability ที่ร้องขอ
    /// พร้อมทำบันทึกประวัติการอนุญาต (Allow) หรือปฏิเสธ (Deny) ลงไฟล์ประวัติการตรวจสอบ
    pub fn authorize_token(&self, token: &CapabilityToken, capability: &str) -> Result<bool> {
        let allowed = token.is_valid()
            && self
                .policy_engine
                .authorize(token, &token.scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger
            .record(entry)
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        Ok(allowed)
    }

    /// ยืนยันความถูกต้องของโทเค็นโดยระบุ ID, รหัสลับ (Secret Key), ขอบเขต (Scope) และ Capability ที่ต้องการ
    /// จะใช้วิธีเปรียบเทียบรหัสลับแบบคงเวลา (Constant-time comparison) เพื่อความปลอดภัยสูงสุด
    pub fn validate(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> Result<bool> {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            return Ok(false);
        };

        // ตรวจสอบความถูกต้องของรหัสลับ (Secret Key) แบบคงเวลาเพื่อป้องกัน Timing Attacks
        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            return Ok(false);
        }

        let allowed = token.is_valid() && self.policy_engine.authorize(token, scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger
            .record(entry)
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        Ok(allowed)
    }

    /// ตัดสินใจเชิงนโยบายความปลอดภัย (Policy Decision) สำหรับการเข้าถึงที่ร้องขอ
    /// คืนผลลัพธ์เป็น `PolicyDecision` (Allow หรือ Deny) พร้อมบันทึกประวัติลงไฟล์การตรวจสอบ
    pub fn decision_for(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> Result<PolicyDecision> {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            return Ok(PolicyDecision::Deny);
        };

        // เปรียบเทียบรหัสลับด้วยวิธีคงเวลาเพื่อป้องกัน Timing Attacks ในการถอดรหัสลับ/เปรียบเทียบโทเค็น
        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            return Ok(PolicyDecision::Deny);
        }

        let decision = self.policy_engine.decision(token, scope, capability);
        let entry = match decision {
            PolicyDecision::Allow => AuditEntry::allowed(token.id),
            PolicyDecision::Deny => AuditEntry::denied(token.id),
        };
        self.audit_logger
            .record(entry)
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        Ok(decision)
    }

    /// ดึงรายการประวัติการตรวจสอบการเข้าถึงทั้งหมดที่มีบันทึกไว้
    #[must_use]
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_logger.entries()
    }
}

impl Default for CapabilitySecurityManager {
    /// สร้างค่าเริ่มต้นสำหรับ `CapabilitySecurityManager`
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::PolicyDecision;
    use crate::token::{CapabilityToken, Scope};
    use crate::{CapabilityError, CapabilitySecurityManager};
    use std::time::{Duration, SystemTime};

    #[test]
    fn issue_and_validate_token() {
        let log_path = std::env::temp_dir().join("test_audit_1.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            1,
            Scope::Process(42),
            vec!["read".to_string()],
            Duration::from_secs(60),
            [9u8; 32],
        );

        manager
            .issue_token(token.clone())
            .expect("issue should succeed");

        assert!(
            manager
                .validate(1, &[9u8; 32], &Scope::Process(42), "read")
                .expect("validate should succeed")
        );
        assert!(
            manager
                .authorize_token(&token, "read")
                .expect("authorize should succeed")
        );
        assert_eq!(
            manager
                .decision_for(1, &[9u8; 32], &Scope::Process(42), "read")
                .expect("decision should succeed"),
            PolicyDecision::Allow
        );
        assert_eq!(manager.audit_entries().len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn rejects_expired_or_unauthorized_token() {
        let log_path = std::env::temp_dir().join("test_audit_2.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let expired = CapabilityToken {
            id: 2,
            scope: Scope::Thread(7),
            capabilities: vec!["write".to_string()],
            expires_at: SystemTime::now() - Duration::from_secs(1),
            secret: [8u8; 32],
        };

        manager
            .issue_token(expired.clone())
            .expect("issue should succeed");

        assert!(
            !manager
                .authorize_token(&expired, "write")
                .expect("authorize should succeed")
        );
        assert!(
            !manager
                .validate(2, &[8u8; 32], &Scope::Thread(7), "write")
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(2, &[8u8; 32], &Scope::Thread(7), "write")
                .expect("decision should succeed"),
            PolicyDecision::Deny
        );
        assert_eq!(manager.audit_entries().len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn global_scope_can_authorize_across_scopes() {
        let log_path = std::env::temp_dir().join("test_audit_3.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            3,
            Scope::Global,
            vec!["execute".to_string()],
            Duration::from_secs(60),
            [7u8; 32],
        );

        manager
            .issue_token(token.clone())
            .expect("issue should succeed");
        assert!(
            manager
                .authorize_token(&token, "execute")
                .expect("authorize should succeed")
        );
        assert_eq!(
            manager
                .decision_for(3, &[7u8; 32], &Scope::Process(99), "execute")
                .expect("decision should succeed"),
            PolicyDecision::Allow
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn deny_capability_not_in_policy_allowlist() {
        let log_path = std::env::temp_dir().join("test_audit_4.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            4,
            Scope::Global,
            vec!["write".to_string()],
            Duration::from_secs(60),
            [6u8; 32],
        );

        manager
            .issue_token(token.clone())
            .expect("issue should succeed");

        assert!(
            !manager
                .authorize_token(&token, "write")
                .expect("authorize should succeed")
        );
        assert!(
            !manager
                .validate(4, &[6u8; 32], &Scope::Global, "write")
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(4, &[6u8; 32], &Scope::Global, "write")
                .expect("decision should succeed"),
            PolicyDecision::Deny
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn audit_write_failure_is_fail_closed() {
        let log_path = std::env::temp_dir().join("test_audit_dir");
        let _ = std::fs::remove_dir_all(&log_path);
        std::fs::create_dir_all(&log_path).expect("directory should be created");

        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            5,
            Scope::Global,
            vec!["read".to_string()],
            Duration::from_secs(60),
            [5u8; 32],
        );

        assert_eq!(
            manager.issue_token(token),
            Err(CapabilityError::AuditWriteFailed)
        );

        let _ = std::fs::remove_dir_all(&log_path);
    }
}
