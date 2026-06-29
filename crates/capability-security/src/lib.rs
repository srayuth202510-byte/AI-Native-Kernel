#![deny(unsafe_code)]

pub mod audit;
pub mod metrics;
pub mod policy;
pub mod token;

pub use metrics::{SecurityMetrics, render_metrics};

use crate::audit::{AuditEntry, AuditLogger};
use crate::policy::{PolicyDecision, PolicyEngine};
pub use crate::token::{CapabilityToken, Scope};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;
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
    /// โทเค็นถูกเพิกถอนแล้ว
    #[error("token has been revoked")]
    TokenRevoked,
    /// ออกโทเค็นเกินอัตราที่กำหนด (rate limit exceeded)
    #[error("token issuance rate limited")]
    RateLimited,
}

#[derive(Clone)]
struct RevocationCallback(std::sync::Arc<dyn Fn(u64, Scope) + Send + Sync>);

impl std::fmt::Debug for RevocationCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationCallback").finish()
    }
}

/// ตัวจัดการความปลอดภัยอิงความสามารถ (Capability-based Security Manager)
/// ทำหน้าที่ควบคุมสิทธิ์ ออกโทเค็น ตรวจสอบสิทธิ์ เพิกถอนโทเค็น และบันทึกประวัติความปลอดภัย
#[derive(Debug)]
pub struct CapabilitySecurityManager {
    /// ตารางเก็บโทเค็นความสามารถทั้งหมด มีการใช้ `RwLock` เพื่อให้สามารถใช้งานข้ามเธรดได้อย่างปลอดภัย
    tokens: RwLock<HashMap<u64, CapabilityToken>>,
    /// รายการรหัสโทเค็นที่ถูกเพิกถอนแล้ว (Revoked Token IDs)
    revoked: RwLock<HashSet<u64>>,
    /// กลไกการประเมินนโยบายเพื่อตัดสินใจอนุญาตหรือปฏิเสธสิทธิ์
    policy_engine: PolicyEngine,
    /// ตัวบันทึกประวัติการตรวจสอบการทำงานและความปลอดภัย (Audit Logger)
    audit_logger: AuditLogger,
    /// ตัววัดผลความปลอดภัย (Prometheus Metrics)
    metrics: Option<std::sync::Arc<SecurityMetrics>>,
    /// ประวัติเวลาที่ออกโทเค็นล่าสุด แยกตาม Scope (rate limiting per scope)
    issue_rate: RwLock<HashMap<Scope, VecDeque<Instant>>>,
    /// อัตราสูงสุดที่อนุญาตให้ออกโทเค็นต่อวินาทีต่อแต่ละ Scope
    max_issue_rate: usize,
    /// Callback สำหรับการแจ้งเตือนเมื่อโทเค็นถูกเพิกถอน (Revocation callback)
    revocation_callback: RwLock<Option<RevocationCallback>>,
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
    fn tokens_read(&self) -> RwLockReadGuard<'_, HashMap<u64, CapabilityToken>> {
        self.tokens.read()
    }

    fn tokens_write(&self) -> RwLockWriteGuard<'_, HashMap<u64, CapabilityToken>> {
        self.tokens.write()
    }

    fn revoked_read(&self) -> RwLockReadGuard<'_, HashSet<u64>> {
        self.revoked.read()
    }

    fn revoked_write(&self) -> RwLockWriteGuard<'_, HashSet<u64>> {
        self.revoked.write()
    }

    fn issue_rate_write(&self) -> RwLockWriteGuard<'_, HashMap<Scope, VecDeque<Instant>>> {
        self.issue_rate.write()
    }

    /// สร้างตัวจัดการความปลอดภัย `CapabilitySecurityManager` ใหม่ด้วยการตั้งค่าเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate_limit(100)
    }

    #[must_use]
    pub fn with_rate_limit(max_issue_rate: usize) -> Self {
        let metrics = SecurityMetrics::register(prometheus::default_registry()).ok();
        Self {
            tokens: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::default(),
            metrics,
            issue_rate: RwLock::new(HashMap::new()),
            max_issue_rate,
            revocation_callback: RwLock::new(None),
        }
    }

    /// สร้างตัวจัดการความปลอดภัย `CapabilitySecurityManager` ใหม่พร้อมระบุพาธในการบันทึกไฟล์ประวัติการตรวจสอบ
    #[must_use]
    pub fn new_with_log_path(log_path: std::path::PathBuf) -> Self {
        Self::new_with_log_path_and_rate(log_path, 100)
    }

    #[must_use]
    pub fn new_with_log_path_and_rate(log_path: std::path::PathBuf, max_issue_rate: usize) -> Self {
        let metrics = SecurityMetrics::register(prometheus::default_registry()).ok();
        Self {
            tokens: RwLock::new(HashMap::new()),
            revoked: RwLock::new(HashSet::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::new(log_path),
            metrics,
            issue_rate: RwLock::new(HashMap::new()),
            max_issue_rate,
            revocation_callback: RwLock::new(None),
        }
    }

    /// ออกโทเค็นความสามารถ (Capability Token) ใหม่ บันทึกลงในระบบเพื่อใช้งาน และบันทึกประวัติ (Audit Log)
    ///
    /// Rate limit: ควบคุมโดย `max_issue_rate` ต่อ 1 วินาที แยกตาม Scope ป้องกัน audit log flooding
    pub async fn issue_token(&self, token: CapabilityToken) -> Result<()> {
        let now = Instant::now();
        // Rate limit check — release lock before audit I/O
        {
            let mut rate_map = self.issue_rate_write();
            let rate_queue = rate_map.entry(token.scope).or_default();

            rate_queue.push_back(now);
            while rate_queue
                .front()
                .is_some_and(|t| now.duration_since(*t).as_secs_f64() > 1.0)
            {
                rate_queue.pop_front();
            }
            if self.max_issue_rate > 0 && rate_queue.len() > self.max_issue_rate {
                return Err(CapabilityError::RateLimited);
            }
        }

        self.audit_logger
            .record(AuditEntry::issued(token.id))
            .await
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        if let Some(ref m) = self.metrics {
            m.tokens_issued_total.inc();
            m.audit_entries_total.inc();
        }
        self.tokens_write().insert(token.id, token);
        Ok(())
    }

    /// เพิกถอนโทเค็นความสามารถ (Capability Token) ตามรหัสโทเค็น
    /// โทเค็นที่ถูกเพิกถอนแล้วจะไม่สามารถใช้งานได้อีกต่อไป แม้จะยังไม่หมดอายุ
    pub async fn revoke_token(&self, token_id: u64) -> Result<()> {
        self.revoked_write().insert(token_id);

        let scope_opt = self.tokens_read().get(&token_id).map(|t| t.scope);
        if let Some(scope) = scope_opt {
            if let Some(ref callback) = *self.revocation_callback.read() {
                (callback.0)(token_id, scope);
            }
        }

        self.audit_logger
            .record(AuditEntry::revoked(token_id))
            .await
            .map_err(|_| CapabilityError::AuditWriteFailed)?;
        if let Some(ref m) = self.metrics {
            m.audit_entries_total.inc();
        }
        Ok(())
    }

    /// ลงทะเบียน Callback สำหรับประมวลผลเมื่อโทเค็นถูกเพิกถอน (เช่น ลบ PID ใน allowed_pids)
    pub fn register_revocation_callback(
        &self,
        callback: std::sync::Arc<dyn Fn(u64, Scope) + Send + Sync>,
    ) {
        *self.revocation_callback.write() = Some(RevocationCallback(callback));
    }

    /// ดึงรายการโทเค็นทั้งหมดในระบบเพื่อนำมาตรวจสอบ/วิเคราะห์ (เช่น การตรวจจับการหมดอายุ)
    #[must_use]
    pub fn get_tokens(&self) -> Vec<CapabilityToken> {
        self.tokens_read().values().cloned().collect()
    }

    /// ตรวจสอบว่าโทเค็นถูกเพิกถอนแล้วหรือไม่
    #[must_use]
    pub fn is_revoked(&self, token_id: u64) -> bool {
        self.revoked_read().contains(&token_id)
    }

    /// ตรวจสอบว่ามี Token ที่ยื่นคำขอและยังใช้งานได้อยู่สำหรับ Process ID นี้หรือไม่
    /// เป็นการคืนค่า `true` แบบรวดเร็วโดยไม่ต้องคืนค่า Object และไม่ต้อง Clone (O(1) หรือใกล้เคียง)
    #[must_use]
    pub fn has_valid_token_for_pid(&self, pid: u32) -> bool {
        let tokens = self.tokens_read();
        let revoked = self.revoked_read();
        for token in tokens.values() {
            if let Scope::Process(p) = token.scope {
                if p == pid && token.is_valid() && !revoked.contains(&token.id) {
                    return true;
                }
            }
        }
        false
    }

    /// ทำความสะอาดหน่วยความจำ (Garbage Collection) เพื่อป้องกัน Memory Leak
    /// จะลบ Token ที่หมดอายุ, คิวเรทลิมิตที่เกิน 1 วินาที และ ID การเพิกถอนที่ไม่มี Token อยู่ในระบบแล้ว
    pub fn garbage_collect(&self) {
        let mut tokens = self.tokens_write();
        let mut revoked = self.revoked_write();
        let mut issue_rate = self.issue_rate_write();
        let now_time = Instant::now();

        // 1. ลบ Token ที่หมดอายุ
        tokens.retain(|_, token| token.is_valid());

        // 2. ลบ ID การเพิกถอน ที่ตัว Token หายไปจาก HashMap แล้ว
        revoked.retain(|id| tokens.contains_key(id));

        // 3. ลบเรทลิมิตคิวที่ไม่มีกิจกรรมภายใน 1 วินาทีที่ผ่านมา
        issue_rate.retain(|_, queue| {
            while queue
                .front()
                .is_some_and(|t| now_time.duration_since(*t).as_secs_f64() > 1.0)
            {
                queue.pop_front();
            }
            !queue.is_empty()
        });
    }

    /// จำนวนโทเค็นที่ถูกเพิกถอนทั้งหมด
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked_read().len()
    }

    /// ตรวจสอบสิทธิ์ของโทเค็นโดยอ้างอิงกับ Capability ที่ร้องขอ
    /// พร้อมทำบันทึกประวัติการอนุญาต (Allow) หรือปฏิเสธ (Deny) ลงไฟล์ประวัติการตรวจสอบ
    pub async fn authorize_token(&self, token: &CapabilityToken, capability: &str) -> Result<bool> {
        let allowed = token.is_valid()
            && !self.is_revoked(token.id)
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
            .await
            .map_err(|_| CapabilityError::AuditWriteFailed)?;

        if let Some(ref m) = self.metrics {
            m.audit_entries_total.inc();
            let label = if allowed { "allow" } else { "deny" };
            m.policy_decisions_total.with_label_values(&[label]).inc();
        }
        Ok(allowed)
    }

    /// ยืนยันความถูกต้องของโทเค็นโดยระบุ ID, รหัสลับ (Secret Key), ขอบเขต (Scope) และ Capability ที่ต้องการ
    /// จะใช้วิธีเปรียบเทียบรหัสลับแบบคงเวลา (Constant-time comparison) เพื่อความปลอดภัยสูงสุด
    pub async fn validate(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> Result<bool> {
        let token = {
            let tokens = self.tokens_read();
            tokens.get(&token_id).cloned()
        };
        let Some(token) = token else {
            if let Some(ref m) = self.metrics {
                m.token_validation_failures_total.inc();
            }
            return Ok(false);
        };

        // ตรวจสอบว่าโทเค็นถูกเพิกถอนแล้วหรือไม่
        if self.is_revoked(token_id) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .await
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            if let Some(ref m) = self.metrics {
                m.audit_entries_total.inc();
                m.policy_decisions_total.with_label_values(&["deny"]).inc();
                m.token_validation_failures_total.inc();
            }
            return Ok(false);
        }

        // ตรวจสอบความถูกต้องของรหัสลับ (Secret Key) แบบคงเวลาเพื่อป้องกัน Timing Attacks
        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .await
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            if let Some(ref m) = self.metrics {
                m.audit_entries_total.inc();
                m.policy_decisions_total.with_label_values(&["deny"]).inc();
                m.token_validation_failures_total.inc();
            }
            return Ok(false);
        }

        let allowed = token.is_valid() && self.policy_engine.authorize(&token, scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger
            .record(entry)
            .await
            .map_err(|_| CapabilityError::AuditWriteFailed)?;

        if let Some(ref m) = self.metrics {
            m.audit_entries_total.inc();
            let label = if allowed { "allow" } else { "deny" };
            m.policy_decisions_total.with_label_values(&[label]).inc();
            if !allowed {
                m.token_validation_failures_total.inc();
            }
        }
        Ok(allowed)
    }

    /// ตัดสินใจเชิงนโยบายความปลอดภัย (Policy Decision) สำหรับการเข้าถึงที่ร้องขอ
    /// คืนผลลัพธ์เป็น `PolicyDecision` (Allow หรือ Deny) พร้อมบันทึกประวัติลงไฟล์การตรวจสอบ
    pub async fn decision_for(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> Result<PolicyDecision> {
        let token = {
            let tokens = self.tokens_read();
            tokens.get(&token_id).cloned()
        };
        let Some(token) = token else {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .await
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            if let Some(ref m) = self.metrics {
                m.audit_entries_total.inc();
                m.policy_decisions_total.with_label_values(&["deny"]).inc();
            }
            return Ok(PolicyDecision::Deny);
        };

        // ตรวจสอบว่าโทเค็นถูกเพิกถอนแล้วหรือไม่
        if self.is_revoked(token_id) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .await
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            if let Some(ref m) = self.metrics {
                m.audit_entries_total.inc();
                m.policy_decisions_total.with_label_values(&["deny"]).inc();
            }
            return Ok(PolicyDecision::Deny);
        }

        // เปรียบเทียบรหัสลับด้วยวิธีคงเวลาเพื่อป้องกัน Timing Attacks ในการถอดรหัสลับ/เปรียบเทียบโทเค็น
        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger
                .record(AuditEntry::denied(token_id))
                .await
                .map_err(|_| CapabilityError::AuditWriteFailed)?;
            if let Some(ref m) = self.metrics {
                m.audit_entries_total.inc();
                m.policy_decisions_total.with_label_values(&["deny"]).inc();
            }
            return Ok(PolicyDecision::Deny);
        }

        let decision = self.policy_engine.decision(&token, scope, capability);
        let entry = match decision {
            PolicyDecision::Allow => AuditEntry::allowed(token.id),
            PolicyDecision::Deny => AuditEntry::denied(token.id),
        };
        self.audit_logger
            .record(entry)
            .await
            .map_err(|_| CapabilityError::AuditWriteFailed)?;

        if let Some(ref m) = self.metrics {
            m.audit_entries_total.inc();
            let label = match decision {
                PolicyDecision::Allow => "allow",
                PolicyDecision::Deny => "deny",
            };
            m.policy_decisions_total.with_label_values(&[label]).inc();
        }
        Ok(decision)
    }

    /// ดึงรายการประวัติการตรวจสอบการเข้าถึงทั้งหมดที่มีบันทึกไว้
    pub async fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_logger.entries().await
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

    fn test_log_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("test_audit_{name}.log"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[tokio::test]
    async fn issue_and_validate_token() {
        let log_path = test_log_path("1");
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
            .await
            .expect("issue should succeed");

        assert!(
            manager
                .validate(1, &[9u8; 32], &Scope::Process(42), "read")
                .await
                .expect("validate should succeed")
        );
        assert!(
            manager
                .authorize_token(&token, "read")
                .await
                .expect("authorize should succeed")
        );
        assert_eq!(
            manager
                .decision_for(1, &[9u8; 32], &Scope::Process(42), "read")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Allow
        );
        assert_eq!(manager.audit_entries().await.len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn rejects_expired_or_unauthorized_token() {
        let log_path = test_log_path("2");
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
            .await
            .expect("issue should succeed");

        assert!(
            !manager
                .authorize_token(&expired, "write")
                .await
                .expect("authorize should succeed")
        );
        assert!(
            !manager
                .validate(2, &[8u8; 32], &Scope::Thread(7), "write")
                .await
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(2, &[8u8; 32], &Scope::Thread(7), "write")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Deny
        );
        assert_eq!(manager.audit_entries().await.len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn global_scope_can_authorize_across_scopes() {
        let log_path = test_log_path("3");
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
            .await
            .expect("issue should succeed");
        assert!(
            manager
                .authorize_token(&token, "execute")
                .await
                .expect("authorize should succeed")
        );
        assert_eq!(
            manager
                .decision_for(3, &[7u8; 32], &Scope::Process(99), "execute")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Allow
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn deny_capability_not_in_policy_allowlist() {
        let log_path = test_log_path("4");
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
            .await
            .expect("issue should succeed");

        assert!(
            !manager
                .authorize_token(&token, "write")
                .await
                .expect("authorize should succeed")
        );
        assert!(
            !manager
                .validate(4, &[6u8; 32], &Scope::Global, "write")
                .await
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(4, &[6u8; 32], &Scope::Global, "write")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Deny
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn audit_write_failure_is_fail_closed() {
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
            manager.issue_token(token).await,
            Err(CapabilityError::AuditWriteFailed)
        );

        let _ = std::fs::remove_dir_all(&log_path);
    }

    #[tokio::test]
    async fn revoke_token_denies_subsequent_access() {
        let log_path = test_log_path("revoke_1");
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            10,
            Scope::Process(1),
            vec!["read".to_string()],
            Duration::from_secs(60),
            [10u8; 32],
        );

        manager
            .issue_token(token.clone())
            .await
            .expect("issue should succeed");

        // ตรวจสอบว่าโทเค็นใช้งานได้ก่อนเพิกถอน
        assert!(
            manager
                .authorize_token(&token, "read")
                .await
                .expect("authorize should succeed")
        );
        assert!(
            manager
                .validate(10, &[10u8; 32], &Scope::Process(1), "read")
                .await
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(10, &[10u8; 32], &Scope::Process(1), "read")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Allow
        );

        // เพิกถอนโทเค็น
        manager
            .revoke_token(10)
            .await
            .expect("revoke should succeed");
        assert!(manager.is_revoked(10));
        assert_eq!(manager.revoked_count(), 1);

        // ตรวจสอบว่าโทเค็นใช้งานไม่ได้หลังเพิกถอน
        assert!(
            !manager
                .authorize_token(&token, "read")
                .await
                .expect("authorize should succeed")
        );
        assert!(
            !manager
                .validate(10, &[10u8; 32], &Scope::Process(1), "read")
                .await
                .expect("validate should succeed")
        );
        assert_eq!(
            manager
                .decision_for(10, &[10u8; 32], &Scope::Process(1), "read")
                .await
                .expect("decision should succeed"),
            PolicyDecision::Deny
        );

        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn revoke_nonexistent_token_succeeds() {
        let log_path = test_log_path("revoke_2");
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());

        // เพิกถอนโทเค็นที่ไม่มีอยู่ — ต้องไม่ error
        manager
            .revoke_token(999)
            .await
            .expect("revoke should succeed");
        assert!(manager.is_revoked(999));

        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn revoked_token_logs_denied_in_audit() {
        let log_path = test_log_path("revoke_3");
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            11,
            Scope::Global,
            vec!["read".to_string()],
            Duration::from_secs(60),
            [11u8; 32],
        );

        manager
            .issue_token(token.clone())
            .await
            .expect("issue should succeed");
        manager
            .revoke_token(11)
            .await
            .expect("revoke should succeed");

        // authorize หลังเพิกถอน — ต้องได้ denied audit entry
        let _ = manager.authorize_token(&token, "read").await;
        let entries = manager.audit_entries().await;
        let denied_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.action == "denied" && e.token_id == 11)
            .collect();
        assert!(
            !denied_entries.is_empty(),
            "revoked token authorization should log denied"
        );
        // ต้องมี revoked entry
        let revoked_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.action == "revoked" && e.token_id == 11)
            .collect();
        assert_eq!(
            revoked_entries.len(),
            1,
            "should have exactly one revoked entry"
        );

        let _ = std::fs::remove_file(&log_path);
    }

    #[tokio::test]
    async fn test_issue_token_rate_limit_per_scope() {
        let log_path = test_log_path("rate_limit");
        // Rate limit 2 tokens per second
        let manager = CapabilitySecurityManager::new_with_log_path_and_rate(log_path.clone(), 2);

        // Issuing 2 tokens in Scope A should succeed
        manager
            .issue_token(CapabilityToken::new(
                1,
                Scope::Process(100),
                vec![],
                Duration::from_secs(60),
                [1; 32],
            ))
            .await
            .unwrap();
        manager
            .issue_token(CapabilityToken::new(
                2,
                Scope::Process(100),
                vec![],
                Duration::from_secs(60),
                [2; 32],
            ))
            .await
            .unwrap();

        // The 3rd token in Scope A should fail due to rate limiting
        assert_eq!(
            manager
                .issue_token(CapabilityToken::new(
                    3,
                    Scope::Process(100),
                    vec![],
                    Duration::from_secs(60),
                    [3; 32]
                ))
                .await,
            Err(CapabilityError::RateLimited)
        );

        // But issuing in a different Scope (B) should succeed (its own bucket)
        manager
            .issue_token(CapabilityToken::new(
                4,
                Scope::Process(200),
                vec![],
                Duration::from_secs(60),
                [4; 32],
            ))
            .await
            .unwrap();

        let _ = std::fs::remove_file(&log_path);
    }
}
