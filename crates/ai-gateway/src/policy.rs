//! แบบจำลองนโยบายและการยืนยันตัวตนสำหรับ data plane
//!
//! # ทำไมไม่ใช้ `capability_security` เดิม
//!
//! `Scope` ของ host plane เป็น `Process(u32) | Thread(u32) | Global` ซึ่งเป็น
//! *เอกลักษณ์ของ process* ไม่สามารถแทน "ผู้เช่า A เรียกโมเดล X ได้แต่เรียก
//! embedding ไม่ได้" ได้ และ `PolicyEngine::authorize` คืนค่า `bool` ซึ่งไม่มีประโยธน์
//! ให้บอกลูกค้าว่า*ทำไม*ถึงถูกปฏิเสธ
//!
//! โมดูลนี้จึงสร้างโมเดลของตัวเองสำหรับ data plane โดย**ยืมหลักการ** (fail-closed,
//! ตรวจสอบได้, เทียบแบบคงเวลา) แต่ไม่ยืมชนิดข้อมูล

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;
use thiserror::Error;

use crate::wire::Endpoint;

/// ข้อผิดพลาดของชั้นยืนยันตัวตนและนโยบาย
#[derive(Debug, Error)]
pub enum AuthError {
    /// ไม่มี header `Authorization`
    #[error("missing authorization header")]
    MissingCredentials,
    /// รูปแบบ header ไม่ถูกต้อง
    #[error("malformed authorization header")]
    MalformedHeader,
    /// ไม่พบผู้เช่าสำหรับคีย์ที่ใช้
    #[error("unknown tenant key")]
    UnknownTenant,
    /// ผู้เช่าถูกระงับหรือยกเลิก
    #[error("tenant is suspended")]
    TenantSuspended,
    /// คีย์หมดอายุ
    #[error("tenant key expired")]
    KeyExpired,
    /// ไม่มีสิทธิ์เรียกเส้นทางที่ร้องขอ
    #[error("tenant not permitted for endpoint {endpoint}")]
    EndpointNotPermitted {
        /// เส้นทางที่ถูกปฏิเสธ
        endpoint: &'static str,
    },
    /// ไม่มีสิทธิ์เรียกโมเดลที่ร้องขอ
    #[error("tenant not permitted for model {model}")]
    ModelNotPermitted {
        /// ชื่อโมเดลที่ถูกปฏิเสธ
        model: String,
    },
    /// เกินเพดานจำนวนคำขอพร้อมกัน
    #[error("concurrent request limit reached")]
    ConcurrencyLimit,
}

/// เหตุผลของการตัดสินใจ — ส่งกลับให้ลูกค้าและเขียนลง audit log
///
/// ไม่ใช่แค่ bool เพราะลูกค้าต้องรู้ว่าจะแก้อะไร เช่น ขอสิทธิ์เพิ่ม หรือเปลี่ยน endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DenyReason {
    /// ไม่มีข้อมูลรับรอง
    MissingCredentials,
    /// รูปแบบข้อมูลรับรองผิด
    MalformedHeader,
    /// ไม่รู้จักผู้เช่า
    UnknownTenant,
    /// ผู้เช่าถูกระงับ
    TenantSuspended,
    /// คีย์หมดอายุ
    KeyExpired,
    /// ไม่มีสิทธิ์ตามเส้นทาง
    EndpointNotPermitted,
    /// ไม่มีสิทธิ์ตามโมเดล
    ModelNotPermitted,
    /// เกินเพดานพร้อมกัน
    ConcurrencyLimit,
}

impl DenyReason {
    /// ชื่อแบบคงที่สำหรับ audit log และ metric label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingCredentials => "missing_credentials",
            Self::MalformedHeader => "malformed_header",
            Self::UnknownTenant => "unknown_tenant",
            Self::TenantSuspended => "tenant_suspended",
            Self::KeyExpired => "key_expired",
            Self::EndpointNotPermitted => "endpoint_not_permitted",
            Self::ModelNotPermitted => "model_not_permitted",
            Self::ConcurrencyLimit => "concurrency_limit",
        }
    }

    /// แปลงจากข้อผิดพลาดของชั้นยืนยันตัวตน
    #[must_use]
    pub fn from_error(err: &AuthError) -> Self {
        match err {
            AuthError::MissingCredentials => Self::MissingCredentials,
            AuthError::MalformedHeader => Self::MalformedHeader,
            AuthError::UnknownTenant => Self::UnknownTenant,
            AuthError::TenantSuspended => Self::TenantSuspended,
            AuthError::KeyExpired => Self::KeyExpired,
            AuthError::EndpointNotPermitted { .. } => Self::EndpointNotPermitted,
            AuthError::ModelNotPermitted { .. } => Self::ModelNotPermitted,
            AuthError::ConcurrencyLimit => Self::ConcurrencyLimit,
        }
    }
}

/// ผลการตัดสินใจของนโยบาย data plane
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// อนุญาต
    Allow,
    /// ปฏิเสธ พร้อมเหตุผล
    Deny(DenyReason),
}

impl Verdict {
    /// ตรวจว่าอนุญาตหรือไม่
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// เหตุผลของการปฏิเสธ (ถ้ามี)
    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Deny(r) => Some(*r),
            Self::Allow => None,
        }
    }
}

/// สิทธิ์ของผู้เช่าหนึ่งราย
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicy {
    /// รหัสผู้เช่า
    pub tenant_id: String,
    /// เส้นทางที่เรียกได้ — ว่างเปล่าหมายถึงไม่อนุญาตทุกเส้นทาง (fail-closed)
    pub allowed_endpoints: BTreeSet<&'static str>,
    /// โมเดลที่เรียกได้ — ว่างเปล่าหมายถึงไม่อนุญาตทุกโมเดล
    pub allowed_models: BTreeSet<String>,
    /// จำนวนคำขอพร้อมกันสูงสุด
    pub max_concurrent: u32,
    /// หยุดใช้งานชั่วคราวหรือไม่
    pub suspended: bool,
}

/// ข้อมูลรับรองของผู้เช่าหนึ่งราย
#[derive(Debug, Clone)]
pub struct TenantCredential {
    /// รหัสผู้เช่า
    pub tenant_id: String,
    /// คีย์ลับ (เก็บเป็น byte เพื่อให้เทียบแบบคงเวลาได้)
    pub key: Vec<u8>,
    /// เวลาหมดอายุ
    pub expires_at: SystemTime,
}

/// ผลการยืนยันตัวตนที่สำเร็จ
#[derive(Debug, Clone)]
pub struct TenantIdentity {
    /// รหัสผู้เช่า
    pub tenant_id: String,
    /// นโยบายของผู้เช่า
    pub policy: TenantPolicy,
}

/// ตัวตรวจสอบนโยบายและยืนยันตัวตนของ data plane
///
/// ค่าของทั้งหมดมาจาก configuration ที่โหลดตอนเริ่มทำงาน และการเปลี่ยนแปลงต้อง
/// เป็นการโหลด config ใหม่ทั้งชุด (hot reload ในอนาคต) — ไม่มีการแก้แบบบางส่วน
/// ซึ่งจะทำให้เกิดสถานะกึ่งอนุญาตที่ตรวจสอบยาก
///
/// ไม่มี "ผู้เช่าเริ่มต้น" และไม่มีโหมดยอมรับทุกคีย์ — คีย์ที่ไม่ตรงกับ
/// credential ใดเลยถูกปฏิเสธเสมอ เพราะการยอมรับคีย์ที่ไม่รู้จักเป็นการเปิด
/// ให้ผู้ใดก็ตามเข้ามาในฐานะของผู้เช่าหนึ่งโดยไม่ต้องมี credential
#[derive(Debug, Clone)]
pub struct DataPlanePolicy {
    tenants: BTreeMap<String, TenantPolicy>,
    credentials: BTreeMap<String, TenantCredential>,
}

impl DataPlanePolicy {
    /// สร้างนโยบายจากรายการผู้เช่าและข้อมูลรับรอง
    #[must_use]
    pub fn new(tenants: Vec<TenantPolicy>, credentials: Vec<TenantCredential>) -> Self {
        Self {
            tenants: tenants
                .into_iter()
                .map(|t| (t.tenant_id.clone(), t))
                .collect(),
            credentials: credentials
                .into_iter()
                .map(|c| (c.tenant_id.clone(), c))
                .collect(),
        }
    }

    /// สร้างนโยบายแบบปฏิเสธทุกคน (ค่าเริ่มต้นที่ปลอดภัยที่สุด)
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            tenants: BTreeMap::new(),
            credentials: BTreeMap::new(),
        }
    }

    /// ยืนยันตัวตนจาก header `Authorization`
    ///
    /// รองรับรูปแบบ `Bearer <key>` และ `ApiKey <key>` เท่านั้น — ไม่รับคีย์ดิบ
    /// เพื่อไม่ให้ลูกค้าส่งคีย์ผิดวิธีโดยไม่รู้ตัว
    ///
    /// # Errors
    /// คืน `Err` เมื่อไม่มี header, รูปแบบผิด, ไม่พบผู้เช่า, หมดอายุ หรือถูกระงับ
    pub fn authenticate(&self, header: Option<&str>) -> Result<TenantIdentity, AuthError> {
        let raw = header.ok_or(AuthError::MissingCredentials)?;
        let key = parse_bearer(raw).ok_or(AuthError::MalformedHeader)?;
        let key = key.as_bytes();

        // เปรียบเทียบกับทุก credential เพื่อไม่ให้เวลาตอบสนองบอกว่าคีย์นั้น
        // ใกล้เคียงกับคีย์ใด — คีย์ที่ไม่รู้จักถูกปฏิเสธเสมอ
        let tenant_id = self
            .credentials
            .iter()
            .find(|(_, cred)| constant_time_eq(&cred.key, key))
            .map(|(id, _)| id.clone())
            .ok_or(AuthError::UnknownTenant)?;

        let cred = self
            .credentials
            .get(&tenant_id)
            .ok_or(AuthError::UnknownTenant)?;

        if SystemTime::now() > cred.expires_at {
            return Err(AuthError::KeyExpired);
        }

        let policy = self
            .tenants
            .get(&tenant_id)
            .cloned()
            .ok_or(AuthError::UnknownTenant)?;

        if policy.suspended {
            return Err(AuthError::TenantSuspended);
        }

        Ok(TenantIdentity { tenant_id, policy })
    }

    /// ตรวจสิทธิ์การเรียกเส้นทางและโมเดล
    ///
    /// # Errors
    /// คืน `Err` เมื่อไม่มีสิทธิ์ตามเส้นทางหรือโมเดล
    pub fn authorize(&self, identity: &TenantIdentity, endpoint: Endpoint, model: &str) -> Verdict {
        if identity.policy.suspended {
            return Verdict::Deny(DenyReason::TenantSuspended);
        }
        if !identity
            .policy
            .allowed_endpoints
            .contains(endpoint.as_str())
        {
            return Verdict::Deny(DenyReason::EndpointNotPermitted);
        }
        // รายการโมเดลว่าง = ไม่อนุญาตให้เรียกโมเดลใด ๆ ทั้งสิ้น (fail-closed)
        if !identity.policy.allowed_models.iter().any(|m| m == model) {
            return Verdict::Deny(DenyReason::ModelNotPermitted);
        }
        Verdict::Allow
    }

    /// จำนวนผู้เช่าที่ลงทะเบียน
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// ตรวจว่ามีผู้เช่ารายนี้หรือไม่
    #[must_use]
    pub fn has_tenant(&self, tenant_id: &str) -> bool {
        self.tenants.contains_key(tenant_id)
    }
}

/// แยกคีย์ออกจาก header `Authorization`
#[must_use]
pub fn parse_bearer(header: &str) -> Option<&str> {
    let (scheme, key) = header.split_once(' ')?;
    let scheme = scheme.trim();
    if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("apikey") {
        return None;
    }
    let key = key.trim();
    if key.is_empty() { None } else { Some(key) }
}

/// เทียบสองสตริงแบบคงเวลา (constant-time)
///
/// ใช้กับการเทียบคีย์ลับทุกครั้งเพื่อกัน timing attack
///
/// ไม่มีการ `return` ก่อนจบลูป แม้ความยาวไม่เท่ากัน เพราะการออกจากลูปเร็วเมื่อ
/// ความยาวต่างกันจะเปิดช่องให้ผู้โจมตีเดาความยาวของคีย์ที่ถูกเปรียบเทียบได้
/// ความยาวถูกรวมเข้าไปใน `diff` แทนการแยกพิจารณา
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// นโยบายแบบอ่านง่ายสำหรับไฟล์ config (TOML/JSON)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyFile {
    /// รายการผู้เช่า
    #[serde(default)]
    pub tenants: Vec<TenantFile>,
}

/// รายการผู้เช่าในไฟล์ config
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantFile {
    /// รหัสผู้เช่า
    pub id: String,
    /// คีย์ลับ (เขียนเป็นข้อความในไฟล์ config เพื่อความง่ายในการเริ่มต้นใช้งาน)
    pub key: String,
    /// เส้นทางที่อนุญาต
    #[serde(default)]
    pub allowed_endpoints: Vec<String>,
    /// โมเดลที่อนุญาต (ว่าง = ไม่อนุญาตให้เรียกใด ๆ)
    #[serde(default)]
    pub allowed_models: Vec<String>,
    /// จำนวนคำขอพร้อมกันสูงสุด
    #[serde(default)]
    pub max_concurrent: u32,
    /// ระงับการใช้งาน
    #[serde(default)]
    pub suspended: bool,
}

impl PolicyFile {
    /// แปลงเป็นนโยบายที่ใช้งานได้
    ///
    /// เส้นทางที่ไม่รู้จักจะถูกข้าม (พิมพ์เตือนไว้ใน log) แทนที่จะผ่านเข้ามา
    /// แล้วไปตัดสินใจทีหลัง — เพราะการยอมรับค่าที่ไม่เข้าใจ
    /// เป็นการเปิดช่องให้ตั้งค่าผิดโดยไม่รู้ตัว
    #[must_use]
    pub fn into_policy(self) -> (DataPlanePolicy, Vec<String>) {
        let mut warnings = Vec::new();
        let mut tenants = Vec::new();
        let mut credentials = Vec::new();

        for t in self.tenants {
            let mut endpoints = BTreeSet::new();
            for name in &t.allowed_endpoints {
                match parse_endpoint(name) {
                    Some(e) => {
                        endpoints.insert(e);
                    }
                    None => {
                        warnings.push(format!("unknown endpoint '{name}' for tenant '{}'", t.id))
                    }
                }
            }
            credentials.push(TenantCredential {
                tenant_id: t.id.clone(),
                key: t.key.into_bytes(),
                expires_at: SystemTime::now() + std::time::Duration::from_secs(86_400),
            });
            tenants.push(TenantPolicy {
                tenant_id: t.id.clone(),
                allowed_endpoints: endpoints,
                allowed_models: t.allowed_models.into_iter().collect(),
                max_concurrent: t.max_concurrent,
                suspended: t.suspended,
            });
        }

        (DataPlanePolicy::new(tenants, credentials), warnings)
    }
}

/// แปลงชื่อเส้นทางเป็น [`Endpoint`] คืน `None` เมื่อไม่รู้จัก
#[must_use]
pub fn parse_endpoint(name: &str) -> Option<&'static str> {
    match name {
        "chat_completions" | "/v1/chat/completions" => Some(Endpoint::ChatCompletions.as_str()),
        "completions" | "/v1/completions" => Some(Endpoint::Completions.as_str()),
        "embeddings" | "/v1/embeddings" => Some(Endpoint::Embeddings.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn credential(tenant: &str, key: &str) -> TenantCredential {
        TenantCredential {
            tenant_id: tenant.to_string(),
            key: key.as_bytes().to_vec(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        }
    }

    fn policy(tenant: &str, endpoints: &[&'static str], models: &[&str]) -> TenantPolicy {
        TenantPolicy {
            tenant_id: tenant.to_string(),
            allowed_endpoints: endpoints.iter().copied().collect(),
            allowed_models: models.iter().map(|s| (*s).to_string()).collect(),
            max_concurrent: 10,
            suspended: false,
        }
    }

    fn sample() -> DataPlanePolicy {
        DataPlanePolicy::new(
            vec![policy(
                "acme",
                &["chat_completions", "embeddings"],
                &["gpt-x"],
            )],
            vec![credential("acme", "secret-key-1")],
        )
    }

    #[test]
    fn authenticates_valid_bearer_token() {
        let p = sample();
        let id = p
            .authenticate(Some("Bearer secret-key-1"))
            .expect("should authenticate");
        assert_eq!(id.tenant_id, "acme");
    }

    #[test]
    fn accepts_apikey_scheme() {
        let p = sample();
        assert!(p.authenticate(Some("ApiKey secret-key-1")).is_ok());
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let p = sample();
        assert!(p.authenticate(Some("bearer secret-key-1")).is_ok());
        assert!(p.authenticate(Some("BEARER secret-key-1")).is_ok());
    }

    #[test]
    fn rejects_missing_header() {
        let p = sample();
        assert!(matches!(
            p.authenticate(None),
            Err(AuthError::MissingCredentials)
        ));
    }

    #[test]
    fn rejects_unknown_scheme() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("Basic dXNlcjpwYXNz")),
            Err(AuthError::MalformedHeader)
        ));
    }

    #[test]
    fn rejects_raw_key_without_scheme() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("secret-key-1")),
            Err(AuthError::MalformedHeader)
        ));
    }

    #[test]
    fn rejects_empty_key() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("Bearer   ")),
            Err(AuthError::MalformedHeader)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("Bearer wrong-key")),
            Err(AuthError::UnknownTenant)
        ));
    }

    #[test]
    fn rejects_expired_key() {
        let p = DataPlanePolicy::new(
            vec![policy("acme", &["chat_completions"], &["gpt-x"])],
            vec![TenantCredential {
                tenant_id: "acme".to_string(),
                key: b"k".to_vec(),
                expires_at: SystemTime::now() - Duration::from_secs(1),
            }],
        );
        assert!(matches!(
            p.authenticate(Some("Bearer k")),
            Err(AuthError::KeyExpired)
        ));
    }

    #[test]
    fn rejects_suspended_tenant() {
        let mut pol = policy("acme", &["chat_completions"], &["gpt-x"]);
        pol.suspended = true;
        let p = DataPlanePolicy::new(vec![pol], vec![credential("acme", "k")]);
        assert!(matches!(
            p.authenticate(Some("Bearer k")),
            Err(AuthError::TenantSuspended)
        ));
    }

    #[test]
    fn authorize_allows_permitted_endpoint_and_model() {
        let p = sample();
        let id = p.authenticate(Some("Bearer secret-key-1")).expect("auth");
        assert_eq!(
            p.authorize(&id, Endpoint::ChatCompletions, "gpt-x"),
            Verdict::Allow
        );
    }

    #[test]
    fn authorize_denies_unlisted_endpoint() {
        let p = DataPlanePolicy::new(
            vec![policy("acme", &["chat_completions"], &["gpt-x"])],
            vec![credential("acme", "k")],
        );
        let id = p.authenticate(Some("Bearer k")).expect("auth");
        let v = p.authorize(&id, Endpoint::Embeddings, "gpt-x");
        assert_eq!(v, Verdict::Deny(DenyReason::EndpointNotPermitted));
    }

    #[test]
    fn authorize_denies_unlisted_model() {
        let p = sample();
        let id = p.authenticate(Some("Bearer secret-key-1")).expect("auth");
        let v = p.authorize(&id, Endpoint::ChatCompletions, "gpt-y");
        assert_eq!(v, Verdict::Deny(DenyReason::ModelNotPermitted));
    }

    #[test]
    fn empty_model_allowlist_denies_everything() {
        let p = DataPlanePolicy::new(
            vec![policy("acme", &["chat_completions"], &[])],
            vec![credential("acme", "k")],
        );
        let id = p.authenticate(Some("Bearer k")).expect("auth");
        assert_eq!(
            p.authorize(&id, Endpoint::ChatCompletions, "anything"),
            Verdict::Deny(DenyReason::ModelNotPermitted)
        );
    }

    #[test]
    fn empty_endpoint_allowlist_denies_everything() {
        let p = DataPlanePolicy::new(
            vec![policy("acme", &[], &["gpt-x"])],
            vec![credential("acme", "k")],
        );
        let id = p.authenticate(Some("Bearer k")).expect("auth");
        assert_eq!(
            p.authorize(&id, Endpoint::ChatCompletions, "gpt-x"),
            Verdict::Deny(DenyReason::EndpointNotPermitted)
        );
    }

    #[test]
    fn deny_all_policy_rejects_everything() {
        let p = DataPlanePolicy::deny_all();
        assert_eq!(p.tenant_count(), 0);
        assert!(matches!(
            p.authenticate(Some("Bearer anything")),
            Err(AuthError::UnknownTenant)
        ));
    }

    #[test]
    fn unmatched_key_is_rejected_even_when_tenant_exists() {
        // คีย์ที่ไม่รู้จักต้องถูกปฏิเสธเสมอ การยอมรับคีย์ใด ๆ เป็นผู้เช่าที่ระบุ
        // จะเป็นการเปิดให้ผู้ใดก็ตามเข้ามาในฐานะนั้นโดยไม่ต้องมี credential
        let p = DataPlanePolicy::new(
            vec![policy("fallback", &["chat_completions"], &["gpt-x"])],
            vec![credential("fallback", "any-key")],
        );
        assert!(matches!(
            p.authenticate(Some("Bearer unrecognized-key")),
            Err(AuthError::UnknownTenant)
        ));
        // คีย์ที่ตรงกันจึงยังผ่านได้
        assert!(p.authenticate(Some("Bearer any-key")).is_ok());
    }

    #[test]
    fn prefix_of_valid_key_is_rejected() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("Bearer secret-key")),
            Err(AuthError::UnknownTenant)
        ));
    }

    #[test]
    fn longer_key_is_rejected() {
        let p = sample();
        assert!(matches!(
            p.authenticate(Some("Bearer secret-key-1-extra")),
            Err(AuthError::UnknownTenant)
        ));
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn parse_bearer_variants() {
        assert_eq!(parse_bearer("Bearer abc"), Some("abc"));
        assert_eq!(parse_bearer("apikey abc"), Some("abc"));
        assert_eq!(parse_bearer("Bearer  abc  "), Some("abc"));
        assert_eq!(parse_bearer("Basic abc"), None);
        assert_eq!(parse_bearer("abc"), None);
        assert_eq!(parse_bearer("Bearer "), None);
    }

    #[test]
    fn parse_endpoint_accepts_names_and_paths() {
        assert_eq!(parse_endpoint("embeddings"), Some("embeddings"));
        assert_eq!(
            parse_endpoint("/v1/chat/completions"),
            Some("chat_completions")
        );
        assert_eq!(parse_endpoint("nonsense"), None);
    }

    #[test]
    fn policy_file_round_trips_and_warns_on_unknown_endpoint() {
        let raw = r#"{
            "tenants": [
                {
                    "id": "acme",
                    "key": "k1",
                    "allowed_endpoints": ["chat_completions", "bogus_endpoint"],
                    "allowed_models": ["gpt-x"],
                    "max_concurrent": 4
                }
            ]
        }"#;
        let file: PolicyFile = serde_json::from_str(raw).expect("should parse");
        let (policy, warnings) = file.into_policy();
        assert_eq!(policy.tenant_count(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("bogus_endpoint"));
    }

    #[test]
    fn verdict_helpers() {
        assert!(Verdict::Allow.is_allowed());
        assert!(!Verdict::Deny(DenyReason::KeyExpired).is_allowed());
        assert_eq!(Verdict::Allow.deny_reason(), None);
        assert_eq!(
            Verdict::Deny(DenyReason::KeyExpired).deny_reason(),
            Some(DenyReason::KeyExpired)
        );
    }

    #[test]
    fn deny_reason_maps_from_error() {
        assert_eq!(
            DenyReason::from_error(&AuthError::KeyExpired),
            DenyReason::KeyExpired
        );
        assert_eq!(
            DenyReason::from_error(&AuthError::ConcurrencyLimit),
            DenyReason::ConcurrencyLimit
        );
    }

    #[test]
    fn deny_reason_strings_are_stable() {
        assert_eq!(DenyReason::UnknownTenant.as_str(), "unknown_tenant");
        assert_eq!(
            DenyReason::ModelNotPermitted.as_str(),
            "model_not_permitted"
        );
    }
}
