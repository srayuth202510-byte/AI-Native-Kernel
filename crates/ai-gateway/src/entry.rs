//! รายการบันทึกเหตุการณ์ของ data plane (API audit entries)
//!
//! # ทำไมไม่ขยาย `capability_security::audit::AuditEntry`
//!
//! `AuditEntry` เป็นโครงสร้างรูปแบบ syscall — มี `pid`, `uid`, `syscall` และไม่มีที่ให้
//! `tenant`, `model`, `endpoint`, `request_id` หรือ `latency_ms` อีกทั้งสิ้น การยัดข้อมูล
//! API ลงในฟิลด์ `reason` เป็นการสูญเสียความหมายที่จะกลายเป็นภาระต่อทีมในอนาคต
//!
//! นอกจากนี้ `compute_hash` ของ `AuditEntry` แฮชโครงสร้างที่ serialize แล้ว การเพิ่ม
//! ฟิลด์จึง**เปลี่ยนแฮชของทุกรายการที่เขียนไว้แล้ว** และทำให้ `validate_log` ปฏิเสธ
//! audit log ของทุก deployment ที่อัปเกรดไบนารี
//!
//! ดังนั้นชนิดข้อมูลชุดใหม่นี้จึงแยกออกมาต่างหาก และใช้ ChainedLog แบบเจนริก
//! จาก `capability-security` แทนการเขียนซ้ำโค้ด hash chain

use capability_security::chained_log::{ChainEntry, ChainedLog, ChainedLogError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use thiserror::Error;

/// ข้อผิดพลาดของ audit chain ของ data plane
#[derive(Debug, Error)]
pub enum ApiAuditError {
    /// เปิดหรือเขียนไฟล์ไม่สำเร็จ
    #[error("api audit i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// serialize ไม่สำเร็จ
    #[error("api audit serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// I/O เกินเวลา
    #[error("api audit i/o timed out")]
    Timeout,
    /// hash chain ไม่ต่อเนื่อง — ถูกแก้ไขหรือเสียหาย
    #[error("api audit chain validation failed")]
    ValidationFailed,
}

impl From<ChainedLogError> for ApiAuditError {
    fn from(e: ChainedLogError) -> Self {
        match e {
            ChainedLogError::Io(e) => Self::Io(e),
            ChainedLogError::Serialize(e) => Self::Serialize(e),
            ChainedLogError::Timeout => Self::Timeout,
            ChainedLogError::ValidationFailed => Self::ValidationFailed,
        }
    }
}

/// การตัดสินใจที่บันทึกลง audit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiDecision {
    /// อนุญาต
    Allow,
    /// อนุญาตแต่ปิดบังข้อมูลบางส่วน
    Redacted,
    /// ปฏิเสธ
    Deny,
}

impl ApiDecision {
    /// ชื่อแบบคงที่สำหรับ metric label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Redacted => "redacted",
            Self::Deny => "deny",
        }
    }
}

/// รายการบันทึกเหตุการณ์หนึ่งรายการของ data plane
///
/// ทุกฟิลด์เป็นชนิดข้อมูลของ API โดยเฉพาะ ไม่มีฟิลด์ที่ต้อง "ยัด" จากโครงสร้าง
/// ของ host plane
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiAuditEntry {
    /// รหัสผู้เช่า
    pub tenant_id: String,
    /// รหัสคำขอที่สุ่มขึ้น ใช้เชื่อม request/response และตามหาในการสืบสวน
    pub request_id: String,
    /// เส้นทางที่เรียก
    pub endpoint: String,
    /// โมเดลที่ร้องขอ
    pub model: String,
    /// ผลการตัดสินใจ
    pub decision: ApiDecision,
    /// เหตุผลของการตัดสินใจ
    pub reason: String,
    /// เวลาแบบวินาทีนับจาก UNIX epoch
    pub timestamp: u64,
    /// เวลาที่ประมวลผลรวม เป็นมิลลิวินาที
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// จำนวนโทเคนของ prompt (ประมาณ)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    /// จำนวนโทเคนของคำตอบ
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    /// จำนวนรายการข้อมูลส่วนบุคคลที่ถูกปิดบัง
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_count: Option<u32>,
    /// รหัสกฎ injection ที่ตรงกัน (วงเล็ปคั่นด้วย comma)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_rules: Option<String>,
    /// ระดับความน่าสงสัยการขโมยโมเดล
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction_level: Option<String>,
    /// คะแนนความน่าสงสัยการขโมยโมเดล
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extraction_score: Option<f64>,
    /// รหัสของ shard ที่รายการนี้อยู่ — ใช้รวม timeline จากหลายผู้เช่า
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// แฮชของรายการนี้ ผูกกับรายการก่อนหน้าใน chain เดียวกัน
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl ApiAuditEntry {
    /// สร้างรายการบันทึกใหม่
    #[must_use]
    pub fn new(tenant_id: &str, request_id: &str, endpoint: &str, model: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            request_id: request_id.to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            decision: ApiDecision::Allow,
            reason: String::new(),
            timestamp: now_secs(),
            latency_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            redacted_count: None,
            injection_rules: None,
            extraction_level: None,
            extraction_score: None,
            chain_id: None,
            hash: None,
        }
    }

    /// ตั้งผลการตัดสินใจพร้อมเหตุผล
    #[must_use]
    pub fn with_decision(mut self, decision: ApiDecision, reason: &str) -> Self {
        self.decision = decision;
        self.reason = reason.to_string();
        self
    }

    /// คำนวณแฮชของรายการโดยผูกกับแฮชของรายการก่อนหน้า
    #[must_use]
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        let mut temp = self.clone();
        temp.hash = None;
        let json = serde_json::to_vec(&temp).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json);
        hasher.update(previous_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl ChainEntry for ApiAuditEntry {
    fn compute_hash(&self, previous_hash: &str) -> String {
        self.compute_hash(previous_hash)
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = Some(hash);
    }

    fn hash(&self) -> Option<String> {
        self.hash.clone()
    }

    fn set_chain_id(&mut self, chain_id: &str) {
        self.chain_id = Some(chain_id.to_string());
    }
}

/// เวลาปัจจุบันเป็นวินาทีนับจาก UNIX epoch
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// สร้าง `request_id` แบบสุ่มสำหรับเชื่อม request กับ response
#[must_use]
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Hash chain ของ data plane แยกต่อผู้เช่า (sharded per tenant)
///
/// ใช้ `ChainedLog<ApiAuditEntry>` จาก `capability-security` แทนการเขียนซ้ำ
/// โค้ด hash chain — ดูรายละเอียดที่ `capability_security::chained_log::ChainedLog`
pub type ApiAuditChain = ChainedLog<ApiAuditEntry>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("api-audit-{name}.jsonl"))
    }

    fn entry(tenant: &str, n: usize) -> ApiAuditEntry {
        ApiAuditEntry::new(tenant, &format!("req-{n}"), "chat_completions", "gpt-x")
            .with_decision(ApiDecision::Allow, "ok")
    }

    #[tokio::test]
    async fn records_and_reads_back() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t1");

        chain.record(entry("t1", 1)).await.expect("record");
        chain.record(entry("t1", 2)).await.expect("record");

        let entries = chain.entries().await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].request_id, "req-1");
        assert_eq!(entries[1].request_id, "req-2");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stamps_chain_id_on_every_entry() {
        let path = temp_path("chainid");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "tenant-7");
        chain.record(entry("tenant-7", 1)).await.expect("record");
        let entries = chain.entries().await;
        assert_eq!(entries[0].chain_id.as_deref(), Some("tenant-7"));
        assert_eq!(chain.chain_id(), "tenant-7");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn validates_untouched_chain() {
        let path = temp_path("valid");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t");
        for i in 0..5 {
            chain.record(entry("t", i)).await.expect("record");
        }
        assert!(chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn detects_tampering() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t");
        chain.record(entry("t", 1)).await.expect("record");
        chain.record(entry("t", 2)).await.expect("record");

        let content = std::fs::read_to_string(&path).expect("read");
        let tampered = content.replace("req-1", "req-9");
        std::fs::write(&path, tampered).expect("write");

        assert!(!chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn detects_deleted_entry() {
        let path = temp_path("delete");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t");
        for i in 0..4 {
            chain.record(entry("t", i)).await.expect("record");
        }
        let content = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        // ลบรายการกลางออก
        let kept = format!("{}\n{}\n", lines[0], lines[3]);
        std::fs::write(&path, kept).expect("write");

        assert!(
            !chain.validate().await.expect("validate"),
            "removing a middle entry must break the chain"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn resumes_chain_across_instances() {
        let path = temp_path("resume");
        let _ = std::fs::remove_file(&path);

        let first = ApiAuditChain::new(path.clone(), "t");
        first.record(entry("t", 1)).await.expect("record");
        drop(first);

        // instance ใหม่ต้องต่อ chain เดิม ไม่เริ่มใหม่
        let second = ApiAuditChain::new(path.clone(), "t");
        second.record(entry("t", 2)).await.expect("record");

        assert!(second.validate().await.expect("validate"));
        assert_eq!(second.entries().await.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn empty_chain_validates() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t");
        assert!(chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn repair_newline_after_truncated_write() {
        let path = temp_path("newline");
        // ไฟล์ที่จบด้วยข้อความไม่มี newline (จำลอง crash กลางเขียน)
        std::fs::write(&path, "{\"partial\":").expect("write");
        let chain = ApiAuditChain::new(path.clone(), "t");
        chain.record(entry("t", 1)).await.expect("record");

        let content = std::fs::read_to_string(&path).expect("read");
        // รายการใหม่ต้องขึ้นบรรทัดใหม่ ไม่ถูกต่อท้ายข้อความครึ่งท่อน
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected partial + new record, got {content:?}"
        );
        assert_eq!(lines[0], r#"{"partial":"#);
        // บรรทัดที่สองต้องเป็นรายการที่ถอดได้จริง
        let entry: ApiAuditEntry = serde_json::from_str(lines[1]).expect("new record parses");
        assert_eq!(entry.request_id, "req-1");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn records_deny_with_reason() {
        let path = temp_path("deny");
        let _ = std::fs::remove_file(&path);
        let chain = ApiAuditChain::new(path.clone(), "t");
        let e = ApiAuditEntry::new("t", "r1", "embeddings", "gpt-x")
            .with_decision(ApiDecision::Deny, "model_not_permitted");
        chain.record(e).await.expect("record");
        let entries = chain.entries().await;
        assert_eq!(entries[0].decision, ApiDecision::Deny);
        assert_eq!(entries[0].reason, "model_not_permitted");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hash_excludes_hash_field_itself() {
        let e = entry("t", 1);
        let h1 = e.compute_hash("");
        let mut with_hash = e.clone();
        with_hash.hash = Some("deadbeef".to_string());
        assert_eq!(with_hash.compute_hash(""), h1);
    }

    #[test]
    fn hash_depends_on_previous_hash() {
        let e = entry("t", 1);
        assert_ne!(e.compute_hash(""), e.compute_hash("prev"));
    }

    #[test]
    fn decision_strings_are_stable() {
        assert_eq!(ApiDecision::Allow.as_str(), "allow");
        assert_eq!(ApiDecision::Redacted.as_str(), "redacted");
        assert_eq!(ApiDecision::Deny.as_str(), "deny");
    }

    #[test]
    fn request_ids_are_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_ne!(a, b);
    }
}
