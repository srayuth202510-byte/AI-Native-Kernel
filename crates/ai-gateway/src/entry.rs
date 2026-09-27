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
//! ดังนั้นชนิดข้อมูลชุดใหม่นี้จึงแยกออกมาต่างหาก และ**แชร์เฉพาะกลไก hash chain**
//! ไม่ใช่ตัวข้อมูล — ดูรายละเอียดการแยกชิ้นส่วนใน `docs/pivot_ai_infra_security.md` §5

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// เวลาที่รอ I/O ของ audit chain
const AUDIT_IO_TIMEOUT: Duration = Duration::from_secs(5);

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
/// การแยกต่อผู้เช่ามีเหตุผลด้านประสิทธิภาพ ไม่ใช่เพราะความสะดวก —
/// `capability_security` ใช้ mutex เดียวทั้งระบบ ซึ่งเหมาะกับการเขียน audit
/// กี่รายการต่อวินาทีของ host plane แต่จะกลายเป็นคอขวดเมื่อใช้เป็น gateway
/// ที่รับหลายร้อยคำขอต่อวินาที (ดู `docs/pivot_ai_infra_security.md` §5)
///
/// แต่ละ shard ตรวจสอบความถูกต้องได้อย่างอิสระ และ `chain_id` ในแต่ละรายการ
/// เชื่อมกลับมาเป็น timeline เดียวได้
#[derive(Debug)]
pub struct ApiAuditChain {
    log_path: PathBuf,
    chain_id: String,
    last_hash: std::sync::Arc<parking_lot::Mutex<Option<String>>>,
    writer: std::sync::Arc<tokio::sync::Mutex<Option<tokio::fs::File>>>,
}

impl ApiAuditChain {
    /// สร้าง chain สำหรับผู้เช่าหนึ่งราย
    #[must_use]
    pub fn new(log_path: PathBuf, chain_id: &str) -> Self {
        Self {
            log_path,
            chain_id: chain_id.to_string(),
            last_hash: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// รหัสของ shard นี้
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// พาธของไฟล์ log ของ shard นี้
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// อ่านแฮชล่าสุดจากท้ายไฟล์โดยไม่อ่านทั้งไฟล์
    async fn last_hash_from_file(&self) -> String {
        const INITIAL_TAIL_CHUNK: u64 = 64 * 1024;
        let path = self.log_path.clone();

        let result = tokio::time::timeout(AUDIT_IO_TIMEOUT, async {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = tokio::fs::File::open(&path).await.ok()?;
            let len = file.metadata().await.ok()?.len();
            let mut chunk = INITIAL_TAIL_CHUNK;
            loop {
                let start = len.saturating_sub(chunk);
                file.seek(std::io::SeekFrom::Start(start)).await.ok()?;
                let mut buf = Vec::with_capacity((len - start) as usize);
                file.read_to_end(&mut buf).await.ok()?;
                let text = String::from_utf8_lossy(&buf);
                let text = if start > 0 {
                    match text.find('\n') {
                        Some(i) => &text[i + 1..],
                        None => "",
                    }
                } else {
                    &text
                };
                if let Some(h) = text
                    .lines()
                    .rev()
                    .filter_map(|l| serde_json::from_str::<ApiAuditEntry>(l).ok())
                    .find_map(|e| e.hash)
                {
                    return Some(h);
                }
                if start == 0 {
                    return None;
                }
                chunk *= 4;
            }
        })
        .await;

        match result {
            Ok(Some(h)) => h,
            _ => String::new(),
        }
    }

    /// ตรวจว่าไฟล์จบด้วย newline หรือไม่ (สัญญาณว่า crash กลางการเขียน)
    async fn ends_without_newline(path: &Path) -> bool {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let Ok(mut file) = tokio::fs::File::open(path).await else {
            return false;
        };
        let Ok(meta) = file.metadata().await else {
            return false;
        };
        if meta.len() == 0 {
            return false;
        }
        if file
            .seek(std::io::SeekFrom::Start(meta.len() - 1))
            .await
            .is_err()
        {
            return false;
        }
        let mut last = [0u8; 1];
        file.read_exact(&mut last).await.is_ok() && last[0] != b'\n'
    }

    /// บันทึกรายการลง chain
    ///
    /// # Errors
    /// คืน `Err` เมื่อเขียนไฟล์ไม่สำเร็จหรือเกินเวลา — ผู้เรียกต้องตัดสินใจแบบ
    /// fail-closed เมื่อ audit เขียนไม่ได้ เพราะการตัดสินใจที่ไม่ถูกบันทึก
    /// เท่ากับไม่มีการควบคุม
    pub async fn record(&self, mut entry: ApiAuditEntry) -> Result<(), ApiAuditError> {
        let mut guard = self.writer.lock().await;

        // คัดลอกแฮชออกมาให้จบก่อน await — การถือ `MutexGuard` ข้ามจุด await
        // จะทำให้เทาที่รออยู่หยุดกลางคัน และ task ที่ต้องการแฮชเดียวกันจะติดตาย
        let cached_hash: Option<String> = self.last_hash.lock().clone();
        let prev_hash = match cached_hash {
            Some(h) => h,
            None => {
                let h = self.last_hash_from_file().await;
                *self.last_hash.lock() = Some(h.clone());
                h
            }
        };

        entry.chain_id = Some(self.chain_id.clone());
        let hash = entry.compute_hash(&prev_hash);
        entry.hash = Some(hash.clone());

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        if guard.is_none() {
            let repair = Self::ends_without_newline(&self.log_path).await;
            let mut file = tokio::time::timeout(
                AUDIT_IO_TIMEOUT,
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_path),
            )
            .await
            .map_err(|_| ApiAuditError::Timeout)?
            .map_err(ApiAuditError::Io)?;
            if repair {
                file.write_all(b"\n").await.map_err(ApiAuditError::Io)?;
            }
            *guard = Some(file);
        }

        let Some(file) = guard.as_mut() else {
            return Err(ApiAuditError::Io(std::io::Error::other(
                "api audit writer unavailable",
            )));
        };

        let write_result = tokio::time::timeout(AUDIT_IO_TIMEOUT, async {
            file.write_all(line.as_bytes()).await?;
            file.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| ApiAuditError::Timeout)
        .and_then(|inner| inner.map_err(ApiAuditError::Io));

        if let Err(e) = write_result {
            // handle อาจอยู่ในสถานะครึ่ง ๆ — ทิ้งเพื่อให้เปิดใหม่ และล้าง cache
            // ไม่เช่นนั้นรายการถัดไปจะผูกกับ hash ของรายการที่เขียนไม่สำเร็จ
            *guard = None;
            *self.last_hash.lock() = None;
            return Err(e);
        }

        *self.last_hash.lock() = Some(hash);
        Ok(())
    }

    /// อ่านรายการทั้งหมดของ shard นี้
    pub async fn entries(&self) -> Vec<ApiAuditEntry> {
        let content =
            match tokio::time::timeout(AUDIT_IO_TIMEOUT, tokio::fs::read_to_string(&self.log_path))
                .await
            {
                Ok(Ok(c)) => c,
                _ => String::new(),
            };
        content
            .lines()
            .filter_map(|l| serde_json::from_str::<ApiAuditEntry>(l).ok())
            .collect()
    }

    /// ตรวจสอบความถูกต้องของ hash chain ทั้งหมด
    ///
    /// # Errors
    /// คืน `Err` เมื่ออ่านไฟล์ไม่สำเร็จ
    pub async fn validate(&self) -> Result<bool, ApiAuditError> {
        let entries = self.entries().await;
        if entries.is_empty() {
            return Ok(true);
        }
        let mut prev = String::new();
        for entry in &entries {
            let Some(recorded) = entry.hash.as_deref() else {
                return Ok(false);
            };
            if entry.compute_hash(&prev) != recorded {
                return Ok(false);
            }
            prev = recorded.to_string();
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
