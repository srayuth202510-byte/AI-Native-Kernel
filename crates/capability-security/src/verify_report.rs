//! รายงานผลการตรวจสอบ hash chain สำหรับ SIEM (`ank verify-audit`)
//!
//! `verify-audit` มีสองคำสั่งที่ต้องออกรายงานรูปแบบเดียวกัน: `ank-cli verify-audit`
//! (host plane, ไฟล์เดียว) และ `ai-gateway verify-audit` (data plane, หนึ่งไฟล์ต่อ
//! shard) โมดูลนี้คือ schema กลาง — ทั้งสองฝั่งสร้าง [`VerifyReport`] ชุดเดียวกัน
//! SIEM จึง parse ด้วย parser เดียวได้ ไม่ต้องแยกตาม plane
//!
//! การตรวจสอบจริงทำผ่าน [`ChainedLog::validate`] เสมอ ไม่มีการเขียนอัลกอริทึมซ้ำ
//! ในแต่ละคำสั่ง เพราะอัลกอริทึมสองชุดที่ "ควรจะเหมือนกัน" จะค่อย ๆ ต่างกันไปเอง
use crate::chained_log::{ChainEntry, ChainedLog};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// ผลการตรวจ chain หนึ่งไฟล์ — หนึ่งรายการต่อ shard สำหรับ SIEM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    /// รหัส chain (`host-plane` สำหรับไฟล์ host, ชื่อไฟล์สำหรับ shard)
    pub chain_id: String,
    /// พาธของไฟล์ที่ตรวจ
    pub file: String,
    /// จำนวนรายการที่ถอดได้ (บรรทัดที่เสียถูกข้าม — ดู `ChainedLog::entries`)
    pub entries: usize,
    /// สายโซ่ถูกต้องครบทุกข้อหรือไม่
    pub valid: bool,
    /// เหตุผลเมื่อตรวจไม่ได้/ไม่ผ่าน (`None` เมื่อผ่าน)
    pub error: Option<String>,
}

/// รายงานรวมทั้งคำสั่ง verify — เอกสาร JSON หนึ่งฉบับต่อหนึ่งการรัน
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// คำสั่งที่ออกรายงาน (`ank-cli verify-audit` หรือ `ai-gateway verify-audit`)
    pub tool: String,
    /// เป้าหมายที่ตรวจ (ไฟล์ log หรือไดเรกทอรี shard)
    pub target: String,
    /// เวลาที่ตรวจเป็นวินาที UNIX epoch
    pub checked_at_unix: u64,
    /// ทุก chain ผ่านหรือไม่ (AND ของทุก chain — chain เดียวพังคือทั้งรายงานพัง)
    pub valid: bool,
    /// จำนวนรายการรวมทุก chain
    pub total_entries: usize,
    /// ผลราย chain
    pub chains: Vec<ChainReport>,
}

impl VerifyReport {
    /// เริ่มรายงานเปล่าสำหรับเป้าหมายหนึ่ง
    #[must_use]
    pub fn new(tool: &str, target: &Path) -> Self {
        Self {
            tool: tool.to_string(),
            target: target.display().to_string(),
            checked_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            valid: true,
            total_entries: 0,
            chains: Vec::new(),
        }
    }

    /// เพิ่มผลราย chain แล้วพับ `valid`/`total_entries` ให้ตรงกันเสมอ
    /// เพื่อไม่ให้ผู้เรียกต้องจำว่าต้อง AND เองแล้วลืม
    pub fn push(&mut self, chain: ChainReport) {
        // รายงานเปล่าที่ไม่มี chain เลยต้องไม่ถูกตีความว่าผ่าน — ผู้เรียกที่เจอ
        // ไดเรกทอรีว่างต้องตัดสินใจเองว่าจะ error (gateway ทำแบบนั้นอยู่แล้ว)
        self.valid = self.valid && chain.valid;
        self.total_entries += chain.entries;
        self.chains.push(chain);
    }

    /// แปลงเป็น JSON สำหรับ SIEM (pretty เพื่อให้คนอ่านได้ด้วย)
    ///
    /// # Errors
    /// คืน `Err` เมื่อ serialize ไม่สำเร็จ (ไม่ควรเกิดกับ struct นี้ แต่
    /// กฎของ repo ห้าม `unwrap` ในโค้ดที่ไม่ใช่เทสต์ จึงคืน `Result`)
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// ตรวจไฟล์ chain หนึ่งไฟล์ผ่าน [`ChainedLog::validate`] แล้วห่อเป็น [`ChainReport`]
///
/// ใช้กับ entry ทุกชนิดที่ implement [`ChainEntry`] จึงใช้ได้ทั้ง `AuditEntry`
/// (host plane) และ `ApiAuditEntry` (data plane) โดยไม่ต้องเขียนโค้ดตรวจซ้ำ
pub async fn verify_chain_file<E: ChainEntry>(path: &Path, chain_id: &str) -> ChainReport {
    let file = path.display().to_string();
    if !path.exists() {
        return ChainReport {
            chain_id: chain_id.to_string(),
            file,
            entries: 0,
            valid: false,
            error: Some("audit file not found".to_string()),
        };
    }
    let chain = ChainedLog::<E>::new(PathBuf::from(path), chain_id);
    match chain.validate().await {
        Ok(valid) => {
            let entries = chain.entries().await.len();
            ChainReport {
                chain_id: chain_id.to_string(),
                file,
                entries,
                valid,
                error: (!valid).then(|| "hash chain mismatch".to_string()),
            }
        }
        Err(e) => ChainReport {
            chain_id: chain_id.to_string(),
            file,
            entries: 0,
            valid: false,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEntry, AuditLogger};

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("verify-report-{name}-{}.jsonl", std::process::id()))
    }

    #[tokio::test]
    async fn valid_chain_reports_entries_and_no_error() {
        let path = temp_path("ok");
        let logger = AuditLogger::new(path.clone());
        logger.record(AuditEntry::allowed(1)).await.expect("record");
        logger.record(AuditEntry::allowed(2)).await.expect("record");

        let report = verify_chain_file::<AuditEntry>(&path, "host-plane").await;
        assert!(report.valid);
        assert_eq!(report.entries, 2);
        assert_eq!(report.error, None);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn tampered_chain_reports_invalid() {
        let path = temp_path("tampered");
        let logger = AuditLogger::new(path.clone());
        logger.record(AuditEntry::allowed(1)).await.expect("record");
        // แก้เนื้อหาบรรทัดแรกโดย JSON ยังถอดได้ — validate ต้องจับ hash ไม่ตรงได้
        let content = std::fs::read_to_string(&path).expect("read");
        let tampered = content.replacen("\"allowed\"", "\"forged!!\"", 1);
        assert_ne!(content, tampered, "test setup must actually change a line");
        std::fs::write(&path, tampered).expect("write");

        let report = verify_chain_file::<AuditEntry>(&path, "host-plane").await;
        assert!(!report.valid, "tampered line must break the chain");
        assert!(report.error.is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn missing_file_reports_invalid() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        let report = verify_chain_file::<AuditEntry>(&path, "host-plane").await;
        assert!(!report.valid);
        assert_eq!(report.entries, 0);
        assert!(report.error.is_some());
    }

    #[tokio::test]
    async fn empty_file_reports_valid_with_zero_entries() {
        let path = temp_path("empty");
        std::fs::write(&path, "").expect("write empty");
        let report = verify_chain_file::<AuditEntry>(&path, "host-plane").await;
        assert!(report.valid);
        assert_eq!(report.entries, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn report_json_round_trips_with_stable_fields() {
        // golden-shape: ฟิลด์ที่ SIEM ต้องพึ่งต้องคงที่ ชื่อเปลี่ยน = parser พัง
        let mut report =
            VerifyReport::new("ank-cli verify-audit", Path::new("/var/log/ank/audit.log"));
        report.push(ChainReport {
            chain_id: "host-plane".to_string(),
            file: "/var/log/ank/audit.log".to_string(),
            entries: 2,
            valid: true,
            error: None,
        });
        let json = report.to_json().expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse back");
        for field in [
            "tool",
            "target",
            "checked_at_unix",
            "valid",
            "total_entries",
            "chains",
        ] {
            assert!(
                value.get(field).is_some(),
                "top-level field {field} must exist, got {json}"
            );
        }
        assert_eq!(value["tool"], "ank-cli verify-audit");
        assert_eq!(value["valid"], true);
        assert_eq!(value["total_entries"], 2);
        assert_eq!(value["chains"][0]["chain_id"], "host-plane");
        assert!(value["checked_at_unix"].as_u64().is_some());
    }

    #[test]
    fn single_broken_chain_fails_the_whole_report() {
        let mut report = VerifyReport::new("ai-gateway verify-audit", Path::new("/tmp/audit"));
        report.push(ChainReport {
            chain_id: "acme".to_string(),
            file: "/tmp/audit/acme.jsonl".to_string(),
            entries: 10,
            valid: true,
            error: None,
        });
        assert!(report.valid);
        report.push(ChainReport {
            chain_id: "mallory".to_string(),
            file: "/tmp/audit/mallory.jsonl".to_string(),
            entries: 3,
            valid: false,
            error: Some("hash chain mismatch".to_string()),
        });
        assert!(!report.valid, "one broken shard must fail the report");
        assert_eq!(report.total_entries, 13);
    }
}
