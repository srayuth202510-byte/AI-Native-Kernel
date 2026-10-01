//! รายงานผลการตรวจสอบ hash chain สำหรับ SIEM (`ank verify-audit`)
//!
//! `verify-audit` มีสองคำสั่งที่ต้องออกรายงานรูปแบบเดียวกัน: `ank-cli verify-audit`
//! (host plane, ไฟล์เดียว) และ `ai-gateway verify-audit` (data plane, หนึ่งไฟล์ต่อ
//! shard) โมดูลนี้คือ schema กลาง — ทั้งสองฝั่งสร้าง [`VerifyReport`] ชุดเดียวกัน
//! SIEM จึง parse ด้วย parser เดียวได้ ไม่ต้องแยกตาม plane
//!
//! การตรวจสอบจริงทำผ่าน [`ChainedLog::validate`] เสมอ ไม่มีการเขียนอัลกอริทึมซ้ำ
//! ในแต่ละคำสั่ง เพราะอัลกอริทึมสองชุดที่ "ควรจะเหมือนกัน" จะค่อย ๆ ต่างกันไปเอง
//!
//! ## ข้อจำกัดที่ต้องรู้: ตรวจการตัดทิ้ง (truncation) ไม่ได้
//!
//! hash chain ตรวจได้แค่ "สิ่งที่เหลืออยู่ต่อเนื่องกันหรือไม่" — การลบ entry ท้ายไฟล์
//! ทิ้ง (หรือ truncate เหลือ 0 ไบต์) ทำให้ส่วนที่เหลือยัง valid อยู่ดี ไฟล์ว่างจึง
//! รายงาน `valid: true` เสมอ รายงานนี้ไม่เคยแปลว่า "ไม่มีอะไรหาย" ให้ตรวจขนาดไฟล์
//! และรอบ rotation จากภายนอกประกอบ และทุกครั้งที่ `total_entries == 0` ทั้งสอง CLI
//! จะพิมพ์คำเตือนผ่าน [`VerifyReport::empty_log_warning`] (ดู test ประกอบ)
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

    /// คำเตือนเมื่อ log ว่าง — คืน `Some` เมื่อ `total_entries == 0`
    ///
    /// ไฟล์ว่าง (หรือถูก truncate เหลือ 0 บรรทัด) จะ valid เสมอตามนิยามของ
    /// hash chain ทั้งสอง CLI ต้องพิมพ์คำเตือนนี้ทาง stderr ทุกครั้ง ไม่ว่า
    /// `--format` จะเป็นอะไร เพื่อไม่ให้ `valid: true` ถูกอ่านว่า "ไม่มีอะไรหาย"
    #[must_use]
    pub fn empty_log_warning(&self) -> Option<&'static str> {
        if self.total_entries == 0 {
            Some(
                "log is empty: hash chains cannot detect truncation to empty — \
                 check file size and rotation externally",
            )
        } else {
            None
        }
    }
}

/// ตรวจไฟล์ chain หนึ่งไฟล์ผ่าน [`ChainedLog::validate`] แล้วห่อเป็น [`ChainReport`]
///
/// ใช้กับ entry ทุกชนิดที่ implement [`ChainEntry`] จึงใช้ได้ทั้ง `AuditEntry`
/// (host plane) และ `ApiAuditEntry` (data plane) โดยไม่ต้องเขียนโค้ดตรวจซ้ำ
pub async fn verify_chain_file<E: ChainEntry>(path: &Path, chain_id: &str) -> ChainReport {
    let (report, _) = verify_chain_with_hashes::<E>(path, chain_id).await;
    report
}

/// ตรวจไฟล์ chain พร้อมคืนลำดับแฮช — ใช้ภายในสำหรับการเทียบ checkpoint
async fn verify_chain_with_hashes<E: ChainEntry>(
    path: &Path,
    chain_id: &str,
) -> (ChainReport, Vec<String>) {
    let file = path.display().to_string();
    if !path.exists() {
        return (
            ChainReport {
                chain_id: chain_id.to_string(),
                file,
                entries: 0,
                valid: false,
                error: Some("audit file not found".to_string()),
            },
            Vec::new(),
        );
    }
    let chain = ChainedLog::<E>::new(PathBuf::from(path), chain_id);
    match chain.validate().await {
        Ok(valid) => {
            let entries = chain.entries().await;
            let hashes: Vec<String> = entries.iter().filter_map(|e| ChainEntry::hash(e)).collect();
            let report = ChainReport {
                chain_id: chain_id.to_string(),
                file,
                entries: entries.len(),
                valid,
                error: (!valid).then(|| "hash chain mismatch".to_string()),
            };
            (report, hashes)
        }
        Err(e) => (
            ChainReport {
                chain_id: chain_id.to_string(),
                file,
                entries: 0,
                valid: false,
                error: Some(e.to_string()),
            },
            Vec::new(),
        ),
    }
}

/// จุดตรวจภายนอกของ chain หนึ่งไฟล์ — จำจำนวน entry และแฮชล่าสุดไว้
///
/// hash chain ตรวจ "ความต่อเนื่องของสิ่งที่เหลือ" ได้ แต่ตรวจ "สิ่งที่หายไป"
/// ไม่ได้ การเทียบกับ checkpoint ที่บันทึกไว้คราวก่อนจึงเป็นวิธีเดียวที่จับ
/// การตัดทิ้ง (truncation) หรือเขียนประวัติใหม่ โดยไม่ต้องไว้ใจไฟล์ log เอง
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    /// ไฟล์ที่ checkpoint นี้เป็นของ
    pub file: String,
    /// จำนวน entry ตอนบันทึก
    pub entries: usize,
    /// แฮชของ entry สุดท้ายตอนบันทึก (ว่างเมื่อ chain ว่าง)
    pub last_hash: String,
}

/// ชุด checkpoint ทุก chain — ไฟล์ JSON ที่ verifier เก็บไว้นอก log
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    /// checkpoint รายไฟล์
    pub chains: Vec<ChainCheckpoint>,
}

impl AuditCheckpoint {
    /// ค้นหา checkpoint ของไฟล์ (ถ้าเคยบันทึกไว้)
    #[must_use]
    pub fn find(&self, file: &str) -> Option<&ChainCheckpoint> {
        self.chains.iter().find(|c| c.file == file)
    }

    /// บันทึก/แทนที่ checkpoint ของไฟล์
    pub fn upsert(&mut self, entry: ChainCheckpoint) {
        if let Some(slot) = self.chains.iter_mut().find(|c| c.file == entry.file) {
            *slot = entry;
        } else {
            self.chains.push(entry);
        }
    }

    /// โหลดจากไฟล์ — ไฟล์ไม่มีถือเป็นรอบแรก (ว่าง) ไม่ใช่ error
    ///
    /// # Errors
    /// คืน `Err` เมื่อไฟล์มีอยู่แต่อ่าน/ถอดไม่ได้ ผู้เรียกควรเตือนแล้วตรวจต่อ
    /// แบบไม่มี checkpoint ดีกว่าล้มทั้งคำสั่งเพราะไฟล์ state เสีย
    pub async fn load(path: &Path) -> Result<Self, String> {
        match tokio::fs::read_to_string(path).await {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("parse checkpoint: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("read checkpoint: {e}")),
        }
    }

    /// บันทึกลงไฟล์
    ///
    /// # Errors
    /// คืน `Err` เมื่อเขียนไม่สำเร็จ
    pub async fn save(&self, path: &Path) -> Result<(), String> {
        let text =
            serde_json::to_string_pretty(self).map_err(|e| format!("serialize checkpoint: {e}"))?;
        tokio::fs::write(path, text)
            .await
            .map_err(|e| format!("write checkpoint: {e}"))?;
        Ok(())
    }
}

/// ตรวจไฟล์ chain พร้อมเทียบ checkpoint ภายนอก
///
/// คืนรายงาน (ที่ทำเครื่องหมาย `valid: false` แล้วเมื่อเจอ truncation/rewrite)
/// กับ checkpoint ใหม่สำหรับรอบนี้ ผู้เรียกควรบันทึก checkpoint ใหม่**เฉพาะเมื่อ
/// รายงาน valid** — บันทึกทับตอน chain พังเท่ากับรับรองประวัติที่พังเป็น baseline
pub async fn verify_chain_checked<E: ChainEntry>(
    path: &Path,
    chain_id: &str,
    checkpoint: &AuditCheckpoint,
) -> (ChainReport, ChainCheckpoint) {
    let (mut report, hashes) = verify_chain_with_hashes::<E>(path, chain_id).await;
    let fresh = ChainCheckpoint {
        file: path.display().to_string(),
        entries: hashes.len(),
        last_hash: hashes.last().cloned().unwrap_or_default(),
    };
    // เทียบเฉพาะตอน validate ผ่าน — ถ้า chain พังอยู่แล้ว error เดิมสำคัญกว่า
    if report.valid {
        if let Some(prev) = checkpoint.find(&fresh.file) {
            if hashes.len() < prev.entries {
                report.valid = false;
                report.error = Some(format!(
                    "truncation detected: entries decreased {} -> {}",
                    prev.entries,
                    hashes.len()
                ));
            } else if !prev.last_hash.is_empty() && !hashes.contains(&prev.last_hash) {
                report.valid = false;
                report.error =
                    Some("history rewritten: checkpoint hash not found in chain".to_string());
            }
        }
    }
    (report, fresh)
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

    #[test]
    fn empty_report_warns_about_undetectable_truncation() {
        // ไฟล์ว่าง valid เสมอ — ต้องมีคำเตือน ไม่ใช่ความเงียบ
        let report = VerifyReport::new("ank-cli verify-audit", Path::new("/var/log/ank/audit.log"));
        assert_eq!(report.total_entries, 0);
        assert!(
            report.empty_log_warning().is_some(),
            "empty log must warn: truncation to empty is undetectable"
        );

        let mut report =
            VerifyReport::new("ank-cli verify-audit", Path::new("/var/log/ank/audit.log"));
        report.push(ChainReport {
            chain_id: "host-plane".to_string(),
            file: "/var/log/ank/audit.log".to_string(),
            entries: 1,
            valid: true,
            error: None,
        });
        assert_eq!(report.empty_log_warning(), None);
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    fn checkpoint(entries: usize, last_hash: &str) -> AuditCheckpoint {
        AuditCheckpoint {
            chains: vec![ChainCheckpoint {
                file: "/tmp/audit.log".to_string(),
                entries,
                last_hash: last_hash.to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn append_only_growth_passes_checkpoint() {
        let dir = std::env::temp_dir().join("ckpt-growth");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("audit.log");

        let logger = crate::audit::AuditLogger::new(path.clone());
        logger
            .record(crate::audit::AuditEntry::allowed(1))
            .await
            .expect("record");
        logger
            .record(crate::audit::AuditEntry::allowed(2))
            .await
            .expect("record");

        // รอบแรก: ไม่มี checkpoint มาก่อน → ผ่านและได้ baseline
        let empty = AuditCheckpoint::default();
        let (report, fresh) =
            verify_chain_checked::<crate::audit::AuditEntry>(&path, "host-plane", &empty).await;
        assert!(report.valid);
        assert_eq!(fresh.entries, 2);
        assert!(!fresh.last_hash.is_empty());

        // รอบสอง: ต่อท้ายอีก entry — ต้องผ่านเทียบกับ baseline
        logger
            .record(crate::audit::AuditEntry::allowed(3))
            .await
            .expect("record");
        let saved = AuditCheckpoint {
            chains: vec![fresh],
        };
        let (report, _) =
            verify_chain_checked::<crate::audit::AuditEntry>(&path, "host-plane", &saved).await;
        assert!(report.valid, "append-only growth must pass: {report:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn truncated_tail_is_detected() {
        let dir = std::env::temp_dir().join("ckpt-truncate");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("audit.log");

        let logger = crate::audit::AuditLogger::new(path.clone());
        for id in 1..=3u64 {
            logger
                .record(crate::audit::AuditEntry::allowed(id))
                .await
                .expect("record");
        }
        let (report, fresh) = verify_chain_checked::<crate::audit::AuditEntry>(
            &path,
            "host-plane",
            &AuditCheckpoint::default(),
        )
        .await;
        assert!(report.valid);
        let saved = AuditCheckpoint {
            chains: vec![fresh],
        };

        // ตัด entry ท้ายทิ้ง — chain ที่เหลือยัง valid ในตัวเอง แต่สั้นลง
        let content = std::fs::read_to_string(&path).expect("read");
        let mut lines: Vec<&str> = content.lines().collect();
        lines.pop();
        std::fs::write(&path, lines.join("\n") + "\n").expect("write");

        let (report, _) =
            verify_chain_checked::<crate::audit::AuditEntry>(&path, "host-plane", &saved).await;
        assert!(!report.valid, "truncated tail must fail");
        assert!(
            report.error.as_deref().unwrap_or("").contains("truncation"),
            "error must say truncation, got {:?}",
            report.error
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rewritten_history_is_detected() {
        let dir = std::env::temp_dir().join("ckpt-rewrite");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("audit.log");

        let logger = crate::audit::AuditLogger::new(path.clone());
        for id in 1..=2u64 {
            logger
                .record(crate::audit::AuditEntry::allowed(id))
                .await
                .expect("record");
        }
        let (_, fresh) = verify_chain_checked::<crate::audit::AuditEntry>(
            &path,
            "host-plane",
            &AuditCheckpoint::default(),
        )
        .await;
        let saved = AuditCheckpoint {
            chains: vec![fresh],
        };

        // เขียนประวัติใหม่จำนวนเท่าเดิมแต่เนื้อหาต่าง (hash เปลี่ยนหมด)
        let logger2 = crate::audit::AuditLogger::new(path.clone());
        let _ = std::fs::remove_file(&path);
        for id in 11..=12u64 {
            logger2
                .record(crate::audit::AuditEntry::denied(id))
                .await
                .expect("record");
        }

        let (report, _) =
            verify_chain_checked::<crate::audit::AuditEntry>(&path, "host-plane", &saved).await;
        assert!(!report.valid, "rewritten history must fail");
        assert!(
            report.error.as_deref().unwrap_or("").contains("rewritten"),
            "error must say rewritten, got {:?}",
            report.error
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn checkpoint_save_load_round_trips() {
        let dir = std::env::temp_dir().join("ckpt-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("checkpoint.json");

        let cp = checkpoint(7, "abc123");
        cp.save(&path).await.expect("save");
        let loaded = AuditCheckpoint::load(&path).await.expect("load");
        assert_eq!(loaded, cp);

        // ไฟล์ไม่มี = รอบแรก ไม่ใช่ error
        let missing = AuditCheckpoint::load(&dir.join("nope.json")).await;
        assert_eq!(missing, Ok(AuditCheckpoint::default()));

        // ไฟล์เสีย = error (ผู้เรียกต้องเตือนแล้วตรวจต่อ ไม่ใช่ล้ม)
        std::fs::write(dir.join("bad.json"), "{oops").expect("write");
        assert!(AuditCheckpoint::load(&dir.join("bad.json")).await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
