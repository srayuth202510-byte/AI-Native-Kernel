use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to open audit log")]
    Open(#[source] std::io::Error),
    #[error("failed to serialize audit entry")]
    Serialize(#[source] serde_json::Error),
    #[error("failed to write audit entry")]
    Write(#[source] std::io::Error),
    #[error("audit log validation failed")]
    ValidationFailed,
}

/// รายการบันทึกประวัติการตรวจสอบการเข้าใช้งานหรือการตัดสินใจด้านความปลอดภัย (Audit Entry)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// การกระทำที่เกิดขึ้น (เช่น "issued", "allowed", "denied")
    pub action: String,
    /// รหัสเฉพาะตัวของโทเค็นความสามารถที่เกี่ยวข้อง
    pub token_id: u64,
    /// เวลาที่เกิดการกระทำขึ้นในรูปแบบวินาทีสะสมนับตั้งแต่ UNIX Epoch
    pub timestamp: u64,
    /// Process ID ที่เกี่ยวข้อง (ถ้ามี)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// User ID ที่เกี่ยวข้อง (ถ้ามี)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// ชื่อ syscall ที่เกี่ยวข้อง (ถ้ามี)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall: Option<String>,
    /// Anomaly score จาก T-Cell (ถ้ามี)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_score: Option<f64>,
    /// เหตุผลในการตัดสินใจ (ถ้ามี)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// ลายเซ็นแฮชทางคริปโทกราฟีของ Entry และประวัติก่อนหน้า (Cryptographic Hash chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl AuditEntry {
    /// คำนวณค่าแฮชของรายการโดยผูกกับประวัติก่อนหน้าเพื่อตรวจสอบความถูกต้องแบบย้อนหลัง (Hash chaining)
    pub fn compute_hash(&self, previous_hash: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut temp = self.clone();
        temp.hash = None;
        let json_data = serde_json::to_vec(&temp).unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(&json_data);
        hasher.update(previous_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// สร้างข้อมูลบันทึกประวัติการตรวจสอบใหม่
    #[must_use]
    pub fn new(action: &str, token_id: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            action: action.to_string(),
            token_id,
            timestamp,
            pid: None,
            uid: None,
            syscall: None,
            anomaly_score: None,
            reason: None,
            hash: None,
        }
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "ออกโทเค็น" (Issued)
    #[must_use]
    pub fn issued(token_id: u64) -> Self {
        Self::new("issued", token_id)
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "อนุญาตให้เข้าใช้งาน" (Allowed)
    #[must_use]
    pub fn allowed(token_id: u64) -> Self {
        Self::new("allowed", token_id)
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "ปฏิเสธการเข้าใช้งาน" (Denied)
    #[must_use]
    pub fn denied(token_id: u64) -> Self {
        Self::new("denied", token_id)
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "เพิกถอนโทเค็น" (Revoked)
    #[must_use]
    pub fn revoked(token_id: u64) -> Self {
        Self::new("revoked", token_id)
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "ปฏิเสธ syscall" (Syscall Denied)
    #[must_use]
    pub fn syscall_denied(pid: u32, uid: u32, syscall: &str, reason: &str) -> Self {
        let mut entry = Self::new("syscall_denied", 0);
        entry.pid = Some(pid);
        entry.uid = Some(uid);
        entry.syscall = Some(syscall.to_string());
        entry.reason = Some(reason.to_string());
        entry
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "quarantine process" (Process Quarantined)
    #[must_use]
    pub fn process_quarantined(pid: u32, uid: u32, anomaly_score: f64, reason: &str) -> Self {
        let mut entry = Self::new("process_quarantined", 0);
        entry.pid = Some(pid);
        entry.uid = Some(uid);
        entry.anomaly_score = Some(anomaly_score);
        entry.reason = Some(reason.to_string());
        entry
    }

    /// สร้างข้อมูลบันทึกประวัติสำหรับการ "kill process" (Process Killed)
    #[must_use]
    pub fn process_killed(pid: u32, uid: u32, anomaly_score: f64, reason: &str) -> Self {
        let mut entry = Self::new("process_killed", 0);
        entry.pid = Some(pid);
        entry.uid = Some(uid);
        entry.anomaly_score = Some(anomaly_score);
        entry.reason = Some(reason.to_string());
        entry
    }
}

/// ตัวบันทึกข้อมูลการตรวจสอบการทำงานและความปลอดภัยลงในระบบจัดเก็บไฟล์ถาวร (Audit Logger)
#[derive(Debug, Clone)]
pub struct AuditLogger {
    /// พาธสำหรับจัดเก็บไฟล์บันทึกประวัติ (Log File)
    log_path: PathBuf,
    /// แฮชล่าสุดที่คำนวณและเขียนลงไฟล์แล้ว
    last_hash: std::sync::Arc<parking_lot::Mutex<Option<String>>>,
}

impl AuditLogger {
    /// สร้างตัวบันทึกข้อมูลการตรวจสอบ `AuditLogger` ใหม่พร้อมพาธของไฟล์ล็อก
    #[must_use]
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: std::sync::Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    fn get_last_hash_from_file(&self) -> String {
        if let Ok(file) = File::open(&self.log_path) {
            let reader = BufReader::new(file);
            let mut last_h = String::new();
            for line_str in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line_str) {
                    if let Some(h) = entry.hash {
                        last_h = h;
                    }
                }
            }
            last_h
        } else {
            String::new()
        }
    }

    /// บันทึกรายการตรวจสอบลงในไฟล์ล็อก พร้อมทำ Hash Chaining กับประวัติก่อนหน้า
    pub fn record(&self, mut entry: AuditEntry) -> Result<(), AuditError> {
        let mut cache = self.last_hash.lock();
        let prev_hash = match &*cache {
            Some(h) => h.clone(),
            None => {
                let h = self.get_last_hash_from_file();
                *cache = Some(h.clone());
                h
            }
        };

        let hash = entry.compute_hash(&prev_hash);
        entry.hash = Some(hash.clone());

        // เปิดไฟล์แบบเขียนต่อท้ายอย่างเดียว (append-only) และสร้างใหม่หากยังไม่มี
        // ซึ่งเป็นการทำงานรูปแบบ WORM (Write Once Read Many) ในระดับระบบปฏิบัติการเพื่อความปลอดภัยของข้อมูลประวัติ
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(AuditError::Open)?;
        let json_str = serde_json::to_string(&entry).map_err(AuditError::Serialize)?;
        writeln!(file, "{}", json_str).map_err(AuditError::Write)?;

        *cache = Some(hash);
        Ok(())
    }

    /// ดึงประวัติรายการการตรวจสอบทั้งหมดจากไฟล์ล็อก
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        if let Ok(file) = File::open(&self.log_path) {
            let reader = BufReader::new(file);
            for line_str in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line_str) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    /// ตรวจสอบความถูกต้องของสายโซ่แฮชทั้งหมด (Hash Chain Validation)
    /// คืนค่า Ok(true) หากข้อมูลไม่ถูกดัดแปลง หรือ Ok(false) หากประวัติถูกแก้ไข/ถูกแทรกแซง
    pub fn validate_log(&self) -> Result<bool, AuditError> {
        let entries = self.entries();
        if entries.is_empty() {
            return Ok(true);
        }

        let mut prev_hash = String::new();
        for entry in &entries {
            let Some(recorded_hash) = entry.hash.as_deref() else {
                return Ok(false);
            };
            let computed = entry.compute_hash(&prev_hash);
            if computed != recorded_hash {
                return Ok(false);
            }
            prev_hash = recorded_hash.to_string();
        }

        Ok(true)
    }
}

impl Default for AuditLogger {
    /// สร้างค่าเริ่มต้นสำหรับตัวบันทึกข้อมูล โดยกำหนดให้ไฟล์บันทึกเริ่มต้นชื่อ "audit.log"
    fn default() -> Self {
        Self::new(PathBuf::from("audit.log"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("ank-audit-{name}.log"));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn record_and_reload_entries_round_trip() {
        let path = test_log_path("round-trip");
        let logger = AuditLogger::new(path.clone());

        logger
            .record(AuditEntry::issued(1))
            .expect("first record should succeed");
        logger
            .record(AuditEntry::allowed(1))
            .expect("second record should succeed");

        let entries = logger.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "issued");
        assert_eq!(entries[1].action, "allowed");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn entries_skip_invalid_json_lines() {
        let path = test_log_path("skip-invalid");
        std::fs::write(
            &path,
            "{\"action\":\"issued\",\"token_id\":1,\"timestamp\":1}\nnot-json\n",
        )
        .expect("fixture log should be written");

        let logger = AuditLogger::new(path.clone());
        let entries = logger.entries();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].token_id, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn helper_constructors_use_expected_actions() {
        assert_eq!(AuditEntry::issued(1).action, "issued");
        assert_eq!(AuditEntry::allowed(1).action, "allowed");
        assert_eq!(AuditEntry::denied(1).action, "denied");
        assert_eq!(AuditEntry::revoked(1).action, "revoked");
    }

    #[test]
    fn test_audit_hash_chain_validation() {
        let path = test_log_path("validation");
        let logger = AuditLogger::new(path.clone());

        logger.record(AuditEntry::issued(10)).unwrap();
        logger.record(AuditEntry::allowed(20)).unwrap();
        logger.record(AuditEntry::denied(30)).unwrap();

        // 1. ตรวจสอบว่าแฮชเชนปกติผ่านฉลุย
        assert!(logger.validate_log().unwrap(), "normal log should be valid");

        // 2. จำลองการแก้ไขไฟล์ (tampering) ในแถวที่สอง
        let lines = std::fs::read_to_string(&path).unwrap();
        let mut lines_vec: Vec<String> = lines.lines().map(|s| s.to_string()).collect();
        // แก้ไข token_id ของบรรทัดที่สองจาก 20 เป็น 99
        lines_vec[1] = lines_vec[1].replace("\"token_id\":20", "\"token_id\":99");
        let new_content = lines_vec.join("\n") + "\n";
        std::fs::write(&path, new_content).unwrap();

        // 3. ตรวจสอบว่า validation จับได้ว่าโดนดัดแปลงข้อมูล
        assert!(
            !logger.validate_log().unwrap(),
            "tampered log should fail validation"
        );

        let _ = std::fs::remove_file(path);
    }
}
