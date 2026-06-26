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
}

/// รายการบันทึกประวัติการตรวจสอบการเข้าใช้งานหรือการตัดสินใจด้านความปลอดภัย (Audit Entry)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// การกระทำที่เกิดขึ้น (เช่น "issued", "allowed", "denied")
    pub action: String,
    /// รหัสเฉพาะตัวของโทเค็นความสามารถที่เกี่ยวข้อง
    pub token_id: u64,
    /// เวลาที่เกิดการกระทำขึ้นในรูปแบบวินาทีสะสมนับตั้งแต่ UNIX Epoch
    pub timestamp: u64,
}

impl AuditEntry {
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
}

/// ตัวบันทึกข้อมูลการตรวจสอบการทำงานและความปลอดภัยลงในระบบจัดเก็บไฟล์ถาวร (Audit Logger)
#[derive(Debug)]
pub struct AuditLogger {
    /// พาธสำหรับจัดเก็บไฟล์บันทึกประวัติ (Log File)
    log_path: PathBuf,
}

impl AuditLogger {
    /// สร้างตัวบันทึกข้อมูลการตรวจสอบ `AuditLogger` ใหม่พร้อมพาธของไฟล์ล็อก
    #[must_use]
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// บันทึกรายการตรวจสอบลงในไฟล์ล็อก
    pub fn record(&self, entry: AuditEntry) -> Result<(), AuditError> {
        // เปิดไฟล์แบบเขียนต่อท้ายอย่างเดียว (append-only) และสร้างใหม่หากยังไม่มี
        // ซึ่งเป็นการทำงานรูปแบบ WORM (Write Once Read Many) ในระดับระบบปฏิบัติการเพื่อความปลอดภัยของข้อมูลประวัติ
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(AuditError::Open)?;
        let json_str = serde_json::to_string(&entry).map_err(AuditError::Serialize)?;
        writeln!(file, "{}", json_str).map_err(AuditError::Write)?;
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
}

impl Default for AuditLogger {
    /// สร้างค่าเริ่มต้นสำหรับตัวบันทึกข้อมูล โดยกำหนดให้ไฟล์บันทึกเริ่มต้นชื่อ "audit.log"
    fn default() -> Self {
        Self::new(PathBuf::from("audit.log"))
    }
}
