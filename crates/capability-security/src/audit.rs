use crate::chained_log::{ChainEntry, ChainedLog, ChainedLogError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;
use thiserror::Error;

/// ข้อผิดพลาดจากการเขียน/ตรวจสอบไฟล์ audit log
#[derive(Debug, Error)]
pub enum AuditError {
    /// เปิดไฟล์ audit log ไม่สำเร็จ
    #[error("failed to open audit log")]
    Open(#[source] std::io::Error),
    /// แปลงรายการบันทึกเป็น JSON ไม่สำเร็จ
    #[error("failed to serialize audit entry")]
    Serialize(#[source] serde_json::Error),
    /// เขียนรายการบันทึกลงไฟล์ไม่สำเร็จ
    #[error("failed to write audit entry")]
    Write(#[source] std::io::Error),
    /// การอ่าน/เขียนไฟล์เกินเวลาที่กำหนด (ป้องกัน I/O ค้าง)
    #[error("audit I/O timed out")]
    Timeout,
    /// hash chain ของ log ไม่ต่อเนื่อง — ไฟล์อาจถูกแก้ไขหรือเสียหาย
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

/// Implement ChainEntry for AuditEntry to enable generic ChainedLog usage
impl ChainEntry for AuditEntry {
    fn compute_hash(&self, prev_hash: &str) -> String {
        // Use the existing compute_hash method
        self.compute_hash(prev_hash)
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = Some(hash);
    }

    fn hash(&self) -> Option<String> {
        self.hash.clone()
    }
}

/// ตัวบันทึกข้อมูลการตรวจสอบการทำงานและความปลอดภัยลงในระบบจัดเก็บไฟล์ถาวร (Audit Logger)
/// ใช้ ChainedLog<AuditEntry> ภายในเพื่อให้ได้กลไก hash chain แบบเจนริก
#[derive(Debug, Clone)]
pub struct AuditLogger {
    /// โครงสร้าง hash chain ภายใน
    inner: ChainedLog<AuditEntry>,
}

impl AuditLogger {
    /// สร้างตัวบันทึกข้อมูลการตรวจสอบ `AuditLogger` ใหม่พร้อมพาธของไฟล์ล็อก
    #[must_use]
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            inner: ChainedLog::new(log_path, "host-plane"),
        }
    }

    /// บันทึกรายการตรวจสอบลงในไฟล์ล็อก พร้อมทำ Hash Chaining กับประวัติก่อนหน้า
    ///
    /// # Errors
    /// คืน `Err` เมื่อเขียนไฟล์ไม่สำเร็จหรือเกินเวลา
    pub async fn record(&self, entry: AuditEntry) -> Result<(), AuditError> {
        self.inner.record(entry).await.map_err(|e| match e {
            ChainedLogError::Io(e) => AuditError::Write(e),
            ChainedLogError::Serialize(e) => AuditError::Serialize(e),
            ChainedLogError::Timeout => AuditError::Timeout,
            ChainedLogError::ValidationFailed => AuditError::ValidationFailed,
        })
    }

    /// ดึงประวัติรายการการตรวจสอบทั้งหมดจากไฟล์ล็อก
    pub async fn entries(&self) -> Vec<AuditEntry> {
        self.inner.entries().await
    }

    /// ตรวจสอบความถูกต้องของสายโซ่แฮชทั้งหมด (Hash Chain Validation)
    /// คืนค่า Ok(true) หากข้อมูลไม่ถูกดัดแปลง หรือ Ok(false) หากประวัติถูกแก้ไข/ถูกแทรกแซง
    ///
    /// # Errors
    /// คืน `Err` เมื่ออ่านไฟล์ไม่สำเร็จ
    pub async fn validate_log(&self) -> Result<bool, AuditError> {
        self.inner.validate().await.map_err(|e| match e {
            ChainedLogError::Io(e) => AuditError::Write(e),
            ChainedLogError::Serialize(e) => AuditError::Serialize(e),
            ChainedLogError::Timeout => AuditError::Timeout,
            ChainedLogError::ValidationFailed => AuditError::ValidationFailed,
        })
    }
}

impl Default for AuditLogger {
    /// สร้างค่าเริ่มต้นสำหรับตัวบันทึกข้อมูล โดยกำหนดให้ไฟล์บันทึกเริ่มต้นชื่อ "audit.log"
    fn default() -> Self {
        Self::new(PathBuf::from("audit.log"))
    }
}
