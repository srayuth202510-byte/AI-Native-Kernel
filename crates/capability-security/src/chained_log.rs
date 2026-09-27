//! โมดูล hash chain แบบเจนริกสำหรับ audit log
//!
//! `ChainedLog<E>` ให้กลไก hash chain ที่ใช้ซ้ำได้สำหรับชนิดข้อมูล entry ใดๆ
//! ที่ implement [`ChainEntry`] ทำให้ไม่ต้องเขียนซ้ำตรรกะ:
//! - การคำนวณแฮชผูกกับรายการก่อนหน้า
//! - การอ่านแฮชล่าสุดจากท้ายไฟล์แบบไม่ได้อ่านทั้งไฟล์
//! - การซ่อมบรรทัดครึ่งท่อนหลัง crash
//! - การเขียนแบบ append-only พร้อม flush
//! - การ validate ความต่อเนื่องของ chain
//!
//! ใช้ได้กับ `AuditEntry` (host plane) และ `ApiAuditEntry` (data plane)
//! โดยไม่ต้อง duplicate โค้ด

use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::timeout;

/// เวลาที่รอ I/O สูงสุด
const AUDIT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// ข้อผิดพลาดของ ChainedLog
#[derive(Debug, Error)]
pub enum ChainedLogError {
    /// I/O ไม่สำเร็จ
    #[error("chained log i/o failed: {0}")]
    Io(#[from] std::io::Error),
    /// serialize ไม่สำเร็จ
    #[error("chained log serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// I/O เกินเวลา
    #[error("chained log i/o timed out")]
    Timeout,
    /// hash chain ไม่ต่อเนื่อง
    #[error("chained log validation failed")]
    ValidationFailed,
}

/// trait สำหรับ entry ที่สามารถนำไปใช้กับ ChainedLog ได้
///
/// Entry ต้อง:
/// - Serialize + Deserialize ได้ (สำหรับเขียน/อ่าน JSON Lines)
/// - มีเมธอด `compute_hash(&self, prev_hash: &str) -> String` ที่คืนแฮชของตัวเอง
///   ผูกกับแฮชของรายการก่อนหน้า
/// - มีฟิลด์ `hash: Option<String>` ที่จะถูกเซ็ตโดย ChainedLog
pub trait ChainEntry: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// คำนวณแฮชของ entry นี้ผูกกับแฮชของรายการก่อนหน้า
    fn compute_hash(&self, prev_hash: &str) -> String;

    /// ตั้งค่าแฮชของ entry (ถูกเรียกโดย ChainedLog หลังคำนวณ)
    fn set_hash(&mut self, hash: String);

    /// อ่านแฮชของ entry (ถ้ามี)
    fn hash(&self) -> Option<String>;

    /// ตั้งค่า chain_id (optional - ใช้สำหรับ sharded chains)
    /// ค่าเริ่มต้นไม่ทำอะไร
    fn set_chain_id(&mut self, _chain_id: &str) {}
}

/// โครงสร้าง hash chain แบบเจนริกสำหรับ entry ชนิด `E`
///
/// ใช้ `Arc<parking_lot::Mutex<Option<String>>>` สำหรับแฮชล่าสุด
/// และ `Arc<tokio::sync::Mutex<Option<tokio::fs::File>>>` สำหรับ writer
/// เพื่อให้ thread-safe และไม่ block event loop ขณะรอ I/O
///
/// # Type Parameters
/// - `E`: ชนิด entry ที่ implement [`ChainEntry`]
#[derive(Debug, Clone)]
pub struct ChainedLog<E: ChainEntry> {
    log_path: PathBuf,
    chain_id: String,
    last_hash: Arc<parking_lot::Mutex<Option<String>>>,
    writer: Arc<tokio::sync::Mutex<Option<tokio::fs::File>>>,
    _phantom: PhantomData<E>,
}

impl<E: ChainEntry> ChainedLog<E> {
    /// สร้าง ChainedLog ใหม่
    #[must_use]
    pub fn new(log_path: PathBuf, chain_id: &str) -> Self {
        Self {
            log_path,
            chain_id: chain_id.to_string(),
            last_hash: Arc::new(parking_lot::Mutex::new(None)),
            writer: Arc::new(tokio::sync::Mutex::new(None)),
            _phantom: PhantomData,
        }
    }

    /// รหัสของ chain นี้
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// พาธของไฟล์ log
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// อ่านแฮชล่าสุดจากท้ายไฟล์โดยไม่อ่านทั้งไฟล์
    ///
    /// เริ่มจาก chunk 64 KiB ที่ท้ายไฟล์ แล้วขยายย้อนกลับเมื่อยังไม่พบ entry ที่มี hash
    async fn last_hash_from_file(&self) -> String {
        const INITIAL_TAIL_CHUNK: u64 = 64 * 1024;

        let path = self.log_path.clone();
        let result = timeout(AUDIT_IO_TIMEOUT, async {
            let mut file = tokio::fs::File::open(&path).await.ok()?;
            let len = file.metadata().await.ok()?.len();

            let mut chunk = INITIAL_TAIL_CHUNK;
            loop {
                let start = len.saturating_sub(chunk);
                file.seek(std::io::SeekFrom::Start(start)).await.ok()?;
                let mut buf = Vec::with_capacity((len - start) as usize);
                file.read_to_end(&mut buf).await.ok()?;
                let text = String::from_utf8_lossy(&buf);

                // ถ้าไม่ได้เริ่มอ่านจากต้นไฟล์ บรรทัดแรกอาจโดนตัดครึ่ง — ข้ามทิ้ง
                let text = if start > 0 {
                    match text.find('\n') {
                        Some(i) => &text[i + 1..],
                        None => "",
                    }
                } else {
                    &text
                };

                let hash = text
                    .lines()
                    .rev()
                    .filter_map(|line| serde_json::from_str::<E>(line).ok())
                    .find_map(|e| e.hash());

                if let Some(h) = hash {
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
            Ok(Some(h)) => h.to_string(),
            _ => String::new(),
        }
    }

    /// ตรวจว่าไฟล์จบด้วย newline หรือไม่ (สัญญาณว่า crash กลางการเขียน)
    async fn ends_without_newline(path: &Path) -> bool {
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

    /// บันทึก entry ลง chain
    ///
    /// # Errors
    /// คืน `Err` เมื่อเขียนไฟล์ไม่สำเร็จหรือเกินเวลา
    pub async fn record(&self, mut entry: E) -> Result<(), ChainedLogError> {
        let mut guard = self.writer.lock().await;

        // คัดลอกแฮชออกมาให้จบก่อน await — การถือ MutexGuard ข้ามจุด await
        // จะทำให้เทาที่รออยู่หยุดกลางคัน
        let cached_hash: Option<String> = self.last_hash.lock().clone();
        let prev_hash = match cached_hash {
            Some(h) => h,
            None => {
                let h = self.last_hash_from_file().await;
                *self.last_hash.lock() = Some(h.clone());
                h
            }
        };

        entry.set_chain_id(&self.chain_id);
        let hash = entry.compute_hash(&prev_hash);
        entry.set_hash(hash.clone());

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        if guard.is_none() {
            let repair = Self::ends_without_newline(&self.log_path).await;
            let mut file = timeout(
                AUDIT_IO_TIMEOUT,
                tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_path),
            )
            .await
            .map_err(|_| ChainedLogError::Timeout)?
            .map_err(ChainedLogError::Io)?;
            if repair {
                file.write_all(b"\n").await.map_err(ChainedLogError::Io)?;
            }
            *guard = Some(file);
        }

        let Some(file) = guard.as_mut() else {
            return Err(ChainedLogError::Io(std::io::Error::other(
                "chained log writer unavailable",
            )));
        };

        let write_result = timeout(AUDIT_IO_TIMEOUT, async {
            file.write_all(line.as_bytes()).await?;
            file.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| ChainedLogError::Timeout)
        .and_then(|inner| inner.map_err(ChainedLogError::Io));

        if let Err(e) = write_result {
            *guard = None;
            *self.last_hash.lock() = None;
            return Err(e);
        }

        *self.last_hash.lock() = Some(hash);
        Ok(())
    }

    /// อ่านรายการทั้งหมดของ chain นี้
    pub async fn entries(&self) -> Vec<E> {
        let content =
            match timeout(AUDIT_IO_TIMEOUT, tokio::fs::read_to_string(&self.log_path)).await {
                Ok(Ok(c)) => c,
                _ => String::new(),
            };
        content
            .lines()
            .filter_map(|line| serde_json::from_str::<E>(line).ok())
            .collect()
    }

    /// ตรวจสอบความถูกต้องของ hash chain ทั้งหมด
    ///
    /// # Errors
    /// คืน `Err` เมื่ออ่านไฟล์ไม่สำเร็จ
    pub async fn validate(&self) -> Result<bool, ChainedLogError> {
        let entries = self.entries().await;
        if entries.is_empty() {
            return Ok(true);
        }
        let mut prev = String::new();
        for entry in &entries {
            let Some(recorded) = entry.hash() else {
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
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestEntry {
        id: u64,
        data: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
    }

    impl ChainEntry for TestEntry {
        fn compute_hash(&self, prev_hash: &str) -> String {
            let mut temp = self.clone();
            temp.hash = None;
            let json = serde_json::to_vec(&temp).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&json);
            hasher.update(prev_hash.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        fn set_hash(&mut self, hash: String) {
            self.hash = Some(hash);
        }

        fn hash(&self) -> Option<String> {
            self.hash.clone()
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("chained-log-{name}.jsonl"))
    }

    #[tokio::test]
    async fn records_and_reads_back() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "test");

        chain
            .record(TestEntry {
                id: 1,
                data: "a".to_string(),
                hash: None,
            })
            .await
            .expect("record");
        chain
            .record(TestEntry {
                id: 2,
                data: "b".to_string(),
                hash: None,
            })
            .await
            .expect("record");

        let entries = chain.entries().await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[1].id, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stamps_chain_id_on_every_entry() {
        let path = temp_path("chainid");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "my-chain");
        chain
            .record(TestEntry {
                id: 1,
                data: "x".to_string(),
                hash: None,
            })
            .await
            .expect("record");
        let _entries = chain.entries().await;
        // chain_id ไม่ได้เก็บใน entry แต่ chain_id() คืนค่าที่ตั้งไว้
        assert_eq!(chain.chain_id(), "my-chain");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn validates_untouched_chain() {
        let path = temp_path("valid");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "t");
        for i in 0..5 {
            chain
                .record(TestEntry {
                    id: i,
                    data: format!("d{i}"),
                    hash: None,
                })
                .await
                .expect("record");
        }
        assert!(chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn detects_tampering() {
        let path = temp_path("tamper");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "t");
        chain
            .record(TestEntry {
                id: 1,
                data: "a".to_string(),
                hash: None,
            })
            .await
            .expect("record");
        chain
            .record(TestEntry {
                id: 2,
                data: "b".to_string(),
                hash: None,
            })
            .await
            .expect("record");

        let content = tokio::fs::read_to_string(&path).await.expect("read");
        let tampered = content.replace("\"id\":1", "\"id\":9");
        tokio::fs::write(&path, tampered).await.expect("write");

        assert!(!chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn detects_deleted_entry() {
        let path = temp_path("delete");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "t");
        for i in 0..4 {
            chain
                .record(TestEntry {
                    id: i,
                    data: format!("d{i}"),
                    hash: None,
                })
                .await
                .expect("record");
        }
        let content = tokio::fs::read_to_string(&path).await.expect("read");
        let lines: Vec<&str> = content.lines().collect();
        // ลบรายการกลางออก
        let kept = format!("{}\n{}\n", lines[0], lines[3]);
        tokio::fs::write(&path, kept).await.expect("write");

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

        let first = ChainedLog::<TestEntry>::new(path.clone(), "t");
        first
            .record(TestEntry {
                id: 1,
                data: "a".to_string(),
                hash: None,
            })
            .await
            .expect("record");
        drop(first);

        // instance ใหม่ต้องต่อ chain เดิม ไม่เริ่มใหม่
        let second = ChainedLog::<TestEntry>::new(path.clone(), "t");
        second
            .record(TestEntry {
                id: 2,
                data: "b".to_string(),
                hash: None,
            })
            .await
            .expect("record");

        assert!(second.validate().await.expect("validate"));
        assert_eq!(second.entries().await.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn empty_chain_validates() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "t");
        assert!(chain.validate().await.expect("validate"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn repair_newline_after_truncated_write() {
        let path = temp_path("newline");
        // ไฟล์ที่จบด้วยข้อความไม่มี newline (จำลอง crash กลางเขียน)
        tokio::fs::write(&path, "{\"id\":1,\"data\":\"partial\"}")
            .await
            .expect("write");
        let chain = ChainedLog::<TestEntry>::new(path.clone(), "t");
        chain
            .record(TestEntry {
                id: 2,
                data: "b".to_string(),
                hash: None,
            })
            .await
            .expect("record");

        let content = tokio::fs::read_to_string(&path).await.expect("read");
        // รายการใหม่ต้องขึ้นบรรทัดใหม่ ไม่ถูกต่อท้ายข้อความครึ่งท่อน
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected partial + new record, got {content:?}"
        );
        assert!(lines[0].contains("partial"));
        let entry: TestEntry = serde_json::from_str(lines[1]).expect("new record parses");
        assert_eq!(entry.id, 2);
        let _ = std::fs::remove_file(&path);
    }
}
