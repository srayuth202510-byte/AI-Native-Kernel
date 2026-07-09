//! Chaos tests สำหรับ Failure Domain: WORM Audit Logger
//!
//! ทดสอบว่า audit log รักษา hash chain ได้ภายใต้สถานการณ์วิกฤต:
//! เขียนพร้อมกันหลาย task, process restart, crash กลางการเขียน,
//! และ path ที่เขียนไม่ได้ — ทุกกรณีต้องไม่ panic และ chain ต้อง validate ผ่าน

use capability_security::audit::{AuditEntry, AuditLogger};
use std::sync::Arc;

fn temp_log(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ank-chaos-audit-{name}-{}-{}.log",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

/// เขียนพร้อมกัน 8 tasks — hash chain ต้องไม่ fork และไม่มีบรรทัดปนกัน
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn chaos_concurrent_records_keep_hash_chain_intact() {
    let path = temp_log("concurrent");
    let logger = Arc::new(AuditLogger::new(path.clone()));

    let mut handles = Vec::new();
    for task in 0..8u64 {
        let logger = Arc::clone(&logger);
        handles.push(tokio::spawn(async move {
            for i in 0..50u64 {
                logger
                    .record(AuditEntry::issued(task * 1000 + i))
                    .await
                    .expect("concurrent record should succeed");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("task should not panic");
    }

    let entries = logger.entries().await;
    assert_eq!(entries.len(), 400, "all 400 entries must be present");
    assert!(
        logger.validate_log().await.expect("validation should run"),
        "hash chain must be intact after concurrent writes"
    );

    let _ = std::fs::remove_file(path);
}

/// จำลอง process restart — logger ตัวใหม่ต้องต่อ chain จาก tail ของไฟล์เดิมได้
#[tokio::test]
async fn chaos_logger_restart_continues_chain_via_tail_read() {
    let path = temp_log("restart");

    {
        let logger = AuditLogger::new(path.clone());
        for i in 0..20 {
            logger.record(AuditEntry::issued(i)).await.expect("record");
        }
    }

    let logger = AuditLogger::new(path.clone());
    for i in 20..40 {
        logger.record(AuditEntry::issued(i)).await.expect("record");
    }

    let entries = logger.entries().await;
    assert_eq!(entries.len(), 40);
    assert!(
        logger.validate_log().await.expect("validation should run"),
        "chain must stay valid across logger restarts"
    );

    let _ = std::fs::remove_file(path);
}

/// จำลอง crash กลางการเขียน (บรรทัดครึ่งท่อนไม่มี newline ปิดท้าย)
/// logger ใหม่ต้องซ่อมบรรทัดค้าง ต่อ chain จาก entry ดีตัวสุดท้าย
/// และ entry ใหม่ต้องไม่หายไปกับบรรทัดเสีย
#[tokio::test]
async fn chaos_partial_trailing_line_is_repaired_on_recovery() {
    let path = temp_log("partial");

    {
        let logger = AuditLogger::new(path.clone());
        for i in 0..10 {
            logger.record(AuditEntry::issued(i)).await.expect("record");
        }
    }

    // เขียนบรรทัดครึ่งท่อนทับท้ายไฟล์ (ไม่มี newline)
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for corruption");
        write!(file, "{{\"action\":\"trunc").expect("write partial line");
    }

    let logger = AuditLogger::new(path.clone());
    logger
        .record(AuditEntry::issued(99))
        .await
        .expect("record after partial line");

    let entries = logger.entries().await;
    assert_eq!(
        entries.len(),
        11,
        "10 originals + 1 new entry; the partial line is skipped, not merged"
    );
    assert_eq!(entries.last().map(|e| e.token_id), Some(99));
    assert!(
        logger.validate_log().await.expect("validation should run"),
        "chain must skip the corrupt line and stay valid"
    );

    let _ = std::fs::remove_file(path);
}

/// path ที่เขียนไม่ได้ — record ต้องคืน Err ทุกครั้ง ไม่ panic และไม่ค้าง
#[tokio::test]
async fn chaos_unwritable_path_fails_gracefully() {
    let path = std::path::PathBuf::from("/nonexistent-ank-chaos-dir/audit.log");
    let logger = AuditLogger::new(path);

    for i in 0..5 {
        let result = logger.record(AuditEntry::issued(i)).await;
        assert!(result.is_err(), "record must fail cleanly, not panic");
    }
}
