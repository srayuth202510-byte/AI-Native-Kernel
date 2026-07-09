#![no_main]

//! Fuzz: AuditEntry JSON parser + hash chain
//!
//! ยิง bytes สุ่มเป็น JSON เข้า parser ของ AuditEntry (เส้นทางเดียวกับที่
//! logger ใช้อ่านไฟล์กลับ) — ต้องไม่ panic และ round-trip ต้องเสถียร

use capability_security::audit::AuditEntry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data).into_owned();

    // 1. parse bytes สุ่มเป็น AuditEntry — ห้าม panic ไม่ว่า input จะเป็นอะไร
    if let Ok(mut entry) = serde_json::from_str::<AuditEntry>(&text) {
        // 2. hash chain ต้อง deterministic
        let prev = entry.hash.clone().unwrap_or_default();
        let h1 = entry.compute_hash(&prev);
        let h2 = entry.compute_hash(&prev);
        assert_eq!(h1, h2, "compute_hash must be deterministic");

        // 3. round-trip: serialize แล้ว parse กลับต้องได้ hash เดิม
        entry.hash = Some(h1.clone());
        if let Ok(serialized) = serde_json::to_string(&entry) {
            let restored: AuditEntry =
                serde_json::from_str(&serialized).expect("round-trip must parse");
            assert_eq!(restored.hash.as_deref(), Some(h1.as_str()));
            assert_eq!(restored.compute_hash(&prev), h1);
        }
    }

    // 4. สร้าง entry จาก input สุ่มโดยตรง แล้ว chain 3 entries — ห้าม panic
    let mut prev = String::new();
    for i in 0..3u64 {
        let mut entry = AuditEntry::new(&text, i);
        entry.reason = Some(text.clone());
        let hash = entry.compute_hash(&prev);
        entry.hash = Some(hash.clone());
        prev = hash;
    }
});
