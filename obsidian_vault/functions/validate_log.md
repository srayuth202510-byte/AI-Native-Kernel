---
tags: [function, security, worm, audit]
crate: capability-security
file: crates/capability-security/src/audit.rs
updated: 2026-07-09
---

# AuditLogger::validate_log

```rust
pub async fn validate_log(&self) -> Result<bool, AuditError>
```

## หน้าที่
ตรวจความถูกต้องของ hash chain ทั้งไฟล์ — หลักฐานว่า log ไม่ถูกดัดแปลง/ลบ/แทรก:
1. อ่าน entries ทั้งหมด (parse JSON ต่อบรรทัด, บรรทัดเสียถูกข้าม)
2. เดิน chain จาก `prev_hash = ""` → ทุก entry ต้อง `compute_hash(prev) == recorded_hash`
3. คืน `Ok(false)` ทันทีที่ chain ขาด

## คุณสมบัติ Tamper-Evidence
- แก้ไข entry ใดก็ตาม → hash ไม่ตรง → chain ขาดตั้งแต่จุดนั้น
- ลบ entry → entry ถัดไปอ้าง prev_hash ผิด
- ข้อจำกัด: ตัดท้ายไฟล์ (truncate tail) ตรวจไม่เจอด้วย chain เดี่ยว — ต้อง anchor head ภายนอก (Phase 2: remote collector)

## ความสัมพันธ์
- **ตรวจสอบผลของ:** [[audit-record]]
- **ใช้ใน:** chaos tests (concurrent write, restart recovery, partial-line repair)

## หมายเหตุ Performance
อ่านทั้งไฟล์ (O(n)) — ออกแบบมาสำหรับ offline verification ไม่ใช่ hot path

## Related
[[00-Function-Map]] · [[audit-record]]
