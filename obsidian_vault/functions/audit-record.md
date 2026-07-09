---
tags: [function, security, worm, audit]
crate: capability-security
file: crates/capability-security/src/audit.rs
updated: 2026-07-09
---

# AuditLogger::record

```rust
pub async fn record(&self, mut entry: AuditEntry) -> Result<(), AuditError>
```

## หน้าที่
เขียน audit entry ลง WORM log (JSON Lines) พร้อม **SHA-256 hash chaining** — ทุก security decision (ALLOW/DENY/issue/revoke/kill) ต้องผ่านฟังก์ชันนี้ตาม security checklist

## ลำดับการทำงาน (ภายใต้ writer lock ตัวเดียวตลอด)
1. อ่าน `prev_hash` จาก cache — ถ้า cache เย็น (เพิ่ง start) ใช้ **tail-read**: seek ท้ายไฟล์ อ่าน chunk 64KB, parse เฉพาะบรรทัดสุดท้ายที่ valid (ขยาย chunk ×4 ถ้าไม่เจอ)
2. `compute_hash(prev_hash)` → ผูก entry เข้ากับ chain
3. เขียนผ่าน **persistent file handle** (เปิดครั้งเดียว) — ถ้าไฟล์ค้างบรรทัดครึ่งท่อนจาก crash จะปิดบรรทัดให้ก่อน
4. ถ้าเขียนล้มเหลว: ทิ้ง handle + invalidate hash cache → record ถัดไปเริ่มสะอาด

## Concurrency Invariant สำคัญ
writer lock ครอบทั้ง "อ่าน hash → คำนวณ → เขียน" — ถ้าไม่ครอบจะเกิด **chain fork** (2 tasks อ่าน prev เดียวกัน) และ**บรรทัดปนกัน** — มี chaos test ยืนยัน ([[implementation-status]])

## ความสัมพันธ์
- **เรียกโดย:** `issue_token` / `authorize_token` / `revoke_token` ([[grant_capability]] path), kernel-companion tcell task ([[observe_syscall]] Kill/Quarantine)
- **ตรวจสอบโดย:** [[validate_log]]

## Performance (วัดจริง 2026-07-09)
- ก่อนแก้: **57.8 ms** (cold start อ่าน+parse ทั้งไฟล์ 63MB) → หลังแก้: **~12 µs** ผ่าน issue_token
- ประวัติ: repo เคยสะสม audit.log 2.6GB จาก bench — ตอนนี้ bench ใช้ temp path

## Phase 2 Backlog
- Group commit / fsync จริง (`sync_all`) ถ้า throughput ชนเพดาน
- gRPC/OTLP stream ไป remote collector (tamper-proof anchor)

## Related
[[00-Function-Map]] · [[validate_log]] · [[policy-decision]]
