---
tags: [function, security, zero-trust, uds]
crate: capability-security
file: crates/capability-security/src/uds_auth.rs
updated: 2026-07-09
---

# UdsAuthenticator::authenticate / authorize_command

```rust
pub async fn authenticate(&self, peer_uid: u32, peer_pid: u32, token_id: u64, token_secret: &[u8; 32])
    -> Result<UdsSession, UdsAuthError>
pub fn authorize_command(&self, session_id: u64, command: &str) -> Result<bool, UdsAuthError>
```

## หน้าที่
Zero-trust auth สำหรับคำสั่งที่เข้ามาทาง Unix Domain Socket (CLI/TUI → daemon):
1. **authenticate:** ตรวจ token secret ด้วย `constant_time_eq` → สร้าง session พร้อม TTL
2. **authorize_command:** map command → required capability (`CommandCapabilityMap`) แล้วตรวจว่า session ถือ capability นั้น — session ไม่มีจริง/หมดอายุ = **fail-closed**
3. expired sessions ถูก cleanup ตอน connection accept

## Token File Provisioning
`provision_token_file` เขียน token_id + secret (hex) ลงไฟล์ · `load_token_file` parse กลับ (hex ต้อง 64 ตัวอักษรพอดี)

## ความสัมพันธ์
- **เรียกโดย:** kernel-companion UDS server (ทุก connection/command)
- **เรียกไปยัง:** [[policy-decision]] (ผ่าน validate), [[audit-record]] (บันทึกผล auth)

## Fuzz Coverage
`uds_command` target — command สุ่ม + session id สุ่มต้อง**ไม่มีทางได้ `Ok(true)`** โดยไม่ authenticate ก่อน

## Related
[[00-Function-Map]] · [[policy-decision]] · [[audit-record]]
