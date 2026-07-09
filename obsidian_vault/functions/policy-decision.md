---
tags: [function, security, zero-trust, hot-path]
crate: capability-security
file: crates/capability-security/src/policy.rs
updated: 2026-07-09
---

# PolicyEngine::decision

```rust
pub fn decision(&self, token: &CapabilityToken, scope: &Scope, capability: &str) -> PolicyDecision
```

## หน้าที่
**Policy Decision Point** ของทั้งระบบ — ตัดสิน `Allow`/`Deny` แบบ fail-closed:

```
DENY ทันทีถ้า:  token หมดอายุ  ∨  token ไม่มี capability  ∨  capability นอก allowlist
ALLOW ถ้า:      scope ตรงกัน  ∨  token เป็น Global scope
มิฉะนั้น:        default_decision (ค่าเริ่มต้นระบบ = DENY)
```

## Invariants (มี property test คุ้มครอง 6 ข้อ)
1. Token หมดอายุ → DENY เสมอ แม้ default = Allow
2. ไม่มี capability ที่ขอ → DENY เสมอ
3. Capability นอก allowlist → DENY เสมอ
4. `authorize()` สอดคล้องกับ `decision()` ทุกกรณี
5. Global token + allowlisted capability → ALLOW
6. Scope mismatch + default DENY → DENY

## Security Notes
- `CapabilityToken` เทียบกันด้วย manual `PartialEq` ที่ใช้ `constant_time_eq` กับ secret (กัน timing side channel — แก้ 2026-07-09)
- Allowlist เป็น `HashSet` → O(1) lookup

## ความสัมพันธ์
- **เรียกโดย:** `authorize_token` / `validate` / `decision_for` ใน CapabilitySecurityManager ← [[grant_capability]], [[uds-authenticate]], LSM syscall path
- **ทุกผลตัดสินถูกบันทึกโดย:** [[audit-record]]

## Performance (วัดจริง 2026-07-09)
authorize ทั้งเส้นทาง (รวม audit write): **~12 µs** — budget < 1ms (เหลือ headroom ~80×)

## Related
[[00-Function-Map]] · [[audit-record]] · [[grant_capability]]
