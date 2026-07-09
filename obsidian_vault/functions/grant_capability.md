---
tags: [function, scheduler, security]
crate: agent-scheduler
file: crates/agent-scheduler/src/scheduler.rs
updated: 2026-07-09
---

# AgentScheduler::grant_capability

```rust
pub async fn grant_capability(&self, agent_id: u64, token: CapabilityToken) -> Result<(), SchedulerError>
```

## หน้าที่
มอบ capability token ให้ agent — สะพานเชื่อม Scheduling Layer กับ Security Layer:
1. ตรวจว่า agent มีอยู่จริง + token ไม่ว่างเปล่า
2. **PAD (Polymorphic Agent DNA):** XOR `instance_salt` ของ agent เข้ากับ 16 bytes แรกของ secret — token ที่ออกให้แต่ละ agent instance ไม่ซ้ำกันแม้มาจาก token ต้นแบบเดียวกัน
3. `authorize_token` ทุก capability ใน token → DENY ตัวเดียว = ปฏิเสธทั้งใบ
4. `issue_token` เข้าระบบ + push เข้า `agent.capabilities` + broadcast `AgentCapabilityGranted`

## ความสัมพันธ์
- **เรียกโดย:** kernel-companion (ตอน provision agent), CLI/UDS commands
- **เรียกไปยัง:** [[policy-decision]] (ผ่าน authorize_token), [[audit-record]] (ผ่าน issue_token)
- **event ไหลไปยัง:** monitoring channel → [[intent-publish]] subscribers

## Errors
`SchedulerError::AgentNotFound` · `CapabilityDenied` · `CapabilitySecurityFailed`

## Performance (วัดจริง 2026-07-09)
- ก่อนแก้ audit logger: **57.8 ms** (จมอยู่ใน cold-start tail scan ของ [[audit-record]])
- หลังแก้: **~81 µs** (-99.87%)

## Related
[[00-Function-Map]] · [[spawn_agent]] · [[policy-decision]] · [[audit-record]]
