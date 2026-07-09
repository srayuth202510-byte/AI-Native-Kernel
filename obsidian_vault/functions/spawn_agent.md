---
tags: [function, scheduler, hot-path]
crate: agent-scheduler
file: crates/agent-scheduler/src/scheduler.rs
updated: 2026-07-09
---

# AgentScheduler::spawn_agent

```rust
pub async fn spawn_agent(&self, mut agent: AgentControlBlock) -> Result<u64, SchedulerError>
```

## หน้าที่
สร้าง agent ใหม่เข้าระบบ: จัดสรร agent id (ถ้า id == 0), ลงทะเบียน `AgentControlBlock` (state, priority, instance_salt, capabilities) และประกาศ event ผ่าน monitoring channel

## ความสัมพันธ์
- **เรียกโดย:** kernel-companion (intent routing → spawn), delegated spawn route (distributed routing policy), benches/tests
- **ต่อเนื่องไปยัง:** [[grant_capability]] (มอบสิทธิ์), `enqueue_agent` → PriorityQueue ([[choose_best]] สำหรับ compute placement)
- **Supervisor:** ตรวจ `AgentState::Failed` แล้ว restart (chaos test: กู้ 1,000 agents ที่ตายพร้อมกัน)

## Priority Queue Invariants (มี property test)
- Pop เรียงตาม `(Priority, id)` แบบ non-increasing เสมอ
- `RealTime > Interactive > Batch > Eco` — RealTime แซงทุก class

## Performance (วัดจริง 2026-07-09)
- spawn: **~13.1 µs** — budget P99 < 500 µs (headroom ~38×)
- full lifecycle (spawn→pause→resume→terminate): ~13.7 µs

## Related
[[00-Function-Map]] · [[grant_capability]] · [[choose_best]] · [[context-paging]]
