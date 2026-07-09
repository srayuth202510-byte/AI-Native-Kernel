---
tags: [function, intent-bus, event-driven]
crate: intent-bus
file: crates/intent-bus/src/lib.rs
updated: 2026-07-09
---

# IntentBus::publish / subscribe

```rust
pub async fn publish(&self, intent: Intent) -> Result<(), IntentBusError>
pub fn subscribe(&self) -> IntentSubscriber
```

## หน้าที่
Event backbone ของระบบ — fan-out intent ทุกตัวไปยัง subscribers ผ่าน `tokio::sync::broadcast`:
- `Intent { id, intent_type, payload, priority, source, target, metadata }`
- IntentType: `NaturalLanguage` / `Structured` / `Command` / `Event` / `Interrupt`
- Priority: `Low` → `Critical`

## พฤติกรรมเมื่อ overflow
broadcast buffer เต็ม → subscriber ที่ตามไม่ทันได้ `Lagged` (พลาด message เก่า) แต่**ยังรับต่อได้** — มี chaos test ยืนยัน (buffer 8 ช่อง / 1,000 intents / slow subscriber)

## ความสัมพันธ์
- **ผู้ publish หลัก:** User/AI app (intent เข้าระบบ), [[observe_syscall]] path (Cytokine threat events จาก T-Cell, source = "tcell")
- **ผู้ subscribe หลัก:** KernelCompanion routing (→ [[spawn_agent]]), Immune loop (tcell events → B-Cell `learn_threat` → antibody → LSM rule)
- **Semantic Query Cache:** intent-bus มี LRU cache (`NonZeroUsize::MIN` floor) สำหรับ query ซ้ำ

## Fuzz Coverage
`intent_parser` target — payload/metadata สุ่มต้องไม่ panic (JSON round-trip)

## Related
[[00-Function-Map]] · [[observe_syscall]] · [[spawn_agent]]
