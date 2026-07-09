---
tags: [function, memory, paging]
crate: context-memory
file: crates/context-memory/src/lib.rs
updated: 2026-07-09
---

# ContextMemoryManager — put / get / promote / demote

```rust
pub fn put(&self, key: impl Into<String>, value: Vec<u8>)
pub fn get(&self, key: &str) -> Result<Vec<u8>>
pub fn promote(&self, key: &str) -> Result<()>   // Cold→Warm→Hot
pub fn demote(&self, key: &str) -> Result<()>    // Hot→Warm→Cold
pub fn page_to_vram(&self, key: &str) -> Result<()>
pub fn page_kv_to_vram(&self, page: KvCachePage) -> Result<Option<KvCachePage>>
```

## หน้าที่
จัดการ Context Paging Memory 4 ชั้น:

```
VRAM (GPU/NPU, KV-cache)  ←→  Hot (RAM, Vec<f32>)  ←→  Warm (NVMe, RocksDB)  ←→  Cold (disk file)
```

- `get` ทำ auto-promotion: อ่านจาก tier ล่าง → เลื่อนขึ้น tier บน
- VRAM tier ใช้ LRU eviction — ตัวที่ถูกถอดมี callback ย้ายกลับ Hot tier (guard ด้วย `let Some(...) else break` — ไม่มี unwrap)
- Warm tier (RocksDB) รักษา FIFO order ข้าม restart

## ความสัมพันธ์
- **เรียกโดย:** [[spawn_agent]] path (agent context), inference engines (KV-cache paging ผ่าน [[choose_best]] placement)
- **P2P Mesh:** gossip sync context ข้าม node พร้อม trust scoring

## Performance Budget
Agent ↔ Agent context switch: P99 < 50 µs (ยังไม่มี bench ตรง — backlog)

## Related
[[00-Function-Map]] · [[spawn_agent]] · [[choose_best]]
