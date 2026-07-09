---
tags: [function, infrastructure, error-handling]
crate: compute-scheduler
file: crates/compute-scheduler/src/engine.rs
updated: 2026-07-09
---

# build_http_client

```rust
pub(crate) fn build_http_client(timeout: Duration) -> Result<reqwest::Client, EngineError>
```

## หน้าที่
Helper กลางสร้าง HTTP client (timeout + `pool_max_idle_per_host(4)`) ให้ inference engines ทุกตัว — เกิดจากการรื้อ `.expect("failed to create HTTP client")` ที่ซ้ำกัน 8 จุด (2026-07-09)

## Pattern การใช้งาน
- **Constructors** (`LlamaCppEngine::new`, `TensorRtLlmEngine::new`, `MpsEngine::new`, `VllmEngine::new`, `CloudAiEngine::new`) → คืน `Result<Self, EngineError>` — propagate ขึ้นไปตาม convention "no panic in library code"
- **`with_timeout` builders** → graceful degradation: ถ้าสร้าง client ใหม่ล้มเหลว **คง client เดิม** + log warning (fluent API ไม่แตก)

## ความสัมพันธ์
- **ใช้โดย:** ทุก engine ที่ [[choose_best]] เลือกปลายทางให้
- engines มี `fallback_mock` (env `ANK_COMPUTE_MOCK_FALLBACK`) เมื่อ server ไม่พร้อม

## Related
[[00-Function-Map]] · [[choose_best]] · [[error-handling]]
