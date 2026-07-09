---
tags: [function, compute, cost-function]
crate: compute-scheduler
file: crates/compute-scheduler/src/lib.rs
updated: 2026-07-09
---

# ComputeScheduler::choose_best

```rust
pub fn choose_best(&self, candidates: &[(ComputeTarget, ComputeProfile)]) -> Result<ComputeTarget, ComputeError>
```

## หน้าที่
เลือกฮาร์ดแวร์ (CPU/GPU/NPU/Cloud) ที่คะแนนต้นทุนต่ำสุดจาก cost function:

```
Score = latency_ms·w₁ + power_watts·w₂ + cost_units·w₃
```

- อ่าน `AdaptiveWeights` **ครั้งเดียว** แล้วคำนวณ score ตัวละครั้ง (แก้ 2026-07-09 — เดิม `min_by` เรียก score ซ้ำ ~2n ครั้ง + ยึด lock ทุกครั้ง)
- weights ปรับตัวผ่าน EWMA จาก `update_weights(sample)` ทุกครั้งที่มีข้อมูลจริงเข้ามา
- lock poisoning กู้ด้วย `PoisonError::into_inner` (ไม่ panic)

## Invariants (มี property test)
- Monotonic: latency สูงขึ้น (weights ≥ 0) → score ไม่ลดลง
- Zero weights → score = 0 เสมอ
- เลือก candidate ที่ score ต่ำสุดเสมอ / คืน `Err(NoTargetAvailable)` เมื่อ input ว่าง

## ความสัมพันธ์
- **เรียกโดย:** [[spawn_agent]] path (workload placement), PlacementPolicy
- **ข้อมูลจริงจาก:** `scan_real_hardware()` (NVML / sysfs probing)
- **ปลายทาง engines:** LlamaCpp / TensorRT / vLLM / MPS / Cloud — ทุกตัวสร้าง client ผ่าน [[build_http_client]]

## Performance (วัดจริง 2026-07-09)
choose_best 10 candidates: **~12 ns**

## Related
[[00-Function-Map]] · [[spawn_agent]] · [[build_http_client]]
