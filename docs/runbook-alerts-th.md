# Runbook: รับมือ alert จาก watchtower (อ่านจบใน 3 นาที)

> สำหรับ on-call ของ AI platform team — ถ้าเพิ่งตื่นมาตอนตี 3 เริ่มที่ข้อ 1

## 1. ดูความรุนแรงก่อน (จาก webhook: `severity`)

| severity | แปลว่า | ทำทันที |
|---|---|---|
| `critical` | กำลังโดนขโมยโมเดล / ระบบตาบอด / host โดน quarantine | เปิด Grafana + ข้อ 2 ทันที อย่ารอเช้า |
| `high` | injection พุ่ง / PII ไหล / tenant โดน suspend | ดูในชั่วโมงทำงาน ยกเว้นพุ่งต่อเนื่องให้เลื่อนเป็น critical |
| `warn` | probe/auth ผิดปกติ / shed เยอะ | ดู trend พรุ่งนี้ได้ ถ้าไม่โต |
| `info` | telemetry เฉย ๆ | ไม่ต้องทำอะไร (ถ้ามี info มาปลุก = config ผิด ไปแก้ threshold) |

## 2. สืบกลับไปหาหลักฐาน (ทุก alert มีให้ครบ)

webhook มี `sample.request_id` + `tenant_id` — เอาไป grep ใน audit chain:

```bash
grep "<request_id>" <audit_dir>/<tenant>.jsonl
```

แล้วตรวจความสมบูรณ์ของ chain (ใครแตะไฟล์จะรู้):

```bash
ai-gateway verify-audit --dir <audit_dir>
```

`verify-audit` ไม่ผ่าน = อย่าเชื่ออะไรในไฟล์นั้นเลย เลื่อนเป็น incident ระดับระบบ

## 3. ปลด tenant ที่โดน auto-suspend (เมื่อสอบสวนจบ)

- **ไม่ต้องทำอะไรถ้าไม่รีบ** — suspend หมดอายุเองใน 30 นาที (default)
- **รีบปลด**: restart gateway (override เป็น runtime-only หายหมดตอน restart —
  ออกแบบแบบนี้โดยตั้งใจ: restart แล้วลงโทษค้างคือกับดัก)
- **คีย์โดน revoke ไม่กลับมาเอง** — ต้องออกคีย์ใหม่ใน policy file + restart
  (คีย์หลุดต้องไม่ฟื้นเอง ตรงข้ามกับ suspend)

## 4. เสียงดังเกินไป (alert fatigue = ระบบตาย)

- อย่า mute webhook — ไปขัน `threshold`/`cooldown` ใน config แทน
- ขันแล้วรัน red-team corpus ตรวจก่อน deploy:
  `cargo test -p ai-gateway --test redteam` (blocked 17/17 ต้องเขียว)
- กฎไหนยิงเกิน 5 ครั้ง/วันโดยไม่มี incident จริง = threshold ผิด ไป tune

## 5. กรณีพิเศษ

- **`pipeline_healthy = 0`**: ระบบตาบอด — เชื่อ Grafana ไม่ได้ชั่วคราว
  ดู log ตรง (`watcher` ร้องไว้) แล้ว restart gateway ก่อนสืบเรื่องอื่น
- **`alerts_dropped_total` เพิ่ม**: queue เต็ม = alert หาย — เพิ่ม capacity
  หรือลด noise ที่ต้นเหตุ (มักเป็น threshold ต่ำไป)
- **`auto-response-frozen`**: circuit breaker แช่แข็ง automation เพราะ action
  เกินโควตา — อย่าเพิ่งไปเปิดเอง ให้ดูว่า rule ไหนยิงถี่ (มักเป็น threshold ผิด
  หรือโดนโจมตีจริง ดูข้อ 2 ก่อนตัดสินใจ)

## 6. สั่งห้าม (ทำแล้วโดนด่า)

1. ห้ามเปิด `auto_response` ให้ tenant โดยไม่ดูข้อมูล 2 สัปดาห์ก่อน
2. ห้ามเพิ่มกฎเข้า allowlist โดยไม่มี fixture ใน red-team corpus ประกอบ
3. ห้ามแก้ threshold ตรง production โดยไม่รัน replay test ก่อน
4. ห้ามปิด webhook เพื่อ "ให้มันเงียบ" — เงียบปลอมอันตรายกว่าเสียงดัง
