# ออกแบบ: ระบบเฝ้าระวัง + ป้องกันการ hack ที่เกี่ยวกับ AI (Monitoring & Alerting)

> สถานะ: **แบบร่างรอรีวิว** — ยังไม่ลงมือโค้ด ผู้รีวิวต้องตอบคำถามท้ายเอกสารก่อน
> เอกสารนี้อ้างอิง `docs/pivot_ai_infra_security.md` §8 ข้อ 4 ("operators can see
> coverage") และสำรวจโค้ดจริง ณ commit `bc64be93` — ทุกสิ่งที่อ้างว่า "มีอยู่แล้ว"
> มีไฟล์และบรรทัดกำกับ ไม่ใช่ความจำ

## 1. "Hack จาก AI" หมายถึงอะไร — ขอบเขตของเอกสารนี้

วลีนี้ตีความได้สองทาง และระบบต้องรับมือทั้งสองทางเพราะใช้สัญญาณชุดเดียวกัน:

| ทางตีความ | ตัวอย่างการโจมตี | หมายเหตุ |
|---|---|---|
| **A. AI เป็นอาวุธ** — attacker ใช้ AI/LLM เป็นเครื่องมือเจาะ | prompt injection / jailbreak เพื่อหลอกโมเดลให้ข้าม guardrail, automated exfiltration (ให้โมเดลคาย PII/secret ทีละนิด), model extraction (ดูด behavior ไป clone), credential stuffing ด้วยคีย์ที่หลุด | นี่คือภัยหลักของ buyer (AI platform team) |
| **B. AI เป็นตัวการ** — agent ที่เรารันเองถูก compromise หรือ rogue | agent ที่ถูก prompt ฝังคำสั่งแฝงแล้วไปเรียก tool เกินสิทธิ์, agent ยิง request ผิดปกติ (rate/pattern เปลี่ยน), process ของ agent ทำ syscall นอกโปรไฟล์ | รับมือด้วยชั้น host plane (T-cell + LSM) ประกอบกับชั้น gateway |

สิ่งที่เอกสารนี้**ไม่รวม**: การเจาะ infrastructure แบบดั้งเดิมที่ไม่ผ่าน AI เลย
(เช่น SSH brute force เข้า host) — นั่นคืองานของ EDR/IDS เดิม เราไม่ทำซ้ำ
แต่ event จากเราต้องส่งออกไปให้ระบบพวกนั้นได้ (SIEM export มีแล้วบางส่วนใน ANK-066)

## 2. Threat model — สินทรัพย์, ผู้กระทำ, เวกเตอร์

### 2.1 สินทรัพย์ที่ต้องคุ้มครอง (เรียงตามมูลค่าต่อ buyer)

1. **ข้อมูลใน prompt/response** — PII, secret, ข้อมูลลูกค้าของ tenant ที่ไหลผ่านโมเดล
2. **ตัวโมเดลเอง** — weights/behavior ที่ถูกดูดผ่าน extraction (ต้นทุนเทรน)
3. **โควตาและค่าใช้จ่าย** — compute ที่ถูกขโมยใช้ (abuse for free inference, DoS ต่อ tenant อื่น)
4. **ความน่าเชื่อถือของ audit chain** — ถ้า attacker ลบ/แก้ log ได้ ทุกอย่างข้างบนตรวจสอบไม่ได้

### 2.2 เวกเตอร์โจมตี → ตัวตรวจจับที่มีอยู่ → หลักฐาน

| # | เวกเตอร์ | ตัวตรวจจับที่มีอยู่แล้ว | สัญญาณดิบ (field ใน audit) |
|---|---|---|---|
| V1 | Prompt injection / jailbreak (direct, unicode, zero-width — มี fixture ใน `tests/fixtures/`) | `semantic-guard` (`Guard::inspect_fail_closed`) | `decision=Deny reason=prompt_injection_detected`, `injection_rules=<rule_ids>` |
| V2 | PII/secret ไหลออกใน response | guard response prefix + redaction | `decision=Redacted`, `redacted_count=N`, `pii_redacted_in_response` |
| V3 | Model extraction (ดูด behavior เป็นระบบ) | `extraction-det` (`ExtractionDetector::observe`) | `extraction_level=normal/watch/alert/extracting`, `extraction_score` |
| V4 | ใช้คีย์ผิด/หมดอายุ/tenant ถูกระงับ, เรียก model/endpoint เกินสิทธิ์ | `DataPlanePolicy::authenticate/authorize` | `decision=Deny reason=invalid_api_key/expired_api_key/tenant_suspended/policy_violation/...` |
| V5 | DoS / ใช้ทรัพยากรเกิน (concurrency) | semaphore ต่อ tenant (ANK-069) | `decision=Deny reason=concurrency_limit` → HTTP 429 |
| V6 | Agent/process ระดับ host ทำตัวนอกโปรไฟล์ | `immune-system` T-cell (`ThreatDecision::Quarantine`), LSM denials (`kernel-companion`) | quarantine ต่อ PID, LSM deny events |
| V7 | การตอบสนองช้าผิดปกติ (อาจเป็น exfiltration แบบค่อยเป็นค่อยไป หรือ backend โดนยึด) | `latency_ms` ใน audit + perf budget | anomaly ของ latency distribution ต่อ tenant |

**ประเด็นสำคัญ**: ทุกเวกเตอร์ V1–V5 เขียน audit entry ลง hash chain ต่อ tenant อยู่แล้ว
(`crates/ai-gateway/src/entry.rs:79` — มี `request_id`, `reason`, `injection_rules`,
`extraction_level/score`, `latency_ms`) หลักฐานจึงมีครบ ปัญหาเดียวคือ**ไม่มีใครดูมันแบบ
real-time** — ต้องมา grep ไฟล์เองหลังเกิดเหตุ นี่คือช่องว่างที่เอกสารนี้ปิด

## 3. ช่องว่างที่ยืนยันจากการอ่านโค้ด (ไม่ใช่ความรู้สึก)

1. **ไม่มี `/metrics` endpoint** — gateway มีแค่ `/healthz` (`routes.rs:192-200`) ไม่มี
   Prometheus/text, ไม่มี decision counter, ไม่มีอะไรให้ Grafana scrape
2. **`detection_mode()` เป็น dead code** — มีฟังก์ชัน (`lib.rs:636`) + unit test แต่
   ไม่มีผู้เรียก ไม่มีที่ไหน export ค่านี้ออกไป operator จึง "เชื่อ" coverage ไม่ได้ "เห็น"
3. **ไม่มี alert dispatch** — `should_alert()` (`lib.rs:646`) เป็นแค่ predicate ไม่มี
   webhook/Slack/pager, ไม่มี retry, ไม่มี cooldown — `cytokine.rs:112` มีคำว่า
   "system-wide alert broadcast" แต่เป็นแนวคิดใน-process ไม่ได้ส่งออกนอกระบบ
4. **ไม่มี rules engine** — ไม่มีที่ไหนนิยามว่า "N ครั้งใน M นาที = incident" ทุกการ
   ตัดสินใจเป็นราย request ไม่มีหน้าต่างเวลา ไม่มี dedup (alert fatigue คือวิธีที่
   monitoring ตาย — คนปิดเสียงแล้วพลาดของจริง)

## 4. สถาปัตยกรรมที่เสนอ

```
V1..V7 (detectors ที่มีอยู่แล้ว)
        │  verdict + audit entry (มีอยู่แล้ว ไม่ต้องแก้ detector)
        ▼
┌─────────────────────────────┐
│ 1. Normalize → SecurityEvent │  (ใหม่, เล็ก)
│    tenant, severity, category,│
│    reason, evidence=request_id│
│    + chain hash              │
└─────────────┬───────────────┘
              ├──► ┌──────────────────┐
              │    │ 2a. /metrics      │  Prometheus text: counter/gauge
              │    │ (scrape, pull)    │  ต่อ tenant × reason × level
              │    └──────────────────┘
              │
              └──► ┌──────────────────┐     ┌──────────────────┐
                   │ 2b. Rules engine │────►│ 3. Dispatch       │
                   │ (windowed, in-   │     │ webhook sink ก่อน  │
                   │  process, ต่อ     │     │ (Slack/PagerDuty/  │
                   │  tenant)          │     │  Opsgenie รับ      │
                   └──────────────────┘     │ webhook ได้หมด)    │
                                            └────────┬─────────┘
                                                     ▼
                                            ┌──────────────────┐
                                            │ 4. Response       │
                                            │ auto: suspend/    │
                                            │ revoke/quarantine │
                                            │ (ต้องมี audit)     │
                                            └──────────────────┘
```

### หลักการออกแบบ (ผูกกับ house rule ของ repo — ไม่ใช่สโลแกน)

1. **ส่ง alert นอกเส้นทาง request (out-of-band)** — dispatch ล้มเหลวต้องไม่ทำให้
   request ล้มเหลวหรือช้าลง ใช้ queue มีขอบเขต + นโยบายทิ้งที่ประกาศชัด (เช่น เก็บ
   10k event ล่าสุด เกินแล้วทิ้งตัวเก่าสุดและนับ `alerts_dropped_total` — การทิ้งเงียบ
   โดยไม่มีตัวนับคือการโกหก)
2. **ทุก alert ต้องมีหลักฐานโยงกลับได้** — event ต้องมี `request_id` + chain hash
   ของ tenant นั้น ณ เวลาเกิดเหตุ (มีใน audit อยู่แล้ว แค่ต้องยกมาใส่) alert ที่สืบ
   กลับไปหา evidence ไม่ได้คือ noise
3. **กัน alert fatigue ตั้งแต่ day one** — dedup (firing ซ้ำเรื่องเดิมไม่ส่งซ้ำ),
   cooldown ต่อ rule (เช่น CRITICAL ซ้ำไม่เกิน 1 ครั้ง/5 นาที), severity 4 ระดับพอ
   (INFO/WARN/HIGH/CRITICAL) — ระบบที่ร้องทุกเรื่องจะถูก mute แล้วตาย
4. **Auto-response ทุกครั้งต้องเขียน audit** — กฎเดียวกับ ANK-069: การกระทำที่สืบ
   ย้อนไม่ได้คือ control ที่ไว้ใจไม่ได้ (suspend tenant, revoke key, quarantine PID
   ต้องมี entry ใน chain)
5. **Fail-closed แบบมีขอบเขต** — ถ้า rules engine ล้ม: gateway ยังบังคับนโยบายราย
   request ได้เหมือนเดิม (detector ไม่ได้พึ่ง rules engine) แค่ "ตาบอดชั่วคราว"
   และต้องมี metric `pipeline_healthy=0` บอกว่าตาบอดอยู่ — ห้ามเงียบ

## 5. Alert catalog (ร่าง — ตัวเลขต้อง tune จาก traffic จริง 2 สัปดาห์แรก)

| ID | กฎ | Severity | หน้าต่าง/เกณฑ์ตั้งต้น | Response |
|---|---|---|---|---|
| A1 | Injection พุ่งต่อ tenant | HIGH → CRITICAL ถ้า >50/5min | >10 `prompt_injection_detected` / tenant / 5min | แจ้ง + แนบ rule_ids ที่โดนบ่อยสุด |
| A2 | Extraction ระดับ extracting | CRITICAL | `extraction_level=extracting` ครั้งเดียว | แจ้งทันที + เสนอ suspend tenant (auto หลัง operator เปิด) |
| A3 | Extraction ระดับ alert ต่อเนื่อง | HIGH | `alert` ≥3 ครั้ง / tenant / 1ชม. | แจ้ง + แนบ score trend |
| A4 | PII exfiltration volume | HIGH | `redacted_count` รวม >100 / tenant / 10min หรือ `pii_redacted_in_response` ถี่ผิดปกติ | แจ้ง + ตัวอย่างที่ redact (masked) |
| A5 | Auth attack (เดาคีย์ / คีย์หลุดแล้วมีคนลอง) | HIGH | `invalid_api_key` >20 / 5min (รวมทุก tenant — attacker ไม่รู้ tenant) | แจ้ง + IP/pattern ถ้ามี |
| A6 | Concurrency shed พุ่ง (DoS หรือ tenant โตเกินโควตา) | WARN → HIGH ถ้านาน >15min | `concurrency_limit` >5% ของ request / tenant / 5min | แจ้ง tenant + แนะเพิ่ม `max_concurrent` |
| A7 | Tenant ถูกระงับแล้วยังมีคนเรียก (abuse ต่อ / key หลุด) | HIGH | `tenant_suspended` >5 / 5min | แจ้ง + พิจารณา revoke key |
| A8 | Host-plane: quarantine PID | CRITICAL | ทุกครั้งที่ T-cell สั่ง quarantine | แจ้ง + PID/tenant/เหตุผล |
| A9 | Pipeline ตาบอด (meta-alert — สำคัญสุด) | CRITICAL | `pipeline_healthy=0` หรือ `alerts_dropped_total` เพิ่ม | แจ้งช่องทางสำรอง (rules engine ล้มต้องไม่พึ่งตัวเองแจ้ง) |
| A10 | Latency anomaly ต่อ tenant (exfil ช้า / backend ผิดปกติ) | WARN | P99 latency เบี่ยง >3σ จาก baseline 7 วัน | แจ้ง + ชวนดู ไม่ auto-action |

## 5.5 Red-team corpus & replay harness (สร้างแล้ว 2026-10-03 — ไม่รอ Phase A)

เหตุผลที่ทำก่อน: detector ที่ไม่เคยเจอการโจมตีจริงคือคำกล่าวอ้าง ไม่ใช่ control
และ harness นี้พิสูจน์ตัวเองตั้งแต่วันแรก — มันเจอช่องโหว่จริง (ดู F1–F2 ข้างล่าง)

- **Corpus**: `crates/ai-gateway/tests/fixtures/attacks/{blocked,advisory}/*.json`
  (ปัจจุบัน 15 blocked + 3 advisory) ทุกไฟล์มี `expect.decision/reason` — ไม่มี
  "ยิงดูเฉย ๆ" — body ใช้ PII/secret สังเคราะห์เท่านั้น และอักขระล่องหนเขียนเป็น
  `\u` escape ที่ verify ระดับ byte (เคยมีบทเรียน: อักขระที่พิมพ์ด้วยมืออาจไม่ใช่
  ตัวที่คิด ต้อง assert codepoint)
- **Harness**: `crates/ai-gateway/tests/redteam.rs` — core/audit แยกกันทุก fixture
  (กัน state รั่ว), ตรวจครบห่วง (decision + reason + audit entry + chain verify),
  `blocked/` ตกแล้ว CI แดง, `advisory/` รายงานอย่างเดียวแต่ถ้าวันไหนกันได้จะบอก
 ให้ promote (รอบนี้ promote `pii-aws-key-001` ขึ้นมาแล้ว — ApiKey kind จับ
  AKIA example key ได้ ดีกว่าที่ประเมินไว้)

### ผลการรันครั้งแรก — สิ่งที่เจอ (สถานะ 2026-10-03)

| ID | เรื่อง | สถานะ |
|---|---|---|
| F1 | **JSON escape smuggling**: body ที่เป็น pure-ASCII (`\u0069gnore...`) ได้ Allow เพราะ guard ตรวจข้อความดิบก่อน JSON decode ทั้งที่ model server ถอดเป็น "ignore" เสมอ — bypass สมบูรณ์ของชั้น injection (และ PII เช่นกัน) | **แก้แล้ว**: `inspect_request` ตรวจ `inspection_text()` (รวม string ที่ decode แล้วทั้ง body) แทนข้อความดิบ มี fixture `inj-escape-001` ล็อกไว้ |
| F2 | **Newline obfuscation หลุด**: `\n` ที่ encode ไว้ไม่ถูกยุบ ทั้งที่ model เห็นเป็น newline จริง — unit test เดิมใช้ newline จริงซึ่งมาถึงผ่านสายไม่ได้ (JSON ที่ถูกต้องต้อง escape) จึงพิสูจน์เคสที่เกิดจริงไม่ได้ | **แก้แล้ว**: ใน `inspection_text()` เดียวกัน (decode ก่อน normalize) มี fixture `inj-obf-newline-001` ล็อกไว้ |
| F3 | Thai-language injection หลุด — rule เป็น English regex ล้วน | เปิดอยู่ (`adv-thai-injection-001`) — ต้องมี Thai rules |
| F4 | เลขบัตรประชาชนไทย 13 หลักหลุด — ไม่มี Thai-ID PII kind (`pii.rs` มีแค่ Email/Card/SSN/ApiKey/PhoneIntl/Ipv4) | เปิดอยู่ (`adv-thai-id-001`) — ต้องเพิ่ม data kind |
| F5 | Subtle roleplay ที่ไม่มี trigger word หลุด (คาดไว้แล้ว) | เปิดอยู่ (`adv-roleplay-subtle-001`) — หลักฐานประกอบ pivot §8.4 ว่า signature matcher มี blind spot จริง |

กฎการจัดการ advisory: bypass ที่ยืนยันแล้วห้ามค้างเกิน 1 release — ต้องกลายเป็น
task (Thai rules / Thai-ID kind) หรือกลายเป็น blocked (เมื่อแก้แล้ว) ห้ามปล่อยให้
`advisory/` เป็นสุสาน

## 6. สิ่งที่ไม่ทำ (Non-goals — เขียนไว้กัน scope creep)

- ไม่สร้าง dashboard UI เอง — platform team อยู่ใน Grafana อยู่แล้ว เราส่ง
  Prometheus format + ตัวอย่าง dashboard JSON ให้พอ
- ไม่ทำ ML anomaly detection เองในเฟสแรก — ใช้ threshold + σ ธรรมดาที่อธิบายได้
  โมเดลที่อธิบายไม่ได้คือ alert ที่ operator ไม่กล้า action
- ไม่ auto-burst ขึ้น cloud, ไม่ auto-rotate key — action อัตโนมัติจำกัดแค่
  suspend/revoke/quarantine ที่ย้อนกลับได้และมี audit
- ไม่แตะ detector ที่มีอยู่ — V1–V7 ไม่ต้องแก้ งานนี้คือ "ยกสัญญาณออกมา" ไม่ใช่
  "เขียนตัวจับใหม่"

## 7. แผนงานเป็นเฟส (พร้อมเกณฑ์รับงาน)

**Phase A — มองเห็น (crate ใหม่ `watchtower`, ไม่แตะ request path)**
- `SecurityEvent` + normalize จาก audit entry (unit test ครบทุก reason)
- `/metrics` (Prometheus text): `gateway_decisions_total{tenant,decision,reason}`,
  `gateway_extraction_level{tenant}`, `gateway_sheds_total{tenant}`,
  `gateway_detection_mode{tenant}`, `pipeline_healthy`, `alerts_dropped_total`
- Rules engine in-process: windowed counting ต่อ tenant ต่อ rule, severity,
  dedup + cooldown — เทสต์เวลา (mock clock, ไม่ `sleep` จริง)
- Webhook sink: POST JSON (event + evidence refs), timeout 5s (กฎ AGENTS.md:
  external call ต้องมี timeout), retry 3 ครั้งแบบ backoff แล้วทิ้งแบบนับได้
- เกณฑ์รับ: `cargo test/clippy/fmt` เขียว, เทสต์ยิง event ปลอมแล้ว webhook
  mock ได้ครบ, dispatch ล้มแล้ว request path ไม่ช้าลง (perf budget เดิมยังเขียว)

**Phase B — ตอบโต้ (ต้องมี Phase A ก่อน)**
- Auto-suspend tenant / revoke key / quarantine PID เมื่อกฎ CRITICAL ตรงตาม
  นโยบายที่ operator เปิด (default: แจ้งอย่างเดียว ไม่ auto — เปิด auto ทีละกฎ)
- ทุก auto-action เขียน audit entry + มี alert ของตัวเอง (action ที่เงียบคือบั๊ก)
- ตัวอย่าง Grafana dashboard JSON + runbook ภาษาไทย 1 หน้า (on-call อ่านจบใน 3 นาที)

**Phase C — รวม host plane (ต้องมี privileged env)**
- LSM deny + T-cell quarantine เข้า pipeline เดียวกัน (event source ที่สอง)
- กฎข้าม plane (เช่น gateway เห็น injection + host เห็น syscall แปลกจาก tenant
  เดียวกันใน 10 นาที = CRITICAL ทันที)

## 8. คำถามที่ต้องตอบก่อนลงมือ (ผู้รีวิวตัดสินใจ)

1. **ช่องทางแจ้งเตือนแรกคืออะไร** — webhook กลาง (แนะนำ: Slack กับ PagerDuty รับ
   webhook ได้ทั้งคู่ ไม่ต้องเขียนสองรอบ) หรือมีช่องทางบังคับขององค์กรอยู่แล้ว?
2. **Auto-response เปิดแค่ไหนในวันแรก** — ข้อเสนอ: default แจ้งอย่างเดียวทุกกฎ,
   เปิด auto-suspend ได้ทีละ tenant หลังดู 2 สัปดาห์ รับได้ไหม?
3. **ชื่อ crate `watchtower` โอเคไหม** — หรืออยากได้ชื่ออื่น (ใน repo มี
   immune-system ที่ใช้คำชีววิทยา ถ้าอยากให้เข้าธีมอาจใช้ชื่อแนวนั้น)
4. **เก็บ event ดิบไว้ที่ไหน** — เสนอ: ไม่เก็บซ้ำ ใช้ audit chain เป็น store
   (alert ชี้ไปหา evidence) ถ้าต้องการค้นย้อนหลังเร็ว ค่อยคุยเรื่อง index ทีหลัง
5. **เกณฑ์ A1–A10 รับได้ไหม** — ตัวเลขตั้งต้นมาจากอากาศ ต้อง tune จาก traffic จริง
   ใครเป็นเจ้าของการ tune (platform team หรือเรา)?

> อนุมัติเอกสารนี้ = ตอบ 5 ข้อนี้ + ตั้ง task ANK-071 (Phase A) ใน `docs/tasks.json`
> งานโค้ดเริ่มได้ทันทีหลังอนุมัติ ไม่ต้องรอ design รอบสอง
