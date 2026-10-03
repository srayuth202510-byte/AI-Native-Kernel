# Attack Corpus — ชุดจำลองการโจมตีสำหรับ replay harness (`../redteam.rs`)

กฎของ corpus นี้ (แหก = เทสต์ schema ตก):
1. `body` ใช้ PII/secret **สังเคราะห์เท่านั้น** — ห้ามข้อมูลจริงเด็ดขาด
   (บัตร `4111...` คือ test number ของ Visa, SSN `123-45-6789` คือตัวอย่างในเอกสาร,
   เลขบัตรประชาชนไทยเป็นตัวเลขสมมติล้วน)
2. ทุกไฟล์ต้องมี `expect.decision` + `expect.reason` — ไม่มี "ยิงดูเฉย ๆ"
3. สอง tier:
   - `blocked/` — ต้องกันได้ (gate CI ตกถ้าหลุด)
   - `advisory/` — ช่องโหว่ที่รู้ตัวหรือสงสัย (รายงาน ไม่ gate; ถ้าวันไหนกันได้
     harness จะบอกให้ promote ขึ้น `blocked/`)
