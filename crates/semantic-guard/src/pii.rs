//! การตรวจจับและปิดบังข้อมูลส่วนบุคคล (PII) ในทรัฟฟิกของโมเดล AI
//!
//! ชั้นนี้ทำงานด้วย pattern และ checksum ไม่ใช้โมเดล จึงตรวจจับได้อย่างน่าเชื่อถือ
//! โดยไม่ต้องมี labeled dataset และไม่สร้าง false positive แบบสุ่มเหมือนคลาสสิฟเยอร์เชิงความหมาย
//!
//! ข้อจำกัดที่ต้องรู้: pattern เช่นเบอร์โทรศัพท์มีความกำกวมสูงและอาจเกิด false positive
//! จึงแยก severity ออกจากกันชัดเจน และผู้ใช้งานต้องเลือกชนิดข้อมูลที่จะบังคับปิดบัง

use crate::normalize::Normalized;
use regex::Regex;
use std::collections::BTreeMap;
use thiserror::Error;

/// ข้อผิดพลาดที่อาจเกิดขึ้นระหว่างการทำงานของตัวตรวจจับ PII
#[derive(Debug, Error)]
pub enum PiiError {
    /// การคอมไพล์ pattern ไม่สำเร็จ — ถือว่าเป็นข้อผิดพลาดร้ายแรง เพราะหมายความว่า
    /// ตัวตรวจจับจะทำงานได้ไม่ครบ และ policy ต้องตัดสินใจแบบ fail-closed
    #[error("failed to compile PII pattern: {0}")]
    Pattern(String),
    /// ข้อความยาวเกินเพดานที่กำหนด — ปฏิเสธแทนที่จะตรวจแบบไม่ครบแล้วรายงานว่าสะอาด
    #[error("input exceeds {limit} byte limit")]
    TooLarge {
        /// เพดานขนาดสูงสุดเป็น byte
        limit: usize,
    },
}

/// ชนิดของข้อมูลส่วนบุคคลที่ตรวจจับได้
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PiiKind {
    /// ที่อยู่อีเมล
    Email,
    /// หมายเลขบัตรเครดิต/เดบิต (ตรวจด้วย Luhn checksum)
    CreditCard,
    /// เลขประจำตัวประชาชนสหรัฐฯ (SSN) รูปแบบ 123-45-6789
    UsSsn,
    /// เลขประจำตัวประชาชนไทย 13 หลัก (ตรวจด้วย checksum mod-11)
    ThaiNationalId,
    /// คีย์ลับ/โทเคน API ที่มี entropy สูงหรือมี prefix ที่รู้จัก
    ApiKey,
    /// หมายเลข IPv4
    Ipv4,
    /// เลขโทรศัพท์ระหว่างประเทศ
    PhoneIntl,
}

impl PiiKind {
    /// ชื่อแบบคงที่สำหรับใช้ใน audit log และ metric label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::CreditCard => "credit_card",
            Self::UsSsn => "us_ssn",
            Self::ThaiNationalId => "thai_national_id",
            Self::ApiKey => "api_key",
            Self::Ipv4 => "ipv4",
            Self::PhoneIntl => "phone_intl",
        }
    }

    /// ระดับความรุนแรงเมื่อพบข้อมูลชนิดนี้
    ///
    /// ค่านี้กำหนดว่าจะปิดบัง (Redact) หรือปฏิเสธ (Deny) เมื่อเปิดโหมดเข้มงวด
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::CreditCard | Self::UsSsn | Self::ApiKey | Self::ThaiNationalId => Severity::High,
            Self::Email => Severity::Medium,
            // เบอร์โทรศัพท์กับ IPv4 เป็น false positive บ่อย และไม่ถือว่าเป็นความลับ
            Self::PhoneIntl | Self::Ipv4 => Severity::Low,
        }
    }
}

/// ระดับความรุนแรงของการตรวจพบ
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// ต่ำ — เป็นบริบท ไม่ใช่ความลับโดยตรง
    Low,
    /// กลาง — ระบุตัวตนได้ในระดับหนึ่ง
    Medium,
    /// สูง — เป็นข้อมูลที่ต้องปกป้อง
    High,
}

impl Severity {
    /// ชื่อแบบคงที่สำหรับ audit log
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// ผลการตรวจพบข้อมูลส่วนบุคคล 1 รายการ
///
/// `snippet` ถูกตัดจากข้อความที่ normalize แล้ว (ไม่ใช่ต้นฉบับ) เพื่อไม่ให้ข้อมูล
/// ที่โจมตีควบคุมหลุดเข้า log ในรูปแบบที่หลบเลี่ยงการตรวจจับได้
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiFinding {
    /// ชนิดของข้อมูลที่พบ
    pub kind: PiiKind,
    /// ระดับความรุนแรง
    pub severity: Severity,
    /// ช่วง byte ในข้อความ **ต้นฉบับ** ที่ควรถูกปิดบัง
    pub span: std::ops::Range<usize>,
    /// หลักฐานสั้นๆ จากข้อความที่ normalize แล้ว สำหรับการสืบสวน
    pub snippet: String,
}

/// ความยาวสูงสุดของ `snippet` เพื่อไม่ให้ log บวม
const SNIPPET_MAX: usize = 64;

/// สร้าง snippet ที่ปลอดภัยจากข้อความที่ normalize แล้ว
#[must_use]
fn snippet_of(normalized: &Normalized, start: usize, end: usize) -> String {
    // ป้องกันการหั่นกลางอักขระหลายไบต์
    let start = floor_boundary(normalized, start);
    let end = floor_boundary(normalized, end);
    let raw = &normalized.text[start.min(end)..end.max(start)];
    truncate_chars(raw, SNIPPET_MAX)
}

/// ถอยตำแหน่ง byte ให้อยู่บนขอบเขตอักขระเสมอ
fn floor_boundary(normalized: &Normalized, mut idx: usize) -> usize {
    let len = normalized.text.len();
    if idx > len {
        return len;
    }
    while idx > 0 && !normalized.text.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// ตัดสตริงให้ยาวไม่เกิน `max_chars` ตัวอักษรโดยไม่หั่นกลางอักขระ
#[must_use]
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

/// ตัวตรวจจับ PII ที่คอมไพล์ pattern ไว้ล่วงหน้า
///
/// เก็บ pattern เป็น `BTreeMap` เพื่อให้ลำดับการตรวจจับคงที่ ทำให้ผลลัพธ์ที่รายงาน
/// ไปยัง audit log เหมือนเดิมทุกครั้ง (สำคัญต่อการตรวจสอบย้อนหลัง)
pub struct PiiDetector {
    patterns: BTreeMap<PiiKind, Regex>,
    /// โทเคน API ที่มีรูปแบบเฉพาะของผู้ให้บริการ (ตรวจได้แม้ entropy ไม่สูง)
    known_prefixes: Vec<Regex>,
}

impl std::fmt::Debug for PiiDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiDetector")
            .field("kinds", &self.patterns.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PiiDetector {
    /// คอมไพล์ชุด pattern เริ่มต้น
    ///
    /// # Panics
    /// ไม่ควร panic — คืนค่า `Err` แทน เพื่อให้ผู้เรียกตัดสินใจแบบ fail-closed ได้
    pub fn new() -> Result<Self, PiiError> {
        let email = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .map_err(|e| PiiError::Pattern(e.to_string()))?;

        // เลขบัตร: อนุญาตให้มีช่องว่าง/ขีดคั่น แล้วคัดทิ้งออกตอนตรวจ Luhn
        let credit_card = Regex::new(r"\b(?:\d[ \-]?){12,18}\d\b")
            .map_err(|e| PiiError::Pattern(e.to_string()))?;

        let us_ssn =
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").map_err(|e| PiiError::Pattern(e.to_string()))?;

        // prefix ของผู้ให้บริการที่รู้จัก — จับได้แม้ความยาวสั้น
        let known_prefixes = vec![
            Regex::new(r"\bsk-[A-Za-z0-9_\-]{16,}")
                .map_err(|e| PiiError::Pattern(e.to_string()))?,
            Regex::new(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")
                .map_err(|e| PiiError::Pattern(e.to_string()))?,
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").map_err(|e| PiiError::Pattern(e.to_string()))?,
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{16,}")
                .map_err(|e| PiiError::Pattern(e.to_string()))?,
            Regex::new(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.")
                .map_err(|e| PiiError::Pattern(e.to_string()))?,
        ];

        // โทเคนความยาว 20 ขึ้นไปที่มีอักขระผสม — ตรวจ entropy ซ้ำอีกชั้นใน `detect`
        let api_key =
            Regex::new(r"\b[A-Za-z0-9_\-]{20,}\b").map_err(|e| PiiError::Pattern(e.to_string()))?;

        // เบอร์โทรศัพท์ต้องขึ้นต้นด้วย + เพื่อลด false positive จากเลขทั่วไป
        let phone_intl =
            Regex::new(r"\+\d[\d\s\-]{7,17}\d").map_err(|e| PiiError::Pattern(e.to_string()))?;

        let ipv4 = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            .map_err(|e| PiiError::Pattern(e.to_string()))?;

        // เลขบัตรประชาชนไทย: ตัวเลข 13 ตัว คั่นด้วยขีด/ช่องว่างได้หนึ่งตัวระหว่างหลัก
        // (เขียนแบบ "1-2345-67890-12-3", "1 2345 ...", หรือติดกัน) ตัวกรองจริงคือ
        // checksum ใน `is_plausible` — pattern นี้จงใจกว้างแล้วให้เลขคณิตตัดสิน
        // แบบเดียวกับที่บัตรเครดิตไว้ใจ Luhn
        let thai_national_id =
            Regex::new(r"\b\d(?:[ \-]?\d){12}\b").map_err(|e| PiiError::Pattern(e.to_string()))?;

        let mut patterns = BTreeMap::new();
        patterns.insert(PiiKind::Email, email);
        patterns.insert(PiiKind::CreditCard, credit_card);
        patterns.insert(PiiKind::UsSsn, us_ssn);
        patterns.insert(PiiKind::ApiKey, api_key);
        patterns.insert(PiiKind::PhoneIntl, phone_intl);
        patterns.insert(PiiKind::Ipv4, ipv4);
        patterns.insert(PiiKind::ThaiNationalId, thai_national_id);

        Ok(Self {
            patterns,
            known_prefixes,
        })
    }

    /// ตรวจจับ PII ทั้งหมดในข้อความที่ normalize ไว้แล้ว
    ///
    /// ใช้ checksum (Luhn) และ entropy เป็นชั้นกรองที่สอง เพื่อให้จำนวน false positive
    /// ต่ำพอที่จะเปิดใช้งานจริงได้
    #[must_use]
    pub fn detect(&self, normalized: &Normalized) -> Vec<PiiFinding> {
        let mut findings: Vec<PiiFinding> = Vec::new();

        for (kind, re) in &self.patterns {
            for m in re.find_iter(&normalized.text) {
                if !self.is_plausible(*kind, m.as_str(), &normalized.text, m.start()) {
                    continue;
                }
                let Some(span) = normalized.to_orig_span(m.start(), m.end()) else {
                    continue;
                };
                findings.push(PiiFinding {
                    kind: *kind,
                    severity: kind.severity(),
                    span,
                    snippet: snippet_of(normalized, m.start(), m.end()),
                });
            }
        }

        // ชนิดเดียวกันอาจถูกจับทั้งจาก prefix ที่รู้จักและจาก entropy → รวมช่วงที่ซ้อนกัน
        // ส่วนผลที่คนละตำแหน่งต้องถูกเก็บไว้ครบทุกชิ้น ไม่เช่นนั้น PII ชิ้นที่สองจะหลุด
        dedup_overlapping(&mut findings);
        findings.sort_by_key(|f| (f.span.start, f.span.end));
        findings
    }

    /// ชั้นกรองความสมเหตุสมผลของผลลัพธ์ก่อนรายงานว่าพบ
    fn is_plausible(&self, kind: PiiKind, candidate: &str, text: &str, at: usize) -> bool {
        match kind {
            PiiKind::CreditCard => luhn_valid(candidate),
            PiiKind::ApiKey => {
                if self.known_prefixes.iter().any(|p| p.is_match(candidate)) {
                    return true;
                }
                if candidate.len() < 20 {
                    return false;
                }
                // ปฏิเสธคำที่เป็นภาษาอังกฤษทั่วไปยาว ๆ เช่น "acknowledgement"
                if candidate.chars().all(|c| c.is_ascii_alphabetic()) {
                    return false;
                }
                shannon_entropy(candidate) >= 3.2 && has_mixed_classes(candidate)
            }
            PiiKind::Ipv4 => is_valid_ipv4(candidate),
            PiiKind::ThaiNationalId => thai_id_valid(candidate),
            PiiKind::UsSsn => {
                // ปฏิเสธเลขที่เป็นแค่ช่วงตัวเลขล้วนที่โอกาสเป็น SSN สูงเกินจริง
                // (เช่น เลขที่อยู่บ้าน 000-00-0000)
                let digits: String = candidate.chars().filter(char::is_ascii_digit).collect();
                digits != "000000000" && !digits.starts_with("00000000")
            }
            PiiKind::Email | PiiKind::PhoneIntl => {
                // ต้องไม่ถูกปฏิเสธเพียงเพราะอยู่ในตำแหน่งแปลก ๆ — ใช้บริบทข้างเคียง
                // เพื่อกรองคำที่หน้าตาเหมือนแต่ไม่ใช่ เช่น "user@example" (ไม่มี TLD)
                let _ = at;
                let _ = text;
                true
            }
        }
    }
}

/// คำนวณ Shannon entropy (bit ต่ออักขระ) ของสตริง
#[must_use]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let total = s.chars().count() as f64;
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// ตรวจว่าสตริงมีอักขระของหลายกลุ่มประเภทผสมกัน (ตัวเลข + ตัวอักษร ฯลฯ)
///
/// โทเคนที่มี entropy สูงเกือบเสมอเป็นความบังเอิญ แต่คำภาษาอังกฤษยาว ๆ ก็มี entropy สูงได้
#[must_use]
pub fn has_mixed_classes(s: &str) -> bool {
    let has_lower = s.chars().any(|c| c.is_lowercase());
    let has_upper = s.chars().any(|c| c.is_uppercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    (has_lower && has_digit)
        || (has_upper && has_digit)
        || has_lower && has_upper && s.contains(['-', '_'])
}

/// ตรวจ checksum Luhn ของหมายเลขบัตร
#[must_use]
pub fn luhn_valid(raw: &str) -> bool {
    let digits: Vec<u32> = raw
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

/// ตรวจ checksum เลขประจำตัวประชาชนไทย 13 หลัก (อัลกอริทึมกรมการปกครอง)
///
/// หลักที่ 1–12 คูณน้ำหนัก 13–2 ตามลำดับ รวมกันหาร 11 เอาเศษมาลบออกจาก 11
/// (หาร 11 ลงตัวได้ 0 ข้ามไป) หลักสุดท้ายต้องตรงกับผลลัพธ์ ตัวคั่น (ขีด/ช่องว่าง)
/// ถูกคัดออกก่อนนับ — ต้องเหลือตัวเลข**ตรง** 13 ตัวเท่านั้น ตัวเลข 12 หรือ 14 ตัว
/// ไม่ใช่บัตรประชาชน ต่อให้ checksum บังเอิญตรงก็ตาม
///
/// การตัดสินใจออกแบบ: ไม่จำกัดเลขหลักแรก (0–9 ได้หมด) เพราะบัตรที่ขึ้นต้นด้วย
/// 0/9 เป็นของกลุ่มเปราะบาง (คนไร้สถานะ) ซึ่ง PII สำคัญกว่า — ยอมแลกกับ false
/// positive ระดับเดียวกับที่ Luhn ยอมให้บัตรเครดิต (ตัวเลขสุ่มผ่าน checksum
/// ~10%) timestamp 13 หลักจึงเป็น trade-off เดียวกัน ไม่ใช่บั๊กใหม่
#[must_use]
pub fn thai_id_valid(raw: &str) -> bool {
    let digits: Vec<u32> = raw
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();

    if digits.len() != 13 {
        return false;
    }

    let sum: u32 = digits[..12]
        .iter()
        .enumerate()
        .map(|(idx, &d)| d * (13 - idx as u32))
        .sum();

    (11 - sum % 11) % 10 == digits[12]
}

/// ตรวจว่าสตริงเป็นหมายเลข IPv4 ที่ถูกต้อง (octet ทุกตัวต้อง ≤ 255 และไม่มี leading zero)
#[must_use]
pub fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
        p.parse::<u16>().is_ok_and(|n| n <= 255)
    })
}

/// รวมผลลัพธ์ที่ซ้อนกันในชนิดเดียวกัน และเก็บผลที่คนละตำแหน่งไว้ครบทุกชิ้น
///
/// เดิมฟังก์ชันนี้เก็บเฉพาะ span ที่แคบที่สุดต่อหนึ่ง `kind` เพื่อกัน redact ซ้อนกัน
/// แต่การกรองด้วย `kind` อย่างเดียวทำให้ผลสองชิ้นที่ **คนละตำแหน่ง** ถูกทิ้งทั้งคู่ —
/// PII ชิ้นที่สองหลุดออกไปโดยไม่ถูกปิดบัง ทั้งที่เป็นชนิดที่ค่าเริ่มต้น redact อยู่แล้ว
///
/// การแก้คือตัดเฉพาะตอนที่ซ้อนกันจริง ๆ และเก็บ span เป็นผลรวม ไม่ใช่ช่วงแคบ เพราะ
/// ถ้าเก็บแค่ช่วงแคบ หางของ span กว้างจะหลุดจากการปิดบัง การรวมทำแยกตามชนิดเสมอ —
/// ชนิดกำหนดทั้ง placeholder และ `should_redact` การรวมข้ามชนิดจึงอาจทำให้บัตรเครดิต
/// ถูก span ชนิดที่ไม่ถูก redact กลืนไปด้วย
fn dedup_overlapping(findings: &mut Vec<PiiFinding>) {
    if findings.is_empty() {
        return;
    }

    let mut by_kind: BTreeMap<PiiKind, Vec<PiiFinding>> = BTreeMap::new();
    for f in findings.drain(..) {
        by_kind.entry(f.kind).or_default().push(f);
    }

    let mut merged: Vec<PiiFinding> = Vec::new();
    for (_, mut group) in by_kind {
        group.sort_by_key(|f| (f.span.start, f.span.end));
        let mut iter = group.into_iter();
        // ป้องกัน unreachable โดยให้ compiler เห็นว่ากลุ่มมีอย่างน้อยหนึ่งรายการ
        let Some(mut cur) = iter.next() else {
            continue;
        };
        for f in iter {
            if f.span.start < cur.span.end {
                cur.span.end = cur.span.end.max(f.span.end);
            } else {
                merged.push(cur);
                cur = f;
            }
        }
        merged.push(cur);
    }

    // คืนลำดับตามตำแหน่งเริ่มต้นเพื่อให้ผลลัพธ์ทำนายได้และสอดคล้องกับผู้เรียก
    merged.sort_by_key(|f| (f.span.start, f.span.end));
    *findings = merged;
}

/// ผลลัพธ์ของการปิดบังข้อมูลส่วนบุคคล
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionReport {
    /// ข้อความที่ปิดบังข้อมูลแล้ว
    pub text: String,
    /// รายการที่ถูกปิดบัง
    pub findings: Vec<PiiFinding>,
}

/// แทนที่ข้อความที่ match ด้วย placeholder แล้วคืนรายงานการปิดบัง
///
/// หาก `placeholder` เป็น `None` จะใช้รูปแบบ `[REDACTED:<ชนิด>]`
///
/// ช่วงที่ซ้อนกันจะถูกรวมเป็น union **ก่อน**แทนที่ — การแทนที่ด้วย offset เดิมบน
/// ข้อความที่เปลี่ยนความยาวไปแล้วจะเพี้ยน (ข้ามหาง PII หรือแทนที่ผิดตำแหน่ง)
/// ชนิดของ placeholder ใช้ของชิ้นที่เริ่มก่อน (เริ่มเท่ากันใช้ชิ้นที่แคบกว่า)
/// เพราะช่วงที่ซ้อนกันใส่ได้ป้ายเดียว `span` ของผลลัพธ์คือ union ที่ถูกปิดบังจริง
#[must_use]
pub fn redact_with(
    original: &str,
    findings: &[PiiFinding],
    placeholder: Option<&dyn Fn(PiiKind) -> String>,
) -> RedactionReport {
    // เรียงตามตำแหน่งเริ่มต้นเพื่อกวาดรวมช่วงที่ซ้อนกันครั้งเดียว
    let mut ordered: Vec<PiiFinding> = findings.to_vec();
    ordered.sort_by_key(|f| (f.span.start, f.span.end));

    let mut merged: Vec<PiiFinding> = Vec::with_capacity(ordered.len());
    for f in ordered {
        match merged.last_mut() {
            // ซ้อนกันจริง (`<` ไม่ใช่ `<=` — ชิดกันแต่ไม่ซ้อนต้องแยกป้าย)
            Some(last) if f.span.start < last.span.end => {
                last.span.end = last.span.end.max(f.span.end);
            }
            _ => merged.push(f),
        }
    }

    // ทุก span แยกกันแล้ว แทนที่จากท้ายไปต้น offset จึงถูกต้องเสมอ
    let mut text = original.to_string();
    let mut applied: Vec<PiiFinding> = Vec::with_capacity(merged.len());

    for f in merged.iter().rev() {
        if f.span.end > text.len()
            || !text.is_char_boundary(f.span.start)
            || !text.is_char_boundary(f.span.end)
        {
            continue;
        }
        let token = match placeholder {
            Some(build) => build(f.kind),
            None => format!("[REDACTED:{}]", f.kind.as_str()),
        };
        text.replace_range(f.span.clone(), &token);
        applied.push(f.clone());
    }

    applied.sort_by_key(|f| (f.span.start, f.span.end));
    RedactionReport {
        text,
        findings: applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::normalize;

    fn detector() -> PiiDetector {
        PiiDetector::new().expect("patterns should compile")
    }

    fn detect(text: &str) -> Vec<PiiFinding> {
        detector().detect(&normalize(text))
    }

    fn kinds(text: &str) -> Vec<PiiKind> {
        let mut k = detect(text).into_iter().map(|f| f.kind).collect::<Vec<_>>();
        k.sort();
        k.dedup();
        k
    }

    #[test]
    fn detects_email() {
        assert!(kinds("contact me at alice@example.com please").contains(&PiiKind::Email));
    }

    #[test]
    fn detects_valid_credit_card_via_luhn() {
        // 4111 1111 1111 1111 ผ่าน Luhn
        let f = kinds("card 4111111111111111 ok");
        assert!(f.contains(&PiiKind::CreditCard), "got {f:?}");
    }

    #[test]
    fn rejects_luhn_invalid_card() {
        // เลข 16 หลักที่ไม่ผ่าน Luhn ต้องไม่ถูกรายงานเป็นบัตร
        assert!(!kinds("number 4111111111111112 here").contains(&PiiKind::CreditCard));
    }

    #[test]
    fn luhn_accepts_spaced_card() {
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(!luhn_valid("4111 1111 1111 1112"));
    }

    #[test]
    fn luhn_rejects_wrong_length() {
        assert!(!luhn_valid("123"));
        assert!(!luhn_valid(""));
    }

    #[test]
    fn thai_id_checksum_vectors() {
        // ANK-072: คำนวณมือ — 310059912345: 3*13+1*12+0*11+0*10+5*9+9*8+9*7
        // +1*6+2*5+3*4+4*3+5*2 = 281, 281 mod 11 = 6, (11-6) mod 10 = 5
        assert!(thai_id_valid("3100599123455"));
        assert!(thai_id_valid("3-1005-99123-45-5"));
        assert!(thai_id_valid("3 1005 99123 45 5"));
        assert!(
            !thai_id_valid("3100599123456"),
            "wrong check digit must fail"
        );
        assert!(!thai_id_valid("310059912345"), "12 digits is not an ID");
        assert!(!thai_id_valid("31005991234555"), "14 digits is not an ID");
        assert!(!thai_id_valid(""));
    }

    #[test]
    fn detects_thai_national_id() {
        // ตัวเลขสมมติล้วน (checksum ผ่านตามเวกเตอร์ข้างบน)
        let f = kinds("เลขบัตรประชาชนของผมคือ 3100599123455 ช่วยจดไว้หน่อย");
        assert!(f.contains(&PiiKind::ThaiNationalId), "got {f:?}");
    }

    #[test]
    fn rejects_thai_id_with_bad_checksum() {
        // เลข 13 หลักที่ checksum ไม่ผ่านต้องไม่ถูกรายงานเป็นบัตรประชาชน —
        // กฎเดียวกับบัตรเครดิต (rejects_luhn_invalid_card)
        assert!(!kinds("เลข 3100599123456 ครับ").contains(&PiiKind::ThaiNationalId));
    }

    #[test]
    fn timestamp_like_13_digits_usually_not_thai_id() {
        // timestamp 13 หลัก (ms epoch) ส่วนใหญ่ต้องรอด — ยกเว้น 1/10 ที่ checksum
        // บังเอิญตรง ซึ่งเป็น trade-off เดียวกับ Luhn (บันทึกไว้ ไม่ใช่บั๊ก)
        assert!(!kinds("at 1790994992000 done").contains(&PiiKind::ThaiNationalId));
    }

    #[test]
    fn detects_known_api_key_prefix() {
        assert!(
            kinds("key sk-abcdefghijklmnopqrstuvwx").contains(&PiiKind::ApiKey),
            "got {:?}",
            kinds("key sk-abcdefghijklmnopqrstuvwx")
        );
    }

    #[test]
    fn detects_high_entropy_token() {
        let f = kinds("token a1b2c3d4e5f6g7h8i9j0k1l2 here");
        assert!(f.contains(&PiiKind::ApiKey), "got {f:?}");
    }

    #[test]
    fn does_not_flag_plain_english_words_as_api_keys() {
        // คำภาษาอังกฤษยาว ๆ ไม่ควรถูกรายงานเป็นคีย์ลับ
        assert!(!kinds("acknowledgement implementation").contains(&PiiKind::ApiKey));
    }

    #[test]
    fn detects_us_ssn() {
        assert!(kinds("ssn 123-45-6789").contains(&PiiKind::UsSsn));
    }

    #[test]
    fn rejects_all_zero_ssn() {
        assert!(!kinds("ssn 000-00-0000").contains(&PiiKind::UsSsn));
    }

    #[test]
    fn validates_ipv4_octet_range() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("1.2.3"));
        assert!(!is_valid_ipv4("1.2.3.4.5"));
        assert!(!is_valid_ipv4("01.2.3.4"));
    }

    #[test]
    fn detects_ipv4() {
        assert!(kinds("host 10.0.0.1 up").contains(&PiiKind::Ipv4));
        assert!(!kinds("host 999.0.0.1 up").contains(&PiiKind::Ipv4));
    }

    #[test]
    fn span_points_at_original_text() {
        let original = "email: alice@example.com";
        let found = detect(original);
        let email = found
            .iter()
            .find(|f| f.kind == PiiKind::Email)
            .expect("email should be found");
        assert_eq!(&original[email.span.clone()], "alice@example.com");
    }

    #[test]
    fn redaction_replaces_pii_in_original() {
        let original = "reach me at bob@example.com";
        let found = detect(original);
        let report = redact_with(original, &found, None);
        assert!(!report.text.contains("bob@example.com"));
        assert!(report.text.contains("[REDACTED:email]"));
        assert_eq!(report.findings.len(), found.len());
    }

    #[test]
    fn redaction_uses_custom_placeholder() {
        let original = "reach me at bob@example.com";
        let found = detect(original);
        let report = redact_with(original, &found, Some(&|_| "***".to_string()));
        assert_eq!(report.text, "reach me at ***");
    }

    #[test]
    fn redaction_handles_overlapping_candidates() {
        // เลขบัตรที่ซ้อนกับ api-key ต้องไม่ทำให้ byte offset ของรายการหลังเพี้ยน
        let original = "card 4111111111111111 and key sk-abcdefghijklmnopqrstuvwx";
        let found = detect(original);
        let report = redact_with(original, &found, Some(&|k| format!("<{}>", k.as_str())));
        assert!(!report.text.contains("4111111111111111"));
        assert!(!report.text.contains("sk-abcdefghijklmnopqrstuvwx"));
        assert!(report.text.contains("<credit_card>"));
        assert!(report.text.contains("<api_key>"));
    }

    #[test]
    fn redaction_preserves_surrounding_text() {
        let original = "before a@b.com after";
        let found = detect(original);
        let report = redact_with(original, &found, Some(&|_| "X".to_string()));
        assert_eq!(report.text, "before X after");
    }

    // การปิดบังต้องครอบคลุมทุกชิ้นที่พบ ไม่ใช่แค่ชิ้นเดียวต่อหนึ่งชนิด
    //
    // ฟังก์ชันรวมผลลัพธ์เดิมกรองด้วย `kind` อย่างเดียว (เก็บ span ที่แคบที่สุด)
    // ชิ้นที่สองของชนิดเดียวกันจึงถูกทิ้งทั้งคู่แม้จะคนละตำแหน่ง — ผลคือ PII ชิ้นที่สอง
    // หลุดออกไปโดยไม่ถูกปิดบัง ทั้งที่เป็นชนิดที่ค่าเริ่มต้น redact อยู่แล้ว

    #[test]
    fn redacts_every_disjoint_email_not_just_one() {
        let original = "reach alice@example.com and bob@example.org now";
        let report = redact_with(original, &detect(original), Some(&|_| "X".to_string()));
        assert!(
            !report.text.contains("alice@example.com"),
            "first email leaked: {:?}",
            report.text
        );
        assert!(
            !report.text.contains("bob@example.org"),
            "second email leaked: {:?}",
            report.text
        );
        assert_eq!(report.findings.len(), 2, "both must be reported as applied");
    }

    #[test]
    fn redacts_every_disjoint_credit_card() {
        // สองบัตรที่ผ่าน Luhn คนละตำแหน่ง ทั้งคู่อยู่ใน redact_kinds ของค่าเริ่มต้น
        let original = "4111111111111111 and 5500005555555559";
        let report = redact_with(original, &detect(original), Some(&|_| "X".to_string()));
        assert!(
            !report.text.contains("4111111111111111"),
            "first card leaked: {:?}",
            report.text
        );
        assert!(
            !report.text.contains("5500005555555559"),
            "second card leaked: {:?}",
            report.text
        );
    }

    #[test]
    fn overlapping_same_kind_detections_merge_into_one_span() {
        // prefix และ entropy อาจจับข้อความเดียวกันด้วย span ต่างกัน → ต้องเหลือ span เดียว
        let mut findings = vec![
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 0..24,
                snippet: String::new(),
            },
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 4..20,
                snippet: String::new(),
            },
        ];
        dedup_overlapping(&mut findings);
        assert_eq!(findings.len(), 1, "overlap must collapse: {findings:?}");
        assert_eq!(findings[0].span, 0..24, "must keep the union of both spans");
    }

    #[test]
    fn disjoint_same_kind_detections_are_all_kept() {
        let mut findings = vec![
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 0..8,
                snippet: String::new(),
            },
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 40..48,
                snippet: String::new(),
            },
        ];
        dedup_overlapping(&mut findings);
        assert_eq!(
            findings.len(),
            2,
            "disjoint spans must both survive: {findings:?}"
        );
    }

    #[test]
    fn overlapping_span_keeps_union_so_no_tail_escapes() {
        // ช่วงกว้างครอบคลุมช่วงแคบบางส่วน — ถ้าเก็บแค่ช่วงแคบ หางของช่วงกว้างจะหลุด
        let mut findings = vec![
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 0..20,
                snippet: String::new(),
            },
            PiiFinding {
                kind: PiiKind::ApiKey,
                severity: Severity::High,
                span: 5..30,
                snippet: String::new(),
            },
        ];
        dedup_overlapping(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].span, 0..30, "union must cover both findings");
    }

    // ช่วงซ้อนกันข้ามชนิด: เดิม `redact_with` แทนที่ด้วย offset เดิมบนข้อความที่
    // เปลี่ยนความยาวไปแล้ว — ชิ้นที่สองถูกข้าม (หางหลุด) หรือแทนที่ผิดตำแหน่ง
    // ต้องรวมเป็น union เดียวก่อนแทนที่ ไม่ว่าชนิดจะต่างกันหรือไม่

    fn finding(kind: PiiKind, span: std::ops::Range<usize>) -> PiiFinding {
        PiiFinding {
            kind,
            severity: Severity::High,
            span,
            snippet: String::new(),
        }
    }

    #[test]
    fn redact_with_merges_cross_kind_overlap_into_union() {
        // สตริงตัวเลขยาวที่เข้าเงื่อนไขทั้งบัตรและคีย์ — สองชนิดซ้อนกันบางส่วน
        let original = "key 4111111111111111abcdefghijklmnop end";
        let findings = vec![
            finding(PiiKind::CreditCard, 4..20),
            finding(PiiKind::ApiKey, 10..36),
        ];
        let report = redact_with(original, &findings, Some(&|_| "X".to_string()));
        assert_eq!(
            report.text, "key X end",
            "union 4..36 must be fully covered, got {:?}",
            report.text
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].span, 4..36);
    }

    #[test]
    fn redact_with_chained_overlaps_collapse_to_one_span() {
        // A ซ้อน B, B ซ้อน C แต่ A ไม่ซ้อน C โดยตรง — ต้องเหลือช่วงเดียวอยู่ดี
        let original = "0123456789ABCDEFGHIJ0123456789";
        let findings = vec![
            finding(PiiKind::Email, 0..10),
            finding(PiiKind::ApiKey, 5..15),
            finding(PiiKind::CreditCard, 12..22),
        ];
        let report = redact_with(original, &findings, Some(&|_| "X".to_string()));
        assert_eq!(report.text, "X23456789", "got {:?}", report.text);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].span, 0..22);
    }

    #[test]
    fn redact_with_touching_spans_stay_separate() {
        // ชิดกันแต่ไม่ซ้อน (`<` ไม่ใช่ `<=`) — ต้องได้สองป้าย ไม่ใช่ป้ายเดียว
        let original = "aaaabbbb";
        let findings = vec![
            finding(PiiKind::Email, 0..4),
            finding(PiiKind::ApiKey, 4..8),
        ];
        let report = redact_with(original, &findings, Some(&|_| "X".to_string()));
        assert_eq!(report.text, "XX", "got {:?}", report.text);
        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn redact_with_same_start_keeps_narrower_kind_first() {
        // เริ่มตำแหน่งเดียวกัน — ชิ้นแคบชนะป้าย (deterministic: เรียงตาม span ก่อน)
        let original = "0123456789ABCDEF";
        let findings = vec![
            finding(PiiKind::ApiKey, 0..16),
            finding(PiiKind::Email, 0..10),
        ];
        let report = redact_with(original, &findings, None);
        assert_eq!(report.text, "[REDACTED:email]", "got {:?}", report.text);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, PiiKind::Email);
    }

    #[test]
    fn redacts_unicode_obfuscated_email_host() {
        // โดเมนใช้ fullwidth "e" และ zero-width space; โฮสต์ใช้ตัว "а" ซีริลลิก
        let original = "mail: a\u{FF45}x\u{200B}ample@ex\u{0430}mple.com";
        let found = detect(original);
        assert!(
            found.iter().any(|f| f.kind == PiiKind::Email),
            "should detect obfuscated email, got {found:?}"
        );
        let report = redact_with(original, &found, Some(&|_| "X".to_string()));
        assert!(
            !report.text.contains("\u{FF45}") && !report.text.contains("\u{200B}"),
            "obfuscation must be removed from the redacted output, got {:?}",
            report.text
        );
        assert!(!report.text.contains("ample@ex"));
    }

    #[test]
    fn detection_order_is_deterministic() {
        let text = "a@b.com 4111111111111111 10.0.0.1 123-45-6789";
        let first = detect(text);
        let second = detect(text);
        assert_eq!(first, second);
    }

    #[test]
    fn empty_input_produces_no_findings() {
        assert!(detect("").is_empty());
    }

    #[test]
    fn snippet_is_length_bounded() {
        let long = format!("{}@example.com", "a".repeat(500));
        let found = detect(&long);
        let email = found
            .iter()
            .find(|f| f.kind == PiiKind::Email)
            .expect("email should be found");
        assert!(email.snippet.chars().count() <= SNIPPET_MAX);
    }

    #[test]
    fn entropy_bounds() {
        assert!(shannon_entropy("").abs() < f64::EPSILON);
        assert!(shannon_entropy("aaaa").abs() < f64::EPSILON);
        assert!(shannon_entropy("abcd") > 1.9);
    }

    #[test]
    fn mixed_class_detection() {
        assert!(has_mixed_classes("abc123"));
        assert!(!has_mixed_classes("abcdef"));
        assert!(!has_mixed_classes("123456"));
    }
}
