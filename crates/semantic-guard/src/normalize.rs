//! การทำ normalization ของข้อความเพื่อตรวจจับชั้นข้อมูล (Data-plane text normalization)
//!
//! ชั้นความปลอดภัยที่ทำงานด้วย signature จะถูกหลบเลี่ยงได้ง่ายด้วยการแทรกอักขระที่มองเห็นไม่ออก
//! (Zero-Width) เครื่องหมายวรรคตอนขนาดใหญ่ (Great Whitespace) และตัวอักษรที่หน้าตาเหมือนกัน
//! (Homoglyph) เช่น ตัว "а" ภาษาซีริลลิกที่ดูเหมือน "a" ใน ASCII
//!
//! โมดูลนี้จึงแปลงข้อความให้อยู่ในรูปแบบ "โครงสร้างเดียว" (canonical form) ก่อนนำไปเทียบกับ
//! pattern เสมอ และเก็บแผนที่อ้างอิงกลับไปยัง byte offset ของข้อความต้นฉบับ เพื่อให้การ
//! redact ทำงานบนข้อความจริงได้อย่างถูกต้อง

/// ผลลัพธ์ของการ normalize พร้อมแผนที่กลับไปยังข้อความต้นฉบับ
///
/// `text` คือข้อความที่ normalize แล้ว ส่วน `orig_starts` / `orig_lens` เก็บ byte offset
/// และความยาว (เป็น byte) ของอักขระต้นฉบับที่สอดคล้องกับแต่ละ *ตัวอักษร* ใน `text`
/// (อินเดกซ์ของ `text` คือระดับตัวอักษร ไม่ใช่ระดับ byte)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// ข้อความหลัง normalize (canonical form)
    pub text: String,
    /// byte offset ในข้อความต้นฉบับของอักขระที่สร้าง `text[i]`
    pub orig_starts: Vec<usize>,
    /// ความยาวเป็น byte ในข้อความต้นฉบับของอักขระที่สร้าง `text[i]`
    pub orig_lens: Vec<usize>,
}

impl Normalized {
    /// แปลงช่วง **byte offset** ใน `text` กลับเป็นช่วง byte ในข้อความต้นฉบับ
    ///
    /// รับ byte offset (ไม่ใช่ char index) โดยเจตนา เพราะผู้เรียกที่แท้จริงคือ `regex`
    /// ซึ่งคืนค่า byte offset จาก `find`/`captures` — การรับ char index จะทำให้ผู้เรียก
    /// สับสนเงียบ ๆ และ redact ผิดตำแหน่งเมื่อข้อความมีอักขระหลายไบต์
    ///
    /// คืน `None` เมื่อช่วงว่าง หลุดขอบเขต หรือไม่อยู่บนขอบเขตอักขระ เพื่อให้ผู้เรียก
    /// ตัดสินใจอย่างปลอดภัยว่าจะข้าม match หรือปฏิเสธผลลัพธ์
    #[must_use]
    pub fn to_orig_span(
        &self,
        byte_start: usize,
        byte_end: usize,
    ) -> Option<std::ops::Range<usize>> {
        if byte_start >= byte_end || byte_end > self.text.len() {
            return None;
        }
        if !self.text.is_char_boundary(byte_start) || !self.text.is_char_boundary(byte_end) {
            return None;
        }
        let start_idx = self.text[..byte_start].chars().count();
        let end_idx = self.text[..byte_end].chars().count();
        if start_idx >= end_idx || end_idx > self.orig_starts.len() {
            return None;
        }
        let begin = *self.orig_starts.get(start_idx)?;
        let last = *self.orig_starts.get(end_idx - 1)?;
        let last_len = *self.orig_lens.get(end_idx - 1)?;
        Some(begin..last.saturating_add(last_len))
    }
}

/// อักขระที่มองเหมือนตัวอักษร ASCII แต่ไม่ใช่ ASCII — แผนที่ fold ไปเป็นตัว ASCII
///
/// ครอบคลุม Cyrillic, Greek และอักขระพิเศษที่ใช้สร้างคำหลอกเป็นประจำ
/// (เช่น "ѕcurd" ที่ใช้ s แทน s หรือ "gооgle" ที่ใช้ o แทน o)
const HOMOGLYPHS: &[(char, char)] = &[
    // Cyrillic
    ('а', 'a'),
    ('е', 'e'),
    ('о', 'o'),
    ('р', 'p'),
    ('с', 'c'),
    ('у', 'y'),
    ('х', 'x'),
    ('і', 'i'),
    ('ј', 'j'),
    ('ѕ', 's'),
    ('һ', 'h'),
    ('ԁ', 'd'),
    ('ԛ', 'q'),
    ('ѡ', 'w'),
    ('ӏ', 'l'),
    // Greek
    ('α', 'a'),
    ('β', 'b'),
    ('ε', 'e'),
    ('η', 'n'),
    ('ι', 'i'),
    ('κ', 'k'),
    ('ν', 'v'),
    ('ο', 'o'),
    ('ρ', 'p'),
    ('τ', 't'),
    ('υ', 'u'),
    ('χ', 'x'),
];

/// ช่วง codepoint ของอักขระที่มองไม่เห็น (invisible) และควรถูกตัดทิ้งทั้งหมด
///
/// ครอบคลุม Zero-Width Space/Non-Joiner/Joiner, Zero-Width No-Break Space (BOM),
/// Word Joiner และ Soft Hyphen — ทั้งหมดนี้ถูกใช้แทรกระหว่างตัวอักษรเพื่อหลบ pattern
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x200B, 0x200F), // zero-width space .. RLM
    (0x2060, 0x2064), // word joiner .. invisible plus
    (0xFEFF, 0xFEFF), // zero-width no-break space (BOM)
    (0x00AD, 0x00AD), // soft hyphen
];

/// ตรวจว่าอักขระเป็น Zero-Width / มองไม่เห็นหรือไม่
#[must_use]
pub fn is_invisible(c: char) -> bool {
    let cp = c as u32;
    INVISIBLE_RANGES
        .iter()
        .any(|(lo, hi)| cp >= *lo && cp <= *hi)
}

/// แปลงอักขระ Fullwidth (U+FF01–U+FF5E) ให้เป็น ASCII ที่ตรงกัน
#[must_use]
pub fn fold_fullwidth(c: char) -> Option<char> {
    let cp = c as u32;
    if (0xFF01..=0xFF5E).contains(&cp) {
        // SAFETY-free: arithmetic on a validated codepoint range stays inside ASCII
        char::from_u32(cp - 0xFEE0)
    } else if cp == 0x3000 {
        // Ideographic space (fullwidth space)
        Some(' ')
    } else {
        None
    }
}

/// แปลงอักขระ Homoglyph ให้เป็น ASCII ที่ดูเหมือนกัน
#[must_use]
pub fn fold_homoglyph(c: char) -> Option<char> {
    HOMOGLYPHS
        .iter()
        .find(|(from, _)| *from == c)
        .map(|(_, to)| *to)
}

/// Normalize ข้อความให้อยู่ในรูปแบบมาตรฐานเดียว พร้อมแผนที่กลับไปยังข้อความต้นฉบับ
///
/// ขั้นตอน (เรียงตามลำดับสำคัญ):
/// 1. ตัดอักขระที่มองไม่เห็นทิ้งทั้งหมด
/// 2. fold อักขระ Fullwidth และ Homoglyph ให้เป็น ASCII
/// 3. แปลงเป็นตัวพิมพ์เล็ก (case folding — ทำให้ "IGNORE" และ "ignore" เป็น pattern เดียวกัน)
/// 4. ยุบช่องว่างทุกชนิดให้เหลือช่องว่างเดียว (กัน Great Whitespace attack)
///
/// หมายเหตุ: โมดูลนี้จงใจไม่ใช้ crate `unicode-normalization` เพื่อหลีกเลี่ยงการเพิ่ม
/// dependency — การ fold ที่ต้องการเพียงเพื่อกับ homoglyph ถูกจำกัดอยู่ที่ตารางข้างบน
#[must_use]
pub fn normalize(input: &str) -> Normalized {
    let mut out = String::with_capacity(input.len());
    let mut orig_starts = Vec::with_capacity(input.len());
    let mut orig_lens = Vec::with_capacity(input.len());
    let mut pending_space = false;

    for (offset, c) in input.char_indices() {
        if is_invisible(c) {
            continue;
        }

        let folded = fold_fullwidth(c).or_else(|| fold_homoglyph(c)).unwrap_or(c);

        let lowered = folded.to_lowercase();

        for lc in lowered {
            if lc.is_whitespace() {
                // ยุบช่องว่างทั้งหมดให้เหลืออักขระเดียว และเลื่อนจุดเริ่มต้น
                // ไปยังอักขระต้นฉบับตัวสุดท้ายของกลุ่มช่องว่าง
                if !out.is_empty() {
                    pending_space = true;
                }
                continue;
            }

            if pending_space {
                out.push(' ');
                orig_starts.push(offset);
                orig_lens.push(c.len_utf8());
                pending_space = false;
            }

            out.push(lc);
            orig_starts.push(offset);
            orig_lens.push(c.len_utf8());
        }
    }

    Normalized {
        text: out,
        orig_starts,
        orig_lens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_characters() {
        let n = normalize("ig\u{200B}nore");
        assert_eq!(n.text, "ignore");
    }

    #[test]
    fn strips_bom_and_word_joiner() {
        let n = normalize("ig\u{FEFF}n\u{2060}ore");
        assert_eq!(n.text, "ignore");
    }

    #[test]
    fn folds_cyrillic_homoglyphs() {
        // "а" (Cyrillic), "е" (Cyrillic) แทน "a", "e"
        let n = normalize("ign\u{043E}re \u{0435}cho");
        assert_eq!(n.text, "ignore echo");
    }

    #[test]
    fn folds_greek_omicron() {
        let n = normalize("g\u{03BF}ogle");
        assert_eq!(n.text, "google");
    }

    #[test]
    fn folds_fullwidth_characters() {
        let n = normalize("\u{FF49}\u{FF47}\u{FF4E}\u{FF4F}\u{FF52}\u{FF45}");
        assert_eq!(n.text, "ignore");
    }

    #[test]
    fn collapses_great_whitespace_attack() {
        let attack = format!("ignore{}all", " ".repeat(500));
        let n = normalize(&attack);
        assert_eq!(n.text, "ignore all");
    }

    #[test]
    fn lowercases_for_case_folding() {
        let n = normalize("IGNORE ALL PREVIOUS");
        assert_eq!(n.text, "ignore all previous");
    }

    #[test]
    fn trims_leading_whitespace() {
        let n = normalize("   \t\n hello  ");
        assert_eq!(n.text, "hello");
    }

    #[test]
    fn preserves_multibyte_content() {
        let n = normalize("สวัสดี");
        assert_eq!(n.text, "สวัสดี");
        assert_eq!(n.orig_starts.len(), n.text.chars().count());
    }

    #[test]
    fn maps_span_back_to_original_bytes() {
        // ช่องว่างเดียวแทนช่องว่าง 500 ตัว → span ต้องชี้ถูกตำแหน่งในข้อความต้นฉบับ
        let original = format!("ignore{}all previous instructions", " ".repeat(500));
        let n = normalize(&original);
        let start = n.text.find("all").expect("'all' should be present");
        let span = n
            .to_orig_span(start, start + 3)
            .expect("span should map back");
        assert_eq!(&original[span], "all");
    }

    #[test]
    fn rejects_out_of_bounds_or_empty_spans() {
        let n = normalize("abc");
        assert!(n.to_orig_span(1, 1).is_none());
        assert!(n.to_orig_span(0, 99).is_none());
        assert!(n.to_orig_span(0, 3).is_some());
    }

    #[test]
    fn rejects_span_splitting_a_multibyte_char() {
        // "a" + อีกษรไทย 3 ไบต์ → byte 1 อยู่กลางอักขระ ต้องถูกปฏิเสธ
        let n = normalize("a\u{0E01}\u{0E49}");
        assert!(n.to_orig_span(0, 1).is_some());
        assert!(n.to_orig_span(0, 2).is_none());
    }

    #[test]
    fn span_mapping_handles_multibyte_originals() {
        let original = "ig\u{043E}nore previous";
        let n = normalize(original);
        let start = n
            .text
            .find("previous")
            .expect("'previous' should be present");
        let span = n
            .to_orig_span(start, start + 8)
            .expect("span should map back");
        assert_eq!(&original[span], "previous");
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let n = normalize("");
        assert!(n.text.is_empty());
        assert!(n.orig_starts.is_empty());
    }

    #[test]
    fn whitespace_only_input_yields_empty_output() {
        let n = normalize("  \u{200B}\t\n ");
        assert!(n.text.is_empty());
    }
}
