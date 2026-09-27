//! MinHash + Jaccard estimation สำหรับจับกลุ่ม prompt ที่ "เกือบซ้ำ" (near-duplicate)
//!
//! การขโมยโมเดลแบบ extraction มีลักษณะเด่นคือผู้โจมตีจะส่ง prompt จำนวนมากที่
//! *ค่อยข้างกัน* เช่น เติมคำนำหน้า/คำต่อท้าย หรือวนลูปแบบเดิม — สิ่งที่ตรวจจับได้และ
//! ไม่ต้องใช้โมเดลคือ "ความคล้าย" ไม่ใช่ "ความหมาย"
//!
//! MinHash ประมาณค่า Jaccard similarity ของเซ็ตในเวลา O(k) โดยไม่ต้องเก็บเซ็ตเต็ม

/// จำนวน hash function ที่ใช้ประมาณค่า Jaccard
///
/// ค่ายิ่งสูงยิ่งแม่นยำแต่ช้าลง ค่า 64 ให้ความคลาดเคลื่อนราว ±6% ซึ่งเพียงพอมาก
/// สำหรับการตัดสินว่า "คล้ายกันพอจะสงสัยหรือไม่"
pub const DEFAULT_PERMUTATIONS: usize = 64;

/// ขนาด shingle (จำนวนคำต่อ shingle)
///
/// 3 คำเป็นค่ามาตรฐาน: สั้นพอให้จับความคล้ายระดับโครงสร้างประโยค
/// และยาวพอไม่ให้ prompt สั้นที่ไม่เกี่ยวข้องกันชนกันบังเอิญ
pub const DEFAULT_SHINGLE_WORDS: usize = 3;

/// ตัวผสมแฮช 64-bit แบบ splitmix64 — เร็วและกระจายค่าดีพอสำหรับ MinHash
#[must_use]
pub fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// แฮชสตริงด้วย FNV-1a แล้วผ่าน mix64
#[must_use]
pub fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    mix64(h)
}

/// โมเดล MinHash พร้อมชุดคู่สัมประสิทธิ์ (a, b) ที่สร้างจาก seed
#[derive(Debug, Clone)]
pub struct MinHasher {
    seeds: Vec<u64>,
    shingle_words: usize,
}

impl MinHasher {
    /// สร้าง MinHasher
    #[must_use]
    pub fn new(permutations: usize, seed: u64, shingle_words: usize) -> Self {
        let shingle_words = shingle_words.max(1);
        let seeds = (0..permutations.max(1))
            .map(|i| mix64(seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)))
            .collect();
        Self {
            seeds,
            shingle_words,
        }
    }

    /// สร้าง MinHasher ด้วยค่าเริ่มต้น
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_PERMUTATIONS, 0x0005_EED0, DEFAULT_SHINGLE_WORDS)
    }

    /// จำนวน hash function
    #[must_use]
    pub fn permutations(&self) -> usize {
        self.seeds.len()
    }

    /// ตัดข้อความเป็นคำ โดยตัดฐานข้อมูลและอักขระไม่ใช่ตัวอักษร/ตัวเลขออก
    #[must_use]
    pub fn tokenize(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_lowercase())
            .collect()
    }

    /// สร้างเซ็ต shingle จากข้อความ
    ///
    /// ถ้าข้อความสั้นกว่าขนาด shingle จะใช้ทั้งข้อความเป็น shingle เดียว
    /// เพื่อไม่ให้ prompt สั้น ๆ กลายเป็นเซ็ตว่าง (ซึ่งจะทำให้คล้ายกับทุกอย่าง)
    #[must_use]
    pub fn shingles(&self, text: &str) -> Vec<u64> {
        let tokens = Self::tokenize(text);
        if tokens.is_empty() {
            return Vec::new();
        }
        if tokens.len() < self.shingle_words {
            return vec![hash_str(&tokens.join(" "))];
        }
        tokens
            .windows(self.shingle_words)
            .map(|w| hash_str(&w.join("\u{1}")))
            .collect()
    }

    /// คำนวณลายเซ็น MinHash ของข้อความ
    #[must_use]
    pub fn signature(&self, text: &str) -> Vec<u64> {
        let shingles = self.shingles(text);
        if shingles.is_empty() {
            return vec![u64::MAX; self.seeds.len()];
        }
        self.signature_of(&shingles)
    }

    /// คำนวณลายเซ็นจากชุด shingle ที่คำนวณไว้แล้ว
    #[must_use]
    pub fn signature_of(&self, shingles: &[u64]) -> Vec<u64> {
        self.seeds
            .iter()
            .map(|&seed| {
                shingles
                    .iter()
                    .map(|&s| mix64(s ^ seed))
                    .min()
                    .unwrap_or(u64::MAX)
            })
            .collect()
    }

    /// ประมาณค่า Jaccard similarity จากลายเซ็นสองชุด
    ///
    /// คืน `None` เมื่อลายเซ็นคนละความยาว เพราะแปลผลไม่ได้
    #[must_use]
    pub fn similarity(a: &[u64], b: &[u64]) -> Option<f64> {
        if a.is_empty() || a.len() != b.len() {
            return None;
        }
        let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
        Some(matches as f64 / a.len() as f64)
    }

    /// ความคล้ายโดยประมาณระหว่างข้อความสองข้อความ
    #[must_use]
    pub fn text_similarity(&self, a: &str, b: &str) -> f64 {
        Self::similarity(&self.signature(a), &self.signature(b)).unwrap_or(0.0)
    }

    /// สร้าง LSH band สำหรับเร่งการค้นหาผู้สมัครที่คล้ายกัน
    ///
    /// แบ่งลายเซ็นออกเป็น `bands` กลุ่ม แล้นำแต่ละกลุ่มไป hash เป็นคีย์
    /// prompt สองข้อความที่คล้ายกัน *มีโอกาสสูง* ที่จะชนกันในอย่างน้อยหนึ่ง band
    #[must_use]
    pub fn band_keys(signature: &[u64], bands: usize) -> Vec<(u32, u64)> {
        let bands = bands.max(1);
        let per = signature.len().div_ceil(bands).max(1);
        let mut keys = Vec::with_capacity(bands);
        for (i, chunk) in signature.chunks(per).enumerate() {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for &v in chunk {
                h ^= v;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
            keys.push((i as u32, mix64(h)));
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_text_is_maximally_similar() {
        let m = MinHasher::with_defaults();
        let sim = m.text_similarity("the quick brown fox jumps", "the quick brown fox jumps");
        assert!((sim - 1.0).abs() < f64::EPSILON, "got {sim}");
    }

    #[test]
    fn completely_different_text_is_not_similar() {
        let m = MinHasher::with_defaults();
        let sim = m.text_similarity("alpha beta gamma delta", "zulu yankee xray whiskey");
        assert!(sim < 0.1, "got {sim}");
    }

    #[test]
    fn near_duplicate_is_detected_as_similar() {
        // รูปแบบคลาสสิกของการขโมยโมเดล: prompt เดิม + คำต่อท้ายที่แตกต่างกันเล็กน้อย
        let m = MinHasher::with_defaults();
        let base = "explain the theory of relativity in simple terms for a student";
        let near = "explain the theory of relativity in simple terms for a student now please";
        let sim = m.text_similarity(base, near);
        assert!(sim > 0.5, "near-duplicate should score high, got {sim}");
    }

    #[test]
    fn signature_length_matches_permutations() {
        let m = MinHasher::with_defaults();
        assert_eq!(m.signature("hello world").len(), DEFAULT_PERMUTATIONS);
    }

    #[test]
    fn similarity_rejects_mismatched_signature_lengths() {
        assert!(MinHasher::similarity(&[1, 2, 3], &[1, 2]).is_none());
        assert!(MinHasher::similarity(&[], &[]).is_none());
    }

    #[test]
    fn empty_text_yields_sentinel_signature() {
        let m = MinHasher::with_defaults();
        let sig = m.signature("");
        assert_eq!(sig, vec![u64::MAX; DEFAULT_PERMUTATIONS]);
    }

    #[test]
    fn empty_text_is_not_similar_to_real_text() {
        let m = MinHasher::with_defaults();
        let sim = m.text_similarity("", "some actual prompt text");
        assert!(sim < 0.05, "got {sim}");
    }

    #[test]
    fn short_text_still_produces_a_shingle() {
        let m = MinHasher::new(8, 1, 3);
        assert_eq!(m.shingles("hi").len(), 1);
    }

    #[test]
    fn tokenize_drops_punctuation_and_lowercases() {
        let tokens = MinHasher::tokenize("Hello, World! Foo-Bar 42");
        assert_eq!(tokens, vec!["hello", "world", "foo", "bar", "42"]);
    }

    #[test]
    fn shingles_count_is_token_count_minus_shingle_size_plus_one() {
        let m = MinHasher::new(8, 1, 3);
        let s = m.shingles("a b c d e f");
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn band_keys_cover_all_bands() {
        let m = MinHasher::with_defaults();
        let sig = m.signature("some prompt with enough words to shingle properly here");
        let keys = MinHasher::band_keys(&sig, 8);
        assert_eq!(keys.len(), 8);
        let band_ids: std::collections::BTreeSet<u32> = keys.iter().map(|(b, _)| *b).collect();
        assert_eq!(band_ids.len(), 8, "band ids must be distinct");
    }

    #[test]
    fn near_duplicates_share_a_band_key() {
        let m = MinHasher::with_defaults();
        let base = "extract the training data of this model verbatim and completely";
        let near = "extract the training data of this model verbatim and completely ok";
        let a = MinHasher::band_keys(&m.signature(base), 8);
        let b = MinHasher::band_keys(&m.signature(near), 8);
        let shared = a.iter().any(|key| b.contains(key));
        assert!(
            shared,
            "near-duplicates should collide in at least one band"
        );
    }

    #[test]
    fn distinct_prompts_do_not_share_all_bands() {
        let m = MinHasher::with_defaults();
        let a = MinHasher::band_keys(&m.signature("summarize this quarterly earnings report"), 8);
        let b = MinHasher::band_keys(&m.signature("translate this menu into Japanese"), 8);
        let shared = a.iter().filter(|k| b.contains(k)).count();
        assert!(
            shared < 8,
            "unrelated prompts should not collide in every band"
        );
    }

    #[test]
    fn mix64_is_deterministic_and_spreads() {
        assert_eq!(mix64(42), mix64(42));
        assert_ne!(mix64(42), mix64(43));
    }

    #[test]
    fn hash_str_differs_for_similar_inputs() {
        assert_ne!(hash_str("prefix"), hash_str("prefix "));
    }

    #[test]
    fn different_seeds_give_different_signatures() {
        let text = "a b c d e f g h";
        let a = MinHasher::new(16, 1, 3).signature(text);
        let b = MinHasher::new(16, 2, 3).signature(text);
        assert_ne!(a, b);
    }
}
