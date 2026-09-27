//! ตัวตรวจจับการขโมยโมเดล (Model-extraction detector)
//!
//! ตรวจจับรูปแบบเชิงสถิติของการดึงข้อมูลออกจากโมเดล เช่น การยิง prompt จำนวนมาก
//! ในรูปแบบเดียวกันเพื่อสร้างชุดข้อมูลฝึกเลียน หรือการวนเก็บคำตอบเพื่อประมาณค่าโมเดล
//!
//! # ข้อดีของการตรวจที่ "ไม่ต้องใช้โมเดล"
//!
//! การขโมยโมเดลมีลักษณะเป็น *รูปแบบเชิงสถิติ* มากกว่าเป็นเรื่องความหมาย —
//! ผู้โจมตีต้องยิงคำขอจำนวนมากในเวลาสั้น ด้วย prompt ที่คล้ายกัน จึงตรวจจับได้
//! ด้วยการวัดอัตรา อัตราการใช้โทเคน และความคล้ายของ prompt โดยไม่ต้องมีคลาสสิฟเยอร์
//!
//! # ข้อจำกัดที่ต้องรู้
//!
//! งานแบตช์ที่ถูกต้องจะทำให้อัตราคำขอและการใช้โทเคนสูงขึ้นจริง ดังนั้นผลลัพธ์
//! คือ *ความน่าสงสัย* ไม่ใช่หลักฐานการกระทำผิด — ตัวตรวจจึงแยก "แจ้งเตือน"
//! ออกจาก "จำกัดอัตรา" และไม่ตัดสินใจปฏิเสธโดยตรง
//!
//! ค่า threshold ต้องปรับตามลักษณะงานจริงของแต่ละ deployment ค่าเริ่มต้นเป็นจุดตั้งต้น
//! ไม่ใช่ค่าที่ผ่านการปรับจูนแล้ว

use crate::minhash::{DEFAULT_PERMUTATIONS, MinHasher};
use crate::window::SlidingWindow;
use dashmap::DashMap;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// ข้อผิดพลาดของตัวตรวจจับ
#[derive(Debug, Error)]
pub enum ExtractionError {
    /// ไม่ได้ระบุผู้เช่า (tenant) — ไม่สามารถแยกพฤติกรรมได้
    #[error("tenant id must not be empty")]
    EmptyTenant,
    /// ค่า threshold อยู่นอกช่วงที่ยอมรับได้
    #[error("threshold {name}={value} out of range {min}..={max}")]
    ThresholdOutOfRange {
        /// ชื่อพารามิเตอร์
        name: &'static str,
        /// ค่าที่ตั้งไว้
        value: f64,
        /// ขอบเขตขั้นต่ำที่ยอมรับได้
        min: f64,
        /// ขอบเขตสูงสุดที่ยอมรับได้
        max: f64,
    },
}

/// ระดับความน่าสงสัย
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SuspicionLevel {
    /// ไม่พบรูปแบบผิดปกติ
    Normal,
    /// พบบางสัญญาณ — ควรเฝ้าดูแต่ยังไม่ควรจำกัด
    Suspicious,
    /// พบสัญญาณหลายตัวพร้อมกัน — ควรแจ้งเตือนผู้ดำเนินการ
    Alert,
    /// พบรูปแบบการขโมยโมเดลชัดเจน — ควรจำกัดอัตรา
    Extracting,
}

impl SuspicionLevel {
    /// ชื่อแบบคงที่สำหรับ metric label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Suspicious => "suspicious",
            Self::Alert => "alert",
            Self::Extracting => "extracting",
        }
    }
}

/// เหตุผลที่ทำให้เกิดความน่าสงสัย
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signal {
    /// อัตราคำขอต่อวินาทีสูงผิดปกติ
    HighRequestRate,
    /// อัตราการใช้โทเคนต่อวินาทีสูงผิดปกติ
    HighTokenBurn,
    /// สัดส่วน prompt ที่ไม่ซ้ำกันต่ำมาก (ยิง template เดิมซ้ำ)
    LowDistinctRatio,
    /// สัดส่วน prompt ที่คล้ายของเดิมสูงมาก (การไล่นับแบบเป็นระบบ)
    SystematicEnumeration,
    /// ความยาว prompt สม่ำเสมอผิดปกติ (สคริปต์อัตโนมัติ ไม่ใช่มนุษย์)
    UniformPromptLength,
}

impl Signal {
    /// ชื่อแบบคงที่สำหรับ metric label และ audit log
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HighRequestRate => "high_request_rate",
            Self::HighTokenBurn => "high_token_burn",
            Self::LowDistinctRatio => "low_distinct_ratio",
            Self::SystematicEnumeration => "systematic_enumeration",
            Self::UniformPromptLength => "uniform_prompt_length",
        }
    }
}

/// ผลการตรวจสอบหนึ่งครั้ง
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionVerdict {
    /// ระดับความน่าสงสัย
    pub level: SuspicionLevel,
    /// คะแนนความน่าสงสัย 0.0–1.0
    pub score: f64,
    /// เหตุผลที่ทำให้เกิดความน่าสงสัย
    pub signals: Vec<Signal>,
    /// จำนวนคำขอทั้งหมดที่บันทึกไว้สำหรับผู้เช่านี้
    pub observed_requests: u64,
    /// ควรแจ้งเตือนผู้ดำเนินการหรือไม่
    pub should_alert: bool,
    /// ควรจำกัดอัตราคำขอหรือไม่
    pub should_throttle: bool,
}

/// น้ำหนักของแต่ละสัญญาณในการคิดคะแนนรวม
///
/// ให้น้ำหนักสัญญาณเชิงโครงสร้าง (การไล่นับแบบเป็นระบบ) สูงกว่าสัญญาณเชิงปริมาณ
/// (อัตราคำขอ) เพราะอัตราสูงเกิดได้จากงานแบตช์ที่ถูกต้อง แต่การไล่นับ template
/// เดิมซ้ำ ๆ แทบไม่เกิดจากการใช้งานทั่วไป
const SIGNAL_WEIGHTS: &[(Signal, f64)] = &[
    (Signal::SystematicEnumeration, 0.32),
    (Signal::LowDistinctRatio, 0.28),
    (Signal::HighTokenBurn, 0.20),
    (Signal::HighRequestRate, 0.12),
    (Signal::UniformPromptLength, 0.08),
];

/// น้ำหนักของสัญญาณนั้น ๆ
#[must_use]
pub fn signal_weight(signal: Signal) -> f64 {
    SIGNAL_WEIGHTS
        .iter()
        .find(|(s, _)| *s == signal)
        .map_or(0.0, |(_, w)| *w)
}

/// ค่าขอบเขตและน้ำหนักของการตรวจจับ
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// ความยาวหน้าต่างเวลาสำหรับวัดอัตรา
    pub window: Duration,
    /// จำนวนคำขอต่อวินาทีที่ถือว่าสูงผิดปกติ
    pub max_requests_per_sec: f64,
    /// จำนวนโทเคนต่อวินาทีที่ถือว่าสูงผิดปกติ
    pub max_tokens_per_sec: f64,
    /// สัดส่วน prompt ที่ไม่ซ้ำกันต่ำกว่านี้ถือว่าผิดปกติ
    pub min_distinct_ratio: f64,
    /// สัดส่วน prompt ที่คล้ายของเดิมสูงกว่านี้ถือว่ากำลังไล่นับ
    pub max_similarity_ratio: f64,
    /// จำนวน prompt ที่ต้องมาก่อนจะเริ่มให้คะแนน (กันผลบวกปลอมจาก traffic น้อย)
    pub warmup_requests: u64,
    /// จำนวนลายเซ็น MinHash ที่เก็บย้อนหลังเพื่อเทียบความคล้าย
    pub history_depth: usize,
    /// จำนวน permutation ของ MinHash
    pub permutations: usize,
    /// จำนวน LSH band
    pub bands: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            max_requests_per_sec: 5.0,
            max_tokens_per_sec: 2_000.0,
            min_distinct_ratio: 0.25,
            max_similarity_ratio: 0.70,
            warmup_requests: 20,
            history_depth: 512,
            permutations: DEFAULT_PERMUTATIONS,
            bands: 16,
        }
    }
}

impl ExtractionConfig {
    /// ตรวจความถูกต้องของค่าตั้ง
    ///
    /// # Errors
    /// คืน `Err` เมื่อค่าใดอยู่นอกช่วงที่ให้ความหมาย
    pub fn validate(&self) -> Result<(), ExtractionError> {
        let checks: [(&'static str, f64, f64, f64); 4] = [
            (
                "max_requests_per_sec",
                self.max_requests_per_sec,
                0.1,
                1_000_000.0,
            ),
            (
                "max_tokens_per_sec",
                self.max_tokens_per_sec,
                0.1,
                100_000_000.0,
            ),
            // สัดส่วนต้องอยู่ในช่วง 0.0–1.0
            ("min_distinct_ratio", self.min_distinct_ratio, 0.0, 1.0),
            ("max_similarity_ratio", self.max_similarity_ratio, 0.0, 1.0),
        ];
        for (name, value, min, max) in checks {
            if !(min..=max).contains(&value) {
                return Err(ExtractionError::ThresholdOutOfRange {
                    name,
                    value,
                    min,
                    max,
                });
            }
        }
        if self.window.is_zero() {
            return Err(ExtractionError::ThresholdOutOfRange {
                name: "window",
                value: 0.0,
                min: f64::MIN_POSITIVE,
                max: f64::MAX,
            });
        }
        Ok(())
    }

    fn window_ms(&self) -> u64 {
        u64::try_from(self.window.as_millis()).unwrap_or(u64::MAX)
    }
}

/// สถานะสะสมของผู้เช่าหนึ่งราย
#[derive(Debug)]
struct TenantState {
    /// จำนวนคำขอในหน้าต่างเวลา
    requests: SlidingWindow,
    /// จำนวนโทเคนในหน้าต่างเวลา
    tokens: SlidingWindow,
    /// จำนวนคำขอทั้งหมดที่เคยเห็น
    total_requests: u64,
    /// ลายเซ็น MinHash ล่าสุด (เก็บย้อนหลังตาม `history_depth`)
    history: std::collections::VecDeque<Vec<u64>>,
    /// จำนวน prompt ที่ "ซ้ำ" เมื่อเทียบกับประวัติ (คล้ายเกินเกณฑ์)
    near_duplicate_hits: u64,
    /// ผลรวมความยาว prompt และกำลังสอง เพื่อคำนวณความแปรปรวน
    length_sum: f64,
    length_sum_sq: f64,
    /// เวลาแก้ไขล่าสุด (สำหรับการเก็บกวาด)
    last_seen_ms: u64,
}

impl TenantState {
    fn new(window_ms: u64, history_depth: usize) -> Self {
        Self {
            requests: SlidingWindow::new(window_ms),
            tokens: SlidingWindow::new(window_ms),
            total_requests: 0,
            history: std::collections::VecDeque::with_capacity(history_depth),
            near_duplicate_hits: 0,
            length_sum: 0.0,
            length_sum_sq: 0.0,
            last_seen_ms: 0,
        }
    }

    /// คำนวณความแปรปรวนของความยาว prompt (population variance)
    fn length_variance(&self) -> f64 {
        let n = self.total_requests as f64;
        if n < 2.0 {
            return 0.0;
        }
        let mean = self.length_sum / n;
        let var = (self.length_sum_sq / n) - (mean * mean);
        // ความคลาดเคลื่อนเชิงตัวเลขอาจทำให้ผลติดลบเล็กน้อย
        var.max(0.0)
    }

    /// สัดส่วนความยาว prompt ที่ "ผิดปกติ" ในแง่สถิติ (ค่า z-score ต่ำกว่า 0.15)
    fn is_uniform_length(&self) -> bool {
        if self.total_requests < 30 {
            return false;
        }
        let mean = self.length_sum / self.total_requests as f64;
        if mean <= 0.0 {
            return false;
        }
        let cv = self.length_variance().sqrt() / mean;
        // สัมประสิทธิของความแปรปรวนต่ำมาก = ความยาวคงที่ผิดปกติ
        // (คนธรรมดาพิมพ์ความยาวแกว่ง ๆ ค่า CV ปกติอย่างน้อย 0.3)
        cv < 0.15
    }
}

/// ตัวตรวจจับการขโมยโมเดลแยกตามผู้เช่า (tenant)
pub struct ExtractionDetector {
    config: ExtractionConfig,
    hasher: MinHasher,
    tenants: DashMap<String, TenantState>,
}

impl std::fmt::Debug for ExtractionDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractionDetector")
            .field("config", &self.config)
            .field("tenants", &self.tenants.len())
            .finish()
    }
}

impl ExtractionDetector {
    /// สร้างตัวตรวจจับ
    ///
    /// # Errors
    /// คืน `Err` เมื่อค่าตั้งอยู่นอกช่วงที่ให้ความหมาย — ตัวตรวจจับที่ตั้งค่าผิด
    /// จะรายงานความน่าสงสัยผิดทั้งระบบ ซึ่งแย่กว่าการไม่มีตัวตรวจจับเลย
    pub fn new(config: ExtractionConfig) -> Result<Self, ExtractionError> {
        config.validate()?;
        let hasher = MinHasher::new(
            config.permutations,
            0x0005_EED0,
            crate::minhash::DEFAULT_SHINGLE_WORDS,
        );
        Ok(Self {
            config,
            hasher,
            tenants: DashMap::new(),
        })
    }

    /// สร้างตัวตรวจจับด้วยค่าตั้งเริ่มต้น
    ///
    /// # Errors
    /// คืน `Err` เมื่อค่าเริ่มต้นไม่ผ่านการตรวจสอบ
    pub fn with_defaults() -> Result<Self, ExtractionError> {
        Self::new(ExtractionConfig::default())
    }

    /// การตั้งค่าที่ใช้งานอยู่
    #[must_use]
    pub fn config(&self) -> &ExtractionConfig {
        &self.config
    }

    /// บันทึกคำขอหนึ่งรายการและคืนผลประเมิน
    ///
    /// `now_ms` ต้องเป็นเวลาแบบ monotonic เดียวกับที่ใช้ทั้งระบบ
    /// `prompt_tokens` คือจำนวนโทเคนของ prompt, `completion_tokens` คือของคำตอบ
    ///
    /// # Errors
    /// คืน `Err` เมื่อ `tenant` ว่างเปล่า
    pub fn observe(
        &self,
        tenant: &str,
        prompt: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        now_ms: u64,
    ) -> Result<ExtractionVerdict, ExtractionError> {
        if tenant.is_empty() {
            return Err(ExtractionError::EmptyTenant);
        }

        let window_ms = self.config.window_ms();
        let history_depth = self.config.history_depth;

        let signature = self.hasher.signature(prompt);
        let prompt_chars = prompt.chars().count() as f64;
        let total_tokens = prompt_tokens.saturating_add(completion_tokens);

        // ใช้ entry API เพื่อลดการ lock ทั้ง map และคงขอบเขตการเขียนให้แคบที่สุด
        let mut state = self
            .tenants
            .entry(tenant.to_string())
            .or_insert_with(|| TenantState::new(window_ms, history_depth));

        // 1) เทียบความคล้ายกับประวัติก่อน — เพิ่มลงประวัติหลังจากนั้น
        let mut near_dup = false;
        for prev in &state.history {
            if let Some(sim) = MinHasher::similarity(&signature, prev) {
                if sim >= self.config.max_similarity_ratio {
                    near_dup = true;
                    break;
                }
            }
        }
        if near_dup {
            state.near_duplicate_hits += 1;
        }

        // 2) บันทึกลงหน้าต่างเวลาและสถิติความยาว
        state.requests.add(now_ms, 1.0);
        state.tokens.add(now_ms, total_tokens as f64);
        state.total_requests += 1;
        state.length_sum += prompt_chars;
        state.length_sum_sq += prompt_chars * prompt_chars;
        state.last_seen_ms = now_ms;

        if state.history.len() >= history_depth {
            state.history.pop_front();
        }
        state.history.push_back(signature);

        // 3) ประเมินสัญญาณ
        let window_secs = self.config.window.as_secs_f64().max(f64::MIN_POSITIVE);
        let request_rate = state.requests.sum(now_ms) / window_secs;
        let token_rate = state.tokens.sum(now_ms) / window_secs;
        let total = state.total_requests;
        let near_dup_ratio = state.near_duplicate_hits as f64 / total as f64;

        // สัดส่วน prompt ที่ไม่ซ้ำ = 1 - สัดส่วนที่คล้ายประวัติ
        let distinct_ratio = 1.0 - near_dup_ratio;

        let mut signals: Vec<Signal> = Vec::new();
        if request_rate > self.config.max_requests_per_sec {
            signals.push(Signal::HighRequestRate);
        }
        if token_rate > self.config.max_tokens_per_sec {
            signals.push(Signal::HighTokenBurn);
        }
        if total >= self.config.warmup_requests && distinct_ratio < self.config.min_distinct_ratio {
            signals.push(Signal::LowDistinctRatio);
        }
        if total >= self.config.warmup_requests && near_dup_ratio > self.config.max_similarity_ratio
        {
            signals.push(Signal::SystematicEnumeration);
        }
        if state.is_uniform_length() {
            signals.push(Signal::UniformPromptLength);
        }

        // 4) คะแนนถ่วงน้ำหนัก (ไม่เกิน 1.0)
        let score = signals
            .iter()
            .map(|s| signal_weight(*s))
            .sum::<f64>()
            .clamp(0.0, 1.0);

        // 5) ระดับความน่าสงสัย
        //    เกณฑ์อ้างอิงจำนวนสัญญาณ *และ* สัญญาณเชิงโครงสร้าง เพราะการมีสัญญาณ
        //    เชิงปริมาณอย่างเดียว (อัตราสูง) เกิดได้จากงานแบตช์ที่ถูกต้อง
        let structural = signals
            .iter()
            .any(|s| matches!(s, Signal::SystematicEnumeration | Signal::LowDistinctRatio));
        let level = if total < self.config.warmup_requests {
            SuspicionLevel::Normal
        } else if signals.len() >= 3 && (structural || score >= 0.5) {
            SuspicionLevel::Extracting
        } else if signals.len() >= 2 || score >= 0.4 {
            SuspicionLevel::Alert
        } else if !signals.is_empty() {
            SuspicionLevel::Suspicious
        } else {
            SuspicionLevel::Normal
        };

        Ok(ExtractionVerdict {
            level,
            score,
            signals,
            observed_requests: total,
            should_alert: level >= SuspicionLevel::Alert,
            should_throttle: level >= SuspicionLevel::Extracting,
        })
    }

    /// จำนวนผู้เช่าที่มีสถานะติดตามอยู่
    #[must_use]
    pub fn tracked_tenants(&self) -> usize {
        self.tenants.len()
    }

    /// ล้างสถานะของผู้เช่าหนึ่งราย (ใช้เมื่อเปลี่ยนนโยบายหรือแก้ไข false positive)
    pub fn reset_tenant(&self, tenant: &str) {
        self.tenants.remove(tenant);
    }

    /// ล้างสถานะทั้งหมด
    pub fn reset_all(&self) {
        self.tenants.clear();
    }

    /// เก็บกวาดสถานะของผู้เช่าที่ไม่มีคำขอมานานแล้ว
    ///
    /// คืนจำนวนรายการที่ถูกลบ เพื่อให้ผู้เรียก log ได้
    pub fn gc(&self, now_ms: u64, idle_timeout: Duration) -> usize {
        let cutoff_ms =
            now_ms.saturating_sub(u64::try_from(idle_timeout.as_millis()).unwrap_or(u64::MAX));
        let mut removed = 0usize;
        self.tenants.retain(|_, state| {
            if state.last_seen_ms < cutoff_ms {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// LSH band keys ของ prompt — ใช้ร่วมกับดัชนีภายนอกเพื่อค้นหาผู้สมัคร
    #[must_use]
    pub fn band_keys(&self, prompt: &str) -> Vec<(u32, u64)> {
        MinHasher::band_keys(&self.hasher.signature(prompt), self.config.bands)
    }
}

/// คำนวณคะแนนความน่าสงสัยจากสัญญาณที่กำหนด (ใช้ในเทสต์และการวิเคราะห์ย้อนหลัง)
#[must_use]
pub fn score_signals(signals: &[Signal]) -> f64 {
    signals
        .iter()
        .map(|s| signal_weight(*s))
        .sum::<f64>()
        .clamp(0.0, 1.0)
}

/// โครงสร้างข้อมูลสรุปสำหรับ metric
#[derive(Debug, Clone)]
pub struct TenantSnapshot {
    /// จำนวนคำขอทั้งหมด
    pub total_requests: u64,
    /// อัตราคำขอต่อวินาทีในหน้าต่างเวลาปัจจุบัน
    pub request_rate: f64,
    /// อัตราการใช้โทเคนต่อวินาทีในหน้าต่างเวลาปัจจุบัน
    pub token_rate: f64,
    /// สัดส่วน prompt ที่ไม่ซ้ำกับประวัติ
    pub distinct_ratio: f64,
    /// ความยาว prompt เฉลี่ยเป็นอักขระ
    pub mean_prompt_chars: f64,
    /// ส่วนเบี่ยงเบนมาตรฐานของความยาว prompt
    pub prompt_length_cv: f64,
}

/// ดึงสรุปสถานะปัจจุบันของผู้เช่าเพื่อส่งออก metric
#[must_use]
pub fn snapshot(
    detector: &ExtractionDetector,
    tenant: &str,
    now_ms: u64,
) -> Option<TenantSnapshot> {
    let state = detector.tenants.get(tenant)?;
    let window_secs = detector.config.window.as_secs_f64().max(f64::MIN_POSITIVE);
    let total = state.total_requests as f64;
    let mean = if total > 0.0 {
        state.length_sum / total
    } else {
        0.0
    };
    let cv = if mean > 0.0 {
        state.length_variance().sqrt() / mean
    } else {
        0.0
    };
    let near_dup_ratio = if total > 0.0 {
        state.near_duplicate_hits as f64 / total
    } else {
        0.0
    };
    Some(TenantSnapshot {
        total_requests: state.total_requests,
        request_rate: state.requests.sum(now_ms) / window_secs,
        token_rate: state.tokens.sum(now_ms) / window_secs,
        distinct_ratio: 1.0 - near_dup_ratio,
        mean_prompt_chars: mean,
        prompt_length_cv: cv,
    })
}

/// แปลงแผนที่ผู้เช่าเป็น `HashMap` ธรรมดา (ใช้ในเทสต์และการส่งออกข้อมูล)
#[must_use]
pub fn tenant_ids(detector: &ExtractionDetector) -> HashMap<String, ()> {
    detector
        .tenants
        .iter()
        .map(|e| (e.key().clone(), ()))
        .collect()
}
