// We allow unsafe code in this crate to interface with C-FFI bindings (ONNX Runtime, llama.cpp)
pub mod llama;
pub mod onnx;
pub mod vram_manager;

/// โมดูลจัดการงบประมาณ VRAM แบบ per-agent (GpuBudgetController)
pub mod budget;
/// โมดูล CUDA Driver API FFI (cuMemAlloc/cuMemFree) สำหรับ NVIDIA GPU
pub mod cuda_ffi;
/// โมดูล GPU OOM killer — priority-based preemption เมื่อ VRAM เต็ม
pub mod gpu_oom;
/// โมดูลจัดการ GPU memory pool สำหรับ CUDA/ROCm abstraction
pub mod gpu_pool;
/// โมดูลเชื่อมต่อ Apple MPS (Metal Performance Shaders) ผ่าน llama.cpp
pub mod mps;
/// โมดูล ROCm HIP FFI (hipMalloc/hipFree) สำหรับ AMD GPU
pub mod rocm_ffi;
/// โมดูลเชื่อมต่อ vLLM (subprocess engine สำหรับ NVIDIA + AMD ROCm)
pub mod vllm;

/// โมดูลจัดการคิวและการมัดรวมงานเพื่อส่งเข้า GPU (Batching Manager)
pub mod batching;
/// โมดูลสื่อสารกับ Cloud Inference API (OpenAI-compatible)
pub mod cloud;
/// โมดูลคำนวณต้นทุน/คะแนนของทรัพยากรประมวลผล
pub mod cost;
/// โมดูลเชื่อมต่อ Inference Engine ภายนอก (Llama.cpp, TensorRT-LLM)
pub mod engine;
/// โมดูลเชื่อมต่อเพื่ออ่านข้อมูลฮาร์ดแวร์จริง (CPU/GPU/NPU)
pub mod hardware;
/// โมดูล NPU vendor-specific runtime abstractions
pub mod npu;
/// โมดูลติดตามและตอบสนองต่อสภาวะแวดล้อม (System Observer)
pub mod observer;
/// โมดูลจัดสรรอุปกรณ์ (Placement Policy) ตามภาระงาน
pub mod placement;
/// โมดูลจัดการน้ำหนักปรับตัว (Adaptive Weights) ตามสถิติการใช้งานจริง
pub mod weights;
use crate::cost::score_target;
use crate::weights::AdaptiveWeights;
use std::sync::RwLock;
use thiserror::Error;

/// ข้อผิดพลาดจากการคำนวณและการจัดสรรทรัพยากรประมวลผล
#[must_use]
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ComputeError {
    /// เกิดขึ้นเมื่อไม่มีฮาร์ดแวร์ประมวลผลที่เหมาะสมให้เลือกใช้งาน
    #[error("no compute target available")]
    NoTargetAvailable,
}

/// ฮาร์ดแวร์เป้าหมายสำหรับการประมวลผล AI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComputeTarget {
    /// หน่วยประมวลผลกลาง (CPU)
    Cpu,
    /// หน่วยประมวลผลกราฟิก (GPU)
    Gpu,
    /// หน่วยประมวลผลโครงข่ายประสาทเทียม (NPU)
    Npu,
    /// คลาวด์ หรือ Server ภายนอก
    Cloud,
}

/// รันไทม์จำลองสำหรับการประมวลผลโมเดล AI (Inference Runtime)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InferenceRuntime {
    /// llama.cpp - เหมาะกับ CPU/NPU และ Edge deployments
    LlamaCpp,
    /// ONNX Runtime - เหมาะกับ NPU และ cross-platform workloads
    OnnxRuntime,
    /// TensorRT-LLM - เหมาะกับ GPU ประสิทธิภาพสูง
    TensorRtLlm,
    /// vLLM - รองรับ NVIDIA GPU + AMD ROCm 6+ (subprocess)
    Vllm,
    /// Apple MPS (Metal Performance Shaders) - Apple Silicon GPU
    Mps,
}

impl InferenceRuntime {
    /// จำลองการรันโมเดล (Mock inference execution) และส่งคืนความหน่วงในการประมวลผลจริง (ms)
    #[must_use]
    pub fn execute_mock_inference(&self, tokens: usize) -> f64 {
        match self {
            Self::LlamaCpp => tokens as f64 * 0.5,
            Self::OnnxRuntime => tokens as f64 * 0.3,
            Self::TensorRtLlm => tokens as f64 * 0.08,
            Self::Vllm => tokens as f64 * 0.06, // vLLM continuous batching = efficient
            Self::Mps => tokens as f64 * 0.12,  // Apple MPS ≈ Mac latency
        }
    }
}

// ---- NPU Vendor Abstraction ----

/// NPU Vendor identifier — ระบุผู้ผลิต NPU สำหรับ vendor-specific profiling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NpuVendor {
    /// Intel Gaudi 2/3 (Habana Labs) — edge AI accelerator
    IntelGaudi,
    /// Intel OpenVINO NPU — Lunar Lake / Arrow Lake integrated NPU
    IntelOpenvino,
    /// Google TPU v4/v5e — cloud/edge AI
    GoogleTpu,
    /// Apple Neural Engine (ANE) — M1/M2/M3/M4 integrated NPU
    AppleSilicon,
    /// Qualcomm Hexagon DSP — mobile/edge AI
    QualcommHexagon,
    /// Qualcomm QNN/HTP — Snapdragon X Elite NPU
    QualcommQnn,
    /// AMD XDNA / Ryzen AI — PC/workstation NPU
    AmdXdna,
    /// Unknown or generic NPU
    Generic,
}

impl NpuVendor {
    /// ชื่อ vendor สำหรับ logging และ metrics
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntelGaudi => "intel_gaudi",
            Self::IntelOpenvino => "intel_openvino",
            Self::GoogleTpu => "google_tpu",
            Self::AppleSilicon => "apple_silicon",
            Self::QualcommHexagon => "qualcomm_hexagon",
            Self::QualcommQnn => "qualcomm_qnn",
            Self::AmdXdna => "amd_xdna",
            Self::Generic => "generic",
        }
    }
}

/// NPU Hardware Profile — ข้อมูลประสิทธิภาพเฉพาะ vendor
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NpuProfile {
    /// ความหน่วงพื้นฐานของ NPU vendor นี้ (ms)
    pub base_latency_ms: f64,
    /// พลังงาน_typical (วัตต์)
    pub power_watts: f64,
    /// ค่าใช้จ่าย (หน่วยสมมุติ)
    pub cost_units: f64,
    /// จำนวน TOPS (Tera Operations Per Second)
    pub tops: f64,
    /// หน่วยความจำที่ใช้ร่วม (GB) — 0 ถ้าใช้ shared memory
    pub memory_gb: f64,
}

impl NpuProfile {
    /// สร้าง ComputeProfile จาก NpuProfile (แปลงเป็น format ที่ scheduler เข้าใจ)
    #[must_use]
    pub fn to_compute_profile(&self) -> ComputeProfile {
        ComputeProfile {
            latency_ms: self.base_latency_ms,
            power_watts: self.power_watts,
            cost_units: self.cost_units,
        }
    }

    /// โปรไฟล์สำหรับ Intel Gaudi 3
    #[must_use]
    pub fn intel_gaudi3() -> Self {
        Self {
            base_latency_ms: 8.0,
            power_watts: 90.0,
            cost_units: 25.0,
            tops: 1835.0,
            memory_gb: 128.0,
        }
    }

    /// โปรไฟล์สำหรับ Google TPU v5e
    #[must_use]
    pub fn google_tpu_v5e() -> Self {
        Self {
            base_latency_ms: 12.0,
            power_watts: 40.0,
            cost_units: 30.0,
            tops: 393.0,
            memory_gb: 16.0,
        }
    }

    /// โปรไฟล์สำหรับ Apple M4 Neural Engine
    #[must_use]
    pub fn apple_m4_ne() -> Self {
        Self {
            base_latency_ms: 5.0,
            power_watts: 8.0,
            cost_units: 0.0, // built-in, no marginal cost
            tops: 38.0,
            memory_gb: 0.0, // shared unified memory
        }
    }

    /// โปรไฟล์สำหรับ Qualcomm Hexagon (骁龙 8 Gen 3)
    #[must_use]
    pub fn qualcomm_hexagon() -> Self {
        Self {
            base_latency_ms: 10.0,
            power_watts: 12.0,
            cost_units: 5.0,
            tops: 73.0,
            memory_gb: 0.0, // shared
        }
    }

    /// โปรไฟล์สำหรับ AMD Ryzen AI (XDNA 2)
    #[must_use]
    pub fn amd_xdna2() -> Self {
        Self {
            base_latency_ms: 9.0,
            power_watts: 15.0,
            cost_units: 8.0,
            tops: 48.0,
            memory_gb: 0.0, // shared
        }
    }

    /// โปรไฟล์สำหรับ Intel OpenVINO NPU (Lunar Lake / Arrow Lake)
    #[must_use]
    pub fn intel_openvino_npu() -> Self {
        Self {
            base_latency_ms: 6.0,
            power_watts: 15.0,
            cost_units: 3.0, // integrated, low marginal cost
            tops: 40.0,
            memory_gb: 0.0, // shared system memory
        }
    }

    /// โปรไฟล์สำหรับ Qualcomm QNN/HTP NPU (Snapdragon X Elite)
    #[must_use]
    pub fn qualcomm_qnn_npu() -> Self {
        Self {
            base_latency_ms: 7.0,
            power_watts: 18.0,
            cost_units: 4.0,
            tops: 45.0,
            memory_gb: 0.0, // shared
        }
    }

    /// โปรไฟล์สำหรับ generic/unknown NPU
    #[must_use]
    pub fn generic() -> Self {
        Self {
            base_latency_ms: 15.0,
            power_watts: 10.0,
            cost_units: 15.0,
            tops: 0.0,
            memory_gb: 0.0,
        }
    }
}

/// NPU Runtime trait — abstraction สำหรับ vendor-specific NPU operations
///
/// Vendor-specific implementations จะ implement trait นี้เพื่อให้
/// ComputeScheduler สามารถเรียกใช้ NPU ได้โดยไม่ต้องรู้รายละเอียดของ vendor
#[async_trait::async_trait]
pub trait NpuRuntime: Send + Sync {
    /// ระบุ vendor ของ NPU นี้
    fn vendor(&self) -> NpuVendor;

    /// ชื่อ runtime สำหรับ logging
    fn name(&self) -> &str;

    /// โปรไฟล์ฮาร์ดแวร์ของ NPU นี้
    fn profile(&self) -> NpuProfile;

    /// ตรวจสอบว่า runtime พร้อมใช้งานหรือไม่
    async fn is_available(&self) -> bool;

    /// จำลองการ inference (mock) — คืน latency จริง (ms)
    async fn execute_inference(&self, tokens: usize) -> f64;

    /// โหลดโมเดล (mock)
    async fn load_model(&self, model_path: &str) -> Result<(), String>;

    /// ปิด runtime
    async fn shutdown(&self) -> Result<(), String>;
}

/// การตัดสินใจผลลัพธ์การจัดสรร (PlacementDecision) ที่รวบรวมทั้งฮาร์ดแวร์เป้าหมายและรันไทม์ที่เลือก
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlacementDecision {
    pub target: ComputeTarget,
    pub runtime: Option<InferenceRuntime>,
}

/// โปรไฟล์ข้อมูลประสิทธิภาพและพลังงานของฮาร์ดแวร์แต่ละประเภท
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ComputeProfile {
    /// ความหน่วงในการประมวลผล มีหน่วยเป็นมิลลิวินาที (Latency)
    pub latency_ms: f64,
    /// อัตราการใช้พลังงาน มีหน่วยเป็นวัตต์ (Power)
    pub power_watts: f64,
    /// ค่าใช้จ่ายของระบบ มีหน่วยเป็นหน่วยสมมุติ (Cost)
    pub cost_units: f64,
}

/// ตัวจัดตารางเวลาและวิเคราะห์การใช้ทรัพยากรประมวลผล (Compute Scheduler)
/// ทำหน้าที่เลือกฮาร์ดแวร์ประมวลผลที่ดีที่สุดตามฟังก์ชันต้นทุนและตัวแปรปรับตัว (Adaptive Weights)
#[derive(Debug, Clone)]
pub struct ComputeScheduler {
    /// ค่าน้ำหนักปรับตัวที่ใช้ในการคำนวณคะแนนต้นทุน ถูกป้องกันด้วย RwLock เพื่อความปลอดภัยในการทำงานหลายเธรด
    weights: std::sync::Arc<RwLock<AdaptiveWeights>>,
    /// ตัวจัดการงบประมาณ VRAM และ Circuit Breaker
    pub vram_manager: std::sync::Arc<crate::vram_manager::GpuVramManager>,
}

impl ComputeScheduler {
    /// สร้างตัวจัดตารางเวลา `ComputeScheduler` ใหม่พร้อมค่าเริ่มต้นค่าน้ำหนักปรับตัว
    #[must_use]
    pub fn new() -> Self {
        Self {
            weights: std::sync::Arc::new(RwLock::new(AdaptiveWeights::default())),
            vram_manager: std::sync::Arc::new(crate::vram_manager::GpuVramManager::default()),
        }
    }

    /// สร้าง `ComputeScheduler` โดยกำหนดค่าน้ำหนักปรับตัวเริ่มต้น
    #[must_use]
    pub fn with_weights(weights: AdaptiveWeights) -> Self {
        Self {
            weights: std::sync::Arc::new(RwLock::new(weights)),
            vram_manager: std::sync::Arc::new(crate::vram_manager::GpuVramManager::default()),
        }
    }

    /// คำนวณคะแนนต้นทุนสำหรับโปรไฟล์ประสิทธิภาพฮาร์ดแวร์ที่กำหนด
    /// ยิ่งคะแนนต่ำ หมายถึงฮาร์ดแวร์นั้นมีประสิทธิภาพ/ต้นทุนที่คุ้มค่ากว่าในการทำงาน
    pub fn score(&self, profile: ComputeProfile) -> f64 {
        let weights = self.weights.read().expect("compute weights lock poisoned");
        score_target(profile, &weights)
    }

    /// เลือกฮาร์ดแวร์ประมวลผลที่ดีที่สุด (คะแนนต่ำสุด) จากตัวเลือกที่มีให้ทั้งหมด
    /// คืนค่า `Ok(ComputeTarget)` เมื่อเลือกได้สำเร็จ หรือ `Err(ComputeError)` หากไม่มีตัวเลือกให้เลือก
    pub fn choose_best(
        &self,
        candidates: &[(ComputeTarget, ComputeProfile)],
    ) -> Result<ComputeTarget, ComputeError> {
        candidates
            .iter()
            .min_by(|(_, left), (_, right)| {
                self.score(*left)
                    .partial_cmp(&self.score(*right))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(target, _)| *target)
            .ok_or(ComputeError::NoTargetAvailable)
    }

    /// อัปเดตค่าน้ำหนักปรับตัวด้วยตัวอย่างข้อมูล (Sample) โปรไฟล์ประสิทธิภาพใหม่ล่าสุด
    pub fn update_weights(&self, sample: ComputeProfile) {
        let mut weights = self.weights.write().expect("compute weights lock poisoned");
        weights.observe(sample);
    }

    /// สแกนหาฮาร์ดแวร์จริงในเครื่องระบบ และส่งคืนรายการพร้อม ComputeProfile ที่วัดได้จริง
    pub async fn scan_real_hardware(&self) -> Vec<(ComputeTarget, ComputeProfile)> {
        let mut prober = hardware::HardwareProber::new();
        prober.scan_hardware().await
    }

    /// จัดการการรันงานพร้อมกลไก Circuit Breaker (Phase 1 Tune-Up)
    /// หากเป้าหมายหลัก (เช่น GPU/NPU) ทำงานล้มเหลว จะสลับกลับไปใช้ CPU ทันที (Fallback)
    pub async fn execute_with_circuit_breaker<F, Fut, T, E>(
        &self,
        primary_target: ComputeTarget,
        task: F,
    ) -> Result<T, E>
    where
        F: Fn(ComputeTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        match task(primary_target).await {
            Ok(result) => Ok(result),
            Err(e) => {
                if primary_target != ComputeTarget::Cpu {
                    tracing::warn!(
                        "Circuit Breaker: {:?} target failed, falling back to CPU",
                        primary_target
                    );
                    // Fallback to CPU
                    task(ComputeTarget::Cpu).await
                } else {
                    Err(e)
                }
            }
        }
    }
}

impl Default for ComputeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choose_best_prefers_lower_score() {
        // ทดสอบว่าฟังก์ชันเลือกเป้าหมายการประมวลผล เลือกฮาร์ดแวร์ที่ได้คะแนนคำนวณต่ำที่สุด (ดีที่สุด)
        let scheduler = ComputeScheduler::new();
        let candidates = [
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: 10.0,
                    power_watts: 10.0,
                    cost_units: 10.0,
                },
            ),
            (
                ComputeTarget::Gpu,
                ComputeProfile {
                    latency_ms: 1.0,
                    power_watts: 2.0,
                    cost_units: 3.0,
                },
            ),
        ];

        assert_eq!(
            scheduler
                .choose_best(&candidates)
                .expect("candidate should exist"),
            ComputeTarget::Gpu
        );
    }

    #[test]
    fn choose_best_returns_error_when_no_candidates() {
        // ทดสอบว่าคืน error เมื่อไม่มีตัวเลือกฮาร์ดแวร์ใดเลย (NoTargetAvailable)
        let scheduler = ComputeScheduler::new();
        let result = scheduler.choose_best(&[]);
        assert_eq!(result, Err(ComputeError::NoTargetAvailable));
    }

    #[test]
    fn choose_best_single_candidate_always_wins() {
        // ทดสอบว่าหากมีตัวเลือกเดียว ต้องเลือกตัวนั้นเสมอ ไม่ว่าคะแนนจะเป็นเท่าใด
        let scheduler = ComputeScheduler::new();
        let candidates = [(
            ComputeTarget::Npu,
            ComputeProfile {
                latency_ms: 999.0,
                power_watts: 999.0,
                cost_units: 999.0,
            },
        )];
        assert_eq!(
            scheduler
                .choose_best(&candidates)
                .expect("should pick single candidate"),
            ComputeTarget::Npu
        );
    }

    #[test]
    fn score_is_non_negative_for_positive_profiles() {
        // ทดสอบ property: คะแนนจะต้องไม่ติดลบสำหรับโปรไฟล์ที่มีค่าบวกทุกตัว
        let scheduler = ComputeScheduler::new();
        let profiles = [
            ComputeProfile {
                latency_ms: 0.0,
                power_watts: 0.0,
                cost_units: 0.0,
            },
            ComputeProfile {
                latency_ms: 1.0,
                power_watts: 50.0,
                cost_units: 100.0,
            },
            ComputeProfile {
                latency_ms: 500.0,
                power_watts: 300.0,
                cost_units: 1.0,
            },
        ];
        for profile in profiles {
            assert!(
                scheduler.score(profile) >= 0.0,
                "คะแนนต้องไม่ติดลบสำหรับโปรไฟล์ที่มีค่าบวก: {:?}",
                profile
            );
        }
    }

    #[test]
    fn update_weights_converges_toward_sample() {
        // ทดสอบว่า EWMA ค่อยๆ ดึงค่าน้ำหนักเข้าหา normalized sample ตามสัมประสิทธิ์ alpha=0.1
        let scheduler = ComputeScheduler::new();
        let sample = ComputeProfile {
            latency_ms: 100.0,
            power_watts: 10.0,
            cost_units: 1.0,
        };

        let contrast_profile = ComputeProfile {
            latency_ms: 1.0,
            power_watts: 100.0,
            cost_units: 100.0,
        };

        // บันทึก score ก่อนอัปเดต โดยใช้ profile ที่ไม่เหมือน sample เพื่อให้เห็นผลจาก weight shift ชัดเจน
        let score_before = scheduler.score(contrast_profile);
        // อัปเดตน้ำหนักหลายรอบให้มีการเปลี่ยนแปลงมากพอ
        for _ in 0..20 {
            scheduler.update_weights(sample);
        }
        let score_after = scheduler.score(contrast_profile);

        // หลัง update หลายรอบ คะแนนควรเปลี่ยนแปลง (EWMA มีผล)
        assert_ne!(
            (score_before * 1000.0) as i64,
            (score_after * 1000.0) as i64,
            "คะแนนต้องเปลี่ยนหลัง update weights"
        );
    }

    #[test]
    fn update_weights_preserves_normalized_weight_budget() {
        let scheduler = ComputeScheduler::new();
        let sample = ComputeProfile {
            latency_ms: 1000.0,
            power_watts: 10.0,
            cost_units: 1.0,
        };

        for _ in 0..10 {
            scheduler.update_weights(sample);
        }

        let weights = scheduler
            .weights
            .read()
            .expect("compute weights lock poisoned");
        let total = weights.latency + weights.power + weights.cost;

        assert!(
            (total - 1.0).abs() < 1e-9,
            "weights must remain normalized, got {total}"
        );
    }

    #[test]
    fn three_way_comparison_picks_npu_as_cheapest() {
        // ทดสอบการเปรียบเทียบ 3 ทาง: CPU/GPU/NPU โดย NPU มีต้นทุนต่ำสุด
        let scheduler = ComputeScheduler::new();
        let candidates = [
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: 50.0,
                    power_watts: 80.0,
                    cost_units: 20.0,
                },
            ),
            (
                ComputeTarget::Gpu,
                ComputeProfile {
                    latency_ms: 5.0,
                    power_watts: 150.0,
                    cost_units: 50.0,
                },
            ),
            (
                ComputeTarget::Npu,
                ComputeProfile {
                    latency_ms: 2.0,
                    power_watts: 10.0,
                    cost_units: 5.0,
                },
            ),
        ];
        assert_eq!(
            scheduler.choose_best(&candidates).expect("should pick NPU"),
            ComputeTarget::Npu
        );
    }

    #[tokio::test]
    async fn scan_real_hardware_returns_at_least_cpu() {
        let scheduler = ComputeScheduler::new();
        let profiles = scheduler.scan_real_hardware().await;
        assert!(!profiles.is_empty(), "ควรพบฮาร์ดแวร์จริงอย่างน้อย 1 ประเภท");
        assert!(
            profiles
                .iter()
                .any(|(target, _)| *target == ComputeTarget::Cpu),
            "ต้องมีผลลัพธ์ของ CPU อยู่ในรายการวัดผล"
        );
    }

    #[test]
    fn test_vram_reservation_and_circuit_breaker() {
        use crate::vram_manager::{GpuVramManager, VramError};

        // Create VramManager with 1000 MB mock VRAM, 80% circuit breaker threshold (800 MB)
        let vram_mgr = GpuVramManager::new(1000 * 1024 * 1024, 80.0);

        // 1. Successful reservation (300 MB)
        assert!(vram_mgr.reserve_vram("agent-1", 300 * 1024 * 1024).is_ok());
        assert_eq!(vram_mgr.current_usage(), 300 * 1024 * 1024);

        // 2. Successful reservation (400 MB) -> Total 700 MB (70%)
        assert!(vram_mgr.reserve_vram("agent-2", 400 * 1024 * 1024).is_ok());
        assert_eq!(vram_mgr.current_usage(), 700 * 1024 * 1024);

        // 3. Circuit breaker triggers on 200 MB -> Total would be 900 MB (90% > 80% threshold)
        let res = vram_mgr.reserve_vram("agent-3", 200 * 1024 * 1024);
        assert_eq!(
            res,
            Err(VramError::CircuitBreakerTriggered {
                threshold_percent: 80.0
            })
        );

        // 4. Release VRAM for agent-1
        vram_mgr.release_vram("agent-1");
        assert_eq!(vram_mgr.current_usage(), 400 * 1024 * 1024);

        // 5. Total capacity and physical free check
        assert_eq!(vram_mgr.total_capacity(), 1000 * 1024 * 1024);
        assert!(vram_mgr.physical_free_vram() <= 1000 * 1024 * 1024);
    }
}
