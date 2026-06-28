use crate::{
    ComputeError, ComputeProfile, ComputeScheduler, ComputeTarget, InferenceRuntime,
    PlacementDecision,
};
use tracing::{debug, instrument};

/// ชนิดของภาระงาน (Workload Class) สำหรับเลือกฮาร์ดแวร์เป้าหมายที่เหมาะสมที่สุด
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadClass {
    /// งานระดับเคอร์เนล เช่น ตรวจสอบ LSM Policy หรือจัดการ Security Token
    KernelLogic,
    /// งานรันโมเดล LLM ขนาดเล็ก (ต่ำกว่า 7B parameters)
    SmallLlm,
    /// งานรันโมเดล LLM ขนาดใหญ่ (เน้น Reasoning)
    LargeLlm,
    /// งานสร้างและดึงข้อมูล Vector Indexing (Semantic Search)
    VectorIndexing,
}

/// นโยบายจัดสรรทรัพยากรแบบรับรู้อุปกรณ์ (Device-aware Placement Policy)
#[derive(Debug)]
pub struct PlacementPolicy {
    scheduler: ComputeScheduler,
}

impl PlacementPolicy {
    /// สร้างนโยบายการจัดสรรด้วย Scheduler ที่กำหนด
    #[must_use]
    pub fn new(scheduler: ComputeScheduler) -> Self {
        Self { scheduler }
    }

    /// ดึงรายการของอุปกรณ์ (Compute Target) ที่เหมาะสมและอนุญาตสำหรับงานแต่ละประเภท
    #[must_use]
    pub fn allowed_targets(workload: WorkloadClass) -> Vec<ComputeTarget> {
        match workload {
            // Kernel Logic ต้องการความเสถียรและ latency ต่ำในการเรียกใช้เสมอ ให้ล็อกที่ CPU
            WorkloadClass::KernelLogic => vec![ComputeTarget::Cpu],
            // Small LLM เหมาะกับการรันแบบ Edge บน NPU เป็นหลัก (ประหยัดพลังงาน)
            WorkloadClass::SmallLlm => vec![ComputeTarget::Npu, ComputeTarget::Cpu],
            // Large LLM ต้องใช้พลังประมวลผลสูง (Batch reasoning) ให้ใช้ GPU หรือรันบน Cloud
            WorkloadClass::LargeLlm => vec![ComputeTarget::Gpu, ComputeTarget::Cloud],
            // Vector Indexing รองรับการประมวลผลแบบขนาน ใช้ได้ดีทั้ง GPU และ NPU
            WorkloadClass::VectorIndexing => vec![ComputeTarget::Gpu, ComputeTarget::Npu],
        }
    }

    /// ประเมินและเลือกอุปกรณ์ที่ดีที่สุดสำหรับงานที่กำหนด
    /// อิงจากโปรไฟล์การทำงานจริง (real profiles) ของแต่ละอุปกรณ์ที่มีอยู่
    ///
    /// # Errors
    /// คืนค่า `ComputeError::NoTargetAvailable` หากไม่มีอุปกรณ์ใดรองรับงานนี้
    #[instrument(skip(self, available_profiles), fields(workload = ?workload))]
    pub fn place(
        &self,
        workload: WorkloadClass,
        available_profiles: &[(ComputeTarget, ComputeProfile)],
    ) -> Result<ComputeTarget, ComputeError> {
        let allowed = Self::allowed_targets(workload);

        // คัดกรองเอาเฉพาะโปรไฟล์ของอุปกรณ์ที่งานนั้นอนุญาตให้รันได้
        let candidates: Vec<(ComputeTarget, ComputeProfile)> = available_profiles
            .iter()
            .filter(|(target, _)| allowed.contains(target))
            .copied()
            .collect();

        if candidates.is_empty() {
            debug!("ไม่มีอุปกรณ์เป้าหมายที่ตรงกับ Allowed Targets ของงานนี้");
            return Err(ComputeError::NoTargetAvailable);
        }

        // ให้ Scheduler คำนวณ cost/score และเลือกสิ่งที่ดีที่สุด
        let best_target = self.scheduler.choose_best(&candidates)?;
        debug!(best_target = ?best_target, "Placement Policy ตัดสินใจเลือกอุปกรณ์");

        Ok(best_target)
    }

    /// ตัดสินใจเลือกรันไทม์การประมวลผล (Inference Runtime) ที่เหมาะสมตามอุปกรณ์เป้าหมายและชนิดภาระงาน
    #[must_use]
    pub fn select_runtime(
        target: ComputeTarget,
        workload: WorkloadClass,
    ) -> Option<InferenceRuntime> {
        match target {
            ComputeTarget::Cpu => match workload {
                WorkloadClass::KernelLogic => None,
                WorkloadClass::SmallLlm | WorkloadClass::LargeLlm => {
                    Some(InferenceRuntime::LlamaCpp)
                }
                WorkloadClass::VectorIndexing => Some(InferenceRuntime::OnnxRuntime),
            },
            ComputeTarget::Gpu => match workload {
                WorkloadClass::KernelLogic => None,
                _ => Some(InferenceRuntime::TensorRtLlm),
            },
            ComputeTarget::Npu => match workload {
                WorkloadClass::KernelLogic => None,
                WorkloadClass::SmallLlm => Some(InferenceRuntime::LlamaCpp),
                _ => Some(InferenceRuntime::OnnxRuntime),
            },
            ComputeTarget::Cloud => match workload {
                WorkloadClass::KernelLogic => None,
                _ => Some(InferenceRuntime::LlamaCpp),
            },
        }
    }

    /// ประเมินและเลือกอุปกรณ์พร้อมรันไทม์การประมวลผลที่ดีที่สุด
    ///
    /// # Errors
    /// คืนค่า `ComputeError::NoTargetAvailable` หากไม่มีอุปกรณ์ใดรองรับงานนี้
    #[instrument(skip(self, available_profiles), fields(workload = ?workload))]
    pub fn place_with_runtime(
        &self,
        workload: WorkloadClass,
        available_profiles: &[(ComputeTarget, ComputeProfile)],
    ) -> Result<PlacementDecision, ComputeError> {
        let target = self.place(workload, available_profiles)?;
        let runtime = Self::select_runtime(target, workload);
        Ok(PlacementDecision { target, runtime })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weights::{AdaptiveWeights, SchedulerMode};

    fn dummy_profiles() -> Vec<(ComputeTarget, ComputeProfile)> {
        vec![
            (
                ComputeTarget::Cpu,
                ComputeProfile {
                    latency_ms: 10.0,
                    power_watts: 50.0,
                    cost_units: 10.0,
                },
            ),
            (
                ComputeTarget::Gpu,
                ComputeProfile {
                    latency_ms: 2.0,
                    power_watts: 200.0,
                    cost_units: 100.0,
                },
            ),
            (
                ComputeTarget::Npu,
                ComputeProfile {
                    latency_ms: 5.0,
                    power_watts: 10.0,
                    cost_units: 20.0,
                },
            ),
            (
                ComputeTarget::Cloud,
                ComputeProfile {
                    latency_ms: 200.0,
                    power_watts: 0.0,
                    cost_units: 500.0,
                },
            ),
        ]
    }

    #[test]
    fn kernel_logic_always_placed_on_cpu() {
        let scheduler = ComputeScheduler::new();
        let policy = PlacementPolicy::new(scheduler);
        let profiles = dummy_profiles();

        let target = policy.place(WorkloadClass::KernelLogic, &profiles).unwrap();
        assert_eq!(target, ComputeTarget::Cpu);
    }

    #[test]
    fn large_llm_placed_on_gpu_in_throughput_mode() {
        // ในโหมด Throughput (เน้น Latency) Large LLM ควรลง GPU (latency = 2.0)
        let weights = AdaptiveWeights::from_mode(SchedulerMode::Throughput);
        let scheduler = ComputeScheduler::with_weights(weights);
        let policy = PlacementPolicy::new(scheduler);
        let profiles = dummy_profiles();

        let target = policy.place(WorkloadClass::LargeLlm, &profiles).unwrap();
        assert_eq!(target, ComputeTarget::Gpu);
    }

    #[test]
    fn small_llm_placed_on_npu_in_battery_mode() {
        // ในโหมด Battery (เน้น Power) Small LLM ควรลง NPU (power = 10.0 vs CPU 50.0)
        let weights = AdaptiveWeights::from_mode(SchedulerMode::Battery);
        let scheduler = ComputeScheduler::with_weights(weights);
        let policy = PlacementPolicy::new(scheduler);
        let profiles = dummy_profiles();

        let target = policy.place(WorkloadClass::SmallLlm, &profiles).unwrap();
        assert_eq!(target, ComputeTarget::Npu);
    }

    #[test]
    fn placement_fails_if_required_hardware_missing() {
        let scheduler = ComputeScheduler::new();
        let policy = PlacementPolicy::new(scheduler);
        // มีเฉพาะ CPU
        let profiles = vec![(
            ComputeTarget::Cpu,
            ComputeProfile {
                latency_ms: 10.0,
                power_watts: 10.0,
                cost_units: 10.0,
            },
        )];

        // LargeLlm ต้องการ GPU หรือ Cloud เท่านั้น
        let result = policy.place(WorkloadClass::LargeLlm, &profiles);
        assert_eq!(result, Err(ComputeError::NoTargetAvailable));
    }

    #[test]
    fn select_runtime_rules() {
        assert_eq!(
            PlacementPolicy::select_runtime(ComputeTarget::Cpu, WorkloadClass::SmallLlm),
            Some(InferenceRuntime::LlamaCpp)
        );
        assert_eq!(
            PlacementPolicy::select_runtime(ComputeTarget::Gpu, WorkloadClass::LargeLlm),
            Some(InferenceRuntime::TensorRtLlm)
        );
        assert_eq!(
            PlacementPolicy::select_runtime(ComputeTarget::Npu, WorkloadClass::VectorIndexing),
            Some(InferenceRuntime::OnnxRuntime)
        );
        assert_eq!(
            PlacementPolicy::select_runtime(ComputeTarget::Cpu, WorkloadClass::KernelLogic),
            None
        );
    }

    #[test]
    fn place_with_runtime_computes_correct_decision() {
        let scheduler = ComputeScheduler::new();
        let policy = PlacementPolicy::new(scheduler);
        let profiles = dummy_profiles();

        let decision = policy
            .place_with_runtime(WorkloadClass::SmallLlm, &profiles)
            .unwrap();

        assert_eq!(decision.target, ComputeTarget::Npu);
        assert_eq!(decision.runtime, Some(InferenceRuntime::LlamaCpp));
    }

    #[test]
    fn mock_inference_execution_latencies() {
        let llama = InferenceRuntime::LlamaCpp;
        let onnx = InferenceRuntime::OnnxRuntime;
        let trt = InferenceRuntime::TensorRtLlm;

        assert_eq!(llama.execute_mock_inference(100), 50.0);
        assert_eq!(onnx.execute_mock_inference(100), 30.0);
        assert_eq!(trt.execute_mock_inference(100), 8.0);
    }
}
