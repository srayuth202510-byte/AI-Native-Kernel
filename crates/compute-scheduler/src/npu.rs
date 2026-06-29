use crate::{NpuProfile, NpuRuntime, NpuVendor};
use tracing::{debug, info, warn};

// ---- Intel Gaudi Runtime ----

pub struct IntelGaudiRuntime {
    profile: NpuProfile,
}

impl IntelGaudiRuntime {
    pub fn new() -> Self {
        Self {
            profile: NpuProfile::intel_gaudi3(),
        }
    }
}

impl Default for IntelGaudiRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NpuRuntime for IntelGaudiRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::IntelGaudi
    }

    fn name(&self) -> &str {
        "intel_gaudi3"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        // Check for Intel Gaudi device via sysfs
        let gaudi_paths = ["/sys/class/accel/accel0/device/vendor", "/dev/accel0"];
        for path in &gaudi_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                debug!("Intel Gaudi detected at {}", path);
                return true;
            }
        }
        false
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        // Gaudi 3: ~1835 TOPS, very fast for large batches
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 1000.0).sqrt().max(1.0);
        base_ms * batch_factor * 0.01 // mock: very fast
    }

    async fn load_model(&self, model_path: &str) -> Result<(), String> {
        info!(model = model_path, "Intel Gaudi: loading model");
        // In real implementation: call Habana SynapseAI API
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        info!("Intel Gaudi: shutting down");
        Ok(())
    }
}

// ---- Google TPU Runtime ----

pub struct TpuRuntime {
    profile: NpuProfile,
}

impl TpuRuntime {
    pub fn new() -> Self {
        Self {
            profile: NpuProfile::google_tpu_v5e(),
        }
    }
}

impl Default for TpuRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NpuRuntime for TpuRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::GoogleTpu
    }

    fn name(&self) -> &str {
        "google_tpu_v5e"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        // Check for TPU device via /dev/accel or env var
        if let Ok(addr) = std::env::var("TPU_ADDRESS") {
            if !addr.is_empty() {
                debug!("Google TPU detected via TPU_ADDRESS={}", addr);
                return true;
            }
        }
        let tpu_paths = ["/dev/accel0", "/dev/tpu0"];
        for path in &tpu_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                debug!("Google TPU detected at {}", path);
                return true;
            }
        }
        false
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 500.0).max(1.0);
        base_ms * batch_factor * 0.01
    }

    async fn load_model(&self, model_path: &str) -> Result<(), String> {
        info!(model = model_path, "Google TPU: loading model");
        // In real implementation: call JAX/XLA TPU runtime
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        info!("Google TPU: shutting down");
        Ok(())
    }
}

// ---- Apple Silicon Neural Engine Runtime ----

pub struct AppleNpuRuntime {
    profile: NpuProfile,
}

impl AppleNpuRuntime {
    pub fn new() -> Self {
        Self {
            profile: NpuProfile::apple_m4_ne(),
        }
    }
}

impl Default for AppleNpuRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NpuRuntime for AppleNpuRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::AppleSilicon
    }

    fn name(&self) -> &str {
        "apple_m4_neural_engine"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        // Apple Silicon NPU is integrated — detect via platform check
        #[cfg(target_os = "macos")]
        {
            // On macOS with Apple Silicon, NE is always available
            debug!("Apple Neural Engine detected (macOS)");
            return true;
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        // ANE: very low power, moderate latency
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 200.0).max(1.0);
        base_ms * batch_factor * 0.01
    }

    async fn load_model(&self, model_path: &str) -> Result<(), String> {
        info!(model = model_path, "Apple Neural Engine: loading model");
        // In real implementation: use CoreML framework
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        info!("Apple Neural Engine: shutting down");
        Ok(())
    }
}

// ---- Qualcomm Hexagon Runtime ----

pub struct HexagonRuntime {
    profile: NpuProfile,
}

impl HexagonRuntime {
    pub fn new() -> Self {
        Self {
            profile: NpuProfile::qualcomm_hexagon(),
        }
    }
}

impl Default for HexagonRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NpuRuntime for HexagonRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::QualcommHexagon
    }

    fn name(&self) -> &str {
        "qualcomm_hexagon_dsp"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        // Check for Hexagon DSP device
        let hexagon_paths = ["/dev/cdsp0", "/dev/dsp0", "/sys/class/dsp/dsp0"];
        for path in &hexagon_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                debug!("Qualcomm Hexagon detected at {}", path);
                return true;
            }
        }
        false
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 300.0).max(1.0);
        base_ms * batch_factor * 0.01
    }

    async fn load_model(&self, model_path: &str) -> Result<(), String> {
        info!(model = model_path, "Qualcomm Hexagon: loading model");
        // In real implementation: use Qualcomm AI Engine Direct (QNN)
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        info!("Qualcomm Hexagon: shutting down");
        Ok(())
    }
}

// ---- AMD XDNA Runtime ----

pub struct XdnaRuntime {
    profile: NpuProfile,
}

impl XdnaRuntime {
    pub fn new() -> Self {
        Self {
            profile: NpuProfile::amd_xdna2(),
        }
    }
}

impl Default for XdnaRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NpuRuntime for XdnaRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::AmdXdna
    }

    fn name(&self) -> &str {
        "amd_xdna2_ryzen_ai"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        // Check for AMD XDNA device
        let xdna_paths = ["/dev/accel0", "/sys/class/accel/accel0/device/vendor"];
        for path in &xdna_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                // Additional check: verify vendor ID is AMD (0x1022)
                if path.ends_with("vendor") {
                    if let Ok(content) = tokio::fs::read_to_string(path).await {
                        if content.trim() == "0x1022" {
                            debug!("AMD XDNA detected");
                            return true;
                        }
                    }
                } else {
                    debug!("AMD XDNA device found at {}", path);
                    return true;
                }
            }
        }
        false
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 400.0).max(1.0);
        base_ms * batch_factor * 0.01
    }

    async fn load_model(&self, model_path: &str) -> Result<(), String> {
        info!(model = model_path, "AMD XDNA: loading model");
        // In real implementation: use Ryzen AI SDK / ONNX Runtime VitisAI
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        info!("AMD XDNA: shutting down");
        Ok(())
    }
}

// ---- Factory: create runtime by vendor ----

/// สร้าง NpuRuntime ตาม vendor ที่ระบุ
pub fn create_npu_runtime(vendor: NpuVendor) -> Box<dyn NpuRuntime> {
    match vendor {
        NpuVendor::IntelGaudi => Box::new(IntelGaudiRuntime::new()),
        NpuVendor::GoogleTpu => Box::new(TpuRuntime::new()),
        NpuVendor::AppleSilicon => Box::new(AppleNpuRuntime::new()),
        NpuVendor::QualcommHexagon => Box::new(HexagonRuntime::new()),
        NpuVendor::AmdXdna => Box::new(XdnaRuntime::new()),
        NpuVendor::Generic => {
            warn!("Generic NPU vendor — no vendor-specific runtime available");
            // Return a generic fallback
            Box::new(GenericNpuRuntime::new())
        }
    }
}

// ---- Generic NPU Runtime (fallback) ----

struct GenericNpuRuntime {
    profile: NpuProfile,
}

impl GenericNpuRuntime {
    fn new() -> Self {
        Self {
            profile: NpuProfile::generic(),
        }
    }
}

#[async_trait::async_trait]
impl NpuRuntime for GenericNpuRuntime {
    fn vendor(&self) -> NpuVendor {
        NpuVendor::Generic
    }

    fn name(&self) -> &str {
        "generic_npu"
    }

    fn profile(&self) -> NpuProfile {
        self.profile
    }

    async fn is_available(&self) -> bool {
        true // Generic always "available" as fallback
    }

    async fn execute_inference(&self, tokens: usize) -> f64 {
        let base_ms = self.profile.base_latency_ms;
        let batch_factor = (tokens as f64 / 200.0).max(1.0);
        base_ms * batch_factor * 0.01
    }

    async fn load_model(&self, _model_path: &str) -> Result<(), String> {
        warn!("Generic NPU: no vendor-specific model loading available");
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vendor_profiles() {
        let gaudi = NpuProfile::intel_gaudi3();
        assert!(gaudi.tops > 1000.0, "Gaudi 3 should have >1000 TOPS");

        let tpu = NpuProfile::google_tpu_v5e();
        assert!(tpu.power_watts < 50.0, "TPU v5e should be <50W");

        let apple = NpuProfile::apple_m4_ne();
        assert!(apple.power_watts < 15.0, "Apple NE should be <15W");

        let hexagon = NpuProfile::qualcomm_hexagon();
        assert!(hexagon.power_watts < 20.0, "Hexagon should be <20W");

        let xdna = NpuProfile::amd_xdna2();
        assert!(xdna.tops > 40.0, "XDNA 2 should have >40 TOPS");
    }

    #[tokio::test]
    async fn test_create_runtimes() {
        let vendors = [
            NpuVendor::IntelGaudi,
            NpuVendor::GoogleTpu,
            NpuVendor::AppleSilicon,
            NpuVendor::QualcommHexagon,
            NpuVendor::AmdXdna,
            NpuVendor::Generic,
        ];

        for vendor in vendors {
            let runtime = create_npu_runtime(vendor);
            assert_eq!(runtime.vendor(), vendor);
            assert!(!runtime.name().is_empty());
        }
    }

    #[tokio::test]
    async fn test_npu_profile_to_compute_profile() {
        let npu = NpuProfile::intel_gaudi3();
        let compute = npu.to_compute_profile();
        assert_eq!(compute.latency_ms, npu.base_latency_ms);
        assert_eq!(compute.power_watts, npu.power_watts);
        assert_eq!(compute.cost_units, npu.cost_units);
    }

    #[tokio::test]
    async fn test_mock_inference() {
        let runtime = create_npu_runtime(NpuVendor::IntelGaudi);
        let latency = runtime.execute_inference(1000).await;
        assert!(
            latency > 0.0,
            "Mock inference should return positive latency"
        );
    }
}
