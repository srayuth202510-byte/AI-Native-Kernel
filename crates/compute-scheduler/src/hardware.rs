use crate::{ComputeProfile, ComputeTarget};
use nvml_wrapper::Nvml;
use sysinfo::System;
use tracing::{debug, warn};

/// Probe the system to discover available compute targets and their actual capabilities.
pub struct HardwareProber {
    sys: System,
    nvml: Option<Nvml>,
}

impl Default for HardwareProber {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareProber {
    #[must_use]
    pub fn new() -> Self {
        let sys = System::new_all();
        let nvml = match Nvml::init() {
            Ok(n) => {
                debug!("NVML initialized successfully. NVIDIA GPU detected.");
                Some(n)
            }
            Err(e) => {
                warn!("NVML initialization failed (no NVIDIA GPU or driver missing): {}", e);
                None
            }
        };

        Self { sys, nvml }
    }

    /// Scan and return a list of profiles for the current hardware.
    #[must_use]
    pub fn scan_hardware(&mut self) -> Vec<(ComputeTarget, ComputeProfile)> {
        self.sys.refresh_all();
        let mut profiles = Vec::new();

        // 1. CPU Profiling
        let cpu_count = self.sys.cpus().len() as f64;
        let cpu_profile = ComputeProfile {
            // Rough heuristic: more CPUs = lower latency
            latency_ms: 50.0 / cpu_count.max(1.0),
            power_watts: 65.0, // Baseline TDP assumption
            cost_units: 5.0,
        };
        profiles.push((ComputeTarget::Cpu, cpu_profile));

        // 2. GPU Profiling
        if let Some(ref nvml) = self.nvml {
            if let Ok(device_count) = nvml.device_count() {
                if device_count > 0 {
                    // We just take the first GPU for the profile as an example
                    let power = if let Ok(dev) = nvml.device_by_index(0) {
                        dev.power_usage().unwrap_or(150_000) as f64 / 1000.0 // mW to W
                    } else {
                        150.0
                    };

                    let gpu_profile = ComputeProfile {
                        latency_ms: 10.0, // Highly parallel tasks are fast
                        power_watts: power,
                        cost_units: 50.0, // GPU is expensive
                    };
                    profiles.push((ComputeTarget::Gpu, gpu_profile));
                }
            }
        } else {
            // Fallback or simulated GPU if needed, but in real scan we just don't add it.
            debug!("No actual GPU found during hardware scan.");
        }

        // 3. NPU Profiling
        // Linux NPU APIs are still nascent (e.g. /dev/accel). We do a basic check.
        if std::path::Path::new("/dev/accel").exists() {
            debug!("NPU block device found at /dev/accel");
            let npu_profile = ComputeProfile {
                latency_ms: 15.0,
                power_watts: 10.0, // NPU is very power efficient
                cost_units: 15.0,
            };
            profiles.push((ComputeTarget::Npu, npu_profile));
        }

        profiles
    }
}
