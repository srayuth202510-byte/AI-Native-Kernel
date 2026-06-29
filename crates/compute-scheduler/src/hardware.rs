use crate::{ComputeProfile, ComputeTarget, NpuProfile, NpuVendor};
use nvml_wrapper::Nvml;
use std::path::Path;
use sysinfo::System;
use tracing::{debug, info, warn};

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
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub fn new() -> Self {
        let sys = System::new_all();
        let nvml = match Nvml::init() {
            Ok(n) => {
                debug!("NVML initialized successfully. NVIDIA GPU detected.");
                Some(n)
            }
            Err(e) => {
                warn!(
                    "NVML initialization failed (no NVIDIA GPU or driver missing): {}",
                    e
                );
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

        // 2. GPU Profiling with NVML
        if let Some(ref nvml) = self.nvml {
            if let Ok(device_count) = nvml.device_count() {
                if device_count > 0 {
                    for i in 0..device_count.min(4) {
                        // max 4 GPUs
                        if let Ok(dev) = nvml.device_by_index(i) {
                            let power_watts = dev
                                .power_usage()
                                .map(|p| p as f64 / 1000.0)
                                .unwrap_or(150.0);

                            let mem_info = dev.memory_info().ok();
                            let vram_gb = mem_info
                                .map(|m| m.total as f64 / 1_024.0 / 1_024.0 / 1_024.0)
                                .unwrap_or(0.0);

                            let util = dev.utilization_rates().ok();
                            let gpu_util = util.map(|u| u.gpu as f64).unwrap_or(0.0);

                            let clock = dev
                                .clock_info(nvml_wrapper::enum_wrappers::device::Clock::SM)
                                .ok();
                            let clock_mhz = clock.unwrap_or(0);

                            // ปรับแต่ง latency/power/cost ตาม spec จริง
                            let latency_ms = if vram_gb > 0.0 {
                                5.0 + (80.0 - vram_gb.min(80.0)) * 0.1 // GPU ที่มี VRAM มาก → latency ต่ำ
                            } else {
                                10.0
                            };

                            let cost_units = 20.0 + vram_gb * 1.5; // GPU ใหญ่ → แพง
                            let gpu_num = if device_count > 1 {
                                format!("GPU-{i}")
                            } else {
                                "GPU".to_string()
                            };

                            info!(
                                gpu = %gpu_num,
                                power_w = %power_watts,
                                vram_gb = %vram_gb,
                                gpu_util = %gpu_util,
                                clock_mhz = %clock_mhz,
                                "HardwareProber: GPU detected"
                            );

                            profiles.push((
                                ComputeTarget::Gpu,
                                ComputeProfile {
                                    latency_ms,
                                    power_watts,
                                    cost_units,
                                },
                            ));
                        }
                    }
                }
            }
        } else {
            debug!("No actual GPU found during hardware scan.");
        }

        // 3. NPU Profiling — ตรวจสอบหลาย path + vendor-specific profiles
        let npu_devices = Self::probe_npu_devices();
        for (path, vendor) in &npu_devices {
            debug!(
                "NPU device found at {} (vendor: {})",
                path.display(),
                vendor.as_str()
            );
            let npu_profile = match vendor {
                NpuVendor::IntelGaudi => NpuProfile::intel_gaudi3(),
                NpuVendor::GoogleTpu => NpuProfile::google_tpu_v5e(),
                NpuVendor::AppleSilicon => NpuProfile::apple_m4_ne(),
                NpuVendor::QualcommHexagon => NpuProfile::qualcomm_hexagon(),
                NpuVendor::AmdXdna => NpuProfile::amd_xdna2(),
                NpuVendor::Generic => NpuProfile::generic(),
            };
            profiles.push((ComputeTarget::Npu, npu_profile.to_compute_profile()));
            info!(
                path = %path.display(),
                vendor = vendor.as_str(),
                tops = npu_profile.tops,
                power = npu_profile.power_watts,
                "HardwareProber: NPU detected"
            );
        }

        profiles
    }

    /// ตรวจสอบ NPU devices จากหลาย paths + ระบุ vendor
    /// - `/dev/accel*` (Intel/AMD NPU, upstream kernel)
    /// - `/dev/davinci*` (Huawei Ascend)
    /// - `/dev/npu*` (vendor NPU)
    /// - `/sys/class/accel/*` (modern kernel NPU class)
    /// - `/dev/cdsp0`, `/dev/dsp0` (Qualcomm Hexagon)
    fn probe_npu_devices() -> Vec<(std::path::PathBuf, NpuVendor)> {
        let mut devices = Vec::new();

        // /dev/accel* — modern Linux accel subsystem
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("accel")
                    || name_str.starts_with("davinci")
                    || name_str.starts_with("npu")
                {
                    let vendor = Self::detect_npu_vendor(&entry.path());
                    devices.push((entry.path(), vendor));
                }
            }
        }

        // /sys/class/accel/* — kernel device class
        if Path::new("/sys/class/accel").exists() {
            if let Ok(entries) = std::fs::read_dir("/sys/class/accel") {
                for entry in entries.flatten() {
                    let dev_path = entry.path().join("dev");
                    if dev_path.exists() {
                        let vendor = Self::detect_npu_vendor(&entry.path());
                        devices.push((entry.path(), vendor));
                    }
                }
            }
        }

        // /dev/accel/ — directory-based accel
        if Path::new("/dev/accel").is_dir() {
            if let Ok(entries) = std::fs::read_dir("/dev/accel") {
                for entry in entries.flatten() {
                    let vendor = Self::detect_npu_vendor(&entry.path());
                    devices.push((entry.path(), vendor));
                }
            }
        }

        // /dev/cdsp*, /dev/dsp* — Qualcomm Hexagon DSP
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("cdsp") || name_str.starts_with("dsp") {
                    devices.push((entry.path(), NpuVendor::QualcommHexagon));
                }
            }
        }

        devices
    }

    /// ตรวจสอบ vendor ของ NPU จาก sysfs vendor ID
    fn detect_npu_vendor(device_path: &Path) -> NpuVendor {
        // ลองอ่าน vendor ID จาก sysfs
        let vendor_paths = [
            device_path.join("vendor"),
            device_path
                .parent()
                .map(|p| p.join("vendor"))
                .unwrap_or_default(),
        ];

        for vendor_path in &vendor_paths {
            if let Ok(vendor_id) = std::fs::read_to_string(vendor_path) {
                let vendor_id = vendor_id.trim();
                match vendor_id {
                    "0x8086" | "0x8087" => return NpuVendor::IntelGaudi, // Intel (Habana)
                    "0x1022" => return NpuVendor::AmdXdna,               // AMD
                    "0x10de" => return NpuVendor::Generic,               // NVIDIA (not NPU)
                    "0x103c" => return NpuVendor::QualcommHexagon,       // HP (Qualcomm)
                    _ => {}
                }
            }
        }

        // Check device path for hints
        let path_str = device_path.to_string_lossy();
        if path_str.contains("npu") || path_str.contains("davinci") {
            // Could be Huawei Ascend or other vendor
            NpuVendor::Generic
        } else {
            NpuVendor::Generic
        }
    }
}
