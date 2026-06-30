use crate::{ComputeProfile, ComputeTarget, NpuProfile, NpuVendor};
use nvml_wrapper::Nvml;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tokio::task;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const CLOUD_LATENCY_MS: f64 = 200.0;
const CLOUD_POWER_WATTS: f64 = 0.0;
const CLOUD_COST_UNITS: f64 = 500.0;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub async fn scan_hardware(&mut self) -> Vec<(ComputeTarget, ComputeProfile)> {
        self.sys.refresh_all();
        let mut profiles = Vec::new();

        // 1. CPU Profiling
        let cpu_count = self.sys.cpus().len() as f64;
        let cpu_profile = ComputeProfile {
            latency_ms: 50.0 / cpu_count.max(1.0),
            power_watts: 65.0,
            cost_units: 5.0,
        };
        profiles.push((ComputeTarget::Cpu, cpu_profile));

        // 2. GPU Profiling with NVML
        if let Some(ref nvml) = self.nvml {
            if let Ok(device_count) = nvml.device_count() {
                if device_count > 0 {
                    for i in 0..device_count.min(4) {
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

                            let latency_ms = if vram_gb > 0.0 {
                                5.0 + (80.0 - vram_gb.min(80.0)) * 0.1
                            } else {
                                10.0
                            };

                            let cost_units = 20.0 + vram_gb * 1.5;
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

        // 3. Cloud probing via env-configured endpoint
        if let Some(profile) = Self::probe_cloud().await {
            profiles.push((ComputeTarget::Cloud, profile));
        }

        // 4. NPU Profiling — ตรวจสอบหลาย path + vendor-specific profiles
        let npu_devices = Self::probe_npu_devices().await;
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

    /// Probe cloud endpoint from environment variables.
    /// Checks CLOUD_ENDPOINT_URL, CLOUD_API_KEY, CLOUD_MODEL.
    async fn probe_cloud() -> Option<ComputeProfile> {
        let endpoint = std::env::var("CLOUD_ENDPOINT_URL").ok()?;
        let _api_key = std::env::var("CLOUD_API_KEY").ok()?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;

        let url = format!("{}/v1/chat/completions", endpoint);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() || resp.status().is_client_error() => {
                info!(
                    endpoint = %endpoint,
                    "HardwareProber: cloud endpoint reachable"
                );
                Some(ComputeProfile {
                    latency_ms: CLOUD_LATENCY_MS,
                    power_watts: CLOUD_POWER_WATTS,
                    cost_units: CLOUD_COST_UNITS,
                })
            }
            Ok(resp) => {
                debug!(
                    endpoint = %endpoint,
                    status = %resp.status(),
                    "HardwareProber: cloud endpoint unreachable"
                );
                None
            }
            Err(_) => None,
        }
    }

    /// ตรวจสอบ NPU devices จากหลาย paths + ระบุ vendor
    async fn probe_npu_devices() -> Vec<(std::path::PathBuf, NpuVendor)> {
        let mut devices = Vec::new();

        // Collect all /dev entries in a single spawn_blocking call
        let dev_entries = Self::collect_dir_entries("/dev").await;
        if let Some(ref entries) = dev_entries {
            for (name, path) in entries {
                let name_str = name.to_string_lossy();
                if name_str.starts_with("accel")
                    || name_str.starts_with("davinci")
                    || name_str.starts_with("npu")
                {
                    let vendor = Self::detect_npu_vendor(path).await;
                    devices.push((path.clone(), vendor));
                }
            }
        }

        // /sys/class/accel — kernel device class
        if Self::path_is_dir("/sys/class/accel").await {
            let accel_entries = Self::collect_dir_entries("/sys/class/accel").await;
            if let Some(ref entries) = accel_entries {
                for (_, path) in entries {
                    let dev_path = path.join("dev");
                    if Self::path_exists(&dev_path).await {
                        let vendor = Self::detect_npu_vendor(path).await;
                        devices.push((path.clone(), vendor));
                    }
                }
            }
        }

        // /dev/accel/ — directory-based accel
        if Self::path_is_dir("/dev/accel").await {
            let accel_dev_entries = Self::collect_dir_entries("/dev/accel").await;
            if let Some(ref entries) = accel_dev_entries {
                for (_, path) in entries {
                    let vendor = Self::detect_npu_vendor(path).await;
                    devices.push((path.clone(), vendor));
                }
            }
        }

        // /dev/cdsp*, /dev/dsp* — Qualcomm Hexagon DSP — reuse collected dev entries
        if let Some(ref entries) = dev_entries {
            for (name, path) in entries {
                let name_str = name.to_string_lossy();
                if name_str.starts_with("cdsp") || name_str.starts_with("dsp") {
                    devices.push((path.clone(), NpuVendor::QualcommHexagon));
                }
            }
        }

        devices
    }

    /// Collect all entries from a directory in a single spawn_blocking call.
    async fn collect_dir_entries(path: &str) -> Option<Vec<(std::ffi::OsString, PathBuf)>> {
        let path: Arc<str> = Arc::from(path);
        timeout(
            PROBE_TIMEOUT,
            task::spawn_blocking(move || {
                Path::new(path.as_ref())
                    .read_dir()
                    .ok()
                    .map(|iter| iter.flatten().map(|e| (e.file_name(), e.path())).collect())
            }),
        )
        .await
        .ok()?
        .ok()?
    }

    /// Check if a path exists as a directory using spawn_blocking.
    async fn path_is_dir(path: &str) -> bool {
        let path: Arc<str> = Arc::from(path);
        timeout(
            PROBE_TIMEOUT,
            task::spawn_blocking(move || Path::new(path.as_ref()).is_dir()),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(false)
    }

    /// Check if a path exists using spawn_blocking.
    async fn path_exists(path: &Path) -> bool {
        let path_buf: Arc<PathBuf> = Arc::new(path.to_path_buf());
        timeout(
            PROBE_TIMEOUT,
            task::spawn_blocking(move || path_buf.as_ref().exists()),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(false)
    }

    /// ตรวจสอบ vendor ของ NPU จาก sysfs vendor ID
    async fn detect_npu_vendor(device_path: &Path) -> NpuVendor {
        let paths = [
            device_path.join("vendor"),
            device_path
                .parent()
                .map(|p| p.join("vendor"))
                .unwrap_or_default(),
        ];

        for p in &paths {
            let p_clone = p.clone();
            let result = timeout(
                PROBE_TIMEOUT,
                task::spawn_blocking(move || std::fs::read_to_string(&p_clone).ok()),
            )
            .await;
            if let Ok(Ok(Some(vendor_id))) = result {
                let vendor_id = vendor_id.trim();
                match vendor_id {
                    "0x8086" | "0x8087" => return NpuVendor::IntelGaudi,
                    "0x1022" => return NpuVendor::AmdXdna,
                    "0x10de" => return NpuVendor::Generic,
                    "0x103c" => return NpuVendor::QualcommHexagon,
                    _ => {}
                }
            }
        }

        NpuVendor::Generic
    }
}
