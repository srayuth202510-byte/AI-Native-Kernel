//! # การตรวจจับความสามารถของ Kernel สำหรับ AI-Native Kernel
//!
//! โมดูลนี้ทำหน้าที่ตรวจจับคุณลักษณะและความสามารถของระบบปฏิบัติการ Linux Host
//! เพื่อวิเคราะห์และตัดสินใจโหมดการทำงาน (Deployment Mode) ที่เหมาะสมที่สุด
//! (เช่น Production, Degraded หรือ Simulation) ก่อนทำการ Boot ระบบจริง

use std::fmt;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// โครงสร้างข้อมูลสำหรับรุ่นของ Linux Kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    /// แปลงข้อความรุ่น Kernel (เช่น "6.1.0-21-amd64") เป็นโครงสร้างข้อมูล `KernelVersion`
    #[must_use]
    pub fn parse(version_str: &str) -> Option<Self> {
        let clean_str = version_str.trim().split('-').next()?;
        let parts: Vec<&str> = clean_str.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;
        let patch = parts
            .get(2)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// ตรวจสอบว่ารุ่น Kernel มีรุ่นขั้นต่ำตรงตามที่ระบุหรือไม่
    #[must_use]
    pub fn meets_minimum(&self, major: u32, minor: u32) -> bool {
        if self.major > major {
            true
        } else if self.major == major {
            self.minor >= minor
        } else {
            false
        }
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// โหมดการทำงานของ AI-Native Kernel ที่แนะนำตามผลลัพธ์การตรวจสอบ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentMode {
    /// โหมดการทำงานเต็มประสิทธิภาพบน Kernel จริง (eBPF + LSM Hooks)
    Production,
    /// โหมดรันแบบลดรูป (เช่น ติดตั้ง LSM ไม่ได้ แต่ยังสามารถใช้ eBPF Tracer ดักจับข้อมูลได้)
    Degraded { reasons: Vec<String> },
    /// โหมดการทำงานจำลองบนพื้นที่ผู้ใช้ (Pure Userspace Simulation) เนื่องจากขาดสิทธิ์หรือฟีเจอร์ของ Kernel
    Simulation { reasons: Vec<String> },
}

impl DeploymentMode {
    /// ตรวจสอบว่าโหมดนี้เป็น Production หรือไม่
    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }

    /// ตรวจสอบว่าโหมดนี้เป็น Simulation หรือไม่
    #[must_use]
    pub fn is_simulation(&self) -> bool {
        matches!(self, Self::Simulation { .. })
    }

    /// ตรวจสอบว่าโหมดนี้อนุญาตให้ทำงาน eBPF Tracer หรือไม่
    #[must_use]
    pub fn allows_ebpf_tracer(&self) -> bool {
        match self {
            Self::Production | Self::Degraded { .. } => true,
            Self::Simulation { .. } => false,
        }
    }

    /// ตรวจสอบว่าโหมดนี้อนุญาตให้ทำงาน LSM Hooks หรือไม่
    #[must_use]
    pub fn allows_lsm_hooks(&self) -> bool {
        match self {
            Self::Production => true,
            Self::Degraded { .. } | Self::Simulation { .. } => false,
        }
    }
}

impl fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => write!(f, "Production (Full eBPF + LSM)"),
            Self::Degraded { reasons } => {
                write!(f, "Degraded Mode - Reasons: {}", reasons.join("; "))
            }
            Self::Simulation { reasons } => {
                write!(
                    f,
                    "Simulation Mode (Userspace Only) - Reasons: {}",
                    reasons.join("; ")
                )
            }
        }
    }
}

/// โครงสร้างข้อมูลสำหรับรายงานผลการตรวจสอบรายรายการ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityDiagnostic {
    pub check: String,
    pub passed: bool,
    pub detail: String,
    pub remediation: Option<String>,
}

/// โครงสร้างข้อมูลความสามารถของระบบและ Kernel ทั้งหมดที่ตรวจสอบพบ
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelCapabilities {
    pub kernel_version: Option<KernelVersion>,
    pub has_bpf_lsm_config: bool,
    pub has_btf: bool,
    pub is_root: bool,
    pub bpf_fs_mounted: bool,
    pub cap_bpf: bool,
    pub cap_sys_admin: bool,
    pub cap_perfmon: bool,
}

/// อุปกรณ์ตรวจหาและวิเคราะห์ความสามารถของ Kernel
pub struct KernelCapabilityDetector;

impl KernelCapabilityDetector {
    /// ตรวจหาความสามารถของระบบในปัจจุบัน
    #[must_use]
    pub fn detect() -> KernelCapabilities {
        let mut caps = KernelCapabilities::default();

        // 1. ตรวจสอบรุ่น Kernel
        if let Ok(version_str) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            caps.kernel_version = KernelVersion::parse(&version_str);
        }

        // 2. ตรวจสอบสิทธิ์ผู้ใช้ Root
        caps.is_root = nix::unistd::Uid::current().is_root();

        // 3. ตรวจสอบ Linux Capabilities (CapEff) จาก /proc/self/status
        let (cap_bpf, cap_sys_admin, cap_perfmon) = Self::detect_effective_capabilities();
        caps.cap_bpf = cap_bpf;
        caps.cap_sys_admin = cap_sys_admin;
        caps.cap_perfmon = cap_perfmon;

        // 4. ตรวจสอบ BTF (BPF Type Format)
        caps.has_btf = Path::new("/sys/kernel/btf/vmlinux").exists();

        // 5. ตรวจสอบการ Mount BPF Filesystem
        caps.bpf_fs_mounted = Path::new("/sys/fs/bpf").exists();

        // 6. ตรวจสอบ CONFIG_BPF_LSM ใน Boot Config
        if let Some(ref version) = caps.kernel_version {
            let config_path = format!("/boot/config-{}", version);
            if Path::new(&config_path).exists() {
                if let Ok(config_content) = fs::read_to_string(&config_path) {
                    caps.has_bpf_lsm_config = config_content.contains("CONFIG_BPF_LSM=y");
                }
            } else if Path::new("/proc/config.gz").exists() {
                // ทางเลือกสำรองถ้าเปิด /proc/config.gz ไว้
                // ไม่เปิดการแตกไฟล์ gz แบบหนักเพื่อหลีกเลี่ยง dependency เพิ่มเติม
                // แต่ถ้า config ธรรมดาใน /boot ไม่มี เราก็พิจารณาตามการ detect config lsm
                caps.has_bpf_lsm_config = false;
            }
        }

        // เสริมการเช็ค BPF LSM จาก sysfs/lsm ถ้ามี (บางระบบ kernel 6.x อาจจะมีบอกใน lsm list)
        if !caps.has_bpf_lsm_config {
            if let Ok(lsm_content) = fs::read_to_string("/sys/kernel/security/lsm") {
                if lsm_content.contains("bpf") {
                    caps.has_bpf_lsm_config = true;
                }
            }
        }

        caps
    }

    /// ตรวจวิเคราะห์และประเมินผลความสามารถของระบบและสร้างรายการบันทึกผลตรวจสอบ (Diagnostics)
    #[must_use]
    pub fn diagnose() -> Vec<CapabilityDiagnostic> {
        let caps = Self::detect();
        let mut diagnostics = Vec::new();

        // Check 1: Kernel Version
        let version_passed = caps.kernel_version.is_some_and(|v| v.meets_minimum(5, 19));
        let version_detail = match &caps.kernel_version {
            Some(v) => format!("Kernel version detected: {v} (Required >= 5.19)"),
            None => "Unable to detect kernel version".to_string(),
        };
        diagnostics.push(CapabilityDiagnostic {
            check: "Kernel Version".to_string(),
            passed: version_passed,
            detail: version_detail,
            remediation: if version_passed {
                None
            } else {
                Some("Upgrade to a Linux host with kernel version 5.19 or newer.".to_string())
            },
        });

        // Check 2: BTF Support
        diagnostics.push(CapabilityDiagnostic {
            check: "BTF Support".to_string(),
            passed: caps.has_btf,
            detail: if caps.has_btf {
                "BPF Type Format (BTF) debugging information is enabled at /sys/kernel/btf/vmlinux.".to_string()
            } else {
                "BPF Type Format (BTF) not found. Required by Aya eBPF loader.".to_string()
            },
            remediation: if caps.has_btf {
                None
            } else {
                Some("Enable CONFIG_DEBUG_INFO_BTF=y when building kernel or install kernel-debuginfo.".to_string())
            },
        });

        // Check 3: Root or Capabilities
        let has_sufficient_privileges =
            caps.is_root || (caps.cap_bpf && caps.cap_sys_admin && caps.cap_perfmon);
        let priv_detail = format!(
            "Running as root: {} | Effective Capabilities - CAP_BPF: {}, CAP_SYS_ADMIN: {}, CAP_PERFMON: {}",
            caps.is_root, caps.cap_bpf, caps.cap_sys_admin, caps.cap_perfmon
        );
        diagnostics.push(CapabilityDiagnostic {
            check: "User Privileges".to_string(),
            passed: has_sufficient_privileges,
            detail: priv_detail,
            remediation: if has_sufficient_privileges {
                None
            } else {
                Some("Run the daemon as root or set capabilities via setcap (CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON).".to_string())
            },
        });

        // Check 4: CONFIG_BPF_LSM
        diagnostics.push(CapabilityDiagnostic {
            check: "CONFIG_BPF_LSM".to_string(),
            passed: caps.has_bpf_lsm_config,
            detail: if caps.has_bpf_lsm_config {
                "CONFIG_BPF_LSM is enabled in kernel config or active.".to_string()
            } else {
                "CONFIG_BPF_LSM is not enabled. BPF-based Linux Security Modules cannot attach.".to_string()
            },
            remediation: if caps.has_bpf_lsm_config {
                None
            } else {
                Some("Rebuild kernel with CONFIG_BPF_LSM=y or append 'lsm=landlock,lockdown,yama,integrity,bpf' to GRUB_CMDLINE_LINUX.".to_string())
            },
        });

        // Check 5: BPF Filesystem
        diagnostics.push(CapabilityDiagnostic {
            check: "BPF Filesystem".to_string(),
            passed: caps.bpf_fs_mounted,
            detail: if caps.bpf_fs_mounted {
                "BPF filesystem is mounted at /sys/fs/bpf.".to_string()
            } else {
                "BPF filesystem directory (/sys/fs/bpf) is missing or not mounted.".to_string()
            },
            remediation: if caps.bpf_fs_mounted {
                None
            } else {
                Some("Mount BPF filesystem manually: mount -t bpf bpffs /sys/fs/bpf".to_string())
            },
        });

        diagnostics
    }

    /// แนะนำโหมดการทำงานอิงตาม Capabilities ของระบบ
    #[must_use]
    pub fn recommended_mode(caps: &KernelCapabilities) -> DeploymentMode {
        let mut reasons = Vec::new();

        // 1. ตรวจสอบว่าระบบรองรับความต้องการระดับพื้นฐานสำหรับ eBPF หรือไม่ (BTF + สิทธิ์การรัน)
        let privileges_ok = caps.is_root || (caps.cap_bpf && caps.cap_sys_admin);
        let basic_ebpf_ok = caps.has_btf && privileges_ok;

        if !basic_ebpf_ok {
            if !caps.has_btf {
                reasons.push("Missing BTF support (/sys/kernel/btf/vmlinux)".to_string());
            }
            if !privileges_ok {
                reasons.push(
                    "Insufficient privileges (Requires Root or CAP_BPF+CAP_SYS_ADMIN)".to_string(),
                );
            }
            return DeploymentMode::Simulation { reasons };
        }

        // 2. หากรองรับ eBPF ตรวจสอบสิทธิ์และคุณลักษณะเสริมของ LSM
        if !caps.has_bpf_lsm_config {
            reasons.push(
                "CONFIG_BPF_LSM is not enabled or not found in kernel boot config".to_string(),
            );
            return DeploymentMode::Degraded { reasons };
        }

        DeploymentMode::Production
    }

    /// ทำการพิมพ์ผลลัพธ์ Diagnostics ลงระบบ Log (info! หรือ warn! ตามความสำเร็จของเงื่อนไข)
    pub fn log_diagnostics(diagnostics: &[CapabilityDiagnostic]) {
        info!("=== การตรวจสอบความเข้ากันได้ของระบบ (System Compatibility Check) ===");
        for diag in diagnostics {
            if diag.passed {
                info!("  [PASS] {}: {}", diag.check, diag.detail);
            } else {
                warn!("  [FAIL] {}: {}", diag.check, diag.detail);
                if let Some(ref rem) = diag.remediation {
                    warn!("         -> คำแนะนำ: {}", rem);
                }
            }
        }
    }

    /// ตรวจหาการตั้งสิทธิ์ (Capabilities) จากไฟล์ระบบ /proc/self/status
    fn detect_effective_capabilities() -> (bool, bool, bool) {
        let mut cap_bpf = false;
        let mut cap_sys_admin = false;
        let mut cap_perfmon = false;

        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("CapEff:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let hex_str = parts[1];
                        if let Ok(val) = u64::from_str_radix(hex_str, 16) {
                            // CAP_SYS_ADMIN = 21
                            cap_sys_admin = (val & (1 << 21)) != 0;
                            // CAP_PERFMON = 38
                            cap_perfmon = (val & (1 << 38)) != 0;
                            // CAP_BPF = 39
                            cap_bpf = (val & (1 << 39)) != 0;
                        }
                    }
                    break;
                }
            }
        }

        (cap_bpf, cap_sys_admin, cap_perfmon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        let v1 = KernelVersion::parse("6.1.0-21-amd64").unwrap();
        assert_eq!(v1.major, 6);
        assert_eq!(v1.minor, 1);
        assert_eq!(v1.patch, 0);

        let v2 = KernelVersion::parse("5.19.17").unwrap();
        assert_eq!(v2.major, 5);
        assert_eq!(v2.minor, 19);
        assert_eq!(v2.patch, 17);

        let v3 = KernelVersion::parse("6.12");
        assert!(v3.is_some());
        let v3 = v3.unwrap();
        assert_eq!(v3.major, 6);
        assert_eq!(v3.minor, 12);
        assert_eq!(v3.patch, 0);

        let invalid = KernelVersion::parse("invalid");
        assert!(invalid.is_none());
    }

    #[test]
    fn test_kernel_meets_minimum() {
        let v = KernelVersion {
            major: 6,
            minor: 1,
            patch: 0,
        };
        assert!(v.meets_minimum(5, 19));
        assert!(v.meets_minimum(6, 0));
        assert!(v.meets_minimum(6, 1));
        assert!(!v.meets_minimum(6, 2));
        assert!(!v.meets_minimum(7, 0));
    }

    #[test]
    fn test_deployment_mode_display() {
        let mode_prod = DeploymentMode::Production;
        assert_eq!(format!("{}", mode_prod), "Production (Full eBPF + LSM)");

        let mode_degraded = DeploymentMode::Degraded {
            reasons: vec!["CONFIG_BPF_LSM not set".to_string()],
        };
        assert!(format!("{}", mode_degraded).contains("CONFIG_BPF_LSM not set"));

        let mode_sim = DeploymentMode::Simulation {
            reasons: vec!["No root".to_string()],
        };
        assert!(format!("{}", mode_sim).contains("No root"));
    }

    #[test]
    fn test_deployment_mode_accessors() {
        let prod = DeploymentMode::Production;
        assert!(prod.is_production());
        assert!(!prod.is_simulation());
        assert!(prod.allows_ebpf_tracer());
        assert!(prod.allows_lsm_hooks());

        let degraded = DeploymentMode::Degraded { reasons: vec![] };
        assert!(!degraded.is_production());
        assert!(!degraded.is_simulation());
        assert!(degraded.allows_ebpf_tracer());
        assert!(!degraded.allows_lsm_hooks());

        let sim = DeploymentMode::Simulation { reasons: vec![] };
        assert!(!sim.is_production());
        assert!(sim.is_simulation());
        assert!(!sim.allows_ebpf_tracer());
        assert!(!sim.allows_lsm_hooks());
    }

    #[test]
    fn test_diagnostics_generation() {
        // Run diagnose on testing machine, should succeed to return diagnostics list.
        let diags = KernelCapabilityDetector::diagnose();
        assert!(!diags.is_empty());
        for d in &diags {
            assert!(!d.check.is_empty());
            assert!(!d.detail.is_empty());
        }
    }

    #[test]
    fn test_recommended_mode() {
        // 1. Production Case
        let caps_prod = KernelCapabilities {
            kernel_version: Some(KernelVersion {
                major: 6,
                minor: 1,
                patch: 0,
            }),
            has_bpf_lsm_config: true,
            has_btf: true,
            is_root: true,
            bpf_fs_mounted: true,
            cap_bpf: true,
            cap_sys_admin: true,
            cap_perfmon: true,
        };
        assert_eq!(
            KernelCapabilityDetector::recommended_mode(&caps_prod),
            DeploymentMode::Production
        );

        // 2. Degraded Case (LSM missing)
        let caps_degraded = KernelCapabilities {
            kernel_version: Some(KernelVersion {
                major: 6,
                minor: 1,
                patch: 0,
            }),
            has_bpf_lsm_config: false,
            has_btf: true,
            is_root: true,
            bpf_fs_mounted: true,
            cap_bpf: true,
            cap_sys_admin: true,
            cap_perfmon: true,
        };
        assert!(matches!(
            KernelCapabilityDetector::recommended_mode(&caps_degraded),
            DeploymentMode::Degraded { .. }
        ));

        // 3. Simulation Case (No BTF)
        let caps_sim_no_btf = KernelCapabilities {
            kernel_version: Some(KernelVersion {
                major: 6,
                minor: 1,
                patch: 0,
            }),
            has_bpf_lsm_config: true,
            has_btf: false,
            is_root: true,
            bpf_fs_mounted: true,
            cap_bpf: true,
            cap_sys_admin: true,
            cap_perfmon: true,
        };
        assert!(matches!(
            KernelCapabilityDetector::recommended_mode(&caps_sim_no_btf),
            DeploymentMode::Simulation { .. }
        ));

        // 4. Simulation Case (No root, no caps)
        let caps_sim_no_priv = KernelCapabilities {
            kernel_version: Some(KernelVersion {
                major: 6,
                minor: 1,
                patch: 0,
            }),
            has_bpf_lsm_config: true,
            has_btf: true,
            is_root: false,
            bpf_fs_mounted: true,
            cap_bpf: false,
            cap_sys_admin: false,
            cap_perfmon: false,
        };
        assert!(matches!(
            KernelCapabilityDetector::recommended_mode(&caps_sim_no_priv),
            DeploymentMode::Simulation { .. }
        ));
    }
}
