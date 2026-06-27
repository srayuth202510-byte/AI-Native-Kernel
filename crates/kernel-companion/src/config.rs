use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration for the AI-Native Kernel companion daemon.
/// Loaded from `config/default.toml` and overridable via CLI args / env vars.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub kernel_companion: KernelCompanionConfig,
    #[serde(default)]
    pub agent_scheduler: AgentSchedulerConfig,
    #[serde(default)]
    pub context_memory: ContextMemoryConfig,
    #[serde(default)]
    pub compute_scheduler: ComputeSchedulerConfig,
    #[serde(default)]
    pub capability_security: CapabilitySecurityConfig,
    #[serde(default)]
    pub intent_bus: IntentBusConfig,
    #[serde(default)]
    pub immune_system: ImmuneSystemConfig,
    #[serde(default)]
    pub ebpf: EbpfConfig,
}

impl Config {
    /// Load config from the default path (`config/default.toml`), then
    /// overlay with environment variables (`ANK_*`).
    pub fn load() -> anyhow::Result<Self> {
        let config_path = Self::find_default_path();
        let config: Config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            toml::from_str(&content)?
        } else {
            Config::default()
        };
        Ok(config.apply_env_overrides())
    }

    /// Load config from a specific file path.
    pub fn load_from(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config.apply_env_overrides())
    }

    fn find_default_path() -> PathBuf {
        // Check CARGO_MANIFEST_DIR first (dev), then relative to binary
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            let p = PathBuf::from(manifest)
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("config").join("default.toml"));
            if let Some(p) = p {
                if p.exists() {
                    return p;
                }
            }
        }
        // Check relative to binary
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_default();
        let rel = exe_dir.join("../../../config/default.toml");
        if rel.exists() {
            return rel;
        }
        // Fallback: check ANK_CONFIG_PATH
        if let Ok(path) = std::env::var("ANK_CONFIG_PATH") {
            return PathBuf::from(path);
        }
        PathBuf::from("config/default.toml")
    }

    fn apply_env_overrides(mut self) -> Self {
        if let Ok(v) = std::env::var("ANK_LOG_LEVEL") {
            self.general.log_level = v;
        }
        if let Ok(v) = std::env::var("ANK_UDS_SOCKET_PATH") {
            self.kernel_companion.uds_socket_path = v;
        }
        if let Ok(v) = std::env::var("ANK_INTENT_BUS_CAPACITY") {
            if let Ok(n) = v.parse() {
                self.kernel_companion.intent_bus_capacity = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_MAX_AGENTS") {
            if let Ok(n) = v.parse() {
                self.agent_scheduler.max_agents = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_MAX_RESTART_ATTEMPTS") {
            if let Ok(n) = v.parse() {
                self.agent_scheduler.max_restart_attempts = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_HOT_CAPACITY") {
            if let Ok(n) = v.parse() {
                self.context_memory.hot_capacity = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_WARM_CAPACITY") {
            if let Ok(n) = v.parse() {
                self.context_memory.warm_capacity = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_AUDIT_LOG_PATH") {
            self.capability_security.audit_log_path = v;
        }
        if let Ok(v) = std::env::var("ANK_COMPUTE_MODE") {
            self.compute_scheduler.default_mode = v;
        }
        if let Ok(v) = std::env::var("ANK_EARLY_BPF") {
            if let Ok(b) = v.parse::<bool>() {
                self.ebpf.enable_fallback = b;
            }
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCompanionConfig {
    #[serde(default = "default_uds_socket")]
    pub uds_socket_path: String,
    #[serde(default = "default_intent_bus_cap")]
    pub intent_bus_capacity: usize,
    #[serde(default = "default_monitoring_cap")]
    pub monitoring_channel_capacity: usize,
}

impl Default for KernelCompanionConfig {
    fn default() -> Self {
        Self {
            uds_socket_path: default_uds_socket(),
            intent_bus_capacity: default_intent_bus_cap(),
            monitoring_channel_capacity: default_monitoring_cap(),
        }
    }
}

fn default_uds_socket() -> String {
    "/tmp/ank-companion.sock".to_string()
}
fn default_intent_bus_cap() -> usize {
    1024
}
fn default_monitoring_cap() -> usize {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSchedulerConfig {
    #[serde(default = "default_max_agents")]
    pub max_agents: usize,
    #[serde(default = "default_max_restart")]
    pub max_restart_attempts: u32,
    #[serde(default = "default_supervisor_interval")]
    pub supervisor_interval_ms: u64,
    #[serde(default = "default_next_id")]
    pub next_agent_id_start: u64,
}

impl Default for AgentSchedulerConfig {
    fn default() -> Self {
        Self {
            max_agents: default_max_agents(),
            max_restart_attempts: default_max_restart(),
            supervisor_interval_ms: default_supervisor_interval(),
            next_agent_id_start: default_next_id(),
        }
    }
}

fn default_max_agents() -> usize {
    100
}
fn default_max_restart() -> u32 {
    3
}
fn default_supervisor_interval() -> u64 {
    100
}
fn default_next_id() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextMemoryConfig {
    #[serde(default = "default_hot_cap")]
    pub hot_capacity: usize,
    #[serde(default = "default_warm_cap")]
    pub warm_capacity: usize,
    #[serde(default = "default_rocksdb")]
    pub enable_rocksdb: bool,
}

impl Default for ContextMemoryConfig {
    fn default() -> Self {
        Self {
            hot_capacity: default_hot_cap(),
            warm_capacity: default_warm_cap(),
            enable_rocksdb: default_rocksdb(),
        }
    }
}

fn default_hot_cap() -> usize {
    256
}
fn default_warm_cap() -> usize {
    1024
}
fn default_rocksdb() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeSchedulerConfig {
    #[serde(default = "default_compute_mode")]
    pub default_mode: String,
    #[serde(default = "default_alpha")]
    pub adaptive_alpha: f64,
    #[serde(default = "default_weight_latency")]
    pub weight_latency: f64,
    #[serde(default = "default_weight_power")]
    pub weight_power: f64,
    #[serde(default = "default_weight_cost")]
    pub weight_cost: f64,
}

impl Default for ComputeSchedulerConfig {
    fn default() -> Self {
        Self {
            default_mode: default_compute_mode(),
            adaptive_alpha: default_alpha(),
            weight_latency: default_weight_latency(),
            weight_power: default_weight_power(),
            weight_cost: default_weight_cost(),
        }
    }
}

fn default_compute_mode() -> String {
    "throughput".to_string()
}
fn default_alpha() -> f64 {
    0.1
}
fn default_weight_latency() -> f64 {
    0.8
}
fn default_weight_power() -> f64 {
    0.1
}
fn default_weight_cost() -> f64 {
    0.1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySecurityConfig {
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: String,
}

impl Default for CapabilitySecurityConfig {
    fn default() -> Self {
        Self {
            audit_log_path: default_audit_log_path(),
        }
    }
}

fn default_audit_log_path() -> String {
    "/tmp/ank-audit.log".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentBusConfig {
    #[serde(default = "default_intent_bus_capacity")]
    pub default_capacity: usize,
}

impl Default for IntentBusConfig {
    fn default() -> Self {
        Self {
            default_capacity: default_intent_bus_capacity(),
        }
    }
}

fn default_intent_bus_capacity() -> usize {
    1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmuneSystemConfig {
    #[serde(default = "default_tcell_interval")]
    pub tcell_check_interval_ms: u64,
    #[serde(default = "default_bcell_interval")]
    pub bcell_learning_interval_ms: u64,
    #[serde(default = "default_macrophage_interval")]
    pub macrophage_gc_interval_ms: u64,
    #[serde(default = "default_max_anomaly")]
    pub max_anomaly_score: u32,
    #[serde(default = "default_quarantine")]
    pub quarantine_duration_secs: u64,
}

impl Default for ImmuneSystemConfig {
    fn default() -> Self {
        Self {
            tcell_check_interval_ms: default_tcell_interval(),
            bcell_learning_interval_ms: default_bcell_interval(),
            macrophage_gc_interval_ms: default_macrophage_interval(),
            max_anomaly_score: default_max_anomaly(),
            quarantine_duration_secs: default_quarantine(),
        }
    }
}

fn default_tcell_interval() -> u64 {
    5000
}
fn default_bcell_interval() -> u64 {
    10000
}
fn default_macrophage_interval() -> u64 {
    30000
}
fn default_max_anomaly() -> u32 {
    10
}
fn default_quarantine() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    #[serde(default = "default_ebpf_fallback")]
    pub enable_fallback: bool,
    #[serde(default = "default_tracepoint_program")]
    pub tracepoint_program: String,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enable_fallback: default_ebpf_fallback(),
            tracepoint_program: default_tracepoint_program(),
        }
    }
}

fn default_ebpf_fallback() -> bool {
    true
}
fn default_tracepoint_program() -> String {
    "sys_enter_tp".to_string()
}
