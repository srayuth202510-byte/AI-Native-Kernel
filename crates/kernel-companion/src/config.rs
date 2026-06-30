use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

fn parse_bool_value(value: &str) -> Option<bool> {
    value.parse::<bool>().ok()
}

fn resolve_ebpf_fallback_env(
    enable_fallback: Option<&str>,
    legacy_enable_fallback: Option<&str>,
) -> Option<bool> {
    enable_fallback
        .and_then(parse_bool_value)
        .or_else(|| legacy_enable_fallback.and_then(parse_bool_value))
}

/// Top-level configuration for the AI-Native Kernel companion daemon.
/// Loaded from `config/default.toml` and overridable via CLI args / env vars.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    /// ข้อมูล `general` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub general: GeneralConfig,
    #[serde(default)]
    /// ข้อมูล `kernel_companion` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub kernel_companion: KernelCompanionConfig,
    #[serde(default)]
    /// ข้อมูล `agent_scheduler` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub agent_scheduler: AgentSchedulerConfig,
    #[serde(default)]
    /// ข้อมูล `context_memory` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub context_memory: ContextMemoryConfig,
    #[serde(default)]
    /// ข้อมูล `compute_scheduler` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub compute_scheduler: ComputeSchedulerConfig,
    #[serde(default)]
    /// ข้อมูล `capability_security` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub capability_security: CapabilitySecurityConfig,
    #[serde(default)]
    /// ข้อมูล `intent_bus` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub intent_bus: IntentBusConfig,
    #[serde(default)]
    /// ข้อมูล `immune_system` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub immune_system: ImmuneSystemConfig,
    #[serde(default)]
    /// ข้อมูล `ebpf` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub ebpf: EbpfConfig,
    #[serde(default)]
    /// ข้อมูล `lsm` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub lsm: LsmConfig,
    #[serde(default)]
    /// ข้อมูล `retry_telemetry` สำหรับการกำหนดค่าการทำ retry/backoff และการตรวจตราแบบมีการหมดอายุ (TTL)
    pub retry_telemetry: RetryTelemetryConfig,
    #[serde(default)]
    /// ข้อมูล `observability` สำหรับ tracing/OpenTelemetry
    pub observability: ObservabilityConfig,
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
        if let Ok(v) = std::env::var("ANK_METRICS_ADDR") {
            self.kernel_companion.metrics_server_addr = v;
        }
        if let Ok(v) = std::env::var("ANK_INTENT_BUS_CAPACITY") {
            if let Ok(n) = v.parse() {
                self.kernel_companion.intent_bus_capacity = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_INTENT_BRIDGE_ENABLED") {
            if let Ok(b) = v.parse::<bool>() {
                self.intent_bus.bridge_enabled = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_INTENT_BRIDGE_LISTEN_ADDR") {
            self.intent_bus.bridge_listen_addr = v;
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
        if let Ok(v) = std::env::var("ANK_LOCAL_NODE_ID") {
            self.agent_scheduler.local_node_id = v;
        }
        if let Ok(v) = std::env::var("ANK_REMOTE_ROUTING_ENABLED") {
            if let Ok(b) = v.parse::<bool>() {
                self.agent_scheduler.distributed_enabled = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_REMOTE_OVERLOAD_THRESHOLD") {
            if let Ok(n) = v.parse() {
                self.agent_scheduler.remote_overload_threshold_percent = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_REMOTE_MIN_TRUST") {
            if let Ok(n) = v.parse() {
                self.agent_scheduler.min_remote_trust_score = n;
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
        if let Ok(v) = std::env::var("ANK_WARM_STORE_PATH") {
            self.context_memory.warm_store_path = v;
        }
        if let Ok(v) = std::env::var("ANK_P2P_ENABLED") {
            if let Ok(b) = v.parse::<bool>() {
                self.context_memory.p2p_enabled = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_P2P_LISTEN_ADDR") {
            self.context_memory.p2p_listen_addr = v;
        }
        if let Ok(v) = std::env::var("ANK_AUDIT_LOG_PATH") {
            self.capability_security.audit_log_path = v;
        }
        if let Ok(v) = std::env::var("ANK_MAX_ISSUE_RATE") {
            if let Ok(n) = v.parse() {
                self.capability_security.max_issue_rate = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_COMPUTE_MODE") {
            self.compute_scheduler.default_mode = v;
        }
        let enable_fallback = std::env::var("ANK_EBPF_ENABLE_FALLBACK").ok();
        let legacy_enable_fallback = std::env::var("ANK_EARLY_BPF").ok();
        if let Some(enable_fallback) = resolve_ebpf_fallback_env(
            enable_fallback.as_deref(),
            legacy_enable_fallback.as_deref(),
        ) {
            self.ebpf.enable_fallback = enable_fallback;
        }
        if let Ok(v) = std::env::var("ANK_LSM_PROFILE") {
            self.lsm.active_profile = v;
        }
        if let Ok(v) = std::env::var("ANK_RATE_THRESHOLD") {
            if let Ok(n) = v.parse() {
                self.immune_system.rate_threshold = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_DENY_THRESHOLD") {
            if let Ok(n) = v.parse() {
                self.immune_system.deny_threshold = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_KILL_THRESHOLD") {
            if let Ok(n) = v.parse() {
                self.immune_system.kill_threshold = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_MAX_ATTEMPTS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.retry_max_attempts = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_INITIAL_BACKOFF_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.retry_initial_backoff_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_BACKOFF_MULTIPLIER") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.retry_backoff_multiplier = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_MAX_BACKOFF_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.retry_max_backoff_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_TIMEOUT_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.retry_timeout_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_RETRY_USE_JITTER") {
            if let Ok(b) = v.parse::<bool>() {
                self.retry_telemetry.retry_use_jitter = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_METRIC_CACHE_TTL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.metric_cache_ttl_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_TELEMETRY_SNAPSHOT_TTL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.telemetry_snapshot_ttl_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_AUDIT_LOG_TTL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.audit_log_ttl_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_INTENT_METADATA_TTL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.intent_metadata_ttl_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_CLEANUP_INTERVAL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.cleanup_interval_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_INCLUDE_TIMESTAMPS") {
            if let Ok(b) = v.parse::<bool>() {
                self.retry_telemetry.include_timestamps = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_AUTO_CLEANUP") {
            if let Ok(b) = v.parse::<bool>() {
                self.retry_telemetry.auto_cleanup = b;
            }
        }
        if let Ok(v) = std::env::var("ANK_TELEMETRY_PUBLISH_INTERVAL_MS") {
            if let Ok(n) = v.parse() {
                self.retry_telemetry.telemetry_publish_interval_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ANK_OTEL_ENDPOINT") {
            self.observability.otel_endpoint = v;
        }
        if let Ok(v) = std::env::var("ANK_OTEL_SERVICE_NAME") {
            self.observability.otel_service_name = v;
        }
        if let Ok(v) = std::env::var("ANK_OTEL_EXPORT_TIMEOUT_MS") {
            if let Ok(n) = v.parse() {
                self.observability.otel_export_timeout_ms = n;
            }
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `GeneralConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `GeneralConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    /// ข้อมูล `log_level` สำหรับการกำหนดค่าหรือสถานะภายใน
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
/// โครงสร้างข้อมูล `KernelCompanionConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `KernelCompanionConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct KernelCompanionConfig {
    #[serde(default = "default_uds_socket")]
    /// ข้อมูล `uds_socket_path` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub uds_socket_path: String,
    #[serde(default = "default_intent_bus_cap")]
    /// ข้อมูล `intent_bus_capacity` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub intent_bus_capacity: usize,
    #[serde(default = "default_monitoring_cap")]
    /// ข้อมูล `monitoring_channel_capacity` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub monitoring_channel_capacity: usize,
    #[serde(default = "default_metrics_addr")]
    /// ข้อมูล `metrics_server_addr` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub metrics_server_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `RetryTelemetryConfig` ใช้สำหรับการกำหนดค่าการทำ retry/backoff และการตรวจตราแบบมีการหมดอายุ (TTL)
/// โครงสร้างข้อมูล `RetryTelemetryConfig` ใช้สำหรับการกำหนดค่าการทำ retry/backoff และการตรวจตราแบบมีการหมดอายุ (TTL)
pub struct RetryTelemetryConfig {
    #[serde(default)]
    /// ข้อมูล `retry_max_attempts` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_max_attempts: u32,
    #[serde(default)]
    /// ข้อมูล `retry_initial_backoff_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_initial_backoff_ms: u64,
    #[serde(default)]
    /// ข้อมูล `retry_backoff_multiplier` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_backoff_multiplier: f64,
    #[serde(default)]
    /// ข้อมูล `retry_max_backoff_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_max_backoff_ms: u64,
    #[serde(default)]
    /// ข้อมูล `retry_timeout_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_timeout_ms: u64,
    #[serde(default)]
    /// ข้อมูล `retry_use_jitter` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub retry_use_jitter: bool,
    #[serde(default)]
    /// ข้อมูล `metric_cache_ttl_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub metric_cache_ttl_ms: u64,
    #[serde(default)]
    /// ข้อมูล `telemetry_snapshot_ttl_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub telemetry_snapshot_ttl_ms: u64,
    #[serde(default)]
    /// ข้อมูล `audit_log_ttl_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub audit_log_ttl_ms: u64,
    #[serde(default)]
    /// ข้อมูล `intent_metadata_ttl_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub intent_metadata_ttl_ms: u64,
    #[serde(default)]
    /// ข้อมูล `cleanup_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub cleanup_interval_ms: u64,
    #[serde(default)]
    /// ข้อมูล `include_timestamps` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub include_timestamps: bool,
    #[serde(default)]
    /// ข้อมูล `auto_cleanup` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub auto_cleanup: bool,
    #[serde(default)]
    /// ข้อมูล `telemetry_publish_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub telemetry_publish_interval_ms: u64,
}

impl Default for RetryTelemetryConfig {
    fn default() -> Self {
        Self {
            retry_max_attempts: 3,
            retry_initial_backoff_ms: 100,
            retry_backoff_multiplier: 2.0,
            retry_max_backoff_ms: 10_000,
            retry_timeout_ms: 5_000,
            retry_use_jitter: true,
            metric_cache_ttl_ms: 300_000,
            telemetry_snapshot_ttl_ms: 60_000,
            audit_log_ttl_ms: 86_400_000,
            intent_metadata_ttl_ms: 300_000,
            cleanup_interval_ms: 60_000,
            include_timestamps: true,
            auto_cleanup: true,
            telemetry_publish_interval_ms: 2_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_otel_endpoint")]
    pub otel_endpoint: String,
    #[serde(default = "default_otel_service_name")]
    pub otel_service_name: String,
    #[serde(default = "default_otel_export_timeout_ms")]
    pub otel_export_timeout_ms: u64,
    #[serde(default = "default_json_log_output")]
    pub json_log_output: String,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otel_endpoint: default_otel_endpoint(),
            otel_service_name: default_otel_service_name(),
            otel_export_timeout_ms: default_otel_export_timeout_ms(),
            json_log_output: default_json_log_output(),
        }
    }
}

fn default_otel_endpoint() -> String {
    String::new()
}
fn default_otel_service_name() -> String {
    "ank-kernel-companion".to_string()
}
fn default_otel_export_timeout_ms() -> u64 {
    10_000
}
fn default_json_log_output() -> String {
    "stderr".to_string()
}

impl Default for KernelCompanionConfig {
    fn default() -> Self {
        Self {
            uds_socket_path: default_uds_socket(),
            intent_bus_capacity: default_intent_bus_cap(),
            monitoring_channel_capacity: default_monitoring_cap(),
            metrics_server_addr: default_metrics_addr(),
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
fn default_metrics_addr() -> String {
    "127.0.0.1:9090".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `AgentSchedulerConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `AgentSchedulerConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct AgentSchedulerConfig {
    #[serde(default = "default_max_agents")]
    /// ข้อมูล `max_agents` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub max_agents: usize,
    #[serde(default = "default_max_restart")]
    /// ข้อมูล `max_restart_attempts` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub max_restart_attempts: u32,
    #[serde(default = "default_supervisor_interval")]
    /// ข้อมูล `supervisor_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub supervisor_interval_ms: u64,
    #[serde(default = "default_next_id")]
    /// ข้อมูล `next_agent_id_start` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub next_agent_id_start: u64,
    #[serde(default = "default_distributed_enabled")]
    /// เปิดใช้การกระจาย spawn ไปยัง remote nodes
    pub distributed_enabled: bool,
    #[serde(default = "default_local_node_id")]
    /// logical node id ของ scheduler ปัจจุบัน
    pub local_node_id: String,
    #[serde(default = "default_remote_overload_threshold_percent")]
    /// threshold เป็นเปอร์เซ็นต์ก่อน route งานไปยัง remote node
    pub remote_overload_threshold_percent: u8,
    #[serde(default = "default_min_remote_trust_score")]
    /// trust ขั้นต่ำของ remote node ที่ยอมรับ
    pub min_remote_trust_score: u8,
    #[serde(default = "default_max_remote_candidates")]
    /// จำนวน remote candidates สูงสุดที่ใช้จัดอันดับต่อรอบ
    pub max_remote_candidates: usize,
}

impl Default for AgentSchedulerConfig {
    fn default() -> Self {
        Self {
            max_agents: default_max_agents(),
            max_restart_attempts: default_max_restart(),
            supervisor_interval_ms: default_supervisor_interval(),
            next_agent_id_start: default_next_id(),
            distributed_enabled: default_distributed_enabled(),
            local_node_id: default_local_node_id(),
            remote_overload_threshold_percent: default_remote_overload_threshold_percent(),
            min_remote_trust_score: default_min_remote_trust_score(),
            max_remote_candidates: default_max_remote_candidates(),
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
fn default_distributed_enabled() -> bool {
    false
}
fn default_local_node_id() -> String {
    "node-local".to_string()
}
fn default_remote_overload_threshold_percent() -> u8 {
    80
}
fn default_min_remote_trust_score() -> u8 {
    70
}
fn default_max_remote_candidates() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `ContextMemoryConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `ContextMemoryConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct ContextMemoryConfig {
    #[serde(default = "default_hot_cap")]
    /// ข้อมูล `hot_capacity` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub hot_capacity: usize,
    #[serde(default = "default_warm_cap")]
    /// ข้อมูล `warm_capacity` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub warm_capacity: usize,
    #[serde(default = "default_p2p_enabled")]
    /// ข้อมูล `p2p_enabled` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub p2p_enabled: bool,
    #[serde(default = "default_p2p_listen_addr")]
    /// ข้อมูล `p2p_listen_addr` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub p2p_listen_addr: String,
    #[serde(default = "default_p2p_bootstrap")]
    /// ข้อมูล `p2p_bootstrap_nodes` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub p2p_bootstrap_nodes: Vec<String>,
    #[serde(default = "default_warm_store_path")]
    /// ข้อมูล `warm_store_path` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub warm_store_path: String,
}

impl Default for ContextMemoryConfig {
    fn default() -> Self {
        Self {
            hot_capacity: default_hot_cap(),
            warm_capacity: default_warm_cap(),
            p2p_enabled: default_p2p_enabled(),
            p2p_listen_addr: default_p2p_listen_addr(),
            p2p_bootstrap_nodes: default_p2p_bootstrap(),
            warm_store_path: default_warm_store_path(),
        }
    }
}

fn default_hot_cap() -> usize {
    256
}
fn default_warm_cap() -> usize {
    1024
}
fn default_p2p_enabled() -> bool {
    false
}
fn default_p2p_listen_addr() -> String {
    "127.0.0.1:9091".to_string()
}
fn default_p2p_bootstrap() -> Vec<String> {
    Vec::new()
}
fn default_warm_store_path() -> String {
    if std::env::var("CARGO_MANIFEST_DIR").is_ok() {
        format!(
            "{}/ank-warm-store-{}",
            std::env::temp_dir().to_string_lossy(),
            uuid::Uuid::new_v4()
        )
    } else {
        "/tmp/ank-warm-store".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `ComputeSchedulerConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `ComputeSchedulerConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct ComputeSchedulerConfig {
    #[serde(default = "default_compute_mode")]
    /// ข้อมูล `default_mode` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub default_mode: String,
    #[serde(default = "default_alpha")]
    /// ข้อมูล `adaptive_alpha` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub adaptive_alpha: f64,
    #[serde(default = "default_weight_latency")]
    /// ข้อมูล `weight_latency` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub weight_latency: f64,
    #[serde(default = "default_weight_power")]
    /// ข้อมูล `weight_power` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub weight_power: f64,
    #[serde(default = "default_weight_cost")]
    /// ข้อมูล `weight_cost` สำหรับการกำหนดค่าหรือสถานะภายใน
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
/// โครงสร้างข้อมูล `CapabilitySecurityConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `CapabilitySecurityConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct CapabilitySecurityConfig {
    #[serde(default = "default_audit_log_path")]
    /// ข้อมูล `audit_log_path` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub audit_log_path: String,
    #[serde(default = "default_max_issue_rate")]
    /// ข้อมูล `max_issue_rate` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub max_issue_rate: usize,
}

impl Default for CapabilitySecurityConfig {
    fn default() -> Self {
        Self {
            audit_log_path: default_audit_log_path(),
            max_issue_rate: default_max_issue_rate(),
        }
    }
}

fn default_audit_log_path() -> String {
    "/tmp/ank-audit.log".to_string()
}
fn default_max_issue_rate() -> usize {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `IntentBusConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `IntentBusConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct IntentBusConfig {
    #[serde(default = "default_intent_bus_capacity")]
    /// ข้อมูล `default_capacity` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub default_capacity: usize,
    #[serde(default = "default_bridge_enabled")]
    /// เปิด listener/forwarder สำหรับ delegated intents ข้ามโหนด
    pub bridge_enabled: bool,
    #[serde(default = "default_bridge_listen_addr")]
    /// TCP listen addr สำหรับ network intent bridge
    pub bridge_listen_addr: String,
    #[serde(default = "default_bridge_connect_timeout_ms")]
    /// timeout สำหรับ outbound TCP connect
    pub bridge_connect_timeout_ms: u64,
    #[serde(default = "default_bridge_request_timeout_ms")]
    /// timeout สำหรับ read/write/ack ของ bridge
    pub bridge_request_timeout_ms: u64,
    #[serde(default)]
    /// รายชื่อ peer nodes ที่ bridge สามารถส่ง delegated intent ไปหาได้
    pub bridge_peers: Vec<IntentBridgePeerConfig>,
}

impl Default for IntentBusConfig {
    fn default() -> Self {
        Self {
            default_capacity: default_intent_bus_capacity(),
            bridge_enabled: default_bridge_enabled(),
            bridge_listen_addr: default_bridge_listen_addr(),
            bridge_connect_timeout_ms: default_bridge_connect_timeout_ms(),
            bridge_request_timeout_ms: default_bridge_request_timeout_ms(),
            bridge_peers: Vec::new(),
        }
    }
}

fn default_intent_bus_capacity() -> usize {
    1024
}
fn default_bridge_enabled() -> bool {
    false
}
fn default_bridge_listen_addr() -> String {
    "127.0.0.1:9191".to_string()
}
fn default_bridge_connect_timeout_ms() -> u64 {
    1_000
}
fn default_bridge_request_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentBridgePeerConfig {
    pub node_id: String,
    pub addr: String,
    #[serde(default)]
    pub available_agent_slots: usize,
    #[serde(default = "default_peer_trust_score")]
    pub trust_score: u8,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_peer_trust_score() -> u8 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `ImmuneSystemConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `ImmuneSystemConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct ImmuneSystemConfig {
    #[serde(default = "default_tcell_interval")]
    /// ข้อมูล `tcell_check_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub tcell_check_interval_ms: u64,
    #[serde(default = "default_bcell_interval")]
    /// ข้อมูล `bcell_learning_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub bcell_learning_interval_ms: u64,
    #[serde(default = "default_macrophage_interval")]
    /// ข้อมูล `macrophage_gc_interval_ms` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub macrophage_gc_interval_ms: u64,
    #[serde(default = "default_max_anomaly")]
    /// ข้อมูล `max_anomaly_score` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub max_anomaly_score: u32,
    #[serde(default = "default_quarantine")]
    /// ข้อมูล `quarantine_duration_secs` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub quarantine_duration_secs: u64,
    #[serde(default = "default_rate_threshold")]
    /// ข้อมูล `rate_threshold` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub rate_threshold: u32,
    #[serde(default = "default_deny_threshold")]
    /// ข้อมูล `deny_threshold` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub deny_threshold: u32,
    #[serde(default = "default_kill_threshold")]
    /// ข้อมูล `kill_threshold` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub kill_threshold: u32,
}

impl Default for ImmuneSystemConfig {
    fn default() -> Self {
        Self {
            tcell_check_interval_ms: default_tcell_interval(),
            bcell_learning_interval_ms: default_bcell_interval(),
            macrophage_gc_interval_ms: default_macrophage_interval(),
            max_anomaly_score: default_max_anomaly(),
            quarantine_duration_secs: default_quarantine(),
            rate_threshold: default_rate_threshold(),
            deny_threshold: default_deny_threshold(),
            kill_threshold: default_kill_threshold(),
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
fn default_rate_threshold() -> u32 {
    100
}
fn default_deny_threshold() -> u32 {
    5
}
fn default_kill_threshold() -> u32 {
    15
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `EbpfConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `EbpfConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct EbpfConfig {
    #[serde(default = "default_ebpf_fallback")]
    /// ข้อมูล `enable_fallback` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub enable_fallback: bool,
    #[serde(default = "default_tracepoint_program")]
    /// ข้อมูล `tracepoint_program` สำหรับการกำหนดค่าหรือสถานะภายใน
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
    false
}
fn default_tracepoint_program() -> String {
    "sys_enter_tp".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `LsmProfileConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `LsmProfileConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct LsmProfileConfig {
    #[serde(default)]
    /// ข้อมูล `allowed_syscalls` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub allowed_syscalls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// โครงสร้างข้อมูล `LsmConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `LsmConfig` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct LsmConfig {
    #[serde(default = "default_lsm_profile")]
    /// ข้อมูล `active_profile` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub active_profile: String,
    #[serde(default = "default_lsm_profiles")]
    /// ข้อมูล `profiles` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub profiles: BTreeMap<String, LsmProfileConfig>,
}

impl Default for LsmConfig {
    fn default() -> Self {
        Self {
            active_profile: default_lsm_profile(),
            profiles: default_lsm_profiles(),
        }
    }
}

impl LsmConfig {
    /// รายชื่อ syscall ที่อนุญาตตาม profile ที่ active อยู่
    #[must_use]
    pub fn allowed_syscalls(&self) -> HashSet<String> {
        self.profiles
            .get(&self.active_profile)
            .map(|profile| profile.allowed_syscalls.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// คืนชื่อ profile ที่ใช้งานอยู่
    #[must_use]
    pub fn active_profile_name(&self) -> &str {
        &self.active_profile
    }
}

fn default_lsm_profile() -> String {
    "runtime".to_string()
}

fn default_lsm_profiles() -> BTreeMap<String, LsmProfileConfig> {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "strict".to_string(),
        LsmProfileConfig {
            allowed_syscalls: strict_allowlist().iter().map(|s| s.to_string()).collect(),
        },
    );
    profiles.insert(
        "runtime".to_string(),
        LsmProfileConfig {
            allowed_syscalls: runtime_allowlist().iter().map(|s| s.to_string()).collect(),
        },
    );
    profiles.insert(
        "dev".to_string(),
        LsmProfileConfig {
            allowed_syscalls: dev_allowlist().iter().map(|s| s.to_string()).collect(),
        },
    );
    profiles
}

fn strict_allowlist() -> &'static [&'static str] {
    &["read", "write", "recvmsg", "close"]
}

fn runtime_allowlist() -> &'static [&'static str] {
    &[
        "read",
        "write",
        "recvmsg",
        "close",
        "poll",
        "mprotect",
        "clone",
        "clone3",
        "futex",
        "rt_sigaction",
        "rt_sigprocmask",
        "sigaltstack",
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "sched_yield",
        "getpid",
        "gettid",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "brk",
        "mmap",
        "munmap",
        "madvise",
        "fstat",
        "newfstatat",
        "statx",
        "lseek",
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "openat",
        "openat2",
        "readlinkat",
        "fchmod",
        "fchown",
        "fchdir",
        "getrandom",
        "prlimit64",
        "sendmsg",
        "recvfrom",
        "sendto",
        "pipe2",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "eventfd2",
        "ioctl",
        "fcntl",
        "socket",
        "connect",
        "accept",
        "accept4",
        "bind",
        "listen",
        "shutdown",
        "getsockname",
        "getpeername",
        "setsockopt",
        "getsockopt",
    ]
}

fn dev_allowlist() -> &'static [&'static str] {
    &[
        "read",
        "write",
        "recvmsg",
        "close",
        "poll",
        "mprotect",
        "clone",
        "clone3",
        "futex",
        "rt_sigaction",
        "rt_sigprocmask",
        "sigaltstack",
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "sched_yield",
        "getpid",
        "gettid",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "brk",
        "mmap",
        "munmap",
        "madvise",
        "fstat",
        "newfstatat",
        "statx",
        "lseek",
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "openat",
        "openat2",
        "readlinkat",
        "fchmod",
        "fchown",
        "fchdir",
        "getrandom",
        "prlimit64",
        "sendmsg",
        "recvfrom",
        "sendto",
        "socket",
        "connect",
        "accept",
        "accept4",
        "pipe2",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "eventfd2",
        "ioctl",
        "fcntl",
        "fsync",
        "fdatasync",
        "ftruncate",
        "chmod",
        "chown",
        "rename",
        "mkdir",
        "rmdir",
        "unlink",
        "symlink",
        "link",
        "fallocate",
        "copy_file_range",
        "memfd_create",
        "statx",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lsm_profile_is_runtime() {
        let config = LsmConfig::default();
        assert_eq!(config.active_profile_name(), "runtime");
        assert!(config.profiles.contains_key("strict"));
        assert!(config.profiles.contains_key("runtime"));
        assert!(config.profiles.contains_key("dev"));
    }

    #[test]
    fn runtime_profile_contains_common_runtime_syscalls() {
        let config = LsmConfig::default();
        let allowed = config.allowed_syscalls();
        assert!(allowed.contains("openat"));
        assert!(allowed.contains("poll"));
        assert!(allowed.contains("futex"));
        assert!(
            allowed.contains("socket"),
            "socket should be in runtime profile for network-aware agents"
        );
    }

    #[test]
    fn strict_profile_is_small_and_explicit() {
        let config = LsmConfig::default();
        let strict = &config.profiles["strict"].allowed_syscalls;
        assert_eq!(strict, &vec!["read", "write", "recvmsg", "close"]);
    }

    #[test]
    fn new_fallback_env_var_takes_precedence() {
        let resolved = resolve_ebpf_fallback_env(Some("false"), Some("true"));
        assert_eq!(resolved, Some(false));
    }

    #[test]
    fn legacy_fallback_env_var_is_still_supported() {
        let resolved = resolve_ebpf_fallback_env(None, Some("true"));
        assert_eq!(resolved, Some(true));
    }

    #[test]
    fn invalid_new_fallback_env_var_falls_back_to_legacy() {
        let resolved = resolve_ebpf_fallback_env(Some("not-a-bool"), Some("true"));
        assert_eq!(resolved, Some(true));
    }
}
