use clap::Parser;
use kernel_companion::KernelCompanion;
use kernel_companion::config::Config;
use kernel_companion::observability::init_tracing;
use std::path::PathBuf;

/// AI-Native Kernel Companion Daemon
///
/// Hybrid-Companion daemon that sits alongside the Linux kernel to provide
/// eBPF-based syscall tracing, LSM policy enforcement, AI Agent lifecycle
/// management, and intent-driven compute scheduling.
#[derive(Parser, Debug)]
#[command(name = "ank-companion", version, about)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short = 'c', long = "config", env = "ANK_CONFIG_PATH")]
    config: Option<PathBuf>,

    /// Unix Domain Socket path for external intent injection
    #[arg(short = 's', long = "uds-socket", env = "ANK_UDS_SOCKET_PATH")]
    uds_socket: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(
        short = 'l',
        long = "log-level",
        env = "ANK_LOG_LEVEL",
        default_value = "info"
    )]
    log_level: String,

    /// Intent bus channel capacity
    #[arg(long = "intent-bus-cap", env = "ANK_INTENT_BUS_CAPACITY")]
    intent_bus_capacity: Option<usize>,

    /// Maximum number of concurrent agents
    #[arg(long = "max-agents", env = "ANK_MAX_AGENTS")]
    max_agents: Option<usize>,

    /// Hot store capacity (context memory pages)
    #[arg(long = "hot-capacity", env = "ANK_HOT_CAPACITY")]
    hot_capacity: Option<usize>,

    /// Warm store capacity (context memory pages)
    #[arg(long = "warm-capacity", env = "ANK_WARM_CAPACITY")]
    warm_capacity: Option<usize>,

    /// Audit log file path
    #[arg(long = "audit-log", env = "ANK_AUDIT_LOG_PATH")]
    audit_log_path: Option<String>,

    /// Metrics server bind address
    #[arg(long = "metrics-addr", env = "ANK_METRICS_ADDR")]
    metrics_addr: Option<String>,

    /// Active LSM allowlist profile (strict, runtime, dev)
    #[arg(long = "lsm-profile", env = "ANK_LSM_PROFILE")]
    lsm_profile: Option<String>,

    /// Disable eBPF fallback simulation
    #[arg(long = "no-bpf-fallback")]
    no_bpf_fallback: bool,
}

/// Entry point for the AI-Native Kernel Companion Daemon.
/// Runs on the Tokio async runtime and orchestrates all subsystems.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config from file (or defaults), then overlay CLI + env
    let mut config = if let Some(ref cfg_path) = cli.config {
        Config::load_from(cfg_path)?
    } else {
        Config::load()?
    };

    // CLI overrides
    if let Some(socket) = cli.uds_socket {
        config.kernel_companion.uds_socket_path = socket;
    }
    config.general.log_level = cli.log_level;
    if let Some(cap) = cli.intent_bus_capacity {
        config.kernel_companion.intent_bus_capacity = cap;
    }
    if let Some(max) = cli.max_agents {
        config.agent_scheduler.max_agents = max;
    }
    if let Some(hot) = cli.hot_capacity {
        config.context_memory.hot_capacity = hot;
    }
    if let Some(warm) = cli.warm_capacity {
        config.context_memory.warm_capacity = warm;
    }
    if let Some(log) = cli.audit_log_path {
        config.capability_security.audit_log_path = log;
    }
    if let Some(metrics_addr) = cli.metrics_addr {
        config.kernel_companion.metrics_server_addr = metrics_addr;
    }
    if let Some(profile) = cli.lsm_profile {
        config.lsm.active_profile = profile;
    }
    if cli.no_bpf_fallback {
        config.ebpf.enable_fallback = false;
    }

    let _ = init_tracing(&config.general.log_level);

    println!(
        "AI-Native Kernel Companion Daemon starting... (log: {})",
        config.general.log_level
    );

    let companion = KernelCompanion::with_config(&config);
    companion.run().await
}
