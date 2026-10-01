use ai_gateway::{
    AppState, GatewayConfig, GatewayCore, build_router, entry::ApiAuditEntry, policy::PolicyFile,
    proxy::Upstream,
};
use capability_security::verify_report::{VerifyReport, verify_chain_file};
use clap::{Parser, Subcommand};
use semantic_guard::{DetectionMode, GuardConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Default, Clone, Parser)]
struct Args {
    /// Address to listen on
    #[arg(long, env = "ANK_GATEWAY_LISTEN")]
    listen: Option<String>,

    /// Upstream model server URL
    #[arg(long, env = "ANK_GATEWAY_UPSTREAM")]
    upstream: Option<String>,

    /// Audit log directory
    #[arg(long, env = "ANK_GATEWAY_AUDIT_DIR")]
    audit_dir: Option<PathBuf>,

    /// Tenant policy file
    #[arg(long, env = "ANK_GATEWAY_POLICY_FILE")]
    policy_file: Option<PathBuf>,

    /// Enable semantic guard
    #[arg(
        long, env = "ANK_GATEWAY_GUARD",
        num_args = 0..=1, default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    guard_enabled: Option<bool>,

    /// Enable extraction detector
    #[arg(
        long, env = "ANK_GATEWAY_EXTRACTION",
        num_args = 0..=1, default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    extraction_enabled: Option<bool>,

    /// Log level
    #[arg(long, env = "ANK_LOG")]
    log_level: Option<String>,
}

/// AI Infrastructure Security Gateway
#[derive(Debug, Parser)]
#[command(name = "ai-gateway", version, about = "AI infrastructure security gateway — OpenAI-compatible enforcement proxy", long_about = None)]
struct Cli {
    #[command(flatten)]
    args: Args,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run reverse proxy
    Serve {
        #[command(flatten)]
        args: Args,
    },
    /// Verify hash chains in audit directory
    VerifyAudit {
        /// Directory to verify (default: audit_dir from config)
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Output format: human (default) or json (SIEM)
        #[arg(long, default_value = "human")]
        format: String,

        /// Write the JSON report to this file as well
        #[arg(long)]
        output: Option<PathBuf>,

        #[command(flatten)]
        args: Args,
    },
}

/// Merge outer and inner args, inner takes precedence
fn merge_args(outer: &Args, inner: &Args) -> Args {
    Args {
        listen: inner.listen.clone().or_else(|| outer.listen.clone()),
        upstream: inner.upstream.clone().or_else(|| outer.upstream.clone()),
        audit_dir: inner.audit_dir.clone().or_else(|| outer.audit_dir.clone()),
        policy_file: inner
            .policy_file
            .clone()
            .or_else(|| outer.policy_file.clone()),
        guard_enabled: inner.guard_enabled.or(outer.guard_enabled),
        extraction_enabled: inner.extraction_enabled.or(outer.extraction_enabled),
        log_level: inner.log_level.clone().or_else(|| outer.log_level.clone()),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let (args, verify) = match &cli.command {
        Some(Command::Serve { args }) => (merge_args(&cli.args, args), None),
        Some(Command::VerifyAudit {
            dir,
            format,
            output,
            args,
        }) => (
            merge_args(&cli.args, args),
            Some((dir.clone(), format.clone(), output.clone())),
        ),
        None => (cli.args.clone(), None),
    };

    let log_level = args.log_level.clone().unwrap_or_else(|| "info".to_string());
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .try_init();

    let config = match build_config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Invalid config: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match verify {
        Some((Some(dir), format, output)) => verify_audit(dir, &format, output.as_ref()).await,
        _ => serve(config).await,
    }
}

fn build_config(args: &Args) -> Result<GatewayConfig, String> {
    let defaults = GatewayConfig::default();
    let config = GatewayConfig {
        listen_addr: args.listen.clone().unwrap_or(defaults.listen_addr),
        upstream_url: args.upstream.clone().unwrap_or(defaults.upstream_url),
        audit_dir: args.audit_dir.clone().unwrap_or(defaults.audit_dir),
        policy_file: args.policy_file.clone().unwrap_or(defaults.policy_file),
        guard_enabled: args.guard_enabled.unwrap_or(true),
        extraction_enabled: args.extraction_enabled.unwrap_or(true),
        ..defaults
    };
    config.validate().map_err(|e| e.to_string())?;
    Ok(config)
}

async fn load_policy(path: &PathBuf) -> Result<ai_gateway::DataPlanePolicy, String> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(path = %path.display(), "policy file not found — denying all");
            return Ok(ai_gateway::DataPlanePolicy::deny_all());
        }
        Err(e) => return Err(format!("read policy file {}: {e}", path.display())),
    };

    let file: PolicyFile = serde_json::from_str(&text)
        .map_err(|e| format!("parse policy file {}: {e}", path.display()))?;
    let (policy, warnings) = file.into_policy();
    for w in &warnings {
        tracing::warn!(warning = %w, "policy file warning");
    }
    Ok(policy)
}

async fn serve(config: GatewayConfig) -> std::process::ExitCode {
    let policy = match load_policy(&config.policy_file).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Load policy failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let guard_cfg = GuardConfig {
        detection_mode: DetectionMode::PiiAndSignatures,
        ..GuardConfig::default()
    };
    let extraction_cfg = ai_gateway::ExtractionConfig::default();

    let guard = if config.guard_enabled {
        match semantic_guard::Guard::with_config(guard_cfg.clone()) {
            Ok(g) => Some(Arc::new(g)),
            Err(e) => {
                eprintln!("Create semantic guard failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let core = match GatewayCore::new(
        config.clone(),
        policy,
        config.guard_enabled.then_some(guard_cfg),
        config.extraction_enabled.then_some(extraction_cfg),
    )
    .await
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Initialize gateway core failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let upstream = match Upstream::new(
        &config.upstream_url,
        config.upstream_timeout,
        config.max_inspect_prefix_bytes,
    ) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Create upstream client failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let addr: SocketAddr = match config.listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid listen address {}: {e}", config.listen_addr);
            return std::process::ExitCode::FAILURE;
        }
    };

    let router = build_router(
        AppState {
            core,
            upstream: upstream.clone(),
            guard,
        },
        config.max_body_bytes,
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Bind {} failed: {e}", addr);
            return std::process::ExitCode::FAILURE;
        }
    };

    tracing::info!(
        listen = %addr,
        upstream = %config.upstream_url,
        audit_dir = %config.audit_dir.display(),
        guard_enabled = config.guard_enabled,
        extraction_enabled = config.extraction_enabled,
        "gateway ready"
    );

    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("Server error: {e}");
        return std::process::ExitCode::FAILURE;
    }

    tracing::info!("gateway stopped");
    std::process::ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM handler install failed");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}

async fn verify_audit(
    dir: PathBuf,
    format: &str,
    output: Option<&PathBuf>,
) -> std::process::ExitCode {
    if format != "human" && format != "json" {
        eprintln!("Unknown --format '{format}': expected human or json");
        return std::process::ExitCode::FAILURE;
    }

    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Audit directory not found: {}", dir.display());
            return std::process::ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("Read audit directory {}: {e}", dir.display());
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut files = Vec::new();
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "jsonl") {
                    files.push(path);
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("Read dir entries: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    if files.is_empty() {
        eprintln!("No audit files (*.jsonl) found in {}", dir.display());
        return std::process::ExitCode::FAILURE;
    }

    // ตรวจทุก shard ผ่าน ChainedLog::validate แล้วรวมเป็นรายงานเดียว —
    // schema เดียวกับ `ank-cli verify-audit` เพื่อให้ SIEM ใช้ parser เดียว
    files.sort();
    let mut report = VerifyReport::new("ai-gateway verify-audit", &dir);
    for file in &files {
        let chain_id = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        report.push(verify_chain_file::<ApiAuditEntry>(file, &chain_id).await);
    }

    if format == "json" {
        if let Some(out) = output {
            if !write_report_file(&report, out).await {
                return std::process::ExitCode::FAILURE;
            }
        } else {
            match report.to_json() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("Serialize report: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
    } else {
        for chain in &report.chains {
            if chain.valid {
                println!("OK      {} ({} entries)", chain.file, chain.entries);
            } else if let Some(err) = &chain.error {
                eprintln!("ERROR   {}: {}", chain.file, err);
            } else {
                eprintln!("INVALID {}", chain.file);
            }
        }
        if let Some(out) = output {
            if !write_report_file(&report, out).await {
                return std::process::ExitCode::FAILURE;
            }
        }
        if report.valid {
            println!("\nAll {} chains valid", report.chains.len());
        } else {
            eprintln!("\nAt least one chain is invalid");
        }
    }

    if report.valid {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

/// เขียนรายงาน JSON ลงไฟล์ — คืน `false` เมื่อ serialize หรือเขียนไม่สำเร็จ
async fn write_report_file(report: &VerifyReport, out: &PathBuf) -> bool {
    let json = match report.to_json() {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Serialize report: {e}");
            return false;
        }
    };
    match tokio::fs::write(out, &json).await {
        Ok(()) => {
            println!("Wrote JSON report to {}", out.display());
            true
        }
        Err(e) => {
            eprintln!("Write {}: {e}", out.display());
            false
        }
    }
}
