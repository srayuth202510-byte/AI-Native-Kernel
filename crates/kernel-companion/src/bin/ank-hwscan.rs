//! ank-hwscan — สแกน compute hardware ของเครื่องแล้วออกรายงาน (standalone)
//!
//! ไม่ต้องบูต daemon — รันบนเครื่องใหม่เพื่อดูว่ามี CPU/GPU/NPU/iGPU อะไรบ้าง
//! พิมพ์สรุปอ่านง่ายทาง stderr และ **JSON report ทาง stdout** เพื่อให้ Claude
//! Code อ่านต่อ (path A) หรือ connector ส่งให้ Claude API (path B) ได้
//!
//!   ank-hwscan            # สรุป + JSON
//!   ank-hwscan > hw.json  # เก็บเฉพาะ JSON (สรุปยังออก stderr)

use compute_scheduler::{ComputeScheduler, ComputeTarget};

/// อ่าน kernel release จาก /proc (ว่างถ้าอ่านไม่ได้)
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// total RAM (MB) จาก /proc/meminfo field MemTotal (0 ถ้าอ่านไม่ได้)
fn total_ram_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                let rest = l.strip_prefix("MemTotal:")?;
                rest.split_whitespace().next()?.parse::<u64>().ok()
            })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// รายชื่อ node ใน directory ที่ขึ้นต้นด้วย prefix (เช่น renderD*, accel*)
fn dev_nodes(dir: &str, prefix: &str) -> Vec<String> {
    let mut nodes: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .collect();
    nodes.sort();
    nodes
}

#[tokio::main]
async fn main() {
    let scheduler = ComputeScheduler::new();
    let targets = scheduler.scan_real_hardware().await;

    let kernel = kernel_release();
    let cpu_cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(0);
    let ram_mb = total_ram_mb();
    // /dev/dri/renderD* = iGPU/GPU render node; /dev/accel* = NPU (Intel/Qualcomm)
    let render_nodes = dev_nodes("/dev/dri", "renderD");
    let accel_nodes = dev_nodes("/dev/accel", "accel");
    let has_nvidia = std::path::Path::new("/dev/nvidia0").exists();

    // ── human summary → stderr ──
    eprintln!("── ank-hwscan ──");
    eprintln!("kernel      : {kernel}");
    eprintln!("cpu cores   : {cpu_cores}");
    eprintln!("total RAM   : {ram_mb} MB");
    eprintln!(
        "GPU render  : {}",
        if render_nodes.is_empty() {
            "(none — no /dev/dri render node)".to_string()
        } else {
            format!("{render_nodes:?} (iGPU/GPU present — Vulkan/OpenCL candidate)")
        }
    );
    eprintln!(
        "NPU accel   : {}",
        if accel_nodes.is_empty() {
            "(none)".to_string()
        } else {
            format!("{accel_nodes:?}")
        }
    );
    eprintln!("NVIDIA      : {}", if has_nvidia { "yes" } else { "no" });
    eprintln!("compute targets discovered by prober:");
    for (target, profile) in &targets {
        eprintln!(
            "  - {:<6} latency={:.1}ms power={:.1}W cost={:.1}",
            format!("{target:?}"),
            profile.latency_ms,
            profile.power_watts,
            profile.cost_units
        );
    }
    eprintln!("────────────────");

    // ── machine-readable report → stdout ──
    let targets_json: Vec<serde_json::Value> = targets
        .iter()
        .map(|(target, p)| {
            serde_json::json!({
                "target": format!("{target:?}"),
                "latency_ms": p.latency_ms,
                "power_watts": p.power_watts,
                "cost_units": p.cost_units,
            })
        })
        .collect();
    let report = serde_json::json!({
        "kernel": kernel,
        "cpu_cores": cpu_cores,
        "total_ram_mb": ram_mb,
        "dri_render_nodes": render_nodes,
        "accel_nodes": accel_nodes,
        "has_nvidia": has_nvidia,
        "has_gpu_target": targets.iter().any(|(t, _)| *t == ComputeTarget::Gpu),
        "has_npu_target": targets.iter().any(|(t, _)| *t == ComputeTarget::Npu),
        "compute_targets": targets_json,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
}
