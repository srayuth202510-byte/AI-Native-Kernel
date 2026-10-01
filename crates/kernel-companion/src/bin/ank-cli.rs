//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
use anyhow::{Context, Result};
use compute_scheduler::ComputeScheduler;
use compute_scheduler::placement::PlacementPolicy;
use compute_scheduler::placement::WorkloadClass;
use intent_bus::{Intent, IntentPriority, IntentType};
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("AI-Native Kernel CLI (ank-cli)");
        println!("Usage:");
        println!("  ank-cli spawn-agent [payload]    Spawns a new agent");
        println!("  ank-cli status                  Gets system & immune stats");
        println!("  ank-cli list-quarantine         Lists currently quarantined process IDs");
        println!("  ank-cli set-threshold <r> <d> [k] Sets T-Cell rate, deny & kill thresholds");
        println!("  ank-cli set-lsm-profile <name>  Switches active LSM profile");
        println!("  ank-cli verify-audit <log> [--format human|json] [--output <path>]");
        println!("      Verifies the cryptographic hash chain of an audit log");
        return Ok(());
    }

    let cmd = &args[1];
    let payload = if args.len() > 2 { &args[2] } else { "{}" };

    // สร้างโครงสร้าง Intent สำหรับส่งเข้าไปยัง IntentBus
    let mut intent = Intent::new(
        uuid::Uuid::new_v4().to_string(),
        IntentType::Command,
        cmd,
        IntentPriority::High,
        "ank-cli",
    );

    // แมตช์คำสั่งควบคุมต่างๆ เพื่อแพ็คข้อมูลลงใน Intent อย่างเหมาะสม
    match cmd.as_str() {
        "spawn-agent" => {
            if args.len() > 2 {
                intent
                    .metadata
                    .insert("payload".to_string(), payload.to_string());
            }
        }
        "status" | "list-quarantine" => {}
        "set-threshold" => {
            if args.len() < 4 {
                println!(
                    "Usage: ank-cli set-threshold <rate_threshold> <deny_threshold> [kill_threshold]"
                );
                return Ok(());
            }
            // เก็บค่า Threshold ที่จะตั้งค่าส่งต่อไปยัง TCellAgent ผ่าน metadata
            intent
                .metadata
                .insert("rate".to_string(), args[2].to_string());
            intent
                .metadata
                .insert("deny".to_string(), args[3].to_string());
            if args.len() > 4 {
                intent
                    .metadata
                    .insert("kill".to_string(), args[4].to_string());
            }
        }
        "set-lsm-profile" => {
            if args.len() < 3 {
                println!("Usage: ank-cli set-lsm-profile <profile>");
                println!("available: strict|runtime|dev");
                return Ok(());
            }
            intent
                .metadata
                .insert("profile".to_string(), args[2].to_string());
        }
        "place" => {
            // คำสั่งวางงานบนอุปกรณ์ที่เหมาะสมตามสถิติจริง
            if args.len() < 3 {
                println!("Usage: ank-cli place <workload>");
                println!("workload: kernel|small|large|vector");
                return Ok(());
            }
            let wl = match args[2].as_str() {
                "kernel" => WorkloadClass::KernelLogic,
                "small" => WorkloadClass::SmallLlm,
                "large" => WorkloadClass::LargeLlm,
                "vector" => WorkloadClass::VectorIndexing,
                _ => {
                    println!("Unknown workload: {}", args[2]);
                    return Ok(());
                }
            };
            let scheduler = ComputeScheduler::new();
            let policy = PlacementPolicy::new(scheduler.clone());
            let profiles = scheduler.scan_real_hardware().await;
            match policy.place(wl, &profiles) {
                Ok(target) => println!("เลือกอุปกรณ์สำหรับงาน {}: {:?}", args[2], target),
                Err(e) => println!("ไม่สามารถวางงานได้: {:?}", e),
            }
        }
        "verify-audit" => {
            // ank-cli verify-audit <log_file> [--format human|json] [--output <path>]
            let mut log_arg: Option<&str> = None;
            let mut format = "human";
            let mut output: Option<&str> = None;
            let mut rest = args[2..].iter().peekable();
            while let Some(arg) = rest.next() {
                if let Some(value) = arg.strip_prefix("--format=") {
                    format = value;
                } else if arg == "--format" {
                    match rest.next() {
                        Some(value) => format = value,
                        None => {
                            println!("--format requires a value: human or json");
                            return Err(anyhow::anyhow!("--format requires a value"));
                        }
                    }
                } else if let Some(value) = arg.strip_prefix("--output=") {
                    output = Some(value);
                } else if *arg == "--output" {
                    match rest.next() {
                        Some(value) => output = Some(value),
                        None => {
                            println!("--output requires a path");
                            return Err(anyhow::anyhow!("--output requires a path"));
                        }
                    }
                } else if !arg.starts_with('-') {
                    if log_arg.is_none() {
                        log_arg = Some(arg);
                    }
                } else {
                    println!("Unknown flag for verify-audit: {arg}");
                    println!(
                        "Usage: ank-cli verify-audit <log_file> [--format human|json] [--output <path>]"
                    );
                    return Err(anyhow::anyhow!("unknown flag {arg}"));
                }
            }
            let Some(log_file) = log_arg else {
                println!(
                    "Usage: ank-cli verify-audit <log_file> [--format human|json] [--output <path>]"
                );
                return Ok(());
            };
            if format != "human" && format != "json" {
                println!("Unknown --format '{format}': expected human or json");
                return Err(anyhow::anyhow!("unknown --format '{format}'"));
            }
            let log_path = std::path::PathBuf::from(log_file);

            // ตรวจผ่าน ChainedLog::validate เสมอ ไม่เขียนอัลกอริทึมซ้ำตรงนี้ —
            // อัลกอริทึมสองชุดที่ "ควรจะเหมือนกัน" จะค่อย ๆ ต่างกันไปเอง
            let chain = capability_security::verify_report::verify_chain_file::<
                capability_security::audit::AuditEntry,
            >(&log_path, "host-plane")
            .await;
            let mut report = capability_security::verify_report::VerifyReport::new(
                "ank-cli verify-audit",
                &log_path,
            );
            report.push(chain);

            if format == "json" {
                let json = report
                    .to_json()
                    .map_err(|e| anyhow::anyhow!("failed to serialize report: {e}"))?;
                if let Some(out) = output {
                    tokio::fs::write(out, &json)
                        .await
                        .with_context(|| format!("failed to write JSON report to {out}"))?;
                    println!("Wrote JSON report to {out}");
                } else {
                    println!("{json}");
                }
            } else {
                println!("Validating {} audit entries...", report.total_entries);
                if report.total_entries == 0 && report.valid {
                    println!("Success: Audit log is empty.");
                } else if report.valid {
                    println!("SUCCESS: Cryptographic audit log is valid. WORM property intact.");
                }
                if let Some(out) = output {
                    let json = report
                        .to_json()
                        .map_err(|e| anyhow::anyhow!("failed to serialize report: {e}"))?;
                    tokio::fs::write(out, &json)
                        .await
                        .with_context(|| format!("failed to write JSON report to {out}"))?;
                    println!("Wrote JSON report to {out}");
                }
            }

            if report.valid {
                return Ok(());
            }
            for chain in &report.chains {
                if let Some(err) = &chain.error {
                    eprintln!("ERROR: {}: {}", chain.file, err);
                }
            }
            return Err(anyhow::anyhow!("audit chain INVALID: {:?}", log_path));
        }
        _ => {
            // คำสั่งอื่นๆ นอกเหนือจากนี้ ให้ส่งเป็น payload ทั่วไป
            if args.len() > 2 {
                intent
                    .metadata
                    .insert("payload".to_string(), payload.to_string());
            }
        }
    }

    let config = kernel_companion::config::Config::load().unwrap_or_default();
    let socket_path = &config.kernel_companion.uds_socket_path;
    // เชื่อมต่อเข้ากับ Unix Domain Socket Server ของ Kernel Companion
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("Failed to connect to UDS at {}", socket_path))?;

    let mut session_id: Option<u64> = None;

    if let Ok((token_id, secret)) = capability_security::uds_auth::load_token_file() {
        let mut auth_intent = Intent::new(
            uuid::Uuid::new_v4().to_string(),
            IntentType::Command,
            "auth",
            IntentPriority::High,
            "ank-cli",
        );
        auth_intent
            .metadata
            .insert("token_id".to_string(), token_id.to_string());

        let mut secret_hex = String::with_capacity(64);
        for &b in &secret {
            secret_hex.push_str(&format!("{:02x}", b));
        }
        auth_intent
            .metadata
            .insert("secret".to_string(), secret_hex);

        {
            let auth_json = serde_json::to_string(&auth_intent)?;
            stream.write_all(auth_json.as_bytes()).await?;
            stream.write_all(b"\n").await?;
            stream.flush().await?;

            let mut buf_reader = BufReader::new(&mut stream);
            let mut auth_response = String::new();
            if buf_reader.read_line(&mut auth_response).await? > 0 {
                if let Ok(json_resp) = serde_json::from_str::<serde_json::Value>(&auth_response) {
                    if json_resp["success"].as_bool().unwrap_or(false) {
                        session_id = json_resp["session_id"].as_u64();
                    } else {
                        let msg = json_resp["message"].as_str().unwrap_or("Unknown error");
                        eprintln!("ข้อผิดพลาดการยืนยันตัวตน Zero-Trust: {}", msg);
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("ล้มเหลวในการอ่านผลการตรวจสอบสิทธิ์");
                    std::process::exit(1);
                }
            } else {
                eprintln!("ไม่ได้รับการตอบกลับจากเซิร์ฟเวอร์ในขั้นตอนตรวจสอบสิทธิ์");
                std::process::exit(1);
            }
        }
    }

    if let Some(sess_id) = session_id {
        intent
            .metadata
            .insert("session_id".to_string(), sess_id.to_string());
    }

    // แปลง Intent เป็น JSON และส่งไปทางซ็อกเก็ต
    let json = serde_json::to_string(&intent)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // หากเป็นคำสั่งสืบค้นข้อมูลหรือคำสั่งตั้งค่า ให้รอรับผลการตอบกลับจาก Companion
    if cmd == "status"
        || cmd == "list-quarantine"
        || cmd == "set-threshold"
        || cmd == "set-lsm-profile"
    {
        let (reader, _) = stream.split();
        let mut buf_reader = BufReader::new(reader);
        let mut response_line = String::new();

        if buf_reader.read_line(&mut response_line).await? > 0 {
            if let Ok(json_resp) = serde_json::from_str::<serde_json::Value>(&response_line) {
                // พิมพ์ผลลัพธ์ที่ได้จากการตอบกลับของ UDS Server เป็นภาษาไทยและฟอร์แมตสวยงาม
                if cmd == "status" {
                    println!("=========================================");
                    println!("          สถานะระบบ AI-Native Kernel");
                    println!("=========================================");
                    println!(
                        "Companion Daemon : {}",
                        json_resp["status"].as_str().unwrap_or("unknown")
                    );
                    println!("Running Agents   : {}", json_resp["running_agents"]);

                    let pids = json_resp["quarantined_pids"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .map(|v| v.as_u64().unwrap_or(0))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    println!("Quarantined PIDs : {:?}", pids);

                    let blocked = json_resp["blocked_syscalls"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .map(|v| v.as_str().unwrap_or("").to_string())
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    let active_lsm_profile = json_resp["active_lsm_profile"]
                        .as_str()
                        .unwrap_or("unknown");
                    let allowed_syscalls_count =
                        json_resp["allowed_syscalls_count"].as_u64().unwrap_or(0);
                    println!("Blocked Syscalls : {:?}", blocked);
                    println!(
                        "LSM Profile      : {} ({} allowed syscalls)",
                        active_lsm_profile, allowed_syscalls_count
                    );

                    let vram_allocated = json_resp["vram_allocated"].as_u64().unwrap_or(0);
                    let vram_capacity = json_resp["vram_capacity"].as_u64().unwrap_or(0);
                    let p2p_enabled = json_resp["p2p_enabled"].as_bool().unwrap_or(false);
                    let p2p_peers = json_resp["p2p_peers"].as_u64().unwrap_or(0);

                    println!(
                        "VRAM Paging      : {} / {} bytes",
                        vram_allocated, vram_capacity
                    );
                    if p2p_enabled {
                        println!("P2P Context Mesh : Online ({} active peers)", p2p_peers);
                    } else {
                        println!("P2P Context Mesh : Offline");
                    }

                    if let Some(hardware) = json_resp["hardware_targets"].as_array() {
                        println!("-----------------------------------------");
                        println!("          อุปกรณ์ฮาร์ดแวร์จริงที่ตรวจพบ");
                        println!("-----------------------------------------");
                        for hw in hardware {
                            let target = hw["target"].as_str().unwrap_or("Unknown");
                            let latency = hw["latency_ms"].as_f64().unwrap_or(0.0);
                            let power = hw["power_watts"].as_f64().unwrap_or(0.0);
                            let cost = hw["cost_units"].as_f64().unwrap_or(0.0);
                            println!(
                                "  Device: {:<6} | Latency: {:>5.1}ms | Power: {:>5.1}W | Cost: {:>5.1}",
                                target, latency, power, cost
                            );
                        }
                    }
                    println!("=========================================");
                } else if cmd == "list-quarantine" {
                    let pids = json_resp["quarantined_pids"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .map(|v| v.as_u64().unwrap_or(0))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    println!("รายชื่อ PID ที่ถูกกักกัน (Quarantined Process): {:?}", pids);
                } else if cmd == "set-threshold" {
                    let success = json_resp["success"].as_bool().unwrap_or(false);
                    let msg = json_resp["message"].as_str().unwrap_or("");
                    if success {
                        println!("สำเร็จ: {}", msg);
                    } else {
                        println!("เกิดข้อผิดพลาด: {}", msg);
                    }
                } else if cmd == "set-lsm-profile" {
                    let success = json_resp["success"].as_bool().unwrap_or(false);
                    let msg = json_resp["message"].as_str().unwrap_or("");
                    let active = json_resp["active_lsm_profile"]
                        .as_str()
                        .unwrap_or("unknown");
                    let count = json_resp["allowed_syscalls_count"].as_u64().unwrap_or(0);
                    let profiles = json_resp["available_profiles"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .map(|v| v.as_str().unwrap_or("").to_string())
                                .collect::<Vec<String>>()
                        })
                        .unwrap_or_default();
                    if success {
                        println!("สำเร็จ: {}", msg);
                    } else {
                        println!("เกิดข้อผิดพลาด: {}", msg);
                    }
                    println!("LSM Profile      : {} ({} allowed syscalls)", active, count);
                    println!("Available Profiles: {:?}", profiles);
                }
            } else {
                println!("ผลการตอบกลับ: {}", response_line.trim());
            }
        } else {
            println!("ไม่ได้รับการตอบกลับจากระบบ Daemon");
        }
    } else {
        println!("ส่ง Intent สำเร็จ: {}", cmd);
    }

    Ok(())
}
