use anyhow::{Context, Result};
use intent_bus::{Intent, IntentPriority, IntentType};
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    // หากไม่มีการระบุอาร์กิวเมนต์ที่จำเป็น ให้พิมพ์คำแนะนำการใช้งาน CLI
    if args.len() < 2 {
        println!("AI-Native Kernel CLI (ank-cli)");
        println!("Usage:");
        println!("  ank-cli spawn-agent [payload]    Spawns a new agent");
        println!("  ank-cli status                  Gets system & immune stats");
        println!("  ank-cli list-quarantine         Lists currently quarantined process IDs");
        println!("  ank-cli set-threshold <r> <d>   Sets T-Cell rate & deny thresholds");
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
                println!("Usage: ank-cli set-threshold <rate_threshold> <deny_threshold>");
                return Ok(());
            }
            // เก็บค่า Threshold ที่จะตั้งค่าส่งต่อไปยัง TCellAgent ผ่าน metadata
            intent
                .metadata
                .insert("rate".to_string(), args[2].to_string());
            intent
                .metadata
                .insert("deny".to_string(), args[3].to_string());
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

    let socket_path = "/tmp/ank-companion.sock";
    // เชื่อมต่อเข้ากับ Unix Domain Socket Server ของ Kernel Companion
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("Failed to connect to UDS at {}", socket_path))?;

    // แปลง Intent เป็น JSON และส่งไปทางซ็อกเก็ต
    let json = serde_json::to_string(&intent)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // หากเป็นคำสั่งสืบค้นข้อมูลหรือคำสั่งตั้งค่า ให้รอรับผลการตอบกลับจาก Companion
    if cmd == "status" || cmd == "list-quarantine" || cmd == "set-threshold" {
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
                    println!("Blocked Syscalls : {:?}", blocked);
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
