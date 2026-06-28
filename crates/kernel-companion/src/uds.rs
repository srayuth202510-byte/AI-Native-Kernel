use crate::lsm::LsmPolicyEngine;
use crate::tokio_util_cancel::CancellationToken;
use agent_scheduler::AgentScheduler;
use anyhow::Result;
use compute_scheduler::ComputeScheduler;
use immune_system::TCellAgent;
use intent_bus::{Intent, IntentBus, IntentType};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task;
use tracing::{debug, error, info};

/// เริ่มต้น Unix Domain Socket Server สำหรับรับ Intent จากภายนอก
/// และรองรับการตอบกลับข้อมูลสืบค้นหรือคำสั่งควบคุมความปลอดภัยของ CLI แบบสองทาง (Bidirectional)
pub async fn start_uds_server(
    intent_bus: Arc<IntentBus>,
    tcell: Option<Arc<TCellAgent>>,
    lsm: Option<Arc<LsmPolicyEngine>>,
    agent_scheduler: Option<Arc<AgentScheduler>>,
    compute_scheduler: Option<Arc<ComputeScheduler>>,
    socket_path: &str,
    cancel: CancellationToken,
) -> Result<()> {
    // ลบไฟล์ซ็อกเก็ตเก่าถ้ามี
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)?;
    info!("UDS Server listening on {}", socket_path);

    let tcell = tcell.clone();
    let lsm = lsm.clone();
    let agent_scheduler = agent_scheduler.clone();
    let compute_scheduler = compute_scheduler.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {
                    if cancel.is_cancelled() {
                        info!("UDS Server shutting down...");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut socket, _addr)) => {
                            let bus = Arc::clone(&intent_bus);
                            let tcell = tcell.clone();
                            let lsm = lsm.clone();
                            let agent_scheduler = agent_scheduler.clone();
                            let compute_scheduler = compute_scheduler.clone();

                            tokio::spawn(async move {
                                let (reader, mut writer) = socket.split();
                                let mut buf_reader = BufReader::new(reader);
                                let mut line = String::new();

                                loop {
                                    line.clear();
                                    match buf_reader.read_line(&mut line).await {
                                        Ok(0) => break, // EOF
                                        Ok(_) => {
                                            if let Ok(intent) = serde_json::from_str::<Intent>(&line) {
                                                debug!("Received intent via UDS: {:?}", intent.id);

                                                // ตรวจจับคำสั่งดึงข้อมูล หรือควบคุมความปลอดภัยของ CLI
                                                if intent.intent_type == IntentType::Command {
                                                    let cmd = intent.payload.as_str();
                                                    // กรณีคำสั่งดึงสถานะโดยรวม
                                                     if cmd == "status" {
                                                        let mut running_agents = 0;
                                                        let mut quarantined_pids = Vec::new();
                                                        let mut blocked_syscalls = Vec::new();
                                                        let mut hardware_targets = Vec::new();
                                                        let mut active_lsm_profile = String::from("unknown");
                                                        let mut allowed_syscalls_count = 0usize;

                                                        if let Some(ref sched) = agent_scheduler {
                                                            running_agents = sched.get_running_agents().await.len();
                                                        }
                                                        if let Some(ref tc) = tcell {
                                                            quarantined_pids = tc.get_quarantined_pids().await;
                                                        }
                                                        if let Some(ref l) = lsm {
                                                            blocked_syscalls = l.get_blocked_syscalls();
                                                            active_lsm_profile = l.active_profile_name().to_string();
                                                            allowed_syscalls_count = l.get_allowed_syscalls().len();
                                                        }
                                                        if let Some(ref cs) = compute_scheduler {
                                                            let cs = Arc::clone(cs);
                                                            let hardware_profiles = task::spawn_blocking(move || cs.scan_real_hardware())
                                                                .await
                                                                .unwrap_or_default();
                                                            for (target, profile) in hardware_profiles {
                                                                hardware_targets.push(serde_json::json!({
                                                                    "target": format!("{:?}", target),
                                                                    "latency_ms": profile.latency_ms,
                                                                    "power_watts": profile.power_watts,
                                                                    "cost_units": profile.cost_units,
                                                                }));
                                                            }
                                                        }

                                                        let response = serde_json::json!({
                                                            "status": "online",
                                                            "running_agents": running_agents,
                                                            "quarantined_pids": quarantined_pids,
                                                            "blocked_syscalls": blocked_syscalls,
                                                            "active_lsm_profile": active_lsm_profile,
                                                            "allowed_syscalls_count": allowed_syscalls_count,
                                                            "hardware_targets": hardware_targets,
                                                        });
                                                        let resp_json = format!("{}\n", response);
                                                        let _ = writer.write_all(resp_json.as_bytes()).await;
                                                        let _ = writer.flush().await;
                                                        continue;
                                                    // กรณีดึงรายการ PID ที่กำลังโดนกักกัน
                                                    } else if cmd == "list-quarantine" {
                                                        let mut pids = Vec::new();
                                                        if let Some(ref tc) = tcell {
                                                            pids = tc.get_quarantined_pids().await;
                                                        }
                                                        let response = serde_json::json!({
                                                            "quarantined_pids": pids
                                                        });
                                                        let resp_json = format!("{}\n", response);
                                                        let _ = writer.write_all(resp_json.as_bytes()).await;
                                                        let _ = writer.flush().await;
                                                        continue;
                                                    // กรณีตั้งค่า Threshold ความปลอดภัยของ T-Cell
                                                    } else if cmd == "set-threshold" {
                                                        let rate = intent.metadata.get("rate").and_then(|r| r.parse::<u64>().ok());
                                                        let deny = intent.metadata.get("deny").and_then(|d| d.parse::<u32>().ok());
                                                        let kill = intent.metadata.get("kill").and_then(|k| k.parse::<u32>().ok());

                                                        let mut success = false;
                                                        if let (Some(r), Some(d)) = (rate, deny) {
                                                            if let Some(ref tc) = tcell {
                                                                tc.update_thresholds(r, d, kill.unwrap_or(15));
                                                                success = true;
                                                            }
                                                        }

                                                        let response = serde_json::json!({
                                                            "success": success,
                                                            "message": if success { "Thresholds updated successfully" } else { "Failed to parse rate or deny from metadata" }
                                                        });
                                                        let resp_json = format!("{}\n", response);
                                                        let _ = writer.write_all(resp_json.as_bytes()).await;
                                                        let _ = writer.flush().await;
                                                        continue;
                                                    // กรณีสลับ LSM allowlist profile runtime
                                                    } else if cmd == "set-lsm-profile" {
                                                        let requested_profile = intent.metadata.get("profile").cloned();
                                                        let mut success = false;
                                                        let mut message = String::from("Missing profile metadata");
                                                        let mut active_lsm_profile = String::from("unknown");
                                                        let mut allowed_syscalls_count = 0usize;
                                                        let mut available_profiles = Vec::new();

                                                        if let Some(profile) = requested_profile {
                                                            if let Some(ref l) = lsm {
                                                                available_profiles = l.available_profiles();
                                                                match l.set_active_profile(&profile) {
                                                                    Ok(()) => {
                                                                        success = true;
                                                                        message = format!("LSM profile switched to {profile}");
                                                                        active_lsm_profile = l.active_profile_name();
                                                                        allowed_syscalls_count = l.get_allowed_syscalls().len();
                                                                    }
                                                                    Err(err) => {
                                                                        message = err.to_string();
                                                                        active_lsm_profile = l.active_profile_name();
                                                                        allowed_syscalls_count = l.get_allowed_syscalls().len();
                                                                    }
                                                                }
                                                            } else {
                                                                message = "LSM engine unavailable".to_string();
                                                            }
                                                        }

                                                        let response = serde_json::json!({
                                                            "success": success,
                                                            "message": message,
                                                            "active_lsm_profile": active_lsm_profile,
                                                            "allowed_syscalls_count": allowed_syscalls_count,
                                                            "available_profiles": available_profiles,
                                                        });
                                                        let resp_json = format!("{}\n", response);
                                                        let _ = writer.write_all(resp_json.as_bytes()).await;
                                                        let _ = writer.flush().await;
                                                        continue;
                                                    }
                                                }

                                                // สำหรับคำสั่งธรรมดาทั่วไป ให้ส่งเข้าสู่บัส Intent เพื่อโปรเซสตามปกติ
                                                if let Err(e) = bus.publish(intent).await {
                                                    error!("Failed to publish UDS intent: {}", e);
                                                }
                                            } else {
                                                error!("Failed to parse intent JSON: {}", line);
                                            }
                                        }
                                        Err(e) => {
                                            error!("UDS read error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("UDS accept error: {}", e);
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_bus::{Intent, IntentPriority, IntentType};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    /// Helper: spawn a UDS server with all subsystems = None, return (cancel, socket_path)
    async fn spawn_uds_server() -> (Arc<IntentBus>, CancellationToken, String) {
        let socket_path = format!("/tmp/ank-uds-test-{}.sock", uuid::Uuid::new_v4());
        let intent_bus = Arc::new(IntentBus::new(10));
        let cancel = CancellationToken::new();
        start_uds_server(
            Arc::clone(&intent_bus),
            None,
            None,
            None,
            None,
            &socket_path,
            cancel.clone(),
        )
        .await
        .expect("start_uds_server");
        tokio::time::sleep(Duration::from_millis(50)).await;
        (intent_bus, cancel, socket_path)
    }

    /// Helper: send JSON line, read response line
    async fn send_command(
        client: &mut UnixStream,
        payload: &str,
        metadata: HashMap<String, String>,
    ) -> String {
        let mut intent = Intent::new(
            uuid::Uuid::new_v4().to_string(),
            IntentType::Command,
            payload,
            IntentPriority::High,
            "test",
        );
        intent.metadata = metadata;
        let line = format!("{}\n", serde_json::to_string(&intent).unwrap());
        client.write_all(line.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = String::new();
        let mut reader = tokio::io::BufReader::new(&mut *client);
        reader.read_line(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn test_uds_server_lifecycle_and_publish() {
        let socket_path = format!("/tmp/test-ank-companion-{}.sock", uuid::Uuid::new_v4());
        let intent_bus = Arc::new(IntentBus::new(10));
        let mut sub = intent_bus.subscribe();
        let cancel = CancellationToken::new();

        start_uds_server(
            Arc::clone(&intent_bus),
            None,
            None,
            None,
            None,
            &socket_path,
            cancel.clone(),
        )
        .await
        .expect("Failed to start UDS server");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("Failed to connect to UDS socket");

        let intent = Intent::new(
            "uds-test-1",
            IntentType::Command,
            "test payload",
            IntentPriority::High,
            "uds-client",
        );

        let json_line = format!("{}\n", serde_json::to_string(&intent).unwrap());
        client.write_all(json_line.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(500), sub.receive())
            .await
            .expect("Timeout waiting for intent")
            .expect("No intent received");

        assert_eq!(received.id, "uds-test-1");
        assert_eq!(received.payload, "test payload");

        // Send invalid JSON
        client.write_all(b"invalid-json\n").await.unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_status_command_returns_online() {
        let (_bus, cancel, socket_path) = spawn_uds_server().await;
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        let resp = send_command(&mut client, "status", HashMap::new()).await;
        let parsed: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(parsed["status"], "online");
        assert_eq!(parsed["running_agents"], 0);
        assert_eq!(parsed["blocked_syscalls"], serde_json::json!([]));
        assert_eq!(parsed["hardware_targets"], serde_json::json!([]));

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_list_quarantine_command() {
        let (_bus, cancel, socket_path) = spawn_uds_server().await;
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        let resp = send_command(&mut client, "list-quarantine", HashMap::new()).await;
        let parsed: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(parsed["quarantined_pids"], serde_json::json!([]));

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_set_threshold_without_tcell() {
        let (_bus, cancel, socket_path) = spawn_uds_server().await;
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        let mut meta = HashMap::new();
        meta.insert("rate".to_string(), "10".to_string());
        meta.insert("deny".to_string(), "5".to_string());
        let resp = send_command(&mut client, "set-threshold", meta).await;
        let parsed: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        // No TCell → success should be false
        assert_eq!(parsed["success"], false);
        assert_eq!(
            parsed["message"],
            "Failed to parse rate or deny from metadata"
        );

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_set_lsm_profile_without_lsm() {
        let (_bus, cancel, socket_path) = spawn_uds_server().await;
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        let mut meta = HashMap::new();
        meta.insert("profile".to_string(), "strict".to_string());
        let resp = send_command(&mut client, "set-lsm-profile", meta).await;
        let parsed: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(parsed["success"], false);
        assert_eq!(parsed["message"], "LSM engine unavailable");

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_unknown_command_publishes_to_bus() {
        let (bus, cancel, socket_path) = spawn_uds_server().await;
        let mut sub = bus.subscribe();
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        // "unknown" is not a recognized command, so it should be published to the bus
        let mut meta = HashMap::new();
        meta.insert("foo".to_string(), "bar".to_string());
        let mut intent = Intent::new(
            "unknown-cmd",
            IntentType::Command,
            "unknown",
            IntentPriority::High,
            "test",
        );
        intent.metadata = meta;
        let line = format!("{}\n", serde_json::to_string(&intent).unwrap());
        client.write_all(line.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(500), sub.receive())
            .await
            .expect("Timeout")
            .expect("No intent");
        assert_eq!(received.payload, "unknown");

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_non_command_intent_publishes_to_bus() {
        let (bus, cancel, socket_path) = spawn_uds_server().await;
        let mut sub = bus.subscribe();
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        let intent = Intent::new(
            "nl-intent",
            IntentType::NaturalLanguage,
            "open the browser",
            IntentPriority::Medium,
            "test",
        );
        let line = format!("{}\n", serde_json::to_string(&intent).unwrap());
        client.write_all(line.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(500), sub.receive())
            .await
            .expect("Timeout")
            .expect("No intent");
        assert_eq!(received.payload, "open the browser");
        assert_eq!(received.intent_type, IntentType::NaturalLanguage);

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }

    #[tokio::test]
    async fn uds_set_threshold_missing_metadata() {
        let (_bus, cancel, socket_path) = spawn_uds_server().await;
        let mut client = UnixStream::connect(&socket_path).await.unwrap();

        // No 'rate' metadata → should fail
        let mut meta = HashMap::new();
        meta.insert("deny".to_string(), "5".to_string());
        let resp = send_command(&mut client, "set-threshold", meta).await;
        let parsed: serde_json::Value = serde_json::from_str(resp.trim()).unwrap();
        assert_eq!(parsed["success"], false);

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tokio::fs::remove_file(&socket_path).await;
    }
}
