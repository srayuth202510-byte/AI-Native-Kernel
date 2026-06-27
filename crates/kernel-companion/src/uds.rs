use crate::lsm::LsmPolicyEngine;
use crate::tokio_util_cancel::CancellationToken;
use agent_scheduler::AgentScheduler;
use anyhow::Result;
use immune_system::TCellAgent;
use intent_bus::{Intent, IntentBus, IntentType};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

/// เริ่มต้น Unix Domain Socket Server สำหรับรับ Intent จากภายนอก
pub async fn start_uds_server(
    intent_bus: Arc<IntentBus>,
    tcell: Option<Arc<TCellAgent>>,
    lsm: Option<Arc<LsmPolicyEngine>>,
    agent_scheduler: Option<Arc<AgentScheduler>>,
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
                                                    if cmd == "status" {
                                                        let mut running_agents = 0;
                                                        let mut quarantined_pids = Vec::new();
                                                        let mut blocked_syscalls = Vec::new();

                                                        if let Some(ref sched) = agent_scheduler {
                                                            running_agents = sched.get_running_agents().await.len();
                                                        }
                                                        if let Some(ref tc) = tcell {
                                                            quarantined_pids = tc.get_quarantined_pids().await;
                                                        }
                                                        if let Some(ref l) = lsm {
                                                            blocked_syscalls = l.get_blocked_syscalls();
                                                        }

                                                        let response = serde_json::json!({
                                                            "status": "online",
                                                            "running_agents": running_agents,
                                                            "quarantined_pids": quarantined_pids,
                                                            "blocked_syscalls": blocked_syscalls,
                                                        });
                                                        let resp_json = format!("{}\n", response);
                                                        let _ = writer.write_all(resp_json.as_bytes()).await;
                                                        let _ = writer.flush().await;
                                                        continue;
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
                                                    } else if cmd == "set-threshold" {
                                                        let rate = intent.metadata.get("rate").and_then(|r| r.parse::<u64>().ok());
                                                        let deny = intent.metadata.get("deny").and_then(|d| d.parse::<u32>().ok());

                                                        let mut success = false;
                                                        if let (Some(r), Some(d)) = (rate, deny) {
                                                            if let Some(ref tc) = tcell {
                                                                tc.update_thresholds(r, d);
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
                                                    }
                                                }

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
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_uds_server_lifecycle_and_publish() {
        let socket_path = format!("/tmp/test-ank-companion-{}.sock", uuid::Uuid::new_v4());
        let intent_bus = Arc::new(IntentBus::new(10));
        let mut sub = intent_bus.subscribe();
        let cancel = CancellationToken::new();

        // Start UDS Server
        start_uds_server(
            Arc::clone(&intent_bus),
            None,
            None,
            None,
            &socket_path,
            cancel.clone(),
        )
        .await
        .expect("Failed to start UDS server");

        // Wait a short duration for the socket to bind and start listening
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to UDS and send a valid intent
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

        // Receive from IntentBus
        let received = tokio::time::timeout(std::time::Duration::from_millis(500), sub.receive())
            .await
            .expect("Timeout waiting for intent")
            .expect("No intent received");

        assert_eq!(received.id, "uds-test-1");
        assert_eq!(received.payload, "test payload");

        // Send invalid JSON line
        client.write_all(b"invalid-json\n").await.unwrap();
        client.flush().await.unwrap();

        // Make sure no intent is published (timeout should occur if we try to receive)
        // Wait briefly to allow processing
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Cancel server
        cancel.cancel();

        // Wait a short duration for shutdown
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cleanup
        let _ = tokio::fs::remove_file(&socket_path).await;
    }
}
