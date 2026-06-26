use anyhow::Result;
use intent_bus::{Intent, IntentBus};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};
use crate::tokio_util_cancel::CancellationToken;

/// เริ่มต้น Unix Domain Socket Server สำหรับรับ Intent จากภายนอก
pub async fn start_uds_server(
    intent_bus: Arc<IntentBus>,
    socket_path: &str,
    cancel: CancellationToken,
) -> Result<()> {
    // ลบไฟล์ซ็อกเก็ตเก่าถ้ามี
    let _ = tokio::fs::remove_file(socket_path).await;

    let listener = UnixListener::bind(socket_path)?;
    info!("UDS Server listening on {}", socket_path);

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
                            tokio::spawn(async move {
                                let (reader, _writer) = socket.split();
                                let mut buf_reader = BufReader::new(reader);
                                let mut line = String::new();

                                loop {
                                    line.clear();
                                    match buf_reader.read_line(&mut line).await {
                                        Ok(0) => break, // EOF
                                        Ok(_) => {
                                            if let Ok(intent) = serde_json::from_str::<Intent>(&line) {
                                                debug!("Received intent via UDS: {:?}", intent.id);
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
