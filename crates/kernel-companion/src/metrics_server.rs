use crate::tokio_util_cancel::CancellationToken;
use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info};

/// เริ่มต้น HTTP Server ขนาดเล็กเพื่อรองรับการดึงข้อมูล Prometheus Metrics
/// โดยจะดักฟัง TCP Connection และตอบกลับ HTTP/1.1 200 OK เฉพาะทางเลือก GET /metrics
pub async fn start_metrics_server(addr_str: &str, cancel: CancellationToken) -> Result<()> {
    let addr: SocketAddr = addr_str.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("Prometheus Telemetry Server listening on http://{}", addr);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if cancel.is_cancelled() {
                        info!("Prometheus Telemetry Server shutting down...");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut socket, _client_addr)) => {
                            tokio::spawn(async move {
                                let (reader, mut writer) = socket.split();
                                let mut buf_reader = BufReader::new(reader);
                                let mut request_line = String::new();

                                // อ่านบรรทัดแรกของ HTTP Request
                                if let Ok(n) = buf_reader.read_line(&mut request_line).await {
                                    if n > 0 && request_line.starts_with("GET /metrics") {
                                        // เรนเดอร์ metrics ออกมาในรูปแบบ Prometheus text format
                                        match capability_security::render_metrics(prometheus::default_registry()) {
                                            Ok(metrics_data) => {
                                                let response = format!(
                                                    "HTTP/1.1 200 OK\r\n\
                                                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                                                     Content-Length: {}\r\n\
                                                     Connection: close\r\n\
                                                     \r\n\
                                                     {}",
                                                    metrics_data.len(),
                                                    metrics_data
                                                );
                                                let _ = writer.write_all(response.as_bytes()).await;
                                            }
                                            Err(e) => {
                                                error!("Failed to render metrics: {}", e);
                                                let response = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                                                let _ = writer.write_all(response.as_bytes()).await;
                                            }
                                        }
                                    } else {
                                        // ถ้าเรียกใช้งานหน้าอื่นที่ไม่ใช่ /metrics ให้ส่ง 404
                                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
                                        let _ = writer.write_all(response.as_bytes()).await;
                                    }
                                    let _ = writer.flush().await;
                                }
                            });
                        }
                        Err(e) => {
                            error!("Prometheus Server accept error: {}", e);
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
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_metrics_server_lifecycle_and_response() {
        let cancel = CancellationToken::new();
        let port = 19090; // หลีกเลี่ยงพอร์ตชน
        let addr_str = format!("127.0.0.1:{}", port);

        // เริ่มต้นเซิร์ฟเวอร์
        start_metrics_server(&addr_str, cancel.clone())
            .await
            .expect("Failed to start metrics server");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // เชื่อมต่อส่ง GET /metrics HTTP Request
        let mut stream = TcpStream::connect(&addr_str)
            .await
            .expect("Failed to connect to metrics server");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // อ่านผลลัพธ์ตอบกลับ
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        // ตรวจสอบความถูกต้องของการตอบกลับ
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("security_tokens_issued_total"));

        // ทดสอบเส้นทางอื่นๆ ที่ไม่มีอยู่จริง (GET /invalid) -> ต้องได้ 404
        let mut stream = TcpStream::connect(&addr_str)
            .await
            .expect("Failed to connect");
        stream
            .write_all(b"GET /invalid HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let mut response2 = String::new();
        stream.read_to_string(&mut response2).await.unwrap();
        assert!(response2.starts_with("HTTP/1.1 404 Not Found"));

        // สั่งหยุดทำงาน
        cancel.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
