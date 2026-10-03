//! Webhook sink — ส่ง alert ออกนอกระบบทางเดียว
//!
//! sink เดียวรองรับทุกปลายทางที่รับ webhook (Slack/PagerDuty/Opsgenie/LINE)
//! เพราะทั้งหมดคือ "POST JSON ไปที่ URL" — ไม่เขียนโค้ดแยกต่อ vendor
//! payload ใช้ schema ของเราเอง ตัวอย่าง mapping ไปแต่ละเจ้าอยู่ใน docs
//!
//! กฎเหล็ก: timeout ทุกครั้ง (5s ตาม AGENTS.md — external call ห้ามรอไม่จำกัด),
//! retry แบบ backoff 3 ครั้งแล้วยอมแพ้พร้อม error (dispatcher เป็นคนนับทิ้ง)
//! ไม่ panic, ไม่ block request path (sink ถูกเรียกจาก dispatcher task เท่านั้น)

use crate::rules::FiredAlert;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use std::time::Duration;
use thiserror::Error;

/// ข้อผิดพลาดของการส่ง alert
#[derive(Debug, Error)]
pub enum SinkError {
    /// สร้าง HTTP client ไม่ได้
    #[error("cannot build webhook client: {0}")]
    Build(String),
    /// ส่งไม่สำเร็จหลัง retry ครบ (เก็บสถานะ HTTP สุดท้ายไว้สืบสวน)
    #[error("webhook delivery failed after {attempts} attempts: {last}")]
    Delivery {
        /// จำนวนครั้งที่ลองทั้งหมด
        attempts: u32,
        /// ข้อความผิดพลาดครั้งสุดท้าย
        last: String,
    },
}

/// รูปร่าง JSON ที่ส่งออก — schema ของเราเอง ไม่ผูกกับ vendor ใด
#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    /// ฉบับ schema (เผื่อเปลี่ยนรูปร่างในอนาคตโดยไม่เงียบ)
    pub schema: &'static str,
    /// รหัสกฎที่ยิง
    pub rule_id: String,
    /// ผู้เช่าที่เกี่ยวข้อง
    pub tenant_id: String,
    /// ความรุนแรง
    pub severity: String,
    /// ผลรวมนับในหน้าต่างที่ทำให้ยิง
    pub total: u64,
    /// จุดเริ่มหน้าต่าง (ms epoch)
    pub window_started_ms: u64,
    /// ตัวอย่างเหตุการณ์ (มี request_id สำหรับสืบกลับไปหา audit chain)
    pub sample: SamplePayload,
}

/// ส่วนตัวอย่างเหตุการณ์ใน payload
#[derive(Debug, Clone, Serialize)]
pub struct SamplePayload {
    /// หมวดเหตุการณ์
    pub category: String,
    /// เหตุผลแบบเครื่องอ่าน
    pub reason: String,
    /// ตัวชี้หลักฐาน (request_id ของ audit entry)
    pub request_id: String,
    /// หลักฐานเสริม
    pub evidence: String,
}

impl From<FiredAlert> for AlertPayload {
    fn from(alert: FiredAlert) -> Self {
        Self {
            schema: "watchtower.alert/v1",
            rule_id: alert.rule_id.clone(),
            tenant_id: alert.tenant_id.clone(),
            severity: alert.severity.as_str().to_string(),
            total: alert.total,
            window_started_ms: alert.window_started_ms,
            sample: SamplePayload {
                category: alert.sample.category.clone(),
                reason: alert.sample.reason.clone(),
                request_id: alert.sample.request_id.clone(),
                evidence: alert.sample.evidence.clone(),
            },
        }
    }
}

/// เวลารอ response ต่อครั้ง (AGENTS.md: external call ต้องมี timeout)
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);
/// จำนวนครั้งที่ลองสูงสุด (รวมครั้งแรก)
pub const MAX_ATTEMPTS: u32 = 3;

/// ปลายทางการส่ง alert — trait นี้ทำให้ dispatcher ทดสอบได้โดยไม่ต้องพึ่ง
/// network จริง (เขียน future ชัด ๆ พร้อม `+ Send` เพราะ `async fn` ใน trait
/// ไม่รับประกัน Send ให้เอง แล้ว `tokio::spawn` ต้องการ Send)
pub trait AlertSink: Send + Sync {
    /// ส่ง alert หนึ่งครั้ง (รวม retry ภายในถ้ามี) — รับ owned เพราะ dispatcher
    /// ถือ alert แบบ owned จาก channel อยู่แล้ว จะได้ไม่มีปัญหา lifetime สองชั้น
    fn send(
        &self,
        alert: FiredAlert,
    ) -> impl std::future::Future<Output = Result<(), SinkError>> + Send + '_;
}

/// ปลายทาง webhook — clone ได้ แชร์ client เดียวกัน (connection pool)
#[derive(Debug, Clone)]
pub struct WebhookSink {
    client: reqwest::Client,
    url: String,
    bearer: Option<SecretString>,
}

impl AlertSink for WebhookSink {
    fn send(
        &self,
        alert: FiredAlert,
    ) -> impl std::future::Future<Output = Result<(), SinkError>> + Send + '_ {
        self.deliver(alert)
    }
}

impl WebhookSink {
    /// สร้าง sink ใหม่
    ///
    /// # Errors
    /// คืน `Err` เมื่อสร้าง HTTP client ไม่ได้
    pub fn new(url: &str, bearer: Option<SecretString>) -> Result<Self, SinkError> {
        let client = reqwest::Client::builder()
            .timeout(DELIVERY_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| SinkError::Build(e.to_string()))?;
        Ok(Self {
            client,
            url: url.to_string(),
            bearer,
        })
    }

    /// ส่ง alert หนึ่งครั้ง พร้อม retry backoff (100ms → 400ms)
    ///
    /// คืน `Err` เมื่อครบทุกความพยายามแล้วยังไม่สำเร็จ — ผู้เรียก (dispatcher)
    /// ต้องนับทิ้ง ไม่ใช่เงียบ
    async fn deliver(&self, alert: FiredAlert) -> Result<(), SinkError> {
        let payload = AlertPayload::from(alert);
        let mut last = "no attempt made".to_string();
        for attempt in 1..=MAX_ATTEMPTS {
            let mut req = self.client.post(&self.url).json(&payload);
            if let Some(token) = &self.bearer {
                req = req.bearer_auth(token.expose_secret());
            }
            match req.send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last = format!("http {}", resp.status());
                }
                Err(e) => {
                    last = if e.is_timeout() {
                        format!("timeout after {DELIVERY_TIMEOUT:?}")
                    } else {
                        e.to_string()
                    };
                }
            }
            if attempt < MAX_ATTEMPTS {
                // backoff 100ms, 400ms — รวม worst case ยังอยู่ในหลักวินาที
                // ไม่ใช่หลักนาที (alert ช้า 1 วิ ดีกว่า alert หาย)
                tokio::time::sleep(Duration::from_millis(100 * 4_u64.pow(attempt - 1))).await;
            }
        }
        Err(SinkError::Delivery {
            attempts: MAX_ATTEMPTS,
            last,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SecurityEvent, Severity};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn alert() -> FiredAlert {
        FiredAlert {
            rule_id: "r1".to_string(),
            tenant_id: "acme".to_string(),
            severity: Severity::High,
            total: 5,
            window_started_ms: 1000,
            sample: SecurityEvent::new("acme", "auth", "invalid_api_key", Severity::High, "r1", 1),
        }
    }

    /// mock webhook server — อ่าน request หนึ่งครั้งแล้วตอบตามสคริปต์
    async fn mock_server(
        script: Vec<u16>,
        seen: Arc<AtomicUsize>,
        bodies: Arc<parking_lot::Mutex<Vec<String>>>,
        auth_seen: Arc<parking_lot::Mutex<Vec<String>>>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            for status in script {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = vec![0u8; 16384];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                seen.fetch_add(1, Ordering::SeqCst);
                let auth = text
                    .lines()
                    .find(|l| l.to_lowercase().starts_with("authorization:"))
                    .unwrap_or("")
                    .to_string();
                auth_seen.lock().push(auth);
                // body อยู่หลัง \r\n\r\n
                let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                bodies.lock().push(body);
                let reason = match status {
                    200 => "OK",
                    429 => "Too Many Requests",
                    _ => "Server Error",
                };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });
        format!("http://{addr}/hook")
    }

    #[test]
    fn payload_schema_is_versioned_and_evidenced() {
        let p = AlertPayload::from(alert());
        let v = serde_json::to_value(&p).expect("serialize");
        assert_eq!(v["schema"], "watchtower.alert/v1");
        assert_eq!(v["rule_id"], "r1");
        assert_eq!(v["sample"]["request_id"], "r1");
    }

    #[tokio::test]
    async fn delivers_json_with_bearer_auth() {
        let seen = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let auths = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let url = mock_server(vec![200], seen.clone(), bodies.clone(), auths.clone()).await;

        let sink =
            WebhookSink::new(&url, Some("s3cr3t".parse().expect("test secret"))).expect("sink");
        sink.send(alert()).await.expect("deliver");

        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert!(
            auths.lock()[0].contains("Bearer s3cr3t"),
            "bearer must be sent, got {:?}",
            auths.lock()[0]
        );
        let body: serde_json::Value =
            serde_json::from_str(&bodies.lock()[0]).expect("valid JSON body");
        assert_eq!(body["schema"], "watchtower.alert/v1");
        assert_eq!(body["tenant_id"], "acme");
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        let seen = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let auths = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let url = mock_server(
            vec![500, 500, 200],
            seen.clone(),
            bodies.clone(),
            auths.clone(),
        )
        .await;

        let sink = WebhookSink::new(&url, None).expect("sink");
        sink.send(alert()).await.expect("eventual success");
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let seen = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let auths = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let url = mock_server(
            vec![500, 500, 500, 500],
            seen.clone(),
            bodies.clone(),
            auths.clone(),
        )
        .await;

        let sink = WebhookSink::new(&url, None).expect("sink");
        let err = sink.send(alert()).await.expect_err("must fail");
        assert!(matches!(err, SinkError::Delivery { attempts: 3, .. }));
        assert_eq!(seen.load(Ordering::SeqCst), 3, "must stop at MAX_ATTEMPTS");
    }

    #[tokio::test]
    async fn slow_server_hits_timeout_not_hang() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            // รับ connection แล้วเงย — ไม่ตอบอะไรเลย
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let sink = WebhookSink::new(&format!("http://{addr}/hook"), None).expect("sink");
        let start = std::time::Instant::now();
        let err = sink.send(alert()).await.expect_err("must time out");
        // 3 ครั้ง × (5s timeout + backoff ~0.5s) — ต้องจบในหลักสิบวิ ไม่ใช่ค้าง
        assert!(
            start.elapsed() < Duration::from_secs(25),
            "delivery must be bounded, took {:?}",
            start.elapsed()
        );
        assert!(matches!(err, SinkError::Delivery { .. }));
    }
}
