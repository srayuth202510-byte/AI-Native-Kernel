//! Dispatcher — คิวมีขอบเขตระหว่าง rules engine กับ webhook sink
//!
//! เหตุผลที่ต้องมีคิวแทนที่จะส่งตรง: การส่ง webhook ใช้เวลาเป็นหลักวินาที
//! (timeout + retry) ถ้า engine รอส่งทุกครั้ง request path จะช้าลงตาม
//! dispatcher จึงเป็น task เบื้องหลังคอยกิน queue ส่วน engine แค่ `try_enqueue`
//! แล้วไปต่อทันที
//!
//! เมื่อ queue เต็ม: ทิ้ง alert ตัวใหม่และนับ `alerts_dropped_total` — การทิ้ง
//! เงียบโดยไม่มีตัวนับคือการโกหก (ดู design doc หลักการข้อ 1)

use crate::metrics::WatchtowerMetrics;
use crate::rules::FiredAlert;
use crate::sink::AlertSink;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// ความจุ queue เริ่มต้น — ใหญ่พอให้ burst ผ่าน เล็กพอให้เต็มแล้วรู้ตัวเร็ว
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// ผลของการพยายามเข้าคิว
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    /// เข้าคิวแล้ว (dispatcher จะส่งต่อ)
    Queued,
    /// คิวเต็ม — ทิ้งแล้ว (นับใน `alerts_dropped_total` แล้ว)
    Dropped,
}

/// ตัวจ่าย alert แบบ out-of-band — generic เหนือ sink เพื่อให้เทสต์เสียบ sink
/// ปลอมที่คุมจังหวะได้ (deterministic ไม่ flaky)
pub struct Dispatcher<S = crate::sink::WebhookSink> {
    tx: mpsc::Sender<FiredAlert>,
    dropped: Arc<AtomicU64>,
    metrics: Option<Arc<WatchtowerMetrics>>,
    task: JoinHandle<()>,
    _sink: std::marker::PhantomData<S>,
}

impl<S: AlertSink + Send + Sync + 'static> Dispatcher<S> {
    /// เริ่ม dispatcher task เบื้องหลัง (ต้องเรียกใน tokio runtime)
    #[must_use]
    pub fn start(sink: S, capacity: usize, metrics: Option<Arc<WatchtowerMetrics>>) -> Self {
        let (tx, mut rx) = mpsc::channel::<FiredAlert>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(async move {
            while let Some(alert) = rx.recv().await {
                let rule_id = alert.rule_id.clone();
                let tenant_id = alert.tenant_id.clone();
                if let Err(e) = sink.send(alert).await {
                    // ส่งไม่สำเร็จหลัง retry ครบ — บันทึกไว้สืบสวน ไม่ panic
                    // (task ตาย = pipeline ตาบอดทั้งเส้น ดู A9)
                    tracing::warn!(
                        rule = %rule_id,
                        tenant = %tenant_id,
                        error = %e,
                        "webhook delivery failed permanently"
                    );
                }
            }
        });
        Self {
            tx,
            dropped,
            metrics,
            task,
            _sink: std::marker::PhantomData,
        }
    }

    /// พยายามเข้าคิวแบบไม่รอ — ไม่มีทาง block request path
    #[must_use]
    pub fn try_enqueue(&self, alert: FiredAlert) -> Enqueue {
        match self.tx.try_send(alert) {
            Ok(()) => Enqueue::Queued,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                if let Some(m) = &self.metrics {
                    m.alerts_dropped_total.inc();
                }
                Enqueue::Dropped
            }
        }
    }

    /// จำนวน alert ที่ทิ้งเพราะคิวเต็มตั้งแต่เริ่ม
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }

    /// task เบื้องหลังยังมีชีวิตหรือไม่ (gateway ใช้ประกอบ `pipeline_healthy`)
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.task.is_finished()
    }

    /// หยุด dispatcher แบบ graceful — รอคิวที่เหลือส่งให้หมดก่อน
    pub async fn shutdown(self) {
        drop(self.tx);
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SecurityEvent, Severity};
    use crate::sink::WebhookSink;

    fn alert(tenant: &str) -> FiredAlert {
        FiredAlert {
            rule_id: "r1".to_string(),
            tenant_id: tenant.to_string(),
            severity: Severity::High,
            total: 1,
            window_started_ms: 0,
            sample: SecurityEvent::new(tenant, "auth", "invalid_api_key", Severity::High, "r1", 0),
        }
    }

    /// sink ที่ค้างตามคำสั่ง — ใช้บังคับให้ queue เต็มแบบ deterministic
    /// (ไม่ต้องพึ่ง timing จริง จึงไม่ flaky)
    ///
    /// ใช้ `watch` ไม่ใช่ `Notify` เพราะ `notify_waiters` ทำสัญญาณหายถ้า consumer
    /// ยังมาไม่ถึง (hang ถาวร) ส่วน `watch` จำค่าล่าสุดไว้ — เปิดแล้วเปิดเลย
    struct GateSink {
        open: tokio::sync::watch::Receiver<bool>,
        received: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    impl crate::sink::AlertSink for GateSink {
        // manual_async_fn โดยตั้งใจ: `async fn` ใน trait ไม่รับประกัน Send
        // ให้ future แต่ dispatcher spawn ลง runtime ต้องการ Send — เขียน
        // future ชัด ๆ ตรงนี้จึงไม่ใช่ style แต่เป็นข้อกำหนด
        #[allow(clippy::manual_async_fn)]
        fn send(
            &self,
            alert: FiredAlert,
        ) -> impl std::future::Future<Output = Result<(), crate::sink::SinkError>> + Send + '_
        {
            async move {
                let mut open = self.open.clone();
                let _ = open.wait_for(|v| *v).await;
                self.received.lock().push(alert.tenant_id.clone());
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts() {
        // consumer ค้างที่ gate → producer ยัดจนเต็มแล้วต้องทิ้งพร้อมนับ
        let (open_tx, open_rx) = tokio::sync::watch::channel(false);
        let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let metrics = WatchtowerMetrics::register(&prometheus::Registry::new()).expect("metrics");
        let dispatcher = Dispatcher::start(
            GateSink {
                open: open_rx,
                received: received.clone(),
            },
            2,
            Some(metrics.clone()),
        );

        assert_eq!(dispatcher.try_enqueue(alert("a")), Enqueue::Queued);
        assert_eq!(dispatcher.try_enqueue(alert("b")), Enqueue::Queued);
        // ที่ว่างใน channel หมด (consumer ยังค้าง) → ตัวที่สามต้องทิ้ง
        // หมายเหตุ: consumer อาจดึงตัวแรกออกไปก่อนถ้า scheduler สลับ — ยัดเผื่อ
        let mut dropped = 0;
        for i in 0..8 {
            if dispatcher.try_enqueue(alert(&format!("x{i}"))) == Enqueue::Dropped {
                dropped += 1;
            }
        }
        assert!(dropped > 0, "a full queue must drop, got all queued");
        assert_eq!(dispatcher.dropped_count() as usize, dropped);
        assert_eq!(
            metrics.alerts_dropped_total.get() as usize,
            dropped,
            "every drop must be counted in the metric"
        );

        let _ = open_tx.send(true);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn dispatcher_delivers_queued_alerts() {
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen_clone = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await;
                seen_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            }
        });

        let sink = WebhookSink::new(&format!("http://{addr}/hook"), None).expect("sink");
        let dispatcher = Dispatcher::start(sink, 16, None);
        assert!(dispatcher.is_alive());
        assert_eq!(dispatcher.try_enqueue(alert("a")), Enqueue::Queued);
        assert_eq!(dispatcher.try_enqueue(alert("b")), Enqueue::Queued);
        assert_eq!(dispatcher.dropped_count(), 0);
        dispatcher.shutdown().await;
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
