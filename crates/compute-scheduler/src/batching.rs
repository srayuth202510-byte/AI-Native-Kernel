use crate::engine::{AiEngine, EngineError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tracing::{debug, error, info};

/// โครงสร้างคำขอที่ส่งเข้ามารอจัดคิวทำ Batch
pub struct BatchRequest {
    pub prompt: String,
    pub max_tokens: usize,
    pub response_tx: oneshot::Sender<Result<String, EngineError>>,
}

/// ตัวจัดการคิวเพื่อรวมกลุ่มงานส่งให้ GPU ทีละ Batch (Batching Manager)
pub struct BatchManager {
    sender: mpsc::Sender<BatchRequest>,
}

impl BatchManager {
    /// สร้าง BatchManager และเริ่มทำงาน Background Task
    pub fn new(engine: Arc<dyn AiEngine>, max_batch_size: usize, max_wait_time: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<BatchRequest>(1024);

        tokio::spawn(async move {
            info!(
                "BatchManager: เริ่มต้นทำงาน (Max Batch: {}, Wait Time: {:?})",
                max_batch_size, max_wait_time
            );
            loop {
                let mut batch = Vec::new();
                let mut max_tokens_in_batch = 0;

                // พยายามดึงตัวแรกออกมา (บล็อกจนกว่าจะมีงานแรกเข้ามา)
                let first_req = rx.recv().await;
                let Some(req) = first_req else {
                    info!("BatchManager: Channel ปิด สิ้นสุดการทำงาน");
                    break;
                };

                max_tokens_in_batch = max_tokens_in_batch.max(req.max_tokens);
                batch.push(req);

                // รอรับงานเพิ่มจนกว่าจะครบโควตา หรือหมดเวลา
                let timeout = time::sleep(max_wait_time);
                tokio::pin!(timeout);

                loop {
                    if batch.len() >= max_batch_size {
                        break;
                    }
                    tokio::select! {
                        _ = &mut timeout => {
                            // หมดเวลารอ (Wait Time) ให้ลุยเท่าที่มี
                            break;
                        }
                        req_opt = rx.recv() => {
                            match req_opt {
                                Some(req) => {
                                    max_tokens_in_batch = max_tokens_in_batch.max(req.max_tokens);
                                    batch.push(req);
                                }
                                None => break, // Channel ปิดกลางคัน
                            }
                        }
                    }
                }

                // สกัด Prompt และยิงเข้า AI Engine
                let prompts: Vec<String> = batch.iter().map(|r| r.prompt.clone()).collect();
                debug!(
                    "BatchManager: ประมวลผล Batch ชุดใหม่ จำนวน {} รายการ",
                    prompts.len()
                );

                let results = engine.generate_batch(&prompts, max_tokens_in_batch).await;

                // แจกจ่ายผลลัพธ์กลับไปยัง Agent หรือผู้เรียกแต่ละคน
                match results {
                    Ok(outputs) => {
                        for (req, output) in batch.into_iter().zip(outputs) {
                            let _ = req.response_tx.send(Ok(output));
                        }
                    }
                    Err(e) => {
                        error!("BatchManager: การประมวลผลล้มเหลวทั้ง Batch: {}", e);
                        for req in batch {
                            // จำเป็นต้อง Clone Error (ในชีวิตจริงอาจต้องใช้วิธีอื่น หาก Error ไม่รองรับ Clone)
                            let _ = req
                                .response_tx
                                .send(Err(EngineError::Internal(e.to_string())));
                        }
                    }
                }
            }
        });

        Self { sender: tx }
    }

    /// ส่งงานใหม่เข้าคิว Batch
    pub async fn submit(
        &self,
        prompt: impl Into<String>,
        max_tokens: usize,
    ) -> Result<String, EngineError> {
        let (tx, rx) = oneshot::channel();
        let req = BatchRequest {
            prompt: prompt.into(),
            max_tokens,
            response_tx: tx,
        };

        if self.sender.send(req).await.is_err() {
            return Err(EngineError::Internal("Batch queue closed".into()));
        }

        rx.await
            .unwrap_or_else(|_| Err(EngineError::Internal("Response channel dropped".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{LlamaCppEngine, TensorRtLlmEngine};
    use std::time::Instant;

    #[tokio::test]
    async fn test_batch_manager_groups_requests() {
        let engine = Arc::new(TensorRtLlmEngine::new("/dummy/sock"));
        let batch_manager = Arc::new(BatchManager::new(engine, 2, Duration::from_millis(50)));

        let bm1 = Arc::clone(&batch_manager);
        let t1 = tokio::spawn(async move { bm1.submit("Prompt 1", 10).await });

        let bm2 = Arc::clone(&batch_manager);
        let t2 = tokio::spawn(async move { bm2.submit("Prompt 2", 10).await });

        let (res1, res2) = tokio::join!(t1, t2);

        assert_eq!(
            res1.unwrap().unwrap(),
            "[TensorRT-LLM mock] tokens_limit=10: Prompt 1..."
        );
        assert_eq!(
            res2.unwrap().unwrap(),
            "[TensorRT-LLM mock] tokens_limit=10: Prompt 2..."
        );
    }

    #[tokio::test]
    async fn test_batch_manager_timeout_flushes_queue() {
        let engine = Arc::new(LlamaCppEngine::new("http://dummy"));
        // Wait time 200ms, batch size 5
        let batch_manager = Arc::new(BatchManager::new(engine, 5, Duration::from_millis(200)));

        let start = Instant::now();
        // Submit only 1 item, so it must wait for timeout to flush
        let res = batch_manager.submit("Single", 10).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(res, "[llama.cpp mock] tokens_limit=10: Single...");
        // Should have waited at least ~200ms (timeout) + 150ms (llama engine latency)
        assert!(elapsed >= Duration::from_millis(200));
    }
}
