use crate::InferenceRuntime;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("การเชื่อมต่อ Inference Engine ภายนอกล้มเหลว: {0}")]
    ConnectionFailed(String),
    #[error("Inference Engine ใช้เวลาประมวลผลนานเกินกำหนด (Timeout)")]
    Timeout,
    #[error("ข้อผิดพลาดอื่นๆ: {0}")]
    Internal(String),
}

/// Abstraction สำหรับ AI Runtime Engine ทุกประเภท
#[async_trait::async_trait]
pub trait AiEngine: Send + Sync {
    /// สร้างข้อความตอบกลับจาก Prompt (Inference)
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError>;

    /// ประมวลผลแบบแบตช์ (Batch Processing) เหมาะสำหรับรันไทม์ฝั่ง GPU (เช่น TensorRT-LLM)
    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError>;

    /// คืนค่าประเภทของ Inference Runtime
    fn runtime_type(&self) -> InferenceRuntime;
}

/// การเชื่อมต่อกับ Llama.cpp (มักรันเป็น HTTP Server บน Edge/CPU/NPU)
pub struct LlamaCppEngine {
    endpoint_url: String,
}

impl LlamaCppEngine {
    #[must_use]
    pub fn new(endpoint_url: impl Into<String>) -> Self {
        Self {
            endpoint_url: endpoint_url.into(),
        }
    }
}

#[async_trait::async_trait]
impl AiEngine for LlamaCppEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        info!(
            "LlamaCppEngine: กำลังส่งงานไปยัง {} (Prompt: {} chars, MaxTokens: {})",
            self.endpoint_url,
            prompt.len(),
            max_tokens
        );
        // จำลอง Network Latency ในการเรียกไปยัง Local HTTP Server (เช่น llama.cpp server)
        tokio::time::sleep(Duration::from_millis(150)).await;
        Ok(format!("[Llama.cpp Output]: {}", prompt))
    }

    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError> {
        // llama.cpp อาจไม่ได้ออกแบบมาเพื่อ Batch ขนาดใหญ่ แต่ก็สามารถทำ Loop ได้
        debug!(
            "LlamaCppEngine: ประมวลผล Batch ขนาด {} รายการ (แบบลำดับ)",
            prompts.len()
        );
        let mut results = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            results.push(self.generate(prompt, max_tokens).await?);
        }
        Ok(results)
    }

    fn runtime_type(&self) -> InferenceRuntime {
        InferenceRuntime::LlamaCpp
    }
}

/// การเชื่อมต่อกับ TensorRT-LLM (มักสื่อสารผ่าน Unix Domain Socket (UDS) หรือ gRPC บน GPU)
pub struct TensorRtLlmEngine {
    socket_path: String,
}

impl TensorRtLlmEngine {
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

#[async_trait::async_trait]
impl AiEngine for TensorRtLlmEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        let res = self
            .generate_batch(&[prompt.to_string()], max_tokens)
            .await?;
        res.into_iter()
            .next()
            .ok_or_else(|| EngineError::Internal("ไม่มีผลลัพธ์กลับมา".into()))
    }

    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError> {
        info!(
            "TensorRtLlmEngine: Dispatching BATCH ขนาน {} รายการ ไปยัง UDS {} (MaxTokens: {})",
            prompts.len(),
            self.socket_path,
            max_tokens
        );
        // จำลอง Throughput มหาศาลของ GPU ด้วยเวลาประมวลผลที่สั้นมาก
        tokio::time::sleep(Duration::from_millis(30)).await;

        let results = prompts
            .iter()
            .map(|p| format!("[TensorRT-LLM Output]: {}", p))
            .collect();
        Ok(results)
    }

    fn runtime_type(&self) -> InferenceRuntime {
        InferenceRuntime::TensorRtLlm
    }
}
