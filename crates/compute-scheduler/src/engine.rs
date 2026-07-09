use crate::InferenceRuntime;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// ข้อผิดพลาดจากการเรียก inference engine ภายนอก (llama.cpp / vLLM / ONNX)
#[derive(Debug, Error)]
pub enum EngineError {
    /// เชื่อมต่อ engine ไม่สำเร็จ (เครือข่าย/socket)
    #[error("Inference engine connection failed: {0}")]
    ConnectionFailed(String),
    /// engine ไม่ตอบกลับภายในเวลาที่กำหนด
    #[error("Inference engine timeout")]
    Timeout,
    /// engine ตอบกลับด้วยข้อผิดพลาดภายใน
    #[error("Inference engine error: {0}")]
    Internal(String),
}

/// สร้าง HTTP client พร้อม timeout และ connection pool ที่กำหนด
pub(crate) fn build_http_client(timeout: Duration) -> Result<reqwest::Client, EngineError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(4)
        .build()
        .map_err(|e| EngineError::ConnectionFailed(format!("failed to create HTTP client: {e}")))
}

/// Abstraction สำหรับ AI Runtime Engine ทุกประเภท
#[async_trait::async_trait]
pub trait AiEngine: Send + Sync {
    /// สร้างข้อความตอบกลับจาก Prompt (Inference)
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError>;

    /// ประมวลผลแบบแบตช์ (Batch Processing)
    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError>;

    /// คืนค่าประเภทของ Inference Runtime
    fn runtime_type(&self) -> InferenceRuntime;

    /// ตรวจสอบว่า engine พร้อมใช้งานหรือไม่
    async fn is_healthy(&self) -> bool;
}

// ── llama.cpp HTTP Server Integration ──────────────────────────────

#[derive(Serialize)]
struct LlamaCppCompletionRequest {
    prompt: String,
    #[serde(rename = "n_predict")]
    n_predict: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
}

#[derive(Deserialize)]
struct LlamaCppCompletionResponse {
    content: String,
    #[serde(default)]
    #[allow(dead_code)]
    stop: bool,
    #[serde(default)]
    #[allow(dead_code)]
    tokens_predicted: Option<usize>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LlamaCppHealthResponse {
    status: String,
}

/// การเชื่อมต่อกับ Llama.cpp HTTP Server
/// รองรับทั้ง mode จริง (HTTP) และ fallback กลับไปใช้ mock เมื่อ server ไม่พร้อม
pub struct LlamaCppEngine {
    endpoint_url: String,
    client: reqwest::Client,
    /// Timeout สำหรับแต่ละ request
    request_timeout: Duration,
    /// โหมดจำลองเมื่อไม่สามารถเชื่อมต่อ server ได้
    fallback_mock: bool,
}

impl LlamaCppEngine {
    /// สร้าง engine ใหม่ที่เชื่อมต่อกับ llama.cpp server
    pub fn new(endpoint_url: impl Into<String>) -> Result<Self, EngineError> {
        let client = build_http_client(Duration::from_secs(60))?;

        Ok(Self {
            endpoint_url: endpoint_url.into(),
            client,
            request_timeout: Duration::from_secs(30),
            fallback_mock: std::env::var("ANK_COMPUTE_MOCK_FALLBACK")
                .ok()
                .and_then(|val| val.parse::<bool>().ok())
                .unwrap_or(true),
        })
    }

    /// กำหนด timeout สำหรับ request
    /// หากสร้าง client ใหม่ไม่สำเร็จ จะคงใช้ client เดิมและปรับเฉพาะ request timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        match build_http_client(timeout) {
            Ok(client) => self.client = client,
            Err(e) => warn!(error = %e, "keeping existing HTTP client after rebuild failure"),
        }
        self
    }

    /// ปิด fallback mock — จะ error ทันทีถ้า server ไม่พร้อม
    #[must_use]
    pub fn with_no_fallback(mut self) -> Self {
        self.fallback_mock = false;
        self
    }

    /// Health check — ตรวจสอบว่า llama.cpp server พร้อมรับงาน
    async fn check_health(&self) -> bool {
        let url = format!("{}/health", self.endpoint_url);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// เรียกใช้ llama.cpp /completion endpoint
    async fn call_completion(
        &self,
        prompt: &str,
        max_tokens: usize,
    ) -> Result<String, EngineError> {
        let url = format!("{}/completion", self.endpoint_url);

        let request = LlamaCppCompletionRequest {
            prompt: prompt.to_string(),
            n_predict: max_tokens,
            temperature: Some(0.7),
            stream: false,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    EngineError::Timeout
                } else {
                    EngineError::ConnectionFailed(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EngineError::Internal(format!("HTTP {status}: {body}")));
        }

        let completion: LlamaCppCompletionResponse = response
            .json()
            .await
            .map_err(|e| EngineError::Internal(format!("failed to parse response: {e}")))?;

        Ok(completion.content)
    }

    /// Fallback mock — ใช้เมื่อ server ไม่พร้อม (dev/test mode)
    fn mock_generate(prompt: &str, max_tokens: usize) -> String {
        let truncated = if prompt.len() > 50 {
            &prompt[..50]
        } else {
            prompt
        };
        format!("[llama.cpp mock] tokens_limit={max_tokens}: {truncated}...")
    }
}

#[async_trait::async_trait]
impl AiEngine for LlamaCppEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        info!(
            endpoint = %self.endpoint_url,
            prompt_len = prompt.len(),
            max_tokens,
            "LlamaCppEngine: generating"
        );

        match self.call_completion(prompt, max_tokens).await {
            Ok(text) => Ok(text),
            Err(e) if self.fallback_mock => {
                warn!(error = %e, "LlamaCppEngine: server unavailable, using mock fallback");
                Ok(Self::mock_generate(prompt, max_tokens))
            }
            Err(e) => Err(e),
        }
    }

    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError> {
        debug!(
            batch_size = prompts.len(),
            "LlamaCppEngine: processing batch sequentially"
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

    async fn is_healthy(&self) -> bool {
        self.check_health().await
    }
}

// ── TensorRT-LLM Engine ───────────────────────────────────────────

#[derive(Serialize)]
struct TensorRtBatchRequest {
    prompts: Vec<String>,
    #[serde(rename = "max_tokens")]
    max_tokens: usize,
}

#[derive(Deserialize)]
struct TensorRtBatchResponse {
    outputs: Vec<String>,
}

/// การเชื่อมต่อกับ TensorRT-LLM Server (มักสื่อสารผ่าน HTTP/gRPC หรือ UDS)
pub struct TensorRtLlmEngine {
    endpoint: String,
    client: reqwest::Client,
    fallback_mock: bool,
}

impl TensorRtLlmEngine {
    /// สร้าง engine ที่เชื่อมต่อกับ TensorRT-LLM server
    /// `endpoint` สามารถเป็น HTTP URL หรือ UDS path ก็ได้
    pub fn new(endpoint: impl Into<String>) -> Result<Self, EngineError> {
        let client = build_http_client(Duration::from_secs(120))?;

        Ok(Self {
            endpoint: endpoint.into(),
            client,
            fallback_mock: std::env::var("ANK_COMPUTE_MOCK_FALLBACK")
                .ok()
                .and_then(|val| val.parse::<bool>().ok())
                .unwrap_or(true),
        })
    }

    /// ปิด mock fallback — ถ้าเชื่อมต่อ engine จริงไม่ได้ให้คืน error แทนการจำลองผล
    #[must_use]
    pub fn with_no_fallback(mut self) -> Self {
        self.fallback_mock = false;
        self
    }

    fn mock_generate(prompt: &str, max_tokens: usize) -> String {
        let truncated = if prompt.len() > 50 {
            &prompt[..50]
        } else {
            prompt
        };
        format!("[TensorRT-LLM mock] tokens_limit={max_tokens}: {truncated}...")
    }
}

#[async_trait::async_trait]
impl AiEngine for TensorRtLlmEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        let results = self
            .generate_batch(&[prompt.to_string()], max_tokens)
            .await?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::Internal("no result returned".into()))
    }

    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError> {
        info!(
            endpoint = %self.endpoint,
            batch_size = prompts.len(),
            max_tokens,
            "TensorRtLlmEngine: dispatching batch"
        );

        let request = TensorRtBatchRequest {
            prompts: prompts.to_vec(),
            max_tokens,
        };

        match self.client.post(&self.endpoint).json(&request).send().await {
            Ok(resp) if resp.status().is_success() => {
                let batch_resp: TensorRtBatchResponse = resp
                    .json()
                    .await
                    .map_err(|e| EngineError::Internal(format!("failed to parse response: {e}")))?;
                Ok(batch_resp.outputs)
            }
            Ok(resp) if self.fallback_mock => {
                let status = resp.status();
                warn!(
                    status = %status,
                    "TensorRtLlmEngine: server returned error, using mock fallback"
                );
                Ok(prompts
                    .iter()
                    .map(|p| Self::mock_generate(p, max_tokens))
                    .collect())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(EngineError::Internal(format!("HTTP {status}: {body}")))
            }
            Err(e) if self.fallback_mock => {
                warn!(error = %e, "TensorRtLlmEngine: server unavailable, using mock fallback");
                Ok(prompts
                    .iter()
                    .map(|p| Self::mock_generate(p, max_tokens))
                    .collect())
            }
            Err(e) => {
                if e.is_timeout() {
                    Err(EngineError::Timeout)
                } else {
                    Err(EngineError::ConnectionFailed(e.to_string()))
                }
            }
        }
    }

    fn runtime_type(&self) -> InferenceRuntime {
        InferenceRuntime::TensorRtLlm
    }

    async fn is_healthy(&self) -> bool {
        match self.client.get(&self.endpoint).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_llama_cpp_engine_mock_fallback() {
        let engine = LlamaCppEngine::new("http://localhost:19876")
            .expect("engine")
            .with_no_fallback();
        assert_eq!(engine.runtime_type(), InferenceRuntime::LlamaCpp);

        // Server not running — should fail with no fallback
        let result = engine.generate("test", 10).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_llama_cpp_engine_with_fallback() {
        // Use a non-existent port — will use mock fallback
        let engine = LlamaCppEngine::new("http://localhost:19876").expect("engine");
        let result = engine.generate("hello world", 100).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("llama.cpp mock"));
    }

    #[tokio::test]
    async fn test_tensor_rt_engine_mock_fallback() {
        let engine = TensorRtLlmEngine::new("http://localhost:19877").expect("engine");
        let result = engine.generate("test prompt", 50).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("TensorRT-LLM mock"));
    }

    #[tokio::test]
    async fn test_tensor_rt_engine_batch_mock() {
        let engine = TensorRtLlmEngine::new("http://localhost:19877").expect("engine");
        let prompts = vec!["prompt A".to_string(), "prompt B".to_string()];
        let results = engine.generate_batch(&prompts, 20).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].contains("TensorRT-LLM mock"));
    }

    #[tokio::test]
    async fn test_health_check_returns_false_when_down() {
        let engine = LlamaCppEngine::new("http://localhost:19876").expect("engine");
        assert!(!engine.is_healthy().await);
    }
}
