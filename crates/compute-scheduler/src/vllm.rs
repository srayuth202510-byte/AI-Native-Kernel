use crate::InferenceRuntime;
use crate::engine::{AiEngine, EngineError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// vLLM Model Identifier — รองรับหลายรุ่นโมเดล
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VllmModelConfig {
    /// ชื่อ/พาธของโมเดล (เช่น "Qwen/Qwen2.5-7B-Instruct")
    pub model: String,
    /// ขนาด tensor parallel (GPU count)
    pub tensor_parallel_size: usize,
    /// CUDA device IDs (เช่น "0,1")
    pub cuda_devices: Option<String>,
    /// ขนาด GPU memory utilization (0.0–1.0)
    pub gpu_memory_utilization: f64,
    /// ขนาด maximum model len (tokens)
    pub max_model_len: usize,
    /// dtype สำหรับ weight (auto, half, float16, bfloat16)
    pub dtype: String,
}

impl Default for VllmModelConfig {
    fn default() -> Self {
        Self {
            model: "Qwen/Qwen2.5-7B-Instruct".to_string(),
            tensor_parallel_size: 1,
            cuda_devices: None,
            gpu_memory_utilization: 0.85,
            max_model_len: 4096,
            dtype: "auto".to_string(),
        }
    }
}

/// ข้อผิดพลาดของ vLLM subprocess
#[derive(Debug, thiserror::Error)]
pub enum VllmError {
    /// หา vLLM binary ไม่พบบนระบบ
    #[error("vLLM binary not found: {0}")]
    BinaryNotFound(String),
    /// vLLM subprocess เริ่มทำงานไม่สำเร็จ
    #[error("vLLM failed to start: {0}")]
    StartFailed(String),
    /// vLLM process ตายระหว่างทำงาน
    #[error("vLLM process died: {0}")]
    ProcessDied(String),
    /// เรียก HTTP API ของ vLLM ล้มเหลว
    #[error("HTTP request failed: {0}")]
    HttpError(String),
}

/// vLLM Subprocess Engine
///
/// จัดการ vLLM เป็น subprocess ที่รันด้วย Python
/// รองรับ NVIDIA CUDA และ AMD ROCm 6+
///
/// ## Architecture
/// ```text
/// AI-Native Kernel ──tokio::process──► vLLM (Python subprocess)
///                                        │
///                                        ├── NVIDIA GPU (CUDA)
///                                        └── AMD GPU (ROCm 6+)
///                                        ── HTTP API (OpenAI-compatible)
/// ```
///
/// ## การติดตั้ง vLLM
/// - NVIDIA: `pip install vllm`
/// - AMD ROCm: `pip install vllm-rocm`
pub struct VllmEngine {
    /// HTTP endpoint ของ vLLM (OpenAI-compatible)
    endpoint: String,
    /// HTTP client
    client: reqwest::Client,
    /// Process handle (ถ้ากำลังจัดการ subprocess เอง)
    process: Arc<Mutex<Option<Child>>>,
    /// Timeout สำหรับ request
    request_timeout: Duration,
    /// Fallback mock mode
    fallback_mock: bool,
}

impl VllmEngine {
    /// สร้าง vLLM engine จาก endpoint URL ที่มีอยู่แล้ว
    pub fn new(endpoint: impl Into<String>) -> Result<Self, EngineError> {
        let client = crate::engine::build_http_client(Duration::from_secs(120))?;

        Ok(Self {
            endpoint: endpoint.into(),
            client,
            process: Arc::new(Mutex::new(None)),
            request_timeout: Duration::from_secs(60),
            fallback_mock: std::env::var("ANK_COMPUTE_MOCK_FALLBACK")
                .ok()
                .and_then(|val| val.parse::<bool>().ok())
                .unwrap_or(true),
        })
    }

    /// ตั้งค่า timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// ปิด mock fallback
    #[must_use]
    pub fn with_no_fallback(mut self) -> Self {
        self.fallback_mock = false;
        self
    }

    /// เริ่ม vLLM เป็น subprocess
    ///
    /// # Arguments
    /// * `vllm_bin` — path/command สำหรับ vLLM (default: "vllm")
    /// * `config` — การตั้งค่าโมเดล
    ///
    /// # Errors
    /// คืน `VllmError::BinaryNotFound` ถ้าหา vLLM ไม่เจอ
    pub async fn start(&self, vllm_bin: &str, config: &VllmModelConfig) -> Result<(), VllmError> {
        let mut cmd = Command::new(vllm_bin);

        // Detect AMD ROCm vs NVIDIA CUDA
        let platform_flag =
            if std::env::var("ROCM_HOME").is_ok() || std::env::var("HIP_VISIBLE_DEVICES").is_ok() {
                "--rocm".to_string()
            } else {
                "--trust-remote-code".to_string()
            };

        cmd.arg("serve")
            .arg(&config.model)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg("8000")
            .arg("--tensor-parallel-size")
            .arg(config.tensor_parallel_size.to_string())
            .arg("--gpu-memory-utilization")
            .arg(config.gpu_memory_utilization.to_string())
            .arg("--max-model-len")
            .arg(config.max_model_len.to_string())
            .arg("--dtype")
            .arg(&config.dtype);

        if config.tensor_parallel_size > 1 {
            cmd.arg("--pipeline-parallel-size")
                .arg(config.tensor_parallel_size.to_string());
        }

        cmd.arg(&platform_flag);

        if let Some(ref devices) = config.cuda_devices {
            cmd.env("CUDA_VISIBLE_DEVICES", devices);
        }

        // ROCm specific
        if std::env::var("ROCM_HOME").is_ok() {
            cmd.env("HSA_OVERRIDE_GFX_VERSION", "11.0.0");
        }

        let child = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    VllmError::BinaryNotFound(vllm_bin.to_string())
                } else {
                    VllmError::StartFailed(e.to_string())
                }
            })?;

        let mut process = self.process.lock().await;
        *process = Some(child);

        info!(
            model = %config.model,
            tensor_parallel = %config.tensor_parallel_size,
            "vLLM subprocess started"
        );

        Ok(())
    }

    /// เรียก vLLM /v1/completions endpoint
    async fn call_completion(
        &self,
        prompt: &str,
        max_tokens: usize,
    ) -> Result<String, EngineError> {
        let url = format!("{}/v1/completions", self.endpoint);

        #[derive(Serialize)]
        struct VllmCompletionRequest {
            prompt: String,
            max_tokens: usize,
            temperature: f64,
            stream: bool,
        }

        #[derive(Deserialize)]
        struct VllmCompletionResponse {
            choices: Vec<VllmChoice>,
        }

        #[derive(Deserialize)]
        struct VllmChoice {
            text: String,
        }

        let request = VllmCompletionRequest {
            prompt: prompt.to_string(),
            max_tokens,
            temperature: 0.7,
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

        let completion: VllmCompletionResponse = response
            .json()
            .await
            .map_err(|e| EngineError::Internal(format!("failed to parse response: {e}")))?;

        completion
            .choices
            .into_iter()
            .next()
            .map(|c| c.text)
            .ok_or_else(|| EngineError::Internal("no completion choices returned".to_string()))
    }

    fn mock_generate(prompt: &str, max_tokens: usize) -> String {
        let truncated = if prompt.len() > 50 {
            &prompt[..50]
        } else {
            prompt
        };
        format!("[vLLM mock] tokens_limit={max_tokens}: {truncated}...")
    }

    /// คืน HTTP endpoint
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[async_trait::async_trait]
impl AiEngine for VllmEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        info!(
            endpoint = %self.endpoint,
            prompt_len = prompt.len(),
            max_tokens,
            "VllmEngine: generating"
        );

        match self.call_completion(prompt, max_tokens).await {
            Ok(text) => Ok(text),
            Err(e) if self.fallback_mock => {
                warn!(error = %e, "VllmEngine: server unavailable, using mock fallback");
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
            "VllmEngine: processing batch sequentially"
        );
        let mut results = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            results.push(self.generate(prompt, max_tokens).await?);
        }
        Ok(results)
    }

    fn runtime_type(&self) -> InferenceRuntime {
        InferenceRuntime::Vllm
    }

    async fn is_healthy(&self) -> bool {
        let url = format!("{}/health", self.endpoint);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vllm_engine_no_fallback() {
        let engine = VllmEngine::new("http://localhost:18000")
            .expect("engine")
            .with_no_fallback();
        assert_eq!(engine.runtime_type(), InferenceRuntime::Vllm);

        let result = engine.generate("test", 10).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vllm_engine_with_fallback() {
        let engine = VllmEngine::new("http://localhost:18000").expect("engine");
        let result = engine.generate("hello world", 100).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("vLLM mock"));
    }

    #[tokio::test]
    async fn test_vllm_engine_batch_mock() {
        let engine = VllmEngine::new("http://localhost:18000").expect("engine");
        let prompts = vec!["prompt A".to_string(), "prompt B".to_string()];
        let results = engine.generate_batch(&prompts, 20).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_vllm_health_check_returns_false_when_down() {
        let engine = VllmEngine::new("http://localhost:18000").expect("engine");
        assert!(!engine.is_healthy().await);
    }

    #[test]
    fn test_vllm_model_config_default() {
        let config = VllmModelConfig::default();
        assert_eq!(config.model, "Qwen/Qwen2.5-7B-Instruct");
        assert_eq!(config.tensor_parallel_size, 1);
        assert_eq!(config.max_model_len, 4096);
    }
}
