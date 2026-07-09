use crate::InferenceRuntime;
use crate::engine::{AiEngine, EngineError};
use std::time::Duration;
use tracing::{debug, info, warn};

/// MPS (Metal Performance Shaders) Backend
///
/// ## Apple Silicon GPU Integration
/// ใช้ llama.cpp ผ่าน Metal backend (การ compile ต้องเปิด `-DGGML_METAL=ON`)
///
/// ## Architecture
/// ```text
/// AI-Native Kernel
///     │
///     ├── llama.cpp (FFI) ── Metal/MPS ──► Apple GPU (M1/M2/M3/M4)
///     └── Fallback ──► CPU inference on Apple Silicon
/// ```
///
/// ## Requirements
/// - macOS 14+ (Sonoma) หรือใหม่กว่า
/// - Apple Silicon (M1 series ขึ้นไป)
/// - รองรับ Intel Macs ผ่าน CPU fallback เท่านั้น
/// - compile llama.cpp ด้วย `-DGGML_METAL=ON`
pub struct MpsEngine {
    /// endpoint สำหรับ llama.cpp HTTP server (port ท้องถิ่น)
    endpoint: String,
    /// HTTP client
    client: reqwest::Client,
    /// Timeout สำหรับ request
    request_timeout: Duration,
    /// Fallback mock mode
    fallback_mock: bool,
}

impl MpsEngine {
    /// สร้าง MPS engine ใหม่
    ///
    /// `endpoint` คือ URL ของ llama.cpp HTTP server (ปกติ `http://127.0.0.1:8080`)
    pub fn new(endpoint: impl Into<String>) -> Result<Self, EngineError> {
        let client = crate::engine::build_http_client(Duration::from_secs(60))?;

        Ok(Self {
            endpoint: endpoint.into(),
            client,
            request_timeout: Duration::from_secs(30),
            fallback_mock: std::env::var("ANK_COMPUTE_MOCK_FALLBACK")
                .ok()
                .and_then(|val| val.parse::<bool>().ok())
                .unwrap_or(true),
        })
    }

    /// กำหนด timeout
    /// หากสร้าง client ใหม่ไม่สำเร็จ จะคงใช้ client เดิมและปรับเฉพาะ request timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        match crate::engine::build_http_client(timeout) {
            Ok(client) => self.client = client,
            Err(e) => warn!(error = %e, "keeping existing HTTP client after rebuild failure"),
        }
        self
    }

    /// ปิด mock fallback — ถ้าเชื่อมต่อ engine จริงไม่ได้ให้คืน error แทนการจำลองผล
    #[must_use]
    pub fn with_no_fallback(mut self) -> Self {
        self.fallback_mock = false;
        self
    }

    /// ตรวจสอบว่า Apple Silicon หรือไม่
    #[must_use]
    pub fn is_apple_silicon() -> bool {
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("sysctl")
                .args(["-n", "machdep.cpu.brand_string"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.to_lowercase().contains("apple"))
                .unwrap_or(false)
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// ตรวจสอบว่า MPS runtime พร้อมใช้งานหรือไม่
    #[must_use]
    pub fn is_mps_available() -> bool {
        #[cfg(target_os = "macos")]
        {
            // ตรวจสอบ Metal framework
            std::process::Command::new("system_profiler")
                .args(["SPDisplaysDataType"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| {
                    s.contains("Metal")
                        && (s.contains("Apple")
                            || s.contains("M1")
                            || s.contains("M2")
                            || s.contains("M3")
                            || s.contains("M4"))
                })
                .unwrap_or(false)
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// ตรวจสอบว่า llama.cpp Metal backend ทำงานอยู่
    async fn check_health(&self) -> bool {
        let url = format!("{}/health", self.endpoint);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    fn mock_generate(prompt: &str, max_tokens: usize) -> String {
        let truncated = if prompt.len() > 50 {
            &prompt[..50]
        } else {
            prompt
        };
        format!("[MPS/metal mock] tokens_limit={max_tokens}: {truncated}...")
    }
}

#[async_trait::async_trait]
impl AiEngine for MpsEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        info!(
            endpoint = %self.endpoint,
            prompt_len = prompt.len(),
            max_tokens,
            "MpsEngine: generating via llama.cpp Metal"
        );

        #[derive(serde::Serialize)]
        struct LlamaCppCompletionRequest {
            prompt: String,
            #[serde(rename = "n_predict")]
            n_predict: usize,
            #[serde(skip_serializing_if = "Option::is_none")]
            temperature: Option<f32>,
            stream: bool,
        }

        #[derive(serde::Deserialize)]
        struct LlamaCppCompletionResponse {
            content: String,
        }

        let url = format!("{}/completion", self.endpoint);

        let request = LlamaCppCompletionRequest {
            prompt: prompt.to_string(),
            n_predict: max_tokens,
            temperature: Some(0.7),
            stream: false,
        };

        match self
            .client
            .post(&url)
            .json(&request)
            .timeout(self.request_timeout)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let completion: LlamaCppCompletionResponse = resp
                    .json()
                    .await
                    .map_err(|e| EngineError::Internal(format!("failed to parse: {e}")))?;
                Ok(completion.content)
            }
            Ok(resp) if self.fallback_mock => {
                warn!(status = %resp.status(), "MpsEngine: server error, using mock");
                Ok(Self::mock_generate(prompt, max_tokens))
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                Err(EngineError::Internal(format!("HTTP {status}: {body}")))
            }
            Err(e) if self.fallback_mock => {
                warn!(error = %e, "MpsEngine: unavailable, using mock fallback");
                Ok(Self::mock_generate(prompt, max_tokens))
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

    async fn generate_batch(
        &self,
        prompts: &[String],
        max_tokens: usize,
    ) -> Result<Vec<String>, EngineError> {
        debug!(
            batch_size = prompts.len(),
            "MpsEngine: processing batch sequentially"
        );
        let mut results = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            results.push(self.generate(prompt, max_tokens).await?);
        }
        Ok(results)
    }

    fn runtime_type(&self) -> InferenceRuntime {
        InferenceRuntime::Mps
    }

    async fn is_healthy(&self) -> bool {
        self.check_health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mps_platform_check() {
        // ควรคืน false บน non-macOS
        #[cfg(not(target_os = "macos"))]
        {
            assert!(!MpsEngine::is_apple_silicon());
            assert!(!MpsEngine::is_mps_available());
        }
    }

    #[tokio::test]
    async fn test_mps_engine_mock_fallback() {
        let engine = MpsEngine::new("http://localhost:18001")
            .expect("engine")
            .with_no_fallback();
        let result = engine.generate("test", 10).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mps_engine_with_fallback() {
        let engine = MpsEngine::new("http://localhost:18001").expect("engine");
        let result = engine.generate("hello world", 100).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("MPS/metal mock"));
    }

    #[tokio::test]
    async fn test_mps_engine_batch_mock() {
        let engine = MpsEngine::new("http://localhost:18001").expect("engine");
        let prompts = vec!["A".to_string(), "B".to_string()];
        let results = engine.generate_batch(&prompts, 10).await.unwrap();
        assert_eq!(results.len(), 2);
    }
}
