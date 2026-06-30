use crate::InferenceRuntime;
use crate::engine::{AiEngine, EngineError};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

const DEFAULT_RETRY_MAX: u32 = 3;
const DEFAULT_RETRY_BASE_MS: u64 = 500;
const DEFAULT_RETRY_MAX_MS: u64 = 10_000;

#[derive(Debug, Clone)]
pub struct RetryConfig {
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_RETRY_MAX,
            base_delay_ms: DEFAULT_RETRY_BASE_MS,
            max_delay_ms: DEFAULT_RETRY_MAX_MS,
        }
    }
}

fn backoff_ms(attempt: u32, config: &RetryConfig) -> u64 {
    let delay = config.base_delay_ms * 2u64.pow(attempt);
    delay.min(config.max_delay_ms)
}

fn jitter_ms(base: u64) -> u64 {
    let jitter = fastrand::u64(0..=base.saturating_div(2));
    base.saturating_add(jitter)
}

async fn retry<F, Fut, T>(config: &RetryConfig, operation: F) -> Result<T, EngineError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, EngineError>>,
{
    let mut last_err = None;
    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < config.max_retries {
                    let delay_ms = backoff_ms(attempt, config);
                    let sleep_ms = jitter_ms(delay_ms);
                    warn!(
                        attempt,
                        error = %e,
                        retry_ms = sleep_ms,
                        "CloudAiEngine: retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| EngineError::Internal("retry exhausted".into())))
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
    max_tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    stream: bool,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CloudHealthResponse {
    status: String,
}

pub struct CloudAiEngine {
    endpoint_url: String,
    api_key: String,
    model: String,
    client: reqwest::Client,
    request_timeout: Duration,
    retry_config: RetryConfig,
    fallback_mock: bool,
}

impl CloudAiEngine {
    #[must_use]
    pub fn new(
        endpoint_url: impl Into<String>,
        api_key: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to create HTTP client");

        Self {
            endpoint_url: endpoint_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            client,
            request_timeout: Duration::from_secs(60),
            retry_config: RetryConfig::default(),
            fallback_mock: std::env::var("ANK_COMPUTE_MOCK_FALLBACK")
                .ok()
                .and_then(|val| val.parse::<bool>().ok())
                .unwrap_or(true),
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self.client = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to create HTTP client");
        self
    }

    #[must_use]
    pub fn with_no_fallback(mut self) -> Self {
        self.fallback_mock = false;
        self
    }

    #[must_use]
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    async fn call_chat_completion(
        &self,
        prompt: &str,
        max_tokens: usize,
    ) -> Result<String, EngineError> {
        let url = format!("{}/v1/chat/completions", self.endpoint_url);

        let request = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens,
            temperature: Some(0.7),
            stream: false,
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
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

        let completion: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| EngineError::Internal(format!("failed to parse response: {e}")))?;

        completion
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| EngineError::Internal("no choices in response".into()))
    }

    async fn check_health(&self) -> bool {
        let url = format!("{}/v1/chat/completions", self.endpoint_url);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    fn mock_generate(prompt: &str, max_tokens: usize, model: &str) -> String {
        let truncated = if prompt.len() > 50 {
            &prompt[..50]
        } else {
            prompt
        };
        format!("[cloud mock] model={model} tokens_limit={max_tokens}: {truncated}...")
    }
}

#[async_trait::async_trait]
impl AiEngine for CloudAiEngine {
    async fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String, EngineError> {
        info!(
            endpoint = %self.endpoint_url,
            model = %self.model,
            prompt_len = prompt.len(),
            max_tokens,
            "CloudAiEngine: generating"
        );

        let result = retry(&self.retry_config, || async {
            self.call_chat_completion(prompt, max_tokens).await
        })
        .await;

        match result {
            Ok(text) => Ok(text),
            Err(e) if self.fallback_mock => {
                warn!(error = %e, "CloudAiEngine: server unavailable, using mock fallback");
                Ok(Self::mock_generate(prompt, max_tokens, &self.model))
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
            "CloudAiEngine: processing batch sequentially"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> CloudAiEngine {
        CloudAiEngine::new("http://localhost:19000", "sk-test-key", "gpt-4o-mini")
    }

    #[tokio::test]
    async fn test_cloud_engine_mock_fallback() {
        let engine = test_engine().with_no_fallback();
        assert_eq!(engine.runtime_type(), InferenceRuntime::LlamaCpp);

        let result = engine.generate("test prompt", 50).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cloud_engine_with_fallback() {
        let engine = test_engine();
        let result = engine.generate("hello cloud", 100).await;
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("cloud mock"));
        assert!(text.contains("gpt-4o-mini"));
    }

    #[tokio::test]
    async fn test_cloud_engine_batch_mock() {
        let engine = test_engine();
        let prompts = vec!["prompt A".to_string(), "prompt B".to_string()];
        let results = engine.generate_batch(&prompts, 20).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].contains("cloud mock"));
        assert!(results[1].contains("cloud mock"));
    }

    #[tokio::test]
    async fn test_health_check_returns_false_when_down() {
        let engine = test_engine();
        assert!(!engine.is_healthy().await);
    }

    #[tokio::test]
    async fn test_retry_eventually_succeeds() {
        let attempt = std::sync::atomic::AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 3,
            base_delay_ms: 10,
            max_delay_ms: 100,
        };

        let result = retry(&config, || async {
            let prev = attempt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if prev < 2 {
                Err(EngineError::ConnectionFailed("not ready".into()))
            } else {
                Ok("success".to_string())
            }
        })
        .await;

        assert_eq!(result.unwrap(), "success");
    }

    #[tokio::test]
    async fn test_retry_exhausted_returns_error() {
        let attempt = std::sync::atomic::AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 2,
            base_delay_ms: 10,
            max_delay_ms: 100,
        };

        let result = retry(&config, || async {
            attempt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err::<String, EngineError>(EngineError::ConnectionFailed("always fails".into()))
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempt.load(std::sync::atomic::Ordering::Relaxed), 3); // 0, 1, 2
    }

    #[test]
    fn test_backoff_ms() {
        let config = RetryConfig::default();
        assert_eq!(backoff_ms(0, &config), 500);
        assert_eq!(backoff_ms(1, &config), 1000);
        assert_eq!(backoff_ms(2, &config), 2000);
        assert_eq!(backoff_ms(3, &config), 4000);
        assert_eq!(backoff_ms(4, &config), 8000);
        assert_eq!(backoff_ms(5, &config), 10_000); // capped
    }

    #[test]
    fn test_jitter_ms_in_range() {
        for base in [100, 500, 1000].iter() {
            for _ in 0..100 {
                let j = jitter_ms(*base);
                assert!(j >= *base, "jitter should not be less than base");
                assert!(
                    j <= base.saturating_add(base / 2),
                    "jitter should not exceed base + 50%"
                );
            }
        }
    }
}
