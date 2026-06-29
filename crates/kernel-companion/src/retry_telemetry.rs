use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub backoff_multiplier: f64,
    pub max_backoff_ms: u64,
    pub timeout_ms: u64,
    pub use_jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
            backoff_multiplier: 2.0,
            max_backoff_ms: 10_000,
            timeout_ms: 5_000,
            use_jitter: true,
        }
    }
}

impl RetryConfig {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_attempts: u32,
        initial_backoff_ms: u64,
        backoff_multiplier: f64,
        max_backoff_ms: u64,
        timeout_ms: u64,
        use_jitter: bool,
    ) -> Self {
        Self {
            max_attempts,
            initial_backoff_ms,
            backoff_multiplier,
            max_backoff_ms,
            timeout_ms,
            use_jitter,
        }
    }

    pub async fn retry_with_backoff<F, Fut, T, E>(
        &self,
        f: F,
        operation_name: Option<&str>,
    ) -> anyhow::Result<T>
    where
        F: Fn() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
        E: std::fmt::Display + Send + Sync + 'static,
        T: Send + 'static,
    {
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 0..=self.max_attempts {
            let start = Instant::now();

            match timeout(Duration::from_millis(self.timeout_ms), f()).await {
                Ok(Ok(result)) => {
                    if attempt > 0 {
                        let op_name = operation_name.unwrap_or("operation");
                        tracing::debug!(
                            attempt = attempt + 1,
                            elapsed_ms = start.elapsed().as_millis(),
                            "Retry successful: {op_name}",
                        );
                    }
                    return Ok(result);
                }
                Ok(Err(e)) => {
                    last_error = Some(anyhow::anyhow!("{}", e));
                    if attempt == self.max_attempts {
                        break;
                    }
                }
                Err(_) => {
                    let op_name = operation_name.unwrap_or("operation");
                    tracing::warn!(
                        attempt = attempt + 1,
                        timeout_ms = start.elapsed().as_millis(),
                        "Operation timed out: {op_name}",
                    );
                    last_error = Some(anyhow::anyhow!("Operation timed out"));
                    if attempt == self.max_attempts {
                        break;
                    }
                }
            }

            if attempt < self.max_attempts {
                let backoff_ms = self.calculate_backoff(attempt + 1);
                let jitter = self.jitter(backoff_ms, attempt);

                let op_name = operation_name.unwrap_or("operation");
                tracing::info!(
                    attempt = attempt + 1,
                    backoff_ms = jitter,
                    "Retrying operation: {op_name}",
                );

                sleep(Duration::from_millis(jitter)).await;
            }
        }

        let op_name = operation_name.unwrap_or("operation");
        let msg = match last_error {
            Some(e) => format!(
                "{e}: failed {op_name} after {max} attempts",
                max = self.max_attempts + 1
            ),
            None => format!(
                "{op_name} failed unexpectedly after {max} attempts",
                max = self.max_attempts + 1
            ),
        };
        Err(anyhow::anyhow!(msg))
    }

    fn jitter(&self, backoff_ms: u64, attempt: u32) -> u64 {
        if !self.use_jitter {
            return backoff_ms;
        }
        let range = (backoff_ms as f64 * 0.1) as u64;
        if range == 0 {
            return backoff_ms;
        }
        let seed = u64::from(attempt)
            .wrapping_mul(1103515245)
            .wrapping_add(12345)
            ^ backoff_ms;
        let offset = seed.wrapping_mul(6364136223846793005) % (range * 2 + 1);
        (backoff_ms as i64 + offset as i64 - range as i64).clamp(1, i64::MAX) as u64
    }

    fn calculate_backoff(&self, attempt: u32) -> u64 {
        let ms =
            self.initial_backoff_ms as f64 * self.backoff_multiplier.powi((attempt - 1) as i32);
        (ms as u64).min(self.max_backoff_ms)
    }
}

#[derive(Debug, Clone)]
pub struct TelemetryTTLConfig {
    pub metric_cache_ttl_ms: u64,
    pub telemetry_snapshot_ttl_ms: u64,
    pub audit_log_ttl_ms: u64,
    pub intent_metadata_ttl_ms: u64,
    pub cleanup_interval_ms: u64,
    pub telemetry_publish_interval_ms: u64,
    pub include_timestamps: bool,
    pub auto_cleanup: bool,
}

impl Default for TelemetryTTLConfig {
    fn default() -> Self {
        Self {
            metric_cache_ttl_ms: 300_000,
            telemetry_snapshot_ttl_ms: 60_000,
            audit_log_ttl_ms: 86_400_000,
            intent_metadata_ttl_ms: 300_000,
            cleanup_interval_ms: 60_000,
            telemetry_publish_interval_ms: 2_000,
            include_timestamps: true,
            auto_cleanup: true,
        }
    }
}

impl TelemetryTTLConfig {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metric_cache_ttl_ms: u64,
        telemetry_snapshot_ttl_ms: u64,
        audit_log_ttl_ms: u64,
        intent_metadata_ttl_ms: u64,
        cleanup_interval_ms: u64,
        telemetry_publish_interval_ms: u64,
        include_timestamps: bool,
        auto_cleanup: bool,
    ) -> Self {
        Self {
            metric_cache_ttl_ms,
            telemetry_snapshot_ttl_ms,
            audit_log_ttl_ms,
            intent_metadata_ttl_ms,
            cleanup_interval_ms,
            telemetry_publish_interval_ms,
            include_timestamps,
            auto_cleanup,
        }
    }

    #[allow(dead_code)]
    fn is_expired(&self, timestamp: Instant, ttl_ms: u64) -> bool {
        timestamp.elapsed().as_millis() as u64 > ttl_ms
    }

    #[allow(dead_code)]
    async fn cleanup_expired_entries<T1, T2, T3, T4>(
        &self,
        _metric_cache: Arc<RwLock<T1>>,
        _telemetry_snapshots: Arc<RwLock<T2>>,
        _audit_entries: Arc<RwLock<T3>>,
        _intent_metadata: Arc<RwLock<T4>>,
    ) -> usize {
        0
    }
}

impl Default for RetryAndTelemetryManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RetryAndTelemetryManager {
    retry_config: RetryConfig,
    telemetry_ttl_config: TelemetryTTLConfig,
}

impl RetryAndTelemetryManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            retry_config: RetryConfig::default(),
            telemetry_ttl_config: TelemetryTTLConfig::default(),
        }
    }

    #[must_use]
    pub fn with_configs(
        retry_config: RetryConfig,
        telemetry_ttl_config: TelemetryTTLConfig,
    ) -> Self {
        Self {
            retry_config,
            telemetry_ttl_config,
        }
    }

    #[must_use]
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    #[must_use]
    pub fn retry_config_mut(&mut self) -> &mut RetryConfig {
        &mut self.retry_config
    }

    #[must_use]
    pub fn telemetry_ttl_config(&self) -> &TelemetryTTLConfig {
        &self.telemetry_ttl_config
    }

    #[must_use]
    pub fn telemetry_ttl_config_mut(&mut self) -> &mut TelemetryTTLConfig {
        &mut self.telemetry_ttl_config
    }

    pub async fn execute_with_retry<F, Fut, T, E>(
        &self,
        f: F,
        operation_name: Option<&str>,
    ) -> anyhow::Result<T>
    where
        F: Fn() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
        E: std::fmt::Display + Send + Sync + 'static,
        T: Send + 'static,
    {
        self.retry_config
            .retry_with_backoff(f, operation_name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert_eq!(config.max_backoff_ms, 10_000);
        assert_eq!(config.timeout_ms, 5_000);
        assert!(config.use_jitter);
    }

    #[tokio::test]
    async fn test_retry_with_backoff_success_immediate() {
        let config = RetryConfig::default();
        let counter = Arc::new(tokio::sync::Mutex::new(0));
        let counter_clone = Arc::clone(&counter);

        let result = config
            .retry_with_backoff(
                move || {
                    let counter = Arc::clone(&counter_clone);
                    async move {
                        let mut val = counter.lock().await;
                        *val += 1;
                        if *val < 3 {
                            Err(anyhow::anyhow!("Attempt failed"))
                        } else {
                            Ok(42)
                        }
                    }
                },
                Some("test_operation"),
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(*counter.lock().await, 3);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let config = RetryConfig::default();
        let attempts = Arc::new(tokio::sync::Mutex::new(0));
        let attempts_moved = Arc::clone(&attempts);

        let result: anyhow::Result<i32> = config
            .retry_with_backoff(
                move || {
                    let attempts_clone = Arc::clone(&attempts_moved);
                    async move {
                        let mut val = attempts_clone.lock().await;
                        *val += 1;
                        Err(anyhow::anyhow!("Always fail"))
                    }
                },
                Some("failing_operation"),
            )
            .await;

        assert!(result.is_err());
        assert_eq!(*attempts.lock().await, 4);
    }

    #[test]
    fn test_calculate_backoff() {
        let config = RetryConfig::default();
        assert_eq!(config.calculate_backoff(1), 100);
        assert_eq!(config.calculate_backoff(2), 200);
        assert_eq!(config.calculate_backoff(3), 400);
        assert_eq!(config.calculate_backoff(4), 800);
        assert_eq!(config.calculate_backoff(5), 1600);
        assert_eq!(config.calculate_backoff(6), 3200);
        assert_eq!(config.calculate_backoff(7), 6400);
        assert_eq!(config.calculate_backoff(8), 10000);
        assert_eq!(config.calculate_backoff(9), 10000);
    }

    #[tokio::test]
    async fn test_telemetry_ttl_config_default() {
        let config = TelemetryTTLConfig::default();
        assert_eq!(config.metric_cache_ttl_ms, 300_000);
        assert_eq!(config.telemetry_snapshot_ttl_ms, 60_000);
        assert_eq!(config.audit_log_ttl_ms, 86_400_000);
        assert_eq!(config.intent_metadata_ttl_ms, 300_000);
        assert_eq!(config.cleanup_interval_ms, 60_000);
        assert_eq!(config.telemetry_publish_interval_ms, 2_000);
        assert!(config.include_timestamps);
        assert!(config.auto_cleanup);
    }

    #[test]
    fn test_telemetry_ttl_is_expired() {
        let config = TelemetryTTLConfig::default();
        let timestamp = Instant::now() - Duration::from_millis(1500);
        assert!(config.is_expired(timestamp, 1000));
        let timestamp = Instant::now();
        assert!(!config.is_expired(timestamp, 5_000_000));
    }

    #[tokio::test]
    async fn test_retry_and_telemetry_manager_new() {
        let manager = RetryAndTelemetryManager::new();
        assert_eq!(manager.retry_config().max_attempts, 3);
        assert!(manager.telemetry_ttl_config().auto_cleanup);
    }
}
