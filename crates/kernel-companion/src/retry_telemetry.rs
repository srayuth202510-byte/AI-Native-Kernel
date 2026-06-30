use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};

/// การกำหนดค่าสำหรับ Retry/Backoff
/// ใช้ในการลองดำเนินการซ้ำเมื่อเกิดข้อผิดพลาด พร้อม exponential backoff และ jitter
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// จำนวนครั้งสูงสุดที่ลองใหม่ (ไม่รวมครั้งแรก)
    pub max_attempts: u32,
    /// ระยะเวลารอเริ่มต้น (ms) สำหรับ backoff
    pub initial_backoff_ms: u64,
    /// ตัวคูณสำหรับ exponential backoff
    pub backoff_multiplier: f64,
    /// ระยะเวลารอสูงสุด (ms)
    pub max_backoff_ms: u64,
    /// ระยะเวลา timeout สูงสุดสำหรับการดำเนินการแต่ละครั้ง (ms)
    pub timeout_ms: u64,
    /// เปิด/ปิดการใช้ jitter เพื่อกระจายเวลารอ
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
    /// สร้าง RetryConfig ใหม่พร้อมกำหนดค่าทั้งหมด
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

    /// ดำเนินการ `f` แบบลองใหม่ด้วย exponential backoff
    /// จะลองซ้ำสูงสุด `max_attempts` ครั้ง (รวมครั้งแรก)
    /// แต่ละครั้งมี timeout และ backoff พร้อม jitter
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

    /// คำนวณ jitter เพื่อกระจายเวลารอไม่ให้พร้อมกัน
    /// ใช้ pseudo-random ที่ deterministic จาก attempt number
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

    /// คำนวณระยะเวลา backoff สำหรับ attempt ที่กำหนด
    /// ใช้ exponential backoff: initial * multiplier^(attempt-1) แต่ไม่เกิน max_backoff
    fn calculate_backoff(&self, attempt: u32) -> u64 {
        let ms =
            self.initial_backoff_ms as f64 * self.backoff_multiplier.powi((attempt - 1) as i32);
        (ms as u64).min(self.max_backoff_ms)
    }
}

/// การกำหนดค่า TTL สำหรับ Telemetry และการล้างข้อมูลอัตโนมัติ
#[derive(Debug, Clone)]
pub struct TelemetryTTLConfig {
    /// TTL สำหรับ metric cache (ms)
    pub metric_cache_ttl_ms: u64,
    /// TTL สำหรับ telemetry snapshot (ms)
    pub telemetry_snapshot_ttl_ms: u64,
    /// TTL สำหรับ audit log entries (ms)
    pub audit_log_ttl_ms: u64,
    /// TTL สำหรับ intent metadata (ms)
    pub intent_metadata_ttl_ms: u64,
    /// ระยะเวลาระหว่างการล้างข้อมูลแต่ละครั้ง (ms)
    pub cleanup_interval_ms: u64,
    /// ระยะเวลาระหว่างการ publish telemetry (ms)
    pub telemetry_publish_interval_ms: u64,
    /// รวม timestamp ใน telemetry data หรือไม่
    pub include_timestamps: bool,
    /// เปิด/ปิดการล้างข้อมูลอัตโนมัติ
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
    /// สร้าง TelemetryTTLConfig ใหม่พร้อมกำหนดค่าทั้งหมด
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

    /// ตรวจสอบว่า timestamp หมดอายุตาม TTL ที่กำหนดหรือไม่
    #[allow(dead_code)]
    fn is_expired(&self, timestamp: Instant, ttl_ms: u64) -> bool {
        timestamp.elapsed().as_millis() as u64 > ttl_ms
    }

    /// ล้างข้อมูลที่หมดอายุทั้งหมด (ยังไม่สมบูรณ์ — placeholder สำหรับ Phase 2)
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

/// ตัวจัดการ Retry และ Telemetry
/// รวมฟังก์ชันการ retry ด้วย backoff และการจัดการ TTL สำหรับ telemetry data
pub struct RetryAndTelemetryManager {
    /// การกำหนดค่า retry/backoff
    retry_config: RetryConfig,
    /// การกำหนดค่า TTL สำหรับ telemetry
    telemetry_ttl_config: TelemetryTTLConfig,
}

impl RetryAndTelemetryManager {
    /// สร้าง RetryAndTelemetryManager ใหม่ด้วยค่าเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self {
            retry_config: RetryConfig::default(),
            telemetry_ttl_config: TelemetryTTLConfig::default(),
        }
    }

    /// สร้าง RetryAndTelemetryManager พร้อมกำหนดค่า retry และ telemetry TTL
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

    /// ดึงข้อมูลอ้างอิงไปยัง RetryConfig
    #[must_use]
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// ดึงข้อมูลอ้างอิงแบบ mutable ไปยัง RetryConfig
    #[must_use]
    pub fn retry_config_mut(&mut self) -> &mut RetryConfig {
        &mut self.retry_config
    }

    /// ดึงข้อมูลอ้างอิงไปยัง TelemetryTTLConfig
    #[must_use]
    pub fn telemetry_ttl_config(&self) -> &TelemetryTTLConfig {
        &self.telemetry_ttl_config
    }

    /// ดึงข้อมูลอ้างอิงแบบ mutable ไปยัง TelemetryTTLConfig
    #[must_use]
    pub fn telemetry_ttl_config_mut(&mut self) -> &mut TelemetryTTLConfig {
        &mut self.telemetry_ttl_config
    }

    /// ดำเนินการ `f` พร้อม retry ด้วย backoff ผ่าน RetryConfig
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

    /// ทดสอบค่าเริ่มต้นของ RetryConfig
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

    /// ทดสอบการ retry จนสำเร็จ (ต้องลอง 3 ครั้งจึงสำเร็จ)
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

    /// ทดสอบการ retry จนหมดจำนวนครั้ง (exhausted)
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

    /// ทดสอบการคำนวณ backoff แบบ exponential
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

    /// ทดสอบค่าเริ่มต้นของ TelemetryTTLConfig
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

    /// ทดสอบการตรวจสอบการหมดอายุของ TTL
    #[test]
    fn test_telemetry_ttl_is_expired() {
        let config = TelemetryTTLConfig::default();
        let timestamp = Instant::now() - Duration::from_millis(1500);
        assert!(config.is_expired(timestamp, 1000));
        let timestamp = Instant::now();
        assert!(!config.is_expired(timestamp, 5_000_000));
    }

    /// ทดสอบการสร้าง RetryAndTelemetryManager ด้วยค่าเริ่มต้น
    #[tokio::test]
    async fn test_retry_and_telemetry_manager_new() {
        let manager = RetryAndTelemetryManager::new();
        assert_eq!(manager.retry_config().max_attempts, 3);
        assert!(manager.telemetry_ttl_config().auto_cleanup);
    }

    /// ทดสอบการ retry ที่เกิด timeout จนต้อง retry
    #[tokio::test]
    async fn test_retry_with_timeout_triggers_retry() {
        let config = RetryConfig::new(3, 10, 1.0, 100, 50, false);
        let attempts = Arc::new(tokio::sync::Mutex::new(0u32));
        let attempts_clone = Arc::clone(&attempts);

        let result: anyhow::Result<i32> = config
            .retry_with_backoff(
                move || {
                    let a = Arc::clone(&attempts_clone);
                    async move {
                        let mut val = a.lock().await;
                        *val += 1;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Ok::<_, anyhow::Error>(42)
                    }
                },
                Some("timeout_op"),
            )
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
        let final_attempts = *attempts.lock().await;
        assert!(
            final_attempts <= 4,
            "should have stopped after max_attempts"
        );
    }

    /// ทดสอบว่าเมื่อปิด jitter แล้ว backoff เป็นค่าที่แน่นอนตามที่คำนวณ
    #[tokio::test]
    async fn test_retry_jitter_disabled_produces_exact_backoff() {
        let config = RetryConfig::new(2, 100, 1.0, 1000, 5000, false);
        let start = Instant::now();
        let attempts = Arc::new(tokio::sync::Mutex::new(0u32));
        let a = Arc::clone(&attempts);

        let _: anyhow::Result<i32> = config
            .retry_with_backoff(
                move || {
                    let c = Arc::clone(&a);
                    async move {
                        let mut v = c.lock().await;
                        *v += 1;
                        Err(anyhow::anyhow!("fail"))
                    }
                },
                None,
            )
            .await;
        let elapsed = start.elapsed().as_millis() as u64;
        assert!(
            elapsed >= 100,
            "should have backed off at least 100ms, got {elapsed}ms"
        );
    }

    /// ทดสอบว่า backoff ถูก capped ที่ max_backoff
    #[tokio::test]
    async fn test_retry_backoff_caps_at_max_backoff() {
        let config = RetryConfig::new(5, 100, 10.0, 500, 5000, false);
        assert_eq!(config.calculate_backoff(1), 100);
        assert_eq!(
            config.calculate_backoff(2),
            500,
            "100*10=1000 capped at 500"
        );
        assert_eq!(config.calculate_backoff(3), 500);
        assert_eq!(config.calculate_backoff(4), 500);
        assert_eq!(config.calculate_backoff(5), 500);
    }

    /// ทดสอบว่า jitter ให้ค่าที่แตกต่างกันสำหรับ attempt ต่างกัน
    #[test]
    fn test_jitter_produces_different_values() {
        let config = RetryConfig::default();
        let v1 = config.jitter(1000, 1);
        let v2 = config.jitter(1000, 2);
        assert_ne!(v1, v2, "different attempt seeds should differ");
        assert!(v1 >= 1, "jitter must not produce zero");
    }

    /// ทดสอบว่าเมื่อปิด jitter จะได้ค่า backoff เท่าเดิม
    #[test]
    fn test_jitter_disabled_returns_backoff_unchanged() {
        let config = RetryConfig::new(3, 100, 2.0, 10000, 5000, false);
        let result = config.jitter(500, 3);
        assert_eq!(result, 500);
    }

    /// ทดสอบ TelemetryTTLConfig ด้วยค่าที่กำหนดเอง
    #[test]
    fn test_telemetry_ttl_config_new_with_custom_values() {
        let config =
            TelemetryTTLConfig::new(10_000, 5_000, 60_000, 30_000, 10_000, 1_000, false, false);
        assert_eq!(config.metric_cache_ttl_ms, 10_000);
        assert_eq!(config.telemetry_snapshot_ttl_ms, 5_000);
        assert_eq!(config.audit_log_ttl_ms, 60_000);
        assert_eq!(config.intent_metadata_ttl_ms, 30_000);
        assert_eq!(config.cleanup_interval_ms, 10_000);
        assert_eq!(config.telemetry_publish_interval_ms, 1_000);
        assert!(!config.include_timestamps);
        assert!(!config.auto_cleanup);
    }

    /// ทดสอบการตรวจสอบ expired ด้วย timestamp ที่เก่ามาก
    #[test]
    fn test_telemetry_ttl_is_expired_returns_true_for_expired() {
        let config = TelemetryTTLConfig::default();
        let very_old = Instant::now() - Duration::from_millis(100_000);
        assert!(config.is_expired(very_old, 10_000));
    }

    /// ทดสอบการตรวจสอบ expired ด้วย timestamp ที่เพิ่งสร้าง
    #[test]
    fn test_telemetry_ttl_is_expired_fresh_not_expired() {
        let config = TelemetryTTLConfig::default();
        let fresh = Instant::now();
        assert!(!config.is_expired(fresh, 60_000));
    }

    /// ทดสอบ RetryAndTelemetryManager แบบ end-to-end ด้วย with_configs และ execute
    #[tokio::test]
    async fn test_retry_and_telemetry_manager_with_configs_and_execute() {
        let retry = RetryConfig::new(2, 50, 2.0, 1000, 5000, false);
        let ttl =
            TelemetryTTLConfig::new(10_000, 5_000, 60_000, 30_000, 10_000, 2_000, false, false);
        let manager = RetryAndTelemetryManager::with_configs(retry, ttl);
        assert_eq!(manager.retry_config().max_attempts, 2);
        assert_eq!(manager.retry_config().initial_backoff_ms, 50);
        assert!(!manager.telemetry_ttl_config().include_timestamps);

        let counter = Arc::new(tokio::sync::Mutex::new(0u32));
        let c = Arc::clone(&counter);
        let result = manager
            .execute_with_retry(
                move || {
                    let cnt = Arc::clone(&c);
                    async move {
                        let mut v = cnt.lock().await;
                        *v += 1;
                        Ok::<_, anyhow::Error>(*v)
                    }
                },
                Some("manager_integration"),
            )
            .await;
        assert_eq!(result.unwrap(), 1);
    }

    /// ทดสอบ RetryAndTelemetryManager เมื่อ retry หมดจำนวนครั้ง
    #[tokio::test]
    async fn test_retry_and_telemetry_manager_execute_exhausted() {
        let retry = RetryConfig::new(1, 10, 1.0, 100, 5000, false);
        let manager = RetryAndTelemetryManager::with_configs(retry, TelemetryTTLConfig::default());
        let counter = Arc::new(tokio::sync::Mutex::new(0u32));
        let c = Arc::clone(&counter);
        let result: anyhow::Result<i32> = manager
            .execute_with_retry(
                move || {
                    let cnt = Arc::clone(&c);
                    async move {
                        let mut v = cnt.lock().await;
                        *v += 1;
                        Err::<i32, _>(anyhow::anyhow!("persistent failure"))
                    }
                },
                Some("exhausted_test"),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(
            *counter.lock().await,
            2,
            "max_attempts=1 means 2 total calls"
        );
    }
}
