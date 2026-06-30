use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// ตัวแปร global สำหรับจัดเก็บ KernelMetrics (initialized once)
static KERNEL_METRICS: OnceLock<Arc<KernelMetrics>> = OnceLock::new();
/// ตัวแปร global สำหรับป้องกันการ init tracing ซ้ำ
static TRACING_INIT: OnceLock<()> = OnceLock::new();
/// ตัวแปร global สำหรับจัดเก็บ OTel Tracer Provider (สำหรับ shutdown)
static OTEL_PROVIDER: OnceLock<Mutex<Option<SdkTracerProvider>>> = OnceLock::new();

/// โหมดที่รู้จักสำหรับ eBPF components
const KNOWN_EBPF_MODES: [&str; 2] = ["real", "simulation"];

/// ตัววัดผล Kernel Metrics สำหรับ Prometheus
/// ใช้ติดตามการตัดสินใจของ LSM, สถานะ eBPF, และเหตุการณ์ syscall
#[derive(Debug)]
pub struct KernelMetrics {
    /// จำนวนการตัดสินใจของ LSM Policy แบ่งตามผล (allow/deny) และเหตุผล
    pub lsm_policy_decisions_total: IntCounterVec,
    /// จำนวน syscall ที่ถูกบล็อกโดย immune-system antibodies ปัจจุบัน
    pub lsm_blocked_syscalls: IntGauge,
    /// จำนวนครั้งที่พยายาม attach eBPF แบ่งตาม component และผลลัพธ์
    pub ebpf_attach_attempts_total: IntCounterVec,
    /// โหมดการทำงานปัจจุบันของแต่ละ eBPF component (real/simulation)
    pub ebpf_active_mode: IntGaugeVec,
    /// จำนวนเหตุการณ์ syscall ที่สังเกตเห็น แบ่งตาม decision และชื่อ syscall
    pub syscall_events_total: IntCounterVec,
    /// จำนวนเหตุการณ์ syscall ที่ถูก drop แบ่งตามสาเหตุ
    pub syscall_event_drops_total: IntCounterVec,
    /// จำนวนครั้งที่ cache ถูก invalidate แบ่งตามขอบเขต
    pub cache_invalidations_total: IntCounterVec,
}

impl KernelMetrics {
    /// ลงทะเบียน metrics ทั้งหมดกับ Prometheus Registry
    pub fn register(registry: &Registry) -> Result<Arc<Self>, prometheus::Error> {
        let lsm_policy_decisions_total = IntCounterVec::new(
            Opts::new(
                "ank_lsm_policy_decisions_total",
                "LSM policy decisions grouped by allow or deny and the decision reason",
            ),
            &["decision", "reason"],
        )?;

        let lsm_blocked_syscalls = IntGauge::with_opts(Opts::new(
            "ank_lsm_blocked_syscalls",
            "Current number of syscalls blocked by immune-system antibodies",
        ))?;

        let ebpf_attach_attempts_total = IntCounterVec::new(
            Opts::new(
                "ank_ebpf_attach_attempts_total",
                "eBPF attach attempts grouped by component and result",
            ),
            &["component", "result"],
        )?;

        let ebpf_active_mode = IntGaugeVec::new(
            Opts::new(
                "ank_ebpf_active_mode",
                "Active execution mode for each eBPF-backed component",
            ),
            &["component", "mode"],
        )?;

        let syscall_events_total = IntCounterVec::new(
            Opts::new(
                "ank_syscall_events_total",
                "Observed syscall events grouped by policy decision and syscall name",
            ),
            &["decision", "syscall"],
        )?;

        let syscall_event_drops_total = IntCounterVec::new(
            Opts::new(
                "ank_syscall_event_drops_total",
                "Dropped syscall events grouped by drop reason",
            ),
            &["reason"],
        )?;

        let cache_invalidations_total = IntCounterVec::new(
            Opts::new(
                "ank_cache_invalidations_total",
                "Syscall decision cache invalidations grouped by scope",
            ),
            &["scope"],
        )?;

        registry.register(Box::new(lsm_policy_decisions_total.clone()))?;
        registry.register(Box::new(lsm_blocked_syscalls.clone()))?;
        registry.register(Box::new(ebpf_attach_attempts_total.clone()))?;
        registry.register(Box::new(ebpf_active_mode.clone()))?;
        registry.register(Box::new(syscall_events_total.clone()))?;
        registry.register(Box::new(syscall_event_drops_total.clone()))?;
        registry.register(Box::new(cache_invalidations_total.clone()))?;

        Ok(Arc::new(Self {
            lsm_policy_decisions_total,
            lsm_blocked_syscalls,
            ebpf_attach_attempts_total,
            ebpf_active_mode,
            syscall_events_total,
            syscall_event_drops_total,
            cache_invalidations_total,
        }))
    }

    /// บันทึกการตัดสินใจของ LSM Policy (allow/deny)
    pub fn record_lsm_decision(&self, decision: &str, reason: &str) {
        self.lsm_policy_decisions_total
            .with_label_values(&[decision, reason])
            .inc();
    }

    /// ตั้งค่าจำนวน syscall ที่ถูกบล็อกโดย antibodies
    pub fn set_blocked_syscalls(&self, count: usize) {
        self.lsm_blocked_syscalls.set(count as i64);
    }

    /// บันทึกความพยายามในการ attach eBPF
    pub fn record_attach_attempt(&self, component: &str, result: &str) {
        self.ebpf_attach_attempts_total
            .with_label_values(&[component, result])
            .inc();
    }

    /// ตั้งค่าโหมดการทำงานปัจจุบันของ eBPF component
    pub fn set_active_mode(&self, component: &str, mode: &str) {
        for known_mode in KNOWN_EBPF_MODES {
            self.ebpf_active_mode
                .with_label_values(&[component, known_mode])
                .set(if known_mode == mode { 1 } else { 0 });
        }
    }

    /// บันทึกเหตุการณ์ syscall ที่สังเกตเห็น
    pub fn record_syscall_event(&self, decision: &str, syscall: &str) {
        self.syscall_events_total
            .with_label_values(&[decision, syscall])
            .inc();
    }

    /// บันทึกเหตุการณ์ syscall ที่ถูก drop
    pub fn record_syscall_drop(&self, reason: &str) {
        self.syscall_event_drops_total
            .with_label_values(&[reason])
            .inc();
    }

    /// บันทึกการ invalidate cache
    pub fn record_cache_invalidation(&self, scope: &str) {
        self.cache_invalidations_total
            .with_label_values(&[scope])
            .inc();
    }
}

/// ดึงอินสแตนซ์ของ KernelMetrics (สร้างครั้งแรกและเก็บไว้ใน OnceLock)
#[must_use]
pub fn kernel_metrics() -> Arc<KernelMetrics> {
    Arc::clone(KERNEL_METRICS.get_or_init(|| {
        KernelMetrics::register(prometheus::default_registry())
            .expect("kernel observability metrics registration should succeed once")
    }))
}

/// การกำหนดค่าสำหรับ Tracing (structured logging + OpenTelemetry)
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// ระดับการบันทึก log (trace/debug/info/warn/error)
    pub log_level: String,
    /// ปลายทางของ OpenTelemetry collector
    pub otel_endpoint: String,
    /// ชื่อ service สำหรับ OTel
    pub otel_service_name: String,
    /// ระยะเวลา timeout สำหรับ OTel export (ms)
    pub otel_export_timeout_ms: u64,
}

/// เริ่มต้นระบบ Tracing ด้วย structured JSON logging และ OTel (ถ้ากำหนด endpoint)
/// สามารถเรียกได้ครั้งเดียวเท่านั้น การเรียกซ้ำจะถูกข้าม
pub fn init_tracing(config: &TracingConfig) -> Result<(), Box<dyn std::error::Error>> {
    if TRACING_INIT.get().is_some() {
        return Ok(());
    }

    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .parse_lossy(&config.log_level);

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_current_span(true)
        .with_span_list(true);

    let otel_layer = if !config.otel_endpoint.is_empty() {
        let timeout = std::time::Duration::from_millis(config.otel_export_timeout_ms);
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(&config.otel_endpoint)
            .with_timeout(timeout)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_attribute(KeyValue::new(
                        "service.name",
                        config.otel_service_name.clone(),
                    ))
                    .build(),
            )
            .with_batch_exporter(span_exporter)
            .build();
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        let _ = OTEL_PROVIDER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("OTel provider lock")
            .replace(tracer_provider);
        Some(tracing_opentelemetry::layer())
    } else {
        None
    };

    let subscriber = tracing_subscriber::Registry::default()
        .with(env_filter)
        .with(json_layer)
        .with(otel_layer);

    subscriber.try_init()?;
    let _ = TRACING_INIT.set(());
    Ok(())
}

/// ปิดระบบ Tracing และ flush OTel spans ทั้งหมดก่อนปิดโปรแกรม
pub fn shutdown_tracing() {
    if let Some(guard) = OTEL_PROVIDER.get() {
        if let Some(provider) = guard.lock().expect("OTel provider lock").take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("OTel tracer provider shutdown warning: {e:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ทดสอบการลงทะเบียนและแสดงผล Kernel Metrics ทั้งหมด
    #[test]
    fn register_and_render_kernel_metrics() {
        let registry = Registry::new();
        let metrics = KernelMetrics::register(&registry).expect("metrics should register");

        metrics.record_lsm_decision("allow", "allowlist");
        metrics.record_attach_attempt("lsm", "success");
        metrics.set_active_mode("tracer", "simulation");
        metrics.record_syscall_event("deny", "execve");
        metrics.record_syscall_drop("channel_full");
        metrics.set_blocked_syscalls(3);

        let rendered = capability_security::render_metrics(&registry).expect("render should work");
        assert!(rendered.contains("ank_lsm_policy_decisions_total"));
        assert!(rendered.contains("ank_ebpf_attach_attempts_total"));
        assert!(rendered.contains("ank_ebpf_active_mode"));
        assert!(rendered.contains("ank_syscall_events_total"));
        assert!(rendered.contains("ank_syscall_event_drops_total"));
        assert!(rendered.contains("ank_lsm_blocked_syscalls"));
    }
}
