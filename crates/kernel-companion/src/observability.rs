use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use std::io::Write;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::metadata::Metadata;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::{Interest, SetGlobalDefaultError};
use tracing::{Event, Subscriber};

static KERNEL_METRICS: OnceLock<Arc<KernelMetrics>> = OnceLock::new();
static TRACING_INIT: OnceLock<()> = OnceLock::new();

const KNOWN_EBPF_MODES: [&str; 2] = ["real", "simulation"];

#[derive(Debug)]
/// โครงสร้างข้อมูล `KernelMetrics` ใช้สำหรับเก็บสถานะและการตั้งค่า
/// โครงสร้างข้อมูล `KernelMetrics` ใช้สำหรับเก็บสถานะและการตั้งค่า
pub struct KernelMetrics {
    /// ข้อมูล `lsm_policy_decisions_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `lsm_policy_decisions_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub lsm_policy_decisions_total: IntCounterVec,
    /// ข้อมูล `lsm_blocked_syscalls` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `lsm_blocked_syscalls` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub lsm_blocked_syscalls: IntGauge,
    /// ข้อมูล `ebpf_attach_attempts_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `ebpf_attach_attempts_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub ebpf_attach_attempts_total: IntCounterVec,
    /// ข้อมูล `ebpf_active_mode` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `ebpf_active_mode` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub ebpf_active_mode: IntGaugeVec,
    /// ข้อมูล `syscall_events_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `syscall_events_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub syscall_events_total: IntCounterVec,
    /// ข้อมูล `syscall_event_drops_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `syscall_event_drops_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub syscall_event_drops_total: IntCounterVec,
    /// ข้อมูล `cache_invalidations_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    /// ข้อมูล `cache_invalidations_total` สำหรับการกำหนดค่าหรือสถานะภายใน
    pub cache_invalidations_total: IntCounterVec,
}

impl KernelMetrics {
    /// ฟังก์ชัน `register` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `register` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
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

    /// ฟังก์ชัน `record_lsm_decision` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `record_lsm_decision` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn record_lsm_decision(&self, decision: &str, reason: &str) {
        self.lsm_policy_decisions_total
            .with_label_values(&[decision, reason])
            .inc();
    }

    /// ฟังก์ชัน `set_blocked_syscalls` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `set_blocked_syscalls` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn set_blocked_syscalls(&self, count: usize) {
        self.lsm_blocked_syscalls.set(count as i64);
    }

    /// ฟังก์ชัน `record_attach_attempt` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `record_attach_attempt` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn record_attach_attempt(&self, component: &str, result: &str) {
        self.ebpf_attach_attempts_total
            .with_label_values(&[component, result])
            .inc();
    }

    /// ฟังก์ชัน `set_active_mode` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `set_active_mode` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn set_active_mode(&self, component: &str, mode: &str) {
        for known_mode in KNOWN_EBPF_MODES {
            self.ebpf_active_mode
                .with_label_values(&[component, known_mode])
                .set(if known_mode == mode { 1 } else { 0 });
        }
    }

    /// ฟังก์ชัน `record_syscall_event` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `record_syscall_event` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn record_syscall_event(&self, decision: &str, syscall: &str) {
        self.syscall_events_total
            .with_label_values(&[decision, syscall])
            .inc();
    }

    /// ฟังก์ชัน `record_syscall_drop` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `record_syscall_drop` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn record_syscall_drop(&self, reason: &str) {
        self.syscall_event_drops_total
            .with_label_values(&[reason])
            .inc();
    }

    /// ฟังก์ชัน `record_cache_invalidation` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    /// ฟังก์ชัน `record_cache_invalidation` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
    pub fn record_cache_invalidation(&self, scope: &str) {
        self.cache_invalidations_total
            .with_label_values(&[scope])
            .inc();
    }
}

#[must_use]
/// ฟังก์ชัน `kernel_metrics` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
/// ฟังก์ชัน `kernel_metrics` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
pub fn kernel_metrics() -> Arc<KernelMetrics> {
    Arc::clone(KERNEL_METRICS.get_or_init(|| {
        KernelMetrics::register(prometheus::default_registry())
            .expect("kernel observability metrics registration should succeed once")
    }))
}

/// ฟังก์ชัน `init_tracing` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
/// ฟังก์ชัน `init_tracing` ใช้สำหรับดำเนินการที่เกี่ยวข้องกับระบบ
pub fn init_tracing(level: &str) -> Result<(), SetGlobalDefaultError> {
    if TRACING_INIT.get().is_some() {
        return Ok(());
    }

    let subscriber = SimpleSubscriber::new(parse_level(level));
    match tracing::subscriber::set_global_default(subscriber) {
        Ok(()) => {
            let _ = TRACING_INIT.set(());
            Ok(())
        }
        Err(err) => {
            let _ = TRACING_INIT.set(());
            Err(err)
        }
    }
}

fn parse_level(level: &str) -> LevelFilter {
    match level.to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    }
}

struct SimpleSubscriber {
    max_level: LevelFilter,
    next_span_id: AtomicU64,
}

impl SimpleSubscriber {
    fn new(max_level: LevelFilter) -> Self {
        Self {
            max_level,
            next_span_id: AtomicU64::new(1),
        }
    }
}

impl Subscriber for SimpleSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.max_level >= LevelFilter::from_level(*metadata.level())
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(self.next_span_id.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        if !self.enabled(metadata) {
            return;
        }

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "[{timestamp}] {} {}{}",
            metadata.level(),
            metadata.target(),
            visitor.render_suffix(),
        );
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn clone_span(&self, id: &Id) -> Id {
        id.clone()
    }

    fn try_close(&self, _id: Id) -> bool {
        true
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.enabled(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.max_level)
    }
}

#[derive(Default)]
struct EventVisitor {
    fields: Vec<String>,
}

impl EventVisitor {
    fn push_field(&mut self, field: &Field, value: String) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn render_suffix(&self) -> String {
        if self.fields.is_empty() {
            String::new()
        } else {
            format!(" {}", self.fields.join(" "))
        }
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push_field(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_field(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_field(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_field(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push_field(field, format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
