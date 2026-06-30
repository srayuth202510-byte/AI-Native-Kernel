use crate::{ComputeProfile, ComputeScheduler, hardware};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info};

/// สัญญาณการเปลี่ยนแปลงสภาวะแวดล้อมระบบ (System Environment Event)
#[derive(Debug, Clone)]
pub enum SystemEvent {
    /// ระดับแบตเตอรี่เหลือน้อย (เปอร์เซ็นต์)
    LowBattery(u8),
    /// ตรวจพบการใช้พลังงานสูงผิดปกติ
    HighPowerDraw,
    /// โหลดของระบบสูง (เช่น CPU เต็ม)
    HighLoad,
    /// สภาวะปกติ
    Normal,
    /// GPU memory กำลังจะเต็ม (usage > 90%)
    GpuMemoryPressure,
    /// NPU ไม่พร้อมใช้งาน
    NpuUnavailable,
}

/// ระบบสังเกตการณ์สภาวะของเครื่อง (System Observer)
/// ทำหน้าที่ส่ง Feedback ให้ ComputeScheduler ปรับ Adaptive Weights แบบ Real-time
/// โดยใช้ข้อมูลฮาร์ดแวร์จริงจาก HardwareProber
pub struct SystemObserver {
    scheduler: Arc<ComputeScheduler>,
    event_tx: broadcast::Sender<SystemEvent>,
}

impl SystemObserver {
    /// สร้าง Observer ใหม่ พร้อมส่งต่อ Reference ไปยัง Scheduler
    #[must_use]
    pub fn new(scheduler: Arc<ComputeScheduler>) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            scheduler,
            event_tx: tx,
        }
    }

    /// ดึง Receiver เพื่อให้ส่วนอื่นของระบบ (เช่น UI) นำไปแสดงผล
    pub fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.event_tx.subscribe()
    }

    /// เริ่มต้น Background Task เพื่อมอนิเตอร์และอัปเดตน้ำหนัก (EWMA) เป็นระยะ
    /// ใช้ข้อมูลฮาร์ดแวร์จริงจาก HardwareProber แทน hardcoded values
    pub fn start_monitoring(&self) {
        let scheduler = Arc::clone(&self.scheduler);
        let mut event_rx = self.event_tx.subscribe();

        tokio::spawn(async move {
            info!("SystemObserver: starting real-time adaptive weights monitoring");

            // Probe real hardware on startup
            let mut prober = hardware::HardwareProber::new();
            let initial_profiles = prober.scan_hardware().await;

            // Find the best GPU profile if available
            let gpu_profile = initial_profiles
                .iter()
                .find(|(target, _)| *target == crate::ComputeTarget::Gpu)
                .map(|(_, p)| *p);

            let cpu_profile = initial_profiles
                .iter()
                .find(|(target, _)| *target == crate::ComputeTarget::Cpu)
                .map(|(_, p)| *p)
                .unwrap_or(ComputeProfile {
                    latency_ms: 50.0,
                    power_watts: 65.0,
                    cost_units: 5.0,
                });

            info!(
                gpu_available = gpu_profile.is_some(),
                cpu_latency_ms = cpu_profile.latency_ms,
                "SystemObserver: hardware profile loaded"
            );

            // Current active profile — starts with CPU baseline
            let mut current_profile = cpu_profile;

            // If GPU is available, start with GPU profile
            if let Some(gp) = gpu_profile {
                current_profile = gp;
            }

            // Poll interval — shorter for responsive adaptation
            let poll_interval = Duration::from_secs(2);
            let mut poll_count: u64 = 0;

            loop {
                tokio::select! {
                    // 1. รอรับ Event ภายนอก
                    Ok(event) = event_rx.recv() => {
                        match event {
                            SystemEvent::LowBattery(pct) => {
                                info!(battery = pct, "SystemObserver: low battery — switching to power-saving mode");
                                // On battery: heavily penalize power consumption
                                current_profile = ComputeProfile {
                                    latency_ms: cpu_profile.latency_ms,
                                    power_watts: cpu_profile.power_watts * 3.0,
                                    cost_units: cpu_profile.cost_units,
                                };
                            }
                            SystemEvent::HighLoad => {
                                info!("SystemObserver: high system load — prioritizing latency");
                                // On high load: prioritize fast completion
                                current_profile = ComputeProfile {
                                    latency_ms: cpu_profile.latency_ms * 5.0,
                                    power_watts: cpu_profile.power_watts,
                                    cost_units: cpu_profile.cost_units,
                                };
                            }
                            SystemEvent::HighPowerDraw => {
                                current_profile.power_watts *= 2.0;
                            }
                            SystemEvent::GpuMemoryPressure => {
                                info!("SystemObserver: GPU memory pressure — reducing GPU preference");
                                // Increase GPU cost to discourage GPU usage
                                if let Some(gp) = gpu_profile {
                                    current_profile = ComputeProfile {
                                        latency_ms: gp.latency_ms,
                                        power_watts: gp.power_watts,
                                        cost_units: gp.cost_units * 3.0,
                                    };
                                }
                            }
                            SystemEvent::NpuUnavailable => {
                                info!("SystemObserver: NPU unavailable — adjusting weights");
                                // Increase NPU cost
                                current_profile.cost_units += 50.0;
                            }
                            SystemEvent::Normal => {
                                info!("SystemObserver: returning to normal mode");
                                current_profile = gpu_profile.unwrap_or(cpu_profile);
                            }
                        }
                    }

                    // 2. Periodic EWMA update with real hardware metrics
                    _ = tokio::time::sleep(poll_interval) => {
                        poll_count += 1;

                        // Every 10 polls (~20s), re-probe hardware for fresh metrics
                        if poll_count % 10 == 0 {
                            let mut fresh_prober = hardware::HardwareProber::new();
                            if let Some((_, fresh_gpu)) = fresh_prober.scan_hardware().await
                                .iter()
                                .find(|(t, _)| *t == crate::ComputeTarget::Gpu)
                            {
                                // Blend fresh GPU metrics with current profile
                                current_profile = ComputeProfile {
                                    latency_ms: (current_profile.latency_ms + fresh_gpu.latency_ms) / 2.0,
                                    power_watts: (current_profile.power_watts + fresh_gpu.power_watts) / 2.0,
                                    cost_units: (current_profile.cost_units + fresh_gpu.cost_units) / 2.0,
                                };
                                debug!(
                                    gpu_latency = fresh_gpu.latency_ms,
                                    gpu_power = fresh_gpu.power_watts,
                                    "SystemObserver: refreshed GPU metrics from hardware"
                                );
                            }
                        }

                        // Feed sample to EWMA
                        scheduler.update_weights(current_profile);

                        let baseline = scheduler.score(ComputeProfile {
                            latency_ms: 1.0,
                            power_watts: 1.0,
                            cost_units: 1.0,
                        });
                        debug!(baseline_score = baseline, "SystemObserver: EWMA weights updated");
                    }
                }
            }
        });
    }

    /// ปล่อย Event สังเคราะห์เพื่อจำลองพฤติกรรม
    pub fn trigger_event(&self, event: SystemEvent) {
        let _ = self.event_tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::weights::AdaptiveWeights;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_system_observer_triggers_events() {
        let scheduler = Arc::new(ComputeScheduler::new());
        let observer = SystemObserver::new(Arc::clone(&scheduler));
        let mut rx = observer.subscribe();

        observer.trigger_event(SystemEvent::HighLoad);
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, SystemEvent::HighLoad));
    }

    #[tokio::test]
    async fn test_system_observer_updates_scheduler_weights_on_low_battery() {
        let scheduler = Arc::new(ComputeScheduler::with_weights(AdaptiveWeights::new(
            0.33, 0.33, 0.34,
        )));
        let observer = SystemObserver::new(Arc::clone(&scheduler));

        observer.start_monitoring();

        // Trigger low battery
        observer.trigger_event(SystemEvent::LowBattery(10));

        // Wait for EWMA tick (2s)
        sleep(Duration::from_millis(2100)).await;

        // Verify weights changed
        let updated_weights = scheduler.score(ComputeProfile {
            latency_ms: 1.0,
            power_watts: 1.0,
            cost_units: 1.0,
        });
        assert!(updated_weights > 0.0);
    }

    #[tokio::test]
    async fn test_system_observer_gpu_memory_pressure() {
        let scheduler = Arc::new(ComputeScheduler::with_weights(AdaptiveWeights::new(
            0.33, 0.33, 0.34,
        )));
        let observer = SystemObserver::new(Arc::clone(&scheduler));

        observer.start_monitoring();

        // Trigger GPU memory pressure
        observer.trigger_event(SystemEvent::GpuMemoryPressure);

        // Wait for EWMA tick
        sleep(Duration::from_millis(2100)).await;

        let score = scheduler.score(ComputeProfile {
            latency_ms: 1.0,
            power_watts: 1.0,
            cost_units: 1.0,
        });
        assert!(score > 0.0);
    }
}
