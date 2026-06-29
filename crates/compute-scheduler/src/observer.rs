use crate::{ComputeProfile, ComputeScheduler};
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
}

/// ระบบสังเกตการณ์สภาวะของเครื่อง (System Observer)
/// ทำหน้าที่ส่ง Feedback ให้ ComputeScheduler ปรับ Adaptive Weights แบบ Real-time
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
    pub fn start_monitoring(&self) {
        let scheduler = Arc::clone(&self.scheduler);
        let mut event_rx = self.event_tx.subscribe();

        tokio::spawn(async move {
            info!("SystemObserver: เริ่มต้นกระบวนการ Real-time Adaptive Weights (EWMA)");

            // สถานะจำลองปัจจุบัน
            let mut current_profile = ComputeProfile {
                latency_ms: 10.0,
                power_watts: 15.0,
                cost_units: 5.0,
            };

            loop {
                tokio::select! {
                    // 1. รอรับ Event ภายนอก (เช่น จากการจำลองเหตุการณ์แบตเตอรี่ต่ำ)
                    Ok(event) = event_rx.recv() => {
                        match event {
                            SystemEvent::LowBattery(pct) => {
                                info!("SystemObserver: แบตเตอรี่ต่ำ ({}%) - เพิ่มน้ำหนักด้านการประหยัดพลังงาน!", pct);
                                // หากแบตต่ำ การใช้พลังงานจะมี "ราคา" หรือ Penalty สูงมากในมุมมองของระบบ
                                current_profile.power_watts = 100.0;
                                current_profile.latency_ms = 10.0;
                            }
                            SystemEvent::HighLoad => {
                                info!("SystemObserver: ระบบโหลดหนัก - เพิ่มน้ำหนักด้าน Latency เพื่อเคลียร์งาน!");
                                // หากโหลดหนัก เวลาคือสิ่งมีค่าที่สุด (Penalty สูง)
                                current_profile.latency_ms = 100.0;
                                current_profile.power_watts = 15.0;
                            }
                            SystemEvent::HighPowerDraw => {
                                current_profile.power_watts = 80.0;
                            }
                            SystemEvent::Normal => {
                                info!("SystemObserver: สภาวะปกติ");
                                current_profile = ComputeProfile {
                                    latency_ms: 10.0,
                                    power_watts: 15.0,
                                    cost_units: 5.0,
                                };
                            }
                        }
                    }

                    // 2. ลูปการอัปเดตสม่ำเสมอทุกๆ 2 วินาที (EWMA Drift)
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {
                        // ป้อน Sample ให้ Scheduler อัปเดตผ่าน EWMA
                        scheduler.update_weights(current_profile);

                        let current_weights = scheduler.score(ComputeProfile {
                            latency_ms: 1.0, power_watts: 1.0, cost_units: 1.0
                        });
                        debug!("SystemObserver: EWMA Weights Updated (Score Baseline: {:.4})", current_weights);
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
