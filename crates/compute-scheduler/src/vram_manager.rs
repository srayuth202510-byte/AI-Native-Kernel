use nvml_wrapper::Nvml;
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{info, warn};

/// ข้อผิดพลาดของการจัดสรร VRAM หรือ Circuit Breaker ทำงาน
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum VramError {
    /// VRAM ไม่พอสำหรับคำขอนี้
    #[error("VRAM Out-of-Memory: ต้องการ {requested} ไบต์ แต่เหลือพื้นที่สำหรับ Agent เพียง {available} ไบต์")]
    OutOfMemory {
        /// จำนวนไบต์ที่ขอ
        requested: usize,
        /// จำนวนไบต์ที่เหลือให้จัดสรรได้
        available: usize,
    },
    /// การใช้งาน VRAM รวมแตะเกณฑ์สูงสุด — ระงับการจัดสรรใหม่ชั่วคราว
    #[error(
        "GPU Circuit Breaker ทำงานเนื่องจากมีระดับการใช้งาน VRAM เกินเกณฑ์สูงสุด ({threshold_percent}%)"
    )]
    CircuitBreakerTriggered {
        /// เกณฑ์เปอร์เซ็นต์ที่ตั้งไว้
        threshold_percent: f64,
    },
}

/// ระบบควบคุมและจำกัดการใช้ VRAM ของ Agent แบบ Multi-tenant
#[derive(Debug)]
pub struct GpuVramManager {
    /// บันทึกขนาด VRAM ที่จัดสรรให้แก่ Agent แต่ละตัว (ขนาดของ Model/KV cache ที่จองไว้)
    allocated: RwLock<HashMap<String, usize>>,
    /// ขนาดความจุ VRAM สูงสุดของระบบจำลอง (ในกรณีที่ไม่มี GPU จริง)
    mock_total_capacity: usize,
    /// เกณฑ์การทำงานของ Circuit Breaker (เปอร์เซ็นต์การใช้งานสูงสุด เช่น 90.0%)
    circuit_breaker_threshold: f64,
}

impl Default for GpuVramManager {
    fn default() -> Self {
        // Default: 8 GB mock capacity, 90.0% circuit breaker threshold
        Self::new(8 * 1024 * 1024 * 1024, 90.0)
    }
}

impl GpuVramManager {
    /// สร้างตัวจัดการ VRAM ใหม่ ระบุความจุจำลอง (เมื่อไม่มี GPU จริง) และเกณฑ์ circuit breaker
    #[must_use]
    pub fn new(mock_total_capacity: usize, circuit_breaker_threshold: f64) -> Self {
        Self {
            allocated: RwLock::new(HashMap::new()),
            mock_total_capacity,
            circuit_breaker_threshold,
        }
    }

    /// ตรวจสอบระดับการใช้งาน VRAM รวมในปัจจุบัน (ไบต์)
    pub fn current_usage(&self) -> usize {
        let allocated = self.allocated.read();
        allocated.values().sum()
    }

    /// ดึงขนาด VRAM ทั้งหมดของ GPU
    /// หากมี GPU จริง (NVML) จะดึงจากไดรเวอร์ หากไม่มีจะใช้ความจุจำลอง
    pub fn total_capacity(&self) -> usize {
        if let Ok(nvml) = Nvml::init() {
            if let Ok(dev) = nvml.device_by_index(0) {
                if let Ok(mem) = dev.memory_info() {
                    return mem.total as usize;
                }
            }
        }
        self.mock_total_capacity
    }

    /// ดึงขนาด VRAM จริงที่ยังว่างอยู่บน GPU รวม
    pub fn physical_free_vram(&self) -> usize {
        if let Ok(nvml) = Nvml::init() {
            if let Ok(dev) = nvml.device_by_index(0) {
                if let Ok(mem) = dev.memory_info() {
                    return mem.free as usize;
                }
            }
        }
        // Fallback to mock remaining
        let usage = self.current_usage();
        self.mock_total_capacity.saturating_sub(usage)
    }

    /// จองเนื้อที่ VRAM สำหรับ Agent
    ///
    /// # Errors
    /// คืนค่า `VramError::OutOfMemory` หรือ `VramError::CircuitBreakerTriggered` หากจองไม่สำเร็จ
    pub fn reserve_vram(&self, agent_id: &str, requested_bytes: usize) -> Result<(), VramError> {
        let total = self.total_capacity();
        let current_alloc = self.current_usage();

        // 1. ตรวจสอบขีดจำกัดสูงสุด
        if current_alloc + requested_bytes > total {
            return Err(VramError::OutOfMemory {
                requested: requested_bytes,
                available: total.saturating_sub(current_alloc),
            });
        }

        // 2. ตรวจสอบเกณฑ์การทำงานของ Circuit Breaker
        let usage_percent = ((current_alloc + requested_bytes) as f64 / total as f64) * 100.0;
        if usage_percent > self.circuit_breaker_threshold {
            warn!(
                agent_id = %agent_id,
                usage_percent = %usage_percent,
                "GPU Circuit Breaker triggered! VRAM allocation rejected to prevent GPU OOM crash."
            );
            return Err(VramError::CircuitBreakerTriggered {
                threshold_percent: self.circuit_breaker_threshold,
            });
        }

        // 3. บันทึกการจองเนื้อที่
        let mut allocated = self.allocated.write();
        allocated.insert(agent_id.to_string(), requested_bytes);
        info!(
            agent_id = %agent_id,
            allocated_mb = %(requested_bytes / 1024 / 1024),
            total_allocated_mb = %((current_alloc + requested_bytes) / 1024 / 1024),
            "VRAM allocated successfully."
        );

        Ok(())
    }

    /// ปลดปล่อยเนื้อที่ VRAM เมื่อ Agent ทำงานเสร็จสิ้น หรือต้องการคืนพื้นที่
    pub fn release_vram(&self, agent_id: &str) {
        let mut allocated = self.allocated.write();
        if let Some(bytes) = allocated.remove(agent_id) {
            info!(
                agent_id = %agent_id,
                released_mb = %(bytes / 1024 / 1024),
                "VRAM released successfully."
            );
        }
    }
}
