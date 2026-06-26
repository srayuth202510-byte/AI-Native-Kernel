/// โหมดการจัดตารางเวลาของระบบ เพื่อปรับเปลี่ยนพฤติกรรมตามสภาพแวดล้อม
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// โหมดประหยัดพลังงาน (Edge/Laptop) - ให้น้ำหนักกับการใช้พลังงานต่ำสุด
    Battery,
    /// โหมดประสิทธิภาพสูงสุด (Server) - ให้น้ำหนักกับความเร็ว (Latency ต่ำสุด)
    Throughput,
    /// โหมดประหยัดค่าใช้จ่าย (Cloud) - ให้น้ำหนักกับต้นทุนทางการเงินต่ำสุด
    Cost,
}

/// ค่าน้ำหนักปรับตัว (Adaptive Weights) สำหรับการคำนวณคะแนนประสิทธิภาพทรัพยากร
/// ค่าน้ำหนักเหล่านี้จะถูกอัปเดตแบบเรียลไทม์ตามสถิติการใช้งานที่บันทึกได้จริง
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveWeights {
    /// น้ำหนักของปัจจัยความหน่วง (Latency weight)
    pub latency: f64,
    /// น้ำหนักของปัจจัยการใช้พลังงาน (Power consumption weight)
    pub power: f64,
    /// น้ำหนักของปัจจัยค่าใช้จ่าย (Cost weight)
    pub cost: f64,
}

impl AdaptiveWeights {
    /// สร้างออบเจกต์ `AdaptiveWeights` ใหม่ด้วยน้ำหนักเริ่มต้นแบบกำหนดเอง
    #[must_use]
    pub fn new(latency: f64, power: f64, cost: f64) -> Self {
        Self {
            latency,
            power,
            cost,
        }
    }

    /// สร้างค่าน้ำหนักเริ่มต้นที่ตั้งค่ามาสำหรับโหมดการทำงานที่ระบุ
    #[must_use]
    pub fn from_mode(mode: SchedulerMode) -> Self {
        match mode {
            SchedulerMode::Battery => Self::new(0.1, 0.8, 0.1),
            SchedulerMode::Throughput => Self::new(0.8, 0.1, 0.1),
            SchedulerMode::Cost => Self::new(0.1, 0.1, 0.8),
        }
    }

    /// อัปเดตค่าน้ำหนักปรับตัวปัจจุบันโดยใช้สูตรการคำนวณ Exponential Weighted Moving Average (EWMA)
    /// โดยใช้สัมประสิทธิ์การปรับปรุง (alpha) เท่ากับ 0.1
    pub fn observe(&mut self, sample: crate::ComputeProfile) {
        let alpha = 0.1;
        self.latency = self.latency * (1.0 - alpha) + sample.latency_ms * alpha;
        self.power = self.power * (1.0 - alpha) + sample.power_watts * alpha;
        self.cost = self.cost * (1.0 - alpha) + sample.cost_units * alpha;
    }
}

impl Default for AdaptiveWeights {
    /// กำหนดค่าน้ำหนักเริ่มต้นของระบบ โดยใช้โหมด Throughput เป็นมาตรฐาน (เน้น Latency)
    fn default() -> Self {
        Self::from_mode(SchedulerMode::Throughput)
    }
}
