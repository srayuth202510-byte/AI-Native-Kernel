//! ตัวนับแบบหน้าต่างเวลาเลื่อน (Sliding-window counters) สำหรับวัดอัตราคำขอและอัตราการใช้โทเคน
//!
//! ใช้โครงสร้างแบบ ring ของถังเวลา (time buckets) เพื่อให้ทั้ง `add` และ `sum` ทำงาน
//! ในเวลา O(1) เฉลี่ย โดยไม่ต้องเก็บทุก event ไว้ — สำคัญเพราะ hot path ของ gateway
//! จะเรียกใช้ตัวนับนี้ทุกคำขอ

/// ตัวนับแบบหน้าต่างเวลาเลื่อนที่เก็บยอดแบบถัง (bucketed sliding-window counter)
///
/// ค่าที่เพิ่มถูกรวมเข้าถังตามเวลา และถังเก่าจะถูกเลื่อนทิ้งเมื่อถึงรอบใหม่
/// ทำให้หน่วยความจำคงที่ ไม่โตตามจำนวน event
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// ความกว้างของถังเวลาเป็นมิลลิวินาที
    bucket_width_ms: u64,
    /// จำนวนถังที่เก็บไว้ (หน้าต่าง = `bucket_width_ms * capacity`)
    capacity: usize,
    /// ถังเรียงจากเก่าไปใหม่
    buckets: std::collections::VecDeque<(u64, f64)>,
}

impl SlidingWindow {
    /// สร้างหน้าต่างเวลา
    ///
    /// # Panics
    /// panic เมื่อ `window_ms` เป็นศูนย์ เพราะจะทำให้การคำนวณถังหารด้วยศูนย์
    #[must_use]
    pub fn new(window_ms: u64) -> Self {
        assert!(window_ms > 0, "window_ms must be greater than zero");
        // ถังละเอียดพอสมเหตุสมผล: 1/16 ของหน้าต่าง แต่ไม่น้อยกว่า 1 ถัง
        let bucket_width_ms = (window_ms / 16).max(1);
        let capacity = window_ms.div_ceil(bucket_width_ms).max(1) as usize;
        Self {
            bucket_width_ms,
            capacity,
            buckets: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    /// สร้างหน้าต่างเวลาพร้อมกำหนดจำนวนถังเอง (มีขนาดถังขั้นต่ำ 1)
    #[must_use]
    pub fn with_buckets(window_ms: u64, bucket_width_ms: u64) -> Self {
        assert!(window_ms > 0, "window_ms must be greater than zero");
        assert!(
            bucket_width_ms > 0,
            "bucket_width_ms must be greater than zero"
        );
        let capacity = window_ms.div_ceil(bucket_width_ms).max(1) as usize;
        Self {
            bucket_width_ms,
            capacity,
            buckets: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    /// เพิ่มยอดเข้าถังของเวลา `now_ms`
    ///
    /// เวลาที่ผ่านมาแล้ว (นาฬิกาถอยหลัง) จะถูกปฏิเสธด้วยการไม่เพิ่ม เพื่อไม่ให้
    /// ผู้โจมตีส่ง timestamp ในอดีตมาปัดคะแนนของตัวเอง
    pub fn add(&mut self, now_ms: u64, value: f64) {
        let bucket = now_ms / self.bucket_width_ms;
        self.advance(bucket, value);
    }

    fn advance(&mut self, bucket: u64, value: f64) {
        if let Some(&(last_bucket, _)) = self.buckets.back() {
            if bucket == last_bucket {
                self.buckets.back_mut().expect("back was just checked").1 += value;
                return;
            }
            if bucket < last_bucket {
                // เวลาถอยหลัง — ไม่แก้ไขสถานะเดิม
                return;
            }
        }

        // เลื่อนถังเก่าออกจนกว่าจะถึงถังเป้าหมาย (หรือหน้าต่างเลื่อนไปจนหมด)
        while let Some(&(last_bucket, _)) = self.buckets.back() {
            if bucket - last_bucket > self.capacity as u64 {
                self.buckets.clear();
                break;
            }
            if last_bucket + 1 >= bucket {
                break;
            }
            self.buckets.push_back((last_bucket + 1, 0.0));
        }

        self.buckets.push_back((bucket, value));
        while self.buckets.len() > self.capacity {
            self.buckets.pop_front();
        }
    }

    /// ยอดรวมในหน้าต่างเวลาณ `now_ms`
    ///
    /// หน้าต่างครอบคลุม `capacity` ถังล่าสุด (รวมถังปัจจุบัน) ดังนั้นเกณฑ์ตัดคือ
    /// `current - (capacity - 1)` **แบบรวม** — ถ้าใช้แบบตัดออก ถังปัจจุบันจะหายไป
    #[must_use]
    pub fn sum(&self, now_ms: u64) -> f64 {
        let current = now_ms / self.bucket_width_ms;
        let oldest = current.saturating_sub(self.capacity.saturating_sub(1) as u64);
        self.buckets
            .iter()
            .filter(|(b, _)| *b >= oldest && *b <= current)
            .map(|(_, v)| *v)
            .sum()
    }

    /// จำนวนถังที่มีข้อมูลจริง (ใช้ตรวจว่ามี activity หรือไม่)
    #[must_use]
    pub fn active_buckets(&self) -> usize {
        self.buckets.iter().filter(|(_, v)| *v > 0.0).count()
    }

    /// ล้างสถานะทั้งหมด
    pub fn clear(&mut self) {
        self.buckets.clear();
    }

    /// ความกว้างของถังเวลาเป็นมิลลิวินาที
    #[must_use]
    pub fn bucket_width_ms(&self) -> u64 {
        self.bucket_width_ms
    }

    /// จำนวนถังสูงสุดที่เก็บได้
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_values_in_same_bucket() {
        let mut w = SlidingWindow::with_buckets(1000, 100);
        w.add(0, 1.0);
        w.add(50, 2.0);
        assert!((w.sum(50) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drops_values_that_fall_out_of_window() {
        let mut w = SlidingWindow::with_buckets(1000, 100);
        w.add(0, 5.0);
        // เลื่อนเวลาไปพ้นหน้าต่าง (10 ถัง)
        let total = w.sum(2000);
        assert!(total < 5.0, "old value should age out, got {total}");
        assert!((w.sum(2000) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn keeps_values_inside_window() {
        let mut w = SlidingWindow::with_buckets(1000, 100);
        w.add(900, 3.0);
        let total = w.sum(900);
        assert!((total - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn handles_large_time_jump_without_unbounded_growth() {
        let mut w = SlidingWindow::new(60_000);
        w.add(0, 1.0);
        // ข้ามไป 1 ปี — ต้องเคลียร์ถังเก่า ไม่ใช่เดินเติมจนขยะ
        w.add(365 * 24 * 3_600_000, 1.0);
        assert!(w.sum(365 * 24 * 3_600_000) <= 1.0);
        assert!(w.active_buckets() <= 1);
    }

    #[test]
    fn rejects_backwards_timestamps() {
        let mut w = SlidingWindow::with_buckets(1000, 100);
        w.add(900, 5.0);
        // timestamp ย้อนหลังไม่ควรถูกนับ
        w.add(100, 100.0);
        let total = w.sum(900);
        assert!((total - 5.0).abs() < f64::EPSILON, "got {total}");
    }

    #[test]
    fn memory_is_bounded_by_capacity() {
        let mut w = SlidingWindow::new(1000);
        for i in 0..10_000 {
            w.add(i * 10, 1.0);
        }
        assert!(w.buckets.len() <= w.capacity());
    }

    #[test]
    fn clear_resets_state() {
        let mut w = SlidingWindow::new(1000);
        w.add(0, 7.0);
        w.clear();
        assert!((w.sum(0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sums_weighted_values() {
        let mut w = SlidingWindow::new(1000);
        w.add(0, 1500.0);
        w.add(0, 500.0);
        assert!((w.sum(0) - 2000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn active_buckets_reflects_activity() {
        let mut w = SlidingWindow::with_buckets(1000, 100);
        w.add(0, 1.0);
        w.add(100, 1.0);
        assert_eq!(w.active_buckets(), 2);
    }

    #[test]
    fn reports_geometry() {
        let w = SlidingWindow::with_buckets(1000, 100);
        assert_eq!(w.bucket_width_ms(), 100);
        assert_eq!(w.capacity(), 10);
    }

    #[test]
    fn zero_window_panics() {
        let result = std::panic::catch_unwind(|| SlidingWindow::new(0));
        assert!(result.is_err());
    }
}
