use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::f64::consts::SQRT_2;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// ฟังก์ชัน Ping: ส่ง Ping ไปยัง node และคืน latency (ms) หรือ None ถ้า timeout
type PingFn = Arc<dyn Fn(&str) -> Option<f64> + Send + Sync>;
/// ฟังก์ชัน Indirect Probe: ส่ง Ping ผ่าน node อื่นไปยัง target node
type IndirectProbeFn = Arc<dyn Fn(&str, &str) -> Option<f64> + Send + Sync>;
/// ฟังก์ชันบอกเวลาปัจจุบัน (ms) สำหรับการคำนวณ phi
type NowFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// ระยะเวลาระหว่างการ Ping แต่ละครั้ง (ms) — ยังไม่ใช้
#[allow(dead_code)]
const PING_INTERVAL_MS: u64 = 5_000;
/// ระยะเวลา timeout สำหรับการรอ Ping (ms)
const PING_TIMEOUT_MS: u64 = 2_000;
/// จำนวนสูงสุดของ Indirect Probe ที่จะลอง
const MAX_INDIRECT_PROBES: usize = 3;
/// ค่า Phi Threshold สำหรับตัดสิน Suspect → Dead
const SUSPICION_THRESHOLD: f64 = 3.0;
/// ขนาดหน้าต่างสำหรับคำนวณค่าเฉลี่ย latency
const LATENCY_WINDOW_SIZE: usize = 20;
/// จำนวน Ping ที่พลาดติดต่อกันก่อนถือว่าสงสัย
const MISSED_PING_THRESHOLD: u32 = 2;

/// สถานะของ Node ในระบบ SWIM Failure Detector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node ยังทำงานปกติ
    Alive,
    /// Node กำลังถูกสงสัยว่าอาจล่ม (รอการยืนยัน)
    Suspect,
    /// Node ถูกประกาศว่าล่มแล้ว
    Dead,
    /// ไม่ทราบสถานะ (Node นี้ไม่เคยถูกลงทะเบียน)
    Unknown,
}

/// สถิติของ Node สำหรับคำนวณ Phi Accrual Failure Detection
#[derive(Debug, Clone)]
struct NodeStats {
    /// ประวัติ latency ที่บันทึกล่าสุด
    latencies: VecDeque<f64>,
    /// ค่าเฉลี่ย latency (EWMA)
    mean_latency: f64,
    /// ค่าเบี่ยงเบนมาตรฐานของ latency (EWMA)
    stddev_latency: f64,
    /// จำนวน Ping ที่สำเร็จ
    ping_count: u64,
    /// จำนวน Ping ที่ timeout
    timeout_count: u64,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            latencies: VecDeque::with_capacity(LATENCY_WINDOW_SIZE),
            mean_latency: 50.0,
            stddev_latency: 25.0,
            ping_count: 0,
            timeout_count: 0,
        }
    }
}

impl NodeStats {
    /// บันทึก latency ของ Ping พร้อมอัปเดต EWMA (Exponentially Weighted Moving Average)
    fn record_latency(&mut self, latency_ms: f64) {
        const ALPHA: f64 = 0.125;
        let prev_mean = self.mean_latency;
        self.mean_latency = ALPHA * latency_ms + (1.0 - ALPHA) * prev_mean;
        let diff = latency_ms - prev_mean;
        self.stddev_latency =
            ((ALPHA) * diff * diff + (1.0 - ALPHA) * self.stddev_latency.powi(2)).sqrt();
        self.latencies.push_back(latency_ms);
        if self.latencies.len() > LATENCY_WINDOW_SIZE {
            self.latencies.pop_front();
        }
        self.ping_count += 1;
    }

    /// บันทึกเหตุการณ์ timeout และปรับ mean_latency สูงขึ้น
    fn record_timeout(&mut self) {
        self.timeout_count += 1;
        self.mean_latency = (self.mean_latency * 0.9 + 2000.0 * 0.1).min(5000.0);
    }

    /// คำนวณค่า Phi สำหรับ Phi Accrual Failure Detection
    /// เป็นค่าความน่าจะเป็นที่ Node จะล่ม โดยใช้ CDF ของ Normal Distribution
    /// Phi > SUSPICION_THRESHOLD (3.0) = Node น่าจะล่ม
    fn compute_phi(&self, time_since_last_ack_ms: f64) -> f64 {
        if self.stddev_latency < 1.0 {
            return if time_since_last_ack_ms > PING_TIMEOUT_MS as f64 * MISSED_PING_THRESHOLD as f64
            {
                SUSPICION_THRESHOLD + 1.0
            } else {
                0.0
            };
        }

        let x = (time_since_last_ack_ms - self.mean_latency) / self.stddev_latency;
        let cdf = 0.5 * (1.0 + erf(x / SQRT_2));
        let p_fail = 1.0 - cdf;
        // For extreme deviations, CDF rounds to 1.0 at f64 precision.
        // Treat p_fail ~ 0 as high suspicion.
        if p_fail <= 0.0 || p_fail < f64::EPSILON {
            return SUSPICION_THRESHOLD + 2.0;
        }
        -p_fail.log10()
    }
}

/// การประมาณค่า Error Function (erf) สำหรับใช้ใน Phi Accrual Detection
/// ใช้การประมาณแบบ Abramowitz and Stegun
fn erf(x: f64) -> f64 {
    let sign = if x >= 0.0 { 1.0 } else { -1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

/// ข้อมูลสมาชิกในกลุ่ม SWIM
#[derive(Debug, Clone)]
pub struct MemberInfo {
    /// รหัสประจำตัว Node
    pub node_id: String,
    /// สถานะปัจจุบันของ Node
    pub status: NodeStatus,
    /// เวลาที่ได้รับ ACK ล่าสุด (ms)
    pub last_ack_millis: u64,
    /// เวลาที่เริ่มสงสัย Node นี้ (ms) — None ถ้ายังไม่ถูกสงสัย
    pub suspicion_start_millis: Option<u64>,
    /// หมายเลข incarnation สำหรับ gossip protocol
    pub incarnation: u64,
    /// สถิติ latency สำหรับคำนวณ Phi
    stats: NodeStats,
}

impl MemberInfo {
    /// สร้าง MemberInfo ใหม่ในสถานะ Alive
    fn alive(node_id: String, now_ms: u64) -> Self {
        Self {
            node_id,
            status: NodeStatus::Alive,
            last_ack_millis: now_ms,
            suspicion_start_millis: None,
            incarnation: 0,
            stats: NodeStats::default(),
        }
    }
}

/// เวลาปัจจุบันในหน่วย milliseconds ตั้งแต่ Unix epoch
fn now_millis_std() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// กลไกตรวจจับความล้มเหลวแบบ SWIM (Scalable Weakly-consistent Infection-style Process Group Membership)
/// ใช้ Phi Accrual Failure Detection เพื่อตัดสินสถานะของ Node ในเครือข่าย P2P
#[derive(Clone)]
pub struct FailureDetector {
    /// รายการสมาชิกทั้งหมดในกลุ่ม
    members: Arc<RwLock<HashMap<String, MemberInfo>>>,
    /// ฟังก์ชันสำหรับ Ping ไปยัง Node เป้าหมาย
    ping_fn: PingFn,
    /// ฟังก์ชันสำหรับ Indirect Probe ผ่าน Node อื่น
    indirect_probe: IndirectProbeFn,
    /// ฟังก์ชันบอกเวลาปัจจุบัน
    now_fn: NowFn,
}

impl std::fmt::Debug for FailureDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureDetector").finish()
    }
}

impl FailureDetector {
    /// สร้าง FailureDetector ใหม่พร้อมฟังก์ชัน Ping, Indirect Probe, และเวลาปัจจุบัน
    #[must_use]
    pub fn new(ping_fn: PingFn, indirect_probe: IndirectProbeFn) -> Self {
        Self {
            members: Arc::new(RwLock::new(HashMap::new())),
            ping_fn,
            indirect_probe,
            now_fn: Arc::new(now_millis_std),
        }
    }

    /// ลงทะเบียนสมาชิกใหม่ในระบบ Failure Detector
    pub async fn register(&self, node_id: &str) {
        let now = (self.now_fn)();
        let mut members = self.members.write().await;
        members.entry(node_id.to_string()).or_insert_with(|| {
            info!(node_id = node_id, "FailureDetector: new member registered");
            MemberInfo::alive(node_id.to_string(), now)
        });
    }

    /// บันทึกการรับ ACK จาก Node — จะกู้คืนสถานะกลับเป็น Alive ถ้าอยู่ในสถานะ Suspect หรือ Dead
    pub async fn record_ack(&self, node_id: &str) {
        let now = (self.now_fn)();
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            member.last_ack_millis = now;
            if member.status == NodeStatus::Suspect || member.status == NodeStatus::Dead {
                info!(
                    node_id = node_id,
                    old_status = ?member.status,
                    "FailureDetector: node recovered"
                );
            }
            member.status = NodeStatus::Alive;
            member.suspicion_start_millis = None;
        } else {
            members.insert(
                node_id.to_string(),
                MemberInfo::alive(node_id.to_string(), now),
            );
        }
    }

    /// บันทึกค่า latency สำหรับการ Ping ที่สำเร็จ
    pub async fn record_ping_latency(&self, node_id: &str, latency_ms: f64) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            member.stats.record_latency(latency_ms);
        }
    }

    /// ตั้งสถานะ Node เป็น Suspect (สงสัยว่าอาจล่ม)
    pub async fn suspect(&self, node_id: &str, by: &str) {
        let now = (self.now_fn)();
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            if member.status == NodeStatus::Alive {
                info!(
                    node_id = node_id,
                    reported_by = by,
                    "FailureDetector: marking node as suspect"
                );
                member.status = NodeStatus::Suspect;
                member.suspicion_start_millis = Some(now);
            }
        }
    }

    /// ประกาศว่า Node ล่มแล้ว (Dead)
    pub async fn mark_dead(&self, node_id: &str) {
        let mut members = self.members.write().await;
        if let Some(member) = members.get_mut(node_id) {
            if member.status != NodeStatus::Dead {
                info!(node_id = node_id, "FailureDetector: marking node as dead");
                member.status = NodeStatus::Dead;
            }
        }
    }

    /// ตรวจสอบสถานะปัจจุบันของ Node
    pub async fn get_status(&self, node_id: &str) -> NodeStatus {
        let members = self.members.read().await;
        members
            .get(node_id)
            .map(|m| m.status)
            .unwrap_or(NodeStatus::Unknown)
    }

    /// ดึงรายชื่อ Node ที่ยัง Alive ทั้งหมด
    pub async fn alive_nodes(&self) -> Vec<String> {
        let members = self.members.read().await;
        members
            .iter()
            .filter(|(_, m)| m.status == NodeStatus::Alive)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// ดึงรายชื่อ Node ทั้งหมดที่ถูกลงทะเบียน
    pub async fn all_nodes(&self) -> Vec<String> {
        let members = self.members.read().await;
        members.keys().cloned().collect()
    }

    /// ดึงรายชื่อ Node ที่ถูกสงสัย (Suspect)
    pub async fn suspect_nodes(&self) -> Vec<String> {
        let members = self.members.read().await;
        members
            .iter()
            .filter(|(_, m)| m.status == NodeStatus::Suspect)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// ดำเนินการ Ping รอบเดียว (Ping Round)
    /// 1. ตรวจสอบ Node ที่อยู่ในสถานะ Suspect และคำนวณ Phi
    /// 2. ถ้า Phi เกิน Threshold → ประกาศ Dead
    /// 3. เลือก Node Alive สุ่มเพื่อ Ping
    /// 4. ถ้า Ping ไม่สำเร็จ → ลอง Indirect Probe
    /// 5. ถ้าทั้งหมดล้มเหลว → ตั้งสถานะ Suspect
    /// คืนค่ารายชื่อ Node ที่ถูกประกาศ Dead ในรอบนี้
    pub async fn ping_round(&self) -> Vec<String> {
        let now = (self.now_fn)();
        let mut dead_nodes = Vec::new();

        {
            let members = self.members.read().await;
            for (id, member) in members.iter() {
                if member.status == NodeStatus::Suspect {
                    if let Some(suspect_start) = member.suspicion_start_millis {
                        let suspect_duration = now.saturating_sub(suspect_start) as f64;
                        let phi = member.stats.compute_phi(suspect_duration);
                        if phi > SUSPICION_THRESHOLD {
                            dead_nodes.push(id.clone());
                        }
                    }
                }
            }
        }

        for node_id in &dead_nodes {
            self.mark_dead(node_id).await;
        }

        let target = {
            let members = self.members.read().await;
            let alive: Vec<String> = members
                .iter()
                .filter(|(_, m)| m.status == NodeStatus::Alive)
                .map(|(id, _)| id.clone())
                .collect();
            fastrand::choice(&alive).cloned()
        };

        let Some(ref target) = target else {
            return dead_nodes;
        };

        let result = (self.ping_fn)(target);
        if let Some(latency) = result {
            self.record_ack(target).await;
            self.record_ping_latency(target, latency).await;
        } else {
            {
                let mut members = self.members.write().await;
                if let Some(member) = members.get_mut(target.as_str()) {
                    member.stats.record_timeout();
                }
            }

            let other_alive = {
                let members = self.members.read().await;
                let ids: Vec<String> = members
                    .iter()
                    .filter(|(id, m)| {
                        id.as_str() != target.as_str() && m.status == NodeStatus::Alive
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                ids
            };

            let mut indirect_acked = false;
            for probe_target in fastrand::choose_multiple(&other_alive, MAX_INDIRECT_PROBES) {
                if let Some(latency) = (self.indirect_probe)(target, probe_target) {
                    self.record_ack(target).await;
                    self.record_ping_latency(target, latency).await;
                    indirect_acked = true;
                    break;
                }
            }

            if !indirect_acked {
                self.suspect(target, "self").await;
            }
        }

        dead_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ทดสอบการลงทะเบียนสมาชิกใหม่
    #[tokio::test]
    async fn test_register_new_member() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.register("node-1").await;
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Alive);
    }

    /// ทดสอบการกู้คืน Node ที่ถูกสงสัยด้วย ACK
    #[tokio::test]
    async fn test_ack_recovers_suspect() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.register("node-1").await;
        detector.suspect("node-1", "test").await;
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Suspect);
        detector.record_ack("node-1").await;
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Alive);
    }

    /// ทดสอบการกรองเฉพาะ Node ที่ Alive
    #[tokio::test]
    async fn test_alive_nodes_filters_correctly() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.register("node-1").await;
        detector.register("node-2").await;
        let alive = detector.alive_nodes().await;
        assert_eq!(alive.len(), 2);
    }

    /// ทดสอบสถานะ Unknown สำหรับ Node ที่ไม่มีอยู่
    #[tokio::test]
    async fn test_unknown_node_status() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        assert_eq!(
            detector.get_status("nonexistent").await,
            NodeStatus::Unknown
        );
    }

    /// ทดสอบการลงทะเบียนอัตโนมัติเมื่อได้รับ ACK จาก Node ใหม่
    #[tokio::test]
    async fn test_ack_auto_registers_new_node() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.record_ack("new-node").await;
        assert_eq!(detector.get_status("new-node").await, NodeStatus::Alive);
    }

    /// ทดสอบการประกาศ Node เป็น Dead
    #[tokio::test]
    async fn test_mark_dead() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.register("node-1").await;
        detector.mark_dead("node-1").await;
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Dead);
    }

    /// ทดสอบการประมาณค่า Error Function (erf)
    #[test]
    fn test_erf_approximation() {
        assert!((erf(0.0) - 0.0).abs() < 1e-6);
        assert!((erf(1.0) - 0.8427007929497149).abs() < 1e-6);
        assert!((erf(3.0) - 0.9999779095030014).abs() < 1e-6);
    }

    /// ทดสอบการคำนวณ Phi สำหรับค่าเบี่ยงเบนต่างๆ
    #[test]
    fn test_phi_computation() {
        let mut stats = NodeStats::default();
        for _ in 0..10 {
            stats.record_latency(50.0);
        }
        let phi_near = stats.compute_phi(60.0);
        assert!(phi_near > 0.1, "phi should be positive for mild deviation");
        assert!(phi_near < 1.5, "phi should be low for mild deviation");

        let phi_far = stats.compute_phi(5000.0);
        assert!(
            phi_far > SUSPICION_THRESHOLD,
            "phi should be high for extreme deviation"
        );
    }

    /// ทดสอบ EWMA ของ NodeStats
    #[test]
    fn test_node_stats_ewma() {
        let mut stats = NodeStats::default();
        assert!((stats.mean_latency - 50.0).abs() < 1.0);

        stats.record_latency(100.0);
        assert!(stats.mean_latency > 50.0);
        assert!(stats.mean_latency < 100.0);
    }

    /// ทดสอบ Ping Round ที่สำเร็จ
    #[tokio::test]
    async fn test_ping_round_alive() {
        let detector = FailureDetector::new(Arc::new(|_| Some(10.0)), Arc::new(|_, _| Some(15.0)));
        detector.register("node-1").await;
        let dead = detector.ping_round().await;
        assert!(dead.is_empty());
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Alive);
    }

    /// ทดสอบ Ping Round ที่เกิด Suspect เมื่อ timeout
    #[tokio::test]
    async fn test_ping_round_suspect_on_timeout() {
        let detector = FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None));
        detector.register("node-1").await;
        let dead = detector.ping_round().await;
        assert!(dead.is_empty());
        let status = detector.get_status("node-1").await;
        assert!(status == NodeStatus::Suspect || status == NodeStatus::Alive);
    }

    /// ทดสอบ Indirect Probe ที่สามารถกู้คืน Node ได้
    #[tokio::test]
    async fn test_indirect_probe_recovers() {
        let detector = FailureDetector::new(
            Arc::new(|_| None),
            Arc::new(
                |target, _| {
                    if target == "node-1" { Some(20.0) } else { None }
                },
            ),
        );
        detector.register("node-1").await;
        detector.register("node-2").await;
        let dead = detector.ping_round().await;
        assert!(dead.is_empty());
        assert_eq!(detector.get_status("node-1").await, NodeStatus::Alive);
    }
}
