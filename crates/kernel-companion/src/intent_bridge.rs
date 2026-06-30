use crate::config::IntentBridgePeerConfig;
use crate::tokio_util_cancel::CancellationToken;
use anyhow::{Context, Result, anyhow};
use intent_bus::{Intent, IntentBus, META_ROUTING_MODE, META_TARGET_NODE, ROUTING_MODE_DELEGATED};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn};

/// ซองจดหมาย (Envelope) สำหรับส่ง Intent ผ่านเครือข่ายระหว่างโหนด
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RoutedIntentEnvelope {
    /// Intent ที่ต้องการส่ง
    intent: Intent,
}

/// การตอบรับ (Acknowledgment) สำหรับ Intent ที่ส่งผ่านเครือข่าย
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RoutedIntentAck {
    /// สถานะการยอมรับ Intent
    accepted: bool,
    /// รหัสโหนดที่ตอบรับ
    node_id: String,
    /// ข้อผิดพลาดหากไม่ยอมรับ
    error: Option<String>,
}

/// สะพานเชื่อมต่อ Intent (Intent Bridge) สำหรับการสื่อสารข้ามโหนดผ่าน TCP
/// ใช้ส่ง Intent ที่ถูก Delegate ไปยังโหนดอื่นในเครือข่าย
/// รองรับการ timeout และ ACK เพื่อความน่าเชื่อถือ
#[derive(Debug, Clone)]
pub struct IntentBridge {
    /// รหัสของโหนดท้องถิ่น
    local_node_id: String,
    /// รายการโหนดปลายทางที่รู้จัก (Peer) พร้อม Socket Address
    peers: Arc<RwLock<HashMap<String, SocketAddr>>>,
    /// ระยะเวลารอการเชื่อมต่อสูงสุด
    connect_timeout: Duration,
    /// ระยะเวลารอการตอบรับสูงสุด
    request_timeout: Duration,
}

impl IntentBridge {
    /// สร้าง IntentBridge ใหม่พร้อมกำหนดค่ารายการ Peer และ Timeout
    #[must_use]
    pub fn new(
        local_node_id: impl Into<String>,
        peers: &[IntentBridgePeerConfig],
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        let peer_map = peers
            .iter()
            .filter_map(|peer| {
                peer.addr
                    .parse::<SocketAddr>()
                    .ok()
                    .map(|addr| (peer.node_id.clone(), addr))
            })
            .collect();

        Self {
            local_node_id: local_node_id.into(),
            peers: Arc::new(RwLock::new(peer_map)),
            connect_timeout,
            request_timeout,
        }
    }

    /// ดึงรายการ Peer ทั้งหมดพร้อมที่อยู่ Socket
    pub async fn peer_configs(&self) -> Vec<(String, SocketAddr)> {
        self.peers
            .read()
            .await
            .iter()
            .map(|(node_id, addr)| (node_id.clone(), *addr))
            .collect()
    }

    /// เพิ่มหรืออัปเดต Peer ใหม่ในระบบ
    pub async fn upsert_peer(&self, node_id: impl Into<String>, addr: SocketAddr) {
        self.peers.write().await.insert(node_id.into(), addr);
    }

    /// ลบ Peer ออกจากระบบ
    pub async fn remove_peer(&self, node_id: &str) {
        self.peers.write().await.remove(node_id);
    }

    /// เริ่มต้น Listener สำหรับรับ Intent จากโหนดอื่นผ่าน TCP
    /// เมื่อได้รับการเชื่อมต่อจะส่ง Intent เข้าสู่ Intent Bus ท้องถิ่น
    pub async fn start_listener(
        &self,
        intent_bus: Arc<IntentBus>,
        listen_addr: SocketAddr,
        cancel: CancellationToken,
    ) -> Result<()> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("Intent bridge failed to bind {listen_addr}"))?;
        info!(
            node_id = %self.local_node_id,
            addr = %listen_addr,
            "Intent bridge listener started"
        );

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if cancel.is_cancelled() {
                        info!(node_id = %self.local_node_id, "Intent bridge listener shutting down");
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (socket, peer_addr) = match accept_res {
                        Ok(pair) => pair,
                        Err(error) => {
                            warn!(?error, "Intent bridge accept failed");
                            continue;
                        }
                    };

                    let bus = Arc::clone(&intent_bus);
                    let local_node_id = self.local_node_id.clone();
                    let request_timeout = self.request_timeout;
                    tokio::spawn(async move {
                        if let Err(error) = handle_inbound_connection(
                            socket,
                            bus,
                            local_node_id,
                            request_timeout,
                        )
                        .await
                        {
                            warn!(?error, %peer_addr, "Intent bridge inbound connection failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// เริ่มต้น Forwarder สำหรับส่ง Intent ขาออกไปยังโหนดอื่น
    /// จะตรวจสอบว่า Intent ควรถูก Forward หรือไม่ก่อนส่ง
    pub async fn start_forwarder(
        &self,
        intent_bus: Arc<IntentBus>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let mut subscriber = intent_bus.subscribe();
        info!(node_id = %self.local_node_id, "Intent bridge forwarder started");

        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if cancel.is_cancelled() {
                        info!(node_id = %self.local_node_id, "Intent bridge forwarder shutting down");
                        break;
                    }
                }
                intent = subscriber.receive() => {
                    let Some(intent) = intent else {
                        break;
                    };

                    if !should_forward_intent(&self.local_node_id, &intent) {
                        continue;
                    }

                    let target_node = match intent.metadata.get(META_TARGET_NODE) {
                        Some(target) => target.clone(),
                        None => continue,
                    };

                    self.forward_intent(&target_node, intent).await?;
                }
            }
        }

        Ok(())
    }

    /// ส่ง Intent ไปยังโหนดปลายทางผ่าน TCP พร้อมรอ ACK
    /// ใช้ serialization แบบ JSON สำหรับส่งข้อมูล และ retry ด้วย timeout
    async fn forward_intent(&self, target_node: &str, intent: Intent) -> Result<()> {
        let target_addr = self
            .peers
            .read()
            .await
            .get(target_node)
            .copied()
            .ok_or_else(|| anyhow!("unknown intent bridge peer: {target_node}"))?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(target_addr))
            .await
            .context("intent bridge connect timed out")?
            .with_context(|| format!("intent bridge failed to connect to {target_addr}"))?;

        let envelope = RoutedIntentEnvelope { intent };
        let line = format!(
            "{}\n",
            serde_json::to_string(&envelope).context("intent bridge encode failed")?
        );

        timeout(self.request_timeout, stream.write_all(line.as_bytes()))
            .await
            .context("intent bridge write timed out")?
            .context("intent bridge write failed")?;
        timeout(self.request_timeout, stream.flush())
            .await
            .context("intent bridge flush timed out")?
            .context("intent bridge flush failed")?;

        let mut reader = BufReader::new(stream);
        let mut ack_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut ack_line))
            .await
            .context("intent bridge ack timed out")?
            .context("intent bridge ack read failed")?;

        let ack: RoutedIntentAck =
            serde_json::from_str(&ack_line).context("intent bridge ack decode failed")?;
        if !ack.accepted {
            return Err(anyhow!(
                "intent bridge peer {} rejected intent: {}",
                ack.node_id,
                ack.error.unwrap_or_else(|| "unknown error".to_string())
            ));
        }

        debug!(target_node, "Intent bridge forwarded delegated intent");
        Ok(())
    }
}

/// ตรวจสอบว่า Intent ควรถูก Forward ไปยังโหนดอื่นหรือไม่
/// Intent จะถูก Forward ต่อเมื่ออยู่ในโหมด Delegated และเป้าหมายไม่ใช่โหนดท้องถิ่น
fn should_forward_intent(local_node_id: &str, intent: &Intent) -> bool {
    intent.metadata.get(META_ROUTING_MODE).map(String::as_str) == Some(ROUTING_MODE_DELEGATED)
        && intent
            .metadata
            .get(META_TARGET_NODE)
            .is_some_and(|target_node| target_node != local_node_id)
}

/// จัดการการเชื่อมต่อขาเข้า (Inbound Connection) จากโหนดอื่น
/// อ่าน Intent จาก Socket, ตรวจสอบเป้าหมาย, และเผยแพร่เข้าสู่ Intent Bus
/// ส่ง ACK กลับเพื่อยืนยันการรับ
async fn handle_inbound_connection(
    socket: TcpStream,
    intent_bus: Arc<IntentBus>,
    local_node_id: String,
    request_timeout: Duration,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    timeout(request_timeout, buf_reader.read_line(&mut line))
        .await
        .context("intent bridge read timed out")?
        .context("intent bridge read failed")?;

    let envelope: RoutedIntentEnvelope =
        serde_json::from_str(&line).context("intent bridge decode failed")?;
    let target_ok = envelope
        .intent
        .metadata
        .get(META_TARGET_NODE)
        .is_none_or(|target| target == &local_node_id);

    let ack = if target_ok {
        intent_bus
            .publish(envelope.intent)
            .await
            .context("intent bridge publish failed")?;
        RoutedIntentAck {
            accepted: true,
            node_id: local_node_id,
            error: None,
        }
    } else {
        RoutedIntentAck {
            accepted: false,
            node_id: local_node_id,
            error: Some("intent target does not match this node".to_string()),
        }
    };

    let ack_line = format!(
        "{}\n",
        serde_json::to_string(&ack).context("intent bridge ack encode failed")?
    );
    timeout(request_timeout, writer.write_all(ack_line.as_bytes()))
        .await
        .context("intent bridge ack write timed out")?
        .context("intent bridge ack write failed")?;
    timeout(request_timeout, writer.flush())
        .await
        .context("intent bridge ack flush timed out")?
        .context("intent bridge ack flush failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_bus::{
        IntentPriority, IntentType, META_TARGET_NODE, ROUTING_MODE_DELEGATED, ROUTING_MODE_LOCAL,
    };
    use tokio::time::timeout;

    /// ทดสอบว่า Intent จะถูก Forward เฉพาะเมื่ออยู่ในโหมด Delegated และเป้าหมายไม่ใช่โหนดท้องถิ่น
    #[test]
    fn forwards_only_delegated_remote_intents() {
        let local = "node-a";
        let delegated_remote = Intent::new(
            "1",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::High,
            "test",
        )
        .with_metadata(META_ROUTING_MODE, ROUTING_MODE_DELEGATED)
        .with_metadata(META_TARGET_NODE, "node-b");
        assert!(should_forward_intent(local, &delegated_remote));

        let delegated_local = delegated_remote
            .clone()
            .with_metadata(META_TARGET_NODE, "node-a");
        assert!(!should_forward_intent(local, &delegated_local));

        let local_intent = delegated_remote
            .clone()
            .with_metadata(META_ROUTING_MODE, ROUTING_MODE_LOCAL);
        assert!(!should_forward_intent(local, &local_intent));
    }

    /// ทดสอบว่า Intent Bridge สามารถ Forward Intent ไปยัง Listener ของอีกโหนดได้สำเร็จ
    #[tokio::test]
    async fn bridge_forwards_intent_to_remote_listener() {
        let target_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind loopback listener: {error}"),
        };
        let target_addr = target_listener.local_addr().unwrap();
        drop(target_listener);

        let target_bus = Arc::new(IntentBus::new(16));
        let source_bus = Arc::new(IntentBus::new(16));
        let target_cancel = CancellationToken::new();
        let source_cancel = CancellationToken::new();

        let target_bridge = IntentBridge::new(
            "node-b",
            &[],
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        let source_bridge = IntentBridge::new(
            "node-a",
            &[IntentBridgePeerConfig {
                node_id: "node-b".to_string(),
                addr: target_addr.to_string(),
                available_agent_slots: 1,
                trust_score: 100,
                capabilities: vec!["small".to_string()],
            }],
            Duration::from_secs(1),
            Duration::from_secs(2),
        );

        let target_listener_task = tokio::spawn({
            let bus = Arc::clone(&target_bus);
            let cancel = target_cancel.clone();
            async move { target_bridge.start_listener(bus, target_addr, cancel).await }
        });
        let source_forwarder_task = tokio::spawn({
            let bus = Arc::clone(&source_bus);
            let cancel = source_cancel.clone();
            async move { source_bridge.start_forwarder(bus, cancel).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut subscriber = target_bus.subscribe();
        let delegated_intent = Intent::new(
            "delegated-1",
            IntentType::Command,
            "spawn-agent",
            IntentPriority::High,
            "source-test",
        )
        .with_metadata(META_ROUTING_MODE, ROUTING_MODE_DELEGATED)
        .with_metadata(META_TARGET_NODE, "node-b");
        source_bus.publish(delegated_intent.clone()).await.unwrap();

        let received = timeout(Duration::from_secs(2), subscriber.receive())
            .await
            .expect("timed out waiting for delegated intent")
            .expect("expected delegated intent");
        assert_eq!(received.id, delegated_intent.id);
        assert_eq!(received.payload, "spawn-agent");
        assert_eq!(
            received.metadata.get(META_TARGET_NODE).map(String::as_str),
            Some("node-b")
        );

        source_cancel.cancel();
        target_cancel.cancel();
        source_forwarder_task.await.unwrap().unwrap();
        target_listener_task.await.unwrap().unwrap();
    }
}
