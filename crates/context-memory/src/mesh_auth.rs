//! Mutual authentication + integrity สำหรับ P2P mesh (Hardening H6)
//!
//! ปิดช่องโหว่ที่ mesh transport เป็น raw TCP + JSON plaintext ไม่มีการ
//! พิสูจน์ตัวตน peer — ใครต่อ TCP มาถึง port ก็ยัด record ปลอม/ปลอมเป็น node
//! trust สูงได้ ซึ่งขัดกับ Zero-Trust ของโปรเจกต์
//!
//! กลไก: ทุก [`P2PMessage`] ถูกห่อใน [`SignedWire`] ที่แนบ HMAC-SHA256
//! คำนวณด้วย pre-shared key ต่อ mesh — ผู้รับตรวจ tag ก่อนประมวลผล ปฏิเสธ
//! ข้อความที่ signature ไม่ผ่าน (ปลอม/ถูกแก้กลางทาง) และปฏิเสธ replay
//! (timestamp นอก window หรือ nonce ซ้ำ) trust_score จึงมีความหมายจริง
//! เพราะผูกกับ identity ที่ปลอมไม่ได้ (ต้องถือ key จึงจะเซ็นในนาม node ได้)
//!
//! หมายเหตุ: เฟสนี้ให้ integrity + authenticity + anti-replay — ยังไม่เข้ารหัส
//! สาย (confidentiality) ซึ่งเป็นงานของ mTLS เฟสถัดไป

use crate::p2p_mesh::P2PMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// ขนาด block ของ SHA-256 (ไบต์) — ใช้ pad key ใน HMAC
const SHA256_BLOCK: usize = 64;
/// ช่วงเวลาที่ยอมรับข้อความ (มิลลิวินาที) — เกินกว่านี้ทั้งเก่าและอนาคตถือ replay/skew
const REPLAY_WINDOW_MS: u64 = 60_000;

/// ซองข้อความที่เซ็นแล้วบนสาย — ห่อ [`P2PMessage`] เดิมพร้อม nonce และ HMAC tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWire {
    /// ข้อความจริง
    pub msg: P2PMessage,
    /// ค่าสุ่มต่อข้อความ กัน replay (ต่อให้ timestamp ยังอยู่ใน window)
    pub nonce: String,
    /// HMAC-SHA256 (hex) เหนือ `serialize(msg) || 0x00 || nonce`
    pub sig: String,
}

/// สาเหตุที่ข้อความขาเข้าถูกปฏิเสธ
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeshAuthError {
    /// wire ไม่ถูก format (parse ไม่ได้)
    #[error("malformed signed wire: {0}")]
    Malformed(String),
    /// HMAC ไม่ตรง — ข้อความปลอมหรือถูกแก้ หรือ key ไม่ตรงกัน
    #[error("signature verification failed")]
    BadSignature,
    /// timestamp เก่า/อนาคตเกิน window
    #[error("message timestamp outside replay window")]
    StaleTimestamp,
    /// เห็น nonce นี้แล้วภายใน window — เป็น replay
    #[error("replayed nonce")]
    ReplayedNonce,
}

/// คำนวณ HMAC-SHA256 ตามนิยามมาตรฐาน (RFC 2104) ด้วย `sha2`
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // ย่อ key ที่ยาวเกิน block ด้วย hash ก่อน แล้ว pad ให้เต็ม block
    let mut block_key = Zeroizing::new([0u8; SHA256_BLOCK]);
    if key.len() > SHA256_BLOCK {
        let digest = Sha256::digest(key);
        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new([0x36u8; SHA256_BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; SHA256_BLOCK]);
    for i in 0..SHA256_BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad[..]);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad[..]);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// เปรียบเทียบ tag 32 ไบต์แบบคงเวลา กัน timing attack ตอน verify HMAC
#[must_use]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// ผู้เซ็น/ตรวจข้อความของ mesh — ถือ pre-shared key และ replay guard
pub struct MeshAuth {
    /// pre-shared key ต่อ mesh (zeroize เมื่อ drop)
    key: Zeroizing<Vec<u8>>,
    /// nonce ที่เห็นแล้ว → timestamp ของข้อความ (สำหรับ prune)
    seen_nonces: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for MeshAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ห้าม leak key ลง log/debug
        f.debug_struct("MeshAuth").finish_non_exhaustive()
    }
}

impl MeshAuth {
    /// สร้างตัวเซ็นจาก pre-shared key — key ต้องไม่ว่าง (เรียก fail closed
    /// จากฝั่ง caller ถ้า key ว่าง)
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key: Zeroizing::new(key),
            seen_nonces: Mutex::new(HashMap::new()),
        }
    }

    /// ข้อความที่ต้องเซ็น: `serialize(msg) || 0x00 || nonce` — คั่นด้วย NUL
    /// เพื่อไม่ให้เขต msg/nonce กำกวม (canonical framing)
    fn signing_bytes(inner_json: &str, nonce: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(inner_json.len() + 1 + nonce.len());
        buf.extend_from_slice(inner_json.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(nonce.as_bytes());
        buf
    }

    /// ห่อและเซ็นข้อความ คืน wire line (JSON) พร้อมส่ง
    ///
    /// # Errors
    /// คืน error หาก serialize ไม่สำเร็จ
    pub fn seal(&self, msg: &P2PMessage) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_string(msg)?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let tag = hmac_sha256(&self.key, &Self::signing_bytes(&inner, &nonce));
        let wire = SignedWire {
            msg: msg.clone(),
            nonce,
            sig: hex_encode(&tag),
        };
        serde_json::to_string(&wire)
    }

    /// ตรวจ wire line: parse → verify HMAC → ตรวจ replay → คืน [`P2PMessage`]
    ///
    /// # Errors
    /// คืน [`MeshAuthError`] หาก parse ไม่ได้, signature ไม่ผ่าน, timestamp
    /// นอก window หรือ nonce ซ้ำ
    pub fn open(&self, line: &str) -> Result<P2PMessage, MeshAuthError> {
        let wire: SignedWire = serde_json::from_str(line.trim())
            .map_err(|e| MeshAuthError::Malformed(e.to_string()))?;

        // 1. verify HMAC — re-serialize msg (deterministic) แล้วเทียบ tag
        let inner = serde_json::to_string(&wire.msg)
            .map_err(|e| MeshAuthError::Malformed(e.to_string()))?;
        let expected = hmac_sha256(&self.key, &Self::signing_bytes(&inner, &wire.nonce));
        let provided = hex_decode(&wire.sig).ok_or(MeshAuthError::BadSignature)?;
        if !constant_time_eq(&expected, &provided) {
            return Err(MeshAuthError::BadSignature);
        }

        // 2. replay window ตาม timestamp ของข้อความ
        let now = now_millis();
        let ts = wire.msg.timestamp_millis;
        let too_old = ts + REPLAY_WINDOW_MS < now;
        let too_new = ts > now + REPLAY_WINDOW_MS;
        if too_old || too_new {
            return Err(MeshAuthError::StaleTimestamp);
        }

        // 3. nonce dedup ภายใน window (prune ตัวที่ออก window ไปด้วย)
        let mut seen = self.seen_nonces.lock().expect("mesh nonce mutex poisoned");
        seen.retain(|_, &mut seen_ts| seen_ts + REPLAY_WINDOW_MS >= now);
        if seen.contains_key(&wire.nonce) {
            return Err(MeshAuthError::ReplayedNonce);
        }
        seen.insert(wire.nonce.clone(), ts);

        Ok(wire.msg)
    }
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_mesh::MessageType;
    use std::net::SocketAddr;

    fn sample_msg() -> P2PMessage {
        P2PMessage {
            from: "node-a".to_string(),
            from_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            to: None,
            msg_type: MessageType::Ping,
            data: vec![1, 2, 3],
            timestamp_millis: now_millis(),
        }
    }

    #[test]
    fn hmac_matches_known_rfc4231_vector() {
        // RFC 4231 test case 1: key=0x0b*20, data="Hi There"
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_encode(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn seal_then_open_round_trips() {
        let auth = MeshAuth::new(b"shared-mesh-key".to_vec());
        let msg = sample_msg();
        let line = auth.seal(&msg).expect("seal");
        let opened = auth.open(&line).expect("open");
        assert_eq!(opened.from, msg.from);
        assert_eq!(opened.data, msg.data);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signer = MeshAuth::new(b"key-one".to_vec());
        let verifier = MeshAuth::new(b"key-two".to_vec());
        let line = signer.seal(&sample_msg()).expect("seal");
        assert!(matches!(
            verifier.open(&line),
            Err(MeshAuthError::BadSignature)
        ));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let auth = MeshAuth::new(b"k".to_vec());
        let line = auth.seal(&sample_msg()).expect("seal");
        // แก้ไบต์ใน data ของ msg โดยไม่แตะ sig — HMAC ต้องจับได้
        let tampered = line.replace("[1,2,3]", "[1,2,4]");
        assert_ne!(tampered, line, "test setup: payload must actually change");
        assert!(matches!(
            auth.open(&tampered),
            Err(MeshAuthError::BadSignature)
        ));
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let auth = MeshAuth::new(b"k".to_vec());
        let line = auth.seal(&sample_msg()).expect("seal");
        auth.open(&line).expect("first delivery accepted");
        assert!(matches!(
            auth.open(&line),
            Err(MeshAuthError::ReplayedNonce)
        ));
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let auth = MeshAuth::new(b"k".to_vec());
        let mut msg = sample_msg();
        msg.timestamp_millis = now_millis().saturating_sub(REPLAY_WINDOW_MS * 3);
        let line = auth.seal(&msg).expect("seal");
        assert!(matches!(
            auth.open(&line),
            Err(MeshAuthError::StaleTimestamp)
        ));
    }

    #[test]
    fn malformed_wire_is_rejected() {
        let auth = MeshAuth::new(b"k".to_vec());
        assert!(matches!(
            auth.open("not json"),
            Err(MeshAuthError::Malformed(_))
        ));
    }
}
