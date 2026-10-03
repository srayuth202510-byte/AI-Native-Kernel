//! TLS termination ฝั่ง data plane
//!
//! ก่อนหน้านี้ gateway รับเฉพาะ HTTP เปล่า และบังคับให้วางหลัง reverse proxy ที่มี TLS
//! ซึ่งขัดกับ `docs/pivot_ai_infra_security.md` §6.1 ที่ให้ TLS termination เป็นส่วนหนึ่งของ
//! gateway และทำให้ต้องมีองค์ประกอบเพิ่มอีกชั้นก่อนถึงโมเดล — ซึ่งคือ hop ที่
//! ทำให้ tail latency แย่ลงโดยไม่มีใครเห็น
//!
//! # ทำไมเป็น TLS 1.3 เท่านั้น
//!
//! ใช้ ring provider แบบเดียวกับ `context-memory/src/mesh_tls.rs` (H7) และปิด
//! TLS 1.2 ออก ตัวเลือกอื่น (อ่าน cert จาก env, สร้าง cert เอง) ไม่มีในโมดูลนี้ —
//! key ต้องมาจากไฟล์ที่ operator ควบคุมเท่านั้น ถ้าไม่มี cert ก็**ไม่ยอมรับ
//! plaintext** แทนที่จะ fallback เงียบ ๆ (fail-closed)
//!
//! # ขอบเขตของ handshake
//!
//! handshake ทำใน task แยกต่อ connection เพื่อไม่ให้ client ที่ช้าหนึ่งตัวบล็อก
//! ทั้ง listener แต่การปล่อยให้ handshake ไหลได้ไม่จำกัดคือ DoS vector ตรง ๆ
//! (client ที่เปิด socket ค้างไว้ทั้งหมด) จึงมีเพดานจำนวน handshake ที่ค้างอยู่
//! และ timeout ต่อ handshake ตามกฎเดียวกับ external call อื่นใน `AGENTS.md`
//! เมื่อเพดานเต็ม เราตัดการเชื่อมต่อทิ้ง ไม่รอคิว — เพราะการรอคิวคือการให้
//! attacker ควบคุม latency ของผู้ใช้จริง

use std::future::Future;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

/// เวลาสูงสุดที่ยอมให้ TLS handshake ของ connection หนึ่งค้าง
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// จำนวน handshake ที่อนุญาตให้ค้างพร้อมกัน — เกินแล้วตัดการเชื่อมต่อทิ้ง
const MAX_PENDING_HANDSHAKES: usize = 256;

/// จำนวน accept ที่ล้มเหลวติดกันก่อนถือว่า listener พังจริง (กัน hot spin)
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 16;

/// ข้อผิดพลาดของชั้น TLS
#[derive(Debug, Error)]
pub enum TlsError {
    /// ตั้งค่าไม่ครบหรือไม่มีความหมาย
    #[error("tls config error: {0}")]
    Config(String),
    /// อ่านไฟล์ไม่ได้
    #[error("cannot read {path}: {source}")]
    Read {
        /// พาธที่อ่านไม่ได้
        path: PathBuf,
        /// สาเหตุจากระบบปฏิบัติการ
        source: std::io::Error,
    },
    /// ไฟล์ PEM ใช้ไม่ได้
    #[error("{path} is not a usable PEM file: {reason}")]
    Pem {
        /// พาธไฟล์
        path: PathBuf,
        /// เหตุผลที่ parse ไม่ผ่าน
        reason: String,
    },
    /// rustls ประกอบ config ไม่ได้
    #[error("cannot build rustls server config: {0}")]
    Build(String),
}

/// ตำแหน่งใบรับรองและกุญแจสำหรับ TLS termination
///
/// ทั้งคู่ต้องมาพร้อมกันเสมอ — ให้ครบคู่แล้วค่อยตัดสินใจเปิด TLS ดีกว่าการรับ
/// plaintext เฉย ๆ เมื่อ operator ใส่ค่าไม่ครบ
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsSettings {
    /// ไฟล์ certificate (PEM)
    pub cert_file: PathBuf,
    /// ไฟล์ private key (PEM: PKCS#8, PKCS#1 หรือ SEC1)
    pub key_file: PathBuf,
}

impl TlsSettings {
    /// ตรวจว่าค่าที่ระบุมีความหมาย
    ///
    /// # Errors
    /// คืน `Err` เมื่อพาธใดพาธหนึ่งว่าง
    pub fn validate(&self) -> Result<(), TlsError> {
        if self.cert_file.as_os_str().is_empty() {
            return Err(TlsError::Config("tls cert_file is empty".to_string()));
        }
        if self.key_file.as_os_str().is_empty() {
            return Err(TlsError::Config("tls key_file is empty".to_string()));
        }
        Ok(())
    }
}

/// สร้าง `TlsAcceptor` จากไฟล์ cert/key
///
/// # Errors
/// คืน `Err` เมื่ออ่านไฟล์ไม่ได้, ไม่พบ certificate ในไฟล์, parse private key
/// ไม่ได้ หรือประกอบ `ServerConfig` ไม่สำเร็จ — ทุกกรณีคืน error และไม่มีทาง
/// fallback ไปรับ plaintext
pub fn load_acceptor(settings: &TlsSettings) -> Result<TlsAcceptor, TlsError> {
    settings.validate()?;

    let certs = read_certs(&settings.cert_file)?;
    let key = read_private_key(&settings.key_file)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // TLS 1.3 เท่านั้น — 1.2 ถูกตัดออกที่ระดับ protocol ไม่ใช่แค่ cipher suite
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Build(format!("protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Build(format!("single cert: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn read_file(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let bytes = read_file(path)?;
    let certs: Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut BufReader::new(bytes.as_slice())).collect();
    let certs = certs.map_err(|e| TlsError::Pem {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    if certs.is_empty() {
        return Err(TlsError::Pem {
            path: path.to_path_buf(),
            reason: "no CERTIFICATE block found".to_string(),
        });
    }
    Ok(certs)
}

/// อ่าน private key รองรับทั้ง PKCS#8, PKCS#1 และ SEC1
///
/// PEM ที่ export มาจาก `openssl` เก่าอาจเป็น `RSA PRIVATE KEY` (PKCS#1) หรือ
/// `EC PRIVATE KEY` (SEC1) ซึ่งไม่ใช่ `PRIVATE KEY` (PKCS#8) — ถ้าอ่านเฉพาะ
/// PKCS#8 operator จะเจอ error ตอนหมุนใบรับรองครั้งแรก ทั้งสามรูปแบบผ่าน
/// `PemObject` ของ `rustls::pki_types` ซึ่งเลือก block ตามชื่อให้เอง
fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let bytes = read_file(path)?;
    PrivateKeyDer::from_pem_slice(bytes.as_slice()).map_err(|e| TlsError::Pem {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// ให้บริการ router ผ่าน TLS จนกว่า `shutdown` จะจบ
///
/// คืนหลังปิดการรับ connection ใหม่ **และ** รอ connection ที่ค้างอยู่จบ
/// (รวม stream ที่ยังส่งไม่จบอย่าง SSE) ด้วย `GracefulShutdown`
///
/// # Errors
/// คืน `Err` เมื่อ accept ล้มเหลวติดกันหลายครั้งจนถือว่า listener ใช้ไม่ได้
pub async fn serve_tls<F>(
    listener: TcpListener,
    router: Router,
    acceptor: TlsAcceptor,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let router = Arc::new(router);
    let builder = auto::Builder::new(TokioExecutor::new());
    // `GracefulShutdown` ไม่ใช่ `Clone` และ `shutdown()` กิด ownership
    // จึงเก็บเป็น `Option` ใน mutex เพื่อให้ task ที่รับ connection ขอ `watcher`
    // ได้ (การ borrow เท่านั้น) และให้จุดปิด server `take()` ออกมาเรียกเอง
    // lock ถูกถือเฉพาะตอน clone watcher ไม่ค้างข้าม `.await`
    let graceful = Arc::new(parking_lot::Mutex::new(Some(GracefulShutdown::new())));
    let permits = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let mut shutdown = std::pin::pin!(shutdown);
    let mut consecutive_errors: u32 = 0;

    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };

        let (stream, _peer) = match accepted {
            Ok(pair) => {
                consecutive_errors = 0;
                pair
            }
            Err(e) => {
                consecutive_errors += 1;
                tracing::warn!(
                    error = %e,
                    consecutive_errors,
                    "tls accept failed"
                );
                if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return Err(e);
                }
                continue;
            }
        };

        // ไม่มี permit = handshake ค้างเต็มเพดาน → ตัดทิ้ง ไม่เข้าคิว
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!("dropping connection: too many pending TLS handshakes");
            continue;
        };

        let acceptor = acceptor.clone();
        let router = Arc::clone(&router);
        let builder = builder.clone();
        let graceful = Arc::clone(&graceful);

        tokio::spawn(async move {
            // permit คืมจน handshake จบ — ปล่อยตอน handshake เสร็จไม่ว่าจะสำเร็จ
            // หรือล้มเหลว แล้ว connection ต่ออยู่ใน graceful watch แทน
            let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
            let tls_stream = match handshake.await {
                Ok(Ok(s)) => {
                    drop(permit);
                    s
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "tls handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = HANDSHAKE_TIMEOUT.as_secs(),
                        "tls handshake timed out"
                    );
                    return;
                }
            };

            // `axum::Router` เป็น `tower::Service` ส่วน hyper ต้องการ
            // `hyper::service::Service` — `TowerToHyperService` เป็นสะพาน
            // ต้อง clone router ออกมาก่อนเพราะ `Arc<Router>` เองไม่ implement
            let service = TowerToHyperService::new(router.as_ref().clone());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), service);
            let watcher = graceful.lock().as_ref().map(GracefulShutdown::watcher);
            if let Some(watcher) = watcher {
                let _ = watcher.watch(conn).await;
            }
        });
    }

    tracing::info!("no new tls connections; draining in-flight requests");
    // ต้องปลด mutex guard ก่อน `.await` — guard ของ `parking_lot` ไม่เป็น `Send`
    // ถ้าถือข้าม await แล้วฟังก์ชันนี้จะกลายเป็น non-Send และ `tokio::spawn` ใช้ไม่ได้
    let pending_shutdown = graceful.lock().take();
    if let Some(shutdown) = pending_shutdown {
        shutdown.shutdown().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-gw-tls-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn self_signed(dir: &Path) -> TlsSettings {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, generated.cert.pem()).expect("write cert");
        std::fs::write(&key, generated.key_pair.serialize_pem()).expect("write key");
        TlsSettings {
            cert_file: cert,
            key_file: key,
        }
    }

    #[test]
    fn loads_acceptor_from_pem_pair() {
        let dir = temp_dir("acceptor");
        let settings = self_signed(&dir);
        let acceptor = load_acceptor(&settings).expect("acceptor must build");
        let _ = acceptor;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_missing_cert_file() {
        let dir = temp_dir("missing-cert");
        let settings = TlsSettings {
            cert_file: dir.join("nope.pem"),
            key_file: dir.join("key.pem"),
        };
        let Err(err) = load_acceptor(&settings) else {
            panic!("missing cert file must fail to load");
        };
        assert!(matches!(err, TlsError::Read { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_pem_file_without_certificate_block() {
        let dir = temp_dir("no-cert-block");
        let settings = self_signed(&dir);
        std::fs::write(&settings.cert_file, "not a pem at all\n").expect("write junk");
        let Err(err) = load_acceptor(&settings) else {
            panic!("non-PEM cert file must fail to load");
        };
        assert!(matches!(err, TlsError::Pem { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_key_file_without_private_key_block() {
        let dir = temp_dir("no-key-block");
        let settings = self_signed(&dir);
        std::fs::write(&settings.key_file, "-----BEGIN CERTIFICATE-----\n\n")
            .expect("write wrong block");
        let Err(err) = load_acceptor(&settings) else {
            panic!("key file without PRIVATE KEY block must fail");
        };
        assert!(matches!(err, TlsError::Pem { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_half_configured_pair() {
        let settings = TlsSettings {
            cert_file: PathBuf::from("/tmp/cert.pem"),
            key_file: PathBuf::new(),
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn rejects_malformed_private_key_body() {
        // block ถูกต้องแต่ body เป็นขยะ — ต้อง fail ตอนโหลด ไม่ใช่ตอน handshake
        // ข้อสังเกต: PEM decode สำเร็จ (base64 ถูกต้อง) แต่ DER ใช้ไม่ได้ จึงไป
        // fail ที่ `with_single_cert` แทน — ข้อสำคัญคือไม่มีทางได้ acceptor
        let dir = temp_dir("bad-key-body");
        let settings = self_signed(&dir);
        std::fs::write(
            &settings.key_file,
            "-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----\n",
        )
        .expect("write junk key");
        let Err(err) = load_acceptor(&settings) else {
            panic!("malformed private key body must fail to load");
        };
        assert!(
            matches!(err, TlsError::Pem { .. } | TlsError::Build(_)),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
