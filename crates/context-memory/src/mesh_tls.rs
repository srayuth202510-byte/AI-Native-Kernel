//! mTLS สำหรับ P2P mesh — ชั้นเข้ารหัสสาย (confidentiality) ต่อยอดจาก H6
//! (Hardening H7)
//!
//! H6 ให้ integrity + authenticity + anti-replay ผ่าน HMAC แต่ payload ยัง
//! วิ่ง plaintext บนสาย ดักอ่านได้ H7 ปิดช่องนี้ด้วย TLS 1.3 โดยไม่ต้องมี
//! PKI: **derive cert/key แบบ deterministic จาก pre-shared key เดียวกับ H6**
//! ทุก node ที่ถือ PSK จะได้ identity เดียวกัน แล้ว pin peer cert ให้ตรง
//! identity นั้น — peer ที่ไม่ถือ PSK สร้าง cert ที่ตรงไม่ได้ (และพิสูจน์
//! ครอบครอง private key ตอน handshake ไม่ได้) จึงถูกปฏิเสธที่ชั้น TLS
//!
//! ได้ confidentiality กัน active MITM โดย operator ยังจัดการ secret เดียว
//! (`p2p_mesh_key_hex`) เหมือนเดิม ไม่ต้องแจก cert หรือตั้ง CA
//!
//! การแบ่ง identity ราย node ยังทำที่ชั้น H6 (node_id ใน HMAC-signed message)
//! — TLS พิสูจน์ "เป็นสมาชิก mesh (ถือ PSK)", H6 พิสูจน์ authenticity ราย
//! ข้อความในโดเมนความเชื่อถือเดียวกัน

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// ป้ายกำกับสำหรับ derive seed แยกจากการใช้งาน PSK อื่น (domain separation)
const TLS_SEED_LABEL: &[u8] = b"ank-mesh-tls-v1";
/// ชื่อ SNI คงที่ของ mesh — ไม่ได้ใช้ verify (เรา pin cert) แต่ต้องมีค่า
const MESH_SERVER_NAME: &str = "ank-mesh";

/// derive seed 32 ไบต์แบบ deterministic จาก PSK: `SHA256(psk || label)`
fn derive_seed(psk: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(psk);
    hasher.update(TLS_SEED_LABEL);
    hasher.finalize().into()
}

/// สร้าง PKCS#8 DER ของ Ed25519 private key จาก seed 32 ไบต์
/// (prefix เป็น template มาตรฐานของ PKCS#8 v1 สำหรับ Ed25519)
fn ed25519_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    // 302e020100300506032b657004220420 || seed(32)
    const PKCS8_ED25519_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&PKCS8_ED25519_PREFIX);
    der.extend_from_slice(seed);
    der
}

/// derive cert + private key แบบ deterministic จาก PSK — ทุก node ที่ถือ PSK
/// เดียวกันจะได้ผลลัพธ์ byte-for-byte เท่ากัน (serial + validity คงที่,
/// Ed25519 signing เป็น deterministic)
///
/// # Errors
/// คืน error หากสร้าง keypair/cert ไม่สำเร็จ
fn derive_identity(
    psk: &[u8],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, SerialNumber};

    let seed = derive_seed(psk);
    let pkcs8 = ed25519_pkcs8_der(&seed);
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.clone()),
        &PKCS_ED25519,
    )
    .map_err(|e| format!("derive keypair: {e}"))?;

    let mut params =
        CertificateParams::new(vec![MESH_SERVER_NAME.to_string()]).map_err(|e| e.to_string())?;
    // ค่าคงที่เพื่อให้ cert DER reproducible ข้าม node (serial + validity คงที่)
    params.serial_number = Some(SerialNumber::from(1u64));
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2100, 1, 1);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("self-sign cert: {e}"))?;
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::try_from(pkcs8).map_err(|e| format!("key der: {e}"))?;
    Ok((cert_der, key_der))
}

/// verifier ที่ยอมรับ peer cert เฉพาะเมื่อ **ตรง byte-for-byte** กับ cert ที่
/// derive จาก PSK ของเรา — ทำหน้าที่ทั้งฝั่ง client (verify server) และ
/// server (verify client) การตรวจ signature ของ handshake ยัง delegate ไป
/// crypto provider เพื่อพิสูจน์ว่า peer ครอบครอง private key จริง
#[derive(Debug)]
struct PinnedCertVerifier {
    expected: CertificateDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
    fn check_pinned(&self, presented: &CertificateDer<'_>) -> bool {
        presented.as_ref() == self.expected.as_ref()
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.check_pinned(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "mesh TLS: server cert does not match PSK-derived identity".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for PinnedCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.check_pinned(end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "mesh TLS: client cert does not match PSK-derived identity".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// acceptor + connector สำหรับ mesh mTLS — สร้างจาก PSK เดียวกับ H6
pub struct MeshTls {
    acceptor: TlsAcceptor,
    connector: TlsConnector,
}

impl std::fmt::Debug for MeshTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshTls").finish_non_exhaustive()
    }
}

impl MeshTls {
    /// สร้าง TLS acceptor/connector จาก PSK — cert/key derive แบบ
    /// deterministic และ verifier pin ให้ตรง identity ที่ derive ได้
    ///
    /// # Errors
    /// คืน error หาก derive identity หรือ build rustls config ไม่สำเร็จ
    pub fn from_psk(psk: &[u8]) -> Result<Self, String> {
        let (cert, key) = derive_identity(psk)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedCertVerifier {
            expected: cert.clone(),
            provider: Arc::clone(&provider),
        });

        // ── server side: ต้อง client auth และ pin client cert ──
        let server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("server tls versions: {e}"))?
            .with_client_cert_verifier(verifier.clone() as Arc<dyn ClientCertVerifier>)
            .with_single_cert(vec![cert.clone()], key.clone_key())
            .map_err(|e| format!("server single cert: {e}"))?;

        // ── client side: present cert เดียวกัน และ pin server cert ──
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("client tls versions: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier as Arc<dyn ServerCertVerifier>)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| format!("client auth cert: {e}"))?;

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            connector: TlsConnector::from(Arc::new(client_config)),
        })
    }

    /// TLS acceptor สำหรับ inbound connection
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }

    /// TLS connector สำหรับ outbound connection
    #[must_use]
    pub fn connector(&self) -> TlsConnector {
        self.connector.clone()
    }

    /// ชื่อ server สำหรับ TLS connect (เรา pin cert จึงเป็นค่าคงที่)
    #[must_use]
    pub fn server_name() -> ServerName<'static> {
        ServerName::try_from(MESH_SERVER_NAME).expect("static mesh server name is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_derivation_is_deterministic() {
        // PSK เดียวกัน → cert/key เดียวกัน byte-for-byte (ต่าง node verify กันได้)
        let (c1, _k1) = derive_identity(b"mesh-secret").expect("derive");
        let (c2, _k2) = derive_identity(b"mesh-secret").expect("derive");
        assert_eq!(c1.as_ref(), c2.as_ref(), "same PSK must yield same cert");
    }

    #[test]
    fn different_psk_yields_different_identity() {
        let (c1, _) = derive_identity(b"key-one").expect("derive");
        let (c2, _) = derive_identity(b"key-two").expect("derive");
        assert_ne!(
            c1.as_ref(),
            c2.as_ref(),
            "different PSK must yield different cert"
        );
    }

    #[test]
    fn mesh_tls_builds_from_psk() {
        // สร้าง acceptor/connector สำเร็จ = rustls config ประกอบได้จริง
        let tls = MeshTls::from_psk(b"a-shared-mesh-secret").expect("build mesh tls");
        let _ = tls.acceptor();
        let _ = tls.connector();
    }
}
