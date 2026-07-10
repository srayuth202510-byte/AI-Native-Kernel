#![allow(missing_docs)]
//! Benchmarks สำหรับ mesh crypto: H6 (HMAC seal/open + replay guard) และ
//! H7 (PSK-derived cert + TLS handshake) — วัดทั้ง per-message hot path
//! และ per-connection setup cost

use context_memory::mesh_auth::{MeshAuth, hmac_sha256};
use context_memory::mesh_tls::MeshTls;
use context_memory::p2p_mesh::{MessageType, P2PMessage};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

const KEY: &[u8] = b"benchmark-mesh-pre-shared-key-0123";

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn sample_msg(payload_len: usize) -> P2PMessage {
    P2PMessage {
        from: "bench-node".to_string(),
        from_addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        to: None,
        msg_type: MessageType::RecordSync,
        data: vec![7u8; payload_len],
        timestamp_millis: now_millis(),
    }
}

// ── H6: HMAC + seal/open ──

fn bench_hmac(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    c.bench_function("hmac_sha256_1kb", |b| {
        b.iter(|| hmac_sha256(black_box(KEY), black_box(&data)));
    });
}

fn bench_seal(c: &mut Criterion) {
    // seal = serialize + nonce + HMAC (ไม่แตะ replay state) — per-message ขาส่ง
    let auth = MeshAuth::new(KEY.to_vec());
    let msg = sample_msg(256);
    c.bench_function("mesh_auth_seal_256b", |b| {
        b.iter(|| auth.seal(black_box(&msg)).unwrap());
    });
}

fn bench_open(c: &mut Criterion) {
    // open = parse + verify HMAC + replay check — per-message ขารับ
    // ใช้ MeshAuth ใหม่ต่อ iteration เพื่อไม่ให้ seen_nonces โตจนบิดผล
    c.bench_function("mesh_auth_open_256b", |b| {
        b.iter_batched(
            || {
                let auth = MeshAuth::new(KEY.to_vec());
                let line = auth.seal(&sample_msg(256)).unwrap();
                (auth, line)
            },
            |(auth, line)| {
                auth.open(black_box(&line)).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_seal_open_roundtrip(c: &mut Criterion) {
    // ต้นทาง crypto รวมต่อข้อความ 1 ตัว (sender seal + receiver open)
    c.bench_function("mesh_auth_seal_open_roundtrip_256b", |b| {
        b.iter_batched(
            || (MeshAuth::new(KEY.to_vec()), sample_msg(256)),
            |(auth, msg)| {
                let line = auth.seal(black_box(&msg)).unwrap();
                auth.open(black_box(&line)).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

// ── H7: PSK-derived cert + TLS handshake ──

fn bench_tls_from_psk(c: &mut Criterion) {
    // one-time-per-node: derive cert/key จาก PSK + build rustls config
    c.bench_function("mesh_tls_from_psk", |b| {
        b.iter(|| MeshTls::from_psk(black_box(KEY)).unwrap());
    });
}

fn bench_tls_handshake(c: &mut Criterion) {
    // per-connection: full TLS 1.3 handshake (mutual pinned cert) บน loopback
    let rt = Runtime::new().unwrap();
    let tls = Arc::new(MeshTls::from_psk(KEY).unwrap());

    let addr: SocketAddr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_tls = Arc::clone(&tls);
        // accept loop ค้างอยู่ตลอดอายุ runtime: รับ TCP → ทำ server handshake → drop
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = server_tls.acceptor();
                    tokio::spawn(async move {
                        let _ = acceptor.accept(stream).await;
                    });
                }
            }
        });
        addr
    });

    let client_tls = Arc::clone(&tls);
    c.bench_function("mesh_tls_handshake_loopback", |b| {
        b.iter(|| {
            rt.block_on(async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                let _stream = client_tls
                    .connector()
                    .connect(MeshTls::server_name(), tcp)
                    .await
                    .unwrap();
            });
        });
    });
}

criterion_group!(
    benches,
    bench_hmac,
    bench_seal,
    bench_open,
    bench_seal_open_roundtrip,
    bench_tls_from_psk,
    bench_tls_handshake,
);
criterion_main!(benches);
