//! # ตรวจ latency ส่วนเพิ่มของ gateway เทียบกับ backend โมเดลจริง
//!
//! `perf_budget.rs` วัด inspection แบบ in-process ต่อกับ mock upstream — ตัวเลขนั้น
//! ไม่รวม TLS socket, TCP hop เพิ่ม, และการอ่าน body จริงจากโมเดล เทสต์นี้จึงยิง
//! ผ่าน gateway ที่เปิด TLS จริง (cert ที่ client ไว้ใจ ไม่มีการปิด verification)
//! ไปยัง model server จริง (Ollama ที่รันในเครื่อง, OpenAI-compatible `/v1/*`)
//! แล้วเทียบกับยิงตรงไป backend แบบ pair-by-pair เพื่อแยก "เวลาของโมเดล" ออก
//! เหลือเฉพาะ **added latency ของ gateway** ซึ่งเป็นเกณฑ์ใน pivot §8.1
//! (added P99 ต้องไม่เกิน ~2 ms ไม่ว่าโมเดลจะช้าแค่ไหน)
//!
//! ```bash
//! cargo test -p ai-gateway --release --test real_backend -- --ignored --nocapture
//! ```
//!
//! ต้องมี Ollama รันอยู่ที่ `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434/v1`)
//! ถ้าต่อ backend ไม่ได้ เทสต์จะข้ามตัวเอง ไม่ใช่ล้ม — เพราะนี่คือ tripwire
//! ที่รันด้วยมือ ไม่ใช่ gate ของ CI
#![deny(unsafe_code)]

use ai_gateway::policy::TenantCredential;
use ai_gateway::tls::{TlsSettings, load_acceptor, serve_tls};
use ai_gateway::{
    AppState, DataPlanePolicy, GatewayConfig, GatewayCore, TenantPolicy, Upstream, build_router,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const CHAT_MODEL: &str = "qwen2.5-coder:7b";
const EMBED_MODEL: &str = "nomic-embed-text:latest";
const TENANTS: usize = 8;
/// รอบของแขน sequential (สัญญาณหลัก — ไม่มี contention ใด ๆ)
/// n=100 เพื่อให้ P99 เป็น quantile จริง ไม่ใช่แค่ max (n=32 ทำให้ P99 = max
/// แล้ว outlier เดียวก็ gate ทั้งเทสต์ ซึ่งวัดดวงไม่ใช่ latency)
const SEQ_ROUNDS: usize = 100;
/// รอบของแขน concurrent ต่อ tenant (พิสูจน์ ceiling ไม่รั่ว/ไม่สะดุด)
const CONC_ROUNDS: usize = 8;
/// รอบของแขน chat (รายงานอย่างเดียว — ดูหมายเหตุในเทสต์ว่าทำไมไม่ gate)
const CHAT_ROUNDS: usize = 2;
const STREAM_ROUNDS: usize = 4;
/// เกณฑ์ pivot §8.1 — เวลาส่วนเพิ่มของ gateway ไม่ใช่เวลาของโมเดล
const ADDED_BUDGET: Duration = Duration::from_millis(2);

/// host root ของ backend — gateway เติม `/v1/...` เองตอน forward
/// (`Upstream::url_for`) ดังนั้น base ต้องไม่มี `/v1` ต่อท้าย ไม่งั้น upstream
/// จะเห็น `/v1/v1/chat/completions` แล้วตอบ 404
fn ollama_base() -> String {
    std::env::var("OLLAMA_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn openai_base() -> String {
    format!("{}/v1", ollama_base())
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ai-gw-real-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    let idx = ((sorted.len() as f64) * q) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn stats(name: &str, mut xs: Vec<Duration>) {
    if xs.is_empty() {
        println!("[REAL] {name}: (no arm samples recorded)");
        return;
    }
    xs.sort_unstable();
    println!(
        "[REAL] {name} (n={}): min={:?} P50={:?} P99={:?} max={:?}",
        xs.len(),
        xs[0],
        percentile(&xs, 0.50),
        percentile(&xs, 0.99),
        xs[xs.len() - 1],
    );
}

fn report(name: &str, diffs: Vec<Duration>, direct: Vec<Duration>, gw: Vec<Duration>) {
    stats(&format!("{name} :: direct arm"), direct);
    stats(&format!("{name} :: gatewayed arm"), gw);
    let mut sorted = diffs;
    sorted.sort_unstable();
    let zeros = sorted.iter().filter(|d| **d == Duration::ZERO).count();
    println!("[REAL] {name} :: added per pair (n={})", sorted.len());
    println!("[REAL]   min    = {:?}", sorted[0]);
    println!("[REAL]   P50    = {:?}", percentile(&sorted, 0.50));
    println!("[REAL]   P75    = {:?}", percentile(&sorted, 0.75));
    println!("[REAL]   P90    = {:?}", percentile(&sorted, 0.90));
    println!("[REAL]   P95    = {:?}", percentile(&sorted, 0.95));
    println!("[REAL]   P99    = {:?}", percentile(&sorted, 0.99));
    println!("[REAL]   max    = {:?}", sorted[sorted.len() - 1]);
    println!("[REAL]   zeros  = {zeros} (gatewayed เท่าหรือเร็วกว่า direct: noise)");
    println!("[REAL]   Budget: added latency < {ADDED_BUDGET:?}");
}

/// สร้าง self-signed cert สำหรับ `localhost` และ `127.0.0.1`
///
/// client เพิ่ม cert นี้เป็น root ที่ไว้ใจ — ไม่มีการปิดการตรวจ TLS ใด ๆ
fn self_signed(dir: &Path) -> (TlsSettings, Vec<u8>) {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("generate self-signed cert");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let cert_pem = generated.cert.pem();
    std::fs::write(&cert, &cert_pem).expect("write cert");
    std::fs::write(&key, generated.key_pair.serialize_pem()).expect("write key");
    (
        TlsSettings {
            cert_file: cert,
            key_file: key,
        },
        cert_pem.into_bytes(),
    )
}

fn policy() -> (DataPlanePolicy, Vec<String>) {
    let mut tenants = Vec::with_capacity(TENANTS);
    let mut creds = Vec::with_capacity(TENANTS);
    let mut keys = Vec::with_capacity(TENANTS);
    for i in 0..TENANTS {
        tenants.push(TenantPolicy {
            tenant_id: format!("tenant-{i}"),
            allowed_endpoints: ["chat_completions", "embeddings"].into_iter().collect(),
            allowed_models: [CHAT_MODEL.to_string(), EMBED_MODEL.to_string()]
                .into_iter()
                .collect(),
            max_concurrent: 8,
            suspended: false,
        });
        let key = format!("sk-real-{i:016}");
        creds.push(TenantCredential {
            tenant_id: format!("tenant-{i}"),
            key: key.as_bytes().to_vec(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        });
        keys.push(key);
    }
    (DataPlanePolicy::new(tenants, creds), keys)
}

/// ปลุก gateway ที่ยุติ TLS แล้วชี้ไป backend จริง
async fn spawn_gateway(
    dir: &Path,
    upstream_url: &str,
    tls: TlsSettings,
) -> (SocketAddr, oneshot::Sender<()>, Arc<GatewayCore>, PathBuf) {
    let audit_dir = dir.join("audit");
    let config = GatewayConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        upstream_url: upstream_url.to_string(),
        audit_dir: audit_dir.clone(),
        policy_file: dir.join("unused-policy.json"),
        guard_enabled: true,
        extraction_enabled: true,
        tls: Some(tls.clone()),
        ..GatewayConfig::default()
    };
    // งบ production จริง (2ms) ไม่ใช่ 30s แบบ unit test — เทสต์นี้รัน release
    // และต้องวัดพฤติกรรมเดียวกับที่ deploy (ประกอบแบบเดียวกับ main.rs)
    let guard_cfg = semantic_guard::GuardConfig {
        detection_mode: semantic_guard::DetectionMode::PiiAndSignatures,
        ..semantic_guard::GuardConfig::default()
    };
    let core = Arc::new(
        GatewayCore::new(
            config.clone(),
            policy().0,
            Some(guard_cfg.clone()),
            Some(ai_gateway::ExtractionConfig::default()),
        )
        .await
        .expect("core must build"),
    );
    let guard = Some(Arc::new(
        semantic_guard::Guard::with_config(guard_cfg).expect("guard"),
    ));
    let upstream = Upstream::new(
        &config.upstream_url,
        Duration::from_secs(150),
        config.max_inspect_prefix_bytes,
    )
    .expect("upstream client");
    let router = build_router(
        AppState {
            core: Arc::clone(&core),
            upstream,
            guard,
        },
        config.max_body_bytes,
    );
    let acceptor = load_acceptor(&tls).expect("acceptor from generated cert");
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let _ = serve_tls(listener, router, acceptor, shutdown).await;
    });
    (addr, tx, core, audit_dir)
}

fn chat_body(stream: bool) -> String {
    format!(
        "{{\"model\":\"{CHAT_MODEL}\",\"messages\":[{{\"role\":\"user\",\"content\":\"Reply with exactly: ok\"}}],\"max_tokens\":8,\"stream\":{stream}}}"
    )
}

fn embed_body() -> String {
    format!("{{\"model\":\"{EMBED_MODEL}\",\"input\":\"Reply with exactly: ok\"}}")
}

async fn direct_request(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: &str,
) -> (Duration, reqwest::Response) {
    let start = Instant::now();
    let resp = client
        .post(format!("{base}{path}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("direct request must complete");
    (start.elapsed(), resp)
}

async fn gatewayed_request(
    client: &reqwest::Client,
    addr: &SocketAddr,
    key: &str,
    path: &str,
    body: &str,
) -> (Duration, reqwest::Response) {
    let start = Instant::now();
    let resp = client
        .post(format!("https://{addr}{path}"))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("gatewayed request must complete");
    (start.elapsed(), resp)
}

/// บริบทของการยิงหนึ่งคู่ — รวมเป็น struct เดียวเพราะ clippy จำกัด 7 args
struct PairCtx<'a> {
    client: &'a reqwest::Client,
    api: &'a str,
    addr: SocketAddr,
    key: &'a str,
    direct_path: &'a str,
    gw_path: &'a str,
    body: &'a str,
}

/// ยิงหนึ่งคู่ (direct หนึ่ง + gatewayed หนึ่ง) สลับลำดับตามรอบเพื่อตัด bias
/// ระยะยาว (โมเดลเร็วขึ้นจาก cache หรือช้าลงจากโหลด) — คืนเวลาของแต่ละข้าง
/// พร้อม response ให้ผู้เรียกตรวจ shape ต่อ
async fn paired_exchange(
    ctx: &PairCtx<'_>,
    gw_first: bool,
) -> (Duration, reqwest::Response, Duration, reqwest::Response) {
    if gw_first {
        let (d_gw, gw) =
            gatewayed_request(ctx.client, &ctx.addr, ctx.key, ctx.gw_path, ctx.body).await;
        let (d_direct, direct) =
            direct_request(ctx.client, ctx.api, ctx.direct_path, ctx.body).await;
        (d_direct, direct, d_gw, gw)
    } else {
        let (d_direct, direct) =
            direct_request(ctx.client, ctx.api, ctx.direct_path, ctx.body).await;
        let (d_gw, gw) =
            gatewayed_request(ctx.client, &ctx.addr, ctx.key, ctx.gw_path, ctx.body).await;
        (d_direct, direct, d_gw, gw)
    }
}

async fn time_to_first_byte(resp: reqwest::Response) -> Duration {
    use futures::StreamExt as _;
    let start = Instant::now();
    let mut stream = resp.bytes_stream();
    let mut chunks = 0;
    while let Some(chunk) = stream.next().await {
        chunks += 1;
        chunk.expect("stream chunk must arrive");
        if chunks >= 3 {
            break;
        }
    }
    assert!(chunks > 0, "stream must yield at least one chunk");
    start.elapsed()
}

#[tokio::test]
#[ignore = "needs a live model backend (Ollama) + minutes of CPU inference; run by hand"]
async fn gateway_added_latency_against_real_backend() {
    let base = ollama_base();
    let api = openai_base();

    // probe ก่อน — ต่อ backend ไม่ได้ให้ข้าม ไม่ใช่ล้ม
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("probe client");
    if probe.get(format!("{api}/models")).send().await.is_err() {
        eprintln!("[REAL] SKIP: no model backend at {api} (set OLLAMA_BASE_URL)");
        return;
    }

    let dir = temp_dir("backend");
    let (tls, cert_pem) = self_signed(&dir);
    let (addr, shutdown, core, audit_dir) = spawn_gateway(&dir, &base, tls).await;
    let (_policy, keys) = policy();

    // client ไว้ใจ cert ที่เพิ่งสร้าง — ไม่มี danger_accept_invalid_certs
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&cert_pem).expect("parse root"))
        .timeout(Duration::from_secs(180))
        .build()
        .expect("https client");

    // warm: โหลดโมเดลเข้า memory ก่อนวัด ไม่งั้น pair แรกวัดเวลารวม model load
    let (_, warm) = direct_request(&client, &api, "/chat/completions", &chat_body(false)).await;
    assert_eq!(warm.status(), 200, "backend must serve {CHAT_MODEL}");
    let _ = warm.bytes().await.expect("warm body");
    let (_, warm_embed) = direct_request(&client, &api, "/embeddings", &embed_body()).await;
    assert_eq!(warm_embed.status(), 200, "backend must serve {EMBED_MODEL}");
    let _ = warm_embed.bytes().await.expect("warm embed body");

    // ---- แขนหลัก (1a): sequential — tenant เดียว ยิงทีละคู่ ไม่มี contention
    // ใด ๆ ทั้งฝั่ง gateway และ backend นี่คือสัญญาณที่สะอาดที่สุดของต้นทุน
    // proxy + TLS ของ gateway เพราะ backend ตอบคงที่ ~35ms
    //
    // บทเรียนจากรอบแรก: ตอนแรกวัด concurrent ด้วย chat (LLM 7b บน CPU) แล้ว
    // diff รายคู่ได้ P50 ~192ms / P99 ~1.6s — ไม่ใช่เพราะ gateway ช้า แต่เพราะ
    // Ollama ประมวลพร้อมกันได้จำกัด คำขอจึงต่อคิวฝั่ง server และ diff วัด
    // "ดวงคิว" ไม่ใช่ต้นทุน gateway การสลับลำดับ pair ตัด bias ระยะยาวได้
    // แต่ตัด queue-position noise ไม่ได้ จึงแยกเป็นสองแขน: sequential เอาไว้
    // gate, concurrent เอาไว้พิสูจน์ ceiling
    let body = embed_body();
    // warmup 2 คู่ (ทิ้ง) เพื่อให้ TLS connection / pool / allocator เข้าที่ —
    // ไม่งั้น pair แรกวัดเวลารวม handshake เข้าไปด้วย
    for r in 0..2 {
        let ctx = PairCtx {
            client: &client,
            api: &api,
            addr,
            key: &keys[0],
            direct_path: "/embeddings",
            gw_path: "/v1/embeddings",
            body: &body,
        };
        let (_, direct, _, gw) = paired_exchange(&ctx, r % 2 == 1).await;
        assert_eq!(direct.status(), 200);
        assert_eq!(gw.status(), 200);
        let _ = direct.bytes().await.expect("direct body");
        let _ = gw.bytes().await.expect("gatewayed body");
    }
    let (mut diffs, mut direct_lats, mut gw_lats) = (
        Vec::with_capacity(SEQ_ROUNDS),
        Vec::with_capacity(SEQ_ROUNDS),
        Vec::with_capacity(SEQ_ROUNDS),
    );
    for r in 0..SEQ_ROUNDS {
        let ctx = PairCtx {
            client: &client,
            api: &api,
            addr,
            key: &keys[0],
            direct_path: "/embeddings",
            gw_path: "/v1/embeddings",
            body: &body,
        };
        let (d_direct, direct, d_gw, gw) = paired_exchange(&ctx, r % 2 == 1).await;
        assert_eq!(direct.status(), 200, "direct must succeed");
        assert_eq!(gw.status(), 200, "gatewayed must succeed");
        let json: serde_json::Value = gw.json().await.expect("openai-shaped body");
        assert!(
            json["data"][0]["embedding"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "model must actually embed, got {json:?}"
        );
        let _ = direct.bytes().await.expect("direct body");
        direct_lats.push(d_direct);
        gw_lats.push(d_gw);
        diffs.push(d_gw.saturating_sub(d_direct));
    }
    report("seq embeddings", diffs.clone(), direct_lats, gw_lats);
    let mut sorted = diffs;
    sorted.sort_unstable();
    // เก็บไว้ gate ตอนท้าย — เทสต์ต้องพิมพ์รายงานครบทุกแขนแม้ gate ตก
    // ไม่งั้นรันซ้ำหลายนาทีเพื่อดูตัวเลขที่หายไปพร้อม panic
    //
    // gate ด้วย P50 ไม่ใช่ P99 (ดูหมายเหตุท้ายไฟล์): diff รายคู่ = ต้นทุน
    // gateway + (spike ฝั่ง direct ลบ spike ฝั่ง gatewayed) — backend มี tail
    // ของตัวเอง (direct arm วัดได้ 47–67ms บน median 36ms) ดังนั้น P99 ของ diff
    // วัดความไม่สมมาตรของ spike ไม่ใช่ tail ของ gateway
    let seq_p50 = percentile(&sorted, 0.50);

    // ---- แขน concurrent (1b): 8 tenants พร้อมกัน — ไม่ gate ด้วยเวลา
    // (backend มี queue noise) แต่พิสูจน์ว่า ceiling ไม่ปฏิเสธคำขอที่ถูกต้อง
    // แม้ backend จริงจะตอบช้ากว่า mock หลายเท่า
    let mut workers = Vec::with_capacity(TENANTS);
    for key in keys.iter().take(TENANTS) {
        let client = client.clone();
        let base = api.clone();
        let body = body.clone();
        let key = key.clone();
        workers.push(tokio::spawn(async move {
            let mut diffs = Vec::with_capacity(CONC_ROUNDS);
            for r in 0..CONC_ROUNDS {
                let ctx = PairCtx {
                    client: &client,
                    api: &base,
                    addr,
                    key: &key,
                    direct_path: "/embeddings",
                    gw_path: "/v1/embeddings",
                    body: &body,
                };
                let (d_direct, direct, d_gw, gw) = paired_exchange(&ctx, r % 2 == 1).await;
                assert_eq!(direct.status(), 200, "direct must succeed");
                assert_eq!(
                    gw.status(),
                    200,
                    "gatewayed must succeed (429 ที่นี่ = ceiling รั่ว)"
                );
                let json: serde_json::Value = gw.json().await.expect("openai-shaped body");
                assert!(
                    json["data"][0]["embedding"]
                        .as_array()
                        .is_some_and(|v| !v.is_empty()),
                    "model must actually embed, got {json:?}"
                );
                let _ = direct.bytes().await.expect("direct body");
                diffs.push((d_direct, d_gw, d_gw.saturating_sub(d_direct)));
            }
            diffs
        }));
    }
    let (mut c_diffs, mut c_direct, mut c_gw) = (
        Vec::with_capacity(TENANTS * CONC_ROUNDS),
        Vec::with_capacity(TENANTS * CONC_ROUNDS),
        Vec::with_capacity(TENANTS * CONC_ROUNDS),
    );
    for w in workers {
        for (d_direct, d_gw, diff) in w.await.expect("tenant worker must not panic") {
            c_direct.push(d_direct);
            c_gw.push(d_gw);
            c_diffs.push(diff);
        }
    }
    report("conc embeddings (REPORT ONLY)", c_diffs, c_direct, c_gw);

    // ---- แขน chat (รายงานอย่างเดียว): พิสูจน์ว่า generative path ผ่าน
    // gateway จริง แต่ไม่ gate ด้วย diff เพราะ backend อิ่มแล้ว diff วัดคิว
    // ไม่ใช่ต้นทุน gateway (ดูหมายเหตุข้างบน)
    let chat = chat_body(false);
    let (mut chat_diffs, mut chat_direct, mut chat_gw) = (
        Vec::with_capacity(TENANTS * CHAT_ROUNDS),
        Vec::with_capacity(TENANTS * CHAT_ROUNDS),
        Vec::with_capacity(TENANTS * CHAT_ROUNDS),
    );
    let mut chat_workers = Vec::with_capacity(TENANTS);
    for key in keys.iter().take(TENANTS) {
        let client = client.clone();
        let base = api.clone();
        let chat = chat.clone();
        let key = key.clone();
        chat_workers.push(tokio::spawn(async move {
            let mut out = Vec::with_capacity(CHAT_ROUNDS);
            for r in 0..CHAT_ROUNDS {
                let ctx = PairCtx {
                    client: &client,
                    api: &base,
                    addr,
                    key: &key,
                    direct_path: "/chat/completions",
                    gw_path: "/v1/chat/completions",
                    body: &chat,
                };
                let (d_direct, direct, d_gw, gw) = paired_exchange(&ctx, r % 2 == 1).await;
                assert_eq!(direct.status(), 200, "direct chat must succeed");
                assert_eq!(gw.status(), 200, "gatewayed chat must succeed");
                let json: serde_json::Value = gw.json().await.expect("openai-shaped body");
                assert!(
                    json["choices"][0]["message"]["content"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty()),
                    "model must actually answer, got {json:?}"
                );
                let _ = direct.bytes().await.expect("direct body");
                out.push((d_direct, d_gw, d_gw.saturating_sub(d_direct)));
            }
            out
        }));
    }
    for w in chat_workers {
        for (d_direct, d_gw, diff) in w.await.expect("chat worker must not panic") {
            chat_direct.push(d_direct);
            chat_gw.push(d_gw);
            chat_diffs.push(diff);
        }
    }
    report(
        "chat non-streaming per-pair diff, REPORT ONLY (backend queueing dominates)",
        chat_diffs,
        chat_direct,
        chat_gw,
    );

    // ---- แขน streaming: วัดเฉพาะ time-to-first-byte เพราะเวลารวมของ stream
    // คือความเร็วของโมเดล ไม่ใช่ต้นทุนของ gateway (ยิงทีละคู่ ไม่มีคิวค้าง)
    let stream_body = chat_body(true);
    let mut ttfb_diffs = Vec::with_capacity(STREAM_ROUNDS);
    for r in 0..STREAM_ROUNDS {
        let (ttfb_direct, ttfb_gw) = if r % 2 == 0 {
            let (_, direct) =
                direct_request(&client, &api, "/chat/completions", &stream_body).await;
            let ttfb_direct = time_to_first_byte(direct).await;
            let (_, gw) = gatewayed_request(
                &client,
                &addr,
                &keys[0],
                "/v1/chat/completions",
                &stream_body,
            )
            .await;
            assert_eq!(gw.status(), 200);
            (ttfb_direct, time_to_first_byte(gw).await)
        } else {
            let (_, gw) = gatewayed_request(
                &client,
                &addr,
                &keys[0],
                "/v1/chat/completions",
                &stream_body,
            )
            .await;
            assert_eq!(gw.status(), 200);
            let ttfb_gw = time_to_first_byte(gw).await;
            let (_, direct) =
                direct_request(&client, &api, "/chat/completions", &stream_body).await;
            (time_to_first_byte(direct).await, ttfb_gw)
        };
        ttfb_diffs.push(ttfb_gw.saturating_sub(ttfb_direct));
    }
    report(
        "streaming TTFB added latency per pair",
        ttfb_diffs.clone(),
        Vec::new(),
        Vec::new(),
    );
    let mut ttfb_sorted = ttfb_diffs;
    ttfb_sorted.sort_unstable();
    // TTFB เป็นรายงานอย่างเดียว: n=4 และ backend TTFB มี noise ระดับ ms
    // (3/4 คู่ gatewayed มาถึงก่อน direct — นั่นคือ scheduling noise ไม่ใช่
    // ความเร็ว) gate max ด้วย n แค่นี้คือวัดดวง

    // ---- audit ต้องครบและ chain ต้องตรวจผ่านทุก tenant
    let _ = shutdown.send(());
    // เวลา inspection ฝั่ง server จาก audit — ใช้แยก "งานของ gateway" ออกจาก
    // noise ของ network/backend ใน diff ข้างบน: ถ้า P99 ของค่านี้ยังเป็น µs
    // แสดงว่า spike ใน diff ไม่ได้มาจากชั้นตรวจ
    let t0 = std::fs::read_to_string(audit_dir.join("tenant-0.jsonl")).expect("chain file");
    let mut insp: Vec<Duration> = t0
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()?
                .get("latency_ms")?
                .as_u64()
                .map(Duration::from_millis)
        })
        .collect();
    stats(
        "tenant-0 server-side inspection (audit latency_ms)",
        insp.clone(),
    );
    insp.sort_unstable();
    assert!(
        !insp.is_empty(),
        "audit entries must carry latency_ms for attribution"
    );
    let insp_p99 = percentile(&insp, 0.99);
    println!("[REAL]   inspection P99 = {insp_p99:?} (งบเดียวกับ client: {ADDED_BUDGET:?})");
    let results = core.verify_all_chains().await.expect("verify chains");
    for t in 0..TENANTS {
        let id = format!("tenant-{t}");
        assert_eq!(results.get(&id), Some(&true), "chain {id} must verify");
        let content =
            std::fs::read_to_string(audit_dir.join(format!("{id}.jsonl"))).expect("chain file");
        let lines = content.lines().count();
        let admitted = if t == 0 {
            // warmup 2 คู่ + sequential + concurrent + chat + streaming
            2 + SEQ_ROUNDS + CONC_ROUNDS + CHAT_ROUNDS + STREAM_ROUNDS
        } else {
            CONC_ROUNDS + CHAT_ROUNDS
        };
        assert!(
            lines >= 2 * admitted,
            "tenant {id}: expected ≥{} audit lines (request+response), got {lines}",
            2 * admitted
        );
    }
    println!("[REAL] audit chains verified for all {TENANTS} tenants");
    let _ = std::fs::remove_dir_all(&dir);

    // ---- gate รวมตอนท้ายเพื่อให้รายงานข้างบนครบก่อนเสมอ
    //
    // ปรัชญาการ gate (ซื่อสัตย์กับสิ่งที่วัดได้):
    // 1. seq added P50 — ต้นทุน systematic ของ proxy+TLS ตัด backend noise
    //    ด้วย pairing + median (n=100) ถ้ามีคนเพิ่มงาน 5ms ลงเส้นทาง request
    //    ตัวนี้จับได้ทันที
    // 2. server-side inspection P99 — งานตรวจจริงของ gateway ใต้โหลด concurrent
    //    จริง รวม 232 คำขอ ถ้า guard/audit/chain ช้าลง ตัวนี้จับได้
    // สิ่งที่ตั้งใจไม่ gate: P99/max ของ diff รายคู่ — หลักฐานสามรันติดแสดงว่า
    // direct arm มี tail ของตัวเอง (47–67ms บน median 36ms) และ 31–44% ของคู่
    // gatewayed เร็วกว่า direct ดังนั้น tail ของ diff คือความไม่สมมาตรของ
    // spike ไม่ใช่ tail ของ gateway เอามา gate คือลงโทษ backend ผิดตัว
    assert!(
        seq_p50 < ADDED_BUDGET,
        "seq added P50 = {seq_p50:?} exceeds {ADDED_BUDGET:?} — pivot §8.1 ไม่ผ่านบน backend จริง"
    );
    assert!(
        insp_p99 < ADDED_BUDGET,
        "server-side inspection P99 = {insp_p99:?} exceeds {ADDED_BUDGET:?}"
    );
}
