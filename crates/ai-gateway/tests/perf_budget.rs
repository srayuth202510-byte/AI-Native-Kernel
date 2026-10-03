//! # เทสต์งบเวลา Data Plane — เอกสารเป้าหมาย `docs/pivot_ai_infra_security.md` §8
//!
//! ข้อ 1 ใน "What would kill this" ระบุว่า *"If the added P99 exceeds ~2 ms in a
//! real vLLM deployment, buyers reject it regardless of features. Measure in
//! step 4, before building anything else."* — ไฟล์นี้คือการวัดนั้น
//!
//! **ต้องรันด้วย `--release`** เพราะงบ 2ms ของ production ไม่เสถียรใน debug build
//! (regex และ MinHash ถูกคอมไพล์แบบไม่ optimize) ตัวเลขใน debug build ไม่มีความหมาย
//! กับ production และจะทำให้เข้าใจผิดว่า budget ถูกละเมิด
//!
//! ```bash
//! cargo test -p ai-gateway --release --test perf_budget -- --nocapture
//! ```
//!
//! แต่ละชั้นวัดแยกกัน เพราะเมื่อรวมกันจะไม่รู้ว่าตัวไหนกินเวลา — และถ้าอัปสตรีมในอนาคต
//! ชั้นไหนช้าลง เราต้องชี้ชั่วได้โดยไม่ต้องไล่หาทั้ง pipeline
//!
//! **การเขียน audit อยู่บนเส้นทาง request ไม่ใช่ background** — `inspect_request` เรียก
//! `record_audit().await` inline (`lib.rs`) ซึ่งเป็น file append + flush ใต้ per-tenant
//! mutex ทุก request และ fail-closed ถ้าเขียนไม่ได้ ดังนั้นเทสต์
//! `budget_inspect_request_including_audit_*` จึงวัดเส้นทางจริงครบทุกอย่าง ส่วนอีกเทสต์
//! ที่ชื่อ "CPU layers only" จงใจตัด audit ออกเพื่อแยกให้เห็นว่า disk กินส่วนแบ่งแค่ไหน
#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ai_gateway::policy::TenantCredential;
use ai_gateway::{
    DataPlanePolicy, Endpoint, GatewayConfig, GatewayCore, RequestSummary, TenantPolicy,
};
use extraction_det::ExtractionDetector;
use semantic_guard::{Direction, Guard, GuardAction, GuardConfig};

// ---- งบเวลาจาก pivot doc ----
//
// `pivot_ai_infra_security.md` §6 "Latency budget (binding)": guard budget
// P99 < 2 ms ต่อชั้น และ AGENTS.md ตั้ง LSM decision P99 < 1 ms — gateway hop
// ต้องไม่กิน latency ของ inference เอง
const GUARD_BUDGET: Duration = Duration::from_millis(2);

const SAMPLES: usize = 2_000;

// ทุกเทสต์ในไฟล์นี้ถูก gate ด้วย `#[cfg_attr(debug_assertions, ignore = ...)]`
//
// ตัวเลขใน debug ไม่มีความหมายกับ production: regex และ MinHash ทำงานช้ากว่า
// release หลายเท่า จน guard fail-closed ก่อนชั้นอื่นจะทำงานทัน — ผลคือเทสต์จะ
// fail เพราะ debug ช้า ไม่ใช่เพราะ production ช้า ซึ่งเป็นสัญญาณหลอกที่แย่กว่า
// ไม่มีเทสต์เลย ดังนั้น debug จึง skip แทนที่จะ assert

/// พิมพ์ผลและ assert กับงบ — แยกเพื่อให้ทุกเทสต์รายงานในรูปแบบเดียวกัน
fn report(layer: &str, latencies: &mut [Duration], budget: Duration) {
    latencies.sort();
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[((latencies.len() as f64) * 0.99) as usize];
    let max = *latencies.last().unwrap_or(&Duration::ZERO);

    println!("[PERF] {layer} ({SAMPLES} samples)");
    println!("[PERF]   P50  = {p50:?}");
    println!("[PERF]   P99  = {p99:?}");
    println!("[PERF]   MAX  = {max:?}");
    println!("[PERF]   Budget: P99 < {budget:?}");

    assert!(
        p99 < budget,
        "{layer} P99 = {p99:?} exceeds {budget:?} budget — pivot doc §6 is binding"
    );
}

fn bench_policy() -> DataPlanePolicy {
    let mut endpoints = BTreeSet::new();
    endpoints.insert("chat_completions");
    endpoints.insert("completions");
    endpoints.insert("embeddings");
    let mut models = BTreeSet::new();
    models.insert("demo-model".to_string());

    DataPlanePolicy::new(
        vec![TenantPolicy {
            tenant_id: "acme".to_string(),
            allowed_endpoints: endpoints,
            allowed_models: models,
            max_concurrent: 10,
            suspended: false,
            auto_response: false,
        }],
        vec![TenantCredential {
            tenant_id: "acme".to_string(),
            key: b"sk-bench-key-000000000000".to_vec(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        }],
    )
}

/// ---- BUDGET-1: ยืนยันตัวตน + ตรวจสิทธิ์ ----
///
/// วัดเส้นทางที่ทุก request ต้องผ่านก่อนถึงชั้นข้อมูล: bearer parse → constant-time
/// key compare → expiry → policy lookup → endpoint/model allowlist
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_auth_and_authorize_p99_within_guard_budget() {
    let policy = bench_policy();
    let header = "Bearer sk-bench-key-000000000000";
    let _identity = policy
        .authenticate(Some(header))
        .expect("bench credential must authenticate");
    let mut latencies = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let start = Instant::now();
        let id = policy.authenticate(Some(header)).expect("auth");
        let verdict = policy.authorize(&id, Endpoint::ChatCompletions, "demo-model");
        latencies.push(start.elapsed());
        assert!(verdict.is_allowed());
    }

    report("auth + authorize", &mut latencies, GUARD_BUDGET);
}

/// ---- BUDGET-2: semantic-guard ----
///
/// ชั้นที่ pivot doc ผูก budget ไว้โดยตรง วัดด้วยข้อความที่สะอาด (Allow) และ
/// ข้อความที่มี PII (Redacted) เพราะ redact ต้อง allocate string ใหม่และคืน
/// ค่าโดย copy ทั้งข้อความ — ถ้ามี path ใดแพงกว่า path สะอาด ต้องเห็น
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_semantic_guard_clean_p99_within_budget() {
    let guard = Guard::new().expect("guard must build");
    let clean = "Please summarize the quarterly revenue report for the finance team.";
    let mut latencies = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let start = Instant::now();
        let verdict = guard
            .inspect(clean, Direction::Inbound)
            .expect("clean passes");
        latencies.push(start.elapsed());
        assert_eq!(verdict.action, GuardAction::Allow);
    }

    report("guard (clean text)", &mut latencies, GUARD_BUDGET);
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_semantic_guard_pii_redaction_p99_within_budget() {
    let guard = Guard::new().expect("guard must build");
    // ผสม PII หลายชนิดเพื่อให้ redact ทำงานเต็มทาง (credit card, SSN, email, api key)
    let pii_text = "Contact ada@example.com about card 4111 1111 1111 1111, ssn 123-45-6789, \
                    key sk-live-abc123def456ghi789. Please reply.";
    let mut latencies = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let start = Instant::now();
        let verdict = guard
            .inspect(pii_text, Direction::Inbound)
            .expect("redact path");
        latencies.push(start.elapsed());
        assert_eq!(verdict.action, GuardAction::Redacted);
    }

    report("guard (PII redaction)", &mut latencies, GUARD_BUDGET);
}

/// ---- BUDGET-3: extraction-det ----
///
/// วัด `observe` ทั้ง path: MinHash signature → sliding-window rate → history
/// similarity → score. เป็นชั้นที่แพงที่สุดเชิง CPU เพราะ hash ทุก prompt
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_extraction_det_observe_p99_within_budget() {
    let detector = ExtractionDetector::with_defaults().expect("detector must build");
    let prompt = "Explain the difference between a mutex and a semaphore in Rust.";
    let mut latencies = Vec::with_capacity(SAMPLES);

    // ใช้ now_ms ที่เดินหน้าเล็กน้อยเพื่อไม่ให้ทั้งหมดตกในหน้าต่างเวลาเดียวกัน
    for i in 0..SAMPLES {
        let start = Instant::now();
        let verdict = detector
            .observe("acme", prompt, 12, 40, i as u64 * 10)
            .expect("observe");
        latencies.push(start.elapsed());
        let _ = verdict;
    }

    report("extraction-det observe", &mut latencies, GUARD_BUDGET);
}

/// ---- BUDGET-4: ถอด request body ----
///
/// `RequestSummary::parse` คือจุดที่ JSON กลายเป็นข้อความที่ชั้น guard จะตรวจ
/// ถ้าถอดช้ากว่าตัว guard เอง แปลว่าเรากำลังวัด layer ที่ถูก
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_request_summary_parse_p99_within_budget() {
    let body = r#"{"model":"demo-model","messages":[
        {"role":"system","content":"You are a helpful assistant."},
        {"role":"user","content":"Summarize the incident report from 2026-07-11 for the on-call engineer."}
    ],"max_tokens":256,"temperature":0.2}"#;
    let mut latencies = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let start = Instant::now();
        let summary = RequestSummary::parse(Endpoint::ChatCompletions, body).expect("parses");
        latencies.push(start.elapsed());
        assert_eq!(summary.model, "demo-model");
    }

    report("request summary parse", &mut latencies, GUARD_BUDGET);
}

/// ---- รวมสามชั้นตามลำดับจริงใน gateway (เฉพาะ CPU, ไม่รวมการเขียน audit) ----
///
/// เอกสารบังคับลำดับ ยืนยันตัวตน → ตรวจสิทธิ์ → ตรวจข้อมูล → ตรวจการขโมยโมเดล
/// เทสต์นี้ยืนยันว่าลำดับนั้นรวมกันแล้วยังอยู่ในงบเดียวกัน ไม่ใช่แค่แต่ละชั้น
/// ผ่านแยกกันแล้วพอกัน
///
/// จงใจ**ไม่**เรียก `GatewayCore` เพราะต้องการ isolate ต้นทุน CPU ล้วน — เส้นทางจริง
/// ที่มีการเขียน audit อยู่ใน `budget_inspect_request_including_audit_p99_within_budget`
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_cpu_layers_only_p99_within_budget() {
    let policy = bench_policy();
    let guard_cfg = GuardConfig::default();
    let guard = Guard::with_config(guard_cfg).expect("guard must build");
    let detector = ExtractionDetector::with_defaults().expect("detector must build");
    let header = "Bearer sk-bench-key-000000000000";
    let body = r#"{"model":"demo-model","messages":[
        {"role":"user","content":"ada@example.com reported card 4111 1111 1111 1111 on 123-45-6789"}
    ]}"#;
    let mut latencies = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        let start = Instant::now();

        let identity = policy
            .authenticate(Some(header))
            .expect("auth must succeed in bench");
        let summary = RequestSummary::parse(Endpoint::ChatCompletions, body).expect("parses");
        let verdict = policy.authorize(&identity, Endpoint::ChatCompletions, &summary.model);
        assert!(verdict.is_allowed());

        let guard_verdict = guard
            .inspect(&summary.prompt_text, Direction::Inbound)
            .expect("guard path");
        assert_eq!(guard_verdict.action, GuardAction::Redacted);

        let _ = detector
            .observe(
                &identity.tenant_id,
                &summary.prompt_text,
                24,
                40,
                i as u64 * 10,
            )
            .expect("observe");

        latencies.push(start.elapsed());
    }

    report(
        "CPU layers only (auth+authorize+parse+guard+extraction, no audit write)",
        &mut latencies,
        GUARD_BUDGET,
    );
}

/// ---- เส้นทาง request จริงครบทุกอย่าง รวมการเขียน audit ----
///
/// `GatewayCore::inspect_request` คือฟังก์ชันที่ handler เรียกจริง: ยืนยันตัวตน →
/// ตรวจสิทธิ์ → ถอด body → ตรวจข้อมูล → ตรวจการขโมยโมเดล → **เขียน audit chain**
/// การเขียน audit เป็น `record_audit().await` แบบ inline (`lib.rs`) ไม่ใช่
/// background task ดังนั้น file append + flush จึงอยู่ในตัวเลขนี้ด้วย
///
/// นี่คือตัวเลขที่ต้องเทียบกับงบ 2ms เพราะเป็นสิ่งที่ request จริงต้องจ่าย
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_inspect_request_including_audit_p99_within_budget() {
    let audit_dir = std::env::temp_dir().join(format!(
        "ai-gw-perf-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let config = GatewayConfig {
        audit_dir: audit_dir.clone(),
        guard_enabled: true,
        extraction_enabled: true,
        ..GatewayConfig::default()
    };
    let core = GatewayCore::new(config, bench_policy(), None, None)
        .await
        .expect("core must build with audit dir");

    let header = "Bearer sk-bench-key-000000000000";
    let body = r#"{"model":"demo-model","messages":[
        {"role":"user","content":"ada@example.com reported card 4111 1111 1111 1111 on 123-45-6789"}
    ]}"#;
    let mut latencies = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        let start = Instant::now();
        let inspection = core
            .inspect_request(
                Some(header),
                Endpoint::ChatCompletions,
                "demo-model",
                body,
                i as u64 * 10,
            )
            .await
            .expect("request must pass enforcement");
        latencies.push(start.elapsed());
        assert!(
            matches!(
                inspection.inspection.decision,
                ai_gateway::ApiDecision::Allow | ai_gateway::ApiDecision::Redacted
            ),
            "unexpected decision {:?}",
            inspection.inspection.decision
        );
    }

    // พิสูจน์ว่า audit เขียนจริง — ถ้า chain ว่าง แปลว่าตัวเลขที่วัดได้ไม่ได้รวม disk
    let files: Vec<_> = std::fs::read_dir(&audit_dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    assert!(!files.is_empty(), "audit chain file must exist");
    let lines = std::fs::read_to_string(&files[0])
        .expect("read audit log")
        .lines()
        .count();
    assert_eq!(lines, SAMPLES, "every request must be audited on path");

    report(
        "inspect_request (auth+parse+guard+extraction+audit write)",
        &mut latencies,
        GUARD_BUDGET,
    );

    let _ = std::fs::remove_dir_all(&audit_dir);
}

/// ---- BUDGET-7: หลายผู้เช่าพร้อมกัน ----
///
/// เทสต์ก่อนหน้าวัดทีละ request ตามลำดับ ซึ่งพิสูจน์ได้แค่ว่า "ชั้นไหนช้า" แต่ไม่ได้
/// พิสูจน์สิ่งที่ผู้ซื้อจะเจอจริง: หลายผู้เช่ายิงพร้อมกัน ซึ่งเป็นรูปแบบการใช้งาน
/// ปกติของ platform team เพราะผู้เช่าคนละรายก็ยิงพร้อมกัน
///
/// สิ่งที่ต้องการพิสูจน์คือ sharding ทำงานจริง: ผู้เช่าคนละ shard เขียน chain
/// คนละไฟล์ จึงไม่ควรแย่ง lock กัน (`GatewayCore::record_audit` clone `Arc` ออก
/// ก่อน `await`) ถ้าวันนี้หนึ่งผู้เช่าเขียนช้าลง P99 ของทุกผู้เช่าต้องไม่ขยับตาม
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_concurrent_tenants_p99_within_budget() {
    const TENANTS: usize = 8;
    const PER_TENANT: usize = 250;

    let (core, audit_dir, headers) = concurrent_fixture("concurrent-tenants", TENANTS).await;
    let body = bench_body();

    let started = Instant::now();
    let mut tasks = Vec::with_capacity(TENANTS);
    for header in headers {
        let core = core.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(PER_TENANT);
            for i in 0..PER_TENANT {
                let start = Instant::now();
                let inspection = core
                    .inspect_request(
                        Some(&header),
                        Endpoint::ChatCompletions,
                        "demo-model",
                        body,
                        u64::try_from(i).unwrap_or(0) * 10,
                    )
                    .await
                    .expect("request must pass enforcement");
                latencies.push(start.elapsed());
                assert!(
                    matches!(
                        inspection.inspection.decision,
                        ai_gateway::ApiDecision::Allow | ai_gateway::ApiDecision::Redacted
                    ),
                    "unexpected decision {:?}",
                    inspection.inspection.decision
                );
            }
            latencies
        }));
    }

    let mut latencies = Vec::with_capacity(TENANTS * PER_TENANT);
    for task in tasks {
        latencies.extend(task.await.expect("tenant task must not panic"));
    }
    let wall = started.elapsed();
    let total = TENANTS * PER_TENANT;

    // ทุกผู้เช่าต้องมี chain ของตัวเอง และ chain ต้องผ่าน — ถ้ามีการแย่ง lock
    // แบบผิด จะเห็นเป็น entry หายหรือ chain ที่ validate ไม่ผ่าน
    let results = core.verify_all_chains().await.expect("verify chains");
    assert_eq!(results.len(), TENANTS, "one chain per tenant expected");
    for (tenant, valid) in &results {
        assert!(
            valid,
            "chain for {tenant} must validate after concurrent load"
        );
    }

    report(
        &format!("concurrent tenants ({TENANTS} tenants x {PER_TENANT} requests)"),
        &mut latencies,
        GUARD_BUDGET,
    );
    println!(
        "[PERF]   Wall: {total} requests in {wall:?} ({:.0} req/s)",
        total as f64 / wall.as_secs_f64()
    );

    let _ = std::fs::remove_dir_all(&audit_dir);
}

/// ---- BUDGET-8: ผู้เช่าเดียวยิงพร้อมกัน ----
///
/// นี่คือช่องว่างที่ pivot doc §8.1 ยอมรับเองว่ายังไม่ได้วัด: *"concurrent requests
/// to the same tenant serialize on that chain lock, which is not exercised by this
/// single-stream test"* การ serialize เป็นเรื่องถูกต้องสำหรับ hash chain
/// (ลำดับต้องไม่ถูกแทรก) แต่ต้องพิสูจน์ว่ามันไม่พา tail พ้นงบ 2ms
///
/// ความหมายของตัวเลข: ที่ concurrency ที่กำหนด คำขอที่เข้าคิวท้ายสุดต้องจบได้
/// ภายในงบเดียวกับ request เดี่ยว ถ้าเกิน แปลว่า chain lock เป็นคอขวด ไม่ใช่ disk
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_concurrent_same_tenant_chain_lock_p99_within_budget() {
    const CONCURRENCY: usize = 16;
    const PER_WORKER: usize = 125;

    // ผู้เช่าคนเดียว — ทุก request เขียน chain ไฟล์เดียวกัน จึง serialize บน mutex
    // ของ chain นั้นตามการออกแบบ (ดู §5 "per-tenant chains")
    //
    // เพดานต้องยกพอให้ {CONCURRENCY} writers ผ่านได้ทั้งหมด ไม่งั้นเทสต์นี้จะวัด
    // "โควตาหมด" แทน "mutex ช้า" — ซึ่งเป็นคนละเรื่องกัน การทดสอบเพดานมีที่
    // budget_concurrency_ceiling_is_enforced_under_real_concurrency แยกแล้ว
    let (core, audit_dir, headers) =
        concurrent_fixture_with_limit("concurrent-same-tenant", 1, CONCURRENCY as u32).await;
    let header = headers.first().expect("fixture has one tenant").clone();
    let body = bench_body();

    let mut tasks = Vec::with_capacity(CONCURRENCY);
    for worker in 0..CONCURRENCY {
        let core = core.clone();
        let header = header.clone();
        tasks.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(PER_WORKER);
            for i in 0..PER_WORKER {
                let start = Instant::now();
                core.inspect_request(
                    Some(&header),
                    Endpoint::ChatCompletions,
                    "demo-model",
                    body,
                    u64::try_from(worker * PER_WORKER + i).unwrap_or(0) * 10,
                )
                .await
                .expect("request must pass enforcement");
                latencies.push(start.elapsed());
            }
            latencies
        }));
    }

    let mut latencies = Vec::with_capacity(CONCURRENCY * PER_WORKER);
    for task in tasks {
        latencies.extend(task.await.expect("worker task must not panic"));
    }

    // chain เดียวต้องมี entry ครบทุก request — การ serialize ต้องไม่ทำให้
    // entry หาย ซึ่งคือบั๊กจริงของการเขียน audit แบบมี lock
    let entries = std::fs::read_to_string(audit_dir.join("tenant-0.jsonl"))
        .expect("audit chain written")
        .lines()
        .count();
    assert_eq!(
        entries,
        CONCURRENCY * PER_WORKER,
        "every concurrent request must land in the chain"
    );

    let results = core.verify_all_chains().await.expect("verify chains");
    assert_eq!(results.get("tenant-0"), Some(&true));

    report(
        &format!("same tenant, {CONCURRENCY} concurrent writers on one chain"),
        &mut latencies,
        GUARD_BUDGET,
    );

    let _ = std::fs::remove_dir_all(&audit_dir);
}

/// สร้าง core สำหรับเทสต์ concurrent พร้อมผู้เช่าตามจำนวนที่ขอ
///
/// คืน `(core, audit_dir, headers)` — header แต่ละตัวคือ credential ของผู้เช่า
/// คนละคน ผู้เช่าชื่อ `tenant-{i}` เพื่อให้ชื่อไฟล์ chain ทำนายได้
async fn concurrent_fixture(
    name: &str,
    tenants: usize,
) -> (std::sync::Arc<GatewayCore>, PathBuf, Vec<String>) {
    concurrent_fixture_with_limit(name, tenants, 10).await
}

/// เหมือน [`concurrent_fixture`] แต่กำหนดเพดานขำพร้อมกันเอง
async fn concurrent_fixture_with_limit(
    name: &str,
    tenants: usize,
    max_concurrent: u32,
) -> (std::sync::Arc<GatewayCore>, PathBuf, Vec<String>) {
    concurrent_fixture_full(name, tenants, max_concurrent, true).await
}

/// fixture ที่ปิดชั้นตรวจข้อมูล — ใช้กับเทสต์ที่วัด**ตรรกะ**ของเพดาน
/// ไม่ใช่ latency เพราะงบ 2ms ของ guard ใน debug build จะ fail-closed
/// ปฏิเสธคำขอก่อนถึงจุดที่เรากำลังวัด
async fn concurrent_fixture_without_guard(
    name: &str,
    tenants: usize,
    max_concurrent: u32,
) -> (std::sync::Arc<GatewayCore>, PathBuf, Vec<String>) {
    concurrent_fixture_full(name, tenants, max_concurrent, false).await
}

async fn concurrent_fixture_full(
    name: &str,
    tenants: usize,
    max_concurrent: u32,
    with_guard: bool,
) -> (std::sync::Arc<GatewayCore>, PathBuf, Vec<String>) {
    let audit_dir = std::env::temp_dir().join(format!(
        "ai-gw-perf-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let config = GatewayConfig {
        audit_dir: audit_dir.clone(),
        guard_enabled: with_guard,
        extraction_enabled: with_guard,
        ..GatewayConfig::default()
    };

    let mut policies = Vec::with_capacity(tenants);
    let mut creds = Vec::with_capacity(tenants);
    for i in 0..tenants {
        policies.push(TenantPolicy {
            tenant_id: format!("tenant-{i}"),
            allowed_endpoints: ["chat_completions"].into_iter().collect(),
            allowed_models: ["demo-model".to_string()].into_iter().collect(),
            max_concurrent,
            suspended: false,
            auto_response: false,
        });
        creds.push(TenantCredential {
            tenant_id: format!("tenant-{i}"),
            key: format!("sk-bench-{i:016}").into_bytes(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        });
    }

    let core = GatewayCore::new(config, DataPlanePolicy::new(policies, creds), None, None)
        .await
        .expect("core must build");

    let headers = (0..tenants)
        .map(|i| format!("Bearer sk-bench-{i:016}"))
        .collect();
    (std::sync::Arc::new(core), audit_dir, headers)
}

fn bench_body() -> &'static str {
    r#"{"model":"demo-model","messages":[
        {"role":"user","content":"ada@example.com reported card 4111 1111 1111 1111 on 123-45-6789"}
    ]}"#
}

/// ANK-069: ต้องพิสูจน์ว่าเพดาน "พร้อมกัน" บังคับจริงภายใต้ concurrency จริง
/// ไม่ใช่แค่ถือ handle ค้างไว้ — และผู้ที่โดนปฏิเสธต้องถูกนับแยกจากที่ผ่าน
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_concurrency_ceiling_is_enforced_under_real_concurrency() {
    const LIMIT: u32 = 4;
    const WORKERS: usize = 32;
    const ROUNDS: usize = 40;

    let (core, audit_dir, headers) = concurrent_fixture_without_guard("ceiling", 1, LIMIT).await;
    let body = bench_body();

    let mut handles = Vec::with_capacity(WORKERS);
    for w in 0..WORKERS {
        let core = std::sync::Arc::clone(&core);
        let header = headers[0].clone();
        let body = body.to_string();
        handles.push(tokio::spawn(async move {
            let mut admitted = 0usize;
            let mut shed = 0usize;
            for r in 0..ROUNDS {
                match core
                    .inspect_request(
                        Some(header.as_str()),
                        Endpoint::ChatCompletions,
                        "demo-model",
                        &body,
                        (w * ROUNDS + r) as u64,
                    )
                    .await
                {
                    Ok(ok) => {
                        // permit ถูกถืออยู่ระหว่างนี้ — เหมือน handler ที่ยังทำงานไม่เสร็จ
                        admitted += 1;
                        assert!(ok._permit.is_some(), "admitted request must hold a slot");
                        drop(ok);
                    }
                    Err(e) => {
                        assert!(
                            matches!(
                                e,
                                ai_gateway::GatewayError::Auth(
                                    ai_gateway::AuthError::ConcurrencyLimit
                                )
                            ),
                            "only the ceiling may shed load, got {e:?}"
                        );
                        shed += 1;
                    }
                }
            }
            (admitted, shed)
        }));
    }

    let mut admitted = 0usize;
    let mut shed = 0usize;
    for h in handles {
        let (a, s) = h.await.expect("worker must not panic");
        admitted += a;
        shed += s;
    }

    assert_eq!(
        admitted + shed,
        WORKERS * ROUNDS,
        "every request must get a verdict, none may vanish"
    );
    assert!(
        shed > 0,
        "32 workers on a ceiling of {LIMIT} must produce shedding, got 0"
    );
    // ทุกการปฏิเสธต้องมีร่องรอยใน audit
    let content = std::fs::read_to_string(audit_dir.join("tenant-0.jsonl")).expect("audit chain");
    let shed_audited = content
        .lines()
        .filter(|l| l.contains("concurrency_limit"))
        .count();
    assert_eq!(
        shed_audited, shed,
        "every shed request must be audited: {shed_audited} audited vs {shed} shed"
    );

    let _ = std::fs::remove_dir_all(&audit_dir);
}
