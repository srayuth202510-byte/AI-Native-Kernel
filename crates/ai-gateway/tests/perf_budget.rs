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
//! **สิ่งที่ไม่อยู่ในไฟล์นี้:** การเขียน audit log ถูก `tokio::spawn` แยกออกไปแล้ว
//! (`routes.rs` เขียน audit ใน background task) จึงไม่อยู่ในเส้นทางวิกฤตของ request
//! และไม่ถูกนับในงบ 2ms — การวัดมันต้องเป็น throughput test แยก เพราะมันผูกกับ
//! disk flush ไม่ใช่ CPU
#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ai_gateway::policy::TenantCredential;
use ai_gateway::{DataPlanePolicy, Endpoint, RequestSummary, TenantPolicy};
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

/// ---- รวมสามชั้นตามลำดับจริงใน gateway ----
///
/// เอกสารบังคับลำดับ ยืนยันตัวตน → ตรวจสิทธิ์ → ตรวจข้อมูล → ตรวจการขโมยโมเดล
/// เทสต์นี้ยืนยันว่าลำดับนั้นรวมกันแล้วยังอยู่ในงบเดียวกัน ไม่ใช่แค่แต่ละชั้น
/// ผ่านแยกกันแล้วพอกัน
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "perf budget is only meaningful in --release; debug regex/MinHash exceeds 2ms"
)]
fn budget_full_enforcement_pipeline_p99_within_budget() {
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
        "full pipeline (auth+authorize+parse+guard+extraction)",
        &mut latencies,
        GUARD_BUDGET,
    );
}
