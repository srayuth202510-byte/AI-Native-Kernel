//! # Red-team replay harness — ยิง attack corpus ผ่าน gateway ทั้งเส้น
//!
//! อ่าน fixture จาก `tests/fixtures/attacks/{blocked,advisory}/*.json` แล้วยิง
//! ผ่าน `GatewayCore::inspect_request` ทีละไฟล์ด้วย core/audit แยกกัน (กัน
//! state รั่วข้าม fixture) แล้วตรวจครบห่วง: decision + reason ตรง `expect`
//! และมี audit entry เขียนจริง
//!
//! สอง tier ตาม `fixtures/attacks/README.md`:
//! - `blocked/` — ต้องกันได้ ตกแล้ว CI แดง
//! - `advisory/` — ช่องโหว่ที่รู้ตัว/สงสัย รายงานอย่างเดียว ไม่ gate ถ้าวันไหน
//!   กันได้ harness จะบอกให้ promote ขึ้น `blocked/`
//!
//! ```bash
//! cargo test -p ai-gateway --test redteam -- --nocapture
//! ```
#![deny(unsafe_code)]

use ai_gateway::policy::TenantCredential;
use ai_gateway::{
    ApiDecision, DataPlanePolicy, Endpoint, GatewayConfig, GatewayCore, TenantPolicy,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, serde::Deserialize)]
struct Fixture {
    id: String,
    category: String,
    description: String,
    endpoint: String,
    model: String,
    body: String,
    expect: Expect,
    advisory: bool,
    note: String,
}

#[derive(Debug, serde::Deserialize)]
struct Expect {
    decision: String,
    reason: String,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/attacks")
}

/// อ่าน fixture ทั้งหมดจาก tier ที่ระบุ เรียงตามชื่อไฟล์ให้ลำดับคงที่
fn load_tier(tier: &str) -> Vec<(String, Fixture)> {
    let dir = corpus_dir().join(tier);
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "tier {tier} must not be empty — an empty corpus silently proves nothing"
    );
    entries
        .into_iter()
        .map(|p| {
            let raw =
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            let fixture: Fixture =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()));
            (p.display().to_string(), fixture)
        })
        .collect()
}

fn parse_endpoint(name: &str, id: &str) -> Endpoint {
    match name {
        "chat_completions" => Endpoint::ChatCompletions,
        "completions" => Endpoint::Completions,
        "embeddings" => Endpoint::Embeddings,
        other => panic!("fixture {id}: unknown endpoint {other:?}"),
    }
}

fn parse_decision(name: &str, id: &str) -> ApiDecision {
    match name {
        "allow" => ApiDecision::Allow,
        "deny" => ApiDecision::Deny,
        "redacted" => ApiDecision::Redacted,
        other => panic!("fixture {id}: unknown decision {other:?}"),
    }
}

async fn replay_core(audit_dir: PathBuf) -> GatewayCore {
    let config = GatewayConfig {
        audit_dir,
        guard_enabled: true,
        extraction_enabled: true,
        ..GatewayConfig::default()
    };
    // งบ guard ขยายเฉพาะเทสต์ (แบบเดียวกับ core tests) เพราะ 2ms ของ
    // production ไม่เสถียรใน debug build
    let guard_cfg = semantic_guard::GuardConfig {
        budget: Duration::from_secs(30),
        ..semantic_guard::GuardConfig::default()
    };
    let policy = DataPlanePolicy::new(
        vec![TenantPolicy {
            tenant_id: "red".to_string(),
            allowed_endpoints: ["chat_completions", "embeddings"].into_iter().collect(),
            allowed_models: ["gpt-x".to_string()].into_iter().collect(),
            max_concurrent: 64,
            suspended: false,
        }],
        vec![TenantCredential {
            tenant_id: "red".to_string(),
            key: b"sk-redteam".to_vec(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        }],
    );
    GatewayCore::new(
        config,
        policy,
        Some(guard_cfg),
        Some(ai_gateway::ExtractionConfig::default()),
    )
    .await
    .expect("replay core must build")
}

#[test]
fn redteam_corpus_schema() {
    // กัน corpus เน่า: ทุกไฟล์ต้องมีฟิลด์ครบ, endpoint/decision รู้จัก,
    // body เป็น JSON ที่ถอดได้, advisory ต้องมี note (bypass ที่ไม่มีคำอธิบาย
    // คือหนี้ที่ไม่มีเจ้าของ)
    for tier in ["blocked", "advisory"] {
        for (path, f) in load_tier(tier) {
            assert!(!f.id.is_empty(), "{path}: id must not be empty");
            assert!(!f.category.is_empty(), "{path}: category must not be empty");
            assert!(
                !f.description.is_empty(),
                "{path}: description must not be empty"
            );
            assert!(!f.model.is_empty(), "{path}: model must not be empty");
            parse_endpoint(&f.endpoint, &f.id);
            parse_decision(&f.expect.decision, &f.id);
            assert!(
                !f.expect.reason.is_empty(),
                "{path}: expect.reason must not be empty"
            );
            let body: serde_json::Value =
                serde_json::from_str(&f.body).unwrap_or_else(|e| panic!("{path}: body: {e}"));
            assert_eq!(
                body["model"].as_str(),
                Some(f.model.as_str()),
                "{path}: body.model must match fixture model"
            );
            if tier == "advisory" {
                assert!(
                    f.advisory,
                    "{path}: files under advisory/ must set advisory=true"
                );
                assert!(
                    !f.note.is_empty(),
                    "{path}: advisory fixture without a note is untracked debt"
                );
            } else {
                assert!(
                    !f.advisory,
                    "{path}: files under blocked/ must set advisory=false"
                );
            }
        }
    }
}

#[tokio::test]
async fn redteam_replay_blocked_corpus() {
    let fixtures = load_tier("blocked");
    for (i, (path, f)) in fixtures.iter().enumerate() {
        let audit_dir = std::env::temp_dir().join(format!(
            "ai-gw-redteam-{}-{}-{}",
            std::process::id(),
            f.id,
            i
        ));
        let _ = std::fs::remove_dir_all(&audit_dir);
        let core = replay_core(audit_dir.clone()).await;

        let out = core
            .inspect_request(
                Some("Bearer sk-redteam"),
                parse_endpoint(&f.endpoint, &f.id),
                &f.model,
                &f.body,
                i as u64,
            )
            .await
            .unwrap_or_else(|e| panic!("{}: inspect failed: {e:?}", f.id));
        let want = parse_decision(&f.expect.decision, &f.id);
        assert_eq!(
            out.inspection.decision, want,
            "{} ({}): decision mismatch — attack got through or over-blocked",
            f.id, path
        );
        assert_eq!(
            out.inspection.reason, f.expect.reason,
            "{}: reason mismatch",
            f.id
        );

        // การปฏิเสธ/ปิดบังที่ไม่มี audit คือ control ที่ตรวจสอบไม่ได้
        let chain =
            std::fs::read_to_string(audit_dir.join("red.jsonl")).expect("audit chain written");
        assert!(
            chain.contains(&f.expect.reason),
            "{}: audit chain must record reason {:?}, got {chain:?}",
            f.id,
            f.expect.reason
        );

        let results = core.verify_all_chains().await.expect("verify chains");
        assert_eq!(
            results.get("red"),
            Some(&true),
            "{}: audit chain must verify after attack",
            f.id
        );
        let _ = std::fs::remove_dir_all(&audit_dir);
        println!(
            "[REDTEAM] BLOCKED  {:30} {} ({})",
            f.id, f.expect.reason, f.category
        );
    }
    println!(
        "[REDTEAM] blocked tier: {} / {} held",
        fixtures.len(),
        fixtures.len()
    );
}

#[tokio::test]
async fn redteam_report_advisory_corpus() {
    // รายงานอย่างเดียว ไม่ gate — แต่ถ้า advisory ตัวไหนกันได้แล้วต้องบอกให้
    // promote ขึ้น blocked/ ไม่ใช่ปล่อยให้เน่าอยู่ตรงนี้
    let fixtures = load_tier("advisory");
    let mut bypassed = 0usize;
    for (i, (_, f)) in fixtures.iter().enumerate() {
        let audit_dir = std::env::temp_dir().join(format!(
            "ai-gw-redteam-adv-{}-{}-{}",
            std::process::id(),
            f.id,
            i
        ));
        let _ = std::fs::remove_dir_all(&audit_dir);
        let core = replay_core(audit_dir.clone()).await;

        let out = core
            .inspect_request(
                Some("Bearer sk-redteam"),
                parse_endpoint(&f.endpoint, &f.id),
                &f.model,
                &f.body,
                i as u64,
            )
            .await
            .unwrap_or_else(|e| panic!("{}: inspect failed: {e:?}", f.id));
        let want = parse_decision(&f.expect.decision, &f.id);
        if out.inspection.decision == want && out.inspection.reason == f.expect.reason {
            println!("[REDTEAM] PROMOTE  {:30} now held — move to blocked/", f.id);
        } else {
            bypassed += 1;
            println!(
                "[REDTEAM] BYPASS   {:30} got {:?}/{:?} — {}",
                f.id, out.inspection.decision, out.inspection.reason, f.note
            );
        }
        let _ = std::fs::remove_dir_all(&audit_dir);
    }
    println!(
        "[REDTEAM] advisory tier: {bypassed} bypassed / {} total",
        fixtures.len()
    );
}
