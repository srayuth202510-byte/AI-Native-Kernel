//! Privileged E2E validation ของ H1 + H2 + H3 ผ่าน authorize flow จริง
//!
//! สิ่งที่พิสูจน์ (ต้องรันด้วย root + CAP_BPF + kernel BTF + cgroup v2 —
//! เครื่องที่ไม่มีสิทธิ์จะ SKIP อย่างสุภาพ):
//!
//! 1. child process ที่ยังอยู่โลกของ host เปิดไฟล์ได้ (baseline)
//! 2. `authorize_process_token` สำเร็จ → child ถูกย้ายเข้า agent cgroup
//!    พร้อม allow-list ที่ผูก start time (H2) → **ยังเปิดไฟล์ได้**
//!    (ขา allow: อยู่ใต้ default-DENY แต่ identity ตรง จึงผ่าน)
//! 3. authorize ด้วย secret ผิด → deny path → child โดนบล็อกทันที
//!
//! รัน: `sudo -E cargo test -p kernel-companion --test privileged_h1_h2`

use capability_security::{CapabilityToken, Scope};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// probe shell: รอคำสั่งทาง stdin แล้ววัดผล operation แต่ละแบบ รายงานทาง
/// stdout ที่เปิดค้างไว้แล้ว (write ไม่ถูก hook)
///
/// สำคัญ: ห้ามมี redirect `2>/dev/null` ในสคริปต์ — จะทำให้ bash เปิด
/// /dev/null ใหม่ทุกครั้ง ซึ่งอยู่นอก scope_path ของ H3 แล้วโดน DENY จน
/// วัดผลผิด stderr ของ child ถูกตั้งเป็น null ตั้งแต่ spawn (host world)
/// อยู่แล้ว จึงใช้ fd เดิมได้โดยไม่ trigger file_open
///
/// - `probe [path]`  → เปิดไฟล์ด้วย builtin redirect (วัด file_open ของ
///   PID นี้ล้วนๆ) → `OK` / `DENIED`
/// - `execprobe`     → exec ใน subshell (กัน bash แม่ตายเมื่อ exec ถูก
///   ปฏิเสธ) → `EXECOK` / `EXECDENIED`
const PROBE_SCRIPT: &str = r#"while read -r cmd arg; do
  case "$cmd" in
    probe) if read -r _ < "${arg:-/etc/hostname}"; then echo OK; else echo DENIED; fi ;;
    execprobe) if ( exec /bin/true ); then echo EXECOK; else echo EXECDENIED; fi ;;
    quit) exit 0 ;;
  esac
done"#;

async fn probe(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    command: &str,
) -> String {
    stdin
        .write_all(format!("{command}\n").as_bytes())
        .await
        .expect("write probe command");
    stdin.flush().await.expect("flush probe command");
    tokio::time::timeout(Duration::from_secs(5), stdout.next_line())
        .await
        .expect("probe must answer within 5s")
        .expect("probe stdout must be readable")
        .expect("probe must not close stdout")
}

#[tokio::test]
async fn e2e_h2_allow_path_through_real_authorize_flow() {
    let cgroup_path = format!("/sys/fs/cgroup/ank-h2-e2e-{}", std::process::id());

    let run_id = uuid::Uuid::new_v4();
    let mut config = kernel_companion::config::Config::default();
    config.kernel_companion.uds_socket_path = format!("/tmp/ank-h2-e2e-{run_id}.sock");
    config.kernel_companion.metrics_server_addr = "127.0.0.1:0".to_string();
    // audit log เฉพาะของ run นี้ — path กลาง (/tmp/ank-audit.log) ใช้ไม่ได้
    // เมื่อรันเป็น root: fs.protected_regular ห้าม O_CREAT ทับไฟล์ของ user
    // อื่นใน sticky dir และ hash chain ก็ไม่ควรปนข้าม test run อยู่แล้ว
    config.capability_security.audit_log_path = format!("/tmp/ank-h2-e2e-{run_id}-audit.log");
    // ต้องเป็น real eBPF เท่านั้น — ปิด fallback แล้วถือ boot ล้มเหลว
    // เป็น "เครื่องไม่มีสิทธิ์" (พฤติกรรมเดียวกับ privileged tests อื่นใน repo)
    config.ebpf.enable_fallback = false;
    config.lsm.agent_cgroup_path = Some(cgroup_path.clone());

    let mut companion = kernel_companion::KernelCompanion::with_config(&config);
    if let Err(e) = companion.boot().await {
        eprintln!("SKIP e2e_h2_allow_path_through_real_authorize_flow: {e:#}");
        return;
    }

    // ── spawn child probe (เริ่มในโลกของ host) ──
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(PROBE_SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe child");
    let child_pid = child.id().expect("child must have a PID");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();

    // 1. baseline: host world ต้องเปิดไฟล์ได้
    assert_eq!(
        probe(&mut stdin, &mut stdout, "probe").await,
        "OK",
        "host-world probe must open files"
    );

    // ── issue token + authorize → allow-list (H2 identity) + ย้ายเข้า cgroup ──
    let token = CapabilityToken::new(
        7001,
        Scope::Process(child_pid),
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0x5A; 32],
    );
    companion
        .capability_security()
        .issue_token(token.clone())
        .await
        .expect("issue token");
    let allowed = companion
        .authorize_process_token(child_pid, token.id, &[0x5A; 32], "read")
        .await
        .expect("authorize must not error");
    assert!(allowed, "valid token must authorize");

    // 2. ขา allow ของ H2: child อยู่ใน agent cgroup (default-DENY) แล้ว
    //    แต่ PID + start time ตรงกับ allow-list → ต้องเปิดไฟล์ได้
    assert_eq!(
        probe(&mut stdin, &mut stdout, "probe").await,
        "OK",
        "authorized agent inside the cgroup must pass (H2 allow path)"
    );

    // 3. deny path: secret ผิด → deny_pid → โดนบล็อกทันที
    let denied = companion
        .authorize_process_token(child_pid, token.id, &[0x00; 32], "read")
        .await
        .expect("deny path must not error");
    assert!(!denied, "wrong secret must not authorize");
    assert_eq!(
        probe(&mut stdin, &mut stdout, "probe").await,
        "DENIED",
        "de-authorized agent must be blocked"
    );

    // ── cleanup ──
    let _ = stdin.write_all(b"quit\n").await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    companion.shutdown().await;
    let _ = tokio::fs::remove_file(&config.kernel_companion.uds_socket_path).await;
    let _ = tokio::fs::remove_file(&config.capability_security.audit_log_path).await;
    let _ = std::fs::remove_dir(&cgroup_path);

    eprintln!("PASS: H2 allow path validated end-to-end through authorize_process_token");
}

/// H3: intent-derived scope ต้องถูกบังคับใช้ใน kernel จริง —
/// token ให้แค่ `read` + intent จำกัด `scope_path` → agent เปิดไฟล์ใต้
/// prefix ได้, นอก prefix โดนปฏิเสธ (bpf_d_path), และ exec โดนปฏิเสธ
/// เพราะ token ไม่ได้ให้ class นั้น
#[tokio::test]
async fn e2e_h3_intent_scope_enforced_in_kernel() {
    let run_pid = std::process::id();
    let cgroup_path = format!("/sys/fs/cgroup/ank-h3-e2e-{run_pid}");
    let data_dir = format!("/tmp/ank-h3-e2e-{run_pid}");

    let run_id = uuid::Uuid::new_v4();
    let mut config = kernel_companion::config::Config::default();
    config.kernel_companion.uds_socket_path = format!("/tmp/ank-h3-e2e-{run_id}.sock");
    config.kernel_companion.metrics_server_addr = "127.0.0.1:0".to_string();
    config.capability_security.audit_log_path = format!("/tmp/ank-h3-e2e-{run_id}-audit.log");
    config.ebpf.enable_fallback = false;
    config.lsm.agent_cgroup_path = Some(cgroup_path.clone());

    let mut companion = kernel_companion::KernelCompanion::with_config(&config);
    if let Err(e) = companion.boot().await {
        eprintln!("SKIP e2e_h3_intent_scope_enforced_in_kernel: {e:#}");
        return;
    }

    // ไฟล์ในขอบเขต — ต้องมีเนื้อหา เพราะ probe ใช้ `read` วัดผล (open
    // สำเร็จแต่ไฟล์ว่างจะแยกไม่ออกจากถูกปฏิเสธ)
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let allowed_file = format!("{data_dir}/allowed.txt");
    std::fs::write(&allowed_file, "in-scope data\n").expect("write data file");

    let mut child = Command::new("bash")
        .arg("-c")
        .arg(PROBE_SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe child");
    let child_pid = child.id().expect("child must have a PID");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();

    // token ให้แค่ read (ไม่มี exec/net) + intent ประกาศขอบเขต path
    let token = CapabilityToken::new(
        7002,
        Scope::Process(child_pid),
        vec!["read".to_string()],
        Duration::from_secs(60),
        [0x6B; 32],
    );
    companion
        .capability_security()
        .issue_token(token.clone())
        .await
        .expect("issue token");

    let intent = intent_bus::Intent::new(
        "h3-e2e",
        intent_bus::IntentType::Structured,
        "summarize project files",
        intent_bus::IntentPriority::Medium,
        "e2e-test",
    );
    let mut intent = intent;
    intent
        .metadata
        .insert("scope_path".to_string(), data_dir.clone());

    let allowed = companion
        .authorize_process_token_with_scope(child_pid, token.id, &[0x6B; 32], "read", Some(&intent))
        .await
        .expect("scoped authorize must not error");
    assert!(allowed, "valid token must authorize");

    // 1. เปิดไฟล์ใต้ prefix — ต้องผ่าน
    assert_eq!(
        probe(&mut stdin, &mut stdout, &format!("probe {allowed_file}")).await,
        "OK",
        "in-scope file must open (H3 allow within prefix)"
    );

    // 2. เปิดไฟล์นอก prefix — kernel เทียบ bpf_d_path แล้วต้องปฏิเสธ
    assert_eq!(
        probe(&mut stdin, &mut stdout, "probe /etc/hostname").await,
        "DENIED",
        "out-of-scope file must be denied by the path prefix"
    );

    // 3. exec /bin/true — agent นี้ scope แค่ read ใต้ data dir จึง exec
    //    ไม่ได้: token ไม่ได้ให้ class exec (bprm_check) และ /bin/true ก็อยู่
    //    นอก path prefix (file_open ของ binary) — โดนปฏิเสธทั้งสองทาง
    assert_eq!(
        probe(&mut stdin, &mut stdout, "execprobe").await,
        "EXECDENIED",
        "exec must be denied for an agent scoped to read a data dir"
    );

    // ── cleanup ──
    let _ = stdin.write_all(b"quit\n").await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    companion.shutdown().await;
    let _ = tokio::fs::remove_file(&config.kernel_companion.uds_socket_path).await;
    let _ = tokio::fs::remove_file(&config.capability_security.audit_log_path).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    let _ = std::fs::remove_dir(&cgroup_path);

    eprintln!("PASS: H3 intent scope enforced in kernel (path prefix + exec class)");
}

/// H8: capability-scoped skill manifest — โหลด skill.md ที่ประกาศ scope
/// (file-only + path prefix) แล้ว authorize agent ผ่าน scope ที่ compile จาก
/// manifest จริง → kernel บังคับตามที่ skill ประกาศ (in-scope อ่านได้,
/// out-of-scope + exec โดนปฏิเสธ) พิสูจน์ว่า "ความถนัด = ขอบเขตที่ kernel
/// บังคับได้" ไม่ใช่แค่ instructions
#[tokio::test]
async fn e2e_h8_skill_manifest_scope_enforced_in_kernel() {
    let run_pid = std::process::id();
    let cgroup_path = format!("/sys/fs/cgroup/ank-h8-e2e-{run_pid}");
    let data_dir = format!("/tmp/ank-h8-e2e-{run_pid}");
    let skills_dir = format!("/tmp/ank-h8-skills-{run_pid}");

    let run_id = uuid::Uuid::new_v4();
    let mut config = kernel_companion::config::Config::default();
    config.kernel_companion.uds_socket_path = format!("/tmp/ank-h8-e2e-{run_id}.sock");
    config.kernel_companion.metrics_server_addr = "127.0.0.1:0".to_string();
    config.capability_security.audit_log_path = format!("/tmp/ank-h8-e2e-{run_id}-audit.log");
    config.ebpf.enable_fallback = false;
    config.lsm.agent_cgroup_path = Some(cgroup_path.clone());

    let mut companion = kernel_companion::KernelCompanion::with_config(&config);
    if let Err(e) = companion.boot().await {
        eprintln!("SKIP e2e_h8_skill_manifest_scope_enforced_in_kernel: {e:#}");
        return;
    }

    // ── เขียน skill manifest ที่ประกาศ scope: file-only ใต้ data_dir ──
    std::fs::create_dir_all(&skills_dir).expect("create skills dir");
    let manifest = format!(
        "+++\n\
         name = \"file-summarizer\"\n\
         description = \"summarize project files\"\n\
         [capabilities]\n\
         scope_path = \"{data_dir}\"\n\
         allow = [\"file\"]\n\
         +++\n\
         Read files under the project and summarize.\n"
    );
    std::fs::write(format!("{skills_dir}/file-summarizer.md"), manifest).expect("write skill");

    let (registry, errors) =
        kernel_companion::SkillRegistry::load_dir(std::path::Path::new(&skills_dir))
            .expect("load skills dir");
    assert!(errors.is_empty(), "skill manifest must parse cleanly");
    let skill = registry.get("file-summarizer").expect("skill loaded");

    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let allowed_file = format!("{data_dir}/notes.txt");
    std::fs::write(&allowed_file, "in-scope data\n").expect("write data file");

    let mut child = Command::new("bash")
        .arg("-c")
        .arg(PROBE_SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe child");
    let child_pid = child.id().expect("child must have a PID");
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout")).lines();

    // token grant กว้าง (read+exec+net) — skill ต้อง narrow ลงเหลือแค่ file+path
    let token = CapabilityToken::new(
        7003,
        Scope::Process(child_pid),
        vec!["read".to_string(), "exec".to_string(), "net".to_string()],
        Duration::from_secs(60),
        [0x7C; 32],
    );
    companion
        .capability_security()
        .issue_token(token.clone())
        .await
        .expect("issue token");

    // authorize ผ่าน intent ที่ compile จาก skill manifest จริง
    let allowed = companion
        .authorize_process_token_with_scope(
            child_pid,
            token.id,
            &[0x7C; 32],
            "read",
            Some(&skill.to_intent()),
        )
        .await
        .expect("skill-scoped authorize must not error");
    assert!(allowed, "valid token must authorize");

    // 1. ไฟล์ใต้ scope_path ของ skill → เปิดได้
    assert_eq!(
        probe(&mut stdin, &mut stdout, &format!("probe {allowed_file}")).await,
        "OK",
        "in-scope file must open (skill declared this path)"
    );
    // 2. นอก scope_path → โดนปฏิเสธ
    assert_eq!(
        probe(&mut stdin, &mut stdout, "probe /etc/hostname").await,
        "DENIED",
        "out-of-scope file must be denied per skill manifest"
    );
    // 3. exec → skill ไม่ได้ประกาศ exec (แม้ token ให้) → ถูก narrow ออก → ปฏิเสธ
    assert_eq!(
        probe(&mut stdin, &mut stdout, "execprobe").await,
        "EXECDENIED",
        "exec must be denied — skill did not declare the exec class"
    );

    let _ = stdin.write_all(b"quit\n").await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    companion.shutdown().await;
    let _ = tokio::fs::remove_file(&config.kernel_companion.uds_socket_path).await;
    let _ = tokio::fs::remove_file(&config.capability_security.audit_log_path).await;
    let _ = std::fs::remove_dir_all(&data_dir);
    let _ = std::fs::remove_dir_all(&skills_dir);
    let _ = std::fs::remove_dir(&cgroup_path);

    eprintln!("PASS: H8 skill-manifest scope enforced in kernel (declared capabilities only)");
}
