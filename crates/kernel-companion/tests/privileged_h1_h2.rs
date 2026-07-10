//! Privileged E2E validation ของ H1 + H2 ขา allow ผ่าน authorize flow จริง
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

/// probe shell: รอคำสั่งทาง stdin แล้วลองเปิดไฟล์ด้วย bash builtin redirect
/// (ไม่ exec ลูกใหม่ — จะได้วัด file_open ของ PID นี้ล้วนๆ) แล้วรายงานผล
/// ทาง stdout ที่เปิดค้างไว้แล้ว (write ไม่ถูก hook)
const PROBE_SCRIPT: &str = r#"while read -r cmd; do
  case "$cmd" in
    probe) if read -r _ < /etc/hostname 2>/dev/null; then echo OK; else echo DENIED; fi ;;
    quit) exit 0 ;;
  esac
done"#;

async fn probe(
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
) -> String {
    stdin
        .write_all(b"probe\n")
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
        eprintln!("SKIP e2e_h2_allow_path_through_real_authorize_flow: {e}");
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
        probe(&mut stdin, &mut stdout).await,
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
        probe(&mut stdin, &mut stdout).await,
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
        probe(&mut stdin, &mut stdout).await,
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
