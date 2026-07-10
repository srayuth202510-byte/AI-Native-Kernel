//! ank-run — launcher ที่รัน process ใด ๆ ใต้ capability scope ของ skill (H8/A)
//!
//! `ank-run --skill <file.md> -- <cmd> [args...]`
//!
//! รวม H1–H8 มาเป็น UX เดียวแบบ firejail/bwrap: อ่าน skill manifest → boot
//! companion → spawn child แบบ **stopped** (กัน race ก่อน enroll) → authorize
//! child PID ด้วย scope ที่ compile จาก skill (ย้ายเข้า agent cgroup H1 +
//! start-time identity H2 + scope H3) → `SIGCONT` ให้ child วิ่งต่อ **ใต้
//! scope ที่ skill ประกาศ** ต่อจากนั้น kernel บังคับ ไม่ว่า child จะร่วมมือ
//! หรือไม่ (non-cooperative enforcement)
//!
//! หมายเหตุ: การรัน enforcement จริงต้อง root/CAP_BPF (real eBPF attach)
//! บนเครื่องไม่มีสิทธิ์จะ degrade เป็น simulation (child ยังรันได้ แต่ไม่ถูก
//! บังคับที่ kernel) — ใช้ `--no-fallback` เพื่อบังคับ fail-closed

use anyhow::{Context, Result, bail};
use capability_security::{CapabilityToken, Scope};
use kernel_companion::config::Config;
use kernel_companion::{AgentCgroup, KernelCompanion, Skill};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::process::Stdio;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "Usage: ank-run --skill <manifest.md> [--cgroup <path>] [--no-fallback] -- <cmd> [args...]"
    );
    std::process::exit(2);
}

struct Args {
    skill_path: String,
    cgroup_path: String,
    no_fallback: bool,
    command: Vec<String>,
}

fn parse_args() -> Args {
    let mut skill_path = None;
    let mut cgroup_path = format!("/sys/fs/cgroup/ank-run-{}", std::process::id());
    let mut no_fallback = false;
    let mut command = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--skill" => skill_path = it.next(),
            "--cgroup" => {
                if let Some(v) = it.next() {
                    cgroup_path = v;
                }
            }
            "--no-fallback" => no_fallback = true,
            "--" => {
                command.extend(it.by_ref());
                break;
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    let Some(skill_path) = skill_path else {
        eprintln!("--skill is required");
        usage();
    };
    if command.is_empty() {
        eprintln!("no command given after --");
        usage();
    }
    Args {
        skill_path,
        cgroup_path,
        no_fallback,
        command,
    }
}

/// อ่าน state ของ process จาก /proc/<pid>/stat field 3 (คืน `None` ถ้าหาย)
fn proc_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')').map(|(_, r)| r).unwrap_or(&stat);
    after_comm.split_whitespace().next()?.chars().next()
}

/// รอจน child เข้าสถานะ stopped ('T') หรือหมดเวลา
async fn wait_stopped(pid: u32, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match proc_state(pid) {
            Some('T') => return true,
            None => return false, // process หายไปแล้ว
            _ => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    false
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    let skill = Skill::load(std::path::Path::new(&args.skill_path))
        .with_context(|| format!("cannot load skill manifest {}", args.skill_path))?;
    eprintln!(
        "ank-run: skill '{}' — {}",
        skill.manifest.name, skill.manifest.description
    );

    // ── boot companion แบบเบา: ปิดงานที่ไม่จำเป็นสำหรับ launcher ──
    let mut config = Config::default();
    config.kernel_companion.uds_socket_path = format!("/tmp/ank-run-{}.sock", std::process::id());
    config.kernel_companion.metrics_server_addr = "127.0.0.1:0".to_string();
    config.context_memory.p2p_enabled = false;
    config.context_memory.sfs_enabled = false;
    config.ebpf.enable_fallback = !args.no_fallback;

    // ตรวจว่าสร้าง agent cgroup ได้ไหม (ต้อง root) — enforcement จริงต้องมี
    // cgroup ถ้าไม่ได้: --no-fallback → fail closed; ไม่งั้นเตือนว่า
    // enforcement OFF แล้วรันต่อ (dev/demo บนเครื่องไม่มีสิทธิ์)
    let mut enforced = true;
    match AgentCgroup::ensure(&args.cgroup_path) {
        Ok(_) => config.lsm.agent_cgroup_path = Some(args.cgroup_path.clone()),
        Err(e) => {
            if args.no_fallback {
                bail!("cannot set up agent cgroup (need root) and --no-fallback set: {e}");
            }
            eprintln!(
                "ank-run: WARNING — cannot create agent cgroup ({e}); running WITHOUT kernel \
                 enforcement (dev mode). Run as root for real scope enforcement."
            );
            enforced = false;
        }
    }

    let mut companion = KernelCompanion::with_config(&config);
    companion
        .boot()
        .await
        .context("companion boot failed (need root/CAP_BPF for real enforcement)")?;

    // ── spawn child แบบ stopped: หยุดตัวเองก่อน exec target (กัน race ก่อน enroll)
    // shell หยุดตัวเองด้วย SIGSTOP → ank-run enroll → SIGCONT → exec target
    // target จึงถือกำเนิดใต้ scope ของ skill ตั้งแต่แรก ส่ง command เป็น
    // positional params ($1..) แล้ว `exec "$@"` เพื่อคง arg boundaries และ
    // เลี่ยง shell injection จาก args
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(r#"kill -STOP "$$"; exec "$@""#)
        .arg("ank-run-child") // $0 (ชื่อ placeholder)
        .args(&args.command) // $1..
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn child")?;
    let child_pid = child.id().context("child has no PID")?;

    if !wait_stopped(child_pid, Duration::from_secs(5)).await {
        let _ = child.kill().await;
        bail!("child did not reach stopped state before enrollment");
    }

    // ── enroll: issue token + authorize ด้วย scope ที่ compile จาก skill ──
    let secret = [0u8; 32];
    let token = CapabilityToken::new(
        u64::from(child_pid),
        Scope::Process(child_pid),
        vec![
            "read".to_string(),
            "write".to_string(),
            "exec".to_string(),
            "net".to_string(),
        ],
        Duration::from_secs(24 * 3600),
        secret,
    );
    companion
        .capability_security()
        .issue_token(token.clone())
        .await
        .context("issue token")?;
    let allowed = companion
        .authorize_process_token_with_scope(
            child_pid,
            token.id,
            &secret,
            "read",
            Some(&skill.to_intent()),
        )
        .await
        .context("authorize child under skill scope")?;
    if !allowed {
        let _ = child.kill().await;
        bail!("authorization denied for child");
    }
    eprintln!(
        "ank-run: enrolled PID {child_pid} under skill '{}' ({}) — resuming",
        skill.manifest.name,
        if enforced {
            "kernel-enforced"
        } else {
            "dev mode, not enforced"
        }
    );

    // ── ปล่อย child วิ่งต่อใต้ scope ──
    kill(Pid::from_raw(child_pid as i32), Signal::SIGCONT).context("SIGCONT child")?;

    let status = child.wait().await.context("wait child")?;
    companion.shutdown().await;
    let _ = tokio::fs::remove_file(&config.kernel_companion.uds_socket_path).await;
    let _ = std::fs::remove_dir(&args.cgroup_path);

    std::process::exit(status.code().unwrap_or(1));
}
