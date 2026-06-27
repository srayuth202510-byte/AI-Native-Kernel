use anyhow::Result;
use bytes::BytesMut;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, instrument, warn};

use crate::lsm::{LsmDecision, LsmPolicyEngine};

// ---- Types ----

#[derive(Debug, Error)]
pub enum TracerError {
    #[error("eBPF program load failed: {0}")]
    LoadFailed(String),
    #[error("tracepoint attach failed: {0}")]
    AttachFailed(String),
    #[error("ring buffer error: {0}")]
    RingBufferError(String),
    #[error("tracer cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    pub syscall_nr: u64,
    pub syscall_name: String,
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

pub type SyscallEventReceiver = mpsc::Receiver<SyscallEvent>;

// ---- SyscallTracer ----

pub struct SyscallTracer {
    policy: Arc<LsmPolicyEngine>,
    event_tx: mpsc::Sender<SyscallEvent>,
    syscall_table: HashMap<u64, &'static str>,
}

impl SyscallTracer {
    #[must_use]
    pub fn new(policy: Arc<LsmPolicyEngine>) -> (Self, SyscallEventReceiver) {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let tracer = Self {
            policy,
            event_tx,
            syscall_table: build_syscall_table(),
        };
        (tracer, event_rx)
    }

    #[instrument(skip(self, cancel))]
    pub async fn run(self, cancel: CancellationToken) -> Result<(), TracerError> {
        info!("SyscallTracer starting — attempting real eBPF program load");

        match self.try_run_bpf(cancel.clone()).await {
            Ok(()) => {
                info!("SyscallTracer running on real eBPF");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "real eBPF load failed — falling back to simulation mode");
                self.run_simulation_loop(cancel).await
            }
        }
    }

    #[instrument(skip(self, cancel))]
    async fn try_run_bpf(&self, cancel: CancellationToken) -> Result<(), TracerError> {
        let bpf_bytes = load_bpf_program_bytes()
            .map_err(|e| TracerError::LoadFailed(format!("cannot load BPF .o bytes: {e}")))?;

        let mut bpf =
            aya::Bpf::load(&bpf_bytes).map_err(|e| TracerError::LoadFailed(e.to_string()))?;

        let program: &mut aya::programs::TracePoint = bpf
            .program_mut("sys_enter_tp")
            .ok_or_else(|| TracerError::LoadFailed("no sys_enter_tp program".into()))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                TracerError::LoadFailed(format!("program type mismatch: {e}"))
            })?;

        program
            .load()
            .map_err(|e| TracerError::LoadFailed(e.to_string()))?;

        program
            .attach("raw_syscalls", "sys_enter")
            .map_err(|e| TracerError::AttachFailed(e.to_string()))?;

        info!("eBPF tracepoint sys_enter attached — polling ring buffer");

        let map = bpf
            .take_map("syscall_events")
            .ok_or_else(|| TracerError::RingBufferError("map syscall_events not found".into()))?;

        let mut perf_array: aya::maps::PerfEventArray<_> = map
            .try_into()
            .map_err(|e: aya::maps::MapError| TracerError::RingBufferError(e.to_string()))?;

        let cpus =
            aya::util::online_cpus().map_err(|e| TracerError::RingBufferError(e.to_string()))?;

        let mut buffers: Vec<PerfBufferState> = Vec::new();
        for cpu_id in cpus {
            let buf = perf_array
                .open(cpu_id, None)
                .map_err(|e| TracerError::RingBufferError(e.to_string()))?;
            buffers.push(PerfBufferState {
                cpu_id,
                buf,
                out_bufs: vec![BytesMut::with_capacity(4096)],
            });
        }

        let poll_interval = std::time::Duration::from_millis(1);

        while !cancel.is_cancelled() {
            for state in buffers.iter_mut() {
                match state.buf.read_events(&mut state.out_bufs) {
                    Ok(events) if events.read > 0 => {
                        for buf in state.out_bufs.iter() {
                            if let Some(raw) = parse_raw_event(buf) {
                                let event =
                                    self.process_syscall_event(raw.syscall_nr, raw.pid, raw.uid);
                                if self.event_tx.try_send(event).is_err() {
                                    debug!("event channel full — dropping syscall event");
                                }
                            }
                        }
                        if events.lost > 0 {
                            debug!(lost = events.lost, "perf events lost");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!(cpu = state.cpu_id, error = %e, "read_events error");
                    }
                }
            }
            tokio::time::sleep(poll_interval).await;
        }

        info!("SyscallTracer eBPF loop stopped (cancel)");
        Ok(())
    }

    #[instrument(skip(self, cancel))]
    async fn run_simulation_loop(&self, cancel: CancellationToken) -> Result<(), TracerError> {
        info!("SyscallTracer running in simulation mode (Phase 1 — no real kernel tracepoint)");

        let simulated: &[(u64, u32, u32)] = &[
            (0, 1000, 1000),
            (1, 1000, 1000),
            (59, 1001, 0),
            (2, 1002, 1000),
        ];

        for &(syscall_nr, pid, uid) in simulated {
            if cancel.is_cancelled() {
                info!("SyscallTracer received cancel signal — stopping");
                return Err(TracerError::Cancelled);
            }

            let event = self.process_syscall_event(syscall_nr, pid, uid);
            debug!(
                syscall = %event.syscall_name,
                pid = event.pid,
                decision = ?event.decision,
                "processed syscall event"
            );

            if self.event_tx.send(event).await.is_err() {
                warn!("SyscallEvent receiver closed — stopping tracer");
                break;
            }
        }

        info!("SyscallTracer stopped (simulation loop complete)");
        Ok(())
    }

    #[instrument(skip(self), fields(syscall_nr, pid, uid))]
    pub fn process_syscall_event(&self, syscall_nr: u64, pid: u32, uid: u32) -> SyscallEvent {
        let syscall_name = self
            .syscall_table
            .get(&syscall_nr)
            .copied()
            .unwrap_or("unknown");

        let lsm_decision = self.policy.decision_for_syscall(syscall_name);
        let decision = match lsm_decision {
            LsmDecision::Allow => PolicyDecision::Allow,
            LsmDecision::Deny => {
                warn!(
                    syscall = syscall_name,
                    pid, uid, "LSM denied syscall per Zero-Trust policy"
                );
                PolicyDecision::Deny
            }
        };

        SyscallEvent {
            syscall_nr,
            syscall_name: syscall_name.to_string(),
            pid,
            uid,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            decision,
        }
    }
}

// ---- Per-buffer state ----

struct PerfBufferState {
    #[allow(dead_code)]
    cpu_id: u32,
    buf: aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>,
    out_bufs: Vec<BytesMut>,
}

// ---- Raw event struct matching BPF C definition ----

#[repr(C)]
struct RawSyscallEvent {
    syscall_nr: u64,
    pid: u32,
    uid: u32,
    timestamp_ns: u64,
}

fn parse_raw_event(buf: &[u8]) -> Option<RawSyscallEvent> {
    let size = std::mem::size_of::<RawSyscallEvent>();
    if buf.len() < size {
        return None;
    }
    let syscall_nr = u64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
    let uid = u32::from_ne_bytes(buf[12..16].try_into().ok()?);
    let timestamp_ns = u64::from_ne_bytes(buf[16..24].try_into().ok()?);
    Some(RawSyscallEvent {
        syscall_nr,
        pid,
        uid,
        timestamp_ns,
    })
}

// ---- BPF program loading ----

/// Load a compiled BPF .o file by stem name (e.g., "syscall-tracer" or "lsm-security").
/// Looks in BPF_OUT_DIR first, then CARGO_MANIFEST_DIR/target/bpf/, then common paths.
pub fn load_bpf_o(stem: &str) -> Result<Vec<u8>> {
    let filename = format!("{}.bpf.o", stem);
    let bpf_o_path = if let Ok(out_dir) = std::env::var("BPF_OUT_DIR") {
        std::path::PathBuf::from(out_dir).join(&filename)
    } else if let Ok(cargo_manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        std::path::PathBuf::from(cargo_manifest)
            .join("target")
            .join("bpf")
            .join(&filename)
    } else {
        // Check relative to the current binary
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_default();
        let rel = exe_dir.join(&filename);
        if rel.exists() {
            return Ok(std::fs::read(&rel)?);
        }
        anyhow::bail!(
            "BPF_OUT_DIR and CARGO_MANIFEST_DIR not set, and {} not found near binary",
            filename
        );
    };

    if !bpf_o_path.exists() {
        anyhow::bail!("BPF object file not found: {}", bpf_o_path.display());
    }

    Ok(std::fs::read(&bpf_o_path)?)
}

// Backward compatibility for internal use
fn load_bpf_program_bytes() -> Result<Vec<u8>> {
    load_bpf_o("syscall-tracer")
}

// ---- CancellationToken ----

pub mod tokio_util_cancel {
    #[derive(Clone, Default)]
    pub struct CancellationToken {
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl CancellationToken {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        pub fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        #[must_use]
        pub fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
}

use tokio_util_cancel::CancellationToken;

// ---- x86_64 syscall table ----

pub fn build_syscall_table() -> HashMap<u64, &'static str> {
    let mut table = HashMap::new();
    table.insert(0, "read");
    table.insert(1, "write");
    table.insert(2, "open");
    table.insert(3, "close");
    table.insert(4, "stat");
    table.insert(5, "fstat");
    table.insert(6, "lstat");
    table.insert(7, "poll");
    table.insert(8, "lseek");
    table.insert(9, "mmap");
    table.insert(10, "mprotect");
    table.insert(11, "munmap");
    table.insert(12, "brk");
    table.insert(41, "socket");
    table.insert(42, "connect");
    table.insert(43, "accept");
    table.insert(44, "sendto");
    table.insert(45, "recvfrom");
    table.insert(46, "sendmsg");
    table.insert(47, "recvmsg");
    table.insert(56, "clone");
    table.insert(57, "fork");
    table.insert(58, "vfork");
    table.insert(59, "execve");
    table.insert(60, "exit");
    table.insert(61, "wait4");
    table.insert(62, "kill");
    table.insert(63, "uname");
    table.insert(80, "chdir");
    table.insert(81, "fchdir");
    table.insert(82, "rename");
    table.insert(83, "mkdir");
    table.insert(84, "rmdir");
    table.insert(85, "creat");
    table.insert(86, "link");
    table.insert(87, "unlink");
    table.insert(88, "symlink");
    table.insert(89, "readlink");
    table.insert(90, "chmod");
    table.insert(91, "fchmod");
    table.insert(92, "chown");
    table.insert(93, "fchown");
    table.insert(94, "lchown");
    table
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracer() -> (SyscallTracer, SyscallEventReceiver) {
        SyscallTracer::new(Arc::new(LsmPolicyEngine::new()))
    }

    #[test]
    fn process_read_syscall_is_allowed() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 1000, 1000);
        assert_eq!(event.syscall_name, "read");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_write_syscall_is_allowed() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(1, 1000, 1000);
        assert_eq!(event.syscall_name, "write");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_execve_syscall_is_denied() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(59, 1001, 0);
        assert_eq!(event.syscall_name, "execve");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn unknown_syscall_is_denied() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(9999, 1000, 1000);
        assert_eq!(event.syscall_name, "unknown");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn syscall_event_contains_pid_and_uid() {
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 42, 1337);
        assert_eq!(event.pid, 42);
        assert_eq!(event.uid, 1337);
    }

    #[tokio::test]
    async fn simulation_loop_sends_events_to_channel() {
        let cancel = CancellationToken::new();
        let (tracer, mut rx) = make_tracer();

        tokio::spawn(async move {
            let _ = tracer.run(cancel).await;
        });

        let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("should receive event within 500ms")
            .expect("channel should be open");

        assert_eq!(event.syscall_nr, 0);
        assert_eq!(event.syscall_name, "read");
    }

    #[test]
    fn syscall_table_covers_common_syscalls() {
        let table = build_syscall_table();
        assert!(table.contains_key(&0), "must have read");
        assert!(table.contains_key(&1), "must have write");
        assert!(table.contains_key(&59), "must have execve");
        assert!(table.contains_key(&41), "must have socket");
        assert!(table.len() >= 30, "table should have at least 30 entries");
    }

    #[test]
    fn tracer_falls_back_to_simulation_when_bpf_missing() {
        let (tracer, mut rx) = make_tracer();
        let cancel = CancellationToken::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            tokio::spawn(async move {
                let _ = tracer.run(cancel).await;
            });

            let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
                .await
                .expect("should receive event within 500ms")
                .expect("channel should be open");

            assert_eq!(event.syscall_nr, 0);
            assert_eq!(event.syscall_name, "read");
        });
    }
}
