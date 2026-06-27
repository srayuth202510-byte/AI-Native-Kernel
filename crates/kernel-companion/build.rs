use std::path::Path;
use std::process::Command;

fn candidate_works(candidate: &str) -> bool {
    if candidate.is_empty() {
        return false;
    }

    if candidate.contains('/') {
        return Path::new(candidate).exists();
    }

    Command::new(candidate).arg("--version").output().is_ok()
}

fn resolve_tool(env_var: &str, candidates: &[&str]) -> Option<String> {
    if let Ok(value) = std::env::var(env_var) {
        if !value.is_empty() {
            return Some(value);
        }
    }

    for candidate in candidates {
        if candidate_works(candidate) {
            return Some((*candidate).to_string());
        }
    }

    None
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let bpf_out_dir = Path::new(&out_dir).join("bpf");
    std::fs::create_dir_all(&bpf_out_dir).ok();

    let bpf_sources: &[&str] = &[
        "src/ebpf/syscall-tracer.bpf.c",
        "src/ebpf/lsm-security.bpf.c",
    ];

    for src in bpf_sources {
        println!("cargo:rerun-if-changed={}", src);
    }
    println!("cargo:rerun-if-env-changed=CLANG_BIN");
    println!("cargo:rerun-if-env-changed=BPFTOOL_BIN");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let prebuilt_bpf_dir = Path::new(&manifest_dir).join("target").join("bpf");
    let prebuilt_syscall = prebuilt_bpf_dir.join("syscall-tracer.bpf.o");
    let prebuilt_lsm = prebuilt_bpf_dir.join("lsm-security.bpf.o");
    if prebuilt_syscall.exists() && prebuilt_lsm.exists() {
        println!(
            "cargo:warning=using prebuilt eBPF objects from {}",
            prebuilt_bpf_dir.display()
        );
        println!("cargo:rustc-env=BPF_OUT_DIR={}", prebuilt_bpf_dir.display());
        return;
    }

    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let bpf_inc = format!(
        "/usr/src/linux-headers-{}/tools/bpf/resolve_btfids/libbpf/include",
        kernel_release
    );

    let vmlinux_h = bpf_out_dir.join("vmlinux.h");
    let clang = resolve_tool(
        "CLANG_BIN",
        &[
            "clang",
            "clang-18",
            "clang-17",
            "/usr/lib/llvm-18/bin/clang",
            "/usr/lib/llvm-17/bin/clang",
            "/usr/lib/llvm-16/bin/clang",
            "/usr/local/bin/clang",
        ],
    );
    let bpftool = resolve_tool(
        "BPFTOOL_BIN",
        &["bpftool", "/usr/sbin/bpftool", "/usr/local/bin/bpftool"],
    );

    let can_compile = Path::new("/sys/kernel/btf/vmlinux").exists()
        && Path::new(&bpf_inc).join("bpf/bpf_helpers.h").exists()
        && clang.is_some()
        && bpftool.is_some()
        && bpf_sources.iter().all(|s| Path::new(s).exists());

    if can_compile {
        let clang = clang.expect("clang should be resolved");
        let bpftool = bpftool.expect("bpftool should be resolved");

        if !vmlinux_h.exists() {
            let vmlinux_output = match Command::new(&bpftool)
                .args([
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ])
                .output()
            {
                Ok(output) => output,
                Err(err) => {
                    println!("cargo:warning=bpftool invocation failed: {err}");
                    print_bpf_disabled_instructions();
                    return;
                }
            };

            if vmlinux_output.status.success() {
                std::fs::write(&vmlinux_h, vmlinux_output.stdout).expect("write vmlinux.h");
            } else {
                let stderr = String::from_utf8_lossy(&vmlinux_output.stderr);
                println!("cargo:warning=bpftool stderr: {stderr}");
                println!(
                    "cargo:warning=bpftool failed to generate vmlinux.h — BPF will not be compiled"
                );
                print_bpf_disabled_instructions();
                return;
            }
        }

        let mut all_succeeded = true;
        for src in bpf_sources {
            let stem = Path::new(src).file_stem().unwrap().to_str().unwrap();
            let bpf_o_dst = bpf_out_dir.join(format!("{}.bpf.o", stem));

            let clang_status = Command::new(&clang)
                .args([
                    "-O2",
                    "-target",
                    "bpf",
                    "-g",
                    "-I",
                    vmlinux_h.parent().unwrap().to_str().unwrap(),
                    "-I",
                    &bpf_inc,
                    "-c",
                ])
                .arg(src)
                .arg("-o")
                .arg(&bpf_o_dst)
                .status()
                .expect("clang should be available");

            if !clang_status.success() {
                println!(
                    "cargo:warning=clang failed to compile {src} — falling back to simulation"
                );
                all_succeeded = false;
            } else {
                println!("eBPF {stem} compiled successfully ✓");
            }
        }

        if all_succeeded {
            println!("cargo:rustc-env=BPF_OUT_DIR={}", bpf_out_dir.display());
        }
    } else {
        println!("cargo:warning=eBPF compilation prerequisites not met — using simulation mode");
        if clang.is_none() {
            println!("cargo:warning=clang/clang-18/clang-17 not found in PATH");
        }
        if bpftool.is_none() {
            println!("cargo:warning=bpftool not found in PATH");
        }
        print_bpf_disabled_instructions();
    }
}

fn print_bpf_disabled_instructions() {
    println!("cargo:warning=  To enable real eBPF tracing, ensure:");
    println!("cargo:warning=    1. Kernel BTF:  /sys/kernel/btf/vmlinux");
    println!(
        "cargo:warning=    2. BPF headers: /usr/src/linux-headers-$(uname -r)/.../bpf/bpf_helpers.h"
    );
    println!("cargo:warning=    3. clang with BPF target support");
    println!("cargo:warning=    4. bpftool installed");
}
