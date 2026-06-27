use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let bpf_out_dir = Path::new(&out_dir).join("bpf");
    std::fs::create_dir_all(&bpf_out_dir).ok();

    let bpf_c_src = Path::new("src/ebpf/syscall-tracer.bpf.c");
    let bpf_o_dst = bpf_out_dir.join("syscall-tracer.bpf.o");

    println!("cargo:rerun-if-changed={}", bpf_c_src.display());

    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let bpf_inc = format!(
        "/usr/src/linux-headers-{}/tools/bpf/resolve_btfids/libbpf/include",
        kernel_release
    );

    let vmlinux_h = bpf_out_dir.join("vmlinux.h");

    let can_compile = Path::new("/sys/kernel/btf/vmlinux").exists()
        && Path::new(&bpf_inc).join("bpf/bpf_helpers.h").exists()
        && Command::new("clang").arg("--version").output().is_ok()
        && bpf_c_src.exists();

    if can_compile {
        if !vmlinux_h.exists() {
            let vmlinux_output = Command::new("bpftool")
                .args([
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ])
                .output()
                .expect("bpftool should be available");

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

        let clang_status = Command::new("clang")
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
            .arg(bpf_c_src)
            .arg("-o")
            .arg(&bpf_o_dst)
            .status()
            .expect("clang should be available");

        if !clang_status.success() {
            println!(
                "cargo:warning=clang failed to compile BPF program — falling back to simulation"
            );
            print_bpf_disabled_instructions();
            return;
        }

        println!("cargo:rustc-env=BPF_OUT_DIR={}", bpf_out_dir.display());
        println!("cargo:warning=eBPF syscall-tracer compiled successfully ✓");
    } else {
        println!("cargo:warning=eBPF compilation prerequisites not met — using simulation mode");
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
