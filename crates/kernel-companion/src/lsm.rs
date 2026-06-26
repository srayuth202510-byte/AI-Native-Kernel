#![no_std]
#![warn(
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_lint_unexpected,
    unused_qualifications,
    unused_extern_crates,
    clippy::all,
    clippy::pedantic
)]
#[macro_use]
extern crate aya_bpf;

/// EBPF program that attaches to LSM hooks for capability enforcement
#[aya_bpf::program(name = "ai_native_kernel")]
pub mod ai_native_kernel {
    #[linkage = "lsm"]
    pub fn ai_lsm_hook() -> i32 {
        ai_native_kernel_ebpf.lsm_hook()
    }
}