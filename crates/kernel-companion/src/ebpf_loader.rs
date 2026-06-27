//! Utility to load compiled eBPF object files.
//! The build script (build.rs) compiles C sources in `ebpf/` into .o files placed under
//! `target/bpf/`. This module provides a small helper that reads the binary data at runtime.
//!
//! The function returns the raw bytes of the `.o` file, which can then be fed to `aya::Bpf::load`.
//! Errors are wrapped in `anyhow::Error` for easy propagation.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

/// Load the compiled eBPF object file with the given base name.
///
/// * `name` – the base name of the eBPF program without extension, e.g. "lsm-security".
///
/// The function looks for the file at `target/bpf/<name>.o`. If the file does not exist,
/// a clear error is returned so that the caller can fall back to simulation mode.
pub fn load_bpf_o(name: &str) -> Result<Vec<u8>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("bpf");
    path.push(format!("{name}.o"));

    if !path.exists() {
        return Err(anyhow!("eBPF object file not found: {}", path.display()));
    }

    let bytes = fs::read(&path).map_err(|e| anyhow!("Failed to read {}: {}", path.display(), e))?;
    Ok(bytes)
}
