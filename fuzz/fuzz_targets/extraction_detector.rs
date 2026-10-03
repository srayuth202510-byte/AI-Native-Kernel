//! Fuzz target for extraction detector

#![no_main]

use extraction_det::{ExtractionConfig, ExtractionDetector};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = ExtractionConfig::default();
    let detector = ExtractionDetector::new(config).expect("detector should build");

    let tenant_id = String::from_utf8_lossy(data.get(..16).unwrap_or(data)).into_owned();
    let prompt = String::from_utf8_lossy(data).into_owned();
    let prompt_tokens = data.len().min(1000) as u64;
    let completion_tokens = data.get(16..32).map(|b| b.iter().sum::<u8>() as u64).unwrap_or(10);
    let now_ms = 1_700_000_000_000; // Fixed timestamp for determinism

    let _ = detector.observe(&tenant_id, &prompt, prompt_tokens, completion_tokens, now_ms);
});