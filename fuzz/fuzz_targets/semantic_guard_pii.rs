//! Fuzz target for semantic_guard PII detection

#![no_main]

use libfuzzer_sys::fuzz_target;
use semantic_guard::{Direction, Guard, GuardConfig, DetectionMode};

fuzz_target!(|data: &[u8]| {
    // Test with PiiOnly mode
    let config = GuardConfig {
        detection_mode: DetectionMode::PiiOnly,
        ..GuardConfig::default()
    };
    let guard = Guard::with_config(config).expect("guard should build");

    let input = String::from_utf8_lossy(data).into_owned();

    // Test inbound with PiiOnly
    let _ = guard.inspect(&input, Direction::Inbound);

    // Test outbound
    let _ = guard.inspect(&input, Direction::Outbound);

    // Test with PiiAndSignatures mode
    let config = GuardConfig::default();
    let guard = Guard::with_config(config).expect("guard should build");

    let _ = guard.inspect(&input, Direction::Inbound);
    let _ = guard.inspect(&input, Direction::Outbound);

    // Test fail-closed path
    let _ = guard.inspect_fail_closed(&input, Direction::Inbound);
    let _ = guard.inspect_fail_closed(&input, Direction::Outbound);
});