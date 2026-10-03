//! Fuzz target for semantic_guard injection detection

#![no_main]

use libfuzzer_sys::fuzz_target;
use semantic_guard::{Direction, Guard, GuardConfig};

fuzz_target!(|data: &[u8]| {
    let config = GuardConfig::default();
    let guard = Guard::with_config(config).expect("guard should build");

    let input = String::from_utf8_lossy(data).into_owned();

    // Test inbound (checks both PII and injection)
    let _ = guard.inspect(&input, Direction::Inbound);

    // Test outbound (checks PII only)
    let _ = guard.inspect(&input, Direction::Outbound);
});