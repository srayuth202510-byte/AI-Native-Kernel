//! Fuzz target for NLP parser in kernel-companion

#![no_main]

use intent_bus::{Intent, IntentPriority, IntentType};
use kernel_companion::nlp::parse_natural_language_intent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data).into_owned();

    // Create an Intent with NaturalLanguage type
    let intent = Intent::new(
        "fuzz-intent",
        IntentType::NaturalLanguage,
        input,
        IntentPriority::Medium,
        "fuzzer",
    );

    let parsed = parse_natural_language_intent(&intent);
    if let Some(parsed) = parsed {
        // Test serialization round-trip
        let _ = serde_json::to_string(&parsed);

        // Test metadata handling
        let _ = parsed.metadata;
        let _ = parsed.target;
    }
});