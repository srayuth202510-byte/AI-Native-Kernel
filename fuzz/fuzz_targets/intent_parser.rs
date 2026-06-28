#![no_main]

use intent_bus::{Intent, IntentPriority, IntentType};
use kernel_companion::nlp::parse_natural_language_intent;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let payload = String::from_utf8_lossy(data).into_owned();
    let intent_type = match data.first().copied().unwrap_or_default() % 5 {
        0 => IntentType::NaturalLanguage,
        1 => IntentType::Structured,
        2 => IntentType::Command,
        3 => IntentType::Event,
        _ => IntentType::Interrupt,
    };
    let priority = match data.get(1).copied().unwrap_or_default() % 4 {
        0 => IntentPriority::Low,
        1 => IntentPriority::Medium,
        2 => IntentPriority::High,
        _ => IntentPriority::Critical,
    };

    let mut intent = Intent::new("fuzz-intent", intent_type, payload, priority, "fuzzer");
    if let Some(target) = data.get(2..16) {
        intent.target = Some(String::from_utf8_lossy(target).into_owned());
    }

    let mut metadata = HashMap::new();
    metadata.insert(
        "hint".to_string(),
        String::from_utf8_lossy(data.get(16..48).unwrap_or_default()).into_owned(),
    );
    metadata.insert(
        "tenant".to_string(),
        format!("{}", data.get(48).copied().unwrap_or_default()),
    );
    intent.metadata = metadata;

    let parsed = parse_natural_language_intent(&intent);
    if let Some(parsed) = parsed {
        let _ = serde_json::to_string(&parsed);
    }

    if let Ok(serialized) = serde_json::to_string(&intent) {
        let _ = serde_json::from_str::<Intent>(&serialized);
    }
});
