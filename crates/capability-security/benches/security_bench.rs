use capability_security::{
    CapabilitySecurityManager, CapabilityToken, Scope,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::time::Duration;

fn bench_issue_token(c: &mut Criterion) {
    let manager = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        1,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0xABu8; 32],
    );

    c.bench_function("issue_token", |b| {
        b.iter(|| {
            manager.issue_token(black_box(token.clone())).unwrap();
        });
    });
}

fn bench_authorize_token_allow(c: &mut Criterion) {
    let manager = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        2,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0xABu8; 32],
    );
    manager.issue_token(token.clone()).unwrap();

    c.bench_function("authorize_token_allow", |b| {
        b.iter(|| {
            let result = manager
                .authorize_token(black_box(&token), "read")
                .unwrap();
            black_box(result)
        });
    });
}

fn bench_authorize_token_deny(c: &mut Criterion) {
    let manager = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        3,
        Scope::Global,
        vec!["write".to_string()],
        Duration::from_secs(3600),
        [0xABu8; 32],
    );
    manager.issue_token(token.clone()).unwrap();

    c.bench_function("authorize_token_deny", |b| {
        b.iter(|| {
            let result = manager
                .authorize_token(black_box(&token), "write")
                .unwrap();
            black_box(result)
        });
    });
}

fn bench_validate_token(c: &mut Criterion) {
    let manager = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        4,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0x42u8; 32],
    );
    manager.issue_token(token).unwrap();

    c.bench_function("validate_token", |b| {
        b.iter(|| {
            let result = manager
                .validate(4, &[0x42u8; 32], &Scope::Global, "read")
                .unwrap();
            black_box(result)
        });
    });
}

fn bench_decision_for(c: &mut Criterion) {
    let manager = CapabilitySecurityManager::new();
    let token = CapabilityToken::new(
        5,
        Scope::Process(99),
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0x99u8; 32],
    );
    manager.issue_token(token).unwrap();

    c.bench_function("decision_for_allow", |b| {
        b.iter(|| {
            let result = manager
                .decision_for(5, &[0x99u8; 32], &Scope::Process(99), "read")
                .unwrap();
            black_box(result)
        });
    });
}

fn bench_constant_time_eq(c: &mut Criterion) {
    let arr_a = [0xABu8; 32];
    let arr_b = [0xABu8; 32];

    c.bench_function("constant_time_eq_match", |bench| {
        bench.iter(|| {
            let result = capability_security::constant_time_eq(black_box(&arr_a), black_box(&arr_b));
            black_box(result)
        });
    });

    let arr_c = [0xCDu8; 32];
    c.bench_function("constant_time_eq_mismatch", |bench| {
        bench.iter(|| {
            let result =
                capability_security::constant_time_eq(black_box(&arr_a), black_box(&arr_c));
            black_box(result)
        });
    });
}

criterion_group!(
    benches,
    bench_issue_token,
    bench_authorize_token_allow,
    bench_authorize_token_deny,
    bench_validate_token,
    bench_decision_for,
    bench_constant_time_eq,
);
criterion_main!(benches);
