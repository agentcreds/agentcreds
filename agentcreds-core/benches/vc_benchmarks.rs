//! Benchmarks for capability credential issuance, verification, and JSON-LD I/O.

use agentcreds_core::did::{AgentIdentity, DidMethod, TrustAnchor};
use agentcreds_core::vc::{CapabilityClaims, CapabilityCredential};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn claims() -> CapabilityClaims {
    CapabilityClaims::new(
        vec![
            "tool:search".into(),
            "tool:summarize".into(),
            "tool:email".into(),
        ],
        3,
        3600,
    )
}

fn setup() -> (TrustAnchor, AgentIdentity, CapabilityCredential) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap();
    (anchor, agent, vc)
}

fn bench_issue(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    c.bench_function("vc_issue", |b| {
        b.iter(|| CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap())
    });
}

fn bench_verify(c: &mut Criterion) {
    let (anchor, _agent, vc) = setup();

    let mut group = c.benchmark_group("vc_verify");
    group.bench_function("strict_issuer", |b| {
        b.iter(|| vc.verify(black_box(&anchor), true).unwrap())
    });
    group.bench_function("non_strict", |b| {
        b.iter(|| vc.verify(black_box(&anchor), false).unwrap())
    });
    group.finish();
}

fn bench_json_round_trip(c: &mut Criterion) {
    let (_anchor, _agent, vc) = setup();
    let json = vc.to_json().unwrap();

    let mut group = c.benchmark_group("vc_json");
    group.bench_function("to_json", |b| b.iter(|| vc.to_json().unwrap()));
    group.bench_function("from_json", |b| {
        b.iter(|| CapabilityCredential::from_json(black_box(&json)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_issue, bench_verify, bench_json_round_trip);
criterion_main!(benches);
