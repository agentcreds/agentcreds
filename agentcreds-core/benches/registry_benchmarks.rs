//! Benchmarks for trust registry registration, resolution, and cross-org
//! credential verification.

use agentcreds_core::did::{AgentIdentity, DidMethod, TrustAnchor};
use agentcreds_core::registry::{CrossOrgVerifier, TrustEntry, TrustLevel, TrustRegistry};
use agentcreds_core::vc::{CapabilityClaims, CapabilityCredential};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

fn setup() -> (TrustAnchor, CapabilityCredential, TrustRegistry) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let entry = TrustEntry::new(
        anchor.did(),
        "Benchmark Org",
        anchor.public_key().clone(),
        TrustLevel::Verified,
    );
    let mut registry = TrustRegistry::new();
    registry.register(entry);

    (anchor, vc, registry)
}

fn bench_register(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();

    c.bench_function("registry_register", |b| {
        b.iter_batched(
            TrustRegistry::new,
            |mut registry| {
                let entry = TrustEntry::new(
                    anchor.did(),
                    "Benchmark Org",
                    anchor.public_key().clone(),
                    TrustLevel::Verified,
                );
                registry.register(entry);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_resolve_cached(c: &mut Criterion) {
    let (anchor, _vc, mut registry) = setup();

    c.bench_function("registry_resolve_cached", |b| {
        b.iter(|| {
            registry.resolve(black_box(anchor.did())).unwrap();
        })
    });
}

fn bench_cross_org_verify(c: &mut Criterion) {
    let (_anchor, vc, mut registry) = setup();

    c.bench_function("registry_cross_org_verify", |b| {
        b.iter(|| {
            let mut verifier = CrossOrgVerifier::new(&mut registry);
            verifier.verify(black_box(&vc)).unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_register,
    bench_resolve_cached,
    bench_cross_org_verify,
);
criterion_main!(benches);
