//! Benchmarks for DID identity creation, signing, and key encoding.

use agentcreds_core::did::{AgentIdentity, DidMethod, KeyAlgorithm, TrustAnchor};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_identity_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity_create");
    group.bench_function("ed25519", |b| {
        b.iter(|| AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::Ed25519)).unwrap())
    });
    group.bench_function("p256", |b| {
        b.iter(|| AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap())
    });
    group.finish();
}

fn bench_trust_anchor_generate(c: &mut Criterion) {
    c.bench_function("trust_anchor_generate", |b| {
        b.iter(|| TrustAnchor::generate().unwrap())
    });
}

fn bench_sign(c: &mut Criterion) {
    let ed25519 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::Ed25519)).unwrap();
    let p256 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
    let message = b"benchmark message for agentcreds signing";

    let mut group = c.benchmark_group("sign");
    group.bench_function("ed25519", |b| {
        b.iter(|| ed25519.sign(black_box(message)).unwrap())
    });
    group.bench_function("p256", |b| {
        b.iter(|| p256.sign(black_box(message)).unwrap())
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let ed25519 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::Ed25519)).unwrap();
    let p256 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
    let message = b"benchmark message for agentcreds signing";
    let ed25519_sig = ed25519.sign(message).unwrap();
    let p256_sig = p256.sign(message).unwrap();

    let mut group = c.benchmark_group("verify");
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            ed25519
                .verify(black_box(message), black_box(&ed25519_sig))
                .unwrap()
        })
    });
    group.bench_function("p256", |b| {
        b.iter(|| {
            p256.verify(black_box(message), black_box(&p256_sig))
                .unwrap()
        })
    });
    group.finish();
}

fn bench_multibase_encode(c: &mut Criterion) {
    let ed25519 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::Ed25519)).unwrap();
    let p256 = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();

    let mut group = c.benchmark_group("multibase_encode");
    group.bench_function("ed25519", |b| {
        b.iter(|| ed25519.public_key().to_multibase())
    });
    group.bench_function("p256", |b| b.iter(|| p256.public_key().to_multibase()));
    group.finish();
}

criterion_group!(
    benches,
    bench_identity_create,
    bench_trust_anchor_generate,
    bench_sign,
    bench_verify,
    bench_multibase_encode,
);
criterion_main!(benches);
