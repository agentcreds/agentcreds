//! Benchmarks for OAuth Status List revocation list creation, mutation, and checks.

use agentcreds_core::did::TrustAnchor;
use agentcreds_core::revocation::RevocationList;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

const LIST_URL: &str = "https://registry.example.com/status/1";

fn bench_new_list(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();

    let mut group = c.benchmark_group("revocation_list_new");
    group.bench_function("default_size_131072", |b| {
        b.iter(|| RevocationList::new(LIST_URL, &anchor, None).unwrap())
    });
    group.bench_function("small_1024", |b| {
        b.iter(|| RevocationList::new(LIST_URL, &anchor, Some(1024)).unwrap())
    });
    group.finish();
}

fn bench_revoke(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();

    c.bench_function("revocation_revoke", |b| {
        b.iter_batched(
            || RevocationList::new(LIST_URL, &anchor, None).unwrap(),
            |mut list| list.revoke(42, &anchor).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_is_revoked(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();
    let mut list = RevocationList::new(LIST_URL, &anchor, None).unwrap();
    list.revoke(42, &anchor).unwrap();

    let mut group = c.benchmark_group("revocation_is_revoked");
    group.bench_function("revoked_index", |b| b.iter(|| list.is_revoked(42).unwrap()));
    group.bench_function("valid_index", |b| b.iter(|| list.is_revoked(7).unwrap()));
    group.finish();
}

fn bench_verify_signature(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();
    let list = RevocationList::new(LIST_URL, &anchor, None).unwrap();

    c.bench_function("revocation_verify_signature", |b| {
        b.iter(|| list.verify(&anchor).unwrap())
    });
}

criterion_group!(
    benches,
    bench_new_list,
    bench_revoke,
    bench_is_revoked,
    bench_verify_signature,
);
criterion_main!(benches);
