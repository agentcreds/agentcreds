//! Benchmarks for delegation token minting, attenuation, verification, and
//! CBOR wire encoding - including the cost of verification at increasing
//! delegation chain depths (chain depth is capped at 10, see `delegation` module docs).

use agentcreds_core::delegation::{Action, DelegationToken, Scope};
use agentcreds_core::did::{AgentIdentity, DidMethod, TrustAnchor};
use agentcreds_core::vc::{CapabilityClaims, CapabilityCredential};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

const CHAIN_DEPTHS: [u32; 5] = [0, 1, 3, 5, 10];

fn setup() -> (AgentIdentity, CapabilityCredential) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(
        vec![
            "tool:search".into(),
            "tool:email".into(),
            "tool:calendar".into(),
        ],
        10,
        3600,
    );
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    (agent, vc)
}

/// Builds a delegation chain of the given depth. Every hop reuses the same
/// scope (max_depth held constant), which is always a valid attenuation
/// since `is_subset_of` permits equal bounds.
fn chain_of_depth(vc: &CapabilityCredential, agent: &AgentIdentity, depth: u32) -> DelegationToken {
    let scope = Scope::with_budget_and_depth(
        vec!["tool:search".into(), "tool:email".into()],
        Some(500),
        10,
    );
    let mut token = DelegationToken::mint(vc, scope.clone(), 3600, agent).unwrap();
    for _ in 0..depth {
        let sub_agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        token = token.attenuate(scope.clone(), 3600, &sub_agent).unwrap();
    }
    token
}

fn bench_mint(c: &mut Criterion) {
    let (agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 3);

    c.bench_function("delegation_mint", |b| {
        b.iter(|| DelegationToken::mint(&vc, scope.clone(), 300, &agent).unwrap())
    });
}

fn bench_attenuate(c: &mut Criterion) {
    let (agent, vc) = setup();
    let root_scope = Scope::with_budget_and_depth(
        vec![
            "tool:search".into(),
            "tool:email".into(),
            "tool:calendar".into(),
        ],
        Some(500),
        5,
    );
    let token = DelegationToken::mint(&vc, root_scope, 3600, &agent).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 5);
    let sub_agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    c.bench_function("delegation_attenuate", |b| {
        b.iter(|| token.attenuate(narrow.clone(), 60, &sub_agent).unwrap())
    });
}

fn bench_verify_by_depth(c: &mut Criterion) {
    let (agent, vc) = setup();
    let action = Action::new("tool:search", "query=benchmark");

    let mut group = c.benchmark_group("delegation_verify_by_depth");
    for depth in CHAIN_DEPTHS {
        let token = chain_of_depth(&vc, &agent, depth);
        group.bench_with_input(BenchmarkId::from_parameter(depth), &token, |b, token| {
            b.iter(|| token.verify(black_box(&action)).unwrap())
        });
    }
    group.finish();
}

fn bench_cbor_round_trip_by_depth(c: &mut Criterion) {
    let (agent, vc) = setup();

    let mut group = c.benchmark_group("delegation_cbor_by_depth");
    for depth in CHAIN_DEPTHS {
        let token = chain_of_depth(&vc, &agent, depth);
        let bytes = token.to_cbor().unwrap();

        group.bench_with_input(BenchmarkId::new("to_cbor", depth), &token, |b, token| {
            b.iter(|| token.to_cbor().unwrap())
        });
        group.bench_with_input(BenchmarkId::new("from_cbor", depth), &bytes, |b, bytes| {
            b.iter(|| DelegationToken::from_cbor(black_box(bytes)).unwrap())
        });
    }
    group.finish();
}

/// The full offline authorization decision a relying party makes per tool call:
/// `verify_rooted` - the delegation chain rooted in an anchor-issued credential,
/// with monotonic-narrowing enforcement, at increasing chain depths. This is the
/// hot-path latency the "no runtime callback" property (R3) trades for; there is
/// no network in it.
fn bench_verify_rooted_by_depth(c: &mut Criterion) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(
        vec![
            "tool:search".into(),
            "tool:email".into(),
            "tool:calendar".into(),
        ],
        10,
        3600,
    );
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let action = Action::new("tool:search", "query=benchmark");

    let mut group = c.benchmark_group("delegation_verify_rooted_by_depth");
    for depth in CHAIN_DEPTHS {
        let token = chain_of_depth(&vc, &agent, depth);
        group.bench_with_input(BenchmarkId::from_parameter(depth), &token, |b, token| {
            b.iter(|| {
                token
                    .verify_rooted(black_box(&action), black_box(&vc), black_box(&anchor))
                    .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_mint,
    bench_attenuate,
    bench_verify_by_depth,
    bench_verify_rooted_by_depth,
    bench_cbor_round_trip_by_depth,
);
criterion_main!(benches);
