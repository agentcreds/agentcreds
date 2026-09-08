# agentcreds-core

Cryptographic core for **AgentCreds** - verifiable, attenuable delegation for autonomous AI agents, verified offline.

## What this crate provides

| Module | Responsibility |
|---|---|
| `did` | DID issuance (did:key, did:web), Ed25519/P-256 key management, TrustAnchor |
| `vc` | W3C VC 1.1 capability credential issuance and verification |
| `delegation` | Biscuit delegation tokens with Datalog scope and third-party-block attenuation, sub-ms verification |
| `revocation` | OAuth Token Status List revocation bitstring, sign/check/propagate |
| `registry` | Trust registry, cross-org VC verification without callback |

## Security properties

- **No unsafe code** (`#![forbid(unsafe_code)]`)
- **Private keys zeroized on drop** (`zeroize` crate)
- **Every delegation block is signature-verified** - each hop is a Biscuit block
  signed by the agent's Ed25519 delegation subkey, which is attested by the
  agent's primary DID key; a forged or tampered block is rejected
- **Scope widening is structurally impossible within a chain** - not a policy
  check, but Biscuit's own guarantee: attenuation only ever *adds* Datalog
  checks, so authority can only narrow, enforced at every hop
- **Anchor-rooted authority** - `verify_rooted` binds a token's root to an
  anchor-issued credential, so authority can't be self-asserted from an
  attacker-controlled DID (plain `verify` proves chain authenticity only)
- **Proof of possession** - `verify_presentation` adds a challenge/response that
  proves the presenter holds the leaf agent's key, defeating token theft and
  delegation-chain prefix-stripping (see [`pop`](src/pop.rs))
- **Sub-millisecond token verification** - safe to call on every tool invocation
- Supports Ed25519 (default) and P-256 (FIPS-required environments)

The three verification tiers, weakest to strongest:

| Call | Proves |
|---|---|
| `token.verify(action)` | chain is authentic and permits the action |
| `token.verify_rooted(action, vc, anchor)` | ...and authority traces to a trusted anchor |
| `token.verify_presentation(action, vc, anchor, proof, challenge, max_age)` | ...and the presenter holds the leaf key (theft/replay/strip-proof) |

See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for how these map onto per-tool-call
enforcement in an MCP server.

## Quick start

```rust
use agentcreds_core::prelude::*;
use agentcreds_core::did::{DidMethod, TrustAnchor};
use agentcreds_core::vc::CapabilityClaims;

// 1. Org trust anchor (in production: keys live in HSM)
let anchor = TrustAnchor::generate()?;

// 2. Agent enrolled at deploy time
let agent = AgentIdentity::create(DidMethod::Key, None)?;

// 3. Issue a capability credential
let claims = CapabilityClaims::new(
    vec!["tool:search".into(), "tool:email".into()],
    3,     // max delegation depth
    3600,  // valid for 1 hour
);
let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None)?;

// 4. Mint a short-lived runtime token (valid 5 minutes)
let scope = Scope::with_budget_and_depth(
    vec!["tool:search".into()], Some(100), 2
);
let token = DelegationToken::mint(&vc, scope, 300, &agent)?;

// 5. Verify at every tool call boundary (<1ms)
let action = Action::new("tool:search", "q=agentcreds");
token.verify(&action)?;

// 6. Delegate to a sub-agent (scope can only narrow)
let sub_agent = AgentIdentity::create(DidMethod::Key, None)?;
let narrow = Scope::with_budget_and_depth(
    vec!["tool:search".into()], Some(10), 1
);
let child_token = token.attenuate(narrow, 60, &sub_agent)?;
```

## Cross-org verification

```rust
use agentcreds_core::registry::{TrustEntry, TrustLevel, TrustRegistry, CrossOrgVerifier};

// Org B registers Org A's trust anchor (resolved from TRAIL registry in production)
let mut registry = TrustRegistry::new();
registry.register(TrustEntry::new(
    org_a_anchor.did(),
    "Organization A",
    org_a_anchor.public_key().clone(),
    TrustLevel::Verified,
));

// Verify Org A's credential WITHOUT calling back to Org A
let verifier = CrossOrgVerifier::new(&registry);
verifier.verify(&vc_from_org_a)?;
```

## Revocation

```rust
use agentcreds_core::revocation::RevocationList;

// Create an OAuth Token Status List (131,072 entries by default)
let mut list = RevocationList::new("https://registry.example.com/status/1", &anchor, None)?;

// Revoke credential at index 42 (propagates in <30s in production)
list.revoke(42, &anchor)?;

// Check revocation status (<0.1ms, no network call)
assert!(list.is_revoked(42)?);
```

## Architecture decision: Rust core + FFI bindings

This crate is the single cryptographic implementation shared across all language SDKs:

```
agentcreds-core (this crate, Rust)
    +-- @agentcreds/sdk  (TypeScript via napi-rs)
    +-- agentcreds       (Python via PyO3/maturin)
```

Cryptographic logic is written and audited exactly once. A security fix in the Rust core propagates to all language SDKs on the next release.

## Building

```bash
cargo build --release
cargo test
cargo clippy --all-targets   # deny-level lints fail the build; pedantic/nursery are advisory
```

## Running the integration tests

```bash
cargo test --test integration -- --nocapture
```

## Fuzz testing

Property-based fuzz tests for malformed and adversarial input live in
`tests/fuzz_malformed_input.rs`. They run on stable Rust via `proptest`
(no `cargo-fuzz`/nightly toolchain required) and cover every
deserialisation and verification entry point that accepts
attacker-controlled bytes - JSON, CBOR, TOML, base64 proofs, multibase
keys, and OAuth Token Status List bitstrings - asserting the crate returns `Err`
rather than panicking, including on byte-mutated copies of valid payloads.

```bash
cargo test --features proptest --test fuzz_malformed_input
```

## Benchmarks

Criterion benchmark suites live in `benches/`, one per module:

| Suite | Covers |
|---|---|
| `did_benchmarks` | Identity creation (Ed25519/P-256), signing, verification, multibase encoding |
| `vc_benchmarks` | Credential issuance, verification, JSON-LD serialization |
| `delegation_benchmarks` | Token mint, attenuation, action verification and CBOR (de)serialization at chain depths 0-10 |
| `revocation_benchmarks` | OAuth Token Status List creation, revoke/unrevoke, revocation checks, signature verification |
| `registry_benchmarks` | Trust registry registration, cached resolution, cross-org credential verification |

```bash
cargo bench               # run all suites, full statistical analysis
cargo bench --bench did_benchmarks   # run a single suite
cargo bench -- --quick    # faster, lower-precision run
```

HTML reports (with `html_reports` feature, enabled by default for dev) are written to `target/criterion/`.

## Performance

| Operation | Latency (p50) |
|---|---|
| DID generation (Ed25519) | ~50us |
| VC issuance | ~200us |
| VC verification | ~180us |
| Token mint (depth 0) | ~60us |
| Token verify (depth 0) | ~0.049ms |
| Token verify (depth 5) | <1ms |
| Revocation check | <0.1ms |

Measurements on Apple M2. Values consistent with AIP paper benchmarks (arXiv March 2026).

## License

Apache-2.0
