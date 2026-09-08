# Stability

AgentCreds is **v0.1.0, pre-1.0**, and the README's blanket note is honest: APIs may
change between minor versions. But "pre-1.0" does not mean everything floats equally.
This document says exactly what is pinned, what floats, and what a change to each
surface costs. It exists so that an integrator can tell the difference between a
surface they can build a product on and a surface they should wrap.

There are three tiers.

## Tier 1 - Wire and protocol surface (vectors-pinned)

These are the byte-level contracts between independent implementations. Each is pinned
by a versioned conformance-vector suite in [`conformance/`](conformance/); the vectors
are the contract, and CI on both runtimes consumes them, so this tier cannot drift
silently.

| surface | pinned by | format |
| --- | --- | --- |
| Credential / delegation-token / presentation wire (CBOR envelopes, verification decisions, chain shape) | `vectors.json` | 3 |
| Canonicalization (`agentcreds-jcs-v1`) - byte-exact canonical JSON | `jcs_vectors.json` | 1 |
| A2A layer - header names, the `AgentCreds-A2A-Principal/1.` scheme, bound-args encoding, the shared deny-code registry, octets (`agentcreds-octets-v1`) parse + semantic-equality behaviour | `a2a_vectors.json` | 1 |
| Revocation artifact - OAuth Token Status List (`statuslist+jwt`) | verified in-suite | per spec |

**Change policy for this tier:** a breaking change bumps the relevant vector-suite
`format` integer, regenerates the suite, and gets a CHANGELOG entry with a migration
note. Consumers refuse an unrecognised format rather than skipping cases, so a bump is
loud by construction. We treat changes here as protocol changes, not refactors - they
are rare and deliberate.

Two deliberate non-promises inside this tier, both documented in the vector suites:

- **Octets bind output is holder-chosen.** Python ASCII-escapes, Node does not; both
  are conformant. The contract is that every verifier parses any holder's bytes and
  reaches the same semantic verdict. Do not depend on the bytes a particular holder
  emits.
- **Delegation tokens are short-lived by design** (autonomy-ladder TTL caps, 1 hour at
  level 0 down to 5 minutes at level 3). No stability promise can make a token
  outlive its ladder cap.

## Tier 2 - Language APIs (pre-1.0, may change between minors)

The Rust (`agentcreds-core`), Python (`agentcreds` / `agentcreds-runtime`), and Node
(`@agentcreds/sdk` / `@agentcreds/runtime`) APIs follow pre-1.0 semver: **minor
versions may break; patch versions do not.** Breaking API changes get a CHANGELOG
entry naming the old and new form. We do not promise deprecation cycles before 1.0.

Within this tier, stability is not uniform:

- **Most stable:** `agentcreds_core::interop` - the wrapper contract for standard
  formats - and the verification entry points (`verify_rooted`, presentation
  verification, and their `_at` seams). We expect changes here to be rare and will
  call them out prominently.
- **Standard churn:** constructors, builders, error types, module layout.
- **Feature-gated surfaces** (`bbs`, SD-JWT opt-in, `resolver-web`): these are the
  youngest code and the most likely to change shape. Gate your own use of them
  accordingly.
- The Node runtime is **A2A-only by design** (the enforcement layer is Python-only);
  this is an architectural decision, not a gap awaiting parity, and code written
  against it should not expect enforcer APIs to appear.

## Tier 3 - Undeclared internals (no promise)

Anything not exported from a crate/package root, any `_`-prefixed symbol, test
utilities, generators, and the repository layout itself. These change without notice.

Note the distinction: a *wire constant* can be Tier 1 while the *symbol* that holds it
is Tier 3. The principal-header scheme string is a pinned wire contract; the private
constant it lives in on the Python side is not an API.

## What 1.0 will mean

1.0 lifts Tier 2 to real semver (breaking changes only at majors, with deprecation
cycles). It is gated on the completion of an external cryptographic review and on the
API feedback window that precedes it - not on a date.
