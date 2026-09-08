# Changelog

All notable changes to the AgentCreds SDK are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, cryptographic wire formats and APIs may change
between minor versions.

## [Unreleased]

## [node-0.1.1] - 2026-09-08

### Fixed

- **`@agentcreds/sdk` 0.1.1** - 0.1.0 on npm published the parent package without its
  per-platform binding packages, so installation succeeded and `require` threw on
  every platform. 0.1.1 ships the four platform packages
  (`@agentcreds/sdk-{linux-x64-gnu,darwin-x64,darwin-arm64,win32-x64-msvc}`) and the
  parent's `optionalDependencies` pointing at them. 0.1.0 is deprecated on npm; no
  other component is affected.

## [0.1.0] - 2026-09-07

Initial public release of the AgentCreds SDK. (Re-cut from the unpublished
2026-07-28 candidate; everything below ships together as the first release.)

### Added

- **`agentcreds-core`** - the offline, deterministic cryptographic core:
  - DIDs (`did:key`, `did:web`) over Ed25519 and P-256; organizational trust anchors.
  - W3C VC 1.1 capability credentials, issued and verified fully offline.
  - Biscuit-based delegation with Datalog scope and cryptographically monotone
    attenuation; sub-millisecond, anchor-rooted per-call verification.
  - Proof-of-possession binding (defeats token theft and prefix-stripping).
  - Selective disclosure - SD-JWT (opt-in `sd-jwt` feature) and BBS+ unlinkable
    presentations (opt-in `bbs` feature).
  - SPIFFE/WIMSE - JWT-SVID bridging and JWKS trust-bundle federation.
  - Revocation primitives - signed OAuth Token Status List lists, anchor-verified.
  - The privacy-preserving audit compositor.
- **`agentcreds-resolvers`** - networked DID resolvers (`did:web`, DIF Universal
  Resolver, cheqd/indy), kept out of the core so the core stays offline.
- **`agentcreds` (Python)** and **`@agentcreds/sdk` (Node)** - native bindings.
- **`agentcreds-runtime`** (Python MCP middleware) and **`@agentcreds/runtime`**
  (Node A2A runtime) - drop-in per-call enforcement.
- **`conformance/`** - three cross-language agreement-vector suites, verified in CI
  by every language surface:
  - `vectors.json` - authorization decisions (credentials, delegation chains,
    presentations, revocation, key rotation), judged as of `evaluated_at`.
  - `jcs_vectors.json` - byte-exact RFC 8785 canonicalization
    (`agentcreds-jcs-v1`), because two implementations that canonicalize
    differently disagree about what a token authorizes.
  - `a2a_vectors.json` - the deterministic A2A layer above the cryptography:
    header names, the principal-header scheme, bound-args encoding, the shared
    deny-code registry, and octets parse/semantic-equality verdicts.
- **Explicit verification instants** - `verify_at`, `verify_rooted_at`,
  `Presentation::verify_at`, `verify_presentation_at`, and
  `verify_anchor_signed(now)` take the instant as an argument, so expiry
  boundaries are deterministically testable and vector files can be judged as of
  their generation time.
- **Spend limits in the delegation scope** - `max_action_cost` (USD-cents) is an
  enforced per-action cap: minted as a Datalog check, it travels with the
  authority, can only tighten across hops, and makes pricing mandatory (a capped
  token denies unpriced actions). `budget_usd` is the advisory ceiling on
  delegated authority. Neither is a running balance.
- **`STABILITY.md`** - a three-tier stability statement: the wire/protocol surface
  is pinned by the versioned vector suites; language APIs float pre-1.0 with a
  documented gradient; internals carry no promise.

### Fixed

- Credential issuance with an out-of-range lifetime returns an error instead of
  panicking on timestamp overflow.

[Unreleased]: https://github.com/agentcreds/agentcreds/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentcreds/agentcreds/releases/tag/v0.1.0
