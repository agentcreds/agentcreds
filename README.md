# AgentCreds

**Verifiable, attenuable delegation for AI agents - org-rooted and verified offline.**

AgentCreds gives autonomous agents *verifiable, scoped, attenuable, and revocable*
authority. An organization's trust anchor issues a capability credential to an
agent; the agent mints a short-lived runtime token it presents on every tool
call; it can delegate a *narrower* slice of that authority to sub-agents; and any
relying party - even in another organization - can verify the whole chain offline
in well under a millisecond.

> Status: **v0.1.0, pre-1.0.** APIs may change between minor versions, but not all
> surfaces float equally: the wire-level contracts are pinned by versioned
> conformance vectors. See [STABILITY.md](STABILITY.md) for exactly what is pinned,
> what floats, and what a change to each surface costs. Licensed under Apache-2.0.

## How it works

```
TrustAnchor --issues--> CapabilityCredential (the anchor of authority)
                              |
                       mint   v
                        DelegationToken  -- a real Biscuit; Datalog scope
                              |              (tools, budget, depth, TTL)
                    attenuate v              scope can only NARROW
                        DelegationToken'  -- signed by the sub-agent
                              |
                       verify v  (< 1 ms, offline, on every tool call)
                          allow / deny  + proof-of-possession of the leaf key
```

The credential is the **anchor**; the Biscuit token is the **bearer**. Widening
scope is structurally impossible - it's a property of the token, not a policy
check.

## Packages

| Crate / package | Language | What it is |
|---|---|---|
| [`agentcreds-core`](agentcreds-core/) | Rust | The offline, deterministic cryptographic core - DIDs, credentials, the Biscuit delegation engine, proof-of-possession, SD-JWT/BBS+ selective disclosure, SPIFFE, WIMSE federation, revocation primitives, and the audit compositor. No network. |
| [`agentcreds-resolvers`](agentcreds-resolvers/) | Rust | Networked DID resolvers (`did:web`, DIF Universal Resolver, cheqd/indy) kept *out* of the core, so the core stays unconditionally offline. |
| [`agentcreds` (Python)](agentcreds-py/) | Python | Native (PyO3) bindings to the core. |
| [`@agentcreds/sdk`](agentcreds-node/) | Node / TypeScript | Native (napi) bindings to the core. |
| [`agentcreds-runtime`](agentcreds-runtime/) | Python | Drop-in MCP middleware that enforces AgentCreds tokens on every tool call. |
| [`@agentcreds/runtime`](agentcreds-runtime-node/) | Node / TypeScript | Runtime enforcement for agent-to-agent (A2A) task hops. |

## Install

```bash
pip install agentcreds              # Python
npm install @agentcreds/sdk         # Node / TypeScript
cargo add agentcreds-core           # Rust
```

Runs on Linux, macOS, and Windows. CI tests Linux on every push and Windows weekly; macOS wheels are built and smoke-tested on every release. Rust MSRV 1.88; Python >= 3.8; Node >= 16.
IETF SD-JWT selective disclosure sits behind the core's `sd-jwt` feature, which the
Python and Node bindings enable unconditionally - so it is available out of the box
unless you depend on `agentcreds-core` directly. BBS+ unlinkable disclosure is behind
`bbs` (heavier pairing-crypto build), is enabled by no binding, and is not called by
anything here: a working primitive to build on rather than a feature to switch on.

## Quickstart

```python
import agentcreds as ac

# 1. An org's root of trust issues a capability credential to an agent.
anchor = ac.TrustAnchor.generate()
agent  = ac.AgentIdentity.create_did_key()
claims = ac.CapabilityClaims(tools=["tool:search", "tool:email"],
                             max_delegation_depth=2, valid_for_secs=3600)
vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)

# 2. The agent mints a short-lived runtime token (the bearer it presents).
scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=1)
token = ac.DelegationToken.mint(vc, scope, 300, agent)

# 3. Verify before every tool call - chain authenticity + scope, offline.
token.verify(ac.Action("tool:search", "q=hello"))                     # ok
token.verify_rooted(ac.Action("tool:search", "q=hello"), vc, anchor)  # anchor-rooted

# 4. Delegate a NARROWER slice to a sub-agent (widening is impossible).
sub = ac.AgentIdentity.create_did_key()
child = token.attenuate(ac.Scope(tools=["tool:search"], max_depth=0), 60, sub)
```

Each package ships a `QUICKSTART.md` and runnable `examples/`. Full API docs for
the Rust core are on [docs.rs/agentcreds-core](https://docs.rs/agentcreds-core).

## Capabilities

- **Identity** - `did:key` and `did:web`, Ed25519 and P-256 keys, organizational trust anchors.
- **Credentials** - W3C VC 1.1 capability credentials, issued and verified offline.
- **Delegation** - real Biscuit tokens with Datalog scope; cryptographically monotone attenuation; sub-millisecond per-call verification.
- **Proof of possession** - defeats token theft and delegation prefix-stripping.
- **A2A identity headers** - attach signed, audience-bound capability to agent-to-agent task hops; verified offline.
- **Selective disclosure** - prove a capability without revealing the rest. **SD-JWT** is integrated end to end (a credential format, issued and verified through the bindings). **BBS+** adds unlinkability but is a Rust-only core primitive: implemented and tested, not wired into delegation, revocation or the bindings.
- **SPIFFE / WIMSE** - bridge SPIRE-issued JWT-SVIDs to credentials, and federate peer trust domains by exchanging JWKS trust bundles.
- **Revocation** - signed OAuth Token Status List revocation lists, verified against the issuer's anchor on every fetch, with a caching client and a <=30s propagation signal.
- **Audit compositor** - a privacy-preserving joint chain-of-custody across orgs, built from signed commitments (no raw logs shared).
- **MCP middleware** - enforce all of the above inside any MCP server.

## Repository layout

```
agentcreds-core/          Rust core (offline)         - src/, examples, tests, benches
agentcreds-resolvers/     Networked DID resolvers     - did:web / cheqd / indy / universal
agentcreds-py/            Python bindings (agentcreds)
agentcreds-node/          Node bindings (@agentcreds/sdk)
agentcreds-runtime/       Python MCP middleware
agentcreds-runtime-node/  Node A2A runtime (@agentcreds/runtime)
conformance/              Shared cross-language golden vectors
```

## Build & test

```bash
# Rust core (and the BBS+ / SD-JWT features)
cd agentcreds-core && cargo test
cargo test --features bbs
cargo test --features sd-jwt

# Python bindings (build a wheel, then the smoke test)
cd agentcreds-py && maturin build --out dist && python examples/quickstart.py

# Node bindings (build the native addon, then the smoke test)
cd agentcreds-node && npm install && npm run build:debug && node examples/quickstart.js
```

CI runs on every push - Linux by default, with the fuller matrix weekly, or
Linux-only where a repo sets the `CI_LINUX_ONLY` variable - see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Contributor setup, the
bindings rebuild loop, and code conventions are in
[CONTRIBUTING.md](CONTRIBUTING.md); release notes in [CHANGELOG.md](CHANGELOG.md).

## Security

- `#![forbid(unsafe_code)]` in the core; private keys zeroized on drop.
- The core's verify path makes **no network calls** - safe to run on every tool
  invocation. Networked DID resolution is isolated in `agentcreds-resolvers`.
- Authority is **anchor-rooted** (`verify_rooted`) - it cannot be self-asserted
  from an attacker-controlled DID.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are
accepted under the [Developer Certificate of Origin](DCO) - sign off your commits
with `git commit -s`.
