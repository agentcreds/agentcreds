# agentcreds (Python)

Python bindings for **AgentCreds** - verifiable, attenuable delegation for autonomous AI agents, verified offline.

These bindings wrap the `agentcreds-core` Rust engine via [PyO3](https://pyo3.rs)/[maturin](https://www.maturin.rs/).

## A note on async

Every operation in this SDK is **synchronous** - there is no `async`/`await`
anywhere in this API. The underlying Rust operations (DID generation,
credential issuance/verification, token minting/attenuation/verification,
revocation checks) all complete in well under a millisecond, so wrapping them
in coroutines would add overhead without benefit. This is a deliberate
deviation from async-styled quickstarts you may see elsewhere in the
AgentCreds docs.

## Installation

```bash
pip install agentcreds
```

(or, building from source: `maturin build --release` / `maturin develop`)

## Quick start

```python
import agentcreds as ac

# 1. Org trust anchor (in production: keys live in an HSM)
anchor = ac.TrustAnchor.generate()

# 2. Agent enrolled at deploy time
agent = ac.AgentIdentity.create_did_key()

# 3. Issue a capability credential
claims = ac.CapabilityClaims(
    tools=["tool:search", "tool:email"],
    max_delegation_depth=3,
    valid_for_secs=3600,  # valid for 1 hour
)
vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)

# 4. Mint a short-lived runtime token (valid 5 minutes)
scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=2)
token = ac.DelegationToken.mint(vc, scope, 300, agent)

# 5. Verify at every tool call boundary (<1ms)
action = ac.Action("tool:search", "q=agentcreds")
token.verify(action)

# 6. Delegate to a sub-agent (scope can only narrow)
sub_agent = ac.AgentIdentity.create_did_key()
narrow = ac.Scope(tools=["tool:search"], budget_usd=10, max_depth=1)
child_token = token.attenuate(narrow, 60, sub_agent)
```

## Cross-org verification

```python
import agentcreds as ac

# Org B registers Org A's trust anchor (resolved from a TRAIL registry in production)
registry = ac.TrustRegistry()
registry.register(ac.TrustEntry(
    org_a_anchor.did,
    "Organization A",
    org_a_anchor.public_key,
    "verified",
))

# Verify Org A's credential WITHOUT calling back to Org A
entry = registry.verify_credential(vc_from_org_a)
print(f"Verified by {entry.org_name} ({entry.trust_level})")
```

## Revocation

```python
import agentcreds as ac

# Create an OAuth Token Status List (131,072 entries by default)
revocation_list = ac.RevocationList("https://registry.example.com/status/1", anchor)

# Revoke credential at index 42 (propagates in <30s in production)
revocation_list.revoke(42, anchor)

# Check revocation status (<0.1ms, no network call)
assert revocation_list.is_revoked(42)
```

## Error handling

All errors raised by this SDK derive from `agentcreds.AgentCredsError`:

```python
import agentcreds as ac

try:
    token.verify(ac.Action("tool:delete-everything", ""))
except ac.ActionDeniedError as e:
    print(f"denied: {e}")
except ac.TokenExpiredError as e:
    print(f"expired: {e}")
except ac.AgentCredsError as e:
    print(f"other agentcreds error: {e}")
```

| Exception | Raised when |
|---|---|
| `DidError` | DID resolution, signature, or key-material problems |
| `CredentialError` | Malformed claims, issuer mismatch, invalid proof |
| `CredentialExpiredError` | A credential's `expiration_date` has passed |
| `CredentialRevokedError` | A credential's index is set in a revocation list |
| `DelegationError` | Token chain integrity / depth-limit problems |
| `ScopeWideningError` | An attenuation attempt would widen scope |
| `TokenExpiredError` | A delegation token (or one of its blocks) has expired |
| `ActionDeniedError` | The requested tool is not in the leaf block's scope |
| `RevocationError` | Revocation list index out of bounds / bad signature |
| `SerializationError` | JSON / CBOR / base64 (de)serialization failure |
| `ValidationError` | A field value is missing or out of bounds |

## Type stubs

A `agentcreds.pyi` stub ships with this package for editor/IDE autocomplete
and static type checking (mypy/pyright).

## Building

```bash
maturin build --release
cargo test --manifest-path ../agentcreds-core/Cargo.toml
```

## License

Apache-2.0
