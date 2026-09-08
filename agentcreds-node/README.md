# @agentcreds/sdk (Node.js / TypeScript)

Node.js bindings for **AgentCreds** - verifiable, attenuable delegation for autonomous AI agents, verified offline.

> **Scope.** This SDK is at parity with the Python core binding - identities,
> credentials, tokens, presentations, revocation, key history, ADRs including
> accountability and R10 verdicts. The **runtime enforcement** layer is different:
> `@agentcreds/runtime` is **A2A-only by design** and is
> not an MCP policy enforcement point. R10 execution-time gates, step-up approval and
> the MCP enforcer are Python-only. A Node *agent* can talk to a Python PEP over the
> wire; a Node service cannot host one.

These bindings wrap the `agentcreds-core` Rust engine via [napi-rs](https://napi.rs).

## A note on async

Every operation in this SDK is **synchronous** - there is no `Promise`/
`async`/`await` anywhere in this API. The underlying Rust operations (DID
generation, credential issuance/verification, token minting/attenuation/
verification, revocation checks) all complete in well under a millisecond,
so wrapping them in promises would add overhead without benefit. This is a
deliberate deviation from async-styled quickstarts you may see elsewhere in
the AgentCreds docs.

## Installation

```bash
npm install @agentcreds/sdk
```

(or, building from source: `npm run build`, which invokes `napi build
--platform --release`)

## Quick start

```typescript
import * as ac from "@agentcreds/sdk";

// 1. Org trust anchor (in production: keys live in an HSM)
const anchor = ac.TrustAnchor.generate();

// 2. Agent enrolled at deploy time
const agent = ac.AgentIdentity.createDidKey();

// 3. Issue a capability credential
const claims = new ac.CapabilityClaims({
  tools: ["tool:search", "tool:email"],
  maxDelegationDepth: 3,
  validForSecs: 3600, // valid for 1 hour
});
const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims);

// 4. Mint a short-lived runtime token (valid 5 minutes)
const scope = new ac.Scope({ tools: ["tool:search"], budgetUsd: 100, maxDepth: 2 });
const token = ac.DelegationToken.mint(vc, scope, 300, agent);

// 5. Verify at every tool call boundary (<1ms)
const action = new ac.Action("tool:search", "q=agentcreds");
token.verify(action);

// 6. Delegate to a sub-agent (scope can only narrow)
const subAgent = ac.AgentIdentity.createDidKey();
const narrow = new ac.Scope({ tools: ["tool:search"], budgetUsd: 10, maxDepth: 1 });
const childToken = token.attenuate(narrow, 60, subAgent);
```

## Cross-org verification

```typescript
import * as ac from "@agentcreds/sdk";

// Org B registers Org A's trust anchor (resolved from a TRAIL registry in production)
const registry = new ac.TrustRegistry();
registry.register(new ac.TrustEntry(
  orgAAnchor.did,
  "Organization A",
  orgAAnchor.publicKey,
  "verified",
));

// Verify Org A's credential WITHOUT calling back to Org A
const entry = registry.verifyCredential(vcFromOrgA);
console.log(`Verified by ${entry.orgName} (${entry.trustLevel})`);
```

## Revocation

```typescript
import * as ac from "@agentcreds/sdk";

// Create an OAuth Token Status List (131,072 entries by default)
const revocationList = new ac.RevocationList("https://registry.example.com/status/1", anchor);

// Revoke credential at index 42 (propagates in <30s in production)
revocationList.revoke(42, anchor);

// Check revocation status (<0.1ms, no network call)
console.assert(revocationList.isRevoked(42));
```

## Error handling

Every error thrown by this SDK is a JS `Error` whose `message` is prefixed
with an error kind, mirroring the exception hierarchy of the Python
bindings (`agentcreds.AgentCredsError` and its subclasses). Branch on the
prefix with `error.message.startsWith(...)`:

```typescript
import * as ac from "@agentcreds/sdk";

try {
  token.verify(new ac.Action("tool:delete-everything", ""));
} catch (e) {
  const message = e instanceof Error ? e.message : String(e);
  if (message.startsWith("ActionDeniedError")) {
    console.log(`denied: ${message}`);
  } else if (message.startsWith("TokenExpiredError")) {
    console.log(`expired: ${message}`);
  } else {
    console.log(`other agentcreds error: ${message}`);
  }
}
```

| Message prefix | Raised when |
|---|---|
| `DidError` | DID resolution, signature, or key-material problems |
| `CredentialError` | Malformed claims, issuer mismatch, invalid proof |
| `CredentialExpiredError` | A credential's `expirationDate` has passed |
| `CredentialRevokedError` | A credential's index is set in a revocation list |
| `DelegationError` | Token chain integrity / depth-limit problems |
| `ScopeWideningError` | An attenuation attempt would widen scope |
| `TokenExpiredError` | A delegation token (or one of its blocks) has expired |
| `ActionDeniedError` | The requested tool is not in the leaf block's scope |
| `RevocationError` | Revocation list index out of bounds / bad signature |
| `SerializationError` | JSON / CBOR / base64 (de)serialization failure |
| `ValidationError` | A field value is missing, out of bounds, or of the wrong sign (e.g. a negative index) |

Arguments rejected directly by the binding layer (e.g. a negative
`validForSecs`) throw with `error.code === "InvalidArg"`; errors propagated
from `agentcreds-core` throw with `error.code === "GenericFailure"`. In
both cases the `message` prefix table above applies.

## Type declarations

A hand-written `index.d.ts` ships with this package for editor/IDE
autocomplete and TypeScript type checking. Running `napi build` regenerates
this file directly from the Rust `#[napi]` annotations in `src/`.

## Building

```bash
npm run build              # napi build --platform --release
cargo test --manifest-path ../agentcreds-core/Cargo.toml
```

## License

Apache-2.0
