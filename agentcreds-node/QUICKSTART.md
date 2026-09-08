# Issue your first agent in 5 minutes

```bash
npm install @agentcreds/sdk
```

```typescript
import * as ac from "@agentcreds/sdk";

// This is your sandbox key - generated locally, instantly.
// No signup, no dashboard, no network call.
const anchor = ac.TrustAnchor.generate();

// 1. Create an agent identity
const agent = ac.AgentIdentity.createDidKey();

// 2. Issue it a credential: what it can do, and for how long
const claims = new ac.CapabilityClaims({
  tools: ["tool:search", "tool:email"],
  maxDelegationDepth: 3,
  validForSecs: 3600, // 1 hour
});
const vc = ac.CapabilityCredential.issue(anchor, agent.did, claims);

// 3. Mint a short-lived runtime token the agent carries
const scope = new ac.Scope({ tools: ["tool:search"], budgetUsd: 100, maxDepth: 2 });
const token = ac.DelegationToken.mint(vc, scope, 300, agent); // valid 5 minutes

// 4. Verify before every tool call
token.verify(new ac.Action("tool:search", "q=agentcreds"));

console.log("Agent issued:", agent.did);
console.log("tool:search - allowed");
```

Run it:

```bash
npx tsx quickstart.ts
```

```
Agent issued: did:key:z6Mk...
tool:search - allowed
```

Done. You've issued an agent identity, a signed credential, a runtime token, and verified an action against it - all offline, no API key to manage.

## One line each

- `TrustAnchor.generate()` - your sandbox key. Same call you'd use in production, just keep the result safe.
- `AgentIdentity.createDidKey()` - a new agent identity.
- `CapabilityCredential.issue(...)` - signs a credential stating what the agent may do.
- `DelegationToken.mint(...)` - a short-lived token the agent presents at runtime.
- `token.verify(action)` - throws if the action isn't permitted.

## Delegate to a sub-agent

Scope can only narrow on delegation - never widen, enforced cryptographically:

```typescript
const subAgent = ac.AgentIdentity.createDidKey();
const narrow = new ac.Scope({ tools: ["tool:search"], budgetUsd: 10, maxDepth: 1 });
const childToken = token.attenuate(narrow, 60, subAgent);
```

## Going further

[README.md](./README.md) - cross-org verification, revocation, error handling, type declarations.
