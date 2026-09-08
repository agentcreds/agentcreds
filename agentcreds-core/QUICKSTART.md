# Issue your first agent in 5 minutes

```bash
cargo new quickstart && cd quickstart
cargo add agentcreds-core
```

```rust
use agentcreds_core::prelude::*;

fn main() -> agentcreds_core::Result<()> {
    // This is your sandbox key - generated locally, instantly.
    // No signup, no dashboard, no network call.
    let anchor = TrustAnchor::generate()?;

    // 1. Create an agent identity
    let agent = AgentIdentity::create(DidMethod::Key, None)?;

    // 2. Issue it a credential: what it can do, and for how long
    let claims = CapabilityClaims::new(
        vec!["tool:search".into(), "tool:email".into()],
        3,     // max delegation depth
        3600,  // 1 hour
    );
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None)?;

    // 3. Mint a short-lived runtime token the agent carries
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent)?; // valid 5 minutes

    // 4. Verify before every tool call (chain authenticity + scope)
    token.verify(&Action::new("tool:search", "q=agentcreds"))?;

    // 4b. A relying party that holds the credential uses the complete,
    // anchor-rooted check - it also proves the authority traces to the anchor.
    token.verify_rooted(&Action::new("tool:search", "q=agentcreds"), &vc, &anchor)?;

    println!("Agent issued: {}", agent.did());
    println!("tool:search - allowed");
    Ok(())
}
```

Run it:

```bash
cargo run
```

```
Agent issued: did:key:z6Mk...
tool:search - allowed
```

Done. You've issued an agent identity, a signed credential, a runtime token, and verified an action against it - all offline, no API key to manage.

## One line each

- `TrustAnchor::generate()` - your sandbox key. Same call you'd use in production, just keep the result safe.
- `AgentIdentity::create(DidMethod::Key, None)` - a new agent identity.
- `CapabilityCredential::issue(&anchor, ...)` - signs a credential stating what the agent may do.
- `DelegationToken::mint(...)` - a short-lived token the agent presents at runtime.
- `token.verify(&action)` - returns `Err` if the action isn't permitted.

## Delegate to a sub-agent

Scope can only narrow on delegation - never widen, enforced cryptographically:

```rust
let sub_agent = AgentIdentity::create(DidMethod::Key, None)?;
let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
let child_token = token.attenuate(narrow, 60, &sub_agent)?;
```

## Going further

[README.md](./README.md) - cross-org verification, revocation, benchmarks, fuzz testing.
