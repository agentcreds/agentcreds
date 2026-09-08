# Issue your first agent in 5 minutes

```bash
pip install agentcreds
```

```python
import agentcreds as ac

# This is your sandbox key - generated locally, instantly.
# No signup, no dashboard, no network call.
anchor = ac.TrustAnchor.generate()

# 1. Create an agent identity
agent = ac.AgentIdentity.create_did_key()

# 2. Issue it a credential: what it can do, and for how long
claims = ac.CapabilityClaims(
    tools=["tool:search", "tool:email"],
    max_delegation_depth=3,
    valid_for_secs=3600,  # 1 hour
)
vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)

# 3. Mint a short-lived runtime token the agent carries
scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=2)
token = ac.DelegationToken.mint(vc, scope, 300, agent)  # valid 5 minutes

# 4. Verify before every tool call
token.verify(ac.Action("tool:search", "q=agentcreds"))

print("Agent issued:", agent.did)
print("tool:search - allowed")
```

Run it:

```bash
python quickstart.py
```

```
Agent issued: did:key:z6Mk...
tool:search - allowed
```

Done. You've issued an agent identity, a signed credential, a runtime token, and verified an action against it - all offline, no API key to manage.

## One line each

- `TrustAnchor.generate()` - your sandbox key. Same call you'd use in production, just keep the result safe.
- `AgentIdentity.create_did_key()` - a new agent identity.
- `CapabilityCredential.issue(...)` - signs a credential stating what the agent may do.
- `DelegationToken.mint(...)` - a short-lived token the agent presents at runtime.
- `token.verify(action)` - raises if the action isn't permitted.

## Delegate to a sub-agent

Scope can only narrow on delegation - never widen, enforced cryptographically:

```python
sub_agent = ac.AgentIdentity.create_did_key()
narrow = ac.Scope(tools=["tool:search"], budget_usd=10, max_depth=1)
child_token = token.attenuate(narrow, 60, sub_agent)
```

## Going further

[README.md](./README.md) - cross-org verification, revocation, error handling, type stubs.
