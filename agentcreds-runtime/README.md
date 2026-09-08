# agentcreds-runtime

Runtime **agent-identity enforcement** built on
[AgentCreds](https://github.com/agentcreds/agentcreds). Every tool call is
authenticated, authorized, and audited - the caller must present a delegation
token that is cryptographically authentic, rooted in a credential from a trust
anchor you accept, scoped to the tool (and resource) being called, and
accompanied by a fresh proof that the caller holds the leaf agent's key.

Two transports share one policy core:

- **MCP** (interactive, sessionful) - `IdentityEnforcer` + a FastMCP adapter.
- **A2A** (agent-to-agent, no MCP server) - `A2AVerifier` + a self-contained header
  envelope.

Both enforce the same guarantees: anchor-rooted authority, proof-of-possession,
**revocation**, **on-behalf-of principal binding**, **argument binding**,
**multi-issuer trust**, and tamper-evident audit / ADR.

> Pure-Python package (the core `agentcreds` SDK is a compiled PyO3 extension it
> imports). Install name `agentcreds-runtime`; import path `agentcreds_runtime`.
>
> **This is the only MCP policy enforcement point.** `@agentcreds/runtime` (Node) is
> A2A-only by design - R10 gates, step-up approval and the MCP enforcer are not ported,
> because a second enforcement implementation would have to be kept correct twice and
> the conformance suite covers this one. A Node agent talks to this PEP over the wire.

## Install

```bash
pip install agentcreds-runtime            # both transports
pip install "agentcreds-runtime[mcp]"     # + the FastMCP adapter (official MCP SDK)
```

## MCP: per-session enforcement

```python
from agentcreds_runtime import IdentityEnforcer, PolicyConfig

enforcer = IdentityEnforcer(anchor, config=PolicyConfig(max_age_secs=60, audit=my_audit_sink))

challenge_cbor = enforcer.issue_challenge(session_id)   # send to the client
# ... per tool call, with the presentation bytes the client returned:
decision = enforcer.authorize(session_id, tool, arguments, presentation_cbor)
if decision.denied:
    handle(decision.code)            # see "Denial codes" below
chain = enforcer.enforce(session_id, tool, arguments, presentation_cbor)  # or: raises
```

Holder side: `present(token, credential, challenge_cbor, leaf_agent, action=None)`.

### FastMCP adapter

```python
from agentcreds_runtime import IdentityEnforcer
from agentcreds_runtime.fastmcp import guard_tool

enforcer = IdentityEnforcer(anchor)

@mcp.tool()
@guard_tool(enforcer, "tool:search")
async def search(q: str, ctx: Context, agentcreds_presentation: str, agentcreds_chain=None):
    return do_search(q)   # reached only if enforcement passed
```

## A2A: no MCP server

When agent A hands a task directly to agent B, A attaches a self-contained
identity header and B verifies it **offline**. A2A is one-shot, so the *sender*
mints the proof-of-possession challenge with `audience` set to the receiver.

```python
from agentcreds_runtime import A2AVerifier, make_a2a_header

# Sender (caller):
header = make_a2a_header(token, vc, agent, audience="a2a://orders.example/agent")

# Receiver:
verifier = A2AVerifier(audience="a2a://orders.example/agent", anchor=anchor)
decision = verifier.authorize(header, "tool:search", {"q": "hi"})
```

`verify` runs audience-match + anchor-rooted + proof-of-possession; a header minted
for another receiver, or outside `max_age_secs`, is rejected.

### Replay protection

A2A is callback-free, so within the freshness window a header could be re-sent
verbatim. Each header is made **single-use by default** (an in-process guard).
For more than one receiver replica, pass a shared guard so replays are caught
across replicas; to turn it off, set `enable_replay_protection=False`:

```python
from agentcreds_runtime import A2AVerifier, RedisReplayGuard

verifier = A2AVerifier(audience=me, anchor=anchor)                       # default: on (in-memory)
# verifier = A2AVerifier(..., replay_guard=RedisReplayGuard(redis))      # many replicas
# verifier = A2AVerifier(..., enable_replay_protection=False)            # off
```

> MCP has the same option (`IdentityEnforcer(..., replay_guard=...)`) but it is
> **off by default**: the per-session challenge means legitimate calls reuse
> byte-identical presentations, so single-use enforcement requires per-call
> `rotate_challenge`. A2A senders mint a fresh challenge per message, so it is
> safe to default on there.

### On-behalf-of over A2A (the wire envelope)

There is no session to establish *who the human is*, so the human's verifiable
identity travels **with the message** and is validated independently by the
receiver - restoring the confused-deputy protection. The envelope is a
header-name -> value mapping:

```python
from agentcreds_runtime import make_a2a_envelope, A2AVerifier, principal_resolver_from_oidc

# Sender: capability + the human's OIDC token.
envelope = make_a2a_envelope(token, vc, agent, audience=me, principal_token=id_token)
#   {"AgentCreds-A2A": "...", "AgentCreds-A2A-Principal": "AgentCreds-A2A-Principal/1...."}

# Receiver: validate the human via your IdP, then verify the capability.
verifier = A2AVerifier(audience=me, anchor=anchor,
                       principal_resolver=principal_resolver_from_oidc(provider))
decision = verifier.authorize_envelope(envelope, "tool:read_email", {},
                                       resource="mailbox:alice@acme.com/42")
```

The core then enforces that the capability token's bound principal equals the
*independently verified* human - so a valid token for Bob cannot drive an agent
whose authority is bound to Alice.

## Shared policy (both transports)

Every option below works identically on `IdentityEnforcer` and `A2AVerifier`. The
shared policy knobs live on a `PolicyConfig(...)` passed as `config=`; the trust
anchor and transport-specific options stay direct on the constructor.

| Feature | How |
|---|---|
| **Revocation** | `config=PolicyConfig(revocation_check=...)` (a callable; or `revocation_check_from_list(list, anchor)`). Denied -> `credential_revoked`. Fail-closed by default. |
| **Multi-issuer** | `anchor_for=` (a resolver; or `anchor_resolver_from_registry(registry)`) instead of a single `anchor`. Untrusted issuer -> `untrusted_issuer`. |
| **Argument binding** | Sender binds with `make_a2a_header(..., action=...)` / `present(..., action=...)`; receiver sets `config=PolicyConfig(require_argument_binding=True)`. Tampered args -> `possession_failed`; unbound when required -> `argument_binding_required`. |
| **On-behalf-of** | MCP: `enforcer.bind_principal(session_id, human_did)`. A2A: the principal envelope above. Mismatch -> `principal_mismatch`. |
| **Audit / ADR** | `config=PolicyConfig(audit=..., adr_sink=..., adr_stream=...)` - a structured `AuthzDecision` for every allow *and* deny, carrying the security signal, the correlation `vc_id`, and **who answers** (`accountable_party` + `accountability_source`, read from the credential). With a stream, records fold into a tamper-evident hash-chain (`sign_checkpoint` -> `AdrStream.replay`). |
| **Tracing an effect** | `Decision.record_id` is the ADR's per-call id; `guard_tool` hands it to a handler declaring `agentcreds_record_id`. Log it beside whatever the call changes. An ADR proves authority was *checked*, not that the tool ran - and `vc_id` joins on the credential, which every call shares, so this id is what makes the pairing exact. |
| **Declared canonicalization** | `config=PolicyConfig(canonicalization_profile=..., require_canonicalization_profile=...)`; holders declare theirs via the `agentcreds_canon_profile` argument. A disagreeing profile -> `canonicalization_profile_mismatch` rather than `possession_failed`, so an interop defect is distinguishable from altered arguments. Both refuse - the distinction is diagnostic, which is why the declaration may be unauthenticated. |
| **Freshness by consequence** | `config=PolicyConfig(max_age_by_autonomy={3: 5, 0: 300})` maps the credential's `autonomy_level` to a tighter `max_age_secs`. Only ever narrows: an entry longer than the global bound is clamped. |
| **No blind retry** | `@idempotent(store)` falls back to `agentcreds_record_id` when the caller supplies no key, so duplicate suppression does not depend on client cooperation. Not a substitute for reconciling an indeterminate post-dispatch outcome. |
| **Horizontal scale** | MCP: `session_store=RedisSessionStore(redis)`. A2A: `replay_guard=RedisReplayGuard(redis)`. |

## Denial codes

`Decision.code` (and the `AccessDenied.code` raised by `enforce`) is one of:
`no_active_challenge`, `malformed_presentation`, `possession_failed`,
`not_authorized`, `credential_invalid`, `credential_revoked`,
`principal_mismatch`, `argument_binding_required`, `untrusted_issuer`,
`replayed_presentation`, `approval_already_consumed`,
`canonicalization_profile_mismatch`, `access_denied`.

`approval_already_consumed` is deliberately distinct from `approval_required_denied`:
the first means the evidence verified and satisfied policy but its reliance unit was
already spent (a replay against a *valid* human approval), the second that the evidence
was unsatisfactory. The ADR records the two as separate `evaluation` / `admission`
verdicts for the same reason - collapsed into one field they are indistinguishable, and
they call for opposite responses.

## Status

The policy core, the MCP `IdentityEnforcer`, and the A2A `A2AVerifier` (including
the wire envelope and replay guard) are covered by the test suite, run against the
real `agentcreds` wheel. The FastMCP adapter is intentionally thin over the
enforcer. See [examples/](examples/) for runnable end-to-end flows.
