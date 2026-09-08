# MCP integration design - `agentcreds.mcp.middleware()`

This is the design and prerequisite-API note for the Phase 2 deliverable: drop-in
identity enforcement for an MCP server. The goal is **identity in ~3 lines** - wrap
an MCP server and every tool call is authenticated, authorized, and audited, with
zero config for the default case.

The cryptographic primitives this middleware needs already exist in
`agentcreds-core` and are exposed in the Python and Node SDKs. This document maps
the MCP request lifecycle onto those primitives so the middleware package is
"wiring", not new crypto.

## What the middleware enforces, per tool call

1. **Authenticity** - the delegation token is signed at every hop and rooted in a
   credential issued by a trusted anchor (`DelegationToken::verify_rooted`).
2. **Authorization** - the requested tool is within the token's (possibly
   attenuated) scope.
3. **Possession** - the caller currently holds the leaf agent's private key, so a
   stolen or stripped token can't be replayed (`ProofOfPossession`).
4. **Audit** - the delegation chain is logged against the action
   (`DelegationToken::chain()`), with no key material.

Items 1-3 are exactly `DelegationToken::verify_presentation(...)`, bundled with the
backing credential as a `Presentation`.

## Request lifecycle

```
 Agent (MCP client)                         MCP server + AgentCreds middleware
 ------------------                         -----------------------------------
 1. connect ------------------------------->  issue PopChallenge (per session
                                               or per call), return it
 2. for each tools/call:
      build Action from (tool, args)
      proof = token.prove_possession(
                  challenge, leaf_agent)
      presentation = Presentation.create(
                  token, vc, challenge, leaf_agent)
      attach presentation.to_cbor() in
      the call's _meta / auth field  ------->  presentation = Presentation.from_cbor(meta)
                                               action = Action(tool_name, args_digest)
                                               presentation.verify(
                                                   action, anchor, challenge, max_age)
                                               +- ok    -> invoke the real tool
                                               +- error -> return MCP error (-32001)
                                               log presentation token chain + action
```

Notes:
- **Challenge granularity.** A fresh `PopChallenge` per tool call gives per-call
  replay protection; a per-session challenge is cheaper and still defeats theft
  across sessions. The `max_age_secs` window bounds replay either way. Start with
  a per-session challenge and a short window (e.g. 60s) and tighten if needed.
- **Where the anchor comes from.** For a single-org deployment the server holds its
  own `TrustAnchor` public DID statically. For cross-org calls (Phase 3) the
  server resolves the issuer's anchor from a `TrustRegistry`
  (`CrossOrgVerifier`) instead - `verify_rooted` already takes the anchor, so the
  middleware just swaps where the anchor is sourced.
- **Credential caching.** `Presentation` carries the full VC so verification needs
  no side fetch. In a latency-sensitive server, exchange the VC once at session
  setup, cache it keyed by the agent DID, and have the client send only
  `token + proof` per call (reconstruct the `Presentation` server-side from the
  cached VC). Both paths use the same `verify_presentation`.

## Python sketch (the shape the middleware package will take)

```python
import agentcreds as ac

class AgentCredsMiddleware:
    def __init__(self, anchor: ac.TrustAnchor, *, max_age_secs: int = 60):
        self._anchor = anchor
        self._max_age = max_age_secs
        self._challenges: dict[str, ac.PopChallenge] = {}   # session_id -> challenge

    def on_connect(self, session_id: str) -> bytes:
        challenge = ac.PopChallenge(audience=f"mcp://{session_id}")
        self._challenges[session_id] = challenge
        return challenge.to_cbor()                          # send to the client

    def on_tool_call(self, session_id: str, tool: str, args: str, meta: bytes):
        challenge = self._challenges[session_id]
        presentation = ac.Presentation.from_cbor(meta)
        action = ac.Action(tool, args)
        try:
            presentation.verify(action, self._anchor, challenge, self._max_age)
        except ac.ProofOfPossessionError:
            raise McpError(-32001, "agent possession check failed")
        except ac.ActionDeniedError:
            raise McpError(-32001, f"agent not authorized for {tool}")
        except ac.DelegationError as e:
            raise McpError(-32001, f"agent credential invalid: {e}")
        # authorized - invoke the real tool, then audit the chain.
        audit_log(session_id, tool, presentation.token.chain())
```

The TypeScript middleware is the same shape against `@agentcreds/sdk`
(`Presentation.fromCbor`, `presentation.verify(action, anchor, challenge, maxAgeSecs)`),
catching on `error.message` prefixes (`ProofOfPossessionError:`, `ActionDeniedError:`).

## What the middleware package still has to build (not crypto)

- Transport wiring for the challenge handshake over MCP (carry the challenge in the
  initialize result; carry the presentation in each `tools/call` `_meta`).
- A canonical `tool name + args -> Action` mapping (decide whether args are bound
  into the action and at what granularity).
- Session bookkeeping (challenge issue/rotate/expire) and the VC cache.
- Structured audit emission via the **ADR event stream** (`agentcreds_core::adr`):
  build an `AuthzDecision` from each `verify`/`verify_rooted` result and record it
  to an `AdrStream` whose sink forwards to your SIEM.
- The A2A counterpart: attach a `Presentation` as the signed identity header on an
  outgoing A2A task; the receiver verifies with the same call.

## Primitive reference

| Need | API (Rust / Python / Node) |
|---|---|
| Verifier issues challenge | `PopChallenge::new(audience)` / `PopChallenge(audience)` / `new PopChallenge(audience)` |
| Holder proves possession | `token.prove_possession(challenge, leaf_agent)` / same / `token.provePossession(...)` |
| Bundle for the wire | `Presentation::create(token, vc, challenge, leaf_agent)` + `to_cbor()` |
| Verifier checks everything | `presentation.verify(action, anchor, challenge, max_age)` |
| Token-only authenticity | `token.verify_rooted(action, vc, anchor)` (no possession) |
| Audit chain (no keys) | `token.chain()` |
