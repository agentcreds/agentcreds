# @agentcreds/runtime

Runtime AgentCreds enforcement for Node, built on [`@agentcreds/sdk`](../agentcreds-node).

## Scope: agent-to-agent (A2A) only - this is deliberate

This package verifies **A2A** requests: agent A hands a task directly to agent B, A
attaches a self-contained identity header, and B verifies it offline. That is the whole
supported surface, and it is complete for that surface.

It is **not** a Node port of `agentcreds-runtime` (Python). The following are Python-only
and are **not planned** here:

| | Python | Node |
|---|---|---|
| A2A verifier, replay guard | DONE | DONE |
| MCP `IdentityEnforcer` (sessionful, per-tool-call) | DONE | NO |
| R10 execution-time gates + approval evidence | DONE | NO |
| Step-up approval, approver directory | DONE | NO |
| Key-history cache, trust-registry cache | DONE | NO |
| Usage metering, Cedar policy hook, decision reporter | DONE | NO |
| Session / idempotency / consumed-approval stores | DONE | NO |

**Why say so rather than fix it.** The enforcement layer is where the security-relevant
behavior lives, and a second implementation of it would have to be kept correct twice -
every gap closed in one would have to be closed again in the other, on a lag, with the
conformance suite covering only the first. A partial second enforcement point that *looks*
like the reference is worse than none: it invites a deployment that believes it has R10
and does not.

**If you need MCP enforcement, R10 gates, or step-up approval, run the Python PEP.** The
capability lives behind an MCP endpoint, so the language of your *agent* is unconstrained -
a Node agent talks to a Python PEP over the wire like any other client.

## What the Node SDK *does* cover, in full

`@agentcreds/sdk` is at parity with the Python core binding: identities, credentials
(including `resources`, `accountableParty`, `partyVersion`, `partyCommitment`), delegation
tokens, presentations, proof of possession, revocation, key history and rotation, trust
registry, approver directories, `OwnershipRecord`, and Authorization Decision Records
**including recording accountability and the R10 evaluation/admission verdicts**.

So a Node service can issue, mint, attenuate, verify, and produce a complete, digest-covered
decision record. What it cannot do is host the MCP policy enforcement point.

## Conformance

The end-to-end enforcement harnesses are Python and exercise the Python enforcement path.
Node has `test/conformance.test.js` (28 cases, the shared cross-language vector set) plus
`test/accountability.test.js`, which pins that the party commitment computed here is
**byte-identical** to Python's - without that, a Node verifier could not check a
commitment a Python control plane stamped, and the disagreement would look like a
tampered record rather than a binding mismatch.

Read a green Node run as *"the SDK-layer vectors pass"*, never as *"R10 is enforced"*.
