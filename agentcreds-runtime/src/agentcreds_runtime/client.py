"""Holder-side helpers - what an MCP client does to present its authority."""

from __future__ import annotations

import agentcreds as ac


def present(
    token: "ac.DelegationToken",
    credential: "ac.CapabilityCredential",
    challenge_cbor: bytes,
    leaf_agent: "ac.AgentIdentity",
    action: "ac.Action | None" = None,
) -> bytes:
    """Build the wire bytes to attach to an MCP tool call.

    Given the server's challenge (as received CBOR), the agent's token, its
    backing credential, and the leaf agent identity (which must hold the leaf
    key), produce a `Presentation` and return its CBOR encoding.

    Pass ``action`` (an ``agentcreds.Action`` with the same tool, canonical
    parameters, and resource the server will see) to **bind the proof to this
    exact request** - the resulting presentation is then valid only for that call
    and cannot be reused for different arguments. The parameters must be
    canonicalized the same way the server does -
    ``agentcreds_runtime.jcs_canonicalize_args`` (RFC 8785), which is what
    :class:`PolicyConfig` defaults to.

    Declare the profile alongside the call (the ``agentcreds_canon_profile`` tool
    argument over MCP, the ``AgentCreds-A2A-Canon-Profile`` header over A2A).
    Verifiers require it for bound presentations by default, and a mismatch is
    reported as a named profile failure rather than as a possession failure.
    """
    challenge = ac.PopChallenge.from_cbor(challenge_cbor)
    if action is not None:
        challenge = challenge.with_request_binding(action.request_binding())
    presentation = ac.Presentation.create(token, credential, challenge, leaf_agent)
    return presentation.to_cbor()
