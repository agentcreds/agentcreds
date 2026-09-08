"""End-to-end A2A verification, runnable against the real agentcreds wheel.

    python examples/a2a_verify.py

Plays both sides - a sender mints A2A headers, a receiver (`A2AVerifier`) verifies
them - covering the plain path, the single-use replay guard, and the on-behalf-of
wire envelope.
"""

import agentcreds as ac

from agentcreds_runtime import (
    A2AVerifier,
    CANON_PROFILE_JCS,
    InMemoryReplayGuard,
    PolicyConfig,
    jcs_canonicalize_args,
    make_a2a_envelope,
    make_a2a_header,
)

RECEIVER = "a2a://orders.example/agent"


def main():
    # -- A trust anchor issues an agent a capability credential + runtime token. --
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=1), 300, agent)

    # -- Plain A2A: sender mints a header, receiver verifies it offline. --
    verifier = A2AVerifier(
        audience=RECEIVER,
        anchor=anchor,
        replay_guard=InMemoryReplayGuard(),
        # No revocation source in a self-contained demo, so say so. A real receiver
        # passes `revocation_check_from_list(...)`; there is no default because
        # silence would mean accepting every revoked credential.
        config=PolicyConfig(revocation_check=False),
    )
    # Bind the header to the exact call. Required by default: an unbound header is
    # replayable against any arguments for this tool inside the freshness window.
    args = {"q": "hi"}
    action = ac.Action("tool:search", jcs_canonicalize_args(args))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=action)
    assert verifier.authorize(
        header, "tool:search", args, canonicalization_profile=CANON_PROFILE_JCS
    ).allowed
    print("plain A2A:        allowed")

    # A header minted for a different receiver is rejected here.
    other = make_a2a_header(token, vc, agent, audience="a2a://evil.example/agent")
    assert verifier.authorize(other, "tool:search", {}).denied
    print("wrong audience:   denied")

    # The single-use guard rejects a verbatim replay of an accepted header. Replay the
    # ORIGINAL call exactly - same arguments, same declared profile - so the only thing
    # under test is the replay, not a binding or profile difference.
    assert (
        verifier.authorize(
            header, "tool:search", args, canonicalization_profile=CANON_PROFILE_JCS
        ).code
        == "replayed_presentation"
    )
    print("replayed header:  denied")

    # -- On-behalf-of: the human's identity rides in the envelope. --
    # (Here we issue a credential bound to a human DID directly; in production the
    # principal_token is the human's OIDC ID token validated via OidcProvider.)
    import datetime

    human = ac.HumanIdentity.from_idp("https://login.acme.com", "auth0|alice")
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    obo_claims = ac.CapabilityClaims(
        ["tool:read_email"], 2, 3600,
        on_behalf_of=human.authorize(expires, ["tool:read_email"], ["mailbox:alice@acme.com/*"]),
    )
    obo_vc = ac.CapabilityCredential.issue(anchor, agent.did, obo_claims)
    obo_token = ac.DelegationToken.mint(
        obo_vc, ac.Scope(["tool:read_email"], max_depth=1, resources=["mailbox:alice@acme.com/42"]),
        300, agent)

    # The receiver resolves the principal token to Alice's DID; here we trust it
    # directly for the demo (production: principal_resolver_from_oidc(provider)).
    obo_verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=lambda _token: human.did, config=PolicyConfig(revocation_check=False),
    )
    # The binding covers the resource as well as the tool and arguments, so the action
    # has to name the same mailbox the call below asks for.
    obo_action = ac.Action(
        "tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42"
    )
    envelope = make_a2a_envelope(
        obo_token, obo_vc, agent, audience=RECEIVER,
        principal_token="<alice's id token>",
        action=obo_action, canonicalization_profile=CANON_PROFILE_JCS)
    assert set(envelope) == {
        "AgentCreds-A2A", "AgentCreds-A2A-Principal", "AgentCreds-A2A-Canon-Profile"}
    decision = obo_verifier.authorize_envelope(
        envelope, "tool:read_email", {}, resource="mailbox:alice@acme.com/42")
    assert decision.allowed
    print("OBO envelope:     allowed, on behalf of", decision.chain[0].agent_did[:24] + "...")

    # A session for a different human cannot drive Alice's agent.
    bob_verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=lambda _token: "did:web:login.acme.com:u:zBob", config=PolicyConfig(revocation_check=False),
    )
    assert bob_verifier.authorize_envelope(
        envelope, "tool:read_email", {}, resource="mailbox:alice@acme.com/42").code == "principal_mismatch"
    print("confused deputy:  denied")

    print("\nAll A2A example checks passed.")


if __name__ == "__main__":
    main()
