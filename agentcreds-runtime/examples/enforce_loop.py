"""Runnable, transport-free demonstration of the full enforcement loop.

Plays both sides in one process - the holder (an agent) and the verifier (a
server's IdentityEnforcer) - so you can see exactly what crosses the wire and
what each denial looks like. No MCP SDK required.

    python examples/enforce_loop.py
"""

import agentcreds as ac

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    PolicyConfig,
    jcs_canonicalize_args,
    present,
)


def build_agent():
    """An org issues an agent a credential and the agent mints a runtime token."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=["tool:search", "tool:summarize"],
        max_delegation_depth=2,
        valid_for_secs=3600,
    )
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=1)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


def main():
    anchor, agent, vc, token = build_agent()

    audit = []
    enforcer = IdentityEnforcer(
        anchor,
        config=PolicyConfig(
            max_age_secs=60,
            audit=audit.append,
            audit_denied=True,
            # No revocation source in a self-contained demo, so say so. There is no
            # default: silence would have meant accepting every revoked credential.
            # A real deployment passes `revocation_check_from_list(...)` here.
            revocation_check=False,
        ),
    )

    # 1. Session setup: server issues a challenge, client receives it.
    session = "demo-session"
    challenge = enforcer.issue_challenge(session)

    # 2. Client binds the proof to the exact call it is about to make. Argument
    #    binding is required by default: an unbound proof says "this holder is here
    #    now" and nothing about WHAT it asked for, so one captured from a
    #    `{"q": "agentcreds"}` call could be replayed against any other arguments.
    args = {"q": "agentcreds"}
    action = ac.Action("tool:search", jcs_canonicalize_args(args))
    presentation = present(token, vc, challenge, agent, action=action)

    # 3. Allowed call. The profile is declared alongside the binding so a
    #    disagreement about representation reports as itself rather than as a
    #    possession failure.
    d = enforcer.authorize(
        session, "tool:search", args, presentation,
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    print("tool:search ->", "ALLOW" if d.allowed else f"DENY ({d.code})")
    print("  chain:", [(h.depth, h.agent_did[:24] + "...", h.tools) for h in d.chain])

    # 4. Tool outside the token's scope - bound to that call, so the denial is
    #    about scope rather than about the binding.
    other = ac.Action("tool:summarize", jcs_canonicalize_args({}))
    d = enforcer.authorize(
        session, "tool:summarize", {},
        present(token, vc, challenge, agent, action=other),
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    print("tool:summarize ->", "ALLOW" if d.allowed else f"DENY ({d.code})")

    # 5. Replay after the server rotates its challenge. Replay the ORIGINAL call
    #    verbatim - same arguments, same declared profile - so the only thing that
    #    changed is the challenge, and the denial is about the replay itself.
    enforcer.rotate_challenge(session)
    d = enforcer.authorize(
        session, "tool:search", args, presentation,
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    print("replayed presentation ->", "ALLOW" if d.allowed else f"DENY ({d.code})")

    # 6. A delegated sub-agent presents its own narrower token, bound to its own call.
    sub = ac.AgentIdentity.create_did_key()
    child = token.attenuate(ac.Scope(tools=["tool:search"], budget_usd=10, max_depth=0), 60, sub)
    fresh = enforcer.issue_challenge(session)
    sub_action = ac.Action("tool:search", jcs_canonicalize_args({}))
    sub_presentation = present(child, vc, fresh, sub, action=sub_action)
    d = enforcer.authorize(
        session, "tool:search", {}, sub_presentation,
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    print("sub-agent tool:search ->", "ALLOW" if d.allowed else f"DENY ({d.code})")

    print(f"\naudit records: {len(audit)}")


if __name__ == "__main__":
    main()
