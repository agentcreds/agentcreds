"""R2 - cross-organizational verification, offline, no per-interaction agreement.

Demonstrates the WIMSE R2 requirement:

    "A relying party in one organization MUST be able to verify authority that
     originated under another organization's trust anchor without a pre-existing
     bilateral agreement specific to the interaction."

The relying party (Org B's PEP) is configured with **only** the shared trust
framework's anchor and a signed trust registry - it has NO prior knowledge of
Org A's anchor. It nonetheless verifies, fully offline, an authority that Org A
issued: it resolves A's anchor *out of the multilateral registry*, checks A's
trust level, and verifies the credential's signature + delegation chain. No
bilateral, per-interaction handshake is involved.

Three cases prove the trust is real, not blanket:
  1. Org A  (registered, trust_level=verified)   -> ALLOW  (cross-org success)
  2. Org D  (registered, trust_level=self_asserted, below the RP's minimum) -> DENY
  3. Org C  (NOT in the registry at all)          -> DENY

Run (needs the Linux `agentcreds` wheel + this package):
    python examples/r2_cross_org.py
"""

import agentcreds as ac

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    jcs_canonicalize_args,
    IdentityEnforcer,
    PolicyConfig,
    anchor_resolver_from_registry,
    present,
)


def issue_agent(org_anchor: "ac.TrustAnchor"):
    """An org issues one of its agents a capability credential and the agent mints
    a runtime delegation token. Returns (agent, credential, token)."""
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600
    )
    vc = ac.CapabilityCredential.issue(org_anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=0), 300, agent)
    return agent, vc, token


def try_call(enforcer: "IdentityEnforcer", label: str, agent, vc, token) -> None:
    """Present `org`'s authority to the relying party and report allow/deny."""
    session = f"session-{label}"
    challenge = enforcer.issue_challenge(session)
    # Bind the proof to this exact call. Required by default, and orthogonal to what
    # this demo is about - but leaving it unbound made every row below deny with
    # `argument_binding_required` while the summary still claimed R2 was satisfied.
    args = {"q": "hello"}
    action = ac.Action("tool:search", jcs_canonicalize_args(args))
    presentation = present(token, vc, challenge, agent, action=action)
    d = enforcer.authorize(
        session, "tool:search", args, presentation,
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    if d.allowed:
        issuer = d.chain[0].agent_did if d.chain else vc.issuer
        print(f"  {label:<32} -> ALLOW   (verified authority rooted in {vc.issuer[:28]}...)")
    else:
        print(f"  {label:<32} -> DENY    ({d.code}: {d.reason})")


def main() -> None:
    # -- The shared trust framework (a multilateral root, NOT a bilateral deal) --
    framework = ac.TrustAnchor.generate()

    # -- Three independent organizations, each with its own root of trust -------
    org_a = ac.TrustAnchor.generate()  # a verified member
    org_d = ac.TrustAnchor.generate()  # a member, but only self-asserted
    org_c = ac.TrustAnchor.generate()  # NOT a member of the framework

    # -- The framework operator builds + signs the registry (once, offline) -----
    registry = ac.TrustRegistry()
    registry.minimum_trust_level = "verified"
    registry.register(ac.TrustEntry(org_a.did, "Org A", org_a.public_key, "verified"))
    registry.register(ac.TrustEntry(org_d.did, "Org D", org_d.public_key, "self_asserted"))
    signed_config = registry.export(framework, 1)  # anchor-signed, versioned, portable
    wire = signed_config.to_json()  # <- the only thing distributed to relying parties

    print("Trust framework anchor :", framework.did[:40], "...")
    print("Signed registry (v%d) members:" % signed_config.version,
          ", ".join(e.org_name for e in signed_config.entries))
    print("Org C (unregistered)   :", org_c.did[:40], "...")
    print()

    # -- The relying party (Org B's PEP) bootstraps from ONLY: the framework ----
    #    anchor + the signed registry. It has never seen Org A/D/C's anchors.
    received = ac.SignedTrustConfig.from_json(wire)
    received.verify(framework)  # tamper-evidence: signed by the framework we trust
    rp_registry = ac.TrustRegistry.from_config(received, framework)

    # Multi-issuer enforcement: resolve each credential's issuer anchor from the
    # registry (no single pinned anchor). This is the R2 switch.
    enforcer = IdentityEnforcer(
        anchor_for=anchor_resolver_from_registry(rp_registry),
        config=PolicyConfig(max_age_secs=60, audit_denied=True, revocation_check=False),
    )

    print("Relying party verifies (offline, no per-interaction agreement):")
    # 1. Cross-org success - authority rooted in Org A's anchor, which the RP only
    #    knows through the multilateral registry.
    try_call(enforcer, "Org A  (registered/verified)", *issue_agent(org_a))
    # 2. Registered but below the RP's minimum trust level - graded trust, denied.
    try_call(enforcer, "Org D  (registered/self_asserted)", *issue_agent(org_d))
    # 3. Unknown issuer - not in the framework at all - denied.
    try_call(enforcer, "Org C  (unregistered)", *issue_agent(org_c))

    print("\nR2 satisfied: Org A's authority verified with no A-specific setup -")
    print("only a one-time, multilateral trust-framework import.")


if __name__ == "__main__":
    main()
