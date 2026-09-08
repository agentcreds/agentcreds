"""Hybrid R10 at the enforcement point: evidence signed by an individual approver.

Anchor-signed approval proves only that *the organization* approved. The hybrid model
proves *who*, by having the human sign with their own key and checking that key against
an anchor-signed approver directory. That directory is the only thing binding a key to a
person, which is what makes IdP offboarding effective here: drop someone from the
directory and their signature stops satisfying gates on the next fetch.

Before this, `IdentityEnforcer` failed closed on `approval-key` gates - correctly, but it
meant the hybrid model could not be enforced by the reference PEP at all.

Every accept case is paired with a control, because "enforces the directory" and "accepts
any signature" agree on the accept cases alone.
"""

import time

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    PolicyConfig,
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    jcs_canonicalize_args,
    present,
)
from agentcreds_runtime.errors import CODE_APPROVAL

TOOL = "tool:wire"


def world(gate_kind="approval-key"):
    """An agent whose token gates `TOOL` on execution-time human authorization."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    gate = (
        ac.Gate.approval_key(TOOL) if gate_kind == "approval-key" else ac.Gate.approval(TOOL)
    )
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, None)
    scope = ac.Scope(tools=[TOOL], max_depth=0).with_gates([gate])
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


def approver(approver_id="alice@example.com", roles=None):
    key = ac.AgentIdentity.create_did_key()
    entry = ac.ApproverEntry(approver_id, key.did, roles or [], None)
    return entry, key, approver_id


def directory(anchor, entries, version=1):
    return ac.ApproverDirectory.seal(list(entries), version, anchor, None)


def evidence_by(who, key, action, approval_id="apr-1", ttl=300):
    return ac.ApprovalEvidence.approve_by_key(
        action, who, key, approval_id, int(time.time()) + ttl
    )


#: The action the enforcer will check against for a call with no arguments. Evidence
#: must be bound to the CANONICALIZED form ("{}"), not the empty string - approval is
#: bound to the exact request, so a mismatch here is the binding working as intended.
def gated_action():
    return ac.Action(TOOL, jcs_canonicalize_args({}))


def decide(enf, vc, token, agent, evidence=(), session="s1"):
    challenge = enf.issue_challenge(session)
    return enf.authorize(
        session, TOOL, {}, present(token, vc, challenge, agent, action=ac.Action(TOOL, jcs_canonicalize_args({}))), approval_evidence=list(evidence), canonicalization_profile=CANON_PROFILE_JCS
    )


# -- The capability ------------------------------------------------------------


def test_approver_key_evidence_satisfies_the_gate():
    anchor, agent, vc, token = world()
    entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))

    ev = evidence_by(who, key, gated_action())
    decision = decide(enf, vc, token, agent, [ev])
    assert decision.allowed, decision.reason


def test_without_a_directory_the_same_call_is_denied():
    """The control, and the previous behavior: an approval-key gate the PEP cannot
    evaluate must fail closed rather than be waved through."""
    anchor, agent, vc, token = world()
    _entry, key, who = approver()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # no directory

    ev = evidence_by(who, key, gated_action())
    decision = decide(enf, vc, token, agent, [ev])
    assert decision.denied
    assert decision.code == CODE_APPROVAL


def test_a_missing_directory_reports_a_pep_fault_not_a_missing_approval():
    """These need opposite responses - fix the deployment vs. get someone to approve -
    and are indistinguishable to the caller unless the reason says which."""
    anchor, agent, vc, token = world()
    _entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=lambda: None, config=PolicyConfig(revocation_check=False))

    decision = decide(enf, vc, token, agent, [evidence_by(who, key, gated_action())])
    assert decision.denied
    assert "directory" in decision.reason.lower(), decision.reason


# -- The security content: the directory is authoritative ----------------------


def test_an_approver_not_in_the_directory_is_refused():
    anchor, agent, vc, token = world()
    enrolled, _ek, _ewho = approver("alice@example.com")
    _oe, outsider_key, outsider_who = approver("mallory@evil.example")
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [enrolled]), config=PolicyConfig(revocation_check=False))

    ev = evidence_by(outsider_who, outsider_key, gated_action())
    decision = decide(enf, vc, token, agent, [ev])
    assert decision.denied, "a key outside the directory approved an action"


def test_removing_an_approver_takes_effect_without_restarting():
    """The joiner/mover/leaver property. The enforcer reads the directory through a
    callable, so an offboarding reaches it on the next decision."""
    anchor, agent, vc, token = world()
    alice, alice_key, alice_who = approver("alice@example.com")
    bob, _bob_key, _bob_who = approver("bob@example.com")

    current = {"dir": directory(anchor, [alice, bob], 1)}
    enf = IdentityEnforcer(anchor, approver_directory=lambda: current["dir"], config=PolicyConfig(revocation_check=False))

    # Control: alice can approve while enrolled, so the refusal below is attributable to
    # the offboarding rather than to her evidence being malformed.
    ev1 = evidence_by(alice_who, alice_key, gated_action(), approval_id="apr-1")
    assert decide(enf, vc, token, agent, [ev1], session="s1").allowed

    # Alice leaves. Same enforcer, same process - only the directory changed.
    current["dir"] = directory(anchor, [bob], 2)
    ev2 = evidence_by(alice_who, alice_key, gated_action(), approval_id="apr-2")
    decision = decide(enf, vc, token, agent, [ev2], session="s2")
    assert decision.denied, "a departed approver still satisfied the gate"


def test_a_directory_signed_by_another_anchor_is_refused():
    anchor, agent, vc, token = world()
    stranger = ac.TrustAnchor.generate()
    entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(stranger, [entry]), config=PolicyConfig(revocation_check=False))

    decision = decide(enf, vc, token, agent, [evidence_by(who, key, gated_action())])
    assert decision.denied, "a directory from a foreign anchor authorized an approver"


def test_evidence_for_a_different_action_is_refused():
    anchor, agent, vc, token = world()
    entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))

    ev = evidence_by(who, key, ac.Action("tool:something-else", ""))
    assert decide(enf, vc, token, agent, [ev]).denied


def test_expired_evidence_is_refused():
    anchor, agent, vc, token = world()
    entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))

    ev = ac.ApprovalEvidence.approve_by_key(
        gated_action(), who, key, "apr-x", int(time.time()) - 1
    )
    assert decide(enf, vc, token, agent, [ev]).denied


# -- Composition with the rest of the gate machinery ---------------------------


def test_one_time_reliance_still_applies_to_approver_key_evidence():
    """The hybrid path must not bypass the consumed-approvals ledger, or the same
    signature would be replayable for the whole of its validity window."""
    anchor, agent, vc, token = world()
    entry, key, who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))

    ev = evidence_by(who, key, gated_action(), approval_id="apr-once")
    assert decide(enf, vc, token, agent, [ev], session="s1").allowed
    second = decide(enf, vc, token, agent, [ev], session="s2")
    assert second.denied, "the same approval was relied upon twice"


def test_supplying_a_directory_recognizes_the_hybrid_kind_automatically():
    """A caller who passes a directory has stated their intent. Requiring them to also
    repeat the kind would fail closed in a way that looks like a policy bug."""
    anchor, _agent, _vc, _token = world()
    entry, _key, _who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))
    assert "approval-key" in enf._gate_kinds


def test_anchor_signed_gates_are_unaffected_by_the_directory():
    """Regression guard: adding hybrid support must not change the anchor-signed path."""
    anchor, agent, vc, token = world(gate_kind="approval")
    entry, _key, _who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))

    ev = ac.ApprovalEvidence.approve(
        gated_action(), "ops@example.com", "apr-anchor", int(time.time()) + 300, anchor
    )
    assert decide(enf, vc, token, agent, [ev]).allowed


def test_an_unknown_gate_kind_still_fails_closed():
    anchor, agent, vc, token = world()
    entry, _key, _who = approver()
    enf = IdentityEnforcer(anchor, approver_directory=directory(anchor, [entry]), config=PolicyConfig(revocation_check=False))
    # A gate kind nothing recognizes.
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    vc2 = ac.CapabilityCredential.issue(anchor, agent.did, claims, None)
    scope2 = ac.Scope(tools=[TOOL], max_depth=0).with_gates([ac.Gate("quorum", TOOL)])
    token2 = ac.DelegationToken.mint(vc2, scope2, 300, agent)

    decision = decide(enf, vc2, token2, agent)
    assert decision.denied
    assert "quorum" in decision.reason
