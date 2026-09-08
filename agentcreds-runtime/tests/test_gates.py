"""End-to-end R10 (execution-time human authorization) via the Python API."""

import time

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    GateDenied,
    PolicyConfig,
    enforce_gates,
    jcs_canonicalize_args,
)


def _gated_world(tool="tool:pay"):
    """A rooted token that gates `tool` on human approval (R10)."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[tool], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=[tool], budget_usd=100, max_depth=1).require_approval(tool)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    action = ac.Action(tool, "amount=100")
    return anchor, agent, vc, token, action


def test_gate_travels_and_denies_without_evidence():
    anchor, _agent, vc, token, action = _gated_world()
    # The designation is carried inside the delegated authority.
    assert any(g.tool == "tool:pay" and g.kind == "approval" for g in token.gates())
    assert len(token.required_gates(action)) == 1
    # Designated action, no evidence -> refused (fail closed).
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor)


def test_evidence_allows_and_is_one_time():
    anchor, _agent, vc, token, action = _gated_world()
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator:carol", "appr-1", now + 300, anchor)
    consumed = ac.ConsumedApprovals()

    # First reliance: allowed, id relied upon.
    relied = enforce_gates(token, action, vc, anchor, [ev], consumed=consumed, now=now)
    assert relied == ["appr-1"]

    # Re-using the same evidence is refused (R10 one-time).
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor, [ev], consumed=consumed, now=now)


def test_evidence_carried_as_json():
    anchor, _agent, vc, token, action = _gated_world()
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "op", "appr-2", now + 300, anchor)
    # Round-trips over the wire and still satisfies the gate.
    ev2 = ac.ApprovalEvidence.from_json(ev.to_json())
    assert enforce_gates(token, action, vc, anchor, [ev2], now=now) == ["appr-2"]


def test_unrecognized_gate_kind_fails_closed():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1).with_gates(
        [ac.Gate("biometric", "tool:pay")]
    )
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    action = ac.Action("tool:pay", "amount=100")
    # The PEP recognizes only "approval" -> the biometric designation is unauthorized.
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor)


def test_gate_survives_attenuation():
    anchor, _agent, vc, token, action = _gated_world()
    child_agent = ac.AgentIdentity.create_did_key()
    narrow = ac.Scope(tools=["tool:pay"], budget_usd=50, max_depth=0)
    child = token.attenuate(narrow, 200, child_agent)
    # The child did not re-declare the gate, yet it still travels (monotone).
    assert any(g.tool == "tool:pay" for g in child.gates())
    with pytest.raises(GateDenied):
        enforce_gates(child, action, vc, anchor)


def test_enforcer_integrates_gate_end_to_end():
    # The full PEP path: a gated tool is denied without evidence, allowed with
    # principal-bound evidence carried on the call, and refused on evidence re-use.
    from agentcreds_runtime import (
    CANON_PROFILE_JCS,
        IdentityEnforcer,
        InMemoryConsumedApprovals,
        jcs_canonicalize_args,
        present,
    )
    from agentcreds_runtime.errors import CODE_ALREADY_CONSUMED, CODE_APPROVAL

    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1).require_approval("tool:pay")
    token = ac.DelegationToken.mint(vc, scope, 300, agent)

    enf = IdentityEnforcer(anchor, consumed_approvals=InMemoryConsumedApprovals(), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s1")

    # Gated tool, no evidence -> denied (fail closed).
    d = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert d.denied and d.code == CODE_APPROVAL

    # Evidence bound to the exact action the enforcer builds (canonicalized args,
    # no principal/resource) -> allowed.
    action = ac.Action("tool:pay", jcs_canonicalize_args({}))
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator", "e1", now + 300, anchor)
    d2 = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert d2.allowed, d2.reason

    # Second call re-using the same evidence -> denied (one-time), and denied with
    # its OWN code: the evidence verified and satisfied policy, it was simply already
    # spent. Sharing `CODE_APPROVAL` with "no evidence at all" made the two
    # indistinguishable to anything reading the decision rather than the reason text.
    d3 = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert d3.denied and d3.code == CODE_ALREADY_CONSUMED


def test_one_time_reliance_survives_downstream_denial_and_retries():
    # Regression: R10 one-time reliance must commit only AFTER every gate passes.
    # A gated tool with valid evidence that is denied by a *later* gate (contextual
    # policy) must not burn the evidence - a retry once policy allows succeeds with the
    # same evidence, and one-time reliance still holds thereafter.
    from agentcreds_runtime import (
        IdentityEnforcer,
        InMemoryConsumedApprovals,
        PolicyConfig,
        jcs_canonicalize_args,
        present,
    )
    from agentcreds_runtime.errors import (
        CODE_ALREADY_CONSUMED,
        CODE_APPROVAL,
        CODE_POLICY,
    )

    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1).require_approval("tool:pay")
    token = ac.DelegationToken.mint(vc, scope, 300, agent)

    blocked = {"on": True}  # a policy gate that denies the first call, then allows
    enf = IdentityEnforcer(
        anchor,
        config=PolicyConfig(policy_hook=lambda _pin: "blocked by policy" if blocked["on"] else None, revocation_check=False),
        consumed_approvals=InMemoryConsumedApprovals(),
    )
    ch = enf.issue_challenge("s1")

    action = ac.Action("tool:pay", jcs_canonicalize_args({}))
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator", "e-retry", now + 300, anchor)

    # Valid evidence, but the policy gate (which runs AFTER the R10 gate) denies.
    d1 = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert d1.denied and d1.code == CODE_POLICY  # denied downstream, NOT by R10 re-use

    # Policy now allows; the SAME evidence must still be accepted - it was never consumed.
    blocked["on"] = False
    d2 = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert d2.allowed, d2.reason

    # And now it IS committed - a further re-use is refused (one-time still holds),
    # as already-consumed rather than as unsatisfactory evidence.
    d3 = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert d3.denied and d3.code == CODE_ALREADY_CONSUMED


def test_consumed_record_holds_until_evidence_expiry_not_fixed_ttl():
    # Regression: the one-time record must remember an id until its evidence's own
    # expiry, so a consumed id is never forgotten while the evidence is still valid -
    # the one-time guarantee no longer depends on the store's fallback TTL.
    from agentcreds_runtime import InMemoryConsumedApprovals

    store = InMemoryConsumedApprovals(ttl_secs=0)  # fallback TTL forgets immediately
    now = int(time.time())

    # Recorded with a far evidence expiry -> a replay is refused even though the fixed
    # 0-second TTL has "elapsed": the id is held until the evidence would expire.
    assert store.try_consume("appr-x", not_after=now + 300) is True
    assert store.try_consume("appr-x", not_after=now + 300) is False

    # With NO expiry the store falls back to the fixed TTL (0s -> immediately forgettable).
    assert store.try_consume("appr-y") is True
    assert store.try_consume("appr-y") is True


def test_enforcer_fails_closed_on_recognized_but_unsupported_gate_kind():
    # Regression: a gate kind the enforcer RECOGNIZES but has no handler for (here
    # approval-key, which needs an approver directory this PEP does not verify against)
    # must fail CLOSED - it must never slip through the gate loop unenforced. Even with
    # the kind added to recognized_gate_kinds and no evidence, the tool is denied.
    from agentcreds_runtime import (
        APPROVAL,
        APPROVAL_KEY,
        IdentityEnforcer,
        InMemoryConsumedApprovals,
        present,
    )
    from agentcreds_runtime.errors import CODE_ALREADY_CONSUMED, CODE_APPROVAL

    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1).with_gates(
        [ac.Gate.approval_key("tool:pay")]
    )
    token = ac.DelegationToken.mint(vc, scope, 300, agent)

    enf = IdentityEnforcer(
        anchor,
        recognized_gate_kinds=(APPROVAL, APPROVAL_KEY),  # misconfig: approval-key "recognized"
        consumed_approvals=InMemoryConsumedApprovals(), config=PolicyConfig(revocation_check=False),
    )
    ch = enf.issue_challenge("s1")
    d = enf.authorize("s1", "tool:pay", {}, present(token, vc, ch, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert d.denied and d.code == CODE_APPROVAL
    assert "failing closed" in d.reason


def test_credential_mandated_gate_is_enforced():
    # A gated CREDENTIAL: the token is minted with a plain scope (no gate) yet the
    # credential's mandate is enforced - a gated credential can't be spent ungated.
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    claims.require_approval("tool:pay")
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1)  # no gate declared
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    action = ac.Action("tool:pay", "amount=100")

    # The mandate traveled into the token and is enforced without evidence.
    assert any(g.tool == "tool:pay" for g in token.gates())
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor)

    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "op", "m1", now + 300, anchor)
    assert enforce_gates(token, action, vc, anchor, [ev], now=now) == ["m1"]


def test_hybrid_approver_key_end_to_end():
    # Hybrid R10: the tool is gated on approver-KEY approval; the approver signs
    # with their own key, verified against an org-anchor-signed directory.
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:pay"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:pay"], budget_usd=100, max_depth=1).with_gates(
        [ac.Gate.approval_key("tool:pay")]
    )
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    action = ac.Action("tool:pay", "amount=100")
    now = int(time.time())

    # Enrol an approver key in the anchor-signed directory.
    approver = ac.AgentIdentity.create_did_key()
    directory = ac.ApproverDirectory.seal(
        [ac.ApproverEntry("operator:carol", approver.did, ["finance"])], 1, anchor
    )

    # No evidence -> denied (fail closed).
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor, directory=directory)

    # Approver-key-signed evidence -> allowed; directory auto-recognizes approval-key.
    ev = ac.ApprovalEvidence.approve_by_key(action, "operator:carol", approver, "ak-1", now + 300)
    consumed = ac.ConsumedApprovals()
    relied = enforce_gates(token, action, vc, anchor, [ev], directory=directory, consumed=consumed, now=now)
    assert relied == ["ak-1"]

    # Re-use refused (one-time), and a directory round-trips over the wire.
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor, [ev], directory=directory, consumed=consumed, now=now)
    directory2 = ac.ApproverDirectory.from_json(directory.to_json())
    assert directory2.version == directory.version

    # Evidence from a NON-enrolled approver is rejected (forgery fails).
    rogue = ac.AgentIdentity.create_did_key()
    bad = ac.ApprovalEvidence.approve_by_key(action, "operator:mallory", rogue, "ak-x", now + 300)
    with pytest.raises(GateDenied):
        enforce_gates(token, action, vc, anchor, [bad], directory=directory, now=now)


def test_ungated_tool_needs_no_evidence():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:read"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:read"], budget_usd=100, max_depth=1)  # no gate
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    action = ac.Action("tool:read", "")
    assert enforce_gates(token, action, vc, anchor) == []
