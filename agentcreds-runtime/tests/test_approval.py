"""Tests for human-in-the-loop step-up approval (Model A: synchronous block), end-to-end
through the real wheel + IdentityEnforcer. The poll flow now issues the same principal-bound
``ApprovalEvidence`` as carried gates, verified offline against the org anchor."""

import threading
import time

import agentcreds as ac

from agentcreds_runtime import IdentityEnforcer, InMemoryApprovalClient, PolicyConfig, present, CANON_PROFILE_JCS, jcs_canonicalize_args
from agentcreds_runtime.errors import CODE_APPROVAL, CODE_NOT_AUTHORIZED


def make_world(tools=("tool:transfer",), budget=100, depth=2):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=list(tools), max_delegation_depth=depth, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=list(tools), budget_usd=budget, max_depth=depth)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


def big_transfer(pin):
    """Flag transfers over 100 for human approval."""
    return pin.tool == "tool:transfer" and int((pin.arguments or {}).get("amount", 0)) > 100


# -- Allow / deny / not-flagged ------------------------------------------------


def test_auto_approve_allows_flagged_call():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=InMemoryApprovalClient(anchor, auto="approve"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed


def test_auto_deny_denies_flagged_call():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=InMemoryApprovalClient(anchor, auto="deny"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_APPROVAL
    assert "denied by operator" in decision.reason


def test_unflagged_call_is_not_held():
    # A would-be-deny client proves the policy gate decided NOT to escalate a small transfer.
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=InMemoryApprovalClient(anchor, auto="deny"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:transfer", {"amount": 50}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 50}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


# -- The real synchronous block ------------------------------------------------


def test_blocks_until_operator_approves():
    anchor, agent, vc, token = make_world()
    client = InMemoryApprovalClient(anchor)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=client, approval_timeout_secs=5, approval_poll_interval_secs=0.05, revocation_check=False))
    ch = enf.issue_challenge("s1")

    def operator():
        for _ in range(200):
            pending = client.list_pending()
            if pending:
                client.approve(pending[0].approval_id, "alice")
                return
            time.sleep(0.02)

    t = threading.Thread(target=operator)
    t.start()
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    t.join()
    assert decision.allowed


def test_timeout_denies():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=InMemoryApprovalClient(anchor), approval_timeout_secs=1, approval_poll_interval_secs=0.05, revocation_check=False))
    ch = enf.issue_challenge("s1")
    start = time.monotonic()
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_APPROVAL and "timed out" in decision.reason
    assert time.monotonic() - start >= 1  # actually blocked for the window


# -- Binding + ordering + fail-closed ------------------------------------------


def test_evidence_bound_to_wrong_action_is_denied():
    anchor, agent, vc, token = make_world()

    class WrongBindingClient(InMemoryApprovalClient):
        def poll(self, approval_id):
            with self._lock:
                req = self._pending.get(approval_id)
            if req is None:
                return None
            # Validly anchor-signed, but bound to a DIFFERENT action -> verify fails.
            other = ac.Action("tool:transfer", "amount=forged")
            return ac.ApprovalEvidence.approve(other, "evil", approval_id, int(time.time()) + 300, self._anchor)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=WrongBindingClient(anchor), approval_timeout_secs=2, approval_poll_interval_secs=0.05, revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_APPROVAL
    assert "not bound to this action" in decision.reason


def test_forged_evidence_from_wrong_anchor_is_denied():
    anchor, agent, vc, token = make_world()

    class ForgedAnchorClient(InMemoryApprovalClient):
        def poll(self, approval_id):
            with self._lock:
                req = self._pending.get(approval_id)
            if req is None:
                return None
            # Bound to the right action but signed by an anchor the PEP does not trust.
            attacker = ac.TrustAnchor.generate()
            return ac.ApprovalEvidence.approve(req.action(), "evil", approval_id, int(time.time()) + 300, attacker)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=ForgedAnchorClient(anchor), approval_timeout_secs=2, approval_poll_interval_secs=0.05, revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_APPROVAL


def test_approval_not_consulted_before_authority_proven():
    # A call denied by the capability (out of scope) must never reach the approval gate.
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    seen = []

    def policy(pin):
        seen.append(pin.tool)
        return True

    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=policy, approval_client=InMemoryApprovalClient(anchor, auto="approve"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:admin", {}, present(token, vc, ch, agent, action=ac.Action("tool:admin", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_NOT_AUTHORIZED
    assert seen == []  # the approval policy never ran


def test_approval_policy_error_fails_closed():
    anchor, agent, vc, token = make_world()

    def boom(_pin):
        raise RuntimeError("policy engine down")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=boom, approval_client=InMemoryApprovalClient(anchor, auto="approve"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_APPROVAL


def test_client_failure_fails_closed():
    anchor, agent, vc, token = make_world()

    class BrokenClient(InMemoryApprovalClient):
        def request(self, req):
            raise RuntimeError("approvals service unreachable")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(approval_policy=big_transfer, approval_client=BrokenClient(anchor), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 500}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 500}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_APPROVAL and "unavailable" in decision.reason
