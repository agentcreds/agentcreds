"""Regressions for four defects that a green SDK suite passed straight over.

All four were found on 2026-07-31 by driving `draft-reece-wimse-cross-org-delegation-01`
R2 and R10 through the **live MCP PEP** (`deploy/local-harness/r2_pep.py`, `r10_pep.py`)
rather than through the library. Each one let a requirement hold at this layer while being
unenforceable one layer up. The local harness is not run in CI, so without these tests
nothing stops them coming back.

They share a shape worth naming: **the safe behavior was reachable but not the default**,
so every test that configured things explicitly passed. `test_gates.py`, for instance,
passes `consumed_approvals=InMemoryConsumedApprovals()` in every case that depends on it -
which is exactly why nobody noticed the constructor default made it a no-op.
"""

import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    AccessDenied,
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    PolicyConfig,
    jcs_canonicalize_args,
    present,
)
from agentcreds_runtime.errors import (
    CODE_ALREADY_CONSUMED,
    CODE_APPROVAL,
    CODE_CANON_PROFILE,
)
from agentcreds_runtime.fastmcp import (
    CANON_PROFILE_ARG,
    EVIDENCE_ARG,
    PRESENTATION_ARG,
    guard_tool,
)


class FakeCtx:
    def __init__(self, client_id):
        self.client_id = client_id


def _gated_world(tool="tool:pay"):
    """A credential that MANDATES approval for `tool`, and a token minted from it."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[tool], max_delegation_depth=1, valid_for_secs=3600)
    claims.require_approval(tool)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=[tool], max_depth=0), 300, agent)
    return anchor, agent, vc, token


# -- 1. Trust-config freshness must be reachable from Python --------------------
# The Rust core had `verify_current` / `is_current` / `not_after` / `export_valid_until`;
# the PyO3 bindings exposed NONE of them. The deployed PEP called `verify_current` on the
# Python object, so cross-org registry mode died at import with AttributeError - the whole
# R2 path was unreachable in any Python deployment, and no Python relying party could
# publish an expiring trust config at all.


def _framework_and_member():
    framework = ac.TrustAnchor.create_did_key()
    member = ac.TrustAnchor.create_did_key()
    reg = ac.TrustRegistry()
    reg.register(ac.TrustEntry(member.did, "Member", member.public_key, "verified"))
    return framework, member, reg


def test_signed_trust_config_exposes_the_freshness_surface():
    framework, _member, reg = _framework_and_member()
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    config = reg.export_valid_until(framework, 1, future)

    assert config.not_after is not None
    assert config.is_current()
    config.verify_current(framework)  # must not raise
    assert ac.TrustRegistry.from_config(config, framework) is not None


def test_unbounded_config_is_always_current():
    framework, _member, reg = _framework_and_member()
    config = reg.export(framework, 1)
    assert config.not_after is None
    assert config.is_current()
    config.verify_current(framework)


def test_expired_config_is_authentic_but_refused():
    # Authenticity and freshness are SEPARATE checks. A lapsed config is still genuinely
    # framework-signed, and conflating the two is how a stale registry stays trusted.
    framework, _member, reg = _framework_and_member()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    stale = reg.export_valid_until(framework, 2, past)

    assert not stale.is_current()
    stale.verify(framework)  # authentic - must NOT raise
    with pytest.raises(Exception):
        stale.verify_current(framework)
    with pytest.raises(Exception):
        ac.TrustRegistry.from_config(stale, framework)


def test_sealed_expiry_cannot_be_extended():
    # The expiry is inside the signed digest, so extending it must break the signature.
    # Edit the serialized JSON rather than string-replacing the getter's rfc3339 form -
    # the two renderings differ, so a `.replace()` silently matches nothing and the test
    # passes while asserting on an untouched config.
    framework, _member, reg = _framework_and_member()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    stale = reg.export_valid_until(framework, 3, past)

    doc = json.loads(stale.to_json())
    assert doc["not_after"] is not None, "expiry is not in the serialized form"
    doc["not_after"] = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    with pytest.raises(Exception):
        ac.SignedTrustConfig.from_json(json.dumps(doc)).verify(framework)

    # Dropping the expiry entirely must break it too - otherwise "unbounded" would be a
    # free downgrade from "expired".
    doc.pop("not_after")
    with pytest.raises(Exception):
        ac.SignedTrustConfig.from_json(json.dumps(doc)).verify(framework)


# -- 2. Only the reserved names are stripped from the request binding -----------
# The demo tool declared `agentcreds_evidence` instead of EVIDENCE_ARG. Evidence never
# reached the enforcer AND the stray parameter joined the canonicalized arguments, denying
# correctly-bound clients with a crypto-looking `possession_failed`. Adding an optional
# parameter server-side is a BREAKING change for bound clients unless it is reserved.


def test_reserved_names_are_excluded_from_the_binding():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=0),
                                    300, agent)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    # The client binds over the plain tool arguments only.
    action = ac.Action("tool:search", jcs_canonicalize_args({"q": "rust"}))
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()

    @guard_tool(enf, "tool:search")
    async def handler(q, ctx=None, **kwargs):
        return "ok"

    # Both reserved kwargs present on the call; neither may alter the binding.
    assert asyncio.run(handler(q="rust", ctx=FakeCtx("s1"),
                               **{PRESENTATION_ARG: pres, EVIDENCE_ARG: "",
                                  CANON_PROFILE_ARG: CANON_PROFILE_JCS})) == "ok"


def test_a_non_reserved_extra_argument_does_change_the_binding():
    # The other half of the contract, asserted so the guarantee above is not vacuous:
    # anything NOT reserved is part of the request binding by design.
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=0),
                                    300, agent)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s2")
    action = ac.Action("tool:search", jcs_canonicalize_args({"q": "rust"}))
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()

    @guard_tool(enf, "tool:search")
    async def handler(q, ctx=None, **kwargs):
        return "ok"

    with pytest.raises(AccessDenied):
        asyncio.run(handler(q="rust", ctx=FakeCtx("s2"), extra="unbound",
                            **{PRESENTATION_ARG: pres}))


# -- 3. An empty evidence argument means "no evidence", not "malformed" ---------
# A tool that accepts optional evidence must declare it with a default, and over MCP that
# default is a string - which FastMCP materialises into EVERY call. Treating "" as a parse
# failure meant that merely OFFERING the approval path denied every ungated call.


def test_empty_evidence_argument_is_not_malformed():
    from agentcreds_runtime.fastmcp import _coerce_evidence

    assert _coerce_evidence(None) == []
    assert _coerce_evidence("") == []
    assert _coerce_evidence([""]) == []


def test_offering_the_approval_path_does_not_break_ungated_calls():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:read"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)  # NO gate
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:read"], max_depth=0),
                                    300, agent)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s3")
    # The handler takes no tool arguments, so the binding covers the tool alone.
    action = ac.Action("tool:read", jcs_canonicalize_args({}))
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()

    @guard_tool(enf, "tool:read")
    async def handler(ctx=None, **kwargs):
        return "ok"

    # The tool declares the approval parameter and the caller supplies nothing for it.
    assert asyncio.run(handler(ctx=FakeCtx("s3"),
                               **{PRESENTATION_ARG: pres, EVIDENCE_ARG: "",
                                  CANON_PROFILE_ARG: CANON_PROFILE_JCS})) == "ok"


# -- 4. R10 one-time reliance must not depend on opt-in configuration ----------
# `consumed_approvals=None` made `_commit_reliance` a no-op returning True, so "MUST be
# relied upon at most once" failed OPEN on a default. Observed against the live PEP: the
# same evidence was accepted twice.


def test_one_time_reliance_holds_with_no_explicit_store():
    anchor, agent, vc, token = _gated_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # deliberately NOT passing consumed_approvals
    challenge = enf.issue_challenge("s4")

    action = ac.Action("tool:pay", jcs_canonicalize_args({}))
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator", "appr-default", now + 300, anchor)

    first = enf.authorize("s4", "tool:pay", {}, present(token, vc, challenge, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))),
                          approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert first.allowed, first.reason

    second = enf.authorize("s4", "tool:pay", {}, present(token, vc, challenge, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))),
                           approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert second.denied and second.code == CODE_ALREADY_CONSUMED
    assert "already been relied upon" in second.reason


def test_reliance_ledger_can_still_be_disabled_deliberately():
    # `False` is the explicit opt-out, so the unsafe posture has to be typed out rather
    # than inherited from a default.
    anchor, agent, vc, token = _gated_world()
    enf = IdentityEnforcer(anchor, consumed_approvals=False, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s5")

    action = ac.Action("tool:pay", jcs_canonicalize_args({}))
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator", "appr-off", now + 300, anchor)

    for _ in range(2):
        d = enf.authorize("s5", "tool:pay", {}, present(token, vc, challenge, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))),
                          approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
        assert d.allowed, d.reason


def test_a_falsy_custom_store_is_still_used():
    # The opt-out is `is False`, not truthiness. A caller's store that reports empty as
    # falsy must still be honoured - resolving it by truthiness would silently drop the
    # ledger and re-open the hole this whole section exists to close.
    class EmptyIsFalsy:
        def __init__(self):
            self.seen = set()

        def __len__(self):  # falsy while empty
            return len(self.seen)

        def try_consume(self, approval_id, not_after=None):
            if approval_id in self.seen:
                return False
            self.seen.add(approval_id)
            return True

    anchor, agent, vc, token = _gated_world()
    store = EmptyIsFalsy()
    assert not store  # precondition: falsy at construction
    enf = IdentityEnforcer(anchor, consumed_approvals=store, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s6")

    action = ac.Action("tool:pay", jcs_canonicalize_args({}))
    now = int(time.time())
    ev = ac.ApprovalEvidence.approve(action, "operator", "appr-falsy", now + 300, anchor)

    assert enf.authorize("s6", "tool:pay", {}, present(token, vc, challenge, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))),
                         approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS).allowed
    second = enf.authorize("s6", "tool:pay", {}, present(token, vc, challenge, agent, action=ac.Action("tool:pay", jcs_canonicalize_args({}))),
                           approval_evidence=[ev], canonicalization_profile=CANON_PROFILE_JCS)
    assert second.denied and second.code == CODE_ALREADY_CONSUMED


# -- 5. The canonicalization profile default (2026-08-13) ----------------------
# Same shape as the four above: JCS was reachable but `json-sorted-v1` was the default,
# so every test that configured a profile explicitly passed while the out-of-the-box
# pairing was the one that breaks across languages. The default is now JCS. These two
# pin what that means in both directions.


def _bound_world(tool="tool:search"):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[tool], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=[tool], max_depth=0), 300, agent)
    return anchor, agent, vc, token


def _bound_call(enf, agent, vc, token, session, args, **reserved):
    challenge = enf.issue_challenge(session)
    action = ac.Action("tool:search", jcs_canonicalize_args(args))
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()

    @guard_tool(enf, "tool:search")
    async def handler(q, ctx=None, **kwargs):
        return "ok"

    return handler(q=args["q"], ctx=FakeCtx(session),
                   **{PRESENTATION_ARG: pres, **reserved})


def test_a_bound_holder_that_declares_nothing_is_refused_with_a_reason():
    """The strict posture, on by default since 2026-08-13.

    Before JCS became the default, silence was harmless - the default profile was the
    same thing a legacy holder computed, so it matched by accident. Now silence means
    the two sides may compute different bindings, and only for non-ASCII strings and
    floats, so it passes testing and fails on the first accented name. Refusing up front
    with a named reason beats an undiagnosable `possession_failed`.
    """
    anchor, agent, vc, token = _bound_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # defaults: JCS, profile required

    with pytest.raises(AccessDenied) as exc:
        asyncio.run(_bound_call(enf, agent, vc, token, "declare-1", {"q": "café"}))
    assert exc.value.code == CODE_CANON_PROFILE
    assert "no canonicalization profile declared" in exc.value.decision.reason


def test_declaring_the_profile_is_all_that_was_missing():
    # The other half, so the test above is not passing for some unrelated reason.
    anchor, agent, vc, token = _bound_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    assert asyncio.run(_bound_call(
        enf, agent, vc, token, "declare-2", {"q": "café"},
        **{CANON_PROFILE_ARG: CANON_PROFILE_JCS},
    )) == "ok"


def test_an_unbound_presentation_needs_no_declaration():
    """The requirement applies to bound presentations only.

    An unbound one computed no binding string, so there is no profile to disagree
    about. Refusing it is `require_argument_binding`'s job, and this knob must not
    quietly start doing that as well.
    """
    anchor, agent, vc, token = _bound_world()
    # `require_argument_binding=False` so the unbound presentation reaches the profile
    # check at all - this test is about the profile knob, and the binding knob refusing
    # first would make it pass for the wrong reason.
    enf = IdentityEnforcer(anchor, config=PolicyConfig(
        revocation_check=False, require_argument_binding=False))
    challenge = enf.issue_challenge("unbound-1")
    pres = base64.b64encode(present(token, vc, challenge, agent)).decode()  # no action

    @guard_tool(enf, "tool:search")
    async def handler(q, ctx=None, **kwargs):
        return "ok"

    assert asyncio.run(handler(q="café", ctx=FakeCtx("unbound-1"),
                               **{PRESENTATION_ARG: pres})) == "ok"


def test_a_profile_this_verifier_does_not_compute_is_refused_as_a_profile_failure():
    """Not as `possession_failed`, which is what altered arguments look like.

    Both refuse, so the distinction is diagnostic rather than an authorization
    difference - but the diagnosis is the point: reported identically, every integration
    defect looks like an attack and every attack looks like an integration defect.
    """
    anchor, agent, vc, token = _bound_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))

    with pytest.raises(AccessDenied) as exc:
        asyncio.run(_bound_call(
            enf, agent, vc, token, "unknown-1", {"q": "café"},
            **{CANON_PROFILE_ARG: "agentcreds-someone-elses-v9"},
        ))
    assert exc.value.code == CODE_CANON_PROFILE
    assert "agentcreds-someone-elses-v9" in exc.value.decision.reason


def test_a_verifier_must_state_its_revocation_posture():
    """No default is possible, so silence is refused rather than interpreted.

    `consumed_approvals` could default safely because an in-process ledger exists to
    fall back on. A revocation source cannot be invented, so the old `None` default
    meant "accept every revoked credential" - on a config the docstring called a secure
    baseline. Both postures now have to be typed out.
    """
    anchor = ac.TrustAnchor.generate()
    with pytest.raises(ValueError, match="revocation_check"):
        IdentityEnforcer(anchor)
    with pytest.raises(ValueError, match="revocation_check"):
        IdentityEnforcer(anchor, config=PolicyConfig(max_age_secs=30))
    # `False` is the explicit opt-out, and it builds.
    assert IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False)) is not None
