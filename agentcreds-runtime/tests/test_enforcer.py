"""End-to-end tests for IdentityEnforcer against the real agentcreds wheel.

Each test plays both sides: it mints a token + credential (holder), drives the
enforcer (verifier), and asserts the allow/deny outcome and its code.
"""

import datetime

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    AccessDenied,
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    InMemoryReplayGuard,
    InMemorySessionStore,
    PolicyConfig,
    RedisSessionStore,
    anchor_resolver_from_registry,
    jcs_canonicalize_args,
    predicate_policy,
    present,
    revocation_check_from_list,
)
from agentcreds_runtime.errors import (
    CODE_CREDENTIAL,
    CODE_MALFORMED,
    CODE_NO_CHALLENGE,
    CODE_NOT_AUTHORIZED,
    CODE_POLICY,
    CODE_POSSESSION,
    CODE_PRINCIPAL,
    CODE_REPLAY,
    CODE_REVOKED,
    CODE_UNBOUND,
    CODE_UNTRUSTED_ISSUER,
)


def make_world(tools=("tool:search",), depth=2):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=list(tools), max_delegation_depth=depth, valid_for_secs=3600
    )
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=list(tools), budget_usd=100, max_depth=depth)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


def test_allow_happy_path():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(max_age_secs=60, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "rust"})))

    decision = enf.authorize("s1", "tool:search", {"q": "rust"}, presentation, canonicalization_profile=CANON_PROFILE_JCS)

    assert decision.allowed
    assert decision.code is None
    assert decision.chain and decision.chain[0].agent_did == agent.did
    assert "tool:search" in decision.chain[0].tools


def test_enforce_returns_chain_on_allow():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))

    chain = enf.enforce("s1", "tool:search", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert chain[0].agent_did == agent.did


def test_deny_no_challenge():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = ac.PopChallenge("mcp://elsewhere").to_cbor()
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))

    # Never issued a challenge for "s1".
    decision = enf.authorize("s1", "tool:search", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_NO_CHALLENGE


def test_deny_malformed_presentation():
    anchor, _agent, _vc, _token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, b"not a presentation", canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_MALFORMED


def test_deny_tool_not_in_scope():
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:admin", jcs_canonicalize_args({})))

    decision = enf.authorize("s1", "tool:admin", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_NOT_AUTHORIZED


def test_deny_wrong_anchor():
    _anchor, agent, vc, token = make_world()
    other_anchor = ac.TrustAnchor.generate()
    enf = IdentityEnforcer(other_anchor, config=PolicyConfig(revocation_check=False))  # not the issuer
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))

    decision = enf.authorize("s1", "tool:search", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_CREDENTIAL


def test_deny_replay_after_challenge_rotation():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    # Server rotates the challenge; the captured presentation is now stale.
    enf.rotate_challenge("s1")

    decision = enf.authorize("s1", "tool:search", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POSSESSION


def test_enforce_raises_access_denied():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.issue_challenge("s1")
    with pytest.raises(AccessDenied) as exc:
        enf.enforce("s1", "tool:search", {}, b"garbage", canonicalization_profile=CANON_PROFILE_JCS)
    assert exc.value.code == CODE_MALFORMED


def test_attenuated_token_presented_by_subagent():
    # A delegated sub-agent presents its own (narrower) token: the leaf is the
    # sub-agent, so it must prove possession with the sub-agent key.
    anchor, agent, vc, token = make_world(tools=("tool:search", "tool:email"), depth=2)
    sub = ac.AgentIdentity.create_did_key()
    narrow = ac.Scope(tools=["tool:search"], budget_usd=10, max_depth=1)
    child = token.attenuate(narrow, 120, sub)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s2")
    presentation = present(child, vc, challenge, sub, action=ac.Action("tool:search", jcs_canonicalize_args({})))  # sub holds the leaf key

    allow = enf.authorize("s2", "tool:search", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    assert allow.allowed
    assert allow.chain[-1].agent_did == sub.did
    # tool:email was attenuated away at this hop.
    deny = enf.authorize("s2", "tool:email", {}, present(child, vc, challenge, sub, action=ac.Action("tool:email", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert deny.denied and deny.code == CODE_NOT_AUTHORIZED


def test_audit_hook_fires_on_allow_and_optionally_deny():
    anchor, agent, vc, token = make_world()
    records = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(audit=records.append, audit_denied=True, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    presentation = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"})))

    enf.authorize("s1", "tool:search", {"q": "x"}, presentation, canonicalization_profile=CANON_PROFILE_JCS)
    enf.authorize("s1", "tool:admin", {}, presentation, canonicalization_profile=CANON_PROFILE_JCS)  # denied

    assert len(records) == 2
    assert records[0].allowed and records[0].tool == "tool:search"
    assert (not records[1].allowed) and records[1].code == CODE_NOT_AUTHORIZED


def test_adr_sink_emits_allow_and_deny_with_signals():
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    adrs = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=adrs.append, revocation_check=False))
    challenge = enf.issue_challenge("s1")

    enf.authorize("s1", "tool:search", {"q": "x"}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"}))), canonicalization_profile=CANON_PROFILE_JCS)
    enf.authorize("s1", "tool:admin", {}, present(token, vc, challenge, agent, action=ac.Action("tool:admin", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)  # denied

    assert len(adrs) == 2
    allow_adr, deny_adr = adrs

    assert allow_adr.allowed and allow_adr.decision == "allow"
    assert allow_adr.kind == "presentation"
    assert allow_adr.subject_did == agent.did
    assert allow_adr.action == "tool:search"
    assert allow_adr.signals == []
    assert allow_adr.vc_id and allow_adr.vc_id == deny_adr.vc_id  # correlation id

    assert not deny_adr.allowed
    assert deny_adr.signals == ["action_denied"]
    assert deny_adr.reason


def test_adr_carries_the_accountable_party_from_the_credential():
    """The accountable party is a claim on the CREDENTIAL, and `from_token` builds
    the record from the token - so this was `None` on every decision the deployed
    PEP ever recorded, and "who answers for this action" fell back to a join on
    `vc_id`, which is the join the field exists to remove.

    Asserted on both allow and deny: a denied call is exactly when an auditor most
    wants to know whose agent tried it."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600,
        accountable_party="team:payments-platform",
    )
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=0), 300, agent)

    adrs = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=adrs.append, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    enf.authorize("s1", "tool:search", {"q": "x"}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"}))), canonicalization_profile=CANON_PROFILE_JCS)
    enf.authorize("s1", "tool:admin", {}, present(token, vc, challenge, agent, action=ac.Action("tool:admin", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)  # denied

    assert len(adrs) == 2
    for adr in adrs:
        assert adr.accountable_party == "team:payments-platform"
        # Who answers and how firmly are one question - never one without the other.
        assert adr.accountability_source is not None


def test_decision_record_id_pairs_a_decision_with_its_effect():
    """`vc_id` correlates to the CREDENTIAL, so every call under it shares one -
    enough to say an agent could have caused an effect, never that it did. The
    per-call record id is what makes the pairing exact.

    The negative half is the point: assert the two calls DO share a vc_id, so the
    reason the record id is needed stays visible."""
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    adrs = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=adrs.append, revocation_check=False))

    def call(q):
        challenge = enf.issue_challenge("s1")
        return enf.authorize("s1", "tool:search", {"q": q},
                             present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": q}))), canonicalization_profile=CANON_PROFILE_JCS)

    d1, d2 = call("first"), call("second")

    assert d1.allowed and d2.allowed
    assert adrs[0].vc_id == adrs[1].vc_id, "same credential - insufficient on its own"
    assert d1.record_id and d2.record_id
    assert d1.record_id != d2.record_id
    assert [a.id for a in adrs] == [d1.record_id, d2.record_id]


def test_record_id_is_none_when_nothing_records():
    """No sink, no stream, no id - rather than a fabricated one that resolves to
    nothing. A caller logging it against an effect must be able to tell the
    difference between "decision urn:adr:x" and "not recorded"."""
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(max_age_secs=60, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    d = enf.authorize("s1", "tool:search", {"q": "x"}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert d.allowed and d.record_id is None


def test_adr_for_undecodable_presentation_has_no_subject():
    anchor, *_ = make_world()
    adrs = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=adrs.append, revocation_check=False))
    enf.issue_challenge("s1")
    enf.authorize("s1", "tool:search", {}, b"garbage", canonicalization_profile=CANON_PROFILE_JCS)

    assert len(adrs) == 1
    assert not adrs[0].allowed
    assert adrs[0].subject_did == ""
    assert adrs[0].signals == ["signature_invalid"]


def _world_with_status(index=7, list_url="https://issuer.example/revocation/1"):
    """A world whose credential carries an OAuth Status List entry, plus the issuer's
    (initially empty) revocation list."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600
    )
    rev_list = ac.RevocationList(list_url, anchor, 1024)
    status = ac.CredentialStatus(list_url, index)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, status)
    scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=1)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token, rev_list


def test_revoked_credential_is_denied():
    anchor, agent, vc, token, rev_list = _world_with_status(index=7)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=revocation_check_from_list(rev_list, anchor)))
    challenge = enf.issue_challenge("s1")

    # Valid and not revoked -> allowed.
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed

    # The issuer revokes the credential's slot -> the same presentation is denied.
    rev_list.revoke(7, anchor)
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_REVOKED


def test_stale_signed_revocation_list_is_denied():
    # R7 bounded staleness of the *signed state*: a validly-signed list whose
    # `updated` timestamp is older than max_signed_age is rejected regardless of
    # revocation-bit state or any fetch cache - the frozen-issuer / replayed-old-
    # list case a fetch-recency bound cannot catch. Fails closed (CODE_REVOKED).
    anchor, agent, vc, token, rev_list = _world_with_status(index=7)

    # A generous bound: the fresh, unrevoked list passes.
    enf_ok = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=revocation_check_from_list(rev_list, anchor, max_signed_age=datetime.timedelta(hours=1))))
    ch_ok = enf_ok.issue_challenge("s1")
    assert enf_ok.authorize("s1", "tool:search", {}, present(token, vc, ch_ok, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed

    # A bound nothing can satisfy: every signed state is "too old" -> deny, even though
    # nothing is revoked.
    #
    # NOT timedelta(0), which was flaky. The check is `age > max_signed_age`, so a zero
    # bound needs age strictly positive - but `updated` is stamped by Rust's Utc::now()
    # and read against Python's datetime.now(), and those two clock reads straddle each
    # other by a few hundred microseconds. Age therefore comes out negative about half
    # the time and the list looks fresh. A negative bound expresses the same intent
    # ("no staleness is acceptable") without racing clock granularity.
    enf_strict = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=revocation_check_from_list(rev_list, anchor, max_signed_age=datetime.timedelta(seconds=-1))))
    ch_s = enf_strict.issue_challenge("s2")
    decision = enf_strict.authorize("s2", "tool:search", {}, present(token, vc, ch_s, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_REVOKED


def test_revocation_emits_revoked_adr_signal():
    anchor, agent, vc, token, rev_list = _world_with_status(index=3)
    rev_list.revoke(3, anchor)
    adrs = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_sink=adrs.append, revocation_check=revocation_check_from_list(rev_list, anchor)))
    challenge = enf.issue_challenge("s1")
    enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert len(adrs) == 1
    assert not adrs[0].allowed
    assert adrs[0].signals == ["revoked"]


def test_credential_without_status_is_allowed():
    # `make_world` issues a credential with no status entry -> never revoked.
    anchor, agent, vc, token = make_world()
    list_url = "https://issuer.example/revocation/1"
    rev_list = ac.RevocationList(list_url, anchor, 1024)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=revocation_check_from_list(rev_list, anchor)))
    challenge = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_revocation_check_error_fails_closed_by_default():
    anchor, agent, vc, token = make_world()

    def boom(_credential):
        raise RuntimeError("revocation list unreachable")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=boom))
    challenge = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_REVOKED


def test_revocation_check_error_can_fail_open():
    anchor, agent, vc, token = make_world()

    def boom(_credential):
        raise RuntimeError("revocation list unreachable")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=boom, fail_open_on_revocation_error=True))
    challenge = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed


def _obo_world(
    tools=("tool:read_email",),
    resources=("mailbox:alice@acme.com/42",),
    authority=("mailbox:alice@acme.com/*",),
):
    """An on-behalf-of world: a credential bound to a human principal, and a
    resource-scoped token minted from it."""
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    human = ac.HumanIdentity.from_idp("https://login.acme.com", "auth0|alice")
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    auth = human.authorize(exp, list(tools), list(authority))
    claims = ac.CapabilityClaims(
        tools=list(tools), max_delegation_depth=1, valid_for_secs=3600, on_behalf_of=auth
    )
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=list(tools), max_depth=1, resources=list(resources))
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, human, vc, token


def test_obo_allows_with_bound_principal_and_resource():
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", human.did)
    challenge = enf.issue_challenge("s1")

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.allowed


def test_obo_denied_without_bound_principal():
    # An on-behalf-of token cannot be used without an authenticated human session.
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")  # no bind_principal

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.denied
    assert decision.code == CODE_PRINCIPAL


def test_obo_denied_with_wrong_principal():
    # The confused-deputy guard: a session for a different human cannot drive an
    # agent whose token is bound to Alice.
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", "did:web:evil.example")
    challenge = enf.issue_challenge("s1")

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.denied
    assert decision.code == CODE_PRINCIPAL


def test_obo_denied_for_unlisted_resource():
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", human.did)
    challenge = enf.issue_challenge("s1")

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:bob@acme.com/1")),
        resource="mailbox:bob@acme.com/1",  # Bob's mailbox - not in scope
        canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.denied
    assert decision.code == CODE_NOT_AUTHORIZED


def test_obo_denied_when_resource_omitted():
    # A resource-scoped token requires the call to name a permitted resource.
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", human.did)
    challenge = enf.issue_challenge("s1")

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS,
    )  # no resource
    assert decision.denied
    assert decision.code == CODE_NOT_AUTHORIZED


def test_obo_clear_session_unbinds_principal():
    anchor, agent, human, vc, token = _obo_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", human.did)
    enf.clear_session("s1")
    challenge = enf.issue_challenge("s1")

    decision = enf.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.denied
    assert decision.code == CODE_PRINCIPAL


def test_non_obo_token_unaffected_by_acting_for():
    # A plain (non-OBO) token works whether or not a principal is bound.
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.bind_principal("s1", "did:web:somebody")  # ignored by a non-OBO token
    challenge = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def _bound_present(token, vc, challenge, agent, tool, arguments, resource=None):
    """Holder side: build a presentation bound to the exact request the server
    will reconstruct (same canonicalization)."""
    action = ac.Action(tool, jcs_canonicalize_args(arguments), resource=resource)
    return present(token, vc, challenge, agent, action=action)


def test_argument_binding_allows_matching_request():
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    enf = IdentityEnforcer(anchor, config=PolicyConfig(require_argument_binding=True, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = _bound_present(token, vc, challenge, agent, "tool:transfer", {"amount": 10})

    decision = enf.authorize("s1", "tool:transfer", {"amount": 10}, pres, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed


def test_argument_binding_denies_tampered_arguments():
    # A presentation bound to amount=10 cannot be reused for amount=1000000.
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    enf = IdentityEnforcer(anchor, config=PolicyConfig(require_argument_binding=True, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = _bound_present(token, vc, challenge, agent, "tool:transfer", {"amount": 10})

    decision = enf.authorize("s1", "tool:transfer", {"amount": 1000000}, pres, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POSSESSION


def test_require_argument_binding_rejects_unbound_presentation():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(require_argument_binding=True, revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = present(token, vc, challenge, agent)  # unbound - no action

    decision = enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNBOUND


def test_unbound_presentation_allowed_when_not_required():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # default: binding not required
    challenge = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_bound_presentation_is_held_to_action_even_when_not_required():
    # Binding is enforced whenever present, independent of the require flag.
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # not requiring binding
    challenge = enf.issue_challenge("s1")
    pres = _bound_present(token, vc, challenge, agent, "tool:transfer", {"amount": 10})

    assert enf.authorize("s1", "tool:transfer", {"amount": 10}, pres, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:transfer", {"amount": 999}, pres, canonicalization_profile=CANON_PROFILE_JCS).denied


# -- Contextual policy hook (ABAC, post-verify gate) ---------------------------


def test_policy_hook_allows_when_condition_met():
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))

    def cap_amount(pin):
        return "amount exceeds limit" if (pin.arguments or {}).get("amount", 0) > 100 else None

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=predicate_policy({"tool:transfer": cap_amount}), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 50}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 50}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed


def test_policy_hook_denies_with_reason_and_code():
    # The capability grants tool:transfer; the policy adds a per-argument condition
    # the credential can't express.
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))

    def cap_amount(pin):
        return "amount exceeds limit" if (pin.arguments or {}).get("amount", 0) > 100 else None

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=predicate_policy({"tool:transfer": cap_amount}), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 1000}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 1000}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POLICY
    assert "exceeds" in decision.reason
    # The verified chain is still attached to the denial, for audit.
    assert decision.chain and decision.chain[-1].agent_did == agent.did


def test_policy_hook_sees_verified_context():
    # The hook receives the OIDC-bound principal, the request, and the verified
    # chain - the three authority inputs combined.
    anchor, agent, human, vc, token = _obo_world()
    seen = {}

    def hook(pin):
        seen.update(
            principal=pin.principal, tool=pin.tool,
            arguments=pin.arguments, chain_leaf=pin.chain[-1].agent_did,
        )
        return None

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=hook, revocation_check=False))
    enf.bind_principal("s1", human.did)
    ch = enf.issue_challenge("s1")
    decision = enf.authorize(
        "s1", "tool:read_email", {"folder": "inbox"}, present(token, vc, ch, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({"folder": "inbox"}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.allowed
    assert seen["principal"] == human.did
    assert seen["tool"] == "tool:read_email"
    assert seen["arguments"] == {"folder": "inbox"}
    assert seen["chain_leaf"] == agent.did


def test_policy_hook_not_consulted_before_authority_proven():
    # A call denied by the capability (out of scope) must never reach the policy
    # gate - policy refines authority, it can't grant it.
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    calls = []

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=lambda pin: calls.append(pin.tool) or None, revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:admin", {}, present(token, vc, ch, agent, action=ac.Action("tool:admin", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_NOT_AUTHORIZED
    assert calls == []  # hook never ran


def test_policy_hook_error_fails_closed_by_default():
    anchor, agent, vc, token = make_world()

    def boom(_pin):
        raise RuntimeError("policy engine unreachable")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=boom, revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POLICY


def test_policy_hook_error_can_fail_open():
    anchor, agent, vc, token = make_world()

    def boom(_pin):
        raise RuntimeError("policy engine unreachable")

    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=boom, fail_open_on_policy_error=True, revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_predicate_policy_allows_tool_without_a_rule():
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    # Only tool:transfer has a (deny-all) rule; tool:search has none -> allowed.
    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=predicate_policy({"tool:transfer": lambda _p: "no"}), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_policy_denial_emits_action_denied_adr_and_audit():
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    adrs, records = [], []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=predicate_policy({"tool:transfer": lambda _p: "blocked by policy"}), adr_sink=adrs.append, audit=records.append, audit_denied=True, revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:transfer", {"amount": 5}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 5}))), canonicalization_profile=CANON_PROFILE_JCS)

    assert decision.denied and decision.code == CODE_POLICY
    assert len(adrs) == 1 and not adrs[0].allowed and adrs[0].signals == ["action_denied"]
    assert len(records) == 1 and not records[0].allowed and records[0].code == CODE_POLICY


class _FakeRedis:
    """Minimal in-process stand-in for the Redis methods RedisSessionStore uses."""

    def __init__(self):
        self.kv = {}

    def setex(self, key, ttl, value):
        self.kv[key] = value

    def get(self, key):
        return self.kv.get(key)

    def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)


def test_shared_session_store_works_across_replicas():
    # A challenge issued on one replica is honoured on another sharing the store.
    anchor, agent, vc, token = make_world()
    store = InMemorySessionStore()
    replica_1 = IdentityEnforcer(anchor, session_store=store, config=PolicyConfig(revocation_check=False))
    replica_2 = IdentityEnforcer(anchor, session_store=store, config=PolicyConfig(revocation_check=False))

    challenge = replica_1.issue_challenge("s1")
    pres = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert replica_2.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_shared_store_shares_principal_binding_across_replicas():
    anchor, agent, human, vc, token = _obo_world()
    store = InMemorySessionStore()
    replica_1 = IdentityEnforcer(anchor, session_store=store, config=PolicyConfig(revocation_check=False))
    replica_2 = IdentityEnforcer(anchor, session_store=store, config=PolicyConfig(revocation_check=False))

    replica_1.bind_principal("s1", human.did)          # bound on replica 1
    challenge = replica_2.issue_challenge("s1")          # challenge from replica 2
    decision = replica_2.authorize(
        "s1", "tool:read_email", {}, present(token, vc, challenge, agent, action=ac.Action("tool:read_email", jcs_canonicalize_args({}), resource="mailbox:alice@acme.com/42")),
        resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS,
    )
    assert decision.allowed  # replica 2 saw replica 1's principal binding


def test_expired_session_challenge_is_evicted():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, session_store=InMemorySessionStore(ttl_secs=0), config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    decision = enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_NO_CHALLENGE


def test_in_memory_store_roundtrip_and_clear():
    store = InMemorySessionStore()
    store.put_challenge("s1", b"chal")
    store.put_principal("s1", "did:web:alice")
    assert store.get_challenge("s1") == b"chal"
    assert store.get_principal("s1") == "did:web:alice"
    store.clear("s1")
    assert store.get_challenge("s1") is None
    assert store.get_principal("s1") is None


def test_redis_session_store_roundtrip():
    store = RedisSessionStore(_FakeRedis(), ttl_secs=60, namespace="t")
    store.put_challenge("s1", b"chal")
    store.put_principal("s1", "did:web:alice")
    assert store.get_challenge("s1") == b"chal"
    assert store.get_principal("s1") == "did:web:alice"
    store.clear("s1")
    assert store.get_challenge("s1") is None
    assert store.get_principal("s1") is None


def test_enforcer_with_redis_store_authorizes():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, session_store=RedisSessionStore(_FakeRedis()), config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_multi_issuer_accepts_registered_and_rejects_unregistered():
    # Two issuing orgs; the registry trusts only the first.
    anchor_a, agent_a, vc_a, token_a = make_world()
    anchor_b, agent_b, vc_b, token_b = make_world()

    registry = ac.TrustRegistry()
    registry.minimum_trust_level = "verified"
    registry.register(ac.TrustEntry(anchor_a.did, "Org A", anchor_a.public_key, "verified"))

    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_registry(registry), config=PolicyConfig(revocation_check=False))

    # Org A's credential (registered) is accepted.
    ch_a = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token_a, vc_a, ch_a, agent_a, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed

    # Org B's credential (not registered) is rejected.
    ch_b = enf.issue_challenge("s2")
    decision = enf.authorize("s2", "tool:search", {}, present(token_b, vc_b, ch_b, agent_b, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER


def test_registry_below_minimum_trust_level_is_rejected():
    anchor, agent, vc, token = make_world()
    registry = ac.TrustRegistry()
    registry.minimum_trust_level = "authoritative"
    # Registered, but only at "verified" - below the required "authoritative".
    registry.register(ac.TrustEntry(anchor.did, "Org", anchor.public_key, "verified"))

    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_registry(registry), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER


def test_anchor_for_returning_none_denies_as_untrusted():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor_for=lambda _credential: None, config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER


def test_enforcer_requires_anchor_or_resolver():
    with pytest.raises(ValueError):
        IdentityEnforcer(config=PolicyConfig(revocation_check=False))


def test_mcp_replay_guard_rejects_reused_presentation():
    # With per-session challenge reuse the presentation bytes are identical, so a
    # configured replay guard rejects the second use.
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, replay_guard=InMemoryReplayGuard(), config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS).code == CODE_REPLAY


def test_mcp_replay_guard_allows_after_rotation():
    # The intended pattern: rotate the challenge per call -> a fresh presentation.
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, replay_guard=InMemoryReplayGuard(), config=PolicyConfig(revocation_check=False))
    c1 = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, c1, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    c2 = enf.rotate_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, c2, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_mcp_no_replay_guard_allows_reuse():
    # Default (no guard): the per-session presentation may be reused across calls.
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s1")
    pres = present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:search", {}, pres, canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_adr_stream_chains_and_checkpoints():
    anchor, agent, vc, token = make_world()
    stream = ac.AdrStream()
    forwarded = []
    enf = IdentityEnforcer(anchor, config=PolicyConfig(adr_stream=stream, adr_sink=forwarded.append, revocation_check=False))
    challenge = enf.issue_challenge("s1")

    for _ in range(3):
        enf.authorize("s1", "tool:search", {}, present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)

    assert stream.count() == 3
    assert [a.seq for a in forwarded] == [0, 1, 2]

    # The stamped records replay to the stream's signed head - tamper-evident.
    checkpoint = stream.sign_checkpoint(anchor)
    checkpoint.verify(anchor)  # raises on failure
    assert ac.AdrStream.replay(forwarded) == checkpoint.head
    # Dropping a record breaks the match.
    assert ac.AdrStream.replay(forwarded[:2]) != checkpoint.head
