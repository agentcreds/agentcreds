"""Anchor resolution that follows a signed key-history chain.

A `did:key` anchor's identity IS its public key, so rotating the key yields a new DID.
Pinning the current DID therefore makes every rotation a breaking change for every
relying party. These tests fix the alternative: pin the ROOT once and follow the chain.

The negatives carry the weight. A resolver that returned an anchor unconditionally would
satisfy the accept cases and be worthless, so every reject case below names a distinct
way the chain can fail to authorize an issuer.
"""

import json
from datetime import datetime, timedelta, timezone

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    PolicyConfig,
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    anchor_resolver_from_key_history,
    jcs_canonicalize_args,
    present,
)
from agentcreds_runtime.errors import CODE_UNTRUSTED_ISSUER


def rotated_org(hops=1):
    """An org that has rotated its anchor `hops` times, with the history to prove it."""
    anchors = [ac.TrustAnchor.create_did_key() for _ in range(hops + 1)]
    history = ac.KeyHistory.genesis(anchors[0])
    for old, new in zip(anchors, anchors[1:]):
        history.push(ac.RotationStatement.issue(old, new))
    # `authorize_issuer` requires a seal: the repudiations and expiry it consults are
    # strippable otherwise. The CURRENT key signs.
    history.seal(anchors[-1], 1)
    return anchors, history


def credential_from(anchor, agent, tools=("tool:echo",)):
    claims = ac.CapabilityClaims(
        tools=list(tools), max_delegation_depth=1, valid_for_secs=3600
    )
    return ac.CapabilityCredential.issue(anchor, agent.did, claims, None)


# -- accept --------------------------------------------------------------------


def test_credential_from_the_current_key_resolves():
    (root, current), history = rotated_org()
    resolve = anchor_resolver_from_key_history(history, root.did)

    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(current, agent)

    anchor = resolve(vc)
    assert anchor is not None, "the post-rotation key must resolve from the pinned root"
    vc.verify(anchor)  # and the anchor it returns must actually verify the credential


def test_credential_from_a_superseded_key_still_resolves():
    """Planned rotation does not invalidate what the old key already signed - a
    credential issued before the rotation must keep verifying until its own expiry."""
    (root, _current), history = rotated_org()
    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(root, agent)  # issued by the ROOT, before rotating

    anchor = anchor_resolver_from_key_history(history, root.did)(vc)
    assert anchor is not None
    vc.verify(anchor)


def test_resolves_across_several_rotations():
    anchors, history = rotated_org(hops=3)
    resolve = anchor_resolver_from_key_history(history, anchors[0].did)
    agent = ac.AgentIdentity.create_did_key()
    # every key the org has held must authorize
    for a in anchors:
        assert resolve(credential_from(a, agent)) is not None, f"{a.did} should authorize"


# -- reject --------------------------------------------------------------------


def test_issuer_outside_the_history_is_refused():
    (root, _current), history = rotated_org()
    stranger = ac.TrustAnchor.create_did_key()
    agent = ac.AgentIdentity.create_did_key()

    resolve = anchor_resolver_from_key_history(history, root.did)
    assert resolve(credential_from(stranger, agent)) is None


def test_history_rooted_elsewhere_is_refused():
    """The pin is what makes the chain meaningful. A history that does not begin at the
    pinned root must not authorize anything, however well-formed it is internally."""
    (root, _current), history = rotated_org()
    other_root = ac.TrustAnchor.create_did_key()
    agent = ac.AgentIdentity.create_did_key()

    resolve = anchor_resolver_from_key_history(history, other_root.did)
    assert resolve(credential_from(root, agent)) is None


def test_unchained_succession_cannot_be_appended():
    """`push` refuses a statement whose `previous_did` is not the current tip, so a
    succession from an unrelated key cannot be grafted on in the first place."""
    root = ac.TrustAnchor.create_did_key()
    attacker = ac.TrustAnchor.create_did_key()
    attacker_next = ac.TrustAnchor.create_did_key()

    history = ac.KeyHistory.genesis(root)
    with pytest.raises(Exception, match="chain"):
        history.push(ac.RotationStatement.issue(attacker, attacker_next))
    assert history.current_did() == root.did, "the tip must be unmoved"


def test_tampered_succession_is_refused():
    """The signature is what makes a succession an endorsement rather than a claim.

    This case has to be built by editing the serialized history: `push` verifies both
    linkage AND signature, so a forged link cannot be introduced through the API. An
    earlier version of this test used `push` and therefore only ever exercised the
    linkage check while claiming to test forgery - it passed because the history stayed
    empty, which is a different assertion entirely.
    """
    (root, current), history = rotated_org()
    attacker = ac.TrustAnchor.create_did_key()

    # Redirect the endorsement to the attacker's key. Linkage still looks right - the
    # statement still claims to come from the root - but the signature no longer covers
    # `next_did`, so chain verification must fail.
    doc = json.loads(history.to_json())
    doc["rotations"][0]["next_did"] = attacker.did
    tampered = ac.KeyHistory.from_json(json.dumps(doc))

    agent = ac.AgentIdentity.create_did_key()
    resolve = anchor_resolver_from_key_history(tampered, root.did)
    assert resolve(credential_from(attacker, agent)) is None, "forged successor authorized"
    # ...and the tamper invalidates the whole chain, not merely the attacker's entry.
    assert resolve(credential_from(current, agent)) is None


# -- seal, repudiation, freshness ----------------------------------------------


def test_unsealed_history_is_refused():
    """An unsealed history carries unauthenticated repudiations and expiry, so the
    resolver must refuse it rather than resolve through it."""
    root = ac.TrustAnchor.create_did_key()
    nxt = ac.TrustAnchor.create_did_key()
    history = ac.KeyHistory.genesis(root)
    history.push(ac.RotationStatement.issue(root, nxt))  # deliberately not sealed

    agent = ac.AgentIdentity.create_did_key()
    assert anchor_resolver_from_key_history(history, root.did)(credential_from(nxt, agent)) is None


def test_repudiated_issuer_is_refused_while_the_rest_still_resolves():
    (root, current), history = rotated_org()
    history.repudiate(root.did)
    history.seal(current, 2)

    agent = ac.AgentIdentity.create_did_key()
    resolve = anchor_resolver_from_key_history(history, root.did)
    assert resolve(credential_from(root, agent)) is None, "repudiated key authorized"
    # Control: without this, a resolver that refused everything would also pass above.
    assert resolve(credential_from(current, agent)) is not None
    assert history.active_dids() == [current.did]


def test_expired_seal_is_refused_though_authentic():
    (root, current), history = rotated_org()
    history.seal(current, 2, datetime.now(timezone.utc) - timedelta(hours=1))

    assert not history.is_current()
    history.verify_sealed(root.did)  # authentic - must not raise
    with pytest.raises(Exception):
        history.verify_current(root.did)

    agent = ac.AgentIdentity.create_did_key()
    assert anchor_resolver_from_key_history(history, root.did)(credential_from(current, agent)) is None


def test_enforcer_denies_a_repudiated_issuer():
    """Through the full enforcement path, with the specific denial code."""
    (root, current), history = rotated_org()
    history.repudiate(root.did)
    history.seal(current, 2)

    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(root, agent)  # issued by the now-repudiated key
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )
    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_key_history(history, root.did), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s4")
    decision = enf.authorize("s4", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER, decision.reason


# -- through the enforcement path ----------------------------------------------


def test_enforcer_authorizes_across_a_rotation():
    """The point of the whole exercise: a rotation must not break a relying party that
    pinned the root. Runs the full enforcement path, not just the resolver."""
    (root, current), history = rotated_org()
    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(current, agent)
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )

    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_key_history(history, root.did), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed, decision.reason


def test_enforcer_denies_an_issuer_outside_the_history():
    """The same path must refuse a stranger, with the SPECIFIC untrusted-issuer code -
    asserting only 'denied' would pass for any reason at all."""
    (root, _current), history = rotated_org()
    stranger = ac.TrustAnchor.create_did_key()
    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(stranger, agent)
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )

    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_key_history(history, root.did), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s2")
    decision = enf.authorize("s2", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER, decision.reason


def test_pinning_the_current_key_is_what_rotation_breaks():
    """The control for this entire feature. Pinning the CURRENT key - what a deployment
    does today - denies traffic after a rotation. Without this, the accept cases above
    would not demonstrate that anything was actually fixed."""
    (root, current), _history = rotated_org()
    agent = ac.AgentIdentity.create_did_key()
    vc = credential_from(current, agent)
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )

    # Pinned to the ROOT key, the pre-rotation configuration.
    enf = IdentityEnforcer(ac.TrustAnchor.from_did_key(root.did), config=PolicyConfig(revocation_check=False))
    ch = enf.issue_challenge("s3")
    decision = enf.authorize("s3", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied, "a stale pin should reject the post-rotation issuer"
