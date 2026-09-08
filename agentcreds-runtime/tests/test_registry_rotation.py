"""Cross-organizational rotation: a member rotates, the framework re-signs nothing.

Without this, a member org that rotates its anchor is refused by every relying party
until the trust framework re-signs the registry and every party re-imports it - a
multilateral event caused by one member's own key hygiene. The registry pins the member's
stable ROOT; the member's signed key history carries the rotation.

Each accept case below is paired with a control, because "accepts the rotated key" and
"accepts anything" produce identical results on the positive cases alone.
"""

from datetime import datetime, timedelta, timezone

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    PolicyConfig,
    CANON_PROFILE_JCS,
    jcs_canonicalize_args,
    IdentityEnforcer,
    anchor_resolver_from_registry,
    present,
)
from agentcreds_runtime.errors import CODE_UNTRUSTED_ISSUER


def member(level="verified", hops=1):
    """A framework member registered by its ROOT, having rotated `hops` times."""
    anchors = [ac.TrustAnchor.create_did_key() for _ in range(hops + 1)]
    history = ac.KeyHistory.genesis(anchors[0])
    for old, new in zip(anchors, anchors[1:]):
        history.push(ac.RotationStatement.issue(old, new))
    history.seal(anchors[-1], 1)
    entry = ac.TrustEntry(anchors[0].did, "Member", anchors[0].public_key, level)
    return anchors, history, entry


def registry_with(entry, minimum="verified"):
    reg = ac.TrustRegistry()
    reg.register(entry)
    reg.minimum_trust_level = minimum
    return reg


def credential_from(anchor):
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:echo"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    return ac.CapabilityCredential.issue(anchor, agent.did, claims, None), agent


def test_rotated_member_resolves_without_re_registering():
    anchors, history, entry = member()
    reg = registry_with(entry)
    resolve = anchor_resolver_from_registry(reg, [history])

    vc, _ = credential_from(anchors[-1])  # issued by the CURRENT key
    anchor = resolve(vc)
    assert anchor is not None, "post-rotation issuer must resolve via the member's history"
    vc.verify(anchor)


def test_without_the_history_the_same_credential_is_refused():
    """The control. Registry mode as it stands today refuses a rotated member, so the
    test above demonstrates a real change rather than a permissive resolver."""
    anchors, _history, entry = member()
    reg = registry_with(entry)
    resolve = anchor_resolver_from_registry(reg)  # no histories supplied

    vc, _ = credential_from(anchors[-1])
    assert resolve(vc) is None


def test_unregistered_member_is_refused_even_with_a_valid_history():
    """A well-formed history is not membership. The root must be in the registry."""
    anchors, history, _entry = member()
    reg = registry_with(
        ac.TrustEntry(
            ac.TrustAnchor.create_did_key().did, "Someone else",
            ac.TrustAnchor.create_did_key().public_key, "verified",
        )
    )
    resolve = anchor_resolver_from_registry(reg, [history])
    vc, _ = credential_from(anchors[-1])
    assert resolve(vc) is None


def test_rotation_cannot_escape_the_minimum_trust_level():
    """The security-relevant case: the gate applies to the ROOT entry, so a member
    cannot promote itself by rotating."""
    anchors, history, entry = member(level="self_asserted")
    reg = registry_with(entry, minimum="verified")
    resolve = anchor_resolver_from_registry(reg, [history])

    vc, _ = credential_from(anchors[-1])
    assert resolve(vc) is None, "a self_asserted member cleared an 'verified' minimum"

    # Control: lower the bar and the same credential resolves, so the refusal above is
    # attributable to the trust level.
    reg.minimum_trust_level = "self_asserted"
    assert anchor_resolver_from_registry(reg, [history])(vc) is not None


def test_repudiated_key_is_refused_cross_org():
    anchors, history, entry = member()
    root, current = anchors[0], anchors[-1]
    vc_old, _ = credential_from(root)
    vc_new, _ = credential_from(current)

    history.repudiate(root.did)
    history.seal(current, 2)
    resolve = anchor_resolver_from_registry(registry_with(entry), [history])

    assert resolve(vc_old) is None, "repudiated key resolved"
    assert resolve(vc_new) is not None, "repudiating one key disabled the member"


def test_expired_history_is_refused_cross_org():
    anchors, history, entry = member()
    history.seal(anchors[-1], 2, datetime.now(timezone.utc) - timedelta(hours=1))
    resolve = anchor_resolver_from_registry(registry_with(entry), [history])
    vc, _ = credential_from(anchors[-1])
    assert resolve(vc) is None


def test_a_non_rotating_member_is_unaffected():
    """Migration safety: an org that has never rotated has root == current, so an
    existing registry keeps working with no history at all."""
    anchor = ac.TrustAnchor.create_did_key()
    entry = ac.TrustEntry(anchor.did, "Static", anchor.public_key, "verified")
    resolve = anchor_resolver_from_registry(registry_with(entry))
    vc, _ = credential_from(anchor)
    assert resolve(vc) is not None


def test_enforcer_accepts_a_rotated_member_end_to_end():
    anchors, history, entry = member()
    vc, agent = credential_from(anchors[-1])
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )
    enf = IdentityEnforcer(
        anchor_for=anchor_resolver_from_registry(
            registry_with(entry), [history]
        ), config=PolicyConfig(revocation_check=False)
    )
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed, decision.reason


def test_enforcer_denies_a_non_member_with_the_specific_code():
    anchors, history, entry = member()
    stranger = ac.TrustAnchor.create_did_key()
    vc, agent = credential_from(stranger)
    token = ac.DelegationToken.mint(
        vc, ac.Scope(tools=["tool:echo"], max_depth=0), 300, agent
    )
    enf = IdentityEnforcer(
        anchor_for=anchor_resolver_from_registry(
            registry_with(entry), [history]
        ), config=PolicyConfig(revocation_check=False)
    )
    ch = enf.issue_challenge("s2")
    decision = enf.authorize("s2", "tool:echo", {}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_UNTRUSTED_ISSUER, decision.reason
