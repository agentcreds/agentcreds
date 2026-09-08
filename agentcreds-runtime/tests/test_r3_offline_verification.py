"""R3: identity verification makes no network call.

`draft-reece-wimse-cross-org-delegation-01` R3 requires a relying party to verify a
delegated identity **without a callback to the issuer**. That is the property this file
guards, and it is easy to erode by accident - three fetching caches were added to this
runtime (key history, approver directory, trust registry), each reachable from the
authorization path.

The distinction that keeps R3 true:

* **Verification** is pure. A `did:key` embeds its own public key, so checking a
  credential, token chain, proof of possession, rotation chain, approver directory or
  trust config is arithmetic over bytes already in hand. No resolver, no callback.
* **Acquisition** may fetch. Those caches obtain *signed artifacts* on a TTL. That is
  not identity resolution: nobody is asked "who is this DID?" - and whatever arrives is
  verified offline against something pinned before it is believed.

So a PEP configured with its artifacts in hand performs the entire authorization decision
with the network unplugged. These tests unplug it and prove exactly that.
"""

import socket

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    IdentityEnforcer,
    PolicyConfig,
    anchor_resolver_from_key_history,
    anchor_resolver_from_registry,
    jcs_canonicalize_args,
    present,
)

TOOL = "tool:search"


@pytest.fixture
def no_network(monkeypatch):
    """Make any socket use raise. Anything reaching the network fails loudly."""

    def blocked(*args, **kwargs):
        raise AssertionError(
            "R3 VIOLATION: the verification path attempted a network call"
        )

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    return None


def agent_world(anchor, gates=None):
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=2, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, None)
    scope = ac.Scope(tools=[TOOL], max_depth=1)
    if gates:
        scope = scope.with_gates(gates)
    return agent, vc, ac.DelegationToken.mint(vc, scope, 300, agent)


def authorize(enf, vc, token, agent, session="s1", evidence=()):
    challenge = enf.issue_challenge(session)
    return enf.authorize(
        session, TOOL, {}, present(token, vc, challenge, agent, action=ac.Action(TOOL, jcs_canonicalize_args({}))),
        approval_evidence=list(evidence), canonicalization_profile=CANON_PROFILE_JCS,
    )


# -- The core claim ------------------------------------------------------------


def test_pinned_anchor_verification_is_fully_offline(no_network):
    anchor = ac.TrustAnchor.generate()
    agent, vc, token = agent_world(anchor)
    decision = authorize(IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False)), vc, token, agent)
    assert decision.allowed, decision.reason


def test_an_attenuated_chain_verifies_offline(no_network):
    """Multi-hop is where a naive implementation might want to look something up."""
    anchor = ac.TrustAnchor.generate()
    agent, vc, _token = agent_world(anchor)
    parent = ac.DelegationToken.mint(vc, ac.Scope(tools=[TOOL], max_depth=1), 300, agent)
    delegate = ac.AgentIdentity.create_did_key()
    # The delegate signs the narrowing block; the chain records the hop.
    child = parent.attenuate(ac.Scope(tools=[TOOL], max_depth=0), 300, delegate)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("s2")
    decision = enf.authorize(
        "s2", TOOL, {}, present(child, vc, challenge, delegate, action=ac.Action(TOOL, jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS
    )
    assert decision.allowed, decision.reason


def test_rotation_resolves_offline_from_a_held_history(no_network):
    """A rotated issuer is resolved by walking a signed chain, not by asking anyone.
    Each statement is signed by the outgoing key, whose public key is in its own DID."""
    root = ac.TrustAnchor.create_did_key()
    current = ac.TrustAnchor.create_did_key()
    history = ac.KeyHistory.genesis(root)
    history.push(ac.RotationStatement.issue(root, current))
    history.seal(current, 1)

    agent, vc, token = agent_world(current)
    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_key_history(history, root.did), config=PolicyConfig(revocation_check=False))
    assert authorize(enf, vc, token, agent, session="s3").allowed


def test_cross_org_resolution_is_offline_from_a_held_registry(no_network):
    """R2 through a framework, with no callback to the issuer - the registry is already
    in hand and is itself verified offline."""
    framework = ac.TrustAnchor.create_did_key()
    member = ac.TrustAnchor.create_did_key()
    reg = ac.TrustRegistry()
    reg.register(ac.TrustEntry(member.did, "Member", member.public_key, "verified"))
    reg.minimum_trust_level = "verified"
    config = reg.export(framework, 1)

    # Verifying the config itself is also offline.
    config.verify_current(framework)
    imported = ac.TrustRegistry.from_config(config, framework)

    agent, vc, token = agent_world(member)
    enf = IdentityEnforcer(anchor_for=anchor_resolver_from_registry(imported), config=PolicyConfig(revocation_check=False))
    assert authorize(enf, vc, token, agent, session="s4").allowed


def test_r10_approval_gates_are_satisfied_offline(no_network):
    """Both approval kinds. The hybrid directory is a held artifact like any other."""
    import time

    anchor = ac.TrustAnchor.generate()
    approver = ac.AgentIdentity.create_did_key()
    entry = ac.ApproverEntry("alice@example.com", approver.did, [], None)
    directory = ac.ApproverDirectory.seal([entry], 1, anchor, None)

    agent, vc, token = agent_world(anchor, gates=[ac.Gate.approval_key(TOOL)])
    action = ac.Action(TOOL, jcs_canonicalize_args({}))
    evidence = ac.ApprovalEvidence.approve_by_key(
        action, "alice@example.com", approver, "apr-1", int(time.time()) + 300
    )

    enf = IdentityEnforcer(anchor, approver_directory=directory, config=PolicyConfig(revocation_check=False))
    assert authorize(enf, vc, token, agent, session="s5", evidence=[evidence]).allowed


def test_revocation_can_be_checked_offline_from_a_held_list(no_network):
    """R7 with the list already in hand. Fetching it is a freshness concern (bounded
    staleness), not a verification one - the signed list decides either way."""
    from agentcreds_runtime import revocation_check_from_list

    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    rev = ac.RevocationList("https://issuer.example/revocation/1", anchor, 1024)
    status = ac.CredentialStatus("https://issuer.example/revocation/1", 7)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, status)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=[TOOL], max_depth=0), 300, agent)

    from agentcreds_runtime import PolicyConfig

    enf = IdentityEnforcer(
        anchor,
        config=PolicyConfig(revocation_check=revocation_check_from_list(rev, anchor)),
    )
    assert authorize(enf, vc, token, agent, session="s6").allowed


# -- The honest counterpart ----------------------------------------------------


def test_the_fetching_caches_are_the_only_thing_that_needs_the_network(no_network):
    """R3 is about verification, not acquisition. A cache configured to fetch WILL use
    the network - and must fail closed rather than pretend, which is what this asserts.

    Recorded so the boundary is explicit: the caches are opt-in, and a deployment that
    holds its artifacts never reaches this path.
    """
    from agentcreds_runtime import KeyHistoryCache

    root = ac.TrustAnchor.create_did_key()
    cache = KeyHistoryCache({root.did: "https://issuer.example/key-history"})
    # The socket block surfaces as a failed refresh, which the cache turns into "no
    # verified artifact" rather than an exception on the authorization path.
    assert cache.get(root.did) is None
    assert cache.status()[root.did].fetched_ok is False


def test_a_seeded_cache_serves_verification_offline(no_network):
    """And once an artifact is held - seeded or previously fetched - the cache answers
    from memory, so steady-state verification stays offline even in fetching mode."""
    from agentcreds_runtime import KeyHistoryCache, anchor_resolver_from_key_history_cache

    root = ac.TrustAnchor.create_did_key()
    current = ac.TrustAnchor.create_did_key()
    history = ac.KeyHistory.genesis(root)
    history.push(ac.RotationStatement.issue(root, current))
    history.seal(current, 1)

    cache = KeyHistoryCache(
        {root.did: "https://issuer.example/key-history"}, ttl_secs=3600
    )
    cache.seed(root.did, history)

    agent, vc, token = agent_world(current)
    enf = IdentityEnforcer(
        anchor_for=anchor_resolver_from_key_history_cache(cache, root.did), config=PolicyConfig(revocation_check=False)
    )
    assert authorize(enf, vc, token, agent, session="s7").allowed
