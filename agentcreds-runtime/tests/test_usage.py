"""Tests for the stateful usage gate (rate/quota + spend), end-to-end through the
real wheel and the IdentityEnforcer, plus the in-memory and Redis-shaped stores."""

import agentcreds as ac

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    jcs_canonicalize_args,
    IdentityEnforcer,
    InMemoryUsageStore,
    PolicyConfig,
    RedisUsageStore,
    present,
    rate_limit,
    spend_limit,
    usage_gate,
)
from agentcreds_runtime.errors import CODE_QUOTA


def make_world(tools=("tool:search",), budget=100, depth=2):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=list(tools), max_delegation_depth=depth, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=list(tools), budget_usd=budget, max_depth=depth)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


# -- In-memory store unit behavior --------------------------------------------


def test_usage_store_add_get_roundtrip():
    store = InMemoryUsageStore()
    assert store.get("k") == 0
    assert store.add("k", 5, ttl_secs=60) == 5
    assert store.add("k", 3, ttl_secs=60) == 8
    assert store.get("k") == 8


def test_usage_store_expiry_resets_counter():
    store = InMemoryUsageStore()
    store.add("k", 5, ttl_secs=0)  # already expired
    assert store.get("k") == 0


# -- Rate limit (end-to-end) ---------------------------------------------------


def test_rate_limit_allows_up_to_max_then_denies():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(InMemoryUsageStore(), rate_limit(2, per_secs=3600)), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    denied = enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert denied.denied
    assert denied.code == CODE_QUOTA
    assert "rate limit" in denied.reason


def test_rate_limit_is_per_agent_key():
    anchor, agent_a, vc_a, token_a = make_world()
    # Same issuing anchor, different agent identity -> independent rate bucket.
    agent_b = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=2, valid_for_secs=3600)
    vc_b = ac.CapabilityCredential.issue(anchor, agent_b.did, claims)
    token_b = ac.DelegationToken.mint(vc_b, ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=2), 300, agent_b)

    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(InMemoryUsageStore(), rate_limit(1, per_secs=3600)), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token_a, vc_a, ch, agent_a, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    # agent_a is now at its limit...
    assert enf.authorize("s1", "tool:search", {}, present(token_a, vc_a, ch, agent_a, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).denied
    # ...but agent_b has its own bucket.
    assert enf.authorize("s1", "tool:search", {}, present(token_b, vc_b, ch, agent_b, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


# -- Spend meter (end-to-end) --------------------------------------------------


def test_spend_meter_enforces_declared_budget():
    # budget defaults to the credential's leaf budget_usd (100 here); cost from args.
    anchor, agent, vc, token = make_world(tools=("tool:transfer",), budget=100)
    gate = usage_gate(
        InMemoryUsageStore(),
        spend_limit(cost=lambda pin: int(pin.arguments.get("amount", 0))),
    )
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=gate, revocation_check=False))
    ch = enf.issue_challenge("s1")

    assert enf.authorize("s1", "tool:transfer", {"amount": 60}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 60}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    # 60 + 60 = 120 > 100 -> denied, and (two-phase) NOT charged...
    denied = enf.authorize("s1", "tool:transfer", {"amount": 60}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 60}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert denied.denied and denied.code == CODE_QUOTA and "budget" in denied.reason
    # ...so a 30 still fits under the remaining 40 (proves the denied call wasn't charged).
    assert enf.authorize("s1", "tool:transfer", {"amount": 30}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 30}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_spend_meter_skips_when_no_budget_declared():
    # A credential with no budget_usd and no explicit cap -> nothing to meter, allowed.
    anchor, agent, vc, token = make_world(budget=None)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(InMemoryUsageStore(), spend_limit()), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_explicit_budget_overrides_credential():
    anchor, agent, vc, token = make_world(tools=("tool:transfer",), budget=1000)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(InMemoryUsageStore(), spend_limit(budget=50, cost=lambda pin: int(pin.arguments.get("amount", 0)))), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:transfer", {"amount": 40}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 40}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:transfer", {"amount": 40}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 40}))), canonicalization_profile=CANON_PROFILE_JCS).denied


# -- Combined rules + fail-closed ----------------------------------------------


def test_combined_rules_denied_call_charges_nothing():
    # rate (limit 5) + spend (limit 100). A call that passes rate but busts spend must
    # NOT consume a rate token (two-phase: check all, commit only if all pass).
    anchor, agent, vc, token = make_world(tools=("tool:transfer",), budget=100)
    store = InMemoryUsageStore()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(store, rate_limit(5, per_secs=3600), spend_limit(cost=lambda pin: int(pin.arguments.get("amount", 0)))), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:transfer", {"amount": 80}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 80}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    # 80 + 80 busts the budget -> denied; rate token must not have been spent.
    assert enf.authorize("s1", "tool:transfer", {"amount": 80}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 80}))), canonicalization_profile=CANON_PROFILE_JCS).denied
    # 20 fits (80+20=100) AND we've only consumed 2 of 5 rate tokens.
    assert enf.authorize("s1", "tool:transfer", {"amount": 20}, present(token, vc, ch, agent, action=ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 20}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_usage_meter_store_error_fails_closed():
    class BrokenStore(InMemoryUsageStore):
        def get(self, key):
            raise RuntimeError("usage backend down")

    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(BrokenStore(), rate_limit(10, 60)), revocation_check=False))
    ch = enf.issue_challenge("s1")
    decision = enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_QUOTA


def test_usage_meter_store_error_can_fail_open():
    class BrokenStore(InMemoryUsageStore):
        def get(self, key):
            raise RuntimeError("usage backend down")

    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(BrokenStore(), rate_limit(10, 60)), fail_open_on_usage_error=True, revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed


# -- Redis-shaped store --------------------------------------------------------


class _FakeRedis:
    """Minimal stand-in exposing the get/incrby/expire RedisUsageStore uses."""

    def __init__(self):
        self.kv = {}

    def get(self, key):
        return self.kv.get(key)

    def incrby(self, key, amount):
        self.kv[key] = self.kv.get(key, 0) + amount
        return self.kv[key]

    def expire(self, key, ttl):
        pass


def test_redis_usage_store_roundtrip_and_enforces():
    store = RedisUsageStore(_FakeRedis())
    assert store.get("k") == 0
    assert store.add("k", 4, 60) == 4
    assert store.add("k", 1, 60) == 5
    assert store.get("k") == 5

    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(usage_meter=usage_gate(RedisUsageStore(_FakeRedis()), rate_limit(1, 3600)), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert enf.authorize("s1", "tool:search", {}, present(token, vc, ch, agent, action=ac.Action("tool:search", jcs_canonicalize_args({}))), canonicalization_profile=CANON_PROFILE_JCS).denied
