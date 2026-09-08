"""Tests for the optional Cedar-backed policy hook.

The functional tests are skipped unless `cedarpy` is installed (it's an optional
extra); the optionality tests always run to prove the runtime works without it.
"""

import agentcreds as ac
import importlib.util

import pytest

import agentcreds_runtime
from agentcreds_runtime import IdentityEnforcer, PolicyConfig, PolicyInput, cedar_policy_hook, present, CANON_PROFILE_JCS, jcs_canonicalize_args
from agentcreds_runtime.errors import CODE_POLICY

HAVE_CEDAR = importlib.util.find_spec("cedarpy") is not None
requires_cedar = pytest.mark.skipif(not HAVE_CEDAR, reason="requires the optional 'cedarpy' extra")


def _pin(tool="tool:echo", arguments=None, principal=None, resource=None, chain=None):
    return PolicyInput(
        principal=principal, tool=tool, arguments=arguments or {},
        args="", resource=resource, chain=chain or [], token=None,
    )


def make_world(tools=("tool:echo",), depth=2):
    import agentcreds as ac

    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=list(tools), max_delegation_depth=depth, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=list(tools), budget_usd=100, max_depth=depth)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


# -- Optionality (always runs) -------------------------------------------------


def test_cedar_module_imports_without_engine():
    # Importing the runtime (and the cedar module) must never require cedarpy.
    import agentcreds_runtime.cedar as cedar_mod

    assert hasattr(cedar_mod, "cedar_policy_hook")
    assert agentcreds_runtime.cedar_policy_hook is cedar_mod.cedar_policy_hook


@pytest.mark.skipif(HAVE_CEDAR, reason="cedarpy installed; the ImportError path can't be exercised")
def test_building_hook_without_engine_raises_importerror():
    with pytest.raises(ImportError):
        cedar_policy_hook("permit(principal, action, resource);")


# -- Functional (requires cedarpy) ---------------------------------------------


@requires_cedar
def test_cedar_permit_all_allows():
    hook = cedar_policy_hook("permit(principal, action, resource);")
    assert hook(_pin(arguments={"text": "hi"})) is None


@requires_cedar
def test_cedar_deny_by_default():
    # No permit -> Cedar denies; the hook returns a reason string.
    hook = cedar_policy_hook("")
    reason = hook(_pin())
    assert reason and "Cedar" in reason


@requires_cedar
def test_cedar_forbid_on_request_argument():
    policies = (
        "permit(principal, action, resource);\n"
        "forbid(principal, action, resource)\n"
        "  when { context.args has amount && context.args.amount > 100 };"
    )
    hook = cedar_policy_hook(policies)
    assert hook(_pin(tool="tool:transfer", arguments={"amount": 50})) is None
    assert hook(_pin(tool="tool:transfer", arguments={"amount": 1000})) is not None


@requires_cedar
def test_cedar_gates_on_oidc_principal():
    policies = 'permit(principal == Agent::"did:key:alice", action, resource);'
    hook = cedar_policy_hook(policies)
    assert hook(_pin(principal="did:key:alice")) is None
    assert hook(_pin(principal="did:key:bob")) is not None  # deny-by-default


@requires_cedar
def test_cedar_hook_end_to_end_through_enforcer():
    anchor, agent, vc, token = make_world(tools=("tool:echo",))
    # A forbid that fires for this tool -> the verified call is denied at the policy gate.
    policies = (
        "permit(principal, action, resource);\n"
        'forbid(principal, action == Action::"tool:echo", resource);'
    )
    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=cedar_policy_hook(policies), revocation_check=False))
    ch = enf.issue_challenge("s1")

    decision = enf.authorize("s1", "tool:echo", {"text": "hi"}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({"text": "hi"}))), canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POLICY


@requires_cedar
def test_cedar_hook_end_to_end_allows_when_permitted():
    anchor, agent, vc, token = make_world(tools=("tool:echo",))
    enf = IdentityEnforcer(anchor, config=PolicyConfig(policy_hook=cedar_policy_hook("permit(principal, action, resource);"), revocation_check=False))
    ch = enf.issue_challenge("s1")
    assert enf.authorize("s1", "tool:echo", {"text": "hi"}, present(token, vc, ch, agent, action=ac.Action("tool:echo", jcs_canonicalize_args({"text": "hi"}))), canonicalization_profile=CANON_PROFILE_JCS).allowed
