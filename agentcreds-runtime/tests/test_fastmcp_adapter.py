"""Tests for the FastMCP adapter decorator, using a fake Context and handler.

These exercise the adapter wiring without requiring the `mcp` SDK to be
installed (the adapter never imports it at load time).
"""

import asyncio
import base64

import agentcreds as ac
import pytest

from agentcreds_runtime import (AccessDenied, CANON_PROFILE_JCS, IdentityEnforcer, PolicyConfig,
                                jcs_canonicalize_args, present)
from agentcreds_runtime.fastmcp import CANON_PROFILE_ARG, default_session_id, guard_tool


class FakeCtx:
    def __init__(self, client_id):
        self.client_id = client_id


def make_world():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(tools=["tool:search"], budget_usd=100, max_depth=1)
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, vc, token


def test_default_session_id_prefers_client_id():
    assert default_session_id(FakeCtx("sess-42")) == "sess-42"


def test_guard_allows_and_injects_chain():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("sess-42")
    presentation_b64 = base64.b64encode(present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "rust"})))).decode()

    seen = {}

    @guard_tool(enf, "tool:search")
    async def handler(q, ctx=None, agentcreds_presentation=None, agentcreds_chain=None, **kwargs):
        seen["q"] = q
        seen["chain"] = agentcreds_chain
        return "ok"

    result = asyncio.run(
        handler(q="rust", ctx=FakeCtx("sess-42"), agentcreds_presentation=presentation_b64, **{CANON_PROFILE_ARG: CANON_PROFILE_JCS})
    )
    assert result == "ok"
    assert seen["q"] == "rust"
    assert seen["chain"][0].agent_did == agent.did


def test_guard_denies_without_presentation():
    anchor, _agent, _vc, _token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    enf.issue_challenge("sess-42")

    @guard_tool(enf, "tool:search")
    async def handler(ctx=None, agentcreds_presentation=None, **kwargs):
        return "ok"

    with pytest.raises(AccessDenied):
        asyncio.run(handler(ctx=FakeCtx("sess-42")))


def test_guard_denies_wrong_tool_scope():
    anchor, agent, vc, token = make_world()
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))
    challenge = enf.issue_challenge("sess-7")
    presentation_b64 = base64.b64encode(present(token, vc, challenge, agent, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "rust"})))).decode()

    @guard_tool(enf, "tool:admin")  # tool the token does not grant
    async def handler(ctx=None, agentcreds_presentation=None, **kwargs):
        return "ok"

    with pytest.raises(AccessDenied) as exc:
        asyncio.run(handler(ctx=FakeCtx("sess-7"), agentcreds_presentation=presentation_b64, **{CANON_PROFILE_ARG: CANON_PROFILE_JCS}))
    assert exc.value.code == "not_authorized"
