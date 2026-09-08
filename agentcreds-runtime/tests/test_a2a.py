"""End-to-end tests for the A2A verifier against the real agentcreds wheel.

Each test plays both sides: the sender mints an A2A header; the receiver
(`A2AVerifier`) verifies it. Mirrors the MCP enforcer tests for the no-MCP path.
"""

import base64
import datetime
import json

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    A2A_CANON_PROFILE_HEADER_NAME,
    A2A_HEADER_NAME,
    A2A_PRINCIPAL_HEADER_NAME,
    A2AVerifier,
    CANON_PROFILE_JCS,
    InMemoryReplayGuard,
    PolicyConfig,
    RedisReplayGuard,
    anchor_resolver_from_registry,
    jcs_canonicalize_args,
    make_a2a_envelope,
    make_a2a_header,
    make_a2a_principal_header,
    parse_a2a_principal_header,
    principal_resolver_from_oidc,
    revocation_check_from_list,
)
from agentcreds_runtime.errors import (
    CODE_MALFORMED,
    CODE_NOT_AUTHORIZED,
    CODE_POSSESSION,
    CODE_PRINCIPAL,
    CODE_REPLAY,
    CODE_REVOKED,
    CODE_UNBOUND,
    CODE_UNTRUSTED_ISSUER,
)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

RECEIVER = "a2a://orders.example/agent"
ISS, AUD, SUB = "https://login.acme.com", "agentcreds-prod", "auth0|alice"


def make_world(tools=("tool:search",)):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=list(tools), max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=list(tools), budget_usd=100, max_depth=1), 300, agent)
    return anchor, agent, vc, token


# -- Core path -----------------------------------------------------------------


def test_a2a_happy_path():
    anchor, agent, vc, token = make_world()
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"})))
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))

    decision = verifier.authorize(header, "tool:search", {"q": "x"}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed
    assert decision.chain[0].agent_did == agent.did


def test_a2a_wrong_audience_rejected():
    # A header minted for a different receiver must not verify here.
    anchor, agent, vc, token = make_world()
    header = make_a2a_header(token, vc, agent, audience="a2a://other.example/agent", action=ac.Action("tool:search", jcs_canonicalize_args({})))
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))

    decision = verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POSSESSION


def test_a2a_tool_not_in_scope():
    anchor, agent, vc, token = make_world(tools=("tool:search",))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:admin", jcs_canonicalize_args({})))
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))

    decision = verifier.authorize(header, "tool:admin", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_NOT_AUTHORIZED


def test_a2a_malformed_header():
    anchor, *_ = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))
    decision = verifier.authorize("not-an-a2a-header", "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_MALFORMED


def test_a2a_wrong_anchor_rejected():
    _anchor, agent, vc, token = make_world()
    other = ac.TrustAnchor.generate()
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    verifier = A2AVerifier(audience=RECEIVER, anchor=other, config=PolicyConfig(revocation_check=False))
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).denied


def test_a2a_requires_anchor_or_resolver():
    with pytest.raises(ValueError):
        A2AVerifier(audience=RECEIVER, config=PolicyConfig(revocation_check=False))


def test_a2a_requires_audience():
    anchor, *_ = make_world()
    with pytest.raises(ValueError):
        A2AVerifier(audience="", anchor=anchor, config=PolicyConfig(revocation_check=False))


# -- Argument binding ----------------------------------------------------------


def test_a2a_argument_binding_allows_match_and_denies_tamper():
    anchor, agent, vc, token = make_world(tools=("tool:transfer",))
    action = ac.Action("tool:transfer", jcs_canonicalize_args({"amount": 10}))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=action)
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(require_argument_binding=True, revocation_check=False))

    assert verifier.authorize(header, "tool:transfer", {"amount": 10},
                              canonicalization_profile=CANON_PROFILE_JCS).allowed
    tampered = verifier.authorize(header, "tool:transfer", {"amount": 1000000},
                                  canonicalization_profile=CANON_PROFILE_JCS)
    assert tampered.denied and tampered.code == CODE_POSSESSION


def test_a2a_require_binding_rejects_unbound_header():
    anchor, agent, vc, token = make_world()
    header = make_a2a_header(token, vc, agent, audience=RECEIVER)  # unbound - no action
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(require_argument_binding=True, revocation_check=False))
    decision = verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_UNBOUND


# -- Multi-issuer --------------------------------------------------------------


def test_a2a_multi_issuer_via_registry():
    anchor_a, agent_a, vc_a, token_a = make_world()
    anchor_b, agent_b, vc_b, token_b = make_world()
    registry = ac.TrustRegistry()
    registry.minimum_trust_level = "verified"
    registry.register(ac.TrustEntry(anchor_a.did, "Org A", anchor_a.public_key, "verified"))

    verifier = A2AVerifier(audience=RECEIVER, anchor_for=anchor_resolver_from_registry(registry), config=PolicyConfig(revocation_check=False))

    header_a = make_a2a_header(token_a, vc_a, agent_a, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert verifier.authorize(header_a, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed

    header_b = make_a2a_header(token_b, vc_b, agent_b, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    decision = verifier.authorize(header_b, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_UNTRUSTED_ISSUER


# -- Revocation ----------------------------------------------------------------


def test_a2a_revoked_credential_denied():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    list_url = "https://issuer.example/revocation/1"
    rev_list = ac.RevocationList(list_url, anchor, 1024)
    status = ac.CredentialStatus(list_url, 7)
    claims = ac.CapabilityClaims(tools=["tool:search"], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims, status)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=["tool:search"], max_depth=1), 300, agent)

    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=revocation_check_from_list(rev_list, anchor)))
    assert verifier.authorize(make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({}))), "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed

    rev_list.revoke(7, anchor)
    decision = verifier.authorize(make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({}))), "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_REVOKED


# -- Replay protection ---------------------------------------------------------


class _FakeRedisNX:
    """Minimal Redis stand-in supporting SET key val NX EX (returns True/None)."""

    def __init__(self):
        self.kv = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True


def test_a2a_replay_guard_rejects_reused_header():
    anchor, agent, vc, token = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, replay_guard=InMemoryReplayGuard(), config=PolicyConfig(revocation_check=False))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))

    # First use is admitted; the same header replayed verbatim is rejected.
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed
    replayed = verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS)
    assert replayed.denied
    assert replayed.code == CODE_REPLAY


def test_a2a_replay_protection_is_on_by_default():
    anchor, agent, vc, token = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))  # default in-memory guard
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).code == CODE_REPLAY


def test_a2a_replay_protection_can_be_disabled():
    anchor, agent, vc, token = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, enable_replay_protection=False, config=PolicyConfig(revocation_check=False))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed  # reuse permitted


def test_a2a_fresh_headers_are_each_admitted():
    anchor, agent, vc, token = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, replay_guard=InMemoryReplayGuard(), config=PolicyConfig(revocation_check=False))
    # Each call mints a fresh challenge -> distinct header -> all admitted.
    for _ in range(3):
        header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
        assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed


def test_a2a_replay_guard_with_redis_backend():
    anchor, agent, vc, token = make_world()
    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor, replay_guard=RedisReplayGuard(_FakeRedisNX()), config=PolicyConfig(revocation_check=False))
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:search", jcs_canonicalize_args({})))
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).allowed
    assert verifier.authorize(header, "tool:search", {}, canonicalization_profile=CANON_PROFILE_JCS).code == CODE_REPLAY


def test_in_memory_replay_guard_unit():
    guard = InMemoryReplayGuard(ttl_secs=300)
    assert guard.record_if_new("k1") is True
    assert guard.record_if_new("k1") is False  # already seen
    assert guard.record_if_new("k2") is True


def test_in_memory_replay_guard_ttl_zero_never_blocks():
    # ttl=0 means entries expire immediately -> nothing is ever a replay.
    guard = InMemoryReplayGuard(ttl_secs=0)
    assert guard.record_if_new("k1") is True
    assert guard.record_if_new("k1") is True


# -- On-behalf-of over A2A -----------------------------------------------------


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _forge_oidc(sub=SUB):
    """Return (id_token, jwks) for a freshly generated Ed25519 IdP key."""
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": "k1"}).encode())
    payload = _b64u(json.dumps({
        "iss": ISS, "aud": AUD, "sub": sub,
        "exp": int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp()),
    }).encode())
    signing = f"{header}.{payload}"
    id_token = f"{signing}.{_b64u(sk.sign(signing.encode()))}"
    jwks = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "use": "sig", "x": _b64u(pub)}]})
    return id_token, jwks


def _obo_world(sub=SUB):
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    human = ac.HumanIdentity.from_idp(ISS, sub)
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    auth = human.authorize(exp, ["tool:read_email"], ["mailbox:alice@acme.com/*"])
    claims = ac.CapabilityClaims(["tool:read_email"], 2, 3600, on_behalf_of=auth)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    scope = ac.Scope(["tool:read_email"], max_depth=1, resources=["mailbox:alice@acme.com/42"])
    token = ac.DelegationToken.mint(vc, scope, 300, agent)
    return anchor, agent, human, vc, token


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_a2a_obo_allows_verified_human():
    anchor, agent, human, vc, token = _obo_world()
    id_token, jwks = _forge_oidc()
    provider = ac.OidcProvider(ISS, AUD)
    provider.add_keys_from_jwks(jwks)

    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=principal_resolver_from_oidc(provider), config=PolicyConfig(revocation_check=False),
    )
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:read_email", jcs_canonicalize_args(None), resource="mailbox:alice@acme.com/42"))
    decision = verifier.authorize_obo(
        header, id_token, "tool:read_email", None, resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_a2a_obo_denies_unverifiable_principal_token():
    anchor, agent, human, vc, token = _obo_world()
    provider = ac.OidcProvider(ISS, AUD)  # no keys -> nothing validates
    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=principal_resolver_from_oidc(provider), config=PolicyConfig(revocation_check=False),
    )
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:read_email", jcs_canonicalize_args(None), resource="mailbox:alice@acme.com/42"))
    decision = verifier.authorize_obo(
        header, "garbage.token.value", "tool:read_email", None, resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied and decision.code == CODE_PRINCIPAL


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_a2a_obo_confused_deputy_rejected():
    # The capability token is bound to Alice; a valid token for Bob must not let
    # the agent act - the core principal check fails (confused-deputy guard).
    anchor, agent, human, vc, token = _obo_world(sub="auth0|alice")
    bob_token, jwks = _forge_oidc(sub="auth0|bob")
    provider = ac.OidcProvider(ISS, AUD)
    provider.add_keys_from_jwks(jwks)

    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=principal_resolver_from_oidc(provider), config=PolicyConfig(revocation_check=False),
    )
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:read_email", jcs_canonicalize_args(None), resource="mailbox:alice@acme.com/42"))
    decision = verifier.authorize_obo(
        header, bob_token, "tool:read_email", None, resource="mailbox:alice@acme.com/42", canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_PRINCIPAL


def test_a2a_obo_requires_resolver():
    anchor, agent, human, vc, token = _obo_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))  # no principal_resolver
    header = make_a2a_header(token, vc, agent, audience=RECEIVER, action=ac.Action("tool:read_email", jcs_canonicalize_args(None)))
    with pytest.raises(ValueError):
        verifier.authorize_obo(header, "tok", "tool:read_email", None, canonicalization_profile=CANON_PROFILE_JCS)


# -- Wire envelope -------------------------------------------------------------


def test_principal_header_round_trip():
    token = "eyJhbGciOiJFZERTQSJ9.payload.sig"
    header = make_a2a_principal_header(token)
    assert header.startswith("AgentCreds-A2A-Principal/1.")
    assert parse_a2a_principal_header(header) == token


def test_parse_principal_header_rejects_bad_scheme():
    with pytest.raises(ValueError):
        parse_a2a_principal_header("not-a-principal-header")


def test_envelope_non_obo_round_trip():
    anchor, agent, vc, token = make_world()
    envelope = make_a2a_envelope(token, vc, agent, audience=RECEIVER, canonicalization_profile=CANON_PROFILE_JCS, action=ac.Action("tool:search", jcs_canonicalize_args({"q": "x"})))
    assert set(envelope) == {A2A_HEADER_NAME, A2A_CANON_PROFILE_HEADER_NAME}  # no principal header without OBO
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))
    assert verifier.authorize_envelope(envelope, "tool:search", {"q": "x"}).allowed


def test_envelope_missing_capability_header():
    anchor, *_ = make_world()
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))
    decision = verifier.authorize_envelope({"X-Other": "v"}, "tool:search", {})
    assert decision.denied and decision.code == CODE_MALFORMED


def test_envelope_header_lookup_is_case_insensitive():
    anchor, agent, vc, token = make_world()
    envelope = make_a2a_envelope(
        token, vc, agent, audience=RECEIVER,
        canonicalization_profile=CANON_PROFILE_JCS,
        action=ac.Action("tool:search", jcs_canonicalize_args({})),
    )
    # Simulate a server that lower-cases header names.
    lowered = {k.lower(): v for k, v in envelope.items()}
    verifier = A2AVerifier(audience=RECEIVER, anchor=anchor, config=PolicyConfig(revocation_check=False))
    assert verifier.authorize_envelope(lowered, "tool:search", {}).allowed


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_envelope_obo_allows_verified_human():
    anchor, agent, human, vc, token = _obo_world()
    id_token, jwks = _forge_oidc()
    provider = ac.OidcProvider(ISS, AUD)
    provider.add_keys_from_jwks(jwks)
    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=principal_resolver_from_oidc(provider), config=PolicyConfig(revocation_check=False),
    )
    # The binding covers the resource as well as the tool and arguments, and the call
    # below passes `None` for arguments - so the action has to match on all three.
    envelope = make_a2a_envelope(
        token, vc, agent, audience=RECEIVER, principal_token=id_token,
        canonicalization_profile=CANON_PROFILE_JCS,
        action=ac.Action("tool:read_email", jcs_canonicalize_args(None),
                         resource="mailbox:alice@acme.com/42"),
    )
    assert set(envelope) == {
        A2A_HEADER_NAME, A2A_PRINCIPAL_HEADER_NAME, A2A_CANON_PROFILE_HEADER_NAME}

    decision = verifier.authorize_envelope(
        envelope, "tool:read_email", None, resource="mailbox:alice@acme.com/42")
    assert decision.allowed


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
def test_envelope_obo_confused_deputy_rejected():
    anchor, agent, human, vc, token = _obo_world(sub="auth0|alice")
    bob_token, jwks = _forge_oidc(sub="auth0|bob")
    provider = ac.OidcProvider(ISS, AUD)
    provider.add_keys_from_jwks(jwks)
    verifier = A2AVerifier(
        audience=RECEIVER, anchor=anchor,
        principal_resolver=principal_resolver_from_oidc(provider), config=PolicyConfig(revocation_check=False),
    )
    envelope = make_a2a_envelope(token, vc, agent, audience=RECEIVER, principal_token=bob_token, action=ac.Action("tool:read_email", jcs_canonicalize_args(None), resource="mailbox:alice@acme.com/42"), canonicalization_profile=CANON_PROFILE_JCS)
    decision = verifier.authorize_envelope(
        envelope, "tool:read_email", None, resource="mailbox:alice@acme.com/42")
    assert decision.denied and decision.code == CODE_PRINCIPAL
