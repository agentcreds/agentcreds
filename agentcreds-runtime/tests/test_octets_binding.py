"""The carry-the-octets binding profile (`agentcreds-octets-v1`).

Canonicalization is a workaround for not having the original octets, and every bug it
has ever produced comes from two implementations disagreeing about how to *write* a
value. This profile carries the holder's bytes instead, so the verifier checks the proof
over exactly what was signed and then compares meanings rather than spellings.

The load-bearing test here is `test_a_serialization_no_canonicalizer_would_ever_emit`:
if a holder can serialize its arguments in a deliberately perverse way and still verify,
then no agreement about serialization is required, which is the entire claim.
"""

import asyncio
import base64
import json

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    CANON_PROFILE_JCS,
    CANON_PROFILE_OCTETS,
    IdentityEnforcer,
    PolicyConfig,
    jcs_canonicalize_args,
    octets_bind_args,
    present,
)
from agentcreds_runtime.errors import CODE_ARGS_MISMATCH, CODE_BOUND_ARGS, CODE_POSSESSION
from agentcreds_runtime.fastmcp import BOUND_ARGS_ARG, CANON_PROFILE_ARG, PRESENTATION_ARG
from agentcreds_runtime.octets import (
    MAX_BOUND_ARGS_BYTES,
    BoundArgsError,
    parse_bound_args,
    semantic_eq,
)

TOOL = "tool:pay"


class FakeCtx:
    def __init__(self, client_id):
        self.client_id = client_id


def _octets_enforcer():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=[TOOL], max_depth=0), 300, agent)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(
        canonicalization_profile=CANON_PROFILE_OCTETS,
        require_argument_binding=True, revocation_check=False,
    ))
    return enf, agent, vc, token


def _call(enf, agent, vc, token, session, *, signed_octets, delivered, carried=None,
          profile=CANON_PROFILE_OCTETS):
    """Sign over `signed_octets`, deliver `delivered`, carry `carried` (default: signed).

    Splitting the three lets a test move exactly one of them, which is what separates
    "the arguments changed" from "the carried copy changed".
    """
    challenge = enf.issue_challenge(session)
    action = ac.Action(TOOL, signed_octets)
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()
    return enf.authorize(
        session, TOOL, delivered, base64.b64decode(pres),
        canonicalization_profile=profile,
        bound_arguments=signed_octets if carried is None else carried,
    )


# -- semantic_eq: the rules the profile rests on -------------------------------


def test_semantic_eq_ignores_spelling_but_not_meaning():
    # Key order is not meaning; array order is.
    assert semantic_eq({"a": 1, "b": 2}, {"b": 2, "a": 1})
    assert not semantic_eq([1, 2], [2, 1])
    # A JSON number is a number: how it was written is not part of its meaning.
    assert semantic_eq({"n": 1}, {"n": 1.0})
    assert semantic_eq({"n": 1e2}, {"n": 100})
    assert not semantic_eq({"n": 1}, {"n": 2})


def test_semantic_eq_does_not_confuse_booleans_with_numbers():
    # `bool` is an `int` subclass in Python, so a naive numeric compare says True == 1.
    # That would let a holder sign `{"admin": 1}` and a caller deliver `{"admin": true}`.
    assert not semantic_eq({"admin": True}, {"admin": 1})
    assert not semantic_eq({"admin": False}, {"admin": 0})
    assert semantic_eq({"admin": True}, {"admin": True})


def test_semantic_eq_compares_large_integers_exactly():
    # The 2^53 cliff that `agentcreds-jcs-v1` inherits does not exist here: nothing is
    # routed through a double, so neighbouring integers stay distinguishable.
    assert not semantic_eq({"id": 9007199254740993}, {"id": 9007199254740992})
    assert semantic_eq({"id": 9007199254740993}, {"id": 9007199254740993})


def test_semantic_eq_rejects_structural_mismatches():
    assert not semantic_eq({"a": 1}, {"a": 1, "b": 2})   # extra key
    assert not semantic_eq({"a": 1}, {"a": "1"})         # number vs string
    assert not semantic_eq([1], {"0": 1})                # array vs object
    assert not semantic_eq(None, 0)


# -- parse_bound_args: everything here runs before anything is authenticated ----


def test_carried_octets_have_a_size_ceiling():
    oversized = json.dumps({"blob": "x" * (MAX_BOUND_ARGS_BYTES + 100)})
    with pytest.raises(BoundArgsError, match="over the"):
        parse_bound_args(oversized)


def test_carried_octets_reject_json_that_is_not_json():
    with pytest.raises(BoundArgsError):
        parse_bound_args("{not json")
    with pytest.raises(BoundArgsError):
        parse_bound_args(None)
    # Python's json accepts these by default; they are not JSON, and NaN != NaN would
    # make the comparison below unresolvable rather than merely false.
    with pytest.raises(BoundArgsError, match="not valid JSON"):
        parse_bound_args('{"n": NaN}')
    with pytest.raises(BoundArgsError, match="not valid JSON"):
        parse_bound_args('{"n": Infinity}')


# -- End to end ----------------------------------------------------------------


def test_a_serialization_no_canonicalizer_would_ever_emit():
    """The claim of the profile, stated as a test.

    The holder serializes with indentation, trailing spaces and unsorted keys - output
    no canonicalizer produces and no verifier could guess. It verifies anyway, because
    the verifier never re-serializes: it checks the proof over these exact bytes and
    then compares the parsed result to what was delivered.
    """
    enf, agent, vc, token = _octets_enforcer()
    args = {"q": "café", "amount": 1.0, "zeta": [1, 2], "alpha": None}
    perverse = json.dumps(args, indent=4, sort_keys=False, ensure_ascii=False)
    assert perverse != jcs_canonicalize_args(args), "fixture must not be accidentally canonical"

    decision = _call(enf, agent, vc, token, "s-perverse",
                     signed_octets=perverse, delivered=args)
    assert decision.allowed, decision.reason


def test_the_same_call_under_jcs_needs_the_canonical_form_and_only_that():
    """The contrast that makes the point above meaningful.

    Under a canonicalizing profile the holder has no freedom: emit anything but the
    canonical bytes and a request nobody tampered with is refused.
    """
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    token = ac.DelegationToken.mint(vc, ac.Scope(tools=[TOOL], max_depth=0), 300, agent)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # defaults: JCS

    args = {"q": "café", "amount": 1.0}
    challenge = enf.issue_challenge("s-jcs")
    action = ac.Action(TOOL, json.dumps(args, indent=4, ensure_ascii=False))
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()
    decision = enf.authorize("s-jcs", TOOL, args, base64.b64decode(pres),
                             canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.denied
    assert decision.code == CODE_POSSESSION


def test_altering_the_delivered_arguments_is_named_for_what_it_is():
    """A tamper reports as `argument_mismatch`, not as a crypto failure.

    This is the diagnostic the profile buys. Under canonicalization the same event is
    indistinguishable from two implementations disagreeing about a float.
    """
    enf, agent, vc, token = _octets_enforcer()
    signed = octets_bind_args({"amount": 10, "to": "alice"})
    decision = _call(enf, agent, vc, token, "s-tamper",
                     signed_octets=signed, delivered={"amount": 1000000, "to": "mallory"})
    assert decision.denied
    assert decision.code == CODE_ARGS_MISMATCH


def test_altering_the_carried_copy_breaks_the_proof_instead():
    """The other half: the carried octets are not a free-text side channel.

    Rewriting them to match tampered arguments does not help - the proof was computed
    over the originals, so it stops verifying.
    """
    enf, agent, vc, token = _octets_enforcer()
    signed = octets_bind_args({"amount": 10})
    forged = octets_bind_args({"amount": 1000000})
    decision = _call(enf, agent, vc, token, "s-forge",
                     signed_octets=signed, delivered={"amount": 1000000}, carried=forged)
    assert decision.denied
    # The carried copy agrees with what was delivered, so the comparison passes and the
    # signature is what refuses it.
    assert decision.code == CODE_POSSESSION


def test_the_profile_requires_the_carried_copy():
    enf, agent, vc, token = _octets_enforcer()
    signed = octets_bind_args({"amount": 10})
    decision = _call(enf, agent, vc, token, "s-missing",
                     signed_octets=signed, delivered={"amount": 10}, carried="")
    assert decision.denied
    assert decision.code == CODE_BOUND_ARGS


def test_an_oversized_carried_copy_is_refused_before_any_crypto():
    enf, agent, vc, token = _octets_enforcer()
    signed = octets_bind_args({"amount": 10})
    decision = _call(enf, agent, vc, token, "s-huge", signed_octets=signed,
                     delivered={"amount": 10},
                     carried=json.dumps({"x": "y" * (MAX_BOUND_ARGS_BYTES + 10)}))
    assert decision.denied
    assert decision.code == CODE_BOUND_ARGS


def test_large_integers_survive_that_jcs_would_lose():
    """The 2^53 cliff is a property of canonicalizing through doubles, not of binding."""
    enf, agent, vc, token = _octets_enforcer()
    args = {"record_id": 9007199254740993}
    decision = _call(enf, agent, vc, token, "s-bigint",
                     signed_octets=octets_bind_args(args), delivered=args)
    assert decision.allowed, decision.reason

    # ...and the neighbour it would have collided with is still refused.
    neighbour = _call(enf, agent, vc, token, "s-bigint-2",
                      signed_octets=octets_bind_args(args),
                      delivered={"record_id": 9007199254740992})
    assert neighbour.denied
    assert neighbour.code == CODE_ARGS_MISMATCH


def test_key_order_and_number_spelling_do_not_have_to_match():
    """The delivered arguments need only *mean* the same thing."""
    enf, agent, vc, token = _octets_enforcer()
    signed = '{"b":2,"a":1.0}'   # holder's spelling
    decision = _call(enf, agent, vc, token, "s-shape",
                     signed_octets=signed, delivered={"a": 1, "b": 2})
    assert decision.allowed, decision.reason


# -- Through the MCP adapter, where the reserved argument must be stripped ------


def test_the_reserved_bound_args_argument_never_reaches_the_comparison():
    """The trap this repo has already fallen into once, in a new place.

    `agentcreds_bound_args` arrives as a tool kwarg. If it is not stripped it appears in
    the delivered arguments but not in the holder's copy, so the comparison can never
    match and every correctly-bound client is refused.
    """
    from agentcreds_runtime.fastmcp import guard_tool

    enf, agent, vc, token = _octets_enforcer()
    args = {"amount": 10}
    signed = octets_bind_args(args)
    challenge = enf.issue_challenge("s-mcp")
    action = ac.Action(TOOL, signed)
    pres = base64.b64encode(present(token, vc, challenge, agent, action=action)).decode()

    @guard_tool(enf, TOOL)
    async def handler(amount, ctx=None, **kwargs):
        return "ok"

    assert asyncio.run(handler(
        amount=10, ctx=FakeCtx("s-mcp"),
        **{PRESENTATION_ARG: pres, BOUND_ARGS_ARG: signed,
           CANON_PROFILE_ARG: CANON_PROFILE_OCTETS},
    )) == "ok"


# -- The signed arguments, surfaced but never substituted ----------------------


def test_an_allow_carries_the_arguments_that_were_actually_signed():
    """`bound_arguments` is the identity object; the delivered one is only equivalent.

    `semantic_eq` deliberately treats 1 and 1.0 as the same JSON number - correct for
    JSON, but a tool that branches on `isinstance(x, int)` can tell them apart. A caller
    that needs identity rather than equivalence invokes with this.
    """
    enf, agent, vc, token = _octets_enforcer()
    signed = '{"amount":1}'                      # holder signed an integer
    decision = _call(enf, agent, vc, token, "s-surface",
                     signed_octets=signed, delivered={"amount": 1.0})   # transport: float
    assert decision.allowed, decision.reason
    assert decision.bound_arguments == {"amount": 1}
    assert isinstance(decision.bound_arguments["amount"], int)


def test_bound_arguments_is_absent_under_a_canonicalizing_profile():
    # Nothing was carried, so there is no stronger object to offer - and a caller must
    # not be able to mistake "this profile has no signed copy" for "the copy is empty".
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=[TOOL], max_delegation_depth=1, valid_for_secs=3600)
    vc = ac.CapabilityCredential.issue(anchor, agent.did, claims)
    tok = ac.DelegationToken.mint(vc, ac.Scope(tools=[TOOL], max_depth=0), 300, agent)
    enf = IdentityEnforcer(anchor, config=PolicyConfig(revocation_check=False))  # defaults: JCS

    args = {"amount": 10}
    challenge = enf.issue_challenge("s-jcs-none")
    action = ac.Action(TOOL, jcs_canonicalize_args(args))
    pres = base64.b64encode(present(tok, vc, challenge, agent, action=action)).decode()
    decision = enf.authorize("s-jcs-none", TOOL, args, base64.b64decode(pres),
                             canonicalization_profile=CANON_PROFILE_JCS)
    assert decision.allowed, decision.reason
    assert decision.bound_arguments is None


def test_a_denial_never_carries_signed_arguments():
    # They would not be trustworthy: on the mismatch path the comparison failed, and on
    # the parse path there is nothing to carry.
    enf, agent, vc, token = _octets_enforcer()
    signed = octets_bind_args({"amount": 10})
    decision = _call(enf, agent, vc, token, "s-deny-none",
                     signed_octets=signed, delivered={"amount": 999})
    assert decision.denied
    assert decision.bound_arguments is None


# -- semantic_eq hardening -----------------------------------------------------


def test_semantic_eq_is_total_on_a_mapping_whose_protocols_disagree():
    """What the snapshot actually buys: a decision instead of a crash.

    Be precise about the property. Reading `keys()` for the key set and `__getitem__`
    for the values trusts two protocols to agree; when they do not, the comparison can
    look up a key that the other side does not have and raise - and an exception on the
    authorization path is a denial-of-service, not a refusal. Taking one snapshot makes
    the comparison total and deterministic.

    What it does NOT buy: protection from an object that shows the *tool* something
    different from what it showed the comparison. Nothing in comparison mode can close
    that, because the tool is handed the delivered object rather than our snapshot -
    which is the argument for `Docs/pep-argument-rewrite.md`, not against this.

    Nothing hostile reaches here today: the delivered arguments are the framework's own
    JSON parse, so a plain dict.
    """

    class ProtocolsDisagree(dict):
        def items(self):
            return [("amount", 10)]        # under-reports what the dict really holds

    hostile = ProtocolsDisagree({"amount": 10, "to": "mallory"})
    # A verdict, not a KeyError - and one derived entirely from `items()`.
    assert semantic_eq(hostile, {"amount": 10}) is True
    assert semantic_eq(hostile, {"amount": 10, "to": "mallory"}) is False


def test_semantic_eq_is_total_on_a_sequence_whose_length_and_iteration_disagree():
    class ShortIter(list):
        def __iter__(self):
            return iter([1])               # claims one element; len() says three

    hostile = ShortIter([1, 2, 3])
    # `list()` takes one snapshot, so length and contents come from the same view and
    # `zip` cannot silently compare a truncated pair.
    assert semantic_eq(hostile, [1]) is True
    assert semantic_eq(hostile, [1, 2, 3]) is False
