"""Selective disclosure across the Python binding (SD-JWT).

The Rust core proves the cryptography. These cover the part a deployment actually
touches: whether a holder can present a *subset* of its claims through this binding at
all, and whether the withheld ones are genuinely absent rather than merely unreported.

Checked here because a Python relying party sees SD-JWT through this binding and nothing
else. `agentcreds-py` enables the core's `sd-jwt` feature unconditionally, but nothing
asserted the surface was reachable - so "is selective disclosure available to a
deployment?" had no test that could answer it either way.

Note the scope: SD-JWT only. **BBS+ is not in the wheel** - the core's `bbs` feature is
opt-in and neither binding enables it - so unlinkable presentation remains Rust-only.

Run:  pytest tests/test_selective_disclosure.py
"""

import json

import pytest

import agentcreds as ac


def _issued():
    anchor = ac.TrustAnchor.generate()
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(
        tools=["tool:search", "tool:email", "tool:admin"],
        max_delegation_depth=1,
        valid_for_secs=3600,
    )
    return anchor, agent, ac.SdJwt.from_capability(anchor, agent.did, claims, 3600)


def test_the_binding_exposes_disclosable_claims():
    _, _, sd = _issued()
    claims = sd.disclosable_claims()
    assert claims, "no disclosable claims - selective disclosure is unreachable from Python"
    assert "tools" in claims


def test_a_subset_verifies_and_reveals_only_what_was_disclosed():
    anchor, _, sd = _issued()
    available = sd.disclosable_claims()
    chosen, withheld = available[0], available[1:]

    disclosed = ac.SdJwt.verify_presentation(sd.present([chosen]), anchor)
    body = json.loads(disclosed.disclosed_json)

    assert chosen in body
    for w in withheld:
        assert w not in body, f"withheld claim {w!r} came back from the verifier"


def test_withheld_claims_are_absent_from_the_presentation_bytes():
    """The property that matters: not hidden behind an API, actually not sent.

    A verifier that simply declined to *report* undisclosed claims would pass the test
    above while still receiving them.
    """
    _, _, sd = _issued()
    available = sd.disclosable_claims()
    presentation = sd.present([available[0]])

    for w in available[1:]:
        assert w not in presentation, f"withheld claim {w!r} is present in the wire bytes"


def test_disclosing_everything_reveals_everything():
    anchor, _, sd = _issued()
    available = sd.disclosable_claims()
    disclosed = ac.SdJwt.verify_presentation(sd.present(available), anchor)
    body = json.loads(disclosed.disclosed_json)
    for c in available:
        assert c in body


def test_an_unrelated_anchor_does_not_verify_the_presentation():
    _, _, sd = _issued()
    presentation = sd.present(sd.disclosable_claims()[:1])
    with pytest.raises(Exception):
        ac.SdJwt.verify_presentation(presentation, ac.TrustAnchor.generate())


def test_a_tampered_presentation_is_refused():
    anchor, _, sd = _issued()
    presentation = sd.present(sd.disclosable_claims()[:1])
    with pytest.raises(Exception):
        ac.SdJwt.verify_presentation(presentation[:-4] + "AAAA", anchor)


def test_a_parsed_sd_jwt_round_trips():
    _, _, sd = _issued()
    assert ac.SdJwt.parse(sd.as_str()).disclosable_claims() == sd.disclosable_claims()
