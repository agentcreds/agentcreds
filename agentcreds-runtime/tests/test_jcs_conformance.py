"""RFC 8785 canonicalization, held to the SHARED cross-language vectors.

``conformance/jcs_vectors.json`` is the contract between the Rust, Python
and Node runtimes. Argument binding hashes a *string*, so a Python enforcement point and
a Node holder must emit byte-identical text from the same arguments or a legitimate call
is refused as tampering.

This file exists because Python was the *generator* of that fixture and, until now, the
only runtime that never asserted against it. Rust (``tests/jcs_conformance.rs``) and Node
(``test/jcs.test.js``) both did. That asymmetry is the dangerous one: a regression in the
Python canonicalizer would leave its own inline expectations to be updated alongside it,
the fixture unregenerated, and the divergence surfacing in production as an unexplained
binding mismatch rather than as a red test here.

Measured on 2026-08-12, the predecessor profile (``agentcreds-json-sorted-v1``) had Python
and Node disagreeing on 9 of 18 ordinary cases - every non-ASCII string, and floats in
four separate ways.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentcreds_runtime import jcs, CANON_PROFILE_JCS
from agentcreds_runtime.policy import CANON_PROFILE_JCS

VECTORS_PATH = Path(__file__).resolve().parents[2] / "conformance" / "jcs_vectors.json"
SUITE = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def test_profile_identifier_matches_the_shared_vectors() -> None:
    # The identifier travels on the wire alongside the binding. Changing it silently
    # orphans every holder still declaring the old one, and the mismatch presents as a
    # possession failure rather than as the version skew it actually is.
    assert SUITE["profile"] == CANON_PROFILE_JCS == "agentcreds-jcs-v1"


def test_every_shared_vector_canonicalizes_to_the_same_bytes_as_rust_and_node() -> None:
    cases = SUITE["cases"]
    assert cases, "vectors file is empty"
    for case in cases:
        assert jcs.canonicalize(case["value"]) == case["expected_jcs"], (
            f"diverged from the shared vector for {case['value']!r}"
        )


def test_the_fixture_on_disk_is_what_this_implementation_produces() -> None:
    """The committed file must be regenerated when the canonicalizer changes.

    Without this, an intentional change to `jcs.py` plus an updated inline expectation
    leaves a stale fixture that Rust and Node keep asserting against - so the *other two*
    runtimes go red for a change that was made here.
    """
    regenerated = [
        {**case, "expected_jcs": jcs.canonicalize(case["value"])}
        for case in SUITE["cases"]
    ]
    assert regenerated == SUITE["cases"], (
        "conformance/jcs_vectors.json is stale - regenerate it"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, "0"),
        (-0.0, "0"),  # ECMAScript prints negative zero as "0"
        (1.0, "1"),  # no trailing ".0" - the classic Python/JS divergence
        (-1.5, "-1.5"),
        (1e20, "100000000000000000000"),  # below the exponential threshold
        (1e21, "1e+21"),  # at it
        (1e-6, "0.000001"),  # above the small threshold
        (1e-7, "1e-7"),  # below it, and the exponent is not zero-padded
        (9007199254740992.0, "9007199254740992"),  # 2**53
        (5e-324, "5e-324"),  # smallest subnormal
    ],
)
def test_numbers_follow_ecmascript_tostring(value: float, expected: str) -> None:
    # RFC 8785 does not define a number format; it defers to ECMAScript Number::toString,
    # because JSON came from JavaScript. Python's repr switches to exponential notation at
    # different magnitudes and zero-pads the exponent, so the thresholds must be pinned.
    assert jcs.serialize_number(value) == expected


def test_values_json_cannot_represent_are_refused_not_guessed() -> None:
    # A canonicalizer that substitutes emits a string the other side cannot reproduce,
    # which presents as tampering on a request that was never tampered with.
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(jcs.JcsError):
            jcs.canonicalize({"a": bad})
