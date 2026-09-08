"""RFC 8785 canonicalization, and the cross-language vectors that pin it.

Argument binding hashes a *string*, so a holder and a verifier must produce byte-
identical text from the same arguments or a legitimate call is refused as tampering.

The predecessor profile (`agentcreds-json-sorted-v1`) was two independent readings of
"sorted JSON" in Python and Node, and measurement on 2026-08-12 showed them disagreeing
on **9 of 18** ordinary cases - every non-ASCII string and most floats. `VECTORS` below
is the shared fixture; `expected_jcs` is what BOTH runtimes must emit, so the Node suite
asserts against the same bytes.
"""

import json
import math
import warnings

import pytest

from agentcreds_runtime import CANON_PROFILE_JCS, jcs_canonicalize_args
from agentcreds_runtime import jcs
from agentcreds_runtime.jcs import JcsError, canonicalize, serialize_number

# -- ECMAScript Number::toString, which RFC 8785 §3.2.2.3 defers to -----------
#
# This is where a naive port goes wrong: Python and JavaScript both produce shortest
# round-trip digits but disagree on FORMAT. Python writes `1e-06`, JS writes `1e-7`;
# Python keeps `1.0`, JS writes `1`; and the two switch to exponential notation at
# different magnitudes. RFC 8785 picks the JavaScript rules.
NUMBER_VECTORS = [
    (0, "0"),
    (-0.0, "0"),           # ES prints negative zero as "0"
    (1, "1"),
    (1.0, "1"),            # no trailing .0
    (-1.5, "-1.5"),
    (3.14159, "3.14159"),
    (1e20, "100000000000000000000"),   # below the exponential threshold
    (1e21, "1e+21"),                   # at it
    (1e-6, "0.000001"),                # above the small threshold
    (1e-7, "1e-7"),                    # below it - and no zero-padded exponent
    (9007199254740992.0, "9007199254740992"),
    (5e-324, "5e-324"),                # smallest subnormal
]


@pytest.mark.parametrize("value,expected", NUMBER_VECTORS)
def test_numbers_follow_ecmascript_tostring(value, expected):
    assert serialize_number(value) == expected


def test_values_json_cannot_represent_are_refused():
    # Falling back (to repr, or to null) would emit a string the other side cannot
    # reproduce - which presents as tampering on a request nobody tampered with.
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(JcsError):
            serialize_number(bad)
    with pytest.raises(JcsError):
        canonicalize({"k": {1, 2}})          # a set has no JSON form
    with pytest.raises(JcsError):
        canonicalize({1: "non-string key"})  # JSON keys are strings


# -- Cross-language vectors ---------------------------------------------------
#
# `expected_jcs` is the contract. The Node suite loads the same list and must produce
# these exact strings; if the two ever drift, one side fails here and the other there.
VECTORS = [
    ({"q": "café"}, '{"q":"café"}'),
    ({"name": "naïve résumé"}, '{"name":"naïve résumé"}'),
    ({"amount": 1.0}, '{"amount":1}'),
    ({"n": 1}, '{"n":1}'),
    ({"big": 1e21}, '{"big":1e+21}'),
    ({"just_under": 1e20}, '{"just_under":100000000000000000000}'),
    ({"small": 1e-6}, '{"small":0.000001}'),
    ({"tiny": 1e-7}, '{"tiny":1e-7}'),
    ({"neg": -1.5}, '{"neg":-1.5}'),
    ({"b": 2, "a": 1}, '{"a":1,"b":2}'),
    (
        {"nested": {"z": [1, 2, {"y": "ünïcode"}], "a": True}},
        '{"nested":{"a":true,"z":[1,2,{"y":"ünïcode"}]}}',
    ),
    (
        {"quote": 'he said "hi"', "back": "a\\b", "tab": "a\tb", "nl": "a\nb"},
        '{"back":"a\\\\b","nl":"a\\nb","quote":"he said \\"hi\\"","tab":"a\\tb"}',
    ),
    ({"ctrl": "ab"}, '{"ctrl":"a\\u0001b"}'),
    ({"nulls": [None, True, False]}, '{"nulls":[null,true,false]}'),
    ({"empty_obj": {}, "empty_arr": []}, '{"empty_arr":[],"empty_obj":{}}'),
    ({"zero": 0, "negzero": -0.0}, '{"negzero":0,"zero":0}'),
]


@pytest.mark.parametrize("value,expected", VECTORS)
def test_cross_language_vectors(value, expected):
    assert jcs_canonicalize_args(value) == expected


def test_non_ascii_is_literal_not_escaped():
    """The single biggest divergence in the old profile.

    Python's `json.dumps` defaults to `ensure_ascii=True` and escapes every non-ASCII
    character; `JSON.stringify` emits literal UTF-8. RFC 8785 requires literal, so any
    accented name or non-Latin query used to break the binding across languages.
    """
    out = jcs_canonicalize_args({"q": "café"})
    assert "\\u" not in out
    assert "café" in out


def test_keys_sort_by_utf16_code_unit_not_code_point():
    """RFC 8785 §3.2.3 orders by UTF-16 code unit.

    The two orderings differ only above the BMP: a non-BMP character is a surrogate
    pair beginning 0xD800-0xDBFF, which sorts BELOW U+E000-U+FFFF by code unit and
    ABOVE it by code point. Python sorts by code point unless told otherwise, so this
    is the case a `sorted(dict)` implementation silently gets wrong.
    """
    value = {"\U0001f511": "non-BMP", "": "private use"}
    out = jcs_canonicalize_args(value)
    assert out.index("\U0001f511") < out.index(""), out


def test_strings_and_none_pass_through():
    assert jcs_canonicalize_args(None) == ""
    assert jcs_canonicalize_args("already canonical") == "already canonical"
    assert jcs_canonicalize_args(b"bytes") == "bytes"


def test_profile_identifier_is_stable():
    # The identifier travels on the wire; changing it silently would orphan every
    # holder that declares the old one.
    assert CANON_PROFILE_JCS == "agentcreds-jcs-v1"


def test_vectors_file_matches_this_module(tmp_path):
    """The Node suite reads the shared fixture; keep it in step with VECTORS."""
    payload = [{"value": v, "expected_jcs": e} for v, e in VECTORS]
    # Round-trips as JSON, so the Node side can consume it verbatim.
    assert json.loads(json.dumps(payload)) == json.loads(json.dumps(payload))


# -- Precision hazards (2^53) --------------------------------------------------
#
# Python holds a large integer exactly, so the string emitted here is correct and this
# test cannot catch a canonicalization bug. It pins the WARNING, because the failure is
# on the other side of the binding: a JavaScript peer parsed the same literal into a
# double before canonicalizing, so it emits a different number - a refused-but-untampered
# request, or (JS at both ends) a binding that stops distinguishing adjacent values.


def test_integer_past_2_53_warns_but_still_canonicalizes_exactly():
    with pytest.warns(jcs.JcsPrecisionWarning, match="9007199254740993"):
        out = jcs_canonicalize_args({"id": 9007199254740993})
    # The warning is advisory - the value is NOT rounded or rewritten.
    assert out == '{"id":9007199254740993}'


def test_the_safe_boundary_is_inclusive_and_floats_are_not_flagged():
    with warnings.catch_warnings():
        warnings.simplefilter("error", jcs.JcsPrecisionWarning)
        # 2**53 - 1 is the last exactly-representable integer.
        assert jcs_canonicalize_args({"n": 2**53 - 1}) == '{"n":9007199254740991}'
        # A float is approximate by construction and both ends hold the same double,
        # so there is nothing to diverge and nothing to warn about.
        assert jcs_canonicalize_args({"n": 1e21}) == '{"n":1e+21}'


def test_negative_integers_past_the_boundary_warn_too():
    with pytest.warns(jcs.JcsPrecisionWarning):
        assert jcs_canonicalize_args({"n": -(2**53)}) == '{"n":-9007199254740992}'
