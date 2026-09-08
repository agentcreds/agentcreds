"""The shared A2A-layer agreement vectors, consumed from the Python side.

``conformance/a2a_vectors.json`` is the contract between the Python and Node runtimes
for everything A2A-specific that sits ABOVE the cryptography: header names, the
principal-header scheme, bound-args encoding, the shared deny-code registry, and octets
parse/semantic-equality behaviour. The Node consumer is
``agentcreds-runtime-node/test/a2a-vectors.test.js``.

This suite is also the regeneration guard: it re-derives every derivable value from the
implementation and compares against the file, so an implementation change that would
silently strand the vectors fails here with "regenerate", the same convention as the JCS
suite.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from agentcreds_runtime import a2a, errors, octets  # noqa: E402

VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "conformance" / "a2a_vectors.json"
)
SUPPORTED_FORMAT = 1

DOC = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
CASES = DOC["cases"]


def test_format_is_supported():
    # Refusing an unknown format is the convention across every vector suite here:
    # silently skipping unrecognised cases reports success for checks that never ran.
    assert DOC["format"] == SUPPORTED_FORMAT, (
        f"a2a_vectors.json is format {DOC['format']}; this consumer understands "
        f"{SUPPORTED_FORMAT} - update the consumer, do not skip"
    )


def test_header_names_and_scheme_match_the_file():
    names = CASES["header_names"]
    assert names["capability"] == a2a.A2A_HEADER_NAME
    assert names["principal"] == a2a.A2A_PRINCIPAL_HEADER_NAME
    assert names["bound_args"] == a2a.A2A_BOUND_ARGS_HEADER_NAME
    assert names["canon_profile"] == a2a.A2A_CANON_PROFILE_HEADER_NAME
    assert CASES["principal_scheme_prefix"] == a2a._A2A_PRINCIPAL_SCHEME, (
        "the scheme prefix is wire-visible; changing it strands every Node peer - "
        "regenerate the vectors AND bump their format"
    )


def test_shared_deny_codes_match_the_file():
    expected = {name: getattr(errors, f"CODE_{name}") for name in CASES["codes"]}
    assert CASES["codes"] == expected, (
        "the deny-code registry is the wire contract with Node - a changed string "
        "here is a protocol change, not a rename"
    )


def test_octets_profile_constants_match():
    assert CASES["octets_profile"] == octets.PROFILE
    assert CASES["max_bound_args_bytes"] == octets.MAX_BOUND_ARGS_BYTES


def test_principal_headers_make_and_parse_exactly():
    for case in CASES["principal_headers"]:
        assert a2a.make_a2a_principal_header(case["token"]) == case["header"], (
            f"make must be byte-identical for {case['token']!r}"
        )
        assert a2a.parse_a2a_principal_header(case["header"]) == case["token"]


def test_malformed_principal_headers_are_rejected():
    for value in CASES["malformed_principal_headers"]:
        with pytest.raises(ValueError):
            a2a.parse_a2a_principal_header(value)


def test_bound_args_headers_make_and_parse_exactly():
    for case in CASES["bound_args_headers"]:
        assert a2a.make_a2a_bound_args_header(case["bound"]) == case["header"]
        assert a2a.parse_a2a_bound_args_header(case["header"]) == case["bound"]


def test_octets_parse_and_semantic_equality_agree_with_the_file():
    # The octets contract: bind OUTPUT is holder-chosen (both JSON dialects in the file
    # are conformant), but every verifier must PARSE either dialect and reach the same
    # semantic-equality verdict. This is what lets a Python holder talk to a Node
    # verifier and vice versa without either side re-serializing.
    for case in CASES["octets_parse_semantic"]:
        parsed = octets.parse_bound_args(case["bound"])
        got = octets.semantic_eq(parsed, case["args"])
        assert got == case["equal"], (
            f"semantic_eq({case['bound']!r}, {case['args']!r}) = {got}, "
            f"vectors say {case['equal']}"
        )


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL  {name}: {e}")
    raise SystemExit(1 if failures else 0)
