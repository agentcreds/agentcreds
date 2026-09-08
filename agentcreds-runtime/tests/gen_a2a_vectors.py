#!/usr/bin/env python3
"""Generate ``conformance/a2a_vectors.json`` - the shared A2A-layer agreement vectors.

WHY THIS SUITE EXISTS
The Python and Node runtimes implement the same A2A protocol and, until 2026-09-07,
proved their agreement nowhere: each tested its own implementation, which is exactly the
two-implementations-no-comparison shape that let the two `did:web` resolvers diverge.
The cryptographic layer is already covered - the core conformance vectors prove the
presentation bytes and decisions agree through both bindings - but the A2A layer ON TOP
(header names, the principal-header scheme, bound-args encoding, deny codes, semantic
equality) had no shared fixture.

WHY THESE VECTORS ARE STATIC AND THE CRYPTO ONES ARE NOT
A2A headers embed presentations whose tokens expire within the hour, and the runtime
verifiers deliberately have no `now` seam (they are the enforcement path). So live-crypto
A2A golden files cannot sit in a repository. Everything in THIS file is deterministic
string/JSON work with no keys and no clock - which is precisely the layer where two
implementations drift silently.

WHAT IS DELIBERATELY NOT ASSERTED
`octets bind_args` OUTPUT equality. The octets profile's documented contract is that the
serialization is holder-chosen - Python's `json.dumps` ASCII-escapes, Node's
`JSON.stringify` does not, and both are conformant. The contract is that every verifier
PARSES any holder's bytes and compares them semantically the same way; the
`octets_parse_semantic` cases pin that, feeding both runtimes fixed holder bytes from
both dialects.

Regenerate (only when the A2A layer changes) with:
    python tests/gen_a2a_vectors.py
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from agentcreds_runtime import a2a, errors, octets  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[2] / "conformance" / "a2a_vectors.json"

# Wire codes BOTH runtimes must use for the same condition. Python-only codes (the MCP
# enforcer's policy/quota/approval family) are excluded: Node is A2A-only by design and
# never emits them, so listing them here would assert a contract that does not exist.
SHARED_CODES = {
    "MALFORMED": errors.CODE_MALFORMED,
    "POSSESSION": errors.CODE_POSSESSION,
    "NOT_AUTHORIZED": errors.CODE_NOT_AUTHORIZED,
    "CREDENTIAL": errors.CODE_CREDENTIAL,
    "REVOKED": errors.CODE_REVOKED,
    "PRINCIPAL": errors.CODE_PRINCIPAL,
    "UNBOUND": errors.CODE_UNBOUND,
    "UNTRUSTED_ISSUER": errors.CODE_UNTRUSTED_ISSUER,
    "REPLAY": errors.CODE_REPLAY,
    "CANON_PROFILE": errors.CODE_CANON_PROFILE,
    "ARGS_MISMATCH": errors.CODE_ARGS_MISMATCH,
    "BOUND_ARGS": errors.CODE_BOUND_ARGS,
    "DENIED": errors.CODE_DENIED,
}

# Deliberately NOT JWT-shaped and low-entropy (< 3.5 bits/char): a realistic fake token
# next to a field named "token" trips gitleaks - in our hooks, in the export leak gate,
# and in the scanner of every implementer who vendors the published file. The dotted
# base64url structure is what the case exercises; realism carries nothing.
PRINCIPAL_TOKENS = [
    "dGVzdA.dGVzdA.c2ln",  # base64url("test"."test"."sig")
    "a",  # 1 byte: exercises base64url padding-stripping on both sides
    "token-with_url+unsafe/chars=and spaces é",  # forces urlsafe alphabet + UTF-8
]

BOUND_ARGS_STRINGS = [
    '{"q":"café"}',  # literal UTF-8 bytes (the Node bind_args dialect)
    '{"q":"caf\\u00e9"}',  # ASCII-escaped (the Python json.dumps dialect)
    "{}",
]

# Fixed holder bytes in BOTH dialects; each pair states whether the two sides are
# semantically the same arguments. This is the octets contract: a verifier in either
# runtime must parse either dialect and reach the same equality verdict.
OCTETS_SEMANTIC_CASES = [
    {"bound": '{"q":"café","n":1}', "args": {"q": "café", "n": 1}, "equal": True},
    {"bound": '{"q":"caf\\u00e9","n":1}', "args": {"q": "café", "n": 1}, "equal": True},
    {"bound": '{"n":1.0,"q":"x"}', "args": {"q": "x", "n": 1}, "equal": True},  # 1.0 == 1, order-free
    {"bound": '{"q":"cafe"}', "args": {"q": "café"}, "equal": False},
    {"bound": '{"a":[1,2,3]}', "args": {"a": [1, 2, 3]}, "equal": True},
    {"bound": '{"a":[1,2,3]}', "args": {"a": [1, 3, 2]}, "equal": False},
    {"bound": '{"nested":{"x":null,"y":true}}', "args": {"nested": {"y": True, "x": None}}, "equal": True},
]

MALFORMED_PRINCIPAL_HEADERS = [
    "SomeOtherScheme/1.0 abc",
    "AgentCreds-A2A-Principal/2.whatever",  # wrong major
    "",
]


def main() -> None:
    cases = {
        "header_names": {
            "capability": a2a.A2A_HEADER_NAME,
            "principal": a2a.A2A_PRINCIPAL_HEADER_NAME,
            "bound_args": a2a.A2A_BOUND_ARGS_HEADER_NAME,
            "canon_profile": a2a.A2A_CANON_PROFILE_HEADER_NAME,
        },
        "principal_scheme_prefix": a2a._A2A_PRINCIPAL_SCHEME,
        "codes": SHARED_CODES,
        "octets_profile": octets.PROFILE,
        "max_bound_args_bytes": octets.MAX_BOUND_ARGS_BYTES,
        "principal_headers": [
            {"token": tok, "header": a2a.make_a2a_principal_header(tok)}
            for tok in PRINCIPAL_TOKENS
        ],
        "malformed_principal_headers": MALFORMED_PRINCIPAL_HEADERS,
        "bound_args_headers": [
            {"bound": s, "header": a2a.make_a2a_bound_args_header(s)}
            for s in BOUND_ARGS_STRINGS
        ],
        "octets_parse_semantic": OCTETS_SEMANTIC_CASES,
    }
    doc = {
        "format": 1,
        "note": (
            "Shared A2A-layer agreement vectors. Deterministic string/JSON contracts "
            "only - no keys, no clock; the cryptographic layer is proven by the core "
            "conformance vectors. Generated from the Python runtime "
            "(tests/gen_a2a_vectors.py) - regenerate there, never hand-edit. Octets "
            "bind OUTPUT is deliberately absent: the profile makes serialization "
            "holder-chosen, so only parse+semantic agreement is a contract."
        ),
        "cases": cases,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
