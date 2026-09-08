"""The carry-the-octets binding profile (``agentcreds-octets-v1``).

Canonicalization is a workaround for not having the original octets. JWS and COSE
sidestep the whole problem by signing what they received; a re-serializing transport
like MCP takes that option away, so `agentcreds-jcs-v1` reconstructs the bytes on both
sides and hopes two implementations agree.

This profile removes the hope. The holder serializes its arguments however it likes,
signs *those exact bytes*, and **carries them** alongside the presentation. The verifier
never re-serializes anything:

1. It verifies the proof over the carried octets - the literal string the holder signed.
2. It parses them, and compares the result to what the transport actually delivered by
   **semantic** equality.

Both must hold. Altering the delivered arguments fails step 2; altering the carried
octets fails step 1. No two implementations ever need to agree on how to *write* a
float - only on what a float *is*, which their JSON parsers already do.

What it costs, stated plainly:

* **Payload.** The arguments travel twice. :data:`MAX_BOUND_ARGS_BYTES` caps the carried
  copy, because an unbounded attacker-supplied string on the authorization path is a
  denial-of-service primitive, not a feature.
* **Confidentiality.** The carried copy lands wherever the transport puts reserved
  arguments, which is often logged more casually than a request body. Arguments that
  are sensitive enough to matter should not be bound under this profile without
  checking where they will end up.

This is *comparison*, not authority: the tool still executes the arguments the transport
delivered. What the profile guarantees is that those arguments are semantically the ones
the holder signed. Making the carried copy authoritative - substituting it into the call
- is a strictly stronger property and a much larger change, because the enforcement
point would become rewriting rather than admitting.
"""

from __future__ import annotations

import json

__all__ = [
    "PROFILE",
    "MAX_BOUND_ARGS_BYTES",
    "BoundArgsError",
    "bind_args",
    "parse_bound_args",
    "semantic_eq",
]

#: The profile identifier that travels on the wire alongside a binding.
PROFILE = "agentcreds-octets-v1"

#: Ceiling on the carried copy, in bytes. The arguments travel twice under this profile,
#: and the second copy is attacker-controlled text that the verifier must parse before it
#: has authenticated anything. 64 KiB is far above any plausible tool call.
MAX_BOUND_ARGS_BYTES = 64 * 1024


class BoundArgsError(ValueError):
    """Carried octets that are missing, oversized, or not parseable JSON."""


def _reject_constant(name: str):
    # `json.loads` accepts NaN/Infinity by default. They are not JSON, they cannot be
    # compared for equality (NaN != NaN), and accepting them here would mean parsing
    # something the holder could not have meant.
    raise BoundArgsError(f"{name} is not valid JSON")


def bind_args(args: object) -> str:
    """Serialize arguments on the **holder** side, for both signing and carrying.

    The exact serialization does not matter - that is the point of the profile - so this
    is a plain compact ``json.dumps``. What matters is that the string returned here is
    the one bound into the action AND the one carried to the verifier. Deriving them
    separately would reintroduce exactly the divergence this profile exists to remove.
    """
    return json.dumps(args, separators=(",", ":"), allow_nan=False)


def parse_bound_args(text: object) -> object:
    """Parse carried octets on the **verifier** side.

    Raises :class:`BoundArgsError` rather than returning a sentinel: this runs before
    anything has been authenticated, so every failure has to be a refusal.
    """
    if text is None:
        raise BoundArgsError("no bound arguments were carried")
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="strict")
    if not isinstance(text, str):
        raise BoundArgsError(f"bound arguments must be text, got {type(text).__name__}")
    size = len(text.encode("utf-8"))
    if size > MAX_BOUND_ARGS_BYTES:
        raise BoundArgsError(
            f"bound arguments are {size} bytes, over the {MAX_BOUND_ARGS_BYTES}-byte limit"
        )
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except BoundArgsError:
        raise
    except ValueError as exc:
        raise BoundArgsError(f"bound arguments are not valid JSON: {exc}") from exc


def semantic_eq(a: object, b: object) -> bool:
    """Structural equality over two parsed JSON values.

    This is the whole reason the profile is simpler than canonicalization: *comparing*
    two values is forgiving where *emitting* one is not. Nothing here has to decide how
    many digits a float gets, when to use exponential notation, or which characters to
    escape - only whether two already-parsed values mean the same thing.

    Objects compare as unordered key sets; arrays keep their order, because order is
    meaning in JSON. Numbers compare numerically, so a holder that wrote ``1`` and a
    transport that delivered ``1.0`` agree - two integers compare *exactly*, which is
    how this profile avoids the 2^53 cliff that `agentcreds-jcs-v1` inherits.
    """
    # `bool` is an `int` subclass in Python, so it has to be settled before the numeric
    # branch or `True` would compare equal to `1`.
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, int) and isinstance(b, int):
            return a == b  # exact: no double in the middle, so no 2^53 cliff
        return float(a) == float(b)
    # Containers are snapshotted through a SINGLE access protocol before anything is
    # compared. Reading a mapping's `keys()` and then its `__getitem__` - or a sequence's
    # `__len__` and then its `__iter__` - trusts two protocols to agree, and an object
    # where they disagree could have a key skipped or an element substituted between the
    # comparison and the call. Nothing hostile reaches here today (the delivered
    # arguments are the framework's own JSON parse, so a plain dict), which is precisely
    # why it is cheap to make that not matter.
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        sa, sb = list(a), list(b)
        return len(sa) == len(sb) and all(semantic_eq(x, y) for x, y in zip(sa, sb))
    if isinstance(a, dict) and isinstance(b, dict):
        sa, sb = dict(a.items()), dict(b.items())
        return sa.keys() == sb.keys() and all(semantic_eq(sa[k], sb[k]) for k in sa)
    return False
