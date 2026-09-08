"""JSON Canonicalization Scheme (RFC 8785), delegating to the core.

Argument binding hashes a *string*, so holder and verifier must produce byte-identical
text from the same arguments or a legitimate call is refused as tampering. The
predecessor profile was two independent implementations of "sorted JSON" and they
disagreed on **9 of 18** ordinary cases - every non-ASCII string, and floats in four
separate ways.

This module used to be a third implementation: a hand-written Python port of RFC 8785,
including ECMAScript ``Number::toString``. That port is gone. The same algorithm
maintained twice in two languages is the thing most likely to drift, and the number
formatting is the hardest part of the profile to get right - Python's ``repr`` agrees on
the digits but not on where the decimal point goes or when exponential form starts.

What remains here is the Python-shaped surface: the argument conventions
(``None``/``str``/``bytes`` pass-through), the exception type, and the precision warning.
The canonicalization itself is `agentcreds_core::jcs`, reached through the wheel and
pinned - along with the Node implementation - by the shared vectors in
``conformance/jcs_vectors.json``.
"""

from __future__ import annotations

import warnings

import agentcreds as _ac

__all__ = [
    "canonicalize",
    "serialize_number",
    "JcsError",
    "JcsPrecisionWarning",
    "MAX_SAFE_INTEGER",
]


class JcsError(ValueError):
    """A value that RFC 8785 cannot represent (NaN, Infinity, a non-string key)."""


class JcsPrecisionWarning(UserWarning):
    """An integer too large to survive the JSON data model's IEEE-754 doubles.

    Not an error: Python holds the value exactly and canonicalizes it exactly, so the
    string emitted here is right. The hazard is on the *other* side of the binding.
    """


#: Above this magnitude, integers stop being uniquely representable as doubles - 2^53
#: and 2^53+1 both round to the same value. Matches JavaScript's
#: ``Number.MAX_SAFE_INTEGER``, which is where the loss actually happens.
MAX_SAFE_INTEGER = _ac.JCS_MAX_SAFE_INTEGER


def _warn_precision_hazards(value: object) -> None:
    """Warn once per oversized integer, located by RFC 6901 pointer.

    Python is the side that gets these right, which is exactly why it has to say so: a
    JavaScript holder or verifier parsed the same literal into a double and lost the low
    bits before canonicalization ran, so it canonicalizes a *different* integer. The
    binding then either mismatches - a legitimate call refused - or, if both ends are JS,
    silently stops distinguishing the value from its neighbour.
    """
    for pointer, literal in _ac.jcs_precision_hazards(value):
        where = f" at {pointer}" if pointer else ""
        warnings.warn(
            f"integer {literal}{where} exceeds 2^53-1 and does not survive the JSON "
            f"data model; argument binding cannot reliably distinguish it from an "
            f"adjacent value. Carry large identifiers as strings.",
            JcsPrecisionWarning,
            stacklevel=3,
        )


def serialize_number(value: float | int) -> str:
    """ECMAScript ``Number::toString`` (ECMA-262 §6.1.6.1.20), as RFC 8785 requires.

    Integers are handled here because they print exactly and must not be routed through
    a double - that rounding is the 2^53 hazard itself. Everything else defers to the
    core's port of the ECMAScript algorithm.
    """
    if isinstance(value, bool):  # bool is an int subclass - reject before the int path
        raise JcsError("booleans are not numbers in JCS")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            _warn_precision_hazards({"n": value})
        return str(value)
    try:
        return _ac.jcs_serialize_float(float(value))
    except ValueError as exc:
        raise JcsError(str(exc)) from exc


def canonicalize(value) -> str:
    """The RFC 8785 canonical form of ``value``.

    Raises :class:`JcsError` rather than falling back to ``repr``. A canonicalizer that
    guesses produces a string the other side cannot reproduce, which presents as a
    tampering signal on a request that was never tampered with - so an unrepresentable
    argument has to fail loudly at the holder.
    """
    try:
        out = _ac.jcs_canonicalize(value)
    except ValueError as exc:
        raise JcsError(str(exc)) from exc
    _warn_precision_hazards(value)
    return out
