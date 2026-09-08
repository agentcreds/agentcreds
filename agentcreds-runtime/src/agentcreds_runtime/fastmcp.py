"""Adapter for the official MCP Python SDK (FastMCP).

This module does not import `mcp` at load time, so importing `agentcreds_runtime`
never requires the MCP SDK. The pieces here are thin wiring over
`IdentityEnforcer`; the enforcement decision itself lives in the enforcer and is
SDK-version independent.

Integration model
-----------------
1. When a session initializes, call ``enforcer.issue_challenge(session_id)`` and
   deliver the returned CBOR to the client (e.g. via an `initialize` result
   field or a dedicated `agentcreds/challenge` tool). The client signs it and
   returns a `Presentation`.
2. The client attaches the presentation (base64-encoded CBOR) to each tool call.
   The simplest portable convention - used by :func:`guard_tool` - is a reserved
   string argument (default ``"agentcreds_presentation"``). When you pin to an
   SDK version that exposes request ``_meta`` in the tool `Context`, move the
   presentation there and pass a custom ``presentation_getter`` instead.

:func:`guard_tool` is a decorator for a FastMCP async tool coroutine. It enforces
identity, then calls your handler; on failure it raises :class:`AccessDenied`,
which FastMCP surfaces to the client as a tool error.
"""

from __future__ import annotations

import base64
from functools import wraps
from typing import Awaitable, Callable, Optional

from .enforcer import IdentityEnforcer
from .errors import CODE_MALFORMED, AccessDenied, Decision

#: Default reserved tool argument carrying the base64-CBOR presentation.
PRESENTATION_ARG = "agentcreds_presentation"

#: Reserved argument by which a holder declares its canonicalization profile
#: (-02 §1.3). Like the others it is STRIPPED before the arguments are
#: canonicalized - a reserved name that reaches the binding denies every
#: correctly-bound client with a crypto-looking error, which has happened.
CANON_PROFILE_ARG = "agentcreds_canon_profile"

#: Reserved argument carrying the holder's literal serialized arguments under
#: `agentcreds-octets-v1` - the bytes it signed, so the verifier never re-serializes
#: anything. Ignored by every other profile.
#:
#: Reserved, and therefore stripped before the arguments are compared: left in, it would
#: appear in the delivered arguments but not in the holder's copy, so the semantic
#: comparison could never match and every correctly-bound client would be refused.
BOUND_ARGS_ARG = "agentcreds_bound_args"

#: Default reserved tool argument carrying R10 approval evidence - a JSON string
#: (one grant) or a list of JSON strings (m-of-n). Optional; only tools the
#: presented token gates on human approval require it.
EVIDENCE_ARG = "agentcreds_approval"


def default_session_id(ctx: object) -> str:
    """Best-effort **stable** per-connection identifier from a FastMCP `Context`.

    Must be identical across every call in one client session: a challenge issued
    on the ``issue_challenge`` call is looked up on the later tool call, so a
    *per-request* id (e.g. ``request_id``, which changes on every call) must NOT
    be used - that yields ``no_active_challenge``. Prefer the transport session id
    (the streamable-HTTP ``Mcp-Session-Id``), then the underlying session object's
    identity; fall back to ``"default"`` only if none is present.
    """
    for attr in ("client_id", "session_id"):
        val = getattr(ctx, attr, None)
        if val:
            return str(val)
    # Streamable-HTTP: the Mcp-Session-Id header is stable for the connection.
    try:
        sid = ctx.request_context.request.headers.get("mcp-session-id")  # type: ignore[attr-defined]
        if sid:
            return str(sid)
    except Exception:  # noqa: BLE001 - best-effort across SDK versions
        pass
    session = getattr(ctx, "session", None)
    if session is not None:
        return str(id(session))
    return "default"


def _coerce_presentation(value: object) -> bytes:
    if value is None:
        raise AccessDenied(
            Decision(False, CODE_MALFORMED, "no presentation attached to call")
        )
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return base64.b64decode(value)
        except Exception as exc:  # noqa: BLE001 - report as malformed
            raise AccessDenied(
                Decision(False, CODE_MALFORMED, f"presentation not base64: {exc}")
            )
    raise AccessDenied(
        Decision(False, CODE_MALFORMED, f"unsupported presentation type: {type(value)!r}")
    )


def _coerce_evidence(value: object) -> "list":
    """Parse R10 approval evidence from a tool argument: absent (None or "") -> none;
    a JSON string -> one; a list of JSON strings (or already-parsed evidence) -> many.

    An empty string means *no evidence*, not malformed evidence. A tool that accepts
    optional evidence has to declare the parameter with a default, and over MCP that
    default is a string (``agentcreds_approval: str = ""``) which FastMCP materialises
    into every call. Treating "" as a parse failure therefore denied every ungated
    call on any tool that merely *offered* the approval path - observed as
    ``malformed_presentation: approval evidence not valid JSON``.
    """
    import agentcreds as ac

    if value is None or value == "":
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for item in items:
        if item == "":
            continue  # same rationale as above, per element
        if isinstance(item, ac.ApprovalEvidence):
            out.append(item)
        elif isinstance(item, str):
            try:
                out.append(ac.ApprovalEvidence.from_json(item))
            except Exception as exc:  # noqa: BLE001 - report as malformed
                raise AccessDenied(
                    Decision(False, CODE_MALFORMED, f"approval evidence not valid JSON: {exc}")
                )
        else:
            raise AccessDenied(
                Decision(False, CODE_MALFORMED, f"unsupported evidence type: {type(item)!r}")
            )
    return out


def guard_tool(
    enforcer: IdentityEnforcer,
    tool_name: str,
    *,
    presentation_arg: str = PRESENTATION_ARG,
    session_id_getter: Callable[[object], str] = default_session_id,
    presentation_getter: Optional[Callable[..., object]] = None,
    resource_getter: Optional[Callable[..., Optional[str]]] = None,
    evidence_arg: str = EVIDENCE_ARG,
    evidence_getter: Optional[Callable[..., object]] = None,
) -> Callable[[Callable[..., Awaitable]], Callable[..., Awaitable]]:
    """Wrap a FastMCP async tool handler with identity enforcement.

    The wrapped handler is called only if the presentation verifies. Two values
    are made available to it, each only if it declares the parameter:

    - ``agentcreds_chain`` - the verified delegation chain.
    - ``agentcreds_record_id`` - the id of the Authorization Decision Record that
      permitted this call. **Log it against whatever the call changes.** An ADR
      records that authority was checked and permitted, not that the tool ran or
      what it did; without this id the only join between a decision and its effect
      is ``vc_id``, which every call under the same credential shares.

    By default the presentation is read from the ``presentation_arg`` keyword and
    the session id from a `Context` passed as ``ctx``/``context``. Override
    ``presentation_getter`` (receives the same ``*args, **kwargs``) to source it
    from request metadata instead.

    For on-behalf-of tools, supply ``resource_getter`` (receives the same
    ``*args, **kwargs``) to derive the resource id this call touches - e.g.
    ``lambda **kw: f"mailbox:{kw['mailbox']}"`` - so the enforcer can hold the
    call to the token's resource scope. The session's human principal must have
    been bound out of band via ``enforcer.bind_principal(session_id, did)``.
    """

    def decorator(fn: Callable[..., Awaitable]) -> Callable[..., Awaitable]:
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            ctx = kwargs.get("ctx") or kwargs.get("context")
            session_id = session_id_getter(ctx)

            if presentation_getter is not None:
                raw = presentation_getter(*args, **kwargs)
            else:
                raw = kwargs.get(presentation_arg)
            presentation = _coerce_presentation(raw)

            resource = resource_getter(*args, **kwargs) if resource_getter is not None else None

            # R10 execution-time human-authorization evidence carried with the call
            # (only tools the token gates on approval require it).
            if evidence_getter is not None:
                raw_ev = evidence_getter(*args, **kwargs)
            else:
                raw_ev = kwargs.get(evidence_arg)
            evidence = _coerce_evidence(raw_ev)

            # Arguments handed to the enforcer for audit: everything except the
            # transport/credential plumbing.
            audit_args = {
                k: v
                for k, v in kwargs.items()
                if k not in (presentation_arg, evidence_arg, CANON_PROFILE_ARG,
                             BOUND_ARGS_ARG,
                             "ctx", "context", "agentcreds_chain", "agentcreds_record_id")
            }

            decision = enforcer.enforce_decision(
                session_id, tool_name, audit_args, presentation,
                resource=resource, approval_evidence=evidence,
                canonicalization_profile=kwargs.get(CANON_PROFILE_ARG),
                bound_arguments=kwargs.get(BOUND_ARGS_ARG),
            )

            # Surface the verified chain, and the id of the decision record that
            # permitted this call, to handlers that declare them.
            #
            # A handler that logs `agentcreds_record_id` alongside whatever it
            # changes turns a decision and its effect into a one-to-one pair. An
            # ADR proves authority was checked, not that anything happened; without
            # this id the only join is `vc_id`, which every call under the same
            # credential shares - enough to say an agent could have done it, never
            # enough to say it did.
            import inspect

            params = inspect.signature(fn).parameters
            # A handler taking **kwargs accepts these too. Without that branch the
            # `idempotent` fallback to the decision id silently never engages for a
            # handler written as `**_`, and an absent duplicate-suppression control
            # looks identical to one that is working.
            takes_kwargs = any(
                p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
            )
            if "agentcreds_chain" in params or takes_kwargs:
                kwargs["agentcreds_chain"] = decision.chain
            if "agentcreds_record_id" in params or takes_kwargs:
                kwargs["agentcreds_record_id"] = decision.record_id
            return await fn(*args, **kwargs)

        return wrapper

    return decorator
