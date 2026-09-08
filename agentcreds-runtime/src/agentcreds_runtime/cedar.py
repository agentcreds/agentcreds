"""Optional Cedar-backed policy hook (policy-as-code).

`cedarpy` is an **optional** dependency - importing this module never imports it.
`cedar_policy_hook` imports it lazily and raises a clear `ImportError` (with an
install hint) only if you actually build a Cedar hook without it installed. This
keeps the runtime dependency-free; install the engine with the `cedar` extra
(`pip install "agentcreds-runtime[cedar]"`) to use it.

The hook is a drop-in `PolicyHook` (see `agentcreds_runtime.policy`): it runs as the
final, offline gate *after* the credential has cryptographically verified, mapping
the verified call to a Cedar authorization request:

    principal  ->  <principal_type>::"<OIDC principal DID, else leaf agent DID>"
    action     ->  <action_type>::"<tool>"
    resource   ->  <resource_type>::"<resource id, else the tool>"
    context    ->  { tool, resource, principal_did, depth, budget_usd?, args }

so a Cedar policy can gate on the human's identity, the delegation depth/budget, the
resource, and the request arguments - conditions the capability itself can't express.
Cedar is deny-by-default, so anything not explicitly `permit`-ted is denied. A Cedar
*evaluation error* is raised (not silently denied), which the policy gate then treats
as fail-closed.
"""

from __future__ import annotations

from typing import Optional

from .policy import PolicyHook, PolicyInput

_INSTALL_HINT = (
    "Cedar policy support requires the optional 'cedarpy' package. "
    'Install it with: pip install "agentcreds-runtime[cedar]"  (or: pip install cedarpy)'
)


def _cedar_safe(obj):
    """Coerce an arbitrary value into something Cedar's context accepts (records,
    sets, strings, longs, bools). Cedar has no float type, so non-int numbers and
    other types are stringified rather than risk an evaluation error."""
    if isinstance(obj, bool):  # bool is an int subclass - check first
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return {str(k): _cedar_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_cedar_safe(v) for v in obj]
    return str(obj)


def _uid(entity_type: str, ident: str) -> str:
    escaped = ident.replace("\\", "\\\\").replace('"', '\\"')
    return f'{entity_type}::"{escaped}"'


def cedar_policy_hook(
    policies: str,
    *,
    entities: "Optional[object]" = None,
    schema: "Optional[str]" = None,
    principal_type: str = "Agent",
    action_type: str = "Action",
    resource_type: str = "Resource",
    deny_reason: str = "denied by Cedar policy",
) -> PolicyHook:
    """Build a :data:`~agentcreds_runtime.policy.PolicyHook` that decides each
    verified call with Cedar.

    Parameters
    ----------
    policies:
        Cedar policy text (one or more `permit`/`forbid` statements).
    entities:
        Optional Cedar entities (JSON string or list of entity dicts) for any
        principal/resource attributes or group memberships your policies reference.
        Defaults to an empty store.
    schema:
        Optional Cedar schema (JSON string) to validate requests against.
    principal_type / action_type / resource_type:
        Cedar entity-type names used to build the request uids.
    deny_reason:
        Reason string returned on a Cedar `Deny` (the determining policy ids, if
        any, are appended).

    Raises
    ------
    ImportError:
        If `cedarpy` is not installed (with an install hint).
    """
    try:
        from cedarpy import Decision, is_authorized
    except ImportError as exc:  # pragma: no cover - exercised only without cedarpy
        raise ImportError(_INSTALL_HINT) from exc

    entities_arg = entities if entities is not None else "[]"

    def hook(pin: PolicyInput) -> Optional[str]:
        principal_id = pin.principal or (pin.chain[-1].agent_did if pin.chain else "unknown")
        resource_id = pin.resource or pin.tool

        context = {
            "tool": pin.tool,
            "resource": resource_id,
            "principal_did": pin.principal or "",
            "depth": len(pin.chain) if pin.chain else 0,
            "args": _cedar_safe(pin.arguments) if pin.arguments is not None else {},
        }
        if pin.chain and pin.chain[-1].budget_usd is not None:
            context["budget_usd"] = int(pin.chain[-1].budget_usd)

        request = {
            "principal": _uid(principal_type, principal_id),
            "action": _uid(action_type, pin.tool),
            "resource": _uid(resource_type, resource_id),
            "context": context,
        }

        if schema is not None:
            result = is_authorized(request, policies, entities_arg, schema=schema)
        else:
            result = is_authorized(request, policies, entities_arg)

        diagnostics = getattr(result, "diagnostics", None)
        errors = getattr(diagnostics, "errors", None) or []
        if errors:
            # An evaluation error means the engine couldn't decide - surface it so
            # the policy gate fails CLOSED rather than silently denying.
            raise RuntimeError("cedar policy evaluation error: " + "; ".join(str(e) for e in errors))

        if result.decision == Decision.Allow:
            return None

        reasons = getattr(diagnostics, "reasons", None) or []
        if reasons:
            return f"{deny_reason} (policies: {', '.join(str(r) for r in reasons)})"
        return deny_reason  # deny-by-default: no permit matched

    return hook
