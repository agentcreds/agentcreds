"""R10 - execution-time human-authorization gate enforcement (PEP helper).

The delegated authority itself designates which tools require human approval
before execution (``token.gates()`` - carried in the token, monotone across
hops). This helper enforces those designations at the enforcement point against
carried, **principal-bound**, anchor-verified evidence, with **one-time**
reliance - the strong form of R10:

- verify designation *and* evidence offline (``DelegationToken.verify_rooted_gated``);
- refuse a designated action with no valid evidence;
- treat an unrecognized designation kind as unauthorized (fail closed);
- refuse evidence that has already been relied upon (``ConsumedApprovals``).

Evidence travels with the request; mint it with ``ApprovalEvidence.approve`` and
carry it as JSON (``ApprovalEvidence.to_json`` / ``from_json``).
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Optional, Sequence

import agentcreds as ac

#: The reference gate kind - anchor-attested human approval bound to one exact action.
APPROVAL = "approval"

#: Hybrid gate kind - approval signed by the individual approver's own key,
#: verified against an org-anchor-signed ``ApproverDirectory`` (per-human
#: non-repudiation, single trust root).
APPROVAL_KEY = "approval-key"


class GateDenied(Exception):
    """An in-token execution-time gate (R10) was not satisfied - the action is
    refused. Raised for a missing/invalid/expired grant, an unrecognized gate
    kind (fail closed), or evidence already relied upon (one-time)."""


# -- One-time reliance stores (R10) ----------------------------------------------


class ConsumedApprovalsStore(ABC):
    """Records approval ids already relied upon for execution (R10 one-time).

    Any object with a ``try_consume(approval_id) -> bool`` method works - including
    the core :class:`agentcreds.ConsumedApprovals`; these add TTL eviction and a
    shared (Redis) backend for a multi-replica PEP.

    `not_after` (unix seconds) is the evidence's own expiry: when given, the id is
    remembered until then, so it is never forgotten while the evidence is still
    verifiable. The one-time guarantee therefore does not depend on the store's
    fallback TTL being set at least as long as the evidence lifetime.
    """

    @abstractmethod
    def try_consume(self, approval_id: str, not_after: Optional[int] = None) -> bool:
        """Record `approval_id`, remembered until `not_after` (unix seconds) if given,
        else for the store's fallback TTL. Return True the first time, or False if it
        has already been relied upon (the action must then be refused)."""


class InMemoryConsumedApprovals(ConsumedApprovalsStore):
    """In-process one-time record with TTL eviction. Single-replica; use
    :class:`RedisConsumedApprovals` when more than one PEP shares the load. Each id is
    remembered until its evidence's `not_after`; `ttl_secs` is only the fallback when a
    caller records an id without an expiry."""

    def __init__(self, ttl_secs: int = 900, sweep_interval_secs: int = 60):
        self._ttl = int(ttl_secs)
        self._sweep = int(sweep_interval_secs)
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep:
            return
        self._last_sweep = now
        for k in [k for k, exp in self._seen.items() if exp <= now]:
            self._seen.pop(k, None)

    def try_consume(self, approval_id: str, not_after: Optional[int] = None) -> bool:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            exp = self._seen.get(approval_id)
            if exp is not None and exp > now:
                return False  # already relied upon while still remembered
            # Remember until the evidence's own expiry (translated to the monotonic
            # clock); fall back to the fixed TTL when no expiry is supplied.
            hold = float(self._ttl) if not_after is None else max(0.0, not_after - time.time())
            self._seen[approval_id] = now + hold
            return True


class RedisConsumedApprovals(ConsumedApprovalsStore):
    """Shared one-time record backed by Redis - enforces R10 one-time reliance
    across PEP replicas. Pass a configured client (``redis.Redis(...)`` or anything
    exposing ``set(key, value, nx=..., ex=...)``); uses an atomic ``SET ... NX EX``,
    so the first replica to rely on an id wins and any later reliance is refused.
    Each id is kept until its evidence's `not_after`; `ttl_secs` is only the fallback."""

    def __init__(self, client: object, ttl_secs: int = 900, namespace: str = "agentcreds:approval"):
        self._r = client
        self._ttl = int(ttl_secs)
        self._ns = namespace

    def try_consume(self, approval_id: str, not_after: Optional[int] = None) -> bool:
        # Keep the key until the evidence expires (min 1s for Redis EX); fall back to
        # the fixed TTL when no expiry is supplied.
        ex = self._ttl if not_after is None else max(1, int(not_after - time.time()))
        created = self._r.set(f"{self._ns}:{approval_id}", b"1", nx=True, ex=ex)
        return bool(created)


def enforce_gates(
    token: "ac.DelegationToken",
    action: "ac.Action",
    vc: "ac.CapabilityCredential",
    anchor: "ac.TrustAnchor",
    evidence: "Sequence[ac.ApprovalEvidence]" = (),
    *,
    consumed: "Optional[ac.ConsumedApprovals]" = None,
    recognized_kinds: "Iterable[str]" = (APPROVAL,),
    directory: "Optional[ac.ApproverDirectory]" = None,
    now: "Optional[int]" = None,
) -> List[str]:
    """Run the complete R10 check for ``action`` on ``token``.

    Performs the full anchor-rooted verification (R1-R6) plus, for every gate
    designating ``action.tool``, that carried ``evidence`` (verified, principal-
    bound, unexpired) satisfies it - then enforces one-time reliance via
    ``consumed``.

    Pass ``directory`` (an org-anchor-signed :class:`ac.ApproverDirectory`) to also
    satisfy hybrid ``approval-key`` gates, whose evidence is signed by the
    individual approver's key; ``approval-key`` is then auto-recognized.

    Returns the approval ids relied upon (empty if the tool is not gated). Raises
    :class:`GateDenied` if a gate is unsatisfied, its kind unrecognized, no valid
    evidence is present, or the evidence has already been relied upon.
    """
    now = int(time.time()) if now is None else now
    kinds = list(recognized_kinds)
    if directory is not None and APPROVAL_KEY not in kinds:
        kinds.append(APPROVAL_KEY)
    try:
        relied = token.verify_rooted_gated_with_directory(
            action, vc, anchor, list(evidence), directory, kinds, now
        )
    except ac.AgentCredsError as exc:  # ActionDenied / verification failure -> fail closed
        raise GateDenied(str(exc)) from exc

    if consumed is not None:
        for approval_id in relied:
            if not consumed.try_consume(approval_id):
                raise GateDenied(
                    f"approval evidence {approval_id!r} has already been relied upon "
                    "(R10 one-time)"
                )
    return relied
