"""Idempotency keys for tool handlers - duplicate suppression at the TOOL layer.

**This is a correctness control, not a security control.** Keep the distinction clear:

* :mod:`~agentcreds_runtime.replay` (``ReplayGuard``) is *security*: it stops an
  adversary re-using a captured presentation. It lives on the enforcement path and
  answers "may this proof be used again?"
* Idempotency is *correctness*: it stops a duplicate **delivery** - from a network retry,
  a client bug, a load-balancer resend, or a replay - from causing a duplicate **side
  effect**. It lives in the tool and answers "have I already done this?"

They are complementary and neither substitutes for the other:

==================  =================  ====================
                    Different request  Same request twice
==================  =================  ====================
Request binding     blocked            allowed
Idempotency key     not its job        harmless
Replay guard        blocked            blocked
==================  =================  ====================

Request binding (see ``PolicyConfig.require_argument_binding``) already confines a
captured presentation to the *identical* call. Idempotency makes that identical call
harmless, which is what removes the need to put single-use state on the hot path.

Why the tool owns this: only the tool author knows what "the same operation" means. A
search may repeat freely; a transfer must not. The PEP cannot guess that per tool, and
guessing wrongly is worse than not guessing.

Usage::

    store = InMemoryIdempotencyStore()          # or RedisIdempotencyStore(redis_client)

    @mcp.tool()
    @guard_tool(enforcer, "tool:transfer")
    @idempotent(store)                          # reads `idempotency_key` from the call
    async def transfer(amount: int, idempotency_key: str, ctx: Context, **_) -> str:
        return do_transfer(amount)

A caller that retries with the same ``idempotency_key`` gets the first result back and
the transfer runs once. A caller that omits the key gets the default behavior set by
``require_key``.
"""

from __future__ import annotations

import functools
import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional, Tuple

__all__ = [
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "RedisIdempotencyStore",
    "IdempotencyConflict",
    "idempotent",
]

# Sentinel stored while a call is running, so a concurrent duplicate can be told the
# operation is in flight rather than being allowed to execute a second time.
_IN_FLIGHT = "\x00in-flight"


class IdempotencyConflict(RuntimeError):
    """A duplicate arrived while the first call is still running.

    Mirrors the industry convention (Stripe returns HTTP 409 for this): the caller should
    retry after a short delay rather than assume success or failure. Returning "success"
    would be a lie - the first attempt may still fail.
    """


class IdempotencyStore(ABC):
    """Records in-flight and completed operations by caller-supplied key."""

    @abstractmethod
    def begin(self, key: str) -> Tuple[bool, Optional[str]]:
        """Atomically claim ``key``.

        Returns ``(is_new, prior_result)``:

        * ``(True, None)``  - first caller; execute and then call :meth:`complete`.
        * ``(False, result)`` - already completed; return ``result`` without executing.
        * ``(False, None)``  - already in flight; raise :class:`IdempotencyConflict`.
        """

    @abstractmethod
    def complete(self, key: str, result: str) -> None:
        """Record the result so later duplicates return it instead of re-executing."""

    @abstractmethod
    def abandon(self, key: str) -> None:
        """Release a claimed key after a FAILED attempt, so a retry may proceed.

        Without this a transient failure would wedge the key for its whole TTL and every
        retry would raise :class:`IdempotencyConflict` - turning one failure into a
        sustained outage for that operation.
        """


class InMemoryIdempotencyStore(IdempotencyStore):
    """Single-process store with TTL eviction. Use Redis across replicas.

    The TTL is a *business* lifetime, not a freshness window: it should cover how long a
    client might legitimately retry - typically hours, far longer than the seconds-scale
    ``ReplayGuard`` TTL. These are different concerns with different lifetimes; do not
    reuse one number for both.
    """

    def __init__(self, ttl_secs: int = 24 * 3600, sweep_interval_secs: int = 300):
        self._ttl = int(ttl_secs)
        self._sweep_interval = int(sweep_interval_secs)
        self._entries: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        for k in [k for k, (_, exp) in self._entries.items() if exp <= now]:
            self._entries.pop(k, None)

    def begin(self, key: str) -> Tuple[bool, Optional[str]]:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            entry = self._entries.get(key)
            if entry is not None and entry[1] > now:
                value = entry[0]
                return False, (None if value == _IN_FLIGHT else value)
            self._entries[key] = (_IN_FLIGHT, now + self._ttl)
            return True, None

    def complete(self, key: str, result: str) -> None:
        with self._lock:
            self._entries[key] = (result, time.monotonic() + self._ttl)

    def abandon(self, key: str) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry[0] == _IN_FLIGHT:
                self._entries.pop(key, None)


class RedisIdempotencyStore(IdempotencyStore):
    """Shared store backed by Redis - correct across replicas.

    Pass a configured client (``redis.Redis(...)`` or anything exposing ``set``/``get``/
    ``delete``); this module imports nothing and adds no hard dependency. The claim uses
    an atomic ``SET key ... NX EX ttl`` so exactly one caller wins the race.
    """

    def __init__(
        self,
        client: object,
        ttl_secs: int = 24 * 3600,
        namespace: str = "agentcreds:idem",
    ):
        self._r = client
        self._ttl = int(ttl_secs)
        self._ns = namespace

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    def begin(self, key: str) -> Tuple[bool, Optional[str]]:
        if self._r.set(self._k(key), _IN_FLIGHT, nx=True, ex=self._ttl):
            return True, None
        raw = self._r.get(self._k(key))
        if raw is None:  # expired between SET NX and GET - treat as a fresh claim
            return self.begin(key)
        value = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
        return False, (None if value == _IN_FLIGHT else value)

    def complete(self, key: str, result: str) -> None:
        self._r.set(self._k(key), result, ex=self._ttl)

    def abandon(self, key: str) -> None:
        raw = self._r.get(self._k(key))
        if raw is None:
            return
        value = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
        if value == _IN_FLIGHT:
            self._r.delete(self._k(key))


def idempotent(
    store: IdempotencyStore,
    *,
    key_arg: str = "idempotency_key",
    require_key: bool = False,
    fall_back_to_decision: bool = True,
) -> Callable:
    """Make an async tool handler idempotent on a caller-supplied key.

    ``require_key=False`` (default) runs unkeyed calls normally, which keeps the
    decorator safe to add to an existing tool without breaking callers. Set it ``True``
    for genuinely non-idempotent operations, where silently executing an unkeyed
    duplicate is the failure you are trying to prevent.

    The key is namespaced by handler name, so two tools cannot collide on the same key.

    **Where the key comes from matters (draft-reece -02 §2.5).** A caller-supplied key
    is a *cooperation* mechanism: a client that omits it, or varies it across a retry,
    gets no protection at all - so on its own it does not satisfy "the same authorization
    evidence MUST NOT license a blind retry", because the party the rule constrains is
    the one choosing the key.

    With ``fall_back_to_decision`` (default on), an unkeyed call falls back to
    ``agentcreds_record_id`` - the id of the Authorization Decision Record that permitted
    it, minted server-side, one per authorization. A retry that re-presents the same
    authorization arrives under the same record id and is suppressed; a genuinely new
    call is authorized afresh and gets a new one. The client cannot opt out by staying
    silent, which is the property §2.5 actually needs.

    It is still not a substitute for reconciliation. An indeterminate *post-dispatch*
    outcome - the effect may or may not have happened - is not resolved by refusing the
    retry; it is resolved by reconciling the original attempt, and the decision id is
    what makes that attempt findable.
    """

    def decorate(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            raw_key = kwargs.get(key_arg)
            source = "caller"
            if not raw_key and fall_back_to_decision:
                raw_key = kwargs.get("agentcreds_record_id")
                source = "decision"
            if not raw_key:
                if require_key:
                    raise ValueError(
                        f"{fn.__name__} requires '{key_arg}': it is not safe to execute "
                        "an unkeyed duplicate of a non-idempotent operation"
                    )
                return await fn(*args, **kwargs)

            # Namespaced by source as well as handler, so a caller cannot claim a
            # key that collides with a server-minted decision id.
            key = f"{fn.__name__}:{source}:{raw_key}"
            is_new, prior = store.begin(key)
            if not is_new:
                if prior is None:
                    raise IdempotencyConflict(
                        f"'{raw_key}' is already in flight for {fn.__name__}; retry shortly"
                    )
                return prior

            try:
                result = await fn(*args, **kwargs)
            except BaseException:
                # Release the claim so a retry can proceed; a failed attempt must not
                # wedge the key for its whole TTL.
                store.abandon(key)
                raise
            store.complete(key, result if isinstance(result, str) else str(result))
            return result

        return wrapper

    return decorate
