"""Stateful usage governance - rate/quota and spend metering - for the policy gate.

Authority (which tool, which args, on whose behalf) is settled cryptographically by
the enforcer. This module adds the *stateful* limits that authority can't express on
its own: how many calls an agent may make per window, and how much it may spend. Both
are enforced as the enforcer's final `usage_meter` gate, **after** authority is proven
and revocation cleared, and **fail closed** if the backing store errors.

Two pieces, mirroring the session/replay stores:

- a `UsageStore` (in-process by default, Redis for multiple replicas) holding the
  per-key counters, and
- `usage_gate(store, *rules)`, which turns one or more `rate_limit` / `spend_limit`
  rules into a policy hook. It is **two-phase** - it checks every rule first and only
  commits the counters if *all* pass, so a denied call is never charged.

The credential's own (advisory) `budget_usd` becomes *enforceable* here: `spend_limit()`
defaults its cap to the leaf delegation hop's `budget_usd`.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Callable, Dict, Optional, Tuple

from .policy import PolicyHook, PolicyInput

# Derives the counter key from a verified call (defaults to the leaf agent's DID).
KeyFn = Callable[[PolicyInput], str]
# Derives the cost of a call (defaults to 1 per call).
CostFn = Callable[[PolicyInput], int]


def leaf_agent_key(pin: PolicyInput) -> str:
    """Default counter key: the leaf (acting) agent's DID, else the bound principal."""
    if pin.chain:
        return pin.chain[-1].agent_did
    return pin.principal or "unknown"


# -- Store ----------------------------------------------------------------------


class UsageStore(ABC):
    """Holds integer counters under opaque keys, each with a TTL. Used for both call
    counts and accumulated spend. Implementations must be safe for concurrent use."""

    @abstractmethod
    def get(self, key: str) -> int:
        """Current value for `key` (0 if absent/expired)."""

    @abstractmethod
    def add(self, key: str, amount: int, ttl_secs: int) -> int:
        """Atomically add `amount` to `key`, (re)set its TTL, and return the new total."""


class InMemoryUsageStore(UsageStore):
    """In-process counter store with TTL eviction (the default). Single-replica only -
    use `RedisUsageStore` when more than one enforcer replica shares the load."""

    def __init__(self, sweep_interval_secs: int = 60):
        self._sweep_interval = int(sweep_interval_secs)
        self._counts: Dict[str, Tuple[int, float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        expired = [k for k, (_, exp) in self._counts.items() if exp <= now]
        for k in expired:
            self._counts.pop(k, None)

    def get(self, key: str) -> int:
        with self._lock:
            entry = self._counts.get(key)
            if entry is None:
                return 0
            value, exp = entry
            if exp <= time.monotonic():
                self._counts.pop(key, None)
                return 0
            return value

    def add(self, key: str, amount: int, ttl_secs: int) -> int:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            entry = self._counts.get(key)
            base = entry[0] if entry is not None and entry[1] > now else 0
            value = base + amount
            self._counts[key] = (value, now + ttl_secs)
            return value


class RedisUsageStore(UsageStore):
    """Shared counter store backed by Redis - for multiple enforcer replicas.

    Pass a configured client (``redis.Redis(...)`` or any object exposing
    ``get(key)``, ``incrby(key, amount)``, and ``expire(key, ttl)``); this class
    imports nothing and adds no hard dependency. `incrby` is atomic; the `expire`
    that follows refreshes the TTL.
    """

    def __init__(self, client: object, namespace: str = "agentcreds:usage"):
        self._r = client
        self._ns = namespace

    def _k(self, key: str) -> str:
        return f"{self._ns}:{key}"

    def get(self, key: str) -> int:
        value = self._r.get(self._k(key))
        return int(value) if value is not None else 0

    def add(self, key: str, amount: int, ttl_secs: int) -> int:
        full = self._k(key)
        value = int(self._r.incrby(full, amount))
        self._r.expire(full, ttl_secs)
        return value


# -- Rules ----------------------------------------------------------------------


class UsageRule(ABC):
    """One stateful limit. `plan` turns a verified call into a counter operation, or
    None to skip (nothing to meter for this call)."""

    @abstractmethod
    def plan(self, pin: PolicyInput, now: float) -> "Optional[Tuple[str, int, int, int]]":
        """Return (storage_key, amount, limit, ttl_secs), or None to skip."""

    @abstractmethod
    def reason(self, current: int, amount: int, limit: int) -> str:
        """The deny reason when current + amount would exceed limit."""


class _RateLimitRule(UsageRule):
    def __init__(self, max_calls: int, per_secs: int, *, key: KeyFn, name: str):
        self._max = int(max_calls)
        self._per = int(per_secs)
        self._key = key
        self._name = name

    def plan(self, pin, now):
        window = int(now // self._per)
        skey = f"{self._name}:{self._key(pin)}:{window}"
        return (skey, 1, self._max, self._per * 2)

    def reason(self, current, amount, limit):
        return f"rate limit exceeded: {current + amount}/{limit} calls per {self._per}s"


class _SpendRule(UsageRule):
    def __init__(
        self, budget: Optional[int], *, cost: CostFn, per_secs: Optional[int],
        key: KeyFn, name: str, lifetime_ttl_secs: int,
    ):
        self._budget = budget
        self._cost = cost
        self._per = per_secs
        self._key = key
        self._name = name
        self._lifetime_ttl = int(lifetime_ttl_secs)

    def plan(self, pin, now):
        # Cap: the configured budget, else the credential's own (advisory) leaf budget.
        budget = self._budget
        if budget is None:
            budget = pin.chain[-1].budget_usd if pin.chain else None
        if budget is None:
            return None  # no budget declared anywhere -> nothing to meter
        amount = int(self._cost(pin))
        if amount <= 0:
            return None  # free call -> allowed, uncounted
        lk = self._key(pin)
        if self._per is None:  # lifetime budget
            return (f"{self._name}:{lk}", amount, int(budget), self._lifetime_ttl)
        window = int(now // self._per)
        return (f"{self._name}:{lk}:{window}", amount, int(budget), self._per * 2)

    def reason(self, current, amount, limit):
        return f"budget exceeded: {current + amount}/{limit} (this call costs {amount})"


def rate_limit(
    max_calls: int, per_secs: int, *, key: KeyFn = leaf_agent_key, name: str = "rate"
) -> UsageRule:
    """Limit calls per fixed window. Keyed by the leaf agent DID by default - pass
    `key=lambda pin: f"{leaf_agent_key(pin)}:{pin.tool}"` for a per-tool limit, or a
    principal-based key for a per-human limit."""
    return _RateLimitRule(max_calls, per_secs, key=key, name=name)


def spend_limit(
    budget: Optional[int] = None,
    *,
    cost: CostFn = lambda _pin: 1,
    per_secs: Optional[int] = None,
    key: KeyFn = leaf_agent_key,
    name: str = "spend",
    lifetime_ttl_secs: int = 7 * 24 * 3600,
) -> UsageRule:
    """Meter accumulated spend against a cap. `budget` defaults to the credential's own
    leaf `budget_usd` (turning that advisory value into an enforced one). `cost` derives
    the per-call cost (default 1; e.g. `cost=lambda pin: int(pin.arguments.get("amount", 0))`).
    `per_secs=None` meters lifetime spend; set it for a per-window cap (e.g. daily)."""
    return _SpendRule(
        budget, cost=cost, per_secs=per_secs, key=key, name=name,
        lifetime_ttl_secs=lifetime_ttl_secs,
    )


def usage_gate(store: UsageStore, *rules: UsageRule) -> PolicyHook:
    """Build a policy hook enforcing `rules` against `store`. Two-phase: every rule is
    checked first, and the counters are committed only if *all* pass - so a denied call
    is never charged. Returns the first rule's deny reason, or None to allow.

    Wire it into the enforcer's `usage_meter=` slot (it runs as the final gate). Counter
    errors propagate, so the enforcer's gate fails CLOSED by default."""

    def hook(pin: PolicyInput) -> Optional[str]:
        now = time.time()  # wall clock so windows align across replicas
        commits = []
        for rule in rules:
            planned = rule.plan(pin, now)
            if planned is None:
                continue
            key, amount, limit, ttl = planned
            current = store.get(key)
            if current + amount > limit:
                return rule.reason(current, amount, limit)
            commits.append((key, amount, ttl))
        for key, amount, ttl in commits:
            store.add(key, amount, ttl)
        return None

    return hook
