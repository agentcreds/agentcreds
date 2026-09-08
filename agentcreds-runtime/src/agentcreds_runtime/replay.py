"""Replay protection for A2A identity headers.

A2A is callback-free: the *sender* mints the proof-of-possession challenge, so the
receiver cannot rely on a verifier-issued single-use nonce the way the MCP path
does. That leaves one residual gap - within the freshness window, a captured
header can be re-sent verbatim.

A `ReplayGuard` closes it by making each accepted header **single-use**: it records
a fingerprint of every header it admits, for the freshness window, and rejects a
second presentation of the same one. In-process by default; back it with Redis
(`RedisReplayGuard`) so replays are caught across multiple receiver replicas.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Dict


class ReplayGuard(ABC):
    """Records accepted-header fingerprints and detects re-use within a TTL."""

    @abstractmethod
    def record_if_new(self, key: str) -> bool:
        """Atomically record `key`. Return True if it was new (admit the header),
        or False if it has already been seen within the TTL (a replay)."""


class InMemoryReplayGuard(ReplayGuard):
    """In-process replay guard with TTL eviction. Single-replica only - use
    `RedisReplayGuard` when more than one receiver shares the load.

    The TTL should be at least the verifier's `max_age_secs`: a header older than
    the freshness window is already rejected by the verify step, so the guard only
    needs to remember a fingerprint for that long.
    """

    def __init__(self, ttl_secs: int = 300, sweep_interval_secs: int = 60):
        self._ttl = int(ttl_secs)
        self._sweep_interval = int(sweep_interval_secs)
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _maybe_sweep(self, now: float) -> None:
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            self._seen.pop(k, None)

    def record_if_new(self, key: str) -> bool:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            exp = self._seen.get(key)
            if exp is not None and exp > now:
                return False  # still within TTL -> replay
            self._seen[key] = now + self._ttl
            return True


class RedisReplayGuard(ReplayGuard):
    """Shared replay guard backed by Redis - catches replays across replicas.

    Pass a configured client (``redis.Redis(...)`` or any object exposing
    ``set(key, value, nx=..., ex=...)``); this class imports nothing and adds no
    hard dependency. Uses an atomic ``SET key ... NX EX ttl``: the key is created
    only if absent, so the first caller admits the header and any later caller
    within the TTL is a replay.
    """

    def __init__(self, client: object, ttl_secs: int = 300, namespace: str = "agentcreds:replay"):
        self._r = client
        self._ttl = int(ttl_secs)
        self._ns = namespace

    def record_if_new(self, key: str) -> bool:
        # Truthy when SET created the key (new); falsy (None) when it already
        # existed within its TTL (replay).
        created = self._r.set(f"{self._ns}:{key}", b"1", nx=True, ex=self._ttl)
        return bool(created)
