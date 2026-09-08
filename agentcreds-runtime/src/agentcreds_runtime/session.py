"""Pluggable per-session state for the identity enforcer.

The enforcer keeps two pieces of per-session state: the active proof-of-possession
challenge and the bound on-behalf-of principal. By default these live in process
(`InMemorySessionStore`). For a horizontally-scaled MCP server - more than one
replica behind a load balancer - use a **shared** store (`RedisSessionStore`) so a
session (challenge or principal) established on one replica is honoured on
another. Every store applies a TTL so abandoned sessions are evicted rather than
accumulating forever.

Bring your own backend by implementing `SessionStore` (e.g. Memcached, a database).
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple


class SessionStore(ABC):
    """Storage for the enforcer's per-session challenge and principal binding.

    Values are stored under an opaque `session_id`. Challenges are bytes (the
    CBOR of an `agentcreds.PopChallenge`); principals are the human's DID string.
    Implementations must be safe for concurrent use and should expire entries
    after a TTL.
    """

    @abstractmethod
    def put_challenge(self, session_id: str, challenge_cbor: bytes) -> None:
        """Store (replacing any existing) the active challenge for a session."""

    @abstractmethod
    def get_challenge(self, session_id: str) -> Optional[bytes]:
        """The active challenge bytes for a session, or None if absent/expired."""

    @abstractmethod
    def put_principal(self, session_id: str, principal_did: str) -> None:
        """Bind the verified human principal DID for a session."""

    @abstractmethod
    def get_principal(self, session_id: str) -> Optional[str]:
        """The bound principal DID for a session, or None if absent/expired."""

    @abstractmethod
    def clear(self, session_id: str) -> None:
        """Forget all state for a session."""


class InMemorySessionStore(SessionStore):
    """In-process session store with TTL eviction (the default).

    Fine for a single replica. Entries are evicted lazily on read once expired,
    and a periodic sweep bounds the memory of sessions that are never read again.
    Not shared across processes - use `RedisSessionStore` for multiple replicas.
    """

    def __init__(self, ttl_secs: int = 3600, sweep_interval_secs: int = 60):
        self._ttl = int(ttl_secs)
        self._sweep_interval = int(sweep_interval_secs)
        self._challenges: Dict[str, Tuple[bytes, float]] = {}
        self._principals: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def _maybe_sweep(self, now: float) -> None:
        # Caller holds the lock. Drop expired entries no more than once per
        # interval, so a flood of never-read sessions cannot grow unbounded.
        if now - self._last_sweep < self._sweep_interval:
            return
        self._last_sweep = now
        for store in (self._challenges, self._principals):
            expired = [k for k, (_, exp) in store.items() if exp <= now]
            for k in expired:
                store.pop(k, None)

    def put_challenge(self, session_id: str, challenge_cbor: bytes) -> None:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            self._challenges[session_id] = (bytes(challenge_cbor), now + self._ttl)

    def get_challenge(self, session_id: str) -> Optional[bytes]:
        with self._lock:
            entry = self._challenges.get(session_id)
            if entry is None:
                return None
            value, exp = entry
            if exp <= time.monotonic():
                self._challenges.pop(session_id, None)
                return None
            return value

    def put_principal(self, session_id: str, principal_did: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._maybe_sweep(now)
            self._principals[session_id] = (principal_did, now + self._ttl)

    def get_principal(self, session_id: str) -> Optional[str]:
        with self._lock:
            entry = self._principals.get(session_id)
            if entry is None:
                return None
            value, exp = entry
            if exp <= time.monotonic():
                self._principals.pop(session_id, None)
                return None
            return value

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._challenges.pop(session_id, None)
            self._principals.pop(session_id, None)


class RedisSessionStore(SessionStore):
    """Shared session store backed by Redis - for multiple enforcer replicas.

    Pass a configured client (``redis.Redis(...)`` or any object exposing
    ``setex(key, ttl, value)``, ``get(key)``, and ``delete(*keys)``); this class
    does not import or manage the connection, so it adds no hard dependency.
    Entries expire via Redis's native TTL.
    """

    def __init__(self, client: object, ttl_secs: int = 3600, namespace: str = "agentcreds"):
        self._r = client
        self._ttl = int(ttl_secs)
        self._ns = namespace

    def _challenge_key(self, session_id: str) -> str:
        return f"{self._ns}:chal:{session_id}"

    def _principal_key(self, session_id: str) -> str:
        return f"{self._ns}:prin:{session_id}"

    def put_challenge(self, session_id: str, challenge_cbor: bytes) -> None:
        self._r.setex(self._challenge_key(session_id), self._ttl, bytes(challenge_cbor))

    def get_challenge(self, session_id: str) -> Optional[bytes]:
        value = self._r.get(self._challenge_key(session_id))
        return bytes(value) if value is not None else None

    def put_principal(self, session_id: str, principal_did: str) -> None:
        self._r.setex(self._principal_key(session_id), self._ttl, principal_did)

    def get_principal(self, session_id: str) -> Optional[str]:
        value = self._r.get(self._principal_key(session_id))
        if value is None:
            return None
        return value.decode() if isinstance(value, (bytes, bytearray)) else str(value)

    def clear(self, session_id: str) -> None:
        self._r.delete(self._challenge_key(session_id), self._principal_key(session_id))
