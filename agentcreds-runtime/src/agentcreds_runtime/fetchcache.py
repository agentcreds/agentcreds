"""Shared machinery for fetching signed artifacts at the enforcement point.

The PEP learns things exactly one way: it fetches a **signed artifact** and verifies it
against something the operator pinned. Not by subscription, not by an online callback -
verification stays offline-checkable (R3), and the network only decides *when* we look,
never *what we believe*. This module is that one way, so the security-relevant parts are
written once and every artifact inherits them.

FOUR GATES, applied to every artifact on every admission:

1. **Pinned issuer.** Verified against the DID the operator pinned, not one the fetched
   document names for itself.
2. **Signed.** An unsigned or unsealed artifact is refused. Fields that carry the
   security decision (repudiations, expiry, membership) are strippable otherwise, so
   accepting one would let an attacker downgrade to the permissive case by deletion.
3. **Fresh.** A lapsed artifact is refused rather than assumed current. This is what
   stops an unreachable endpoint from meaning "trust the old copy forever".
4. **Monotonic.** A fetched artifact may not go backwards in `version`. Without this the
   whole mechanism inverts: an issuer's OWN earlier document is validly signed, so
   replaying it undoes whatever the latest one withdrew - un-repudiating a compromised
   key, or restoring a departed approver. **Rollback is the attack a signature check
   does not catch.**

FAILURE IS SAFE IN THE AVAILABILITY DIRECTION. A failed fetch keeps the last verified
artifact, so an issuer that goes dark cannot erase what we already know, and cannot force
a rollback. Trust does not extend indefinitely either: gate 3 eventually refuses the
stale copy and the caller fails closed. Both halves - which means a freshness bound is
only safe when the issuer re-signs on a heartbeat comfortably shorter than the validity.

OBSERVABILITY. A failed refresh is deliberately silent on the authorization path - it
must not deny traffic - but silence is not invisibility. An artifact seeded from
configuration whose endpoint is unreachable behaves *correctly* until its expiry, which
makes a completely broken fetch path indistinguishable from a healthy one right up to the
moment it fails closed. So refreshes are logged, and :meth:`FetchCache.status` reports
whether a source has EVER been fetched (``fetched_ok``). **Alert on that, not on
authorization success** - authorization success is precisely what hides the fault.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Mapping, Optional
from urllib.parse import urlparse

__all__ = ["FetchCache", "FetchedStatus", "require_fetchable"]

log = logging.getLogger(__name__)

DEFAULT_TTL_SECS = 300
DEFAULT_TIMEOUT_SECS = 5
#: Hard cap on a fetched body, bounding memory against a hostile or misbehaving endpoint.
DEFAULT_MAX_BYTES = 1 << 20

_ALLOWED_SCHEMES = ("https", "http")


def require_fetchable(url: str, key: str) -> None:
    """Reject a URL the enforcement point should never dereference.

    These URLs come from signed configuration (a trust registry, a deployment env) that
    names endpoints the signer does not control. Restricting the scheme keeps a hostile
    or mis-signed entry from turning the PEP into a reader of local files, or of whatever
    else the URL library happens to support.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"URL for {key} has unsupported scheme {scheme!r}; "
            f"expected one of {_ALLOWED_SCHEMES}"
        )


@dataclass
class FetchedStatus:
    """What the cache knows about one pinned source. For health output and alerting."""

    key: str
    url: Optional[str]
    version: Optional[int]
    """Version currently held, or ``None`` if nothing has been admitted."""
    fetched_ok: bool
    """Whether a fetch has EVER succeeded for this source.

    **This is the field to alert on.** ``False`` while an artifact is held means the
    cache is running on a seed and has never reached its endpoint - correct today,
    failing closed at expiry. Authorization success cannot reveal this, which is exactly
    why it needs its own signal.
    """
    last_success_at: Optional[float]
    last_failure_at: Optional[float]
    consecutive_failures: int
    total_failures: int
    last_error: Optional[str]

    @property
    def seeded_only(self) -> bool:
        """Holding an artifact that only ever came from configuration."""
        return self.version is not None and not self.fetched_ok

    def age_secs(self, now: Optional[float] = None) -> Optional[float]:
        """Seconds since the last successful fetch, or ``None`` if never."""
        if self.last_success_at is None:
            return None
        return (now if now is not None else time.time()) - self.last_success_at


class FetchCache:
    """Base for TTL-refreshed caches of signed artifacts.

    `sources` maps a **pinned issuer key** (a DID) to the URL publishing that issuer's
    artifact. The pinned key is the map key because it is what the operator committed to;
    anything the fetched document says about itself is a claim, not an identity.

    Subclasses supply :meth:`_parse`, :meth:`_verify` and :meth:`_version`. Everything
    security-relevant - the four gates, bounded reads, scheme restriction, failure
    accounting - lives here so it cannot drift between artifact types.
    """

    #: Label used in log messages, e.g. "key history".
    ARTIFACT = "artifact"

    def __init__(
        self,
        sources: Mapping[str, str],
        *,
        ttl_secs: int = DEFAULT_TTL_SECS,
        timeout_secs: int = DEFAULT_TIMEOUT_SECS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        opener: Optional[Callable[[str, int], str]] = None,
        key_histories: Optional[Any] = None,
    ) -> None:
        for key, url in sources.items():
            require_fetchable(url, key)
        self._sources = dict(sources)
        self._ttl = int(ttl_secs)
        self._timeout = int(timeout_secs)
        self._max_bytes = int(max_bytes)
        self._opener = opener or self._http_get
        self._lock = threading.Lock()
        self._held: "dict[str, tuple[Any, float]]" = {}
        self._stats: "Dict[str, dict]" = {}
        # Key histories used to follow a rotating issuer to its current signing key.
        # A sequence, not a mapping: each history carries its own root, and a mapping
        # keyed by root invites an entry that disagrees with the artifact it holds.
        self._key_histories = key_histories

    # -- subclass contract ----------------------------------------------------

    def _parse(self, body: str) -> Any:
        raise NotImplementedError

    def _verify(self, key: str, artifact: Any) -> None:
        """Gates 1-3. Raise to refuse the artifact."""
        raise NotImplementedError

    def _version(self, artifact: Any) -> int:
        raise NotImplementedError

    # -- public surface -------------------------------------------------------

    def seed(self, key: str, artifact: Any) -> None:
        """Install an artifact without fetching - the make-before-break path.

        Lets a deployment authorize from boot using configuration it already trusts and
        converge onto fetched updates, instead of denying everything until the first
        fetch succeeds. Subject to the same gates as a fetch, including monotonicity, so
        a seed can never roll the cache back either.
        """
        self._admit(key, artifact)

    def get(self, key: str) -> Optional[Any]:
        """The verified artifact for `key`, refreshing it if stale.

        Returns the last verified artifact when a refresh fails, and ``None`` only when
        nothing has ever been verified for this source.
        """
        with self._lock:
            held = self._held.get(key)
            fresh = held is not None and (time.monotonic() - held[1]) < self._ttl
        if fresh:
            return held[0]  # type: ignore[index]
        self.refresh(key)
        with self._lock:
            held = self._held.get(key)
        return held[0] if held else None

    def refresh(self, key: str) -> bool:
        """Fetch and admit one artifact. Returns whether it was admitted.

        Never raises: a failed refresh must not break the authorization path, and the
        freshness gate is what bounds how long the old artifact stays usable.
        """
        url = self._sources.get(key)
        if url is None:
            return False
        try:
            artifact = self._parse(self._opener(url, self._timeout))
        except Exception as exc:
            self._record_failure(key, f"{type(exc).__name__}: {exc}")
            return False
        if not self._admit(key, artifact):
            # Reached the endpoint but the artifact failed the gates. A DIFFERENT fault
            # from an unreachable endpoint - one is infrastructure, the other is the
            # issuer serving something we must not accept - so it is reported apart.
            self._record_failure(key, "fetched artifact refused by the admission gates")
            return False
        self._record_success(key)
        return True

    def refresh_all(self) -> None:
        """Refresh every stale source. For a background thread; not needed on the
        request path, since :meth:`get` refreshes what it needs."""
        for key in tuple(self._sources):
            with self._lock:
                held = self._held.get(key)
                fresh = held is not None and (time.monotonic() - held[1]) < self._ttl
            if not fresh:
                self.refresh(key)

    def __iter__(self) -> Iterator[Any]:
        for key in tuple(self._sources):
            artifact = self.get(key)
            if artifact is not None:
                yield artifact
        with self._lock:
            extra = [a for k, (a, _) in self._held.items() if k not in self._sources]
        yield from extra

    def status(self) -> "Dict[str, FetchedStatus]":
        """Per-source health. Alert on ``fetched_ok`` - see the module note."""
        with self._lock:
            keys = set(self._sources) | set(self._held) | set(self._stats)
            out = {}
            for key in sorted(keys):
                slot = dict(self._slot(key))
                held = self._held.get(key)
                out[key] = FetchedStatus(
                    key=key,
                    url=self._sources.get(key),
                    version=self._version(held[0]) if held else None,
                    fetched_ok=slot["fetched_ok"],
                    last_success_at=slot["last_success_at"],
                    last_failure_at=slot["last_failure_at"],
                    consecutive_failures=slot["consecutive_failures"],
                    total_failures=slot["total_failures"],
                    last_error=slot["last_error"],
                )
            return out

    # -- internals ------------------------------------------------------------

    def _admit(self, key: str, artifact: Any) -> bool:
        try:
            self._verify(key, artifact)  # gates 1-3
        except Exception:
            return False
        with self._lock:
            held = self._held.get(key)
            # Gate 4. `<` not `<=`: re-admitting the same version is how a periodic
            # refresh renews fetch recency on an unchanged artifact.
            if held is not None and self._version(artifact) < self._version(held[0]):
                return False
            self._held[key] = (artifact, time.monotonic())
        return True

    def _slot(self, key: str) -> dict:
        return self._stats.setdefault(
            key,
            {
                "fetched_ok": False,
                "last_success_at": None,
                "last_failure_at": None,
                "consecutive_failures": 0,
                "total_failures": 0,
                "last_error": None,
            },
        )

    def _record_success(self, key: str) -> None:
        with self._lock:
            slot = self._slot(key)
            first = not slot["fetched_ok"]
            slot["fetched_ok"] = True
            slot["last_success_at"] = time.time()
            slot["consecutive_failures"] = 0
            slot["last_error"] = None
            held = self._held.get(key)
            version = self._version(held[0]) if held else None
        if first:
            log.info(
                "%s fetched for %s (version %s) - the endpoint is reachable",
                self.ARTIFACT,
                key,
                version,
            )

    def _record_failure(self, key: str, error: str) -> None:
        with self._lock:
            slot = self._slot(key)
            slot["last_failure_at"] = time.time()
            slot["consecutive_failures"] += 1
            slot["total_failures"] += 1
            slot["last_error"] = error
            n = slot["consecutive_failures"]
            never = not slot["fetched_ok"]
            held = key in self._held
        if never and held:
            # The dangerous state: authorizing from a seed, endpoint never reached. This
            # deployment looks healthy and will fail closed at the artifact's expiry.
            log.error(
                "%s for %s has NEVER been fetched (%d attempt(s)); serving a seeded copy "
                "that will fail closed at its expiry: %s",
                self.ARTIFACT,
                key,
                n,
                error,
            )
        else:
            log.warning(
                "%s refresh failed for %s (%d consecutive): %s",
                self.ARTIFACT,
                key,
                n,
                error,
            )

    def signing_anchor(self, pinned_did: str, issuer_did: str):
        """The anchor that must have signed an artifact pinned to `pinned_did`.

        Directories and trust configs are signed by their issuer's **current** key,
        while a relying party pins a **root** - so once the issuer rotates, the pinned
        DID is no longer the signer and a naive check fails closed on a perfectly valid
        artifact. Following the signed key history is the same move credentials already
        make; without it, rotation silently breaks every artifact except credentials.

        `authorize_issuer` does the whole check: it verifies the sealed chain from the
        pinned root, refuses a **repudiated** key, and returns a verify-only anchor for
        the signer. A history that names this root is therefore authoritative - no
        fallback - or a repudiated key could be readmitted by ignoring the history.

        With no history for this root, only the root itself may sign, which is exactly
        the pre-rotation behavior.
        """
        for history in self._key_histories or ():
            try:
                dids = history.dids()
            except Exception:
                continue
            if not dids or dids[0] != pinned_did:
                continue  # a different organization's history
            return history.authorize_issuer(pinned_did, issuer_did)

        if issuer_did != pinned_did:
            raise ValueError(
                f"artifact signed by {issuer_did}, which is not the pinned {pinned_did} "
                "and no key history authorizes it"
            )
        import agentcreds as _ac

        return _ac.TrustAnchor.from_did_key(pinned_did)

    def _http_get(self, url: str, timeout: int) -> str:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            body = resp.read(self._max_bytes + 1)
        if len(body) > self._max_bytes:
            raise ValueError(f"{self.ARTIFACT} exceeds the size cap")
        return body.decode("utf-8")
