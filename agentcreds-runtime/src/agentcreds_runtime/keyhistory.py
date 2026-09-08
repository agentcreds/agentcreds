"""Fetching and caching signed key histories at the enforcement point.

Without this, a relying party receives key histories as deployment configuration, so an
organization that repudiates a compromised anchor key converges only when every relying
party is reconfigured or redeployed. The control plane learns in a poll interval; the
enforcement point - the layer where the attacker's credential is actually presented -
learns when an operator gets to it. This closes that gap: the PEP fetches the signed
history itself, on the same bounded-staleness discipline it already applies to the
status list.

The history is the authority, not the fetch. It is self-authenticating against a root
the operator pinned independently, so a hostile server on the other end of the URL can
withhold an update but cannot forge one. That is what makes fetching safe at all.

The four gates, failure semantics and health reporting are common to every fetched
artifact and live in :mod:`agentcreds_runtime.fetchcache` - read that module's docstring
for why each one is load-bearing. Of them, **monotonicity** matters most here: an
organization's own earlier history is validly sealed, so replaying it un-repudiates a
compromised key, which is precisely what its holder wants.
"""

from __future__ import annotations

from typing import Callable, Optional

import agentcreds as ac

from .fetchcache import FetchCache, FetchedStatus

__all__ = [
    "KeyHistoryCache",
    "KeyHistoryStatus",
    "anchor_resolver_from_key_history_cache",
]

#: Retained name for the shared status record (histories were the first fetched artifact).
KeyHistoryStatus = FetchedStatus


class KeyHistoryCache(FetchCache):
    """Fetches signed key histories on a TTL, verifying each against its pinned root.

    `sources` maps a **pinned root DID** to the URL publishing that organization's
    history. The root is the key because it is what the operator pinned; the current DID
    changes on every rotation and so cannot identify anything stably.

    Iterating yields every history held, refreshing stale ones, which makes the cache a
    drop-in for the ``key_histories`` argument of
    :func:`~agentcreds_runtime.anchor_resolver_from_registry`. In registry mode that
    costs at most one fetch per member per TTL.
    """

    ARTIFACT = "key history"

    @classmethod
    def from_registry(
        cls, registry: "ac.TrustRegistry", **kwargs: object
    ) -> "KeyHistoryCache":
        """Build a cache from the members that publish a ``key_history_url``.

        Members without one are simply absent: an organization that has never rotated
        has root == current and resolves by direct registration, so it needs no history
        and must not be made to depend on one.
        """
        sources = {}
        for did in registry.registered_dids():
            url = registry.resolve(did).key_history_url
            if url:
                sources[did] = url
        return cls(sources, **kwargs)  # type: ignore[arg-type]

    def _parse(self, body: str) -> "ac.KeyHistory":
        return ac.KeyHistory.from_json(body)

    def _verify(self, key: str, artifact: "ac.KeyHistory") -> None:
        # Chain from the pinned root, sealed, and unexpired - all three in core.
        artifact.verify_current(key)

    def _version(self, artifact: "ac.KeyHistory") -> int:
        return artifact.version


def anchor_resolver_from_key_history_cache(
    cache: KeyHistoryCache, root_did: str
) -> "Callable[[ac.CapabilityCredential], Optional[ac.TrustAnchor]]":
    """Rotating-pin mode, fetching: pin one root, follow the chain, refresh on a TTL.

    The counterpart to :func:`~agentcreds_runtime.anchor_resolver_from_key_history` for
    deployments that fetch rather than receive their history as configuration. Fails
    closed: no verified history, or an issuer the history does not authorize, resolves
    to ``None``.
    """

    def resolve(
        credential: "ac.CapabilityCredential",
    ) -> "Optional[ac.TrustAnchor]":
        history = cache.get(root_did)
        if history is None:
            return None
        try:
            return history.authorize_issuer(root_did, credential.issuer)
        except Exception:
            return None

    return resolve
