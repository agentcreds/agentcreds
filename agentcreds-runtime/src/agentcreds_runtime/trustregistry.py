"""Fetching the signed trust registry at the enforcement point.

In cross-organizational mode a relying party decides who is a framework member from a
`SignedTrustConfig` - signed by the framework anchor, versioned, with its own expiry.
Distributed as static configuration, **removing a member requires redeploying every
relying party**, and until the last one re-imports, the removed organization is still
trusted everywhere. That is the sharpest edge in framework operations: offboarding is
exactly when you cannot afford a slow, coordinated rollout.

Fetching it on a TTL turns member offboarding into a single re-sign at the framework,
converging everywhere within one interval.

WHY THIS IS SAFE TO FETCH, AND WHY IT CAN COME FROM ANYWHERE. The config is signed by
the framework anchor the operator pinned, so the channel carries no authority: a hostile
host can withhold an update but cannot forge membership. Unlike the approver directory -
which carries the identity of every enrolled human and is therefore token-gated - a trust
registry lists member organizations and their public keys, so it can be served from a
static host or CDN with no gating at all.

The four gates, failure semantics and health reporting are shared; see
:mod:`agentcreds_runtime.fetchcache`. **Monotonicity** does the specific work here of
stopping a replayed earlier config from **re-admitting an offboarded member**.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

import agentcreds as ac

from .fetchcache import FetchCache
from .policy import anchor_resolver_from_registry

__all__ = ["TrustRegistryCache", "anchor_resolver_from_registry_cache"]


class TrustRegistryCache(FetchCache):
    """Fetches the framework's signed trust config on a TTL.

    `sources` maps the **pinned framework anchor DID** to the URL publishing its
    `SignedTrustConfig`. Membership is only ever believed because the framework anchor
    said so.

    Pass `key_histories` so the framework can rotate its own anchor without every member
    re-pinning. The two uses are distinct and easy to conflate: histories given to
    :func:`anchor_resolver_from_registry_cache` resolve rotating **members**, while
    histories given to this cache resolve the rotating **framework** that signs the
    config itself.
    """

    ARTIFACT = "trust registry"

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        # Derived registries, memoised by config version. Rebuilding one per authorize
        # call would re-verify every entry on the hot path for no benefit; the version
        # is monotonic, so it is a sufficient cache key.
        self._registries: "dict[str, tuple[int, ac.TrustRegistry]]" = {}

    def _parse(self, body: str) -> "ac.SignedTrustConfig":
        return ac.SignedTrustConfig.from_json(body)

    def _verify(self, key: str, artifact: "ac.SignedTrustConfig") -> None:
        # Signature AND the sealed expiry together. An authentic-but-lapsed config must
        # be refused rather than assumed current, or a framework that stops re-signing
        # silently freezes membership forever.
        #
        # The framework rotates like any other organization, and every member pins its
        # root - so a config sealed by a successor key must resolve through the
        # framework's own key history, or rotating the framework anchor would break the
        # entire framework at once.
        anchor = self.signing_anchor(key, artifact.issuer_did)
        artifact.verify_current(anchor)

    def _version(self, artifact: "ac.SignedTrustConfig") -> int:
        return artifact.version

    def current(self, framework_did: str) -> "Optional[ac.SignedTrustConfig]":
        """The verified signed config for `framework_did`, refreshing if stale."""
        return self.get(framework_did)

    def registry(self, framework_did: str) -> "Optional[ac.TrustRegistry]":
        """A `TrustRegistry` built from the current config, or None if none verifies.

        Rebuilt only when the config version advances.
        """
        config = self.get(framework_did)
        if config is None:
            return None
        held = self._registries.get(framework_did)
        if held is not None and held[0] == config.version:
            return held[1]
        # The SAME resolved signer `_verify` accepted. Rebuilding against the pinned
        # root instead would reject a config a rotated framework legitimately sealed -
        # verification and import must agree on who signed, or one of them is wrong.
        anchor = self.signing_anchor(framework_did, config.issuer_did)
        registry = ac.TrustRegistry.from_config(config, anchor)
        self._registries[framework_did] = (config.version, registry)
        return registry


def anchor_resolver_from_registry_cache(
    cache: TrustRegistryCache,
    framework_did: str,
    key_histories: "Optional[Iterable[ac.KeyHistory]]" = None,
) -> "Callable[[ac.CapabilityCredential], Optional[ac.TrustAnchor]]":
    """Registry mode, fetching: pin the framework anchor and follow its signed config.

    The counterpart to :func:`~agentcreds_runtime.anchor_resolver_from_registry` for
    deployments that fetch rather than receive the registry as configuration. Fails
    closed: no verified config means no member resolves.

    `key_histories` composes as before - pass a
    :class:`~agentcreds_runtime.KeyHistoryCache` so a member that rotates is not refused
    while the framework re-signs nothing.
    """

    def resolve(
        credential: "ac.CapabilityCredential",
    ) -> "Optional[ac.TrustAnchor]":
        registry = cache.registry(framework_did)
        if registry is None:
            return None
        return anchor_resolver_from_registry(registry, key_histories)(credential)

    return resolve
