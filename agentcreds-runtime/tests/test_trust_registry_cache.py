"""Framework member lifecycle at the enforcement point.

Onboarding is expansion and offboarding is contraction, and both come from the same
signed artifact: the framework re-signs its config, relying parties fetch it. The sharp
case is **removal** - as static configuration it needs every relying party redeployed,
and until the last one re-imports, the removed organization is still trusted everywhere.

Each accept case is paired with a control, because "follows the framework" and "accepts
anyone" agree on the accept cases alone.
"""

from datetime import datetime, timedelta, timezone

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    KeyHistoryCache,
    TrustRegistryCache,
    anchor_resolver_from_registry_cache,
)

URL = "https://framework.example/trust-registry"


def member(name="Member", level="verified"):
    anchor = ac.TrustAnchor.create_did_key()
    entry = ac.TrustEntry(anchor.did, name, anchor.public_key, level)
    return anchor, entry


def config(framework, entries, version, minimum="verified", not_after=None):
    reg = ac.TrustRegistry()
    for e in entries:
        reg.register(e)
    reg.minimum_trust_level = minimum
    if not_after is None:
        return reg.export(framework, version)
    return reg.export_valid_until(framework, version, not_after)


def credential_from(anchor):
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:echo"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    return ac.CapabilityCredential.issue(anchor, agent.did, claims, None)


class Server:
    fail = False

    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        if self.fail:
            raise OSError("connection refused")
        return self.bodies[min(self.calls - 1, len(self.bodies) - 1)]


def cache_for(server, framework_did, **kw):
    return TrustRegistryCache({framework_did: URL}, opener=server, **kw)


# -- Member lifecycle ----------------------------------------------------------


def test_offboarding_a_member_takes_effect_on_the_next_fetch():
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, a = member("Org A")
    b_anchor, b = member("Org B")

    server = Server(
        config(framework, [a, b], 1).to_json(),
        config(framework, [b], 2).to_json(),  # Org A removed
    )
    cache = cache_for(server, framework.did, ttl_secs=0)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)

    vc_a = credential_from(a_anchor)
    vc_b = credential_from(b_anchor)

    # Control: Org A is a member first, so its later refusal is attributable to the
    # offboarding and not to the registry never loading.
    assert resolve(vc_a) is not None
    assert resolve(vc_a) is None, "an offboarded member is still trusted"
    assert resolve(vc_b) is not None, "removing one member disabled the framework"


def test_onboarding_a_member_needs_only_the_framework_to_re_sign():
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, a = member("Org A")
    c_anchor, c = member("Org C")

    server = Server(
        config(framework, [a], 1).to_json(),
        config(framework, [a, c], 2).to_json(),
    )
    cache = cache_for(server, framework.did, ttl_secs=0)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)

    vc_c = credential_from(c_anchor)
    assert resolve(vc_c) is None
    assert resolve(vc_c) is not None, "a newly admitted member was not accepted"


def test_a_readmitted_member_cannot_be_restored_by_replaying_the_old_config():
    """Rollback is the attack a signature check does not catch: the framework's OWN
    earlier config is validly signed, so replaying it re-admits whoever was removed."""
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, a = member("Org A")
    _b_anchor, b = member("Org B")

    server = Server(
        config(framework, [b], 2).to_json(),
        config(framework, [a, b], 1).to_json(),  # replayed pre-offboarding config
    )
    cache = cache_for(server, framework.did, ttl_secs=0)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)

    vc_a = credential_from(a_anchor)
    assert resolve(vc_a) is None
    assert resolve(vc_a) is None, "a rollback re-admitted an offboarded member"
    assert cache.current(framework.did).version == 2


# -- Gates ---------------------------------------------------------------------


def test_a_config_signed_by_another_anchor_is_refused():
    ours = ac.TrustAnchor.create_did_key()
    theirs = ac.TrustAnchor.create_did_key()
    rogue_anchor, rogue = member("Rogue")

    cache = cache_for(Server(config(theirs, [rogue], 9).to_json()), ours.did)
    assert cache.current(ours.did) is None, "a foreign anchor defined our membership"


def test_an_expired_config_is_refused():
    framework = ac.TrustAnchor.create_did_key()
    _a_anchor, a = member("Org A")
    stale = config(framework, [a], 1, not_after=datetime.now(timezone.utc) - timedelta(hours=1))
    cache = cache_for(Server(stale.to_json()), framework.did)
    assert cache.current(framework.did) is None


def test_an_unexpired_config_is_accepted():
    """Control for the expiry case."""
    framework = ac.TrustAnchor.create_did_key()
    _a_anchor, a = member("Org A")
    fresh = config(framework, [a], 1, not_after=datetime.now(timezone.utc) + timedelta(hours=1))
    cache = cache_for(Server(fresh.to_json()), framework.did)
    assert cache.current(framework.did) is not None


def test_the_minimum_trust_level_still_applies():
    """The registry's own gate must survive the fetch path - otherwise fetching would
    quietly become a way to admit under-verified members."""
    framework = ac.TrustAnchor.create_did_key()
    low_anchor, low = member("Low", level="self_asserted")
    cache = cache_for(Server(config(framework, [low], 1, minimum="verified").to_json()),
                      framework.did)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)
    assert resolve(credential_from(low_anchor)) is None


# -- Composition and failure ---------------------------------------------------


def test_a_rotating_member_still_resolves_through_its_key_history():
    """Registry fetch and key-history fetch compose: a member that rotates is accepted
    without the framework re-signing anything."""
    framework = ac.TrustAnchor.create_did_key()
    root = ac.TrustAnchor.create_did_key()
    current = ac.TrustAnchor.create_did_key()
    history = ac.KeyHistory.genesis(root)
    history.push(ac.RotationStatement.issue(root, current))
    history.seal(current, 1)

    entry = ac.TrustEntry(root.did, "Rotator", root.public_key, "verified")
    cache = cache_for(Server(config(framework, [entry], 1).to_json()), framework.did)
    histories = KeyHistoryCache({}, opener=lambda *_: "")
    histories.seed(root.did, history)

    resolve = anchor_resolver_from_registry_cache(cache, framework.did, histories)
    assert resolve(credential_from(current)) is not None


def test_a_dead_endpoint_keeps_the_last_verified_config():
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, a = member("Org A")
    server = Server(config(framework, [a], 1).to_json())
    cache = cache_for(server, framework.did, ttl_secs=0)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)
    assert resolve(credential_from(a_anchor)) is not None

    server.fail = True
    assert resolve(credential_from(a_anchor)) is not None


def test_no_config_at_all_fails_closed():
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, _a = member("Org A")
    server = Server("")
    server.fail = True
    cache = cache_for(server, framework.did)
    resolve = anchor_resolver_from_registry_cache(cache, framework.did)
    assert resolve(credential_from(a_anchor)) is None


def test_a_seeded_cache_that_never_fetched_is_visible():
    """A framework config seeded from deployment config whose endpoint is unreachable
    keeps resolving members correctly - and will silently miss every offboarding."""
    framework = ac.TrustAnchor.create_did_key()
    a_anchor, a = member("Org A")
    server = Server("")
    server.fail = True
    cache = cache_for(server, framework.did, ttl_secs=0)
    cache.seed(framework.did, config(framework, [a], 1))

    assert cache.current(framework.did) is not None
    st = cache.status()[framework.did]
    assert st.fetched_ok is False
    assert st.seeded_only is True


def test_the_derived_registry_is_rebuilt_only_when_the_version_advances():
    framework = ac.TrustAnchor.create_did_key()
    _a_anchor, a = member("Org A")
    cache = cache_for(Server(config(framework, [a], 1).to_json()), framework.did)
    first = cache.registry(framework.did)
    assert cache.registry(framework.did) is first, "registry rebuilt with no version change"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y"])
def test_non_http_urls_are_refused_at_construction(url):
    with pytest.raises(ValueError, match="unsupported scheme"):
        TrustRegistryCache({"did:key:zFramework": url})
