"""Fetching key histories at the enforcement point.

Without a fetch path the PEP receives histories as deployment configuration, so a
repudiated anchor key keeps being honoured at the exact layer where the attacker's
credential is presented until someone redeploys. These tests hold the four gates that
make fetching safe, and - as importantly - hold that a *failed* fetch neither erases
what we know nor extends trust indefinitely.

Every accept case is paired with a control, because "honours the update" and "honours
whatever it was handed" are indistinguishable on the accept cases alone.
"""

from datetime import datetime, timedelta, timezone

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    KeyHistoryCache,
    anchor_resolver_from_key_history_cache,
    anchor_resolver_from_registry,
)

URL = "https://issuer.example/key-history"


def org(hops=1):
    """An org that has rotated `hops` times, with a sealed history at version 1."""
    anchors = [ac.TrustAnchor.create_did_key() for _ in range(hops + 1)]
    history = ac.KeyHistory.genesis(anchors[0])
    for old, new in zip(anchors, anchors[1:]):
        history.push(ac.RotationStatement.issue(old, new))
    history.seal(anchors[-1], 1)
    return anchors, history


def credential_from(anchor):
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:echo"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    return ac.CapabilityCredential.issue(anchor, agent.did, claims, None)


def repudiating(history, anchors, version=2):
    """The same history one incident later: the root key is withdrawn."""
    out = ac.KeyHistory.from_json(history.to_json())
    out.repudiate(anchors[0].did)
    out.seal(anchors[-1], version)
    return out


class Server:
    """A scripted endpoint. Serves `bodies` in order, then repeats the last one."""

    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        if self.fail:
            raise OSError("connection refused")
        i = min(self.calls - 1, len(self.bodies) - 1)
        return self.bodies[i]

    fail = False


def cache_for(server, root_did, **kw):
    return KeyHistoryCache({root_did: URL}, opener=server, **kw)


# -- The point of the feature --------------------------------------------------


def test_a_repudiation_reaches_the_pep_without_a_redeploy():
    anchors, history = org()
    root, current = anchors[0], anchors[-1]
    vc_old, vc_new = credential_from(root), credential_from(current)

    server = Server(history.to_json(), repudiating(history, anchors).to_json())
    cache = cache_for(server, root.did, ttl_secs=0)  # every call re-fetches
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)

    # Control: before the repudiation the superseded key is legitimately trusted, so the
    # refusal below is attributable to the repudiation and not to the key being old.
    assert resolve(vc_old) is not None, "a superseded key must stay valid"

    assert resolve(vc_old) is None, "repudiated key still honoured after refresh"
    assert resolve(vc_new) is not None, "repudiating one key disabled the org"


def test_without_a_fetch_the_same_repudiation_never_arrives():
    """The control for the test above: configuration-only is exactly the gap being
    closed, so it must be shown to have the gap."""
    anchors, history = org()
    root = anchors[0]
    vc_old = credential_from(root)

    from agentcreds_runtime import anchor_resolver_from_key_history

    resolve = anchor_resolver_from_key_history(history, root.did)
    assert resolve(vc_old) is not None
    # The issuer repudiates and republishes; a PEP holding a configured copy is unmoved.
    repudiating(history, anchors)
    assert resolve(vc_old) is not None


# -- The four gates ------------------------------------------------------------


def test_a_rolled_back_history_is_refused():
    """The attack a signature check does not catch. The org's OWN earlier history is
    validly sealed, so replaying it would un-repudiate the compromised key."""
    anchors, history = org()
    root = anchors[0]
    vc_old = credential_from(root)

    server = Server(repudiating(history, anchors).to_json(), history.to_json())
    cache = cache_for(server, root.did, ttl_secs=0)
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)

    assert resolve(vc_old) is None
    assert resolve(vc_old) is None, "an older sealed history un-repudiated the key"
    assert cache.get(root.did).version == 2


def test_a_history_rooted_elsewhere_is_refused():
    anchors, _history = org()
    _other_anchors, other = org()
    cache = cache_for(Server(other.to_json()), anchors[0].did)
    assert cache.get(anchors[0].did) is None


def test_an_unsealed_history_is_refused():
    anchors, _history = org()
    unsealed = ac.KeyHistory.genesis(anchors[0])
    unsealed.push(ac.RotationStatement.issue(anchors[0], anchors[1]))
    cache = cache_for(Server(unsealed.to_json()), anchors[0].did)
    assert cache.get(anchors[0].did) is None


def test_an_expired_history_is_refused():
    anchors, _h = org()
    stale = ac.KeyHistory.genesis(anchors[0])
    stale.push(ac.RotationStatement.issue(anchors[0], anchors[1]))
    stale.seal(anchors[-1], 1, datetime.now(timezone.utc) - timedelta(hours=1))
    cache = cache_for(Server(stale.to_json()), anchors[0].did)
    assert cache.get(anchors[0].did) is None


def test_garbage_from_the_endpoint_is_refused():
    anchors, _h = org()
    cache = cache_for(Server("not json at all"), anchors[0].did)
    assert cache.get(anchors[0].did) is None


# -- Failure behavior ---------------------------------------------------------


def test_a_dead_endpoint_does_not_erase_what_was_already_verified():
    """Availability direction: going dark must not let a peer revoke our knowledge."""
    anchors, history = org()
    root, current = anchors[0], anchors[-1]
    server = Server(history.to_json())
    cache = cache_for(server, root.did, ttl_secs=0)
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)
    assert resolve(credential_from(current)) is not None

    server.fail = True
    assert resolve(credential_from(current)) is not None, "a failed fetch dropped a verified history"


def test_a_dead_endpoint_does_not_extend_trust_past_the_freshness_bound():
    """The other half. Serving the last-known history forever would make the seal's
    expiry decorative, so an unreachable endpoint must eventually fail closed."""
    anchors, _h = org()
    root, current = anchors[0], anchors[-1]
    briefly = ac.KeyHistory.genesis(root)
    briefly.push(ac.RotationStatement.issue(root, current))
    briefly.seal(current, 1, datetime.now(timezone.utc) + timedelta(seconds=1))

    server = Server(briefly.to_json())
    cache = cache_for(server, root.did, ttl_secs=0)
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)
    assert resolve(credential_from(current)) is not None

    # The seal lapses and the endpoint is gone, so nothing can renew it.
    briefly_expired = ac.KeyHistory.from_json(briefly.to_json())
    server.bodies = [briefly_expired.to_json()]
    server.fail = True
    import time as _t
    _t.sleep(1.1)
    assert resolve(credential_from(current)) is None, "a lapsed seal was still honoured"


def test_a_failed_first_fetch_fails_closed():
    anchors, _h = org()
    server = Server("")
    server.fail = True
    cache = cache_for(server, anchors[0].did)
    resolve = anchor_resolver_from_key_history_cache(cache, anchors[0].did)
    assert resolve(credential_from(anchors[-1])) is None


def test_the_ttl_bounds_how_often_the_endpoint_is_called():
    anchors, history = org()
    server = Server(history.to_json())
    cache = cache_for(server, anchors[0].did, ttl_secs=300)
    for _ in range(5):
        cache.get(anchors[0].did)
    assert server.calls == 1, "the TTL was not honoured"


# -- Composition with the rest of the enforcement path -------------------------


def test_the_cache_drops_into_registry_mode():
    anchors, history = org()
    root, current = anchors[0], anchors[-1]
    entry = ac.TrustEntry(root.did, "Member", root.public_key, "verified")
    entry.key_history_url = URL
    reg = ac.TrustRegistry()
    reg.register(entry)
    reg.minimum_trust_level = "verified"

    cache = KeyHistoryCache.from_registry(reg, opener=Server(history.to_json()))
    resolve = anchor_resolver_from_registry(reg, cache)
    assert resolve(credential_from(current)) is not None
    assert resolve(credential_from(ac.TrustAnchor.create_did_key())) is None


def test_from_registry_ignores_members_that_publish_no_history():
    """Migration safety: an org that never rotated has root == current and must not be
    made to depend on a history it does not publish."""
    a = ac.TrustAnchor.create_did_key()
    reg = ac.TrustRegistry()
    reg.register(ac.TrustEntry(a.did, "Static", a.public_key, "verified"))
    cache = KeyHistoryCache.from_registry(reg)
    assert list(cache) == []
    assert anchor_resolver_from_registry(reg, cache)(credential_from(a)) is not None


def test_seed_lets_a_deployment_start_from_configuration():
    anchors, history = org()
    root, current = anchors[0], anchors[-1]
    server = Server(history.to_json())
    server.fail = True  # the endpoint is not up yet
    cache = cache_for(server, root.did)
    cache.seed(root.did, history)
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)
    assert resolve(credential_from(current)) is not None


def test_a_seeded_history_cannot_be_rolled_back_either():
    anchors, history = org()
    root = anchors[0]
    cache = cache_for(Server(history.to_json()), root.did)
    cache.seed(root.did, repudiating(history, anchors))
    cache.seed(root.did, history)  # an older, still validly sealed history
    assert cache.get(root.did).version == 2, "a seed rolled the cache back"
    assert cache.get(root.did).repudiated == [root.did], "the repudiation was undone"


# -- URL handling --------------------------------------------------------------


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "gopher://x"])
def test_non_http_urls_are_refused_at_construction(url):
    """The registry is signed by the framework but names endpoints it does not control,
    so a mis-signed or hostile entry must not turn the PEP into a file reader."""
    with pytest.raises(ValueError, match="unsupported scheme"):
        KeyHistoryCache({"did:key:zRoot": url})


def test_an_oversized_body_is_refused():
    """Exercises the REAL reader, not the scripted opener - the cap lives in the HTTP
    path, so a test that stubs that path proves nothing about it."""
    import http.server
    import threading as _th

    anchors, history = org()
    body = history.to_json().encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/key-history"
    try:
        generous = KeyHistoryCache({anchors[0].did: url})
        assert generous.get(anchors[0].did) is not None, "control: the body is servable"

        capped = KeyHistoryCache({anchors[0].did: url}, max_bytes=8)
        assert capped.get(anchors[0].did) is None
    finally:
        srv.shutdown()


# -- Observability -------------------------------------------------------------
#
# The deployment hazard this exists for: a cache seeded from configuration whose
# endpoint is unreachable authorizes CORRECTLY until the seal lapses. Nothing on the
# authorization path can distinguish that from a healthy deployment - which is why
# `fetched_ok` has to be reported separately, and why these tests assert on it rather
# than on whether resolution succeeds.


def test_a_seeded_cache_that_never_reaches_its_endpoint_is_visible():
    anchors, history = org()
    root, current = anchors[0], anchors[-1]
    server = Server(history.to_json())
    server.fail = True
    cache = cache_for(server, root.did, ttl_secs=0)
    cache.seed(root.did, history)
    resolve = anchor_resolver_from_key_history_cache(cache, root.did)

    # Authorization works. This is the trap: it looks entirely healthy.
    assert resolve(credential_from(current)) is not None

    st = cache.status()[root.did]
    assert st.fetched_ok is False, "a never-fetched root reported as fetched"
    assert st.seeded_only is True
    assert st.version == 1, "the seed is in use"
    assert st.consecutive_failures >= 1
    assert st.last_error
    assert st.age_secs() is None


def test_a_healthy_fetch_reports_fetched_ok():
    """Control for the test above: the two states must be distinguishable."""
    anchors, history = org()
    root = anchors[0]
    cache = cache_for(Server(history.to_json()), root.did)
    cache.get(root.did)

    st = cache.status()[root.did]
    assert st.fetched_ok is True
    assert st.seeded_only is False
    assert st.consecutive_failures == 0
    assert st.total_failures == 0
    assert st.age_secs() is not None and st.age_secs() < 60


def test_a_refused_artifact_is_reported_as_a_distinct_fault():
    """Reaching the endpoint and being served something inadmissible is a different
    problem from not reaching it - one is infrastructure, the other is the peer."""
    anchors, history = org()
    _other, foreign = org()
    root = anchors[0]
    cache = cache_for(Server(foreign.to_json()), root.did)
    assert cache.get(root.did) is None

    st = cache.status()[root.did]
    assert st.fetched_ok is False
    assert "admission gates" in st.last_error, st.last_error


def test_recovery_clears_the_consecutive_count_but_keeps_the_total():
    anchors, history = org()
    root = anchors[0]
    server = Server(history.to_json())
    server.fail = True
    cache = cache_for(server, root.did, ttl_secs=0)
    cache.get(root.did)
    assert cache.status()[root.did].consecutive_failures == 1

    server.fail = False
    cache.get(root.did)
    st = cache.status()[root.did]
    assert st.fetched_ok is True
    assert st.consecutive_failures == 0, "recovery did not clear the streak"
    assert st.total_failures == 1, "the outage was forgotten entirely"


def test_status_covers_configured_roots_that_have_produced_nothing():
    anchors, _h = org()
    root = anchors[0]
    server = Server("")
    server.fail = True
    cache = cache_for(server, root.did)
    cache.get(root.did)

    st = cache.status()[root.did]
    assert st.version is None and st.fetched_ok is False
    assert st.seeded_only is False, "nothing is held, so this is not a seeded deployment"
