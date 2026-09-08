"""The approver directory as a fetched artifact: IdP joiner/mover/leaver at the PEP.

The requirement these serve: a leaver must stop being able to approve *here*, at the
enforcement point, without anyone redeploying it. The asymmetry is the security content -
removal takes effect on the next fetch, while a grant is only ever believed because the
org anchor signed it.

Each accept case is paired with a control. "Honours the update" and "honours whatever it
was handed" are indistinguishable on the accept cases alone.
"""

import time

import agentcreds as ac
import pytest

from agentcreds_runtime import ApproverDirectoryCache

URL = "https://org.example/approver-directory"


def approver(approver_id="alice@example.com"):
    key = ac.TrustAnchor.create_did_key()
    return ac.ApproverEntry(approver_id, key.did, [], None), key


def directory(anchor, entries, version, not_after_unix=None):
    return ac.ApproverDirectory.seal(list(entries), version, anchor, not_after_unix)


class Server:
    """A scripted endpoint. Serves `bodies` in order, then repeats the last."""

    fail = False

    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        if self.fail:
            raise OSError("connection refused")
        return self.bodies[min(self.calls - 1, len(self.bodies) - 1)]


def cache_for(server, anchor_did, **kw):
    return ApproverDirectoryCache({anchor_did: URL}, opener=server, **kw)


def ids(d):
    return sorted(e.approver_id for e in d.entries)


# -- The requirement -----------------------------------------------------------


def test_a_leaver_loses_approval_authority_on_the_next_fetch():
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ka = approver("alice@example.com")
    bob, _kb = approver("bob@example.com")

    server = Server(
        directory(anchor, [alice, bob], 1).to_json(),
        directory(anchor, [bob], 2).to_json(),  # alice deactivated in the IdP
    )
    cache = cache_for(server, anchor.did, ttl_secs=0)

    # Control: alice is a legitimate approver first, so her later absence is
    # attributable to the offboarding rather than to the directory never loading.
    assert ids(cache.current(anchor.did)) == ["alice@example.com", "bob@example.com"]

    assert ids(cache.current(anchor.did)) == ["bob@example.com"], "leaver still approves"


def test_a_joiner_is_believed_only_because_the_anchor_signed_it():
    """Expansion comes from the signed artifact. The control is the case below: a
    directory signed by anyone else grants nothing, however well-formed."""
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver("alice@example.com")
    carol, _ = approver("carol@example.com")

    server = Server(
        directory(anchor, [alice], 1).to_json(),
        directory(anchor, [alice, carol], 2).to_json(),
    )
    cache = cache_for(server, anchor.did, ttl_secs=0)
    assert ids(cache.current(anchor.did)) == ["alice@example.com"]
    assert ids(cache.current(anchor.did)) == ["alice@example.com", "carol@example.com"]


def test_a_directory_signed_by_another_anchor_is_refused():
    ours = ac.TrustAnchor.create_did_key()
    theirs = ac.TrustAnchor.create_did_key()
    mallory, _ = approver("mallory@evil.example")

    cache = cache_for(Server(directory(theirs, [mallory], 9).to_json()), ours.did)
    assert cache.current(ours.did) is None, "a foreign anchor minted an approver"


# -- Gates ---------------------------------------------------------------------


def test_a_rolled_back_directory_cannot_restore_a_departed_approver():
    """The attack a signature check does not catch: the org's OWN earlier directory is
    validly signed, so replaying it puts the leaver back."""
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver("alice@example.com")
    bob, _ = approver("bob@example.com")

    server = Server(
        directory(anchor, [bob], 2).to_json(),
        directory(anchor, [alice, bob], 1).to_json(),  # replayed pre-offboarding copy
    )
    cache = cache_for(server, anchor.did, ttl_secs=0)
    assert ids(cache.current(anchor.did)) == ["bob@example.com"]
    assert ids(cache.current(anchor.did)) == ["bob@example.com"], "rollback restored a leaver"
    assert cache.current(anchor.did).version == 2


def test_an_expired_directory_is_refused():
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver()
    stale = directory(anchor, [alice], 1, int(time.time()) - 60)
    cache = cache_for(Server(stale.to_json()), anchor.did)
    assert cache.current(anchor.did) is None


def test_an_unexpired_directory_is_accepted():
    """Control for the expiry case - otherwise 'refused' could just mean 'never loads'."""
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver()
    fresh = directory(anchor, [alice], 1, int(time.time()) + 3600)
    cache = cache_for(Server(fresh.to_json()), anchor.did)
    assert cache.current(anchor.did) is not None


def test_garbage_is_refused():
    anchor = ac.TrustAnchor.create_did_key()
    cache = cache_for(Server("{not a directory}"), anchor.did)
    assert cache.current(anchor.did) is None


# -- Failure behavior and health ----------------------------------------------


def test_a_dead_endpoint_keeps_the_last_verified_directory():
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver()
    server = Server(directory(anchor, [alice], 1).to_json())
    cache = cache_for(server, anchor.did, ttl_secs=0)
    assert cache.current(anchor.did) is not None

    server.fail = True
    assert cache.current(anchor.did) is not None, "a failed fetch dropped the directory"


def test_a_seeded_cache_that_never_fetched_is_visible():
    """The deployment trap: approvals keep working while offboarding silently does not
    reach this PEP. Authorization success cannot reveal it; `fetched_ok` must."""
    anchor = ac.TrustAnchor.create_did_key()
    alice, _ = approver()
    server = Server("")
    server.fail = True
    cache = cache_for(server, anchor.did, ttl_secs=0)
    cache.seed(anchor.did, directory(anchor, [alice], 1))

    assert cache.current(anchor.did) is not None  # looks entirely healthy
    st = cache.status()[anchor.did]
    assert st.fetched_ok is False, "a never-fetched source reported as fetched"
    assert st.seeded_only is True
    assert st.consecutive_failures >= 1


def test_no_directory_at_all_fails_closed():
    anchor = ac.TrustAnchor.create_did_key()
    server = Server("")
    server.fail = True
    cache = cache_for(server, anchor.did)
    assert cache.current(anchor.did) is None


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y"])
def test_non_http_urls_are_refused_at_construction(url):
    with pytest.raises(ValueError, match="unsupported scheme"):
        ApproverDirectoryCache({"did:key:zOrg": url})
