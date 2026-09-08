"""Rotation applies to every anchor-signed artifact, not only credentials.

Rotation used to work for the anchor that issues credentials and nowhere else. The
approver directory and the trust config are signed by their issuer's **current** key
while a relying party pins a **root**, so once the issuer rotated, every one of those
artifacts was refused - the pinned DID was no longer the signer.

That made two things impossible:

* An organization that rotated could not publish an approver directory its own PEPs
  would accept, so the reference PEP refused the combination outright.
* A trust framework could not rotate its anchor at all: every member pins it, so a
  config sealed by the successor broke the entire framework at once.

Both now resolve the signer through the issuer's signed key history - the same move
credentials already made. Each accept case is paired with a control, because "follows
the history" and "accepts any signer" agree on the accept cases alone.
"""

import time

import agentcreds as ac
import pytest

from agentcreds_runtime import (
    ApproverDirectoryCache,
    TrustRegistryCache,
    anchor_resolver_from_registry_cache,
)

URL = "https://org.example/artifact"


def rotated_org():
    """root -> current, with a sealed history pinned at the root."""
    root = ac.TrustAnchor.create_did_key()
    current = ac.TrustAnchor.create_did_key()
    history = ac.KeyHistory.genesis(root)
    history.push(ac.RotationStatement.issue(root, current))
    history.seal(current, 1)
    return root, current, history


def approver_entry(approver_id="alice@example.com"):
    key = ac.AgentIdentity.create_did_key()
    return ac.ApproverEntry(approver_id, key.did, [], None), key


class Server:
    fail = False

    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls = 0

    def __call__(self, url, timeout):
        self.calls += 1
        if self.fail:
            raise OSError("refused")
        return self.bodies[min(self.calls - 1, len(self.bodies) - 1)]


# -- Approver directory published by a rotated organization --------------------


def test_a_directory_sealed_after_rotation_verifies_against_the_pinned_root():
    root, current, history = rotated_org()
    entry, _key = approver_entry()
    directory = ac.ApproverDirectory.seal([entry], 1, current, None)

    cache = ApproverDirectoryCache(
        {root.did: URL}, opener=Server(directory.to_json()), key_histories=[history]
    )
    assert cache.current(root.did) is not None, "a rotated org could not publish a directory"


def test_without_the_history_the_same_directory_is_refused():
    """The control, and the previous behavior: the pinned root is not the signer."""
    root, current, _history = rotated_org()
    entry, _key = approver_entry()
    directory = ac.ApproverDirectory.seal([entry], 1, current, None)

    cache = ApproverDirectoryCache({root.did: URL}, opener=Server(directory.to_json()))
    assert cache.current(root.did) is None


def test_a_directory_sealed_by_a_repudiated_key_is_refused():
    """Following the chain must not mean following it anywhere: a withdrawn key cannot
    publish an approver roster."""
    root, current, history = rotated_org()
    entry, _key = approver_entry()
    # Sealed by the ROOT, which the org then repudiates.
    directory = ac.ApproverDirectory.seal([entry], 1, root, None)

    repudiated = ac.KeyHistory.from_json(history.to_json())
    repudiated.repudiate(root.did)
    repudiated.seal(current, 2)

    ok = ApproverDirectoryCache(
        {root.did: URL}, opener=Server(directory.to_json()), key_histories=[history]
    )
    assert ok.current(root.did) is not None, "control: valid before repudiation"

    refused = ApproverDirectoryCache(
        {root.did: URL}, opener=Server(directory.to_json()), key_histories=[repudiated]
    )
    assert refused.current(root.did) is None, "a repudiated key published a directory"


def test_a_stranger_cannot_sign_a_directory_for_this_org():
    root, _current, history = rotated_org()
    stranger = ac.TrustAnchor.create_did_key()
    entry, _key = approver_entry()
    directory = ac.ApproverDirectory.seal([entry], 1, stranger, None)

    cache = ApproverDirectoryCache(
        {root.did: URL}, opener=Server(directory.to_json()), key_histories=[history]
    )
    assert cache.current(root.did) is None


def test_a_non_rotating_org_still_works_with_no_history():
    """Migration safety: root == current, so nothing changes for existing deployments."""
    anchor = ac.TrustAnchor.create_did_key()
    entry, _key = approver_entry()
    directory = ac.ApproverDirectory.seal([entry], 1, anchor, None)
    cache = ApproverDirectoryCache({anchor.did: URL}, opener=Server(directory.to_json()))
    assert cache.current(anchor.did) is not None


# -- A trust framework rotating its own anchor ---------------------------------


def config_for(framework_anchor, member_anchor, version=1):
    reg = ac.TrustRegistry()
    reg.register(
        ac.TrustEntry(member_anchor.did, "Member", member_anchor.public_key, "verified")
    )
    reg.minimum_trust_level = "verified"
    return reg.export(framework_anchor, version)


def credential_from(anchor):
    agent = ac.AgentIdentity.create_did_key()
    claims = ac.CapabilityClaims(tools=["tool:echo"], max_delegation_depth=1,
                                 valid_for_secs=3600)
    return ac.CapabilityCredential.issue(anchor, agent.did, claims, None)


def test_a_framework_can_rotate_without_every_member_repinning():
    """The case that was impossible. Members pin the framework ROOT; the config is
    sealed by its successor and still resolves."""
    f_root, f_current, f_history = rotated_org()
    member = ac.TrustAnchor.create_did_key()
    config = config_for(f_current, member, 2)

    cache = TrustRegistryCache(
        {f_root.did: URL}, opener=Server(config.to_json()), key_histories=[f_history]
    )
    resolve = anchor_resolver_from_registry_cache(cache, f_root.did)
    assert resolve(credential_from(member)) is not None


def test_without_the_framework_history_the_rotated_config_is_refused():
    """The control: this is what breaking the whole framework looked like."""
    f_root, f_current, _f_history = rotated_org()
    member = ac.TrustAnchor.create_did_key()
    config = config_for(f_current, member, 2)

    cache = TrustRegistryCache({f_root.did: URL}, opener=Server(config.to_json()))
    assert cache.current(f_root.did) is None


def test_a_repudiated_framework_key_cannot_define_membership():
    f_root, f_current, f_history = rotated_org()
    member = ac.TrustAnchor.create_did_key()
    config = config_for(f_root, member, 1)  # sealed by the key about to be withdrawn

    repudiated = ac.KeyHistory.from_json(f_history.to_json())
    repudiated.repudiate(f_root.did)
    repudiated.seal(f_current, 2)

    ok = TrustRegistryCache(
        {f_root.did: URL}, opener=Server(config.to_json()), key_histories=[f_history]
    )
    assert ok.current(f_root.did) is not None, "control: valid before repudiation"

    refused = TrustRegistryCache(
        {f_root.did: URL}, opener=Server(config.to_json()), key_histories=[repudiated]
    )
    assert refused.current(f_root.did) is None


def test_framework_and_member_rotation_compose():
    """Both anchors rotating at once: the framework signs with its successor, and the
    member issues with its own. Two histories, two distinct roles."""
    f_root, f_current, f_history = rotated_org()
    m_root, m_current, m_history = rotated_org()

    reg = ac.TrustRegistry()
    reg.register(ac.TrustEntry(m_root.did, "Member", m_root.public_key, "verified"))
    reg.minimum_trust_level = "verified"
    config = reg.export(f_current, 2)

    cache = TrustRegistryCache(
        {f_root.did: URL}, opener=Server(config.to_json()), key_histories=[f_history]
    )
    # Framework history verifies the CONFIG; member history resolves the ISSUER.
    resolve = anchor_resolver_from_registry_cache(cache, f_root.did, [m_history])
    assert resolve(credential_from(m_current)) is not None
