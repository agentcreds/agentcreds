"""Fetching the signed approver directory at the enforcement point.

R10 step-up approvals are checked against an org-anchor-signed ``ApproverDirectory``.
Distributed as static configuration, that directory is a standing joiner/mover/leaver
problem: **a departed employee stays an authorized approver until someone re-signs and
redistributes it by hand.** Fetching it on a short TTL makes IdP offboarding effective
here within one interval, with no operator action against AgentCreds at all.

WHY A FETCH AND NOT A PUSH. The tighten-only invariant makes JML asymmetric, and that
asymmetry is the whole security argument:

* **Leaver**, or a mover losing authority - a *contraction*. Safe to propagate fast.
* **Joiner**, or a mover gaining authority - an *expansion*. Must come from the signed
  directory and nothing else. If an event could grant approval authority, then anyone
  able to forge or replay one could mint an approver, and a compromised IdP would become
  a direct path to approving privileged actions.

A fetched, anchor-signed artifact serves both correctly: removals take effect as soon as
the new directory is admitted, and grants are only ever believed because the org anchor
signed them. So there is no push channel here by design, not by omission - and the PEP
subscribes to nothing, which keeps enforcement offline-verifiable (R3).

Gates, failure semantics and health reporting are shared - see
:mod:`agentcreds_runtime.fetchcache`. **Monotonicity** is what stops a replayed earlier
directory from restoring a departed approver.
"""

from __future__ import annotations

import time
from typing import Optional

import agentcreds as ac

from .fetchcache import FetchCache

__all__ = ["ApproverDirectoryCache"]


class ApproverDirectoryCache(FetchCache):
    """Fetches the anchor-signed approver directory on a TTL.

    `sources` maps the **pinned org anchor DID** to the URL publishing its directory
    (serverd's ``GET /approver-directory``). A directory is only ever believed because
    the anchor the PEP already trusts signed it - the same root as credentials, with no
    second trust root introduced.

    Pass `key_histories` (a sequence, or a
    :class:`~agentcreds_runtime.KeyHistoryCache`) when the organization may rotate: the
    control plane seals with its **current** key while the PEP pins a **root**, so
    without a history every directory sealed after a rotation is refused.

    The endpoint is normally token-gated: the directory carries the `approver_id` of
    every enrolled human, which is usually an OIDC subject or email address. Pass the
    token via `opener`, or run the PEP where the gate permits it. Integrity does not
    depend on the channel; confidentiality does.
    """

    ARTIFACT = "approver directory"

    def _parse(self, body: str) -> "ac.ApproverDirectory":
        return ac.ApproverDirectory.from_json(body)

    def _verify(self, key: str, artifact: "ac.ApproverDirectory") -> None:
        # Signature AND the sealed expiry together: an authentic-but-lapsed directory
        # must be refused, not assumed current, or the bound is decorative.
        #
        # The signer is resolved through the org's key history when one is supplied, so
        # a directory sealed after a rotation still verifies against the pinned root -
        # and one sealed by a repudiated key does not.
        anchor = self.signing_anchor(key, artifact.issuer_did)
        artifact.verify_current(anchor, int(time.time()))

    def _version(self, artifact: "ac.ApproverDirectory") -> int:
        return artifact.version

    def current(self, anchor_did: str) -> "Optional[ac.ApproverDirectory]":
        """The verified directory for `anchor_did`, refreshing if stale.

        Pass the result straight to the R10 gate. ``None`` means nothing has ever
        verified, and the gate then fails closed - which is correct: an unknown approver
        roster must not satisfy an approval requirement.
        """
        return self.get(anchor_did)
