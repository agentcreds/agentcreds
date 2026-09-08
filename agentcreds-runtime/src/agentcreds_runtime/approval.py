"""Human-in-the-loop step-up approval - the *authority* half of intent integrity.

Identity + authority settle *who* an agent is and *what* it may do; they cannot tell
whether a **permitted** action reflects the user's intent or a prompt injection. This
module lets a policy flag high-risk calls to **hold for human approval** before they run.

Model A (synchronous block): the enforcer's final gate, for a flagged call, registers a
pending approval bound to the **exact action** and blocks (polling) until an operator
approves or denies, or a timeout elapses - so externally it is still a normal allow/deny
(``guard_tool`` and ``Decision`` are unchanged).

The approval is the same **R10 ``ApprovalEvidence``** that carried-evidence gates use: a
principal-bound, anchor-signed attestation of the operator's decision, bound to the exact
action *including the on-behalf-of principal*, verified offline by the PEP against the org
anchor and relied upon only once. The poll flow and the carried-evidence flow now share one
evidence format and one verification path - they differ only in *how* the evidence reaches
the PEP (blocking poll vs. carried with the request).

Only flagged calls ever block or touch the control plane; everything else stays offline.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, List, Optional

import agentcreds as ac

from .policy import PolicyInput

# Decides whether a verified call must be held for human approval.
ApprovalPolicy = Callable[[PolicyInput], bool]


@dataclass(frozen=True)
class ApprovalRequest:
    """A pending high-risk call awaiting a human decision (what an operator reviews).
    Carries the exact action so an approver can mint principal-bound evidence for it."""

    approval_id: str
    tool: str
    principal: Optional[str]
    resource: Optional[str]
    args: str  # canonical arguments

    def action(self) -> "ac.Action":
        """The exact action this approval is bound to (incl. the on-behalf-of principal)."""
        return ac.Action(self.tool, self.args, resource=self.resource, acting_for=self.principal)


class ApprovalDenied(Exception):
    """Raised by a client's poll when an operator denied the held call."""


# -- Clients --------------------------------------------------------------------


class ApprovalClient(ABC):
    """Registers a pending approval and reports its resolution as an
    :class:`ac.ApprovalEvidence`. Implementations decide *where* the human approves:
    in-process (:class:`InMemoryApprovalClient`) or via the control-plane console
    (:class:`HttpApprovalClient`)."""

    @abstractmethod
    def request(self, req: ApprovalRequest) -> None:
        """Register `req` as pending (idempotent on `approval_id`)."""

    @abstractmethod
    def poll(self, approval_id: str) -> "Optional[ac.ApprovalEvidence]":
        """Return the anchor-signed evidence if approved, None if still pending; raise
        :class:`ApprovalDenied` if the operator denied it."""


class InMemoryApprovalClient(ApprovalClient):
    """In-process approvals - single PEP, or tests. The operator (or test) calls
    `approve`/`deny`; on approval it mints principal-bound, anchor-signed
    :class:`ac.ApprovalEvidence`, which the enforcer verifies offline exactly as it would
    control-plane-issued evidence. `auto` resolves every request immediately
    ("approve"/"deny") for non-interactive use."""

    def __init__(self, anchor: "ac.TrustAnchor", *, auto: Optional[str] = None, grant_ttl_secs: int = 300):
        self._anchor = anchor
        self._auto = auto
        self._ttl = int(grant_ttl_secs)
        self._lock = threading.Lock()
        self._pending: dict[str, ApprovalRequest] = {}
        self._resolved: dict[str, object] = {}  # id -> ApprovalEvidence | ApprovalDenied

    def request(self, req: ApprovalRequest) -> None:
        with self._lock:
            self._pending[req.approval_id] = req
            if self._auto == "approve":
                self._resolved[req.approval_id] = self._evidence(req, "auto")
            elif self._auto == "deny":
                self._resolved[req.approval_id] = ApprovalDenied("auto-denied")

    def poll(self, approval_id: str) -> "Optional[ac.ApprovalEvidence]":
        with self._lock:
            res = self._resolved.get(approval_id)
        if res is None:
            return None
        if isinstance(res, ApprovalDenied):
            raise res
        return res

    # Operator / test API ------------------------------------------------------
    def list_pending(self) -> List[ApprovalRequest]:
        with self._lock:
            decided = self._resolved.keys()
            return [r for i, r in self._pending.items() if i not in decided]

    def approve(self, approval_id: str, approver: str = "operator") -> None:
        with self._lock:
            self._resolved[approval_id] = self._evidence(self._pending[approval_id], approver)

    def deny(self, approval_id: str, reason: str = "denied by operator") -> None:
        with self._lock:
            self._resolved[approval_id] = ApprovalDenied(reason)

    def _evidence(self, req: ApprovalRequest, approver: str) -> "ac.ApprovalEvidence":
        return ac.ApprovalEvidence.approve(
            req.action(), approver, req.approval_id, int(time.time()) + self._ttl, self._anchor
        )


class HttpApprovalClient(ApprovalClient):
    """Approvals via the control-plane console. `request` POSTs the pending call to
    `{base_url}/approvals`; `poll` GETs `{base_url}/approvals/{id}` and returns the
    operator's anchor-signed :class:`ac.ApprovalEvidence`. The evidence is verified offline
    by the enforcer (signature + principal-bound binding + expiry), so the client trusts no
    part of the response beyond what the enforcer re-checks."""

    def __init__(self, base_url: str, *, subscriber_token: Optional[str] = None, timeout_secs: int = 5):
        self._base = base_url.rstrip("/")
        self._token = subscriber_token
        self._timeout = timeout_secs

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def request(self, req: ApprovalRequest) -> None:
        body = json.dumps({
            "approval_id": req.approval_id,
            "tool": req.tool,
            "principal": req.principal,
            "resource": req.resource,
            "args": req.args,
        }).encode()
        r = urllib.request.Request(f"{self._base}/approvals", data=body, headers=self._headers(), method="POST")
        with urllib.request.urlopen(r, timeout=self._timeout):  # noqa: S310 (trusted control plane)
            pass

    def poll(self, approval_id: str) -> "Optional[ac.ApprovalEvidence]":
        r = urllib.request.Request(f"{self._base}/approvals/{approval_id}", headers=self._headers())
        with urllib.request.urlopen(r, timeout=self._timeout) as resp:  # noqa: S310
            doc = json.loads(resp.read())
        status = doc.get("status")
        if status == "pending":
            return None
        if status == "denied":
            raise ApprovalDenied(doc.get("reason", "denied by operator"))
        return ac.ApprovalEvidence.from_json(doc["evidence"])


def new_approval_id() -> str:
    return uuid.uuid4().hex
