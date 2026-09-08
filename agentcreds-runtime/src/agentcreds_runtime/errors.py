"""Error and result types for MCP identity enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

# Stable machine-readable codes for a denial. These map cleanly onto the kinds
# of failure a relying party cares about and are safe to log / return to clients.
CODE_NO_CHALLENGE = "no_active_challenge"
CODE_MALFORMED = "malformed_presentation"
CODE_POSSESSION = "possession_failed"
CODE_NOT_AUTHORIZED = "not_authorized"
CODE_CREDENTIAL = "credential_invalid"
CODE_REVOKED = "credential_revoked"
CODE_PRINCIPAL = "principal_mismatch"
CODE_UNBOUND = "argument_binding_required"
CODE_UNTRUSTED_ISSUER = "untrusted_issuer"
CODE_REPLAY = "replayed_presentation"
CODE_POLICY = "policy_denied"
CODE_QUOTA = "usage_limit_exceeded"
CODE_APPROVAL = "approval_required_denied"
#: R10 at-most-once: the evidence verified and satisfied policy, but its reliance
#: unit had already been consumed. Distinct from `CODE_APPROVAL` because the two
#: call for opposite responses - one is a request whose evidence is unsatisfactory,
#: the other is a replay against a *valid* human approval. Collapsed into one code,
#: a conformance suite has to string-match a reason field to tell them apart.
CODE_ALREADY_CONSUMED = "approval_already_consumed"
#: The holder and the verifier canonicalized the request differently, so the
#: exact-action binding was computed over two different representations.
#:
#: Distinct from `possession_failed` on purpose. Both are refusals, and the
#: distinction is diagnostic rather than an authorization difference - but the
#: diagnosis is the whole point: a binding mismatch caused by disagreeing
#: canonicalization profiles is an interop defect, and one caused by altered
#: arguments is an attack. Reported identically, every integration bug looks like
#: a possession failure and every possession failure looks like an integration bug.
CODE_CANON_PROFILE = "canonicalization_profile_mismatch"
#: `agentcreds-octets-v1` only: the proof over the carried octets verified, but those
#: octets do not mean the same thing as the arguments the transport delivered.
#:
#: This is the profile's whole value as a diagnosis. Under a canonicalizing profile the
#: same situation is indistinguishable from two implementations disagreeing about how to
#: write a float, so it reports as `possession_failed` and an operator cannot tell an
#: attack from an interop defect. Here the holder's bytes are in hand and verified, so a
#: mismatch has exactly one meaning: the arguments changed in transit.
CODE_ARGS_MISMATCH = "argument_mismatch"
#: `agentcreds-octets-v1` only: the profile is in force but the carried octets are
#: missing, oversized, or unparseable - so there is nothing to verify the proof against.
CODE_BOUND_ARGS = "bound_arguments_invalid"
CODE_DENIED = "access_denied"


@dataclass(frozen=True)
class ChainHop:
    """One hop of a verified delegation chain, for audit. No key material."""

    depth: int
    agent_did: str
    tools: List[str]
    budget_usd: Optional[int]


@dataclass(frozen=True)
class Decision:
    """The outcome of an authorization check.

    `authorize()` always returns one of these (it never raises for an
    authorization failure); `enforce()` raises `AccessDenied` on a deny instead.
    """

    allowed: bool
    code: Optional[str] = None
    reason: Optional[str] = None
    tool: Optional[str] = None
    # Populated only when `allowed` is True.
    chain: Optional[List[ChainHop]] = None
    #: The id of the Authorization Decision Record this decision produced
    #: (``urn:adr:<hex>``), or None when nothing is recording ADRs.
    #:
    #: **Log this against the effect.** An ADR proves that authority was checked
    #: and permitted; it does not prove the tool ran or what it changed. The two
    #: otherwise join only on ``vc_id`` - the *credential* id, shared by every
    #: call that credential ever authorized - so an auditor can establish "this
    #: agent was allowed to move money" but not "*this* transfer was that call".
    #: Carrying this id into the tool invocation makes that link one-to-one.
    record_id: Optional[str] = None
    #: The arguments the holder actually **signed**, parsed from the carried octets.
    #: Populated only under `agentcreds-octets-v1`, and only on an allow.
    #:
    #: This is the stronger object. What the tool executes is what the *transport*
    #: delivered, and this decision established that the two are semantically equal -
    #: but "semantically equal" is an equivalence relation, not identity, and a tool
    #: that distinguishes ``1`` from ``1.0`` or reads keys in order can tell members of
    #: the same class apart. A caller that wants the guarantee to be identity rather
    #: than equivalence invokes the tool with *this* instead.
    #:
    #: Deliberately not substituted for you: doing that inside the enforcement point
    #: would turn a wrongly-denied call (safe) into a wrongly-executed one (not), and
    #: it has to happen upstream of the framework's own argument validation. See
    #: `Docs/pep-argument-rewrite.md`.
    bound_arguments: Optional[object] = None

    @property
    def denied(self) -> bool:
        return not self.allowed


class AccessDenied(Exception):
    """Raised by `enforce()` when a tool call fails identity enforcement."""

    def __init__(self, decision: Decision):
        self.decision = decision
        self.code = decision.code
        self.reason = decision.reason
        self.tool = decision.tool
        super().__init__(f"{decision.code}: {decision.reason}")
