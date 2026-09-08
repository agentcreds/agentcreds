"""Transport-agnostic identity enforcement for MCP tool calls.

`IdentityEnforcer` is the interactive, sessionful verifier: it issues a per-session
proof-of-possession challenge, holds the bound on-behalf-of principal, and runs
the shared authorization policy (`agentcreds_runtime.policy.PolicyContext`) on each
tool call. It has no dependency on the MCP SDK; the FastMCP adapter in
`agentcreds_runtime.fastmcp` wires it into a live server.

For agent-to-agent (no MCP server) verification, see `agentcreds_runtime.a2a`.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional, Sequence

import agentcreds as ac

_log = logging.getLogger("agentcreds_runtime")

#: Sentinel for a directory that has not been looked up yet - distinct from a
#: lookup that returned None, which must not be retried per gate.
_UNSET = object()

from .errors import (
    CODE_ALREADY_CONSUMED,
    CODE_APPROVAL,
    CODE_MALFORMED,
    CODE_NO_CHALLENGE,
    CODE_REPLAY,
    AccessDenied,
    ChainHop,
    Decision,
)
from .gates import APPROVAL, APPROVAL_KEY
from .policy import (
    AdrSink,
    AnchorResolver,
    ArgsCanonicalizer,
    AuditHook,
    AuditRecord,
    PolicyConfig,
    PolicyContext,
    PolicyHook,
    RevocationCheck,
    adr_signal_for,
    anchor_resolver_from_registry,
    classify_exception,
    revocation_check_from_list,
)
from .replay import ReplayGuard
from .session import InMemorySessionStore, SessionStore

# Re-exported for backwards compatibility (these moved to `policy`).
__all__ = [
    "IdentityEnforcer",
    "PolicyConfig",
    "AuditRecord",
    "AuditHook",
    "AdrSink",
    "ArgsCanonicalizer",
    "RevocationCheck",
    "AnchorResolver",
    "revocation_check_from_list",
    "anchor_resolver_from_registry",
]


class IdentityEnforcer(PolicyContext):
    """Per-tool-call identity enforcement for an MCP server.

    Parameters
    ----------
    anchor / anchor_for:
        The single trust anchor whose credentials this server accepts, or - for
        multiple issuing organizations - an `AnchorResolver` (see
        :func:`anchor_resolver_from_registry`). Exactly one is required.
    config:
        A :class:`~agentcreds_runtime.policy.PolicyConfig` carrying the shared
        policy knobs - freshness (`max_age_secs`), revocation, the contextual
        policy / usage / approval gates and their fail-open posture, argument
        binding, and audit / ADR wiring. Defaults to the safe `PolicyConfig()`
        (fail closed everywhere).
    audience_prefix:
        Challenge audience is ``f"{audience_prefix}{session_id}"``.
    session_store / session_ttl_secs:
        Where per-session state (challenge + bound principal) lives. Defaults to an
        in-process `InMemorySessionStore`; pass a shared `RedisSessionStore` for
        multiple replicas.
    replay_guard:
        Optional single-use enforcement: a verified presentation is admitted once,
        then rejected (`replayed_presentation`). **Requires per-call challenge
        rotation** (`rotate_challenge` before each call) - with the default
        per-session challenge, legitimate calls reuse byte-identical presentations,
        so this is off by default. For multiple replicas use a `RedisReplayGuard`.
    recognized_gate_kinds / consumed_approvals:
        R10 execution-time gate kinds this PEP can satisfy (unrecognized => fail
        closed) and the one-time-reliance record.

        `consumed_approvals` defaults to a process-local
        :class:`~agentcreds_runtime.gates.InMemoryConsumedApprovals`, NOT to
        nothing. R10 requires approval evidence to be "relied upon at most once";
        with no ledger the commit is a silent no-op and the same evidence replays
        indefinitely - a MUST failing open on a default. Verified: a PEP built
        without this accepted byte-identical evidence twice.

        The in-memory default is per-process, so a multi-replica PEP must pass a
        :class:`~agentcreds_runtime.gates.RedisConsumedApprovals` - as it already
        does for the session store and replay guard. Pass ``False`` to disable the
        ledger deliberately (it then behaves as before); ``None`` means "use the
        default", so the unsafe posture has to be typed out.
    """

    def __init__(
        self,
        anchor: "Optional[ac.TrustAnchor]" = None,
        *,
        anchor_for: Optional[AnchorResolver] = None,
        config: Optional[PolicyConfig] = None,
        audience_prefix: str = "mcp://",
        session_store: Optional[SessionStore] = None,
        session_ttl_secs: int = 3600,
        replay_guard: Optional[ReplayGuard] = None,
        recognized_gate_kinds: "Sequence[str]" = (APPROVAL,),
        consumed_approvals: "Optional[object]" = None,
        approver_directory: "Optional[object]" = None,
    ):
        super().__init__(anchor, anchor_for=anchor_for, config=config)
        self._audience_prefix = audience_prefix
        self._store = session_store or InMemorySessionStore(ttl_secs=session_ttl_secs)
        self._replay_guard = replay_guard
        # R10 execution-time gates: which designation kinds this PEP can satisfy
        # (an unrecognized kind fails closed) and the one-time reliance record.
        #
        # `approver_directory` enables the HYBRID model: evidence signed by an individual
        # approver key rather than by the org anchor, checked against an anchor-signed
        # directory. That is what gives per-human non-repudiation - anchor-signed evidence
        # proves only that the organization approved, never who.
        #
        # Accepts a directory or a zero-arg callable returning one. Prefer the callable
        # (e.g. `ApproverDirectoryCache.current` bound to the org DID): a directory read
        # once at startup cannot reflect an IdP offboarding, so a departed approver would
        # keep satisfying gates until the process restarted.
        if callable(approver_directory):
            self._directory_source = approver_directory
        elif approver_directory is not None:
            self._directory_source = lambda d=approver_directory: d
        else:
            self._directory_source = None
        self._gate_kinds = tuple(recognized_gate_kinds)
        # Supplying a directory is an unambiguous statement of intent to support the
        # hybrid kind, so recognize it - matching `gates.run_gates`. Otherwise a caller
        # would have to pass the directory AND repeat the kind, and forgetting the second
        # fails closed in a way that looks like a policy bug.
        if self._directory_source is not None and APPROVAL_KEY not in self._gate_kinds:
            self._gate_kinds = self._gate_kinds + (APPROVAL_KEY,)
        # Default ON - see the class docstring. `False` is the explicit opt-out; test it
        # with `is False` rather than truthiness, so a caller's store that happens to be
        # falsy when empty (a `__len__`/`__bool__` neither shipped store defines, but a
        # custom one easily might) is not silently turned into "no ledger at all".
        if consumed_approvals is False:
            self._consumed = None
        elif consumed_approvals is None:
            from .gates import InMemoryConsumedApprovals  # lazy: avoid an import cycle

            self._consumed = InMemoryConsumedApprovals()
        else:
            self._consumed = consumed_approvals

    # -- Challenge lifecycle ---------------------------------------------------

    def issue_challenge(self, session_id: str) -> bytes:
        """Create and store a fresh challenge for `session_id`; return its CBOR
        bytes to send to the client (e.g. in the MCP initialize result)."""
        challenge = ac.PopChallenge(audience=f"{self._audience_prefix}{session_id}")
        cbor = challenge.to_cbor()
        self._store.put_challenge(session_id, cbor)
        return cbor

    def rotate_challenge(self, session_id: str) -> bytes:
        """Alias for `issue_challenge` - call before each tool call for per-call
        replay protection (at the cost of an extra round trip)."""
        return self.issue_challenge(session_id)

    def clear_session(self, session_id: str) -> None:
        self._store.clear(session_id)

    def _challenge_for(self, session_id: str) -> "Optional[ac.PopChallenge]":
        cbor = self._store.get_challenge(session_id)
        return ac.PopChallenge.from_cbor(cbor) if cbor is not None else None

    # -- On-behalf-of principal ------------------------------------------------

    def bind_principal(self, session_id: str, principal_did: str) -> None:
        """Bind the **verified** human principal this session acts on behalf of.

        Call once per session *after* you authenticate the human (e.g. validate
        their OIDC ID token with `agentcreds.OidcProvider` and derive their DID).
        The bound DID is the `acting_for` of every subsequent call, and the core
        enforces it matches the principal the presented token is bound to.

        Security note: `principal_did` must come from *your* verified session, not
        the client or the token.
        """
        self._store.put_principal(session_id, principal_did)

    def _principal_for(self, session_id: str) -> Optional[str]:
        return self._store.get_principal(session_id)

    # -- Authorization ---------------------------------------------------------

    def authorize(
        self,
        session_id: str,
        tool: str,
        arguments: object,
        presentation_cbor: bytes,
        resource: Optional[str] = None,
        approval_evidence: "Sequence[ac.ApprovalEvidence]" = (),
        canonicalization_profile: Optional[str] = None,
        bound_arguments: Optional[str] = None,
    ) -> Decision:
        """Authorize one tool call. Returns a `Decision`; never raises for an
        authorization failure.

        `resource` is the resource this call touches (held to the token's resource
        scope); the on-behalf-of principal is taken from this session's
        `bind_principal` binding (if any). `approval_evidence` is the execution-time
        human-authorization evidence (R10) carried with the request - required for
        any tool the presented token designates via an in-token gate.

        `bound_arguments` is the holder's literal serialized arguments, required only
        under `agentcreds-octets-v1`; every other profile reconstructs the binding
        string by canonicalizing `arguments` and ignores this."""
        args_str = self._initial_args_str(arguments)

        challenge = self._challenge_for(session_id)
        if challenge is None:
            return self._finish(
                session_id, tool, args_str,
                Decision(False, CODE_NO_CHALLENGE, "no active challenge for this session", tool),
                signal="other",
            )

        try:
            presentation = ac.Presentation.from_cbor(presentation_cbor)
        except Exception as exc:  # malformed / wrong bytes
            return self._finish(
                session_id, tool, args_str,
                Decision(False, CODE_MALFORMED, f"could not decode presentation: {exc}", tool),
                signal="signature_invalid",
            )

        # -02 §1.3: a binding computed under a different canonicalization profile is
        # failed verification, not an ordinary mismatch - and must not be reported as
        # a possession failure, which is what an *altered* argument looks like.
        if (denied := self._deny_if_canon_mismatch(
            presentation, session_id, tool, args_str, canonicalization_profile,
        )) is not None:
            return denied

        # Under `agentcreds-octets-v1` this replaces `args_str` with the bytes the holder
        # actually signed, so the proof below is checked over those and never over
        # anything this verifier re-serialized.
        denied, args_str, signed_arguments = self._resolve_bound_octets(
            presentation, session_id, tool, args_str, arguments, bound_arguments,
        )
        if denied is not None:
            return denied

        if (denied := self._deny_if_unbound(presentation, session_id, tool, args_str)) is not None:
            return denied

        anchor, denied = self._resolve_anchor(presentation, session_id, tool, args_str)
        if denied is not None:
            return denied

        # The on-behalf-of principal comes from this server's verified session,
        # never from the token; `resource` scopes which data this call may touch.
        action = ac.Action(
            tool, args_str, resource=resource, acting_for=self._principal_for(session_id)
        )
        try:
            presentation.verify(
                action, anchor, challenge, self._max_age_for(presentation.credential)
            )
        except ac.AgentCredsError as exc:
            return self._finish(
                session_id, tool, args_str,
                Decision(False, classify_exception(exc), str(exc), tool),
                token=presentation.token, credential=presentation.credential, signal=adr_signal_for(exc),
            )

        # Single-use enforcement (opt-in; requires per-call challenge rotation):
        # a verified presentation may be admitted only once. Recorded after verify
        # so invalid presentations cannot poison the guard.
        if self._replay_guard is not None:
            key = hashlib.sha256(presentation_cbor).hexdigest()
            if not self._replay_guard.record_if_new(key):
                return self._finish(
                    session_id, tool, args_str,
                    Decision(False, CODE_REPLAY, "this presentation has already been used", tool),
                    token=presentation.token, credential=presentation.credential, signal="other",
                )

        if (denied := self._deny_if_revoked(presentation, session_id, tool, args_str)) is not None:
            return denied

        # R10 execution-time human authorization: the token itself designates which
        # tools require a human decision; enforce it against carried, principal-bound,
        # anchor-verified evidence. Runs after authority + revocation so only
        # otherwise-valid calls are held to a human decision. One-time reliance is
        # collected here and *committed* only once every gate has passed (below), so a
        # downstream denial can never burn valid evidence.
        relied_upon: "list[ac.ApprovalEvidence]" = []
        if (denied := self._deny_if_gated(
            presentation, action, anchor, session_id, tool, args_str, approval_evidence, relied_upon,
        )) is not None:
            return denied

        chain = [
            ChainHop(e.depth, e.agent_did, list(e.tools), e.budget_usd)
            for e in presentation.token.chain().entries
        ]

        # Final contextual gate: the verified call (principal + chain + request) is
        # offered to the policy hook for attribute/condition rules the capability
        # can't express. Runs last, after authority is proven and revocation cleared.
        if (denied := self._deny_if_policy(
            session_id, tool, args_str,
            principal=self._principal_for(session_id),
            arguments=arguments, resource=resource, chain=chain,
            token=presentation.token, credential=presentation.credential,
        )) is not None:
            return denied

        # Stateful usage gate (rate/quota + spend) - the final gate, so its counters
        # only advance for calls that pass everything above.
        if (denied := self._deny_if_usage(
            session_id, tool, args_str,
            principal=self._principal_for(session_id),
            arguments=arguments, resource=resource, chain=chain,
            token=presentation.token, credential=presentation.credential,
        )) is not None:
            return denied

        # Human-in-the-loop step-up - escalates flagged calls and BLOCKS until approved
        # or denied/timeout. Last gate, so only fully authorized calls are escalated.
        if (denied := self._hold_for_approval(
            session_id, tool, args_str,
            principal=self._principal_for(session_id),
            arguments=arguments, resource=resource, chain=chain,
            token=presentation.token, credential=presentation.credential, anchor=anchor,
        )) is not None:
            return denied

        # Commit R10 one-time reliance only now that the call has cleared every gate,
        # so a downstream denial (policy, usage, step-up) cannot burn valid evidence and
        # a legitimate retry can re-present it. Each id is remembered until the evidence's
        # own expiry; the commit stays atomic, so a concurrent first reliance wins the race
        # and a genuine re-use is refused here.
        #
        # The verdicts below are recorded separately (R10, draft -02 §2.1). Reaching
        # this line means the evidence verified and satisfied every gate, so
        # `evaluation` is an allow whichever way the commit goes. Only `admission`
        # differs - and an admission denial on a passing evaluation is precisely a
        # replay: the same still-valid human approval, presented twice. A record
        # carrying one verdict reports that identically to evidence that never
        # verified, and the two call for opposite responses.
        evaluated = "allow" if relied_upon else None
        for ev in relied_upon:
            if not self._commit_reliance(ev.approval_id, int(ev.expires_at)):
                return self._finish(
                    session_id, tool, args_str,
                    Decision(False, CODE_ALREADY_CONSUMED,
                             "approval evidence has already been relied upon (R10 one-time)",
                             tool),
                    token=presentation.token, credential=presentation.credential,
                    signal="action_denied",
                    evaluation=evaluated, admission="deny",
                )

        return self._finish(
            session_id, tool, args_str,
            Decision(True, None, None, tool, chain, bound_arguments=signed_arguments),
            token=presentation.token, credential=presentation.credential,
            evaluation=evaluated,
            admission="allow" if relied_upon else None,
        )

    def _deny_if_gated(
        self, presentation, action, anchor, session_id, tool, args_str, evidence, relied_upon
    ) -> "Optional[Decision]":
        """R10: enforce the token's in-authority execution-time gates. For every gate
        designating this tool, require carried, anchor-verified, principal-bound evidence;
        fail closed on an unrecognized gate kind. The matched evidence relied upon is
        appended to `relied_upon`; one-time reliance is **committed by the caller** only
        after every gate has passed, so a downstream denial never consumes valid evidence."""
        token = presentation.token
        gates = token.required_gates(action)
        if not gates:
            return None
        now = int(time.time())
        # Read the directory at most once per authorize call, not once per gate: the
        # source may fetch, and two gates must not disagree about who the approvers are
        # inside a single decision.
        directory = _UNSET
        for gate in gates:
            # An unrecognized OR recognized-but-unsupported kind fails CLOSED. A gate the
            # PEP cannot evaluate must never slip through as satisfied.
            if gate.kind not in self._gate_kinds:
                return self._finish(
                    session_id, tool, args_str,
                    Decision(False, CODE_APPROVAL,
                             f"execution-time gate '{gate.kind}' cannot be satisfied here - "
                             "failing closed (R10)", tool),
                    token=token, credential=presentation.credential, signal="action_denied",
                    evaluation="deny",
                )
            if gate.kind == APPROVAL_KEY:
                if directory is _UNSET:
                    directory = self._current_directory()
                if directory is None:
                    # Distinct from "no valid evidence": this is a PEP-side fault (no
                    # directory configured, or its fetch has never succeeded), not a
                    # missing human approval. The two are indistinguishable to the caller
                    # otherwise, and they need opposite responses.
                    return self._finish(
                        session_id, tool, args_str,
                        Decision(False, CODE_APPROVAL,
                                 "action requires approver-key authorization but no verified "
                                 "approver directory is available here - failing closed (R10)",
                                 tool),
                        token=token, credential=presentation.credential, signal="action_denied",
                    evaluation="deny",
                    )
                match = next(
                    (e for e in evidence
                     if self._evidence_ok_with_directory(e, action, directory, anchor, now)),
                    None,
                )
            else:
                # The binding does not surface a `kind` on anchor-mode evidence, so absence
                # means the reference approval kind; the authoritative check is `_evidence_ok`
                # (anchor verification), which rejects anything not anchor-signed for this action.
                match = next(
                    (e for e in evidence
                     if getattr(e, "kind", APPROVAL) == APPROVAL
                     and self._evidence_ok(e, action, anchor, now)),
                    None,
                )
            if match is None:
                return self._finish(
                    session_id, tool, args_str,
                    Decision(False, CODE_APPROVAL,
                             "action requires human approval; no valid execution-time "
                             "evidence presented (R10)", tool),
                    token=token, credential=presentation.credential, signal="action_denied",
                    evaluation="deny",
                )
            relied_upon.append(match)
        return None

    def _current_directory(self):
        """The approver directory to judge this decision against, or None.

        Never raises: a source that fails - an unreachable endpoint, a directory that no
        longer verifies - must deny rather than crash the request, and the caller turns
        None into an explicit fail-closed denial.
        """
        if self._directory_source is None:
            return None
        try:
            return self._directory_source()
        except Exception as exc:  # noqa: BLE001 - fail closed, but stay diagnosable
            _log.warning(
                "approver directory unavailable; approval-key gates will deny: %s", exc
            )
            return None

    @staticmethod
    def _evidence_ok_with_directory(evidence, action, directory, anchor, now: int) -> bool:
        """Hybrid check: evidence signed by an individual approver key, authorized by the
        anchor-signed directory. The directory is the only thing binding a key to a human,
        so an approver removed from it stops satisfying gates immediately."""
        try:
            evidence.verify_with_directory(action, directory, anchor, now)
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not valid (fail closed)
            _log.debug("approver-key evidence rejected at verify: %s", exc)
            return False

    @staticmethod
    def _evidence_ok(evidence, action, anchor, now: int) -> bool:
        try:
            evidence.verify(action, anchor, now)
            return True
        except Exception as exc:  # noqa: BLE001 - any verification failure -> not valid (fail closed)
            # Log at debug so a genuine bug (e.g. a malformed evidence object raising
            # TypeError) is diagnosable without weakening the gate or being noisy.
            _log.debug("approval evidence rejected at verify: %s", exc)
            return False

    def enforce(
        self,
        session_id: str,
        tool: str,
        arguments: object,
        presentation_cbor: bytes,
        resource: Optional[str] = None,
        approval_evidence: "Sequence[ac.ApprovalEvidence]" = (),
        canonicalization_profile: Optional[str] = None,
        bound_arguments: Optional[str] = None,
    ):
        """Like `authorize`, but raise `AccessDenied` on a deny and return the
        verified chain on allow. Convenient for adapters. `approval_evidence` is
        the R10 execution-time human-authorization evidence carried with the call.

        Returns the chain only. Use :meth:`enforce_decision` when you need the
        decision's `record_id` to log against whatever the call goes on to do."""
        return self.enforce_decision(
            session_id, tool, arguments, presentation_cbor, resource, approval_evidence,
            canonicalization_profile, bound_arguments,
        ).chain

    def enforce_decision(
        self,
        session_id: str,
        tool: str,
        arguments: object,
        presentation_cbor: bytes,
        resource: Optional[str] = None,
        approval_evidence: "Sequence[ac.ApprovalEvidence]" = (),
        canonicalization_profile: Optional[str] = None,
        bound_arguments: Optional[str] = None,
    ) -> Decision:
        """Like `enforce`, but return the whole allow `Decision` rather than just
        the chain - so the caller can read `record_id` and log it alongside the
        effect of the call.

        That link is the difference between "this agent was permitted to move
        money" and "*this* transfer was that decision": an ADR records an
        authorization, not an action, and the two otherwise join only on `vc_id`,
        which every call under the same credential shares."""
        decision = self.authorize(
            session_id, tool, arguments, presentation_cbor, resource, approval_evidence,
            canonicalization_profile, bound_arguments,
        )
        if decision.denied:
            raise AccessDenied(decision)
        return decision
