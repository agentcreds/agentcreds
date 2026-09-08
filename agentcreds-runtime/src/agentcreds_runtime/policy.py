"""Transport-agnostic authorization policy core.

Both the MCP `IdentityEnforcer` (interactive, sessionful) and the A2A
`A2AVerifier` (stateless, one-shot) run the *same* decision after they obtain a
presentation: resolve the trust anchor, require argument binding if configured,
verify, check revocation, and emit audit / ADR records. That shared machinery
lives here as `PolicyContext`; the transport layers add only how the presentation
is obtained and which verify call to run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Mapping, Optional, Union

import agentcreds as ac

_log = logging.getLogger("agentcreds_runtime")

from . import jcs as _jcs
from . import octets as _octets
from .errors import (
    CODE_APPROVAL,
    CODE_ARGS_MISMATCH,
    CODE_BOUND_ARGS,
    CODE_CANON_PROFILE,
    CODE_CREDENTIAL,
    CODE_DENIED,
    CODE_NOT_AUTHORIZED,
    CODE_POLICY,
    CODE_POSSESSION,
    CODE_PRINCIPAL,
    CODE_QUOTA,
    CODE_REVOKED,
    CODE_UNBOUND,
    CODE_UNTRUSTED_ISSUER,
    Decision,
)

# -- Hook / callback types -----------------------------------------------------

# Audit callbacks receive the tool, canonical args, and the verified chain.
AuditHook = Callable[["AuditRecord"], None]
# ADR sinks receive each Authorization Decision Record (allow and deny).
AdrSink = Callable[["ac.AuthzDecision"], None]
# Args canonicalizers turn an arguments object into a stable string.
ArgsCanonicalizer = Callable[[object], str]
# A revocation check: True if the credential has been revoked (may raise).
RevocationCheck = Callable[["ac.CapabilityCredential"], bool]
# An anchor resolver: the anchor to verify a credential against, or None.
AnchorResolver = Callable[["ac.CapabilityCredential"], "Optional[ac.TrustAnchor]"]
# A contextual policy hook: return None to allow, or a short deny reason to deny.
PolicyHook = Callable[["PolicyInput"], Optional[str]]


class PolicyInput:
    """Inputs to a :data:`PolicyHook`.

    A hook runs **only after** the credential has cryptographically verified
    (anchor-rooted, proof-of-possession, scope grants the tool, on-behalf-of
    principal matched, not revoked). It is the place for *contextual* / attribute
    rules the capability itself can't express - argument conditions, time, rate,
    resource attributes, or the principal's OIDC claims - combining the three
    authority inputs (OIDC principal, the VC chain, the request) into one decision.

    It must not re-decide what the capability already settled (which tool / which
    resource / not revoked) - that lives in the credential, not here.
    """

    __slots__ = ("principal", "tool", "arguments", "args", "resource", "chain", "token")

    def __init__(self, *, principal, tool, arguments, args, resource, chain, token):
        self.principal = principal  # OIDC-bound acting_for DID (or None)
        self.tool = tool            # the tool / action name
        self.arguments = arguments  # raw arguments object (e.g. the call kwargs)
        self.args = args            # canonical args string (what was bound / audited)
        self.resource = resource    # resource id this call touches (or None)
        self.chain = chain          # verified delegation chain (list[ChainHop])
        self.token = token          # the verified token (issuer, budget, ...)

    def __repr__(self):
        return f"PolicyInput(tool={self.tool!r}, principal={self.principal!r})"


def predicate_policy(
    rules: "Mapping[str, Callable[[PolicyInput], Optional[str]]]",
) -> PolicyHook:
    """Build a :data:`PolicyHook` that dispatches by tool name.

    Each rule receives the :class:`PolicyInput` and returns a deny reason (a short
    string) or ``None`` to allow. A tool with no rule is allowed - the capability
    already established it is in scope. Suitable as a lightweight, dependency-free
    stand-in for a full policy engine (swap the predicate body for a Cedar / OPA
    evaluation over the same `PolicyInput` when you want policy-as-code).
    """

    def hook(pin: "PolicyInput") -> Optional[str]:
        rule = rules.get(pin.tool)
        return rule(pin) if rule is not None else None

    return hook


class AuditRecord:
    """Emitted on every allowed call (and, if `audit_denied`, on denials)."""

    __slots__ = ("session_id", "tool", "args", "allowed", "code", "chain")

    def __init__(self, session_id, tool, args, allowed, code, chain):
        self.session_id = session_id
        self.tool = tool
        self.args = args
        self.allowed = allowed
        self.code = code
        self.chain = chain

    def __repr__(self):
        state = "allow" if self.allowed else f"deny({self.code})"
        return f"AuditRecord(session={self.session_id!r}, tool={self.tool!r}, {state})"


#: RFC 8785 (JSON Canonicalization Scheme) - **the default** since 2026-08-13, and the
#: profile to use for anything that crosses a language boundary.
#:
#: `json-sorted-v1` was two independent readings of "sorted JSON" and they disagreed on
#: real traffic - Python escaped non-ASCII where Node emitted literal UTF-8, and Python
#: wrote `1.0` where JavaScript wrote `1`. Either produces a binding mismatch on a
#: request nobody tampered with. JCS is a specification rather than a convention, so a
#: fourth language reaches for a conformant library instead of reverse-engineering ours.
#:
#: Defaulting to it is the point: the failure it prevents is a *false refusal* of an
#: untampered request, which a deployment only discovers in production and reads as a
#: security event. A profile that behaves correctly has to be what you get for free.
CANON_PROFILE_JCS = "agentcreds-jcs-v1"

#: Carry the signed octets instead of canonicalizing (:mod:`agentcreds_runtime.octets`).
#:
#: The holder serializes its arguments however it likes, signs those exact bytes, and
#: carries them; the verifier checks the proof over the carried bytes and then compares
#: them to the delivered arguments *semantically*. Nothing has to agree on how to write
#: a float, so the cross-language divergence class disappears rather than being
#: specified away - and a mismatch means the arguments changed, which under a
#: canonicalizing profile is indistinguishable from an interop defect.
#:
#: Not the default: the arguments travel twice, which costs payload and puts a copy
#: wherever the transport keeps reserved arguments. Choose it deliberately - it is the
#: better answer when a binding crosses an organizational or language boundary.
CANON_PROFILE_OCTETS = _octets.PROFILE

#: Serialize arguments for the **holder** under :data:`CANON_PROFILE_OCTETS`. The string
#: this returns must be both bound into the action and carried to the verifier.
octets_bind_args = _octets.bind_args


def jcs_canonicalize_args(args: object) -> str:
    """Canonicalize arguments per RFC 8785 - profile :data:`CANON_PROFILE_JCS`.

    Unrepresentable input raises rather than falling back. A canonicalizer that guesses
    emits a string the other side cannot reproduce, which presents as tampering on a
    request that was never tampered with.
    """
    if args is None:
        return ""
    if isinstance(args, bytes):
        return args.decode()
    if isinstance(args, str):
        return args
    return _jcs.canonicalize(args)


@dataclass(frozen=True)
class PolicyConfig:
    """The transport-agnostic policy knobs shared by every verifier - freshness,
    revocation, the contextual policy / usage / approval gates and their fail-open
    posture, argument binding, and audit / ADR wiring.

    Grouped into one object so the shared block has a single typed, discoverable
    home (add a knob here, not in three constructors). The trust anchor
    (``anchor`` / ``anchor_for``) and transport-specific options stay direct on
    :class:`IdentityEnforcer` / :class:`A2AVerifier`; pass this as ``config=``.

    Every field defaults to the safe posture (fail **closed** on gate errors), with one
    field that has no safe default to offer: ``revocation_check`` must be stated, so a
    bare ``PolicyConfig()`` raises when a verifier is built from it. That is deliberate -
    it used to be the one knob whose default silently accepted every revoked credential.
    """

    max_age_secs: int = 60
    #: How this verifier learns a credential has been revoked. **Required**: there is no
    #: safe default to fall back on, because a revocation source cannot be invented -
    #: unlike `consumed_approvals`, which has a working in-process implementation.
    #:
    #: So the two postures both have to be stated. Supply a check, or pass ``False`` to
    #: say *deliberately no revocation checking*. Leaving it ``None`` raises when the
    #: verifier is built, because the alternative is what this used to do: accept every
    #: revoked credential, silently, on a config the docstring called secure.
    revocation_check: "Union[RevocationCheck, bool, None]" = None
    fail_open_on_revocation_error: bool = False
    #: Refuse a presentation that carries no argument binding. **On by default.**
    #:
    #: An unbound proof says "this holder is here now" and nothing about *what they
    #: asked for*, so a presentation captured from an `amount=10` call can be replayed
    #: against `amount=1000000` - the signature is still valid, because it never covered
    #: the arguments. That is the attack the binding machinery exists to stop, and
    #: leaving the check off by default meant a deployment had to opt in to being
    #: protected by it.
    require_argument_binding: bool = True
    policy_hook: Optional[PolicyHook] = None
    fail_open_on_policy_error: bool = False
    usage_meter: Optional[PolicyHook] = None
    fail_open_on_usage_error: bool = False
    approval_policy: "Optional[Callable[[PolicyInput], bool]]" = None
    approval_client: "Optional[object]" = None
    approval_timeout_secs: int = 120
    approval_poll_interval_secs: float = 2.0
    fail_open_on_approval_error: bool = False
    audit: Optional[AuditHook] = None
    audit_denied: bool = False
    adr_sink: Optional[AdrSink] = None
    adr_stream: "Optional[ac.AdrStream]" = None
    #: RFC 8785 by default. This and `canonicalization_profile` must always describe the
    #: same algorithm - they move together, or every bound call is refused as tampering.
    canonicalize_args: ArgsCanonicalizer = jcs_canonicalize_args
    #: The canonicalization profile this verifier computes bindings under. A holder
    #: that declares a different one is refused as `canonicalization_profile_mismatch`
    #: rather than as a possession failure.
    canonicalization_profile: str = CANON_PROFILE_JCS
    #: Require holders to declare their profile (-02 §1.3 strict posture: a *missing*
    #: mapping is failed verification too). **On since 2026-08-13.**
    #:
    #: It became the default when JCS did. Before that flip the default profile was the
    #: same thing a legacy holder computed, so a holder that declared nothing matched by
    #: accident and silence was harmless. Afterwards silence means the two sides compute
    #: different bindings - and only for non-ASCII strings and floats, so it passes
    #: testing and fails on the first accented name in production. Refusing up front with
    #: a named reason beats an undiagnosable `possession_failed` months later.
    #:
    #: Only applies to presentations that are actually action-bound; an unbound one
    #: computed no binding and has nothing to declare.
    require_canonicalization_profile: bool = True
    #: Freshness **scaled to consequence class** (-02 §2.4): a proof old enough to be
    #: fine for a read is not fine for a payment. Maps the credential's
    #: ``autonomy_level`` (0-3) to a `max_age_secs` for calls under it; levels absent
    #: from the map fall back to `max_age_secs`.
    #:
    #: A single global bound is the wrong shape but the safe default, so this is
    #: opt-in. Only ever *narrows*: an entry longer than `max_age_secs` is clamped,
    #: because a per-class knob that can loosen the global bound turns a freshness
    #: policy into a way around one.
    max_age_by_autonomy: "Optional[Mapping[int, int]]" = None


# Map core exceptions to stable denial codes. Order matters: more specific first.
def classify_exception(exc: BaseException) -> str:
    if isinstance(exc, ac.ProofOfPossessionError):
        return CODE_POSSESSION
    if isinstance(exc, ac.PrincipalMismatchError):
        return CODE_PRINCIPAL
    if isinstance(exc, (ac.ActionDeniedError, ac.ScopeWideningError)):
        return CODE_NOT_AUTHORIZED
    if isinstance(
        exc,
        (
            ac.TokenExpiredError,
            ac.CredentialExpiredError,
            ac.CredentialRevokedError,
            ac.CredentialError,
            ac.DelegationError,
        ),
    ):
        return CODE_CREDENTIAL
    return CODE_DENIED


# Map core exceptions to ADR signals (mirrors ``agentcreds_core::adr::Signal``).
def adr_signal_for(exc: BaseException) -> str:
    if isinstance(exc, ac.ProofOfPossessionError):
        return "proof_of_possession_failed"
    if isinstance(exc, ac.ScopeWideningError):
        return "scope_widening_attempt"
    if isinstance(exc, (ac.ActionDeniedError, ac.PrincipalMismatchError)):
        return "action_denied"
    if isinstance(exc, (ac.TokenExpiredError, ac.CredentialExpiredError)):
        return "expired"
    if isinstance(exc, ac.CredentialRevokedError):
        return "revoked"
    if isinstance(exc, (ac.CredentialError, ac.DelegationError)):
        return "signature_invalid"
    return "other"


def revocation_check_from_list(
    rev_list: "ac.RevocationList",
    anchor: "ac.TrustAnchor",
    *,
    max_signed_age: Optional[timedelta] = None,
) -> RevocationCheck:
    """Build a :data:`RevocationCheck` that resolves a credential's status against
    a local, anchor-signed ``RevocationList`` held in process.

    Suitable for a single-org deployment where the issuer's list is available to
    the verifier. For cross-org, supply your own check that fetches the list from
    ``credential.credential_status.status_list_credential`` and verifies it. The
    list's signature is verified against ``anchor`` on every call.

    R7 bounded staleness: pass ``max_signed_age`` to also reject a list whose
    signed ``updated`` timestamp is older than that bound - the age of the *signed
    state itself*, independent of any fetch cache. This catches a frozen-but-
    serving issuer and a replay of an old-but-valid list, which a fetch-recency
    bound cannot see. On breach the check raises, so the enforcer fails closed
    (``CODE_REVOKED``) by default. Leave ``None`` to disable the bound.
    """

    def check(credential: "ac.CapabilityCredential") -> bool:
        status = credential.credential_status
        if status is None:
            return False  # no status entry -> never revoked
        rev_list.verify(anchor)  # authenticate the list before trusting it
        if max_signed_age is not None:
            age = datetime.now(timezone.utc) - rev_list.updated
            if age > max_signed_age:
                raise RuntimeError(
                    f"revocation list stale: signed state is {age} old, exceeding "
                    f"the configured max_signed_age {max_signed_age} (R7 bounded "
                    "staleness) - failing closed"
                )
        return rev_list.is_revoked(status.status_list_index)

    return check


def anchor_resolver_from_registry(
    registry: "ac.TrustRegistry",
    key_histories: "Optional[Iterable[ac.KeyHistory]]" = None,
) -> AnchorResolver:
    """Build an :data:`AnchorResolver` from an ``agentcreds.TrustRegistry``.

    Accepts a credential only if its issuer is registered at or above the
    registry's ``minimum_trust_level`` and the credential's proof verifies; then
    returns a verify-only anchor for the issuer (``did:key`` issuers). For other
    DID methods, supply your own resolver.

    `key_histories` is the signed :class:`~agentcreds.KeyHistory` of each member that
    has rotated, and makes the registry rotation-aware. A sequence rather than a mapping
    keyed by root: each history already carries its own `root_did`, and a mapping invites
    a key that disagrees with it - an ambiguity with no right answer. Without it a
    member that rotates its anchor is refused by every relying party until the framework
    re-signs the registry and everyone re-imports it - a multilateral event triggered by
    one member's own key hygiene. With it, the registry pins the stable root and the
    member's history carries the rotation.

    The histories are deliberately NOT inside the signed registry. Inlining them would
    put a member's rotation back inside the framework's signature, which is the coupling
    this removes. Distribute them as the revocation list is distributed - the artifact is
    signed, so the channel need not be trusted.

    Trust level is enforced against the ROOT entry, so rotation cannot be used to escape
    a minimum level.

    Note: the registry mutates as it caches resolutions, so serialize access if you share
    one across threads.
    """

    def resolve(credential: "ac.CapabilityCredential") -> "Optional[ac.TrustAnchor]":
        issuer = credential.issuer
        if not issuer.startswith("did:key:"):
            return None  # trusted or not, this helper only builds did:key anchors

        # A history that names this issuer is AUTHORITATIVE for it - decide here and do
        # not fall through.
        #
        # Order matters, and getting it wrong is not cosmetic. Trying direct
        # registration first lets a REPUDIATED ROOT resolve, because the registry entry
        # is keyed on exactly that DID: `verify_credential` succeeds and the history is
        # never consulted. Repudiation would then be bypassable cross-org, which is to
        # say useless. Caught by test_repudiated_key_is_refused_cross_org.
        for history in key_histories or ():
            if issuer not in history.dids():
                continue  # a different member's history
            try:
                # Enforces membership, trust level, the seal, the expiry and any
                # repudiation - all in the core, none re-implemented here.
                registry.verify_credential_rotated(credential, history)
            except Exception:
                return None  # authoritative refusal
            return ac.TrustAnchor.from_did_key(issuer)

        # No history claims this issuer: the plain registered-issuer path.
        try:
            registry.verify_credential(credential)  # trust level + signature
        except ac.AgentCredsError:
            return None  # unregistered, below minimum level, or bad signature
        return ac.TrustAnchor.from_did_key(issuer)

    return resolve


def anchor_resolver_from_key_history(
    history: "ac.KeyHistory", root_did: str
) -> AnchorResolver:
    """Build an :data:`AnchorResolver` that follows a signed key-history chain.

    Pin an organization's **root** anchor DID once; this resolver then accepts a
    credential issued by any key that organization has legitimately held, by verifying
    the rotation chain from `root_did` forward and confirming the credential's issuer
    appears in it (``KeyHistory.authorize_issuer``).

    Why this exists: a ``did:key`` anchor's identity *is* its public key, so rotating
    the key yields a new DID. Pinning the CURRENT DID therefore makes every rotation a
    breaking change for every relying party - which fails closed and denies all of that
    organization's traffic. Pinning the root and following the chain makes rotation a
    local operation for the rotating organization.

    Verification is fully offline: each rotation statement is signed by the outgoing
    key, whose public key is embedded in its own DID, so no resolver or network call is
    involved (R3).

    Fails closed. An unverifiable chain, a chain that does not begin at `root_did`, or
    an issuer absent from it all return ``None``, which the enforcement path treats as
    an untrusted issuer.

    The history must be **sealed** by its current key. ``authorize_issuer`` consults the
    repudiations and the sealed expiry, and both are unauthenticated - strippable - on an
    unsealed history, so it refuses one outright. A repudiated issuer is refused even
    though it appears in the chain; a lapsed seal is refused even though it is authentic.

    KNOWN LIMIT - this does not recover from compromise of the ROOT key. Whoever holds a
    key can endorse a successor, so an attacker with the root can build a rival chain
    from the same root that is internally valid, and a relying party pinned to that root
    cannot adjudicate between the two. Repudiation withdraws a key the organization still
    controls. See Docs/anchor-rotation-and-compromise.md.
    """

    def resolve(credential: "ac.CapabilityCredential") -> "Optional[ac.TrustAnchor]":
        try:
            # Verifies the whole chain from the pinned root AND that the issuer is one
            # of the keys it endorses; returns a verify-only anchor for that issuer.
            return history.authorize_issuer(root_did, credential.issuer)
        except Exception:
            return None

    return resolve


# -- Shared verifier context ---------------------------------------------------


class PolicyContext:
    """Common policy configuration and the shared steps every verifier runs after
    it has a presentation: anchor resolution, the argument-binding requirement,
    revocation, and audit / ADR emission.

    Transport layers (`IdentityEnforcer`, `A2AVerifier`) subclass this, call
    `super().__init__(...)` with the common options, and orchestrate the
    transport-specific bits (obtaining the presentation, the verify call).
    """

    def __init__(
        self,
        anchor: "Optional[ac.TrustAnchor]" = None,
        *,
        anchor_for: Optional[AnchorResolver] = None,
        config: Optional[PolicyConfig] = None,
    ):
        if anchor is None and anchor_for is None:
            raise ValueError(
                "provide either `anchor` (single issuer) or `anchor_for` (multi-issuer)"
            )
        cfg = config or PolicyConfig()
        self._config = cfg
        self._anchor = anchor
        self._anchor_for = anchor_for
        self._max_age = int(cfg.max_age_secs)
        # Revocation has to be STATED, in one direction or the other. There is no safe
        # default to fall back on the way `consumed_approvals` has one, and the failure
        # of the old `None`-means-off behaviour was total and silent: every revoked
        # credential verified, on a config advertised as a secure baseline. Test with
        # `is False` rather than truthiness so a caller's callable object that happens
        # to be falsy is not read as the opt-out.
        if cfg.revocation_check is None:
            raise ValueError(
                "PolicyConfig.revocation_check must be set: supply a check (see "
                "`revocation_check_from_list`), or pass `revocation_check=False` to "
                "declare that this verifier deliberately performs no revocation "
                "checking. It has no default because a revocation source cannot be "
                "invented, and silently having none accepts every revoked credential."
            )
        self._revocation_check = None if cfg.revocation_check is False else cfg.revocation_check
        self._revocation_fail_open = cfg.fail_open_on_revocation_error
        self._require_arg_binding = cfg.require_argument_binding
        self._policy_hook = cfg.policy_hook
        self._policy_fail_open = cfg.fail_open_on_policy_error
        self._usage_meter = cfg.usage_meter
        self._usage_fail_open = cfg.fail_open_on_usage_error
        self._approval_policy = cfg.approval_policy
        self._approval_client = cfg.approval_client
        self._approval_timeout = int(cfg.approval_timeout_secs)
        self._approval_poll_interval = float(cfg.approval_poll_interval_secs)
        self._approval_fail_open = cfg.fail_open_on_approval_error
        self._audit = cfg.audit
        self._audit_denied = cfg.audit_denied
        self._adr_sink = cfg.adr_sink
        self._adr_stream = cfg.adr_stream
        self._canon = cfg.canonicalize_args
        self._canon_profile = cfg.canonicalization_profile
        self._require_canon_profile = cfg.require_canonicalization_profile
        self._max_age_by_autonomy = dict(cfg.max_age_by_autonomy or {})

    # -- Shared deny/resolve steps (each returns a deny Decision, or None) ------

    def _max_age_for(self, credential) -> int:
        """The freshness bound for this credential's consequence class.

        Clamped to the global `max_age_secs`, so the map can only tighten. A
        per-class override that could *extend* the bound would let the least
        careful entry in a config set the policy for everything under it."""
        if not self._max_age_by_autonomy:
            return self._max_age
        try:
            level = credential.claims().autonomy_level
        except Exception:  # noqa: BLE001 - never fail a decision over a freshness lookup
            return self._max_age
        return min(self._max_age, int(self._max_age_by_autonomy.get(level, self._max_age)))

    def _deny_if_canon_mismatch(
        self, presentation, ctx_id, tool, args_str, declared
    ) -> Optional[Decision]:
        """Refuse a holder whose canonicalization profile is not ours, BEFORE the
        binding check would report it as a possession failure (-02 §1.3).

        `declared` is holder-supplied and unauthenticated. That is sound here
        because both paths refuse: the profile can only change *which* refusal is
        reported, never whether the call is admitted. What it buys is a diagnosis -
        an operator can tell an integration defect from an attack instead of
        reading `possession_failed` for both."""
        token = getattr(presentation, "token", None)
        credential = getattr(presentation, "credential", None)

        # An unbound presentation computed no binding string, so there is no profile to
        # disagree about and demanding one is ceremony. It also keeps the two knobs
        # orthogonal: refusing unbound presentations is `require_argument_binding`'s job,
        # and this one must not quietly start doing it as well.
        if not getattr(presentation, "is_action_bound", False):
            return None

        if declared is None:
            if not self._require_canon_profile:
                return None
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_CANON_PROFILE,
                         "no canonicalization profile declared; this verifier computes "
                         f"bindings under {self._canon_profile!r}", tool),
                token=token, credential=credential, signal="signature_invalid",
            )
        if declared != self._canon_profile:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_CANON_PROFILE,
                         f"holder canonicalized under {declared!r}, this verifier under "
                         f"{self._canon_profile!r} - the exact-action binding was computed "
                         "over two different representations", tool),
                token=token, credential=credential, signal="signature_invalid",
            )
        return None

    def _initial_args_str(self, arguments) -> str:
        """The audit string to use *before* the binding string has been settled.

        Under :data:`CANON_PROFILE_OCTETS` the verifier must not canonicalize at all -
        the binding string is the holder's, and arrives moments later. Canonicalizing
        here anyway would be wasted work on the authorization path, would warn about
        precision hazards that this profile does not have, and worst of all would let a
        value the octets profile represents perfectly well but JCS cannot raise straight
        out of a method documented never to raise for an authorization failure.
        """
        if self._canon_profile == CANON_PROFILE_OCTETS:
            return ""
        return self._canon(arguments)

    def _resolve_bound_octets(
        self, presentation, ctx_id, tool, fallback_args_str, arguments, carried
    ):
        """Settle the binding string under :data:`CANON_PROFILE_OCTETS`.

        Returns ``(denial_or_None, args_str, signed_arguments)``. Under any other profile
        this is a no-op: `args_str` stays whatever the configured canonicalizer produced
        and `signed_arguments` is None.

        Under the octets profile the verifier does not canonicalize at all: the string
        used for the binding is the one the **holder** signed and carried, so the proof
        is checked over exactly those bytes. The delivered arguments are then held to it
        by :func:`agentcreds_runtime.octets.semantic_eq`. Both checks must pass -
        altering the delivered arguments fails the comparison, altering the carried
        octets fails the proof - and neither can be traded for the other.

        The comparison runs *before* the signature check. Both refuse, so the ordering
        is diagnostic rather than a security property; doing the cheap parse first keeps
        an unauthenticated caller from spending a signature verification per request.
        """
        if self._canon_profile != CANON_PROFILE_OCTETS:
            return None, fallback_args_str, None

        token = getattr(presentation, "token", None)
        credential = getattr(presentation, "credential", None)
        try:
            bound = _octets.parse_bound_args(carried)
        except _octets.BoundArgsError as exc:
            return self._finish(
                ctx_id, tool, fallback_args_str,
                Decision(False, CODE_BOUND_ARGS,
                         f"{CANON_PROFILE_OCTETS} is in force but the carried arguments "
                         f"are unusable: {exc}", tool),
                token=token, credential=credential, signal="signature_invalid",
            ), fallback_args_str, None

        if not _octets.semantic_eq(bound, arguments):
            return self._finish(
                ctx_id, tool, carried,
                Decision(False, CODE_ARGS_MISMATCH,
                         "the arguments delivered by the transport are not the ones the "
                         "holder signed", tool),
                token=token, credential=credential, signal="signature_invalid",
            ), carried, None

        # The holder's own bytes become the binding string, so nothing is re-serialized.
        # `bound` rides along to the allow decision: it is the only object in this flow
        # that is identical to what was signed rather than merely equivalent to it.
        return None, carried, bound

    def _deny_if_unbound(self, presentation, ctx_id, tool, args_str) -> Optional[Decision]:
        if self._require_arg_binding and not presentation.is_action_bound:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_UNBOUND,
                         "request binding required but the presentation is unbound", tool),
                token=presentation.token, credential=presentation.credential, signal="other",
            )
        return None

    def _resolve_anchor(self, presentation, ctx_id, tool, args_str):
        """Return (anchor, None) on success or (None, deny_decision) when the
        credential's issuer is not trusted."""
        if self._anchor_for is None:
            return self._anchor, None
        try:
            anchor = self._anchor_for(presentation.credential)
        except Exception:  # noqa: BLE001 - a resolver failure is an untrusted issuer
            anchor = None
        if anchor is None:
            return None, self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_UNTRUSTED_ISSUER,
                         "no trusted anchor for the credential issuer", tool),
                token=presentation.token, credential=presentation.credential,
                signal="signature_invalid",
            )
        return anchor, None

    def _deny_if_revoked(self, presentation, ctx_id, tool, args_str) -> Optional[Decision]:
        if self._revocation_check is None:
            return None
        try:
            revoked = self._revocation_check(presentation.credential)
        except Exception as exc:  # noqa: BLE001 - the check's own failure
            if not self._revocation_fail_open:
                return self._finish(
                    ctx_id, tool, args_str,
                    Decision(False, CODE_REVOKED,
                             f"revocation status unavailable: {exc}", tool),
                    token=presentation.token, credential=presentation.credential,
                    signal="revoked",
                )
            # Fail open: availability over strictness. This accepts a credential
            # whose revocation status is *unknown*, so a revoked credential can slip
            # through if the status endpoint is down (or is being DoS'd). Surface it
            # loudly so operators can alert on it.
            _log.warning(
                "revocation check failed; FAILING OPEN - credential accepted despite "
                "unknown revocation status (a revoked credential may be honoured): %s",
                exc,
            )
            revoked = False
        if revoked:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_REVOKED, "credential has been revoked", tool),
                token=presentation.token, credential=presentation.credential, signal="revoked",
            )
        return None

    def _deny_if_policy(
        self, ctx_id, tool, args_str, *, principal, arguments, resource, chain, token,
        credential=None,
    ) -> Optional[Decision]:
        """Final, contextual gate: run the configured policy hook over the verified
        call. Fail **closed** by default if the hook raises (a policy engine that
        can't decide must not admit the call) - mirrors the revocation gate."""
        if self._policy_hook is None:
            return None
        try:
            reason = self._policy_hook(
                PolicyInput(
                    principal=principal, tool=tool, arguments=arguments,
                    args=args_str, resource=resource, chain=chain, token=token,
                )
            )
        except Exception as exc:  # noqa: BLE001 - the hook's own failure
            if not self._policy_fail_open:
                return self._finish(
                    ctx_id, tool, args_str,
                    Decision(False, CODE_POLICY, f"policy evaluation error: {exc}", tool, chain),
                    token=token, credential=credential, signal="action_denied",
                )
            _log.warning(
                "policy hook failed; FAILING OPEN - call allowed despite policy error: %s", exc
            )
            reason = None
        if reason:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_POLICY, str(reason), tool, chain),
                token=token, credential=credential, signal="action_denied",
            )
        return None

    def _deny_if_usage(
        self, ctx_id, tool, args_str, *, principal, arguments, resource, chain, token,
        credential=None,
    ) -> Optional[Decision]:
        """Stateful usage gate (rate/quota + spend), evaluated last - after authority,
        revocation, and the policy hook - so its counters only move for fully authorized
        calls. Fails CLOSED by default if the backing store errors."""
        if self._usage_meter is None:
            return None
        try:
            reason = self._usage_meter(
                PolicyInput(
                    principal=principal, tool=tool, arguments=arguments,
                    args=args_str, resource=resource, chain=chain, token=token,
                )
            )
        except Exception as exc:  # noqa: BLE001 - the meter / store's own failure
            if not self._usage_fail_open:
                return self._finish(
                    ctx_id, tool, args_str,
                    Decision(False, CODE_QUOTA, f"usage metering error: {exc}", tool, chain),
                    token=token, credential=credential, signal="action_denied",
                )
            _log.warning(
                "usage meter failed; FAILING OPEN - call allowed despite metering error: %s", exc
            )
            reason = None
        if reason:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_QUOTA, str(reason), tool, chain),
                token=token, credential=credential, signal="action_denied",
            )
        return None

    def _commit_reliance(self, approval_id: str, not_after: int) -> bool:
        """Record one-time reliance on `approval_id` (R10). For the TTL-based stores the
        id is remembered until `not_after` - the evidence's own expiry - so it is never
        forgotten while the evidence is still verifiable; the one-time guarantee no longer
        depends on the store's TTL being set to the evidence lifetime. Returns False if the
        id was already relied upon. A no-op (True) when no store is configured."""
        store = getattr(self, "_consumed", None)
        if store is None:
            return True
        from .gates import ConsumedApprovalsStore  # lazy: avoid an import cycle

        if isinstance(store, ConsumedApprovalsStore):
            return store.try_consume(approval_id, not_after=not_after)
        # A store that doesn't take `not_after` (e.g. the core `agentcreds.ConsumedApprovals`,
        # which never forgets) - the TTL invariant doesn't apply to it.
        return store.try_consume(approval_id)

    def _hold_for_approval(
        self, ctx_id, tool, args_str, *, principal, arguments, resource, chain, token, anchor,
        credential=None,
    ) -> Optional[Decision]:
        """Human-in-the-loop step-up (Model A): if the approval policy flags this verified
        call, register a pending approval bound to the exact action and **block** until an
        operator approves (-> allow) or denies / it times out (-> deny). Runs last, so only
        fully authorized calls are ever escalated. Fails CLOSED by default."""
        if self._approval_policy is None or self._approval_client is None:
            return None
        # Lazy import avoids a policy<->approval import cycle.
        from .approval import ApprovalDenied, ApprovalRequest, new_approval_id

        def deny(reason: str) -> Decision:
            return self._finish(
                ctx_id, tool, args_str,
                Decision(False, CODE_APPROVAL, reason, tool, chain),
                token=token, credential=credential, signal="action_denied",
            )

        pin = PolicyInput(
            principal=principal, tool=tool, arguments=arguments,
            args=args_str, resource=resource, chain=chain, token=token,
        )
        try:
            needs_approval = self._approval_policy(pin)
        except Exception as exc:  # noqa: BLE001 - undecidable -> fail closed
            return None if self._approval_fail_open else deny(f"approval policy error: {exc}")
        if not needs_approval:
            return None

        # The approval is bound to this exact action (incl. the on-behalf-of principal)
        # and verified against the org anchor - the same ApprovalEvidence a carried gate
        # uses. Poll and carried flows now share one format and one verification path.
        action = ac.Action(tool, args_str, resource=resource, acting_for=principal)
        approval_id = new_approval_id()
        now = int(time.time())
        try:
            self._approval_client.request(
                ApprovalRequest(approval_id, tool, principal, resource, args_str)
            )
            deadline = time.monotonic() + self._approval_timeout
            while True:
                evidence = self._approval_client.poll(approval_id)
                if evidence is not None:
                    try:
                        evidence.verify(action, anchor, now)
                    except Exception as exc:  # noqa: BLE001 - bad/forged/expired evidence
                        return deny(f"approval evidence invalid: {exc}")
                    if not self._commit_reliance(evidence.approval_id, int(evidence.expires_at)):
                        return deny("approval evidence already relied upon (one-time)")
                    return None  # valid evidence -> allow
                if time.monotonic() >= deadline:
                    return deny("approval request timed out")
                time.sleep(self._approval_poll_interval)
        except ApprovalDenied as exc:
            return deny(f"denied by operator: {exc}")
        except Exception as exc:  # noqa: BLE001 - the client's own failure
            if self._approval_fail_open:
                _log.warning("approval client failed; FAILING OPEN - call allowed: %s", exc)
                return None
            return deny(f"approval unavailable: {exc}")

    # -- Audit + ADR emission --------------------------------------------------

    def _finish(
        self, ctx_id, tool, args_str, decision: Decision,
        *, token=None, signal=None, credential=None, evaluation=None, admission=None,
    ) -> Decision:
        if self._audit is not None and (decision.allowed or self._audit_denied):
            self._audit(
                AuditRecord(ctx_id, tool, args_str, decision.allowed, decision.code, decision.chain)
            )
        record_id = self._emit_adr(
            decision, tool, token, signal, credential, evaluation, admission
        )
        # Hand the record id back to the caller so the *effect* of this decision
        # can be logged against it. Without it a decision and the tool call it
        # permitted join only on `vc_id`, which every call under that credential
        # shares - so "which decision authorized this action" has no answer.
        return replace(decision, record_id=record_id) if record_id else decision

    def _emit_adr(
        self, decision: Decision, tool, token, signal, credential=None,
        evaluation=None, admission=None,
    ) -> "Optional[str]":
        """Emit the ADR and return its record id, or None if nothing is recording."""
        if self._adr_stream is None and self._adr_sink is None:
            return None
        if token is not None:
            adr = ac.AuthzDecision.from_token(
                "presentation", token, action=tool,
                allow=decision.allowed,
                signal=None if decision.allowed else (signal or "other"),
                reason=decision.reason,
            )
        else:
            adr = ac.AuthzDecision.deny("presentation", "", signal or "other", decision.reason or "")
        # Who answers, and on what basis. Both are claims on the CREDENTIAL, which
        # the token does not carry - so a record built from the token alone leaves
        # them empty, and answering "who is accountable for this action" falls back
        # to a join the field was added to remove. The verifier holds the
        # credential here, so it costs nothing to say.
        if credential is not None:
            try:
                claims = credential.claims()
                adr = adr.with_accountability(
                    claims.accountable_party,
                    claims.accountability_source,
                    # Which revision of the ownership record named that party, and a
                    # commitment to it. Without the version the party is resolved
                    # against whatever the org chart says whenever someone reads the
                    # log - which is not the org chart that was current when the
                    # credential was issued.
                    claims.party_version,
                    claims.party_commitment,
                )
            except Exception:  # noqa: BLE001 - never fail a decision over its own audit record
                pass
        # R10 evaluation and admission, recorded separately. A single verdict field
        # reports "the evidence was bad" and "the evidence was good and already
        # spent" identically - and only the second is a replay against a valid human
        # approval. Both stay None when no execution-time gate applied.
        if evaluation is not None or admission is not None:
            adr = adr.with_verdicts(evaluation, admission)
        if self._adr_stream is not None:
            adr = self._adr_stream.record(adr)
        if self._adr_sink is not None:
            self._adr_sink(adr)
        return adr.id
