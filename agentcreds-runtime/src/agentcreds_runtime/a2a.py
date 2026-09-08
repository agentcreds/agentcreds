"""Agent-to-agent (A2A) identity verification - no MCP server.

When agent A hands a task directly to agent B, A attaches a self-contained
identity header (``AgentCreds-A2A/1.<base64url>``) and B verifies it **offline**.
Unlike the interactive MCP path, A2A is one-shot: the *sender* mints the
proof-of-possession challenge with `audience` set to the receiver, so there is no
session and no challenge to store.

`A2AVerifier` is the receiver-side counterpart to `IdentityEnforcer`: it runs the
same shared policy (revocation, multi-issuer anchor resolution, required argument
binding, audit/ADR) on top of the A2A presentation's audience + rooted + PoP
check. `make_a2a_header` is the sender-side helper.

On-behalf-of over A2A: because there is no verified session to establish *who the
human is*, the human principal must travel with the message and be independently
verifiable by the receiver. `A2AVerifier.authorize_obo` validates a principal
token (e.g. an OIDC ID token) via a `principal_resolver` to derive the
`acting_for`, restoring the confused-deputy protection.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Callable, Mapping, Optional

import agentcreds as ac

from .errors import (
    AccessDenied,
    ChainHop,
    Decision,
    CODE_MALFORMED,
    CODE_PRINCIPAL,
    CODE_REPLAY,
)
from .policy import (
    AnchorResolver,
    PolicyConfig,
    PolicyContext,
    adr_signal_for,
    classify_exception,
)
from .replay import InMemoryReplayGuard, ReplayGuard

# A principal resolver: given a principal token (e.g. an OIDC ID token), return
# the verified human DID to use as `acting_for`, or None if it does not validate.
PrincipalResolver = Callable[[str], Optional[str]]

#: Header name carrying the capability presentation (its value is produced by
#: :func:`make_a2a_header` / ``Presentation.to_a2a_header``).
A2A_HEADER_NAME = "AgentCreds-A2A"
#: Header name carrying the on-behalf-of principal token (the human's verifiable
#: identity), produced by :func:`make_a2a_principal_header`.
A2A_PRINCIPAL_HEADER_NAME = "AgentCreds-A2A-Principal"
_A2A_PRINCIPAL_SCHEME = "AgentCreds-A2A-Principal/1."
#: Header name carrying the holder's literal serialized arguments under
#: `agentcreds-octets-v1` - the bytes it signed. Base64url like the principal header,
#: so arbitrary argument text cannot inject header syntax. Absent under every other
#: profile, which reconstructs the binding string by canonicalizing instead.
A2A_BOUND_ARGS_HEADER_NAME = "AgentCreds-A2A-Bound-Args"
#: Header name by which a sender declares the canonicalization profile it computed the
#: binding under. The MCP transport has carried this since -02 §1.3; A2A did not, so a
#: profile disagreement over A2A surfaced as `possession_failed` with no diagnosis.
A2A_CANON_PROFILE_HEADER_NAME = "AgentCreds-A2A-Canon-Profile"


def make_a2a_principal_header(principal_token: str) -> str:
    """Wrap a human principal token (e.g. an OIDC ID token) as the on-behalf-of
    header value: ``AgentCreds-A2A-Principal/1.<base64url(token)>``.

    Sent alongside the capability header (:func:`make_a2a_header`) so the receiver
    can validate *who the human is* independently of what the sender claims.
    """
    body = base64.urlsafe_b64encode(principal_token.encode("utf-8")).rstrip(b"=").decode()
    return f"{_A2A_PRINCIPAL_SCHEME}{body}"


def parse_a2a_principal_header(value: str) -> str:
    """Decode an ``AgentCreds-A2A-Principal/1....`` header back to the principal token.

    # Raises
    ValueError if the scheme prefix is missing or the body is not valid base64url.
    """
    if not value.startswith(_A2A_PRINCIPAL_SCHEME):
        raise ValueError(f"missing '{_A2A_PRINCIPAL_SCHEME}' scheme prefix")
    body = value[len(_A2A_PRINCIPAL_SCHEME):]
    padded = body + "=" * (-len(body) % 4)
    return base64.urlsafe_b64decode(padded.encode()).decode("utf-8")


def make_a2a_bound_args_header(bound_arguments: str) -> str:
    """Wrap the holder's serialized arguments as a base64url header value."""
    return base64.urlsafe_b64encode(bound_arguments.encode("utf-8")).rstrip(b"=").decode()


def parse_a2a_bound_args_header(value: str) -> str:
    """Decode an ``AgentCreds-A2A-Bound-Args`` header back to the serialized arguments.

    # Raises
    ValueError if the body is not valid base64url or not UTF-8.
    """
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode()).decode("utf-8")


def make_a2a_header(
    token: "ac.DelegationToken",
    credential: "ac.CapabilityCredential",
    leaf_agent: "ac.AgentIdentity",
    *,
    audience: str,
    action: "Optional[ac.Action]" = None,
) -> str:
    """Sender side: mint an A2A identity header bound to `audience` (the receiver).

    Pass `action` (with the same tool/canonical-parameters/resource the receiver
    will see) to bind the proof to this exact request, so a captured header cannot
    be reused for different arguments.
    """
    challenge = ac.PopChallenge(audience)
    if action is not None:
        challenge = challenge.with_request_binding(action.request_binding())
    presentation = ac.Presentation.create(token, credential, challenge, leaf_agent)
    return presentation.to_a2a_header()


def make_a2a_envelope(
    token: "ac.DelegationToken",
    credential: "ac.CapabilityCredential",
    leaf_agent: "ac.AgentIdentity",
    *,
    audience: str,
    action: "Optional[ac.Action]" = None,
    principal_token: "Optional[str]" = None,
    bound_arguments: "Optional[str]" = None,
    canonicalization_profile: "Optional[str]" = None,
) -> "dict[str, str]":
    """Build the A2A wire envelope as a header-name -> value mapping, ready to merge
    into the outgoing request/task headers.

    Always contains ``AgentCreds-A2A`` (the capability). When `principal_token` is
    given (on-behalf-of), it also contains ``AgentCreds-A2A-Principal`` carrying the
    human's verifiable identity. When `bound_arguments` is given (the
    `agentcreds-octets-v1` profile), it also contains ``AgentCreds-A2A-Bound-Args``
    carrying the exact bytes the holder signed. The receiver passes the headers
    straight to :meth:`A2AVerifier.authorize_envelope`.
    """
    envelope = {
        A2A_HEADER_NAME: make_a2a_header(
            token, credential, leaf_agent, audience=audience, action=action
        )
    }
    if canonicalization_profile is not None:
        envelope[A2A_CANON_PROFILE_HEADER_NAME] = canonicalization_profile
    if bound_arguments is not None:
        envelope[A2A_BOUND_ARGS_HEADER_NAME] = make_a2a_bound_args_header(bound_arguments)
    if principal_token is not None:
        envelope[A2A_PRINCIPAL_HEADER_NAME] = make_a2a_principal_header(principal_token)
    return envelope


def principal_resolver_from_oidc(
    provider: "ac.OidcProvider", *, expected_agent_did: Optional[str] = None
) -> PrincipalResolver:
    """Build a :data:`PrincipalResolver` that validates an OIDC ID token (or RFC
    8693 OBO token) against `provider` and returns the human's DID.

    Pass `expected_agent_did` to require the token's `act` actor (if present) to be
    the sending agent. Returns None on any validation failure.
    """

    def resolve(principal_token: str) -> Optional[str]:
        try:
            human = provider.validate_id_token(principal_token, expected_agent_did)
        except ac.AgentCredsError:
            return None
        return human.human_identity().did

    return resolve


class A2AVerifier(PolicyContext):
    """Receiver-side verifier for A2A identity headers.

    Parameters
    ----------
    audience:
        This receiver's identity (e.g. the task URI or the receiving agent's DID).
        An accepted header's embedded audience must equal this, so a header minted
        for another receiver cannot be replayed here. Required.
    anchor / anchor_for:
        The single trust anchor whose credentials this receiver accepts, or an
        `AnchorResolver` for multiple issuers. Exactly one is required.
    config:
        A :class:`~agentcreds_runtime.policy.PolicyConfig` with the shared policy
        knobs (freshness, revocation, policy / usage / approval gates and their
        fail-open posture, argument binding, audit / ADR wiring). Keep
        `max_age_secs` short: within it a header can be replayed unless a
        `replay_guard` is configured. Defaults to the safe `PolicyConfig()`.
    principal_resolver:
        For on-behalf-of: validates a principal token into a human DID (see
        :meth:`authorize_obo` and :func:`principal_resolver_from_oidc`).
    replay_guard / enable_replay_protection:
        Makes each header **single-use**, closing the residual same-request replay
        window inherent to callback-free A2A. **On by default** with an in-process
        `InMemoryReplayGuard`. For more than one receiver replica, pass a shared
        `RedisReplayGuard` (so a replay is caught across replicas). Set
        `enable_replay_protection=False` to turn it off (e.g. if you dedupe
        upstream). A custom `replay_guard` always wins.
    """

    def __init__(
        self,
        *,
        audience: str,
        anchor: "Optional[ac.TrustAnchor]" = None,
        anchor_for: Optional[AnchorResolver] = None,
        config: Optional[PolicyConfig] = None,
        principal_resolver: Optional[PrincipalResolver] = None,
        replay_guard: Optional[ReplayGuard] = None,
        enable_replay_protection: bool = True,
    ):
        super().__init__(anchor, anchor_for=anchor_for, config=config)
        if not audience:
            raise ValueError("A2AVerifier requires an `audience` (this receiver's identity)")
        self._audience = audience
        self._principal_resolver = principal_resolver
        # Single-use protection is on by default (A2A senders mint a fresh
        # challenge per message, so legitimate headers are always distinct).
        if replay_guard is not None:
            self._replay_guard = replay_guard
        elif enable_replay_protection:
            self._replay_guard = InMemoryReplayGuard(ttl_secs=max(self._max_age + 60, 120))
        else:
            self._replay_guard = None

    def authorize(
        self,
        header: str,
        tool: str,
        arguments: object,
        *,
        resource: Optional[str] = None,
        acting_for: Optional[str] = None,
        bound_arguments: Optional[str] = None,
        canonicalization_profile: Optional[str] = None,
    ) -> Decision:
        """Verify an A2A identity header for one task/tool. Returns a `Decision`;
        never raises for an authorization failure.

        `acting_for` (the verified human DID) is supplied by the caller for
        on-behalf-of tokens - use :meth:`authorize_obo` to derive it from a
        principal token instead. `resource` is held to the token's resource scope.

        `bound_arguments` is the holder's literal serialized arguments, required only
        under `agentcreds-octets-v1`; every other profile ignores it.
        """
        args_str = self._initial_args_str(arguments)

        try:
            presentation = ac.Presentation.from_a2a_header(header)
        except Exception as exc:  # malformed header / wrong bytes
            return self._finish(
                self._audience, tool, args_str,
                Decision(False, CODE_MALFORMED, f"could not parse A2A header: {exc}", tool),
                signal="signature_invalid",
            )

        # Same order as the MCP path: a binding computed under a different profile is a
        # profile failure, not a possession failure, and must not be reported as one.
        if (denied := self._deny_if_canon_mismatch(
            presentation, self._audience, tool, args_str, canonicalization_profile,
        )) is not None:
            return denied

        # Under `agentcreds-octets-v1` the binding string becomes the bytes the holder
        # signed and carried, so nothing below re-serializes the arguments.
        denied, args_str, signed_arguments = self._resolve_bound_octets(
            presentation, self._audience, tool, args_str, arguments, bound_arguments,
        )
        if denied is not None:
            return denied

        if (denied := self._deny_if_unbound(presentation, self._audience, tool, args_str)) is not None:
            return denied

        anchor, denied = self._resolve_anchor(presentation, self._audience, tool, args_str)
        if denied is not None:
            return denied

        action = ac.Action(tool, args_str, resource=resource, acting_for=acting_for)
        try:
            # verify_a2a additionally requires the embedded audience == self._audience.
            presentation.verify_a2a(action, anchor, self._audience, self._max_age)
        except ac.AgentCredsError as exc:
            return self._finish(
                self._audience, tool, args_str,
                Decision(False, classify_exception(exc), str(exc), tool),
                token=presentation.token, credential=presentation.credential, signal=adr_signal_for(exc),
            )

        # Single-use enforcement: a verified header may be admitted only once
        # within the freshness window. Recorded only after verify, so invalid
        # headers cannot poison the guard.
        if self._replay_guard is not None:
            key = hashlib.sha256(header.encode("utf-8")).hexdigest()
            if not self._replay_guard.record_if_new(key):
                return self._finish(
                    self._audience, tool, args_str,
                    Decision(False, CODE_REPLAY, "this A2A header has already been used", tool),
                    token=presentation.token, credential=presentation.credential, signal="other",
                )

        if (denied := self._deny_if_revoked(presentation, self._audience, tool, args_str)) is not None:
            return denied

        chain = [
            ChainHop(e.depth, e.agent_did, list(e.tools), e.budget_usd)
            for e in presentation.token.chain().entries
        ]

        # Final contextual gate (same shared hook as the MCP path); `acting_for` is
        # the independently-verified human principal for on-behalf-of messages.
        if (denied := self._deny_if_policy(
            self._audience, tool, args_str,
            principal=acting_for, arguments=arguments, resource=resource,
            chain=chain, token=presentation.token, credential=presentation.credential,
        )) is not None:
            return denied

        # Stateful usage gate (rate/quota + spend).
        if (denied := self._deny_if_usage(
            self._audience, tool, args_str,
            principal=acting_for, arguments=arguments, resource=resource,
            chain=chain, token=presentation.token, credential=presentation.credential,
        )) is not None:
            return denied

        # Human-in-the-loop step-up - runs last; blocks until approved or denied/timeout.
        if (denied := self._hold_for_approval(
            self._audience, tool, args_str,
            principal=acting_for, arguments=arguments, resource=resource,
            chain=chain, token=presentation.token, credential=presentation.credential, anchor=anchor,
        )) is not None:
            return denied

        return self._finish(
            self._audience, tool, args_str,
            Decision(True, None, None, tool, chain, bound_arguments=signed_arguments),
            token=presentation.token, credential=presentation.credential,
        )

    def authorize_obo(
        self,
        header: str,
        principal_token: str,
        tool: str,
        arguments: object,
        *,
        resource: Optional[str] = None,
        bound_arguments: Optional[str] = None,
        canonicalization_profile: Optional[str] = None,
    ) -> Decision:
        """Verify an on-behalf-of A2A message: independently validate the human's
        `principal_token` (via the configured `principal_resolver`) to derive the
        `acting_for`, then run :meth:`authorize`. The core then enforces that the
        capability token's bound principal matches the verified human - restoring
        the confused-deputy protection that the MCP session binding provides.
        """
        if self._principal_resolver is None:
            raise ValueError("authorize_obo requires a `principal_resolver` on the verifier")
        acting_for = self._principal_resolver(principal_token)
        if acting_for is None:
            return self._finish(
                self._audience, tool, self._initial_args_str(arguments),
                Decision(False, CODE_PRINCIPAL, "could not verify the on-behalf-of principal", tool),
                signal="other",
            )
        return self.authorize(header, tool, arguments, resource=resource,
                              acting_for=acting_for, bound_arguments=bound_arguments,
                              canonicalization_profile=canonicalization_profile)

    def authorize_envelope(
        self,
        headers: "Mapping[str, str]",
        tool: str,
        arguments: object,
        *,
        resource: Optional[str] = None,
    ) -> Decision:
        """Verify a request from its A2A wire envelope (a header-name -> value
        mapping, e.g. the incoming HTTP/task headers built by
        :func:`make_a2a_envelope`).

        Reads the ``AgentCreds-A2A`` capability header and, if present, the
        ``AgentCreds-A2A-Principal`` on-behalf-of header - dispatching to
        :meth:`authorize_obo` when a principal is carried, or :meth:`authorize`
        otherwise. Header-name lookup is case-insensitive.
        """
        lookup = {k.lower(): v for k, v in headers.items()}
        capability = lookup.get(A2A_HEADER_NAME.lower())
        if capability is None:
            return self._finish(
                self._audience, tool, self._initial_args_str(arguments),
                Decision(False, CODE_MALFORMED,
                         f"envelope missing the '{A2A_HEADER_NAME}' header", tool),
                signal="signature_invalid",
            )

        bound_arguments = None
        bound_header = lookup.get(A2A_BOUND_ARGS_HEADER_NAME.lower())
        if bound_header is not None:
            try:
                bound_arguments = parse_a2a_bound_args_header(bound_header)
            except (ValueError, UnicodeDecodeError) as exc:
                return self._finish(
                    self._audience, tool, self._initial_args_str(arguments),
                    Decision(False, CODE_MALFORMED,
                             f"bad {A2A_BOUND_ARGS_HEADER_NAME} header: {exc}", tool),
                    signal="signature_invalid",
                )

        declared_profile = lookup.get(A2A_CANON_PROFILE_HEADER_NAME.lower())

        principal_header = lookup.get(A2A_PRINCIPAL_HEADER_NAME.lower())
        if principal_header is None:
            return self.authorize(capability, tool, arguments, resource=resource,
                                  bound_arguments=bound_arguments,
                                  canonicalization_profile=declared_profile)
        try:
            principal_token = parse_a2a_principal_header(principal_header)
        except ValueError as exc:
            return self._finish(
                self._audience, tool, self._initial_args_str(arguments),
                Decision(False, CODE_MALFORMED, f"bad principal header: {exc}", tool),
                signal="signature_invalid",
            )
        return self.authorize_obo(capability, principal_token, tool, arguments,
                                  resource=resource, bound_arguments=bound_arguments,
                                  canonicalization_profile=declared_profile)

    def enforce(
        self,
        header: str,
        tool: str,
        arguments: object,
        *,
        resource: Optional[str] = None,
        acting_for: Optional[str] = None,
    ):
        """Like `authorize`, but raise `AccessDenied` on a deny and return the
        verified chain on allow."""
        decision = self.authorize(header, tool, arguments, resource=resource, acting_for=acting_for)
        if decision.denied:
            raise AccessDenied(decision)
        return decision.chain
