"""Type stubs for the `agentcreds` native extension module.

Verifiable, attenuable delegation for AI agents - org-rooted and verified offline.

All operations are synchronous - there is no `async`/`await` in this API.
The underlying Rust operations are sub-millisecond.
"""

from datetime import datetime

__version__: str

def default_list_size() -> int:
    """Default OAuth Status List size (131,072 entries / 16KB bitstring)."""
    ...

# -- RFC 8785 canonicalization -------------------------------------------------
#
# Exposed so a holder built on this wheel alone can produce a correct binding string.
# The alternative is reimplementing JCS, which is the divergence the profile exists to
# remove - two independent readings of "sorted JSON" disagreed on 9 of 18 ordinary cases.

JCS_PROFILE: str
JCS_MAX_SAFE_INTEGER: int

def jcs_canonicalize(value: object) -> str:
    """The RFC 8785 canonical form of a JSON-representable value.

    Raises `ValueError` for anything JSON cannot represent (a set, a non-string key,
    NaN) rather than coercing it: a canonicalizer that guesses emits a string the other
    side cannot reproduce, which presents as tampering on an untampered request.
    """
    ...

def jcs_serialize_float(value: float) -> str:
    """ECMAScript `Number::toString`, which RFC 8785 §3.2.2.3 defers to.

    Floats only - an integer prints exactly and must not be routed through a double.
    """
    ...

def jcs_precision_hazards(value: object) -> list[tuple[str, str]]:
    """RFC 6901 pointers to integers too large to survive the JSON data model.

    Empty is the ordinary case. A non-empty result means argument binding over this
    value is weaker than it looks; carry large identifiers as strings.
    """
    ...

# -- Exceptions ----------------------------------------------------------------

class AgentCredsError(Exception): ...
class DidError(AgentCredsError): ...
class CredentialError(AgentCredsError): ...
class CredentialExpiredError(CredentialError): ...
class CredentialRevokedError(CredentialError): ...
class DelegationError(AgentCredsError): ...
class ScopeWideningError(DelegationError): ...
class TokenExpiredError(DelegationError): ...
class ActionDeniedError(DelegationError): ...
class ProofOfPossessionError(DelegationError): ...
class RevocationError(AgentCredsError): ...
class SvidValidationError(AgentCredsError): ...
class SerializationError(AgentCredsError): ...
class ValidationError(AgentCredsError): ...
class ConsentViolationError(CredentialError): ...
class PrincipalMismatchError(DelegationError): ...
class OidcValidationError(AgentCredsError): ...

# -- Identity ------------------------------------------------------------------

class PublicKey:
    @property
    def algorithm(self) -> str: ...
    @property
    def bytes(self) -> bytes: ...
    def to_multibase(self) -> str: ...

class VerificationMethod:
    @property
    def id(self) -> str: ...
    @property
    def type(self) -> str: ...
    @property
    def controller(self) -> str: ...
    @property
    def public_key_multibase(self) -> str: ...

class DidDocument:
    @property
    def id(self) -> str: ...
    @property
    def context(self) -> list[str]: ...
    @property
    def authentication(self) -> list[str]: ...
    @property
    def assertion_method(self) -> list[str]: ...
    @property
    def created(self) -> datetime: ...
    @property
    def updated(self) -> datetime: ...
    @property
    def verification_method(self) -> list[VerificationMethod]: ...
    def primary_key_multibase(self) -> str | None: ...
    def to_json(self) -> str: ...
    def to_dict(self) -> dict[str, object]: ...

class AgentIdentity:
    """An ephemeral or org-anchored agent identity (holds a private key)."""

    @staticmethod
    def create_did_key(algorithm: str | None = None) -> AgentIdentity: ...
    @staticmethod
    def create_did_web(
        host: str, path: str | None = None, algorithm: str | None = None
    ) -> AgentIdentity: ...
    @staticmethod
    def create_did_cheqd(
        network: str, unique_id: str, algorithm: str | None = None
    ) -> AgentIdentity: ...
    @staticmethod
    def create_did_indy(
        namespace: str, unique_id: str, algorithm: str | None = None
    ) -> AgentIdentity: ...
    @property
    def did(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    @property
    def public_key(self) -> PublicKey: ...
    def document(self) -> DidDocument: ...
    def fingerprint(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...
    def verify(self, message: bytes, signature: bytes) -> None: ...

class TrustAnchor:
    """An org's root of trust - issues and verifies credentials."""

    @staticmethod
    def generate() -> TrustAnchor: ...
    @staticmethod
    def create_did_key(algorithm: str | None = None) -> TrustAnchor: ...
    @staticmethod
    def from_did_key(did: str) -> TrustAnchor:
        """A **verify-only** anchor from a ``did:key`` (no private key) - e.g. the
        current key reached by following a ``KeyHistory``. Signing fails."""
        ...
    @staticmethod
    def create_did_web(
        host: str, path: str | None = None, algorithm: str | None = None
    ) -> TrustAnchor: ...
    @staticmethod
    def create_did_cheqd(
        network: str, unique_id: str, algorithm: str | None = None
    ) -> TrustAnchor: ...
    @staticmethod
    def create_did_indy(
        namespace: str, unique_id: str, algorithm: str | None = None
    ) -> TrustAnchor: ...
    @property
    def did(self) -> str: ...
    @property
    def algorithm(self) -> str: ...
    @property
    def public_key(self) -> PublicKey: ...
    def document(self) -> DidDocument: ...
    def verify_signature(self, message: bytes, signature: bytes) -> None: ...

class InMemoryResolver:
    """In-memory DID resolver for tests, local development, and wiring up
    `TrustRegistry` cross-org resolution without a network round-trip.

    Once passed to `TrustRegistry.with_in_memory_resolver()`, the resolver is
    consumed and can no longer be modified.
    """

    def __init__(self) -> None: ...
    def register(self, did: str, document: DidDocument) -> None: ...
    def register_identity(self, identity: AgentIdentity) -> None: ...

# -- Verifiable Credentials ---------------------------------------------------

class CapabilityClaims:
    def __init__(
        self,
        tools: list[str],
        max_delegation_depth: int,
        valid_for_secs: int,
        budget_usd: int | None = None,
        autonomy_level: int = 0,
        model_version: str | None = None,
        artifact_hash: str | None = None,
        authorized_by: str | None = None,
        accountable_party: str | None = None,
        on_behalf_of: HumanAuthorization | None = None,
        resources: list[str] | None = None,
        party_version: int | None = None,
        party_commitment: str | None = None,
    ) -> None: ...
    @property
    def tools(self) -> list[str]: ...
    @property
    def resources(self) -> list[str] | None:
        """Resource-namespace patterns this credential permits, or ``None`` for
        unbounded. A **capability-axis** ceiling alongside ``tools``: ``mint``
        holds a token's resource scope to it, with no principal involved.

        Use this when the bound is the org's grant. Use
        ``on_behalf_of.resource_authority`` only when the entitlement is
        genuinely established elsewhere (a human's IdP), because a principal
        obliges every relying party to independently learn and assert it."""
        ...
    @property
    def budget_usd(self) -> int | None: ...
    @property
    def max_delegation_depth(self) -> int: ...
    @property
    def valid_for_secs(self) -> int: ...
    @property
    def autonomy_level(self) -> int: ...
    @property
    def model_version(self) -> str | None: ...
    @property
    def artifact_hash(self) -> str | None: ...
    @property
    def authorized_by(self) -> str | None: ...
    @property
    def accountable_party(self) -> str | None:
        """Who answers for what this agent does. Never selectively disclosable -
        a verifier is always shown it."""
        ...
    @property
    def accountability_source(self) -> str:
        """How the accountable party was established. Travels with the party
        because in an audit they are one question."""
        ...
    @property
    def party_version(self) -> int | None:
        """Which revision of the ownership record named the accountable party.

        Without it the party is a pointer with no time coordinate, resolved
        against whatever the org chart says whenever someone reads the log.
        ``None`` means no record was configured - not version zero."""
        ...
    @property
    def party_commitment(self) -> str | None:
        """Salted commitment to that ownership record.

        Makes the resolution verifiable: produce the record, recompute, compare.
        A commitment rather than the record itself because the members are
        personal data and a credential is signed, immutable, cross-org, and
        outlives the employment."""
        ...
    @property
    def on_behalf_of(self) -> HumanAuthorization | None:
        """The human principal this credential is bound to (R5), if any."""
        ...
    @property
    def required_gates(self) -> list[Gate]:
        """The execution-time human-authorization gates this credential mandates (R10)."""
        ...
    def require_approval(self, tool: str) -> None:
        """Mandate that `tool` requires execution-time human approval (R10).

        The designation lives in the credential, so derivation can tighten it but
        never remove it - a gated credential cannot be spent ungated."""
        ...
    def validate(self) -> None: ...

class CredentialStatus:
    """An OAuth Status List entry reference for `index` within the list
    published at `registry_url`."""

    def __init__(self, registry_url: str, index: int) -> None: ...
    @property
    def id(self) -> str: ...
    @property
    def type(self) -> str: ...
    @property
    def status_purpose(self) -> str: ...
    @property
    def status_list_index(self) -> int: ...
    @property
    def status_list_credential(self) -> str: ...

class LinkedDataProof:
    @property
    def type(self) -> str: ...
    @property
    def created(self) -> datetime: ...
    @property
    def verification_method(self) -> str: ...
    @property
    def proof_purpose(self) -> str: ...
    @property
    def proof_value(self) -> str: ...
    @property
    def payload_hash(self) -> str: ...

class CapabilityCredential:
    @staticmethod
    def issue(
        anchor: TrustAnchor,
        subject_did: str,
        claims: CapabilityClaims,
        revocation: CredentialStatus | None = None,
    ) -> CapabilityCredential: ...
    @staticmethod
    def from_json(json: str) -> CapabilityCredential: ...
    def to_json(self) -> str: ...
    @property
    def id(self) -> str: ...
    @property
    def context(self) -> list[str]: ...
    @property
    def type(self) -> list[str]: ...
    @property
    def issuer(self) -> str: ...
    @property
    def issuance_date(self) -> datetime: ...
    @property
    def proof(self) -> LinkedDataProof: ...
    @property
    def credential_status(self) -> CredentialStatus | None: ...
    def subject_did(self) -> str: ...
    def claims(self) -> CapabilityClaims: ...
    def expiration_date(self) -> datetime: ...
    def is_valid(self) -> bool: ...
    def verify(self, anchor: TrustAnchor, strict_issuer: bool = True) -> None: ...

# -- Delegation ----------------------------------------------------------------

class Scope:
    """A set of permitted capabilities at one delegation hop. `budget_usd` is
    in USD-cents; `max_depth` is the maximum remaining delegation depth."""

    def __init__(
        self,
        tools: list[str],
        budget_usd: int | None = None,
        max_depth: int = 0,
        resources: list[str] = ...,
    ) -> None: ...
    @property
    def tools(self) -> list[str]: ...
    @property
    def budget_usd(self) -> int | None: ...
    @property
    def max_depth(self) -> int: ...
    @property
    def resources(self) -> list[str]:
        """The resource allow-list this scope is confined to (R6 resource axis)."""
        ...
    @property
    def gates(self) -> list[Gate]:
        """The execution-time gate designations on this scope (R10)."""
        ...
    def require_approval(self, tool: str) -> Scope:
        """Designate `tool` as requiring execution-time human approval (R10).
        Returns a new scope."""
        ...
    def with_gates(self, gates: list[Gate]) -> Scope:
        """Add execution-time gates (R10) to this scope. Returns a new scope."""
        ...
    def is_subset_of(self, parent: Scope) -> bool: ...
    def first_widening_capability(self, parent: Scope) -> str | None: ...

class Action:
    """An action an agent wants to perform - checked against a token's scope."""

    def __init__(
        self,
        tool: str,
        parameters: str,
        resource: str | None = None,
        acting_for: str | None = None,
    ) -> None: ...
    @property
    def tool(self) -> str: ...
    @property
    def parameters(self) -> str: ...
    @property
    def resource(self) -> str | None:
        """The target resource this action touches (R6 resource axis)."""
        ...
    @property
    def acting_for(self) -> str | None:
        """The on-behalf-of principal DID this action is performed for (R5)."""
        ...
    @property
    def timestamp(self) -> datetime: ...
    def request_binding(self) -> bytes:
        """A stable content binding of this action (tool, parameters, resource) -
        pass to `PopChallenge.with_request_binding` so a captured presentation
        cannot be reused for a different call."""
        ...
    def approval_binding(self) -> bytes:
        """The content binding for execution-time human-authorization evidence
        (R10): tool, arguments, target resource and on-behalf-of principal."""
        ...

class ChainEntry:
    @property
    def depth(self) -> int: ...
    @property
    def agent_did(self) -> str: ...
    @property
    def tools(self) -> list[str]: ...
    @property
    def budget_usd(self) -> int | None: ...
    @property
    def issued_at(self) -> datetime: ...
    @property
    def expires_at(self) -> datetime: ...
    @property
    def resources(self) -> list[str]:
        """The resource allow-list this hop is confined to (R6 resource axis)."""
        ...

class DelegationChain:
    """A human-readable, audit-friendly view of a delegation chain. No
    signatures or key material - safe to include in audit logs."""

    @property
    def vc_id(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    @property
    def entries(self) -> list[ChainEntry]: ...
    @property
    def principal_did(self) -> str | None:
        """The human principal the chain is bound to (on-behalf-of), if any."""
        ...

class DelegationToken:
    """A multi-hop delegation token - a chain of signed, append-only blocks.
    Each block narrows the capability scope; widening is structurally
    impossible, not merely policy-blocked."""

    @staticmethod
    def mint(
        vc: CapabilityCredential, scope: Scope, ttl_secs: int, agent: AgentIdentity
    ) -> DelegationToken: ...
    def attenuate(
        self, narrow: Scope, ttl_secs: int, agent: AgentIdentity
    ) -> DelegationToken: ...
    def verify(self, action: Action) -> None:
        """Verify chain integrity/authenticity (all block signatures, expiry,
        hash linkage, monotonic narrowing) and that ``action`` is permitted.

        This proves the chain is authentic but NOT that its root authority came
        from a trusted anchor. Use :meth:`verify_rooted` (or independently
        verify the backing credential) to establish anchor-rooted authority."""
        ...
    def verify_rooted(
        self, action: Action, vc: CapabilityCredential, anchor: TrustAnchor
    ) -> None:
        """Verify ``action`` and bind the token's root to an anchor-issued
        credential: verifies ``vc`` against ``anchor``, that the token derives
        from ``vc``, that the root was minted by the credential subject, and
        that the root scope is within the credential's claims. The complete
        check a relying party should use."""
        ...
    def verify_rooted_at(
        self,
        action: Action,
        vc: CapabilityCredential,
        anchor: TrustAnchor,
        epoch_seconds: int,
    ) -> None:
        """``verify_rooted`` evaluated **as of** ``epoch_seconds`` rather than the
        wall clock.

        One instant governs the credential's expiry, every hop's expiry and the
        Datalog time check, so the answer cannot straddle two clocks. Intended for
        audit re-verification ("was this authorized when it happened?") and for
        golden vectors that must outlive the token lifetimes the autonomy ladder
        permits.

        **Not the enforcement path** - a relying party deciding in real time calls
        ``verify_rooted``. Revocation is not covered: a historical answer also needs
        the status list as it stood then, not today's."""
        ...
    def prove_possession(
        self, challenge: PopChallenge, leaf_agent: AgentIdentity
    ) -> ProofOfPossession:
        """Produce a proof of possession for ``challenge``, signed by the token's
        leaf agent. Only the leaf agent can do this."""
        ...
    def verify_presentation(
        self,
        action: Action,
        vc: CapabilityCredential,
        anchor: TrustAnchor,
        proof: ProofOfPossession,
        expected_challenge: PopChallenge,
        max_age_secs: int,
    ) -> None:
        """The complete presentation check: anchor-rooted verification plus
        proof of possession of the leaf key for ``expected_challenge``."""
        ...
    def verify_rooted_gated(
        self,
        action: Action,
        vc: CapabilityCredential,
        anchor: TrustAnchor,
        evidence: list[ApprovalEvidence],
        recognized_kinds: list[str],
        now_unix: int,
    ) -> list[str]:
        """The complete relying-party check **including R10**: everything
        :meth:`verify_rooted` does, plus every execution-time gate designating
        ``action.tool`` must be satisfied by anchor-verified ``evidence`` bound
        to this exact action. Fails closed on a gate kind not in
        ``recognized_kinds``. Returns the approval ids relied upon - record them
        so each is used at most once."""
        ...
    def verify_rooted_gated_with_directory(
        self,
        action: Action,
        vc: CapabilityCredential,
        anchor: TrustAnchor,
        evidence: list[ApprovalEvidence],
        directory: ApproverDirectory,
        recognized_kinds: list[str],
        now_unix: int,
    ) -> list[str]:
        """Like :meth:`verify_rooted_gated`, but also accepts the hybrid
        ``approval-key`` gate: evidence signed by an approver's own key, verified
        against the org-anchor-signed ``directory``."""
        ...
    def gates(self) -> list[Gate]:
        """The execution-time gate designations carried by this token (R10)."""
        ...
    def required_gates(self, action: Action) -> list[Gate]:
        """The gates designating ``action.tool`` - the human-authorization
        requirements this call must satisfy."""
        ...
    def root_resources(self) -> list[str]:
        """The root resource allow-list this token was minted with (R6)."""
        ...
    @property
    def principal_did(self) -> str | None:
        """The human principal DID this token is bound to (on-behalf-of), or
        None. Invariant along the chain: an intermediary cannot alter it (R5)."""
        ...
    def to_cbor(self) -> bytes: ...
    @staticmethod
    def from_cbor(data: bytes) -> DelegationToken: ...
    @property
    def vc_id(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    def depth(self) -> int: ...
    def chain(self) -> DelegationChain: ...

# -- Proof of Possession / Presentation ---------------------------------------

class PopChallenge:
    """A verifier-issued challenge. Generate one per presentation (or per
    session) and check the returned ``ProofOfPossession`` against it."""

    def __init__(self, audience: str | None = None) -> None: ...
    @property
    def nonce(self) -> bytes: ...
    @property
    def audience(self) -> str | None: ...
    @property
    def issued_at(self) -> datetime: ...
    def with_request_binding(self, binding: bytes) -> PopChallenge:
        """Return a copy of this challenge bound to a specific request (pass
        :meth:`Action.request_binding`). The holder signs the bound challenge, so
        the resulting presentation is valid only for that exact action - a
        captured presentation cannot be replayed with different arguments."""
        ...
    def to_cbor(self) -> bytes: ...
    @staticmethod
    def from_cbor(data: bytes) -> PopChallenge: ...

class ProofOfPossession:
    """A holder's proof that it possesses the leaf agent's private key, for one
    specific challenge and token."""

    @property
    def leaf_did(self) -> str: ...
    def verify(
        self, token: DelegationToken, challenge: PopChallenge, max_age_secs: int
    ) -> None: ...
    def to_cbor(self) -> bytes: ...
    @staticmethod
    def from_cbor(data: bytes) -> ProofOfPossession: ...

class Presentation:
    """The unit that crosses the wire when an agent presents its authority
    (e.g. attached to an MCP ``tools/call``): token + backing credential +
    proof of possession."""

    @property
    def token(self) -> DelegationToken: ...
    @property
    def credential(self) -> CapabilityCredential: ...
    @property
    def is_action_bound(self) -> bool:
        """Whether this presentation's proof is bound to a specific request. A
        verifier requiring per-request binding should reject presentations for
        which this is False."""
        ...
    @staticmethod
    def create(
        token: DelegationToken,
        credential: CapabilityCredential,
        challenge: PopChallenge,
        leaf_agent: AgentIdentity,
    ) -> Presentation: ...
    def verify(
        self,
        action: Action,
        anchor: TrustAnchor,
        challenge: PopChallenge,
        max_age_secs: int,
    ) -> None: ...
    def verify_at(
        self,
        action: Action,
        anchor: TrustAnchor,
        challenge: PopChallenge,
        max_age_secs: int,
        epoch_seconds: int,
    ) -> None:
        """``verify`` evaluated **as of** ``epoch_seconds`` rather than the wall
        clock. One instant governs the credential, every hop, the Datalog time check
        and the proof's own freshness window, so a presentation cannot be judged half
        against one clock and half against another.

        **Not the enforcement path** - a relying party deciding in real time calls
        ``verify``. This exists for audit re-verification and for golden vectors that
        must outlive the one-hour token lifetime the autonomy ladder permits."""
        ...
    def to_cbor(self) -> bytes: ...
    @staticmethod
    def from_cbor(data: bytes) -> Presentation: ...
    def to_a2a_header(self) -> str:
        """Encode this presentation as an A2A identity header string
        (``AgentCreds-A2A/1.<base64url>``), suitable for an A2A task header."""
        ...
    @staticmethod
    def from_a2a_header(header: str) -> Presentation:
        """Decode an A2A identity header string back into a presentation."""
        ...
    def verify_a2a(
        self,
        action: Action,
        anchor: TrustAnchor,
        expected_audience: str,
        max_age_secs: int,
    ) -> None:
        """Verify an A2A presentation as the receiving agent: full presentation
        verification plus a requirement that the embedded challenge audience
        equals ``expected_audience`` (this verifier)."""
        ...

# -- SD-JWT Selective Disclosure -----------------------------------------------

class DisclosedCredential:
    """The result of verifying an SD-JWT presentation: the always-present
    registered claims plus exactly the claims the holder chose to disclose."""

    @property
    def issuer(self) -> str: ...
    @property
    def subject(self) -> str: ...
    @property
    def vct(self) -> str: ...
    @property
    def issued_at(self) -> str:
        """Issuance time as an RFC 3339 timestamp string."""
        ...
    @property
    def expires_at(self) -> str:
        """Expiry as an RFC 3339 timestamp string."""
        ...
    @property
    def disclosed_json(self) -> str:
        """The disclosed claims as a JSON object string (name -> value)."""
        ...

class SdJwt:
    """An SD-JWT capability credential. The issuer hands the whole compact form
    to the holder; the holder calls ``present`` to reveal a subset of claims
    while the rest stay hidden and cryptographically unrecoverable."""

    @staticmethod
    def from_capability(
        anchor: TrustAnchor,
        subject_did: str,
        claims: CapabilityClaims,
        valid_for_secs: int,
    ) -> SdJwt:
        """Issue an SD-JWT whose disclosable claims are the fields of ``claims``."""
        ...
    @staticmethod
    def parse(s: str) -> SdJwt:
        """Parse a compact SD-JWT received from an issuer."""
        ...
    def as_str(self) -> str:
        """The full compact serialization to hand to the holder."""
        ...
    def disclosable_claims(self) -> list[str]:
        """The names of the claims this SD-JWT can disclose."""
        ...
    def present(self, disclose: list[str]) -> str:
        """A presentation revealing only the named claims (plus the always-
        disclosed registered claims). Unknown names are ignored."""
        ...
    @staticmethod
    def verify_presentation(
        presentation: str, anchor: TrustAnchor
    ) -> DisclosedCredential:
        """Verify a presentation against the issuer ``anchor`` and return the
        disclosed claims. Raises on a bad signature, expiry, or a disclosure not
        covered by the signed ``_sd`` set."""
        ...

# -- Revocation ----------------------------------------------------------------

class RevocationList:
    """An OAuth Status List revocation list. One list serves an entire deployment
    environment; publish it at a stable URL."""

    def __init__(self, id: str, anchor: TrustAnchor, size: int | None = None) -> None: ...
    @staticmethod
    def from_status_list_token(token: str) -> RevocationList:
        """Parse an OAuth Status List Token (``typ: statuslist+jwt``) - the form
        published at a credential's ``credentialStatus`` URL. Use this, not
        :meth:`from_json`, when fetching a live status list. Verify against the
        issuer's anchor before trusting it."""
        ...
    def to_status_list_token(self) -> str:
        """Serialize to an OAuth Status List Token (the published form)."""
        ...
    @staticmethod
    def from_json(json: str) -> RevocationList:
        """Deserialise a published list from its JSON form. ``verify`` it against
        the issuer anchor before trusting it - e.g. a relying party fetching the
        list from ``credential.credential_status.status_list_credential``."""
        ...
    def to_json(self) -> str:
        """Serialize to JSON - the published form a relying party fetches."""
        ...
    @property
    def id(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def updated(self) -> datetime: ...
    @property
    def size(self) -> int: ...
    @property
    def encoded_list(self) -> str: ...
    @property
    def signature(self) -> str: ...
    def revoke(self, index: int, anchor: TrustAnchor) -> None: ...
    def unrevoke(self, index: int, anchor: TrustAnchor) -> None: ...
    def is_revoked(self, index: int) -> bool: ...
    def verify(self, anchor: TrustAnchor) -> None: ...
    def revocation_count(self) -> int: ...
    def fingerprint(self) -> str: ...

class RevocationRegistry:
    """Manages multiple revocation lists for different deployment environments."""

    def __init__(self) -> None: ...
    def register(self, list: RevocationList) -> None: ...
    def get(self, list_id: str) -> RevocationList | None: ...
    def revoke(self, list_id: str, index: int, anchor: TrustAnchor) -> None: ...
    def unrevoke(self, list_id: str, index: int, anchor: TrustAnchor) -> None: ...
    def is_revoked(self, list_id: str, index: int, credential_id: str) -> None: ...

# -- Trust Registry / Cross-Org Verification ---------------------------------

class TrustEntry:
    """A registered trust anchor entry. `trust_level` is one of
    `"unverified"`, `"self_asserted"`, `"verified"`, or `"authoritative"`."""

    def __init__(
        self, did: str, org_name: str, public_key: PublicKey, trust_level: str
    ) -> None: ...
    @property
    def did(self) -> str: ...
    @property
    def org_name(self) -> str: ...
    @property
    def public_key(self) -> PublicKey: ...
    @property
    def did_method(self) -> str: ...
    @property
    def trust_level(self) -> str: ...
    @property
    def registered_at(self) -> datetime: ...
    @property
    def revocation_endpoint(self) -> str | None: ...
    key_history_url: str | None
    """Where this member publishes its signed key history. ``None`` = the member does
    not rotate, so its registered DID is both root and current."""

    def verify_signature(self, message: bytes, signature: bytes) -> None: ...

class TrustRegistry:
    """In-process registry for cross-organizational trust anchor resolution
    and offline credential verification."""

    def __init__(self) -> None: ...
    @staticmethod
    def with_in_memory_resolver(resolver: InMemoryResolver) -> TrustRegistry: ...
    @property
    def minimum_trust_level(self) -> str: ...
    @minimum_trust_level.setter
    def minimum_trust_level(self, level: str) -> None: ...
    def register(self, entry: TrustEntry) -> None: ...
    def resolve(self, did: str) -> TrustEntry: ...
    def __len__(self) -> int: ...
    def is_empty(self) -> bool: ...
    def registered_dids(self) -> list[str]: ...
    def verify_credential_rotated(
        self, vc: CapabilityCredential, history: KeyHistory
    ) -> TrustEntry:
        """Verify ``vc`` where its issuer may be a **rotated** key of a registered
        member.

        Resolves the member by the root ``history`` is anchored at, applies the
        registry's minimum trust level to that ROOT entry - so rotation cannot be used
        to escape a level - then lets the verified history decide whether the issuer is
        a key that member still trusts. Enforces the seal, the expiry and any
        repudiation."""
        ...
    def verify_credential(self, vc: CapabilityCredential) -> TrustEntry: ...
    def export(self, anchor: TrustAnchor, version: int) -> "SignedTrustConfig":
        """Export the registry as a signed, versioned config sealed by ``anchor``."""
        ...
    @staticmethod
    def from_config(config: "SignedTrustConfig", anchor: TrustAnchor) -> "TrustRegistry":
        """Build a registry from a verified signed config."""
        ...
    def export_valid_until(
        self, anchor: TrustAnchor, version: int, not_after: datetime | None = None
    ) -> "SignedTrustConfig":
        """Like :meth:`export`, but seals an expiry into the signed config so a
        fail-safe consumer rejects it once stale - bounded staleness for
        distributed trust material. The expiry is inside the signed digest, so it
        cannot be extended without the anchor key. ``None`` means unbounded."""
        ...
    def import_config(self, config: "SignedTrustConfig", anchor: TrustAnchor) -> None:
        """Merge a verified config's entries into this registry (additive)."""
        ...

class SignedTrustConfig:
    """A signed, versioned snapshot of a ``TrustRegistry`` - the persistable,
    tamper-evident trust configuration."""

    @property
    def version(self) -> int: ...
    @property
    def generated_at(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    @property
    def minimum_trust_level(self) -> str: ...
    @property
    def entries(self) -> list[TrustEntry]: ...
    @property
    def not_after(self) -> str | None:
        """The sealed expiry (rfc3339), or None if the config is unbounded."""
        ...
    def verify(self, anchor: TrustAnchor) -> None:
        """Verify the config's signature against ``anchor`` (its issuer).

        Authenticity **only** - an expired config still verifies here. Relying
        parties should use :meth:`verify_current`."""
        ...
    def is_current(self) -> bool:
        """Whether the config is still inside its validity window. An unbounded
        config (``not_after is None``) is always current."""
        ...
    def verify_current(self, anchor: TrustAnchor) -> None:
        """Verify authenticity **and** freshness: the signature must verify
        against ``anchor`` and the config must not be past ``not_after``. The
        fail-safe check a relying party should run before trusting the config;
        :meth:`TrustRegistry.from_config` and ``import_config`` apply it too."""
        ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> "SignedTrustConfig": ...

# -- Human principal & execution-time authorization (WIMSE R5/R6/R10) ---------

class HumanAuthorization:
    """The principal on whose behalf an agent acts - carried inside the
    anchor-signed credential and invariant along the chain (R5).
    `scope_consented` and `resource_authority` are the second authorization
    axis (R6): an action is permitted only when the agent's conveyed authority
    AND the principal's entitlements both admit it.

    Named for the human case, which is the common one, but a principal may also
    be a workload attested by a SPIFFE trust domain - see ``kind``."""

    def __init__(
        self,
        principal_did: str,
        issuer: str,
        subject: str,
        expires_at: datetime,
        scope_consented: list[str] = ...,
        resource_authority: list[str] = ...,
        authorized_at: datetime | None = None,
        kind: str | None = None,
        entitlement_source: str | None = None,
    ) -> None: ...
    @property
    def entitlement_source(self) -> str:
        """Where ``scope_consented`` and ``resource_authority`` came from -
        ``"attested"``, ``"policy"`` or ``"asserted"``. The entitlements bound the
        agent by something established outside the grant of capability; if they are
        ``"asserted"`` they came from whoever requested issuance and bound nothing.
        Defaults to ``"asserted"``; an unrecognised value raises."""
        ...
    @property
    def kind(self) -> str:
        """``"human"`` or ``"workload"`` - which root attested this principal:
        an identity provider, or a SPIFFE trust domain. Defaults to ``"human"``;
        an unrecognised value raises rather than falling back, so an unknown
        kind is never silently reported as a human."""
        ...
    @property
    def principal_did(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def subject(self) -> str: ...
    @property
    def expires_at(self) -> datetime: ...
    @property
    def authorized_at(self) -> datetime | None: ...
    @property
    def scope_consented(self) -> list[str]: ...
    @property
    def resource_authority(self) -> list[str]: ...

class HumanIdentity:
    """A human principal's stable DID, minted from their IdP identity at
    issuance."""

    @staticmethod
    def from_idp(issuer: str, subject: str) -> HumanIdentity:
        """Mint a stable `did:web` for a human from their validated IdP identity."""
        ...
    @property
    def did(self) -> str: ...
    @property
    def issuer(self) -> str: ...
    @property
    def subject(self) -> str: ...
    def authorize(
        self,
        expires_at: datetime,
        scope_consented: list[str] = ...,
        resource_authority: list[str] = ...,
        source: str | None = None,
    ) -> HumanAuthorization:
        """Build a :class:`HumanAuthorization` for this principal, granted now.
    @staticmethod
    def from_spiffe(spiffe_id: str) -> "HumanIdentity":
        """Mint a stable ``did:web`` for a **workload** from its verified SPIFFE ID:
        ``did:web:<trust-domain>:w:<fingerprint>``. The ``:w:`` distinguishes it
        from the ``:u:`` of a human so the two cannot collide.

        The SVID must already have been verified. This does **not** make the
        workload an accountable party - a service cannot answer for an action,
        only the team that operates it can."""
        ...
    @property
    def kind(self) -> str:
        """``"human"`` or ``"workload"`` - which root attested this identity."""
        ...

        ``source`` records where the entitlements came from - ``"attested"``,
        ``"policy"`` or ``"asserted"``. Defaults to ``"asserted"``, the weakest
        reading, because a caller that does not say has established nothing."""
        ...

class VerifiedHumanPrincipal:
    """A human principal whose identity an IdP cryptographically attested."""

    @property
    def issuer(self) -> str: ...
    @property
    def subject(self) -> str: ...
    @property
    def email(self) -> str | None: ...
    @property
    def scope(self) -> list[str]: ...
    @property
    def expires_at(self) -> datetime: ...
    @property
    def acted_by(self) -> str | None:
        """The actor (`act.sub`) for an RFC 8693 on-behalf-of token, if present."""
        ...
    def human_identity(self) -> HumanIdentity:
        """Mint this principal's stable DID from its IdP identity."""
        ...

class OidcProvider:
    """An OpenID Connect provider the org trusts, used to validate human ID
    tokens. Supports RS256, ES256 and EdDSA."""

    def __init__(self, issuer: str, audience: str, leeway_secs: int = 60) -> None: ...
    def add_keys_from_jwks(self, jwks: str) -> None:
        """Import the provider's signing keys from its JWKS document."""
        ...
    def add_rsa_key(self, n: str, e: str, kid: str | None = None) -> None:
        """Add an RSA (`RS256`) signing key from JWKS `n`/`e` (base64url)."""
        ...
    def add_p256_key(self, public_key: bytes, kid: str | None = None) -> None:
        """Add a P-256 (`ES256`) signing key (SEC1 bytes)."""
        ...
    def add_ed25519_key(self, public_key: bytes, kid: str | None = None) -> None:
        """Add an Ed25519 (`EdDSA`) signing key (32 bytes)."""
        ...
    def validate_id_token(
        self,
        id_token: str,
        expected_agent_did: str | None = None,
        expected_nonce: str | None = None,
    ) -> VerifiedHumanPrincipal:
        """Validate an OIDC ID token (or RFC 8693 OBO token) and return the
        verified principal."""
        ...

class Gate:
    """An execution-time human-authorization designation carried inside the
    delegated authority (R10). Derivation may tighten it but never remove it."""

    def __init__(self, kind: str, tool: str) -> None: ...
    @staticmethod
    def approval(tool: str) -> Gate:
        """A gate requiring human approval before `tool` may execute."""
        ...
    @staticmethod
    def approval_key(tool: str) -> Gate:
        """A gate requiring **approver-key-signed** approval (hybrid R10): the
        evidence is signed by the approver's own key rather than the org anchor,
        and is verified against an :class:`ApproverDirectory`."""
        ...
    @property
    def kind(self) -> str: ...
    @property
    def tool(self) -> str: ...

class ApprovalEvidence:
    """Execution-time human-authorization evidence (R10) - an approver's
    decision, bound to one specific action (tool, arguments, target resource and
    on-behalf-of principal) and verifiable **offline**, with no synchronous
    dependency on the issuing org or an approval-orchestration service."""

    @staticmethod
    def approve(
        action: Action,
        approver: str,
        approval_id: str,
        expires_at: int,
        anchor: TrustAnchor,
    ) -> ApprovalEvidence:
        """Mint anchor-signed evidence for `action`, decided by `approver`."""
        ...
    @staticmethod
    def approve_by_key(
        action: Action,
        approver_id: str,
        approver: AgentIdentity,
        approval_id: str,
        expires_at: int,
    ) -> ApprovalEvidence:
        """Mint **approver-key-signed** evidence (hybrid R10), verified against
        an :class:`ApproverDirectory` rather than the org anchor."""
        ...
    @property
    def approval_id(self) -> str: ...
    @property
    def approver(self) -> str: ...
    @property
    def expires_at(self) -> int: ...
    def verify(self, action: Action, anchor: TrustAnchor, now_unix: int) -> None:
        """Verify offline against `anchor` for `action` at `now_unix`."""
        ...
    def verify_with_directory(
        self,
        action: Action,
        directory: ApproverDirectory,
        anchor: TrustAnchor,
        now_unix: int,
        required_role: str | None = None,
    ) -> None:
        """Verify approver-key-signed evidence against an anchor-signed
        directory, optionally requiring a role."""
        ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> ApprovalEvidence: ...

class ConsumedApprovals:
    """A relying party's record of approval evidence already relied upon (R10
    "at most once"). In-process and unbounded; a multi-replica PEP needs a shared
    store - see `agentcreds_runtime.RedisConsumedApprovals`."""

    def __init__(self) -> None: ...
    def try_consume(self, approval_id: str) -> bool:
        """Record `approval_id` as relied upon. True the first time; False on any
        re-use."""
        ...
    def contains(self, approval_id: str) -> bool: ...

class ApproverEntry:
    """One enrolled human approver (hybrid R10): a did:key signing identity,
    roles, and an optional expiry."""

    def __init__(
        self,
        approver_id: str,
        approver_did: str,
        roles: list[str] = ...,
        not_after_unix: int | None = None,
    ) -> None: ...
    @property
    def approver_id(self) -> str: ...
    @property
    def approver_did(self) -> str: ...
    @property
    def not_after_unix(self) -> int | None:
        """Per-approver expiry as unix seconds, or ``None`` if it does not expire."""
        ...
    @property
    def roles(self) -> list[str]: ...

class ApproverDirectory:
    """A versioned, **anchor-signed** directory of human approver keys (hybrid
    R10), distributed to relying parties so approver-key evidence verifies
    offline."""

    @staticmethod
    def seal(
        entries: list[ApproverEntry],
        version: int,
        anchor: TrustAnchor,
        not_after_unix: int | None = None,
    ) -> ApproverDirectory:
        """Seal (sign) a directory with the org `anchor`."""
        ...
    @property
    def version(self) -> int: ...
    @property
    def issuer_did(self) -> str:
        """DID of the anchor that sealed the directory - the org's **current** key,
        which differs from a pinned root once the org has rotated."""
        ...
    @property
    def entries(self) -> list[ApproverEntry]:
        """The enrolled approvers, sorted by ``approver_id`` (the sealed order)."""
        ...
    @property
    def not_after_unix(self) -> int | None:
        """The sealed expiry as unix seconds, or ``None`` if unbounded."""
        ...
    def verify_current(self, anchor: TrustAnchor, now_unix: int) -> None:
        """Verify against `anchor` and expiry at `now_unix`."""
        ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> ApproverDirectory: ...

# -- SPIFFE Adapter ------------------------------------------------------------

class SpiffeId:
    """A parsed SPIFFE ID (``spiffe://<trust_domain><path>``)."""

    @staticmethod
    def parse(s: str) -> SpiffeId:
        """Parse a SPIFFE ID from its ``spiffe://...`` URI form."""
        ...
    @property
    def trust_domain(self) -> str: ...
    @property
    def path(self) -> str: ...
    def uri(self) -> str: ...

class ValidatedSvid:
    """A successfully validated JWT-SVID."""

    @property
    def spiffe_id(self) -> SpiffeId: ...
    @property
    def expires_at(self) -> str:
        """SVID expiry as an RFC 3339 timestamp string."""
        ...
    @property
    def audiences(self) -> list[str]: ...

class SpiffeTrustBundle:
    """The set of public keys for a SPIFFE trust domain, used to validate
    JWT-SVIDs. Supports ``EdDSA`` (Ed25519) and ``ES256`` (P-256) SVIDs."""

    def __init__(self) -> None: ...
    def add_ed25519_key(self, public_key: bytes, kid: str | None = None) -> None:
        """Add an Ed25519 (``EdDSA``) trust-domain key (32 bytes), optionally by ``kid``."""
        ...
    def add_p256_key(self, public_key: bytes, kid: str | None = None) -> None:
        """Add a P-256 (``ES256``) trust-domain key (SEC1 bytes), optionally by ``kid``."""
        ...
    def validate_jwt_svid(
        self, jwt: str, expected_audience: str | None = None
    ) -> ValidatedSvid:
        """Validate a JWT-SVID against this bundle, optionally requiring
        ``expected_audience``. Raises ``SvidValidationError`` on failure."""
        ...
    def to_jwks(self) -> str:
        """Export as a JWKS document (the portable WIMSE trust-bundle exchange
        form) for peers to import."""
        ...
    @staticmethod
    def from_jwks(jwks: str) -> SpiffeTrustBundle:
        """Import a trust bundle from a peer's JWKS document."""
        ...

def issue_from_svid(
    anchor: TrustAnchor,
    agent_did: str,
    svid: ValidatedSvid,
    tools: list[str],
    max_delegation_depth: int,
    valid_for_secs: int,
) -> CapabilityCredential:
    """Issue a capability credential to ``agent_did``, gated on a validated SVID
    (its SPIFFE ID is recorded as the credential's ``authorized_by`` provenance)."""
    ...

# -- WIMSE Federation Bridge ---------------------------------------------------

class FederatedIdentity:
    """A validated, federated workload identity from a peer trust domain."""

    @property
    def spiffe_id(self) -> str:
        """The workload's SPIFFE ID, as a ``spiffe://...`` URI."""
        ...
    @property
    def trust_domain(self) -> str: ...
    @property
    def trust_level(self) -> str:
        """One of ``unverified``/``self_asserted``/``verified``/``authoritative``."""
        ...
    @property
    def expires_at(self) -> str: ...
    @property
    def audiences(self) -> list[str]: ...
    def issue_credential(
        self,
        anchor: TrustAnchor,
        agent_did: str,
        tools: list[str],
        max_delegation_depth: int,
        valid_for_secs: int,
    ) -> CapabilityCredential:
        """Issue a capability credential for this federated workload, signed by
        the relying org's own ``anchor``."""
        ...

class FederationBridge:
    """Federates peer SPIFFE trust domains: import each peer's JWKS bundle, then
    validate SVIDs it signs. Cross-org workload identity without bilateral
    pre-negotiation beyond the one bundle exchange."""

    def __init__(self) -> None: ...
    def add_domain_from_jwks(
        self, trust_domain: str, jwks: str, trust_level: str
    ) -> None:
        """Federate a peer domain by importing its JWKS trust-bundle export.
        ``trust_level`` is one of
        ``unverified``/``self_asserted``/``verified``/``authoritative``."""
        ...
    def trusted_domains(self) -> list[str]: ...
    def validate(
        self, jwt_svid: str, expected_audience: str | None = None
    ) -> FederatedIdentity:
        """Validate a federated SVID, routing it to its trust domain's bundle.
        Raises ``SvidValidationError`` if the domain is not federated or the SVID
        is invalid."""
        ...

# -- Test Harness --------------------------------------------------------------

class MockOrg:
    """A mock organization for local cross-org testing: a trust anchor plus
    one-call agent/credential issuance."""

    def __init__(self, name: str) -> None: ...
    @property
    def name(self) -> str: ...
    @property
    def did(self) -> str: ...
    def issue_agent(
        self,
        tools: list[str],
        budget_usd: int | None = None,
        max_delegation_depth: int = 0,
        valid_for_secs: int = 3600,
    ) -> MockAgent:
        """Create an agent and issue it a capability credential in one call."""
        ...
    def verify_presented(
        self,
        presentation: Presentation,
        action: Action,
        challenge: PopChallenge,
        max_age_secs: int = 60,
    ) -> None:
        """Verify a presentation as a relying party that trusts this org."""
        ...

class MockAgent:
    """An agent issued by a ``MockOrg``: holds the identity and credential, and
    can mint tokens / assemble presentations without exposing key material."""

    @property
    def did(self) -> str: ...
    @property
    def credential(self) -> CapabilityCredential: ...
    def mint(
        self,
        tools: list[str],
        budget_usd: int | None = None,
        max_depth: int = 0,
        ttl_secs: int = 300,
    ) -> DelegationToken:
        """Mint a runtime delegation token for this agent."""
        ...
    def present(
        self, token: DelegationToken, challenge: PopChallenge
    ) -> Presentation:
        """Assemble a presentation of ``token`` for ``challenge``, signed by this agent."""
        ...

# -- Audit Compositor ----------------------------------------------------------

class AuditLog:
    """An org's private, append-only audit log for one correlation id. Only the
    signed commitments (from ``export``) are ever shared - raw records stay
    here."""

    def __init__(self, correlation_id: str, org_id: str) -> None: ...
    def record(self, agent_did: str, action: str, outcome: str) -> int:
        """Append an action; returns its per-org sequence number."""
        ...
    def export(self, anchor: TrustAnchor) -> str:
        """Export signed commitments to share, as a JSON array string."""
        ...
    def reveal(self, seq: int) -> str | None:
        """Selectively reveal one raw record as a JSON string (or ``None``)."""
        ...
    def __len__(self) -> int: ...

class AuditCompositor:
    """Merges multiple orgs' commitments into one verifiable, ordered
    chain-of-custody for a correlation id - without seeing raw logs."""

    def __init__(self, correlation_id: str) -> None: ...
    def ingest(self, commitments_json: str, org_anchor: TrustAnchor) -> None:
        """Ingest one org's exported commitments (the JSON from
        ``AuditLog.export``), verifying every signature against ``org_anchor``."""
        ...
    def chain_of_custody(self) -> str:
        """The merged chain-of-custody as a JSON array string."""
        ...
    def root_hash(self) -> str:
        """A single tamper-evident digest over the whole ordered chain."""
        ...
    def verify_revealed(self, record_json: str) -> bool:
        """Verify a selectively-revealed record against the composited commitment."""
        ...
    def __len__(self) -> int: ...

# -- ADR - authorization decision record event stream --------------------------

class OwnershipRecord:
    """One revision of "who is behind this accountable party".

    Held by the organization and **never** placed in a credential - only
    ``version`` and ``commitment`` travel. The members are personal data, and a
    credential is signed, immutable, presented across organizational boundaries,
    and outlives the employment, so it can neither correct nor erase them.

    Erasure degrades in the right direction: delete someone from the store and the
    commitment stops matching anything you can produce - you lose the ability to
    prove *who was in the team*, and keep the ability to prove *which team*."""

    def __init__(
        self, party_id: str, version: int, members: list[str], salt: str
    ) -> None:
        """`members` is sorted and de-duplicated, so the store's return order
        cannot change the commitment. `salt` must be at least 16 characters - a
        short salt makes the commitment brute-forceable from a candidate
        membership list, which is the exact data it exists to protect."""
        ...
    @property
    def party_id(self) -> str: ...
    @property
    def version(self) -> int: ...
    @property
    def members(self) -> list[str]:
        """The members, sorted. Personal data - keep it here."""
        ...
    @property
    def commitment(self) -> str:
        """The salted commitment, hex. The only part that travels."""
        ...
    def matches(self, commitment: str) -> bool:
        """Whether this record is the one `commitment` was made over - the
        audit-time check."""
        ...

class AuthzDecision:
    """One Authorization Decision Record - who was allowed to do what, the
    outcome, and any security signals. Serializable for export to a SIEM."""

    @staticmethod
    def from_token(
        kind: str,
        token: DelegationToken,
        action: str | None = None,
        allow: bool = True,
        signal: str | None = None,
        reason: str | None = None,
    ) -> "AuthzDecision":
        """Build a record from a token and an outcome. ``allow=False`` marks a
        denial; pass ``signal`` (e.g. ``"action_denied"``) and ``reason``.
        ``kind`` is one of mint/attenuate/verify/verify_rooted/presentation/
        revocation."""
        ...
    @staticmethod
    def allow(kind: str, subject_did: str) -> "AuthzDecision":
        """A bare allow for a subject (e.g. a non-token check)."""
        ...
    @staticmethod
    def deny(kind: str, subject_did: str, signal: str, reason: str) -> "AuthzDecision":
        """A bare deny for a subject, with a signal and reason."""
        ...
    @property
    def id(self) -> str: ...
    @property
    def seq(self) -> int: ...
    @property
    def timestamp(self) -> str: ...
    @property
    def kind(self) -> str: ...
    @property
    def decision(self) -> str: ...
    @property
    def allowed(self) -> bool: ...
    @property
    def subject_did(self) -> str: ...
    @property
    def root_agent_did(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    @property
    def vc_id(self) -> str: ...
    @property
    def action(self) -> str | None: ...
    @property
    def principal_did(self) -> str | None:
        """The principal whose authority was exercised. ``None`` is the autonomous
        case, not a missing value."""
        ...
    def with_accountability(
        self,
        party: str | None,
        source: str | None = None,
        party_version: int | None = None,
        party_commitment: str | None = None,
    ) -> AuthzDecision:
        """Record who answers for this decision, and on what basis.

        Not derivable from the token - the accountable party is a claim on the
        **credential**, so a verifier holds it during verification and passes it
        in. Without this the record answers "who is answerable" only via a join
        back to the credential, which is the join the field exists to remove.

        Both at once, because in an audit "who answers" and "how firmly do we
        know" are one question."""
        ...
    @property
    def accountable_party(self) -> str | None:
        """Who answers for this decision, within the issuing organization. ``None``
        means the credential predates accountability being recorded; the org named
        by ``issuer_did`` is accountable regardless."""
        ...
    @property
    def accountability_source(self) -> str | None:
        """How firmly the accountable party is known. ``None`` means the credential
        predates provenance being recorded, and must be read as the weakest
        source rather than an unknown one."""
        ...
    def with_verdicts(
        self, evaluation: str | None = None, admission: str | None = None
    ) -> AuthzDecision:
        """Record the R10 evaluation and admission outcomes separately.

        ``evaluation="allow"`` with ``admission="deny"`` is a replay: valid,
        policy-satisfying evidence refused because its reliance unit was already
        consumed. A single verdict field reports that identically to evidence that
        never verified - and the two call for opposite responses."""
        ...
    @property
    def evaluation(self) -> str | None:
        """Did the execution-time evidence verify and satisfy policy?
        ``"allow"``, ``"deny"``, or ``None`` when no gate applied."""
        ...
    @property
    def admission(self) -> str | None:
        """Was the reliance unit admitted? ``"allow"``, ``"deny"``, or ``None``."""
        ...
    @property
    def party_version(self) -> int | None:
        """Which revision of the ownership record named the accountable party -
        i.e. which org chart to resolve it against."""
        ...
    @property
    def party_commitment(self) -> str | None:
        """Salted commitment to that ownership record, so the resolution can be
        proved rather than asserted."""
        ...
    @property
    def depth(self) -> int: ...
    @property
    def max_depth(self) -> int: ...
    @property
    def signals(self) -> list[str]: ...
    @property
    def reason(self) -> str | None: ...
    def to_json(self) -> str:
        """The record as a JSON string (for a SIEM/log sink)."""
        ...
    @staticmethod
    def from_json(s: str) -> "AuthzDecision":
        """Parse a record back from its JSON form - the inverse of :meth:`to_json`.

        This is what makes a signed audit export independently checkable from
        Python: read the exported decisions back, replay them with
        :meth:`AdrStream.replay`, and compare against the head in the signed
        :class:`AdrCheckpoint`."""
        ...
    def digest_hex(self) -> str:
        """The canonical SHA-256 digest of this record, hex-encoded."""
        ...

class AdrStream:
    """A recorder that stamps each decision with a sequence number, advances a
    tamper-evident hash-chain, and returns the stamped record to forward."""

    def __init__(self) -> None: ...
    def record(self, decision: AuthzDecision) -> AuthzDecision:
        """Record a decision; returns the stamped record (``seq`` assigned)."""
        ...
    def head(self) -> str:
        """The current hash-chain head (hex)."""
        ...
    def count(self) -> int:
        """The number of decisions recorded so far."""
        ...
    def sign_checkpoint(self, anchor: TrustAnchor) -> "AdrCheckpoint":
        """Sign the current ``(count, head)`` for tamper-evidence."""
        ...
    @staticmethod
    def replay(decisions: list[AuthzDecision]) -> str:
        """Recompute the hash-chain head from an ordered list of decisions."""
        ...

class AdrCheckpoint:
    """An anchor-signed attestation that the decision log reached ``count``
    records with hash-chain ``head``."""

    @property
    def count(self) -> int: ...
    @property
    def head(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    @property
    def signature(self) -> str: ...
    def verify(self, anchor: TrustAnchor) -> None:
        """Verify the checkpoint signature against ``anchor``."""
        ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> "AdrCheckpoint": ...

# -- Compliance - evidence bundles ---------------------------------------------

class EvidenceReport:
    """The summary returned by a successful ``EvidenceBundle.verify``."""

    @property
    def correlation_id(self) -> str: ...
    @property
    def decisions(self) -> int: ...
    @property
    def allowed(self) -> int: ...
    @property
    def denied(self) -> int: ...
    @property
    def signals(self) -> list[str]: ...
    @property
    def checkpoint_verified(self) -> bool: ...
    @property
    def custody_entries(self) -> int: ...

class EvidenceBundle:
    """A signed, self-verifying compliance export of the authorization decisions
    (and optional chain-of-custody) for a delegation flow."""

    @staticmethod
    def seal(
        anchor: TrustAnchor,
        correlation_id: str,
        decisions: list[AuthzDecision],
        subject_did: str | None = None,
        checkpoint: AdrCheckpoint | None = None,
        compositor: AuditCompositor | None = None,
    ) -> "EvidenceBundle":
        """Seal and sign a bundle with ``anchor`` for the flow ``correlation_id``
        (the root ``vc_id``), including ``decisions`` and, optionally, the
        ``subject_did``, a stream ``checkpoint``, and the chain-of-custody from an
        ``AuditCompositor``."""
        ...
    def verify(self, anchor: TrustAnchor) -> EvidenceReport:
        """Verify the bundle against ``anchor`` and return an ``EvidenceReport``."""
        ...
    @property
    def bundle_id(self) -> str: ...
    @property
    def generated_at(self) -> str: ...
    @property
    def issuer_did(self) -> str: ...
    @property
    def correlation_id(self) -> str: ...
    @property
    def subject_did(self) -> str | None: ...
    @property
    def decisions_head(self) -> str: ...
    @property
    def custody_root(self) -> str | None: ...
    @property
    def signature(self) -> str: ...
    def decisions(self) -> list[AuthzDecision]:
        """The decision records included in the bundle."""
        ...
    def to_json(self) -> str:
        """The bundle as a JSON string (the export artifact)."""
        ...
    @staticmethod
    def from_json(s: str) -> "EvidenceBundle": ...

# -- Key rotation - signed key-history chain -----------------------------------

class RotationStatement:
    """A signed endorsement by an outgoing anchor key of its successor."""

    @staticmethod
    def issue(old: TrustAnchor, next: TrustAnchor) -> "RotationStatement":
        """``old`` signs an endorsement of ``next`` (effective now)."""
        ...
    def verify(self) -> None:
        """Verify the statement is authentically signed by the outgoing key."""
        ...
    @property
    def previous_did(self) -> str: ...
    @property
    def next_did(self) -> str: ...
    @property
    def effective_at(self) -> str: ...
    @property
    def signature(self) -> str: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> "RotationStatement": ...

class KeyHistory:
    """The chain of rotation statements from an anchor's original key to its
    current one."""

    def __init__(self, root_did: str) -> None: ...
    @staticmethod
    def genesis(anchor: TrustAnchor) -> "KeyHistory":
        """A new history rooted at ``anchor``'s DID."""
        ...
    def push(self, statement: RotationStatement) -> None:
        """Append a rotation (must chain from the current key and verify)."""
        ...
    def current_did(self) -> str:
        """The current (latest) anchor DID in the chain."""
        ...
    def verify(self, trusted_root_did: str) -> str:
        """Verify the chain from ``trusted_root_did``; return the current DID."""
        ...
    def current_anchor(self, trusted_root_did: str) -> TrustAnchor:
        """Verify the chain and return a verify-only anchor for the current key."""
        ...
    def dids(self) -> list[str]:
        """Every anchor DID the organization legitimately held (root + successors)."""
        ...
    def repudiate(self, did: str) -> None:
        """Withdraw ``did`` from issuance - a credential from it is then refused by
        :meth:`authorize_issuer` even though the key legitimately held the role.

        Repudiation is **wholesale**, not time-bounded: whoever holds a key also
        chooses the issuance timestamp, so a "distrust anything after T" cutoff is
        forgeable. Clears the seal - re-:meth:`seal` or the change is unsigned.
        """
        ...
    def seal(
        self,
        current: TrustAnchor,
        version: int,
        not_after: datetime | None = None,
    ) -> None:
        """Seal the history: the **current** key signs the chain, repudiations and
        expiry. The current key signs rather than the root so a repudiated
        predecessor cannot un-repudiate itself."""
        ...
    def is_current(self) -> bool:
        """Whether the sealed history is inside its validity window (unbounded seals
        are always current)."""
        ...
    def verify_sealed(self, trusted_root_did: str) -> str:
        """Verify the chain **and** the seal under the current key. Authenticity
        only - see :meth:`verify_current`."""
        ...
    def verify_current(self, trusted_root_did: str) -> str:
        """Verify authenticity **and** freshness - the fail-safe check a relying
        party should use."""
        ...
    def active_dids(self) -> list[str]:
        """The DIDs still trusted for issuance (the chain minus the repudiations)."""
        ...
    @property
    def repudiated(self) -> list[str]:
        """The DIDs withdrawn from issuance."""
        ...
    @property
    def not_after(self) -> str | None:
        """The sealed expiry (rfc3339), or None if unbounded."""
        ...
    @property
    def version(self) -> int:
        """The seal version."""
        ...
    def authorize_issuer(self, trusted_root_did: str, issuer_did: str) -> TrustAnchor:
        """The relying party's check: verify the sealed history is authentic and
        current, then confirm ``issuer_did`` is a key the organization still trusts.

        Accepts a superseded key - planned rotation does not invalidate what it
        already signed - but refuses a repudiated one. Requires a **sealed** history:
        the repudiations and expiry are strippable otherwise.
        """
        ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(s: str) -> "KeyHistory": ...

# -- Configuration -------------------------------------------------------------

class IdentityConfig:
    """Identity and cryptographic key configuration."""

    def __init__(
        self,
        did_method: str | None = None,
        key_algorithm: str | None = None,
        web_host: str | None = None,
        web_path: str | None = None,
        cheqd_network: str | None = None,
        indy_namespace: str | None = None,
    ) -> None: ...
    @property
    def did_method(self) -> str: ...
    @property
    def key_algorithm(self) -> str: ...
    @property
    def web_host(self) -> str | None: ...
    @property
    def web_path(self) -> str | None: ...
    @property
    def cheqd_network(self) -> str | None: ...
    @property
    def indy_namespace(self) -> str | None: ...

class DelegationConfig:
    """Delegation chain limits and token lifetime settings."""

    def __init__(
        self,
        max_depth: int | None = None,
        default_ttl_secs: int | None = None,
        max_ttl_secs: int | None = None,
    ) -> None: ...
    @property
    def max_depth(self) -> int: ...
    @property
    def default_ttl_secs(self) -> int: ...
    @property
    def max_ttl_secs(self) -> int: ...
    def clamp_ttl(self, requested_secs: int) -> int: ...

class TrustConfig:
    """Cross-organizational trust verification settings."""

    def __init__(self, minimum_trust_level: str | None = None) -> None: ...
    @property
    def minimum_trust_level(self) -> str: ...

class AgentCredsConfig:
    """Complete SDK configuration. Construct with defaults, or load from a
    TOML file / string / environment variables."""

    def __init__(self) -> None: ...
    @staticmethod
    def from_toml(path: str) -> AgentCredsConfig: ...
    @staticmethod
    def from_toml_str(toml: str) -> AgentCredsConfig: ...
    @staticmethod
    def from_env() -> AgentCredsConfig: ...
    @property
    def identity(self) -> IdentityConfig: ...
    @property
    def delegation(self) -> DelegationConfig: ...
    @property
    def trust(self) -> TrustConfig: ...
    def validate(self) -> None: ...
