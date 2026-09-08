//! Unified error type for all agentcreds-core operations.
//!
//! Uses `thiserror` for ergonomic derive macros while remaining
//! `no_std`-compatible in the variants that don't carry heap strings.

use thiserror::Error;

/// All errors that can be produced by agentcreds-core.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentCredsError {
    // -- DID errors ----------------------------------------------------------
    /// DID method is not supported by this build.
    #[error("unsupported DID method: {method}")]
    UnsupportedDidMethod {
        /// The unsupported DID method string.
        method: String,
    },

    /// Resolver is required for this DID method but none was provided.
    #[error("resolver required for DID method {method}")]
    ResolverRequired {
        /// The DID method that requires a resolver.
        method: String,
    },

    /// DID document failed signature verification.
    #[error("DID document signature invalid: {reason}")]
    InvalidDidSignature {
        /// Human-readable reason the signature check failed.
        reason: String,
    },

    /// DID could not be resolved (not found or network error).
    #[error("DID resolution failed for {did}: {reason}")]
    DidResolutionFailed {
        /// The DID that could not be resolved.
        did: String,
        /// Human-readable resolution failure reason.
        reason: String,
    },

    /// Key material is malformed or wrong length.
    #[error("invalid key material: {reason}")]
    InvalidKeyMaterial {
        /// Human-readable reason the key material is invalid.
        reason: String,
    },

    // -- VC errors ------------------------------------------------------------
    /// Verifiable Credential proof is cryptographically invalid.
    #[error("VC proof verification failed: {reason}")]
    InvalidVcProof {
        /// Human-readable reason the proof is invalid.
        reason: String,
    },

    /// VC has expired.
    #[error("credential expired at {expired_at}")]
    CredentialExpired {
        /// RFC 3339 timestamp at which the credential expired.
        expired_at: String,
    },

    /// VC has been revoked.
    #[error("credential {credential_id} has been revoked")]
    CredentialRevoked {
        /// The credential ID that was revoked.
        credential_id: String,
    },

    /// VC issuer DID does not match the trust anchor.
    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch {
        /// The DID of the expected issuer.
        expected: String,
        /// The DID of the actual issuer found in the credential.
        got: String,
    },

    /// VC claims are malformed or missing required fields.
    #[error("malformed credential claims: {reason}")]
    MalformedClaims {
        /// Human-readable reason the claims are invalid.
        reason: String,
    },

    // -- Delegation / Biscuit errors ------------------------------------------
    /// Attempted to widen scope during attenuation (cryptographically blocked).
    #[error("scope widening attempt: '{capability}' is not present in parent token")]
    ScopeWideningAttempt {
        /// The capability that was illegally added.
        capability: String,
    },

    /// Delegation depth limit exceeded.
    #[error("delegation depth {depth} exceeds maximum {max}")]
    DelegationDepthExceeded {
        /// The attempted delegation depth.
        depth: u32,
        /// The maximum allowed delegation depth.
        max: u32,
    },

    /// Token has expired (TTL elapsed).
    #[error("delegation token expired {secs_ago}s ago")]
    TokenExpired {
        /// Seconds elapsed since the token expired.
        secs_ago: i64,
    },

    /// Biscuit token signature is invalid.
    #[error("biscuit signature invalid: {reason}")]
    InvalidBiscuitSignature {
        /// Human-readable reason the signature is invalid.
        reason: String,
    },

    /// Requested action is not permitted by the token's Datalog policy.
    #[error("action '{action}' denied by policy: {reason}")]
    ActionDenied {
        /// The action that was denied.
        action: String,
        /// Human-readable policy denial reason.
        reason: String,
    },

    /// Token root public key does not match the issuing trust anchor.
    #[error("token root key mismatch")]
    RootKeyMismatch,

    /// Proof-of-possession verification failed (bad signature, stale or
    /// mismatched challenge, or the proof is not bound to this token).
    #[error("proof of possession failed: {reason}")]
    ProofOfPossessionFailed {
        /// Human-readable reason the proof of possession was rejected.
        reason: String,
    },

    /// SPIFFE JWT-SVID validation failed (bad signature, expired, malformed,
    /// audience mismatch, or an untrusted issuing key).
    #[error("SVID validation failed: {reason}")]
    SvidValidationFailed {
        /// Human-readable reason the SVID was rejected.
        reason: String,
    },

    // -- On-behalf-of / human-principal errors --------------------------------
    /// An OIDC ID token (or RFC 8693 OBO token) failed validation - bad
    /// signature, wrong `iss`/`aud`, expired, replayed `nonce`, or an actor
    /// (`act`) claim that does not match the presenting agent.
    #[error("OIDC token validation failed: {reason}")]
    OidcValidationFailed {
        /// Human-readable reason the token was rejected.
        reason: String,
    },

    /// The human principal a delegation token is bound to does not match the one
    /// named by the credential it is rooted in - a principal-swap attempt across
    /// issuance or delegation.
    ///
    /// This is a **token-vs-credential** disagreement. For a token that disagrees
    /// with the *request* being authorized, see [`Self::ActingForMismatch`] - the
    /// two failures have opposite remedies and must not share a message.
    #[error("principal mismatch: token bound to '{got}', credential authorizes '{expected}'")]
    PrincipalMismatch {
        /// The principal DID the credential authorizes.
        expected: String,
        /// The principal DID the token is actually bound to.
        got: String,
    },

    /// The request being authorized does not assert the principal the presented
    /// token is bound to - either it asserts nothing, or it asserts a different
    /// one. The token itself is intact; what is wrong is the `acting_for` on the
    /// [`Action`](crate::delegation::Action).
    ///
    /// `acting_for` must come from the relying party's **own** verified session
    /// (an OIDC login, or the caller's attested SVID) - never from the token,
    /// which would make the check tautological. An `asserted` of `None` on an
    /// otherwise-working deployment usually means the relying party never bound a
    /// principal at all (e.g. `IdentityEnforcer.bind_principal` was not called).
    #[error(
        "acting-for mismatch: the request asserts principal '{}', but the token is bound to \
         '{required}' - `acting_for` must come from the relying party's own verified session",
        .asserted.as_deref().unwrap_or("<none>")
    )]
    ActingForMismatch {
        /// The principal DID the presented token is bound to.
        required: String,
        /// The principal DID the request asserted, or `None` if it asserted none.
        asserted: Option<String>,
    },

    /// A capability or resource was requested that the human principal never
    /// consented to - issuance cannot grant authority beyond the human's own.
    #[error("consent violation: '{capability}' was not consented to by the authorizing principal")]
    ConsentViolation {
        /// The tool or resource that exceeds the principal's consented authority.
        capability: String,
    },

    // -- Revocation errors ----------------------------------------------------
    /// Revocation list index is out of bounds.
    #[error("revocation index {index} out of bounds (list size: {size})")]
    RevocationIndexOutOfBounds {
        /// The index that was out of range.
        index: u64,
        /// The total size of the revocation list.
        size: u64,
    },

    /// Revocation list signature is invalid.
    #[error("revocation list signature invalid")]
    InvalidRevocationListSignature,

    /// Revocation list is authentic, but its signed `updated` timestamp is older
    /// than the relying party's configured bound (R7). Distinct from a fetch-cache
    /// TTL: this bounds the age of the **signed state itself**, catching a
    /// frozen-but-serving issuer or a replay of an old-but-valid list. Fail closed.
    #[error("revocation list stale: signed state is {age_secs}s old (updated {updated}), exceeds configured max age {max_age_secs}s")]
    RevocationListStale {
        /// RFC 3339 timestamp of the list's signed `updated` field.
        updated: String,
        /// Age of the signed state at check time, in seconds.
        age_secs: i64,
        /// The relying party's configured maximum age, in seconds.
        max_age_secs: i64,
    },

    // -- Serialization errors -------------------------------------------------
    /// JSON (de)serialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// CBOR (de)serialization failed.
    #[error("CBOR error: {0}")]
    Cbor(String),

    /// Base64 decode failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64ct::Error),

    // -- Cryptographic primitive errors ---------------------------------------
    /// A cryptographic operation failed (generic - details in reason).
    #[error("cryptographic operation failed: {reason}")]
    CryptoError {
        /// Human-readable reason the cryptographic operation failed.
        reason: String,
    },

    /// RNG failed to produce entropy.
    #[error("entropy source unavailable")]
    EntropyError,

    // -- Policy / validation errors -------------------------------------------
    /// A required field was missing from an input.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: &'static str,
    },

    /// An input value was outside acceptable bounds.
    #[error("value out of bounds for field '{field}': {detail}")]
    OutOfBounds {
        /// The name of the out-of-bounds field.
        field: &'static str,
        /// Human-readable detail describing the constraint violation.
        detail: String,
    },
}

impl From<ciborium::ser::Error<std::io::Error>> for AgentCredsError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        AgentCredsError::Cbor(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for AgentCredsError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        AgentCredsError::Cbor(e.to_string())
    }
}
