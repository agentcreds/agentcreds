use napi::{Error, Status};

use agentcreds_core::error::AgentCredsError as CoreError;

/// Map a core `AgentCredsError` onto a JS-catchable `Error`.
///
/// The thrown error's message is formatted as `"<Kind>: <description>"`,
/// where `<Kind>` matches the exception class names used by the Python
/// bindings (`DidError`, `CredentialExpiredError`, `TokenExpiredError`, ...).
/// JS consumers can branch on `error.message` (e.g.
/// `error.message.includes("TokenExpiredError")`) to distinguish error kinds.
pub fn map_err(e: CoreError) -> Error {
    let msg = e.to_string();
    let kind = match e {
        CoreError::UnsupportedDidMethod { .. }
        | CoreError::ResolverRequired { .. }
        | CoreError::InvalidDidSignature { .. }
        | CoreError::DidResolutionFailed { .. }
        | CoreError::InvalidKeyMaterial { .. } => "DidError",

        CoreError::CredentialExpired { .. } => "CredentialExpiredError",
        CoreError::CredentialRevoked { .. } => "CredentialRevokedError",
        CoreError::InvalidVcProof { .. }
        | CoreError::IssuerMismatch { .. }
        | CoreError::MalformedClaims { .. } => "CredentialError",

        CoreError::ScopeWideningAttempt { .. } => "ScopeWideningError",
        CoreError::TokenExpired { .. } => "TokenExpiredError",
        CoreError::ActionDenied { .. } => "ActionDeniedError",
        CoreError::DelegationDepthExceeded { .. }
        | CoreError::InvalidBiscuitSignature { .. }
        | CoreError::RootKeyMismatch => "DelegationError",

        CoreError::ProofOfPossessionFailed { .. } => "ProofOfPossessionError",
        // Both principal failures map to one JS error name so the runtime's
        // `principal_mismatch` classification stays stable; the message
        // distinguishes a bad token from a request that asserted no principal.
        CoreError::PrincipalMismatch { .. } | CoreError::ActingForMismatch { .. } => {
            "PrincipalMismatchError"
        }

        CoreError::SvidValidationFailed { .. } => "SvidValidationError",
        CoreError::OidcValidationFailed { .. } => "OidcValidationError",
        CoreError::ConsentViolation { .. } => "ConsentViolationError",

        CoreError::RevocationIndexOutOfBounds { .. }
        | CoreError::InvalidRevocationListSignature => "RevocationError",

        CoreError::Json(_) | CoreError::Cbor(_) | CoreError::Base64(_) => "SerializationError",

        CoreError::MissingField { .. } | CoreError::OutOfBounds { .. } => "ValidationError",

        CoreError::CryptoError { .. } | CoreError::EntropyError => "AgentCredsError",

        _ => "AgentCredsError",
    };

    Error::new(Status::GenericFailure, format!("{kind}: {msg}"))
}

/// Construct a `ValidationError`-style error for argument parsing failures
/// (e.g. unknown algorithm/network/trust-level strings) that do not
/// originate from `agentcreds-core`.
pub fn invalid_arg(msg: impl Into<String>) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("ValidationError: {}", msg.into()),
    )
}
