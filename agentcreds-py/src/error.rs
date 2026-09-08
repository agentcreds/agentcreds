use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use agentcreds_core::error::AgentCredsError as CoreError;

create_exception!(agentcreds, AgentCredsError, PyException);
create_exception!(agentcreds, DidError, AgentCredsError);
create_exception!(agentcreds, CredentialError, AgentCredsError);
create_exception!(agentcreds, CredentialExpiredError, CredentialError);
create_exception!(agentcreds, CredentialRevokedError, CredentialError);
create_exception!(agentcreds, DelegationError, AgentCredsError);
create_exception!(agentcreds, ScopeWideningError, DelegationError);
create_exception!(agentcreds, TokenExpiredError, DelegationError);
create_exception!(agentcreds, ActionDeniedError, DelegationError);
create_exception!(agentcreds, ProofOfPossessionError, DelegationError);
create_exception!(agentcreds, PrincipalMismatchError, DelegationError);
create_exception!(agentcreds, RevocationError, AgentCredsError);
create_exception!(agentcreds, SvidValidationError, AgentCredsError);
create_exception!(agentcreds, OidcValidationError, AgentCredsError);
create_exception!(agentcreds, ConsentViolationError, CredentialError);
create_exception!(agentcreds, SerializationError, AgentCredsError);
create_exception!(agentcreds, ValidationError, AgentCredsError);

/// Map a core `AgentCredsError` onto the Python exception hierarchy above.
pub fn map_err(e: CoreError) -> PyErr {
    let msg = e.to_string();
    match e {
        CoreError::UnsupportedDidMethod { .. }
        | CoreError::ResolverRequired { .. }
        | CoreError::InvalidDidSignature { .. }
        | CoreError::DidResolutionFailed { .. }
        | CoreError::InvalidKeyMaterial { .. } => DidError::new_err(msg),

        CoreError::CredentialExpired { .. } => CredentialExpiredError::new_err(msg),
        CoreError::CredentialRevoked { .. } => CredentialRevokedError::new_err(msg),
        CoreError::InvalidVcProof { .. }
        | CoreError::IssuerMismatch { .. }
        | CoreError::MalformedClaims { .. } => CredentialError::new_err(msg),

        CoreError::ScopeWideningAttempt { .. } => ScopeWideningError::new_err(msg),
        CoreError::TokenExpired { .. } => TokenExpiredError::new_err(msg),
        CoreError::ActionDenied { .. } => ActionDeniedError::new_err(msg),
        CoreError::DelegationDepthExceeded { .. }
        | CoreError::InvalidBiscuitSignature { .. }
        | CoreError::RootKeyMismatch => DelegationError::new_err(msg),

        CoreError::ProofOfPossessionFailed { .. } => ProofOfPossessionError::new_err(msg),
        // Both principal failures surface as one Python exception so the runtime's
        // `principal_mismatch` classification stays stable; the *message* is what
        // distinguishes a bad token from a request that asserted no principal.
        CoreError::PrincipalMismatch { .. } | CoreError::ActingForMismatch { .. } => {
            PrincipalMismatchError::new_err(msg)
        }

        CoreError::SvidValidationFailed { .. } => SvidValidationError::new_err(msg),
        CoreError::OidcValidationFailed { .. } => OidcValidationError::new_err(msg),
        CoreError::ConsentViolation { .. } => ConsentViolationError::new_err(msg),

        CoreError::RevocationIndexOutOfBounds { .. }
        | CoreError::InvalidRevocationListSignature => RevocationError::new_err(msg),

        CoreError::Json(_) | CoreError::Cbor(_) | CoreError::Base64(_) => {
            SerializationError::new_err(msg)
        }

        CoreError::MissingField { .. } | CoreError::OutOfBounds { .. } => {
            ValidationError::new_err(msg)
        }

        CoreError::CryptoError { .. } | CoreError::EntropyError => AgentCredsError::new_err(msg),

        _ => AgentCredsError::new_err(msg),
    }
}

/// Register the exception hierarchy on the `agentcreds` module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("AgentCredsError", py.get_type_bound::<AgentCredsError>())?;
    m.add("DidError", py.get_type_bound::<DidError>())?;
    m.add("CredentialError", py.get_type_bound::<CredentialError>())?;
    m.add(
        "CredentialExpiredError",
        py.get_type_bound::<CredentialExpiredError>(),
    )?;
    m.add(
        "CredentialRevokedError",
        py.get_type_bound::<CredentialRevokedError>(),
    )?;
    m.add("DelegationError", py.get_type_bound::<DelegationError>())?;
    m.add(
        "ScopeWideningError",
        py.get_type_bound::<ScopeWideningError>(),
    )?;
    m.add(
        "TokenExpiredError",
        py.get_type_bound::<TokenExpiredError>(),
    )?;
    m.add(
        "ActionDeniedError",
        py.get_type_bound::<ActionDeniedError>(),
    )?;
    m.add(
        "ProofOfPossessionError",
        py.get_type_bound::<ProofOfPossessionError>(),
    )?;
    m.add(
        "PrincipalMismatchError",
        py.get_type_bound::<PrincipalMismatchError>(),
    )?;
    m.add("RevocationError", py.get_type_bound::<RevocationError>())?;
    m.add(
        "SvidValidationError",
        py.get_type_bound::<SvidValidationError>(),
    )?;
    m.add(
        "OidcValidationError",
        py.get_type_bound::<OidcValidationError>(),
    )?;
    m.add(
        "ConsentViolationError",
        py.get_type_bound::<ConsentViolationError>(),
    )?;
    m.add(
        "SerializationError",
        py.get_type_bound::<SerializationError>(),
    )?;
    m.add("ValidationError", py.get_type_bound::<ValidationError>())?;
    Ok(())
}
