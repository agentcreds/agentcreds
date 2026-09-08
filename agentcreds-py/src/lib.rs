//! Python bindings for `agentcreds-core` - verifiable, attenuable
//! delegation for AI agents, verified offline.
//!
//! All bindings are synchronous: every operation in the underlying Rust
//! crate is sub-millisecond, so there is no `async`/`await` in this API.

use pyo3::prelude::*;

mod adr;
mod audit;
mod compliance;
mod config;
mod convert;
mod credential;
mod delegation;
mod error;
mod identity;
mod jcs;
mod oidc;
mod pop;
mod principal;
mod registry;
mod revocation;
mod rotation;
mod sd_jwt;
mod spiffe;
mod testkit;
mod wimse;

use config::{PyAgentCredsConfig, PyDelegationConfig, PyIdentityConfig, PyTrustConfig};
use credential::{
    PyCapabilityClaims, PyCapabilityCredential, PyCredentialStatus, PyHumanAuthorization,
    PyLinkedDataProof, PyOwnershipRecord,
};
use delegation::{
    PyAction, PyApprovalEvidence, PyApproverDirectory, PyApproverEntry, PyChainEntry,
    PyConsumedApprovals, PyDelegationChain, PyDelegationToken, PyGate, PyScope,
};
use identity::{
    PyAgentIdentity, PyDidDocument, PyInMemoryResolver, PyPublicKey, PyTrustAnchor,
    PyVerificationMethod,
};
use registry::{PySignedTrustConfig, PyTrustEntry, PyTrustRegistry};
use revocation::{default_list_size, PyRevocationList, PyRevocationRegistry};

#[pymodule]
fn agentcreds(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    // identity
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyVerificationMethod>()?;
    m.add_class::<PyDidDocument>()?;
    m.add_class::<PyAgentIdentity>()?;
    m.add_class::<PyTrustAnchor>()?;
    m.add_class::<PyInMemoryResolver>()?;

    // verifiable credentials
    m.add_class::<PyCapabilityClaims>()?;
    m.add_class::<PyCredentialStatus>()?;
    m.add_class::<PyLinkedDataProof>()?;
    m.add_class::<PyCapabilityCredential>()?;
    m.add_class::<PyHumanAuthorization>()?;
    m.add_class::<PyOwnershipRecord>()?;

    // human principal (on-behalf-of identity)
    m.add_class::<principal::PyHumanIdentity>()?;

    // delegation
    m.add_class::<PyScope>()?;
    m.add_class::<PyAction>()?;
    m.add_class::<PyChainEntry>()?;
    m.add_class::<PyDelegationChain>()?;
    m.add_class::<PyDelegationToken>()?;
    m.add_class::<PyGate>()?;
    m.add_class::<PyApprovalEvidence>()?;
    m.add_class::<PyConsumedApprovals>()?;
    m.add_class::<PyApproverEntry>()?;
    m.add_class::<PyApproverDirectory>()?;

    // proof of possession / presentation
    m.add_class::<pop::PyPopChallenge>()?;
    m.add_class::<pop::PyProofOfPossession>()?;
    m.add_class::<pop::PyPresentation>()?;

    // SD-JWT selective disclosure
    m.add_class::<sd_jwt::PySdJwt>()?;
    m.add_class::<sd_jwt::PyDisclosedCredential>()?;

    // revocation
    m.add_class::<PyRevocationList>()?;
    m.add_class::<PyRevocationRegistry>()?;
    m.add_function(pyo3::wrap_pyfunction!(default_list_size, m)?)?;

    // trust registry / cross-org verification
    m.add_class::<PyTrustEntry>()?;
    m.add_class::<PyTrustRegistry>()?;
    m.add_class::<PySignedTrustConfig>()?;

    // SPIFFE adapter (JWT-SVID -> capability credential)
    m.add_class::<spiffe::PySpiffeId>()?;
    m.add_class::<spiffe::PyValidatedSvid>()?;
    m.add_class::<spiffe::PySpiffeTrustBundle>()?;
    m.add_function(pyo3::wrap_pyfunction!(spiffe::issue_from_svid, m)?)?;

    // OIDC adapter (human ID token / RFC 8693 OBO token -> credential)
    m.add_class::<oidc::PyOidcProvider>()?;
    m.add_class::<oidc::PyVerifiedHumanPrincipal>()?;
    m.add_function(pyo3::wrap_pyfunction!(oidc::issue_on_behalf_of, m)?)?;

    // RFC 8785 canonicalization, so a wheel-only holder can build a correct binding
    // string instead of reimplementing the profile.
    m.add("JCS_PROFILE", agentcreds_core::jcs::PROFILE)?;
    m.add(
        "JCS_MAX_SAFE_INTEGER",
        agentcreds_core::jcs::MAX_SAFE_INTEGER,
    )?;
    m.add_function(pyo3::wrap_pyfunction!(jcs::jcs_canonicalize, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(jcs::jcs_serialize_float, m)?)?;
    m.add_function(pyo3::wrap_pyfunction!(jcs::jcs_precision_hazards, m)?)?;

    // test harness (mock cross-org verification)
    m.add_class::<testkit::PyMockOrg>()?;
    m.add_class::<testkit::PyMockAgent>()?;

    // WIMSE federation bridge (cross-org workload identity)
    m.add_class::<wimse::PyFederationBridge>()?;
    m.add_class::<wimse::PyFederatedIdentity>()?;

    // audit compositor (joint cross-org chain-of-custody)
    m.add_class::<audit::PyAuditLog>()?;
    m.add_class::<audit::PyAuditCompositor>()?;

    // ADR - authorization decision record event stream
    m.add_class::<adr::PyAuthzDecision>()?;
    m.add_class::<adr::PyAdrStream>()?;
    m.add_class::<adr::PyAdrCheckpoint>()?;

    // compliance - signed evidence bundles
    m.add_class::<compliance::PyEvidenceBundle>()?;
    m.add_class::<compliance::PyEvidenceReport>()?;

    // key rotation - signed key-history chain
    m.add_class::<rotation::PyRotationStatement>()?;
    m.add_class::<rotation::PyKeyHistory>()?;

    // configuration
    m.add_class::<PyIdentityConfig>()?;
    m.add_class::<PyDelegationConfig>()?;
    m.add_class::<PyTrustConfig>()?;
    m.add_class::<PyAgentCredsConfig>()?;

    error::register(py, m)?;

    Ok(())
}
