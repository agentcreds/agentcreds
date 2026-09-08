//! # agentcreds-core
//!
//! Cryptographic core for AgentCreds - verifiable, attenuable delegation for
//! autonomous AI agents, verified offline.
//!
//! ## Architecture
//!
//! ```text
//! +-------------------------------------------------+
//! |                  Public API                      |
//! |  AgentIdentity | CapabilityCredential |          |
//! |  DelegationToken | RevocationService             |
//! +----------+----------------------+---------------+
//!            |                      |
//!   +--------v--------+   +--------v--------+
//!   |   DID layer     |   |  Biscuit/VC      |
//!   |  (did module)   |   |  delegation      |
//!   +--------+--------+   +--------+--------+
//!            |                      |
//!   +--------v----------------------v--------+
//!   |         Cryptographic primitives        |
//!   |   Ed25519 | P-256 | SHA-256 | CBOR      |
//!   +----------------------------------------+
//! ```
//!
//! ## Quick start
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//!
//! // 1. Create an agent identity
//! let identity = AgentIdentity::create(DidMethod::Key, None)?;
//!
//! // 2. Issue a capability credential from a trust anchor
//! let anchor = TrustAnchor::generate()?;
//! let mut claims = CapabilityClaims::new(
//!     vec!["tool:search".into(), "tool:summarise".into()],
//!     3,     // max delegation depth
//!     3600,  // valid for 1 hour
//! );
//! claims.budget_usd = Some(100);
//! let vc = CapabilityCredential::issue(&anchor, identity.did(), claims, None)?;
//!
//! // 3. Mint a short-lived Biscuit runtime token from the VC
//! let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
//! let token = DelegationToken::mint(&vc, scope, 300, &identity)?;
//!
//! // 4. Attenuate for a sub-agent (scope can only narrow)
//! let sub_agent = AgentIdentity::create(DidMethod::Key, None)?;
//! let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
//! let child_token = token.attenuate(narrow, 60, &sub_agent)?;
//!
//! // 5. Verify at the tool call boundary (<1ms): chain authenticity + scope
//! let action = Action::new("tool:search", "query=rust+biscuit");
//! assert!(child_token.verify(&action).is_ok());
//!
//! // 6. A relying party holding the credential uses the anchor-rooted check,
//! //    which also proves the authority traces back to the trust anchor.
//! assert!(child_token.verify_rooted(&action, &vc, &anchor).is_ok());
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used)]
#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod a2a;
pub mod accountability;
pub mod adr;
// Execution-time human-authorization primitives (R10). Not a public path: its types
// (`Gate`, `ApprovalEvidence`, `ApproverDirectory`, `ConsumedApprovals`) are the
// stable API and are re-exported from `delegation`, so the module itself is internal.
pub(crate) mod approval;
// Signed intent statements + alignment evidence (AARM R3/R7). Internal for the same
// reason as `approval`: its types (`IntentStatement`, `AlignmentEvidence`) are the
// stable API and are re-exported from `delegation`.
pub mod audit;
pub mod binding;
pub mod compliance;
pub mod config;
pub mod delegation;
pub mod did;
pub(crate) mod intent;
pub mod interop;
pub mod jcs;
pub mod pop;
pub mod principal;
pub mod rotation;
mod signed;
pub mod vc;
// Opt-in interop format (off by default) - not on the Biscuit runtime path.
#[cfg(feature = "bbs")]
pub mod bbs;
pub mod error;
pub mod oidc;
pub mod registry;
pub mod revocation;
#[cfg(feature = "sd-jwt")]
pub mod sd_jwt;
pub mod spiffe;
pub mod testkit;
pub mod wimse;

/// Convenience re-exports for common usage.
pub mod prelude {
    pub use crate::adr::{
        AdrCheckpoint, AdrSink, AdrStream, AuthzDecision, Decision, DecisionKind, InMemorySink,
        Signal,
    };
    pub use crate::audit::{
        AuditCommitment, AuditCompositor, AuditLog, AuditRecord, CompositeEntry,
    };
    pub use crate::compliance::{EvidenceBundle, EvidenceBundleBuilder, EvidenceReport};
    pub use crate::config::{
        AgentCredsConfig, DelegationConfig, IdentityConfig, IdpConfig, TrustConfig,
    };
    pub use crate::delegation::{Action, ChainEntry, DelegationChain, DelegationToken, Scope};
    pub use crate::did::{
        AgentIdentity, AnchorSigner, DidDocument, DidMethod, DidResolver, InMemoryResolver,
        SoftwareSigner, TrustAnchor, UniversalResolver,
    };
    pub use crate::error::AgentCredsError;
    pub use crate::interop::{
        ClaimMap, CredentialIssuer, CredentialPresenter, CredentialVerifier, DidKeyTrust,
        IdentityClaimMap, KeyBindingChallenge, NativeInterop, PresentationRequest, TrustMap,
        VerifiedCredential,
    };
    pub use crate::oidc::{OidcProvider, VerifiedHumanPrincipal};
    pub use crate::pop::{PopChallenge, Presentation, ProofOfPossession};
    pub use crate::principal::HumanIdentity;
    pub use crate::registry::{
        CrossOrgVerifier, SignedTrustConfig, TrustEntry, TrustLevel, TrustRegistry,
    };
    pub use crate::revocation::{RevocationList, RevocationRegistry};
    pub use crate::rotation::{KeyHistory, RotationStatement};
    #[cfg(feature = "sd-jwt")]
    pub use crate::sd_jwt::{DisclosedCredential, SdJwt};
    pub use crate::spiffe::{SpiffeId, SpiffeTrustBundle, ValidatedSvid};
    pub use crate::testkit::{MockAgent, MockOrg};
    pub use crate::vc::{
        CapabilityClaims, CapabilityCredential, CredentialFormat, CredentialStatus,
        HumanAuthorization,
    };
    pub use crate::wimse::{FederatedIdentity, FederationBridge};
}

/// Crate-wide Result alias.
pub type Result<T> = std::result::Result<T, error::AgentCredsError>;
