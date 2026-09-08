//! Human principal identity - minting a real, stable DID for the human on whose
//! behalf an agent acts.
//!
//! In the on-behalf-of (OBO) flow the human authenticates through an identity
//! provider and holds no signing key inside AgentCreds. "A real DID" therefore
//! means a **stable, resolvable identifier** derived deterministically from the
//! human's IdP identity `(issuer, subject)`, not a fabricated keypair. The
//! binding from that DID to the IdP subject is attested cryptographically by the
//! [`TrustAnchor`](crate::did::TrustAnchor) signing the enclosing
//! [`CapabilityCredential`](crate::vc::CapabilityCredential) - the same human
//! always maps to the same DID, and the anchor vouches for the mapping.
//!
//! ```rust
//! use agentcreds_core::principal::HumanIdentity;
//!
//! # fn demo() -> Result<(), agentcreds_core::error::AgentCredsError> {
//! let human = HumanIdentity::from_idp("https://login.acme.com", "auth0|alice")?;
//! assert!(human.did().starts_with("did:web:login.acme.com:u:"));
//!
//! // The same IdP subject always mints the same DID.
//! let again = HumanIdentity::from_idp("https://login.acme.com", "auth0|alice")?;
//! assert_eq!(human.did(), again.did());
//! # Ok(()) }
//! ```

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::did::DidDocument;
use crate::vc::{AuthoritySource, PrincipalAuthorization, PrincipalKind};
use crate::{error::AgentCredsError, Result};

/// Domain-separation tag for the human-principal DID fingerprint, so a principal
/// identifier can never collide with any other SHA-256 use in the crate.
const HUMAN_PRINCIPAL_DOMAIN: &[u8] = b"agentcreds-human-principal-v1";

/// A human principal's decentralized identity, minted from a validated IdP
/// identity at credential-issuance time.
///
/// The DID is `did:web:<idp-host>:u:<fingerprint>`, where `fingerprint` is a
/// base58 digest of the IdP `(issuer, subject)` - deterministic and stable, and
/// it does not leak the raw subject. The human holds no key; see the module
/// docs for how the binding is attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanIdentity {
    did: String,
    issuer: String,
    subject: String,
    kind: PrincipalKind,
}

impl HumanIdentity {
    /// Mint a stable DID for a **workload** principal from its validated SPIFFE ID.
    ///
    /// The sibling of [`from_idp`](Self::from_idp) for the case where a service, not a
    /// person, is the principal an agent acts for. A SPIFFE ID is structurally what
    /// `(issuer, subject)` already is - a trust domain plus a path - so the same
    /// deterministic construction applies: `did:web:<trust-domain>:w:<fingerprint>`,
    /// with `:w:` distinguishing it from the `:u:` of a human so the two can never
    /// collide in the identifier space.
    ///
    /// **This does not make the workload an accountable party.** A service cannot answer
    /// for an action; the team that operates it can. Accountability travels separately -
    /// see `CapabilityClaims::accountable_party`.
    ///
    /// The SVID must already have been verified against the trust domain's bundle. This
    /// mints an identifier from an attested fact; it does not attest anything itself.
    ///
    /// # Errors
    /// `OutOfBounds` if the SPIFFE ID is not a well-formed `spiffe://<domain>/<path>`.
    pub fn from_spiffe(spiffe_id: &str) -> Result<Self> {
        let spiffe_id = spiffe_id.trim();
        let rest =
            spiffe_id
                .strip_prefix("spiffe://")
                .ok_or_else(|| AgentCredsError::OutOfBounds {
                    field: "spiffe_id",
                    detail: "SPIFFE ID must start with spiffe://".into(),
                })?;
        let (domain, path) = rest
            .split_once('/')
            .ok_or_else(|| AgentCredsError::OutOfBounds {
                field: "spiffe_id",
                detail: "SPIFFE ID must have a trust domain and a workload path".into(),
            })?;
        if domain.is_empty() || path.is_empty() {
            return Err(AgentCredsError::OutOfBounds {
                field: "spiffe_id",
                detail: "SPIFFE ID trust domain and path must both be non-empty".into(),
            });
        }
        let fp = principal_fingerprint(spiffe_id, path);
        Ok(HumanIdentity {
            kind: PrincipalKind::Workload,
            did: format!("did:web:{domain}:w:{fp}"),
            issuer: domain.to_string(),
            subject: spiffe_id.to_string(),
        })
    }

    /// Which kind of principal this identity denotes.
    #[must_use]
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Mint a stable `did:web` for a human from their validated IdP identity.
    ///
    /// `issuer` is the IdP's `iss` (typically an `https://` URL); `subject` is
    /// the IdP's stable `sub` for that human. Both must be non-empty.
    ///
    /// # Errors
    /// `OutOfBounds` if `issuer` has no resolvable host, or if `subject` is empty.
    pub fn from_idp(issuer: &str, subject: &str) -> Result<Self> {
        let issuer = issuer.trim();
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(AgentCredsError::OutOfBounds {
                field: "subject",
                detail: "IdP subject (sub) must not be empty".into(),
            });
        }
        let host = idp_host(issuer)?;
        let fp = principal_fingerprint(issuer, subject);
        Ok(HumanIdentity {
            kind: PrincipalKind::Human,
            did: format!("did:web:{host}:u:{fp}"),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
        })
    }

    /// The human's stable DID (e.g. `did:web:login.acme.com:u:z6Mk...`).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The IdP issuer (`iss`) that attested this human.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The human's IdP subject (`sub`).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Build a [`PrincipalAuthorization`] for this principal, to attach to a
    /// credential's claims as the enforced on-behalf-of dimension.
    ///
    /// `scope_consented` is expressed in tool-identifier space (the IdP bridge maps OAuth
    /// scopes to `"tool:*"` ids); `resource_authority` lists the resource-namespace
    /// patterns the principal is entitled to.
    ///
    /// **`source` is required, not defaulted.** These entitlements are the whole reason
    /// the principal axis exists: they bound the agent by something established outside
    /// the grant of capability. A caller that cannot say where they came from is a caller
    /// that took them from the request - which makes both axes trace to one source and
    /// the second one bound nothing. Making it an argument means that question is
    /// answered at every construction site rather than left to a convention.
    pub fn authorize(
        &self,
        authorized_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        scope_consented: Vec<String>,
        resource_authority: Vec<String>,
        source: AuthoritySource,
    ) -> PrincipalAuthorization {
        PrincipalAuthorization {
            principal_did: self.did.clone(),
            kind: self.kind,
            entitlement_source: source,
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            authorized_at,
            expires_at,
            scope_consented,
            resource_authority,
        }
    }

    /// Build a [`PrincipalAuthorization`] granted now, expiring at `expires_at`.
    pub fn authorize_now(
        &self,
        expires_at: DateTime<Utc>,
        scope_consented: Vec<String>,
        resource_authority: Vec<String>,
        source: AuthoritySource,
    ) -> PrincipalAuthorization {
        self.authorize(
            Utc::now(),
            expires_at,
            scope_consented,
            resource_authority,
            source,
        )
    }

    /// A minimal, **keyless** DID document for publication at the `did:web`
    /// location. The human authenticates via the IdP and controls no key here,
    /// so the document lists no verification method; authority flows through
    /// anchor-signed credentials, not a human-held key. It is never resolved for
    /// delegation-block attestation (a human is never a delegation hop).
    pub fn did_document(&self) -> DidDocument {
        let now = Utc::now();
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: self.did.clone(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            capability_delegation: Vec::new(),
            created: now,
            updated: now,
        }
    }
}

/// Extract the `did:web` host authority from an IdP issuer identifier. Strips a
/// `scheme://`, any userinfo, path, and port, lower-casing the result.
fn idp_host(issuer: &str) -> Result<String> {
    let bad = || AgentCredsError::OutOfBounds {
        field: "issuer",
        detail: format!("cannot derive a host from IdP issuer {issuer:?}"),
    };
    if issuer.is_empty() {
        return Err(bad());
    }
    let after_scheme = issuer.split_once("://").map_or(issuer, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = authority.rsplit('@').next().unwrap_or(authority); // drop userinfo
    let host = host.split(':').next().unwrap_or(host); // drop port
    if host.is_empty() {
        return Err(bad());
    }
    Ok(host.to_lowercase())
}

/// Deterministic, domain-separated base58 fingerprint of an IdP identity.
fn principal_fingerprint(issuer: &str, subject: &str) -> String {
    let mut h = Sha256::new();
    h.update(HUMAN_PRINCIPAL_DOMAIN);
    h.update(issuer.as_bytes());
    h.update([0u8]); // length-unambiguous separator
    h.update(subject.as_bytes());
    let digest = h.finalize();
    // 16 bytes is ample collision resistance for an identifier; keeps the DID short.
    format!("z{}", bs58::encode(&digest[..16]).into_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
    use crate::vc::{CapabilityClaims, CapabilityCredential};
    use chrono::Duration;

    const ISS: &str = "https://login.acme.com";
    const SUB: &str = "auth0|alice";

    #[test]
    fn from_idp_is_deterministic() {
        let a = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let b = HumanIdentity::from_idp(ISS, SUB).unwrap();
        assert_eq!(a.did(), b.did());
    }

    #[test]
    fn different_subjects_get_different_dids() {
        let a = HumanIdentity::from_idp(ISS, "auth0|alice").unwrap();
        let b = HumanIdentity::from_idp(ISS, "auth0|bob").unwrap();
        assert_ne!(a.did(), b.did());
    }

    #[test]
    fn different_issuers_get_different_dids() {
        let a = HumanIdentity::from_idp("https://login.acme.com", SUB).unwrap();
        let b = HumanIdentity::from_idp("https://login.other.com", SUB).unwrap();
        assert_ne!(a.did(), b.did());
    }

    #[test]
    fn did_has_expected_shape() {
        let h = HumanIdentity::from_idp(ISS, SUB).unwrap();
        assert!(h.did().starts_with("did:web:login.acme.com:u:z"));
        assert_eq!(h.issuer(), ISS);
        assert_eq!(h.subject(), SUB);
    }

    #[test]
    fn host_extraction_strips_scheme_port_and_path() {
        let h = HumanIdentity::from_idp("https://login.acme.com:8443/oauth2", SUB).unwrap();
        assert!(h.did().starts_with("did:web:login.acme.com:u:"));
    }

    #[test]
    fn empty_subject_rejected() {
        assert!(matches!(
            HumanIdentity::from_idp(ISS, "   "),
            Err(AgentCredsError::OutOfBounds {
                field: "subject",
                ..
            })
        ));
    }

    #[test]
    fn empty_issuer_rejected() {
        assert!(matches!(
            HumanIdentity::from_idp("", SUB),
            Err(AgentCredsError::OutOfBounds {
                field: "issuer",
                ..
            })
        ));
    }

    #[test]
    fn authorize_binds_the_principal_did() {
        let h = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let auth = h.authorize_now(
            Utc::now() + Duration::hours(1),
            vec!["tool:read_email".into()],
            vec!["mailbox:alice@acme.com/*".into()],
            AuthoritySource::Attested,
        );
        assert_eq!(auth.principal_did, h.did());
        assert_eq!(auth.issuer, ISS);
        assert!(auth.permits_tools(&["tool:read_email".into()]));
        assert!(!auth.permits_tools(&["tool:send_wire".into()]));
    }

    #[test]
    fn keyless_did_document_has_no_verification_method() {
        let h = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let doc = h.did_document();
        assert_eq!(doc.id, h.did());
        assert!(doc.verification_method.is_empty());
    }

    /// End-to-end: an anchor issues an on-behalf-of credential for an agent,
    /// bound to a real human DID, and it verifies. The anchor's signature is
    /// what attests the human-DID <-> IdP-subject binding.
    #[test]
    fn anchor_issues_obo_credential_that_verifies() {
        let human = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

        let mut claims = CapabilityClaims::new(vec!["tool:read_email".into()], 1, 3600);
        claims.on_behalf_of = Some(human.authorize_now(
            Utc::now() + Duration::hours(1),
            vec!["tool:read_email".into(), "tool:search".into()],
            vec!["mailbox:alice@acme.com/*".into()],
            AuthoritySource::Attested,
        ));

        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        assert!(vc.verify(&anchor, true).is_ok());
        assert_eq!(vc.on_behalf_of().unwrap().principal_did, human.did());
    }

    /// Issuance refuses to grant a tool the human never consented to.
    #[test]
    fn unconsented_tool_is_rejected_at_issuance() {
        let human = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

        let mut claims = CapabilityClaims::new(vec!["tool:send_wire".into()], 1, 3600);
        claims.on_behalf_of = Some(human.authorize_now(
            Utc::now() + Duration::hours(1),
            vec!["tool:read_email".into()], // wire transfer not consented
            vec![],
            AuthoritySource::Attested,
        ));

        assert!(matches!(
            CapabilityCredential::issue(&anchor, agent.did(), claims, None),
            Err(AgentCredsError::ConsentViolation { .. })
        ));
    }

    /// The credential cannot outlive the human's authorization window.
    #[test]
    fn credential_expiry_capped_at_human_authorization() {
        let human = HumanIdentity::from_idp(ISS, SUB).unwrap();
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

        // Human consent expires in 60s, but the credential asks for 1 hour.
        let consent_expiry = Utc::now() + Duration::seconds(60);
        let mut claims = CapabilityClaims::new(vec!["tool:read_email".into()], 1, 3600);
        claims.on_behalf_of = Some(human.authorize_now(
            consent_expiry,
            vec!["tool:read_email".into()],
            vec![],
            AuthoritySource::Attested,
        ));

        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        // Expiry is capped at consent (~=60s), well under the requested hour.
        assert!(vc.expiration_date() <= consent_expiry + Duration::seconds(1));
        assert!(vc.expiration_date() < Utc::now() + Duration::minutes(30));
    }
}
