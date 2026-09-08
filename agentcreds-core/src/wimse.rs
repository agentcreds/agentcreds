//! WIMSE federation bridge - portable workload identity across org boundaries.
//!
//! Two organizations each run their own SPIFFE/SPIRE deployment. They federate
//! by exchanging **trust bundles** (the public keys of each domain, as a JWKS -
//! see [`crate::spiffe::SpiffeTrustBundle::to_jwks`]). Once Org A imports Org
//! B's bundle into a [`FederationBridge`], a workload SVID issued by Org B's
//! SPIRE validates at Org A and yields a [`FederatedIdentity`] carrying the
//! trust level Org A assigned to that domain - workload identity made portable
//! without any bilateral pre-negotiation beyond the one bundle exchange.
//!
//! ```rust
//! use agentcreds_core::wimse::FederationBridge;
//! use agentcreds_core::registry::TrustLevel;
//!
//! # fn demo(org_b_jwks: &str, org_b_svid: &str) -> Result<(), agentcreds_core::error::AgentCredsError> {
//! let mut bridge = FederationBridge::new();
//! bridge.add_domain_from_jwks("orgb.example", org_b_jwks, TrustLevel::Verified)?;
//!
//! let fed = bridge.validate(org_b_svid, Some("spiffe://orgb.example/agentcreds"))?;
//! assert_eq!(fed.trust_domain, "orgb.example");
//! # Ok(()) }
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::did::TrustAnchor;
use crate::registry::TrustLevel;
use crate::spiffe::{self, SpiffeId, SpiffeTrustBundle, ValidatedSvid};
use crate::vc::CapabilityCredential;
use crate::{error::AgentCredsError, Result};

fn wimse_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::SvidValidationFailed {
        reason: reason.into(),
    }
}

struct FederatedDomain {
    bundle: SpiffeTrustBundle,
    trust_level: TrustLevel,
}

/// A bridge that federates one or more peer SPIFFE trust domains. SVIDs are
/// routed to the bundle of their own trust domain and validated there.
pub struct FederationBridge {
    domains: HashMap<String, FederatedDomain>,
}

impl Default for FederationBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl FederationBridge {
    /// A bridge that federates nothing yet.
    pub fn new() -> Self {
        FederationBridge {
            domains: HashMap::new(),
        }
    }

    /// Federate `trust_domain`: accept SVIDs it signs, at `trust_level`.
    pub fn add_domain(
        &mut self,
        trust_domain: impl Into<String>,
        bundle: SpiffeTrustBundle,
        trust_level: TrustLevel,
    ) {
        self.domains.insert(
            trust_domain.into(),
            FederatedDomain {
                bundle,
                trust_level,
            },
        );
    }

    /// Federate a peer domain by importing its JWKS trust-bundle export.
    ///
    /// # Errors
    /// `SvidValidationFailed` if the JWKS is malformed.
    pub fn add_domain_from_jwks(
        &mut self,
        trust_domain: impl Into<String>,
        jwks: &str,
        trust_level: TrustLevel,
    ) -> Result<()> {
        let bundle = SpiffeTrustBundle::from_jwks(jwks)?;
        self.add_domain(trust_domain, bundle, trust_level);
        Ok(())
    }

    /// The trust domains this bridge federates.
    pub fn trusted_domains(&self) -> Vec<&str> {
        self.domains.keys().map(String::as_str).collect()
    }

    /// Validate a federated JWT-SVID: route it to its own trust domain's bundle,
    /// verify it there, and return the federated identity carrying that domain's
    /// trust level. Rejects SVIDs from domains this bridge does not federate.
    ///
    /// # Errors
    /// `SvidValidationFailed` if the domain is not federated, the signature is
    /// invalid, the SVID is expired, or the audience does not match.
    pub fn validate(
        &self,
        jwt_svid: &str,
        expected_audience: Option<&str>,
    ) -> Result<FederatedIdentity> {
        let domain = peek_trust_domain(jwt_svid)?;
        let fed = self
            .domains
            .get(&domain)
            .ok_or_else(|| wimse_err(format!("trust domain '{domain}' is not federated")))?;
        let svid = fed.bundle.validate_jwt_svid(jwt_svid, expected_audience)?;
        // Defense in depth: the verified SVID's domain must match the routed one.
        if svid.spiffe_id.trust_domain != domain {
            return Err(wimse_err("SVID trust domain changed after verification"));
        }
        Ok(FederatedIdentity {
            spiffe_id: svid.spiffe_id,
            trust_domain: domain,
            trust_level: fed.trust_level,
            expires_at: svid.expires_at,
            audiences: svid.audiences,
        })
    }
}

/// A validated, federated workload identity from a peer trust domain.
#[derive(Debug, Clone)]
pub struct FederatedIdentity {
    /// The workload's SPIFFE ID.
    pub spiffe_id: SpiffeId,
    /// The peer trust domain that vouches for it.
    pub trust_domain: String,
    /// The trust level the bridge assigns to that domain.
    pub trust_level: TrustLevel,
    /// SVID expiry.
    pub expires_at: DateTime<Utc>,
    /// SVID audiences.
    pub audiences: Vec<String>,
}

impl FederatedIdentity {
    /// Issue a capability credential for this federated workload, signed by the
    /// relying org's own `anchor`. The SPIFFE ID is recorded as provenance.
    ///
    /// # Errors
    /// Propagates credential issuance failure.
    pub fn issue_credential(
        &self,
        anchor: &TrustAnchor,
        agent_did: &str,
        tools: Vec<String>,
        max_delegation_depth: u32,
        valid_for_secs: u64,
    ) -> Result<CapabilityCredential> {
        let svid = ValidatedSvid {
            spiffe_id: self.spiffe_id.clone(),
            expires_at: self.expires_at,
            audiences: self.audiences.clone(),
        };
        spiffe::issue_from_svid(
            anchor,
            agent_did,
            &svid,
            tools,
            max_delegation_depth,
            valid_for_secs,
        )
    }
}

/// Extract the trust domain from a JWT-SVID's *unverified* `sub`, purely to
/// route it to the right bundle. The signature is verified afterwards against
/// that bundle, so a forged `sub` cannot gain trust.
fn peek_trust_domain(jwt: &str) -> Result<String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| wimse_err("malformed JWT"))?;
    let bytes = Base64UrlUnpadded::decode_vec(payload_b64)
        .map_err(|e| wimse_err(format!("JWT payload base64url: {e}")))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| wimse_err(format!("JWT payload JSON: {e}")))?;
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| wimse_err("JWT missing sub"))?;
    Ok(SpiffeId::parse(sub)?.trust_domain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::Duration;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn future() -> i64 {
        (Utc::now() + Duration::hours(1)).timestamp()
    }

    /// Build an Ed25519 JWT-SVID for `domain`/`path`; returns (jwt, raw_pubkey).
    fn ed_svid(domain: &str, path: &str, aud: &str) -> (String, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let header =
            b64(&serde_json::to_vec(&json!({"alg":"EdDSA","typ":"JWT","kid":"k1"})).unwrap());
        let payload = b64(&serde_json::to_vec(&json!({
            "sub": format!("spiffe://{domain}{path}"), "exp": future(), "aud": aud,
        }))
        .unwrap());
        let signing = format!("{header}.{payload}");
        let sig = sk.sign(signing.as_bytes());
        (format!("{signing}.{}", b64(&sig.to_bytes())), pk)
    }

    /// Build a P-256 (ES256) JWT-SVID; returns (jwt, sec1_uncompressed_pubkey).
    fn p256_svid(domain: &str, path: &str, aud: &str) -> (String, Vec<u8>) {
        let sk = P256SigningKey::random(&mut OsRng);
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let header = b64(&serde_json::to_vec(&json!({"alg":"ES256","typ":"JWT"})).unwrap());
        let payload = b64(&serde_json::to_vec(&json!({
            "sub": format!("spiffe://{domain}{path}"), "exp": future(), "aud": aud,
        }))
        .unwrap());
        let signing = format!("{header}.{payload}");
        let sig: p256::ecdsa::Signature = sk.sign(signing.as_bytes());
        (format!("{signing}.{}", b64(&sig.to_bytes())), pk)
    }

    #[test]
    fn federated_svid_from_imported_bundle_is_trusted() {
        let aud = "spiffe://orgb.example/agentcreds";
        let (jwt, pk) = ed_svid("orgb.example", "/workload/api", aud);

        // Org B publishes its trust bundle as JWKS.
        let mut org_b = SpiffeTrustBundle::new();
        org_b.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let jwks = org_b.to_jwks().unwrap();

        // Org A imports it and federates orgb.example at Verified.
        let mut bridge = FederationBridge::new();
        bridge
            .add_domain_from_jwks("orgb.example", &jwks, TrustLevel::Verified)
            .unwrap();

        let fed = bridge.validate(&jwt, Some(aud)).unwrap();
        assert_eq!(fed.trust_domain, "orgb.example");
        assert_eq!(fed.trust_level, TrustLevel::Verified);
        assert_eq!(fed.spiffe_id.path, "/workload/api");

        // Org A issues a capability for the federated workload, with its own anchor.
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = fed
            .issue_credential(&anchor, agent.did(), vec!["tool:search".into()], 2, 3600)
            .unwrap();
        assert_eq!(vc.subject_did(), agent.did());
        assert!(vc.verify(&anchor, true).is_ok());
    }

    #[test]
    fn unfederated_domain_rejected() {
        let (jwt, _pk) = ed_svid("evil.example", "/w", "aud");
        let (_j2, good_pk) = ed_svid("good.example", "/w", "aud");
        let mut good = SpiffeTrustBundle::new();
        good.add_ed25519_key(Some("k1".into()), &good_pk).unwrap();

        let mut bridge = FederationBridge::new();
        bridge.add_domain("good.example", good, TrustLevel::Verified);
        // evil.example is not federated.
        assert!(bridge.validate(&jwt, None).is_err());
    }

    #[test]
    fn federated_domain_wrong_key_rejected() {
        let (jwt, _pk) = ed_svid("orgb.example", "/w", "aud");
        // Bundle holds a *different* key for orgb.example.
        let (_j2, other_pk) = ed_svid("orgb.example", "/w", "aud");
        let mut bundle = SpiffeTrustBundle::new();
        bundle
            .add_ed25519_key(Some("k1".into()), &other_pk)
            .unwrap();

        let mut bridge = FederationBridge::new();
        bridge.add_domain("orgb.example", bundle, TrustLevel::Verified);
        assert!(bridge.validate(&jwt, None).is_err());
    }

    #[test]
    fn jwks_roundtrip_preserves_p256_keys() {
        let aud = "spiffe://orgc.example/agentcreds";
        let (jwt, pk) = p256_svid("orgc.example", "/w", aud);

        // Bundle the P-256 key, export to JWKS, re-import - the EC branch.
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_p256_key(Some("ec1".into()), &pk).unwrap();
        let jwks = bundle.to_jwks().unwrap();

        let mut bridge = FederationBridge::new();
        bridge
            .add_domain_from_jwks("orgc.example", &jwks, TrustLevel::SelfAsserted)
            .unwrap();

        let fed = bridge.validate(&jwt, Some(aud)).unwrap();
        assert_eq!(fed.trust_domain, "orgc.example");
        assert_eq!(fed.trust_level, TrustLevel::SelfAsserted);
    }

    #[test]
    fn trusted_domains_reports_exactly_what_was_federated() {
        // MUTATION-DRIVEN. `trusted_domains()` could be replaced with an empty vec -
        // or with `vec!["xyzzy"]` - and nothing failed. It is the accessor an operator
        // (or console) uses to answer "who do we federate with?", so an answer of
        // nothing, or of a domain that was never added, must be a test failure and not
        // merely wrong.
        let mut bridge = FederationBridge::new();
        assert!(
            bridge.trusted_domains().is_empty(),
            "a fresh bridge federates nobody"
        );

        let bundle_a = SpiffeTrustBundle::new();
        let bundle_b = SpiffeTrustBundle::new();
        bridge.add_domain("orga.example", bundle_a, TrustLevel::Verified);
        bridge.add_domain("orgb.example", bundle_b, TrustLevel::SelfAsserted);

        let mut domains = bridge.trusted_domains();
        domains.sort_unstable();
        assert_eq!(
            domains,
            vec!["orga.example", "orgb.example"],
            "exactly the federated domains - no more, no fewer, none invented"
        );
    }
}
