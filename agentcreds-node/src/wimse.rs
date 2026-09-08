use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::wimse::{FederatedIdentity as CoreFed, FederationBridge as CoreBridge};

use crate::convert::{parse_trust_level, trust_level_to_str};
use crate::credential::CapabilityCredential;
use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;

/// A bridge that federates peer SPIFFE trust domains: import each peer's JWKS
/// bundle, then validate SVIDs it signs.
#[napi]
pub struct FederationBridge {
    inner: CoreBridge,
}

impl Default for FederationBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl FederationBridge {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreBridge::new(),
        }
    }

    /// Federate a peer domain by importing its JWKS trust-bundle export.
    /// `trustLevel` is one of `unverified`/`self_asserted`/`verified`/`authoritative`.
    #[napi]
    pub fn add_domain_from_jwks(
        &mut self,
        trust_domain: String,
        jwks: String,
        trust_level: String,
    ) -> Result<()> {
        let level = parse_trust_level(&trust_level)?;
        self.inner
            .add_domain_from_jwks(trust_domain, &jwks, level)
            .map_err(map_err)
    }

    /// The trust domains this bridge federates.
    #[napi]
    pub fn trusted_domains(&self) -> Vec<String> {
        self.inner
            .trusted_domains()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Validate a federated SVID, routing it to its trust domain's bundle.
    #[napi]
    pub fn validate(
        &self,
        jwt_svid: String,
        expected_audience: Option<String>,
    ) -> Result<FederatedIdentity> {
        let fed = self
            .inner
            .validate(&jwt_svid, expected_audience.as_deref())
            .map_err(map_err)?;
        Ok(FederatedIdentity { inner: fed })
    }
}

/// A validated, federated workload identity from a peer trust domain.
#[napi]
pub struct FederatedIdentity {
    inner: CoreFed,
}

#[napi]
impl FederatedIdentity {
    /// The workload's SPIFFE ID, as a `spiffe://...` URI.
    #[napi(getter)]
    pub fn spiffe_id(&self) -> String {
        self.inner.spiffe_id.uri()
    }

    #[napi(getter)]
    pub fn trust_domain(&self) -> String {
        self.inner.trust_domain.clone()
    }

    /// The trust level assigned to the issuing domain.
    #[napi(getter)]
    pub fn trust_level(&self) -> String {
        trust_level_to_str(self.inner.trust_level).to_string()
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    #[napi(getter)]
    pub fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }

    /// Issue a capability credential for this federated workload, signed by the
    /// relying org's own `anchor`.
    #[napi]
    pub fn issue_credential(
        &self,
        anchor: &TrustAnchor,
        agent_did: String,
        tools: Vec<String>,
        max_delegation_depth: u32,
        valid_for_secs: i64,
    ) -> Result<CapabilityCredential> {
        if valid_for_secs < 0 {
            return Err(invalid_arg("valid_for_secs must be non-negative"));
        }
        let vc = self
            .inner
            .issue_credential(
                &anchor.inner,
                &agent_did,
                tools,
                max_delegation_depth,
                valid_for_secs as u64,
            )
            .map_err(map_err)?;
        Ok(CapabilityCredential { inner: vc })
    }
}
