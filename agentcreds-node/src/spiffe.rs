use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::spiffe::{
    self, SpiffeId as CoreSpiffeId, SpiffeTrustBundle as CoreBundle,
    ValidatedSvid as CoreValidatedSvid,
};

use crate::credential::CapabilityCredential;
use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;

/// A parsed SPIFFE ID (`spiffe://<trust_domain><path>`).
#[napi]
pub struct SpiffeId {
    inner: CoreSpiffeId,
}

#[napi]
impl SpiffeId {
    /// Parse a SPIFFE ID from its `spiffe://...` URI form.
    #[napi(factory)]
    pub fn parse(s: String) -> Result<Self> {
        Ok(Self {
            inner: CoreSpiffeId::parse(&s).map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn trust_domain(&self) -> String {
        self.inner.trust_domain.clone()
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.inner.path.clone()
    }

    #[napi]
    pub fn uri(&self) -> String {
        self.inner.uri()
    }
}

/// A successfully validated JWT-SVID.
#[napi]
pub struct ValidatedSvid {
    inner: CoreValidatedSvid,
}

#[napi]
impl ValidatedSvid {
    #[napi(getter)]
    pub fn spiffe_id(&self) -> SpiffeId {
        SpiffeId {
            inner: self.inner.spiffe_id.clone(),
        }
    }

    /// SVID expiry as an RFC 3339 timestamp string.
    #[napi(getter)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    #[napi(getter)]
    pub fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }
}

/// The set of public keys for a SPIFFE trust domain, used to validate JWT-SVIDs.
#[napi]
pub struct SpiffeTrustBundle {
    inner: CoreBundle,
}

impl Default for SpiffeTrustBundle {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl SpiffeTrustBundle {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreBundle::new(),
        }
    }

    /// Add an Ed25519 (`EdDSA`) trust-domain key (32 bytes), optionally by `kid`.
    #[napi]
    pub fn add_ed25519_key(&mut self, public_key: Buffer, kid: Option<String>) -> Result<()> {
        self.inner
            .add_ed25519_key(kid, public_key.as_ref())
            .map_err(map_err)
    }

    /// Add a P-256 (`ES256`) trust-domain key (SEC1 bytes), optionally by `kid`.
    #[napi]
    pub fn add_p256_key(&mut self, public_key: Buffer, kid: Option<String>) -> Result<()> {
        self.inner
            .add_p256_key(kid, public_key.as_ref())
            .map_err(map_err)
    }

    /// Validate a JWT-SVID against this bundle, optionally requiring `expectedAudience`.
    #[napi]
    pub fn validate_jwt_svid(
        &self,
        jwt: String,
        expected_audience: Option<String>,
    ) -> Result<ValidatedSvid> {
        let svid = self
            .inner
            .validate_jwt_svid(&jwt, expected_audience.as_deref())
            .map_err(map_err)?;
        Ok(ValidatedSvid { inner: svid })
    }

    /// Export this bundle as a JWKS document (the portable WIMSE trust-bundle
    /// exchange form) for peers to import.
    #[napi]
    pub fn to_jwks(&self) -> Result<String> {
        self.inner.to_jwks().map_err(map_err)
    }

    /// Import a trust bundle from a peer's JWKS document.
    #[napi(factory)]
    pub fn from_jwks(jwks: String) -> Result<Self> {
        Ok(Self {
            inner: CoreBundle::from_jwks(&jwks).map_err(map_err)?,
        })
    }
}

/// Issue a capability credential to `agentDid`, gated on a validated SVID (its
/// SPIFFE ID is recorded as the credential's `authorizedBy` provenance).
#[napi]
pub fn issue_from_svid(
    anchor: &TrustAnchor,
    agent_did: String,
    svid: &ValidatedSvid,
    tools: Vec<String>,
    max_delegation_depth: u32,
    valid_for_secs: i64,
) -> Result<CapabilityCredential> {
    if valid_for_secs < 0 {
        return Err(invalid_arg("valid_for_secs must be non-negative"));
    }
    let vc = spiffe::issue_from_svid(
        &anchor.inner,
        &agent_did,
        &svid.inner,
        tools,
        max_delegation_depth,
        valid_for_secs as u64,
    )
    .map_err(map_err)?;
    Ok(CapabilityCredential { inner: vc })
}
