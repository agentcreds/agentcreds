use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::oidc::{
    self, OidcProvider as CoreOidcProvider, VerifiedHumanPrincipal as CoreVerifiedHumanPrincipal,
};

use crate::credential::CapabilityCredential;
use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;
use crate::principal::HumanIdentity;
use agentcreds_core::vc::AuthoritySource;

/// A human principal whose identity an IdP cryptographically attested.
#[napi]
pub struct VerifiedHumanPrincipal {
    pub(crate) inner: CoreVerifiedHumanPrincipal,
}

#[napi]
impl VerifiedHumanPrincipal {
    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[napi(getter)]
    pub fn subject(&self) -> String {
        self.inner.subject.clone()
    }

    #[napi(getter)]
    pub fn email(&self) -> Option<String> {
        self.inner.email.clone()
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }

    #[napi(getter)]
    pub fn scope(&self) -> Vec<String> {
        self.inner.scope.clone()
    }

    /// The actor (`act.sub`) for an RFC 8693 on-behalf-of token, if present.
    #[napi(getter)]
    pub fn acted_by(&self) -> Option<String> {
        self.inner.acted_by.clone()
    }

    /// Mint this principal's stable DID from its IdP identity.
    #[napi]
    pub fn human_identity(&self) -> Result<HumanIdentity> {
        Ok(HumanIdentity {
            inner: self.inner.human_identity().map_err(map_err)?,
        })
    }
}

/// An OpenID Connect provider the org trusts, used to validate human ID tokens.
#[napi]
pub struct OidcProvider {
    inner: CoreOidcProvider,
}

#[napi]
impl OidcProvider {
    /// Build a provider for `issuer` (the IdP's `iss`) and `audience` (your
    /// client id). `leewaySecs` is the allowed clock skew for `exp`/`nbf`
    /// (default 60).
    #[napi(constructor)]
    pub fn new(issuer: String, audience: String, leeway_secs: Option<i64>) -> Self {
        Self {
            inner: CoreOidcProvider::new(issuer, audience).with_leeway(leeway_secs.unwrap_or(60)),
        }
    }

    /// Add an Ed25519 (`EdDSA`) signing key (32 bytes), optionally by `kid`.
    #[napi]
    pub fn add_ed25519_key(&mut self, public_key: Buffer, kid: Option<String>) -> Result<()> {
        self.inner
            .add_ed25519_key(kid, public_key.as_ref())
            .map_err(map_err)
    }

    /// Add a P-256 (`ES256`) signing key (SEC1 bytes), optionally by `kid`.
    #[napi]
    pub fn add_p256_key(&mut self, public_key: Buffer, kid: Option<String>) -> Result<()> {
        self.inner
            .add_p256_key(kid, public_key.as_ref())
            .map_err(map_err)
    }

    /// Add an RSA (`RS256`) signing key from JWKS `n`/`e` (base64url), by `kid`.
    #[napi]
    pub fn add_rsa_key(&mut self, n: String, e: String, kid: Option<String>) -> Result<()> {
        self.inner.add_rsa_key(kid, &n, &e).map_err(map_err)
    }

    /// Import the provider's signing keys from its JWKS document.
    #[napi]
    pub fn add_keys_from_jwks(&mut self, jwks: String) -> Result<()> {
        self.inner.add_keys_from_jwks(&jwks).map_err(map_err)
    }

    /// Validate an OIDC ID token (or RFC 8693 OBO token) and return the verified
    /// human principal. If `expectedAgentDid` is given and the token carries an
    /// `act` actor, they must match; `expectedNonce` is checked when supplied.
    #[napi]
    pub fn validate_id_token(
        &self,
        id_token: String,
        expected_agent_did: Option<String>,
        expected_nonce: Option<String>,
    ) -> Result<VerifiedHumanPrincipal> {
        let principal = self
            .inner
            .validate_id_token(
                &id_token,
                expected_agent_did.as_deref(),
                expected_nonce.as_deref(),
            )
            .map_err(map_err)?;
        Ok(VerifiedHumanPrincipal { inner: principal })
    }
}

/// Issue a capability credential to `agentDid`, bound to a verified human
/// principal. The credential's validity is capped at the human's authorization
/// expiry; `tools` are the granted (and recorded-as-consented) capabilities and
/// `resourceAuthority` bounds which resources the agent may be scoped to.
#[napi]
pub fn issue_on_behalf_of(
    anchor: &TrustAnchor,
    agent_did: String,
    principal: &VerifiedHumanPrincipal,
    tools: Vec<String>,
    resource_authority: Vec<String>,
    max_delegation_depth: u32,
    valid_for_secs: i64,
    resource_source: Option<String>,
) -> Result<CapabilityCredential> {
    if valid_for_secs < 0 {
        return Err(invalid_arg("valid_for_secs must be non-negative"));
    }
    let resource_source = match resource_source.as_deref() {
        None => AuthoritySource::default(),
        Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
            invalid_arg(&format!(
                "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
            ))
        })?,
    };
    let vc = oidc::issue_on_behalf_of(
        &anchor.inner,
        &agent_did,
        &principal.inner,
        tools,
        resource_authority,
        resource_source,
        max_delegation_depth,
        valid_for_secs as u64,
    )
    .map_err(map_err)?;
    Ok(CapabilityCredential { inner: vc })
}
