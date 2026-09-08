use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::principal::HumanIdentity as CoreHumanIdentity;
use agentcreds_core::vc::AuthoritySource;

use crate::credential::HumanAuthorization;
use crate::error::{invalid_arg, map_err};

/// A human principal's stable DID, minted from their IdP identity at issuance.
///
/// The human authenticates through the IdP and holds no key here; the DID is a
/// deterministic, resolvable identifier derived from `(issuer, subject)`.
#[napi]
pub struct HumanIdentity {
    pub(crate) inner: CoreHumanIdentity,
}

#[napi]
impl HumanIdentity {
    /// Mint a stable `did:web` for a human from their validated IdP identity.
    #[napi(factory)]
    pub fn from_idp(issuer: String, subject: String) -> Result<Self> {
        Ok(Self {
            inner: CoreHumanIdentity::from_idp(&issuer, &subject).map_err(map_err)?,
        })
    }

    /// Mint a stable `did:web` for a **workload** from its verified SPIFFE ID.
    ///
    /// `did:web:<trust-domain>:w:<fingerprint>` - `:w:` distinguishes it from the `:u:`
    /// of a human, so the two can never collide in the identifier space.
    ///
    /// The SVID must already have been verified against the trust domain's bundle. This
    /// does **not** make the workload an accountable party: a service cannot answer for
    /// an action, only the team that operates it can.
    #[napi(factory)]
    pub fn from_spiffe(spiffe_id: String) -> Result<Self> {
        Ok(Self {
            inner: CoreHumanIdentity::from_spiffe(&spiffe_id).map_err(map_err)?,
        })
    }

    /// `"human"` or `"workload"` - which root attested this identity.
    #[napi(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind().as_str().to_string()
    }

    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.issuer().to_string()
    }

    #[napi(getter)]
    pub fn subject(&self) -> String {
        self.inner.subject().to_string()
    }

    /// Build a `HumanAuthorization` for this principal, granted now and expiring
    /// at `expiresAt`. `scopeConsented` (tool ids) and `resourceAuthority`
    /// (resource patterns) default to empty.
    #[napi]
    pub fn authorize(
        &self,
        expires_at: DateTime<Utc>,
        scope_consented: Option<Vec<String>>,
        resource_authority: Option<Vec<String>>,
        source: Option<String>,
    ) -> Result<HumanAuthorization> {
        let source = match source.as_deref() {
            None => AuthoritySource::default(),
            Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
                invalid_arg(&format!(
                    "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
                ))
            })?,
        };
        Ok(HumanAuthorization::from_core(self.inner.authorize_now(
            expires_at,
            scope_consented.unwrap_or_default(),
            resource_authority.unwrap_or_default(),
            source,
        )))
    }
}
