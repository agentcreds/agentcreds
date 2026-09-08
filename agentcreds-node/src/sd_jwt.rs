use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::sd_jwt::{self, DisclosedCredential as CoreDisclosed, SdJwt as CoreSdJwt};

use crate::credential::CapabilityClaims;
use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;

/// An SD-JWT capability credential in compact form. The issuer hands the whole
/// thing to the holder; the holder calls `present` to reveal a subset.
#[napi]
pub struct SdJwt {
    inner: CoreSdJwt,
}

#[napi]
impl SdJwt {
    /// Issue an SD-JWT whose disclosable claims are the fields of `claims`
    /// (tools, budget, depth, autonomy, and the optional model/artifact/
    /// authorizer fields when present).
    #[napi(factory)]
    pub fn from_capability(
        anchor: &TrustAnchor,
        subject_did: String,
        claims: &CapabilityClaims,
        valid_for_secs: i64,
    ) -> Result<Self> {
        if valid_for_secs < 0 {
            return Err(invalid_arg("valid_for_secs must be non-negative"));
        }
        Ok(Self {
            inner: CoreSdJwt::from_capability(
                &anchor.inner,
                &subject_did,
                &claims.inner,
                valid_for_secs as u64,
            )
            .map_err(map_err)?,
        })
    }

    /// Parse a compact SD-JWT (e.g. one received from an issuer).
    #[napi(factory)]
    pub fn parse(s: String) -> Result<Self> {
        Ok(Self {
            inner: CoreSdJwt::parse(&s).map_err(map_err)?,
        })
    }

    /// The full compact serialization to hand to the holder.
    #[napi]
    pub fn as_str(&self) -> String {
        self.inner.as_str()
    }

    /// The names of the claims this SD-JWT can disclose.
    #[napi]
    pub fn disclosable_claims(&self) -> Result<Vec<String>> {
        self.inner.disclosable_claims().map_err(map_err)
    }

    /// Holder side: a presentation revealing only the named claims (plus the
    /// always-disclosed registered claims). Unknown names are ignored.
    #[napi]
    pub fn present(&self, disclose: Vec<String>) -> Result<String> {
        let refs: Vec<&str> = disclose.iter().map(String::as_str).collect();
        self.inner.present(&refs).map_err(map_err)
    }

    /// Verifier side: verify a presentation against the issuer `anchor`,
    /// returning the disclosed claims. Throws on a bad signature, expiry, or a
    /// disclosure not covered by the signed `_sd` set.
    #[napi]
    pub fn verify_presentation(
        presentation: String,
        anchor: &TrustAnchor,
    ) -> Result<DisclosedCredential> {
        let inner = sd_jwt::verify_presentation(&presentation, &anchor.inner).map_err(map_err)?;
        Ok(DisclosedCredential { inner })
    }
}

/// The result of verifying an SD-JWT presentation.
#[napi]
pub struct DisclosedCredential {
    inner: CoreDisclosed,
}

#[napi]
impl DisclosedCredential {
    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[napi(getter)]
    pub fn subject(&self) -> String {
        self.inner.subject.clone()
    }

    #[napi(getter)]
    pub fn vct(&self) -> String {
        self.inner.vct.clone()
    }

    #[napi(getter)]
    pub fn issued_at(&self) -> String {
        self.inner.issued_at.to_rfc3339()
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    /// The disclosed claims as a JSON object string (name -> value).
    #[napi(getter)]
    pub fn disclosed_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner.disclosed)
            .map_err(|e| Error::from_reason(format!("SerializationError: {e}")))
    }
}
