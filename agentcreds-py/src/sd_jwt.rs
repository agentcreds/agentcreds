use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::sd_jwt::{self, DisclosedCredential, SdJwt};

use crate::credential::PyCapabilityClaims;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;

/// An SD-JWT capability credential in compact form. The issuer hands the whole
/// thing to the holder; the holder calls `present` to reveal a subset.
#[pyclass(name = "SdJwt", module = "agentcreds")]
pub struct PySdJwt {
    inner: SdJwt,
}

#[pymethods]
impl PySdJwt {
    /// Issue an SD-JWT whose disclosable claims are the fields of `claims`.
    #[staticmethod]
    fn from_capability(
        anchor: &PyTrustAnchor,
        subject_did: &str,
        claims: &PyCapabilityClaims,
        valid_for_secs: u64,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: SdJwt::from_capability(
                &anchor.inner,
                subject_did,
                &claims.inner,
                valid_for_secs,
            )
            .map_err(map_err)?,
        })
    }

    /// Parse a compact SD-JWT (e.g. one received from an issuer).
    #[staticmethod]
    fn parse(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: SdJwt::parse(s).map_err(map_err)?,
        })
    }

    /// The full compact serialization to hand to the holder.
    fn as_str(&self) -> String {
        self.inner.as_str()
    }

    /// The names of the claims this SD-JWT can disclose.
    fn disclosable_claims(&self) -> PyResult<Vec<String>> {
        self.inner.disclosable_claims().map_err(map_err)
    }

    /// Holder side: a presentation revealing only the named claims (plus the
    /// always-disclosed registered claims). Unknown names are ignored.
    fn present(&self, disclose: Vec<String>) -> PyResult<String> {
        let refs: Vec<&str> = disclose.iter().map(String::as_str).collect();
        self.inner.present(&refs).map_err(map_err)
    }

    /// Verifier side: verify a presentation against the issuer `anchor`,
    /// returning the disclosed claims. Raises on a bad signature, expiry, or a
    /// disclosure not covered by the signed `_sd` set.
    #[staticmethod]
    fn verify_presentation(
        presentation: &str,
        anchor: &PyTrustAnchor,
    ) -> PyResult<PyDisclosedCredential> {
        let inner = sd_jwt::verify_presentation(presentation, &anchor.inner).map_err(map_err)?;
        Ok(PyDisclosedCredential { inner })
    }
}

/// The result of verifying an SD-JWT presentation.
#[pyclass(name = "DisclosedCredential", module = "agentcreds")]
pub struct PyDisclosedCredential {
    inner: DisclosedCredential,
}

#[pymethods]
impl PyDisclosedCredential {
    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[getter]
    fn subject(&self) -> String {
        self.inner.subject.clone()
    }

    #[getter]
    fn vct(&self) -> String {
        self.inner.vct.clone()
    }

    #[getter]
    fn issued_at(&self) -> String {
        self.inner.issued_at.to_rfc3339()
    }

    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    /// The disclosed claims as a JSON object string (name -> value).
    #[getter]
    fn disclosed_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.disclosed)
            .map_err(|e| PyValueError::new_err(format!("SerializationError: {e}")))
    }
}
