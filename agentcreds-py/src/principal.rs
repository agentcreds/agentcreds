use chrono::{DateTime, Utc};
use pyo3::prelude::*;

use agentcreds_core::principal::HumanIdentity;
use agentcreds_core::vc::AuthoritySource;

use crate::credential::PyHumanAuthorization;
use crate::error::map_err;

/// A human principal's stable DID, minted from their IdP identity at issuance.
///
/// The human authenticates through the IdP and holds no key here; the DID is a
/// deterministic, resolvable identifier derived from `(issuer, subject)`.
#[pyclass(name = "HumanIdentity", module = "agentcreds")]
#[derive(Clone)]
pub struct PyHumanIdentity {
    pub inner: HumanIdentity,
}

#[pymethods]
impl PyHumanIdentity {
    /// Mint a stable `did:web` for a human from their validated IdP identity.
    #[staticmethod]
    fn from_idp(issuer: &str, subject: &str) -> PyResult<Self> {
        Ok(Self {
            inner: HumanIdentity::from_idp(issuer, subject).map_err(map_err)?,
        })
    }

    /// Mint a stable `did:web` for a **workload** from its verified SPIFFE ID.
    ///
    /// `did:web:<trust-domain>:w:<fingerprint>` - `:w:` distinguishes it from the `:u:`
    /// of a human, so the two can never collide in the identifier space.
    ///
    /// The SVID must already have been verified against the trust domain's bundle: this
    /// mints an identifier from an attested fact, it does not attest anything itself.
    /// And it does **not** make the workload an accountable party - a service cannot
    /// answer for an action, only the team that operates it can.
    #[staticmethod]
    fn from_spiffe(spiffe_id: &str) -> PyResult<Self> {
        Ok(Self {
            inner: HumanIdentity::from_spiffe(spiffe_id).map_err(map_err)?,
        })
    }

    /// `"human"` or `"workload"` - which root attested this identity.
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind().as_str()
    }

    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer().to_string()
    }

    #[getter]
    fn subject(&self) -> String {
        self.inner.subject().to_string()
    }

    /// Build a `HumanAuthorization` for this principal, granted now and expiring at
    /// `expires_at`. `scope_consented` (tool ids) and `resource_authority` (resource
    /// patterns) default to empty.
    ///
    /// `source` records where those entitlements came from - `"attested"`, `"policy"` or
    /// `"asserted"`. It defaults to `"asserted"`, the weakest reading, because a caller
    /// that does not say has not established anything.
    #[pyo3(signature = (expires_at, scope_consented=Vec::new(), resource_authority=Vec::new(),
                        source=None))]
    fn authorize(
        &self,
        expires_at: DateTime<Utc>,
        scope_consented: Vec<String>,
        resource_authority: Vec<String>,
        source: Option<&str>,
    ) -> PyResult<PyHumanAuthorization> {
        let source = match source {
            None => AuthoritySource::default(),
            Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
                ))
            })?,
        };
        Ok(PyHumanAuthorization {
            inner: self.inner.authorize_now(
                expires_at,
                scope_consented,
                resource_authority,
                source,
            ),
        })
    }

    fn __repr__(&self) -> String {
        format!("HumanIdentity(did='{}')", self.inner.did())
    }
}
