use pyo3::prelude::*;

use agentcreds_core::spiffe::{self, SpiffeId, SpiffeTrustBundle, ValidatedSvid};

use crate::credential::PyCapabilityCredential;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;

/// A parsed SPIFFE ID (`spiffe://<trust_domain><path>`).
#[pyclass(name = "SpiffeId", module = "agentcreds")]
#[derive(Clone)]
pub struct PySpiffeId {
    pub inner: SpiffeId,
}

#[pymethods]
impl PySpiffeId {
    /// Parse a SPIFFE ID from its `spiffe://...` URI form.
    #[staticmethod]
    fn parse(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: SpiffeId::parse(s).map_err(map_err)?,
        })
    }

    #[getter]
    fn trust_domain(&self) -> String {
        self.inner.trust_domain.clone()
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path.clone()
    }

    fn uri(&self) -> String {
        self.inner.uri()
    }

    fn __repr__(&self) -> String {
        format!("SpiffeId('{}')", self.inner.uri())
    }
}

/// A successfully validated JWT-SVID.
#[pyclass(name = "ValidatedSvid", module = "agentcreds")]
#[derive(Clone)]
pub struct PyValidatedSvid {
    pub inner: ValidatedSvid,
}

#[pymethods]
impl PyValidatedSvid {
    #[getter]
    fn spiffe_id(&self) -> PySpiffeId {
        PySpiffeId {
            inner: self.inner.spiffe_id.clone(),
        }
    }

    /// SVID expiry as an RFC 3339 timestamp string.
    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }
}

/// The set of public keys for a SPIFFE trust domain, used to validate JWT-SVIDs.
#[pyclass(name = "SpiffeTrustBundle", module = "agentcreds")]
pub struct PySpiffeTrustBundle {
    inner: SpiffeTrustBundle,
}

#[pymethods]
impl PySpiffeTrustBundle {
    #[new]
    fn new() -> Self {
        Self {
            inner: SpiffeTrustBundle::new(),
        }
    }

    /// Add an Ed25519 (`EdDSA`) trust-domain key (32 bytes), optionally by `kid`.
    #[pyo3(signature = (public_key, kid=None))]
    fn add_ed25519_key(&mut self, public_key: &[u8], kid: Option<String>) -> PyResult<()> {
        self.inner.add_ed25519_key(kid, public_key).map_err(map_err)
    }

    /// Add a P-256 (`ES256`) trust-domain key (SEC1 bytes), optionally by `kid`.
    #[pyo3(signature = (public_key, kid=None))]
    fn add_p256_key(&mut self, public_key: &[u8], kid: Option<String>) -> PyResult<()> {
        self.inner.add_p256_key(kid, public_key).map_err(map_err)
    }

    /// Validate a JWT-SVID against this bundle, optionally requiring `expected_audience`.
    #[pyo3(signature = (jwt, expected_audience=None))]
    fn validate_jwt_svid(
        &self,
        jwt: &str,
        expected_audience: Option<String>,
    ) -> PyResult<PyValidatedSvid> {
        let svid = self
            .inner
            .validate_jwt_svid(jwt, expected_audience.as_deref())
            .map_err(map_err)?;
        Ok(PyValidatedSvid { inner: svid })
    }

    /// Export this bundle as a JWKS document (the portable WIMSE trust-bundle
    /// exchange form) for peers to import.
    fn to_jwks(&self) -> PyResult<String> {
        self.inner.to_jwks().map_err(map_err)
    }

    /// Import a trust bundle from a peer's JWKS document.
    #[staticmethod]
    fn from_jwks(jwks: &str) -> PyResult<Self> {
        Ok(Self {
            inner: SpiffeTrustBundle::from_jwks(jwks).map_err(map_err)?,
        })
    }
}

/// Issue a capability credential to `agent_did`, gated on a validated SVID
/// (its SPIFFE ID is recorded as the credential's `authorized_by` provenance).
#[pyfunction]
#[pyo3(signature = (anchor, agent_did, svid, tools, max_delegation_depth, valid_for_secs))]
pub fn issue_from_svid(
    anchor: &PyTrustAnchor,
    agent_did: &str,
    svid: &PyValidatedSvid,
    tools: Vec<String>,
    max_delegation_depth: u32,
    valid_for_secs: u64,
) -> PyResult<PyCapabilityCredential> {
    let vc = spiffe::issue_from_svid(
        &anchor.inner,
        agent_did,
        &svid.inner,
        tools,
        max_delegation_depth,
        valid_for_secs,
    )
    .map_err(map_err)?;
    Ok(PyCapabilityCredential { inner: vc })
}
