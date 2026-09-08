use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::revocation::{RevocationList, RevocationRegistry, DEFAULT_LIST_SIZE};

use crate::error::map_err;
use crate::identity::PyTrustAnchor;

/// Default OAuth Status List size (131,072 entries / 16KB bitstring).
#[pyfunction]
pub fn default_list_size() -> u64 {
    DEFAULT_LIST_SIZE
}

// -- RevocationList ------------------------------------------------------------

#[pyclass(name = "RevocationList", module = "agentcreds")]
#[derive(Clone)]
pub struct PyRevocationList {
    pub inner: RevocationList,
}

#[pymethods]
impl PyRevocationList {
    /// Create a new, empty revocation list published at `id`, signed by `anchor`.
    /// `size` defaults to [`default_list_size`] (131,072 entries).
    #[new]
    #[pyo3(signature = (id, anchor, size=None))]
    fn new(id: &str, anchor: &PyTrustAnchor, size: Option<u64>) -> PyResult<Self> {
        Ok(Self {
            inner: RevocationList::new(id, &anchor.inner, size).map_err(map_err)?,
        })
    }

    /// Deserialise a published revocation list from its JSON form. Call `verify`
    /// against the issuer anchor before trusting it.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        Ok(Self {
            inner: RevocationList::from_json(json).map_err(map_err)?,
        })
    }

    /// Serialize this list to JSON (the published form a relying party fetches).
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse an **OAuth Status List Token** (`typ: statuslist+jwt`) - the form serverd
    /// actually publishes at the credential's `credentialStatus` URL, served with
    /// `Content-Type: application/statuslist+jwt`.
    ///
    /// This is what a Python PEP needs: the token is a JWS, not JSON, so `from_json`
    /// fails on it with `expected value at line 1 column 1`. The core has always had
    /// this parser; it simply was not exposed here, so no Python relying party could
    /// consume a published status list and every revocation check failed closed.
    ///
    /// Call `verify` against the issuer's anchor before trusting the result.
    #[staticmethod]
    fn from_status_list_token(token: &str) -> PyResult<Self> {
        Ok(Self {
            inner: RevocationList::from_status_list_token(token).map_err(map_err)?,
        })
    }

    /// Serialize to an OAuth Status List Token (`statuslist+jwt`) - the published form.
    fn to_status_list_token(&self) -> PyResult<String> {
        self.inner.to_status_list_token().map_err(map_err)
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[getter]
    fn updated(&self) -> DateTime<Utc> {
        self.inner.updated
    }

    #[getter]
    fn size(&self) -> u64 {
        self.inner.size
    }

    #[getter]
    fn encoded_list(&self) -> String {
        self.inner.encoded_list.clone()
    }

    #[getter]
    fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// Revoke the credential at `index`, re-signing the list with `anchor`.
    fn revoke(&mut self, index: u64, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.revoke(index, &anchor.inner).map_err(map_err)
    }

    /// Un-revoke the credential at `index`, re-signing the list with `anchor`.
    fn unrevoke(&mut self, index: u64, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.unrevoke(index, &anchor.inner).map_err(map_err)
    }

    /// True if the credential at `index` is revoked.
    fn is_revoked(&self, index: u64) -> PyResult<bool> {
        self.inner.is_revoked(index).map_err(map_err)
    }

    /// Verify this list's signature against `anchor`.
    fn verify(&self, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// Total number of revoked credentials in this list.
    fn revocation_count(&self) -> PyResult<u64> {
        self.inner.revocation_count().map_err(map_err)
    }

    /// SHA-256 fingerprint of the current list state.
    fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    fn __repr__(&self) -> String {
        format!(
            "RevocationList(id='{}', size={})",
            self.inner.id, self.inner.size
        )
    }
}

// -- RevocationRegistry --------------------------------------------------------

#[pyclass(name = "RevocationRegistry", module = "agentcreds")]
pub struct PyRevocationRegistry {
    pub inner: RevocationRegistry,
}

#[pymethods]
impl PyRevocationRegistry {
    /// Create an empty registry.
    #[new]
    fn new() -> Self {
        Self {
            inner: RevocationRegistry::new(),
        }
    }

    /// Register a revocation list under its ID (URL).
    fn register(&mut self, list: &PyRevocationList) {
        self.inner.register(list.inner.clone());
    }

    /// Look up a revocation list by ID (URL), or `None` if not registered.
    fn get(&self, list_id: &str) -> Option<PyRevocationList> {
        self.inner
            .get(list_id)
            .cloned()
            .map(|inner| PyRevocationList { inner })
    }

    /// Revoke `index` in the list identified by `list_id`, re-signing with `anchor`.
    fn revoke(&mut self, list_id: &str, index: u64, anchor: &PyTrustAnchor) -> PyResult<()> {
        let list = self.inner.get_mut(list_id).ok_or_else(|| {
            PyValueError::new_err(format!("revocation list '{list_id}' not found"))
        })?;
        list.revoke(index, &anchor.inner).map_err(map_err)
    }

    /// Un-revoke `index` in the list identified by `list_id`, re-signing with `anchor`.
    fn unrevoke(&mut self, list_id: &str, index: u64, anchor: &PyTrustAnchor) -> PyResult<()> {
        let list = self.inner.get_mut(list_id).ok_or_else(|| {
            PyValueError::new_err(format!("revocation list '{list_id}' not found"))
        })?;
        list.unrevoke(index, &anchor.inner).map_err(map_err)
    }

    /// Check the revocation status of `credential_id` (raises
    /// `CredentialRevokedError` if revoked, or if `list_id` is unknown).
    fn is_revoked(&self, list_id: &str, index: u64, credential_id: &str) -> PyResult<()> {
        self.inner
            .is_revoked(list_id, index, credential_id)
            .map_err(map_err)
    }

    fn __repr__(&self) -> String {
        "RevocationRegistry()".to_string()
    }
}
