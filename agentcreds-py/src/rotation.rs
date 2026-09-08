use chrono::{DateTime, Utc};
use pyo3::prelude::*;

use agentcreds_core::rotation::{KeyHistory, RotationStatement};

use crate::error::map_err;
use crate::identity::PyTrustAnchor;

/// A signed endorsement by an outgoing anchor key of its successor.
#[pyclass(name = "RotationStatement", module = "agentcreds")]
#[derive(Clone)]
pub struct PyRotationStatement {
    pub inner: RotationStatement,
}

#[pymethods]
impl PyRotationStatement {
    /// Issue a statement: ``old`` signs an endorsement of ``next`` (effective now).
    #[staticmethod]
    fn issue(old: &PyTrustAnchor, next: &PyTrustAnchor) -> PyResult<Self> {
        Ok(Self {
            inner: RotationStatement::issue(&old.inner, &next.inner).map_err(map_err)?,
        })
    }

    /// Verify the statement is authentically signed by the outgoing key.
    fn verify(&self) -> PyResult<()> {
        self.inner.verify().map_err(map_err)
    }

    #[getter]
    fn previous_did(&self) -> String {
        self.inner.previous_did.clone()
    }
    #[getter]
    fn next_did(&self) -> String {
        self.inner.next_did.clone()
    }
    #[getter]
    fn effective_at(&self) -> String {
        self.inner.effective_at.to_rfc3339()
    }
    #[getter]
    fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("SerializationError: {e}"))
        })
    }

    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: serde_json::from_str(s).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("SerializationError: {e}"))
            })?,
        })
    }
}

/// The chain of rotation statements from an anchor's original key to its current.
#[pyclass(name = "KeyHistory", module = "agentcreds")]
pub struct PyKeyHistory {
    pub inner: KeyHistory,
}

#[pymethods]
impl PyKeyHistory {
    /// A new history rooted at ``root_did``.
    #[new]
    fn new(root_did: String) -> Self {
        Self {
            inner: KeyHistory::new(root_did),
        }
    }

    /// A new history rooted at ``anchor``'s DID.
    #[staticmethod]
    fn genesis(anchor: &PyTrustAnchor) -> Self {
        Self {
            inner: KeyHistory::genesis(&anchor.inner),
        }
    }

    /// Append a rotation (must chain from the current key and verify).
    fn push(&mut self, statement: &PyRotationStatement) -> PyResult<()> {
        self.inner.push(statement.inner.clone()).map_err(map_err)
    }

    /// The current (latest) anchor DID in the chain.
    fn current_did(&self) -> String {
        self.inner.current_did().to_string()
    }

    /// Verify the chain from ``trusted_root_did`` and return the current DID.
    fn verify(&self, trusted_root_did: &str) -> PyResult<String> {
        self.inner.verify(trusted_root_did).map_err(map_err)
    }

    /// Verify the chain and return a verify-only ``TrustAnchor`` for the current key.
    fn current_anchor(&self, trusted_root_did: &str) -> PyResult<PyTrustAnchor> {
        Ok(PyTrustAnchor {
            inner: self
                .inner
                .current_anchor(trusted_root_did)
                .map_err(map_err)?,
        })
    }

    /// Every anchor DID the organization legitimately held (root + successors).
    fn dids(&self) -> Vec<String> {
        self.inner.dids()
    }

    /// Verify the chain and confirm ``issuer_did`` is in the history, returning a
    /// verify-only ``TrustAnchor`` for it (use to verify a credential's issuer).
    /// Withdraw `did` from issuance. Re-seal afterwards or the change is unsigned.
    fn repudiate(&mut self, did: &str) -> PyResult<()> {
        self.inner.repudiate(did).map_err(map_err)
    }

    /// Seal the history: the **current** key signs the chain, repudiations and expiry.
    /// `not_after` is an aware ``datetime``; ``None`` for an unbounded seal.
    #[pyo3(signature = (current, version, not_after=None))]
    fn seal(
        &mut self,
        current: &PyTrustAnchor,
        version: u64,
        not_after: Option<DateTime<Utc>>,
    ) -> PyResult<()> {
        self.inner
            .seal(&current.inner, version, not_after)
            .map_err(map_err)
    }

    /// Whether the sealed history is still inside its validity window.
    fn is_current(&self) -> bool {
        self.inner.is_current()
    }

    /// Verify the chain **and** the seal under the current key. Authenticity only -
    /// see :meth:`verify_current` for the fail-safe check.
    fn verify_sealed(&self, trusted_root_did: &str) -> PyResult<String> {
        self.inner.verify_sealed(trusted_root_did).map_err(map_err)
    }

    /// Verify authenticity **and** freshness - what a relying party should use.
    fn verify_current(&self, trusted_root_did: &str) -> PyResult<String> {
        self.inner.verify_current(trusted_root_did).map_err(map_err)
    }

    /// The DIDs still trusted for issuance (the chain minus the repudiations).
    fn active_dids(&self) -> Vec<String> {
        self.inner.active_dids()
    }

    /// The DIDs withdrawn from issuance.
    #[getter]
    fn repudiated(&self) -> Vec<String> {
        self.inner.repudiated.clone()
    }

    /// The sealed expiry (rfc3339), or None if unbounded.
    #[getter]
    fn not_after(&self) -> Option<String> {
        self.inner.not_after.map(|t| t.to_rfc3339())
    }

    /// The seal version.
    #[getter]
    fn version(&self) -> u64 {
        self.inner.version
    }

    fn authorize_issuer(
        &self,
        trusted_root_did: &str,
        issuer_did: &str,
    ) -> PyResult<PyTrustAnchor> {
        Ok(PyTrustAnchor {
            inner: self
                .inner
                .authorize_issuer(trusted_root_did, issuer_did)
                .map_err(map_err)?,
        })
    }

    /// Serialize the history to JSON (the portable artifact relying parties follow).
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a history from JSON.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: KeyHistory::from_json(s).map_err(map_err)?,
        })
    }
}
