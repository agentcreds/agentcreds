use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::audit::{AuditCommitment, AuditCompositor, AuditLog, AuditRecord};

use crate::error::map_err;
use crate::identity::PyTrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(format!("SerializationError: {e}"))
}

/// An org's private, append-only audit log for one correlation id. Only the
/// signed commitments (from ``export``) are ever shared.
#[pyclass(name = "AuditLog", module = "agentcreds")]
pub struct PyAuditLog {
    inner: AuditLog,
}

#[pymethods]
impl PyAuditLog {
    #[new]
    fn new(correlation_id: String, org_id: String) -> Self {
        Self {
            inner: AuditLog::new(correlation_id, org_id),
        }
    }

    /// Append an action; returns its per-org sequence number.
    fn record(&mut self, agent_did: String, action: String, outcome: String) -> u64 {
        self.inner.record(agent_did, action, outcome)
    }

    /// Export signed commitments to share, as a JSON array string.
    fn export(&self, anchor: &PyTrustAnchor) -> PyResult<String> {
        let commitments = self.inner.export(&anchor.inner).map_err(map_err)?;
        serde_json::to_string(&commitments).map_err(ser_err)
    }

    /// Selectively reveal one raw record as a JSON string (or ``None``).
    fn reveal(&self, seq: u64) -> PyResult<Option<String>> {
        match self.inner.reveal(seq) {
            Some(r) => Ok(Some(serde_json::to_string(r).map_err(ser_err)?)),
            None => Ok(None),
        }
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }
}

/// Merges multiple orgs' commitments into one verifiable, ordered
/// chain-of-custody - without seeing raw logs.
#[pyclass(name = "AuditCompositor", module = "agentcreds")]
pub struct PyAuditCompositor {
    pub inner: AuditCompositor,
}

#[pymethods]
impl PyAuditCompositor {
    #[new]
    fn new(correlation_id: String) -> Self {
        Self {
            inner: AuditCompositor::new(correlation_id),
        }
    }

    /// Ingest one org's exported commitments (the JSON from ``AuditLog.export``),
    /// verifying every signature against ``org_anchor``.
    fn ingest(&mut self, commitments_json: &str, org_anchor: &PyTrustAnchor) -> PyResult<()> {
        let commitments: Vec<AuditCommitment> =
            serde_json::from_str(commitments_json).map_err(ser_err)?;
        self.inner
            .ingest(&commitments, &org_anchor.inner)
            .map_err(map_err)
    }

    /// The merged chain-of-custody as a JSON array string.
    fn chain_of_custody(&self) -> PyResult<String> {
        serde_json::to_string(self.inner.chain_of_custody()).map_err(ser_err)
    }

    /// A single tamper-evident digest over the whole ordered chain.
    fn root_hash(&self) -> String {
        self.inner.root_hash()
    }

    /// Verify a selectively-revealed record (the JSON from ``AuditLog.reveal``)
    /// against the composited commitment.
    fn verify_revealed(&self, record_json: &str) -> PyResult<bool> {
        let record: AuditRecord = serde_json::from_str(record_json).map_err(ser_err)?;
        self.inner.verify_revealed(&record).map_err(map_err)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }
}
