use pyo3::prelude::*;

use agentcreds_core::compliance::{EvidenceBundle, EvidenceReport};

use crate::adr::{PyAdrCheckpoint, PyAuthzDecision};
use crate::audit::PyAuditCompositor;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;

/// The summary returned by a successful ``EvidenceBundle.verify``.
#[pyclass(name = "EvidenceReport", module = "agentcreds")]
#[derive(Clone)]
pub struct PyEvidenceReport {
    inner: EvidenceReport,
}

#[pymethods]
impl PyEvidenceReport {
    #[getter]
    fn correlation_id(&self) -> String {
        self.inner.correlation_id.clone()
    }
    #[getter]
    fn decisions(&self) -> usize {
        self.inner.decisions
    }
    #[getter]
    fn allowed(&self) -> usize {
        self.inner.allowed
    }
    #[getter]
    fn denied(&self) -> usize {
        self.inner.denied
    }
    #[getter]
    fn signals(&self) -> Vec<String> {
        self.inner
            .signals
            .iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }
    #[getter]
    fn checkpoint_verified(&self) -> bool {
        self.inner.checkpoint_verified
    }
    #[getter]
    fn custody_entries(&self) -> usize {
        self.inner.custody_entries
    }

    fn __repr__(&self) -> String {
        format!(
            "EvidenceReport(decisions={}, allowed={}, denied={}, checkpoint_verified={})",
            self.inner.decisions,
            self.inner.allowed,
            self.inner.denied,
            self.inner.checkpoint_verified,
        )
    }
}

/// A signed, self-verifying compliance export of the authorization decisions
/// (and optional chain-of-custody) for a delegation flow.
#[pyclass(name = "EvidenceBundle", module = "agentcreds")]
pub struct PyEvidenceBundle {
    inner: EvidenceBundle,
}

#[pymethods]
impl PyEvidenceBundle {
    /// Seal and sign a bundle with ``anchor`` for the flow ``correlation_id``
    /// (the root ``vc_id``), including ``decisions`` and, optionally, the
    /// ``subject_did``, a stream ``checkpoint``, and the chain-of-custody from an
    /// ``AuditCompositor``.
    #[staticmethod]
    #[pyo3(signature = (anchor, correlation_id, decisions, subject_did=None, checkpoint=None, compositor=None))]
    fn seal(
        anchor: &PyTrustAnchor,
        correlation_id: String,
        decisions: Vec<PyAuthzDecision>,
        subject_did: Option<String>,
        checkpoint: Option<PyAdrCheckpoint>,
        compositor: Option<PyRef<'_, PyAuditCompositor>>,
    ) -> PyResult<Self> {
        let mut builder = EvidenceBundle::builder(correlation_id)
            .decisions(decisions.into_iter().map(|d| d.inner).collect());
        if let Some(s) = subject_did {
            builder = builder.subject(s);
        }
        if let Some(cp) = checkpoint {
            builder = builder.stream_checkpoint(cp.inner);
        }
        if let Some(comp) = compositor {
            builder = builder.custody_from(&comp.inner);
        }
        Ok(Self {
            inner: builder.seal(&anchor.inner).map_err(map_err)?,
        })
    }

    /// Verify the bundle against ``anchor`` and return an ``EvidenceReport``.
    fn verify(&self, anchor: &PyTrustAnchor) -> PyResult<PyEvidenceReport> {
        Ok(PyEvidenceReport {
            inner: self.inner.verify(&anchor.inner).map_err(map_err)?,
        })
    }

    #[getter]
    fn bundle_id(&self) -> String {
        self.inner.bundle_id.clone()
    }
    #[getter]
    fn generated_at(&self) -> String {
        self.inner.generated_at.to_rfc3339()
    }
    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[getter]
    fn correlation_id(&self) -> String {
        self.inner.correlation_id.clone()
    }
    #[getter]
    fn subject_did(&self) -> Option<String> {
        self.inner.subject_did.clone()
    }
    #[getter]
    fn decisions_head(&self) -> String {
        self.inner.decisions_head.clone()
    }
    #[getter]
    fn custody_root(&self) -> Option<String> {
        self.inner.custody_root.clone()
    }
    #[getter]
    fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// The decision records included in the bundle.
    fn decisions(&self) -> Vec<PyAuthzDecision> {
        self.inner
            .decisions
            .iter()
            .cloned()
            .map(|inner| PyAuthzDecision { inner })
            .collect()
    }

    /// The bundle as a JSON string (the export artifact).
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a bundle from its JSON string.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: EvidenceBundle::from_json(s).map_err(map_err)?,
        })
    }
}
