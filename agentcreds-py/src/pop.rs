use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use agentcreds_core::pop::{PopChallenge, Presentation, ProofOfPossession};

use crate::credential::PyCapabilityCredential;
use crate::delegation::{PyAction, PyDelegationToken};
use crate::error::map_err;
use crate::identity::{PyAgentIdentity, PyTrustAnchor};

// -- PopChallenge --------------------------------------------------------------

#[pyclass(name = "PopChallenge", module = "agentcreds")]
#[derive(Clone)]
pub struct PyPopChallenge {
    pub inner: PopChallenge,
}

#[pymethods]
impl PyPopChallenge {
    /// Create a fresh challenge with a random nonce. `audience` optionally binds
    /// the proof to a specific verifier (e.g. an MCP server URI).
    #[new]
    #[pyo3(signature = (audience=None))]
    fn new(audience: Option<String>) -> Self {
        Self {
            inner: PopChallenge::new(audience),
        }
    }

    #[getter]
    fn nonce<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.nonce)
    }

    #[getter]
    fn audience(&self) -> Option<String> {
        self.inner.audience.clone()
    }

    #[getter]
    fn issued_at(&self) -> DateTime<Utc> {
        self.inner.issued_at
    }

    /// Return a copy of this challenge bound to a specific request (pass
    /// `Action.request_binding`). The holder signs the bound challenge, so the
    /// resulting presentation is valid only for that exact action.
    fn with_request_binding(&self, binding: String) -> Self {
        Self {
            inner: self.inner.with_request_binding(binding),
        }
    }

    /// Serialize to CBOR for wire transport.
    fn to_cbor<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_cbor().map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Deserialise a challenge from CBOR bytes.
    #[staticmethod]
    fn from_cbor(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: PopChallenge::from_cbor(bytes).map_err(map_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!("PopChallenge(audience={:?})", self.inner.audience)
    }
}

// -- ProofOfPossession ---------------------------------------------------------

#[pyclass(name = "ProofOfPossession", module = "agentcreds")]
#[derive(Clone)]
pub struct PyProofOfPossession {
    pub inner: ProofOfPossession,
}

#[pymethods]
impl PyProofOfPossession {
    #[getter]
    fn leaf_did(&self) -> String {
        self.inner.leaf_did.clone()
    }

    /// Verify this proof against `token` and the `challenge` the verifier
    /// issued, within `max_age_secs`. Raises on failure.
    fn verify(
        &self,
        token: &PyDelegationToken,
        challenge: &PyPopChallenge,
        max_age_secs: i64,
    ) -> PyResult<()> {
        self.inner
            .verify(&token.inner, &challenge.inner, max_age_secs)
            .map_err(map_err)
    }

    /// Serialize to CBOR for wire transport.
    fn to_cbor<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_cbor().map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Deserialise a proof from CBOR bytes.
    #[staticmethod]
    fn from_cbor(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: ProofOfPossession::from_cbor(bytes).map_err(map_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!("ProofOfPossession(leaf_did='{}')", self.inner.leaf_did)
    }
}

// -- Presentation (MCP wire envelope) ------------------------------------------

#[pyclass(name = "Presentation", module = "agentcreds")]
#[derive(Clone)]
pub struct PyPresentation {
    pub inner: Presentation,
}

#[pymethods]
impl PyPresentation {
    /// The delegation token being presented (e.g. for audit via `chain()`).
    #[getter]
    fn token(&self) -> PyDelegationToken {
        PyDelegationToken {
            inner: self.inner.token.clone(),
        }
    }

    /// The credential the token's root is derived from.
    #[getter]
    fn credential(&self) -> PyCapabilityCredential {
        PyCapabilityCredential {
            inner: self.inner.credential.clone(),
        }
    }

    /// Whether this presentation's proof is bound to a specific request. A
    /// verifier requiring per-request binding should reject presentations for
    /// which this is False.
    #[getter]
    fn is_action_bound(&self) -> bool {
        self.inner.is_action_bound()
    }

    /// Assemble a presentation (holder side): mints the proof of possession for
    /// `challenge` using `leaf_agent` and bundles it with the token and its
    /// backing credential.
    #[staticmethod]
    fn create(
        token: &PyDelegationToken,
        credential: &PyCapabilityCredential,
        challenge: &PyPopChallenge,
        leaf_agent: &PyAgentIdentity,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: Presentation::create(
                token.inner.clone(),
                credential.inner.clone(),
                &challenge.inner,
                &leaf_agent.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Verify the full presentation (verifier side): anchor-rooted token
    /// verification plus proof of possession. Raises on failure.
    fn verify(
        &self,
        action: &PyAction,
        anchor: &PyTrustAnchor,
        challenge: &PyPopChallenge,
        max_age_secs: i64,
    ) -> PyResult<()> {
        self.inner
            .verify(&action.inner, &anchor.inner, &challenge.inner, max_age_secs)
            .map_err(map_err)
    }

    /// `verify`, evaluated **as of** `epoch_seconds` rather than the wall clock. One
    /// instant governs the credential, every hop, the Datalog time check and the
    /// proof's freshness window.
    ///
    /// **Not the enforcement path** - a relying party deciding in real time calls
    /// `verify`. This exists for audit re-verification and for golden vectors that must
    /// outlive the one-hour token lifetime the autonomy ladder permits.
    fn verify_at(
        &self,
        action: &PyAction,
        anchor: &PyTrustAnchor,
        challenge: &PyPopChallenge,
        max_age_secs: i64,
        epoch_seconds: i64,
    ) -> PyResult<()> {
        let now = chrono::DateTime::from_timestamp(epoch_seconds, 0)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("epoch_seconds out of range"))?;
        self.inner
            .verify_at(
                &action.inner,
                &anchor.inner,
                &challenge.inner,
                max_age_secs,
                now,
            )
            .map_err(map_err)
    }

    /// Serialize to CBOR for wire transport.
    fn to_cbor<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_cbor().map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Deserialise a presentation from CBOR bytes.
    #[staticmethod]
    fn from_cbor(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Presentation::from_cbor(bytes).map_err(map_err)?,
        })
    }

    /// Encode this presentation as an A2A identity header string
    /// (`AgentCreds-A2A/1.<base64url>`), suitable for an A2A task header.
    fn to_a2a_header(&self) -> PyResult<String> {
        self.inner.to_a2a_header().map_err(map_err)
    }

    /// Decode an A2A identity header string back into a presentation.
    #[staticmethod]
    fn from_a2a_header(header: &str) -> PyResult<Self> {
        Ok(Self {
            inner: Presentation::from_a2a_header(header).map_err(map_err)?,
        })
    }

    /// Verify an A2A presentation as the receiving agent: full presentation
    /// verification plus a requirement that the embedded challenge audience
    /// equals `expected_audience` (this verifier). Raises on failure.
    fn verify_a2a(
        &self,
        action: &PyAction,
        anchor: &PyTrustAnchor,
        expected_audience: &str,
        max_age_secs: i64,
    ) -> PyResult<()> {
        self.inner
            .verify_a2a(
                &action.inner,
                &anchor.inner,
                expected_audience,
                max_age_secs,
            )
            .map_err(map_err)
    }
}
