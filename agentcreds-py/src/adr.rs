use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::adr::{
    replay, AdrCheckpoint, AdrStream, AuthzDecision, Decision, DecisionKind, Signal,
};

use crate::delegation::PyDelegationToken;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(format!("SerializationError: {e}"))
}

fn parse_kind(s: &str) -> PyResult<DecisionKind> {
    DecisionKind::parse(s)
        .ok_or_else(|| PyValueError::new_err(format!("unknown decision kind: {s}")))
}

fn parse_signal(s: &str) -> PyResult<Signal> {
    Signal::parse(s).ok_or_else(|| PyValueError::new_err(format!("unknown signal: {s}")))
}

/// `"allow"` / `"deny"` / absent. Rejected rather than defaulted: a typo silently
/// read as `Allow` would record an admission that never happened.
fn parse_decision(s: Option<&str>) -> PyResult<Option<Decision>> {
    match s {
        None => Ok(None),
        Some("allow") => Ok(Some(Decision::Allow)),
        Some("deny") => Ok(Some(Decision::Deny)),
        Some(other) => Err(PyValueError::new_err(format!(
            "unknown decision {other:?} (expected \"allow\" or \"deny\")"
        ))),
    }
}

/// One Authorization Decision Record - who was allowed to do what, the outcome,
/// and any security signals. Serializable for export to a SIEM (``to_json``).
#[pyclass(name = "AuthzDecision", module = "agentcreds")]
#[derive(Clone)]
pub struct PyAuthzDecision {
    pub inner: AuthzDecision,
}

#[pymethods]
impl PyAuthzDecision {
    /// Build a record from a delegation token and an outcome. ``allow=False``
    /// marks a denial; pass the ``signal`` (e.g. ``"action_denied"``) and
    /// ``reason``. ``kind`` is one of ``mint``/``attenuate``/``verify``/
    /// ``verify_rooted``/``presentation``/``revocation``.
    #[staticmethod]
    #[pyo3(signature = (kind, token, action=None, allow=true, signal=None, reason=None))]
    fn from_token(
        kind: &str,
        token: &PyDelegationToken,
        action: Option<String>,
        allow: bool,
        signal: Option<String>,
        reason: Option<String>,
    ) -> PyResult<Self> {
        let kind = parse_kind(kind)?;
        let mut inner = AuthzDecision::from_token(kind, &token.inner, action.as_deref(), &Ok(()));
        if !allow {
            inner.decision = Decision::Deny;
            inner.signals = vec![match signal {
                Some(s) => parse_signal(&s)?,
                None => Signal::Other,
            }];
            inner.reason = reason;
        }
        Ok(Self { inner })
    }

    /// A bare allow for a subject (e.g. a non-token check).
    #[staticmethod]
    fn allow(kind: &str, subject_did: String) -> PyResult<Self> {
        Ok(Self {
            inner: AuthzDecision::allow(parse_kind(kind)?, subject_did),
        })
    }

    /// A bare deny for a subject, with a signal and reason.
    #[staticmethod]
    fn deny(kind: &str, subject_did: String, signal: &str, reason: String) -> PyResult<Self> {
        Ok(Self {
            inner: AuthzDecision::deny(
                parse_kind(kind)?,
                subject_did,
                parse_signal(signal)?,
                reason,
            ),
        })
    }

    /// Record who answers for this decision, and on what basis.
    ///
    /// Not derivable from the token: the accountable party is a claim on the
    /// **credential**, so a verifier holds it during verification and passes it
    /// in here. Without this the record answers "who is answerable for this
    /// credential" only by a join back to the credential - which is exactly the
    /// join the field exists to remove.
    ///
    /// One call rather than two, because in an audit "who answers" and "how
    /// firmly do we know" are a single question. A record naming the party but
    /// not the basis invites the reader to assume the strongest reading, and the
    /// weakest - a requester naming itself - is the case worth noticing.
    /// `party_version` and `party_commitment` come from the same credential and
    /// turn the party from a name into a resolvable claim - which revision of the
    /// ownership record to read, and proof that the record produced is the one
    /// committed to. Neither is personal data.
    #[pyo3(signature = (party, source=None, party_version=None, party_commitment=None))]
    fn with_accountability(
        &self,
        party: Option<String>,
        source: Option<String>,
        party_version: Option<u64>,
        party_commitment: Option<String>,
    ) -> Self {
        Self {
            inner: self
                .inner
                .clone()
                .with_accountable_party(party)
                .with_accountability_source(source)
                .with_party_record(party_version, party_commitment),
        }
    }

    /// Record the R10 evaluation and admission outcomes separately.
    ///
    /// `evaluation="allow"` with `admission="deny"` is a replay: valid,
    /// policy-satisfying evidence refused because its reliance unit was already
    /// consumed. A single verdict field reports that identically to evidence that
    /// never verified - and the two call for opposite responses.
    ///
    /// Both `None` when no execution-time gate applied, which is the ordinary case.
    #[pyo3(signature = (evaluation=None, admission=None))]
    fn with_verdicts(&self, evaluation: Option<&str>, admission: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            inner: self
                .inner
                .clone()
                .with_verdicts(parse_decision(evaluation)?, parse_decision(admission)?),
        })
    }

    /// Did the execution-time evidence verify and satisfy policy? `"allow"`,
    /// `"deny"`, or `None` when no gate applied.
    #[getter]
    fn evaluation(&self) -> Option<&'static str> {
        self.inner.evaluation.map(Decision::as_str)
    }

    /// Was the reliance unit admitted? `"allow"`, `"deny"`, or `None`.
    #[getter]
    fn admission(&self) -> Option<&'static str> {
        self.inner.admission.map(Decision::as_str)
    }

    /// Which revision of the ownership record named the accountable party.
    #[getter]
    fn party_version(&self) -> Option<u64> {
        self.inner.party_version
    }

    /// Salted commitment to that ownership record.
    #[getter]
    fn party_commitment(&self) -> Option<String> {
        self.inner.party_commitment.clone()
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }
    #[getter]
    fn seq(&self) -> u64 {
        self.inner.seq
    }
    #[getter]
    fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }
    #[getter]
    fn kind(&self) -> String {
        self.inner.kind.as_str().to_string()
    }
    #[getter]
    fn decision(&self) -> String {
        self.inner.decision.as_str().to_string()
    }
    #[getter]
    fn allowed(&self) -> bool {
        matches!(self.inner.decision, Decision::Allow)
    }
    #[getter]
    fn subject_did(&self) -> String {
        self.inner.subject_did.clone()
    }
    #[getter]
    fn root_agent_did(&self) -> String {
        self.inner.root_agent_did.clone()
    }
    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[getter]
    fn vc_id(&self) -> String {
        self.inner.vc_id.clone()
    }
    #[getter]
    fn action(&self) -> Option<String> {
        self.inner.action.clone()
    }
    /// The principal whose authority was exercised, if any. `None` is the autonomous
    /// case, not a missing value.
    #[getter]
    fn principal_did(&self) -> Option<String> {
        self.inner.principal_did.clone()
    }
    /// Who answers for this decision - the responsible party *within* the issuing
    /// organization. `None` means the credential predates accountability being
    /// recorded; the organization named by `issuer_did` is accountable regardless.
    #[getter]
    fn accountable_party(&self) -> Option<String> {
        self.inner.accountable_party.clone()
    }
    /// How firmly the accountable party is known - `"attested"`, `"policy"` or
    /// `"asserted"`. Absent means the credential predates provenance being recorded, and
    /// must be read as the weakest source rather than an unknown one.
    #[getter]
    fn accountability_source(&self) -> Option<String> {
        self.inner.accountability_source.clone()
    }
    #[getter]
    fn depth(&self) -> u32 {
        self.inner.depth
    }
    #[getter]
    fn max_depth(&self) -> u32 {
        self.inner.max_depth
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
    fn reason(&self) -> Option<String> {
        self.inner.reason.clone()
    }

    /// The record as a JSON string (for a SIEM/log sink).
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(ser_err)
    }

    /// Parse a record back from its JSON form.
    ///
    /// The inverse of :meth:`to_json`, and what makes a signed audit export
    /// independently checkable from Python: read the exported decisions back, hand
    /// them to :meth:`AdrStream.replay`, and compare the result against the head in
    /// the signed :class:`AdrCheckpoint`. Without this the checkpoint's *signature*
    /// could be verified here but the chain it attests to could not be recomputed,
    /// so "verifiable export" held only for Rust consumers.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: serde_json::from_str(s).map_err(ser_err)?,
        })
    }

    /// The canonical SHA-256 digest of this record, hex-encoded.
    fn digest_hex(&self) -> String {
        self.inner.digest_hex()
    }

    fn __repr__(&self) -> String {
        format!(
            "AuthzDecision(kind={}, decision={}, subject={:?}, seq={})",
            self.inner.kind.as_str(),
            self.inner.decision.as_str(),
            self.inner.subject_did,
            self.inner.seq,
        )
    }
}

/// A recorder that stamps each decision with a sequence number, advances a
/// tamper-evident hash-chain, and returns the stamped record for forwarding.
#[pyclass(name = "AdrStream", module = "agentcreds")]
pub struct PyAdrStream {
    inner: AdrStream,
}

#[pymethods]
impl PyAdrStream {
    #[new]
    fn new() -> Self {
        Self {
            inner: AdrStream::new(),
        }
    }

    /// Record a decision; returns the stamped record (with its ``seq`` assigned).
    /// Forward the returned record to your SIEM.
    fn record(&mut self, decision: &PyAuthzDecision) -> PyAuthzDecision {
        PyAuthzDecision {
            inner: self.inner.record(decision.inner.clone()),
        }
    }

    /// The current hash-chain head (hex).
    fn head(&self) -> String {
        self.inner.head()
    }

    /// The number of decisions recorded so far.
    fn count(&self) -> u64 {
        self.inner.count()
    }

    /// Sign the current ``(count, head)`` with ``anchor`` for tamper-evidence.
    fn sign_checkpoint(&self, anchor: &PyTrustAnchor) -> PyResult<PyAdrCheckpoint> {
        Ok(PyAdrCheckpoint {
            inner: self.inner.sign_checkpoint(&anchor.inner).map_err(map_err)?,
        })
    }

    /// Recompute the hash-chain head from an ordered list of decisions (to check
    /// a received stream against a signed checkpoint).
    #[staticmethod]
    fn replay(decisions: Vec<PyAuthzDecision>) -> String {
        let records: Vec<AuthzDecision> = decisions.into_iter().map(|d| d.inner).collect();
        replay(&records)
    }
}

/// An anchor-signed attestation that the decision log reached ``count`` records
/// with hash-chain ``head``.
#[pyclass(name = "AdrCheckpoint", module = "agentcreds")]
#[derive(Clone)]
pub struct PyAdrCheckpoint {
    pub inner: AdrCheckpoint,
}

#[pymethods]
impl PyAdrCheckpoint {
    #[getter]
    fn count(&self) -> u64 {
        self.inner.count
    }
    #[getter]
    fn head(&self) -> String {
        self.inner.head.clone()
    }
    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[getter]
    fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// Verify the checkpoint signature against ``anchor``.
    fn verify(&self, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// The checkpoint as a JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(ser_err)
    }

    /// Parse a checkpoint from its JSON string.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: serde_json::from_str(s).map_err(ser_err)?,
        })
    }
}
