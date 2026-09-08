use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use agentcreds_core::delegation::{
    Action, ApprovalEvidence, ApproverDirectory, ApproverEntry, ChainEntry, ConsumedApprovals,
    DelegationChain, DelegationToken, Gate, Scope,
};

use crate::credential::PyCapabilityCredential;
use crate::error::map_err;
use crate::identity::{PyAgentIdentity, PyTrustAnchor};

// -- Scope --------------------------------------------------------------------

#[pyclass(name = "Scope", module = "agentcreds")]
#[derive(Clone)]
pub struct PyScope {
    pub inner: Scope,
}

#[pymethods]
impl PyScope {
    /// Create a scope. `budget_usd` (USD-cents) and `max_depth` default to
    /// unlimited / 0 (no further delegation) when omitted. `resources` is an
    /// exact-match allow-list of resource ids the agent may touch (empty = no
    /// resource constraint).
    #[new]
    #[pyo3(signature = (tools, budget_usd=None, max_depth=0, resources=Vec::new()))]
    fn new(
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_depth: u32,
        resources: Vec<String>,
    ) -> Self {
        Self {
            inner: Scope::with_budget_and_depth(tools, budget_usd, max_depth)
                .with_resources(resources),
        }
    }

    #[getter]
    fn tools(&self) -> Vec<String> {
        let mut tools: Vec<String> = self.inner.tools.iter().cloned().collect();
        tools.sort();
        tools
    }

    #[getter]
    fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[getter]
    fn max_depth(&self) -> u32 {
        self.inner.max_depth
    }

    #[getter]
    fn resources(&self) -> Vec<String> {
        let mut resources: Vec<String> = self.inner.resources.iter().cloned().collect();
        resources.sort();
        resources
    }

    /// True if `self` is permitted under `parent` (tools subset, budget and
    /// depth not wider).
    fn is_subset_of(&self, parent: &PyScope) -> bool {
        self.inner.is_subset_of(&parent.inner)
    }

    /// The first tool in `self` that `parent` does not permit, if any.
    fn first_widening_capability(&self, parent: &PyScope) -> Option<String> {
        self.inner.first_widening_capability(&parent.inner)
    }

    /// Designate `tool` as requiring execution-time human approval (R10). Returns
    /// a new scope; the designation is carried in the token and can only be
    /// tightened (more gates) by later hops, never removed.
    fn require_approval(&self, tool: String) -> Self {
        Self {
            inner: self.inner.clone().require_approval(tool),
        }
    }

    /// Add execution-time gates (R10) to this scope. Returns a new scope.
    fn with_gates(&self, gates: Vec<PyGate>) -> Self {
        Self {
            inner: self
                .inner
                .clone()
                .with_gates(gates.into_iter().map(|g| g.inner).collect()),
        }
    }

    /// The execution-time gate designations on this scope (R10).
    #[getter]
    fn gates(&self) -> Vec<PyGate> {
        self.inner
            .gates
            .iter()
            .cloned()
            .map(|inner| PyGate { inner })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "Scope(tools={:?}, budget_usd={:?}, max_depth={})",
            self.tools(),
            self.inner.budget_usd,
            self.inner.max_depth
        )
    }
}

// -- Action -------------------------------------------------------------------

#[pyclass(name = "Action", module = "agentcreds")]
#[derive(Clone)]
pub struct PyAction {
    pub inner: Action,
}

#[pymethods]
impl PyAction {
    /// Create an action with the current timestamp. `resource` is the resource
    /// this call touches; `acting_for` is the principal DID the call is made on
    /// behalf of (required when the token is bound to a principal).
    #[new]
    #[pyo3(signature = (tool, parameters, resource=None, acting_for=None))]
    fn new(
        tool: String,
        parameters: String,
        resource: Option<String>,
        acting_for: Option<String>,
    ) -> Self {
        let mut action = Action::new(tool, parameters);
        if let Some(r) = resource {
            action = action.on_resource(r);
        }
        if let Some(p) = acting_for {
            action = action.on_behalf_of(p);
        }
        Self { inner: action }
    }

    #[getter]
    fn tool(&self) -> String {
        self.inner.tool.clone()
    }

    #[getter]
    fn parameters(&self) -> String {
        self.inner.parameters.clone()
    }

    #[getter]
    fn timestamp(&self) -> DateTime<Utc> {
        self.inner.timestamp
    }

    #[getter]
    fn resource(&self) -> Option<String> {
        self.inner.resource.clone()
    }

    #[getter]
    fn acting_for(&self) -> Option<String> {
        self.inner.acting_for.clone()
    }

    /// A stable content binding of this action (tool, parameters, resource) - pass
    /// to `PopChallenge.with_request_binding` to bind a presentation to exactly
    /// this request.
    fn request_binding(&self) -> String {
        self.inner.request_binding()
    }

    /// The content binding for execution-time human-authorization evidence (R10):
    /// like `request_binding`, but also binds the on-behalf-of principal, so a
    /// grant approved for one principal cannot satisfy the action for another.
    fn approval_binding(&self) -> String {
        self.inner.approval_binding()
    }

    fn __repr__(&self) -> String {
        format!(
            "Action(tool='{}', parameters='{}')",
            self.inner.tool, self.inner.parameters
        )
    }
}

// -- Gate / ApprovalEvidence / ConsumedApprovals (R10) ---------------------------

/// An execution-time human-authorization designation carried inside the delegated
/// authority (R10). Marks a `tool` as requiring human-approval evidence before
/// execution. Monotone: derivations can add gates, never remove one.
#[pyclass(name = "Gate", module = "agentcreds")]
#[derive(Clone)]
pub struct PyGate {
    pub inner: Gate,
}

#[pymethods]
impl PyGate {
    #[new]
    fn new(kind: String, tool: String) -> Self {
        Self {
            inner: Gate { kind, tool },
        }
    }

    /// A gate requiring human approval before `tool` may execute.
    #[staticmethod]
    fn approval(tool: String) -> Self {
        Self {
            inner: Gate::approval(tool),
        }
    }

    /// A gate requiring **approver-key-signed** approval (hybrid R10): the evidence
    /// is signed by the individual approver's key, verified against an
    /// org-anchor-signed `ApproverDirectory`.
    #[staticmethod]
    fn approval_key(tool: String) -> Self {
        Self {
            inner: Gate::approval_key(tool),
        }
    }

    #[getter]
    fn kind(&self) -> String {
        self.inner.kind.clone()
    }

    #[getter]
    fn tool(&self) -> String {
        self.inner.tool.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Gate(kind='{}', tool='{}')",
            self.inner.kind, self.inner.tool
        )
    }
}

/// Execution-time human-authorization evidence (R10) - an approver's decision
/// bound to one exact action (operation, parameters, resource, **and** principal),
/// signed by the org anchor and verified offline. Carry it with the request
/// (`to_json`/`from_json` for wire transport).
#[pyclass(name = "ApprovalEvidence", module = "agentcreds")]
#[derive(Clone)]
pub struct PyApprovalEvidence {
    pub inner: ApprovalEvidence,
}

#[pymethods]
impl PyApprovalEvidence {
    /// Mint signed evidence for `action`, decided by `approver`, valid until
    /// `expires_at` (unix seconds), signed by the organization `anchor`. Binds the
    /// on-behalf-of principal carried on `action`.
    #[staticmethod]
    fn approve(
        action: &PyAction,
        approver: String,
        approval_id: String,
        expires_at: i64,
        anchor: &PyTrustAnchor,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: ApprovalEvidence::approve(
                &action.inner,
                approver,
                approval_id,
                expires_at,
                &anchor.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Verify offline against `anchor` for `action` at `now_unix` (unix seconds):
    /// signature, principal-bound binding, and expiry. Raises on failure.
    fn verify(&self, action: &PyAction, anchor: &PyTrustAnchor, now_unix: i64) -> PyResult<()> {
        self.inner
            .verify(&action.inner, &anchor.inner, now_unix)
            .map_err(map_err)
    }

    /// Mint **approver-key-signed** evidence (hybrid R10): `approver` (a did:key
    /// signing identity) signs the action binding with its own key, giving
    /// per-human non-repudiation. Verified with `verify_with_directory`.
    #[staticmethod]
    fn approve_by_key(
        action: &PyAction,
        approver_id: String,
        approver: &PyAgentIdentity,
        approval_id: String,
        expires_at: i64,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: ApprovalEvidence::approve_by_key(
                &action.inner,
                approver_id,
                &approver.inner,
                approval_id,
                expires_at,
            )
            .map_err(map_err)?,
        })
    }

    /// Verify approver-key-signed evidence offline against an org-anchor-signed
    /// `directory` for `action` at `now_unix`, optionally requiring `required_role`.
    #[pyo3(signature = (action, directory, anchor, now_unix, required_role=None))]
    fn verify_with_directory(
        &self,
        action: &PyAction,
        directory: &PyApproverDirectory,
        anchor: &PyTrustAnchor,
        now_unix: i64,
        required_role: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .verify_with_directory(
                &action.inner,
                &directory.inner,
                &anchor.inner,
                now_unix,
                required_role.as_deref(),
            )
            .map_err(map_err)
    }

    #[getter]
    fn approval_id(&self) -> String {
        self.inner.approval_id.clone()
    }

    #[getter]
    fn approver(&self) -> String {
        self.inner.approver.clone()
    }

    #[getter]
    fn expires_at(&self) -> i64 {
        self.inner.expires_at
    }

    /// Serialize to JSON for carriage with a request.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("SerializationError: {e}")))
    }

    /// Parse evidence from JSON.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: serde_json::from_str(s)
                .map_err(|e| PyValueError::new_err(format!("SerializationError: {e}")))?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ApprovalEvidence(approval_id='{}', approver='{}')",
            self.inner.approval_id, self.inner.approver
        )
    }
}

/// A relying party's record of approval evidence already relied upon (R10
/// one-time). `try_consume` returns True the first time and False on re-use.
#[pyclass(name = "ConsumedApprovals", module = "agentcreds")]
pub struct PyConsumedApprovals {
    pub inner: ConsumedApprovals,
}

#[pymethods]
impl PyConsumedApprovals {
    #[new]
    fn new() -> Self {
        Self {
            inner: ConsumedApprovals::new(),
        }
    }

    /// Record `approval_id` as relied upon. True the first time; False on any
    /// subsequent call (already used -> the action must be refused).
    fn try_consume(&mut self, approval_id: String) -> bool {
        self.inner.try_consume(&approval_id)
    }

    /// Whether `approval_id` has already been relied upon.
    fn contains(&self, approval_id: String) -> bool {
        self.inner.contains(&approval_id)
    }
}

/// One enrolled human approver (hybrid R10): a did:key signing identity, roles,
/// and an optional expiry (`not_after_unix`, unix seconds).
#[pyclass(name = "ApproverEntry", module = "agentcreds")]
#[derive(Clone)]
pub struct PyApproverEntry {
    pub inner: ApproverEntry,
}

#[pymethods]
impl PyApproverEntry {
    #[new]
    #[pyo3(signature = (approver_id, approver_did, roles=Vec::new(), not_after_unix=None))]
    fn new(
        approver_id: String,
        approver_did: String,
        roles: Vec<String>,
        not_after_unix: Option<i64>,
    ) -> Self {
        Self {
            inner: ApproverEntry {
                approver_id,
                approver_did,
                roles,
                not_after: not_after_unix
                    .and_then(|t| chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0)),
            },
        }
    }

    #[getter]
    fn approver_id(&self) -> String {
        self.inner.approver_id.clone()
    }

    #[getter]
    fn approver_did(&self) -> String {
        self.inner.approver_did.clone()
    }

    #[getter]
    fn roles(&self) -> Vec<String> {
        self.inner.roles.clone()
    }

    /// Per-approver expiry as unix seconds, or None if the entry does not expire.
    #[getter]
    fn not_after_unix(&self) -> Option<i64> {
        self.inner.not_after.map(|t| t.timestamp())
    }
}

/// A versioned, **anchor-signed** directory of human approver keys (hybrid R10).
/// Verified under the same org anchor that roots delegation - no second trust
/// root. The control plane seals and distributes it; the PEP caches it (as JSON)
/// and passes it to `verify_rooted_gated_with_directory`.
#[pyclass(name = "ApproverDirectory", module = "agentcreds")]
#[derive(Clone)]
pub struct PyApproverDirectory {
    pub inner: ApproverDirectory,
}

#[pymethods]
impl PyApproverDirectory {
    /// Seal (sign) a directory with the org `anchor`. `not_after_unix` (unix
    /// seconds) sets an optional staleness bound.
    #[staticmethod]
    #[pyo3(signature = (entries, version, anchor, not_after_unix=None))]
    fn seal(
        entries: Vec<PyApproverEntry>,
        version: u64,
        anchor: &PyTrustAnchor,
        not_after_unix: Option<i64>,
    ) -> PyResult<Self> {
        let not_after =
            not_after_unix.and_then(|t| chrono::DateTime::<chrono::Utc>::from_timestamp(t, 0));
        Ok(Self {
            inner: ApproverDirectory::seal(
                entries.into_iter().map(|e| e.inner).collect(),
                version,
                chrono::Utc::now(),
                not_after,
                &anchor.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Verify against `anchor` and expiry at `now_unix`.
    fn verify_current(&self, anchor: &PyTrustAnchor, now_unix: i64) -> PyResult<()> {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp(now_unix, 0)
            .ok_or_else(|| PyValueError::new_err("invalid timestamp"))?;
        self.inner
            .verify_current(&anchor.inner, now)
            .map_err(map_err)
    }

    #[getter]
    fn version(&self) -> u64 {
        self.inner.version
    }

    /// DID of the anchor that sealed this directory.
    ///
    /// Under rotation this is the org's CURRENT key, which differs from the root a
    /// relying party pinned - so a verifier needs it to resolve the right key through
    /// the organization's key history.
    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    /// The enrolled approvers, sorted by `approver_id` (the sealed order).
    #[getter]
    fn entries(&self) -> Vec<PyApproverEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| PyApproverEntry { inner })
            .collect()
    }

    /// The sealed expiry as unix seconds, or None if unbounded.
    #[getter]
    fn not_after_unix(&self) -> Option<i64> {
        self.inner.not_after.map(|t| t.timestamp())
    }

    /// Serialize to JSON for distribution.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("SerializationError: {e}")))
    }

    /// Parse a directory from JSON.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: serde_json::from_str(s)
                .map_err(|e| PyValueError::new_err(format!("SerializationError: {e}")))?,
        })
    }
}

// -- ChainEntry / DelegationChain (audit view) ---------------------------------

#[pyclass(name = "ChainEntry", module = "agentcreds")]
#[derive(Clone)]
pub struct PyChainEntry {
    pub inner: ChainEntry,
}

#[pymethods]
impl PyChainEntry {
    #[getter]
    fn depth(&self) -> u32 {
        self.inner.depth
    }

    #[getter]
    fn agent_did(&self) -> String {
        self.inner.agent_did.clone()
    }

    #[getter]
    fn tools(&self) -> Vec<String> {
        self.inner.tools.clone()
    }

    #[getter]
    fn resources(&self) -> Vec<String> {
        self.inner.resources.clone()
    }

    #[getter]
    fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[getter]
    fn issued_at(&self) -> DateTime<Utc> {
        self.inner.issued_at
    }

    #[getter]
    fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }

    fn __repr__(&self) -> String {
        format!(
            "ChainEntry(depth={}, agent_did='{}', tools={:?})",
            self.inner.depth, self.inner.agent_did, self.inner.tools
        )
    }
}

#[pyclass(name = "DelegationChain", module = "agentcreds")]
#[derive(Clone)]
pub struct PyDelegationChain {
    pub inner: DelegationChain,
}

#[pymethods]
impl PyDelegationChain {
    #[getter]
    fn vc_id(&self) -> String {
        self.inner.vc_id.clone()
    }

    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    /// The human principal the chain is bound to (on-behalf-of), if any.
    #[getter]
    fn principal_did(&self) -> Option<String> {
        self.inner.principal_did.clone()
    }

    #[getter]
    fn entries(&self) -> Vec<PyChainEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| PyChainEntry { inner })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "DelegationChain(vc_id='{}', entries={})",
            self.inner.vc_id,
            self.inner.entries.len()
        )
    }
}

// -- DelegationToken -----------------------------------------------------------

#[pyclass(name = "DelegationToken", module = "agentcreds")]
#[derive(Clone)]
pub struct PyDelegationToken {
    pub inner: DelegationToken,
}

#[pymethods]
impl PyDelegationToken {
    /// Mint a new delegation token from a capability credential. `scope` must
    /// be a subset of `vc`'s claims; `ttl_secs` is capped at the VC's expiry.
    #[staticmethod]
    fn mint(
        vc: &PyCapabilityCredential,
        scope: &PyScope,
        ttl_secs: u64,
        agent: &PyAgentIdentity,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: DelegationToken::mint(&vc.inner, scope.inner.clone(), ttl_secs, &agent.inner)
                .map_err(map_err)?,
        })
    }

    /// Attenuate this token for a sub-agent. `narrow` must be a subset of the
    /// current leaf block's scope; widening raises `ScopeWideningError`.
    fn attenuate(
        &self,
        narrow: &PyScope,
        ttl_secs: u64,
        agent: &PyAgentIdentity,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: self
                .inner
                .attenuate(narrow.inner.clone(), ttl_secs, &agent.inner)
                .map_err(map_err)?,
        })
    }

    /// Verify the chain's integrity and authenticity (every block signature,
    /// expiry, hash linkage, monotonic scope narrowing) and that `action` is
    /// permitted by the leaf block.
    ///
    /// NOTE: this proves the chain is authentic but not that its root authority
    /// came from a trusted anchor. Use `verify_rooted` (or independently verify
    /// the backing credential) to establish anchor-rooted authority.
    fn verify(&self, action: &PyAction) -> PyResult<()> {
        self.inner.verify(&action.inner).map_err(map_err)
    }

    /// Verify `action` against this token **and** bind its root to an
    /// anchor-issued credential: verifies `vc` against `anchor`, confirms the
    /// token was derived from `vc`, that the root was minted by the credential
    /// subject, and that the root scope is within the credential's claims.
    /// This is the complete check a relying party should use.
    fn verify_rooted(
        &self,
        action: &PyAction,
        vc: &PyCapabilityCredential,
        anchor: &PyTrustAnchor,
    ) -> PyResult<()> {
        self.inner
            .verify_rooted(&action.inner, &vc.inner, &anchor.inner)
            .map_err(map_err)
    }

    /// `verify_rooted`, evaluated **as of** `epoch_seconds` instead of the wall clock.
    ///
    /// One instant governs the credential's expiry, every hop's expiry and the Datalog
    /// time check, so the answer cannot straddle two clocks. For audit re-verification
    /// ("was this authorized when it happened?") and for conformance vectors that must
    /// outlive the token lifetimes the autonomy ladder permits.
    ///
    /// **Not the enforcement path** - a relying party deciding in real time calls
    /// `verify_rooted`. Revocation is not covered: a historical answer also needs the
    /// status list as it stood then.
    fn verify_rooted_at(
        &self,
        action: &PyAction,
        vc: &PyCapabilityCredential,
        anchor: &PyTrustAnchor,
        epoch_seconds: i64,
    ) -> PyResult<()> {
        let now = chrono::DateTime::from_timestamp(epoch_seconds, 0)
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("epoch_seconds out of range"))?;
        self.inner
            .verify_rooted_at(&action.inner, &vc.inner, &anchor.inner, now)
            .map_err(map_err)
    }

    /// The execution-time gate designations carried by this token (R10).
    fn gates(&self) -> Vec<PyGate> {
        self.inner
            .gates()
            .iter()
            .cloned()
            .map(|inner| PyGate { inner })
            .collect()
    }

    /// The gates designating `action.tool` - the human-authorization requirements
    /// to satisfy before executing it (R10).
    fn required_gates(&self, action: &PyAction) -> Vec<PyGate> {
        self.inner
            .required_gates(&action.inner)
            .into_iter()
            .map(|inner| PyGate { inner })
            .collect()
    }

    /// The complete relying-party check **including R10**: everything
    /// `verify_rooted` checks, plus, for every gate designating the requested
    /// tool, that carried, anchor-verified, principal-bound `evidence` satisfies
    /// it. `recognized_kinds` are the gate kinds this party can satisfy (an
    /// unrecognized kind -> denied). Returns the `approval_id`s relied upon - record
    /// them in a `ConsumedApprovals` and refuse a second reliance (one-time).
    #[pyo3(signature = (action, vc, anchor, evidence, recognized_kinds, now_unix))]
    fn verify_rooted_gated(
        &self,
        action: &PyAction,
        vc: &PyCapabilityCredential,
        anchor: &PyTrustAnchor,
        evidence: Vec<PyApprovalEvidence>,
        recognized_kinds: Vec<String>,
        now_unix: i64,
    ) -> PyResult<Vec<String>> {
        let ev: Vec<ApprovalEvidence> = evidence.into_iter().map(|e| e.inner).collect();
        let kinds: Vec<&str> = recognized_kinds.iter().map(String::as_str).collect();
        self.inner
            .verify_rooted_gated(
                &action.inner,
                &vc.inner,
                &anchor.inner,
                &ev,
                &kinds,
                now_unix,
            )
            .map_err(map_err)
    }

    /// Like `verify_rooted_gated`, but also accepts the hybrid `approval-key` gate
    /// kind, whose evidence is verified against an org-anchor-signed `directory`
    /// (per-approver keys, single trust root). Pass `directory=None` for anchor-only.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (action, vc, anchor, evidence, directory, recognized_kinds, now_unix))]
    fn verify_rooted_gated_with_directory(
        &self,
        action: &PyAction,
        vc: &PyCapabilityCredential,
        anchor: &PyTrustAnchor,
        evidence: Vec<PyApprovalEvidence>,
        directory: Option<PyApproverDirectory>,
        recognized_kinds: Vec<String>,
        now_unix: i64,
    ) -> PyResult<Vec<String>> {
        let ev: Vec<ApprovalEvidence> = evidence.into_iter().map(|e| e.inner).collect();
        let kinds: Vec<&str> = recognized_kinds.iter().map(String::as_str).collect();
        let dir = directory.as_ref().map(|d| &d.inner);
        self.inner
            .verify_rooted_gated_with_directory(
                &action.inner,
                &vc.inner,
                &anchor.inner,
                &ev,
                dir,
                &kinds,
                now_unix,
            )
            .map_err(map_err)
    }

    /// Produce a proof of possession for `challenge`, signed by the token's
    /// leaf agent. Only the leaf agent can do this.
    fn prove_possession(
        &self,
        challenge: &crate::pop::PyPopChallenge,
        leaf_agent: &PyAgentIdentity,
    ) -> PyResult<crate::pop::PyProofOfPossession> {
        Ok(crate::pop::PyProofOfPossession {
            inner: self
                .inner
                .prove_possession(&challenge.inner, &leaf_agent.inner)
                .map_err(map_err)?,
        })
    }

    /// The complete presentation check: anchor-rooted verification plus proof
    /// of possession of the leaf key for `expected_challenge`.
    #[allow(clippy::too_many_arguments)]
    fn verify_presentation(
        &self,
        action: &PyAction,
        vc: &PyCapabilityCredential,
        anchor: &PyTrustAnchor,
        proof: &crate::pop::PyProofOfPossession,
        expected_challenge: &crate::pop::PyPopChallenge,
        max_age_secs: i64,
    ) -> PyResult<()> {
        self.inner
            .verify_presentation(
                &action.inner,
                &vc.inner,
                &anchor.inner,
                &proof.inner,
                &expected_challenge.inner,
                max_age_secs,
            )
            .map_err(map_err)
    }

    /// Serialize to CBOR bytes for compact wire transport.
    fn to_cbor<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.to_cbor().map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Deserialise a token from CBOR bytes.
    #[staticmethod]
    fn from_cbor(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: DelegationToken::from_cbor(bytes).map_err(map_err)?,
        })
    }

    #[getter]
    fn vc_id(&self) -> String {
        self.inner.vc_id().to_string()
    }

    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did().to_string()
    }

    /// The human principal DID this token is bound to (on-behalf-of), or None.
    #[getter]
    fn principal_did(&self) -> Option<String> {
        self.inner.principal_did().map(str::to_string)
    }

    /// The root resource allow-list this token was minted with.
    fn root_resources(&self) -> Vec<String> {
        self.inner.root_resources().to_vec()
    }

    /// Current delegation depth (0 = not delegated).
    fn depth(&self) -> u32 {
        self.inner.depth()
    }

    /// Extract the full delegation chain as audit entries.
    fn chain(&self) -> PyDelegationChain {
        PyDelegationChain {
            inner: self.inner.chain(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "DelegationToken(vc_id='{}', depth={})",
            self.inner.vc_id(),
            self.inner.depth()
        )
    }
}
