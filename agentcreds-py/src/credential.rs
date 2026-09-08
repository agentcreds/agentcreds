use chrono::{DateTime, Utc};
use pyo3::prelude::*;

use agentcreds_core::accountability::OwnershipRecord as CoreOwnershipRecord;
use agentcreds_core::vc::{
    AuthoritySource, CapabilityClaims, CapabilityCredential, CredentialStatus, HumanAuthorization,
    LinkedDataProof, PrincipalKind,
};

use crate::error::map_err;
use crate::identity::PyTrustAnchor;

// -- HumanAuthorization (on-behalf-of principal) -------------------------------

/// The human principal, attested by an IdP, on whose behalf an agent acts -
/// the enforced on-behalf-of dimension of a credential.
#[pyclass(name = "HumanAuthorization", module = "agentcreds")]
#[derive(Clone)]
pub struct PyHumanAuthorization {
    pub inner: HumanAuthorization,
}

#[pymethods]
impl PyHumanAuthorization {
    /// Construct a human authorization. `authorized_at` defaults to now;
    /// `scope_consented` (tool ids) and `resource_authority` (resource patterns)
    /// default to empty.
    #[new]
    #[pyo3(signature = (principal_did, issuer, subject, expires_at,
                        scope_consented=Vec::new(), resource_authority=Vec::new(),
                        authorized_at=None, kind=None, entitlement_source=None))]
    fn new(
        principal_did: String,
        issuer: String,
        subject: String,
        expires_at: DateTime<Utc>,
        scope_consented: Vec<String>,
        resource_authority: Vec<String>,
        authorized_at: Option<DateTime<Utc>>,
        kind: Option<&str>,
        entitlement_source: Option<&str>,
    ) -> PyResult<Self> {
        // Rejected rather than defaulted: a typo that silently produced a human
        // principal would misreport which attesting root stands behind the binding.
        let kind = match kind {
            None => PrincipalKind::Human,
            Some(k) => PrincipalKind::parse(k).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown principal kind {k:?} (expected \"human\" or \"workload\")"
                ))
            })?,
        };
        // Rejected rather than defaulted, for the same reason as `kind`: silently
        // reading an unknown source as the default would misreport the evidence behind
        // this principal's entitlements.
        let entitlement_source = match entitlement_source {
            None => AuthoritySource::default(),
            Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
                ))
            })?,
        };
        Ok(Self {
            inner: HumanAuthorization {
                principal_did,
                kind,
                entitlement_source,
                issuer,
                subject,
                authorized_at: authorized_at.unwrap_or_else(Utc::now),
                expires_at,
                scope_consented,
                resource_authority,
            },
        })
    }

    /// Which kind of principal this is - `"human"` or `"workload"` - and therefore
    /// which root attested it: an identity provider, or a SPIFFE trust domain.
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind.as_str()
    }

    /// Where `scope_consented` and `resource_authority` came from - `"attested"`,
    /// `"policy"` or `"asserted"`. The entitlements bound the agent by something
    /// established outside the grant of capability; if they were `"asserted"`, they came
    /// from whoever requested issuance and bound nothing.
    #[getter]
    fn entitlement_source(&self) -> &'static str {
        self.inner.entitlement_source.as_str()
    }

    #[getter]
    fn principal_did(&self) -> String {
        self.inner.principal_did.clone()
    }

    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[getter]
    fn subject(&self) -> String {
        self.inner.subject.clone()
    }

    #[getter]
    fn authorized_at(&self) -> DateTime<Utc> {
        self.inner.authorized_at
    }

    #[getter]
    fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }

    #[getter]
    fn scope_consented(&self) -> Vec<String> {
        self.inner.scope_consented.clone()
    }

    #[getter]
    fn resource_authority(&self) -> Vec<String> {
        self.inner.resource_authority.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "HumanAuthorization(principal_did='{}', issuer='{}')",
            self.inner.principal_did, self.inner.issuer
        )
    }
}

// -- CapabilityClaims ----------------------------------------------------------

#[pyclass(name = "CapabilityClaims", module = "agentcreds")]
#[derive(Clone)]
pub struct PyCapabilityClaims {
    pub inner: CapabilityClaims,
}

#[pymethods]
impl PyCapabilityClaims {
    #[new]
    #[pyo3(signature = (
        tools,
        max_delegation_depth,
        valid_for_secs,
        budget_usd=None,
        autonomy_level=0,
        model_version=None,
        artifact_hash=None,
        authorized_by=None,
        accountable_party=None,
        on_behalf_of=None,
        resources=None,
        party_version=None,
        party_commitment=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        tools: Vec<String>,
        max_delegation_depth: u32,
        valid_for_secs: u64,
        budget_usd: Option<u32>,
        autonomy_level: u8,
        model_version: Option<String>,
        artifact_hash: Option<String>,
        authorized_by: Option<String>,
        accountable_party: Option<String>,
        on_behalf_of: Option<PyHumanAuthorization>,
        resources: Option<Vec<String>>,
        party_version: Option<u64>,
        party_commitment: Option<String>,
    ) -> Self {
        let mut claims = CapabilityClaims::new(tools, max_delegation_depth, valid_for_secs);
        claims.resources = resources;
        claims.budget_usd = budget_usd;
        claims.autonomy_level = autonomy_level;
        claims.model_version = model_version;
        claims.artifact_hash = artifact_hash;
        claims.authorized_by = authorized_by;
        claims.accountable_party = accountable_party;
        claims.party_version = party_version;
        claims.party_commitment = party_commitment;
        claims.on_behalf_of = on_behalf_of.map(|h| h.inner);
        Self { inner: claims }
    }

    /// Mandate that `tool` requires execution-time human approval (R10). Every
    /// delegation token minted from the issued credential is held to it, even if a
    /// minting agent declares no gate - a gated credential cannot be spent ungated.
    fn require_approval(&mut self, tool: String) {
        self.inner
            .required_gates
            .push(agentcreds_core::delegation::Gate::approval(tool));
    }

    /// The execution-time human-authorization gates this credential mandates (R10).
    #[getter]
    fn required_gates(&self) -> Vec<crate::delegation::PyGate> {
        self.inner
            .required_gates
            .iter()
            .cloned()
            .map(|inner| crate::delegation::PyGate { inner })
            .collect()
    }

    #[getter]
    fn tools(&self) -> Vec<String> {
        self.inner.tools.clone()
    }

    /// Resource-namespace patterns this credential permits, or `None` if it
    /// bounds none. A capability-axis ceiling: `mint` holds a token's resource
    /// scope to it, with no principal involved.
    #[getter]
    fn resources(&self) -> Option<Vec<String>> {
        self.inner.resources.clone()
    }

    /// Which revision of the ownership record named the accountable party.
    /// `None` = no record configured, not version zero.
    #[getter]
    fn party_version(&self) -> Option<u64> {
        self.inner.party_version
    }

    /// Salted commitment to that ownership record. Lets an auditor prove the
    /// record they produced is the one committed to, without the members ever
    /// being in the credential.
    #[getter]
    fn party_commitment(&self) -> Option<String> {
        self.inner.party_commitment.clone()
    }

    #[getter]
    fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[getter]
    fn max_delegation_depth(&self) -> u32 {
        self.inner.max_delegation_depth
    }

    #[getter]
    fn valid_for_secs(&self) -> u64 {
        self.inner.valid_for_secs
    }

    #[getter]
    fn autonomy_level(&self) -> u8 {
        self.inner.autonomy_level
    }

    #[getter]
    fn model_version(&self) -> Option<String> {
        self.inner.model_version.clone()
    }

    #[getter]
    fn artifact_hash(&self) -> Option<String> {
        self.inner.artifact_hash.clone()
    }

    #[getter]
    fn authorized_by(&self) -> Option<String> {
        self.inner.authorized_by.clone()
    }

    /// Who answers for what this agent does.
    ///
    /// Unlike `authorized_by`, this is never selectively disclosable - a verifier is
    /// always shown it, because "who is responsible" is not a claim the holder gets to
    /// withhold.
    #[getter]
    fn accountable_party(&self) -> Option<String> {
        self.inner.accountable_party.clone()
    }

    /// How the accountable party was established. Travels with the party because in an
    /// audit they are one question.
    #[getter]
    fn accountability_source(&self) -> &'static str {
        self.inner.accountability_source.as_str()
    }

    #[getter]
    fn on_behalf_of(&self) -> Option<PyHumanAuthorization> {
        self.inner
            .on_behalf_of
            .clone()
            .map(|inner| PyHumanAuthorization { inner })
    }

    /// Validate that claims are internally consistent (raises on failure).
    fn validate(&self) -> PyResult<()> {
        self.inner.validate().map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "CapabilityClaims(tools={:?}, budget_usd={:?}, max_delegation_depth={}, valid_for_secs={})",
            self.inner.tools, self.inner.budget_usd, self.inner.max_delegation_depth, self.inner.valid_for_secs
        )
    }
}

// -- CredentialStatus ----------------------------------------------------------

#[pyclass(name = "CredentialStatus", module = "agentcreds")]
#[derive(Clone)]
pub struct PyCredentialStatus {
    pub inner: CredentialStatus,
}

#[pymethods]
impl PyCredentialStatus {
    /// Construct an OAuth Status List entry reference for `index` within the list
    /// published at `registry_url`.
    #[new]
    fn new(registry_url: &str, index: u64) -> Self {
        Self {
            inner: CredentialStatus::new(registry_url, index),
        }
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn r#type(&self) -> String {
        self.inner.r#type.clone()
    }

    #[getter]
    fn status_purpose(&self) -> String {
        self.inner.status_purpose.clone()
    }

    #[getter]
    fn status_list_index(&self) -> u64 {
        self.inner.status_list_index
    }

    #[getter]
    fn status_list_credential(&self) -> String {
        self.inner.status_list_credential.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "CredentialStatus(id='{}', status_list_index={})",
            self.inner.id, self.inner.status_list_index
        )
    }
}

// -- LinkedDataProof -----------------------------------------------------------

#[pyclass(name = "LinkedDataProof", module = "agentcreds")]
#[derive(Clone)]
pub struct PyLinkedDataProof {
    pub inner: LinkedDataProof,
}

#[pymethods]
impl PyLinkedDataProof {
    #[getter]
    fn r#type(&self) -> String {
        self.inner.r#type.clone()
    }

    #[getter]
    fn created(&self) -> DateTime<Utc> {
        self.inner.created
    }

    #[getter]
    fn verification_method(&self) -> String {
        self.inner.verification_method.clone()
    }

    #[getter]
    fn proof_purpose(&self) -> String {
        self.inner.proof_purpose.clone()
    }

    #[getter]
    fn proof_value(&self) -> String {
        self.inner.proof_value.clone()
    }

    #[getter]
    fn payload_hash(&self) -> String {
        self.inner.payload_hash.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "LinkedDataProof(type='{}', verification_method='{}')",
            self.inner.r#type, self.inner.verification_method
        )
    }
}

// -- CapabilityCredential ------------------------------------------------------

#[pyclass(name = "CapabilityCredential", module = "agentcreds")]
#[derive(Clone)]
pub struct PyCapabilityCredential {
    pub inner: CapabilityCredential,
}

#[pymethods]
impl PyCapabilityCredential {
    /// Issue a new capability credential signed by `anchor`.
    #[staticmethod]
    #[pyo3(signature = (anchor, subject_did, claims, revocation=None))]
    fn issue(
        anchor: &PyTrustAnchor,
        subject_did: &str,
        claims: &PyCapabilityClaims,
        revocation: Option<&PyCredentialStatus>,
    ) -> PyResult<Self> {
        let inner = CapabilityCredential::issue(
            &anchor.inner,
            subject_did,
            claims.inner.clone(),
            revocation.map(|r| r.inner.clone()),
        )
        .map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Deserialise a credential from its JSON-LD representation.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        Ok(Self {
            inner: CapabilityCredential::from_json(json).map_err(map_err)?,
        })
    }

    /// Serialize this credential to canonical JSON-LD.
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn context(&self) -> Vec<String> {
        self.inner.context.clone()
    }

    #[getter]
    fn r#type(&self) -> Vec<String> {
        self.inner.r#type.clone()
    }

    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[getter]
    fn issuance_date(&self) -> DateTime<Utc> {
        self.inner.issuance_date
    }

    #[getter]
    fn proof(&self) -> PyLinkedDataProof {
        PyLinkedDataProof {
            inner: self.inner.proof.clone(),
        }
    }

    #[getter]
    fn credential_status(&self) -> Option<PyCredentialStatus> {
        self.inner
            .credential_status
            .clone()
            .map(|inner| PyCredentialStatus { inner })
    }

    fn subject_did(&self) -> String {
        self.inner.subject_did().to_string()
    }

    fn claims(&self) -> PyCapabilityClaims {
        PyCapabilityClaims {
            inner: self.inner.claims().clone(),
        }
    }

    fn expiration_date(&self) -> DateTime<Utc> {
        self.inner.expiration_date()
    }

    fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    /// Verify this credential's cryptographic proof against `anchor`.
    #[pyo3(signature = (anchor, strict_issuer=true))]
    fn verify(&self, anchor: &PyTrustAnchor, strict_issuer: bool) -> PyResult<()> {
        self.inner
            .verify(&anchor.inner, strict_issuer)
            .map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "CapabilityCredential(id='{}', issuer='{}', subject='{}')",
            self.inner.id,
            self.inner.issuer,
            self.inner.subject_did()
        )
    }
}

// -- OwnershipRecord (resolving a party to humans, later) ----------------------

/// One revision of "who is behind this accountable party".
///
/// Held by the organization and **never** placed in a credential - only its
/// `version` and `commitment` travel. The members are personal data, and a
/// credential is signed, immutable, presented across organizational boundaries,
/// and outlives the employment, so it can neither correct nor erase them.
///
/// The commitment is salted, so it is not a membership oracle over a guessable
/// list. Erasure degrades in the right direction: delete someone from the store
/// and the commitment stops matching anything you can produce - you lose the
/// ability to prove *who was in the team*, and keep the ability to prove *which
/// team*.
#[pyclass(name = "OwnershipRecord", module = "agentcreds")]
#[derive(Clone)]
pub struct PyOwnershipRecord {
    pub inner: CoreOwnershipRecord,
}

#[pymethods]
impl PyOwnershipRecord {
    /// Build a record. `members` is sorted and de-duplicated, so the store's
    /// return order cannot change the commitment. `salt` must be at least 16
    /// characters - a short salt makes the commitment brute-forceable from a
    /// candidate membership list, which is the exact data it exists to protect.
    #[new]
    #[pyo3(signature = (party_id, version, members, salt))]
    fn new(party_id: String, version: u64, members: Vec<String>, salt: String) -> PyResult<Self> {
        Ok(Self {
            inner: CoreOwnershipRecord::new(party_id, version, members, salt).map_err(map_err)?,
        })
    }

    #[getter]
    fn party_id(&self) -> String {
        self.inner.party_id().to_string()
    }

    /// Which revision this is. Goes on the credential; an auditor uses it to ask
    /// the store for the record as it stood at issuance rather than as it stands
    /// now.
    #[getter]
    fn version(&self) -> u64 {
        self.inner.version()
    }

    /// The members, sorted. Personal data - keep it here.
    #[getter]
    fn members(&self) -> Vec<String> {
        self.inner.members().to_vec()
    }

    /// The salted commitment, hex. The only part that travels.
    #[getter]
    fn commitment(&self) -> String {
        self.inner.commitment()
    }

    /// Whether this record is the one `commitment` was made over - the audit-time
    /// check. A record that does not match was not the one committed to.
    fn matches(&self, commitment: &str) -> bool {
        self.inner.matches(commitment)
    }

    fn __repr__(&self) -> String {
        format!(
            "OwnershipRecord(party_id='{}', version={}, members={})",
            self.inner.party_id(),
            self.inner.version(),
            self.inner.members().len()
        )
    }
}
