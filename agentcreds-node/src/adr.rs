use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::adr::{
    replay, AdrCheckpoint as CoreCheckpoint, AdrStream as CoreStream,
    AuthzDecision as CoreDecision, Decision, DecisionKind, Signal,
};

use crate::delegation::DelegationToken;
use crate::error::map_err;
use crate::identity::TrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("SerializationError: {e}"))
}

fn parse_kind(s: &str) -> Result<DecisionKind> {
    DecisionKind::parse(s).ok_or_else(|| Error::from_reason(format!("unknown decision kind: {s}")))
}

fn parse_signal(s: &str) -> Result<Signal> {
    Signal::parse(s).ok_or_else(|| Error::from_reason(format!("unknown signal: {s}")))
}

/// `"allow"` / `"deny"` / absent. Rejected rather than defaulted: a typo silently
/// read as `Allow` would record an admission that never happened.
fn parse_decision(s: Option<&str>) -> Result<Option<Decision>> {
    match s {
        None => Ok(None),
        Some("allow") => Ok(Some(Decision::Allow)),
        Some("deny") => Ok(Some(Decision::Deny)),
        Some(other) => Err(Error::from_reason(format!(
            "unknown decision {other:?} (expected \"allow\" or \"deny\")"
        ))),
    }
}

/// One Authorization Decision Record - who was allowed to do what, the outcome,
/// and any security signals. Serializable for export to a SIEM (`toJson`).
#[napi]
pub struct AuthzDecision {
    pub(crate) inner: CoreDecision,
}

#[napi]
impl AuthzDecision {
    /// Build a record from a delegation token and an outcome. `allow=false`
    /// marks a denial; pass the `signal` (e.g. `"action_denied"`) and `reason`.
    /// `kind` is one of mint/attenuate/verify/verifyRooted/presentation/revocation.
    #[napi(factory)]
    pub fn from_token(
        kind: String,
        token: &DelegationToken,
        action: Option<String>,
        allow: Option<bool>,
        signal: Option<String>,
        reason: Option<String>,
    ) -> Result<Self> {
        let kind = parse_kind(&kind)?;
        let mut inner = CoreDecision::from_token(kind, &token.inner, action.as_deref(), &Ok(()));
        if !allow.unwrap_or(true) {
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
    #[napi(factory)]
    pub fn allow(kind: String, subject_did: String) -> Result<Self> {
        Ok(Self {
            inner: CoreDecision::allow(parse_kind(&kind)?, subject_did),
        })
    }

    /// A bare deny for a subject, with a signal and reason.
    #[napi(factory)]
    pub fn deny(kind: String, subject_did: String, signal: String, reason: String) -> Result<Self> {
        Ok(Self {
            inner: CoreDecision::deny(
                parse_kind(&kind)?,
                subject_did,
                parse_signal(&signal)?,
                reason,
            ),
        })
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }
    #[napi(getter)]
    pub fn seq(&self) -> i64 {
        self.inner.seq as i64
    }
    #[napi(getter)]
    pub fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }
    #[napi(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind.as_str().to_string()
    }
    #[napi(getter)]
    pub fn decision(&self) -> String {
        self.inner.decision.as_str().to_string()
    }
    #[napi(getter)]
    pub fn allowed(&self) -> bool {
        matches!(self.inner.decision, Decision::Allow)
    }
    #[napi(getter)]
    pub fn subject_did(&self) -> String {
        self.inner.subject_did.clone()
    }
    #[napi(getter)]
    pub fn root_agent_did(&self) -> String {
        self.inner.root_agent_did.clone()
    }
    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[napi(getter)]
    pub fn vc_id(&self) -> String {
        self.inner.vc_id.clone()
    }
    #[napi(getter)]
    pub fn action(&self) -> Option<String> {
        self.inner.action.clone()
    }

    /// The principal whose authority was exercised, if any. `None` is the autonomous
    /// case, not a missing value.
    #[napi(getter)]
    pub fn principal_did(&self) -> Option<String> {
        self.inner.principal_did.clone()
    }

    /// Who answers for this decision - the responsible party *within* the issuing
    /// organization. `None` means the credential predates accountability being
    /// recorded; the organization named by `issuerDid` is accountable regardless.
    #[napi(getter)]
    pub fn accountable_party(&self) -> Option<String> {
        self.inner.accountable_party.clone()
    }

    /// How firmly the accountable party is known. Absent means the credential predates
    /// provenance being recorded, and must be read as the weakest source.
    #[napi(getter)]
    pub fn accountability_source(&self) -> Option<String> {
        self.inner.accountability_source.clone()
    }

    /// Record who answers for this decision, and on what basis.
    ///
    /// Not derivable from the token: the accountable party is a claim on the
    /// **credential**, so a verifier holds it during verification and passes it in.
    /// Without this the record answers "who is answerable" only via a join back to
    /// the credential - the join the field exists to remove.
    ///
    /// `partyVersion` and `partyCommitment` come from the same credential and turn
    /// the party from a name into a resolvable claim: which revision of the ownership
    /// record to read, and proof the record produced is the one committed to. Neither
    /// is personal data.
    #[napi]
    pub fn with_accountability(
        &self,
        party: Option<String>,
        source: Option<String>,
        party_version: Option<i64>,
        party_commitment: Option<String>,
    ) -> Self {
        Self {
            inner: self
                .inner
                .clone()
                .with_accountable_party(party)
                .with_accountability_source(source)
                .with_party_record(party_version.map(|v| v as u64), party_commitment),
        }
    }

    /// Record the R10 evaluation and admission outcomes separately.
    ///
    /// `evaluation = "allow"` with `admission = "deny"` is a replay: valid,
    /// policy-satisfying evidence refused because its reliance unit was already
    /// consumed. A single verdict field reports that identically to evidence that
    /// never verified - and the two call for opposite responses.
    ///
    /// Both absent when no execution-time gate applied, which is the ordinary case.
    #[napi]
    pub fn with_verdicts(
        &self,
        evaluation: Option<String>,
        admission: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            inner: self.inner.clone().with_verdicts(
                parse_decision(evaluation.as_deref())?,
                parse_decision(admission.as_deref())?,
            ),
        })
    }

    /// Which revision of the ownership record named the accountable party - i.e.
    /// which org chart to resolve it against.
    #[napi(getter)]
    pub fn party_version(&self) -> Option<i64> {
        self.inner.party_version.map(|v| v as i64)
    }

    /// Salted commitment to that ownership record, so the resolution can be proved
    /// rather than asserted.
    #[napi(getter)]
    pub fn party_commitment(&self) -> Option<String> {
        self.inner.party_commitment.clone()
    }

    /// Did the execution-time evidence verify and satisfy policy? `"allow"`,
    /// `"deny"`, or absent when no gate applied.
    #[napi(getter)]
    pub fn evaluation(&self) -> Option<String> {
        self.inner.evaluation.map(|d| d.as_str().to_string())
    }

    /// Was the reliance unit admitted? `"allow"`, `"deny"`, or absent.
    #[napi(getter)]
    pub fn admission(&self) -> Option<String> {
        self.inner.admission.map(|d| d.as_str().to_string())
    }
    #[napi(getter)]
    pub fn depth(&self) -> i64 {
        self.inner.depth as i64
    }
    #[napi(getter)]
    pub fn max_depth(&self) -> i64 {
        self.inner.max_depth as i64
    }
    #[napi(getter)]
    pub fn signals(&self) -> Vec<String> {
        self.inner
            .signals
            .iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }
    #[napi(getter)]
    pub fn reason(&self) -> Option<String> {
        self.inner.reason.clone()
    }

    /// The record as a JSON string (for a SIEM/log sink).
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(ser_err)
    }

    /// The canonical SHA-256 digest of this record, hex-encoded.
    #[napi]
    pub fn digest_hex(&self) -> String {
        self.inner.digest_hex()
    }
}

/// A recorder that stamps each decision with a sequence number, advances a
/// tamper-evident hash-chain, and returns the stamped record to forward.
#[napi]
pub struct AdrStream {
    inner: CoreStream,
}

impl Default for AdrStream {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl AdrStream {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreStream::new(),
        }
    }

    /// Record a decision; returns the stamped record (with its `seq` assigned).
    /// Forward the returned record to your SIEM.
    #[napi]
    pub fn record(&mut self, decision: &AuthzDecision) -> AuthzDecision {
        AuthzDecision {
            inner: self.inner.record(decision.inner.clone()),
        }
    }

    /// The current hash-chain head (hex).
    #[napi]
    pub fn head(&self) -> String {
        self.inner.head()
    }

    /// The number of decisions recorded so far.
    #[napi]
    pub fn count(&self) -> i64 {
        self.inner.count() as i64
    }

    /// Sign the current `(count, head)` with `anchor` for tamper-evidence.
    #[napi]
    pub fn sign_checkpoint(&self, anchor: &TrustAnchor) -> Result<AdrCheckpoint> {
        Ok(AdrCheckpoint {
            inner: self.inner.sign_checkpoint(&anchor.inner).map_err(map_err)?,
        })
    }

    /// Recompute the hash-chain head from a JSON array of recorded decisions
    /// (e.g. `JSON.stringify(records.map(r => JSON.parse(r.toJson())))`), to
    /// check a received stream against a signed checkpoint.
    #[napi]
    pub fn replay_json(decisions_json: String) -> Result<String> {
        let records: Vec<CoreDecision> = serde_json::from_str(&decisions_json).map_err(ser_err)?;
        Ok(replay(&records))
    }
}

/// An anchor-signed attestation that the decision log reached `count` records
/// with hash-chain `head`.
#[napi]
pub struct AdrCheckpoint {
    pub(crate) inner: CoreCheckpoint,
}

#[napi]
impl AdrCheckpoint {
    #[napi(getter)]
    pub fn count(&self) -> i64 {
        self.inner.count as i64
    }
    #[napi(getter)]
    pub fn head(&self) -> String {
        self.inner.head.clone()
    }
    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[napi(getter)]
    pub fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// Verify the checkpoint signature against `anchor`.
    #[napi]
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// The checkpoint as a JSON string.
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(ser_err)
    }

    /// Parse a checkpoint from its JSON string.
    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: serde_json::from_str(&s).map_err(ser_err)?,
        })
    }
}

#[cfg(test)]
mod accountability_tests {
    use super::*;

    // The ADR is what a Node SIEM sink forwards. A decision that carries the responsible
    // party in core but cannot expose it here answers no audit question.

    fn decision(attributed: bool) -> AuthzDecision {
        let mut inner = CoreDecision::allow(DecisionKind::VerifyRooted, "did:key:zA");
        if attributed {
            inner.principal_did = Some("did:web:acme.example:w:abc".into());
            inner.accountable_party = Some("team:settlement".into());
        }
        AuthzDecision { inner }
    }

    #[test]
    fn the_decision_exposes_who_is_answerable() {
        let d = decision(true);
        assert_eq!(d.accountable_party(), Some("team:settlement".into()));
        assert_eq!(d.principal_did(), Some("did:web:acme.example:w:abc".into()));
    }

    #[test]
    fn an_autonomous_decision_reports_absence_not_an_error() {
        // No principal is the autonomous case, not a gap in the record - and an
        // unattributed decision is a finding worth investigating, so it must be
        // readable rather than a failure.
        let d = decision(false);
        assert_eq!(d.accountable_party(), None);
        assert_eq!(d.principal_did(), None);

        // Absent fields stay off the wire: the JSON a SIEM ingests must not gain nulls
        // that would read as "explicitly nobody".
        let json = d.to_json().unwrap();
        assert!(!json.contains("accountable_party"), "{json}");
        assert!(!json.contains("principal_did"), "{json}");
    }
}
