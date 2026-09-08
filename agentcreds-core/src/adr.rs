//! ADR - the **Authorization Decision Record** event stream.
//!
//! Every time a relying party makes an authorization decision - verifying a
//! delegation token, an anchor-rooted check, a presentation, a revocation
//! lookup - it can emit an [`AuthzDecision`]: a structured, serializable record
//! of *who* was allowed to do *what*, the outcome, and any notable [`Signal`]s
//! (scope-widening attempts, depth-limit hits, expiry, revocation, unrooted
//! authority, failed proof-of-possession). Streaming these to a SIEM is how an
//! operator monitors delegation depth and escalation attempts across a fleet.
//!
//! Staying true to the offline core, this module never does I/O: decisions are
//! fanned out to in-process [`AdrSink`]s that the host wires to its log/SIEM.
//! The [`AdrStream`] additionally keeps a **tamper-evident hash-chain** over the
//! decisions and can emit an anchor-signed [`AdrCheckpoint`], so a downstream
//! consumer can prove no event was dropped, reordered, or forged.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::adr::{AdrStream, AuthzDecision, DecisionKind, Decision, InMemorySink};
//! use std::sync::Arc;
//!
//! // A relying party verifies a token, then records the decision.
//! # let anchor = TrustAnchor::generate()?;
//! # let agent = AgentIdentity::create(DidMethod::Key, None)?;
//! # let vc = CapabilityCredential::issue(&anchor, agent.did(),
//! #     CapabilityClaims::new(vec!["tool:search".into()], 2, 3600), None)?;
//! # let token = DelegationToken::mint(&vc,
//! #     Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1), 300, &agent)?;
//! let action = Action::new("tool:search", "q=rust");
//! let outcome = token.verify_rooted(&action, &vc, &anchor);
//!
//! let sink = Arc::new(InMemorySink::new());
//! let mut stream = AdrStream::new();
//! stream.subscribe(Box::new(sink.clone()));
//!
//! let adr = AuthzDecision::from_token(DecisionKind::VerifyRooted, &token, Some(&action.tool), &outcome);
//! stream.record(adr);
//!
//! assert_eq!(sink.snapshot()[0].decision, Decision::Allow);
//! // The stream's head can be checkpointed and signed for non-repudiation.
//! let checkpoint = stream.sign_checkpoint(&anchor)?;
//! assert!(checkpoint.verify(&anchor).is_ok());
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use std::sync::Mutex;

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::delegation::DelegationToken;
use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

// v2 (2026-08-07): the digest now covers `principal_did`, `accountable_party` and
// `accountability_source`. v1 left them outside the chain, so a stored decision log
// could be rewritten on exactly the fields an audit reads and still verify.
//
// The version bump is deliberate. Adding fields already changes every digest; the
// new domain makes that break unambiguous rather than leaving a v1 chain and a v2
// recomputation to disagree with no explanation. A chain recorded under v1 will not
// replay under v2 - re-checkpoint from the current head, and treat a stored
// `save_chain_state` head from before the upgrade as v1 evidence.
const DIGEST_DOMAIN: &[u8] = b"agentcreds-adr-record-v2";
const CHAIN_DOMAIN: &[u8] = b"agentcreds-adr-chain-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"agentcreds-adr-checkpoint-v1";

fn adr_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::InvalidVcProof {
        reason: reason.into(),
    }
}

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

/// Hash an optional field with an explicit presence tag, so absent and empty are
/// distinct. `None` on an accountability field is a claim in its own right - "this
/// agent acted on no principal's behalf" - and must not be interchangeable with an
/// empty string.
fn write_opt(h: &mut Sha256, field: Option<&str>) {
    match field {
        Some(v) => {
            h.update([1u8]);
            write_field(h, v.as_bytes());
        }
        None => h.update([0u8]),
    }
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    format!("urn:adr:{}", hex::encode(b))
}

// -- Decision / kind / signals ----------------------------------------------------

/// The outcome of an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The action was permitted.
    Allow,
    /// The action was refused.
    Deny,
}

impl Decision {
    /// The canonical lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// What kind of check produced the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// A token was minted from a credential.
    Mint,
    /// A token was attenuated for a sub-agent.
    Attenuate,
    /// Chain-only verification ([`DelegationToken::verify`]).
    Verify,
    /// Anchor-rooted verification ([`DelegationToken::verify_rooted`]).
    VerifyRooted,
    /// A proof-of-possession presentation was checked.
    Presentation,
    /// A revocation status was consulted.
    Revocation,
}

impl DecisionKind {
    /// The canonical lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Attenuate => "attenuate",
            Self::Verify => "verify",
            Self::VerifyRooted => "verify_rooted",
            Self::Presentation => "presentation",
            Self::Revocation => "revocation",
        }
    }

    /// Parse a canonical name (as from [`as_str`](Self::as_str)).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "mint" => Self::Mint,
            "attenuate" => Self::Attenuate,
            "verify" => Self::Verify,
            "verify_rooted" => Self::VerifyRooted,
            "presentation" => Self::Presentation,
            "revocation" => Self::Revocation,
            _ => return None,
        })
    }
}

/// A notable condition attached to a decision - the security-relevant signals an
/// operator watches for. Derived from the failure that caused a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// An attenuation/mint tried to widen scope beyond its parent.
    ScopeWideningAttempt,
    /// Delegation depth exceeded the credential's ceiling.
    DelegationDepthExceeded,
    /// The token or credential had expired.
    Expired,
    /// The credential was revoked (or the revocation list failed to verify).
    Revoked,
    /// The credential issuer did not match the expected anchor.
    IssuerMismatch,
    /// Authority did not trace to the relying party's anchor/credential.
    UnrootedAuthority,
    /// A signature (Biscuit, VC proof, DID, SVID) failed to verify.
    SignatureInvalid,
    /// The requested action was outside the token's policy.
    ActionDenied,
    /// Proof of possession failed (theft / prefix-stripping defense).
    ProofOfPossessionFailed,
    /// A denial that does not map to a more specific signal.
    Other,
}

impl Signal {
    /// The canonical lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScopeWideningAttempt => "scope_widening_attempt",
            Self::DelegationDepthExceeded => "delegation_depth_exceeded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::UnrootedAuthority => "unrooted_authority",
            Self::SignatureInvalid => "signature_invalid",
            Self::ActionDenied => "action_denied",
            Self::ProofOfPossessionFailed => "proof_of_possession_failed",
            Self::Other => "other",
        }
    }

    /// Parse a canonical name (as from [`as_str`](Self::as_str)).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scope_widening_attempt" => Self::ScopeWideningAttempt,
            "delegation_depth_exceeded" => Self::DelegationDepthExceeded,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            "issuer_mismatch" => Self::IssuerMismatch,
            "unrooted_authority" => Self::UnrootedAuthority,
            "signature_invalid" => Self::SignatureInvalid,
            "action_denied" => Self::ActionDenied,
            "proof_of_possession_failed" => Self::ProofOfPossessionFailed,
            "other" => Self::Other,
            _ => return None,
        })
    }

    /// Classify an error into the signal an operator should see.
    #[must_use]
    pub fn from_error(err: &AgentCredsError) -> Self {
        match err {
            AgentCredsError::ScopeWideningAttempt { .. } => Self::ScopeWideningAttempt,
            AgentCredsError::DelegationDepthExceeded { .. } => Self::DelegationDepthExceeded,
            AgentCredsError::TokenExpired { .. } | AgentCredsError::CredentialExpired { .. } => {
                Self::Expired
            }
            AgentCredsError::CredentialRevoked { .. }
            | AgentCredsError::InvalidRevocationListSignature
            | AgentCredsError::RevocationIndexOutOfBounds { .. } => Self::Revoked,
            AgentCredsError::IssuerMismatch { .. } => Self::IssuerMismatch,
            AgentCredsError::RootKeyMismatch => Self::UnrootedAuthority,
            AgentCredsError::ActionDenied { .. } => Self::ActionDenied,
            AgentCredsError::ProofOfPossessionFailed { .. } => Self::ProofOfPossessionFailed,
            AgentCredsError::InvalidBiscuitSignature { .. }
            | AgentCredsError::InvalidVcProof { .. }
            | AgentCredsError::InvalidDidSignature { .. }
            | AgentCredsError::InvalidKeyMaterial { .. }
            | AgentCredsError::SvidValidationFailed { .. } => Self::SignatureInvalid,
            _ => Self::Other,
        }
    }
}

// -- AuthzDecision (the ADR) ------------------------------------------------------

/// One Authorization Decision Record. Serializable for export to a log/SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecision {
    /// Unique record id (`urn:adr:<hex>`).
    pub id: String,
    /// Sequence number within an [`AdrStream`] (0 until recorded).
    pub seq: u64,
    /// When the decision was made.
    pub timestamp: DateTime<Utc>,
    /// Which check produced it.
    pub kind: DecisionKind,
    /// The outcome.
    pub decision: Decision,
    /// The acting (leaf) agent's DID.
    pub subject_did: String,
    /// The root (subject) agent's DID.
    pub root_agent_did: String,
    /// The issuing anchor's DID.
    pub issuer_did: String,
    /// The root credential id - the correlation id, shared with the audit
    /// compositor (see [`crate::audit`]).
    pub vc_id: String,
    /// The requested action/tool, if any.
    pub action: Option<String>,

    /// The principal whose authority the agent was exercising, if any.
    ///
    /// Previously reconstructing this meant joining on `vc_id` back to the credential.
    /// Recording it here makes the decision self-describing: an auditor reading the
    /// chain does not have to hold the credential to know whose authority was used.
    /// `None` is meaningful - it says the agent acted on no principal's behalf, which
    /// is the autonomous case, not a gap in the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_did: Option<String>,

    /// **Who answers for this decision.**
    ///
    /// Carried on the record itself rather than left to a join, because the join used
    /// to land on a credential claim that is advisory *and* selectively disclosable -
    /// a verifier could be denied sight of it. "Who is responsible" is the question an
    /// audit exists to answer, so it belongs in the audit record.
    ///
    /// `None` means the credential predates accountability being recorded; it never
    /// means no one is responsible. The organization whose anchor signed the root
    /// credential (`issuer_did`) is accountable regardless - this narrows *within* that
    /// organization, it does not replace it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountable_party: Option<String>,

    /// Which revision of the ownership record named that party, and a salted
    /// commitment to it - copied from the credential so the decision is
    /// self-describing.
    ///
    /// Together these turn `accountable_party` from a name into a resolvable
    /// claim: the version says which org chart to read, the commitment lets the
    /// reader prove the record they produced is the one that was committed to.
    /// Neither is personal data; the members stay in the organization's own store.
    /// See [`crate::accountability`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_version: Option<u64>,
    /// Salted commitment to the ownership record - see [`Self::party_version`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_commitment: Option<String>,

    /// **Did the execution-time evidence verify and satisfy policy?** (R10)
    ///
    /// Kept separate from [`Self::admission`] because they answer different
    /// questions and fail for opposite reasons. Collapsed into one verdict, the
    /// record cannot distinguish *the evidence was bad* from *the evidence was
    /// good and had already been spent* - and those call for opposite responses:
    /// one is a rejected request, the other is a replay against a valid approval.
    ///
    /// `None` when no execution-time gate applied to the action, which is the
    /// ordinary case and not a gap in the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<Decision>,

    /// **Was the reliance unit admitted?** (R10 at-most-once)
    ///
    /// `Deny` here with [`Self::evaluation`] `Allow` is the honest shape of a
    /// replay: the second attempt presented the same still-valid authorization
    /// and was refused as already consumed, with no outcome. A verifier that
    /// records only the final verdict reports that identically to a request whose
    /// evidence never verified at all.
    ///
    /// `None` when no execution-time gate applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<Decision>,

    /// **How firmly the accountable party is known** - `policy`, `asserted`, `attested`.
    ///
    /// Travels with the party because in an audit they are one question. A record that
    /// says who answers but not on what basis invites the reader to assume the strongest
    /// reading, and the weakest one - a requester naming itself - is exactly the case
    /// worth noticing.
    ///
    /// Omitted when the party is absent or its source was never recorded; absence means
    /// the credential predates provenance being captured, and must be read as the
    /// weakest source rather than an unknown one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountability_source: Option<String>,
    /// Delegation depth at the time of the decision.
    pub depth: u32,
    /// The credential's maximum delegation depth.
    pub max_depth: u32,
    /// Notable signals (empty on a clean allow).
    pub signals: Vec<Signal>,
    /// Human-readable detail (typically the denying error).
    pub reason: Option<String>,
}

impl AuthzDecision {
    /// Build a decision from a delegation token and the result of verifying it.
    /// `Ok` becomes an [`Decision::Allow`]; `Err` becomes a [`Decision::Deny`]
    /// with the classified [`Signal`] and the error text as the reason.
    pub fn from_token(
        kind: DecisionKind,
        token: &DelegationToken,
        action: Option<&str>,
        result: &Result<()>,
    ) -> Self {
        let (decision, signals, reason) = match result {
            Ok(()) => (Decision::Allow, Vec::new(), None),
            Err(e) => (
                Decision::Deny,
                vec![Signal::from_error(e)],
                Some(e.to_string()),
            ),
        };
        AuthzDecision {
            id: new_id(),
            seq: 0,
            timestamp: Utc::now(),
            kind,
            decision,
            subject_did: token.leaf_agent_did().to_string(),
            root_agent_did: token.root_agent_did().to_string(),
            issuer_did: token.issuer_did().to_string(),
            vc_id: token.vc_id().to_string(),
            action: action.map(ToString::to_string),
            // Both come from the verified token/credential, never from the caller.
            principal_did: token.principal_did().map(ToString::to_string),
            accountable_party: None,
            party_version: None,
            party_commitment: None,
            evaluation: None,
            admission: None,
            accountability_source: None,
            depth: token.depth(),
            max_depth: token.max_delegation_depth(),
            signals,
            reason,
        }
    }

    /// Record how the accountable party was established (see
    /// [`crate::vc::AuthoritySource`]).
    ///
    /// Set alongside [`with_accountable_party`](Self::with_accountable_party): in an
    /// audit, who answers and on what basis are one question.
    #[must_use]
    pub fn with_accountability_source(mut self, source: Option<String>) -> Self {
        self.accountability_source = source;
        self
    }

    /// Record who answers for this decision.
    ///
    /// Separate from [`from_token`](Self::from_token) because the accountable party is a
    /// claim on the **credential**, which the token alone does not carry - the caller
    /// holds it during verification and passes it in.
    #[must_use]
    pub fn with_accountable_party(mut self, party: Option<String>) -> Self {
        self.accountable_party = party;
        self
    }

    /// Record which revision of the ownership record named the party, and the
    /// salted commitment to it - both read from the credential.
    ///
    /// Set alongside [`with_accountable_party`](Self::with_accountable_party).
    /// Without these the party is a name resolved against whatever the org chart
    /// says at reading time; with them it is resolvable *as of issuance*, and the
    /// resolution is checkable. See [`crate::accountability`].
    #[must_use]
    pub fn with_party_record(mut self, version: Option<u64>, commitment: Option<String>) -> Self {
        self.party_version = version;
        self.party_commitment = commitment;
        self
    }

    /// Record the R10 evaluation and admission outcomes separately.
    ///
    /// Both `None` when no execution-time gate applied. `evaluation = Allow` with
    /// `admission = Deny` is a replay: valid, policy-satisfying evidence refused
    /// because its reliance unit was already consumed - which a single verdict
    /// field reports identically to evidence that never verified.
    #[must_use]
    pub fn with_verdicts(
        mut self,
        evaluation: Option<Decision>,
        admission: Option<Decision>,
    ) -> Self {
        self.evaluation = evaluation;
        self.admission = admission;
        self
    }

    /// A bare allow for a subject (e.g. a non-token check). Enrich with the
    /// `with_*` setters.
    pub fn allow(kind: DecisionKind, subject_did: impl Into<String>) -> Self {
        Self::bare(kind, subject_did.into(), Decision::Allow, Vec::new(), None)
    }

    /// A bare deny for a subject, with a signal and reason.
    pub fn deny(
        kind: DecisionKind,
        subject_did: impl Into<String>,
        signal: Signal,
        reason: impl Into<String>,
    ) -> Self {
        Self::bare(
            kind,
            subject_did.into(),
            Decision::Deny,
            vec![signal],
            Some(reason.into()),
        )
    }

    fn bare(
        kind: DecisionKind,
        subject_did: String,
        decision: Decision,
        signals: Vec<Signal>,
        reason: Option<String>,
    ) -> Self {
        AuthzDecision {
            id: new_id(),
            seq: 0,
            timestamp: Utc::now(),
            kind,
            decision,
            subject_did,
            root_agent_did: String::new(),
            issuer_did: String::new(),
            vc_id: String::new(),
            action: None,
            principal_did: None,
            accountable_party: None,
            party_version: None,
            party_commitment: None,
            evaluation: None,
            admission: None,
            accountability_source: None,
            depth: 0,
            max_depth: 0,
            signals,
            reason,
        }
    }

    /// Set the requested action.
    #[must_use]
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the correlation (root VC id) and issuer anchor DID.
    #[must_use]
    pub fn with_correlation(
        mut self,
        vc_id: impl Into<String>,
        issuer_did: impl Into<String>,
    ) -> Self {
        self.vc_id = vc_id.into();
        self.issuer_did = issuer_did.into();
        self
    }

    /// The salted-free, canonical SHA-256 digest of this record (32 bytes). Used
    /// by the stream hash-chain; excludes the volatile `seq`.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        write_field(&mut h, self.id.as_bytes());
        h.update(self.timestamp.timestamp().to_le_bytes());
        write_field(&mut h, self.kind.as_str().as_bytes());
        write_field(&mut h, self.decision.as_str().as_bytes());
        write_field(&mut h, self.subject_did.as_bytes());
        write_field(&mut h, self.root_agent_did.as_bytes());
        write_field(&mut h, self.issuer_did.as_bytes());
        write_field(&mut h, self.vc_id.as_bytes());
        write_field(&mut h, self.action.as_deref().unwrap_or("").as_bytes());
        h.update(self.depth.to_le_bytes());
        h.update(self.max_depth.to_le_bytes());
        h.update((self.signals.len() as u64).to_le_bytes());
        for s in &self.signals {
            write_field(&mut h, s.as_str().as_bytes());
        }
        write_field(&mut h, self.reason.as_deref().unwrap_or("").as_bytes());
        // Accountability. Omitting these left the exact fields an audit turns on
        // outside the tamper-evident chain: anyone able to write to a stored
        // decision log could rewrite who was answerable, and both `replay` and the
        // signed checkpoint would still verify. A record is only as trustworthy as
        // the narrowest thing its digest covers.
        //
        // Presence-tagged rather than `unwrap_or("")`, so "no principal" (the
        // autonomous case, which is meaningful) cannot be forged into, or out of,
        // an empty-string principal.
        write_opt(&mut h, self.principal_did.as_deref());
        write_opt(&mut h, self.accountable_party.as_deref());
        write_opt(&mut h, self.accountability_source.as_deref());
        // The party's resolution material. A version an attacker could edit lets a
        // reader be pointed at a *different* revision of the org chart - one that
        // names someone else - without touching the party string at all.
        match self.party_version {
            Some(v) => {
                h.update([1u8]);
                h.update(v.to_le_bytes());
            }
            None => h.update([0u8]),
        }
        write_opt(&mut h, self.party_commitment.as_deref());
        // The R10 verdicts. Outside the hash, a stored log could be edited to turn a
        // refused replay into a request whose evidence merely failed - hiding that a
        // valid human approval was presented twice.
        write_opt(&mut h, self.evaluation.map(Decision::as_str));
        write_opt(&mut h, self.admission.map(Decision::as_str));
        h.finalize().into()
    }

    /// The [`digest`](Self::digest) as a hex string.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest())
    }
}

// -- Sinks ---------------------------------------------------------------------

/// A destination for recorded decisions. The host implements this to forward to
/// a log, metrics pipeline, or SIEM. A `Fn(&AuthzDecision)` closure also works.
pub trait AdrSink: Send + Sync {
    /// Handle one recorded decision. Must not panic; do I/O off the hot path.
    fn emit(&self, decision: &AuthzDecision);
}

impl<F> AdrSink for F
where
    F: Fn(&AuthzDecision) + Send + Sync,
{
    fn emit(&self, decision: &AuthzDecision) {
        self(decision);
    }
}

/// An in-memory sink that retains the most recent decisions (bounded). Useful
/// for tests, a `/recent-decisions` endpoint, or a local ring buffer.
#[derive(Debug)]
pub struct InMemorySink {
    capacity: usize,
    records: Mutex<Vec<AuthzDecision>>,
}

impl InMemorySink {
    /// A sink retaining up to 1024 recent decisions.
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// A sink retaining up to `capacity` recent decisions (oldest dropped).
    pub fn with_capacity(capacity: usize) -> Self {
        InMemorySink {
            capacity: capacity.max(1),
            records: Mutex::new(Vec::new()),
        }
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Vec<AuthzDecision>> {
        // Recover from a poisoned lock rather than propagate a panic.
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A snapshot of the retained decisions, oldest first.
    pub fn snapshot(&self) -> Vec<AuthzDecision> {
        self.guard().clone()
    }

    /// The number of retained decisions.
    pub fn len(&self) -> usize {
        self.guard().len()
    }

    /// Whether no decisions are retained.
    pub fn is_empty(&self) -> bool {
        self.guard().is_empty()
    }
}

impl Default for InMemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl AdrSink for InMemorySink {
    fn emit(&self, decision: &AuthzDecision) {
        let mut records = self.guard();
        if records.len() >= self.capacity {
            records.remove(0);
        }
        records.push(decision.clone());
    }
}

// `Arc<S>` is a sink if `S` is - lets one sink be shared (and inspected) while
// the stream owns a handle.
impl<S: AdrSink + ?Sized> AdrSink for std::sync::Arc<S> {
    fn emit(&self, decision: &AuthzDecision) {
        (**self).emit(decision);
    }
}

// -- AdrStream -----------------------------------------------------------------

/// A recorder that stamps each decision with a sequence number, advances a
/// tamper-evident hash-chain, and fans the decision out to every subscribed
/// [`AdrSink`].
pub struct AdrStream {
    sinks: Vec<Box<dyn AdrSink>>,
    seq: u64,
    head: [u8; 32],
}

impl AdrStream {
    /// A new, empty stream (genesis head).
    pub fn new() -> Self {
        let mut h = Sha256::new();
        h.update(CHAIN_DOMAIN);
        AdrStream {
            sinks: Vec::new(),
            seq: 0,
            head: h.finalize().into(),
        }
    }

    /// Resume a stream at a known `(count, head)` recovered from durable storage,
    /// instead of replaying every decision from genesis. The next
    /// [`record`](Self::record) continues the same hash-chain (assigning seq
    /// `count`), so a resumed stream and a fully-replayed one fold subsequent
    /// decisions identically - this is what lets the durable log be trimmed without
    /// losing restart correctness. `head` is the 32-byte chain head as lowercase
    /// hex (exactly as [`head`](Self::head) returns).
    ///
    /// # Errors
    /// [`AgentCredsError::MalformedClaims`] if `head` is not 32 bytes of hex.
    pub fn resume(count: u64, head: &str) -> Result<Self> {
        let bytes = hex::decode(head).map_err(|e| AgentCredsError::MalformedClaims {
            reason: format!("ADR chain head is not valid hex: {e}"),
        })?;
        let head: [u8; 32] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| AgentCredsError::MalformedClaims {
                    reason: format!("ADR chain head must be 32 bytes, got {}", bytes.len()),
                })?;
        Ok(AdrStream {
            sinks: Vec::new(),
            seq: count,
            head,
        })
    }

    /// Subscribe a sink. All previously and subsequently recorded decisions on
    /// this stream are delivered to every sink at [`record`](Self::record) time.
    pub fn subscribe(&mut self, sink: Box<dyn AdrSink>) -> &mut Self {
        self.sinks.push(sink);
        self
    }

    /// Record a decision: assign its sequence number, fold it into the
    /// hash-chain, and emit it to all sinks. Returns the stamped record.
    pub fn record(&mut self, mut decision: AuthzDecision) -> AuthzDecision {
        decision.seq = self.seq;
        self.head = fold(&self.head, self.seq, &decision.digest());
        self.seq += 1;
        for sink in &self.sinks {
            sink.emit(&decision);
        }
        decision
    }

    /// The current hash-chain head (hex). Two consumers that replay the same
    /// ordered decisions arrive at the same head.
    pub fn head(&self) -> String {
        hex::encode(self.head)
    }

    /// The number of decisions recorded so far.
    pub fn count(&self) -> u64 {
        self.seq
    }

    /// Sign the current `(count, head)` with `anchor` - a checkpoint a consumer
    /// can verify the decision log against.
    ///
    /// # Errors
    /// If the anchor fails to sign.
    pub fn sign_checkpoint(&self, anchor: &TrustAnchor) -> Result<AdrCheckpoint> {
        let mut checkpoint = AdrCheckpoint {
            count: self.seq,
            head: self.head(),
            issuer_did: anchor.did().to_string(),
            signature: String::new(),
        };
        let sig = anchor.sign(&checkpoint.signing_payload())?;
        checkpoint.signature = base64ct::Base64::encode_string(&sig);
        Ok(checkpoint)
    }
}

impl Default for AdrStream {
    fn default() -> Self {
        Self::new()
    }
}

/// Fold one decision into a hash-chain head.
fn fold(prev_head: &[u8; 32], seq: u64, digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update(prev_head);
    h.update(seq.to_le_bytes());
    h.update(digest);
    h.finalize().into()
}

/// Recompute the hash-chain head from an ordered slice of decisions - for a
/// consumer to check its received stream against a signed [`AdrCheckpoint`].
/// Decisions must be in `seq` order (as delivered).
pub fn replay(decisions: &[AuthzDecision]) -> String {
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    let mut head: [u8; 32] = h.finalize().into();
    for d in decisions {
        head = fold(&head, d.seq, &d.digest());
    }
    hex::encode(head)
}

// -- AdrCheckpoint -------------------------------------------------------------

/// An anchor-signed attestation that the decision log reached `count` records
/// with hash-chain `head`. Tamper-evidence for the whole stream in one signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdrCheckpoint {
    /// Number of decisions covered.
    pub count: u64,
    /// The hash-chain head over those decisions (hex).
    pub head: String,
    /// The signing anchor's DID.
    pub issuer_did: String,
    /// The anchor's signature over `(count, head)`.
    pub signature: String,
}

impl AdrCheckpoint {
    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(CHECKPOINT_DOMAIN);
        h.update(self.count.to_le_bytes());
        write_field(&mut h, self.head.as_bytes());
        write_field(&mut h, self.issuer_did.as_bytes());
        h.finalize().to_vec()
    }

    /// Verify the checkpoint signature against `anchor`.
    ///
    /// # Errors
    /// `InvalidVcProof` on an anchor/issuer mismatch or a bad signature.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        if self.issuer_did != anchor.did() {
            return Err(adr_err("checkpoint issuer does not match the anchor"));
        }
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| adr_err(format!("signature base64: {e}")))?;
        anchor
            .verify_signature(&self.signing_payload(), &sig)
            .map_err(|_| adr_err("checkpoint signature does not verify"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::delegation::{Action, Scope};
    use crate::did::{AgentIdentity, DidMethod};
    use crate::vc::{CapabilityClaims, CapabilityCredential};
    use std::sync::Arc;

    fn token() -> (
        TrustAnchor,
        AgentIdentity,
        CapabilityCredential,
        DelegationToken,
    ) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = CapabilityCredential::issue(
            &anchor,
            agent.did(),
            CapabilityClaims::new(vec!["tool:search".into(), "tool:email".into()], 2, 3600),
            None,
        )
        .unwrap();
        let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
        let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
        (anchor, agent, vc, token)
    }

    #[test]
    fn resume_matches_full_replay() {
        let (anchor, _a, vc, token) = token();
        let action = Action::new("tool:search", "q=ok");
        let mk = || {
            let result = token.verify_rooted(&action, &vc, &anchor);
            AuthzDecision::from_token(
                DecisionKind::VerifyRooted,
                &token,
                Some(&action.tool),
                &result,
            )
        };
        // Build the decisions once and fold the *same* objects on both paths.
        let ds: Vec<AuthzDecision> = (0..4).map(|_| mk()).collect();

        // Full stream from genesis.
        let mut full = AdrStream::new();
        for d in &ds {
            full.record(d.clone());
        }
        let full_head = full.head();

        // Record the first two, persist (count, head), then *resume* and record the
        // rest - the head and count must match the full-replay stream exactly.
        let mut a = AdrStream::new();
        a.record(ds[0].clone());
        a.record(ds[1].clone());
        let mut resumed = AdrStream::resume(a.count(), &a.head()).unwrap();
        resumed.record(ds[2].clone());
        resumed.record(ds[3].clone());
        assert_eq!(resumed.head(), full_head);
        assert_eq!(resumed.count(), 4);

        // resume() round-trips a head and rejects malformed ones.
        assert_eq!(AdrStream::resume(2, &a.head()).unwrap().head(), a.head());
        assert!(AdrStream::resume(0, "not-hex").is_err());
        assert!(AdrStream::resume(0, "abcd").is_err());
    }

    #[test]
    fn allow_decision_from_successful_verify() {
        let (anchor, _agent, vc, token) = token();
        let action = Action::new("tool:search", "q=ok");
        let result = token.verify_rooted(&action, &vc, &anchor);
        let adr = AuthzDecision::from_token(
            DecisionKind::VerifyRooted,
            &token,
            Some(&action.tool),
            &result,
        );
        assert_eq!(adr.decision, Decision::Allow);
        assert!(adr.signals.is_empty());
        assert_eq!(adr.vc_id, token.vc_id());
        assert_eq!(adr.subject_did, token.leaf_agent_did());
    }

    #[test]
    fn denied_action_surfaces_action_denied_signal() {
        let (_anchor, _agent, _vc, token) = token();
        let action = Action::new("tool:email", "to=evil"); // narrowed away
        let result = token.verify(&action);
        let adr =
            AuthzDecision::from_token(DecisionKind::Verify, &token, Some(&action.tool), &result);
        assert_eq!(adr.decision, Decision::Deny);
        assert_eq!(adr.signals, vec![Signal::ActionDenied]);
        assert!(adr.reason.is_some());
    }

    #[test]
    fn scope_widening_attempt_is_signalled() {
        let (_anchor, agent, vc, token) = token();
        let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let _ = agent;
        let wider =
            Scope::with_budget_and_depth(vec!["tool:search".into(), "tool:email".into()], None, 1);
        let result = token.attenuate(wider, 60, &sub).map(|_| ());
        let adr = AuthzDecision::from_token(DecisionKind::Attenuate, &token, None, &result);
        assert_eq!(adr.decision, Decision::Deny);
        assert_eq!(adr.signals, vec![Signal::ScopeWideningAttempt]);
        let _ = vc;
    }

    #[test]
    fn unrooted_token_signals_via_verify_rooted() {
        // An attacker's self-rooted token verifies chain-only but fails rooted.
        let attacker_anchor = TrustAnchor::generate().unwrap();
        let attacker = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let attacker_vc = CapabilityCredential::issue(
            &attacker_anchor,
            attacker.did(),
            CapabilityClaims::new(vec!["tool:admin".into()], 2, 3600),
            None,
        )
        .unwrap();
        let scope = Scope::with_budget_and_depth(vec!["tool:admin".into()], None, 1);
        let attacker_token = DelegationToken::mint(&attacker_vc, scope, 300, &attacker).unwrap();

        // Relying party checks against ITS anchor/VC.
        let (anchor, _a, vc, _t) = token();
        let action = Action::new("tool:admin", "");
        let result = attacker_token.verify_rooted(&action, &vc, &anchor);
        let adr = AuthzDecision::from_token(
            DecisionKind::VerifyRooted,
            &attacker_token,
            Some(&action.tool),
            &result,
        );
        assert_eq!(adr.decision, Decision::Deny);
        assert!(!adr.signals.is_empty());
    }

    #[test]
    fn stream_fans_out_and_chains() {
        let (_anchor, _agent, vc, token) = token();
        let action = Action::new("tool:search", "q=ok");
        let sink = Arc::new(InMemorySink::new());
        let mut stream = AdrStream::new();
        stream.subscribe(Box::new(sink.clone()));

        for _ in 0..3 {
            let r = token.verify(&action);
            stream.record(AuthzDecision::from_token(
                DecisionKind::Verify,
                &token,
                Some(&action.tool),
                &r,
            ));
        }
        let _ = vc;

        let captured = sink.snapshot();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].seq, 0);
        assert_eq!(captured[2].seq, 2);
        assert_eq!(stream.count(), 3);
        // A consumer replaying the delivered records reaches the same head.
        assert_eq!(replay(&captured), stream.head());
    }

    #[test]
    fn closure_sink_is_accepted() {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = counter.clone();
        let mut stream = AdrStream::new();
        stream.subscribe(Box::new(move |_d: &AuthzDecision| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        stream.record(AuthzDecision::allow(DecisionKind::Revocation, "did:key:zX"));
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn signed_checkpoint_verifies_and_detects_tampering() {
        let (anchor, _agent, _vc, token) = token();
        let action = Action::new("tool:search", "q=ok");
        let mut stream = AdrStream::new();
        let mut delivered = Vec::new();
        for _ in 0..2 {
            let r = token.verify(&action);
            delivered.push(stream.record(AuthzDecision::from_token(
                DecisionKind::Verify,
                &token,
                Some(&action.tool),
                &r,
            )));
        }
        let checkpoint = stream.sign_checkpoint(&anchor).unwrap();
        assert!(checkpoint.verify(&anchor).is_ok());
        // The signed head matches an honest replay.
        assert_eq!(checkpoint.head, replay(&delivered));

        // Drop a record -> replay no longer matches the signed head.
        assert_ne!(replay(&delivered[..1]), checkpoint.head);

        // A different anchor cannot validate the checkpoint.
        let stranger = TrustAnchor::generate().unwrap();
        assert!(checkpoint.verify(&stranger).is_err());
    }

    #[test]
    fn in_memory_sink_is_bounded() {
        let sink = InMemorySink::with_capacity(2);
        for i in 0..5 {
            sink.emit(&AuthzDecision::allow(
                DecisionKind::Verify,
                format!("did:key:z{i}"),
            ));
        }
        assert_eq!(sink.len(), 2);
        // Oldest dropped; the last two remain.
        let snap = sink.snapshot();
        assert!(snap[0].subject_did.ends_with('3'));
        assert!(snap[1].subject_did.ends_with('4'));
    }

    /// The chain must cover who was answerable, or it protects everything except
    /// the field an audit is actually read for.
    ///
    /// Until v2 of the digest domain it did not: `principal_did`,
    /// `accountable_party` and `accountability_source` were outside the hash, so a
    /// stored decision log could be rewritten to name a different responsible
    /// party and both `replay` and the anchor-signed checkpoint would still pass.
    #[test]
    fn digest_covers_the_accountability_fields() {
        let base = AuthzDecision::allow(DecisionKind::Verify, "did:key:zX");

        let mut party = base.clone();
        party.accountable_party = Some("team:payments".into());
        assert_ne!(
            base.digest(),
            party.digest(),
            "accountable party is unprotected"
        );

        // Swapping one party for another must not collide.
        let mut other = base.clone();
        other.accountable_party = Some("team:reporting".into());
        assert_ne!(
            party.digest(),
            other.digest(),
            "the party can be swapped freely"
        );

        // How firmly it is known is part of the claim: `asserted` must not be
        // silently upgradable to `attested`.
        let mut asserted = party.clone();
        asserted.accountability_source = Some("asserted".into());
        let mut attested = party.clone();
        attested.accountability_source = Some("attested".into());
        assert_ne!(
            asserted.digest(),
            attested.digest(),
            "provenance is unprotected"
        );

        let mut principal = base.clone();
        principal.principal_did = Some("did:web:acme.example:u:abc".into());
        assert_ne!(
            base.digest(),
            principal.digest(),
            "principal is unprotected"
        );

        // The resolution material. An editable version silently points a reader at
        // a different revision of the org chart - naming different people - without
        // the party string changing at all, which is the subtler of the two attacks.
        let mut v7 = party.clone();
        v7 = v7.with_party_record(Some(7), Some("aa".into()));
        let mut v8 = party.clone();
        v8 = v8.with_party_record(Some(8), Some("aa".into()));
        assert_ne!(v7.digest(), v8.digest(), "party version is unprotected");

        let mut other_commit = party.clone();
        other_commit = other_commit.with_party_record(Some(7), Some("bb".into()));
        assert_ne!(
            v7.digest(),
            other_commit.digest(),
            "commitment is unprotected"
        );
        assert_ne!(
            party.digest(),
            v7.digest(),
            "absent version collides with present"
        );

        // The R10 verdicts. The shape that matters is evaluation=allow with
        // admission=deny - a replay of valid, already-spent evidence. If the pair
        // is outside the digest, a stored log can be edited to read as evidence
        // that merely failed, hiding that a valid human approval was presented
        // twice.
        let replay = base
            .clone()
            .with_verdicts(Some(Decision::Allow), Some(Decision::Deny));
        let bad_evidence = base
            .clone()
            .with_verdicts(Some(Decision::Deny), Some(Decision::Deny));
        assert_ne!(base.digest(), replay.digest(), "verdicts are unprotected");
        assert_ne!(
            replay.digest(),
            bad_evidence.digest(),
            "a replay can be rewritten as an evidence failure"
        );

        // Absent must not be forgeable into empty. `None` says "acted on no
        // principal's behalf", which is a claim, not a blank.
        let mut empty = base.clone();
        empty.principal_did = Some(String::new());
        assert_ne!(base.digest(), empty.digest(), "absent collides with empty");
    }

    #[test]
    fn digest_is_stable_and_excludes_seq() {
        let mut a = AuthzDecision::allow(DecisionKind::Verify, "did:key:zX");
        let before = a.digest();
        a.seq = 99; // seq is not part of the digest
        assert_eq!(before, a.digest());
    }

    // -- Vocabularies and builders --------------------------------------------
    //
    // Found unexercised by a production-only coverage audit on 2026-08-08. Two groups,
    // and they fail differently:
    //
    //   * `DecisionKind` / `Signal` are a WIRE VOCABULARY - they cross into the audit
    //     log, the SIEM stream and the control plane's decision API. A name that stops
    //     round-tripping silently orphans records written with the old one.
    //   * The `with_*` builders carry the accountability fields added this week. An
    //     unexercised setter that quietly drops its argument produces decision records
    //     answering "who is responsible" with nothing - the exact question the
    //     accountability work exists to answer.

    /// Every variant round-trips through its canonical name, the names are distinct, and
    /// an unknown name is refused rather than defaulted.
    #[test]
    fn decision_kinds_round_trip_and_reject_unknown_names() {
        let all = [
            DecisionKind::Mint,
            DecisionKind::Attenuate,
            DecisionKind::Verify,
            DecisionKind::VerifyRooted,
            DecisionKind::Presentation,
            DecisionKind::Revocation,
        ];
        for k in all {
            let name = k.as_str();
            assert!(!name.is_empty());
            assert_eq!(
                DecisionKind::parse(name),
                Some(k),
                "{name} must parse back to the variant that emitted it"
            );
        }
        // Two variants sharing a name would silently merge records in the audit log.
        let mut names: Vec<&str> = all.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "decision-kind names must be distinct");

        assert_eq!(DecisionKind::parse("not_a_kind"), None);
        assert_eq!(DecisionKind::parse(""), None);
        assert_eq!(
            DecisionKind::parse("Mint"),
            None,
            "parsing is exact - a case variant is a different name on the wire"
        );
    }

    #[test]
    fn signals_round_trip_and_reject_unknown_names() {
        let all = [
            Signal::ScopeWideningAttempt,
            Signal::DelegationDepthExceeded,
            Signal::Expired,
            Signal::Revoked,
            Signal::IssuerMismatch,
            Signal::UnrootedAuthority,
            Signal::SignatureInvalid,
            Signal::ActionDenied,
            Signal::ProofOfPossessionFailed,
            Signal::Other,
        ];
        for sig in all {
            let name = sig.as_str();
            assert!(!name.is_empty());
            assert_eq!(
                Signal::parse(name),
                Some(sig),
                "{name} must parse back to the variant that emitted it"
            );
        }
        let mut names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "signal names must be distinct");

        assert_eq!(Signal::parse("no_such_signal"), None);
        assert_eq!(Signal::parse(""), None);
    }

    /// Errors map to the signal an operator watches for. This is what makes a denial
    /// alertable, so a mapping that collapsed everything to `Other` would leave the
    /// audit stream technically complete and operationally useless.
    #[test]
    fn errors_map_to_their_operator_visible_signal() {
        use crate::error::AgentCredsError;

        let cases: Vec<(AgentCredsError, Signal)> = vec![
            (
                AgentCredsError::ScopeWideningAttempt {
                    capability: "tool:admin".into(),
                },
                Signal::ScopeWideningAttempt,
            ),
            (
                AgentCredsError::DelegationDepthExceeded { depth: 4, max: 3 },
                Signal::DelegationDepthExceeded,
            ),
            (
                AgentCredsError::CredentialExpired {
                    expired_at: "2020-01-01T00:00:00Z".into(),
                },
                Signal::Expired,
            ),
            (
                AgentCredsError::IssuerMismatch {
                    expected: "a".into(),
                    got: "b".into(),
                },
                Signal::IssuerMismatch,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(
                Signal::from_error(&err),
                want,
                "{err:?} must surface as {want:?}"
            );
        }
    }

    /// The accountability builders must store what they are given - including `None`,
    /// which is meaningful here ("nobody was named") rather than a no-op.
    #[test]
    fn the_accountability_builders_record_what_they_are_given() {
        let d = AuthzDecision::deny(
            DecisionKind::VerifyRooted,
            "did:key:zSubject",
            Signal::ActionDenied,
            "tool not in scope",
        )
        .with_action("tool:email")
        .with_correlation("urn:vc:agentcreds:abc", "did:key:zIssuer")
        .with_accountable_party(Some("team:payments".into()))
        .with_accountability_source(Some("policy".into()));

        assert_eq!(d.decision, Decision::Deny);
        assert_eq!(d.signals, vec![Signal::ActionDenied]);
        assert_eq!(d.reason.as_deref(), Some("tool not in scope"));
        assert_eq!(d.action.as_deref(), Some("tool:email"));
        assert_eq!(d.vc_id, "urn:vc:agentcreds:abc");
        assert_eq!(d.issuer_did, "did:key:zIssuer");
        assert_eq!(d.accountable_party.as_deref(), Some("team:payments"));
        assert_eq!(d.accountability_source.as_deref(), Some("policy"));

        // Clearing is a real operation, not a silent no-op.
        let cleared = d
            .clone()
            .with_accountable_party(None)
            .with_accountability_source(None);
        assert!(cleared.accountable_party.is_none());
        assert!(cleared.accountability_source.is_none());

        // An allow carries no signal or reason - the asymmetry is the point.
        let a = AuthzDecision::allow(DecisionKind::Mint, "did:key:zSubject");
        assert_eq!(a.decision, Decision::Allow);
        assert!(a.signals.is_empty());
        assert!(a.reason.is_none());
    }

    /// The digest must cover the accountability fields. If it did not, an accountable
    /// party could be altered after the fact without breaking the hash chain - leaving
    /// the chain attesting to everything except what it was extended for.
    #[test]
    fn the_digest_covers_the_accountability_fields() {
        let base = AuthzDecision::allow(DecisionKind::Verify, "did:key:zSubject")
            .with_correlation("urn:vc:1", "did:key:zIssuer");

        let with_party = base.clone().with_accountable_party(Some("team:a".into()));
        let other_party = base.clone().with_accountable_party(Some("team:b".into()));

        assert_ne!(
            base.digest(),
            with_party.digest(),
            "naming an accountable party must change the digest"
        );
        assert_ne!(
            with_party.digest(),
            other_party.digest(),
            "a DIFFERENT accountable party must change the digest"
        );
        assert_ne!(
            with_party.digest(),
            with_party
                .clone()
                .with_accountability_source(Some("attested".into()))
                .digest(),
            "the basis for the party must be covered too"
        );

        // Hex is the same digest rendered - a consumer must be able to compare either.
        assert_eq!(
            with_party.digest_hex(),
            hex::encode(with_party.digest()),
            "digest_hex must render the digest, not recompute a different one"
        );
        assert_eq!(with_party.digest_hex().len(), 64);
    }

    /// A fresh stream has a stable head, and the in-memory sink reports its own
    /// emptiness. `InMemorySink::len` / `is_empty` had no caller anywhere in the crate -
    /// they are the read side of the sink a host uses to drain decisions, so they are
    /// exercised here rather than deleted.
    #[test]
    fn a_fresh_stream_and_sink_start_empty_and_advance() {
        let s = AdrStream::default();
        let mut s2 = AdrStream::default();
        assert_eq!(s.count(), 0);
        assert_eq!(s.head(), s2.head(), "two fresh streams start identically");

        s2.record(AuthzDecision::allow(DecisionKind::Mint, "did:key:zA"));
        assert_eq!(s2.count(), 1);
        assert_ne!(
            s.head(),
            s2.head(),
            "recording must advance the head - otherwise the chain attests to nothing"
        );

        let sink = InMemorySink::default();
        assert!(sink.is_empty(), "a fresh sink holds nothing");
        assert_eq!(sink.len(), 0);
        assert!(sink.snapshot().is_empty());
    }
}
