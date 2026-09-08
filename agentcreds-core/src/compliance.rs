//! Compliance evidence bundles - a signed, self-verifying export of the
//! authorization decisions (and optional cross-org chain-of-custody) for a
//! delegation flow over a time window.
//!
//! A relying party collects the [`AuthzDecision`]s for a credential (from the
//! [ADR stream](crate::adr), keyed by `vc_id`) and - optionally - the
//! [`AuditCompositor`]'s chain-of-custody for the same correlation id, then seals
//! them into an [`EvidenceBundle`] under **one anchor signature**. An auditor
//! calls [`EvidenceBundle::verify`] to confirm, entirely offline, that the bundle
//! is authentic and the records are exactly as exported - none added, dropped,
//! reordered, or altered - and gets back an [`EvidenceReport`] summary.
//!
//! The bundle composes existing primitives: each decision contributes its
//! [`AuthzDecision::digest`], the records' [`replay`] head is sealed in, and an
//! optional [`AdrCheckpoint`] cross-references the live stream's signed state.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::adr::{AdrStream, AuthzDecision, DecisionKind};
//! use agentcreds_core::compliance::EvidenceBundle;
//!
//! # let anchor = TrustAnchor::generate()?;
//! # let agent = AgentIdentity::create(DidMethod::Key, None)?;
//! # let vc = CapabilityCredential::issue(&anchor, agent.did(),
//! #     CapabilityClaims::new(vec!["tool:search".into()], 2, 3600), None)?;
//! # let token = DelegationToken::mint(&vc,
//! #     Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1), 300, &agent)?;
//! // Record some decisions on the stream.
//! let mut stream = AdrStream::new();
//! let action = Action::new("tool:search", "q=ok");
//! let mut records = Vec::new();
//! for _ in 0..2 {
//!     let r = token.verify_rooted(&action, &vc, &anchor);
//!     records.push(stream.record(
//!         AuthzDecision::from_token(DecisionKind::VerifyRooted, &token, Some(&action.tool), &r)));
//! }
//!
//! // Seal a compliance bundle for this credential, sign it, and verify it.
//! let bundle = EvidenceBundle::builder(token.vc_id())
//!     .subject(token.root_agent_did())
//!     .decisions(records)
//!     .stream_checkpoint(stream.sign_checkpoint(&anchor)?)
//!     .seal(&anchor)?;
//!
//! let report = bundle.verify(&anchor)?;
//! assert_eq!(report.decisions, 2);
//! assert_eq!(report.allowed, 2);
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::adr::{replay, AdrCheckpoint, AuthzDecision, Decision, Signal};
use crate::audit::{AuditCompositor, CompositeEntry};
use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

const DIGEST_DOMAIN: &[u8] = b"agentcreds-evidence-bundle-v1";

fn ev_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::InvalidVcProof {
        reason: reason.into(),
    }
}

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    format!("urn:evidence:{}", hex::encode(b))
}

// -- EvidenceBundle ------------------------------------------------------------

/// A signed compliance export.
///
/// Authenticity and integrity come from the issuer anchor's `signature` over the
/// whole bundle; completeness is operator-asserted (the issuer chose which records
/// the stated scope includes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Unique bundle id (`urn:evidence:<hex>`).
    pub bundle_id: String,
    /// When the bundle was sealed.
    pub generated_at: DateTime<Utc>,
    /// The sealing anchor's DID.
    pub issuer_did: String,
    /// The delegation flow this covers (typically the root credential `vc_id`).
    pub correlation_id: String,
    /// The credential subject / root agent, if stated.
    pub subject_did: Option<String>,
    /// Start of the covered window, if stated.
    pub window_start: Option<DateTime<Utc>>,
    /// End of the covered window, if stated.
    pub window_end: Option<DateTime<Utc>>,
    /// The authorization decision records, in sequence order.
    pub decisions: Vec<AuthzDecision>,
    /// The hash-chain head over `decisions` (from [`replay`]), sealed for a quick
    /// integrity check.
    pub decisions_head: String,
    /// Optional cross-reference to the live ADR stream's signed state at export.
    pub stream_checkpoint: Option<AdrCheckpoint>,
    /// Optional cross-org chain-of-custody snapshot (from an [`AuditCompositor`]).
    pub custody: Vec<CompositeEntry>,
    /// The audit compositor's `root_hash` for `custody`, if present.
    pub custody_root: Option<String>,
    /// The issuer anchor's signature over the bundle digest.
    pub signature: String,
}

impl EvidenceBundle {
    /// Start building a bundle for `correlation_id` (the delegation flow / `vc_id`).
    #[must_use]
    pub fn builder(correlation_id: impl Into<String>) -> EvidenceBundleBuilder {
        EvidenceBundleBuilder {
            correlation_id: correlation_id.into(),
            subject_did: None,
            window: None,
            decisions: Vec::new(),
            stream_checkpoint: None,
            custody: Vec::new(),
            custody_root: None,
        }
    }

    /// Canonical digest over every field (domain-separated, length-prefixed).
    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        write_field(&mut h, self.bundle_id.as_bytes());
        h.update(self.generated_at.timestamp().to_le_bytes());
        write_field(&mut h, self.issuer_did.as_bytes());
        write_field(&mut h, self.correlation_id.as_bytes());
        write_field(&mut h, self.subject_did.as_deref().unwrap_or("").as_bytes());
        h.update(
            self.window_start
                .map_or(0i64, |t| t.timestamp())
                .to_le_bytes(),
        );
        h.update(
            self.window_end
                .map_or(0i64, |t| t.timestamp())
                .to_le_bytes(),
        );
        h.update((self.decisions.len() as u64).to_le_bytes());
        for d in &self.decisions {
            h.update(d.digest());
        }
        write_field(&mut h, self.decisions_head.as_bytes());
        match &self.stream_checkpoint {
            Some(cp) => {
                h.update([1u8]);
                h.update(cp.count.to_le_bytes());
                write_field(&mut h, cp.head.as_bytes());
                write_field(&mut h, cp.issuer_did.as_bytes());
                write_field(&mut h, cp.signature.as_bytes());
            }
            None => h.update([0u8]),
        }
        h.update((self.custody.len() as u64).to_le_bytes());
        for e in &self.custody {
            write_field(&mut h, e.org_id.as_bytes());
            h.update(e.seq.to_le_bytes());
            h.update(e.timestamp.timestamp().to_le_bytes());
            write_field(&mut h, e.commitment.as_bytes());
        }
        write_field(
            &mut h,
            self.custody_root.as_deref().unwrap_or("").as_bytes(),
        );
        h.finalize().to_vec()
    }

    /// Verify the bundle against `anchor` and return a summary. Checks the issuer
    /// matches, the signature is valid, and the decision records reproduce the
    /// sealed head; if a stream checkpoint is present it must also be authentic.
    ///
    /// # Errors
    /// `InvalidVcProof` on an anchor mismatch, a bad signature, a decision-head
    /// mismatch, or an invalid embedded checkpoint.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<EvidenceReport> {
        if self.issuer_did != anchor.did() {
            return Err(ev_err("evidence bundle issuer does not match the anchor"));
        }
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| ev_err(format!("signature base64: {e}")))?;
        anchor
            .verify_signature(&self.digest(), &sig)
            .map_err(|_| ev_err("evidence bundle signature does not verify"))?;

        // The included records must reproduce the sealed head - no add, drop,
        // reorder, or alter (also guarded by the signature; checked explicitly
        // so a consumer can see *which* invariant failed).
        if replay(&self.decisions) != self.decisions_head {
            return Err(ev_err("decision records do not match the sealed head"));
        }

        let checkpoint_verified = match &self.stream_checkpoint {
            Some(cp) => {
                cp.verify(anchor)?;
                true
            }
            None => false,
        };

        let allowed = self
            .decisions
            .iter()
            .filter(|d| matches!(d.decision, Decision::Allow))
            .count();
        let mut signals: Vec<Signal> = Vec::new();
        for d in &self.decisions {
            for s in &d.signals {
                if !signals.contains(s) {
                    signals.push(*s);
                }
            }
        }

        Ok(EvidenceReport {
            correlation_id: self.correlation_id.clone(),
            decisions: self.decisions.len(),
            allowed,
            denied: self.decisions.len() - allowed,
            signals,
            checkpoint_verified,
            custody_entries: self.custody.len(),
        })
    }

    /// Serialize the bundle to a JSON string (the export artifact).
    ///
    /// # Errors
    /// On a serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(AgentCredsError::from)
    }

    /// Parse a bundle from its JSON string.
    ///
    /// # Errors
    /// On a deserialisation failure.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(AgentCredsError::from)
    }
}

// -- Builder -------------------------------------------------------------------

/// Assembles an [`EvidenceBundle`]; finish with [`seal`](Self::seal).
#[derive(Debug, Clone)]
pub struct EvidenceBundleBuilder {
    correlation_id: String,
    subject_did: Option<String>,
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    decisions: Vec<AuthzDecision>,
    stream_checkpoint: Option<AdrCheckpoint>,
    custody: Vec<CompositeEntry>,
    custody_root: Option<String>,
}

impl EvidenceBundleBuilder {
    /// State the credential subject / root agent the flow concerns.
    #[must_use]
    pub fn subject(mut self, did: impl Into<String>) -> Self {
        self.subject_did = Some(did.into());
        self
    }

    /// State the covered time window.
    #[must_use]
    pub const fn window(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.window = Some((start, end));
        self
    }

    /// Include `decisions` verbatim (sorted by sequence number).
    #[must_use]
    pub fn decisions(mut self, decisions: Vec<AuthzDecision>) -> Self {
        self.decisions = decisions;
        self.decisions.sort_by_key(|d| d.seq);
        self
    }

    /// Include only the decisions in `all` whose `vc_id` matches this bundle's
    /// correlation id (sorted by sequence number) - the common per-flow export.
    #[must_use]
    pub fn decisions_matching(mut self, all: &[AuthzDecision]) -> Self {
        let mut v: Vec<AuthzDecision> = all
            .iter()
            .filter(|d| d.vc_id == self.correlation_id)
            .cloned()
            .collect();
        v.sort_by_key(|d| d.seq);
        self.decisions = v;
        self
    }

    /// Cross-reference the live ADR stream's signed state at export time.
    #[must_use]
    pub fn stream_checkpoint(mut self, checkpoint: AdrCheckpoint) -> Self {
        self.stream_checkpoint = Some(checkpoint);
        self
    }

    /// Attach the cross-org chain-of-custody from an [`AuditCompositor`].
    #[must_use]
    pub fn custody_from(mut self, compositor: &AuditCompositor) -> Self {
        self.custody = compositor.chain_of_custody().to_vec();
        self.custody_root = Some(compositor.root_hash());
        self
    }

    /// Seal and sign the bundle with `anchor` (which becomes its issuer).
    ///
    /// # Errors
    /// If the anchor fails to sign.
    pub fn seal(self, anchor: &TrustAnchor) -> Result<EvidenceBundle> {
        let decisions_head = replay(&self.decisions);
        let (window_start, window_end) = match self.window {
            Some((s, e)) => (Some(s), Some(e)),
            None => (None, None),
        };
        let mut bundle = EvidenceBundle {
            bundle_id: new_id(),
            generated_at: Utc::now(),
            issuer_did: anchor.did().to_string(),
            correlation_id: self.correlation_id,
            subject_did: self.subject_did,
            window_start,
            window_end,
            decisions: self.decisions,
            decisions_head,
            stream_checkpoint: self.stream_checkpoint,
            custody: self.custody,
            custody_root: self.custody_root,
            signature: String::new(),
        };
        let sig = anchor.sign(&bundle.digest())?;
        bundle.signature = base64ct::Base64::encode_string(&sig);
        Ok(bundle)
    }
}

// -- EvidenceReport --------------------------------------------------------------

/// The summary returned by a successful [`EvidenceBundle::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// The delegation flow covered.
    pub correlation_id: String,
    /// Total decision records.
    pub decisions: usize,
    /// How many were allows.
    pub allowed: usize,
    /// How many were denies.
    pub denied: usize,
    /// The distinct signals observed across the denies.
    pub signals: Vec<Signal>,
    /// Whether an embedded stream checkpoint was present and verified.
    pub checkpoint_verified: bool,
    /// Number of chain-of-custody entries included.
    pub custody_entries: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::adr::{AdrStream, DecisionKind};
    use crate::delegation::{Action, DelegationToken, Scope};
    use crate::did::{AgentIdentity, DidMethod};
    use crate::vc::{CapabilityClaims, CapabilityCredential};

    struct World {
        anchor: TrustAnchor,
        vc: CapabilityCredential,
        token: crate::delegation::DelegationToken,
    }

    fn world() -> World {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = CapabilityCredential::issue(
            &anchor,
            agent.did(),
            CapabilityClaims::new(vec!["tool:search".into()], 2, 3600),
            None,
        )
        .unwrap();
        let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
        let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
        World { anchor, vc, token }
    }

    /// Record `n` allow decisions plus one denied call, returning the stream and
    /// the stamped records.
    fn recorded(w: &World) -> (AdrStream, Vec<AuthzDecision>) {
        let mut stream = AdrStream::new();
        let mut records = Vec::new();
        for _ in 0..2 {
            let ok = w
                .token
                .verify_rooted(&Action::new("tool:search", "q=ok"), &w.vc, &w.anchor);
            records.push(stream.record(AuthzDecision::from_token(
                DecisionKind::VerifyRooted,
                &w.token,
                Some("tool:search"),
                &ok,
            )));
        }
        let denied = w.token.verify(&Action::new("tool:admin", ""));
        records.push(stream.record(AuthzDecision::from_token(
            DecisionKind::Verify,
            &w.token,
            Some("tool:admin"),
            &denied,
        )));
        (stream, records)
    }

    #[test]
    fn seals_and_verifies_with_report() {
        let w = world();
        let (stream, records) = recorded(&w);
        let bundle = EvidenceBundle::builder(w.token.vc_id())
            .subject(w.token.root_agent_did())
            .decisions(records)
            .stream_checkpoint(stream.sign_checkpoint(&w.anchor).unwrap())
            .seal(&w.anchor)
            .unwrap();

        let report = bundle.verify(&w.anchor).unwrap();
        assert_eq!(report.decisions, 3);
        assert_eq!(report.allowed, 2);
        assert_eq!(report.denied, 1);
        assert_eq!(report.signals, vec![Signal::ActionDenied]);
        assert!(report.checkpoint_verified);
        assert_eq!(report.correlation_id, w.token.vc_id());
    }

    #[test]
    fn wrong_anchor_is_rejected() {
        let w = world();
        let (_stream, records) = recorded(&w);
        let bundle = EvidenceBundle::builder(w.token.vc_id())
            .decisions(records)
            .seal(&w.anchor)
            .unwrap();
        let stranger = TrustAnchor::generate().unwrap();
        assert!(bundle.verify(&stranger).is_err());
    }

    #[test]
    fn tampering_with_a_decision_is_detected() {
        let w = world();
        let (_stream, records) = recorded(&w);
        let mut bundle = EvidenceBundle::builder(w.token.vc_id())
            .decisions(records)
            .seal(&w.anchor)
            .unwrap();
        // Flip an allow into a (claimed) deny after sealing.
        bundle.decisions[0].decision = Decision::Deny;
        assert!(bundle.verify(&w.anchor).is_err());
    }

    #[test]
    fn dropping_a_record_breaks_the_head() {
        let w = world();
        let (_stream, records) = recorded(&w);
        let mut bundle = EvidenceBundle::builder(w.token.vc_id())
            .decisions(records)
            .seal(&w.anchor)
            .unwrap();
        bundle.decisions.pop(); // remove the last record, keep the sealed head
        let err = bundle.verify(&w.anchor);
        assert!(err.is_err());
    }

    #[test]
    fn decisions_matching_filters_by_correlation() {
        let w = world();
        let (_stream, mut records) = recorded(&w);
        // Add a decision for a different flow.
        let other = AuthzDecision::allow(DecisionKind::Verify, "did:key:zOther");
        records.push(other);
        let bundle = EvidenceBundle::builder(w.token.vc_id())
            .decisions_matching(&records)
            .seal(&w.anchor)
            .unwrap();
        let report = bundle.verify(&w.anchor).unwrap();
        assert_eq!(report.decisions, 3); // the foreign record was excluded
    }

    #[test]
    fn json_round_trip_preserves_verifiability() {
        let w = world();
        let (stream, records) = recorded(&w);
        let bundle = EvidenceBundle::builder(w.token.vc_id())
            .decisions(records)
            .stream_checkpoint(stream.sign_checkpoint(&w.anchor).unwrap())
            .seal(&w.anchor)
            .unwrap();
        let restored = EvidenceBundle::from_json(&bundle.to_json().unwrap()).unwrap();
        assert!(restored.verify(&w.anchor).is_ok());
        assert_eq!(restored.bundle_id, bundle.bundle_id);
    }

    #[test]
    fn custody_from_compositor_is_included() {
        use crate::audit::{AuditCompositor, AuditLog};
        let w = world();
        let (_stream, records) = recorded(&w);
        let corr = w.token.vc_id();
        let mut log = AuditLog::new(corr, w.anchor.did());
        log.record("did:key:zAgent", "tool:search", "allow");
        let mut comp = AuditCompositor::new(corr);
        comp.ingest(&log.export(&w.anchor).unwrap(), &w.anchor)
            .unwrap();

        let bundle = EvidenceBundle::builder(corr)
            .decisions(records)
            .custody_from(&comp)
            .seal(&w.anchor)
            .unwrap();
        let report = bundle.verify(&w.anchor).unwrap();
        assert_eq!(report.custody_entries, 1);
        assert_eq!(
            bundle.custody_root.as_deref(),
            Some(comp.root_hash().as_str())
        );
    }
}
