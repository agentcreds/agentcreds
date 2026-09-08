//! Audit compositor - a joint, privacy-preserving chain-of-custody across orgs.
//!
//! When a delegation crosses an organization boundary, each org logs the actions
//! its own agents/verifiers took. Auditing the *whole* flow means merging those
//! logs - but neither org wants to hand the other its raw log. The compositor
//! solves this with **commitments**:
//!
//! - Each org keeps its raw [`AuditRecord`]s privately in an [`AuditLog`], keyed
//!   by a shared `correlation_id` (typically the delegation token's `vc_id`).
//! - It shares only [`AuditCommitment`]s - salted SHA-256 hashes of each record,
//!   signed by the org's anchor. The raw action/agent never leaves the org.
//! - The [`AuditCompositor`] verifies each org's signatures and merges the
//!   commitments into one timestamp-ordered chain-of-custody, plus a single
//!   `root_hash` both sides can compare to confirm they built the same view.
//! - An org can later **selectively reveal** a single record; the compositor
//!   checks its hash against the published commitment - proving that one entry's
//!   content without disclosing the rest of the log.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::audit::{AuditLog, AuditCompositor};
//!
//! let org_a = TrustAnchor::generate()?;
//! let org_b = TrustAnchor::generate()?;
//! let correlation = "urn:vc:shared-delegation";
//!
//! // Each org logs locally and exports signed commitments.
//! let mut log_a = AuditLog::new(correlation, org_a.did());
//! log_a.record("did:key:zAgentA", "tool:search", "allow");
//! let mut log_b = AuditLog::new(correlation, org_b.did());
//! log_b.record("did:key:zAgentB", "tool:order", "allow");
//!
//! // The compositor merges them without ever seeing the raw actions.
//! let mut comp = AuditCompositor::new(correlation);
//! comp.ingest(&log_a.export(&org_a)?, &org_a)?;
//! comp.ingest(&log_b.export(&org_b)?, &org_b)?;
//! assert_eq!(comp.chain_of_custody().len(), 2);
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

const COMMITMENT_DOMAIN: &[u8] = b"agentcreds-audit-record-v1";
const SIGNATURE_DOMAIN: &[u8] = b"agentcreds-audit-commitment-v1";

fn audit_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::InvalidVcProof {
        reason: reason.into(),
    }
}

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

// -- AuditRecord ----------------------------------------------------------------

/// One action an org logs locally. Stays private - only its [`commitment`] is
/// shared. The `salt` makes the commitment hide the action even from an
/// adversary who guesses likely values.
///
/// [`commitment`]: AuditRecord::commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Shared correlation id (typically the delegation token's `vc_id`).
    pub correlation_id: String,
    /// The org that logged this (its anchor DID).
    pub org_id: String,
    /// Per-org monotonic sequence number within this correlation.
    pub seq: u64,
    /// DID of the agent that acted.
    pub agent_did: String,
    /// The action (e.g. a tool identifier).
    pub action: String,
    /// Outcome (e.g. `"allow"` / `"deny"` / a reason).
    pub outcome: String,
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,
    /// Random salt, hex-encoded.
    #[serde(with = "hex::serde")]
    pub salt: Vec<u8>,
}

impl AuditRecord {
    /// The salted commitment (hex SHA-256) shared in place of the raw record.
    pub fn commitment(&self) -> String {
        let mut h = Sha256::new();
        h.update(COMMITMENT_DOMAIN);
        write_field(&mut h, self.correlation_id.as_bytes());
        write_field(&mut h, self.org_id.as_bytes());
        h.update(self.seq.to_le_bytes());
        write_field(&mut h, self.agent_did.as_bytes());
        write_field(&mut h, self.action.as_bytes());
        write_field(&mut h, self.outcome.as_bytes());
        h.update(self.timestamp.timestamp().to_le_bytes());
        write_field(&mut h, &self.salt);
        hex::encode(h.finalize())
    }
}

// -- AuditCommitment -------------------------------------------------------------

/// The privacy-preserving, signed form of an [`AuditRecord`] that an org shares.
/// Carries no raw payload - only the commitment hash plus routing metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCommitment {
    /// Shared correlation id.
    pub correlation_id: String,
    /// The org that produced this (its anchor DID).
    pub org_id: String,
    /// Per-org sequence number.
    pub seq: u64,
    /// When the underlying action occurred.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 commitment to the raw record.
    pub commitment: String,
    /// The org anchor's signature over this commitment.
    pub signature: String,
}

impl AuditCommitment {
    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(SIGNATURE_DOMAIN);
        write_field(&mut h, self.correlation_id.as_bytes());
        write_field(&mut h, self.org_id.as_bytes());
        h.update(self.seq.to_le_bytes());
        h.update(self.timestamp.timestamp().to_le_bytes());
        write_field(&mut h, self.commitment.as_bytes());
        h.finalize().to_vec()
    }

    /// Verify this commitment's signature against the producing org's anchor.
    ///
    /// # Errors
    /// `InvalidVcProof` on a bad signature or an org/anchor mismatch.
    pub fn verify(&self, org_anchor: &TrustAnchor) -> Result<()> {
        if self.org_id != org_anchor.did() {
            return Err(audit_err("commitment org_id does not match the anchor"));
        }
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| audit_err(format!("signature base64: {e}")))?;
        org_anchor
            .verify_signature(&self.signing_payload(), &sig)
            .map_err(|_| audit_err("commitment signature does not verify"))
    }
}

// -- AuditLog (per-org) ----------------------------------------------------------

/// An org's private, append-only log for one correlation id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    correlation_id: String,
    org_id: String,
    records: Vec<AuditRecord>,
}

impl AuditLog {
    /// A new log for `correlation_id`, owned by the org identified by `org_id`
    /// (its anchor DID).
    pub fn new(correlation_id: impl Into<String>, org_id: impl Into<String>) -> Self {
        AuditLog {
            correlation_id: correlation_id.into(),
            org_id: org_id.into(),
            records: Vec::new(),
        }
    }

    /// Append an action, timestamped now. Returns the assigned sequence number.
    /// See [`record_at`](Self::record_at) to supply an explicit action time.
    pub fn record(
        &mut self,
        agent_did: impl Into<String>,
        action: impl Into<String>,
        outcome: impl Into<String>,
    ) -> u64 {
        self.record_at(agent_did, action, outcome, Utc::now())
    }

    /// Append an action with an explicit `timestamp`. Use this when bridging an
    /// existing decision log (e.g. an [`AuthzDecision`](crate::adr::AuthzDecision))
    /// into commitments: the decision's own time - not export time - is what
    /// belongs in the committed record and drives chain-of-custody ordering.
    /// Returns the assigned sequence number.
    pub fn record_at(
        &mut self,
        agent_did: impl Into<String>,
        action: impl Into<String>,
        outcome: impl Into<String>,
        timestamp: DateTime<Utc>,
    ) -> u64 {
        let seq = self.records.len() as u64;
        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);
        self.records.push(AuditRecord {
            correlation_id: self.correlation_id.clone(),
            org_id: self.org_id.clone(),
            seq,
            agent_did: agent_did.into(),
            action: action.into(),
            outcome: outcome.into(),
            timestamp,
            salt,
        });
        seq
    }

    /// Export signed [`AuditCommitment`]s to share with the compositor. The raw
    /// records stay here.
    ///
    /// # Errors
    /// `InvalidVcProof` if `anchor` does not match this log's org, or signing fails.
    pub fn export(&self, anchor: &TrustAnchor) -> Result<Vec<AuditCommitment>> {
        if anchor.did() != self.org_id {
            return Err(audit_err("anchor does not match this log's org"));
        }
        let mut out = Vec::with_capacity(self.records.len());
        for r in &self.records {
            let mut commitment = AuditCommitment {
                correlation_id: r.correlation_id.clone(),
                org_id: r.org_id.clone(),
                seq: r.seq,
                timestamp: r.timestamp,
                commitment: r.commitment(),
                signature: String::new(),
            };
            let sig = anchor.sign(&commitment.signing_payload())?;
            commitment.signature = base64ct::Base64::encode_string(&sig);
            out.push(commitment);
        }
        Ok(out)
    }

    /// Selectively reveal one raw record (e.g. to substantiate a disputed entry).
    pub fn reveal(&self, seq: u64) -> Option<&AuditRecord> {
        self.records.get(seq as usize)
    }

    /// Number of records logged.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// -- AuditCompositor -------------------------------------------------------------

/// One entry in the merged chain-of-custody (no raw payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeEntry {
    /// The org that produced this entry.
    pub org_id: String,
    /// That org's sequence number.
    pub seq: u64,
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,
    /// The commitment hash.
    pub commitment: String,
}

/// Merges multiple orgs' [`AuditCommitment`]s into one verifiable, ordered
/// chain-of-custody for a single correlation id - without seeing raw logs.
#[derive(Debug, Clone)]
pub struct AuditCompositor {
    correlation_id: String,
    entries: Vec<CompositeEntry>,
}

impl AuditCompositor {
    /// A compositor for `correlation_id`.
    pub fn new(correlation_id: impl Into<String>) -> Self {
        AuditCompositor {
            correlation_id: correlation_id.into(),
            entries: Vec::new(),
        }
    }

    /// Ingest one org's exported commitments, verifying every signature against
    /// `org_anchor` and that they all belong to this correlation. Idempotent
    /// per (org, seq): re-ingesting the same entries does not duplicate them.
    ///
    /// # Errors
    /// `InvalidVcProof` if a commitment is for a different correlation, fails
    /// signature verification, or conflicts with an already-ingested entry.
    pub fn ingest(
        &mut self,
        commitments: &[AuditCommitment],
        org_anchor: &TrustAnchor,
    ) -> Result<()> {
        for c in commitments {
            if c.correlation_id != self.correlation_id {
                return Err(audit_err("commitment correlation_id does not match"));
            }
            c.verify(org_anchor)?;
            // Reject a conflicting re-publish of the same (org, seq).
            if let Some(existing) = self
                .entries
                .iter()
                .find(|e| e.org_id == c.org_id && e.seq == c.seq)
            {
                if existing.commitment != c.commitment {
                    return Err(audit_err(format!(
                        "conflicting commitment for {} seq {}",
                        c.org_id, c.seq
                    )));
                }
                continue; // identical - idempotent
            }
            self.entries.push(CompositeEntry {
                org_id: c.org_id.clone(),
                seq: c.seq,
                timestamp: c.timestamp,
                commitment: c.commitment.clone(),
            });
        }
        self.entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then_with(|| a.org_id.cmp(&b.org_id))
                .then_with(|| a.seq.cmp(&b.seq))
        });
        Ok(())
    }

    /// The merged chain-of-custody, ordered by time (tiebreak org, then seq).
    pub fn chain_of_custody(&self) -> &[CompositeEntry] {
        &self.entries
    }

    /// A single tamper-evident digest over the whole ordered chain. Two parties
    /// that composited the same commitments get the same root.
    pub fn root_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(SIGNATURE_DOMAIN);
        write_field(&mut h, self.correlation_id.as_bytes());
        for e in &self.entries {
            write_field(&mut h, e.org_id.as_bytes());
            h.update(e.seq.to_le_bytes());
            h.update(e.timestamp.timestamp().to_le_bytes());
            write_field(&mut h, e.commitment.as_bytes());
        }
        hex::encode(h.finalize())
    }

    /// Verify a selectively-revealed record against the composited commitment:
    /// the record's recomputed hash must equal the entry the org published.
    ///
    /// # Errors
    /// `InvalidVcProof` if no matching entry exists.
    pub fn verify_revealed(&self, record: &AuditRecord) -> Result<bool> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.org_id == record.org_id && e.seq == record.seq)
            .ok_or_else(|| audit_err("no composited entry for this record"))?;
        Ok(entry.commitment == record.commitment())
    }

    /// Number of entries in the chain-of-custody.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain-of-custody is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const CORR: &str = "urn:vc:shared-delegation";

    fn org_logs() -> (TrustAnchor, TrustAnchor, AuditLog, AuditLog) {
        let org_a = TrustAnchor::generate().unwrap();
        let org_b = TrustAnchor::generate().unwrap();
        let mut log_a = AuditLog::new(CORR, org_a.did());
        log_a.record("did:key:zAgentA", "tool:search", "allow");
        log_a.record("did:key:zAgentA", "tool:email", "deny");
        let mut log_b = AuditLog::new(CORR, org_b.did());
        log_b.record("did:key:zAgentB", "tool:order", "allow");
        (org_a, org_b, log_a, log_b)
    }

    #[test]
    fn composites_two_orgs_into_one_chain() {
        let (org_a, org_b, log_a, log_b) = org_logs();
        let mut comp = AuditCompositor::new(CORR);
        comp.ingest(&log_a.export(&org_a).unwrap(), &org_a).unwrap();
        comp.ingest(&log_b.export(&org_b).unwrap(), &org_b).unwrap();
        assert_eq!(comp.chain_of_custody().len(), 3);
        // Both orgs appear.
        let orgs: Vec<&str> = comp
            .chain_of_custody()
            .iter()
            .map(|e| e.org_id.as_str())
            .collect();
        assert!(orgs.contains(&org_a.did()));
        assert!(orgs.contains(&org_b.did()));
    }

    #[test]
    fn raw_action_never_leaves_the_org() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let exported = log_a.export(&org_a).unwrap();
        // The shared commitments contain no raw action/agent strings.
        let json = serde_json::to_string(&exported).unwrap();
        assert!(!json.contains("tool:search"));
        assert!(!json.contains("zAgentA"));
    }

    #[test]
    fn tampered_commitment_signature_rejected() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let mut exported = log_a.export(&org_a).unwrap();
        exported[0].commitment = "deadbeef".repeat(8); // changed after signing
        let mut comp = AuditCompositor::new(CORR);
        assert!(comp.ingest(&exported, &org_a).is_err());
    }

    #[test]
    fn wrong_anchor_rejected() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let exported = log_a.export(&org_a).unwrap();
        let stranger = TrustAnchor::generate().unwrap();
        let mut comp = AuditCompositor::new(CORR);
        assert!(comp.ingest(&exported, &stranger).is_err());
    }

    #[test]
    fn selective_reveal_matches_commitment() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let mut comp = AuditCompositor::new(CORR);
        comp.ingest(&log_a.export(&org_a).unwrap(), &org_a).unwrap();
        // Reveal record 0 - it matches the composited commitment.
        let revealed = log_a.reveal(0).unwrap();
        assert!(comp.verify_revealed(revealed).unwrap());
        // A doctored copy does not match.
        let mut forged = revealed.clone();
        forged.action = "tool:exfiltrate".into();
        assert!(!comp.verify_revealed(&forged).unwrap());
    }

    #[test]
    fn root_hash_is_order_independent_of_ingest() {
        let (org_a, org_b, log_a, log_b) = org_logs();
        let ea = log_a.export(&org_a).unwrap();
        let eb = log_b.export(&org_b).unwrap();

        let mut c1 = AuditCompositor::new(CORR);
        c1.ingest(&ea, &org_a).unwrap();
        c1.ingest(&eb, &org_b).unwrap();

        let mut c2 = AuditCompositor::new(CORR);
        c2.ingest(&eb, &org_b).unwrap();
        c2.ingest(&ea, &org_a).unwrap();

        // Same commitments, ingested in either order -> same joint root.
        assert_eq!(c1.root_hash(), c2.root_hash());
    }

    #[test]
    fn idempotent_reingest_does_not_duplicate() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let exported = log_a.export(&org_a).unwrap();
        let mut comp = AuditCompositor::new(CORR);
        comp.ingest(&exported, &org_a).unwrap();
        comp.ingest(&exported, &org_a).unwrap(); // again
        assert_eq!(comp.len(), 2);
    }

    #[test]
    fn wrong_correlation_rejected() {
        let (org_a, _b, log_a, _lb) = org_logs();
        let exported = log_a.export(&org_a).unwrap();
        let mut comp = AuditCompositor::new("urn:vc:different");
        assert!(comp.ingest(&exported, &org_a).is_err());
    }
}
