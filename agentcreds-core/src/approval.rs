//! Execution-time human authorization primitives (R10).
//!
//! In-chain gate declarations, approval evidence (anchor- or approver-key-signed),
//! the org-anchor-signed approver directory, and the one-time reliance record.
//! These are re-exported from [`crate::delegation`], so `crate::delegation::Gate`
//! etc. remain the stable paths.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::delegation::Action;
use crate::did::{AgentIdentity, PublicKey, TrustAnchor};
use crate::{error::AgentCredsError, Result};

// -- Gate (R10: execution-time human-authorization designation) ------------------

/// An execution-time human-authorization designation carried **inside** the
/// delegated authority (R10, strong form). It marks a tool as requiring, before
/// execution, evidence of an authorization decision by an accountable human
/// approver distinct from the executing agent.
///
/// Because a gate is a Biscuit fact, it travels with the authority across hops
/// and organizational boundaries, and - Biscuit facts being append-only - a
/// derivation can only **add** gates, never remove one (monotone, tighten-only).
/// A relying party that does not recognize a gate's `kind` MUST treat the
/// designated tool as unauthorized (fail closed); see
/// [`DelegationToken::verify_rooted_gated`](crate::delegation::DelegationToken::verify_rooted_gated).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Gate {
    /// The designation kind - its evidence semantics. The reference kind is
    /// [`Gate::APPROVAL`].
    pub kind: String,
    /// The tool this designation applies to (exact match).
    pub tool: String,
}

impl Gate {
    /// The reference gate kind: a human approval decision, bound to the exact
    /// action (including the on-behalf-of principal), consumable once. Evidence is
    /// attested by the organizational trust anchor (the approver is an attribution).
    pub const APPROVAL: &'static str = "approval";

    /// Hybrid gate kind: like [`APPROVAL`](Self::APPROVAL), but the evidence is
    /// signed by the **individual approver's key**, whose public key is enrolled in
    /// an org-anchor-signed [`ApproverDirectory`] - per-human non-repudiation with
    /// no second trust root.
    pub const APPROVAL_KEY: &'static str = "approval-key";

    /// Gate kind requiring **intent-alignment evidence**: an evaluator judged, out of
    /// band, that the action aligns with a signed
    /// [`IntentStatement`](crate::delegation::IntentStatement) for this agent (AARM R3),
    /// and reported how far it sits from that intent (R7). The judgement is made
    /// elsewhere; the enforcement point verifies the signed evidence offline. See
    /// [`AlignmentEvidence`](crate::delegation::AlignmentEvidence).
    ///
    /// **NOT YET ENFORCED BY `verify_rooted_gated`.** There is no handler for this kind
    /// in the gate loop, so a token carrying it is **denied** - whether or not the
    /// verifier lists it in `recognized_kinds`. That is deliberate: the alternative was
    /// a designation that looks enforced and is not. Until the handler exists, enforce
    /// intent alignment by calling
    /// [`AlignmentEvidence::verify_quorum`](crate::delegation::AlignmentEvidence::verify_quorum)
    /// directly from the policy enforcement point, and do not put this gate in a minted
    /// token.
    pub const INTENT: &'static str = "intent-alignment";

    /// A gate requiring intent-alignment evidence before `tool` may execute.
    pub fn intent(tool: impl Into<String>) -> Self {
        Gate {
            kind: Self::INTENT.to_string(),
            tool: tool.into(),
        }
    }

    /// A gate requiring anchor-attested human approval before `tool` may execute.
    pub fn approval(tool: impl Into<String>) -> Self {
        Gate {
            kind: Self::APPROVAL.to_string(),
            tool: tool.into(),
        }
    }

    /// A gate requiring **approver-key-signed** human approval before `tool` may
    /// execute (hybrid model; needs an [`ApproverDirectory`]).
    pub fn approval_key(tool: impl Into<String>) -> Self {
        Gate {
            kind: Self::APPROVAL_KEY.to_string(),
            tool: tool.into(),
        }
    }
}

/// Length-prefix a field into a running SHA-256 (domain-separated hashing helper).
fn hash_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

// -- ApproverDirectory (hybrid R10: per-approver keys under the org anchor) -------

/// One human approver enrolled in the org's approver directory: their signing key,
/// identified by a self-certifying `did:key`, plus roles and an optional validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverEntry {
    /// Stable approver identity (e.g. an operator DID or OIDC subject).
    pub approver_id: String,
    /// `did:key` encoding the approver's public verification key.
    pub approver_did: String,
    /// Roles this approver holds (e.g. `["finance"]`); a gate may require one.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Optional per-approver expiry.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
}

/// A versioned, **anchor-signed** directory of human approver keys (hybrid R10).
/// It is verified under the *same* organizational trust anchor that roots the
/// delegation system - there is no second trust root - and carries a signed
/// `not_after` so a relying party can bound its staleness (as for revocation and
/// the trust registry). Approver-signed [`ApprovalEvidence`] is checked against
/// the key this directory publishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverDirectory {
    /// Monotonic version (bump on each change; enables rollback detection).
    pub version: u64,
    /// When the directory was sealed.
    pub generated_at: DateTime<Utc>,
    /// DID of the org anchor that signed it.
    pub issuer_did: String,
    /// The enrolled approvers, sorted by `approver_id`.
    pub entries: Vec<ApproverEntry>,
    /// Optional expiry; past this instant a fail-safe consumer rejects it.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    /// The org anchor's signature over the canonical digest (hex).
    pub signature: String,
}

impl ApproverDirectory {
    const DOMAIN: &'static [u8] = b"agentcreds-approver-directory-v1";

    /// Seal (sign) a directory with the org `anchor`. Entries are sorted by
    /// `approver_id` for a deterministic digest.
    pub fn seal(
        mut entries: Vec<ApproverEntry>,
        version: u64,
        generated_at: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
        anchor: &TrustAnchor,
    ) -> Result<Self> {
        entries.sort_by(|a, b| a.approver_id.cmp(&b.approver_id));
        let mut dir = ApproverDirectory {
            version,
            generated_at,
            issuer_did: anchor.did().to_string(),
            entries,
            not_after,
            signature: String::new(),
        };
        dir.signature = crate::signed::encode_signature(&anchor.sign(&dir.digest())?);
        Ok(dir)
    }

    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(Self::DOMAIN);
        h.update(self.version.to_le_bytes());
        h.update(self.generated_at.timestamp().to_le_bytes());
        hash_field(&mut h, self.issuer_did.as_bytes());
        for e in &self.entries {
            hash_field(&mut h, e.approver_id.as_bytes());
            hash_field(&mut h, e.approver_did.as_bytes());
            h.update((e.roles.len() as u64).to_le_bytes());
            for r in &e.roles {
                hash_field(&mut h, r.as_bytes());
            }
            match e.not_after {
                Some(t) => {
                    h.update([1u8]);
                    h.update(t.timestamp().to_le_bytes());
                }
                None => h.update([0u8]),
            }
        }
        match self.not_after {
            Some(t) => {
                h.update([1u8]);
                h.update(t.timestamp().to_le_bytes());
            }
            None => h.update([0u8]),
        }
        h.finalize().to_vec()
    }

    /// Verify the directory against `anchor` and that it is not past its `not_after`
    /// at `now`. Fail-closed: a wrong issuer, bad signature, or expiry all reject.
    ///
    /// # Errors
    /// [`AgentCredsError::InvalidVcProof`] on any of the above.
    pub fn verify_current(&self, anchor: &TrustAnchor, now: DateTime<Utc>) -> Result<()> {
        crate::signed::verify_anchor_signed(
            &self.issuer_did,
            &self.digest(),
            &self.signature,
            self.not_after,
            now,
            anchor,
            "approver directory",
        )
    }

    /// Look up a live approver by `approver_did`, rejecting an entry past its own
    /// `not_after` at `now`.
    pub fn lookup(&self, approver_did: &str, now: DateTime<Utc>) -> Option<&ApproverEntry> {
        self.entries
            .iter()
            .find(|e| e.approver_did == approver_did && e.not_after.map_or(true, |t| now <= t))
    }
}

// -- ApprovalEvidence (R10: execution-time human-authorization evidence) ---------

/// Execution-time human-authorization evidence (R10) - the verifiable form of an
/// approver's decision, bound to one exact action. A relying party verifies it
/// **offline** against the organization's trust anchor (it trusts the signature,
/// never a live approval service), and additionally enforces that it has not
/// previously been relied upon (one-time).
///
/// The signature covers the action's [`approval_binding`](Action::approval_binding),
/// so the evidence is bound to the operation, its parameters, the resource, **and**
/// the on-behalf-of principal - a grant approved for Alice cannot satisfy the same
/// action performed on behalf of Bob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEvidence {
    /// Unique id of this approval decision. The relying party remembers it to
    /// enforce one-time reliance (R10).
    pub approval_id: String,
    /// The gate kind this evidence satisfies ([`Gate::APPROVAL`]).
    pub kind: String,
    /// The action binding it is bound to ([`Action::approval_binding`]).
    pub binding: String,
    /// Identifier of the accountable human approver (distinct from the agent).
    pub approver: String,
    /// Expiry, Unix seconds. Evidence at or after this instant is refused.
    pub expires_at: i64,
    /// Signature over the signing payload, hex-encoded. In anchor mode the
    /// organizational anchor signs; in approver-key mode the approver's own key
    /// signs (see [`approver_did`](Self::approver_did)).
    pub signature: String,
    /// Approver-key (hybrid) mode: the `did:key` of the approver whose key signed
    /// this evidence. `None` = anchor mode (the anchor signed; approver is an
    /// attribution). When set, verification is against this key, looked up in an
    /// [`ApproverDirectory`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_did: Option<String>,
}

impl ApprovalEvidence {
    const DOMAIN: &'static [u8] = b"agentcreds-approval-evidence-v1";
    const DOMAIN_KEY: &'static [u8] = b"agentcreds-approval-evidence-key-v1";

    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        // Anchor mode and approver-key mode are domain-separated, and the key mode
        // additionally binds the signing approver's did:key so it cannot be swapped.
        // Anchor-mode bytes are unchanged from v1 (approver_did = None).
        match &self.approver_did {
            None => {
                h.update(Self::DOMAIN);
                for f in [&self.approval_id, &self.kind, &self.binding, &self.approver] {
                    hash_field(&mut h, f.as_bytes());
                }
            }
            Some(did) => {
                h.update(Self::DOMAIN_KEY);
                for f in [
                    &self.approval_id,
                    &self.kind,
                    &self.binding,
                    &self.approver,
                    did,
                ] {
                    hash_field(&mut h, f.as_bytes());
                }
            }
        }
        h.update(self.expires_at.to_le_bytes());
        h.finalize().to_vec()
    }

    /// Mint signed approval evidence for `action`, decided by `approver`, valid
    /// until `expires_at` (Unix seconds) and signed by the organization `anchor`.
    /// The binding includes the on-behalf-of principal carried on `action`.
    pub fn approve(
        action: &Action,
        approver: impl Into<String>,
        approval_id: impl Into<String>,
        expires_at: i64,
        anchor: &TrustAnchor,
    ) -> Result<Self> {
        let mut ev = ApprovalEvidence {
            approval_id: approval_id.into(),
            kind: Gate::APPROVAL.to_string(),
            binding: action.approval_binding(),
            approver: approver.into(),
            expires_at,
            signature: String::new(),
            approver_did: None,
        };
        let sig = anchor.sign(&ev.signing_payload())?;
        ev.signature = crate::signed::encode_signature(&sig);
        Ok(ev)
    }

    /// Mint **approver-key-signed** evidence (hybrid R10): the individual approver
    /// signs the action binding with their own key (`approver`, a `did:key`
    /// signer), giving per-human non-repudiation. Verified with
    /// [`verify_with_directory`](Self::verify_with_directory) against an
    /// org-anchor-signed [`ApproverDirectory`] - no second trust root. `kind` is
    /// [`Gate::APPROVAL_KEY`].
    pub fn approve_by_key(
        action: &Action,
        approver_id: impl Into<String>,
        approver: &AgentIdentity,
        approval_id: impl Into<String>,
        expires_at: i64,
    ) -> Result<Self> {
        let mut ev = ApprovalEvidence {
            approval_id: approval_id.into(),
            kind: Gate::APPROVAL_KEY.to_string(),
            binding: action.approval_binding(),
            approver: approver_id.into(),
            expires_at,
            signature: String::new(),
            approver_did: Some(approver.did().to_string()),
        };
        ev.signature = crate::signed::encode_signature(&approver.sign(&ev.signing_payload())?);
        Ok(ev)
    }

    /// Verify the evidence **offline** against `anchor` for `action` at `now_unix`:
    /// the signature must verify, the binding must equal the action's
    /// principal-bound approval binding, and it must not be expired. Stateless -
    /// the relying party additionally enforces one-time reliance by remembering
    /// [`approval_id`](Self::approval_id).
    ///
    /// # Errors
    /// [`AgentCredsError::InvalidVcProof`] on a bad signature or a binding/expiry
    /// mismatch.
    pub fn verify(&self, action: &Action, anchor: &TrustAnchor, now_unix: i64) -> Result<()> {
        if self.binding != action.approval_binding() {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "approval evidence is not bound to this action/principal".into(),
            });
        }
        if now_unix >= self.expires_at {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "approval evidence has expired".into(),
            });
        }
        let sig = crate::signed::decode_signature(&self.signature, "approval evidence")?;
        anchor
            .verify_signature(&self.signing_payload(), &sig)
            .map_err(|_| AgentCredsError::InvalidVcProof {
                reason: "approval evidence signature does not verify".into(),
            })
    }

    /// Verify **approver-key-signed** evidence (hybrid R10) offline: the
    /// [`ApproverDirectory`] must verify under `anchor`; the signing approver
    /// (`approver_did`) must be a live directory entry (optionally holding
    /// `required_role`); the binding must equal the action's principal-bound
    /// approval binding; it must not be expired; and the signature must verify
    /// against the approver's published key. Everything roots in the one org anchor
    /// - no second trust root, no runtime lookup.
    ///
    /// # Errors
    /// [`AgentCredsError::InvalidVcProof`] on any failure (directory, enrollment,
    /// role, binding, expiry, or signature).
    pub fn verify_with_directory(
        &self,
        action: &Action,
        directory: &ApproverDirectory,
        anchor: &TrustAnchor,
        now_unix: i64,
        required_role: Option<&str>,
    ) -> Result<()> {
        let now = DateTime::<Utc>::from_timestamp(now_unix, 0).ok_or_else(|| {
            AgentCredsError::InvalidVcProof {
                reason: "invalid timestamp".into(),
            }
        })?;
        directory.verify_current(anchor, now)?;

        let approver_did =
            self.approver_did
                .as_deref()
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "evidence is not approver-key signed".into(),
                })?;
        let entry =
            directory
                .lookup(approver_did, now)
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "approver not enrolled or entry expired".into(),
                })?;
        if let Some(role) = required_role {
            if !entry.roles.iter().any(|r| r == role) {
                return Err(AgentCredsError::InvalidVcProof {
                    reason: format!("approver lacks required role '{role}'"),
                });
            }
        }
        if self.binding != action.approval_binding() {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "approval evidence is not bound to this action/principal".into(),
            });
        }
        if now_unix >= self.expires_at {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "approval evidence has expired".into(),
            });
        }
        let key = PublicKey::from_did_key(approver_did)?;
        let sig = crate::signed::decode_signature(&self.signature, "approval evidence")?;
        key.verify(&self.signing_payload(), &sig)
            .map_err(|_| AgentCredsError::InvalidVcProof {
                reason: "approver-key evidence signature does not verify".into(),
            })
    }
}

/// A relying party's record of approval evidence already relied upon for
/// execution - enforcing R10's "not previously relied upon" (one-time) property.
/// In-process; back it with a shared store for a multi-replica relying party.
///
/// Pair it with [`DelegationToken::verify_rooted_gated`](crate::delegation::DelegationToken::verify_rooted_gated): on success, `try_consume`
/// each returned `approval_id` and refuse the action if any consume returns
/// `false`. Using `approval_id` (rather than the whole evidence) keeps m-of-n
/// bundles and idempotent retries a mechanism choice, not a requirement violation.
#[derive(Debug, Default)]
pub struct ConsumedApprovals {
    seen: std::collections::HashSet<String>,
}

impl ConsumedApprovals {
    /// A fresh, empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `approval_id` as relied upon. Returns `true` the first time and
    /// `false` on every subsequent call - a `false` means the evidence has already
    /// been used for execution and MUST be refused.
    pub fn try_consume(&mut self, approval_id: &str) -> bool {
        self.seen.insert(approval_id.to_string())
    }

    /// Whether `approval_id` has already been relied upon.
    pub fn contains(&self, approval_id: &str) -> bool {
        self.seen.contains(approval_id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::delegation::Action;
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
    use chrono::{Duration, Utc};

    fn action_alice() -> Action {
        Action::new("tool:wire_funds", "amount=5000").on_behalf_of("did:web:alice.example")
    }
    fn future_unix() -> i64 {
        (Utc::now() + Duration::hours(1)).timestamp()
    }
    fn now_unix() -> i64 {
        Utc::now().timestamp()
    }

    // -- Anchor-mode ApprovalEvidence -----------------------------------------

    #[test]
    fn anchor_evidence_verifies_for_its_action() {
        let anchor = TrustAnchor::generate().unwrap();
        let action = action_alice();
        let ev =
            ApprovalEvidence::approve(&action, "approver@acme", "ap-1", future_unix(), &anchor)
                .unwrap();
        assert!(ev.verify(&action, &anchor, now_unix()).is_ok());
        assert_eq!(ev.kind, Gate::APPROVAL);
        assert!(ev.approver_did.is_none());
    }

    #[test]
    fn anchor_evidence_is_bound_to_the_principal() {
        // The headline R10 invariant: approval for Alice's action does NOT satisfy
        // the same operation performed on behalf of Bob.
        let anchor = TrustAnchor::generate().unwrap();
        let ev = ApprovalEvidence::approve(&action_alice(), "ap", "ap-2", future_unix(), &anchor)
            .unwrap();
        let bob = Action::new("tool:wire_funds", "amount=5000").on_behalf_of("did:web:bob.example");
        assert!(ev.verify(&bob, &anchor, now_unix()).is_err());
    }

    #[test]
    fn anchor_evidence_rejects_expired() {
        let anchor = TrustAnchor::generate().unwrap();
        let past = (Utc::now() - Duration::minutes(1)).timestamp();
        let action = action_alice();
        let ev = ApprovalEvidence::approve(&action, "ap", "ap-3", past, &anchor).unwrap();
        assert!(ev.verify(&action, &anchor, now_unix()).is_err());
    }

    #[test]
    fn anchor_evidence_rejects_wrong_anchor_and_tamper() {
        let anchor = TrustAnchor::generate().unwrap();
        let other = TrustAnchor::generate().unwrap();
        let action = action_alice();
        let ev = ApprovalEvidence::approve(&action, "ap", "ap-4", future_unix(), &anchor).unwrap();
        // A different anchor's key must not validate it.
        assert!(ev.verify(&action, &other, now_unix()).is_err());
        // Tampering any signed field breaks the signature.
        let mut forged = ev.clone();
        forged.approver = "attacker".into();
        assert!(forged.verify(&action, &anchor, now_unix()).is_err());
        let mut forged2 = ev.clone();
        forged2.approval_id = "ap-999".into();
        assert!(forged2.verify(&action, &anchor, now_unix()).is_err());
    }

    // -- Approver-key (hybrid) mode + directory -------------------------------

    fn directory_with(
        approver: &AgentIdentity,
        roles: Vec<String>,
        dir_not_after: Option<chrono::DateTime<Utc>>,
        anchor: &TrustAnchor,
    ) -> ApproverDirectory {
        let entry = ApproverEntry {
            approver_id: "alice-approver".into(),
            approver_did: approver.did().to_string(),
            roles,
            not_after: None,
        };
        ApproverDirectory::seal(vec![entry], 1, Utc::now(), dir_not_after, anchor).unwrap()
    }

    #[test]
    fn approver_key_evidence_verifies_with_directory_and_role() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec!["finance".into()], None, &anchor);
        let action = action_alice();
        let ev = ApprovalEvidence::approve_by_key(
            &action,
            "alice-approver",
            &approver,
            "kp-1",
            future_unix(),
        )
        .unwrap();
        assert_eq!(ev.kind, Gate::APPROVAL_KEY);
        assert!(ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), Some("finance"))
            .is_ok());
    }

    #[test]
    fn approver_key_evidence_rejects_missing_role() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec!["ops".into()], None, &anchor);
        let action = action_alice();
        let ev = ApprovalEvidence::approve_by_key(
            &action,
            "alice-approver",
            &approver,
            "kp-2",
            future_unix(),
        )
        .unwrap();
        assert!(ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), Some("finance"))
            .is_err());
    }

    #[test]
    fn approver_key_evidence_rejects_unenrolled_approver() {
        let anchor = TrustAnchor::generate().unwrap();
        let enrolled = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let stranger = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&enrolled, vec![], None, &anchor);
        let action = action_alice();
        let ev =
            ApprovalEvidence::approve_by_key(&action, "stranger", &stranger, "kp-3", future_unix())
                .unwrap();
        assert!(ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), None)
            .is_err());
    }

    #[test]
    fn approver_key_evidence_rejects_expired_entry() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let past = Utc::now() - Duration::minutes(1);
        // Directory itself still valid, but the *entry* has expired.
        let entry = ApproverEntry {
            approver_id: "a".into(),
            approver_did: approver.did().to_string(),
            roles: vec![],
            not_after: Some(past),
        };
        let dir = ApproverDirectory::seal(
            vec![entry],
            1,
            Utc::now(),
            Some(Utc::now() + Duration::hours(1)),
            &anchor,
        )
        .unwrap();
        let action = action_alice();
        let ev = ApprovalEvidence::approve_by_key(&action, "a", &approver, "kp-4", future_unix())
            .unwrap();
        assert!(ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), None)
            .is_err());
    }

    #[test]
    fn approver_key_evidence_rejects_wrong_directory_anchor() {
        let anchor = TrustAnchor::generate().unwrap();
        let other = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec![], None, &anchor);
        let action = action_alice();
        let ev = ApprovalEvidence::approve_by_key(&action, "a", &approver, "kp-5", future_unix())
            .unwrap();
        // Directory sealed by `anchor` but verified under `other`.
        assert!(ev
            .verify_with_directory(&action, &dir, &other, now_unix(), None)
            .is_err());
    }

    #[test]
    fn approver_key_evidence_rejects_tampered_binding() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec![], None, &anchor);
        let action = action_alice();
        let mut ev =
            ApprovalEvidence::approve_by_key(&action, "a", &approver, "kp-6", future_unix())
                .unwrap();
        // Swap the binding to a different amount -> signature no longer matches.
        ev.binding = Action::new("tool:wire_funds", "amount=1")
            .on_behalf_of("did:web:alice.example")
            .approval_binding();
        assert!(ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), None)
            .is_err());
    }

    #[test]
    fn cross_mode_evidence_is_rejected() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec![], None, &anchor);
        let action = action_alice();
        // Anchor-mode evidence carries no approver_did -> the directory path rejects it.
        let anchor_ev =
            ApprovalEvidence::approve(&action, "a", "x-1", future_unix(), &anchor).unwrap();
        assert!(anchor_ev
            .verify_with_directory(&action, &dir, &anchor, now_unix(), None)
            .is_err());
        // Approver-key evidence handed to the anchor-mode path -> signature fails
        // (domain separation + a different signer).
        let key_ev =
            ApprovalEvidence::approve_by_key(&action, "a", &approver, "x-2", future_unix())
                .unwrap();
        assert!(key_ev.verify(&action, &anchor, now_unix()).is_err());
    }

    // -- ApproverDirectory -----------------------------------------------------

    #[test]
    fn directory_verifies_and_looks_up_live_entry() {
        let anchor = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(&approver, vec!["finance".into()], None, &anchor);
        let now = Utc::now();
        assert!(dir.verify_current(&anchor, now).is_ok());
        assert!(dir.lookup(approver.did(), now).is_some());
        assert!(dir.lookup("did:key:zNotHere", now).is_none());
    }

    #[test]
    fn directory_rejects_wrong_anchor_expiry_and_tamper() {
        let anchor = TrustAnchor::generate().unwrap();
        let other = TrustAnchor::generate().unwrap();
        let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let dir = directory_with(
            &approver,
            vec![],
            Some(Utc::now() + Duration::hours(1)),
            &anchor,
        );
        let now = Utc::now();
        assert!(dir.verify_current(&other, now).is_err()); // wrong anchor
        assert!(dir
            .verify_current(&anchor, Utc::now() + Duration::hours(2))
            .is_err()); // past not_after
                        // Tampering an entry after sealing changes the digest.
        let mut forged = dir.clone();
        forged.entries[0].roles.push("admin".into());
        assert!(forged.verify_current(&anchor, now).is_err());
    }

    // -- ConsumedApprovals (one-time reliance, R10) ----------------------------

    #[test]
    fn consumed_approvals_enforce_one_time() {
        let mut seen = ConsumedApprovals::new();
        assert!(!seen.contains("ap-1"));
        assert!(seen.try_consume("ap-1")); // first reliance -> true
        assert!(!seen.try_consume("ap-1")); // replay -> false (must be refused)
        assert!(seen.contains("ap-1"));
        assert!(seen.try_consume("ap-2")); // an independent id is unaffected
    }

    // -- Gate constructors -----------------------------------------------------

    #[test]
    fn gate_constructors_set_kind_and_tool() {
        let g = Gate::approval("tool:wire_funds");
        assert_eq!(g.kind, Gate::APPROVAL);
        assert_eq!(g.tool, "tool:wire_funds");
        let k = Gate::approval_key("tool:wire_funds");
        assert_eq!(k.kind, Gate::APPROVAL_KEY);
    }
}
