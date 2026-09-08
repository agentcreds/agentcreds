//! Signed intent statements and alignment evidence (AARM R3 and R7).
//!
//! # The problem this solves, and the one it refuses to
//!
//! AARM R3 asks that an action be evaluated against "its alignment with the stated agent
//! intent", and R7 that drift between proposed actions and the original intent be
//! tracked. Both are **semantic** judgements. Making that judgement here would put a
//! model in the authorization path, which would cost determinism, offline verification
//! (R3 of the WIMSE requirements: no runtime callback) and the ability for an auditor to
//! re-derive a decision from the record.
//!
//! So this module does not judge alignment. It carries a **signed statement of intent**
//! and verifies **evidence that some evaluator judged an action aligned with it**. The
//! judgement happens out of band and can be as semantic as you like; what reaches the
//! enforcement point is a signature, checked deterministically and offline.
//!
//! That is the same shape as execution-time human approval (see the approval-evidence types re-exported from [`crate::delegation`]): the
//! decision is made elsewhere, the evidence is bound to the exact action, and the relying
//! party verifies rather than re-decides.
//!
//! # Why the agent cannot author its own intent
//!
//! The issuance policy this module obeys states the rule: **nothing that bounds
//! authority may originate from the party being bounded**. An intent the
//! agent declares about itself bounds nothing - a hijacked agent declares whatever intent
//! makes its action look aligned, and the gate returns true by construction.
//!
//! This is not hypothetical. The same mistake was made once already and corrected: taking
//! the consented scope from the caller's own tools made `permits_tools` a tautology, one
//! that "could not fail, so the second axis bounded nothing while appearing to" (see the `oidc` module's note on consented scope). The failure mode is silent - every log line reads "verified".
//!
//! An [`IntentStatement`] is therefore signed by an authority **other than the agent** -
//! the organizational anchor, standing for the human principal or the orchestrator that
//! actually set the task - and is bound to the subject agent, so it cannot be lifted onto
//! a different one.
//!
//! # What is bound to what
//!
//! ```text
//! IntentStatement  --signed by anchor-->  binding()  ------+
//!   task_id, subject_did, statement, declared_by           |
//!                                                          v
//! Action  --approval_binding()-->  tool+params+resource+principal
//!                                                          |
//! AlignmentEvidence  --signed by anchor-->  both bindings <+
//!   + semantic_distance (R7)
//! ```
//!
//! Evidence carries the digest of the intent **and** the digest of the action, so it
//! cannot be moved to a different action, a different intent, or a different principal.
//!
//! # Status: mechanism only, deliberately not wired
//!
//! These types are verifiable today and a policy enforcement point can call
//! [`AlignmentEvidence::verify_quorum`] directly. They are **not** wired into
//! `verify_rooted_gated`, and [`Gate::INTENT`] is refused there rather than silently
//! passed. Revisit that with the goal of **architecting the function properly**, not of
//! finishing the wiring - the current shape is a mechanism that works, not a design that
//! has been proven against real traffic.
//!
//! Preconditions before wiring it as a first-class gate or exposing it in the Python and
//! Node bindings:
//!
//! 1. **Calibrate the scales.** `semantic_distance` and `confidence` are 0..=100
//!    conventions asserted here, not measured quantities. Thresholds mean nothing until
//!    an evaluator's distribution over known-good and known-bad actions is measured on
//!    real traffic. A threshold without calibration is a number, not a control.
//! 2. **Handle correlated evaluator failure.** A quorum defends against one evaluator
//!    being fooled; it does not defend against three variants of one vendor's model being
//!    fooled identically by the same crafted argument. Decide what independence has to
//!    mean, and whether it can be checked rather than assumed.
//! 3. **Settle cross-org gate-kind rollout.** Unknown kinds fail closed, so introducing
//!    one is a coordinated upgrade across every verifier - including verifiers in other
//!    organizations. Minting a gate a peer cannot enforce turns a security feature into
//!    an availability outage. This probably wants negotiation, not unilateral minting.
//! 4. **Design the audit payload deliberately.** A meaningful record carries the
//!    evaluators, distances, confidences and rationales - up to 1 KiB of evaluator text
//!    per evaluator, per decision, in a hash-chained and exported log. Size bound and
//!    redaction policy first.
//! 5. **Add cross-language conformance vectors** if it reaches the bindings. The 28
//!    existing vectors are asserted identically by Rust, Python and Node; a
//!    binding-exposed feature outside that set would be a capability claimed more
//!    broadly than it is tested.
//!
//! The risk that motivates all five: everything else enforced on this path is
//! deterministic and cryptographically grounded. Intent alignment is deterministic in
//! *verification* but its input is a judgement with an unmeasured error rate. Promoting
//! it to peer status with proof-of-possession and revocation invites teams to widen
//! scopes because "the intent gate covers it" - trading a deterministic control for a
//! probabilistic one without noticing.
//!
//! # Example
//!
//! ```rust
//! use agentcreds_core::did::TrustAnchor;
//! use agentcreds_core::delegation::{
//!     Action, AlignmentEvidence, AlignmentPolicy, IntentStatement, Judgement,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let anchor = TrustAnchor::generate()?;
//!
//! // The task-setter declares intent; the agent does not.
//! let intent = IntentStatement::declare(
//!     "task-7", "did:key:zAgent", "Reconcile September invoices",
//!     "did:key:zHumanPrincipal", "intent-1", 1_000, 9_000, &anchor,
//! )?;
//!
//! // An evaluator judges this action aligned, out of band, and signs that judgement.
//! let action = Action::new("tool:search", "{\"q\":\"invoices\"}");
//! let ev = AlignmentEvidence::attest(
//!     &intent,
//!     &action,
//!     Judgement {
//!         evaluator: "evaluator:policy-llm".into(),
//!         evaluator_version: "2026-08-01".into(),
//!         semantic_distance: 12,
//!         confidence: 88,
//!         rationale: "Searching invoices serves the reconciliation task.".into(),
//!     },
//!     "ev-1", 9_000, &anchor,
//! )?;
//!
//! // The enforcement point verifies deterministically, offline. For anything
//! // consequential, require several independent evaluators to agree instead.
//! let policy = AlignmentPolicy::quorum_of(1, 30, 70);
//! let verdict = AlignmentEvidence::verify_quorum(
//!     &[ev], &intent, &action, "did:key:zAgent", &anchor, 1_500, &policy,
//! )?;
//! assert_eq!(verdict.evaluators, ["evaluator:policy-llm@2026-08-01"]);
//! # Ok(())
//! # }
//! ```

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approval::Gate;
use crate::delegation::Action;
use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

/// Length-prefix a field into a running SHA-256, so concatenation is unambiguous.
fn hash_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

/// A signed declaration of what an agent is *for* on a given task.
///
/// Authored by an authority **other than the agent** and signed by the organizational
/// anchor. Bound to `subject_did`, so a statement issued for one agent cannot be
/// presented for another, and to `task_id`, which gives R7 a horizon to measure drift
/// across and gives R2 a thread to accumulate against.
///
/// This is a *statement*, not a permission. It never widens authority: an action must
/// still be inside the delegation token's scope. Intent is an additional bound, checked
/// alongside capability, in the same spirit as the on-behalf-of principal axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentStatement {
    /// Unique id of this statement.
    pub intent_id: String,
    /// The task or thread this intent governs. Actions across a long horizon share it,
    /// which is what makes semantic-distance tracking (R7) meaningful.
    pub task_id: String,
    /// The agent this intent is declared for. Checked at verification, so a statement
    /// cannot be lifted onto a different agent.
    pub subject_did: String,
    /// The declared intent itself - natural language or a structured goal, opaque here.
    pub statement: String,
    /// The authority that declared it: the human principal, orchestrator or operator.
    /// **Must not be the subject agent**; see the module documentation.
    pub declared_by: String,
    /// Issued at, Unix seconds.
    pub issued_at: i64,
    /// Expiry, Unix seconds. A statement at or after this instant is refused.
    pub expires_at: i64,
    /// Anchor signature over the signing payload, hex-encoded.
    pub signature: String,
}

impl IntentStatement {
    const DOMAIN: &'static [u8] = b"agentcreds-intent-statement-v1";

    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(Self::DOMAIN);
        hash_field(&mut h, self.intent_id.as_bytes());
        hash_field(&mut h, self.task_id.as_bytes());
        hash_field(&mut h, self.subject_did.as_bytes());
        hash_field(&mut h, self.statement.as_bytes());
        hash_field(&mut h, self.declared_by.as_bytes());
        h.update(self.issued_at.to_le_bytes());
        h.update(self.expires_at.to_le_bytes());
        h.finalize().to_vec()
    }

    /// Declare an intent for `subject_did`, signed by the organization `anchor`.
    ///
    /// `declared_by` records the authority that set the task. It is refused if it equals
    /// `subject_did`: an agent declaring its own intent is the tautology this module
    /// exists to prevent, and catching it at construction is cheaper than discovering a
    /// gate that never fails.
    ///
    /// # Errors
    /// If `declared_by == subject_did`, if the validity window is empty, or if signing
    /// fails.
    #[allow(clippy::too_many_arguments)]
    pub fn declare(
        task_id: impl Into<String>,
        subject_did: impl Into<String>,
        statement: impl Into<String>,
        declared_by: impl Into<String>,
        intent_id: impl Into<String>,
        issued_at: i64,
        expires_at: i64,
        anchor: &TrustAnchor,
    ) -> Result<Self> {
        let subject_did = subject_did.into();
        let declared_by = declared_by.into();
        if declared_by == subject_did {
            return Err(AgentCredsError::MalformedClaims {
                reason: "an agent may not declare its own intent: a bound that originates \
                         from the party being bounded cannot fail, so it bounds nothing"
                    .into(),
            });
        }
        if expires_at <= issued_at {
            return Err(AgentCredsError::MalformedClaims {
                reason: "intent statement expires at or before it was issued".into(),
            });
        }
        let mut s = IntentStatement {
            intent_id: intent_id.into(),
            task_id: task_id.into(),
            subject_did,
            statement: statement.into(),
            declared_by,
            issued_at,
            expires_at,
            signature: String::new(),
        };
        let sig = anchor.sign(&s.signing_payload())?;
        s.signature = crate::signed::encode_signature(&sig);
        Ok(s)
    }

    /// A stable digest identifying this exact statement, for evidence to reference.
    ///
    /// Covers every signed field, so altering any of them - including the intent text or
    /// the subject - produces a different binding and invalidates evidence issued against
    /// the original.
    pub fn binding(&self) -> String {
        hex::encode(self.signing_payload())
    }

    /// Verify the anchor signature and the validity window at `now_unix`.
    ///
    /// # Errors
    /// If the signature is invalid under `anchor`, or the statement is not yet valid or
    /// has expired.
    pub fn verify(&self, anchor: &TrustAnchor, now_unix: i64) -> Result<()> {
        let sig = crate::signed::decode_signature(&self.signature, "intent statement")?;
        anchor
            .verify_signature(&self.signing_payload(), &sig)
            .map_err(|_| AgentCredsError::MalformedClaims {
                reason: format!(
                    "intent statement '{}' is not signed by this anchor",
                    self.intent_id
                ),
            })?;
        if now_unix < self.issued_at {
            return Err(AgentCredsError::MalformedClaims {
                reason: format!(
                    "intent statement '{}' is not valid until {}",
                    self.intent_id, self.issued_at
                ),
            });
        }
        if now_unix >= self.expires_at {
            return Err(AgentCredsError::MalformedClaims {
                reason: format!(
                    "intent statement '{}' expired at {}",
                    self.intent_id, self.expires_at
                ),
            });
        }
        Ok(())
    }
}

/// One evaluator's judgement about an action, before it is signed.
///
/// A parameter object rather than eight positional arguments, so a caller cannot
/// silently transpose `semantic_distance` and `confidence` - two `u8`s on the same
/// scale whose meanings are opposite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// Identifier of the evaluator: a model, rules engine, or human reviewer.
    pub evaluator: String,
    /// The evaluator's **version**. Recorded separately and signed, so a verdict can be
    /// traced to what produced it. Without this an audit months later cannot tell
    /// whether a bad judgement came from a model revision that has since been replaced,
    /// and a systematically wrong evaluator cannot be correlated to its verdicts.
    pub evaluator_version: String,
    /// How far this action sits from the declared intent: `0` (aligned) to `100`
    /// (unrelated). The R7 drift signal.
    pub semantic_distance: u8,
    /// How sure the evaluator is of that distance: `0` (guessing) to `100` (certain).
    /// Distinct from distance on purpose - "confidently 30" and "no idea, call it 30"
    /// are different inputs to a policy decision, and collapsing them loses the
    /// difference exactly where it matters.
    pub confidence: u8,
    /// Why the evaluator judged as it did, in plain text. Not re-evaluated and not
    /// trusted as a control; it is carried so the decision record answers "why" when
    /// someone asks months later. Capped at [`Judgement::MAX_RATIONALE`] bytes.
    pub rationale: String,
}

impl Judgement {
    /// Maximum rationale length in bytes. Bounded because it is evaluator-supplied text
    /// that lands in a signed receipt and an audit log; unbounded free text on that path
    /// is a storage and log-injection concern, not a feature.
    pub const MAX_RATIONALE: usize = 1024;
}

/// Signed evidence that an evaluator judged one action aligned with one intent.
///
/// Produced **out of band** - by a model, a rules engine or a human - and verified
/// on the enforcement path deterministically and offline. The evaluator's reasoning is
/// carried but never re-run; what is verified is that an identified evaluator, at an
/// identified version, committed to a judgement about this exact action under this exact
/// intent.
///
/// `semantic_distance` is the R7 signal and `confidence` qualifies it. Both are inside
/// the signature, so neither can be adjusted in transit, and policy thresholds them at
/// verification.
///
/// For consequential actions prefer [`verify_quorum`](Self::verify_quorum) over a single
/// verdict: one evaluator that can be fooled is one failure away from a false "aligned",
/// and independent judgements fail independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlignmentEvidence {
    /// Unique id. The relying party remembers it to enforce one-time reliance, using
    /// the same [`ConsumedApprovals`](crate::delegation::ConsumedApprovals) ledger as
    /// human approvals.
    pub evidence_id: String,
    /// The gate kind this evidence satisfies ([`Gate::INTENT`]).
    pub kind: String,
    /// Digest of the [`IntentStatement`] this judgement was made against.
    pub intent_binding: String,
    /// Digest of the action, from [`Action::approval_binding`] - tool, parameters,
    /// resource and on-behalf-of principal.
    pub action_binding: String,
    /// Identifier of the evaluator that made the judgement.
    pub evaluator: String,
    /// The evaluator's version at the time of judgement.
    pub evaluator_version: String,
    /// How far this action sits from the declared intent, `0` (aligned) to `100`
    /// (unrelated). Signed, and thresholded by policy at verification (R7).
    pub semantic_distance: u8,
    /// The evaluator's confidence in that distance, `0` (guessing) to `100` (certain).
    /// Signed, and floored by policy at verification.
    pub confidence: u8,
    /// The evaluator's stated reason. Carried for the audit record, never re-evaluated.
    pub rationale: String,
    /// Expiry, Unix seconds. Evidence at or after this instant is refused.
    pub expires_at: i64,
    /// Anchor signature over the signing payload, hex-encoded.
    pub signature: String,
}

/// Thresholds a relying party applies to alignment evidence.
///
/// Defaults are deliberately strict: [`AlignmentPolicy::single`] is the weakest useful
/// configuration and still requires a distance and a confidence bound to be chosen
/// explicitly, because an unthresholded verdict records a number without acting on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignmentPolicy {
    /// Minimum number of **distinct evaluators** that must independently judge the
    /// action aligned. `1` accepts a single verdict; higher values require agreement.
    ///
    /// Distinctness is by `evaluator`, ignoring version: two revisions of the same model
    /// are not independent, and counting them as two would let one fooled evaluator
    /// satisfy a quorum by itself.
    pub quorum: usize,
    /// Maximum permitted `semantic_distance`. `None` records drift without gating on it.
    pub max_distance: Option<u8>,
    /// Minimum permitted `confidence`. `None` accepts any confidence, including a
    /// self-declared guess.
    pub min_confidence: Option<u8>,
}

impl AlignmentPolicy {
    /// A single evaluator, with an explicit distance ceiling and confidence floor.
    pub fn single(max_distance: u8, min_confidence: u8) -> Self {
        AlignmentPolicy {
            quorum: 1,
            max_distance: Some(max_distance),
            min_confidence: Some(min_confidence),
        }
    }

    /// Require `n` distinct evaluators to agree, with a distance ceiling and confidence
    /// floor. The configuration to prefer in front of anything consequential.
    pub fn quorum_of(n: usize, max_distance: u8, min_confidence: u8) -> Self {
        AlignmentPolicy {
            quorum: n,
            max_distance: Some(max_distance),
            min_confidence: Some(min_confidence),
        }
    }
}

/// What a successful quorum verification found, for the decision record.
///
/// Returned rather than discarded so the ADR can record *which* evaluators agreed and
/// how strongly - a decision that says only "allowed" cannot later answer "on whose
/// judgement, and how sure were they".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignmentVerdict {
    /// The distinct evaluators that agreed, as `evaluator@version`, in input order.
    pub evaluators: Vec<String>,
    /// The **worst** (largest) distance among the accepted evidence.
    pub worst_distance: u8,
    /// The **weakest** (smallest) confidence among the accepted evidence.
    pub weakest_confidence: u8,
}

impl AlignmentEvidence {
    const DOMAIN: &'static [u8] = b"agentcreds-alignment-evidence-v1";

    fn signing_payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(Self::DOMAIN);
        hash_field(&mut h, self.evidence_id.as_bytes());
        hash_field(&mut h, self.kind.as_bytes());
        hash_field(&mut h, self.intent_binding.as_bytes());
        hash_field(&mut h, self.action_binding.as_bytes());
        hash_field(&mut h, self.evaluator.as_bytes());
        hash_field(&mut h, self.evaluator_version.as_bytes());
        hash_field(&mut h, self.rationale.as_bytes());
        h.update([self.semantic_distance]);
        h.update([self.confidence]);
        h.update(self.expires_at.to_le_bytes());
        h.finalize().to_vec()
    }

    /// Mint evidence that `evaluator` judged `action` aligned with `intent`, at
    /// `semantic_distance`, valid until `expires_at`, signed by the organization
    /// `anchor`.
    ///
    /// # Errors
    /// If `semantic_distance` exceeds 100, or signing fails.
    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        intent: &IntentStatement,
        action: &Action,
        judgement: Judgement,
        evidence_id: impl Into<String>,
        expires_at: i64,
        anchor: &TrustAnchor,
    ) -> Result<Self> {
        if judgement.semantic_distance > 100 {
            return Err(AgentCredsError::MalformedClaims {
                reason: "semantic_distance must be 0..=100".into(),
            });
        }
        if judgement.confidence > 100 {
            return Err(AgentCredsError::MalformedClaims {
                reason: "confidence must be 0..=100".into(),
            });
        }
        if judgement.evaluator.is_empty() || judgement.evaluator_version.is_empty() {
            return Err(AgentCredsError::MalformedClaims {
                reason: "evaluator and evaluator_version are required: an unversioned \
                         verdict cannot be traced to what produced it"
                    .into(),
            });
        }
        if judgement.rationale.len() > Judgement::MAX_RATIONALE {
            return Err(AgentCredsError::MalformedClaims {
                reason: format!(
                    "rationale is {} bytes, over the {} limit",
                    judgement.rationale.len(),
                    Judgement::MAX_RATIONALE
                ),
            });
        }
        let mut ev = AlignmentEvidence {
            evidence_id: evidence_id.into(),
            kind: Gate::INTENT.to_string(),
            intent_binding: intent.binding(),
            action_binding: action.approval_binding(),
            evaluator: judgement.evaluator,
            evaluator_version: judgement.evaluator_version,
            semantic_distance: judgement.semantic_distance,
            confidence: judgement.confidence,
            rationale: judgement.rationale,
            expires_at,
            signature: String::new(),
        };
        let sig = anchor.sign(&ev.signing_payload())?;
        ev.signature = crate::signed::encode_signature(&sig);
        Ok(ev)
    }

    /// `evaluator@version`, the identity recorded in an [`AlignmentVerdict`].
    pub fn attribution(&self) -> String {
        format!("{}@{}", self.evaluator, self.evaluator_version)
    }

    /// Verify that **`policy.quorum` distinct evaluators** independently judged this
    /// action aligned with this intent, within the distance ceiling and confidence
    /// floor.
    ///
    /// Independence is the point. A single evaluator that can be fooled - by a crafted
    /// argument, or simply by being wrong - is one failure away from a false "aligned".
    /// Independent evaluators fail independently, so agreement is meaningfully stronger
    /// than one verdict repeated.
    ///
    /// Two rules make that real rather than nominal:
    ///
    /// - **Distinctness is by `evaluator`, ignoring version.** Two revisions of one model
    ///   are not independent; counting them separately would let a single fooled
    ///   evaluator satisfy any quorum by signing repeatedly.
    /// - **Every supplied item must verify.** Invalid evidence is not silently skipped.
    ///   Discarding failures would let an attacker append junk in the hope that whatever
    ///   survives still meets the count, and would hide a misconfigured evaluator behind
    ///   a passing check. The cost is that one expired item fails the whole set, which is
    ///   the fail-closed side of the trade and the right one here.
    ///
    /// One-time reliance is still the caller's, per evidence id, through
    /// [`ConsumedApprovals`](crate::delegation::ConsumedApprovals).
    ///
    /// # Errors
    /// If the policy is unsatisfiable, any item fails [`verify`](Self::verify), or too
    /// few distinct evaluators agreed.
    pub fn verify_quorum(
        evidence: &[AlignmentEvidence],
        intent: &IntentStatement,
        action: &Action,
        agent_did: &str,
        anchor: &TrustAnchor,
        now_unix: i64,
        policy: &AlignmentPolicy,
    ) -> Result<AlignmentVerdict> {
        if policy.quorum == 0 {
            return Err(AgentCredsError::MalformedClaims {
                reason: "an alignment quorum of 0 would accept an action with no \
                         judgement at all"
                    .into(),
            });
        }

        let mut evaluators: Vec<String> = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        let mut worst_distance = 0u8;
        let mut weakest_confidence = 100u8;

        for ev in evidence {
            // Every item, no silent discards. `verify` covers the intent, the subject,
            // the signature, expiry and both bindings.
            ev.verify(
                intent,
                action,
                agent_did,
                anchor,
                now_unix,
                policy.max_distance,
            )?;

            if let Some(min) = policy.min_confidence {
                if ev.confidence < min {
                    return Err(AgentCredsError::ActionDenied {
                        action: action.tool.clone(),
                        reason: format!(
                            "evaluator {} reported confidence {}, under the required {}",
                            ev.attribution(),
                            ev.confidence,
                            min
                        ),
                    });
                }
            }

            if seen.contains(&ev.evaluator.as_str()) {
                return Err(AgentCredsError::ActionDenied {
                    action: action.tool.clone(),
                    reason: format!(
                        "evaluator '{}' judged this action more than once; a quorum \
                         requires distinct evaluators, and repeated verdicts from one \
                         are not independent",
                        ev.evaluator
                    ),
                });
            }
            seen.push(ev.evaluator.as_str());
            evaluators.push(ev.attribution());
            worst_distance = worst_distance.max(ev.semantic_distance);
            weakest_confidence = weakest_confidence.min(ev.confidence);
        }

        if evaluators.len() < policy.quorum {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: format!(
                    "{} distinct evaluator(s) agreed, {} required",
                    evaluators.len(),
                    policy.quorum
                ),
            });
        }

        Ok(AlignmentVerdict {
            evaluators,
            worst_distance,
            weakest_confidence,
        })
    }

    /// Verify this evidence against the intent, the action and the acting agent.
    ///
    /// Checks, in order and all required:
    /// 1. the `intent` itself verifies under `anchor` and is currently valid;
    /// 2. the intent was declared for `agent_did` - it cannot be lifted onto another
    ///    agent;
    /// 3. this evidence is signed by `anchor` and has not expired;
    /// 4. its `intent_binding` matches this intent, and its `action_binding` matches
    ///    this action - so evidence cannot be moved between actions, intents or
    ///    principals;
    /// 5. `semantic_distance` is within `max_distance`, when a threshold is given (R7).
    ///
    /// One-time reliance is **not** enforced here: pass `evidence_id` to a
    /// [`ConsumedApprovals`](crate::delegation::ConsumedApprovals) ledger, exactly as
    /// for human approval evidence, so both kinds share one replay ledger.
    ///
    /// # Errors
    /// If any check above fails, with a reason naming which.
    pub fn verify(
        &self,
        intent: &IntentStatement,
        action: &Action,
        agent_did: &str,
        anchor: &TrustAnchor,
        now_unix: i64,
        max_distance: Option<u8>,
    ) -> Result<()> {
        // 1. The statement must itself be authentic and live. Verified here rather than
        //    trusted from the caller: evidence about an unverified statement proves
        //    nothing, and forgetting this check is the obvious way to misuse the API.
        intent.verify(anchor, now_unix)?;

        // 2. The intent must be for the agent actually acting.
        if intent.subject_did != agent_did {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: format!(
                    "intent statement '{}' was declared for {} but the acting agent is {}",
                    intent.intent_id, intent.subject_did, agent_did
                ),
            });
        }

        if self.kind != Gate::INTENT {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: format!(
                    "alignment evidence has kind '{}', expected '{}'",
                    self.kind,
                    Gate::INTENT
                ),
            });
        }

        // 3. Authenticity and freshness of the judgement itself.
        let sig = crate::signed::decode_signature(&self.signature, "alignment evidence")?;
        anchor
            .verify_signature(&self.signing_payload(), &sig)
            .map_err(|_| AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: format!(
                    "alignment evidence '{}' is not signed by this anchor",
                    self.evidence_id
                ),
            })?;
        if now_unix >= self.expires_at {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: format!(
                    "alignment evidence '{}' expired at {}",
                    self.evidence_id, self.expires_at
                ),
            });
        }

        // 4. The judgement must be about THIS intent and THIS action.
        if self.intent_binding != intent.binding() {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: "alignment evidence was issued against a different intent statement".into(),
            });
        }
        if self.action_binding != action.approval_binding() {
            return Err(AgentCredsError::ActionDenied {
                action: action.tool.clone(),
                reason: "alignment evidence was issued against a different action \
                         (tool, parameters, resource or principal differ)"
                    .into(),
            });
        }

        // 5. R7: drift threshold.
        if let Some(max) = max_distance {
            if self.semantic_distance > max {
                return Err(AgentCredsError::ActionDenied {
                    action: action.tool.clone(),
                    reason: format!(
                        "action is {} from the declared intent, over the permitted {} \
                         (semantic drift)",
                        self.semantic_distance, max
                    ),
                });
            }
        }
        Ok(())
    }

    /// [`verify`](Self::verify) at the current wall-clock time.
    ///
    /// # Errors
    /// As [`verify`](Self::verify).
    pub fn verify_now(
        &self,
        intent: &IntentStatement,
        action: &Action,
        agent_did: &str,
        anchor: &TrustAnchor,
        max_distance: Option<u8>,
    ) -> Result<()> {
        self.verify(
            intent,
            action,
            agent_did,
            anchor,
            Utc::now().timestamp(),
            max_distance,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::delegation::ConsumedApprovals;

    const AGENT: &str = "did:key:zAgent";
    const HUMAN: &str = "did:key:zHumanPrincipal";
    const NOW: i64 = 1_500;

    fn anchor() -> TrustAnchor {
        TrustAnchor::generate().expect("anchor")
    }

    fn intent_for(a: &TrustAnchor, subject: &str) -> IntentStatement {
        IntentStatement::declare(
            "task-7",
            subject,
            "Reconcile September invoices",
            HUMAN,
            "intent-1",
            1_000,
            9_000,
            a,
        )
        .expect("declare")
    }

    fn action() -> Action {
        Action::new("tool:search", "{\"q\":\"invoices\"}")
    }

    fn judgement(evaluator: &str, dist: u8, conf: u8) -> Judgement {
        Judgement {
            evaluator: evaluator.into(),
            evaluator_version: "2026-08-01".into(),
            semantic_distance: dist,
            confidence: conf,
            rationale: "searching invoices serves the reconciliation task".into(),
        }
    }

    fn evidence(a: &TrustAnchor, i: &IntentStatement, act: &Action, dist: u8) -> AlignmentEvidence {
        AlignmentEvidence::attest(
            i,
            act,
            judgement("evaluator:policy-llm", dist, 90),
            "ev-1",
            9_000,
            a,
        )
        .expect("attest")
    }

    /// Evidence from a named evaluator, for quorum tests.
    fn evidence_from(
        a: &TrustAnchor,
        i: &IntentStatement,
        act: &Action,
        evaluator: &str,
        id: &str,
        dist: u8,
        conf: u8,
    ) -> AlignmentEvidence {
        AlignmentEvidence::attest(i, act, judgement(evaluator, dist, conf), id, 9_000, a)
            .expect("attest")
    }

    #[test]
    fn aligned_action_with_valid_evidence_is_accepted() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 12);
        ev.verify(&i, &act, AGENT, &a, NOW, Some(30))
            .expect("aligned action should verify");
    }

    /// The tautology this module exists to prevent, caught at construction.
    #[test]
    fn an_agent_cannot_declare_its_own_intent() {
        let a = anchor();
        let err = IntentStatement::declare(
            "task-7",
            AGENT,
            "do whatever I want",
            AGENT,
            "intent-x",
            1_000,
            9_000,
            &a,
        );
        assert!(
            err.is_err(),
            "an intent whose declarer is the subject bounds nothing and must be refused"
        );
    }

    /// Evidence is bound to the action, so it cannot be replayed onto another one.
    #[test]
    fn evidence_does_not_transfer_to_a_different_action() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let judged = action();
        let ev = evidence(&a, &i, &judged, 5);

        let other = Action::new("tool:transfer", "{\"amount\":100000}");
        assert!(
            ev.verify(&i, &other, AGENT, &a, NOW, Some(30)).is_err(),
            "evidence judged for one action must not authorize another"
        );
    }

    /// The principal is inside `approval_binding`, so approving for Alice does not
    /// approve the same call made for Bob.
    #[test]
    fn evidence_does_not_transfer_across_principals() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let for_alice = action().on_behalf_of("did:key:zAlice");
        let ev = evidence(&a, &i, &for_alice, 5);

        let for_bob = action().on_behalf_of("did:key:zBob");
        assert!(
            ev.verify(&i, &for_bob, AGENT, &a, NOW, Some(30)).is_err(),
            "evidence bound to one principal must not satisfy another"
        );
    }

    /// An intent issued for one agent must not be usable by another.
    #[test]
    fn intent_does_not_transfer_to_another_agent() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);
        assert!(
            ev.verify(&i, &act, "did:key:zOtherAgent", &a, NOW, Some(30))
                .is_err(),
            "an intent declared for one agent must not bind another"
        );
    }

    /// Altering the declared intent invalidates evidence issued against the original -
    /// otherwise the statement could be rewritten after it was judged.
    #[test]
    fn rewriting_the_intent_text_invalidates_the_evidence() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);

        let mut tampered = i.clone();
        tampered.statement = "Exfiltrate the invoice archive".into();
        assert!(
            tampered.verify(&a, NOW).is_err(),
            "a rewritten statement must fail its own signature check"
        );
        assert!(
            ev.verify(&tampered, &act, AGENT, &a, NOW, Some(30))
                .is_err(),
            "evidence must not carry over to a rewritten intent"
        );
    }

    /// `semantic_distance` is signed, so it cannot be lowered to slip under a threshold.
    #[test]
    fn semantic_distance_cannot_be_lowered_in_transit() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let mut ev = evidence(&a, &i, &act, 90);
        ev.semantic_distance = 1;
        assert!(
            ev.verify(&i, &act, AGENT, &a, NOW, Some(30)).is_err(),
            "editing the signed distance must invalidate the signature"
        );
    }

    /// R7: drift beyond the permitted threshold is refused even though the evidence is
    /// authentic - the evaluator judged, policy decides how far is too far.
    #[test]
    fn drift_beyond_the_threshold_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 80);

        assert!(
            ev.verify(&i, &act, AGENT, &a, NOW, Some(30)).is_err(),
            "distance 80 must not pass a threshold of 30"
        );
        ev.verify(&i, &act, AGENT, &a, NOW, Some(90))
            .expect("the same evidence passes a looser threshold");
        ev.verify(&i, &act, AGENT, &a, NOW, None)
            .expect("no threshold means distance is recorded but not gating");
    }

    #[test]
    fn expired_evidence_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);
        assert!(
            ev.verify(&i, &act, AGENT, &a, 9_001, Some(30)).is_err(),
            "evidence at or after its expiry must be refused"
        );
    }

    #[test]
    fn expired_or_premature_intent_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);
        assert!(
            ev.verify(&i, &act, AGENT, &a, 9_500, Some(30)).is_err(),
            "an expired intent must fail even with valid evidence"
        );
        assert!(
            ev.verify(&i, &act, AGENT, &a, 500, Some(30)).is_err(),
            "an intent used before it is valid must be refused"
        );
    }

    /// A different organization's anchor must not validate this evidence.
    #[test]
    fn another_anchor_does_not_validate() {
        let a = anchor();
        let other = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);
        assert!(
            ev.verify(&i, &act, AGENT, &other, NOW, Some(30)).is_err(),
            "evidence must not verify under an unrelated anchor"
        );
    }

    /// Both evidence kinds share one replay ledger, so one-time reliance is uniform.
    #[test]
    fn evidence_is_one_time_through_the_shared_ledger() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let ev = evidence(&a, &i, &act, 5);

        let mut consumed = ConsumedApprovals::new();
        assert!(consumed.try_consume(&ev.evidence_id), "first use consumes");
        assert!(
            !consumed.try_consume(&ev.evidence_id),
            "a second use of the same evidence id must be refused"
        );
    }

    #[test]
    fn distance_above_100_is_rejected_at_mint() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        assert!(
            AlignmentEvidence::attest(&i, &action(), judgement("e", 101, 50), "ev", 9_000, &a)
                .is_err(),
            "semantic_distance is a 0..=100 scale"
        );
    }

    #[test]
    fn an_empty_validity_window_is_rejected() {
        let a = anchor();
        assert!(
            IntentStatement::declare("t", AGENT, "s", HUMAN, "i", 9_000, 9_000, &a).is_err(),
            "a statement that expires when issued is never valid"
        );
    }

    // -- N independent evaluators ------------------------------------------------

    #[test]
    fn a_quorum_of_distinct_evaluators_is_accepted() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let set = [
            evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 10, 90),
            evidence_from(&a, &i, &act, "eval:beta", "ev-2", 25, 80),
            evidence_from(&a, &i, &act, "eval:gamma", "ev-3", 18, 95),
        ];
        let policy = AlignmentPolicy::quorum_of(3, 30, 70);
        let v = AlignmentEvidence::verify_quorum(&set, &i, &act, AGENT, &a, NOW, &policy)
            .expect("three distinct evaluators agreeing should pass");

        assert_eq!(v.evaluators.len(), 3);
        assert_eq!(
            v.worst_distance, 25,
            "the verdict reports the WORST distance"
        );
        assert_eq!(
            v.weakest_confidence, 80,
            "the verdict reports the WEAKEST confidence"
        );
        assert!(
            v.evaluators[0].ends_with("@2026-08-01"),
            "attribution carries the version"
        );
    }

    /// The attack a naive count would allow: one evaluator signing repeatedly.
    #[test]
    fn one_evaluator_cannot_satisfy_a_quorum_by_signing_repeatedly() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let set = [
            evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 10, 90),
            evidence_from(&a, &i, &act, "eval:alpha", "ev-2", 10, 90),
            evidence_from(&a, &i, &act, "eval:alpha", "ev-3", 10, 90),
        ];
        let policy = AlignmentPolicy::quorum_of(3, 30, 70);
        assert!(
            AlignmentEvidence::verify_quorum(&set, &i, &act, AGENT, &a, NOW, &policy).is_err(),
            "three verdicts from one evaluator are not three independent judgements"
        );
    }

    /// Two versions of one evaluator are still one evaluator.
    #[test]
    fn different_versions_of_one_evaluator_are_not_independent() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let mut second = judgement("eval:alpha", 10, 90);
        second.evaluator_version = "2026-09-01".into();
        let set = [
            evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 10, 90),
            AlignmentEvidence::attest(&i, &act, second, "ev-2", 9_000, &a).expect("attest"),
        ];
        let policy = AlignmentPolicy::quorum_of(2, 30, 70);
        assert!(
            AlignmentEvidence::verify_quorum(&set, &i, &act, AGENT, &a, NOW, &policy).is_err(),
            "two revisions of the same model do not fail independently"
        );
    }

    #[test]
    fn too_few_evaluators_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let set = [evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 10, 90)];
        let policy = AlignmentPolicy::quorum_of(3, 30, 70);
        assert!(
            AlignmentEvidence::verify_quorum(&set, &i, &act, AGENT, &a, NOW, &policy).is_err(),
            "one verdict must not satisfy a quorum of three"
        );
    }

    /// Invalid evidence is never silently discarded, so junk cannot be appended in the
    /// hope that the survivors still meet the count.
    #[test]
    fn one_invalid_item_fails_the_whole_set() {
        let a = anchor();
        let other = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let forged = evidence_from(&other, &i, &act, "eval:gamma", "ev-3", 10, 90); // wrong anchor
        let set = [
            evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 10, 90),
            evidence_from(&a, &i, &act, "eval:beta", "ev-2", 10, 90),
            forged,
        ];
        let policy = AlignmentPolicy::quorum_of(2, 30, 70);
        assert!(
            AlignmentEvidence::verify_quorum(&set, &i, &act, AGENT, &a, NOW, &policy).is_err(),
            "an unverifiable item must fail the set, not be skipped"
        );
    }

    #[test]
    fn a_quorum_of_zero_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let policy = AlignmentPolicy {
            quorum: 0,
            max_distance: Some(30),
            min_confidence: Some(70),
        };
        assert!(
            AlignmentEvidence::verify_quorum(&[], &i, &act, AGENT, &a, NOW, &policy).is_err(),
            "a quorum of zero would accept an action nothing judged"
        );
    }

    // -- confidence, version, rationale --------------------------------------------

    #[test]
    fn confidence_below_the_floor_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        // Aligned by distance, but the evaluator is guessing.
        let set = [evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 5, 20)];
        assert!(
            AlignmentEvidence::verify_quorum(
                &set,
                &i,
                &act,
                AGENT,
                &a,
                NOW,
                &AlignmentPolicy::single(30, 70)
            )
            .is_err(),
            "a confident-looking distance from an unconfident evaluator must not pass"
        );
        AlignmentEvidence::verify_quorum(
            &set,
            &i,
            &act,
            AGENT,
            &a,
            NOW,
            &AlignmentPolicy::single(30, 10),
        )
        .expect("the same evidence passes a lower confidence floor");
    }

    #[test]
    fn confidence_and_rationale_and_version_are_signed() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let act = action();
        let base = evidence_from(&a, &i, &act, "eval:alpha", "ev-1", 5, 30);

        for mutate in [
            (|e: &mut AlignmentEvidence| e.confidence = 99) as fn(&mut AlignmentEvidence),
            |e: &mut AlignmentEvidence| e.evaluator_version = "1999-01-01".into(),
            |e: &mut AlignmentEvidence| e.rationale = "because I said so".into(),
        ] {
            let mut ev = base.clone();
            mutate(&mut ev);
            assert!(
                ev.verify(&i, &act, AGENT, &a, NOW, Some(30)).is_err(),
                "editing a signed field must invalidate the evidence"
            );
        }
    }

    #[test]
    fn an_unversioned_evaluator_is_refused_at_mint() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let mut j = judgement("eval:alpha", 5, 90);
        j.evaluator_version = String::new();
        assert!(
            AlignmentEvidence::attest(&i, &action(), j, "ev", 9_000, &a).is_err(),
            "a verdict with no version cannot be traced to what produced it"
        );
    }

    #[test]
    fn an_oversized_rationale_is_refused() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let mut j = judgement("eval:alpha", 5, 90);
        j.rationale = "x".repeat(Judgement::MAX_RATIONALE + 1);
        assert!(
            AlignmentEvidence::attest(&i, &action(), j, "ev", 9_000, &a).is_err(),
            "unbounded evaluator text must not reach a signed receipt"
        );
    }

    #[test]
    fn statement_round_trips_through_json() {
        let a = anchor();
        let i = intent_for(&a, AGENT);
        let back: IntentStatement =
            serde_json::from_str(&serde_json::to_string(&i).expect("ser")).expect("de");
        assert_eq!(back, i);
        back.verify(&a, NOW)
            .expect("round-tripped statement verifies");
    }
}
