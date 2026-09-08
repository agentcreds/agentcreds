//! Proof of Possession (PoP) - binding a token *presentation* to live
//! possession of the leaf agent's private key.
//!
//! A [`DelegationToken`] is a bearer credential: chain verification proves the
//! token is authentic and anchor-rooted, but not that *the party presenting it
//! right now* is the agent it was delegated to. Two attacks remain at the
//! presentation boundary:
//!
//! 1. **Token theft** - an attacker who captures the serialized token (e.g. off
//!    the wire or from a log) replays it.
//! 2. **Prefix stripping** - a holder at depth *k* presents a shorter prefix of
//!    the chain, which carries *broader* scope.
//!
//! PoP closes both. The verifier issues a fresh [`PopChallenge`] (a random
//! nonce). The presenter signs that challenge - bound to the token's leaf block
//! - with the **leaf agent's** key, producing a [`ProofOfPossession`]. The
//! verifier checks the signature against the leaf block's `agent_did`.
//!
//! - A thief without the leaf private key cannot produce the signature.
//! - A holder cannot present a stripped prefix: doing so makes an *earlier*
//!   agent the leaf, whose key they do not hold.
//! - A captured proof cannot be replayed: the nonce is single-use and
//!   freshness-bounded, and the proof is bound to one specific token leaf.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//!
//! let anchor = TrustAnchor::generate()?;
//! let agent  = AgentIdentity::create(DidMethod::Key, None)?;
//! let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
//! let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None)?;
//! let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
//! let token = DelegationToken::mint(&vc, scope, 300, &agent)?;
//!
//! // Verifier issues a challenge; the holder proves possession.
//! let challenge = PopChallenge::new(Some("mcp://orders".into()));
//! let proof = token.prove_possession(&challenge, &agent)?;
//!
//! // Verifier runs the complete presentation check.
//! let action = Action::new("tool:search", "q=ok");
//! token.verify_presentation(&action, &vc, &anchor, &proof, &challenge, 60)?;
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use base64ct::Encoding;

use crate::delegation::{Action, DelegationToken};
use crate::did::{AgentIdentity, PublicKey};
use crate::vc::CapabilityCredential;
use crate::{error::AgentCredsError, Result};

/// Length of the challenge nonce in bytes (256 bits).
const NONCE_LEN: usize = 32;
/// Domain-separation tag mixed into every PoP digest.
const POP_DOMAIN: &[u8] = b"agentcreds-pop-v1";
/// Allowance for clock skew when a challenge appears to be issued slightly in
/// the future, in seconds.
const FUTURE_SKEW_SECS: i64 = 5;

fn pop_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::ProofOfPossessionFailed {
        reason: reason.into(),
    }
}

/// A verifier-issued challenge. Generate one per presentation (or per session)
/// and keep it to check the returned [`ProofOfPossession`] against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopChallenge {
    /// Single-use random nonce.
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    /// Optional audience/verifier identifier (e.g. an MCP server URI). Binds
    /// the proof to this verifier so it cannot be replayed against another.
    pub audience: Option<String>,
    /// When the challenge was issued - used for the freshness window.
    pub issued_at: DateTime<Utc>,
    /// Optional binding to one specific request (see [`crate::delegation::Action::request_binding`]).
    /// Set by the *holder* before signing so the proof covers exactly which
    /// tool/parameters/resource it authorizes; the verifier checks it against the
    /// action it received. `None` = the proof is not bound to a request.
    #[serde(default)]
    pub request_binding: Option<String>,
}

impl PopChallenge {
    /// Create a fresh challenge with a random nonce and the current timestamp.
    pub fn new(audience: Option<String>) -> Self {
        let mut nonce = vec![0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        PopChallenge {
            nonce,
            audience,
            issued_at: Utc::now(),
            request_binding: None,
        }
    }

    /// Return a copy of this challenge bound to a specific request (the holder
    /// passes [`Action::request_binding`](crate::delegation::Action::request_binding)).
    /// The binding is folded into the signed digest, so the resulting proof is
    /// usable only for the matching action.
    #[must_use]
    pub fn with_request_binding(&self, binding: impl Into<String>) -> Self {
        let mut c = self.clone();
        c.request_binding = Some(binding.into());
        c
    }

    /// The digest the leaf agent signs: domain tag, nonce, audience, issue
    /// time, the optional request binding, and the token-leaf binding.
    fn digest(&self, token_binding: &str) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(POP_DOMAIN);
        h.update((self.nonce.len() as u64).to_le_bytes());
        h.update(&self.nonce);
        match &self.audience {
            Some(a) => {
                h.update([1u8]);
                h.update((a.len() as u64).to_le_bytes());
                h.update(a.as_bytes());
            }
            None => h.update([0u8]),
        }
        h.update(self.issued_at.timestamp().to_le_bytes());
        match &self.request_binding {
            Some(b) => {
                h.update([1u8]);
                h.update((b.len() as u64).to_le_bytes());
                h.update(b.as_bytes());
            }
            None => h.update([0u8]),
        }
        h.update(token_binding.as_bytes());
        h.finalize().to_vec()
    }

    /// Constant-shape equality against the challenge the verifier issued. The
    /// holder-set `request_binding` is intentionally **not** compared here (the
    /// issued challenge does not carry it); it is checked against the action in
    /// [`DelegationToken::verify_presentation`].
    fn matches(&self, issued: &PopChallenge) -> bool {
        self.nonce == issued.nonce
            && self.audience == issued.audience
            && self.issued_at == issued.issued_at
    }

    /// Serialize to CBOR for wire transport.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialise from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

/// A holder's proof that it possesses the private key of the token's leaf
/// agent, for one specific challenge and one specific token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPossession {
    /// DID of the leaf agent that produced the proof.
    pub leaf_did: String,
    /// Content hash of the token's leaf block this proof is bound to.
    pub token_binding: String,
    /// The challenge that was signed.
    pub challenge: PopChallenge,
    /// Base64-encoded signature over `challenge.digest(token_binding)`.
    pub signature: String,
}

impl ProofOfPossession {
    /// Verify this proof against the token it claims to bind, the challenge the
    /// verifier issued, and a freshness window in seconds.
    ///
    /// # Errors
    /// `ProofOfPossessionFailed` if the challenge does not match the issued
    /// one, the challenge is stale (or skewed into the future), the proof is
    /// not bound to this token's leaf, or the signature does not verify against
    /// the leaf agent's key.
    pub fn verify(
        &self,
        token: &DelegationToken,
        issued: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.verify_at(token, issued, max_age_secs, Utc::now())
    }

    /// [`verify`](Self::verify) with a caller-supplied `now`, so the freshness
    /// window is deterministic and testable (the offline core reads no clock).
    /// `verify` is exactly this with `now = Utc::now()`.
    ///
    /// # Errors
    /// As [`verify`](Self::verify).
    fn verify_at(
        &self,
        token: &DelegationToken,
        issued: &PopChallenge,
        max_age_secs: i64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // 1. The challenge presented must be the one the verifier issued.
        if !self.challenge.matches(issued) {
            return Err(pop_err("challenge does not match the issued challenge"));
        }

        // 2. Freshness - single-use nonces plus a bounded window defeat replay.
        let age = (now - self.challenge.issued_at).num_seconds();
        if age > max_age_secs {
            return Err(pop_err(format!(
                "challenge is stale ({age}s > {max_age_secs}s)"
            )));
        }
        if age < -FUTURE_SKEW_SECS {
            return Err(pop_err(
                "challenge issued in the future beyond allowed skew",
            ));
        }

        // 3. The proof must be bound to *this* token's leaf, and name the leaf
        //    agent. This is what defeats prefix-stripping: a stripped or
        //    substituted chain has a different leaf binding and (earlier) leaf
        //    agent, so neither the binding nor the DID will match.
        if self.token_binding != token.leaf_binding() {
            return Err(pop_err("proof is not bound to this token's leaf"));
        }
        if self.leaf_did != token.leaf_agent_did() {
            return Err(pop_err(
                "proof leaf DID does not match the token's leaf agent",
            ));
        }

        // 4. The signature must verify against the leaf agent's key - this is
        //    what the presenter must possess.
        let key = PublicKey::from_did_key(&self.leaf_did)?;
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| pop_err(format!("signature is not valid base64: {e}")))?;
        let digest = self.challenge.digest(&self.token_binding);
        key.verify(&digest, &sig)
            .map_err(|e| pop_err(format!("signature does not verify: {e}")))?;

        Ok(())
    }

    /// Serialize to CBOR for wire transport.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialise from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

impl DelegationToken {
    /// Produce a [`ProofOfPossession`] for `challenge`, signed by the token's
    /// leaf agent. Only the leaf agent can do this - `leaf_agent` must hold the
    /// key named in the token's leaf block.
    ///
    /// # Errors
    /// `ProofOfPossessionFailed` if `leaf_agent` is not the token's leaf agent.
    pub fn prove_possession(
        &self,
        challenge: &PopChallenge,
        leaf_agent: &AgentIdentity,
    ) -> Result<ProofOfPossession> {
        if leaf_agent.did() != self.leaf_agent_did() {
            return Err(pop_err("only the token's leaf agent can prove possession"));
        }
        let token_binding = self.leaf_binding();
        let digest = challenge.digest(&token_binding);
        let sig = leaf_agent.sign(&digest)?;
        Ok(ProofOfPossession {
            leaf_did: self.leaf_agent_did().to_string(),
            token_binding,
            challenge: challenge.clone(),
            signature: base64ct::Base64::encode_string(&sig),
        })
    }

    /// The complete presentation check a relying party should run: anchor-rooted
    /// token verification ([`DelegationToken::verify_rooted`]) **plus**
    /// proof-of-possession of the leaf key for `expected_challenge`.
    ///
    /// This is the strongest guarantee the crate offers at a call boundary: the
    /// token is authentic, traces to `anchor` via `vc`, permits `action`, and
    /// the presenter currently holds the leaf agent's private key.
    pub fn verify_presentation(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &crate::did::TrustAnchor,
        proof: &ProofOfPossession,
        expected_challenge: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.verify_presentation_at(
            action,
            vc,
            anchor,
            proof,
            expected_challenge,
            max_age_secs,
            Utc::now(),
        )
    }

    /// [`verify_presentation`](Self::verify_presentation), evaluated **as of `now`**.
    ///
    /// One instant governs the credential, every hop, the Datalog time check and the
    /// proof's own freshness window - so a presentation cannot be judged half against
    /// one clock and half against another.
    ///
    /// Added because the token-only as-of path was not enough: golden presentation
    /// vectors verified against the wall clock and began failing four days after they
    /// were generated, since a token's lifetime is capped by the autonomy ladder at one
    /// hour. See `DelegationToken::verify_rooted_at`, which carries the fuller note on
    /// when as-of verification is appropriate - and why it is not the enforcement path.
    ///
    /// # Errors
    /// As [`verify_presentation`](Self::verify_presentation), judged against `now`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_presentation_at(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &crate::did::TrustAnchor,
        proof: &ProofOfPossession,
        expected_challenge: &PopChallenge,
        max_age_secs: i64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.verify_rooted_at(action, vc, anchor, now)?;
        proof.verify_at(self, expected_challenge, max_age_secs, now)?;
        // If the proof was bound to a specific request, it is valid only for that
        // exact action - defeating reuse of a captured presentation for a
        // different tool/parameters/resource. An unbound proof (None) is accepted
        // here; require binding at the verifier (e.g. the MCP enforcer) where the
        // policy lives.
        if let Some(binding) = &proof.challenge.request_binding {
            if binding != &action.request_binding() {
                return Err(pop_err(
                    "proof of possession is bound to a different request",
                ));
            }
        }
        Ok(())
    }
}

/// The unit that crosses the wire when an agent presents its authority - for
/// example, attached to an MCP `tools/call`. Bundles the token, its backing
/// credential (so the verifier can root it without a side fetch), and the
/// proof of possession.
///
/// In a latency-sensitive deployment the credential can be exchanged once at
/// session setup and cached; this envelope is the self-contained form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Presentation {
    /// The delegation token being presented.
    pub token: DelegationToken,
    /// The credential the token's root is derived from.
    pub credential: CapabilityCredential,
    /// Proof the presenter holds the leaf agent's key.
    pub proof: ProofOfPossession,
}

impl Presentation {
    /// Assemble a presentation for `action` (the holder side).
    ///
    /// Mints the proof of possession for `challenge` using `leaf_agent`. The
    /// `action` is not signed into the proof; bind per-action granularity by
    /// issuing a fresh challenge per call.
    pub fn create(
        token: DelegationToken,
        credential: CapabilityCredential,
        challenge: &PopChallenge,
        leaf_agent: &AgentIdentity,
    ) -> Result<Self> {
        let proof = token.prove_possession(challenge, leaf_agent)?;
        Ok(Presentation {
            token,
            credential,
            proof,
        })
    }

    /// Verify the full presentation (the verifier side): anchor-rooted token
    /// verification plus proof of possession.
    pub fn verify(
        &self,
        action: &Action,
        anchor: &crate::did::TrustAnchor,
        expected_challenge: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.token.verify_presentation(
            action,
            &self.credential,
            anchor,
            &self.proof,
            expected_challenge,
            max_age_secs,
        )
    }

    /// [`verify`](Self::verify), evaluated **as of `now`** rather than the wall clock.
    ///
    /// See [`DelegationToken::verify_presentation_at`]. Used by golden conformance
    /// vectors, which must stay verifiable indefinitely even though a token's lifetime
    /// is capped at one hour by the autonomy ladder, and by audit re-verification.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), judged against `now`.
    pub fn verify_at(
        &self,
        action: &Action,
        anchor: &crate::did::TrustAnchor,
        expected_challenge: &PopChallenge,
        max_age_secs: i64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.token.verify_presentation_at(
            action,
            &self.credential,
            anchor,
            &self.proof,
            expected_challenge,
            max_age_secs,
            now,
        )
    }

    /// Whether this presentation's proof is bound to a specific request. A
    /// verifier that requires per-request binding (e.g. to stop a captured proof
    /// being reused for different arguments) should reject presentations for
    /// which this is false.
    pub fn is_action_bound(&self) -> bool {
        self.proof.challenge.request_binding.is_some()
    }

    /// Serialize to CBOR for wire transport.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialise from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::delegation::Scope;
    use crate::did::{DidMethod, TrustAnchor};
    use crate::vc::CapabilityClaims;

    /// Mints a depth-0 token held by its subject agent.
    fn setup() -> (
        TrustAnchor,
        AgentIdentity,
        CapabilityCredential,
        DelegationToken,
    ) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
        let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
        (anchor, agent, vc, token)
    }

    fn action() -> Action {
        Action::new("tool:search", "q=ok")
    }

    #[test]
    fn pop_happy_path() {
        let (anchor, agent, vc, token) = setup();
        let challenge = PopChallenge::new(Some("mcp://orders".into()));
        let proof = token.prove_possession(&challenge, &agent).unwrap();
        assert!(token
            .verify_presentation(&action(), &vc, &anchor, &proof, &challenge, 60)
            .is_ok());
    }

    // `matches` must require EVERY field to agree - nonce, audience, AND issued_at.
    // (Guards against a `&&`->`||` slip that would let a challenge with the right nonce
    // but a swapped audience or timestamp pass, defeating the per-verifier binding.)
    #[test]
    fn matches_requires_every_field_to_agree() {
        let issued = PopChallenge::new(Some("mcp://orders".into()));
        assert!(issued.matches(&issued), "an identical challenge matches");

        let mut wrong_nonce = issued.clone();
        wrong_nonce.nonce[0] ^= 0xff;
        assert!(
            !wrong_nonce.matches(&issued),
            "a different nonce must not match"
        );

        let mut wrong_audience = issued.clone();
        wrong_audience.audience = Some("mcp://evil".into());
        assert!(
            !wrong_audience.matches(&issued),
            "a different audience must not match"
        );

        let mut wrong_time = issued.clone();
        wrong_time.issued_at = issued.issued_at + chrono::Duration::seconds(1);
        assert!(
            !wrong_time.matches(&issued),
            "a different issued_at must not match"
        );
    }

    // to_cbor must actually serialize (a stub returning empty/constant bytes would
    // break the wire form). A round-trip through from_cbor proves the encoding is real.
    #[test]
    fn challenge_cbor_round_trips() {
        let c = PopChallenge::new(Some("mcp://x".into())).with_request_binding("req-1");
        let round = PopChallenge::from_cbor(&c.to_cbor().unwrap()).unwrap();
        assert_eq!(round.nonce, c.nonce);
        assert_eq!(round.audience, c.audience);
        assert_eq!(round.request_binding, c.request_binding);
    }

    #[test]
    fn proof_cbor_round_trips() {
        let (_anchor, agent, _vc, token) = setup();
        let challenge = PopChallenge::new(Some("mcp://x".into()));
        let proof = token.prove_possession(&challenge, &agent).unwrap();
        let round = ProofOfPossession::from_cbor(&proof.to_cbor().unwrap()).unwrap();
        assert_eq!(round.leaf_did, proof.leaf_did);
        assert_eq!(round.token_binding, proof.token_binding);
        assert_eq!(round.signature, proof.signature);
    }

    // The freshness window is inclusive at both edges: a proof whose age is *exactly*
    // max_age (stale bound) or *exactly* -FUTURE_SKEW (future bound) still verifies;
    // one tick beyond either edge is rejected. Uses the `now`-injecting seam so the
    // boundary is deterministic (guards the `>`/`<` comparisons against off-by-one).
    #[test]
    fn freshness_window_boundaries_are_inclusive() {
        let (_anchor, agent, _vc, token) = setup();
        let challenge = PopChallenge::new(Some("mcp://orders".into()));
        let proof = token.prove_possession(&challenge, &agent).unwrap();
        let max_age = 60i64;
        let issued_at = proof.challenge.issued_at;
        let at = |secs: i64| issued_at + chrono::Duration::seconds(secs);

        // Stale bound (age > max_age): exactly at it passes, one past fails.
        assert!(
            proof
                .verify_at(&token, &challenge, max_age, at(max_age))
                .is_ok(),
            "age exactly at max_age must pass"
        );
        assert!(proof
            .verify_at(&token, &challenge, max_age, at(max_age + 1))
            .is_err());

        // Future-skew bound (age < -FUTURE_SKEW): exactly at it passes, one past fails.
        assert!(
            proof
                .verify_at(&token, &challenge, max_age, at(-FUTURE_SKEW_SECS))
                .is_ok(),
            "a challenge at the edge of allowed future skew must pass"
        );
        assert!(proof
            .verify_at(&token, &challenge, max_age, at(-FUTURE_SKEW_SECS - 1))
            .is_err());
    }

    #[test]
    fn only_leaf_agent_can_prove() {
        let (_anchor, _agent, _vc, token) = setup();
        let stranger = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let challenge = PopChallenge::new(None);
        assert!(matches!(
            token.prove_possession(&challenge, &stranger),
            Err(AgentCredsError::ProofOfPossessionFailed { .. })
        ));
    }

    #[test]
    fn stolen_token_without_leaf_key_cannot_be_presented() {
        // Attacker captures the serialized token but not the leaf private key.
        let (anchor, _agent, vc, token) = setup();
        let bytes = token.to_cbor().unwrap();
        let stolen = DelegationToken::from_cbor(&bytes).unwrap();

        // The attacker generates their own key and tries to forge a proof for
        // the stolen token's leaf DID.
        let attacker = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let challenge = PopChallenge::new(None);
        let token_binding = stolen.leaf_binding();
        let digest = challenge.digest(&token_binding);
        let forged = ProofOfPossession {
            leaf_did: stolen.leaf_agent_did().to_string(), // claims the victim's DID
            token_binding,
            challenge: challenge.clone(),
            signature: base64ct::Base64::encode_string(&attacker.sign(&digest).unwrap()),
        };
        assert!(stolen
            .verify_presentation(&action(), &vc, &anchor, &forged, &challenge, 60)
            .is_err());
    }

    #[test]
    fn prefix_stripping_is_defeated() {
        // Build a 2-hop chain: subject -> b -> c. agent_c is the holder.
        let anchor = TrustAnchor::generate().unwrap();
        let subject = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let agent_b = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let agent_c = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims =
            CapabilityClaims::new(vec!["tool:search".into(), "tool:admin".into()], 3, 3600);
        let vc = CapabilityCredential::issue(&anchor, subject.did(), claims, None).unwrap();
        let root_scope = Scope::with_budget_and_depth(
            vec!["tool:search".into(), "tool:admin".into()],
            Some(500),
            2,
        );
        let t0 = DelegationToken::mint(&vc, root_scope, 600, &subject).unwrap();
        let s1 = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 1);
        let t1 = t0.attenuate(s1, 300, &agent_b).unwrap();
        let s2 = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 0);
        let t2 = t1.attenuate(s2, 60, &agent_c).unwrap();

        let challenge = PopChallenge::new(None);

        // agent_c holds t2 (narrow). The broader prefix is t1, whose leaf agent
        // is agent_b - a key agent_c does not hold. agent_c cannot prove
        // possession of t1, so it cannot present the broader scope.
        assert!(t1.prove_possession(&challenge, &agent_c).is_err());

        // And a forged proof (agent_c signing, claiming to be agent_b) is
        // rejected on verification against t1.
        let binding = t1.leaf_binding();
        let digest = challenge.digest(&binding);
        let forged = ProofOfPossession {
            leaf_did: t1.leaf_agent_did().to_string(),
            token_binding: binding,
            challenge: challenge.clone(),
            signature: base64ct::Base64::encode_string(&agent_c.sign(&digest).unwrap()),
        };
        assert!(forged.verify(&t1, &challenge, 60).is_err());

        // Sanity: agent_c can present its own token t2.
        let proof = t2.prove_possession(&challenge, &agent_c).unwrap();
        assert!(proof.verify(&t2, &challenge, 60).is_ok());
    }

    #[test]
    fn stale_challenge_rejected() {
        let (_anchor, agent, _vc, token) = setup();
        let mut challenge = PopChallenge::new(None);
        challenge.issued_at = Utc::now() - chrono::Duration::seconds(120);
        let proof = token.prove_possession(&challenge, &agent).unwrap();
        // 60s window, challenge is 120s old.
        assert!(matches!(
            proof.verify(&token, &challenge, 60),
            Err(AgentCredsError::ProofOfPossessionFailed { .. })
        ));
    }

    #[test]
    fn mismatched_challenge_rejected() {
        let (_anchor, agent, _vc, token) = setup();
        let issued = PopChallenge::new(None);
        let proof = token.prove_possession(&issued, &agent).unwrap();
        // Verifier checks against a different challenge than was signed.
        let other = PopChallenge::new(None);
        assert!(proof.verify(&token, &other, 60).is_err());
    }

    #[test]
    fn proof_not_bound_to_other_token_rejected() {
        let (_anchor, agent_a, _vc_a, token_a) = setup();
        let (_anchor_b, _agent_b, _vc_b, token_b) = setup();
        let challenge = PopChallenge::new(None);
        let proof_a = token_a.prove_possession(&challenge, &agent_a).unwrap();
        // The proof for token_a must not validate against token_b.
        assert!(proof_a.verify(&token_b, &challenge, 60).is_err());
    }

    #[test]
    fn presentation_verify_at_enforces_expiry_and_scope() {
        // MUTATION-DRIVEN. `Presentation::verify_at` could be stubbed to `Ok(())` with
        // no core test noticing - the exact twin of the `DelegationToken::verify_at`
        // survivor found the same day. Both are the as-of-instant variants added for
        // the golden vectors, which exercise them only through the bindings, where
        // cargo-mutants cannot see. The August seam tests covered
        // `ProofOfPossession::verify_at`; this is the Presentation-level wrapper the
        // conformance adapter actually calls.
        let (anchor, agent, vc, token) = setup();
        let expiry = token.expires_at();
        let challenge = PopChallenge::new(Some("mcp://orders".into()));
        let presentation = Presentation::create(token, vc, &challenge, &agent).unwrap();

        // Valid at the token's expiry instant, refused one nanosecond later - the
        // boundary the wall-clock `verify` cannot pin and `verify_at` exists to reach.
        assert!(presentation
            .verify_at(&action(), &anchor, &challenge, i64::MAX, expiry)
            .is_ok());
        assert!(presentation
            .verify_at(
                &action(),
                &anchor,
                &challenge,
                i64::MAX,
                expiry + chrono::Duration::nanoseconds(1)
            )
            .is_err());

        // Scope is enforced through this entry point too.
        let out_of_scope = Action::new("tool:never-granted", "");
        assert!(presentation
            .verify_at(&out_of_scope, &anchor, &challenge, i64::MAX, expiry)
            .is_err());
    }

    #[test]
    fn presentation_cbor_roundtrip_and_verify() {
        let (anchor, agent, vc, token) = setup();
        let challenge = PopChallenge::new(Some("mcp://orders".into()));
        let presentation = Presentation::create(token, vc, &challenge, &agent).unwrap();

        let bytes = presentation.to_cbor().unwrap();
        let restored = Presentation::from_cbor(&bytes).unwrap();
        assert!(restored.verify(&action(), &anchor, &challenge, 60).is_ok());
    }

    #[test]
    fn tampered_presentation_action_outside_scope_rejected() {
        let (anchor, agent, vc, token) = setup();
        let challenge = PopChallenge::new(None);
        let presentation = Presentation::create(token, vc, &challenge, &agent).unwrap();
        // tool:admin is not in scope.
        let denied = Action::new("tool:admin", "");
        assert!(restored_verify_denied(
            &presentation,
            &denied,
            &anchor,
            &challenge
        ));
    }

    fn restored_verify_denied(
        p: &Presentation,
        action: &Action,
        anchor: &TrustAnchor,
        challenge: &PopChallenge,
    ) -> bool {
        p.verify(action, anchor, challenge, 60).is_err()
    }

    // -- Request (argument) binding -------------------------------------------

    /// A proof bound to one action verifies for exactly that action, and is
    /// rejected for a different one (even same tool, different parameters).
    #[test]
    fn request_bound_proof_rejects_a_different_action() {
        let (anchor, agent, vc, token) = setup();
        let issued = PopChallenge::new(Some("mcp://orders".into()));
        let real = Action::new("tool:search", "amount=10");
        let bound = issued.with_request_binding(real.request_binding());
        let presentation = Presentation::create(token, vc, &bound, &agent).unwrap();

        assert!(presentation.is_action_bound());
        // Exact action -> ok.
        assert!(presentation.verify(&real, &anchor, &issued, 60).is_ok());
        // Same tool, tampered parameters -> rejected by the request binding.
        let tampered = Action::new("tool:search", "amount=1000000");
        assert!(matches!(
            presentation.verify(&tampered, &anchor, &issued, 60),
            Err(AgentCredsError::ProofOfPossessionFailed { .. })
        ));
    }

    /// Binding also covers the resource: a proof bound to one resource is not
    /// valid for another.
    #[test]
    fn request_binding_covers_resource() {
        let (anchor, agent, vc, token) = setup();
        let issued = PopChallenge::new(None);
        let real = Action::new("tool:search", "q=ok").on_resource("doc:1");
        let bound = issued.with_request_binding(real.request_binding());
        let presentation = Presentation::create(token, vc, &bound, &agent).unwrap();

        assert!(presentation.verify(&real, &anchor, &issued, 60).is_ok());
        let other_resource = Action::new("tool:search", "q=ok").on_resource("doc:2");
        assert!(presentation
            .verify(&other_resource, &anchor, &issued, 60)
            .is_err());
    }

    /// Back-compat: an unbound proof carries no request binding and verifies for
    /// any in-scope action (the verifier opts in to requiring binding).
    #[test]
    fn unbound_proof_is_not_request_bound_and_verifies() {
        let (anchor, agent, vc, token) = setup();
        let challenge = PopChallenge::new(None);
        let presentation = Presentation::create(token, vc, &challenge, &agent).unwrap();
        assert!(!presentation.is_action_bound());
        assert!(presentation
            .verify(&action(), &anchor, &challenge, 60)
            .is_ok());
    }

    /// The binding is in the signed digest: tampering with `request_binding`
    /// after signing breaks the signature.
    #[test]
    fn tampering_with_request_binding_breaks_the_signature() {
        let (anchor, agent, vc, token) = setup();
        let issued = PopChallenge::new(None);
        let real = Action::new("tool:search", "q=ok");
        let bound = issued.with_request_binding(real.request_binding());
        let mut presentation = Presentation::create(token, vc, &bound, &agent).unwrap();
        // Swap the binding to one matching a different action (forging the claim).
        let evil = Action::new("tool:search", "q=evil");
        presentation.proof.challenge.request_binding = Some(evil.request_binding());
        // Now neither the original nor the forged action verifies - the digest
        // no longer matches the signature.
        assert!(presentation.verify(&real, &anchor, &issued, 60).is_err());
        assert!(presentation.verify(&evil, &anchor, &issued, 60).is_err());
    }

    #[cfg(feature = "proptest")]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            /// R4 - a request-bound presentation is valid ONLY for the exact action it
            /// was built for: it verifies for that action and fails for any action whose
            /// request-binding differs, so a captured presentation cannot be replayed for
            /// different arguments.
            #[test]
            fn presentation_binds_to_its_exact_action(
                params in "[a-z0-9=&_]{0,24}",
                other_params in "[a-z0-9=&_]{0,24}",
            ) {
                let (anchor, agent, vc, token) = setup();
                let bound = Action::new("tool:search", params.clone());
                let challenge = PopChallenge::new(Some("mcp://x".into()))
                    .with_request_binding(bound.request_binding());
                let proof = token.prove_possession(&challenge, &agent).unwrap();
                // The exact action verifies.
                prop_assert!(token
                    .verify_presentation(&bound, &vc, &anchor, &proof, &challenge, 60)
                    .is_ok());
                // Any action with a different request-binding is rejected.
                prop_assume!(other_params != params);
                let other = Action::new("tool:search", other_params);
                prop_assert!(token
                    .verify_presentation(&other, &vc, &anchor, &proof, &challenge, 60)
                    .is_err());
            }

            /// R4 - a proof minted for one challenge never verifies against a different
            /// (freshly issued) challenge: a captured proof cannot be replayed into
            /// another session even at the same audience.
            #[test]
            fn proof_does_not_verify_against_a_fresh_challenge(aud in "[a-z]{3,10}") {
                let (anchor, agent, vc, token) = setup();
                let challenge = PopChallenge::new(Some(format!("mcp://{aud}")));
                let proof = token.prove_possession(&challenge, &agent).unwrap();
                prop_assert!(token
                    .verify_presentation(&action(), &vc, &anchor, &proof, &challenge, 60)
                    .is_ok());
                // Same audience, new nonce -> the old proof must not be accepted.
                let fresh = PopChallenge::new(Some(format!("mcp://{aud}")));
                prop_assert!(token
                    .verify_presentation(&action(), &vc, &anchor, &proof, &fresh, 60)
                    .is_err());
            }
        }
    }
}
