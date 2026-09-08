//! Trust-anchor key rotation - a signed, verifiable key-history chain.
//!
//! A `did:key` anchor's identity *is* its public key, so rotating the key yields
//! a new DID. To let relying parties keep trusting an organization across a
//! rotation **without redistributing trust**, the outgoing key signs a
//! [`RotationStatement`] endorsing the incoming key. A [`KeyHistory`] is the
//! chain of those statements: a relying party that pins the original anchor DID
//! follows the chain - verifying each link offline - to the current key, and may
//! accept credentials from any key the organization legitimately held.
//!
//! Rotation does **not** revoke credentials issued by a prior key; those remain
//! valid until their own expiry (use [revocation](crate::revocation) to cut them
//! short). Only `did:key` anchors are supported (the verification key is in the
//! identifier). The outgoing key signs the endorsement, so only the holder of the
//! current key can authorize a successor, and a chain that does not start at the
//! pinned root is rejected.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::rotation::{KeyHistory, RotationStatement};
//!
//! // The org pins anchor A0, then rotates A0 -> A1 (e.g. moving the key into a KMS).
//! let a0 = TrustAnchor::generate()?;
//! let a1 = TrustAnchor::generate()?;
//! let stmt = RotationStatement::issue(&a0, &a1)?; // A0's key signs A0 -> A1
//!
//! let mut history = KeyHistory::genesis(&a0);
//! history.push(stmt)?;
//! history.seal(&a1, 1, None)?;  // the CURRENT key seals the chain + repudiations
//!
//! // A relying party trusting A0 follows the chain to the current key.
//! let current = history.current_anchor(a0.did())?; // verify-only anchor for A1
//! assert_eq!(current.did(), a1.did());
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

const STATEMENT_DOMAIN: &[u8] = b"agentcreds-key-rotation-v1";
const SEAL_DOMAIN: &[u8] = b"agentcreds-key-history-seal-v1";

fn rot_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::InvalidDidSignature {
        reason: reason.into(),
    }
}

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

// -- RotationStatement ---------------------------------------------------------

/// A signed endorsement by an outgoing anchor key of its successor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatement {
    /// The outgoing anchor DID (the signer).
    pub previous_did: String,
    /// The incoming anchor DID it endorses.
    pub next_did: String,
    /// When the rotation takes effect (advisory metadata).
    pub effective_at: DateTime<Utc>,
    /// The outgoing key's signature over this statement.
    pub signature: String,
}

impl RotationStatement {
    /// Issue a statement: `old` signs an endorsement of `next` (effective now).
    ///
    /// # Errors
    /// If the outgoing anchor cannot sign (e.g. a verify-only anchor).
    pub fn issue(old: &TrustAnchor, next: &TrustAnchor) -> Result<Self> {
        let mut stmt = Self {
            previous_did: old.did().to_string(),
            next_did: next.did().to_string(),
            effective_at: Utc::now(),
            signature: String::new(),
        };
        let sig = old.sign(&stmt.payload())?;
        stmt.signature = base64ct::Base64::encode_string(&sig);
        Ok(stmt)
    }

    fn payload(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(STATEMENT_DOMAIN);
        write_field(&mut h, self.previous_did.as_bytes());
        write_field(&mut h, self.next_did.as_bytes());
        h.update(self.effective_at.timestamp().to_le_bytes());
        h.finalize().to_vec()
    }

    /// Verify the statement is authentically signed by the outgoing key (whose
    /// public key is embedded in `previous_did`).
    ///
    /// # Errors
    /// `InvalidDidSignature` on a bad signature or an unparseable `previous_did`.
    pub fn verify(&self) -> Result<()> {
        let previous = TrustAnchor::from_did_key(&self.previous_did)?;
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| rot_err(format!("signature base64: {e}")))?;
        previous
            .verify_signature(&self.payload(), &sig)
            .map_err(|_| rot_err("rotation statement signature does not verify"))
    }
}

// -- KeyHistory ----------------------------------------------------------------

/// The chain of [`RotationStatement`]s from an anchor's original key to its
/// current one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHistory {
    /// The original (genesis) anchor DID.
    pub root_did: String,
    /// The rotations, oldest first; each links the prior key to the next.
    pub rotations: Vec<RotationStatement>,
    /// DIDs the organization has withdrawn from issuance. A credential from a
    /// repudiated key is refused by [`authorize_issuer`](Self::authorize_issuer)
    /// even though the key legitimately held the role at some point.
    #[serde(default)]
    pub repudiated: Vec<String>,
    /// Optional sealed expiry. Past it a fail-safe consumer refuses to resolve
    /// through this history rather than assume its copy is current.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    /// Monotonic seal version, so a relying party can tell two seals apart.
    #[serde(default)]
    pub version: u64,
    /// The **current** key's signature over the canonical digest. Empty until sealed.
    #[serde(default)]
    pub signature: String,
}

impl KeyHistory {
    /// A new history rooted at `root_did`, with no rotations yet.
    #[must_use]
    pub fn new(root_did: impl Into<String>) -> Self {
        Self {
            root_did: root_did.into(),
            rotations: Vec::new(),
            repudiated: Vec::new(),
            not_after: None,
            version: 0,
            signature: String::new(),
        }
    }

    /// A new history rooted at `anchor`'s DID.
    #[must_use]
    pub fn genesis(anchor: &TrustAnchor) -> Self {
        Self::new(anchor.did())
    }

    /// The current (latest) anchor DID in the chain.
    #[must_use]
    pub fn current_did(&self) -> &str {
        self.rotations
            .last()
            .map_or(self.root_did.as_str(), |r| r.next_did.as_str())
    }

    /// Append a rotation. The statement must link from the current head and be
    /// authentically signed by it.
    ///
    /// # Errors
    /// If the statement does not chain from the current key or fails to verify.
    pub fn push(&mut self, statement: RotationStatement) -> Result<()> {
        if statement.previous_did != self.current_did() {
            return Err(rot_err(format!(
                "rotation does not chain: expected previous_did {}, got {}",
                self.current_did(),
                statement.previous_did
            )));
        }
        statement.verify()?;
        self.rotations.push(statement);
        Ok(())
    }

    /// The canonical digest a seal signs: the chain, the repudiations, the expiry
    /// and the version. Repudiations are sorted so the digest does not depend on the
    /// order they were added.
    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(SEAL_DOMAIN);
        h.update(self.version.to_le_bytes());
        write_field(&mut h, self.root_did.as_bytes());
        h.update((self.rotations.len() as u64).to_le_bytes());
        for r in &self.rotations {
            write_field(&mut h, r.previous_did.as_bytes());
            write_field(&mut h, r.next_did.as_bytes());
            h.update(r.effective_at.timestamp().to_le_bytes());
            write_field(&mut h, r.signature.as_bytes());
        }
        let mut repudiated = self.repudiated.clone();
        repudiated.sort();
        h.update((repudiated.len() as u64).to_le_bytes());
        for d in &repudiated {
            write_field(&mut h, d.as_bytes());
        }
        // Signed, so an expiry cannot be extended or stripped after sealing.
        match self.not_after {
            Some(t) => {
                h.update([1u8]);
                h.update(t.timestamp().to_le_bytes());
            }
            None => h.update([0u8]),
        }
        h.finalize().to_vec()
    }

    /// Withdraw `did` from issuance. A credential from it is then refused by
    /// [`authorize_issuer`](Self::authorize_issuer) even though the key legitimately
    /// held the role. Re-[`seal`](Self::seal) afterwards, or the change is unsigned
    /// and will not be honoured.
    ///
    /// Repudiation is **wholesale**, not time-bounded. A cutoff of the form "distrust
    /// anything issued after T" looks more precise but is forgeable: whoever holds the
    /// key also chooses the issuance timestamp, so they can backdate around it.
    ///
    /// # Errors
    /// If `did` is not in the chain, or is the current key - repudiating the key that
    /// signs the seal would leave a history that cannot authorize anything, including
    /// itself.
    pub fn repudiate(&mut self, did: &str) -> Result<()> {
        if !self.dids().iter().any(|d| d == did) {
            return Err(rot_err("cannot repudiate a key outside this history"));
        }
        if did == self.current_did() {
            return Err(rot_err(
                "cannot repudiate the current key - rotate to a successor first",
            ));
        }
        if !self.repudiated.iter().any(|d| d == did) {
            self.repudiated.push(did.to_string());
        }
        self.signature.clear(); // the seal no longer covers this state
        Ok(())
    }

    /// Seal the history: `current` signs the chain, repudiations and expiry.
    ///
    /// The **current** key signs, not the root, because a repudiated predecessor must
    /// not be able to un-repudiate itself. The signer's authority derives from the
    /// chain a relying party independently verifies from its pinned root.
    ///
    /// # Errors
    /// If `current` is not the chain's current key, or cannot sign.
    pub fn seal(
        &mut self,
        current: &TrustAnchor,
        version: u64,
        not_after: Option<DateTime<Utc>>,
    ) -> Result<()> {
        if current.did() != self.current_did() {
            return Err(rot_err("a key history must be sealed by its current key"));
        }
        self.version = version;
        self.not_after = not_after;
        self.signature.clear();
        let sig = current.sign(&self.digest())?;
        self.signature = base64ct::Base64::encode_string(&sig);
        Ok(())
    }

    /// Whether the history is inside its sealed validity window. An unbounded seal
    /// (`not_after == None`) is always current.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.not_after.map_or(true, |t| Utc::now() <= t)
    }

    /// Verify the chain **and** that the seal is authentic under the current key.
    ///
    /// [`verify`](Self::verify) checks only the chain, so it says nothing about the
    /// repudiations or the expiry - both of which an attacker would strip. Any path
    /// that relies on those must come through here.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), or if the history is unsealed or the seal does not
    /// verify under the current key.
    pub fn verify_sealed(&self, trusted_root_did: &str) -> Result<String> {
        let current = self.verify(trusted_root_did)?;
        if self.signature.is_empty() {
            return Err(rot_err(
                "key history is not sealed - repudiations and expiry are unauthenticated",
            ));
        }
        let anchor = TrustAnchor::from_did_key(&current)?;
        let sig = base64ct::Base64::decode_vec(&self.signature)
            .map_err(|e| rot_err(format!("seal signature base64: {e}")))?;
        anchor
            .verify_signature(&self.digest(), &sig)
            .map_err(|_| rot_err("key history seal does not verify under the current key"))?;
        Ok(current)
    }

    /// Verify authenticity **and** freshness - the fail-safe check a relying party
    /// should use. Ship an issuer-side re-seal alongside any deployed expiry, or the
    /// bound becomes a self-inflicted outage the moment it elapses.
    ///
    /// # Errors
    /// As [`verify_sealed`](Self::verify_sealed), or if the seal has expired.
    pub fn verify_current(&self, trusted_root_did: &str) -> Result<String> {
        let current = self.verify_sealed(trusted_root_did)?;
        if !self.is_current() {
            return Err(rot_err("key history seal has expired"));
        }
        Ok(current)
    }

    /// Every DID the organization still trusts for issuance: the chain minus the
    /// repudiations.
    #[must_use]
    pub fn active_dids(&self) -> Vec<String> {
        self.dids()
            .into_iter()
            .filter(|d| !self.repudiated.iter().any(|r| r == d))
            .collect()
    }

    /// Verify the whole chain starts at `trusted_root_did` and every link is
    /// authentic and well-linked, returning the **current** anchor DID.
    ///
    /// # Errors
    /// `InvalidDidSignature` if the root does not match, a link is broken, or a
    /// statement fails to verify.
    pub fn verify(&self, trusted_root_did: &str) -> Result<String> {
        if self.root_did != trusted_root_did {
            return Err(rot_err(
                "key history root does not match the trusted anchor",
            ));
        }
        let mut current = self.root_did.clone();
        for statement in &self.rotations {
            if statement.previous_did != current {
                return Err(rot_err("broken rotation chain"));
            }
            statement.verify()?;
            statement.next_did.clone_into(&mut current);
        }
        Ok(current)
    }

    /// Verify the chain and return a **verify-only** [`TrustAnchor`] for the
    /// current key - ready to verify credentials issued after the rotation.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), or if the current DID is not a `did:key`.
    pub fn current_anchor(&self, trusted_root_did: &str) -> Result<TrustAnchor> {
        TrustAnchor::from_did_key(&self.verify(trusted_root_did)?)
    }

    /// Every anchor DID the organization legitimately held (root + each successor).
    #[must_use]
    pub fn dids(&self) -> Vec<String> {
        let mut v = Vec::with_capacity(self.rotations.len() + 1);
        v.push(self.root_did.clone());
        for r in &self.rotations {
            v.push(r.next_did.clone());
        }
        v
    }

    /// The relying party's check on a credential: verify the sealed history is
    /// authentic and current, then confirm `issuer_did` is a key the organization
    /// still trusts for issuance.
    ///
    /// Accepts the current key *or* an earlier one - planned rotation does not
    /// invalidate what a superseded key already signed. Refuses a repudiated key,
    /// which is how a withdrawn key is distinguished from a merely superseded one.
    ///
    /// Requires a **sealed** history: the repudiations and the expiry are only
    /// meaningful if signed, and an unsealed history would let an attacker strip
    /// them. Use [`verify`](Self::verify) directly if you genuinely want the
    /// chain-only check and understand it authenticates neither.
    ///
    /// # Errors
    /// As [`verify_current`](Self::verify_current); or if `issuer_did` is absent from
    /// the history or has been repudiated.
    pub fn authorize_issuer(
        &self,
        trusted_root_did: &str,
        issuer_did: &str,
    ) -> Result<TrustAnchor> {
        self.verify_current(trusted_root_did)?;
        if self.repudiated.iter().any(|d| d == issuer_did) {
            return Err(rot_err("issuer has been repudiated"));
        }
        if !self.dids().iter().any(|d| d == issuer_did) {
            return Err(rot_err("issuer is not in the verified key history"));
        }
        TrustAnchor::from_did_key(issuer_did)
    }

    /// Serialize the history to JSON (the portable artifact relying parties follow).
    ///
    /// # Errors
    /// On serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(AgentCredsError::from)
    }

    /// Parse a history from JSON.
    ///
    /// # Errors
    /// On deserialisation failure.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(AgentCredsError::from)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod, KeyAlgorithm};
    use crate::vc::{CapabilityClaims, CapabilityCredential};

    #[test]
    fn single_rotation_verifies_and_advances_did() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let stmt = RotationStatement::issue(&a0, &a1).unwrap();
        assert!(stmt.verify().is_ok());

        let mut history = KeyHistory::genesis(&a0);
        history.push(stmt).unwrap();
        assert_eq!(history.current_did(), a1.did());
        assert_eq!(history.verify(a0.did()).unwrap(), a1.did());
        assert_eq!(history.current_anchor(a0.did()).unwrap().did(), a1.did());
    }

    #[test]
    fn multi_hop_chain_reaches_current_key() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        // Rotate across algorithms too (Ed25519 -> P-256).
        let a2 = TrustAnchor::create(DidMethod::Key, Some(KeyAlgorithm::P256), None).unwrap();

        let mut history = KeyHistory::genesis(&a0);
        history
            .push(RotationStatement::issue(&a0, &a1).unwrap())
            .unwrap();
        history
            .push(RotationStatement::issue(&a1, &a2).unwrap())
            .unwrap();

        assert_eq!(history.verify(a0.did()).unwrap(), a2.did());
        assert_eq!(history.dids().len(), 3);
    }

    #[test]
    fn push_rejects_a_non_chaining_statement() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let a2 = TrustAnchor::generate().unwrap();
        let mut history = KeyHistory::genesis(&a0);
        // A statement from a1 -> a2, but the head is still a0.
        let skipping = RotationStatement::issue(&a1, &a2).unwrap();
        assert!(history.push(skipping).is_err());
    }

    #[test]
    fn verify_rejects_a_chain_rooted_elsewhere() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let mut history = KeyHistory::genesis(&a0);
        history
            .push(RotationStatement::issue(&a0, &a1).unwrap())
            .unwrap();
        // A relying party that pinned a *different* root rejects this history.
        let stranger = TrustAnchor::generate().unwrap();
        assert!(history.verify(stranger.did()).is_err());
    }

    #[test]
    fn tampered_statement_signature_is_rejected() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let victim = TrustAnchor::generate().unwrap();
        let mut stmt = RotationStatement::issue(&a0, &a1).unwrap();
        // Re-point the endorsement at a victim DID after signing.
        stmt.next_did = victim.did().to_string();
        assert!(stmt.verify().is_err());
    }

    #[test]
    fn credential_from_rotated_key_verifies_through_history() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let mut history = KeyHistory::genesis(&a0);
        history
            .push(RotationStatement::issue(&a0, &a1).unwrap())
            .unwrap();
        // `authorize_issuer` requires a sealed history - the repudiations and expiry it
        // consults are unauthenticated otherwise.
        history.seal(&a1, 1, None).unwrap();

        // The org issues a credential with the NEW key.
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
        let vc = CapabilityCredential::issue(&a1, agent.did(), claims, None).unwrap();

        // A relying party trusting only a0 follows the chain and accepts it.
        let issuer = history.authorize_issuer(a0.did(), &vc.issuer).unwrap();
        assert!(vc.verify(&issuer, true).is_ok());

        // A credential from a key not in the history is not authorized.
        let stranger = TrustAnchor::generate().unwrap();
        assert!(history.authorize_issuer(a0.did(), stranger.did()).is_err());
    }

    #[test]
    fn verify_only_anchor_cannot_issue() {
        let a0 = TrustAnchor::generate().unwrap();
        let verify_only = TrustAnchor::from_did_key(a0.did()).unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        assert!(CapabilityCredential::issue(&verify_only, agent.did(), claims, None).is_err());
    }

    #[test]
    fn json_round_trip_preserves_verification() {
        let a0 = TrustAnchor::generate().unwrap();
        let a1 = TrustAnchor::generate().unwrap();
        let mut history = KeyHistory::genesis(&a0);
        history
            .push(RotationStatement::issue(&a0, &a1).unwrap())
            .unwrap();
        let restored = KeyHistory::from_json(&history.to_json().unwrap()).unwrap();
        assert_eq!(restored.verify(a0.did()).unwrap(), a1.did());
    }

    #[cfg(feature = "proptest")]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            /// Anchor rotation - a signed KeyHistory of any length always resolves from
            /// the trusted root to the current key, survives a JSON round-trip, and is
            /// rejected by a relying party that pinned a different root. A long-lived
            /// anchor can rotate its key without invalidating credentials, verifiable
            /// offline from the conveyed history alone.
            #[test]
            fn any_rotation_chain_resolves_to_current(n in 0usize..=6) {
                let mut anchors = vec![TrustAnchor::generate().unwrap()];
                let mut history = KeyHistory::genesis(&anchors[0]);
                for _ in 0..n {
                    let next = TrustAnchor::generate().unwrap();
                    let stmt = RotationStatement::issue(anchors.last().unwrap(), &next).unwrap();
                    history.push(stmt).unwrap();
                    anchors.push(next);
                }
                let root_did = anchors[0].did().to_string();
                let current = anchors.last().unwrap().did().to_string();

                prop_assert_eq!(history.current_did(), current.as_str());
                prop_assert_eq!(history.verify(&root_did).unwrap(), current.clone());
                prop_assert_eq!(history.dids().len(), n + 1);
                // Persisted and reloaded, it still verifies to the same current key.
                let restored = KeyHistory::from_json(&history.to_json().unwrap()).unwrap();
                prop_assert_eq!(restored.verify(&root_did).unwrap(), current);
                // A relying party that pinned a different root rejects the history.
                let stranger = TrustAnchor::generate().unwrap();
                prop_assert!(history.verify(stranger.did()).is_err());
            }
        }
    }

    // -- seal, repudiation, freshness ------------------------------------------

    fn rotated() -> (TrustAnchor, TrustAnchor, KeyHistory) {
        let root = TrustAnchor::generate().unwrap();
        let next = TrustAnchor::generate().unwrap();
        let mut h = KeyHistory::genesis(&root);
        h.push(RotationStatement::issue(&root, &next).unwrap())
            .unwrap();
        (root, next, h)
    }

    #[test]
    fn unsealed_history_cannot_authorize() {
        // The whole point of sealing: repudiations and expiry are unauthenticated
        // without it, so an attacker could simply strip them.
        let (root, next, h) = rotated();
        assert!(h.verify(root.did()).is_ok(), "the chain itself is fine");
        assert!(h.authorize_issuer(root.did(), next.did()).is_err());
    }

    #[test]
    fn sealed_history_authorizes_every_held_key() {
        let (root, next, mut h) = rotated();
        h.seal(&next, 1, None).unwrap();
        assert!(h.authorize_issuer(root.did(), next.did()).is_ok());
        assert!(
            h.authorize_issuer(root.did(), root.did()).is_ok(),
            "a superseded key still signed things legitimately"
        );
    }

    #[test]
    fn only_the_current_key_may_seal() {
        // A repudiated predecessor must not be able to re-seal itself back in.
        let (root, next, mut h) = rotated();
        assert!(
            h.seal(&root, 1, None).is_err(),
            "the root is no longer current"
        );
        assert!(h.seal(&next, 1, None).is_ok());
    }

    #[test]
    fn repudiated_key_is_refused_but_the_rest_still_works() {
        let (root, next, mut h) = rotated();
        h.repudiate(root.did()).unwrap();
        h.seal(&next, 2, None).unwrap();

        assert!(
            h.authorize_issuer(root.did(), root.did()).is_err(),
            "a repudiated key must not authorize"
        );
        // The control: without this, the assertion above would also hold for a history
        // that authorizes nothing at all.
        assert!(
            h.authorize_issuer(root.did(), next.did()).is_ok(),
            "repudiating one key must not disable the others"
        );
        assert_eq!(h.active_dids(), vec![next.did().to_string()]);
    }

    #[test]
    fn repudiation_must_be_sealed_to_take_effect() {
        let (root, next, mut h) = rotated();
        h.seal(&next, 1, None).unwrap();
        h.repudiate(root.did()).unwrap(); // clears the seal
        assert!(
            h.authorize_issuer(root.did(), next.did()).is_err(),
            "an unsealed repudiation leaves the history unusable until re-sealed"
        );
        h.seal(&next, 2, None).unwrap();
        assert!(h.authorize_issuer(root.did(), next.did()).is_ok());
    }

    #[test]
    fn repudiating_two_keys_records_both_and_repeats_do_not_duplicate() {
        // MUTATION-DRIVEN. `repudiate` guards its push with
        // `!self.repudiated.iter().any(|d| d == did)`. Flipping that `==` to `!=`
        // survived the suite, and it is not a cosmetic difference:
        //
        //   list empty        -> unchanged (still pushes)
        //   list == [did]     -> pushes a DUPLICATE
        //   list == [other]   -> does NOT push, so the second key is silently NOT
        //                        repudiated
        //
        // The third is the dangerous one: repudiate A then B, and B stays trusted.
        // Every existing test repudiated exactly one key from an empty list, which is
        // precisely the case where the mutation is invisible.
        let root = TrustAnchor::generate().unwrap();
        let second = TrustAnchor::generate().unwrap();
        let third = TrustAnchor::generate().unwrap();

        let mut h = KeyHistory::genesis(&root);
        h.push(RotationStatement::issue(&root, &second).unwrap())
            .unwrap();
        h.push(RotationStatement::issue(&second, &third).unwrap())
            .unwrap();

        // Two DISTINCT predecessors, repudiated in turn. Both must be recorded.
        h.repudiate(root.did()).unwrap();
        h.repudiate(second.did()).unwrap();
        assert!(
            h.repudiated.iter().any(|d| d == root.did()),
            "the first repudiation must survive the second"
        );
        assert!(
            h.repudiated.iter().any(|d| d == second.did()),
            "the second key must actually be repudiated"
        );
        assert_eq!(h.repudiated.len(), 2);

        // Repeating a repudiation is idempotent, not additive.
        h.repudiate(root.did()).unwrap();
        assert_eq!(h.repudiated.len(), 2, "re-repudiation must not duplicate");
    }

    #[test]
    fn cannot_repudiate_the_current_key_or_a_stranger() {
        let (root, next, mut h) = rotated();
        assert!(h.repudiate(next.did()).is_err(), "would break its own seal");
        let stranger = TrustAnchor::generate().unwrap();
        assert!(h.repudiate(stranger.did()).is_err());
        assert!(h.repudiate(root.did()).is_ok());
    }

    #[test]
    fn expired_seal_is_authentic_but_refused() {
        // Authenticity and freshness are separate checks; conflating them is how a
        // stale history stays trusted.
        let (root, next, mut h) = rotated();
        h.seal(&next, 1, Some(Utc::now() - chrono::Duration::hours(1)))
            .unwrap();
        assert!(!h.is_current());
        assert!(
            h.verify_sealed(root.did()).is_ok(),
            "still genuinely signed"
        );
        assert!(h.verify_current(root.did()).is_err());
        assert!(h.authorize_issuer(root.did(), next.did()).is_err());
    }

    #[test]
    fn expiry_and_repudiations_cannot_be_edited_after_sealing() {
        let (root, next, mut h) = rotated();
        h.repudiate(root.did()).unwrap();
        h.seal(&next, 1, Some(Utc::now() - chrono::Duration::hours(1)))
            .unwrap();

        // Extend the expiry...
        let mut revived = h.clone();
        revived.not_after = Some(Utc::now() + chrono::Duration::days(365));
        assert!(revived.verify_sealed(root.did()).is_err());

        // ...drop it entirely...
        let mut dropped = h.clone();
        dropped.not_after = None;
        assert!(dropped.verify_sealed(root.did()).is_err());

        // ...or un-repudiate a withdrawn key.
        let mut unrepudiated = h.clone();
        unrepudiated.repudiated.clear();
        assert!(unrepudiated.verify_sealed(root.did()).is_err());
    }

    #[test]
    fn seal_does_not_survive_a_further_rotation() {
        // A rotation changes the current key, so the old seal no longer verifies and
        // the history must be re-sealed by the new key. Fails closed meanwhile.
        let (root, next, mut h) = rotated();
        h.seal(&next, 1, None).unwrap();
        let third = TrustAnchor::generate().unwrap();
        h.push(RotationStatement::issue(&next, &third).unwrap())
            .unwrap();
        assert!(
            h.verify_sealed(root.did()).is_err(),
            "stale seal must not verify"
        );
        h.seal(&third, 2, None).unwrap();
        assert!(h.authorize_issuer(root.did(), third.did()).is_ok());
    }

    #[test]
    fn root_compromise_is_not_recoverable_by_repudiation() {
        // Recorded as a LIMIT, not a gap. Whoever holds a key can endorse a successor,
        // so an attacker with the root can build a rival chain from the same root that
        // is internally valid. A relying party pinned to that root cannot adjudicate
        // between the two from the chains alone. Repudiation serves withdrawal of a key
        // the organization still controls; it is not a remedy for root compromise.
        let root = TrustAnchor::generate().unwrap();
        let legit = TrustAnchor::generate().unwrap();
        let rival = TrustAnchor::generate().unwrap();

        let mut a = KeyHistory::genesis(&root);
        a.push(RotationStatement::issue(&root, &legit).unwrap())
            .unwrap();
        a.seal(&legit, 1, None).unwrap();

        let mut b = KeyHistory::genesis(&root);
        b.push(RotationStatement::issue(&root, &rival).unwrap())
            .unwrap();
        b.seal(&rival, 1, None).unwrap();

        // Both verify against the same pinned root. That is the limit.
        assert!(a.authorize_issuer(root.did(), legit.did()).is_ok());
        assert!(b.authorize_issuer(root.did(), rival.did()).is_ok());
    }
}
