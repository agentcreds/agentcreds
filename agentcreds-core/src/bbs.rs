//! BBS+ selectively-disclosable, **unlinkable** capability credentials.
//!
//! Like [`crate::sd_jwt`], an agent can present a subset of its claims and keep
//! the rest hidden. BBS+ adds one property SD-JWT cannot: **unlinkability**.
//! Each presentation is a freshly-randomized zero-knowledge proof, so a set of
//! colluding verifiers cannot tell that two presentations came from the same
//! credential. The trade-off is heavier, pairing-based crypto (BLS12-381) and a
//! separate issuer key - so this whole module is gated behind the `bbs` feature.
//!
//! - The issuer holds a BBS+ key ([`BbsIssuer`], distinct from a DID anchor) and
//!   signs the ordered message vector `[iss, sub, exp, vct, claim1 ... claimn]`.
//! - The holder calls [`BbsCredential::derive_proof`] to reveal a subset; hidden
//!   claims are proven in zero knowledge and are unrecoverable.
//! - The verifier checks the proof against the issuer's public key
//!   ([`BbsPresentation::verify`]) and learns only the revealed claims.
//!
//! ```rust
//! # #[cfg(feature = "bbs")] {
//! use std::collections::BTreeMap;
//! use serde_json::json;
//! use agentcreds_core::bbs::{BbsIssuer, BbsCredential, BbsPresentation};
//!
//! let issuer = BbsIssuer::generate();
//! let pk = issuer.public_key();
//!
//! let mut claims = BTreeMap::new();
//! claims.insert("tools".to_string(), json!(["tool:search", "tool:email"]));
//! claims.insert("budget_usd".to_string(), json!(500));
//! let cred = BbsCredential::issue(&issuer, "did:key:zAgent", claims, 3600).unwrap();
//!
//! // Reveal only `tools`; budget stays hidden and unlinkable across uses.
//! let pres = cred.derive_proof(&["tools"], b"verifier-nonce").unwrap();
//! let disclosed = pres.verify(&pk, b"verifier-nonce").unwrap();
//! assert!(disclosed.disclosed.contains_key("tools"));
//! assert!(!disclosed.disclosed.contains_key("budget_usd"));
//! # }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bbs_plus::prelude::{
    KeypairG2, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG2, SignatureG1,
    SignatureParamsG1,
};
use blake2::Blake2b;
use chrono::{DateTime, TimeZone, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

/// The `vct` (verifiable credential type) for AgentCreds BBS+ capabilities.
pub const VCT: &str = "AgentCredsCapability";

/// Number of always-revealed registered messages: iss, sub, exp, vct.
const REGISTERED: usize = 4;

/// The `iss` value for an issuer not bound to a DID anchor.
const UNBOUND_ISSUER: &str = "bbs-issuer";

/// Domain-separation tag for the DID-anchor binding. The anchor's primary key
/// signs this tag, the issuer DID, and the BBS+ public key, proving the BBS+ key
/// is controlled by the anchor - the same attestation pattern as the delegation
/// subkey ([`crate::did`]), since a BBS+ (BLS12-381) key is distinct from the
/// anchor's Ed25519/P-256 key.
const BBS_BINDING_DOMAIN: &[u8] = b"agentcreds-bbs-issuer-binding-v1";

fn binding_payload(did: &str, bbs_public_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BBS_BINDING_DOMAIN.len() + 8 + did.len() + bbs_public_key.len());
    m.extend_from_slice(BBS_BINDING_DOMAIN);
    m.extend_from_slice(&(did.len() as u64).to_le_bytes());
    m.extend_from_slice(did.as_bytes());
    m.extend_from_slice(bbs_public_key);
    m
}

fn unbound_did() -> String {
    UNBOUND_ISSUER.to_string()
}

/// Domain-separation label for the public signature parameters. The generators
/// are a public, nothing-up-my-sleeve common reference deterministically hashed
/// from this label; `g1`/`g2`/`h_0` are count-independent (so the issuer public
/// key is stable across credentials with different claim counts).
const PARAM_LABEL: &[u8] = b"agentcreds-bbs-params-v1";

/// Domain tag mixed into every Fiat-Shamir challenge.
const CHALLENGE_DOMAIN: &[u8] = b"agentcreds-bbs-challenge-v1";

fn bbs_err(e: impl core::fmt::Debug) -> AgentCredsError {
    AgentCredsError::CryptoError {
        reason: format!("bbs+: {e:?}"),
    }
}

/// Deterministic, public signature parameters for a given message count. The
/// issuer and every verifier derive identical parameters by hashing
/// [`PARAM_LABEL`] (count-independent `g1`/`g2`/`h_0`).
fn params_for(count: usize) -> SignatureParamsG1<Bls12_381> {
    SignatureParamsG1::<Bls12_381>::new::<Blake2b>(PARAM_LABEL, count)
}

/// Encode one `(name, value)` message as a field element.
fn encode_message(name: &str, value: &Value) -> Result<Fr> {
    let s = format!("{name}={}", serde_json::to_string(value)?);
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    Ok(Fr::from_le_bytes_mod_order(&h.finalize()))
}

/// Fiat-Shamir challenge from the proof transcript + nonce, length-prefixed and
/// domain-separated so prover and verifier derive the same scalar.
fn challenge_from(transcript: &[u8], nonce: &[u8]) -> Fr {
    let mut h = Sha256::new();
    for part in [CHALLENGE_DOMAIN, transcript, nonce] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    Fr::from_le_bytes_mod_order(&h.finalize())
}

fn ark_to_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    value.serialize(&mut buf).map_err(bbs_err)?;
    Ok(buf)
}

fn ark_from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    T::deserialize(bytes).map_err(bbs_err)
}

// -- Issuer ------------------------------------------------------------------

/// A BBS+ issuer: a BLS12-381 key pair, optionally **bound to a DID anchor**.
///
/// A BBS+ key is a different curve from the anchor's Ed25519/P-256 key, so the
/// binding is an anchor-signed attestation over the BBS+ public key (see
/// [`for_anchor`](Self::for_anchor)).
pub struct BbsIssuer {
    keypair: KeypairG2<Bls12_381>,
    did: String,
    attestation: Vec<u8>,
}

impl BbsIssuer {
    /// Generate an **unbound** BBS+ issuer (identified only by its public key).
    /// Prefer [`for_anchor`](Self::for_anchor) to tie the issuer to a DID.
    pub fn generate() -> Self {
        // Parameters only fix the generator count for key generation; any
        // non-zero count works since the public key is independent of it.
        let params = params_for(1);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut OsRng, &params);
        BbsIssuer {
            keypair,
            did: UNBOUND_ISSUER.to_string(),
            attestation: Vec::new(),
        }
    }

    /// Generate a BBS+ issuer **bound to a DID anchor**: `anchor` signs an
    /// attestation over the BBS+ public key, so a verifier can confirm this BBS+
    /// key is controlled by `anchor`'s DID. Issued credentials carry that DID as
    /// their `iss`.
    ///
    /// # Errors
    /// If the anchor fails to sign the binding attestation, or its public key
    /// cannot be encoded.
    pub fn for_anchor(anchor: &TrustAnchor) -> Result<Self> {
        let params = params_for(1);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng(&mut OsRng, &params);
        let pk_bytes = ark_to_bytes(&keypair.public_key)?;
        let attestation = anchor.sign(&binding_payload(anchor.did(), &pk_bytes))?;
        Ok(BbsIssuer {
            keypair,
            did: anchor.did().to_string(),
            attestation,
        })
    }

    /// The issuer's DID (the bound anchor's DID, or `"bbs-issuer"` if unbound).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// This issuer's public key, to hand to verifiers (carries the DID binding,
    /// if bound).
    pub fn public_key(&self) -> BbsPublicKey {
        // Serialization is infallible for a valid in-memory key.
        let bytes = ark_to_bytes(&self.keypair.public_key).unwrap_or_default();
        BbsPublicKey {
            bytes,
            did: self.did.clone(),
            attestation: self.attestation.clone(),
        }
    }
}

/// A serializable BBS+ issuer public key, optionally carrying its DID-anchor
/// binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsPublicKey {
    #[serde(with = "hex::serde")]
    bytes: Vec<u8>,
    /// The DID this key is bound to (`"bbs-issuer"` if unbound).
    #[serde(default = "unbound_did")]
    did: String,
    /// The anchor's signature over [`binding_payload`] (empty if unbound).
    #[serde(default, with = "hex::serde")]
    attestation: Vec<u8>,
}

impl BbsPublicKey {
    fn inner(&self) -> Result<PublicKeyG2<Bls12_381>> {
        ark_from_bytes(&self.bytes)
    }

    /// Raw canonical-serialized public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reconstruct an **unbound** key from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        BbsPublicKey {
            bytes,
            did: UNBOUND_ISSUER.to_string(),
            attestation: Vec::new(),
        }
    }

    /// The DID this BBS+ key is bound to (or `"bbs-issuer"` if unbound).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Whether this key carries a DID-anchor binding.
    pub fn is_bound(&self) -> bool {
        self.did != UNBOUND_ISSUER && !self.attestation.is_empty()
    }

    /// Verify the BBS+ key is attested by its DID anchor - reconstructed from the
    /// `did:key` identifier (the offline path). [`BbsPresentation::verify`] calls
    /// this automatically for a bound key.
    ///
    /// # Errors
    /// If the key is unbound, the DID is not a `did:key`, or the attestation does
    /// not verify against it.
    pub fn verify_binding(&self) -> Result<()> {
        if !self.is_bound() {
            return Err(AgentCredsError::InvalidDidSignature {
                reason: "BBS+ public key carries no DID-anchor binding".into(),
            });
        }
        let anchor = TrustAnchor::from_did_key(&self.did)?;
        anchor.verify_signature(&binding_payload(&self.did, &self.bytes), &self.attestation)
    }
}

// -- Credential ----------------------------------------------------------------

/// A BBS+-signed capability credential. The issuer hands this to the holder,
/// who derives selective-disclosure proofs from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsCredential {
    issuer_id: String,
    subject: String,
    expires_at: i64,
    /// Disclosable claims, in signed order (sorted by name).
    claims: Vec<(String, Value)>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

impl BbsCredential {
    /// Issue a BBS+ credential over `claims` (each individually disclosable).
    ///
    /// # Errors
    /// `CryptoError` on a signing/encoding failure.
    pub fn issue(
        issuer: &BbsIssuer,
        subject_did: &str,
        claims: BTreeMap<String, Value>,
        valid_for_secs: u64,
    ) -> Result<Self> {
        let expires_at =
            (Utc::now() + chrono::Duration::seconds(valid_for_secs as i64)).timestamp();
        let claims: Vec<(String, Value)> = claims.into_iter().collect(); // BTreeMap -> sorted Vec
        let issuer_id = issuer_id_of(issuer)?;
        let messages = build_messages(&issuer_id, subject_did, expires_at, &claims)?;
        let params = params_for(messages.len());
        let sig = SignatureG1::<Bls12_381>::new(
            &mut OsRng,
            &messages,
            &issuer.keypair.secret_key,
            &params,
        )
        .map_err(bbs_err)?;
        Ok(BbsCredential {
            issuer_id,
            subject: subject_did.to_string(),
            expires_at,
            claims,
            signature: ark_to_bytes(&sig)?,
        })
    }

    /// The names of the claims this credential can disclose.
    pub fn disclosable_claims(&self) -> Vec<String> {
        self.claims.iter().map(|(n, _)| n.clone()).collect()
    }

    /// Holder side: derive a zero-knowledge proof revealing only `disclose`
    /// (the registered claims iss/sub/exp/vct are always revealed). `nonce`
    /// binds the proof to a verifier challenge (defeats replay).
    ///
    /// # Errors
    /// `CryptoError` on a proof or encoding failure.
    pub fn derive_proof(&self, disclose: &[&str], nonce: &[u8]) -> Result<BbsPresentation> {
        let messages = build_messages(
            &self.issuer_id,
            &self.subject,
            self.expires_at,
            &self.claims,
        )?;
        let params = params_for(messages.len());
        let sig: SignatureG1<Bls12_381> = ark_from_bytes(&self.signature)?;

        // Registered messages always revealed; disclosable ones per `disclose`.
        let mut revealed_indices: BTreeSet<usize> = (0..REGISTERED).collect();
        for (j, (name, _)) in self.claims.iter().enumerate() {
            if disclose.contains(&name.as_str()) {
                revealed_indices.insert(REGISTERED + j);
            }
        }
        let revealed_msgs: BTreeMap<usize, Fr> =
            revealed_indices.iter().map(|&i| (i, messages[i])).collect();

        let protocol = PoKOfSignatureG1Protocol::<Bls12_381>::init(
            &mut OsRng,
            &sig,
            &params,
            &messages,
            BTreeMap::new(),
            revealed_indices.clone(),
        )
        .map_err(bbs_err)?;

        let mut transcript = Vec::new();
        protocol
            .challenge_contribution(&revealed_msgs, &params, &mut transcript)
            .map_err(bbs_err)?;
        let challenge = challenge_from(&transcript, nonce);

        let proof = protocol.gen_proof(&challenge).map_err(bbs_err)?;

        // Carry the revealed (name, value) pairs so the verifier can rebuild
        // the revealed field elements; hidden claims are never included.
        let names = message_names(&self.claims);
        let revealed: Vec<RevealedMessage> = revealed_indices
            .iter()
            .map(|&i| RevealedMessage {
                index: i,
                name: names[i].clone(),
                value: message_value(
                    &self.issuer_id,
                    &self.subject,
                    self.expires_at,
                    &self.claims,
                    i,
                ),
            })
            .collect();

        Ok(BbsPresentation {
            total_messages: messages.len(),
            revealed,
            proof: ark_to_bytes(&proof)?,
            nonce: nonce.to_vec(),
        })
    }

    /// Serialize to CBOR.
    ///
    /// # Errors
    /// CBOR serialization failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).map_err(AgentCredsError::from)?;
        Ok(buf)
    }

    /// Deserialise from CBOR.
    ///
    /// # Errors
    /// CBOR deserialization failure.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

// -- Presentation ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevealedMessage {
    index: usize,
    name: String,
    value: Value,
}

/// A BBS+ zero-knowledge presentation: reveals a subset of claims, proves the
/// rest in zero knowledge, and is unlinkable across uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbsPresentation {
    total_messages: usize,
    revealed: Vec<RevealedMessage>,
    #[serde(with = "hex::serde")]
    proof: Vec<u8>,
    #[serde(with = "hex::serde")]
    nonce: Vec<u8>,
}

/// The result of verifying a BBS+ presentation.
#[derive(Debug, Clone)]
pub struct BbsDisclosed {
    /// Issuer identifier (revealed `iss`).
    pub issuer: String,
    /// Subject DID (revealed `sub`).
    pub subject: String,
    /// Expiry (revealed `exp`).
    pub expires_at: DateTime<Utc>,
    /// The non-registered claims the holder disclosed.
    pub disclosed: BTreeMap<String, Value>,
}

impl BbsPresentation {
    /// Verifier side: verify against the issuer's public key and an expected
    /// `nonce`, returning the disclosed claims.
    ///
    /// # Errors
    /// `CryptoError` if the proof does not verify; `ProofOfPossessionFailed` on
    /// a nonce mismatch; `CredentialExpired` if past `exp`.
    pub fn verify(&self, issuer_pk: &BbsPublicKey, expected_nonce: &[u8]) -> Result<BbsDisclosed> {
        if self.nonce != expected_nonce {
            return Err(AgentCredsError::ProofOfPossessionFailed {
                reason: "bbs+ presentation nonce does not match".into(),
            });
        }
        let params = params_for(self.total_messages);
        let pk = issuer_pk.inner()?;
        let proof: PoKOfSignatureG1Proof<Bls12_381> = ark_from_bytes(&self.proof)?;

        // Rebuild the revealed field elements from the carried (name, value)s.
        let mut revealed_msgs: BTreeMap<usize, Fr> = BTreeMap::new();
        for r in &self.revealed {
            revealed_msgs.insert(r.index, encode_message(&r.name, &r.value)?);
        }

        let mut transcript = Vec::new();
        proof
            .challenge_contribution(&revealed_msgs, &params, &mut transcript)
            .map_err(bbs_err)?;
        let challenge = challenge_from(&transcript, &self.nonce);

        proof
            .verify(&revealed_msgs, &challenge, &pk, &params)
            .map_err(bbs_err)?;

        // If the issuer key is bound to a DID anchor, require the binding to
        // verify - so a bound BBS+ credential cryptographically traces to a DID.
        if issuer_pk.is_bound() {
            issuer_pk.verify_binding()?;
        }

        // Extract registered + disclosed claims from the (now trusted) revealed set.
        let mut issuer = String::new();
        let mut subject = String::new();
        let mut exp: i64 = 0;
        let mut disclosed = BTreeMap::new();
        for r in &self.revealed {
            match r.index {
                0 => issuer = r.value.as_str().unwrap_or_default().to_string(),
                1 => subject = r.value.as_str().unwrap_or_default().to_string(),
                2 => exp = r.value.as_i64().unwrap_or_default(),
                3 => {} // vct
                _ => {
                    disclosed.insert(r.name.clone(), r.value.clone());
                }
            }
        }

        let expires_at = Utc
            .timestamp_opt(exp, 0)
            .single()
            .ok_or_else(|| bbs_err("invalid exp"))?;
        if Utc::now() > expires_at {
            return Err(AgentCredsError::CredentialExpired {
                expired_at: expires_at.to_rfc3339(),
            });
        }

        // A bound key's revealed `iss` must be the DID it is attested to.
        if issuer_pk.is_bound() && issuer != issuer_pk.did {
            return Err(AgentCredsError::IssuerMismatch {
                expected: issuer_pk.did.clone(),
                got: issuer,
            });
        }

        Ok(BbsDisclosed {
            issuer,
            subject,
            expires_at,
            disclosed,
        })
    }

    /// Serialize to CBOR.
    ///
    /// # Errors
    /// CBOR serialization failure.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).map_err(AgentCredsError::from)?;
        Ok(buf)
    }

    /// Deserialise from CBOR.
    ///
    /// # Errors
    /// CBOR deserialization failure.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

// -- Message vector helpers ------------------------------------------------------

fn issuer_id_of(issuer: &BbsIssuer) -> Result<String> {
    // The `iss` message is the issuer's DID (bound anchor), or the unbound label.
    Ok(issuer.did.clone())
}

fn message_names(claims: &[(String, Value)]) -> Vec<String> {
    let mut names = vec![
        "iss".to_string(),
        "sub".to_string(),
        "exp".to_string(),
        "vct".to_string(),
    ];
    names.extend(claims.iter().map(|(n, _)| n.clone()));
    names
}

fn message_value(
    issuer_id: &str,
    subject: &str,
    exp: i64,
    claims: &[(String, Value)],
    index: usize,
) -> Value {
    match index {
        0 => Value::String(issuer_id.to_string()),
        1 => Value::String(subject.to_string()),
        2 => Value::Number(exp.into()),
        3 => Value::String(VCT.to_string()),
        _ => claims[index - REGISTERED].1.clone(),
    }
}

fn build_messages(
    issuer_id: &str,
    subject: &str,
    exp: i64,
    claims: &[(String, Value)],
) -> Result<Vec<Fr>> {
    let names = message_names(claims);
    let mut out = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let value = message_value(issuer_id, subject, exp, claims, i);
        out.push(encode_message(name, &value)?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issued() -> (BbsIssuer, BbsCredential) {
        let issuer = BbsIssuer::generate();
        let mut claims = BTreeMap::new();
        claims.insert("tools".to_string(), json!(["tool:search", "tool:email"]));
        claims.insert("budget_usd".to_string(), json!(500));
        claims.insert("authorized_by".to_string(), json!("did:key:zSecretBoss"));
        let cred = BbsCredential::issue(&issuer, "did:key:zAgent", claims, 3600).unwrap();
        (issuer, cred)
    }

    fn issued_for(anchor: &TrustAnchor) -> (BbsIssuer, BbsCredential) {
        let issuer = BbsIssuer::for_anchor(anchor).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("tools".to_string(), json!(["tool:search"]));
        claims.insert("budget_usd".to_string(), json!(500));
        let cred = BbsCredential::issue(&issuer, "did:key:zAgent", claims, 3600).unwrap();
        (issuer, cred)
    }

    #[test]
    fn bound_issuer_credential_traces_to_did_anchor() {
        let anchor = TrustAnchor::generate().unwrap();
        let (issuer, cred) = issued_for(&anchor);
        assert_eq!(issuer.did(), anchor.did());

        let pk = issuer.public_key();
        assert!(pk.is_bound());
        assert_eq!(pk.did(), anchor.did());
        assert!(pk.verify_binding().is_ok());

        // The disclosed issuer is the anchor DID, and the binding is enforced.
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        let d = pres.verify(&pk, b"n").unwrap();
        assert_eq!(d.issuer, anchor.did());
    }

    #[test]
    fn forged_bbs_key_binding_is_rejected() {
        let anchor = TrustAnchor::generate().unwrap();
        let (issuer, cred) = issued_for(&anchor);
        let mut pk = issuer.public_key();
        // Corrupt the attestation: the BBS+ key is no longer attested by the DID.
        pk.attestation[0] ^= 0xFF;
        assert!(pk.verify_binding().is_err());
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        assert!(pres.verify(&pk, b"n").is_err());
    }

    #[test]
    fn bbs_key_claiming_a_did_it_does_not_control_is_rejected() {
        // An attacker takes a victim anchor's DID but signs the binding with
        // their own (unrelated) anchor - the binding does not verify.
        let attacker = TrustAnchor::generate().unwrap();
        let (issuer, _cred) = issued_for(&attacker);
        let victim = TrustAnchor::generate().unwrap();
        let mut pk = issuer.public_key();
        pk.did = victim.did().to_string(); // claim the victim DID
        assert!(pk.verify_binding().is_err());
    }

    #[test]
    fn unbound_issuer_still_works() {
        let (issuer, cred) = issued();
        let pk = issuer.public_key();
        assert!(!pk.is_bound());
        assert_eq!(pk.did(), "bbs-issuer");
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        assert!(pres.verify(&pk, b"n").is_ok());
    }

    #[test]
    fn reveal_all_verifies() {
        let (issuer, cred) = issued();
        let pk = issuer.public_key();
        let names = cred.disclosable_claims();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let pres = cred.derive_proof(&refs, b"n").unwrap();
        let d = pres.verify(&pk, b"n").unwrap();
        assert_eq!(d.subject, "did:key:zAgent");
        assert!(d.disclosed.contains_key("tools"));
        assert!(d.disclosed.contains_key("budget_usd"));
    }

    #[test]
    fn selective_disclosure_hides_the_rest() {
        let (issuer, cred) = issued();
        let pk = issuer.public_key();
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        let d = pres.verify(&pk, b"n").unwrap();
        assert!(d.disclosed.contains_key("tools"));
        assert!(!d.disclosed.contains_key("budget_usd"));
        assert!(!d.disclosed.contains_key("authorized_by"));
        assert_eq!(
            d.disclosed.get("tools").unwrap(),
            &json!(["tool:search", "tool:email"])
        );
    }

    #[test]
    fn hidden_claim_not_in_presentation_bytes() {
        let (_issuer, cred) = issued();
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        let wire = pres.to_cbor().unwrap();
        let hay = String::from_utf8_lossy(&wire);
        assert!(!hay.contains("zSecretBoss"));
    }

    #[test]
    fn unlinkable_two_proofs_differ() {
        // The defining BBS+ property: two presentations of the same credential
        // are not byte-correlatable (randomized proofs).
        let (_issuer, cred) = issued();
        let p1 = cred.derive_proof(&["tools"], b"n").unwrap();
        let p2 = cred.derive_proof(&["tools"], b"n").unwrap();
        assert_ne!(p1.proof, p2.proof);
    }

    #[test]
    fn wrong_issuer_key_rejected() {
        let (_issuer, cred) = issued();
        let other = BbsIssuer::generate();
        let pres = cred.derive_proof(&["tools"], b"n").unwrap();
        assert!(pres.verify(&other.public_key(), b"n").is_err());
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let (issuer, cred) = issued();
        let pres = cred.derive_proof(&["tools"], b"issued-nonce").unwrap();
        assert!(pres
            .verify(&issuer.public_key(), b"different-nonce")
            .is_err());
    }

    #[test]
    fn tampered_revealed_value_rejected() {
        let (issuer, cred) = issued();
        let mut pres = cred.derive_proof(&["tools"], b"n").unwrap();
        // Flip the disclosed tools value - the proof no longer matches.
        for r in &mut pres.revealed {
            if r.name == "tools" {
                r.value = json!(["tool:admin"]);
            }
        }
        assert!(pres.verify(&issuer.public_key(), b"n").is_err());
    }

    #[test]
    fn cbor_round_trip() {
        let (issuer, cred) = issued();
        let cred2 = BbsCredential::from_cbor(&cred.to_cbor().unwrap()).unwrap();
        let pres = cred2.derive_proof(&["tools"], b"n").unwrap();
        let pres2 = BbsPresentation::from_cbor(&pres.to_cbor().unwrap()).unwrap();
        assert!(pres2.verify(&issuer.public_key(), b"n").is_ok());
    }
}
