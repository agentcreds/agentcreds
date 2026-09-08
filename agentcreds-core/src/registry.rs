//! Trust registry - cross-organizational trust anchor resolution.
//!
//! In production, this queries the TRAIL (Trust Registry for AI Identity Layer)
//! at DIF, or an org's own hosted registry.
//!
//! This module provides:
//! - `TrustRegistry` - in-process registry for testing and single-org deployments
//! - `TrustEntry`    - a registered trust anchor with its public key
//! - `CrossOrgVerifier` - verifies a VC against a registry (no callback needed)

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

use crate::did::resolver::{DidResolver, InMemoryResolver};
use crate::did::{KeyAlgorithm, PublicKey, TrustAnchor};
use crate::vc::CapabilityCredential;
use crate::{error::AgentCredsError, Result};
use bs58;

/// Trust level assigned to a DID method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Unverified - no attestation backing.
    Unverified = 0,
    /// Self-asserted - org signed its own registration.
    SelfAsserted = 1,
    /// Verified - independent attestation (e.g. consortium member).
    Verified = 2,
    /// Authoritative - e.g. government-issued DID.
    Authoritative = 3,
}

/// A registered trust anchor entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    /// The DID of the trust anchor.
    ///
    /// Treat this as the organization's **root** anchor DID - the identifier a relying
    /// party pins once and never re-imports. An organization that has never rotated has
    /// a root identical to its current key, so an existing registry keeps working
    /// unchanged; one that rotates keeps this entry stable and publishes a
    /// [`KeyHistory`](crate::rotation::KeyHistory) instead. Registering the *current*
    /// key would make every member rotation a multilateral event: the framework would
    /// have to re-sign, and every relying party re-import, because one member changed
    /// its own key.
    pub did: String,
    /// Human-readable organization name.
    pub org_name: String,
    /// The trust anchor's public key (for VC verification).
    pub public_key: PublicKey,
    /// DID method used by this anchor.
    pub did_method: String,
    /// Trust level assigned by the registry.
    pub trust_level: TrustLevel,
    /// When this entry was registered.
    pub registered_at: DateTime<Utc>,
    /// Optional URL to the org's revocation list endpoint.
    pub revocation_endpoint: Option<String>,
    /// Optional URL at which the organization publishes its signed
    /// [`KeyHistory`](crate::rotation::KeyHistory).
    ///
    /// Metadata only - the history is deliberately NOT carried inside the signed
    /// registry. Inlining it would put a member's rotation back inside the framework's
    /// signature, which is the coupling this design removes. Distribution is the
    /// relying party's concern, exactly as it is for the revocation list.
    #[serde(default)]
    pub key_history_url: Option<String>,
}

impl TrustEntry {
    /// Create a new trust entry.
    pub fn new(
        did: impl Into<String>,
        org_name: impl Into<String>,
        public_key: PublicKey,
        trust_level: TrustLevel,
    ) -> Self {
        let did = did.into();
        let did_method = did.split(':').nth(1).unwrap_or("unknown").to_string();
        TrustEntry {
            did,
            org_name: org_name.into(),
            public_key,
            did_method,
            trust_level,
            registered_at: Utc::now(),
            revocation_endpoint: None,
            key_history_url: None,
        }
    }

    /// Verify a signature produced by this trust anchor.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use crate::did::KeyAlgorithm;
        match self.public_key.algorithm {
            KeyAlgorithm::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let key_bytes: [u8; 32] =
                    self.public_key.bytes.as_slice().try_into().map_err(|_| {
                        AgentCredsError::InvalidKeyMaterial {
                            reason: "Ed25519 key wrong length".into(),
                        }
                    })?;
                let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    AgentCredsError::InvalidKeyMaterial {
                        reason: e.to_string(),
                    }
                })?;
                let sig_bytes: [u8; 64] =
                    signature
                        .try_into()
                        .map_err(|_| AgentCredsError::InvalidDidSignature {
                            reason: "signature wrong length".into(),
                        })?;
                let sig = Signature::from_bytes(&sig_bytes);
                vk.verify(message, &sig)
                    .map_err(|e| AgentCredsError::InvalidDidSignature {
                        reason: e.to_string(),
                    })
            }
            KeyAlgorithm::P256 => {
                use p256::ecdsa::{
                    signature::Verifier as EcdsaVerifier, DerSignature, VerifyingKey,
                };
                let vk = VerifyingKey::from_sec1_bytes(&self.public_key.bytes).map_err(|e| {
                    AgentCredsError::InvalidKeyMaterial {
                        reason: e.to_string(),
                    }
                })?;
                let sig = DerSignature::from_bytes(signature).map_err(|e| {
                    AgentCredsError::InvalidDidSignature {
                        reason: e.to_string(),
                    }
                })?;
                vk.verify(message, &sig)
                    .map_err(|e| AgentCredsError::InvalidDidSignature {
                        reason: e.to_string(),
                    })
            }
        }
    }
}

/// In-process trust registry for testing and single-org deployments.
///
/// In production, resolve() can fall back to network-backed DID resolution
/// when an entry is not already cached locally.
pub struct TrustRegistry {
    entries: HashMap<String, TrustEntry>,
    resolver: Box<dyn DidResolver>,
    /// Minimum trust level accepted for cross-org verification.
    pub minimum_trust_level: TrustLevel,
}

impl fmt::Debug for TrustRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRegistry")
            .field("entries", &self.entries)
            .field("minimum_trust_level", &self.minimum_trust_level)
            .finish_non_exhaustive()
    }
}

impl TrustRegistry {
    /// Create a registry backed by an in-memory resolver.
    pub fn new() -> Self {
        TrustRegistry {
            entries: HashMap::new(),
            resolver: Box::new(InMemoryResolver::new()),
            minimum_trust_level: TrustLevel::SelfAsserted,
        }
    }

    /// Create a registry backed by the given resolver.
    pub fn with_resolver(resolver: Box<dyn DidResolver>) -> Self {
        TrustRegistry {
            entries: HashMap::new(),
            resolver,
            minimum_trust_level: TrustLevel::SelfAsserted,
        }
    }

    /// Create a registry with the built-in in-memory resolver.
    pub fn in_memory() -> Self {
        Self::new()
    }

    /// Register a trust anchor.
    pub fn register(&mut self, entry: TrustEntry) {
        self.entries.insert(entry.did.clone(), entry);
    }

    fn public_key_from_document(
        &self,
        did: &str,
        document: &crate::did::DidDocument,
    ) -> Result<PublicKey> {
        let vm = document.verification_method.first().ok_or_else(|| {
            AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "resolved DID document contains no verification method".into(),
            }
        })?;

        let bytes = decode_multibase(&vm.public_key_multibase).map_err(|reason| {
            AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason,
            }
        })?;

        let algorithm = match vm.r#type.as_str() {
            "Ed25519VerificationKey2020" => KeyAlgorithm::Ed25519,
            "EcdsaSecp256r1VerificationKey2019" => KeyAlgorithm::P256,
            other => {
                return Err(AgentCredsError::DidResolutionFailed {
                    did: did.to_string(),
                    reason: format!("unsupported verification method type: {}", other),
                })
            }
        };

        // `decode_multibase` returns the multicodec-prefixed bytes; strip the
        // 2-byte prefix to recover the raw key bytes that `PublicKey::bytes`
        // and `verify_signature` expect (mirrors `PublicKey::to_multibase`).
        let multicodec_prefix: &[u8] = match algorithm {
            KeyAlgorithm::Ed25519 => &[0xed, 0x01],
            KeyAlgorithm::P256 => &[0x12, 0x00],
        };
        let bytes = bytes
            .strip_prefix(multicodec_prefix)
            .ok_or_else(|| AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "public key multibase has an unexpected multicodec prefix".into(),
            })?
            .to_vec();

        Ok(PublicKey { algorithm, bytes })
    }

    /// Resolve a trust anchor by DID.
    /// If the DID is not yet cached, the resolver is used and the result is cached.
    pub fn resolve(&mut self, did: &str) -> Result<&TrustEntry> {
        if !self.entries.contains_key(did) {
            let document = self.resolver.resolve(did)?;
            let public_key = self.public_key_from_document(did, &document)?;
            let entry = TrustEntry {
                did: did.to_string(),
                org_name: document.id.clone(),
                public_key,
                did_method: did.split(':').nth(1).unwrap_or("unknown").to_string(),
                trust_level: TrustLevel::SelfAsserted,
                registered_at: Utc::now(),
                revocation_endpoint: None,
                key_history_url: None,
            };
            self.entries.insert(did.to_string(), entry);
        }
        self.entries
            .get(did)
            .ok_or_else(|| AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "not found in registry".into(),
            })
    }

    /// Number of registered trust anchors.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no trust anchors are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all registered DIDs.
    pub fn registered_dids(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Export the registered anchors and minimum trust level as a **signed,
    /// versioned [`SignedTrustConfig`]** - the portable, tamper-evident artifact you
    /// persist, version-control, and distribute. `anchor` signs it and becomes
    /// its issuer.
    ///
    /// # Errors
    /// If the anchor fails to sign.
    pub fn export(&self, anchor: &TrustAnchor, version: u64) -> Result<SignedTrustConfig> {
        self.export_valid_until(anchor, version, None)
    }

    /// Like [`export`](Self::export), but seals an expiry into the signed config so
    /// a fail-safe consumer rejects it once stale (bounded-staleness for trust
    /// material). Pass `None` for an unbounded config.
    ///
    /// # Errors
    /// If the anchor cannot sign the config digest.
    pub fn export_valid_until(
        &self,
        anchor: &TrustAnchor,
        version: u64,
        not_after: Option<DateTime<Utc>>,
    ) -> Result<SignedTrustConfig> {
        let mut entries: Vec<TrustEntry> = self.entries.values().cloned().collect();
        entries.sort_by(|a, b| a.did.cmp(&b.did)); // deterministic for signing
        let mut config = SignedTrustConfig {
            version,
            generated_at: Utc::now(),
            issuer_did: anchor.did().to_string(),
            minimum_trust_level: self.minimum_trust_level,
            entries,
            not_after,
            signature: String::new(),
        };
        let sig = anchor.sign(&config.digest())?;
        config.signature = base64ct::Base64::encode_string(&sig);
        Ok(config)
    }

    /// Build a registry from a **verified** [`SignedTrustConfig`] (using the in-memory
    /// resolver). Replaces the minimum trust level and entries with the config's.
    ///
    /// # Errors
    /// `InvalidVcProof` if the config does not verify against `anchor`.
    pub fn from_config(config: &SignedTrustConfig, anchor: &TrustAnchor) -> Result<Self> {
        config.verify_current(anchor)?; // fail-safe: reject a stale (expired) config
        let mut registry = Self::new();
        registry.minimum_trust_level = config.minimum_trust_level;
        for entry in &config.entries {
            registry.register(entry.clone());
        }
        Ok(registry)
    }

    /// Merge a **verified** config's entries into this registry (additive; does
    /// not change this registry's minimum trust level).
    ///
    /// # Errors
    /// `InvalidVcProof` if the config does not verify against `anchor`.
    pub fn import(&mut self, config: &SignedTrustConfig, anchor: &TrustAnchor) -> Result<()> {
        config.verify_current(anchor)?; // fail-safe: reject a stale (expired) config
        for entry in &config.entries {
            self.register(entry.clone());
        }
        Ok(())
    }
}

// -- SignedTrustConfig (signed, portable trust registry) -------------------------------

const TRUST_CONFIG_DOMAIN: &[u8] = b"agentcreds-trust-config-v1";

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

/// A signed, versioned snapshot of a [`TrustRegistry`] - the persistable trust
/// configuration.
///
/// An org seals which anchors it trusts (and at what levels) under its own anchor
/// signature; a consumer [`verify`](Self::verify)s it offline before loading, so
/// distributed trust config is tamper-evident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTrustConfig {
    /// Monotonic config version (bump on each change for rollback detection).
    pub version: u64,
    /// When the config was sealed.
    pub generated_at: DateTime<Utc>,
    /// The DID of the anchor that signed it.
    pub issuer_did: String,
    /// The minimum trust level the registry enforces.
    pub minimum_trust_level: TrustLevel,
    /// The trusted anchors, sorted by DID.
    pub entries: Vec<TrustEntry>,
    /// Optional expiry: after this instant the config is stale and a fail-safe
    /// consumer rejects it (bounded staleness for distributed trust material).
    /// Part of the signed digest, so it cannot be extended without the anchor key.
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    /// The issuer anchor's signature over the canonical digest.
    pub signature: String,
}

impl SignedTrustConfig {
    fn digest(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(TRUST_CONFIG_DOMAIN);
        h.update(self.version.to_le_bytes());
        h.update(self.generated_at.timestamp().to_le_bytes());
        write_field(&mut h, self.issuer_did.as_bytes());
        h.update([self.minimum_trust_level as u8]);
        // Expiry is signed so it cannot be extended (or removed) after sealing.
        match self.not_after {
            Some(t) => {
                h.update([1u8]);
                h.update(t.timestamp().to_le_bytes());
            }
            None => h.update([0u8]),
        }
        h.update((self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            write_field(&mut h, e.did.as_bytes());
            write_field(&mut h, e.org_name.as_bytes());
            write_field(&mut h, e.public_key.to_multibase().as_bytes());
            write_field(&mut h, e.did_method.as_bytes());
            h.update([e.trust_level as u8]);
            h.update(e.registered_at.timestamp().to_le_bytes());
            write_field(
                &mut h,
                e.revocation_endpoint.as_deref().unwrap_or("").as_bytes(),
            );
        }
        h.finalize().to_vec()
    }

    /// Verify the config's signature against `anchor` (its issuer).
    ///
    /// # Errors
    /// `InvalidVcProof` on an issuer/anchor mismatch or a bad signature.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        // Signature + issuer only (no expiry); see `verify_current` for the
        // fail-safe check. Shared with the approver directory via `crate::signed`.
        crate::signed::verify_anchor_signed(
            &self.issuer_did,
            &self.digest(),
            &self.signature,
            None,
            Utc::now(),
            anchor,
            "trust config",
        )
    }

    /// Whether the config is still within its (optional) validity window at the
    /// current time. An unbounded config (`not_after == None`) is always current.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.not_after.map_or(true, |t| Utc::now() <= t)
    }

    /// Verify authenticity **and** freshness: the signature must verify against
    /// `anchor` and the config must not be past its `not_after`. This is the
    /// fail-safe check a relying party should use before trusting the config.
    ///
    /// # Errors
    /// `InvalidVcProof` on a bad signature/issuer, or if the config has expired.
    pub fn verify_current(&self, anchor: &TrustAnchor) -> Result<()> {
        crate::signed::verify_anchor_signed(
            &self.issuer_did,
            &self.digest(),
            &self.signature,
            self.not_after,
            Utc::now(),
            anchor,
            "trust config",
        )
    }

    /// Serialize to JSON (the persisted artifact).
    ///
    /// # Errors
    /// On serialization failure.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(AgentCredsError::from)
    }

    /// Parse from JSON.
    ///
    /// # Errors
    /// On deserialisation failure.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(AgentCredsError::from)
    }
}

pub(crate) fn decode_multibase(value: &str) -> std::result::Result<Vec<u8>, String> {
    let encoded = value.strip_prefix('z').ok_or_else(|| {
        "unsupported multibase prefix, expected base58btc starting with 'z'".to_string()
    })?;
    bs58::decode(encoded)
        .into_vec()
        .map_err(|e| format!("base58 decode failed: {}", e))
}

impl TrustRegistry {
    /// Verify `vc` where its issuer may be a **rotated** key of a registered member.
    ///
    /// [`CrossOrgVerifier`] resolves `vc.issuer` directly, so it cannot see a credential
    /// signed by a key the member adopted after registration. This path resolves the
    /// member by the **root** its history is anchored at, applies the same trust-level
    /// gate, then lets the verified history decide whether the issuer is a key that
    /// member still trusts.
    ///
    /// The gate is applied to the ROOT entry deliberately: rotation must not become a
    /// way to escape a minimum trust level. A member registered as `self_asserted` stays
    /// `self_asserted` across any number of rotations.
    ///
    /// # Errors
    /// If the history's root is not registered, the root is below the registry's minimum
    /// trust level, the history is unsealed / expired / does not verify, the issuer is
    /// absent from it or has been repudiated, or the credential's proof fails.
    pub fn verify_credential_rotated(
        &mut self,
        vc: &CapabilityCredential,
        history: &crate::rotation::KeyHistory,
    ) -> Result<&TrustEntry> {
        let min_level = self.minimum_trust_level;
        let root = history.root_did.clone();

        // Membership and trust level are decided by the ROOT entry.
        let level = self.resolve(&root)?.trust_level;
        if level < min_level {
            return Err(AgentCredsError::InvalidVcProof {
                reason: format!("issuer trust level {level:?} below minimum {min_level:?}"),
            });
        }

        // The history decides which keys that member still trusts for issuance, and
        // enforces the seal, the expiry and any repudiation.
        let anchor = history.authorize_issuer(&root, &vc.issuer)?;
        vc.verify(&anchor, true)?;

        // Re-resolve for the returned borrow; `resolve` caches, so this is cheap.
        self.resolve(&root)
    }
}

/// Cross-organizational VC verifier.
///
/// Resolves the issuer's trust anchor from the registry and
/// verifies the credential without calling back to the issuer's
/// infrastructure - enabling offline cross-org verification.
pub struct CrossOrgVerifier<'a> {
    registry: &'a mut TrustRegistry,
}

impl<'a> CrossOrgVerifier<'a> {
    /// Create a verifier backed by the given registry.
    pub fn new(registry: &'a mut TrustRegistry) -> Self {
        CrossOrgVerifier { registry }
    }

    /// Verify a `CapabilityCredential` without contacting the issuer.
    ///
    /// 1. Resolves issuer DID from the registry
    /// 2. Checks trust level meets minimum threshold
    /// 3. Verifies the credential's cryptographic proof
    /// 4. Checks credential has not expired
    pub fn verify(&mut self, vc: &CapabilityCredential) -> Result<&TrustEntry> {
        let min_level = self.registry.minimum_trust_level;
        let entry = self.registry.resolve(&vc.issuer)?;

        // Trust level gate
        if entry.trust_level < min_level {
            return Err(AgentCredsError::InvalidVcProof {
                reason: format!(
                    "issuer trust level {:?} below minimum {:?}",
                    entry.trust_level, min_level
                ),
            });
        }

        // Expiry
        if !vc.is_valid() {
            return Err(AgentCredsError::CredentialExpired {
                expired_at: vc.expiration_date().to_rfc3339(),
            });
        }

        // Reconstruct signed payload and verify signature
        let unsigned_payload = serde_json::json!({
            "id": vc.id,
            "issuer": vc.issuer,
            "issuanceDate": vc.issuance_date.to_rfc3339(),
            "expirationDate": vc.expiration_date.to_rfc3339(),
            "credentialSubject": vc.credential_subject,
        });
        let payload_bytes = serde_json::to_vec(&unsigned_payload)?;

        let sig_bytes = base64ct::Base64::decode_vec(&vc.proof.proof_value).map_err(|e| {
            AgentCredsError::InvalidVcProof {
                reason: format!("base64 decode: {}", e),
            }
        })?;

        entry
            .verify_signature(&payload_bytes, &sig_bytes)
            .map_err(|e| AgentCredsError::InvalidVcProof {
                reason: e.to_string(),
            })?;

        Ok(entry)
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
    use crate::vc::{CapabilityClaims, CapabilityCredential};

    fn setup() -> (
        TrustAnchor,
        AgentIdentity,
        CapabilityCredential,
        TrustRegistry,
    ) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

        let entry = TrustEntry::new(
            anchor.did(),
            "Test Organization",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        );
        let mut registry = TrustRegistry::new();
        registry.register(entry);

        (anchor, agent, vc, registry)
    }

    #[test]
    fn cross_org_verify_succeeds() {
        let (_anchor, _agent, vc, mut registry) = setup();
        let mut verifier = CrossOrgVerifier::new(&mut registry);
        assert!(verifier.verify(&vc).is_ok());
    }

    #[test]
    fn unknown_issuer_fails() {
        let (_anchor, agent, _, mut registry) = setup();
        // Issue a VC from an anchor NOT in the registry
        let unknown_anchor = TrustAnchor::generate().unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let vc = CapabilityCredential::issue(&unknown_anchor, agent.did(), claims, None).unwrap();
        let mut verifier = CrossOrgVerifier::new(&mut registry);
        assert!(matches!(
            verifier.verify(&vc),
            Err(AgentCredsError::DidResolutionFailed { .. })
        ));
    }

    #[test]
    fn trust_level_gate_rejects_low_trust() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:x".into()], 1, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

        let entry = TrustEntry::new(
            anchor.did(),
            "Low Trust Org",
            anchor.public_key().clone(),
            TrustLevel::Unverified,
        );
        let mut registry = TrustRegistry::new();
        registry.register(entry);
        registry.minimum_trust_level = TrustLevel::SelfAsserted;

        let mut verifier = CrossOrgVerifier::new(&mut registry);
        assert!(verifier.verify(&vc).is_err());
    }

    #[test]
    fn registry_resolve_unknown_did() {
        let mut registry = TrustRegistry::new();
        assert!(matches!(
            registry.resolve("did:key:zunknown"),
            Err(AgentCredsError::DidResolutionFailed { .. })
        ));
    }

    #[test]
    fn trust_registry_len_and_is_empty() {
        let mut registry = TrustRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let anchor = TrustAnchor::generate().unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Org A",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        );
        registry.register(entry);

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn trust_registry_registered_dids() {
        let mut registry = TrustRegistry::new();
        let anchor = TrustAnchor::generate().unwrap();
        let did = anchor.did().to_string();
        let entry = TrustEntry::new(
            &did,
            "Org B",
            anchor.public_key().clone(),
            TrustLevel::SelfAsserted,
        );
        registry.register(entry);

        let dids = registry.registered_dids();
        assert_eq!(dids.len(), 1);
        assert!(dids.contains(&did.as_str()));
    }

    #[test]
    fn trust_entry_verify_signature_ed25519() {
        let anchor = TrustAnchor::generate().unwrap();
        let msg = b"test payload for signature verification";
        let sig = anchor.sign(msg).unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Org",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        );
        assert!(entry.verify_signature(msg, &sig).is_ok());
    }

    #[test]
    fn trust_entry_verify_signature_wrong_message_fails() {
        let anchor = TrustAnchor::generate().unwrap();
        let sig = anchor.sign(b"original message").unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Org",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        );
        assert!(entry.verify_signature(b"tampered message", &sig).is_err());
    }

    #[test]
    fn cross_org_verifier_rejects_expired_credential() {
        let (_anchor, _agent, mut vc, mut registry) = setup();
        vc.expiration_date = Utc::now() - chrono::Duration::seconds(1);
        let mut verifier = CrossOrgVerifier::new(&mut registry);
        assert!(matches!(
            verifier.verify(&vc),
            Err(AgentCredsError::CredentialExpired { .. })
        ));
    }

    #[test]
    fn trust_config_export_import_round_trip() {
        let (anchor, _agent, vc, registry) = setup();
        let config = registry.export(&anchor, 7).unwrap();
        assert_eq!(config.version, 7);
        assert_eq!(config.entries.len(), 1);
        assert!(config.verify(&anchor).is_ok());

        // Rebuild a registry from the verified config and re-run cross-org verify.
        let mut rebuilt = TrustRegistry::from_config(&config, &anchor).unwrap();
        assert_eq!(rebuilt.minimum_trust_level, registry.minimum_trust_level);
        let mut verifier = CrossOrgVerifier::new(&mut rebuilt);
        assert!(verifier.verify(&vc).is_ok());

        // JSON round-trip preserves verifiability.
        let restored = SignedTrustConfig::from_json(&config.to_json().unwrap()).unwrap();
        assert!(restored.verify(&anchor).is_ok());
    }

    #[test]
    fn tampered_trust_config_is_rejected() {
        let (anchor, _agent, _vc, registry) = setup();
        let mut config = registry.export(&anchor, 1).unwrap();
        // Promote an entry's trust level after signing.
        config.entries[0].trust_level = TrustLevel::Authoritative;
        assert!(config.verify(&anchor).is_err());
        assert!(TrustRegistry::from_config(&config, &anchor).is_err());
    }

    #[test]
    fn tampering_with_length_prefixed_fields_is_rejected() {
        // MUTATION-DRIVEN. `digest` mixes two kinds of field: some go in directly
        // (`version`, `trust_level`, `registered_at`, `not_after`), and the
        // variable-length ones go through `write_field`, which length-prefixes them so
        // adjacent fields cannot be shifted between one another.
        //
        // Replacing `write_field`'s body with `()` survived the suite. Every existing
        // tamper test mutates a DIRECTLY-hashed field - `tampered_trust_config_is_rejected`
        // changes `trust_level`, `trust_config_signature_and_version_tamper_is_rejected`
        // changes `version` - so none of them notices when the length-prefixed half
        // stops being hashed at all.
        //
        // What that mutant permits is the whole point of the structure: an entry's
        // **DID and public key** are written through `write_field`, so with it neutered
        // an attacker swaps the trusted anchor for one they hold and the signature
        // still verifies. These assertions are what make that impossible.
        let (anchor, _agent, _vc, registry) = setup();

        // The entry's DID - which anchor is trusted.
        let mut config = registry.export(&anchor, 1).unwrap();
        config.entries[0].did = "did:key:zAttackerControlled".into();
        assert!(
            config.verify(&anchor).is_err(),
            "an entry's DID must be covered by the signature"
        );

        // The entry's public key - the key that anchor verifies with.
        let mut config = registry.export(&anchor, 1).unwrap();
        let attacker = TrustAnchor::generate().unwrap();
        config.entries[0].public_key = attacker.public_key().clone();
        assert!(
            config.verify(&anchor).is_err(),
            "an entry's public key must be covered by the signature"
        );

        // The issuing anchor's own DID.
        let mut config = registry.export(&anchor, 1).unwrap();
        config.issuer_did = "did:key:zSomeoneElse".into();
        assert!(
            config.verify(&anchor).is_err(),
            "the issuer DID must be covered by the signature"
        );

        // A purely descriptive field, to pin that the prefixing covers everything it
        // is applied to rather than only the security-critical entries.
        let mut config = registry.export(&anchor, 1).unwrap();
        config.entries[0].org_name = "Totally Different Org".into();
        assert!(
            config.verify(&anchor).is_err(),
            "org_name must be covered by the signature"
        );
    }

    #[test]
    fn trust_config_rejects_wrong_anchor() {
        let (anchor, _agent, _vc, registry) = setup();
        let config = registry.export(&anchor, 1).unwrap();
        let stranger = TrustAnchor::generate().unwrap();
        assert!(config.verify(&stranger).is_err());
    }

    #[test]
    fn trust_level_gate_is_exhaustive() {
        use TrustLevel::{Authoritative, SelfAsserted, Unverified, Verified};
        let levels = [Unverified, SelfAsserted, Verified, Authoritative];
        for &entry_level in &levels {
            for &min_level in &levels {
                let anchor = TrustAnchor::generate().unwrap();
                let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
                let claims = CapabilityClaims::new(vec!["tool:x".into()], 1, 3600);
                let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
                let mut registry = TrustRegistry::new();
                registry.register(TrustEntry::new(
                    anchor.did(),
                    "Org",
                    anchor.public_key().clone(),
                    entry_level,
                ));
                registry.minimum_trust_level = min_level;
                let mut verifier = CrossOrgVerifier::new(&mut registry);
                let accepted = verifier.verify(&vc).is_ok();
                assert_eq!(
                    accepted,
                    entry_level >= min_level,
                    "entry {entry_level:?} vs minimum {min_level:?} accepted={accepted}"
                );
            }
        }
    }

    #[test]
    fn trust_config_signature_and_version_tamper_is_rejected() {
        let (anchor, _agent, _vc, registry) = setup();

        // Flip a byte of the base64 signature -> verify fails.
        let mut config = registry.export(&anchor, 1).unwrap();
        let mut sig = config.signature.clone().into_bytes();
        sig[0] = if sig[0] == b'A' { b'B' } else { b'A' };
        config.signature = String::from_utf8(sig).unwrap();
        assert!(config.verify(&anchor).is_err());

        // A version bump after signing is detected (version is in the signed digest).
        let mut bumped = registry.export(&anchor, 1).unwrap();
        bumped.version = 999;
        assert!(bumped.verify(&anchor).is_err());
    }

    #[test]
    fn import_merges_entries() {
        let (anchor, _agent, _vc, registry) = setup();
        let config = registry.export(&anchor, 1).unwrap();

        // A second org with its own anchor imports the first org's config.
        let mut other = TrustRegistry::new();
        assert!(other.is_empty());
        other.import(&config, &anchor).unwrap();
        assert_eq!(other.len(), 1);
    }

    #[test]
    fn expired_trust_config_is_rejected() {
        let (anchor, _agent, _vc, registry) = setup();
        let past = Utc::now() - chrono::Duration::hours(1);
        let config = registry.export_valid_until(&anchor, 1, Some(past)).unwrap();
        // Authenticity still holds (the signature is valid over the signed expiry)...
        assert!(config.verify(&anchor).is_ok());
        // ...but the fail-safe freshness check and the loaders reject a stale config.
        assert!(!config.is_current());
        assert!(config.verify_current(&anchor).is_err());
        assert!(TrustRegistry::from_config(&config, &anchor).is_err());
        let mut other = TrustRegistry::new();
        assert!(other.import(&config, &anchor).is_err());
    }

    #[test]
    fn unexpired_trust_config_is_accepted() {
        let (anchor, _agent, _vc, registry) = setup();
        let future = Utc::now() + chrono::Duration::hours(1);
        let config = registry
            .export_valid_until(&anchor, 1, Some(future))
            .unwrap();
        assert!(config.is_current());
        assert!(config.verify_current(&anchor).is_ok());
        assert!(TrustRegistry::from_config(&config, &anchor).is_ok());
    }

    #[test]
    fn trust_config_expiry_is_tamper_evident() {
        let (anchor, _agent, _vc, registry) = setup();
        let past = Utc::now() - chrono::Duration::hours(1);

        // Extend the expiry after signing to try to revive a stale config.
        let mut extended = registry.export_valid_until(&anchor, 1, Some(past)).unwrap();
        extended.not_after = Some(Utc::now() + chrono::Duration::days(365));
        assert!(extended.verify(&anchor).is_err());

        // Dropping the expiry entirely likewise breaks the signature.
        let mut dropped = registry.export_valid_until(&anchor, 1, Some(past)).unwrap();
        dropped.not_after = None;
        assert!(dropped.verify(&anchor).is_err());
    }

    #[test]
    fn with_resolver_creates_usable_registry() {
        let identity = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let did = identity.did().to_string();
        let doc = identity.document().clone();
        let anchor = TrustAnchor::from_identity(identity);

        let mut resolver = InMemoryResolver::new();
        resolver.register(&did, doc);

        let mut registry = TrustRegistry::with_resolver(Box::new(resolver));
        assert!(registry.resolve(&did).is_ok());
        assert_eq!(registry.resolve(&did).unwrap().did, did);
        // The resolved entry carries the anchor's public key - verify a signature roundtrip
        let msg = b"hello from resolver test";
        let sig = anchor.sign(msg).unwrap();
        let entry = registry.resolve(&did).unwrap();
        assert!(entry.verify_signature(msg, &sig).is_ok());
    }

    // -- cross-org rotation ----------------------------------------------------

    use crate::rotation::{KeyHistory, RotationStatement};

    /// A member org that has rotated once, registered by its ROOT.
    fn member(level: TrustLevel) -> (TrustAnchor, TrustAnchor, KeyHistory, TrustEntry) {
        let root = TrustAnchor::generate().unwrap();
        let current = TrustAnchor::generate().unwrap();
        let mut history = KeyHistory::genesis(&root);
        history
            .push(RotationStatement::issue(&root, &current).unwrap())
            .unwrap();
        history.seal(&current, 1, None).unwrap();
        let entry = TrustEntry::new(root.did(), "Member", root.public_key().clone(), level);
        (root, current, history, entry)
    }

    fn credential_from(anchor: &TrustAnchor) -> CapabilityCredential {
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        CapabilityCredential::issue(anchor, agent.did(), claims, None).unwrap()
    }

    #[test]
    fn rotated_member_verifies_without_re_registering() {
        // The whole point: the member rotated, the framework re-signed nothing, and the
        // relying party still accepts the new key.
        let (_root, current, history, entry) = member(TrustLevel::Verified);
        let mut reg = TrustRegistry::new();
        reg.register(entry);

        let vc = credential_from(&current);
        assert!(
            reg.verify_credential_rotated(&vc, &history).is_ok(),
            "post-rotation issuer must verify against the registered root"
        );
    }

    #[test]
    fn direct_resolution_alone_would_have_failed() {
        // The control. Without it, the test above would not show that anything was
        // fixed - the plain verifier must genuinely reject the rotated issuer.
        let (_root, current, _history, entry) = member(TrustLevel::Verified);
        let mut reg = TrustRegistry::new();
        reg.register(entry);

        let vc = credential_from(&current);
        let mut verifier = CrossOrgVerifier::new(&mut reg);
        assert!(
            verifier.verify(&vc).is_err(),
            "the current key is not registered"
        );
    }

    #[test]
    fn rotation_cannot_escape_the_minimum_trust_level() {
        // The gate is applied to the ROOT entry, so a member cannot promote itself by
        // rotating. This is the security-relevant case for this feature.
        let (_root, current, history, entry) = member(TrustLevel::SelfAsserted);
        let mut reg = TrustRegistry::new();
        reg.register(entry);
        reg.minimum_trust_level = TrustLevel::Verified;

        let vc = credential_from(&current);
        assert!(reg.verify_credential_rotated(&vc, &history).is_err());

        // Control: lower the bar and the same credential verifies, so the rejection
        // above is attributable to the level and not to something else.
        reg.minimum_trust_level = TrustLevel::SelfAsserted;
        assert!(reg.verify_credential_rotated(&vc, &history).is_ok());
    }

    #[test]
    fn history_for_an_unregistered_root_is_refused() {
        let (_root, current, history, _entry) = member(TrustLevel::Verified);
        let mut reg = TrustRegistry::new(); // nothing registered
        let vc = credential_from(&current);
        assert!(reg.verify_credential_rotated(&vc, &history).is_err());
    }

    #[test]
    fn repudiated_key_is_refused_cross_org() {
        let (root, current, mut history, entry) = member(TrustLevel::Verified);
        let vc_old = credential_from(&root);
        let vc_new = credential_from(&current);

        let mut reg = TrustRegistry::new();
        reg.register(entry);
        assert!(reg.verify_credential_rotated(&vc_old, &history).is_ok());

        history.repudiate(root.did()).unwrap();
        history.seal(&current, 2, None).unwrap();
        assert!(
            reg.verify_credential_rotated(&vc_old, &history).is_err(),
            "a repudiated key must not verify cross-org either"
        );
        assert!(
            reg.verify_credential_rotated(&vc_new, &history).is_ok(),
            "repudiating one key must not disable the member"
        );
    }

    #[test]
    fn unsealed_or_expired_history_is_refused_cross_org() {
        let (_root, current, _h, entry) = member(TrustLevel::Verified);
        let vc = credential_from(&current);
        let mut reg = TrustRegistry::new();
        reg.register(entry);

        // Unsealed: repudiations and expiry would be unauthenticated.
        let (_r2, c2, _h2, e2) = member(TrustLevel::Verified);
        let mut unsealed = KeyHistory::genesis(&_r2);
        unsealed
            .push(RotationStatement::issue(&_r2, &c2).unwrap())
            .unwrap();
        let mut reg2 = TrustRegistry::new();
        reg2.register(e2);
        assert!(reg2
            .verify_credential_rotated(&credential_from(&c2), &unsealed)
            .is_err());

        // Expired seal.
        let (_r3, c3, mut h3, e3) = member(TrustLevel::Verified);
        h3.seal(&c3, 2, Some(Utc::now() - chrono::Duration::hours(1)))
            .unwrap();
        let mut reg3 = TrustRegistry::new();
        reg3.register(e3);
        assert!(reg3
            .verify_credential_rotated(&credential_from(&c3), &h3)
            .is_err());

        let _ = (vc, reg);
    }

    // -- P-256, the other selectable algorithm --------------------------------
    //
    // Found unexercised by a production-only coverage audit on 2026-08-08: the whole
    // `KeyAlgorithm::P256` arm of `verify_signature` and the
    // `EcdsaSecp256r1VerificationKey2019` branch of DID-document parsing had never run.
    //
    // P-256 is not a hypothetical: it is a first-class config option
    // (`key_algorithm = "p256"`), it is the FIPS story, and the deployed AWS KMS anchors
    // are P-256 rather than Ed25519. Every existing test used Ed25519, so the algorithm
    // the production anchors actually use was the one with no coverage.

    fn p256_anchor() -> TrustAnchor {
        TrustAnchor::from_signer(Box::new(
            crate::did::SoftwareSigner::generate(Some(crate::did::KeyAlgorithm::P256)).unwrap(),
        ))
    }

    #[test]
    fn a_p256_anchors_signature_verifies_and_tampering_does_not() {
        let anchor = p256_anchor();
        assert_eq!(anchor.algorithm(), crate::did::KeyAlgorithm::P256);
        let entry = TrustEntry::new(
            anchor.did(),
            "P-256 Organization",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        );

        let msg = b"the message the anchor signed";
        let sig = anchor.sign(msg).unwrap();
        entry
            .verify_signature(msg, &sig)
            .unwrap_or_else(|e| panic!("a P-256 anchor must verify its own signature: {e:?}"));

        // A different message under the same signature must fail - otherwise the
        // verification is not actually binding the message.
        assert!(
            entry
                .verify_signature(b"a different message", &sig)
                .is_err(),
            "P-256 verification must bind the message"
        );

        // A corrupted signature must fail rather than parse loosely.
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(
            entry.verify_signature(msg, &bad).is_err(),
            "an altered P-256 signature must not verify"
        );

        // Garbage that is not even a DER signature.
        assert!(entry.verify_signature(msg, b"not-a-signature").is_err());
    }

    /// A P-256 issuer must work end to end through the cross-org path, not merely at
    /// the signature primitive - that is the layer a relying party actually calls.
    #[test]
    fn cross_org_verification_accepts_a_p256_issuer() {
        let anchor = p256_anchor();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

        let mut registry = TrustRegistry::new();
        registry.register(TrustEntry::new(
            anchor.did(),
            "P-256 Organization",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        ));
        let mut verifier = CrossOrgVerifier::new(&mut registry);
        verifier.verify(&vc).unwrap_or_else(|e| {
            panic!("a credential from a P-256 issuer must verify cross-org: {e:?}")
        });
    }

    /// Both verification-method types resolve to the right algorithm, and an unknown
    /// one is refused rather than defaulted. A silent default here would verify a P-256
    /// key as Ed25519 (or vice versa) and fail confusingly far from the cause.
    ///
    /// Uses each anchor's REAL DID document and only overrides the method type, so the
    /// key bytes and multibase encoding are the ones the product actually emits rather
    /// than a hand-built approximation that could agree with a bug.
    #[test]
    fn did_documents_resolve_both_algorithms_and_refuse_unknown_ones() {
        let registry = TrustRegistry::new();

        for anchor in [TrustAnchor::generate().unwrap(), p256_anchor()] {
            let doc = anchor.document().clone();
            let key = registry
                .public_key_from_document(anchor.did(), &doc)
                .unwrap_or_else(|e| {
                    panic!("{:?} document must resolve: {e:?}", anchor.algorithm())
                });
            assert_eq!(
                key.algorithm,
                anchor.public_key().algorithm,
                "the document's method type must map to the anchor's own algorithm"
            );
            assert_eq!(
                key.bytes,
                anchor.public_key().bytes,
                "resolved key bytes must be the anchor's actual key"
            );
        }

        // An unrecognised verification-method type must be refused. Defaulting here
        // would silently verify one algorithm's key under another's rules.
        let anchor = TrustAnchor::generate().unwrap();
        let mut doc = anchor.document().clone();
        doc.verification_method[0].r#type = "Rsa4096VerificationKeyFromTheFuture".into();
        assert!(
            matches!(
                registry.public_key_from_document(anchor.did(), &doc),
                Err(AgentCredsError::DidResolutionFailed { .. })
            ),
            "an unknown verification-method type must be refused, not defaulted"
        );
    }

    /// Signature verification must refuse mis-sized key material on BOTH algorithms.
    /// A registry entry's key arrives from a resolved document, so "the bytes are the
    /// right length for the algorithm they claim" is not something to assume.
    #[test]
    fn a_registry_entry_refuses_mis_sized_key_material() {
        for algorithm in [
            crate::did::KeyAlgorithm::Ed25519,
            crate::did::KeyAlgorithm::P256,
        ] {
            let signer = crate::did::SoftwareSigner::generate(Some(algorithm)).unwrap();
            let anchor = TrustAnchor::from_signer(Box::new(signer));
            let sig = anchor.sign(b"message").unwrap();

            let bad = TrustEntry::new(
                anchor.did(),
                "Org",
                crate::did::PublicKey {
                    algorithm,
                    bytes: vec![0u8; 7], // wrong length for either algorithm
                },
                TrustLevel::Verified,
            );
            assert!(
                matches!(
                    bad.verify_signature(b"message", &sig),
                    Err(AgentCredsError::InvalidKeyMaterial { .. })
                ),
                "{algorithm:?}: a mis-sized key must be refused as key material"
            );

            // A well-formed key with a mis-sized signature is a DIFFERENT error - the
            // distinction is what tells an operator which side is malformed.
            let good = TrustEntry::new(
                anchor.did(),
                "Org",
                anchor.public_key().clone(),
                TrustLevel::Verified,
            );
            assert!(matches!(
                good.verify_signature(b"message", &[0u8; 4]),
                Err(AgentCredsError::InvalidDidSignature { .. })
            ));
        }
    }

    /// Resolution failures must name the DID and say why. A registry that cannot resolve
    /// is the normal case for an unknown org, so this error is read often.
    #[test]
    fn resolution_failures_name_the_did_and_the_reason() {
        let mut registry = TrustRegistry::in_memory();

        match registry.resolve("did:key:zNeverRegistered") {
            Err(AgentCredsError::DidResolutionFailed { did, reason }) => {
                assert_eq!(did, "did:key:zNeverRegistered");
                assert!(
                    reason.contains("not found"),
                    "the reason must say why: {reason}"
                );
            }
            other => panic!("an unregistered DID must be refused: {other:?}"),
        }

        // A registered one resolves, so the failure above is about registration and not
        // about resolution being broken outright.
        let anchor = TrustAnchor::generate().unwrap();
        registry.register(TrustEntry::new(
            anchor.did(),
            "Org",
            anchor.public_key().clone(),
            TrustLevel::Verified,
        ));
        assert_eq!(registry.resolve(anchor.did()).unwrap().did, anchor.did());
    }

    /// A document whose key bytes carry an unexpected multicodec prefix must be refused
    /// rather than read as the algorithm the method type claimed - the two must agree.
    #[test]
    fn a_document_with_a_mismatched_multicodec_prefix_is_refused() {
        let registry = TrustRegistry::new();
        let anchor = TrustAnchor::generate().unwrap();
        let mut doc = anchor.document().clone();

        // Say Ed25519 in the method type, but encode a body with a foreign prefix.
        doc.verification_method[0].public_key_multibase =
            format!("z{}", bs58::encode(&[0xff, 0xff, 1, 2, 3]).into_string());

        assert!(
            matches!(
                registry.public_key_from_document(anchor.did(), &doc),
                Err(AgentCredsError::DidResolutionFailed { .. })
            ),
            "the method type and the key's multicodec prefix must agree"
        );
    }

    /// `in_memory` is the documented constructor for the built-in resolver, and `Debug`
    /// is what an operator sees in a log line. Neither had a caller.
    #[test]
    fn the_in_memory_constructor_and_debug_view_are_usable() {
        let registry = TrustRegistry::in_memory();
        let rendered = format!("{registry:?}");
        assert!(
            rendered.starts_with("TrustRegistry"),
            "Debug must name the type: {rendered}"
        );
        assert!(
            rendered.contains("minimum_trust_level"),
            "Debug must surface the gate an operator is diagnosing: {rendered}"
        );
    }
}
