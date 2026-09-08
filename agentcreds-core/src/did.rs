//! DID (Decentralized Identifier) layer.
//!
//! Supports:
//! - `did:key`  - ephemeral, self-contained, no registry required
//! - `did:web`  - org-anchored, DNS-resolvable
//!
//! All private key material is wrapped in `ZeroizingKey` which
//! calls `zeroize()` on drop, preventing key material from
//! lingering in memory after use.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::AgentCredsError, Result};

/// DID document resolution infrastructure: the [`DidResolver`] trait, an in-memory
/// resolver, and the multi-method [`UniversalResolver`] dispatcher. The concrete
/// **networked** method resolvers (did:web, DIF Universal Resolver, cheqd/indy) live
/// in the separate `agentcreds-resolvers` crate so the core stays offline.
pub mod resolver;

pub use resolver::{DidResolver, InMemoryResolver, UniversalResolver};

// -- DID Method ---------------------------------------------------------------

/// Supported DID methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DidMethod {
    /// `did:key` - derived directly from public key bytes.
    /// No registry lookup required. Suitable for ephemeral agent identities.
    Key,
    /// `did:web` - anchored to a domain. Requires `host` parameter.
    Web {
        /// DNS host (e.g. `example.com`).
        host: String,
        /// Optional path suffix (e.g. `users/alice`).
        path: Option<String>,
    },
    /// `did:cheqd` - blockchain-backed DID on the Cheqd network.
    Cheqd {
        /// Cheqd network (mainnet or testnet).
        network: CheqdNetwork,
        /// Network-unique identifier portion of the DID.
        unique_id: String,
    },
    /// `did:indy` - Hyperledger Indy DID.
    Indy {
        /// Indy ledger namespace (e.g. `sovrin:main`).
        namespace: String,
        /// Ledger-unique identifier portion of the DID.
        unique_id: String,
    },
}

/// Cheqd networks supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheqdNetwork {
    /// Cheqd mainnet.
    Mainnet,
    /// Cheqd testnet.
    Testnet,
}

impl fmt::Display for CheqdNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheqdNetwork::Mainnet => write!(f, "mainnet"),
            CheqdNetwork::Testnet => write!(f, "testnet"),
        }
    }
}

impl fmt::Display for DidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidMethod::Key => write!(f, "did:key"),
            DidMethod::Web { host, path } => match path {
                Some(p) => write!(f, "did:web:{}:{}", host, p.replace('/', ":")),
                None => write!(f, "did:web:{}", host),
            },
            DidMethod::Cheqd { network, unique_id } => {
                write!(f, "did:cheqd:{}:{}", network, unique_id)
            }
            DidMethod::Indy {
                namespace,
                unique_id,
            } => {
                write!(f, "did:indy:{}:{}", namespace, unique_id)
            }
        }
    }
}

// -- Supported Key Algorithms -------------------------------------------------

/// Cryptographic key algorithm.
///
/// **Crypto-agility checklist** - adding a variant (e.g. a post-quantum `MlDsa65`)
/// requires updating every site that matches over this enum *exhaustively*, so the
/// compiler will flag most of them. The set:
/// - [`PublicKey::to_multibase`] - multicodec prefix for the new key type.
/// - [`PublicKey::from_did_key`] - the prefix -> `(algorithm, key_len)` table.
/// - [`PublicKey::verify`] - verification for the new algorithm.
/// - [`AgentIdentity::create`] and the DID-document verification-method mappings.
/// - `crate::sd_jwt::jose_sign` - the JOSE `alg` and signature encoding.
/// - every [`AnchorSigner`] impl - [`SoftwareSigner`], the private `PublicOnlySigner`, and
///   any external anchor-signing backend.
///
/// The `key_algorithm_variants_are_exhaustively_handled` test is a tripwire: it
/// matches every variant, so a new one fails the build pointing back here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// Ed25519 - default, fast, small signatures.
    Ed25519,
    /// P-256 (ECDSA) - FIPS-approved, required by some enterprise policies.
    P256,
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        KeyAlgorithm::Ed25519
    }
}

// -- Key Material -------------------------------------------------------------

/// Zeroizing wrapper around raw private key bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizingKey(Vec<u8>);

/// Public key bytes with algorithm tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// The signature algorithm this key belongs to.
    pub algorithm: KeyAlgorithm,
    /// Raw public key bytes (encoding is algorithm-dependent).
    #[serde(with = "hex::serde")]
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Encode as multibase (base58btc) for did:key identifiers.
    pub fn to_multibase(&self) -> String {
        let mut prefixed = match self.algorithm {
            // Multicodec prefix for Ed25519 public key: 0xed01
            KeyAlgorithm::Ed25519 => vec![0xed, 0x01],
            // Multicodec prefix for P-256 public key: 0x1200
            KeyAlgorithm::P256 => vec![0x12, 0x00],
        };
        prefixed.extend_from_slice(&self.bytes);
        // Base58btc multibase prefix = 'z'
        format!("z{}", bs58_encode(&prefixed))
    }

    /// Recover a public key from a `did:key` identifier.
    ///
    /// `did:key` is self-contained - the public key is encoded directly in the
    /// DID, so no registry lookup is required. This is the inverse of
    /// [`PublicKey::to_multibase`] applied to the `did:key:` body, and is used
    /// to authenticate delegation block signatures against the signer's DID
    /// without resolving an external document.
    ///
    /// # Errors
    /// Returns `InvalidKeyMaterial` if `did` is not a `did:key`, the multibase
    /// body is malformed, the multicodec prefix is unrecognised, or the key
    /// length is wrong for the indicated algorithm.
    pub fn from_did_key(did: &str) -> Result<Self> {
        let body =
            did.strip_prefix("did:key:")
                .ok_or_else(|| AgentCredsError::InvalidKeyMaterial {
                    reason: format!("not a did:key identifier: {did}"),
                })?;
        let encoded =
            body.strip_prefix('z')
                .ok_or_else(|| AgentCredsError::InvalidKeyMaterial {
                    reason: "did:key body is not base58btc multibase (expected 'z' prefix)".into(),
                })?;
        let decoded =
            bs58::decode(encoded)
                .into_vec()
                .map_err(|e| AgentCredsError::InvalidKeyMaterial {
                    reason: format!("did:key base58 decode failed: {e}"),
                })?;

        // First two bytes are the multicodec prefix; the remainder is the raw
        // public key, exactly as assembled by `to_multibase`.
        let (algorithm, expected_len) = match decoded.get(0..2) {
            Some([0xed, 0x01]) => (KeyAlgorithm::Ed25519, 32),
            Some([0x12, 0x00]) => (KeyAlgorithm::P256, 33), // compressed SEC1
            _ => {
                return Err(AgentCredsError::InvalidKeyMaterial {
                    reason: "unrecognised did:key multicodec prefix".into(),
                })
            }
        };
        let bytes = decoded[2..].to_vec();
        if bytes.len() != expected_len {
            return Err(AgentCredsError::InvalidKeyMaterial {
                reason: format!(
                    "did:key public key length {} does not match algorithm {:?}",
                    bytes.len(),
                    algorithm
                ),
            });
        }
        Ok(PublicKey { algorithm, bytes })
    }

    /// Verify a signature produced over `message` against this public key.
    ///
    /// # Errors
    /// Returns `InvalidKeyMaterial` if the stored key bytes are malformed, or
    /// `InvalidDidSignature` if the signature does not verify.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let key_bytes: [u8; 32] = self.bytes.as_slice().try_into().map_err(|_| {
                    AgentCredsError::InvalidKeyMaterial {
                        reason: "Ed25519 public key wrong length".into(),
                    }
                })?;
                let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    AgentCredsError::InvalidKeyMaterial {
                        reason: e.to_string(),
                    }
                })?;
                let sig_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
                    AgentCredsError::InvalidDidSignature {
                        reason: "signature wrong length".into(),
                    }
                })?;
                let sig = Signature::from_bytes(&sig_bytes);
                vk.verify(message, &sig)
                    .map_err(|e| AgentCredsError::InvalidDidSignature {
                        reason: e.to_string(),
                    })
            }
            KeyAlgorithm::P256 => {
                use p256::ecdsa::{signature::Verifier as EcdsaVerifier, DerSignature};
                let vk = P256VerifyingKey::from_sec1_bytes(&self.bytes).map_err(|e| {
                    AgentCredsError::InvalidKeyMaterial {
                        reason: e.to_string(),
                    }
                })?;
                let sig = DerSignature::from_bytes(signature_bytes).map_err(|e| {
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

/// Domain-separation tag for the delegation-subkey attestation. The agent's
/// primary identity key signs this tag followed by the Ed25519 delegation
/// public key, binding that key (which signs Biscuit delegation blocks) to the
/// agent's DID. Biscuit is Ed25519-only, so a P-256 agent still delegates via
/// an Ed25519 subkey - the attestation is what ties it back to the identity.
pub(crate) const DELEGATION_KEY_DOMAIN: &[u8] = b"agentcreds-delegation-key-v1";

/// The exact bytes a primary identity key signs to attest a delegation key.
pub(crate) fn delegation_attestation_message(delegation_public: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DELEGATION_KEY_DOMAIN.len() + delegation_public.len());
    m.extend_from_slice(DELEGATION_KEY_DOMAIN);
    m.extend_from_slice(delegation_public);
    m
}

/// Verify that `delegation_public` was attested by the primary key of `did`,
/// binding a Biscuit block signer (an Ed25519 delegation key) to a real agent
/// DID without trusting any self-asserted fact.
///
/// For `did:key` the primary key is in the identifier; for a non-`did:key` DID
/// (e.g. `did:web`) it is recovered by resolving the DID document through
/// `resolver`.
///
/// # Errors
/// `ResolverRequired` if a non-`did:key` DID is presented without a resolver;
/// `DidResolutionFailed` if resolution or key extraction fails;
/// `InvalidDidSignature` if the attestation does not verify.
pub(crate) fn verify_delegation_attestation_resolved(
    did: &str,
    delegation_public: &[u8],
    attestation: &[u8],
    resolver: Option<&dyn DidResolver>,
) -> Result<()> {
    let primary = if did.starts_with("did:key:") {
        PublicKey::from_did_key(did)?
    } else {
        let resolver = resolver.ok_or_else(|| AgentCredsError::ResolverRequired {
            method: did.split(':').nth(1).unwrap_or("unknown").to_string(),
        })?;
        let document = resolver.resolve(did)?;
        public_key_from_did_document(did, &document)?
    };
    primary.verify(
        &delegation_attestation_message(delegation_public),
        attestation,
    )
}

/// Extract the primary verification-method public key from a resolved DID
/// document (the multicodec-prefixed multibase, mapped by VM type).
pub(crate) fn public_key_from_did_document(did: &str, document: &DidDocument) -> Result<PublicKey> {
    let vm = document.verification_method.first().ok_or_else(|| {
        AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "resolved DID document has no verification method".into(),
        }
    })?;
    let bytes = crate::registry::decode_multibase(&vm.public_key_multibase).map_err(|reason| {
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
                reason: format!("unsupported verification method type: {other}"),
            })
        }
    };
    let prefix: &[u8] = match algorithm {
        KeyAlgorithm::Ed25519 => &[0xed, 0x01],
        KeyAlgorithm::P256 => &[0x12, 0x00],
    };
    let bytes = bytes
        .strip_prefix(prefix)
        .ok_or_else(|| AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "unexpected multicodec prefix on the public key".into(),
        })?
        .to_vec();
    Ok(PublicKey { algorithm, bytes })
}

fn bs58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = vec![0u32];
    for &byte in input {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &d in digits.iter().rev() {
        result.push(ALPHABET[d as usize] as char);
    }
    result
}

// -- DID Document -------------------------------------------------------------

/// W3C DID Document (simplified - full JSON-LD in production via `ssi` crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context URIs.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID that this document describes.
    pub id: String,
    /// Verification methods (public keys) listed in this document.
    ///
    /// The `alias` accepts the **W3C DID Core spelling**, which is what a conforming
    /// `did:web` document actually carries. Without it `WebResolver` - which
    /// deserialises straight into this type - rejected every spec-conforming document
    /// with "missing field `verification_method`". `UniversalResolver` never hit this
    /// because it maps through its own camelCase DTO first.
    ///
    /// `alias` rather than `rename`: `rename` would also change what this type
    /// *emits*, and anything that has persisted or transmitted the current form would
    /// stop round-tripping. Accepting both spellings fixes resolution without touching
    /// the wire format. Whether documents should also be *emitted* in the spec
    /// spelling is a separate decision - see the note on `DidDocument`.
    #[serde(alias = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Verification method references allowed for authentication.
    pub authentication: Vec<String>,
    /// Verification method references allowed for assertion (VC signing).
    #[serde(alias = "assertionMethod")]
    pub assertion_method: Vec<String>,
    /// Verification method references allowed to sign delegation blocks
    /// (the Ed25519 Biscuit delegation subkey).
    #[serde(default, alias = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,
    /// When this DID document was created.
    pub created: DateTime<Utc>,
    /// When this DID document was last updated.
    pub updated: DateTime<Utc>,
}

/// A verification method entry in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Identifier for this key within the DID document (e.g. `did:key:z...#key-1`).
    pub id: String,
    /// Verification method type (e.g. `Ed25519VerificationKey2020`).
    pub r#type: String,
    /// DID of the entity that controls this key.
    pub controller: String,
    /// Multibase-encoded public key bytes (base58btc prefix `z`).
    ///
    /// Accepts the W3C spelling too - see the note on
    /// [`DidDocument::verification_method`].
    #[serde(alias = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl DidDocument {
    /// Resolve the primary verification key from this document.
    pub fn primary_key_multibase(&self) -> Option<&str> {
        self.verification_method
            .first()
            .map(|vm| vm.public_key_multibase.as_str())
    }
}

// -- AgentIdentity -------------------------------------------------------------

/// A complete agent identity: DID + key pair.
///
/// The private key is zeroized on drop. Never serialize this struct -
/// use `did()` and `document()` to extract the public components.
pub struct AgentIdentity {
    did: String,
    document: DidDocument,
    algorithm: KeyAlgorithm,
    /// Ed25519 private key bytes (zeroized on drop).
    signing_key_ed25519: Option<ZeroizingKey>,
    /// P-256 private key bytes (zeroized on drop).
    signing_key_p256: Option<ZeroizingKey>,
    /// Ed25519 delegation subkey (secret) used to sign Biscuit delegation
    /// blocks. Always present and always Ed25519, even when the primary
    /// identity key is P-256. Zeroized on drop.
    delegation_key_ed25519: ZeroizingKey,
    /// Public half of the delegation subkey (32 bytes).
    delegation_public: Vec<u8>,
    /// Primary-key signature over `DELEGATION_KEY_DOMAIN || delegation_public`,
    /// binding the delegation key to this agent's DID.
    delegation_attestation: Vec<u8>,
    /// Cached verifying key.
    public_key: PublicKey,
}

impl AgentIdentity {
    /// Create a new agent identity with the given DID method and key algorithm.
    ///
    /// # Arguments
    /// * `method`    - DID method to use (`Key` for ephemeral, `Web` for org-anchored)
    /// * `algorithm` - Key algorithm (`Ed25519` default, `P256` for FIPS environments)
    ///
    /// # Example
    /// ```rust,no_run
    /// # use agentcreds_core::did::{AgentIdentity, DidMethod, KeyAlgorithm};
    /// let identity = AgentIdentity::create(DidMethod::Key, None)?;
    /// println!("{}", identity.did());
    /// # Ok::<(), agentcreds_core::error::AgentCredsError>(())
    /// ```
    pub fn create(method: DidMethod, algorithm: Option<KeyAlgorithm>) -> Result<Self> {
        let algo = algorithm.unwrap_or_default();
        match algo {
            KeyAlgorithm::Ed25519 => Self::create_ed25519(method),
            KeyAlgorithm::P256 => Self::create_p256(method),
        }
    }

    /// Generate a fresh Ed25519 delegation subkey, returning its
    /// `(secret_bytes, public_bytes)`.
    fn generate_delegation_key() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (sk.to_bytes().to_vec(), pk)
    }

    fn create_ed25519(method: DidMethod) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes().to_vec();

        let public_key = PublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: pub_bytes.clone(),
        };

        // Ed25519 delegation subkey, attested by the primary key.
        let (deleg_secret, deleg_public) = Self::generate_delegation_key();
        let attestation = signing_key
            .sign(&delegation_attestation_message(&deleg_public))
            .to_bytes()
            .to_vec();

        let did = Self::derive_did(&method, &public_key)?;
        let document = Self::build_document(&did, &public_key, &deleg_public);
        let raw: [u8; SECRET_KEY_LENGTH] = signing_key.to_bytes();

        Ok(AgentIdentity {
            did,
            document,
            algorithm: KeyAlgorithm::Ed25519,
            signing_key_ed25519: Some(ZeroizingKey(raw.to_vec())),
            signing_key_p256: None,
            delegation_key_ed25519: ZeroizingKey(deleg_secret),
            delegation_public: deleg_public,
            delegation_attestation: attestation,
            public_key,
        })
    }

    fn create_p256(method: DidMethod) -> Result<Self> {
        use p256::ecdsa::{signature::Signer as EcdsaSigner, DerSignature};
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = P256VerifyingKey::from(&signing_key);
        // Compressed SEC1 encoding
        let pub_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();

        let public_key = PublicKey {
            algorithm: KeyAlgorithm::P256,
            bytes: pub_bytes,
        };

        // Ed25519 delegation subkey (Biscuit is Ed25519-only), attested with
        // the agent's P-256 primary key.
        let (deleg_secret, deleg_public) = Self::generate_delegation_key();
        let der: DerSignature = signing_key.sign(&delegation_attestation_message(&deleg_public));
        let attestation = der.to_bytes().to_vec();

        let did = Self::derive_did(&method, &public_key)?;
        let document = Self::build_document(&did, &public_key, &deleg_public);
        let raw = signing_key.to_bytes().to_vec();

        Ok(AgentIdentity {
            did,
            document,
            algorithm: KeyAlgorithm::P256,
            signing_key_ed25519: None,
            signing_key_p256: Some(ZeroizingKey(raw)),
            delegation_key_ed25519: ZeroizingKey(deleg_secret),
            delegation_public: deleg_public,
            delegation_attestation: attestation,
            public_key,
        })
    }

    fn derive_did(method: &DidMethod, public_key: &PublicKey) -> Result<String> {
        match method {
            DidMethod::Key => Ok(format!("did:key:{}", public_key.to_multibase())),
            DidMethod::Web { host, path } => {
                let path_part = path
                    .as_deref()
                    .map(|p| format!(":{}", p.trim_matches('/').replace('/', ":")))
                    .unwrap_or_default();
                Ok(format!("did:web:{}{}", host, path_part))
            }
            DidMethod::Cheqd { network, unique_id } => {
                Ok(format!("did:cheqd:{}:{}", network, unique_id))
            }
            DidMethod::Indy {
                namespace,
                unique_id,
            } => Ok(format!("did:indy:{}:{}", namespace, unique_id)),
        }
    }

    fn build_document(did: &str, public_key: &PublicKey, delegation_public: &[u8]) -> DidDocument {
        let vm_id = format!("{}#key-1", did);
        let vm_type = match public_key.algorithm {
            KeyAlgorithm::Ed25519 => "Ed25519VerificationKey2020",
            KeyAlgorithm::P256 => "EcdsaSecp256r1VerificationKey2019",
        };

        let vm = VerificationMethod {
            id: vm_id.clone(),
            r#type: vm_type.to_string(),
            controller: did.to_string(),
            public_key_multibase: public_key.to_multibase(),
        };

        // Second verification method: the Ed25519 delegation subkey, used to
        // sign Biscuit delegation blocks. Listed under `capabilityDelegation`.
        let deleg_vm_id = format!("{}#deleg-1", did);
        let deleg_pub = PublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: delegation_public.to_vec(),
        };
        let deleg_vm = VerificationMethod {
            id: deleg_vm_id.clone(),
            r#type: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase: deleg_pub.to_multibase(),
        };

        let now = Utc::now();
        DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://w3id.org/security/suites/ed25519-2020/v1".into(),
            ],
            id: did.to_string(),
            verification_method: vec![vm, deleg_vm],
            authentication: vec![vm_id.clone()],
            assertion_method: vec![vm_id],
            capability_delegation: vec![deleg_vm_id],
            created: now,
            updated: now,
        }
    }

    /// The agent's DID string (e.g. `did:key:z6Mk...`).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The agent's public DID document.
    pub fn document(&self) -> &DidDocument {
        &self.document
    }

    /// The agent's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The key algorithm in use.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Sign arbitrary bytes with this identity's private key.
    /// Returns raw signature bytes.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            KeyAlgorithm::Ed25519 => {
                let raw = self.signing_key_ed25519.as_ref().ok_or(
                    AgentCredsError::InvalidKeyMaterial {
                        reason: "Ed25519 key not initialized".into(),
                    },
                )?;
                let key_bytes: [u8; SECRET_KEY_LENGTH] = raw.0[..SECRET_KEY_LENGTH]
                    .try_into()
                    .map_err(|_| AgentCredsError::InvalidKeyMaterial {
                        reason: "Ed25519 key wrong length".into(),
                    })?;
                let signing_key = SigningKey::from_bytes(&key_bytes);
                let sig: Signature = signing_key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            KeyAlgorithm::P256 => {
                use p256::ecdsa::{signature::Signer as EcdsaSigner, DerSignature};
                let raw =
                    self.signing_key_p256
                        .as_ref()
                        .ok_or(AgentCredsError::InvalidKeyMaterial {
                            reason: "P-256 key not initialized".into(),
                        })?;
                let key = P256SigningKey::from_slice(&raw.0).map_err(|e| {
                    AgentCredsError::CryptoError {
                        reason: e.to_string(),
                    }
                })?;
                let sig: DerSignature = key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }

    /// Verify a signature produced by `sign()` over `message`.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        self.public_key.verify(message, signature_bytes)
    }

    /// Raw Ed25519 delegation secret-key bytes (32). Crate-internal: used to
    /// build the Biscuit signing keypair that mints/attenuates delegation
    /// tokens. Never exposed beyond the crate.
    pub(crate) fn delegation_secret_bytes(&self) -> &[u8] {
        &self.delegation_key_ed25519.0
    }

    /// Public half of this agent's Ed25519 delegation subkey (32 bytes). This
    /// is the key that signs the agent's Biscuit delegation block, bound to the
    /// agent's DID by [`AgentIdentity::delegation_attestation`].
    pub fn delegation_public_key(&self) -> &[u8] {
        &self.delegation_public
    }

    /// The primary-key attestation binding this agent's delegation subkey to
    /// its DID. Travels with each delegation hop so a verifier can prove the
    /// Biscuit block signer really is this agent.
    pub fn delegation_attestation(&self) -> &[u8] {
        &self.delegation_attestation
    }

    /// Derive a content-addressed fingerprint of this identity.
    /// Used as a stable identifier in audit logs.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.did.as_bytes());
        hasher.update(&self.public_key.bytes);
        hex::encode(hasher.finalize())
    }
}

impl fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("did", &self.did)
            .field("algorithm", &self.algorithm)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

// -- Anchor signer -----------------------------------------------------------

/// A pluggable signing backend for a [`TrustAnchor`]. Abstracts *where* the
/// anchor's private key lives: in software ([`SoftwareSigner`], the default), or
/// in an external HSM / KMS via a host-provided implementation.
///
/// Verification needs only the public key, so it always stays in the offline
/// core; only [`AnchorSigner::sign`] may reach out to an external service in a
/// custom implementation. Implementations must be shareable (`Send + Sync`).
///
/// To use an HSM/KMS, implement this trait (in a crate that has the relevant
/// SDK - keeping `agentcreds-core` offline) and pass it to
/// [`TrustAnchor::from_signer`]. The public key is fetched once at construction;
/// `sign` delegates each issuance/revocation signature to the external key.
pub trait AnchorSigner: Send + Sync {
    /// The signing key's algorithm.
    fn algorithm(&self) -> KeyAlgorithm;

    /// The public key - used to derive the DID and to verify signatures.
    fn public_key(&self) -> &PublicKey;

    /// Sign `message`, returning raw signature bytes in the crate's convention
    /// (Ed25519: 64-byte raw; P-256: DER).
    ///
    /// # Errors
    /// Implementation-defined - e.g. an HSM/KMS transport or authorization failure.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// The default in-process signer: the private key lives in software and is
/// zeroized on drop. Backs [`TrustAnchor::generate`] / [`TrustAnchor::create`].
pub struct SoftwareSigner {
    identity: AgentIdentity,
}

impl SoftwareSigner {
    /// Generate a fresh `did:key` software signing key.
    ///
    /// # Errors
    /// Propagates key-generation failure.
    pub fn generate(algorithm: Option<KeyAlgorithm>) -> Result<Self> {
        Ok(SoftwareSigner {
            identity: AgentIdentity::create(DidMethod::Key, algorithm)?,
        })
    }

    /// Wrap an existing identity's key as a software signer.
    pub fn from_identity(identity: AgentIdentity) -> Self {
        SoftwareSigner { identity }
    }
}

impl AnchorSigner for SoftwareSigner {
    fn algorithm(&self) -> KeyAlgorithm {
        self.identity.algorithm()
    }
    fn public_key(&self) -> &PublicKey {
        self.identity.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.identity.sign(message)
    }
}

/// An [`AnchorSigner`] that holds only a public key, for building a verify-only
/// [`TrustAnchor`] from a known DID. Signing returns an error.
struct PublicOnlySigner {
    public_key: PublicKey,
}

impl AnchorSigner for PublicOnlySigner {
    fn algorithm(&self) -> KeyAlgorithm {
        self.public_key.algorithm
    }
    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        Err(AgentCredsError::CryptoError {
            reason: "verify-only trust anchor has no private key and cannot sign".into(),
        })
    }
}

/// Build a minimal anchor DID document: a single verification method, no
/// delegation subkey (an anchor issues credentials, it does not delegate).
fn build_anchor_document(did: &str, public_key: &PublicKey) -> DidDocument {
    let vm_id = format!("{did}#key-1");
    let vm_type = match public_key.algorithm {
        KeyAlgorithm::Ed25519 => "Ed25519VerificationKey2020",
        KeyAlgorithm::P256 => "EcdsaSecp256r1VerificationKey2019",
    };
    let now = Utc::now();
    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/ed25519-2020/v1".into(),
        ],
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: vm_id.clone(),
            r#type: vm_type.to_string(),
            controller: did.to_string(),
            public_key_multibase: public_key.to_multibase(),
        }],
        authentication: vec![vm_id.clone()],
        assertion_method: vec![vm_id],
        capability_delegation: vec![],
        created: now,
        updated: now,
    }
}

// -- TrustAnchor ---------------------------------------------------------------

/// An organizational trust anchor - the root of all credential issuance.
///
/// Enterprises deploy one TrustAnchor per environment (prod/staging).
/// The public key is registered in the verifiable data registry.
/// The private key lives in an HSM in production - this implementation
/// uses software keys for development and testing.
pub struct TrustAnchor {
    signer: Box<dyn AnchorSigner>,
    did: String,
    document: DidDocument,
}

impl TrustAnchor {
    /// Create a new software-backed trust anchor with the specified DID method.
    ///
    /// For ledger-backed DID methods such as `did:cheqd` and `did:indy`, a
    /// resolver parameter is expected when publication / external resolution
    /// is required by the hosting environment.
    ///
    /// To back the anchor with an HSM/KMS instead of software keys, use
    /// [`TrustAnchor::from_signer`].
    pub fn create(
        method: DidMethod,
        algorithm: Option<KeyAlgorithm>,
        _resolver: Option<&dyn DidResolver>,
    ) -> Result<Self> {
        if matches!(method, DidMethod::Cheqd { .. } | DidMethod::Indy { .. }) && _resolver.is_none()
        {
            return Err(AgentCredsError::ResolverRequired {
                method: method.to_string(),
            });
        }

        let identity = AgentIdentity::create(method, algorithm)?;
        Ok(TrustAnchor::from_identity(identity))
    }

    /// Convenience constructor for a `did:key` / Ed25519 trust anchor.
    /// Intended for tests and local development; production should use `create()`.
    pub fn generate() -> Result<Self> {
        TrustAnchor::create(DidMethod::Key, Some(KeyAlgorithm::Ed25519), None)
    }

    /// Create a software-backed trust anchor from an existing identity.
    pub fn from_identity(identity: AgentIdentity) -> Self {
        let did = identity.did().to_string();
        let document = identity.document().clone();
        TrustAnchor {
            signer: Box::new(SoftwareSigner::from_identity(identity)),
            did,
            document,
        }
    }

    /// Create a trust anchor from a custom [`AnchorSigner`] - e.g. a key held in
    /// an HSM or cloud KMS. The DID is `did:key`, derived from the signer's
    /// public key; signing each credential/revocation list is delegated to the
    /// signer (which may call out to the HSM/KMS), while verification stays
    /// offline in the core.
    pub fn from_signer(signer: Box<dyn AnchorSigner>) -> Self {
        let did = format!("did:key:{}", signer.public_key().to_multibase());
        let document = build_anchor_document(&did, signer.public_key());
        TrustAnchor {
            signer,
            did,
            document,
        }
    }

    /// Construct a **verify-only** anchor from a `did:key` (no private key).
    ///
    /// Use this to verify credentials/signatures against a known anchor DID -
    /// e.g. the current key reached by following a
    /// [`KeyHistory`](crate::rotation::KeyHistory). Signing operations on the
    /// returned anchor return an error. Only `did:key` is supported (the public
    /// key is embedded in the identifier).
    ///
    /// # Errors
    /// If `did` is not a parseable `did:key`.
    pub fn from_did_key(did: &str) -> Result<Self> {
        let public_key = PublicKey::from_did_key(did)?;
        let did = did.to_string();
        let document = build_anchor_document(&did, &public_key);
        Ok(TrustAnchor {
            signer: Box::new(PublicOnlySigner { public_key }),
            did,
            document,
        })
    }

    /// The DID of this trust anchor.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The public key of this trust anchor.
    pub fn public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    /// The trust anchor's public DID document.
    pub fn document(&self) -> &DidDocument {
        &self.document
    }

    /// The key algorithm used by this trust anchor.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.signer.algorithm()
    }

    /// Sign a payload on behalf of the trust anchor (delegated to the signer). Used for
    /// anchor-signed artifacts beyond credentials - e.g. step-up approval grants the PEP
    /// verifies offline via [`verify_signature`](Self::verify_signature).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign(message)
    }

    /// Verify a signature against this trust anchor's public key.
    pub fn verify_signature(&self, message: &[u8], sig: &[u8]) -> Result<()> {
        self.signer.public_key().verify(message, sig)
    }
}

impl fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("did", &self.did)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Crypto-agility tripwire: this match is intentionally exhaustive (no `_`
    /// arm). Adding a `KeyAlgorithm` variant fails to compile here, pointing the
    /// implementer at the migration checklist on the enum.
    #[test]
    fn key_algorithm_variants_are_exhaustively_handled() {
        for alg in [KeyAlgorithm::Ed25519, KeyAlgorithm::P256] {
            match alg {
                KeyAlgorithm::Ed25519 | KeyAlgorithm::P256 => {
                    // A round-trip through a real key proves the variant is wired
                    // into create -> did:key encode -> recover -> verify.
                    let id = AgentIdentity::create(DidMethod::Key, Some(alg)).unwrap();
                    assert_eq!(id.algorithm(), alg);
                    let pk = PublicKey::from_did_key(id.did()).unwrap();
                    assert_eq!(pk.algorithm, alg);
                }
            }
        }
    }

    #[test]
    fn create_did_key_ed25519() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert!(id.did().starts_with("did:key:z"));
        assert_eq!(id.algorithm(), KeyAlgorithm::Ed25519);
    }

    #[test]
    fn create_did_key_p256() {
        let id = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
        assert!(id.did().starts_with("did:key:z"));
        assert_eq!(id.algorithm(), KeyAlgorithm::P256);
    }

    #[test]
    fn create_did_web() {
        let id = AgentIdentity::create(
            DidMethod::Web {
                host: "example.com".into(),
                path: Some("agents/test".into()),
            },
            None,
        )
        .unwrap();
        assert!(id.did().starts_with("did:web:example.com"));
    }

    #[test]
    fn sign_and_verify_round_trip_ed25519() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let message = b"hello agentcreds";
        let sig = id.sign(message).unwrap();
        assert!(id.verify(message, &sig).is_ok());
    }

    #[test]
    fn sign_and_verify_round_trip_p256() {
        let id = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
        let message = b"hello agentcreds p256";
        let sig = id.sign(message).unwrap();
        assert!(id.verify(message, &sig).is_ok());
    }

    #[test]
    fn signature_rejects_tampered_message() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let sig = id.sign(b"original").unwrap();
        assert!(id.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn did_document_structure() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let doc = id.document();
        assert_eq!(doc.id, id.did());
        assert!(!doc.verification_method.is_empty());
        assert!(!doc.authentication.is_empty());
    }

    #[test]
    fn fingerprint_is_deterministic() {
        // Same identity -> same fingerprint every call
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert_eq!(id.fingerprint(), id.fingerprint());
    }

    #[test]
    fn trust_anchor_sign_verify() {
        let anchor = TrustAnchor::generate().unwrap();
        let msg = b"trust anchor test";
        let sig = anchor.sign(msg).unwrap();
        assert!(anchor.verify_signature(msg, &sig).is_ok());
    }

    #[test]
    fn debug_redacts_private_key() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let debug_str = format!("{:?}", id);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("signing_key_ed25519: Some"));
    }

    #[test]
    fn resolver_required_for_cheqd_without_resolver() {
        let result = TrustAnchor::create(
            DidMethod::Cheqd {
                network: CheqdNetwork::Testnet,
                unique_id: "abc123".into(),
            },
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(AgentCredsError::ResolverRequired { .. })
        ));
    }

    #[test]
    fn resolver_required_for_indy_without_resolver() {
        let result = TrustAnchor::create(
            DidMethod::Indy {
                namespace: "sovrin:main".into(),
                unique_id: "abc123".into(),
            },
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(AgentCredsError::ResolverRequired { .. })
        ));
    }

    #[test]
    fn trust_anchor_generate_creates_key_did() {
        let anchor = TrustAnchor::generate().unwrap();
        assert!(anchor.did().starts_with("did:key:"));
    }

    #[test]
    fn trust_anchor_from_identity_preserves_did() {
        let identity = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let expected_did = identity.did().to_string();
        let anchor = TrustAnchor::from_identity(identity);
        assert_eq!(anchor.did(), expected_did);
    }

    #[test]
    fn trust_anchor_debug_redacts_key() {
        let anchor = TrustAnchor::generate().unwrap();
        let debug_str = format!("{:?}", anchor);
        assert_eq!(
            debug_str,
            format!(
                "TrustAnchor {{ did: {:?}, signing_key: \"[REDACTED]\" }}",
                anchor.did()
            )
        );
    }

    /// A custom signer (standing in for an HSM/KMS-backed key) plugs in via
    /// `from_signer`, and an anchor built on it signs and verifies normally.
    #[test]
    fn trust_anchor_from_custom_signer_signs_and_verifies() {
        struct ExternalSigner {
            identity: AgentIdentity,
        }
        impl AnchorSigner for ExternalSigner {
            fn algorithm(&self) -> KeyAlgorithm {
                self.identity.algorithm()
            }
            fn public_key(&self) -> &PublicKey {
                self.identity.public_key()
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                // A real impl would call out to the HSM/KMS here.
                self.identity.sign(message)
            }
        }

        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let expected_did = id.did().to_string();
        let anchor = TrustAnchor::from_signer(Box::new(ExternalSigner { identity: id }));

        // DID is did:key derived from the signer's public key.
        assert!(anchor.did().starts_with("did:key:z"));
        assert_eq!(anchor.did(), expected_did);
        assert_eq!(anchor.document().id, expected_did);

        // Signs and verifies like any anchor.
        let sig = anchor.sign(b"payload").unwrap();
        assert!(anchor.verify_signature(b"payload", &sig).is_ok());
        assert!(anchor.verify_signature(b"tampered", &sig).is_err());
    }

    /// End-to-end: an external-signer anchor issues a credential that verifies
    /// against it - nothing downstream assumes a software key.
    #[test]
    fn custom_signer_anchor_issues_verifiable_credential() {
        use crate::vc::{CapabilityClaims, CapabilityCredential};

        struct ExternalSigner {
            identity: AgentIdentity,
        }
        impl AnchorSigner for ExternalSigner {
            fn algorithm(&self) -> KeyAlgorithm {
                self.identity.algorithm()
            }
            fn public_key(&self) -> &PublicKey {
                self.identity.public_key()
            }
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                self.identity.sign(message)
            }
        }

        let key = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let anchor = TrustAnchor::from_signer(Box::new(ExternalSigner { identity: key }));
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        assert!(vc.verify(&anchor, true).is_ok());
    }

    #[test]
    fn two_identities_have_different_fingerprints() {
        let id1 = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let id2 = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert_ne!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn did_key_multibase_prefix_is_z() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert!(id.did().starts_with("did:key:z"));
        let vm = &id.document().verification_method[0];
        assert!(vm.public_key_multibase.starts_with('z'));
    }

    #[test]
    fn did_cheqd_derives_correct_format() {
        let id = AgentIdentity::create(
            DidMethod::Cheqd {
                network: CheqdNetwork::Testnet,
                unique_id: "test123xyz".into(),
            },
            None,
        )
        .unwrap();
        assert_eq!(id.did(), "did:cheqd:testnet:test123xyz");
    }

    #[test]
    fn did_indy_derives_correct_format() {
        let id = AgentIdentity::create(
            DidMethod::Indy {
                namespace: "sovrin:main".into(),
                unique_id: "WRfXPg8abc".into(),
            },
            None,
        )
        .unwrap();
        assert_eq!(id.did(), "did:indy:sovrin:main:WRfXPg8abc");
    }

    #[test]
    fn did_document_primary_key_is_some() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let doc = id.document();
        assert!(doc.primary_key_multibase().is_some());
        assert!(doc.primary_key_multibase().unwrap().starts_with('z'));
    }

    #[test]
    fn verification_method_type_ed25519() {
        let id = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vm = &id.document().verification_method[0];
        assert_eq!(vm.r#type, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, id.did());
    }

    #[test]
    fn verification_method_type_p256() {
        let id = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
        let vm = &id.document().verification_method[0];
        assert_eq!(vm.r#type, "EcdsaSecp256r1VerificationKey2019");
    }

    #[test]
    fn cross_verify_wrong_identity_rejects_signature() {
        let id1 = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let id2 = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let sig = id1.sign(b"some payload").unwrap();
        assert!(id2.verify(b"some payload", &sig).is_err());
    }

    #[test]
    fn did_web_with_path_derives_correct_format() {
        let id = AgentIdentity::create(
            DidMethod::Web {
                host: "example.com".into(),
                path: Some("users/alice".into()),
            },
            None,
        )
        .unwrap();
        assert!(id.did().starts_with("did:web:example.com:users:alice"));
    }

    #[test]
    fn cheqd_network_display() {
        assert_eq!(CheqdNetwork::Mainnet.to_string(), "mainnet");
        assert_eq!(CheqdNetwork::Testnet.to_string(), "testnet");
    }

    #[cfg(feature = "proptest")]
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        fn host_strategy() -> impl Strategy<Value = String> {
            "[a-z][a-z0-9]{0,8}(\\.[a-z][a-z0-9]{0,8}){0,2}"
        }

        fn segment_strategy() -> impl Strategy<Value = String> {
            "[a-z0-9]{1,8}"
        }

        proptest! {
            /// did:web DIDs are `did:web:{host}` or `did:web:{host}:{seg1}:{seg2}:...`,
            /// and the path segments are recoverable in order.
            #[test]
            fn did_web_path_segments_round_trip(
                host in host_strategy(),
                segments in proptest::collection::vec(segment_strategy(), 0..4),
            ) {
                let path = if segments.is_empty() { None } else { Some(segments.join("/")) };
                let id = AgentIdentity::create(
                    DidMethod::Web { host: host.clone(), path },
                    None,
                ).unwrap();

                let suffix = id.did().strip_prefix("did:web:").unwrap().to_string();
                let mut parts = suffix.split(':');
                prop_assert_eq!(parts.next(), Some(host.as_str()));
                let recovered: Vec<String> = parts.map(String::from).collect();
                prop_assert_eq!(recovered, segments);
            }

            /// did:cheqd DIDs are `did:cheqd:{network}:{unique_id}`, and the
            /// unique_id (even if it contains ':') is recoverable via split_once.
            #[test]
            fn did_cheqd_round_trip(
                network in prop_oneof![Just(CheqdNetwork::Mainnet), Just(CheqdNetwork::Testnet)],
                unique_id in "[a-zA-Z0-9:]{1,16}",
            ) {
                let id = AgentIdentity::create(
                    DidMethod::Cheqd { network, unique_id: unique_id.clone() },
                    None,
                ).unwrap();

                prop_assert_eq!(id.did().to_string(), format!("did:cheqd:{}:{}", network, unique_id));

                let suffix = id.did().strip_prefix("did:cheqd:").unwrap().to_string();
                let (recovered_network, recovered_id) = suffix.split_once(':').unwrap();
                prop_assert_eq!(recovered_network.to_string(), network.to_string());
                prop_assert_eq!(recovered_id.to_string(), unique_id);
            }

            /// did:indy DIDs are `did:indy:{namespace}:{unique_id}`.
            #[test]
            fn did_indy_round_trip(
                namespace in "[a-z]{1,8}",
                unique_id in "[a-zA-Z0-9]{1,16}",
            ) {
                let id = AgentIdentity::create(
                    DidMethod::Indy { namespace: namespace.clone(), unique_id: unique_id.clone() },
                    None,
                ).unwrap();
                prop_assert_eq!(id.did().to_string(), format!("did:indy:{}:{}", namespace, unique_id));
            }

            /// Encoding a public key as multibase and decoding it back returns the
            /// original multicodec-prefixed bytes (Ed25519: 0xed01 prefix).
            #[test]
            fn multibase_round_trips_ed25519(bytes in proptest::collection::vec(any::<u8>(), 32)) {
                let pk = PublicKey { algorithm: KeyAlgorithm::Ed25519, bytes: bytes.clone() };
                let encoded = pk.to_multibase();
                prop_assert!(encoded.starts_with('z'));

                let mut expected = vec![0xed, 0x01];
                expected.extend_from_slice(&bytes);
                prop_assert_eq!(crate::registry::decode_multibase(&encoded).unwrap(), expected);
            }

            /// Same round trip for P-256 (multicodec prefix 0x1200).
            #[test]
            fn multibase_round_trips_p256(bytes in proptest::collection::vec(any::<u8>(), 33)) {
                let pk = PublicKey { algorithm: KeyAlgorithm::P256, bytes: bytes.clone() };
                let encoded = pk.to_multibase();
                prop_assert!(encoded.starts_with('z'));

                let mut expected = vec![0x12, 0x00];
                expected.extend_from_slice(&bytes);
                prop_assert_eq!(crate::registry::decode_multibase(&encoded).unwrap(), expected);
            }
        }
    }

    // -- Method rendering, key material, and document resolution --------------
    //
    // Found unexercised by a production-only coverage audit on 2026-08-08. Three
    // clusters, all on the boundary where untrusted bytes become an identity:
    //
    //   * `Display for DidMethod` composes the DID string an identity is created under.
    //     A wrong separator here produces a DID that resolves nowhere, at issuance time.
    //   * `from_did_key` / `verify` turn attacker-supplied bytes into a key. They must
    //     refuse rather than panic, and refuse for the RIGHT reason.
    //   * `public_key_from_did_document` picks the algorithm from the document's own
    //     method type - the P-256 branch had never run, and P-256 is what the deployed
    //     KMS anchors use.

    #[test]
    fn every_did_method_renders_its_canonical_string() {
        assert_eq!(DidMethod::Key.to_string(), "did:key");
        assert_eq!(
            DidMethod::Web {
                host: "example.com".into(),
                path: None
            }
            .to_string(),
            "did:web:example.com"
        );
        // A path is colon-separated in a DID, not slash-separated - the substitution is
        // the whole reason this arm exists.
        assert_eq!(
            DidMethod::Web {
                host: "example.com".into(),
                path: Some("agents/prod".into())
            }
            .to_string(),
            "did:web:example.com:agents:prod"
        );
        assert_eq!(
            DidMethod::Cheqd {
                network: CheqdNetwork::Testnet,
                unique_id: "abc123".into()
            }
            .to_string(),
            "did:cheqd:testnet:abc123"
        );
        assert_eq!(
            DidMethod::Indy {
                namespace: "sovrin:staging".into(),
                unique_id: "xyz".into()
            }
            .to_string(),
            "did:indy:sovrin:staging:xyz"
        );
    }

    /// `did:key` decoding must refuse an unknown multicodec prefix and a length that
    /// disagrees with the algorithm the prefix declared. Accepting either would hand a
    /// mis-sized buffer to the verifier.
    #[test]
    fn did_key_decoding_refuses_unknown_prefixes_and_wrong_lengths() {
        // Round-trip first, so the rejections below are known to differ from a good key.
        let anchor = TrustAnchor::generate().unwrap();
        let good = PublicKey::from_did_key(anchor.did()).unwrap();
        assert_eq!(good.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(good.bytes.len(), 32);

        // Not a did:key at all.
        assert!(PublicKey::from_did_key("did:web:example.com").is_err());
        assert!(PublicKey::from_did_key("").is_err());
        // Multibase that is not base58btc / not decodable.
        assert!(PublicKey::from_did_key("did:key:NOT-MULTIBASE").is_err());

        // A valid multibase whose multicodec prefix names no algorithm we support.
        let unknown = format!("z{}", bs58_encode(&[0xff, 0xff, 1, 2, 3, 4]));
        assert!(
            matches!(
                PublicKey::from_did_key(&format!("did:key:{unknown}")),
                Err(AgentCredsError::InvalidKeyMaterial { .. })
            ),
            "an unknown multicodec prefix must be refused"
        );

        // Correct Ed25519 prefix, wrong key length.
        let mut short = vec![0xed, 0x01];
        short.extend_from_slice(&[7u8; 8]);
        let short = format!("z{}", bs58_encode(&short));
        assert!(
            matches!(
                PublicKey::from_did_key(&format!("did:key:{short}")),
                Err(AgentCredsError::InvalidKeyMaterial { .. })
            ),
            "a length disagreeing with the declared algorithm must be refused"
        );

        // Correct P-256 prefix, wrong length (compressed SEC1 is 33 bytes).
        let mut p256_short = vec![0x12, 0x00];
        p256_short.extend_from_slice(&[7u8; 32]);
        let p256_short = format!("z{}", bs58_encode(&p256_short));
        assert!(PublicKey::from_did_key(&format!("did:key:{p256_short}")).is_err());
    }

    /// Signature verification must refuse mis-sized key and signature buffers on BOTH
    /// algorithms rather than truncating or padding them.
    #[test]
    fn verification_refuses_mis_sized_keys_and_signatures() {
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::P256] {
            let signer = SoftwareSigner::generate(Some(algorithm)).unwrap();
            let key = signer.public_key().clone();
            let sig = signer.sign(b"message").unwrap();

            // The control: the real key and signature verify.
            key.verify(b"message", &sig)
                .unwrap_or_else(|e| panic!("{algorithm:?} must verify its own: {e:?}"));

            // Wrong message.
            assert!(key.verify(b"other message", &sig).is_err());

            // Truncated signature.
            assert!(key.verify(b"message", &sig[..sig.len() - 1]).is_err());
            // Empty signature.
            assert!(key.verify(b"message", &[]).is_err());

            // Mis-sized key bytes for the declared algorithm.
            let bad_key = PublicKey {
                algorithm,
                bytes: vec![0u8; 7],
            };
            assert!(
                bad_key.verify(b"message", &sig).is_err(),
                "{algorithm:?} must refuse a mis-sized key"
            );
        }
    }

    /// The document's verification-method type selects the algorithm. Both supported
    /// types must resolve to the anchor's real key, and an unknown type must be refused
    /// rather than defaulted - a default would verify one algorithm under another's rules.
    #[test]
    fn document_resolution_covers_both_algorithms_and_refuses_unknown_types() {
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::P256] {
            let anchor = TrustAnchor::from_signer(Box::new(
                SoftwareSigner::generate(Some(algorithm)).unwrap(),
            ));
            let doc = anchor.document().clone();
            let key = public_key_from_did_document(anchor.did(), &doc)
                .unwrap_or_else(|e| panic!("{algorithm:?} document must resolve: {e:?}"));
            assert_eq!(key.algorithm, algorithm);
            assert_eq!(&key.bytes, &anchor.public_key().bytes);
        }

        let anchor = TrustAnchor::generate().unwrap();
        let mut doc = anchor.document().clone();
        doc.verification_method[0].r#type = "SomeFutureVerificationKey".into();
        assert!(
            matches!(
                public_key_from_did_document(anchor.did(), &doc),
                Err(AgentCredsError::DidResolutionFailed { .. })
            ),
            "an unknown verification-method type must be refused"
        );

        // A document with no verification method at all.
        let mut empty = anchor.document().clone();
        empty.verification_method.clear();
        assert!(public_key_from_did_document(anchor.did(), &empty).is_err());
    }

    /// The verify-only signer carries an algorithm and a key but cannot sign - that
    /// asymmetry is what makes it safe to rebuild an anchor from a bare DID.
    #[test]
    fn a_public_only_signer_reports_its_algorithm_and_refuses_to_sign() {
        let anchor = TrustAnchor::generate().unwrap();
        let verify_only = TrustAnchor::from_did_key(anchor.did()).unwrap();

        assert_eq!(verify_only.did(), anchor.did());
        assert_eq!(verify_only.algorithm(), KeyAlgorithm::Ed25519);
        assert_eq!(&verify_only.public_key().bytes, &anchor.public_key().bytes);
        assert!(
            verify_only.sign(b"anything").is_err(),
            "a verify-only anchor must not be able to sign"
        );

        // It still verifies what the real anchor signed - the point of having it.
        let sig = anchor.sign(b"message").unwrap();
        assert!(verify_only.public_key().verify(b"message", &sig).is_ok());
    }
}
