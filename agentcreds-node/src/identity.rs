use std::sync::Mutex;

use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::did::{
    AgentIdentity as CoreAgentIdentity, DidDocument as CoreDidDocument, DidMethod,
    InMemoryResolver as CoreInMemoryResolver, PublicKey as CorePublicKey,
    TrustAnchor as CoreTrustAnchor, VerificationMethod as CoreVerificationMethod,
};

use crate::convert::{algorithm_to_str, parse_algorithm, parse_cheqd_network};
use crate::error::{invalid_arg, map_err};

// -- PublicKey ----------------------------------------------------------------

#[napi]
pub struct PublicKey {
    pub(crate) inner: CorePublicKey,
}

#[napi]
impl PublicKey {
    #[napi(getter)]
    pub fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm)
    }

    #[napi(getter)]
    pub fn bytes(&self) -> Buffer {
        Buffer::from(self.inner.bytes.clone())
    }

    #[napi]
    pub fn to_multibase(&self) -> String {
        self.inner.to_multibase()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "PublicKey(algorithm='{}', multibase='{}')",
            self.algorithm(),
            self.inner.to_multibase()
        )
    }
}

// -- VerificationMethod / DidDocument ------------------------------------------

#[napi]
pub struct VerificationMethod {
    pub(crate) inner: CoreVerificationMethod,
}

#[napi]
impl VerificationMethod {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter, js_name = "type")]
    pub fn type_(&self) -> String {
        self.inner.r#type.clone()
    }

    #[napi(getter)]
    pub fn controller(&self) -> String {
        self.inner.controller.clone()
    }

    #[napi(getter)]
    pub fn public_key_multibase(&self) -> String {
        self.inner.public_key_multibase.clone()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "VerificationMethod(id='{}', type='{}')",
            self.inner.id, self.inner.r#type
        )
    }
}

#[napi]
pub struct DidDocument {
    pub(crate) inner: CoreDidDocument,
}

#[napi]
impl DidDocument {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter)]
    pub fn context(&self) -> Vec<String> {
        self.inner.context.clone()
    }

    #[napi(getter)]
    pub fn authentication(&self) -> Vec<String> {
        self.inner.authentication.clone()
    }

    #[napi(getter)]
    pub fn assertion_method(&self) -> Vec<String> {
        self.inner.assertion_method.clone()
    }

    #[napi(getter)]
    pub fn created(&self) -> DateTime<Utc> {
        self.inner.created
    }

    #[napi(getter)]
    pub fn updated(&self) -> DateTime<Utc> {
        self.inner.updated
    }

    #[napi(getter)]
    pub fn verification_method(&self) -> Vec<VerificationMethod> {
        self.inner
            .verification_method
            .iter()
            .cloned()
            .map(|inner| VerificationMethod { inner })
            .collect()
    }

    #[napi]
    pub fn primary_key_multibase(&self) -> Option<String> {
        self.inner.primary_key_multibase().map(String::from)
    }

    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(|e| map_err(e.into()))
    }

    #[napi]
    pub fn to_object(&self) -> Result<serde_json::Value> {
        serde_json::to_value(&self.inner).map_err(|e| map_err(e.into()))
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!("DidDocument(id='{}')", self.inner.id)
    }
}

// -- AgentIdentity -------------------------------------------------------------

#[napi]
pub struct AgentIdentity {
    pub(crate) inner: CoreAgentIdentity,
}

#[napi]
impl AgentIdentity {
    /// Create an ephemeral `did:key` identity.
    #[napi(factory)]
    pub fn create_did_key(algorithm: Option<String>) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreAgentIdentity::create(DidMethod::Key, algo).map_err(map_err)?,
        })
    }

    /// Create an org-anchored `did:web` identity.
    #[napi(factory)]
    pub fn create_did_web(
        host: String,
        path: Option<String>,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreAgentIdentity::create(DidMethod::Web { host, path }, algo)
                .map_err(map_err)?,
        })
    }

    /// Create a `did:cheqd` identity for the given network.
    #[napi(factory)]
    pub fn create_did_cheqd(
        network: String,
        unique_id: String,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let network = parse_cheqd_network(&network)?;
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreAgentIdentity::create(DidMethod::Cheqd { network, unique_id }, algo)
                .map_err(map_err)?,
        })
    }

    /// Create a `did:indy` identity within the given ledger namespace.
    #[napi(factory)]
    pub fn create_did_indy(
        namespace: String,
        unique_id: String,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreAgentIdentity::create(
                DidMethod::Indy {
                    namespace,
                    unique_id,
                },
                algo,
            )
            .map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[napi(getter)]
    pub fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm())
    }

    #[napi(getter)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key().clone(),
        }
    }

    #[napi]
    pub fn document(&self) -> DidDocument {
        DidDocument {
            inner: self.inner.document().clone(),
        }
    }

    #[napi]
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    #[napi]
    pub fn sign(&self, message: Buffer) -> Result<Buffer> {
        let sig = self.inner.sign(message.as_ref()).map_err(map_err)?;
        Ok(Buffer::from(sig))
    }

    #[napi]
    pub fn verify(&self, message: Buffer, signature: Buffer) -> Result<()> {
        self.inner
            .verify(message.as_ref(), signature.as_ref())
            .map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "AgentIdentity(did='{}', algorithm='{}')",
            self.inner.did(),
            algorithm_to_str(self.inner.algorithm())
        )
    }
}

// -- TrustAnchor ---------------------------------------------------------------

#[napi]
pub struct TrustAnchor {
    pub(crate) inner: CoreTrustAnchor,
}

#[napi]
impl TrustAnchor {
    /// Convenience constructor for a `did:key` / Ed25519 trust anchor.
    #[napi(factory)]
    pub fn generate() -> Result<Self> {
        Ok(Self {
            inner: CoreTrustAnchor::generate().map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:key` identifier.
    #[napi(factory)]
    pub fn create_did_key(algorithm: Option<String>) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreTrustAnchor::create(DidMethod::Key, algo, None).map_err(map_err)?,
        })
    }

    /// Construct a **verify-only** trust anchor from a `did:key` (no private
    /// key) - e.g. the current key reached by following a `KeyHistory`. Use it to
    /// verify credentials/signatures against a known anchor DID; signing fails.
    #[napi(factory)]
    pub fn from_did_key(did: String) -> Result<Self> {
        Ok(Self {
            inner: CoreTrustAnchor::from_did_key(&did).map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:web` identifier.
    #[napi(factory)]
    pub fn create_did_web(
        host: String,
        path: Option<String>,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        Ok(Self {
            inner: CoreTrustAnchor::create(DidMethod::Web { host, path }, algo, None)
                .map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:cheqd` identifier.
    #[napi(factory)]
    pub fn create_did_cheqd(
        network: String,
        unique_id: String,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let network = parse_cheqd_network(&network)?;
        let algo = parse_algorithm(algorithm.as_deref())?;
        let resolver = CoreInMemoryResolver::new();
        Ok(Self {
            inner: CoreTrustAnchor::create(
                DidMethod::Cheqd { network, unique_id },
                algo,
                Some(&resolver),
            )
            .map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:indy` identifier.
    #[napi(factory)]
    pub fn create_did_indy(
        namespace: String,
        unique_id: String,
        algorithm: Option<String>,
    ) -> Result<Self> {
        let algo = parse_algorithm(algorithm.as_deref())?;
        let resolver = CoreInMemoryResolver::new();
        Ok(Self {
            inner: CoreTrustAnchor::create(
                DidMethod::Indy {
                    namespace,
                    unique_id,
                },
                algo,
                Some(&resolver),
            )
            .map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[napi(getter)]
    pub fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm())
    }

    #[napi(getter)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key().clone(),
        }
    }

    #[napi]
    pub fn document(&self) -> DidDocument {
        DidDocument {
            inner: self.inner.document().clone(),
        }
    }

    #[napi]
    pub fn verify_signature(&self, message: Buffer, signature: Buffer) -> Result<()> {
        self.inner
            .verify_signature(message.as_ref(), signature.as_ref())
            .map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!("TrustAnchor(did='{}')", self.inner.did())
    }
}

// -- InMemoryResolver ----------------------------------------------------------

/// In-memory DID resolver used for tests, local development, and wiring up
/// `TrustRegistry` cross-org resolution without a network round-trip.
///
/// Once passed to `TrustRegistry.withInMemoryResolver()`, the resolver is
/// consumed and can no longer be modified.
#[napi]
pub struct InMemoryResolver {
    pub(crate) inner: Mutex<Option<CoreInMemoryResolver>>,
}

#[napi]
impl InMemoryResolver {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Some(CoreInMemoryResolver::new())),
        }
    }

    /// Register a DID document so it can be resolved later.
    #[napi]
    pub fn register(&self, did: String, document: &DidDocument) -> Result<()> {
        let mut guard = self.inner.lock().expect("InMemoryResolver mutex poisoned");
        let resolver = guard.as_mut().ok_or_else(|| {
            invalid_arg(
                "resolver has already been bound to a TrustRegistry and can no longer be modified",
            )
        })?;
        resolver.register(did, document.inner.clone());
        Ok(())
    }

    /// Convenience: register an `AgentIdentity`'s DID document under its own DID.
    #[napi]
    pub fn register_identity(&self, identity: &AgentIdentity) -> Result<()> {
        let mut guard = self.inner.lock().expect("InMemoryResolver mutex poisoned");
        let resolver = guard.as_mut().ok_or_else(|| {
            invalid_arg(
                "resolver has already been bound to a TrustRegistry and can no longer be modified",
            )
        })?;
        resolver.register(
            identity.inner.did().to_string(),
            identity.inner.document().clone(),
        );
        Ok(())
    }

    #[napi]
    pub fn to_string(&self) -> String {
        "InMemoryResolver()".to_string()
    }
}

impl Default for InMemoryResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_did_key_defaults_to_ed25519() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        assert!(agent.did().starts_with("did:key:"));
        assert_eq!(agent.algorithm(), "ed25519");
        assert!(agent.public_key().to_multibase().starts_with('z'));
    }

    #[test]
    fn create_did_key_with_p256() {
        let agent = AgentIdentity::create_did_key(Some("p256".into())).unwrap();
        assert_eq!(agent.algorithm(), "p256");
    }

    #[test]
    fn create_did_key_rejects_unknown_algorithm() {
        assert!(AgentIdentity::create_did_key(Some("rsa".into())).is_err());
    }

    #[test]
    fn agent_identity_sign_and_verify_round_trip() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let message = Buffer::from(b"hello agentcreds".to_vec());
        let signature = agent.sign(message.clone()).unwrap();
        assert!(agent.verify(message, signature).is_ok());
    }

    #[test]
    fn agent_identity_verify_rejects_tampered_message() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let message = Buffer::from(b"hello agentcreds".to_vec());
        let signature = agent.sign(message).unwrap();
        let tampered = Buffer::from(b"hello AGENTCREDS".to_vec());
        assert!(agent.verify(tampered, signature).is_err());
    }

    #[test]
    fn agent_identity_document_matches_did() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let doc = agent.document();
        assert_eq!(doc.id(), agent.did());
        assert!(!doc.verification_method().is_empty());
        let json = doc.to_json().unwrap();
        assert!(json.contains(&agent.did()));
    }

    #[test]
    fn agent_identity_fingerprint_and_to_string() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        assert!(!agent.fingerprint().is_empty());
        assert!(agent.to_string().contains(&agent.did()));
    }

    #[test]
    fn create_did_web_cheqd_and_indy() {
        let web = AgentIdentity::create_did_web("example.com".into(), None, None).unwrap();
        assert!(web.did().starts_with("did:web:example.com"));

        let cheqd =
            AgentIdentity::create_did_cheqd("testnet".into(), "abc123".into(), None).unwrap();
        assert!(cheqd.did().starts_with("did:cheqd:testnet:"));

        let indy = AgentIdentity::create_did_indy("sovrin".into(), "abc123".into(), None).unwrap();
        assert!(indy.did().starts_with("did:indy:sovrin:"));
    }

    #[test]
    fn create_did_cheqd_rejects_unknown_network() {
        assert!(AgentIdentity::create_did_cheqd("devnet".into(), "abc123".into(), None).is_err());
    }

    #[test]
    fn trust_anchor_generate_and_document() {
        let anchor = TrustAnchor::generate().unwrap();
        assert!(anchor.did().starts_with("did:key:"));
        assert_eq!(anchor.algorithm(), "ed25519");
        assert_eq!(anchor.document().id(), anchor.did());
        assert!(anchor.to_string().contains(&anchor.did()));
    }

    #[test]
    fn trust_anchor_create_did_key_with_p256() {
        let anchor = TrustAnchor::create_did_key(Some("p256".into())).unwrap();
        assert_eq!(anchor.algorithm(), "p256");
    }

    #[test]
    fn trust_anchor_create_did_web_cheqd_and_indy() {
        let web = TrustAnchor::create_did_web("example.com".into(), None, None).unwrap();
        assert!(web.did().starts_with("did:web:example.com"));

        let cheqd = TrustAnchor::create_did_cheqd("testnet".into(), "abc123".into(), None).unwrap();
        assert!(cheqd.did().starts_with("did:cheqd:testnet:"));

        let indy = TrustAnchor::create_did_indy("sovrin".into(), "abc123".into(), None).unwrap();
        assert!(indy.did().starts_with("did:indy:sovrin:"));
    }

    #[test]
    fn trust_anchor_create_did_cheqd_rejects_unknown_network() {
        assert!(TrustAnchor::create_did_cheqd("devnet".into(), "abc123".into(), None).is_err());
    }

    #[test]
    fn trust_anchor_verify_signature_rejects_garbage() {
        let anchor = TrustAnchor::generate().unwrap();
        let message = Buffer::from(b"payload".to_vec());
        let bogus_signature = Buffer::from(vec![0u8; 64]);
        assert!(anchor.verify_signature(message, bogus_signature).is_err());
    }

    #[test]
    fn in_memory_resolver_register_and_consume() {
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let resolver = InMemoryResolver::new();
        resolver.register_identity(&agent).unwrap();
        assert_eq!(resolver.to_string(), "InMemoryResolver()");
    }
}
