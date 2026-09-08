use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::registry::{
    CrossOrgVerifier, SignedTrustConfig as CoreTrustConfig, TrustEntry as CoreTrustEntry,
    TrustRegistry as CoreTrustRegistry,
};

use crate::convert::{parse_trust_level, trust_level_to_str};
use crate::credential::CapabilityCredential;
use crate::error::{invalid_arg, map_err};
use crate::identity::{InMemoryResolver, PublicKey, TrustAnchor};

// -- TrustEntry ----------------------------------------------------------------

#[napi]
pub struct TrustEntry {
    pub(crate) inner: CoreTrustEntry,
}

#[napi]
impl TrustEntry {
    /// Create a trust entry. `trustLevel` is one of `"unverified"`,
    /// `"self_asserted"`, `"verified"`, or `"authoritative"`.
    #[napi(constructor)]
    pub fn new(
        did: String,
        org_name: String,
        public_key: &PublicKey,
        trust_level: String,
    ) -> Result<Self> {
        let level = parse_trust_level(&trust_level)?;
        Ok(Self {
            inner: CoreTrustEntry::new(did, org_name, public_key.inner.clone(), level),
        })
    }

    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did.clone()
    }

    #[napi(getter)]
    pub fn org_name(&self) -> String {
        self.inner.org_name.clone()
    }

    #[napi(getter)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key.clone(),
        }
    }

    #[napi(getter)]
    pub fn did_method(&self) -> String {
        self.inner.did_method.clone()
    }

    #[napi(getter)]
    pub fn trust_level(&self) -> &'static str {
        trust_level_to_str(self.inner.trust_level)
    }

    #[napi(getter)]
    pub fn registered_at(&self) -> DateTime<Utc> {
        self.inner.registered_at
    }

    #[napi(getter)]
    pub fn revocation_endpoint(&self) -> Option<String> {
        self.inner.revocation_endpoint.clone()
    }

    /// Where this member publishes its signed key history. `None` = the member does not
    /// rotate, so its registered DID is both root and current.
    #[napi(getter)]
    pub fn key_history_url(&self) -> Option<String> {
        self.inner.key_history_url.clone()
    }

    #[napi(setter)]
    pub fn set_key_history_url(&mut self, url: Option<String>) {
        self.inner.key_history_url = url;
    }

    /// Verify a signature produced by this trust anchor's key.
    #[napi]
    pub fn verify_signature(&self, message: Buffer, signature: Buffer) -> Result<()> {
        self.inner
            .verify_signature(message.as_ref(), signature.as_ref())
            .map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "TrustEntry(did='{}', org_name='{}', trust_level='{}')",
            self.inner.did,
            self.inner.org_name,
            trust_level_to_str(self.inner.trust_level)
        )
    }
}

// -- TrustRegistry -------------------------------------------------------------

#[napi]
pub struct TrustRegistry {
    pub(crate) inner: CoreTrustRegistry,
}

#[napi]
impl TrustRegistry {
    /// Create a registry backed by a fresh, empty in-memory resolver.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreTrustRegistry::new(),
        }
    }

    /// Create a registry backed by `resolver`. The resolver is consumed -
    /// it cannot be modified or reused afterwards.
    #[napi(factory)]
    pub fn with_in_memory_resolver(resolver: &InMemoryResolver) -> Result<Self> {
        let mut guard = resolver
            .inner
            .lock()
            .expect("InMemoryResolver mutex poisoned");
        let inner = guard.take().ok_or_else(|| {
            invalid_arg(
                "resolver has already been bound to a TrustRegistry and can no longer be used",
            )
        })?;
        Ok(Self {
            inner: CoreTrustRegistry::with_resolver(Box::new(inner)),
        })
    }

    /// Minimum trust level accepted by `verifyCredential`.
    #[napi(getter)]
    pub fn minimum_trust_level(&self) -> &'static str {
        trust_level_to_str(self.inner.minimum_trust_level)
    }

    #[napi(setter)]
    pub fn set_minimum_trust_level(&mut self, level: String) -> Result<()> {
        self.inner.minimum_trust_level = parse_trust_level(&level)?;
        Ok(())
    }

    /// Register a trust anchor entry.
    #[napi]
    pub fn register(&mut self, entry: &TrustEntry) {
        self.inner.register(entry.inner.clone());
    }

    /// Resolve a trust anchor by DID, caching the result if a resolver lookup
    /// was required.
    #[napi]
    pub fn resolve(&mut self, did: String) -> Result<TrustEntry> {
        Ok(TrustEntry {
            inner: self.inner.resolve(&did).map_err(map_err)?.clone(),
        })
    }

    /// Number of registered trust anchors.
    #[napi]
    pub fn len(&self) -> i64 {
        self.inner.len() as i64
    }

    /// True if no trust anchors are registered.
    #[napi]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All registered DIDs.
    #[napi]
    pub fn registered_dids(&self) -> Vec<String> {
        self.inner
            .registered_dids()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// Export the registry as a signed, versioned `SignedTrustConfig` sealed by
    /// `anchor` - the portable, tamper-evident artifact you persist/distribute.
    #[napi]
    pub fn export(&self, anchor: &TrustAnchor, version: i64) -> Result<SignedTrustConfig> {
        Ok(SignedTrustConfig {
            inner: self
                .inner
                .export(&anchor.inner, version as u64)
                .map_err(map_err)?,
        })
    }

    /// Build a registry from a verified signed config (in-memory resolver).
    #[napi(factory)]
    pub fn from_config(config: &SignedTrustConfig, anchor: &TrustAnchor) -> Result<Self> {
        Ok(Self {
            inner: CoreTrustRegistry::from_config(&config.inner, &anchor.inner).map_err(map_err)?,
        })
    }

    /// Merge a verified config's entries into this registry (additive).
    #[napi]
    pub fn import_config(
        &mut self,
        config: &SignedTrustConfig,
        anchor: &TrustAnchor,
    ) -> Result<()> {
        self.inner
            .import(&config.inner, &anchor.inner)
            .map_err(map_err)
    }

    /// Verify `vc` against this registry without contacting the issuer:
    /// resolves the issuer's trust entry, checks its trust level meets
    /// `minimumTrustLevel`, and verifies the credential's proof.
    #[napi]
    pub fn verify_credential(&mut self, vc: &CapabilityCredential) -> Result<TrustEntry> {
        let mut verifier = CrossOrgVerifier::new(&mut self.inner);
        let entry = verifier.verify(&vc.inner).map_err(map_err)?;
        Ok(TrustEntry {
            inner: entry.clone(),
        })
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "TrustRegistry(entries={}, minimum_trust_level='{}')",
            self.inner.len(),
            trust_level_to_str(self.inner.minimum_trust_level)
        )
    }
}

impl Default for TrustRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -- SignedTrustConfig -----------------------------------------------------------

/// A signed, versioned snapshot of a `TrustRegistry` - the persistable,
/// tamper-evident trust configuration.
#[napi]
pub struct SignedTrustConfig {
    pub(crate) inner: CoreTrustConfig,
}

#[napi]
impl SignedTrustConfig {
    #[napi(getter)]
    pub fn version(&self) -> i64 {
        self.inner.version as i64
    }
    #[napi(getter)]
    pub fn generated_at(&self) -> String {
        self.inner.generated_at.to_rfc3339()
    }
    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[napi(getter)]
    pub fn minimum_trust_level(&self) -> String {
        trust_level_to_str(self.inner.minimum_trust_level).to_string()
    }
    #[napi(getter)]
    pub fn entries(&self) -> Vec<TrustEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| TrustEntry { inner })
            .collect()
    }

    /// Verify the config's signature against `anchor` (its issuer).
    #[napi]
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// Whether the config is inside its validity window (unbounded = always current).
    #[napi]
    pub fn is_current(&self) -> bool {
        self.inner.is_current()
    }

    /// The sealed expiry (rfc3339), or null if the config is unbounded.
    #[napi(getter)]
    pub fn not_after(&self) -> Option<String> {
        self.inner.not_after.map(|t| t.to_rfc3339())
    }

    /// Verify authenticity **and** freshness - what a relying party should use.
    ///
    /// `verify` alone accepts an EXPIRED config, so a relying party calling only that
    /// honours a lapsed membership list indefinitely: the framework could remove a
    /// member and never be believed.
    #[napi]
    pub fn verify_current(&self, anchor: &TrustAnchor) -> Result<()> {
        self.inner.verify_current(&anchor.inner).map_err(map_err)
    }

    /// The config as a JSON string (the persisted artifact).
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a config from its JSON string.
    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: CoreTrustConfig::from_json(&s).map_err(map_err)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CapabilityClaims, CapabilityClaimsInit, CapabilityCredential};
    use crate::identity::{AgentIdentity, TrustAnchor};

    fn issue_vc(anchor: &TrustAnchor, agent: &AgentIdentity) -> CapabilityCredential {
        let claims = CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools: vec!["tool:search".into()],
            max_delegation_depth: 1,
            valid_for_secs: 3600,
            budget_usd: None,
            autonomy_level: None,
            model_version: None,
            artifact_hash: None,
            authorized_by: None,
            accountable_party: None,
        })
        .unwrap();
        CapabilityCredential::issue(anchor, agent.did(), &claims, None).unwrap()
    }

    #[test]
    fn trust_entry_getters_and_to_string() {
        let anchor = TrustAnchor::generate().unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Acme Corp".into(),
            &anchor.public_key(),
            "verified".into(),
        )
        .unwrap();
        assert_eq!(entry.did(), anchor.did());
        assert_eq!(entry.org_name(), "Acme Corp");
        assert_eq!(entry.trust_level(), "verified");
        assert_eq!(entry.did_method(), "key");
        assert!(entry.revocation_endpoint().is_none());
        assert!(entry.to_string().contains("Acme Corp"));
    }

    #[test]
    fn trust_entry_rejects_unknown_trust_level() {
        let anchor = TrustAnchor::generate().unwrap();
        assert!(TrustEntry::new(
            anchor.did(),
            "Acme".into(),
            &anchor.public_key(),
            "super-trusted".into()
        )
        .is_err());
    }

    #[test]
    fn registry_default_minimum_trust_level_is_self_asserted() {
        let registry = TrustRegistry::new();
        assert_eq!(registry.minimum_trust_level(), "self_asserted");
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_set_minimum_trust_level() {
        let mut registry = TrustRegistry::new();
        registry.set_minimum_trust_level("verified".into()).unwrap();
        assert_eq!(registry.minimum_trust_level(), "verified");
        assert!(registry
            .set_minimum_trust_level("super-trusted".into())
            .is_err());
    }

    #[test]
    fn registry_register_and_resolve() {
        let anchor = TrustAnchor::generate().unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Acme Corp".into(),
            &anchor.public_key(),
            "verified".into(),
        )
        .unwrap();

        let mut registry = TrustRegistry::new();
        registry.register(&entry);

        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert_eq!(registry.registered_dids(), vec![anchor.did()]);

        let resolved = registry.resolve(anchor.did()).unwrap();
        assert_eq!(resolved.did(), anchor.did());
        assert_eq!(resolved.org_name(), "Acme Corp");
    }

    #[test]
    fn registry_resolve_unknown_did_fails() {
        let mut registry = TrustRegistry::new();
        assert!(registry
            .resolve("did:key:zUnknownDoesNotExist".into())
            .is_err());
    }

    #[test]
    fn registry_with_in_memory_resolver_consumes_resolver() {
        let resolver = InMemoryResolver::new();
        let registry = TrustRegistry::with_in_memory_resolver(&resolver).unwrap();
        assert!(registry.is_empty());

        // The resolver was moved into the registry - binding it again must fail.
        assert!(TrustRegistry::with_in_memory_resolver(&resolver).is_err());
    }

    #[test]
    fn verify_credential_against_registered_anchor() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent);

        let entry = TrustEntry::new(
            anchor.did(),
            "Acme Corp".into(),
            &anchor.public_key(),
            "verified".into(),
        )
        .unwrap();
        let mut registry = TrustRegistry::new();
        registry.register(&entry);

        let resolved = registry.verify_credential(&vc).unwrap();
        assert_eq!(resolved.did(), anchor.did());
    }

    #[test]
    fn verify_credential_fails_below_minimum_trust_level() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent);

        let entry = TrustEntry::new(
            anchor.did(),
            "Acme Corp".into(),
            &anchor.public_key(),
            "unverified".into(),
        )
        .unwrap();
        let mut registry = TrustRegistry::new();
        registry.register(&entry);

        assert!(registry.verify_credential(&vc).is_err());
    }

    #[test]
    fn registry_to_string_format() {
        let mut registry = TrustRegistry::new();
        let anchor = TrustAnchor::generate().unwrap();
        let entry = TrustEntry::new(
            anchor.did(),
            "Acme".into(),
            &anchor.public_key(),
            "verified".into(),
        )
        .unwrap();
        registry.register(&entry);
        let s = registry.to_string();
        assert!(s.contains("entries=1"));
        assert!(s.contains("self_asserted"));
    }
}
