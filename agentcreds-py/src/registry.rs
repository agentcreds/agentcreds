use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::registry::{
    CrossOrgVerifier, SignedTrustConfig, TrustEntry, TrustLevel, TrustRegistry,
};

use crate::credential::PyCapabilityCredential;
use crate::error::map_err;
use crate::identity::{PyInMemoryResolver, PyPublicKey, PyTrustAnchor};

pub fn parse_trust_level(level: &str) -> PyResult<TrustLevel> {
    match level.to_ascii_lowercase().as_str() {
        "unverified" => Ok(TrustLevel::Unverified),
        "self_asserted" | "self-asserted" => Ok(TrustLevel::SelfAsserted),
        "verified" => Ok(TrustLevel::Verified),
        "authoritative" => Ok(TrustLevel::Authoritative),
        other => Err(PyValueError::new_err(format!(
            "unknown trust level '{other}' (expected 'unverified', 'self_asserted', 'verified', or 'authoritative')"
        ))),
    }
}

pub fn trust_level_to_str(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Unverified => "unverified",
        TrustLevel::SelfAsserted => "self_asserted",
        TrustLevel::Verified => "verified",
        TrustLevel::Authoritative => "authoritative",
    }
}

// -- TrustEntry ----------------------------------------------------------------

#[pyclass(name = "TrustEntry", module = "agentcreds")]
#[derive(Clone)]
pub struct PyTrustEntry {
    pub inner: TrustEntry,
}

#[pymethods]
impl PyTrustEntry {
    /// Create a trust entry. `trust_level` is one of `"unverified"`,
    /// `"self_asserted"`, `"verified"`, or `"authoritative"`.
    #[new]
    fn new(
        did: String,
        org_name: String,
        public_key: &PyPublicKey,
        trust_level: &str,
    ) -> PyResult<Self> {
        let level = parse_trust_level(trust_level)?;
        Ok(Self {
            inner: TrustEntry::new(did, org_name, public_key.inner.clone(), level),
        })
    }

    #[getter]
    fn did(&self) -> String {
        self.inner.did.clone()
    }

    #[getter]
    fn org_name(&self) -> String {
        self.inner.org_name.clone()
    }

    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key.clone(),
        }
    }

    #[getter]
    fn did_method(&self) -> String {
        self.inner.did_method.clone()
    }

    #[getter]
    fn trust_level(&self) -> &'static str {
        trust_level_to_str(self.inner.trust_level)
    }

    #[getter]
    fn registered_at(&self) -> DateTime<Utc> {
        self.inner.registered_at
    }

    #[getter]
    fn revocation_endpoint(&self) -> Option<String> {
        self.inner.revocation_endpoint.clone()
    }

    /// Where this member publishes its signed key history. `None` = the member does not
    /// rotate, so its registered DID is both root and current.
    #[getter]
    fn key_history_url(&self) -> Option<String> {
        self.inner.key_history_url.clone()
    }

    #[setter]
    fn set_key_history_url(&mut self, url: Option<String>) {
        self.inner.key_history_url = url;
    }

    /// Verify a signature produced by this trust anchor's key.
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        self.inner
            .verify_signature(message, signature)
            .map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustEntry(did='{}', org_name='{}', trust_level='{}')",
            self.inner.did,
            self.inner.org_name,
            trust_level_to_str(self.inner.trust_level)
        )
    }
}

// -- TrustRegistry -------------------------------------------------------------

#[pyclass(name = "TrustRegistry", module = "agentcreds")]
pub struct PyTrustRegistry {
    pub inner: TrustRegistry,
}

#[pymethods]
impl PyTrustRegistry {
    /// Create a registry backed by a fresh, empty in-memory resolver.
    #[new]
    fn new() -> Self {
        Self {
            inner: TrustRegistry::new(),
        }
    }

    /// Create a registry backed by `resolver`. The resolver is consumed -
    /// it cannot be modified or reused afterwards.
    #[staticmethod]
    fn with_in_memory_resolver(resolver: &mut PyInMemoryResolver) -> PyResult<Self> {
        let resolver = resolver.inner.take().ok_or_else(|| {
            PyValueError::new_err(
                "resolver has already been bound to a TrustRegistry and can no longer be used",
            )
        })?;
        Ok(Self {
            inner: TrustRegistry::with_resolver(Box::new(resolver)),
        })
    }

    /// Minimum trust level accepted by `verify_credential`.
    #[getter]
    fn minimum_trust_level(&self) -> &'static str {
        trust_level_to_str(self.inner.minimum_trust_level)
    }

    #[setter]
    fn set_minimum_trust_level(&mut self, level: &str) -> PyResult<()> {
        self.inner.minimum_trust_level = parse_trust_level(level)?;
        Ok(())
    }

    /// Register a trust anchor entry.
    fn register(&mut self, entry: &PyTrustEntry) {
        self.inner.register(entry.inner.clone());
    }

    /// Resolve a trust anchor by DID, caching the result if a resolver lookup
    /// was required.
    fn resolve(&mut self, did: &str) -> PyResult<PyTrustEntry> {
        Ok(PyTrustEntry {
            inner: self.inner.resolve(did).map_err(map_err)?.clone(),
        })
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// True if no trust anchors are registered.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// All registered DIDs.
    fn registered_dids(&self) -> Vec<String> {
        self.inner
            .registered_dids()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// Export the registry as a signed, versioned ``SignedTrustConfig`` sealed by
    /// ``anchor`` - the portable, tamper-evident artifact you persist/distribute.
    fn export(&self, anchor: &PyTrustAnchor, version: u64) -> PyResult<PySignedTrustConfig> {
        Ok(PySignedTrustConfig {
            inner: self.inner.export(&anchor.inner, version).map_err(map_err)?,
        })
    }

    /// Like :meth:`export`, but seals an expiry into the signed config so a
    /// fail-safe consumer rejects it once stale - bounded staleness for
    /// distributed trust material. ``not_after`` is an aware ``datetime``; pass
    /// ``None`` for an unbounded config. The expiry is inside the signed digest,
    /// so it cannot be extended without the anchor key.
    #[pyo3(signature = (anchor, version, not_after=None))]
    fn export_valid_until(
        &self,
        anchor: &PyTrustAnchor,
        version: u64,
        not_after: Option<DateTime<Utc>>,
    ) -> PyResult<PySignedTrustConfig> {
        Ok(PySignedTrustConfig {
            inner: self
                .inner
                .export_valid_until(&anchor.inner, version, not_after)
                .map_err(map_err)?,
        })
    }

    /// Build a registry from a verified signed config (in-memory resolver).
    #[staticmethod]
    fn from_config(config: &PySignedTrustConfig, anchor: &PyTrustAnchor) -> PyResult<Self> {
        Ok(Self {
            inner: TrustRegistry::from_config(&config.inner, &anchor.inner).map_err(map_err)?,
        })
    }

    /// Merge a verified config's entries into this registry (additive).
    fn import_config(
        &mut self,
        config: &PySignedTrustConfig,
        anchor: &PyTrustAnchor,
    ) -> PyResult<()> {
        self.inner
            .import(&config.inner, &anchor.inner)
            .map_err(map_err)
    }

    /// Verify `vc` against this registry without contacting the issuer:
    /// resolves the issuer's trust entry, checks its trust level meets
    /// `minimum_trust_level`, and verifies the credential's proof.
    /// Verify `vc` where its issuer may be a **rotated** key of a registered member.
    ///
    /// Resolves the member by the root its `history` is anchored at, applies the
    /// registry's minimum trust level to that ROOT entry (so rotation cannot be used to
    /// escape a level), then lets the verified history decide whether the issuer is a
    /// key that member still trusts.
    fn verify_credential_rotated(
        &mut self,
        vc: &PyCapabilityCredential,
        history: &crate::rotation::PyKeyHistory,
    ) -> PyResult<PyTrustEntry> {
        Ok(PyTrustEntry {
            inner: self
                .inner
                .verify_credential_rotated(&vc.inner, &history.inner)
                .map_err(map_err)?
                .clone(),
        })
    }

    fn verify_credential(&mut self, vc: &PyCapabilityCredential) -> PyResult<PyTrustEntry> {
        let mut verifier = CrossOrgVerifier::new(&mut self.inner);
        let entry = verifier.verify(&vc.inner).map_err(map_err)?;
        Ok(PyTrustEntry {
            inner: entry.clone(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustRegistry(entries={}, minimum_trust_level='{}')",
            self.inner.len(),
            trust_level_to_str(self.inner.minimum_trust_level)
        )
    }
}

// -- SignedTrustConfig -----------------------------------------------------------

/// A signed, versioned snapshot of a ``TrustRegistry`` - the persistable,
/// tamper-evident trust configuration.
#[pyclass(name = "SignedTrustConfig", module = "agentcreds")]
#[derive(Clone)]
pub struct PySignedTrustConfig {
    pub inner: SignedTrustConfig,
}

#[pymethods]
impl PySignedTrustConfig {
    #[getter]
    fn version(&self) -> u64 {
        self.inner.version
    }
    #[getter]
    fn generated_at(&self) -> String {
        self.inner.generated_at.to_rfc3339()
    }
    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[getter]
    fn minimum_trust_level(&self) -> &'static str {
        trust_level_to_str(self.inner.minimum_trust_level)
    }
    #[getter]
    fn entries(&self) -> Vec<PyTrustEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| PyTrustEntry { inner })
            .collect()
    }

    /// The sealed expiry, or ``None`` if the config is unbounded.
    #[getter]
    fn not_after(&self) -> Option<String> {
        self.inner.not_after.map(|t| t.to_rfc3339())
    }

    /// Verify the config's signature against ``anchor`` (its issuer).
    ///
    /// Authenticity **only** - an expired config still verifies here. Relying
    /// parties should use :meth:`verify_current`.
    fn verify(&self, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// Whether the config is still inside its validity window. An unbounded
    /// config (``not_after is None``) is always current.
    fn is_current(&self) -> bool {
        self.inner.is_current()
    }

    /// Verify authenticity **and** freshness: the signature must verify against
    /// ``anchor`` and the config must not be past ``not_after``. This is the
    /// fail-safe check a relying party should run before trusting the config.
    /// :meth:`TrustRegistry.from_config` and ``import_config`` apply it too.
    fn verify_current(&self, anchor: &PyTrustAnchor) -> PyResult<()> {
        self.inner.verify_current(&anchor.inner).map_err(map_err)
    }

    /// The config as a JSON string (the persisted artifact).
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a config from its JSON string.
    #[staticmethod]
    fn from_json(s: &str) -> PyResult<Self> {
        Ok(Self {
            inner: SignedTrustConfig::from_json(s).map_err(map_err)?,
        })
    }
}
