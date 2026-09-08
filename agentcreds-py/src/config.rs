use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use agentcreds_core::config::{
    AgentCredsConfig as CoreAgentCredsConfig, CheqdNetworkKind,
    DelegationConfig as CoreDelegationConfig, DidMethodKind, IdentityConfig as CoreIdentityConfig,
    KeyAlgorithmKind, TrustConfig as CoreTrustConfig, TrustLevelKind,
};

use crate::error::map_err;

fn parse_did_method_kind(s: &str) -> PyResult<DidMethodKind> {
    match s.to_ascii_lowercase().as_str() {
        "key" => Ok(DidMethodKind::Key),
        "web" => Ok(DidMethodKind::Web),
        "cheqd" => Ok(DidMethodKind::Cheqd),
        "indy" => Ok(DidMethodKind::Indy),
        other => Err(PyValueError::new_err(format!(
            "unknown DID method '{other}' (expected 'key', 'web', 'cheqd', or 'indy')"
        ))),
    }
}

fn did_method_kind_to_str(kind: DidMethodKind) -> &'static str {
    match kind {
        DidMethodKind::Key => "key",
        DidMethodKind::Web => "web",
        DidMethodKind::Cheqd => "cheqd",
        DidMethodKind::Indy => "indy",
    }
}

fn parse_key_algorithm_kind(s: &str) -> PyResult<KeyAlgorithmKind> {
    match s.to_ascii_lowercase().as_str() {
        "ed25519" => Ok(KeyAlgorithmKind::Ed25519),
        "p256" | "p-256" | "secp256r1" => Ok(KeyAlgorithmKind::P256),
        other => Err(PyValueError::new_err(format!(
            "unknown key algorithm '{other}' (expected 'ed25519' or 'p256')"
        ))),
    }
}

fn key_algorithm_kind_to_str(kind: KeyAlgorithmKind) -> &'static str {
    match kind {
        KeyAlgorithmKind::Ed25519 => "ed25519",
        KeyAlgorithmKind::P256 => "p256",
    }
}

fn parse_cheqd_network_kind(s: &str) -> PyResult<CheqdNetworkKind> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(CheqdNetworkKind::Mainnet),
        "testnet" => Ok(CheqdNetworkKind::Testnet),
        other => Err(PyValueError::new_err(format!(
            "unknown cheqd network '{other}' (expected 'mainnet' or 'testnet')"
        ))),
    }
}

fn cheqd_network_kind_to_str(kind: CheqdNetworkKind) -> &'static str {
    match kind {
        CheqdNetworkKind::Mainnet => "mainnet",
        CheqdNetworkKind::Testnet => "testnet",
    }
}

fn parse_trust_level_kind(s: &str) -> PyResult<TrustLevelKind> {
    match s.to_ascii_lowercase().as_str() {
        "unverified" => Ok(TrustLevelKind::Unverified),
        "self_asserted" | "self-asserted" => Ok(TrustLevelKind::SelfAsserted),
        "verified" => Ok(TrustLevelKind::Verified),
        "authoritative" => Ok(TrustLevelKind::Authoritative),
        other => Err(PyValueError::new_err(format!(
            "unknown trust level '{other}' (expected 'unverified', 'self_asserted', 'verified', or 'authoritative')"
        ))),
    }
}

fn trust_level_kind_to_str(kind: TrustLevelKind) -> &'static str {
    match kind {
        TrustLevelKind::Unverified => "unverified",
        TrustLevelKind::SelfAsserted => "self_asserted",
        TrustLevelKind::Verified => "verified",
        TrustLevelKind::Authoritative => "authoritative",
    }
}

// -- IdentityConfig ------------------------------------------------------------

/// Identity and cryptographic key configuration.
#[pyclass(name = "IdentityConfig", module = "agentcreds")]
#[derive(Clone)]
pub struct PyIdentityConfig {
    pub inner: CoreIdentityConfig,
}

#[pymethods]
impl PyIdentityConfig {
    #[new]
    #[pyo3(signature = (
        did_method=None,
        key_algorithm=None,
        web_host=None,
        web_path=None,
        cheqd_network=None,
        indy_namespace=None,
    ))]
    fn new(
        did_method: Option<&str>,
        key_algorithm: Option<&str>,
        web_host: Option<String>,
        web_path: Option<String>,
        cheqd_network: Option<&str>,
        indy_namespace: Option<String>,
    ) -> PyResult<Self> {
        let mut inner = CoreIdentityConfig::default();
        if let Some(m) = did_method {
            inner.did_method = parse_did_method_kind(m)?;
        }
        if let Some(a) = key_algorithm {
            inner.key_algorithm = parse_key_algorithm_kind(a)?;
        }
        inner.web_host = web_host;
        inner.web_path = web_path;
        if let Some(n) = cheqd_network {
            inner.cheqd_network = Some(parse_cheqd_network_kind(n)?);
        }
        inner.indy_namespace = indy_namespace;
        Ok(Self { inner })
    }

    /// Which DID method to use for new identities (`"key"`, `"web"`, `"cheqd"`, or `"indy"`).
    #[getter]
    fn did_method(&self) -> &'static str {
        did_method_kind_to_str(self.inner.did_method)
    }

    /// Preferred key algorithm for new key pairs (`"ed25519"` or `"p256"`).
    #[getter]
    fn key_algorithm(&self) -> &'static str {
        key_algorithm_kind_to_str(self.inner.key_algorithm)
    }

    /// DNS host - required when `did_method = "web"`.
    #[getter]
    fn web_host(&self) -> Option<String> {
        self.inner.web_host.clone()
    }

    /// Optional URL path suffix - used when `did_method = "web"`.
    #[getter]
    fn web_path(&self) -> Option<String> {
        self.inner.web_path.clone()
    }

    /// Cheqd network (`"mainnet"` or `"testnet"`) - required when `did_method = "cheqd"`.
    #[getter]
    fn cheqd_network(&self) -> Option<&'static str> {
        self.inner.cheqd_network.map(cheqd_network_kind_to_str)
    }

    /// Indy ledger namespace - required when `did_method = "indy"`.
    #[getter]
    fn indy_namespace(&self) -> Option<String> {
        self.inner.indy_namespace.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "IdentityConfig(did_method='{}', key_algorithm='{}')",
            self.did_method(),
            self.key_algorithm()
        )
    }
}

// -- DelegationConfig ----------------------------------------------------------

/// Delegation chain limits and token lifetime settings.
#[pyclass(name = "DelegationConfig", module = "agentcreds")]
#[derive(Clone)]
pub struct PyDelegationConfig {
    pub inner: CoreDelegationConfig,
}

#[pymethods]
impl PyDelegationConfig {
    #[new]
    #[pyo3(signature = (max_depth=None, default_ttl_secs=None, max_ttl_secs=None))]
    fn new(
        max_depth: Option<u32>,
        default_ttl_secs: Option<u64>,
        max_ttl_secs: Option<u64>,
    ) -> Self {
        let mut inner = CoreDelegationConfig::default();
        if let Some(d) = max_depth {
            inner.max_depth = d;
        }
        if let Some(t) = default_ttl_secs {
            inner.default_ttl_secs = t;
        }
        if let Some(t) = max_ttl_secs {
            inner.max_ttl_secs = t;
        }
        Self { inner }
    }

    /// Maximum allowed delegation depth.
    #[getter]
    fn max_depth(&self) -> u32 {
        self.inner.max_depth
    }

    /// Default token TTL in seconds when the caller does not specify one.
    #[getter]
    fn default_ttl_secs(&self) -> u64 {
        self.inner.default_ttl_secs
    }

    /// Hard ceiling on token TTL - any caller-supplied value is clamped to this.
    #[getter]
    fn max_ttl_secs(&self) -> u64 {
        self.inner.max_ttl_secs
    }

    /// Clamp a caller-supplied TTL to `max_ttl_secs`.
    fn clamp_ttl(&self, requested_secs: u64) -> u64 {
        self.inner.clamp_ttl(requested_secs)
    }

    fn __repr__(&self) -> String {
        format!(
            "DelegationConfig(max_depth={}, default_ttl_secs={}, max_ttl_secs={})",
            self.inner.max_depth, self.inner.default_ttl_secs, self.inner.max_ttl_secs
        )
    }
}

// -- TrustConfig ---------------------------------------------------------------

/// Cross-organizational trust verification settings.
#[pyclass(name = "TrustConfig", module = "agentcreds")]
#[derive(Clone)]
pub struct PyTrustConfig {
    pub inner: CoreTrustConfig,
}

#[pymethods]
impl PyTrustConfig {
    /// `minimum_trust_level` defaults to `"self_asserted"` when omitted.
    #[new]
    #[pyo3(signature = (minimum_trust_level=None))]
    fn new(minimum_trust_level: Option<&str>) -> PyResult<Self> {
        let mut inner = CoreTrustConfig::default();
        if let Some(level) = minimum_trust_level {
            inner.minimum_trust_level = parse_trust_level_kind(level)?;
        }
        Ok(Self { inner })
    }

    /// VCs from issuers below this level are rejected by `TrustRegistry`.
    #[getter]
    fn minimum_trust_level(&self) -> &'static str {
        trust_level_kind_to_str(self.inner.minimum_trust_level)
    }

    fn __repr__(&self) -> String {
        format!(
            "TrustConfig(minimum_trust_level='{}')",
            self.minimum_trust_level()
        )
    }
}

// -- AgentCredsConfig ---------------------------------------------------------

/// Complete SDK configuration. Construct with defaults, or load from a TOML
/// file / string / environment variables.
#[pyclass(name = "AgentCredsConfig", module = "agentcreds")]
pub struct PyAgentCredsConfig {
    pub inner: CoreAgentCredsConfig,
}

#[pymethods]
impl PyAgentCredsConfig {
    /// Construct a configuration with all defaults (`did:key` / Ed25519, max
    /// delegation depth 3, 1h default / 24h max token TTL, minimum trust
    /// level `"self_asserted"`).
    #[new]
    fn new() -> Self {
        Self {
            inner: CoreAgentCredsConfig::default(),
        }
    }

    /// Load configuration from a TOML file. Missing sections or keys fall
    /// back to their default values.
    #[staticmethod]
    fn from_toml(path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: CoreAgentCredsConfig::from_toml(std::path::Path::new(path)).map_err(map_err)?,
        })
    }

    /// Parse configuration from a TOML string.
    #[staticmethod]
    fn from_toml_str(toml: &str) -> PyResult<Self> {
        Ok(Self {
            inner: CoreAgentCredsConfig::from_toml_str(toml).map_err(map_err)?,
        })
    }

    /// Build configuration from environment variables (`AF_*`), falling back
    /// to defaults for any variable that is not set or unrecognised.
    #[staticmethod]
    fn from_env() -> Self {
        Self {
            inner: CoreAgentCredsConfig::from_env(),
        }
    }

    #[getter]
    fn identity(&self) -> PyIdentityConfig {
        PyIdentityConfig {
            inner: self.inner.identity.clone(),
        }
    }

    #[getter]
    fn delegation(&self) -> PyDelegationConfig {
        PyDelegationConfig {
            inner: self.inner.delegation.clone(),
        }
    }

    #[getter]
    fn trust(&self) -> PyTrustConfig {
        PyTrustConfig {
            inner: self.inner.trust.clone(),
        }
    }

    /// Validate that all required fields for the chosen DID method are present.
    fn validate(&self) -> PyResult<()> {
        self.inner.validate().map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "AgentCredsConfig(did_method='{}', key_algorithm='{}')",
            did_method_kind_to_str(self.inner.identity.did_method),
            key_algorithm_kind_to_str(self.inner.identity.key_algorithm)
        )
    }
}

impl Default for PyAgentCredsConfig {
    fn default() -> Self {
        Self::new()
    }
}
