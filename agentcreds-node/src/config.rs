use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::config::{
    AgentCredsConfig as CoreAgentCredsConfig, CheqdNetworkKind,
    DelegationConfig as CoreDelegationConfig, DidMethodKind, IdentityConfig as CoreIdentityConfig,
    KeyAlgorithmKind, TrustConfig as CoreTrustConfig, TrustLevelKind,
};

use crate::error::{invalid_arg, map_err};

fn parse_did_method_kind(s: &str) -> Result<DidMethodKind> {
    match s.to_ascii_lowercase().as_str() {
        "key" => Ok(DidMethodKind::Key),
        "web" => Ok(DidMethodKind::Web),
        "cheqd" => Ok(DidMethodKind::Cheqd),
        "indy" => Ok(DidMethodKind::Indy),
        other => Err(invalid_arg(format!(
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

fn parse_key_algorithm_kind(s: &str) -> Result<KeyAlgorithmKind> {
    match s.to_ascii_lowercase().as_str() {
        "ed25519" => Ok(KeyAlgorithmKind::Ed25519),
        "p256" | "p-256" | "secp256r1" => Ok(KeyAlgorithmKind::P256),
        other => Err(invalid_arg(format!(
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

fn parse_cheqd_network_kind(s: &str) -> Result<CheqdNetworkKind> {
    match s.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(CheqdNetworkKind::Mainnet),
        "testnet" => Ok(CheqdNetworkKind::Testnet),
        other => Err(invalid_arg(format!(
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

fn parse_trust_level_kind(s: &str) -> Result<TrustLevelKind> {
    match s.to_ascii_lowercase().as_str() {
        "unverified" => Ok(TrustLevelKind::Unverified),
        "self_asserted" | "self-asserted" => Ok(TrustLevelKind::SelfAsserted),
        "verified" => Ok(TrustLevelKind::Verified),
        "authoritative" => Ok(TrustLevelKind::Authoritative),
        other => Err(invalid_arg(format!(
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

fn non_negative_secs(secs: i64) -> Result<u64> {
    if secs < 0 {
        return Err(invalid_arg("seconds value must be non-negative"));
    }
    Ok(secs as u64)
}

// -- IdentityConfig ------------------------------------------------------------

/// Constructor options for [`IdentityConfig`]. All fields are optional and
/// fall back to their config defaults (`did_method = "key"`, `key_algorithm =
/// "ed25519"`) when omitted.
#[napi(object)]
pub struct IdentityConfigInit {
    pub did_method: Option<String>,
    pub key_algorithm: Option<String>,
    pub web_host: Option<String>,
    pub web_path: Option<String>,
    pub cheqd_network: Option<String>,
    pub indy_namespace: Option<String>,
}

/// Identity and cryptographic key configuration.
#[napi]
pub struct IdentityConfig {
    pub(crate) inner: CoreIdentityConfig,
}

#[napi]
impl IdentityConfig {
    #[napi(constructor)]
    pub fn new(init: Option<IdentityConfigInit>) -> Result<Self> {
        let mut inner = CoreIdentityConfig::default();
        if let Some(init) = init {
            if let Some(m) = init.did_method {
                inner.did_method = parse_did_method_kind(&m)?;
            }
            if let Some(a) = init.key_algorithm {
                inner.key_algorithm = parse_key_algorithm_kind(&a)?;
            }
            inner.web_host = init.web_host;
            inner.web_path = init.web_path;
            if let Some(n) = init.cheqd_network {
                inner.cheqd_network = Some(parse_cheqd_network_kind(&n)?);
            }
            inner.indy_namespace = init.indy_namespace;
        }
        Ok(Self { inner })
    }

    /// Which DID method to use for new identities (`"key"`, `"web"`, `"cheqd"`, or `"indy"`).
    #[napi(getter)]
    pub fn did_method(&self) -> &'static str {
        did_method_kind_to_str(self.inner.did_method)
    }

    /// Preferred key algorithm for new key pairs (`"ed25519"` or `"p256"`).
    #[napi(getter)]
    pub fn key_algorithm(&self) -> &'static str {
        key_algorithm_kind_to_str(self.inner.key_algorithm)
    }

    /// DNS host - required when `didMethod = "web"`.
    #[napi(getter)]
    pub fn web_host(&self) -> Option<String> {
        self.inner.web_host.clone()
    }

    /// Optional URL path suffix - used when `didMethod = "web"`.
    #[napi(getter)]
    pub fn web_path(&self) -> Option<String> {
        self.inner.web_path.clone()
    }

    /// Cheqd network (`"mainnet"` or `"testnet"`) - required when `didMethod = "cheqd"`.
    #[napi(getter)]
    pub fn cheqd_network(&self) -> Option<String> {
        self.inner
            .cheqd_network
            .map(cheqd_network_kind_to_str)
            .map(String::from)
    }

    /// Indy ledger namespace - required when `didMethod = "indy"`.
    #[napi(getter)]
    pub fn indy_namespace(&self) -> Option<String> {
        self.inner.indy_namespace.clone()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "IdentityConfig(didMethod='{}', keyAlgorithm='{}')",
            self.did_method(),
            self.key_algorithm()
        )
    }
}

// -- DelegationConfig ----------------------------------------------------------

/// Constructor options for [`DelegationConfig`]. All fields are optional and
/// fall back to their config defaults (`maxDepth = 3`, `defaultTtlSecs =
/// 3600`, `maxTtlSecs = 86400`) when omitted.
#[napi(object)]
pub struct DelegationConfigInit {
    pub max_depth: Option<u32>,
    pub default_ttl_secs: Option<i64>,
    pub max_ttl_secs: Option<i64>,
}

/// Delegation chain limits and token lifetime settings.
#[napi]
pub struct DelegationConfig {
    pub(crate) inner: CoreDelegationConfig,
}

#[napi]
impl DelegationConfig {
    #[napi(constructor)]
    pub fn new(init: Option<DelegationConfigInit>) -> Result<Self> {
        let mut inner = CoreDelegationConfig::default();
        if let Some(init) = init {
            if let Some(d) = init.max_depth {
                inner.max_depth = d;
            }
            if let Some(t) = init.default_ttl_secs {
                inner.default_ttl_secs = non_negative_secs(t)?;
            }
            if let Some(t) = init.max_ttl_secs {
                inner.max_ttl_secs = non_negative_secs(t)?;
            }
        }
        Ok(Self { inner })
    }

    /// Maximum allowed delegation depth.
    #[napi(getter)]
    pub fn max_depth(&self) -> u32 {
        self.inner.max_depth
    }

    /// Default token TTL in seconds when the caller does not specify one.
    #[napi(getter)]
    pub fn default_ttl_secs(&self) -> i64 {
        self.inner.default_ttl_secs as i64
    }

    /// Hard ceiling on token TTL - any caller-supplied value is clamped to this.
    #[napi(getter)]
    pub fn max_ttl_secs(&self) -> i64 {
        self.inner.max_ttl_secs as i64
    }

    /// Clamp a caller-supplied TTL to `maxTtlSecs`.
    #[napi]
    pub fn clamp_ttl(&self, requested_secs: i64) -> Result<i64> {
        let requested = non_negative_secs(requested_secs)?;
        Ok(self.inner.clamp_ttl(requested) as i64)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "DelegationConfig(maxDepth={}, defaultTtlSecs={}, maxTtlSecs={})",
            self.inner.max_depth, self.inner.default_ttl_secs, self.inner.max_ttl_secs
        )
    }
}

// -- TrustConfig ---------------------------------------------------------------

/// Cross-organizational trust verification settings.
#[napi]
pub struct TrustConfig {
    pub(crate) inner: CoreTrustConfig,
}

#[napi]
impl TrustConfig {
    /// `minimumTrustLevel` defaults to `"self_asserted"` when omitted.
    #[napi(constructor)]
    pub fn new(minimum_trust_level: Option<String>) -> Result<Self> {
        let mut inner = CoreTrustConfig::default();
        if let Some(level) = minimum_trust_level {
            inner.minimum_trust_level = parse_trust_level_kind(&level)?;
        }
        Ok(Self { inner })
    }

    /// VCs from issuers below this level are rejected by `TrustRegistry`.
    #[napi(getter)]
    pub fn minimum_trust_level(&self) -> &'static str {
        trust_level_kind_to_str(self.inner.minimum_trust_level)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "TrustConfig(minimumTrustLevel='{}')",
            self.minimum_trust_level()
        )
    }
}

// -- AgentCredsConfig ---------------------------------------------------------

/// Complete SDK configuration. Construct with defaults, or load from a TOML
/// file / string / environment variables.
#[napi]
pub struct AgentCredsConfig {
    pub(crate) inner: CoreAgentCredsConfig,
}

#[napi]
impl AgentCredsConfig {
    /// Construct a configuration with all defaults (`did:key` / Ed25519,
    /// max delegation depth 3, 1h default / 24h max token TTL, minimum
    /// trust level `"self_asserted"`).
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreAgentCredsConfig::default(),
        }
    }

    /// Load configuration from a TOML file. Missing sections or keys fall
    /// back to their default values.
    #[napi(factory)]
    pub fn from_toml(path: String) -> Result<Self> {
        Ok(Self {
            inner: CoreAgentCredsConfig::from_toml(std::path::Path::new(&path)).map_err(map_err)?,
        })
    }

    /// Parse configuration from a TOML string.
    #[napi(factory)]
    pub fn from_toml_str(toml: String) -> Result<Self> {
        Ok(Self {
            inner: CoreAgentCredsConfig::from_toml_str(&toml).map_err(map_err)?,
        })
    }

    /// Build configuration from environment variables (`AF_*`), falling back
    /// to defaults for any variable that is not set or unrecognised.
    #[napi(factory)]
    pub fn from_env() -> Self {
        Self {
            inner: CoreAgentCredsConfig::from_env(),
        }
    }

    #[napi(getter)]
    pub fn identity(&self) -> IdentityConfig {
        IdentityConfig {
            inner: self.inner.identity.clone(),
        }
    }

    #[napi(getter)]
    pub fn delegation(&self) -> DelegationConfig {
        DelegationConfig {
            inner: self.inner.delegation.clone(),
        }
    }

    #[napi(getter)]
    pub fn trust(&self) -> TrustConfig {
        TrustConfig {
            inner: self.inner.trust.clone(),
        }
    }

    /// Validate that all required fields for the chosen DID method are present.
    #[napi]
    pub fn validate(&self) -> Result<()> {
        self.inner.validate().map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "AgentCredsConfig(didMethod='{}', keyAlgorithm='{}')",
            did_method_kind_to_str(self.inner.identity.did_method),
            key_algorithm_kind_to_str(self.inner.identity.key_algorithm)
        )
    }
}

impl Default for AgentCredsConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_did_key_ed25519() {
        let cfg = AgentCredsConfig::new();
        assert_eq!(cfg.identity().did_method(), "key");
        assert_eq!(cfg.identity().key_algorithm(), "ed25519");
        assert_eq!(cfg.delegation().max_depth(), 3);
        assert_eq!(cfg.delegation().default_ttl_secs(), 3_600);
        assert_eq!(cfg.delegation().max_ttl_secs(), 86_400);
        assert_eq!(cfg.trust().minimum_trust_level(), "self_asserted");
    }

    #[test]
    fn from_toml_str_overrides_defaults() {
        let toml = r#"
            [identity]
            did_method    = "cheqd"
            key_algorithm = "p256"
            cheqd_network = "mainnet"

            [delegation]
            max_depth        = 5
            default_ttl_secs = 7200
            max_ttl_secs     = 172800

            [trust]
            minimum_trust_level = "verified"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml.to_string()).unwrap();
        assert_eq!(cfg.identity().did_method(), "cheqd");
        assert_eq!(cfg.identity().key_algorithm(), "p256");
        assert_eq!(cfg.identity().cheqd_network(), Some("mainnet".to_string()));
        assert_eq!(cfg.delegation().max_depth(), 5);
        assert_eq!(cfg.delegation().default_ttl_secs(), 7200);
        assert_eq!(cfg.trust().minimum_trust_level(), "verified");
    }

    #[test]
    fn invalid_toml_str_is_err() {
        assert!(AgentCredsConfig::from_toml_str("not = [valid toml".to_string()).is_err());
    }

    #[test]
    fn web_method_without_host_fails_validation() {
        let cfg = AgentCredsConfig::from_toml_str("[identity]\ndid_method = \"web\"".to_string())
            .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn delegation_config_clamp_ttl() {
        let cfg = DelegationConfig::new(None).unwrap();
        assert_eq!(cfg.clamp_ttl(1_000_000).unwrap(), cfg.max_ttl_secs());
        assert_eq!(cfg.clamp_ttl(100).unwrap(), 100);
        assert!(cfg.clamp_ttl(-1).is_err());
    }

    #[test]
    fn identity_config_init_overrides() {
        let cfg = IdentityConfig::new(Some(IdentityConfigInit {
            did_method: Some("web".into()),
            key_algorithm: Some("p256".into()),
            web_host: Some("example.com".into()),
            web_path: None,
            cheqd_network: None,
            indy_namespace: None,
        }))
        .unwrap();
        assert_eq!(cfg.did_method(), "web");
        assert_eq!(cfg.key_algorithm(), "p256");
        assert_eq!(cfg.web_host(), Some("example.com".to_string()));
    }

    #[test]
    fn identity_config_rejects_unknown_did_method() {
        assert!(IdentityConfig::new(Some(IdentityConfigInit {
            did_method: Some("rsa".into()),
            key_algorithm: None,
            web_host: None,
            web_path: None,
            cheqd_network: None,
            indy_namespace: None,
        }))
        .is_err());
    }

    #[test]
    fn trust_config_rejects_unknown_level() {
        assert!(TrustConfig::new(Some("super-trusted".into())).is_err());
    }
}
