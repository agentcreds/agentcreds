//! SDK configuration - load from TOML file, environment variables, or programmatic defaults.
//!
//! ## Config file (`agentcreds.toml`)
//!
//! ```toml
//! [identity]
//! did_method    = "cheqd"    # "key" | "web" | "cheqd" | "indy"
//! key_algorithm = "ed25519"  # "ed25519" | "p256"
//!
//! # Required when did_method = "web":
//! # web_host = "example.com"
//! # web_path = "users/alice"        # optional
//!
//! # Required when did_method = "cheqd":
//! # cheqd_network = "mainnet"       # "mainnet" | "testnet"
//!
//! # Required when did_method = "indy":
//! # indy_namespace = "sovrin:main"
//!
//! [delegation]
//! max_depth        = 3
//! default_ttl_secs = 3600
//! max_ttl_secs     = 86400
//!
//! [trust]
//! minimum_trust_level = "self_asserted"
//! # "unverified" | "self_asserted" | "verified" | "authoritative"
//! ```
//!
//! ## Environment variables
//!
//! All settings can be overridden with environment variables.
//! Each variable corresponds to one config key, prefixed with `AC_`:
//!
//! | Variable                 | Default         | Values                                      |
//! |--------------------------|-----------------|---------------------------------------------|
//! | `AC_DID_METHOD`          | `key`           | `key`, `web`, `cheqd`, `indy`               |
//! | `AC_KEY_ALGORITHM`       | `ed25519`       | `ed25519`, `p256`                           |
//! | `AC_WEB_HOST`            | -               | DNS host, e.g. `example.com`                |
//! | `AC_WEB_PATH`            | -               | Optional path, e.g. `users/alice`           |
//! | `AC_CHEQD_NETWORK`       | `testnet`       | `mainnet`, `testnet`                        |
//! | `AC_INDY_NAMESPACE`      | -               | Ledger namespace, e.g. `sovrin:main`        |
//! | `AC_DELEGATION_MAX_DEPTH`| `3`             | u32                                         |
//! | `AC_DELEGATION_TTL_SECS` | `3600`          | u64 (seconds)                               |
//! | `AC_DELEGATION_MAX_TTL`  | `86400`         | u64 (seconds)                               |
//! | `AC_TRUST_MIN_LEVEL`     | `self_asserted` | `unverified`, `self_asserted`, `verified`, `authoritative` |
//!
//! ## Usage
//!
//! ```rust,no_run
//! use agentcreds_core::config::AgentCredsConfig;
//! use std::path::Path;
//!
//! // From a TOML file:
//! let cfg = AgentCredsConfig::from_toml(Path::new("agentcreds.toml")).unwrap();
//!
//! // From environment variables (falls back to defaults for unset vars):
//! let cfg = AgentCredsConfig::from_env();
//!
//! // Programmatic (most explicit - good for testing):
//! let cfg = AgentCredsConfig::default();
//!
//! // Create the configured DID method:
//! let method = cfg.identity.did_method().unwrap();
//! let algorithm = cfg.identity.key_algorithm();
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::did::{AnchorSigner, CheqdNetwork, DidMethod, KeyAlgorithm, SoftwareSigner};
use crate::registry::TrustLevel;
use crate::{error::AgentCredsError, Result};

// -- Top-level config ----------------------------------------------------------

/// Complete SDK configuration.
///
/// Load with [`AgentCredsConfig::from_toml`], [`AgentCredsConfig::from_env`],
/// or construct directly and use [`Default`] for fields you don't need to change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredsConfig {
    /// Identity and key material choices.
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Delegation chain limits.
    #[serde(default)]
    pub delegation: DelegationConfig,

    /// Cross-organizational trust verification settings.
    #[serde(default)]
    pub trust: TrustConfig,

    /// Trust-anchor signing backend (software, or an external HSM/KMS).
    #[serde(default)]
    pub signer: SignerConfig,

    /// Trusted OpenID Connect identity providers, for on-behalf-of issuance.
    /// Each `[[idp]]` table names an issuer the org accepts human tokens from.
    #[serde(default)]
    pub idp: Vec<IdpConfig>,
}

impl Default for AgentCredsConfig {
    fn default() -> Self {
        AgentCredsConfig {
            identity: IdentityConfig::default(),
            delegation: DelegationConfig::default(),
            trust: TrustConfig::default(),
            signer: SignerConfig::default(),
            idp: Vec::new(),
        }
    }
}

impl AgentCredsConfig {
    /// Load configuration from a TOML file.
    ///
    /// Missing sections or keys fall back to their [`Default`] values, so a
    /// minimal config file that only overrides specific fields is valid.
    pub fn from_toml(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| AgentCredsError::MalformedClaims {
            reason: format!("failed to read config file '{}': {e}", path.display()),
        })?;
        Self::from_toml_str(&raw)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| AgentCredsError::MalformedClaims {
            reason: format!("TOML parse error: {e}"),
        })
    }

    /// Build configuration from environment variables, falling back to defaults
    /// for any variable that is not set or contains an unrecognised value.
    ///
    /// See the module-level documentation for the full list of variable names.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        cfg.identity.apply_env();
        cfg.delegation.apply_env();
        cfg.trust.apply_env();
        cfg.signer.apply_env();
        cfg
    }

    /// Build the configured trust-anchor signer, using the identity section's
    /// key algorithm. Returns the software signer for the default backend; for
    /// an external HSM/KMS backend, returns an error directing you to construct
    /// it in your host (which has the relevant SDK) and pass it to
    /// [`crate::did::TrustAnchor::from_signer`] - keeping the core offline.
    ///
    /// # Errors
    /// `OutOfBounds` if `signer.backend` is an external backend.
    pub fn build_signer(&self) -> Result<Box<dyn AnchorSigner>> {
        self.signer.build_signer(self.identity.key_algorithm())
    }

    /// Validate that all required fields for the chosen DID method are present.
    ///
    /// Called automatically by [`IdentityConfig::did_method`]; useful to call
    /// eagerly at startup to surface misconfigurations early.
    pub fn validate(&self) -> Result<()> {
        self.identity.did_method().map(|_| ())
    }

    /// The configured identity provider whose `issuer` matches `issuer`, if any.
    /// Use this to resolve the audience / JWKS TTL / trust level for a human
    /// token whose `iss` you have read.
    pub fn idp_for(&self, issuer: &str) -> Option<&IdpConfig> {
        self.idp.iter().find(|i| i.issuer == issuer)
    }
}

// -- Identity config -----------------------------------------------------------

/// Identity and cryptographic key configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Which DID method to use for new identities.
    #[serde(default)]
    pub did_method: DidMethodKind,

    /// Preferred key algorithm for new key pairs.
    #[serde(default)]
    pub key_algorithm: KeyAlgorithmKind,

    /// DNS host - required when `did_method = "web"`.
    #[serde(default)]
    pub web_host: Option<String>,

    /// Optional URL path suffix - used when `did_method = "web"`.
    #[serde(default)]
    pub web_path: Option<String>,

    /// Cheqd network - required when `did_method = "cheqd"`.
    #[serde(default)]
    pub cheqd_network: Option<CheqdNetworkKind>,

    /// Indy ledger namespace - required when `did_method = "indy"`.
    #[serde(default)]
    pub indy_namespace: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        IdentityConfig {
            did_method: DidMethodKind::default(),
            key_algorithm: KeyAlgorithmKind::default(),
            web_host: None,
            web_path: None,
            cheqd_network: None,
            indy_namespace: None,
        }
    }
}

impl IdentityConfig {
    /// Construct the fully-specified [`DidMethod`] for this config.
    ///
    /// For methods that require a unique identifier at runtime (`did:cheqd`,
    /// `did:indy`) this returns the *template* variant - the caller supplies
    /// the per-identity `unique_id` when calling `AgentIdentity::create`.
    ///
    /// Returns an error if required companion fields are absent (e.g. `web_host`
    /// when `did_method = "web"`).
    pub fn did_method(&self) -> Result<DidMethod> {
        match self.did_method {
            DidMethodKind::Key => Ok(DidMethod::Key),

            DidMethodKind::Web => {
                let host = self.web_host.clone().ok_or(AgentCredsError::MissingField {
                    field: "identity.web_host",
                })?;
                Ok(DidMethod::Web {
                    host,
                    path: self.web_path.clone(),
                })
            }

            DidMethodKind::Cheqd => {
                let network = self.cheqd_network.unwrap_or_default().into();
                // unique_id is generated per-identity; return a sentinel value
                // that callers replace when constructing real DIDs.
                Ok(DidMethod::Cheqd {
                    network,
                    unique_id: String::new(),
                })
            }

            DidMethodKind::Indy => {
                let namespace =
                    self.indy_namespace
                        .clone()
                        .ok_or(AgentCredsError::MissingField {
                            field: "identity.indy_namespace",
                        })?;
                // unique_id is generated per-identity; return a sentinel value.
                Ok(DidMethod::Indy {
                    namespace,
                    unique_id: String::new(),
                })
            }
        }
    }

    /// Map the configured key algorithm to the domain type.
    pub fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm.into()
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("AC_DID_METHOD") {
            if let Some(m) = DidMethodKind::from_str(&v) {
                self.did_method = m;
            }
        }
        if let Ok(v) = std::env::var("AC_KEY_ALGORITHM") {
            if let Some(a) = KeyAlgorithmKind::from_str(&v) {
                self.key_algorithm = a;
            }
        }
        if let Ok(v) = std::env::var("AC_WEB_HOST") {
            self.web_host = Some(v);
        }
        if let Ok(v) = std::env::var("AC_WEB_PATH") {
            self.web_path = Some(v);
        }
        if let Ok(v) = std::env::var("AC_CHEQD_NETWORK") {
            if let Some(n) = CheqdNetworkKind::from_str(&v) {
                self.cheqd_network = Some(n);
            }
        }
        if let Ok(v) = std::env::var("AC_INDY_NAMESPACE") {
            self.indy_namespace = Some(v);
        }
    }
}

// -- Delegation config ---------------------------------------------------------

/// Delegation chain limits and token lifetime settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConfig {
    /// Maximum allowed delegation depth. Tokens cannot be attenuated beyond
    /// this value. Corresponds to `CapabilityClaims::max_delegation_depth`.
    pub max_depth: u32,

    /// Default token TTL in seconds when the caller does not specify one.
    pub default_ttl_secs: u64,

    /// Hard ceiling on token TTL - any caller-supplied value is clamped to this.
    pub max_ttl_secs: u64,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        DelegationConfig {
            max_depth: 3,
            default_ttl_secs: 3_600,
            max_ttl_secs: 86_400,
        }
    }
}

impl DelegationConfig {
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("AC_DELEGATION_MAX_DEPTH") {
            if let Ok(n) = v.parse::<u32>() {
                self.max_depth = n;
            }
        }
        if let Ok(v) = std::env::var("AC_DELEGATION_TTL_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                self.default_ttl_secs = n;
            }
        }
        if let Ok(v) = std::env::var("AC_DELEGATION_MAX_TTL") {
            if let Ok(n) = v.parse::<u64>() {
                self.max_ttl_secs = n;
            }
        }
    }

    /// Clamp a caller-supplied TTL to `max_ttl_secs`.
    pub fn clamp_ttl(&self, requested_secs: u64) -> u64 {
        requested_secs.min(self.max_ttl_secs)
    }
}

// -- Trust config --------------------------------------------------------------

/// Cross-organizational trust verification settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// VCs from issuers below this level are rejected by `CrossOrgVerifier`.
    pub minimum_trust_level: TrustLevelKind,
}

impl Default for TrustConfig {
    fn default() -> Self {
        TrustConfig {
            minimum_trust_level: TrustLevelKind::default(),
        }
    }
}

impl TrustConfig {
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("AC_TRUST_MIN_LEVEL") {
            if let Some(t) = TrustLevelKind::from_str(&v) {
                self.minimum_trust_level = t;
            }
        }
    }

    /// Map the configured minimum trust level to the domain type.
    pub fn minimum_trust_level(&self) -> TrustLevel {
        self.minimum_trust_level.into()
    }
}

// -- Signer config -------------------------------------------------------------

/// Trust-anchor signing backend selection. The `software` backend (default)
/// keeps the private key in process; the external backends name a key held in
/// an HSM / cloud KMS, to be wired up by the host application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Which signing backend to use.
    #[serde(default)]
    pub backend: SignerBackendKind,
    /// Backend key identifier - KMS key id/ARN, Key Vault key name, or PKCS#11 label.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Cloud region, for KMS backends (e.g. `us-east-1`).
    #[serde(default)]
    pub region: Option<String>,
}

impl Default for SignerConfig {
    fn default() -> Self {
        SignerConfig {
            backend: SignerBackendKind::default(),
            key_id: None,
            region: None,
        }
    }
}

impl SignerConfig {
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("AC_SIGNER_BACKEND") {
            if let Some(b) = SignerBackendKind::from_str(&v) {
                self.backend = b;
            }
        }
        if let Ok(v) = std::env::var("AC_SIGNER_KEY_ID") {
            self.key_id = Some(v);
        }
        if let Ok(v) = std::env::var("AC_SIGNER_REGION") {
            self.region = Some(v);
        }
    }

    /// Build the configured signer. The `software` backend is constructed here;
    /// an external HSM/KMS backend returns an error directing you to build it in
    /// your host (which has the relevant SDK) and pass it to
    /// [`crate::did::TrustAnchor::from_signer`] - keeping the core offline.
    ///
    /// # Errors
    /// `OutOfBounds` for any external backend.
    pub fn build_signer(&self, algorithm: KeyAlgorithm) -> Result<Box<dyn AnchorSigner>> {
        match self.backend {
            SignerBackendKind::Software => Ok(Box::new(SoftwareSigner::generate(Some(algorithm))?)),
            external => Err(AgentCredsError::OutOfBounds {
                field: "signer.backend",
                detail: format!(
                    "backend '{}' is an external HSM/KMS - construct it in your host \
                     (with its SDK) and pass it to TrustAnchor::from_signer; the core \
                     builds only the 'software' backend to stay offline",
                    external.as_str()
                ),
            }),
        }
    }
}

/// Config-layer signer backend selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignerBackendKind {
    /// In-process software key (default). Zeroized on drop.
    #[default]
    Software,
    /// AWS KMS - host-provided signer.
    AwsKms,
    /// Google Cloud KMS - host-provided signer.
    GcpKms,
    /// Azure Key Vault - host-provided signer.
    AzureKeyVault,
    /// PKCS#11 HSM - host-provided signer.
    Pkcs11,
}

impl SignerBackendKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "software" => Some(Self::Software),
            "aws_kms" | "aws-kms" | "kms" => Some(Self::AwsKms),
            "gcp_kms" | "gcp-kms" | "gcp" | "cloud_kms" => Some(Self::GcpKms),
            "azure_key_vault" | "azure" => Some(Self::AzureKeyVault),
            "pkcs11" | "pkcs#11" | "hsm" => Some(Self::Pkcs11),
            _ => None,
        }
    }

    /// The canonical lowercase backend name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::AwsKms => "aws_kms",
            Self::GcpKms => "gcp_kms",
            Self::AzureKeyVault => "azure_key_vault",
            Self::Pkcs11 => "pkcs11",
        }
    }
}

// -- IdP config (on-behalf-of) -------------------------------------------------

fn default_jwks_ttl_secs() -> u64 {
    3_600
}

/// A trusted OpenID Connect identity provider, declared as a `[[idp]]` table.
///
/// ```toml
/// [[idp]]
/// issuer        = "https://login.acme.com"
/// audience      = "agentcreds-prod"      # your client id
/// jwks_ttl_secs = 3600                    # how long to cache the JWKS
/// trust_level   = "authoritative"
/// # discovery_url = "https://login.acme.com/.well-known/openid-configuration"
/// ```
///
/// The host fetches the provider's JWKS (via discovery) and validates human ID
/// tokens against it in the offline core ([`crate::oidc::OidcProvider`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    /// The provider's exact `iss` - must match the `iss` claim of accepted tokens.
    pub issuer: String,

    /// The audience (client id) accepted tokens must list in `aud`.
    pub audience: String,

    /// How long (seconds) a fetched JWKS may be cached before re-fetching.
    #[serde(default = "default_jwks_ttl_secs")]
    pub jwks_ttl_secs: u64,

    /// Trust level for humans attested by this provider (mirrors WIMSE levels).
    #[serde(default)]
    pub trust_level: TrustLevelKind,

    /// Explicit discovery document URL. Defaults to
    /// `<issuer>/.well-known/openid-configuration` when omitted.
    #[serde(default)]
    pub discovery_url: Option<String>,
}

impl IdpConfig {
    /// The OIDC discovery document URL - the explicit `discovery_url`, or the
    /// standard `<issuer>/.well-known/openid-configuration` derived from `issuer`.
    pub fn discovery_url(&self) -> String {
        self.discovery_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/openid-configuration",
                self.issuer.trim_end_matches('/')
            )
        })
    }

    /// Map the configured trust level to the domain type.
    pub fn trust_level(&self) -> TrustLevel {
        self.trust_level.into()
    }
}

// -- Config-layer enums --------------------------------------------------------
//
// These mirror the domain enums (DidMethod, KeyAlgorithm, etc.) but use
// lowercase serde names for ergonomic TOML/env-var representation.
// Conversions to domain types are provided via `From` / `Into`.

/// Config-layer DID method selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DidMethodKind {
    /// `did:key` - ephemeral, self-contained (default).
    #[default]
    Key,
    /// `did:web` - requires `web_host`.
    Web,
    /// `did:cheqd` - requires `cheqd_network`.
    Cheqd,
    /// `did:indy` - requires `indy_namespace`.
    Indy,
}

impl DidMethodKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "key" => Some(Self::Key),
            "web" => Some(Self::Web),
            "cheqd" => Some(Self::Cheqd),
            "indy" => Some(Self::Indy),
            _ => None,
        }
    }
}

/// Config-layer key algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithmKind {
    /// Ed25519 - fast, small signatures (default).
    #[default]
    Ed25519,
    /// P-256 (ECDSA) - FIPS-approved for enterprise deployments.
    P256,
}

impl KeyAlgorithmKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Some(Self::Ed25519),
            "p256" | "p-256" => Some(Self::P256),
            _ => None,
        }
    }
}

impl From<KeyAlgorithmKind> for KeyAlgorithm {
    fn from(k: KeyAlgorithmKind) -> Self {
        match k {
            KeyAlgorithmKind::Ed25519 => KeyAlgorithm::Ed25519,
            KeyAlgorithmKind::P256 => KeyAlgorithm::P256,
        }
    }
}

/// Config-layer Cheqd network selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheqdNetworkKind {
    /// Cheqd mainnet.
    Mainnet,
    /// Cheqd testnet (default).
    #[default]
    Testnet,
}

impl CheqdNetworkKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }
}

impl From<CheqdNetworkKind> for CheqdNetwork {
    fn from(n: CheqdNetworkKind) -> Self {
        match n {
            CheqdNetworkKind::Mainnet => CheqdNetwork::Mainnet,
            CheqdNetworkKind::Testnet => CheqdNetwork::Testnet,
        }
    }
}

/// Config-layer trust level selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevelKind {
    /// No attestation backing.
    Unverified,
    /// Self-asserted registration (default).
    #[default]
    SelfAsserted,
    /// Independently attested (e.g. consortium member).
    Verified,
    /// Government-issued or equivalent.
    Authoritative,
}

impl TrustLevelKind {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "unverified" => Some(Self::Unverified),
            "self_asserted" => Some(Self::SelfAsserted),
            "verified" => Some(Self::Verified),
            "authoritative" => Some(Self::Authoritative),
            _ => None,
        }
    }
}

impl From<TrustLevelKind> for TrustLevel {
    fn from(t: TrustLevelKind) -> Self {
        match t {
            TrustLevelKind::Unverified => TrustLevel::Unverified,
            TrustLevelKind::SelfAsserted => TrustLevel::SelfAsserted,
            TrustLevelKind::Verified => TrustLevel::Verified,
            TrustLevelKind::Authoritative => TrustLevel::Authoritative,
        }
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_did_key_ed25519() {
        let cfg = AgentCredsConfig::default();
        assert_eq!(cfg.identity.did_method, DidMethodKind::Key);
        assert_eq!(cfg.identity.key_algorithm, KeyAlgorithmKind::Ed25519);
        let method = cfg.identity.did_method().unwrap();
        assert_eq!(method, DidMethod::Key);
        let algo = cfg.identity.key_algorithm();
        assert_eq!(algo, KeyAlgorithm::Ed25519);
    }

    #[test]
    fn toml_round_trip_key() {
        let toml = r#"
            [identity]
            did_method    = "key"
            key_algorithm = "ed25519"
            [delegation]
            max_depth        = 5
            default_ttl_secs = 7200
            max_ttl_secs     = 172800
            [trust]
            minimum_trust_level = "verified"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.identity.did_method, DidMethodKind::Key);
        assert_eq!(cfg.identity.key_algorithm, KeyAlgorithmKind::Ed25519);
        assert_eq!(cfg.delegation.max_depth, 5);
        assert_eq!(cfg.delegation.default_ttl_secs, 7200);
        assert_eq!(cfg.trust.minimum_trust_level, TrustLevelKind::Verified);
    }

    #[test]
    fn toml_web_method() {
        let toml = r#"
            [identity]
            did_method = "web"
            web_host   = "example.com"
            web_path   = "agents/alice"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        let method = cfg.identity.did_method().unwrap();
        assert!(matches!(
            method,
            DidMethod::Web { host, path: Some(_) } if host == "example.com"
        ));
    }

    #[test]
    fn toml_cheqd_method() {
        let toml = r#"
            [identity]
            did_method    = "cheqd"
            cheqd_network = "mainnet"
            key_algorithm = "p256"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.identity.did_method, DidMethodKind::Cheqd);
        assert_eq!(cfg.identity.key_algorithm, KeyAlgorithmKind::P256);
        assert_eq!(cfg.identity.cheqd_network, Some(CheqdNetworkKind::Mainnet));
        let method = cfg.identity.did_method().unwrap();
        assert!(matches!(
            method,
            DidMethod::Cheqd {
                network: CheqdNetwork::Mainnet,
                ..
            }
        ));
        assert_eq!(cfg.identity.key_algorithm(), KeyAlgorithm::P256);
    }

    #[test]
    fn toml_indy_method() {
        let toml = r#"
            [identity]
            did_method     = "indy"
            indy_namespace = "sovrin:main"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        let method = cfg.identity.did_method().unwrap();
        assert!(matches!(
            method,
            DidMethod::Indy { namespace, .. } if namespace == "sovrin:main"
        ));
    }

    #[test]
    fn web_without_host_is_error() {
        let toml = r#"
            [identity]
            did_method = "web"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        assert!(matches!(
            cfg.identity.did_method(),
            Err(AgentCredsError::MissingField {
                field: "identity.web_host"
            })
        ));
    }

    #[test]
    fn indy_without_namespace_is_error() {
        let toml = r#"
            [identity]
            did_method = "indy"
        "#;
        let cfg = AgentCredsConfig::from_toml_str(toml).unwrap();
        assert!(matches!(
            cfg.identity.did_method(),
            Err(AgentCredsError::MissingField {
                field: "identity.indy_namespace"
            })
        ));
    }

    #[test]
    fn clamp_ttl_enforces_max() {
        let cfg = AgentCredsConfig::default();
        assert_eq!(
            cfg.delegation.clamp_ttl(1_000_000),
            cfg.delegation.max_ttl_secs
        );
        assert_eq!(cfg.delegation.clamp_ttl(100), 100);
    }

    #[test]
    fn trust_level_converts_correctly() {
        assert_eq!(
            TrustLevel::from(TrustLevelKind::Unverified),
            TrustLevel::Unverified
        );
        assert_eq!(
            TrustLevel::from(TrustLevelKind::SelfAsserted),
            TrustLevel::SelfAsserted
        );
        assert_eq!(
            TrustLevel::from(TrustLevelKind::Verified),
            TrustLevel::Verified
        );
        assert_eq!(
            TrustLevel::from(TrustLevelKind::Authoritative),
            TrustLevel::Authoritative
        );
    }

    #[test]
    fn key_algorithm_converts_correctly() {
        assert_eq!(
            KeyAlgorithm::from(KeyAlgorithmKind::Ed25519),
            KeyAlgorithm::Ed25519
        );
        assert_eq!(
            KeyAlgorithm::from(KeyAlgorithmKind::P256),
            KeyAlgorithm::P256
        );
    }

    #[test]
    fn minimal_toml_uses_defaults() {
        let cfg = AgentCredsConfig::from_toml_str("[identity]").unwrap();
        assert_eq!(cfg.delegation.max_depth, 3);
        assert_eq!(cfg.trust.minimum_trust_level, TrustLevelKind::SelfAsserted);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = AgentCredsConfig::from_toml_str("not = [valid toml");
        assert!(result.is_err());
    }

    #[test]
    fn signer_defaults_to_software_and_builds() {
        let cfg = AgentCredsConfig::default();
        assert_eq!(cfg.signer.backend, SignerBackendKind::Software);
        let signer = cfg.build_signer().unwrap();
        assert_eq!(signer.algorithm(), KeyAlgorithm::Ed25519);
    }

    #[test]
    fn external_signer_backend_requires_host_wiring() {
        let mut cfg = AgentCredsConfig::default();
        cfg.signer.backend = SignerBackendKind::AwsKms;
        assert!(matches!(
            cfg.build_signer(),
            Err(AgentCredsError::OutOfBounds {
                field: "signer.backend",
                ..
            })
        ));
    }

    #[test]
    fn signer_toml_parses() {
        let cfg = AgentCredsConfig::from_toml_str(
            r#"
            [signer]
            backend = "aws_kms"
            key_id  = "arn:aws:kms:us-east-1:123:key/abc"
            region  = "us-east-1"
        "#,
        )
        .unwrap();
        assert_eq!(cfg.signer.backend, SignerBackendKind::AwsKms);
        assert_eq!(
            cfg.signer.key_id.as_deref(),
            Some("arn:aws:kms:us-east-1:123:key/abc")
        );
        assert_eq!(cfg.signer.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn signer_section_omitted_uses_software_default() {
        let cfg = AgentCredsConfig::from_toml_str("[identity]\ndid_method = \"key\"\n").unwrap();
        assert_eq!(cfg.signer.backend, SignerBackendKind::Software);
    }

    #[test]
    fn idp_section_parses_and_looks_up() {
        let cfg = AgentCredsConfig::from_toml_str(
            r#"
            [[idp]]
            issuer        = "https://login.acme.com"
            audience      = "agentcreds-prod"
            jwks_ttl_secs = 1800
            trust_level   = "authoritative"

            [[idp]]
            issuer   = "https://accounts.google.com"
            audience = "1234.apps.googleusercontent.com"
        "#,
        )
        .unwrap();

        assert_eq!(cfg.idp.len(), 2);
        let acme = cfg.idp_for("https://login.acme.com").unwrap();
        assert_eq!(acme.audience, "agentcreds-prod");
        assert_eq!(acme.jwks_ttl_secs, 1800);
        assert_eq!(acme.trust_level(), TrustLevel::Authoritative);
        assert_eq!(
            acme.discovery_url(),
            "https://login.acme.com/.well-known/openid-configuration"
        );

        // Defaults: ttl falls back to 3600, trust level to self_asserted.
        let google = cfg.idp_for("https://accounts.google.com").unwrap();
        assert_eq!(google.jwks_ttl_secs, 3600);
        assert_eq!(google.trust_level(), TrustLevel::SelfAsserted);

        assert!(cfg.idp_for("https://unknown.example").is_none());
    }

    #[test]
    fn idp_section_omitted_is_empty() {
        let cfg = AgentCredsConfig::from_toml_str("[identity]").unwrap();
        assert!(cfg.idp.is_empty());
    }

    #[test]
    fn idp_explicit_discovery_url_is_used() {
        let cfg = AgentCredsConfig::from_toml_str(
            r#"
            [[idp]]
            issuer        = "https://login.acme.com"
            audience      = "agentcreds-prod"
            discovery_url = "https://login.acme.com/oidc/.well-known/openid-configuration"
        "#,
        )
        .unwrap();
        assert_eq!(
            cfg.idp_for("https://login.acme.com")
                .unwrap()
                .discovery_url(),
            "https://login.acme.com/oidc/.well-known/openid-configuration"
        );
    }

    // -- Environment overrides ------------------------------------------------
    //
    // `apply_env` and every `*Kind::from_str` were previously unreachable from any
    // test: serde deserializes the config-layer enums by `rename_all`, never through
    // `from_str`, so the environment path is the ONLY caller. An unparsable value is
    // meant to leave the default in place rather than fail the process, and nothing
    // was checking that.
    //
    // Environment variables are process-global and Rust runs tests on parallel
    // threads, so every test that touches them takes this lock and restores the
    // previous value. Without that they corrupt each other intermittently - the
    // worst kind of flake.

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set `vars`, run `f`, then restore whatever was there before - including the
    /// "was not set" case, which `remove_var` has to represent explicitly.
    fn with_env<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
        let out = f();
        for (k, prev) in saved {
            match prev {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
        out
    }

    #[test]
    fn env_overrides_every_identity_field() {
        let cfg = with_env(
            &[
                ("AC_DID_METHOD", "web"),
                ("AC_KEY_ALGORITHM", "p-256"),
                ("AC_WEB_HOST", "id.acme.example"),
                ("AC_WEB_PATH", "agents"),
                ("AC_INDY_NAMESPACE", "sovrin:staging"),
                ("AC_CHEQD_NETWORK", "mainnet"),
            ],
            AgentCredsConfig::from_env,
        );

        assert_eq!(cfg.identity.did_method, DidMethodKind::Web);
        assert_eq!(cfg.identity.key_algorithm, KeyAlgorithmKind::P256);
        assert_eq!(cfg.identity.web_host.as_deref(), Some("id.acme.example"));
        assert_eq!(cfg.identity.web_path.as_deref(), Some("agents"));
        assert_eq!(
            cfg.identity.indy_namespace.as_deref(),
            Some("sovrin:staging")
        );
        assert_eq!(cfg.identity.cheqd_network, Some(CheqdNetworkKind::Mainnet));

        // The method resolves with its companion field supplied.
        assert_eq!(
            cfg.identity.did_method().unwrap(),
            DidMethod::Web {
                host: "id.acme.example".into(),
                path: Some("agents".into())
            }
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn env_overrides_delegation_trust_and_signer() {
        let cfg = with_env(
            &[
                ("AC_DELEGATION_MAX_DEPTH", "7"),
                ("AC_DELEGATION_TTL_SECS", "120"),
                ("AC_DELEGATION_MAX_TTL", "300"),
                ("AC_TRUST_MIN_LEVEL", "authoritative"),
                ("AC_SIGNER_BACKEND", "aws-kms"),
                ("AC_SIGNER_KEY_ID", "arn:aws:kms:us-east-1:1:key/abc"),
                ("AC_SIGNER_REGION", "us-east-1"),
            ],
            AgentCredsConfig::from_env,
        );

        assert_eq!(cfg.delegation.max_depth, 7);
        assert_eq!(cfg.delegation.default_ttl_secs, 120);
        assert_eq!(cfg.delegation.max_ttl_secs, 300);
        // The ceiling is applied, not merely stored.
        assert_eq!(cfg.delegation.clamp_ttl(9_999), 300);

        assert_eq!(cfg.trust.minimum_trust_level, TrustLevelKind::Authoritative);
        assert_eq!(cfg.trust.minimum_trust_level(), TrustLevel::Authoritative);

        assert_eq!(cfg.signer.backend, SignerBackendKind::AwsKms);
        assert_eq!(
            cfg.signer.key_id.as_deref(),
            Some("arn:aws:kms:us-east-1:1:key/abc")
        );
        assert_eq!(cfg.signer.region.as_deref(), Some("us-east-1"));
        // An external backend must refuse to build in-process, naming itself.
        // `.err()` rather than `unwrap_err()`: the Ok type is `Box<dyn AnchorSigner>`,
        // which is deliberately not Debug (a signer must not print itself).
        let err = cfg.build_signer().err().unwrap().to_string();
        assert!(
            err.contains("aws_kms"),
            "error should name the backend: {err}"
        );
    }

    /// An unparsable value must leave the default standing, not panic and not
    /// silently zero the field. Config read from the environment is attacker-adjacent
    /// in a container platform, so "garbage in, default out" is the safe posture -
    /// and a numeric field that quietly became 0 would be a delegation-depth or TTL
    /// of nothing.
    #[test]
    fn unparsable_env_values_leave_defaults_intact() {
        let defaults = AgentCredsConfig::default();
        let cfg = with_env(
            &[
                ("AC_DID_METHOD", "not-a-method"),
                ("AC_KEY_ALGORITHM", "rsa4096"),
                ("AC_CHEQD_NETWORK", "devnet"),
                ("AC_TRUST_MIN_LEVEL", "somewhat"),
                ("AC_SIGNER_BACKEND", "quantum"),
                ("AC_DELEGATION_MAX_DEPTH", "-1"),
                ("AC_DELEGATION_TTL_SECS", "soon"),
                ("AC_DELEGATION_MAX_TTL", ""),
            ],
            AgentCredsConfig::from_env,
        );

        assert_eq!(cfg.identity.did_method, defaults.identity.did_method);
        assert_eq!(cfg.identity.key_algorithm, defaults.identity.key_algorithm);
        assert_eq!(
            cfg.identity.cheqd_network, None,
            "a bad network is not stored"
        );
        assert_eq!(
            cfg.trust.minimum_trust_level,
            defaults.trust.minimum_trust_level
        );
        assert_eq!(cfg.signer.backend, defaults.signer.backend);
        assert_eq!(cfg.delegation.max_depth, defaults.delegation.max_depth);
        assert_eq!(
            cfg.delegation.default_ttl_secs,
            defaults.delegation.default_ttl_secs
        );
        assert_eq!(
            cfg.delegation.max_ttl_secs,
            defaults.delegation.max_ttl_secs
        );
    }

    /// Every accepted spelling, including the aliases. These exist so operators can
    /// write `kms` or `p-256` without reading the source; an alias that silently
    /// stopped resolving would fall back to a default rather than error, so it needs
    /// a positive assertion.
    #[test]
    fn every_env_alias_resolves() {
        for (raw, want) in [
            ("key", DidMethodKind::Key),
            ("WEB", DidMethodKind::Web),
            ("Cheqd", DidMethodKind::Cheqd),
            ("indy", DidMethodKind::Indy),
        ] {
            let cfg = with_env(&[("AC_DID_METHOD", raw)], AgentCredsConfig::from_env);
            assert_eq!(cfg.identity.did_method, want, "AC_DID_METHOD={raw}");
        }

        for (raw, want) in [
            ("ed25519", KeyAlgorithmKind::Ed25519),
            ("Ed25519", KeyAlgorithmKind::Ed25519),
            ("p256", KeyAlgorithmKind::P256),
            ("P-256", KeyAlgorithmKind::P256),
        ] {
            let cfg = with_env(&[("AC_KEY_ALGORITHM", raw)], AgentCredsConfig::from_env);
            assert_eq!(cfg.identity.key_algorithm, want, "AC_KEY_ALGORITHM={raw}");
        }

        for (raw, want) in [
            ("mainnet", CheqdNetworkKind::Mainnet),
            ("TESTNET", CheqdNetworkKind::Testnet),
        ] {
            let cfg = with_env(&[("AC_CHEQD_NETWORK", raw)], AgentCredsConfig::from_env);
            assert_eq!(cfg.identity.cheqd_network, Some(want), "network={raw}");
        }

        for (raw, want) in [
            ("unverified", TrustLevelKind::Unverified),
            ("self_asserted", TrustLevelKind::SelfAsserted),
            ("verified", TrustLevelKind::Verified),
            ("AUTHORITATIVE", TrustLevelKind::Authoritative),
        ] {
            let cfg = with_env(&[("AC_TRUST_MIN_LEVEL", raw)], AgentCredsConfig::from_env);
            assert_eq!(cfg.trust.minimum_trust_level, want, "trust={raw}");
        }

        for (raw, want) in [
            ("software", SignerBackendKind::Software),
            ("aws_kms", SignerBackendKind::AwsKms),
            ("aws-kms", SignerBackendKind::AwsKms),
            ("KMS", SignerBackendKind::AwsKms),
            ("gcp_kms", SignerBackendKind::GcpKms),
            ("gcp-kms", SignerBackendKind::GcpKms),
            ("gcp", SignerBackendKind::GcpKms),
            ("cloud_kms", SignerBackendKind::GcpKms),
            ("azure_key_vault", SignerBackendKind::AzureKeyVault),
            ("azure", SignerBackendKind::AzureKeyVault),
            ("pkcs11", SignerBackendKind::Pkcs11),
            ("pkcs#11", SignerBackendKind::Pkcs11),
            ("hsm", SignerBackendKind::Pkcs11),
        ] {
            let cfg = with_env(&[("AC_SIGNER_BACKEND", raw)], AgentCredsConfig::from_env);
            assert_eq!(cfg.signer.backend, want, "AC_SIGNER_BACKEND={raw}");
        }
    }

    /// `as_str` names the backend in the `build_signer` refusal, so an operator can
    /// tell which one they asked for. Every arm needs a value, and the round trip
    /// through `from_str` is what keeps the canonical name parseable by the config
    /// that produced it.
    #[test]
    fn backend_names_round_trip_through_from_str() {
        for backend in [
            SignerBackendKind::Software,
            SignerBackendKind::AwsKms,
            SignerBackendKind::GcpKms,
            SignerBackendKind::AzureKeyVault,
            SignerBackendKind::Pkcs11,
        ] {
            let name = backend.as_str();
            assert!(!name.is_empty());
            assert_eq!(
                SignerBackendKind::from_str(name),
                Some(backend),
                "canonical name '{name}' must parse back to itself"
            );
        }
    }

    /// Every external backend refuses in-process construction and says why. Only the
    /// AWS arm had been exercised, so a backend that started building a live signer
    /// by mistake would not have been noticed.
    #[test]
    fn every_external_backend_refuses_to_build_in_process() {
        for backend in [
            SignerBackendKind::AwsKms,
            SignerBackendKind::GcpKms,
            SignerBackendKind::AzureKeyVault,
            SignerBackendKind::Pkcs11,
        ] {
            let cfg = SignerConfig {
                backend,
                key_id: Some("k".into()),
                region: Some("r".into()),
            };
            let err = cfg
                .build_signer(KeyAlgorithm::Ed25519)
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.contains(backend.as_str()) && err.contains("from_signer"),
                "{backend:?} must name itself and point at TrustAnchor::from_signer: {err}"
            );
        }
    }

    #[test]
    fn from_toml_reads_a_file_and_reports_a_missing_one() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ac-config-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "[identity]\ndid_method = \"web\"\nweb_host = \"h.example\"\n",
        )
        .unwrap();
        let cfg = AgentCredsConfig::from_toml(&path).unwrap();
        assert_eq!(cfg.identity.web_host.as_deref(), Some("h.example"));
        let _ = std::fs::remove_file(&path);

        // The read failure must name the path - a config error that does not say
        // which file it looked at is the least useful error in an operator's day.
        let missing = dir.join("ac-config-does-not-exist-9d1f.toml");
        let err = AgentCredsConfig::from_toml(&missing)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ac-config-does-not-exist-9d1f.toml"),
            "error must name the file: {err}"
        );
    }

    /// `validate` is the eager startup check, and it must agree with the lazy
    /// `did_method()` call it delegates to - otherwise a process passes startup
    /// validation and then fails on first use.
    #[test]
    fn validate_agrees_with_did_method() {
        let mut cfg = AgentCredsConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.identity.did_method = DidMethodKind::Web;
        assert!(
            cfg.validate().is_err(),
            "web without a host must not validate"
        );
        assert!(cfg.identity.did_method().is_err());

        cfg.identity.web_host = Some("h.example".into());
        assert!(cfg.validate().is_ok());
        assert!(cfg.identity.did_method().is_ok());

        cfg.identity.did_method = DidMethodKind::Indy;
        assert!(
            cfg.validate().is_err(),
            "indy without a namespace must not validate"
        );
        cfg.identity.indy_namespace = Some("sovrin".into());
        assert!(cfg.validate().is_ok());

        // Cheqd needs no companion field: the network defaults.
        cfg.identity.did_method = DidMethodKind::Cheqd;
        assert!(cfg.validate().is_ok());
    }
}
