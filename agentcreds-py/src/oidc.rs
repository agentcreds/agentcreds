use chrono::{DateTime, Utc};
use pyo3::prelude::*;

use agentcreds_core::oidc::{self, OidcProvider, VerifiedHumanPrincipal};
use agentcreds_core::vc::AuthoritySource;

use crate::credential::PyCapabilityCredential;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;
use crate::principal::PyHumanIdentity;

/// A human principal whose identity an IdP cryptographically attested.
#[pyclass(name = "VerifiedHumanPrincipal", module = "agentcreds")]
#[derive(Clone)]
pub struct PyVerifiedHumanPrincipal {
    pub inner: VerifiedHumanPrincipal,
}

#[pymethods]
impl PyVerifiedHumanPrincipal {
    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[getter]
    fn subject(&self) -> String {
        self.inner.subject.clone()
    }

    #[getter]
    fn email(&self) -> Option<String> {
        self.inner.email.clone()
    }

    #[getter]
    fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }

    #[getter]
    fn scope(&self) -> Vec<String> {
        self.inner.scope.clone()
    }

    /// The actor (`act.sub`) for an RFC 8693 on-behalf-of token, if present.
    #[getter]
    fn acted_by(&self) -> Option<String> {
        self.inner.acted_by.clone()
    }

    /// Mint this principal's stable DID from its IdP identity.
    fn human_identity(&self) -> PyResult<PyHumanIdentity> {
        Ok(PyHumanIdentity {
            inner: self.inner.human_identity().map_err(map_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "VerifiedHumanPrincipal(issuer='{}', subject='{}')",
            self.inner.issuer, self.inner.subject
        )
    }
}

/// An OpenID Connect provider the org trusts, used to validate human ID tokens.
#[pyclass(name = "OidcProvider", module = "agentcreds")]
pub struct PyOidcProvider {
    inner: OidcProvider,
}

#[pymethods]
impl PyOidcProvider {
    /// Build a provider for `issuer` (the IdP's `iss`) and `audience` (your
    /// client id). `leeway_secs` is the allowed clock skew for `exp`/`nbf`.
    #[new]
    #[pyo3(signature = (issuer, audience, leeway_secs=60))]
    fn new(issuer: String, audience: String, leeway_secs: i64) -> Self {
        Self {
            inner: OidcProvider::new(issuer, audience).with_leeway(leeway_secs),
        }
    }

    /// Add an Ed25519 (`EdDSA`) signing key (32 bytes), optionally by `kid`.
    #[pyo3(signature = (public_key, kid=None))]
    fn add_ed25519_key(&mut self, public_key: &[u8], kid: Option<String>) -> PyResult<()> {
        self.inner.add_ed25519_key(kid, public_key).map_err(map_err)
    }

    /// Add a P-256 (`ES256`) signing key (SEC1 bytes), optionally by `kid`.
    #[pyo3(signature = (public_key, kid=None))]
    fn add_p256_key(&mut self, public_key: &[u8], kid: Option<String>) -> PyResult<()> {
        self.inner.add_p256_key(kid, public_key).map_err(map_err)
    }

    /// Add an RSA (`RS256`) signing key from JWKS `n`/`e` (base64url), by `kid`.
    #[pyo3(signature = (n, e, kid=None))]
    fn add_rsa_key(&mut self, n: &str, e: &str, kid: Option<String>) -> PyResult<()> {
        self.inner.add_rsa_key(kid, n, e).map_err(map_err)
    }

    /// Import the provider's signing keys from its JWKS document.
    fn add_keys_from_jwks(&mut self, jwks: &str) -> PyResult<()> {
        self.inner.add_keys_from_jwks(jwks).map_err(map_err)
    }

    /// Validate an OIDC ID token (or RFC 8693 OBO token) and return the verified
    /// human principal. If `expected_agent_did` is given and the token carries an
    /// `act` actor, they must match; `expected_nonce` is checked when supplied.
    #[pyo3(signature = (id_token, expected_agent_did=None, expected_nonce=None))]
    fn validate_id_token(
        &self,
        id_token: &str,
        expected_agent_did: Option<String>,
        expected_nonce: Option<String>,
    ) -> PyResult<PyVerifiedHumanPrincipal> {
        let principal = self
            .inner
            .validate_id_token(
                id_token,
                expected_agent_did.as_deref(),
                expected_nonce.as_deref(),
            )
            .map_err(map_err)?;
        Ok(PyVerifiedHumanPrincipal { inner: principal })
    }
}

/// Issue a capability credential to `agent_did`, bound to a verified human principal.
/// The credential's validity is capped at the human's authorization expiry.
///
/// **The consented scope is the token's own `scope` claim, not `tools`.** `tools` are the
/// capabilities being granted, and granting one the IdP did not authorize now raises a
/// consent violation - a check that could not fire while the consented scope was a copy
/// of the granted tools.
///
/// `resource_authority` has no standard OIDC claim, so a deployment resolves it and
/// labels it with `resource_source` (`"policy"` normally, `"asserted"` if it genuinely
/// came from the request - in which case it bounds nothing).
#[pyfunction]
#[pyo3(signature = (anchor, agent_did, principal, tools, resource_authority,
                    max_delegation_depth, valid_for_secs, resource_source=None))]
pub fn issue_on_behalf_of(
    anchor: &PyTrustAnchor,
    agent_did: &str,
    principal: &PyVerifiedHumanPrincipal,
    tools: Vec<String>,
    resource_authority: Vec<String>,
    max_delegation_depth: u32,
    valid_for_secs: u64,
    resource_source: Option<&str>,
) -> PyResult<PyCapabilityCredential> {
    let resource_source = match resource_source {
        None => AuthoritySource::default(),
        Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
            ))
        })?,
    };
    let vc = oidc::issue_on_behalf_of(
        &anchor.inner,
        agent_did,
        &principal.inner,
        tools,
        resource_authority,
        resource_source,
        max_delegation_depth,
        valid_for_secs,
    )
    .map_err(map_err)?;
    Ok(PyCapabilityCredential { inner: vc })
}
