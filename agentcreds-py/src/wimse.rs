use pyo3::prelude::*;

use agentcreds_core::wimse::{FederatedIdentity, FederationBridge};

use crate::credential::PyCapabilityCredential;
use crate::error::map_err;
use crate::identity::PyTrustAnchor;
use crate::registry::{parse_trust_level, trust_level_to_str};

/// A bridge that federates peer SPIFFE trust domains: import each peer's JWKS
/// bundle, then validate SVIDs it signs.
#[pyclass(name = "FederationBridge", module = "agentcreds")]
pub struct PyFederationBridge {
    inner: FederationBridge,
}

#[pymethods]
impl PyFederationBridge {
    #[new]
    fn new() -> Self {
        Self {
            inner: FederationBridge::new(),
        }
    }

    /// Federate a peer domain by importing its JWKS trust-bundle export.
    /// `trust_level` is one of `unverified`/`self_asserted`/`verified`/`authoritative`.
    fn add_domain_from_jwks(
        &mut self,
        trust_domain: String,
        jwks: &str,
        trust_level: &str,
    ) -> PyResult<()> {
        let level = parse_trust_level(trust_level)?;
        self.inner
            .add_domain_from_jwks(trust_domain, jwks, level)
            .map_err(map_err)
    }

    /// The trust domains this bridge federates.
    fn trusted_domains(&self) -> Vec<String> {
        self.inner
            .trusted_domains()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Validate a federated SVID, routing it to its trust domain's bundle.
    #[pyo3(signature = (jwt_svid, expected_audience=None))]
    fn validate(
        &self,
        jwt_svid: &str,
        expected_audience: Option<String>,
    ) -> PyResult<PyFederatedIdentity> {
        let fed = self
            .inner
            .validate(jwt_svid, expected_audience.as_deref())
            .map_err(map_err)?;
        Ok(PyFederatedIdentity { inner: fed })
    }
}

/// A validated, federated workload identity from a peer trust domain.
#[pyclass(name = "FederatedIdentity", module = "agentcreds")]
pub struct PyFederatedIdentity {
    inner: FederatedIdentity,
}

#[pymethods]
impl PyFederatedIdentity {
    /// The workload's SPIFFE ID, as a `spiffe://...` URI.
    #[getter]
    fn spiffe_id(&self) -> String {
        self.inner.spiffe_id.uri()
    }

    #[getter]
    fn trust_domain(&self) -> String {
        self.inner.trust_domain.clone()
    }

    /// The trust level assigned to the issuing domain.
    #[getter]
    fn trust_level(&self) -> String {
        trust_level_to_str(self.inner.trust_level).to_string()
    }

    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }

    /// Issue a capability credential for this federated workload, signed by the
    /// relying org's own `anchor`.
    #[pyo3(signature = (anchor, agent_did, tools, max_delegation_depth, valid_for_secs))]
    fn issue_credential(
        &self,
        anchor: &PyTrustAnchor,
        agent_did: &str,
        tools: Vec<String>,
        max_delegation_depth: u32,
        valid_for_secs: u64,
    ) -> PyResult<PyCapabilityCredential> {
        let vc = self
            .inner
            .issue_credential(
                &anchor.inner,
                agent_did,
                tools,
                max_delegation_depth,
                valid_for_secs,
            )
            .map_err(map_err)?;
        Ok(PyCapabilityCredential { inner: vc })
    }
}
