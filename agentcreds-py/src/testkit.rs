use pyo3::prelude::*;

use agentcreds_core::testkit::{MockAgent, MockOrg};

use crate::credential::PyCapabilityCredential;
use crate::delegation::{PyAction, PyDelegationToken};
use crate::error::map_err;
use crate::pop::{PyPopChallenge, PyPresentation};

/// A mock organization for local cross-org testing: a trust anchor plus
/// one-call agent/credential issuance.
#[pyclass(name = "MockOrg", module = "agentcreds")]
pub struct PyMockOrg {
    inner: MockOrg,
}

#[pymethods]
impl PyMockOrg {
    #[new]
    fn new(name: &str) -> PyResult<Self> {
        Ok(Self {
            inner: MockOrg::new(name).map_err(map_err)?,
        })
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name().to_string()
    }

    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_string()
    }

    /// Create an agent and issue it a capability credential in one call.
    #[pyo3(signature = (tools, budget_usd=None, max_delegation_depth=0, valid_for_secs=3600))]
    fn issue_agent(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_delegation_depth: u32,
        valid_for_secs: u64,
    ) -> PyResult<PyMockAgent> {
        let agent = self
            .inner
            .issue_agent(tools, budget_usd, max_delegation_depth, valid_for_secs)
            .map_err(map_err)?;
        Ok(PyMockAgent { inner: agent })
    }

    /// Verify a presentation as a relying party that trusts this org.
    #[pyo3(signature = (presentation, action, challenge, max_age_secs=60))]
    fn verify_presented(
        &self,
        presentation: &PyPresentation,
        action: &PyAction,
        challenge: &PyPopChallenge,
        max_age_secs: i64,
    ) -> PyResult<()> {
        agentcreds_core::testkit::verify_presented(
            &presentation.inner,
            &action.inner,
            &self.inner,
            &challenge.inner,
            max_age_secs,
        )
        .map_err(map_err)
    }
}

/// An agent issued by a [`PyMockOrg`]: holds the identity and credential, and
/// can mint tokens / assemble presentations without exposing key material.
#[pyclass(name = "MockAgent", module = "agentcreds")]
pub struct PyMockAgent {
    inner: MockAgent,
}

#[pymethods]
impl PyMockAgent {
    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_string()
    }

    /// The capability credential issued to this agent.
    #[getter]
    fn credential(&self) -> PyCapabilityCredential {
        PyCapabilityCredential {
            inner: self.inner.credential.clone(),
        }
    }

    /// Mint a runtime delegation token for this agent.
    #[pyo3(signature = (tools, budget_usd=None, max_depth=0, ttl_secs=300))]
    fn mint(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_depth: u32,
        ttl_secs: u64,
    ) -> PyResult<PyDelegationToken> {
        let token = self
            .inner
            .mint(tools, budget_usd, max_depth, ttl_secs)
            .map_err(map_err)?;
        Ok(PyDelegationToken { inner: token })
    }

    /// Assemble a presentation of `token` for `challenge`, signed by this agent.
    fn present(
        &self,
        token: &PyDelegationToken,
        challenge: &PyPopChallenge,
    ) -> PyResult<PyPresentation> {
        let presentation = self
            .inner
            .present(token.inner.clone(), &challenge.inner)
            .map_err(map_err)?;
        Ok(PyPresentation {
            inner: presentation,
        })
    }
}
