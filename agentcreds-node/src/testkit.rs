use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::testkit::{MockAgent as CoreMockAgent, MockOrg as CoreMockOrg};

use crate::credential::CapabilityCredential;
use crate::delegation::{Action, DelegationToken};
use crate::error::{invalid_arg, map_err};
use crate::pop::{PopChallenge, Presentation};

/// A mock organization for local cross-org testing: a trust anchor plus
/// one-call agent/credential issuance.
#[napi]
pub struct MockOrg {
    inner: CoreMockOrg,
}

#[napi]
impl MockOrg {
    #[napi(constructor)]
    pub fn new(name: String) -> Result<Self> {
        Ok(Self {
            inner: CoreMockOrg::new(&name).map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_string()
    }

    /// Create an agent and issue it a capability credential in one call.
    #[napi]
    pub fn issue_agent(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_delegation_depth: u32,
        valid_for_secs: i64,
    ) -> Result<MockAgent> {
        if valid_for_secs < 0 {
            return Err(invalid_arg("valid_for_secs must be non-negative"));
        }
        let agent = self
            .inner
            .issue_agent(
                tools,
                budget_usd,
                max_delegation_depth,
                valid_for_secs as u64,
            )
            .map_err(map_err)?;
        Ok(MockAgent { inner: agent })
    }

    /// Verify a presentation as a relying party that trusts this org.
    #[napi]
    pub fn verify_presented(
        &self,
        presentation: &Presentation,
        action: &Action,
        challenge: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
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

/// An agent issued by a [`MockOrg`]: holds the identity and credential, and can
/// mint tokens / assemble presentations without exposing key material.
#[napi]
pub struct MockAgent {
    inner: CoreMockAgent,
}

#[napi]
impl MockAgent {
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.inner.did().to_string()
    }

    /// The capability credential issued to this agent.
    #[napi(getter)]
    pub fn credential(&self) -> CapabilityCredential {
        CapabilityCredential {
            inner: self.inner.credential.clone(),
        }
    }

    /// Mint a runtime delegation token for this agent.
    #[napi]
    pub fn mint(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_depth: u32,
        ttl_secs: i64,
    ) -> Result<DelegationToken> {
        if ttl_secs < 0 {
            return Err(invalid_arg("ttl_secs must be non-negative"));
        }
        let token = self
            .inner
            .mint(tools, budget_usd, max_depth, ttl_secs as u64)
            .map_err(map_err)?;
        Ok(DelegationToken { inner: token })
    }

    /// Assemble a presentation of `token` for `challenge`, signed by this agent.
    #[napi]
    pub fn present(
        &self,
        token: &DelegationToken,
        challenge: &PopChallenge,
    ) -> Result<Presentation> {
        let presentation = self
            .inner
            .present(token.inner.clone(), &challenge.inner)
            .map_err(map_err)?;
        Ok(Presentation {
            inner: presentation,
        })
    }
}
