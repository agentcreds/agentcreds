//! Local test harness - simulate cross-org verification in dev without two
//! live deployments.
//!
//! [`MockOrg`] stands in for a remote organization: it owns a trust anchor and
//! issues agents and credentials. A relying party verifies a presented token
//! against the issuing org's anchor with [`verify_presented`] - exactly the
//! cross-org check two real deployments would perform, but entirely in-process.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::testkit::{MockOrg, verify_presented};
//!
//! // Two orgs that have never spoken before.
//! let org_a = MockOrg::new("org-a")?;
//! let _org_b = MockOrg::new("org-b")?;
//!
//! // org-a issues an agent and a runtime token.
//! let agent = org_a.issue_agent(vec!["tool:search".into()], Some(100), 1, 3600)?;
//! let token = agent.mint(vec!["tool:search".into()], Some(50), 0, 300)?;
//!
//! // The agent presents to a relying party that trusts org-a.
//! let challenge = PopChallenge::new(Some("mcp://org-b".into()));
//! let presentation = Presentation::create(token, agent.credential.clone(), &challenge, &agent.identity)?;
//! verify_presented(&presentation, &Action::new("tool:search", "q=ok"), &org_a, &challenge, 60)?;
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use crate::delegation::{Action, DelegationToken, Scope};
use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
use crate::pop::{PopChallenge, Presentation};
use crate::vc::{CapabilityClaims, CapabilityCredential};
use crate::{error::AgentCredsError, Result};

/// A mock organization: a trust anchor plus one-call issuance helpers.
pub struct MockOrg {
    anchor: TrustAnchor,
    name: String,
}

impl MockOrg {
    /// Create a mock org with a freshly generated `did:key`/Ed25519 anchor.
    ///
    /// # Errors
    /// Propagates anchor key-generation failure.
    pub fn new(name: &str) -> Result<Self> {
        Ok(MockOrg {
            anchor: TrustAnchor::generate()?,
            name: name.to_string(),
        })
    }

    /// The org's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The org's trust anchor - the root a relying party must trust.
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }

    /// The org's anchor DID.
    pub fn did(&self) -> &str {
        self.anchor.did()
    }

    /// Create an agent and issue it a capability credential in one call.
    ///
    /// # Errors
    /// Propagates identity creation or credential issuance failure.
    pub fn issue_agent(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_delegation_depth: u32,
        valid_for_secs: u64,
    ) -> Result<MockAgent> {
        let agent = AgentIdentity::create(DidMethod::Key, None)?;
        let mut claims = CapabilityClaims::new(tools, max_delegation_depth, valid_for_secs);
        claims.budget_usd = budget_usd;
        let credential = CapabilityCredential::issue(&self.anchor, agent.did(), claims, None)?;
        Ok(MockAgent {
            identity: agent,
            credential,
        })
    }
}

/// An agent issued by a [`MockOrg`]: its identity (holding the signing keys)
/// and the capability credential issued to it.
pub struct MockAgent {
    /// The agent identity.
    pub identity: AgentIdentity,
    /// The capability credential issued to the agent.
    pub credential: CapabilityCredential,
}

impl MockAgent {
    /// The agent's DID.
    pub fn did(&self) -> &str {
        self.identity.did()
    }

    /// Mint a runtime delegation token for this agent.
    ///
    /// # Errors
    /// Propagates minting failure (e.g. scope exceeds the credential).
    pub fn mint(
        &self,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_depth: u32,
        ttl_secs: u64,
    ) -> Result<DelegationToken> {
        let scope = Scope::with_budget_and_depth(tools, budget_usd, max_depth);
        DelegationToken::mint(&self.credential, scope, ttl_secs, &self.identity)
    }

    /// Assemble a presentation of `token` for `challenge`, signing the proof of
    /// possession with this agent's key. Convenience that avoids exposing the
    /// agent's private identity to callers (e.g. language bindings).
    ///
    /// # Errors
    /// Propagates presentation/proof creation failure.
    pub fn present(
        &self,
        token: DelegationToken,
        challenge: &PopChallenge,
    ) -> Result<Presentation> {
        Presentation::create(token, self.credential.clone(), challenge, &self.identity)
    }
}

/// Verify a presentation as a relying party that trusts `issuer_org` - the
/// cross-org check, performed in-process against the issuing org's anchor.
///
/// # Errors
/// Propagates the presentation verification error (anchor mismatch, denied
/// action, failed proof of possession, etc.).
pub fn verify_presented(
    presentation: &Presentation,
    action: &Action,
    issuer_org: &MockOrg,
    challenge: &PopChallenge,
    max_age_secs: i64,
) -> Result<()> {
    presentation.verify(action, issuer_org.anchor(), challenge, max_age_secs)
}

/// Verify that a presentation roots in *one of* the trusted orgs (a relying
/// party that federates several issuers). Returns `Ok` on the first match.
///
/// # Errors
/// `ProofOfPossessionFailed` if the presentation roots in none of the orgs.
pub fn verify_against_any(
    presentation: &Presentation,
    action: &Action,
    trusted_orgs: &[&MockOrg],
    challenge: &PopChallenge,
    max_age_secs: i64,
) -> Result<()> {
    for org in trusted_orgs {
        if presentation
            .verify(action, org.anchor(), challenge, max_age_secs)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(AgentCredsError::ProofOfPossessionFailed {
        reason: "presentation does not root in any trusted org".into(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn present(
        agent: &MockAgent,
        token: DelegationToken,
        audience: &str,
    ) -> (PopChallenge, Presentation) {
        let challenge = PopChallenge::new(Some(audience.to_string()));
        let presentation =
            Presentation::create(token, agent.credential.clone(), &challenge, &agent.identity)
                .unwrap();
        (challenge, presentation)
    }

    #[test]
    fn cross_org_presentation_verifies_against_issuer() {
        let org_a = MockOrg::new("org-a").unwrap();
        let agent = org_a
            .issue_agent(vec!["tool:search".into()], Some(100), 1, 3600)
            .unwrap();
        let token = agent
            .mint(vec!["tool:search".into()], Some(50), 0, 300)
            .unwrap();
        let (challenge, presentation) = present(&agent, token, "mcp://org-b");
        assert!(verify_presented(
            &presentation,
            &Action::new("tool:search", "q=ok"),
            &org_a,
            &challenge,
            60,
        )
        .is_ok());
    }

    #[test]
    fn presentation_does_not_verify_against_a_different_org() {
        let org_a = MockOrg::new("org-a").unwrap();
        let org_b = MockOrg::new("org-b").unwrap();
        let agent = org_a
            .issue_agent(vec!["tool:search".into()], Some(100), 1, 3600)
            .unwrap();
        let token = agent
            .mint(vec!["tool:search".into()], Some(50), 0, 300)
            .unwrap();
        let (challenge, presentation) = present(&agent, token, "mcp://org-b");
        // org_b did not issue this credential - verification must fail.
        assert!(verify_presented(
            &presentation,
            &Action::new("tool:search", "q=ok"),
            &org_b,
            &challenge,
            60,
        )
        .is_err());
    }

    #[test]
    fn verify_against_any_finds_the_issuer() {
        let org_a = MockOrg::new("org-a").unwrap();
        let org_b = MockOrg::new("org-b").unwrap();
        let agent = org_b
            .issue_agent(vec!["tool:search".into()], Some(100), 1, 3600)
            .unwrap();
        let token = agent
            .mint(vec!["tool:search".into()], Some(50), 0, 300)
            .unwrap();
        let (challenge, presentation) = present(&agent, token, "mcp://relying-party");
        assert!(verify_against_any(
            &presentation,
            &Action::new("tool:search", "q=ok"),
            &[&org_a, &org_b],
            &challenge,
            60,
        )
        .is_ok());
    }

    #[test]
    fn delegated_cross_org_chain_verifies() {
        let org_a = MockOrg::new("org-a").unwrap();
        let agent = org_a
            .issue_agent(
                vec!["tool:search".into(), "tool:email".into()],
                Some(100),
                2,
                3600,
            )
            .unwrap();
        let token = agent
            .mint(
                vec!["tool:search".into(), "tool:email".into()],
                Some(100),
                2,
                300,
            )
            .unwrap();
        // Delegate to a sub-agent, narrowing scope.
        let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let child = token
            .attenuate(
                Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1),
                60,
                &sub,
            )
            .unwrap();
        let challenge = PopChallenge::new(Some("mcp://org-b".into()));
        let presentation =
            Presentation::create(child, agent.credential.clone(), &challenge, &sub).unwrap();
        assert!(verify_presented(
            &presentation,
            &Action::new("tool:search", "q=ok"),
            &org_a,
            &challenge,
            60,
        )
        .is_ok());
        // The narrowed-away tool is denied.
        assert!(verify_presented(
            &presentation,
            &Action::new("tool:email", ""),
            &org_a,
            &challenge,
            60,
        )
        .is_err());
    }
}
