use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::delegation::{
    Action as CoreAction, ChainEntry as CoreChainEntry, DelegationChain as CoreDelegationChain,
    DelegationToken as CoreDelegationToken, Scope as CoreScope,
};

use crate::credential::CapabilityCredential;
use crate::error::{invalid_arg, map_err};
use crate::identity::{AgentIdentity, TrustAnchor};

// -- Scope --------------------------------------------------------------------

/// Constructor options for [`Scope`]. `budgetUsd` (USD-cents) and `maxDepth`
/// default to unlimited / 0 (no further delegation) when omitted.
#[napi(object)]
pub struct ScopeInit {
    pub tools: Vec<String>,
    pub budget_usd: Option<u32>,
    pub max_depth: Option<u32>,
}

#[napi]
pub struct Scope {
    pub(crate) inner: CoreScope,
}

#[napi]
impl Scope {
    #[napi(constructor)]
    pub fn new(init: ScopeInit) -> Self {
        Self {
            inner: CoreScope::with_budget_and_depth(
                init.tools,
                init.budget_usd,
                init.max_depth.unwrap_or(0),
            ),
        }
    }

    #[napi(getter)]
    pub fn tools(&self) -> Vec<String> {
        let mut tools: Vec<String> = self.inner.tools.iter().cloned().collect();
        tools.sort();
        tools
    }

    #[napi(getter)]
    pub fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[napi(getter)]
    pub fn max_depth(&self) -> u32 {
        self.inner.max_depth
    }

    #[napi(getter)]
    pub fn resources(&self) -> Vec<String> {
        let mut resources: Vec<String> = self.inner.resources.iter().cloned().collect();
        resources.sort();
        resources
    }

    /// Return a copy of this scope with an exact-match resource allow-list (the
    /// resources the agent may touch). Narrows like tools across hops.
    #[napi]
    pub fn with_resources(&self, resources: Vec<String>) -> Scope {
        Self {
            inner: self.inner.clone().with_resources(resources),
        }
    }

    /// True if `self` is permitted under `parent` (tools subset, budget and
    /// depth not wider).
    #[napi]
    pub fn is_subset_of(&self, parent: &Scope) -> bool {
        self.inner.is_subset_of(&parent.inner)
    }

    /// The first tool in `self` that `parent` does not permit, if any.
    #[napi]
    pub fn first_widening_capability(&self, parent: &Scope) -> Option<String> {
        self.inner.first_widening_capability(&parent.inner)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "Scope(tools={:?}, budget_usd={:?}, max_depth={})",
            self.tools(),
            self.inner.budget_usd,
            self.inner.max_depth
        )
    }
}

// -- Action -------------------------------------------------------------------

#[napi]
pub struct Action {
    pub(crate) inner: CoreAction,
}

#[napi]
impl Action {
    /// Create an action with the current timestamp.
    #[napi(constructor)]
    pub fn new(tool: String, parameters: String) -> Self {
        Self {
            inner: CoreAction::new(tool, parameters),
        }
    }

    #[napi(getter)]
    pub fn tool(&self) -> String {
        self.inner.tool.clone()
    }

    #[napi(getter)]
    pub fn parameters(&self) -> String {
        self.inner.parameters.clone()
    }

    #[napi(getter)]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.inner.timestamp
    }

    #[napi(getter)]
    pub fn resource(&self) -> Option<String> {
        self.inner.resource.clone()
    }

    #[napi(getter)]
    pub fn acting_for(&self) -> Option<String> {
        self.inner.acting_for.clone()
    }

    /// Return a copy of this action tagged with the resource it touches.
    #[napi]
    pub fn with_resource(&self, resource: String) -> Action {
        Self {
            inner: self.inner.clone().on_resource(resource),
        }
    }

    /// Return a copy of this action made on behalf of the given principal DID
    /// (required when the token is bound to a principal).
    #[napi]
    pub fn with_acting_for(&self, principal_did: String) -> Action {
        Self {
            inner: self.inner.clone().on_behalf_of(principal_did),
        }
    }

    /// A stable content binding of this action (tool, parameters, resource) -
    /// pass to `PopChallenge.withRequestBinding` to bind a presentation to
    /// exactly this request.
    #[napi]
    pub fn request_binding(&self) -> String {
        self.inner.request_binding()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "Action(tool='{}', parameters='{}')",
            self.inner.tool, self.inner.parameters
        )
    }
}

// -- ChainEntry / DelegationChain (audit view) ---------------------------------

#[napi]
pub struct ChainEntry {
    pub(crate) inner: CoreChainEntry,
}

#[napi]
impl ChainEntry {
    #[napi(getter)]
    pub fn depth(&self) -> u32 {
        self.inner.depth
    }

    #[napi(getter)]
    pub fn agent_did(&self) -> String {
        self.inner.agent_did.clone()
    }

    #[napi(getter)]
    pub fn tools(&self) -> Vec<String> {
        self.inner.tools.clone()
    }

    #[napi(getter)]
    pub fn resources(&self) -> Vec<String> {
        self.inner.resources.clone()
    }

    #[napi(getter)]
    pub fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[napi(getter)]
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.inner.issued_at
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "ChainEntry(depth={}, agent_did='{}', tools={:?})",
            self.inner.depth, self.inner.agent_did, self.inner.tools
        )
    }
}

#[napi]
pub struct DelegationChain {
    pub(crate) inner: CoreDelegationChain,
}

#[napi]
impl DelegationChain {
    #[napi(getter)]
    pub fn vc_id(&self) -> String {
        self.inner.vc_id.clone()
    }

    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    /// The human principal the chain is bound to (on-behalf-of), if any.
    #[napi(getter)]
    pub fn principal_did(&self) -> Option<String> {
        self.inner.principal_did.clone()
    }

    #[napi(getter)]
    pub fn entries(&self) -> Vec<ChainEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| ChainEntry { inner })
            .collect()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "DelegationChain(vc_id='{}', entries={})",
            self.inner.vc_id,
            self.inner.entries.len()
        )
    }
}

// -- DelegationToken -----------------------------------------------------------

#[napi]
pub struct DelegationToken {
    pub(crate) inner: CoreDelegationToken,
}

#[napi]
impl DelegationToken {
    /// Mint a new delegation token from a capability credential. `scope` must
    /// be a subset of `vc`'s claims; `ttlSecs` is capped at the VC's expiry.
    #[napi(factory)]
    pub fn mint(
        vc: &CapabilityCredential,
        scope: &Scope,
        ttl_secs: i64,
        agent: &AgentIdentity,
    ) -> Result<Self> {
        if ttl_secs < 0 {
            return Err(invalid_arg("ttl_secs must be non-negative"));
        }
        Ok(Self {
            inner: CoreDelegationToken::mint(
                &vc.inner,
                scope.inner.clone(),
                ttl_secs as u64,
                &agent.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Attenuate this token for a sub-agent. `narrow` must be a subset of the
    /// current leaf block's scope; widening throws `ScopeWideningError`.
    #[napi]
    pub fn attenuate(&self, narrow: &Scope, ttl_secs: i64, agent: &AgentIdentity) -> Result<Self> {
        if ttl_secs < 0 {
            return Err(invalid_arg("ttl_secs must be non-negative"));
        }
        Ok(Self {
            inner: self
                .inner
                .attenuate(narrow.inner.clone(), ttl_secs as u64, &agent.inner)
                .map_err(map_err)?,
        })
    }

    /// Verify the chain's integrity and authenticity (every block signature,
    /// expiry, hash linkage, monotonic scope narrowing) and that `action` is
    /// permitted by the leaf block.
    ///
    /// NOTE: this proves the chain is authentic but not that its root authority
    /// came from a trusted anchor. Use `verifyRooted` (or independently verify
    /// the backing credential) to establish anchor-rooted authority.
    #[napi]
    pub fn verify(&self, action: &Action) -> Result<()> {
        self.inner.verify(&action.inner).map_err(map_err)
    }

    /// Verify `action` against this token **and** bind its root to an
    /// anchor-issued credential: verifies `vc` against `anchor`, confirms the
    /// token was derived from `vc`, that the root was minted by the credential
    /// subject, and that the root scope is within the credential's claims.
    /// This is the complete check a relying party should use.
    #[napi]
    pub fn verify_rooted(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
    ) -> Result<()> {
        self.inner
            .verify_rooted(&action.inner, &vc.inner, &anchor.inner)
            .map_err(map_err)
    }

    /// `verifyRooted`, evaluated **as of** `epochSeconds` instead of the wall clock.
    ///
    /// One instant governs the credential's expiry, every hop's expiry and the Datalog
    /// time check, so the answer cannot straddle two clocks. For audit re-verification
    /// ("was this authorized when it happened?") and for conformance vectors that must
    /// outlive the token lifetimes the autonomy ladder permits.
    ///
    /// **Not the enforcement path** - a relying party deciding in real time calls
    /// `verifyRooted`. Revocation is not covered: a historical answer also needs the
    /// status list as it stood then.
    #[napi]
    pub fn verify_rooted_at(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        epoch_seconds: i64,
    ) -> Result<()> {
        let now = chrono::DateTime::from_timestamp(epoch_seconds, 0)
            .ok_or_else(|| napi::Error::from_reason("epochSeconds out of range"))?;
        self.inner
            .verify_rooted_at(&action.inner, &vc.inner, &anchor.inner, now)
            .map_err(map_err)
    }

    /// Produce a proof of possession for `challenge`, signed by the token's
    /// leaf agent. Only the leaf agent can do this.
    #[napi]
    pub fn prove_possession(
        &self,
        challenge: &crate::pop::PopChallenge,
        leaf_agent: &AgentIdentity,
    ) -> Result<crate::pop::ProofOfPossession> {
        Ok(crate::pop::ProofOfPossession {
            inner: self
                .inner
                .prove_possession(&challenge.inner, &leaf_agent.inner)
                .map_err(map_err)?,
        })
    }

    /// The complete presentation check: anchor-rooted verification plus proof
    /// of possession of the leaf key for `expectedChallenge`.
    #[napi]
    pub fn verify_presentation(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        proof: &crate::pop::ProofOfPossession,
        expected_challenge: &crate::pop::PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.inner
            .verify_presentation(
                &action.inner,
                &vc.inner,
                &anchor.inner,
                &proof.inner,
                &expected_challenge.inner,
                max_age_secs,
            )
            .map_err(map_err)
    }

    /// `verifyPresentation`, evaluated **as of** `epochSeconds` instead of the wall
    /// clock. One instant governs the credential, every hop, the Datalog time check and
    /// the proof's freshness window.
    ///
    /// **Not the enforcement path** - a relying party deciding in real time calls
    /// `verifyPresentation`. This exists for audit re-verification and for golden
    /// vectors that must outlive the token lifetimes the autonomy ladder permits.
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_presentation_at(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        proof: &crate::pop::ProofOfPossession,
        expected_challenge: &crate::pop::PopChallenge,
        max_age_secs: i64,
        epoch_seconds: i64,
    ) -> Result<()> {
        let now = chrono::DateTime::from_timestamp(epoch_seconds, 0)
            .ok_or_else(|| napi::Error::from_reason("epochSeconds out of range"))?;
        self.inner
            .verify_presentation_at(
                &action.inner,
                &vc.inner,
                &anchor.inner,
                &proof.inner,
                &expected_challenge.inner,
                max_age_secs,
                now,
            )
            .map_err(map_err)
    }

    /// Serialize to CBOR bytes for compact wire transport.
    #[napi]
    pub fn to_cbor(&self) -> Result<Buffer> {
        let bytes = self.inner.to_cbor().map_err(map_err)?;
        Ok(Buffer::from(bytes))
    }

    /// Deserialise a token from CBOR bytes.
    #[napi(factory)]
    pub fn from_cbor(data: Buffer) -> Result<Self> {
        Ok(Self {
            inner: CoreDelegationToken::from_cbor(data.as_ref()).map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn vc_id(&self) -> String {
        self.inner.vc_id().to_string()
    }

    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did().to_string()
    }

    /// The human principal DID this token is bound to (on-behalf-of), or null.
    #[napi(getter)]
    pub fn principal_did(&self) -> Option<String> {
        self.inner.principal_did().map(str::to_string)
    }

    /// The root resource allow-list this token was minted with.
    #[napi]
    pub fn root_resources(&self) -> Vec<String> {
        self.inner.root_resources().to_vec()
    }

    /// Current delegation depth (0 = not delegated).
    #[napi]
    pub fn depth(&self) -> u32 {
        self.inner.depth()
    }

    /// Extract the full delegation chain as audit entries.
    #[napi]
    pub fn chain(&self) -> DelegationChain {
        DelegationChain {
            inner: self.inner.chain(),
        }
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "DelegationToken(vc_id='{}', depth={})",
            self.inner.vc_id(),
            self.inner.depth()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CapabilityClaims, CapabilityClaimsInit, CapabilityCredential};
    use crate::identity::TrustAnchor;

    fn issue_vc(
        anchor: &TrustAnchor,
        agent: &AgentIdentity,
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_delegation_depth: u32,
    ) -> CapabilityCredential {
        let claims = CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools,
            max_delegation_depth,
            valid_for_secs: 3600,
            budget_usd,
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
    fn scope_tools_are_sorted_and_deduplicated() {
        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:b".into(), "tool:a".into(), "tool:b".into()],
            budget_usd: Some(50),
            max_depth: Some(2),
        });
        assert_eq!(
            scope.tools(),
            vec!["tool:a".to_string(), "tool:b".to_string()]
        );
        assert_eq!(scope.budget_usd(), Some(50));
        assert_eq!(scope.max_depth(), 2);
    }

    #[test]
    fn scope_default_max_depth_is_zero() {
        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:a".into()],
            budget_usd: None,
            max_depth: None,
        });
        assert_eq!(scope.max_depth(), 0);
        assert_eq!(scope.budget_usd(), None);
    }

    #[test]
    fn scope_is_subset_of() {
        let parent = Scope::new(ScopeInit {
            tools: vec!["tool:a".into(), "tool:b".into()],
            budget_usd: Some(100),
            max_depth: Some(3),
        });
        let narrow = Scope::new(ScopeInit {
            tools: vec!["tool:a".into()],
            budget_usd: Some(50),
            max_depth: Some(1),
        });
        let wide = Scope::new(ScopeInit {
            tools: vec!["tool:a".into(), "tool:c".into()],
            budget_usd: Some(50),
            max_depth: Some(1),
        });

        assert!(narrow.is_subset_of(&parent));
        assert!(!wide.is_subset_of(&parent));
        assert_eq!(
            wide.first_widening_capability(&parent),
            Some("tool:c".to_string())
        );
        assert_eq!(narrow.first_widening_capability(&parent), None);
    }

    #[test]
    fn action_getters_and_to_string() {
        let action = Action::new("tool:search".into(), "q=agentcreds".into());
        assert_eq!(action.tool(), "tool:search");
        assert_eq!(action.parameters(), "q=agentcreds");
        assert!(action.to_string().contains("tool:search"));
    }

    #[test]
    fn mint_token_and_verify_action() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(
            &anchor,
            &agent,
            vec!["tool:search".into(), "tool:email".into()],
            Some(100),
            3,
        );

        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(50),
            max_depth: Some(1),
        });
        let token = DelegationToken::mint(&vc, &scope, 300, &agent).unwrap();

        assert_eq!(token.vc_id(), vc.id());
        assert_eq!(token.issuer_did(), anchor.did());
        assert_eq!(token.depth(), 0);

        assert!(token
            .verify(&Action::new("tool:search".into(), "q=agentcreds".into()))
            .is_ok());
        assert!(token
            .verify(&Action::new("tool:email".into(), "to=x".into()))
            .is_err());
    }

    #[test]
    fn mint_rejects_negative_ttl() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent, vec!["tool:search".into()], Some(100), 1);
        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: None,
            max_depth: Some(0),
        });
        assert!(DelegationToken::mint(&vc, &scope, -1, &agent).is_err());
    }

    #[test]
    fn mint_rejects_scope_widening() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent, vec!["tool:search".into()], Some(100), 3);
        let wide_scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into(), "tool:email".into()],
            budget_usd: Some(100),
            max_depth: Some(1),
        });
        assert!(DelegationToken::mint(&vc, &wide_scope, 60, &agent).is_err());
    }

    #[test]
    fn attenuate_and_chain() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let sub_agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(
            &anchor,
            &agent,
            vec!["tool:search".into(), "tool:email".into()],
            Some(100),
            3,
        );

        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into(), "tool:email".into()],
            budget_usd: Some(100),
            max_depth: Some(2),
        });
        let token = DelegationToken::mint(&vc, &scope, 300, &agent).unwrap();

        let narrow = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(10),
            max_depth: Some(1),
        });
        let child = token.attenuate(&narrow, 60, &sub_agent).unwrap();

        assert_eq!(child.depth(), 1);
        assert!(child
            .verify(&Action::new("tool:search".into(), "q=x".into()))
            .is_ok());
        assert!(child
            .verify(&Action::new("tool:email".into(), "to=x".into()))
            .is_err());

        let chain = child.chain();
        assert_eq!(chain.vc_id(), vc.id());
        assert_eq!(chain.issuer_did(), anchor.did());
        let entries = chain.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].depth(), 0);
        assert_eq!(entries[0].agent_did(), agent.did());
        assert_eq!(entries[1].depth(), 1);
        assert_eq!(entries[1].agent_did(), sub_agent.did());
    }

    #[test]
    fn attenuate_rejects_negative_ttl_and_widening() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let sub_agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent, vec!["tool:search".into()], Some(100), 3);

        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(100),
            max_depth: Some(2),
        });
        let token = DelegationToken::mint(&vc, &scope, 300, &agent).unwrap();

        let same = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(100),
            max_depth: Some(2),
        });
        assert!(token.attenuate(&same, -1, &sub_agent).is_err());

        let wider = Scope::new(ScopeInit {
            tools: vec!["tool:search".into(), "tool:email".into()],
            budget_usd: Some(100),
            max_depth: Some(1),
        });
        assert!(token.attenuate(&wider, 60, &sub_agent).is_err());
    }

    #[test]
    fn token_cbor_round_trip() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent, vec!["tool:search".into()], Some(100), 1);
        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(100),
            max_depth: Some(0),
        });
        let token = DelegationToken::mint(&vc, &scope, 300, &agent).unwrap();

        let bytes = token.to_cbor().unwrap();
        let restored = DelegationToken::from_cbor(bytes).unwrap();
        assert_eq!(restored.vc_id(), token.vc_id());
        assert_eq!(restored.depth(), token.depth());
        assert!(restored
            .verify(&Action::new("tool:search".into(), "q=x".into()))
            .is_ok());
    }

    #[test]
    fn delegation_token_to_string_format() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let vc = issue_vc(&anchor, &agent, vec!["tool:search".into()], Some(100), 1);
        let scope = Scope::new(ScopeInit {
            tools: vec!["tool:search".into()],
            budget_usd: Some(100),
            max_depth: Some(0),
        });
        let token = DelegationToken::mint(&vc, &scope, 300, &agent).unwrap();
        assert!(token.to_string().contains(&vc.id()));
        assert!(token.to_string().contains("depth=0"));
    }
}
