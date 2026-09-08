//! Integration tests for agentcreds-core.
//!
//! These tests exercise the full lifecycle:
//! identity -> credential -> delegation -> cross-org verification -> revocation.

#![allow(clippy::unwrap_used)]

use agentcreds_core::did::{CheqdNetwork, DidMethod, KeyAlgorithm, TrustAnchor};
use agentcreds_core::prelude::*;
use agentcreds_core::registry::{CrossOrgVerifier, TrustEntry, TrustLevel, TrustRegistry};
use agentcreds_core::revocation::{RevocationList, RevocationRegistry};
use agentcreds_core::vc::{
    AuthoritySource, CapabilityClaims, CapabilityCredential, CredentialStatus,
};

// -- Scenario 1: Full single-org agent lifecycle -------------------------------

#[test]
fn scenario_single_org_agent_lifecycle() {
    // 1. Org sets up a trust anchor
    let anchor = TrustAnchor::generate().unwrap();

    // 2. Agent is enrolled at deploy time
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    assert!(agent.did().starts_with("did:key:"));

    // 3. Trust anchor issues a capability credential
    let claims = CapabilityClaims {
        tools: vec!["tool:search".into(), "tool:email".into()],
        resources: None,
        budget_usd: Some(500),
        max_delegation_depth: 3,
        valid_for_secs: 3600,
        autonomy_level: 1,
        model_version: Some("gpt-4o-2024-08-06".into()),
        artifact_hash: Some("abc123def456".into()),
        authorized_by: Some("did:key:zUser123".into()),
        accountable_party: None,
        party_version: None,
        party_commitment: None,
        accountability_source: Default::default(),
        on_behalf_of: None,
        required_gates: Vec::new(),
    };
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    assert!(vc.is_valid());
    assert_eq!(vc.subject_did(), agent.did());

    // 4. VC verifies cleanly
    assert!(vc.verify(&anchor, true).is_ok());

    // 5. Agent mints a runtime Biscuit token
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert_eq!(token.depth(), 0);

    // 6. Tool call verified at boundary
    let action = Action::new("tool:search", "query=agentcreds+ssi");
    assert!(token.verify(&action).is_ok());

    // 7. Denied action correctly rejected
    let denied = Action::new("tool:email", "to=attacker");
    assert!(token.verify(&denied).is_err());

    // 8. Audit chain has correct structure
    let chain = token.chain();
    assert_eq!(chain.entries.len(), 1);
    assert_eq!(chain.issuer_did, anchor.did());
}

// -- Scenario 2: Multi-hop delegation across three agents ----------------------

#[test]
fn scenario_multi_hop_delegation() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent_a = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let agent_b = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let agent_c = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let claims = CapabilityClaims {
        tools: vec!["tool:search".into(), "tool:db".into(), "tool:notify".into()],
        resources: None,
        budget_usd: Some(1000),
        max_delegation_depth: 3,
        valid_for_secs: 3600,
        autonomy_level: 2,
        model_version: None,
        artifact_hash: None,
        authorized_by: None,
        accountable_party: None,
        party_version: None,
        party_commitment: None,
        accountability_source: Default::default(),
        on_behalf_of: None,
        required_gates: Vec::new(),
    };
    let vc = CapabilityCredential::issue(&anchor, agent_a.did(), claims, None).unwrap();

    // A -> B: narrows to search + db, budget 200, depth 2
    let scope_a =
        Scope::with_budget_and_depth(vec!["tool:search".into(), "tool:db".into()], Some(200), 2);
    let token_a = DelegationToken::mint(&vc, scope_a, 600, &agent_a).unwrap();

    // A->B: B gets search only, budget 50, depth 1
    let scope_b = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 1);
    let token_b = token_a.attenuate(scope_b, 300, &agent_b).unwrap();
    assert_eq!(token_b.depth(), 1);

    // B->C: C gets search only, budget 10, depth 0
    let scope_c = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 0);
    let token_c = token_b.attenuate(scope_c, 60, &agent_c).unwrap();
    assert_eq!(token_c.depth(), 2);

    // C can search
    assert!(token_c.verify(&Action::new("tool:search", "q=ok")).is_ok());

    // C cannot use db (narrowed away at hop A->B level)
    assert!(token_c
        .verify(&Action::new("tool:db", "query=DROP"))
        .is_err());

    // C cannot delegate further (max_depth = 0)
    let agent_d = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let result = token_c.attenuate(
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(5), 0),
        30,
        &agent_d,
    );
    assert!(matches!(
        result,
        Err(AgentCredsError::DelegationDepthExceeded { .. })
    ));

    // Audit chain has all 3 entries
    let chain = token_c.chain();
    assert_eq!(chain.entries.len(), 3);
    assert_eq!(chain.entries[2].agent_did, agent_c.did());
}

// -- Scenario 3: Cross-org verification without callback ----------------------

#[test]
fn scenario_cross_org_verification() {
    // Org A issues credential
    let anchor_a = TrustAnchor::generate().unwrap();
    let agent_a = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor_a, agent_a.did(), claims, None).unwrap();

    // Org B sets up a registry containing Org A's trust anchor
    let entry_a = TrustEntry::new(
        anchor_a.did(),
        "Organization A",
        anchor_a.public_key().clone(),
        TrustLevel::Verified,
    );
    let mut registry = TrustRegistry::new();
    registry.register(entry_a);

    // Org B verifies Org A's credential WITHOUT calling back to Org A
    let mut verifier = CrossOrgVerifier::new(&mut registry);
    let entry = verifier.verify(&vc).unwrap();
    assert_eq!(entry.org_name, "Organization A");

    // Agent A mints a delegation token and Org B verifies an action
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent_a).unwrap();
    assert!(token
        .verify(&Action::new("tool:search", "cross-org"))
        .is_ok());
}

// `did:cheqd` and `did:indy` resolution against a real ledger is exercised by
// the Tier 6 Docker E2E resolver suite (cheqd-node / von-network) once
// `CheqdResolver` / `IndyResolver` grow real implementations - today both are
// stubs that always return `DidResolutionFailed`. The two scenarios below
// stand in for that until then: they use `InMemoryResolver`, pre-loaded with
// the issuer's DID document, to exercise the cross-org verification path for
// did:cheqd / did:indy issuer DIDs.
#[test]
fn scenario_cross_org_verification_did_cheqd() {
    // `Some(&InMemoryResolver::new())` only satisfies TrustAnchor::create's
    // existence check for ledger-backed methods; it is not used to publish
    // the DID anywhere.
    let anchor = TrustAnchor::create(
        DidMethod::Cheqd {
            network: CheqdNetwork::Testnet,
            unique_id: "test123xyz".into(),
        },
        None,
        Some(&InMemoryResolver::new()),
    )
    .unwrap();

    let agent_a = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent_a.did(), claims, None).unwrap();

    // Org B has not pre-registered Org A's anchor, so verification resolves
    // the issuer's DID document via the registry's resolver.
    let mut resolver = InMemoryResolver::new();
    resolver.register(anchor.did(), anchor.document().clone());
    let mut registry = TrustRegistry::with_resolver(Box::new(resolver));
    let mut verifier = CrossOrgVerifier::new(&mut registry);

    let entry = verifier.verify(&vc).unwrap();
    assert_eq!(entry.did, anchor.did());
    assert_eq!(entry.trust_level, TrustLevel::SelfAsserted);

    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent_a).unwrap();
    assert!(token
        .verify(&Action::new("tool:search", "cross-org cheqd"))
        .is_ok());
}

#[test]
fn scenario_cross_org_verification_did_indy() {
    let anchor = TrustAnchor::create(
        DidMethod::Indy {
            namespace: "sovrin:main".into(),
            unique_id: "WRfXPg8abc".into(),
        },
        None,
        Some(&InMemoryResolver::new()),
    )
    .unwrap();

    let agent_a = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent_a.did(), claims, None).unwrap();

    let mut resolver = InMemoryResolver::new();
    resolver.register(anchor.did(), anchor.document().clone());
    let mut registry = TrustRegistry::with_resolver(Box::new(resolver));
    let mut verifier = CrossOrgVerifier::new(&mut registry);

    let entry = verifier.verify(&vc).unwrap();
    assert_eq!(entry.did, anchor.did());
    assert_eq!(entry.trust_level, TrustLevel::SelfAsserted);

    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent_a).unwrap();
    assert!(token
        .verify(&Action::new("tool:search", "cross-org indy"))
        .is_ok());
}

// -- Scenario 4: Revocation halts a compromised agent -------------------------

#[test]
fn scenario_revocation_halts_compromised_agent() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    // Issue credential with revocation reference at index 7
    let status = CredentialStatus::new("https://registry.example.com/status/1", 7);
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, Some(status)).unwrap();

    // Set up revocation list
    let mut rev_list =
        RevocationList::new("https://registry.example.com/status/1", &anchor, Some(1024)).unwrap();

    // Credential initially valid
    assert!(!rev_list.is_revoked(7).unwrap());

    // Compromise detected - revoke
    rev_list.revoke(7, &anchor).unwrap();
    assert!(rev_list.is_revoked(7).unwrap());

    // Registry propagates the revocation
    let mut registry = RevocationRegistry::new();
    registry.register(rev_list);

    // Any system checking the registry will see the revocation
    let result = registry.is_revoked("https://registry.example.com/status/1", 7, &vc.id);
    assert!(matches!(
        result,
        Err(AgentCredsError::CredentialRevoked { .. })
    ));
}

// -- Scenario 5: Attack - scope widening is structurally blocked ---------------

#[test]
fn scenario_scope_widening_attack_blocked() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    // Attacker sub-agent tries to add tool:admin
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let attack_scope =
        Scope::with_budget_and_depth(vec!["tool:search".into(), "tool:admin".into()], None, 0);
    let result = token.attenuate(attack_scope, 60, &sub);

    assert!(
        matches!(result, Err(AgentCredsError::ScopeWideningAttempt { ref capability }) if capability == "tool:admin"),
        "Expected ScopeWideningAttempt for tool:admin, got: {:?}",
        result
    );
}

// -- Scenario 6: CBOR serialization round-trip for MCP wire transport ----------

#[test]
fn scenario_cbor_wire_transport() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
    let child = token.attenuate(narrow, 60, &sub).unwrap();

    // Serialize -> wire -> deserialise
    let bytes = child.to_cbor().unwrap();
    println!("2-hop token CBOR size: {} bytes", bytes.len());
    assert!(bytes.len() < 4096, "token too large for wire transport");

    let restored = DelegationToken::from_cbor(&bytes).unwrap();
    assert!(restored
        .verify(&Action::new("tool:search", "from wire"))
        .is_ok());
    assert_eq!(restored.depth(), child.depth());
}

// -- Scenario 7: P-256 keys for FIPS-constrained environments -----------------

#[test]
fn scenario_p256_fips_environment() {
    let anchor = TrustAnchor::generate().unwrap();
    // Agent uses P-256 instead of Ed25519 (FIPS requirement)
    let agent = AgentIdentity::create(DidMethod::Key, Some(KeyAlgorithm::P256)).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    assert!(vc.is_valid());

    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(token.verify(&Action::new("tool:search", "fips")).is_ok());
}

// -- Scenario 8: VC JSON serialization for cross-org presentation --------------

#[test]
fn scenario_vc_json_presentation() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let json = vc.to_json().unwrap();
    assert!(json.contains("VerifiableCredential"));
    assert!(json.contains("AgentCapabilityCredential"));
    assert!(json.contains("tool:search"));

    // Deserialise and re-verify
    let restored = CapabilityCredential::from_json(&json).unwrap();
    assert!(restored.verify(&anchor, true).is_ok());
}
