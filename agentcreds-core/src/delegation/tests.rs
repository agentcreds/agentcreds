use super::*;
use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
use crate::principal::HumanIdentity;
use crate::vc::{AuthoritySource, CapabilityClaims, CapabilityCredential};

fn setup() -> (TrustAnchor, AgentIdentity, CapabilityCredential) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims {
        tools: vec![
            "tool:search".into(),
            "tool:email".into(),
            "tool:calendar".into(),
        ],
        resources: None,
        budget_usd: Some(500),
        max_delegation_depth: 3,
        valid_for_secs: 3600,
        autonomy_level: 0,
        model_version: None,
        artifact_hash: None,
        authorized_by: Some("did:key:zRootUser".into()),
        accountable_party: None,
        party_version: None,
        party_commitment: None,
        accountability_source: Default::default(),
        on_behalf_of: None,
        required_gates: Vec::new(),
    };
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    (anchor, agent, vc)
}

#[test]
fn mint_and_verify_simple_action() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(token.verify(&Action::new("tool:search", "q=test")).is_ok());
}

#[test]
fn action_for_unpermitted_tool_is_rejected() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(matches!(
        token.verify(&Action::new("tool:email", "to=evil")),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

#[test]
fn attenuate_narrows_scope() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(
        vec!["tool:search".into(), "tool:email".into()],
        Some(100),
        2,
    );
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
    let child = token.attenuate(narrow, 60, &sub).unwrap();
    assert_eq!(child.depth(), 1);
    assert!(child.verify(&Action::new("tool:search", "q=ok")).is_ok());
    // email was narrowed away.
    assert!(child.verify(&Action::new("tool:email", "")).is_err());
}

#[test]
fn scope_widening_is_rejected() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let wider =
        Scope::with_budget_and_depth(vec!["tool:search".into(), "tool:email".into()], Some(10), 1);
    assert!(matches!(
        token.attenuate(wider, 60, &sub),
        Err(AgentCredsError::ScopeWideningAttempt { .. })
    ));
}

#[test]
fn authorizer_limits_uses_one_second_backstop() {
    // The 1s wall-clock backstop (raised from biscuit-auth's flaky 1ms default) must
    // survive: reverting to the default spuriously denies valid deep OBO chains under
    // scheduler/GC pressure.
    assert_eq!(
        authorizer_limits().max_time,
        std::time::Duration::from_secs(1)
    );
}

#[test]
fn first_widening_capability_names_the_widening_tool() {
    let parent = Scope::with_budget_and_depth(vec!["tool:a".into()], None, 1);
    let wider = Scope::with_budget_and_depth(vec!["tool:a".into(), "tool:b".into()], None, 1);
    // The tool present in `wider` but not `parent` is the widening capability.
    assert_eq!(
        wider.first_widening_capability(&parent),
        Some("tool:b".to_string())
    );
    // When self subset of parent, nothing widens.
    assert_eq!(parent.first_widening_capability(&wider), None);
}

#[test]
fn budget_widening_is_rejected_on_attenuate() {
    // Widening via budget alone (same tools, larger budget) trips only the
    // subset-of check, not the tools-subset check - so the two guards must be OR'd,
    // not AND'd. A larger child budget must be rejected.
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let wider_budget = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 1);
    assert!(matches!(
        token.attenuate(wider_budget, 60, &sub),
        Err(AgentCredsError::ScopeWideningAttempt { .. })
    ));
}

#[test]
fn root_and_leaf_accessors_reflect_the_token() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    // Root (subject) agent is the minter; the token caches the minted max depth
    // (the scope ceiling = 2 here) - a real value, not a 0/1 stub.
    assert_eq!(token.root_agent_did(), agent.did());
    assert_eq!(token.max_delegation_depth(), 2);

    // leaf_binding is a real SHA-256 hex, and a different chain yields a different one.
    let binding = token.leaf_binding();
    assert_eq!(binding.len(), 64);
    assert!(binding.chars().all(|c| c.is_ascii_hexdigit()));

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let child = token
        .attenuate(
            Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1),
            60,
            &sub,
        )
        .unwrap();
    assert_ne!(
        child.leaf_binding(),
        binding,
        "a distinct chain must have a distinct leaf binding"
    );
    // The root is unchanged by attenuation.
    assert_eq!(child.root_agent_did(), agent.did());
}

#[test]
fn root_resources_reflect_the_minted_allowlist() {
    // The gated token is minted with an explicit resource allow-list; the accessor
    // must return exactly that, not an empty or fabricated list.
    let (_anchor, _vc, _human, token) = gated_token();
    assert_eq!(
        token.root_resources(),
        &["mailbox:alice@acme.com/42".to_string()]
    );
}

#[test]
fn vc_pinned_gate_is_merged_and_enforced_for_the_action_tool() {
    // A gate the *credential* pins (distinct from the token's own scope) must be
    // merged in and enforced for the matching tool - and must NOT gate other tools.
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let action = Action::new("tool:search", "q=ok");
    let now = Utc::now().timestamp();

    // A: VC pins an approval gate for the action's tool; the token's scope does not.
    //    With no evidence, the merged gate must fail closed.
    let mut claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    claims.required_gates = vec![Gate::approval("tool:search")];
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(
        matches!(
            token.verify_rooted_gated_with_directory(
                &action,
                &vc,
                &anchor,
                &[],
                None,
                &[Gate::APPROVAL],
                now,
            ),
            Err(AgentCredsError::ActionDenied { .. })
        ),
        "a VC-pinned gate for the action's tool must be enforced"
    );

    // B: a VC gate for a *different* tool must not gate this action.
    let mut claims2 = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    claims2.required_gates = vec![Gate::approval("tool:other")];
    let vc2 = CapabilityCredential::issue(&anchor, agent.did(), claims2, None).unwrap();
    let scope2 = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    let token2 = DelegationToken::mint(&vc2, scope2, 300, &agent).unwrap();
    assert!(
        token2
            .verify_rooted_gated_with_directory(
                &action,
                &vc2,
                &anchor,
                &[],
                None,
                &[Gate::APPROVAL],
                now,
            )
            .is_ok(),
        "a VC gate for a different tool must not gate this action"
    );
}

#[test]
fn three_hop_chain_verifies() {
    let (_anchor, agent1, vc) = setup();
    let agent2 = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let agent3 = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let s1 = Scope::with_budget_and_depth(
        vec!["tool:search".into(), "tool:email".into()],
        Some(100),
        3,
    );
    let t1 = DelegationToken::mint(&vc, s1, 300, &agent1).unwrap();
    let s2 = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 2);
    let t2 = t1.attenuate(s2, 120, &agent2).unwrap();
    let s3 = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
    let t3 = t2.attenuate(s3, 30, &agent3).unwrap();

    assert_eq!(t3.depth(), 2);
    assert!(t3.verify(&Action::new("tool:search", "q=deep")).is_ok());
    assert!(t3.verify(&Action::new("tool:email", "")).is_err());
}

#[test]
fn cbor_round_trip() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let bytes = token.to_cbor().unwrap();
    let restored = DelegationToken::from_cbor(&bytes).unwrap();
    assert_eq!(token.vc_id(), restored.vc_id());
    assert_eq!(token.depth(), restored.depth());
    assert!(restored.verify(&Action::new("tool:search", "q=ok")).is_ok());
}

#[test]
fn delegation_chain_audit_entries() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let chain = token.chain();
    assert_eq!(chain.entries.len(), 1);
    assert_eq!(chain.entries[0].depth, 0);
    assert_eq!(chain.issuer_did, token.issuer_did());
}

#[test]
fn depth_limit_enforced() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 0);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 0);
    assert!(matches!(
        token.attenuate(narrow, 60, &sub),
        Err(AgentCredsError::DelegationDepthExceeded { .. })
    ));
}

#[test]
fn scope_subset_logic() {
    let parent = Scope::with_budget_and_depth(vec!["a".into(), "b".into()], Some(100), 3);
    let child_ok = Scope::with_budget_and_depth(vec!["a".into()], Some(50), 2);
    let child_wide = Scope::with_budget_and_depth(vec!["a".into(), "c".into()], Some(50), 2);
    assert!(child_ok.is_subset_of(&parent));
    assert!(!child_wide.is_subset_of(&parent));
}

#[test]
fn expired_token_is_rejected() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let mut token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    // Force the advisory expiry into the past - the friendly TokenExpired
    // path. (The Datalog time check is the cryptographic enforcement.)
    token.hops[0].expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert!(matches!(
        token.verify(&Action::new("tool:search", "")),
        Err(AgentCredsError::TokenExpired { .. })
    ));
}

#[test]
fn invalid_cbor_rejected() {
    assert!(DelegationToken::from_cbor(b"not valid cbor").is_err());
}

#[test]
fn scope_budget_widening_rejected() {
    let parent = Scope::with_budget_and_depth(vec!["a".into()], Some(50), 3);
    let wider = Scope::with_budget_and_depth(vec!["a".into()], Some(100), 2);
    assert!(!wider.is_subset_of(&parent));
}

#[test]
fn chain_entries_have_correct_agent_dids() {
    let (_anchor, agent, vc) = setup();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 1);
    let child = token.attenuate(narrow, 60, &sub).unwrap();
    let chain = child.chain();
    assert_eq!(chain.entries[0].agent_did, agent.did());
    assert_eq!(chain.entries[1].agent_did, sub.did());
    assert_eq!(chain.entries[0].depth, 0);
    assert_eq!(chain.entries[1].depth, 1);
}

#[test]
fn scope_new_constructor_defaults() {
    let scope = Scope::new(vec!["tool:x".into(), "tool:y".into()]);
    assert!(scope.tools.contains("tool:x"));
    assert_eq!(scope.budget_usd, None);
    assert_eq!(scope.max_depth, 0);
}

#[test]
fn action_new_sets_tool_and_parameters() {
    let action = Action::new("tool:search", "q=hello");
    assert_eq!(action.tool, "tool:search");
    assert_eq!(action.parameters, "q=hello");
}

#[test]
fn mint_from_expired_vc_fails() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let mut vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    vc.expiration_date = Utc::now() - chrono::Duration::seconds(1);
    let scope = Scope::new(vec!["tool:search".into()]);
    assert!(matches!(
        DelegationToken::mint(&vc, scope, 300, &agent),
        Err(AgentCredsError::CredentialExpired { .. })
    ));
}

#[test]
fn token_issuer_did_matches_vc_issuer() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert_eq!(token.issuer_did(), vc.issuer);
    assert_eq!(token.vc_id(), vc.id);
}

#[test]
fn mint_rejects_non_subject_agent() {
    let anchor = TrustAnchor::generate().unwrap();
    let subject = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let other = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, subject.did(), claims, None).unwrap();
    let scope = Scope::new(vec!["tool:search".into()]);
    assert!(DelegationToken::mint(&vc, scope, 300, &other).is_err());
}

// -- Forgery / tampering resistance ----------------------------------------

/// Tampering with the serialized Biscuit breaks the signature chain.
#[test]
fn tampered_biscuit_bytes_rejected() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let mut token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    // Flip bytes in the middle of the Biscuit container.
    let mid = token.biscuit.len() / 2;
    token.biscuit[mid] ^= 0xFF;
    assert!(token.verify(&Action::new("tool:search", "")).is_err());
}

/// A hop whose attestation does not bind its delegation key to its DID is
/// rejected - this is the per-hop identity binding.
#[test]
fn forged_hop_attestation_rejected() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let mut token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    // Corrupt the attestation: it no longer verifies against the DID.
    token.hops[0].attestation[0] ^= 0xFF;
    assert!(token.verify(&Action::new("tool:search", "")).is_err());
}

/// Claiming a different agent DID for a hop than the one whose key signed
/// the block breaks the attestation binding.
#[test]
fn hop_did_substitution_rejected() {
    let (_anchor, agent, vc) = setup();
    let victim = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let mut token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    // Rewrite the root DID to a victim the attacker does not control.
    token.hops[0].agent_did = victim.did().to_string();
    assert!(token.verify(&Action::new("tool:search", "")).is_err());
}

// -- Anchor binding (verify_rooted) ---------------------------------------

#[test]
fn verify_rooted_accepts_legitimate_token() {
    let (anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(token
        .verify_rooted(&Action::new("tool:search", "q=ok"), &vc, &anchor)
        .is_ok());
}

/// The self-signed-DID forgery: an attacker mints a perfectly valid chain
/// from their *own* anchor and VC. `verify` passes, but `verify_rooted`
/// against the relying party's real VC rejects it.
#[test]
fn verify_rooted_rejects_token_from_a_different_credential() {
    let (anchor, _agent, vc) = setup();

    let attacker_anchor = TrustAnchor::generate().unwrap();
    let attacker = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let mut attacker_claims = CapabilityClaims::new(vec!["tool:admin".into()], 5, 3600);
    attacker_claims.budget_usd = Some(1_000_000);
    let attacker_vc =
        CapabilityCredential::issue(&attacker_anchor, attacker.did(), attacker_claims, None)
            .unwrap();
    let broad = Scope::with_budget_and_depth(vec!["tool:admin".into()], Some(1_000_000), 5);
    let attacker_token = DelegationToken::mint(&attacker_vc, broad, 300, &attacker).unwrap();

    // Chain-only verification passes - it is a validly self-signed chain.
    assert!(attacker_token
        .verify(&Action::new("tool:admin", ""))
        .is_ok());
    // Anchor-rooted verification against the real VC/anchor rejects it.
    assert!(attacker_token
        .verify_rooted(&Action::new("tool:admin", ""), &vc, &anchor)
        .is_err());
}

#[test]
fn verify_rooted_rejects_wrong_anchor() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let wrong_anchor = TrustAnchor::generate().unwrap();
    assert!(token
        .verify_rooted(&Action::new("tool:search", "q=ok"), &vc, &wrong_anchor)
        .is_err());
}

/// A `did:web` agent's per-hop delegation-key attestation is verified by
/// resolving its DID document - `verify` without a resolver can't, but
/// `verify_with_resolver` can.
#[test]
fn did_web_hop_requires_and_uses_a_resolver() {
    use crate::did::InMemoryResolver;
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(
        DidMethod::Web {
            host: "example.com".into(),
            path: Some("agents/alice".into()),
        },
        None,
    )
    .unwrap();
    assert!(agent.did().starts_with("did:web:"));

    let claims = CapabilityClaims::new(vec!["tool:search".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let action = Action::new("tool:search", "q=ok");

    // No resolver -> the did:web hop's primary key can't be recovered.
    assert!(matches!(
        token.verify(&action),
        Err(AgentCredsError::ResolverRequired { .. })
    ));

    // With the agent's published did:web document, the attestation verifies.
    let mut resolver = InMemoryResolver::new();
    resolver.register(agent.did(), agent.document().clone());
    assert!(token.verify_with_resolver(&action, &resolver).is_ok());
    assert!(token
        .verify_rooted_with_resolver(&action, &vc, &anchor, &resolver)
        .is_ok());

    // A resolver missing the document still fails (resolution error) - on both the
    // plain and the rooted resolver paths (the rooted path must not shortcut to Ok).
    let empty = InMemoryResolver::new();
    assert!(token.verify_with_resolver(&action, &empty).is_err());
    assert!(token
        .verify_rooted_with_resolver(&action, &vc, &anchor, &empty)
        .is_err());
}

// -- On-behalf-of: principal binding & resource scope ---------------------

/// An anchor, agent, and an on-behalf-of credential bound to a human, whose
/// consent covers `tool:read_email`/`tool:search` and the `alice` mailbox.
fn setup_obo() -> (
    TrustAnchor,
    AgentIdentity,
    CapabilityCredential,
    HumanIdentity,
) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let human = HumanIdentity::from_idp("https://login.acme.com", "auth0|alice").unwrap();
    let claims = CapabilityClaims {
        tools: vec!["tool:read_email".into(), "tool:search".into()],
        resources: None,
        budget_usd: Some(500),
        max_delegation_depth: 3,
        valid_for_secs: 3600,
        autonomy_level: 0,
        model_version: None,
        artifact_hash: None,
        authorized_by: None,
        accountable_party: None,
        party_version: None,
        party_commitment: None,
        accountability_source: Default::default(),
        on_behalf_of: Some(human.authorize_now(
            Utc::now() + chrono::Duration::hours(1),
            vec!["tool:read_email".into(), "tool:search".into()],
            vec!["mailbox:alice@acme.com/*".into()],
            AuthoritySource::Attested,
        )),
        required_gates: Vec::new(),
    };
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    (anchor, agent, vc, human)
}

/// Regression guard for the Biscuit-authorizer run limit on the OBO path. The
/// authorizer's default 1 ms wall-clock `max_time` was timing-flaky (spurious
/// `ActionDenied: Reached Datalog execution limits` when a fast Datalog eval was
/// preempted mid-run under load); the effective bound is now facts/iterations. That
/// flake is preemption-driven and not deterministically reproducible in a unit test,
/// so this guards the deterministic half: an attenuated OBO chain verifies cleanly on
/// every call, and a grossly-too-tight facts/iterations limit would fail it outright.
#[test]
fn obo_chain_verifies_without_tripping_the_run_limit() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let child = token
        .attenuate(
            Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(50), 1)
                .with_resources(vec!["mailbox:alice@acme.com/42".into()]),
            120,
            &sub,
        )
        .unwrap();
    let action = Action::new("tool:read_email", "id=42")
        .on_behalf_of(human.did())
        .on_resource("mailbox:alice@acme.com/42");
    for i in 0..16 {
        child
            .verify_rooted(&action, &vc, &anchor)
            .unwrap_or_else(|e| panic!("valid OBO chain must verify (iteration {i}): {e}"));
    }
}

/// An OBO token can only be exercised on behalf of its bound principal: no
/// `acting_for` is rejected, the wrong one is rejected, the right one passes.
///
/// Asserts the *fields*, not just the variant. An earlier version matched only
/// `PrincipalMismatch { .. }`, which let a message that named the wrong side of
/// the comparison ship - and it then cost a full AWS deploy cycle to re-diagnose.
#[test]
fn obo_token_requires_matching_acting_for() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert_eq!(token.principal_did(), Some(human.did()));

    // No principal asserted -> rejected, and the error must say the REQUEST
    // asserted none while the TOKEN is bound - not the other way round.
    match token.verify(&Action::new("tool:read_email", "")) {
        Err(AgentCredsError::ActingForMismatch { required, asserted }) => {
            assert_eq!(required, human.did());
            assert_eq!(asserted, None);
        }
        other => panic!("expected ActingForMismatch, got {other:?}"),
    }
    // Wrong principal -> rejected, naming what was asserted.
    match token.verify(&Action::new("tool:read_email", "").on_behalf_of("did:web:evil.example")) {
        Err(AgentCredsError::ActingForMismatch { required, asserted }) => {
            assert_eq!(required, human.did());
            assert_eq!(asserted.as_deref(), Some("did:web:evil.example"));
        }
        other => panic!("expected ActingForMismatch, got {other:?}"),
    }
    // Correct principal -> permitted.
    assert!(token
        .verify(&Action::new("tool:read_email", "").on_behalf_of(human.did()))
        .is_ok());
}

/// The regression that cost the 2026-08-06 AWS run: a credential that names a
/// principal, presented with an `Action` carrying no `acting_for`, through
/// `verify_rooted` - the exact shape a PEP produces when it never bound one.
///
/// Two things are pinned here. First, the token is **not** at fault: the
/// principal survives mint, so `principal_did()` still reports it at the moment
/// verification fails. Second, the message must not blame the token, because
/// that is precisely what sent the original investigation into `hydrate`.
#[test]
fn verify_rooted_blames_the_request_not_the_token_when_acting_for_is_absent() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    // A PEP that never called `bind_principal` builds exactly this action.
    let action = Action::new("tool:read_email", "id=42");
    let err = token
        .verify_rooted(&action, &vc, &anchor)
        .expect_err("a token bound to a principal must not verify for an unbound request");

    match &err {
        AgentCredsError::ActingForMismatch { required, asserted } => {
            assert_eq!(required, human.did());
            assert_eq!(*asserted, None);
        }
        other => panic!("expected ActingForMismatch, got {other:?}"),
    }

    // The token still carries the principal - the getter and the failing check
    // agree, so nothing here justifies suspecting re-derivation.
    assert_eq!(token.principal_did(), Some(human.did()));

    // The message must name the request as the side that asserted nothing.
    let msg = err.to_string();
    assert!(
        msg.contains("the request asserts principal '<none>'"),
        "message must blame the request, got: {msg}"
    );
    assert!(
        msg.contains(&format!("token is bound to '{}'", human.did())),
        "message must report the token as bound, got: {msg}"
    );

    // Supplying the principal the relying party verified for itself fixes it -
    // the token needed no change.
    assert!(token
        .verify_rooted(&action.clone().on_behalf_of(human.did()), &vc, &anchor)
        .is_ok());
}

/// The other half of the split, stated honestly: `PrincipalMismatch`
/// (token-vs-credential) is **defense in depth**, not a check production reaches.
///
/// A token records the id of the credential it was minted from, and `mint` copies
/// the principal straight out of that credential - so the two can only disagree if
/// the token is presented with a *different* credential, which the linkage check
/// (step 2) rejects first. That ordering is what this test pins.
///
/// Worth stating because the two variants have very different lifetimes: the
/// token-vs-credential one is a backstop, while the request-vs-token one
/// (`ActingForMismatch`) is the one every PEP can hit - and it was the one
/// carrying the wrong message.
#[test]
fn a_foreign_credential_is_refused_at_linkage_before_the_principal_check() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    // A second, independently issued credential for the same agent that authorizes
    // nobody. Anchor-signed and valid in its own right - only unrelated to the token.
    let mut plain = CapabilityClaims::new(vec!["tool:read_email".into()], 2, 3600);
    plain.budget_usd = Some(100);
    let other_vc = CapabilityCredential::issue(&anchor, agent.did(), plain, None).unwrap();
    assert_ne!(other_vc.id, vc.id, "ids are derived, so these must differ");

    // Correct `acting_for`, so nothing here is the request's fault.
    let action = Action::new("tool:read_email", "").on_behalf_of(human.did());
    match token.verify_rooted(&action, &other_vc, &anchor) {
        Err(AgentCredsError::InvalidBiscuitSignature { reason }) => {
            assert!(
                reason.contains("vc_id"),
                "must fail at credential linkage, got: {reason}"
            );
        }
        other => panic!("expected the linkage check to fire first, got {other:?}"),
    }
}

/// `mint` must refuse a scope wider than the credential grants.
///
/// Found by mutation on 2026-08-07: disabling this check left all 324 core tests
/// green. Both widening tests covered `attenuate`; nothing covered `mint`, so the
/// first hop - the one that turns a credential into a token - could have been
/// widened by a refactor with no test to notice.
///
/// `verify_rooted` re-checks the same subset at step 4, so a widened token would
/// still be refused at a relying party. That is defense in depth working, and it is
/// exactly why the gap was invisible: the *system* stayed safe while the *check*
/// became dead code. Each layer needs its own test or "defense in depth" decays into
/// one layer nobody can find.
#[test]
fn mint_refuses_a_scope_wider_than_the_credential() {
    let (anchor, agent, vc) = setup(); // tools: search/email/calendar, budget 500, depth 3

    // A tool the credential never granted.
    let extra_tool = Scope::with_budget_and_depth(
        vec!["tool:search".into(), "tool:admin".into()],
        Some(100),
        1,
    );
    match DelegationToken::mint(&vc, extra_tool, 300, &agent) {
        Err(AgentCredsError::ScopeWideningAttempt { capability }) => {
            assert_eq!(
                capability, "tool:admin",
                "the widening capability must be named"
            );
        }
        other => panic!("mint accepted a tool the credential never granted: {other:?}"),
    }

    // Budget above the credential's ceiling.
    let extra_budget = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100_000), 1);
    assert!(
        matches!(
            DelegationToken::mint(&vc, extra_budget, 300, &agent),
            Err(AgentCredsError::ScopeWideningAttempt { .. })
        ),
        "mint accepted a budget above the credential's ceiling"
    );

    // Depth beyond the credential's ceiling.
    let extra_depth = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 9);
    assert!(
        matches!(
            DelegationToken::mint(&vc, extra_depth, 300, &agent),
            Err(AgentCredsError::ScopeWideningAttempt { .. })
        ),
        "mint accepted a delegation depth above the credential's ceiling"
    );

    // The control: a scope within the grant still mints. Without it the three cases
    // above also pass for an implementation that refuses every mint.
    let within = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    DelegationToken::mint(&vc, within, 300, &agent).expect("a scope within the grant must mint");
    let _ = &anchor;
}

/// The bound principal is fixed in the authority block, so attenuation can
/// neither drop nor swap it - a sub-agent still acts only for the same human.
#[test]
fn principal_cannot_change_across_hops() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(
        vec!["tool:read_email".into(), "tool:search".into()],
        Some(100),
        3,
    );
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 2);
    let child = token.attenuate(narrow, 60, &sub).unwrap();

    assert_eq!(child.principal_did(), Some(human.did()));
    assert!(child
        .verify(&Action::new("tool:search", "").on_behalf_of(human.did()))
        .is_ok());
    assert!(matches!(
        child.verify(&Action::new("tool:search", "").on_behalf_of("did:web:bob.example")),
        Err(AgentCredsError::ActingForMismatch { .. })
    ));
}

/// `verify_rooted` accepts a legitimate OBO token whose principal matches the
/// credential it derives from.
#[test]
fn verify_rooted_accepts_matching_principal() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let action = Action::new("tool:read_email", "").on_behalf_of(human.did());
    assert!(token.verify_rooted(&action, &vc, &anchor).is_ok());
}

// -- R10: execution-time human authorization (in-chain gate + evidence) ------

// A rooted, on-behalf-of token that gates `tool:read_email` on human approval.
fn gated_token() -> (
    TrustAnchor,
    CapabilityCredential,
    HumanIdentity,
    DelegationToken,
) {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()])
        .require_approval("tool:read_email");
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    (anchor, vc, human, token)
}

fn gated_action(human: &HumanIdentity) -> Action {
    Action::new("tool:read_email", "id=42")
        .on_behalf_of(human.did())
        .on_resource("mailbox:alice@acme.com/42")
}

#[test]
fn r10_gate_travels_and_denies_without_evidence() {
    let (anchor, vc, human, token) = gated_token();
    // The designation is carried inside the delegated authority.
    assert!(token.gates().contains(&Gate::approval("tool:read_email")));
    assert_eq!(token.required_gates(&gated_action(&human)).len(), 1);
    // Designated action, no evidence -> refused (fail closed).
    let now = Utc::now().timestamp();
    let denied = token.verify_rooted_gated(
        &gated_action(&human),
        &vc,
        &anchor,
        &[],
        &[Gate::APPROVAL],
        now,
    );
    assert!(matches!(denied, Err(AgentCredsError::ActionDenied { .. })));
}

#[test]
fn r10_principal_bound_evidence_satisfies_the_gate() {
    let (anchor, vc, human, token) = gated_token();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let ev =
        ApprovalEvidence::approve(&action, "operator:carol", "appr-1", now + 300, &anchor).unwrap();
    let relied = token
        .verify_rooted_gated(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            &[Gate::APPROVAL],
            now,
        )
        .unwrap();
    assert_eq!(relied, vec!["appr-1".to_string()]);
}

#[test]
fn r10_evidence_bound_to_a_different_principal_is_rejected() {
    let (anchor, vc, human, token) = gated_token();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    // Approved for the same operation and resource but a DIFFERENT principal;
    // the approval binding includes the principal, so it cannot satisfy this call.
    let other = Action::new("tool:read_email", "id=42")
        .on_behalf_of("did:key:zSomeoneElse")
        .on_resource("mailbox:alice@acme.com/42");
    let ev =
        ApprovalEvidence::approve(&other, "operator:carol", "appr-2", now + 300, &anchor).unwrap();
    let denied = token.verify_rooted_gated(&action, &vc, &anchor, &[ev], &[Gate::APPROVAL], now);
    assert!(matches!(denied, Err(AgentCredsError::ActionDenied { .. })));
}

#[test]
fn r10_unrecognized_gate_kind_fails_closed() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()])
        .with_gates(vec![Gate {
            kind: "biometric".into(),
            tool: "tool:read_email".into(),
        }]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let now = Utc::now().timestamp();
    // The relying party recognizes only "approval"; the biometric designation
    // is unsatisfiable, so the action is unauthorized.
    let denied = token.verify_rooted_gated(
        &gated_action(&human),
        &vc,
        &anchor,
        &[],
        &[Gate::APPROVAL],
        now,
    );
    assert!(matches!(denied, Err(AgentCredsError::ActionDenied { .. })));
}

#[test]
fn r10_gate_is_monotone_child_cannot_remove() {
    let (anchor, vc, human, token) = gated_token();
    // A sub-agent attenuates WITHOUT re-declaring the gate.
    let child_agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(50), 1)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()]);
    let child = token.attenuate(narrow, 200, &child_agent).unwrap();
    // The designation still travels - a child cannot drop it (monotone).
    assert!(child.gates().contains(&Gate::approval("tool:read_email")));
    let now = Utc::now().timestamp();
    let denied = child.verify_rooted_gated(
        &gated_action(&human),
        &vc,
        &anchor,
        &[],
        &[Gate::APPROVAL],
        now,
    );
    assert!(matches!(denied, Err(AgentCredsError::ActionDenied { .. })));
}

#[test]
fn r10_expired_and_tampered_evidence_rejected() {
    let (anchor, vc, human, token) = gated_token();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    // Expired evidence.
    let expired = ApprovalEvidence::approve(&action, "op", "e1", now - 1, &anchor).unwrap();
    assert!(token
        .verify_rooted_gated(&action, &vc, &anchor, &[expired], &[Gate::APPROVAL], now)
        .is_err());
    // Tampered signature.
    let mut bad = ApprovalEvidence::approve(&action, "op", "e2", now + 300, &anchor).unwrap();
    bad.signature = "00".repeat(bad.signature.len() / 2);
    assert!(token
        .verify_rooted_gated(&action, &vc, &anchor, &[bad], &[Gate::APPROVAL], now)
        .is_err());
}

#[test]
fn r10_evidence_is_one_time() {
    // R10 "not previously relied upon": the same valid evidence, verified twice,
    // is accepted once and refused on re-use via the consumed-approvals record.
    let (anchor, vc, human, token) = gated_token();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let ev = ApprovalEvidence::approve(&action, "op", "once-1", now + 300, &anchor).unwrap();
    let mut consumed = ConsumedApprovals::new();

    // First reliance: verify succeeds and the id consumes cleanly.
    let ids = token
        .verify_rooted_gated(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            &[Gate::APPROVAL],
            now,
        )
        .unwrap();
    assert!(ids.iter().all(|id| consumed.try_consume(id)));

    // Second reliance on the same evidence: cryptographic verify still passes,
    // but the id is already spent -> the relying party must refuse.
    let ids2 = token
        .verify_rooted_gated(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            &[Gate::APPROVAL],
            now,
        )
        .unwrap();
    assert!(
        ids2.iter().all(|id| !consumed.try_consume(id)),
        "re-used evidence must not consume again"
    );
}

#[test]
fn r10_credential_mandated_gate_is_enforced_even_if_token_omits_it() {
    // The *credential* mandates approval for tool:read_email; a token minted with
    // a plain scope (no gate) is still held to it - a gated credential can't be
    // spent ungated (R10 strong form, issuer mandate).
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:read_email".into()], 2, 3600)
        .require_approval("tool:read_email");
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    // Plain scope - the minting agent declares NO gate.
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let action = Action::new("tool:read_email", "id=1");
    let now = Utc::now().timestamp();

    // Denied without evidence - the credential's mandate is enforced.
    assert!(matches!(
        token.verify_rooted_gated(&action, &vc, &anchor, &[], &[Gate::APPROVAL], now),
        Err(AgentCredsError::ActionDenied { .. })
    ));
    // Allowed with valid evidence.
    let ev = ApprovalEvidence::approve(&action, "op", "m1", now + 300, &anchor).unwrap();
    assert!(token
        .verify_rooted_gated(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            &[Gate::APPROVAL],
            now
        )
        .is_ok());
    // mint also emitted the mandated gate into the token, so it travels onward.
    assert!(token.gates().contains(&Gate::approval("tool:read_email")));
}

// -- Hybrid R10: approver-key-signed evidence under the org anchor -----------

fn approver_dir(
    anchor: &TrustAnchor,
    approver: &AgentIdentity,
    roles: Vec<&str>,
) -> ApproverDirectory {
    let entry = ApproverEntry {
        approver_id: "operator:carol".into(),
        approver_did: approver.did().to_string(),
        roles: roles.into_iter().map(String::from).collect(),
        not_after: None,
    };
    ApproverDirectory::seal(vec![entry], 1, Utc::now(), None, anchor).unwrap()
}

fn approval_key_token(
    anchor: &TrustAnchor,
    agent: &AgentIdentity,
    vc: &CapabilityCredential,
) -> DelegationToken {
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()])
        .with_gates(vec![Gate::approval_key("tool:read_email")]);
    let _ = anchor;
    DelegationToken::mint(vc, scope, 300, agent).unwrap()
}

#[test]
fn r10_approver_key_evidence_satisfies_gate() {
    let (anchor, agent, vc, human) = setup_obo();
    let token = approval_key_token(&anchor, &agent, &vc);
    let action = gated_action(&human);
    let now = Utc::now().timestamp();

    // A distinct human approver, enrolled in the org-anchor-signed directory.
    let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let dir = approver_dir(&anchor, &approver, vec!["finance"]);
    let ev =
        ApprovalEvidence::approve_by_key(&action, "operator:carol", &approver, "ak-1", now + 300)
            .unwrap();

    let relied = token
        .verify_rooted_gated_with_directory(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            Some(&dir),
            &[Gate::APPROVAL_KEY],
            now,
        )
        .unwrap();
    assert_eq!(relied, vec!["ak-1".to_string()]);
}

#[test]
fn r10_approver_key_from_non_enrolled_approver_is_rejected() {
    let (anchor, agent, vc, human) = setup_obo();
    let token = approval_key_token(&anchor, &agent, &vc);
    let action = gated_action(&human);
    let now = Utc::now().timestamp();

    let enrolled = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let dir = approver_dir(&anchor, &enrolled, vec![]);
    // Signed by a DIFFERENT approver, absent from the directory - forgery fails.
    let rogue = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let ev =
        ApprovalEvidence::approve_by_key(&action, "operator:mallory", &rogue, "ak-x", now + 300)
            .unwrap();

    assert!(matches!(
        token.verify_rooted_gated_with_directory(
            &action,
            &vc,
            &anchor,
            &[ev],
            Some(&dir),
            &[Gate::APPROVAL_KEY],
            now
        ),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

#[test]
fn r10_approver_key_gate_requires_a_directory() {
    let (anchor, agent, vc, human) = setup_obo();
    let token = approval_key_token(&anchor, &agent, &vc);
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let ev = ApprovalEvidence::approve_by_key(&action, "op", &approver, "ak", now + 300).unwrap();
    // No directory configured -> the approval-key gate is unsatisfiable.
    assert!(matches!(
        token.verify_rooted_gated_with_directory(
            &action,
            &vc,
            &anchor,
            &[ev],
            None,
            &[Gate::APPROVAL_KEY],
            now
        ),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

#[test]
fn r10_approver_directory_tamper_and_expiry_rejected() {
    let (anchor, _agent, _vc, human) = setup_obo();
    let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let ev = ApprovalEvidence::approve_by_key(&action, "op", &approver, "ak", now + 300).unwrap();

    // Tampered directory signature -> rejected.
    let mut dir = approver_dir(&anchor, &approver, vec![]);
    dir.signature = "00".repeat(dir.signature.len() / 2);
    assert!(ev
        .verify_with_directory(&action, &dir, &anchor, now, None)
        .is_err());

    // Expired directory -> rejected (bounded staleness).
    let dir2 = ApproverDirectory::seal(
        vec![ApproverEntry {
            approver_id: "op".into(),
            approver_did: approver.did().to_string(),
            roles: vec![],
            not_after: None,
        }],
        1,
        Utc::now(),
        Some(Utc::now() - chrono::Duration::seconds(10)),
        &anchor,
    )
    .unwrap();
    assert!(ev
        .verify_with_directory(&action, &dir2, &anchor, now, None)
        .is_err());
}

#[test]
fn r10_approver_key_role_requirement_enforced() {
    let (anchor, _agent, _vc, human) = setup_obo();
    let approver = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let dir = approver_dir(&anchor, &approver, vec!["ops"]);
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let ev = ApprovalEvidence::approve_by_key(&action, "op", &approver, "ak", now + 300).unwrap();
    // Approver holds "ops", not "finance".
    assert!(ev
        .verify_with_directory(&action, &dir, &anchor, now, Some("finance"))
        .is_err());
    assert!(ev
        .verify_with_directory(&action, &dir, &anchor, now, Some("ops"))
        .is_ok());
}

#[test]
fn r10_anchor_mode_still_works_via_directory_method() {
    // The directory-aware method is a superset: plain anchor-mode gates and
    // evidence keep working with no directory.
    let (anchor, vc, human, token) = gated_token();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();
    let ev = ApprovalEvidence::approve(&action, "operator", "a1", now + 300, &anchor).unwrap();
    let relied = token
        .verify_rooted_gated_with_directory(
            &action,
            &vc,
            &anchor,
            std::slice::from_ref(&ev),
            None,
            &[Gate::APPROVAL],
            now,
        )
        .unwrap();
    assert_eq!(relied, vec!["a1".to_string()]);
}

#[test]
fn r10_ungated_tool_needs_no_evidence() {
    // `tool:search` is in scope but NOT gated -> no evidence required.
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(
        vec!["tool:read_email".into(), "tool:search".into()],
        Some(100),
        2,
    )
    .with_resources(vec!["mailbox:alice@acme.com/42".into()])
    .require_approval("tool:read_email");
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let action = Action::new("tool:search", "q=ok")
        .on_behalf_of(human.did())
        .on_resource("mailbox:alice@acme.com/42");
    let now = Utc::now().timestamp();
    assert!(token
        .verify_rooted_gated(&action, &vc, &anchor, &[], &[Gate::APPROVAL], now)
        .is_ok());
}

/// A resource-scoped token permits only the listed resources; an unlisted
/// resource, and an absent resource, are both denied.
#[test]
fn resource_scope_is_enforced() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec![
            "mailbox:alice@acme.com/a".into(),
            "mailbox:alice@acme.com/b".into(),
        ]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let p = human.did();

    // Listed resource -> ok.
    assert!(token
        .verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/a")
        )
        .is_ok());
    // Unlisted resource -> denied.
    assert!(matches!(
        token.verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/c")
        ),
        Err(AgentCredsError::ActionDenied { .. })
    ));
    // No resource on a resource-scoped token -> denied.
    assert!(matches!(
        token.verify(&Action::new("tool:read_email", "").on_behalf_of(p)),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

/// Resource scope narrows across a hop: a resource the parent allowed but the
/// child dropped is denied at the child.
#[test]
fn resource_scope_narrows_on_attenuate() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec![
            "mailbox:alice@acme.com/a".into(),
            "mailbox:alice@acme.com/b".into(),
        ]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let narrow = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(50), 1)
        .with_resources(vec!["mailbox:alice@acme.com/a".into()]);
    let child = token.attenuate(narrow, 60, &sub).unwrap();
    let p = human.did();

    assert!(child
        .verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/a")
        )
        .is_ok());
    // /b was narrowed away.
    assert!(matches!(
        child.verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/b")
        ),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

/// A child cannot widen resources: even if it re-lists a resource the parent
/// never granted, the parent's check still rejects it (intersection only).
#[test]
fn resource_widening_via_child_block_has_no_effect() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/a".into()]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    // Child re-lists /a (kept) and tries to add /b (within the human's
    // authority, but the parent never granted it at this hop).
    let narrow = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(50), 1)
        .with_resources(vec![
            "mailbox:alice@acme.com/a".into(),
            "mailbox:alice@acme.com/b".into(),
        ]);
    let child = token.attenuate(narrow, 60, &sub).unwrap();
    let p = human.did();

    // /a still works; /b is rejected because the parent block excludes it.
    assert!(child
        .verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/a")
        )
        .is_ok());
    assert!(matches!(
        child.verify(
            &Action::new("tool:read_email", "")
                .on_behalf_of(p)
                .on_resource("mailbox:alice@acme.com/b")
        ),
        Err(AgentCredsError::ActionDenied { .. })
    ));
}

/// Minting a token whose resources fall outside the human's resource
/// authority is a consent violation.
#[test]
fn mint_rejects_resource_outside_principal_authority() {
    let (_anchor, agent, vc, _human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:bob@acme.com/x".into()]); // not Alice's
    assert!(matches!(
        DelegationToken::mint(&vc, scope, 300, &agent),
        Err(AgentCredsError::ConsentViolation { .. })
    ));
}

/// The audit view surfaces the bound principal and per-hop resources.
#[test]
fn chain_audit_includes_principal_and_resources() {
    let (_anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/a".into()]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let chain = token.chain();
    assert_eq!(chain.principal_did.as_deref(), Some(human.did()));
    assert!(chain.entries[0]
        .resources
        .contains(&"mailbox:alice@acme.com/a".to_string()));
}

/// A non-OBO token is unaffected: it verifies with no `acting_for`.
#[test]
fn non_obo_token_needs_no_principal() {
    let (_anchor, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert_eq!(token.principal_did(), None);
    assert!(token.verify(&Action::new("tool:search", "q=ok")).is_ok());
}

#[test]
fn datalog_injection_in_tool_is_rejected() {
    let (_anchor, agent, vc) = setup();
    // A tool identifier trying to break out of the Datalog string.
    let scope = Scope::new(vec!["tool:\"; allow if true; //".into()]);
    // mint validates scope subset of vc (this tool is not in the VC), so it fails
    // as a widening attempt before any Datalog is emitted.
    assert!(DelegationToken::mint(&vc, scope, 300, &agent).is_err());
}

// -- Refusal paths ------------------------------------------------------------
//
// The checks below all REJECT. An untested refusal is a worse hazard than an
// untested success: if an accept path breaks, some test somewhere goes red; if a
// refusal breaks, the system **fails open** and every suite stays green. These were
// found unexercised by a production-only coverage audit on 2026-08-08 - the same
// shape as the `mint` scope-widening gap that 324 passing tests had not noticed.
//
// Each asserts the *specific* error, not merely `is_err()`. A test that accepts any
// error passes when the code refuses for an unrelated reason, which is how a check can
// be dead while looking covered.

/// Malformed delegation key material must be refused, not panicked on. These are
/// private helpers reachable from untrusted input via token decoding, so the bound is
/// "returns an error" rather than "does not crash".
#[test]
fn malformed_delegation_key_material_is_refused() {
    // Only wrong LENGTHS are refusable here: an Ed25519 secret is an arbitrary
    // 32-byte seed, so there is no such thing as a 32-byte value that is not a
    // valid secret. Asserting otherwise (as a first draft of this test did) fails.
    for bad in [vec![0u8; 5], vec![0u8; 31], vec![0u8; 33]] {
        assert!(
            matches!(
                keypair_from_secret(&bad),
                Err(AgentCredsError::InvalidKeyMaterial { .. })
            ),
            "secret of {} bytes must be refused as key material",
            bad.len()
        );
    }
    for bad in [vec![0u8; 5], vec![0u8; 31]] {
        assert!(
            matches!(
                pubkey_from_bytes(&bad),
                Err(AgentCredsError::InvalidKeyMaterial { .. })
            ),
            "public key of {} bytes must be refused",
            bad.len()
        );
    }
}

/// Datalog string terms are quoted, so any character that could close the quote and
/// inject a clause has to be refused before it reaches a block. This is the injection
/// guard; `datalog_str` is where it lives.
#[test]
fn datalog_terms_reject_quote_breakout_characters() {
    for bad in ["a\"b", "a\\b", "a\nb", "a\rb", "a\0b"] {
        assert!(
            matches!(
                datalog_str(bad),
                Err(AgentCredsError::OutOfBounds { field: "scope", .. })
            ),
            "{bad:?} must not be accepted as a Datalog term"
        );
    }
    // The control: an ordinary tool identifier still quotes.
    assert_eq!(datalog_str("tool:search").unwrap(), "\"tool:search\"");
}

/// The delegation-depth ceiling is enforced when the chain is EXTENDED, not merely
/// when it is presented - so an over-deep token cannot be built in the first place.
///
/// The verify-time check is the backstop behind it. Worth stating which layer refuses:
/// a first draft of this test asserted the refusal at `verify_rooted` and passed only
/// because `attenuate` had already made the over-deep token unconstructible.
#[test]
fn a_chain_deeper_than_the_credential_allows_is_refused() {
    let (anchor, agent, vc) = setup(); // max_delegation_depth = 3
    let mut cur = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 3),
        300,
        &agent,
    )
    .unwrap();

    // Three hops reach the ceiling and must all succeed.
    for hop in 0..3 {
        let child = AgentIdentity::create(DidMethod::Key, None).unwrap();
        cur = cur
            .attenuate(
                Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 0),
                300,
                &child,
            )
            .unwrap_or_else(|e| panic!("hop {hop} is within the ceiling but failed: {e:?}"));
    }
    assert!(cur
        .verify_rooted(&Action::new("tool:search", ""), &vc, &anchor)
        .is_ok());

    // The fourth breaches it, and the error names both sides.
    let child = AgentIdentity::create(DidMethod::Key, None).unwrap();
    match cur.attenuate(
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 0),
        300,
        &child,
    ) {
        Err(AgentCredsError::DelegationDepthExceeded { depth, max }) => {
            assert_eq!((depth, max), (4, 3), "the error must show the breach");
        }
        other => panic!("a fourth hop must be refused: {other:?}"),
    }
}

/// A token presented with the wrong credential is refused at linkage. Three distinct
/// caches back this - vc id, issuer, subject - and each is defence in depth for the
/// others, so each needs its own test or two of the three can rot unnoticed.
#[test]
fn a_token_is_refused_against_a_credential_it_was_not_minted_from() {
    let (anchor_a, agent_a, vc_a) = setup();
    let (_anchor_b, _agent_b, vc_b) = setup(); // different anchor, agent and vc id

    let token = DelegationToken::mint(
        &vc_a,
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1),
        300,
        &agent_a,
    )
    .unwrap();

    // Foreign credential: refused, and NOT by accident of the anchor check - the
    // anchor here is the one that signed vc_a.
    assert!(
        token
            .verify_rooted(&Action::new("tool:search", ""), &vc_b, &anchor_a)
            .is_err(),
        "a token must not verify against a credential it was not derived from"
    );
}

/// An action naming a different human than the token is bound to is refused, and the
/// error names both sides so a diagnosis does not require re-deriving which is which.
///
/// NOTE on the two arms this does *not* reach. `verify_rooted` also rejects a token
/// that carries a principal the credential does not (and vice versa) - but those arms
/// sit behind the vc-id linkage check at step 2, and two different credentials always
/// have different ids. They are therefore reachable only with a forged or corrupted
/// credential, which is exactly what they are defence in depth against. Recorded rather
/// than forced with a synthetic mutation, so the limit is visible to the next reader.
#[test]
fn an_action_naming_a_different_principal_is_refused() {
    let (anchor, agent, vc, human) = setup_obo();
    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 1),
        300,
        &agent,
    )
    .unwrap();
    assert_eq!(token.principal_did(), Some(human.did()));

    let wrong = Action::new("tool:search", "").on_behalf_of("did:key:zSomeoneElse");
    match token.verify_rooted(&wrong, &vc, &anchor) {
        // The token's own Datalog `acting_for` check fires first, which is the
        // cryptographic enforcement; step 5's `PrincipalMismatch` is the layer behind
        // it. Asserting the outer error keeps this test about observable behaviour
        // rather than about which layer happens to win.
        Err(AgentCredsError::ActingForMismatch { required, asserted }) => {
            assert_eq!(required, human.did(), "required = the credential's human");
            assert_eq!(
                asserted.as_deref(),
                Some("did:key:zSomeoneElse"),
                "asserted = what the request claimed"
            );
        }
        other => panic!("an action naming another principal must be refused: {other:?}"),
    }
}

/// A resource outside the human's consented authority is refused even though the tool
/// itself is granted. Consent bounds WHAT the agent may touch, not only which verb it
/// may use - so a token scoped to bob's mailbox under alice's consent must not run.
#[test]
fn a_resource_outside_the_humans_consent_is_refused() {
    let (anchor, agent, vc, human) = setup_obo(); // consent covers alice's mailbox only
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 1)
        .with_resources(vec!["mailbox:bob@acme.com/inbox".into()]);

    // The bound may hold at mint or at verification; either is correct, but it must
    // hold somewhere. Asserting "refused at one of the two layers" keeps the test
    // honest about which layer owns it without pinning an implementation detail.
    let Ok(token) = DelegationToken::mint(&vc, scope, 300, &agent) else {
        return; // refused at mint - the earlier, better layer
    };
    let action = Action::new("tool:search", "")
        .on_resource("mailbox:bob@acme.com/inbox")
        .on_behalf_of(human.did());
    match token.verify_rooted(&action, &vc, &anchor) {
        Err(AgentCredsError::ConsentViolation { capability }) => {
            assert!(
                capability.contains("bob"),
                "the error must name the unconsented resource: {capability}"
            );
        }
        other => panic!("an unconsented resource must be refused: {other:?}"),
    }
}

/// A structurally corrupt token must be refused rather than parsed optimistically.
#[test]
fn a_corrupt_token_is_refused_at_decode_or_verify() {
    let (anchor, agent, vc) = setup();
    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1),
        300,
        &agent,
    )
    .unwrap();
    let mut cbor = token.to_cbor().unwrap();

    // Flip a byte deep in the payload - past any length prefix.
    let idx = cbor.len() / 2;
    cbor[idx] ^= 0xff;

    match DelegationToken::from_cbor(&cbor) {
        Err(_) => {} // refused at decode, which is the earliest and best place
        Ok(t) => assert!(
            t.verify_rooted(&Action::new("tool:search", ""), &vc, &anchor)
                .is_err(),
            "a token whose bytes were altered must not verify"
        ),
    }
}

/// The as-of API added for audit re-verification and golden vectors: it must agree with
/// the wall-clock path at the present instant, and must judge expiry against the instant
/// it is GIVEN - otherwise it is not doing the one thing it exists for.
#[test]
fn as_of_verification_uses_the_instant_it_is_given() {
    let (anchor, agent, vc) = setup();
    let action = Action::new("tool:search", "");
    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1),
        300, // five minutes
        &agent,
    )
    .unwrap();

    let now = Utc::now();
    // Agrees with the default path when asked about now.
    assert!(token.verify_rooted_at(&action, &vc, &anchor, now).is_ok());
    assert!(token.verify_rooted(&action, &vc, &anchor).is_ok());
    assert!(token.verify_at(&action, now).is_ok());

    // Past the token's life: refused, even though the wall clock still accepts it.
    assert!(
        token
            .verify_rooted_at(&action, &vc, &anchor, now + chrono::Duration::hours(2))
            .is_err(),
        "an instant past the token's expiry must be refused"
    );
    // FINDING, recorded rather than asserted: there is **no not-before check**. A
    // token verifies at an instant before it was issued, because the Datalog carries
    // only `time <= expiry`. That is not a hole on the enforcement path - you cannot
    // present a token you do not yet hold - but an as-of caller should know the window
    // is open-ended below, and a future not-before would change this line.
    assert!(
        token
            .verify_rooted_at(&action, &vc, &anchor, now - chrono::Duration::days(1))
            .is_ok(),
        "documents today's behaviour: expiry is bounded above only"
    );
    // The credential's own as-of check agrees.
    assert!(vc.is_valid_at(now));
    assert!(!vc.is_valid_at(now + chrono::Duration::days(365 * 10)));
    assert!(vc
        .verify_at(&anchor, true, now + chrono::Duration::days(365 * 10))
        .is_err());
}

#[cfg(feature = "proptest")]
// Same allowance the other test modules carry. Without it the crate-level
// `deny(clippy::expect_used)` fires here, but only under `--all-features`,
// which is why it stayed latent: the core CI job runs `--all-targets` alone.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    fn nested_tool_lists() -> impl Strategy<Value = (Vec<String>, Vec<String>, Vec<String>)> {
        proptest::collection::vec("tool:[a-z]{1,8}", 0..6).prop_flat_map(|c| {
            let c_for_b = c.clone();
            proptest::sample::subsequence(c.clone(), 0..=c.len()).prop_flat_map(move |b| {
                let b_for_a = b.clone();
                let c_for_a = c_for_b.clone();
                proptest::sample::subsequence(b.clone(), 0..=b.len())
                    .prop_map(move |a| (a, b_for_a.clone(), c_for_a.clone()))
            })
        })
    }

    fn parent_scope() -> Scope {
        Scope::with_budget_and_depth(
            vec![
                "tool:search".into(),
                "tool:email".into(),
                "tool:calendar".into(),
            ],
            Some(500),
            3,
        )
    }

    fn arb_subset_scope(parent: &Scope) -> impl Strategy<Value = Scope> {
        let tools: Vec<String> = parent.tools.iter().cloned().collect();
        let max_budget = parent.budget_usd.unwrap_or(0);
        let max_depth = parent.max_depth;
        (
            proptest::sample::subsequence(tools.clone(), 0..=tools.len()),
            proptest::option::of(0..=max_budget),
            0..=max_depth,
        )
            .prop_map(|(tools, budget, depth)| Scope::with_budget_and_depth(tools, budget, depth))
    }

    proptest! {
        #[test]
        fn scope_subset_is_transitive((a_tools, b_tools, c_tools) in nested_tool_lists()) {
            let a = Scope::new(a_tools);
            let b = Scope::new(b_tools);
            let c = Scope::new(c_tools);
            prop_assert!(a.is_subset_of(&b));
            prop_assert!(b.is_subset_of(&c));
            prop_assert!(a.is_subset_of(&c));
        }

        #[test]
        fn scope_subset_budget_is_monotonic(child_budget in 0u32..10_000, parent_budget in 0u32..10_000) {
            let child = Scope::with_budget_and_depth(vec![], Some(child_budget), 0);
            let parent = Scope::with_budget_and_depth(vec![], Some(parent_budget), 0);
            prop_assert_eq!(child.is_subset_of(&parent), child_budget <= parent_budget);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Whenever `attenuate` succeeds on a scope subset of the parent, the child
        /// verifies for an allowed tool and the depth advances by one.
        #[test]
        fn attenuate_result_is_subset_of_parent(narrow in arb_subset_scope(&parent_scope())) {
            let (_anchor, agent, vc) = setup();
            let token = DelegationToken::mint(&vc, parent_scope(), 3600, &agent).unwrap();
            let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
            let child = token.attenuate(narrow.clone(), 60, &sub).unwrap();
            prop_assert_eq!(child.depth(), 1);
            for t in &narrow.tools {
                prop_assert!(child.verify(&Action::new(t.clone(), "")).is_ok());
            }
        }
    }

    // -- R1 flagship properties: monotonic attenuation is verifiable end-to-end --

    /// A chain of up to three progressively shrinking subsets of the root's tools.
    fn arb_rooted_chain() -> impl Strategy<Value = Vec<Vec<String>>> {
        let root: Vec<String> = vec![
            "tool:search".into(),
            "tool:email".into(),
            "tool:calendar".into(),
        ];
        proptest::sample::subsequence(root, 0..=3).prop_flat_map(|h1| {
            let h1a = h1.clone();
            proptest::sample::subsequence(h1.clone(), 0..=h1.len()).prop_flat_map(move |h2| {
                let h1b = h1a.clone();
                let h2a = h2.clone();
                proptest::sample::subsequence(h2.clone(), 0..=h2.len())
                    .prop_map(move |h3| vec![h1b.clone(), h2a.clone(), h3])
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// R1 - widening is ALWAYS rejected. Attenuation that adds a capability the
        /// parent lacks fails at construction with a clear ScopeWideningAttempt, for
        /// any generated tool disjoint from the parent's set - so a relying party
        /// never depends on the issuer's policy to prevent widening.
        #[test]
        fn widening_tools_is_always_rejected(extra in "x:[a-z]{1,6}") {
            let (_anchor, agent, vc) = setup();
            let root = Scope::with_budget_and_depth(
                vec!["tool:search".into(), "tool:email".into(), "tool:calendar".into()],
                Some(500), 3,
            );
            let token = DelegationToken::mint(&vc, root.clone(), 3600, &agent).unwrap();
            let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
            let mut wide: Vec<String> = root.tools.iter().cloned().collect();
            wide.push(extra); // "x:..." is disjoint from the "tool:*" parent set
            let attempt =
                token.attenuate(Scope::with_budget_and_depth(wide, Some(500), 2), 60, &sub);
            let rejected = matches!(attempt, Err(AgentCredsError::ScopeWideningAttempt { .. }));
            prop_assert!(rejected, "widening must be rejected as ScopeWideningAttempt");
        }

        /// R1 - a child may never raise the budget above its parent.
        #[test]
        fn widening_budget_is_always_rejected(over in 501u32..1_000_000) {
            let (_anchor, agent, vc) = setup();
            let root = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 3);
            let token = DelegationToken::mint(&vc, root, 3600, &agent).unwrap();
            let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
            let attempt = token.attenuate(
                Scope::with_budget_and_depth(vec!["tool:search".into()], Some(over), 2),
                60,
                &sub,
            );
            prop_assert!(attempt.is_err());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// R1 end-to-end - a relying party verifies a random, deeply attenuated chain
        /// from the conveyed authority ALONE: every hop narrows, the leaf verifies
        /// rooted in the anchor for a granted tool, and any tool narrowed away is
        /// denied by the rooted check - not merely by the issuer's intent.
        #[test]
        fn deep_rooted_chain_verifies_and_narrows(hops in arb_rooted_chain()) {
            let (anchor, agent, vc) = setup();
            let root = Scope::with_budget_and_depth(
                vec!["tool:search".into(), "tool:email".into(), "tool:calendar".into()],
                Some(500), 3,
            );
            let mut token = DelegationToken::mint(&vc, root, 3600, &agent).unwrap();
            for tools in &hops {
                let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
                token = token
                    .attenuate(
                        Scope::with_budget_and_depth(tools.clone(), Some(500), 3),
                        60,
                        &sub,
                    )
                    .expect("a subset attenuation must succeed");
            }
            let leaf: std::collections::HashSet<String> =
                hops.last().cloned().unwrap_or_default().into_iter().collect();
            // Granted tools verify rooted in the anchor, from the token alone.
            for t in &leaf {
                prop_assert!(
                    token.verify_rooted(&Action::new(t.clone(), ""), &vc, &anchor).is_ok()
                );
            }
            // A tool narrowed away is denied by the rooted verifier itself.
            for t in ["tool:search", "tool:email", "tool:calendar"] {
                if !leaf.contains(t) {
                    prop_assert!(
                        token.verify_rooted(&Action::new(t, ""), &vc, &anchor).is_err()
                    );
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// R5 invariance - no intermediary agent can alter or drop the bound
        /// principal. After any number of attenuation hops the leaf still requires
        /// the ORIGINAL human and rejects every other principal (and the absence of
        /// one), verified from the conveyed authority alone.
        #[test]
        fn principal_is_invariant_across_any_chain(
            hops in 0u32..=3,
            imposter in "did:key:z[A-Za-z0-9]{20,30}",
        ) {
            let (anchor, agent, vc, human) = setup_obo();
            prop_assume!(imposter.as_str() != human.did());
            let scope = Scope::with_budget_and_depth(
                vec!["tool:read_email".into(), "tool:search".into()],
                Some(500),
                3,
            );
            let mut token = DelegationToken::mint(&vc, scope.clone(), 3600, &agent).unwrap();
            for _ in 0..hops {
                let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
                token = token.attenuate(scope.clone(), 60, &sub).unwrap();
            }
            // The original human is still authorized...
            prop_assert!(token
                .verify_rooted(
                    &Action::new("tool:search", "").on_behalf_of(human.did()),
                    &vc,
                    &anchor,
                )
                .is_ok());
            // ...any imposter principal is rejected...
            prop_assert!(token
                .verify_rooted(
                    &Action::new("tool:search", "").on_behalf_of(imposter.clone()),
                    &vc,
                    &anchor,
                )
                .is_err());
            // ...and acting with no principal at all is rejected.
            prop_assert!(token
                .verify_rooted(&Action::new("tool:search", ""), &vc, &anchor)
                .is_err());
        }
    }
}

/// A gate kind the verifier RECOGNIZES but the enforcement loop does not HANDLE must
/// deny, not pass. Recognition means "I know this designation exists"; it must never be
/// read as "and I have satisfied it". Without an explicit refusal, adding a gate kind
/// without a handler opens a fail-OPEN hole - and listing the kind in `recognized_kinds`
/// is precisely what an operator does to clear the "unrecognized gate kind" denial.
#[test]
fn a_recognized_but_unhandled_gate_kind_fails_closed() {
    let (anchor, agent, vc, human) = setup_obo();
    let scope = Scope::with_budget_and_depth(vec!["tool:read_email".into()], Some(100), 2)
        .with_resources(vec!["mailbox:alice@acme.com/42".into()])
        .with_gates(vec![Gate::intent("tool:read_email")]);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    let action = gated_action(&human);
    let now = Utc::now().timestamp();

    // The operator has listed the kind as recognized, and presents no evidence.
    let out = token.verify_rooted_gated(
        &action,
        &vc,
        &anchor,
        &[],
        &[Gate::APPROVAL, Gate::INTENT],
        now,
    );
    assert!(
        matches!(out, Err(AgentCredsError::ActionDenied { .. })),
        "a recognized gate with no handler and no evidence must DENY; passing it silently          is a designation that appears enforced and is not"
    );
}

// -- Per-action spend cap (ATF S-4) --------------------------------------------

/// A cost at or under the cap passes; over it is refused.
#[test]
fn a_per_action_cost_is_enforced_against_the_cap() {
    let (_a, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    token
        .verify(&Action::new("tool:search", "q").with_cost(100))
        .expect("a cost exactly at the cap must pass");
    token
        .verify(&Action::new("tool:search", "q").with_cost(1))
        .expect("a cost under the cap must pass");
    assert!(
        token
            .verify(&Action::new("tool:search", "q").with_cost(101))
            .is_err(),
        "a cost over the cap must be refused"
    );
}

/// The fail-closed direction: a capped token must not pass an unpriced action.
/// If it did, the cap would be bypassed by simply omitting the price.
#[test]
fn a_capped_token_denies_an_unpriced_action() {
    let (_a, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert!(
        token.verify(&Action::new("tool:search", "q")).is_err(),
        "omitting the cost must not bypass the cap"
    );
}

/// An uncapped token is unchanged by this feature, priced or not.
#[test]
fn an_uncapped_token_is_unaffected_by_cost() {
    let (_a, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    token
        .verify(&Action::new("tool:search", "q"))
        .expect("unpriced still passes without a cap");
    token
        .verify(&Action::new("tool:search", "q").with_cost(999_999))
        .expect("a price is ignored when nothing caps it");
}

/// The cap travels with the authority and tightens across hops.
#[test]
fn attenuation_can_tighten_the_cap_but_not_loosen_it() {
    let (_a, agent, vc) = setup();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let tighter = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 1)
        .with_max_action_cost(50);
    let child = token.attenuate(tighter, 300, &sub).unwrap();
    child
        .verify(&Action::new("tool:search", "q").with_cost(50))
        .expect("at the child's tighter cap");
    assert!(
        child
            .verify(&Action::new("tool:search", "q").with_cost(75))
            .is_err(),
        "the child's tighter cap must bind even though the parent allowed 100"
    );

    let looser = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 1)
        .with_max_action_cost(400);
    assert!(
        token.attenuate(looser, 300, &sub).is_err(),
        "raising the cap is widening and must be refused"
    );
}

/// The attack this design exists to stop: a sub-delegator that simply omits the cap
/// must not escape it. The parent's Datalog check persists regardless of the child's
/// assertion.
#[test]
fn a_sub_delegate_cannot_drop_the_cap_by_omitting_it() {
    let (_a, agent, vc) = setup();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();

    let no_cap = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 1);
    // Refused up front with a clear error rather than minted and denied later.
    assert!(
        token.attenuate(no_cap, 300, &sub).is_err(),
        "omitting the parent's cap is removing it, which is widening"
    );
}

/// A per-action cap above the credential's total ceiling would let one call spend more
/// than the whole delegation permits.
#[test]
fn a_cap_above_the_credential_budget_is_refused_at_mint() {
    let (_a, agent, vc) = setup(); // credential budget_usd = 500
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(501);
    assert!(
        DelegationToken::mint(&vc, scope, 300, &agent).is_err(),
        "a single action must not be permitted to exceed the total ceiling"
    );
}

/// The cap is inside the Biscuit, so editing the advisory audit view cannot raise it.
#[test]
fn tampering_with_the_advisory_hop_cap_does_not_widen_it() {
    let (_a, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let mut token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    token.hops[0].max_action_cost = Some(100_000);
    assert!(
        token
            .verify(&Action::new("tool:search", "q").with_cost(5_000))
            .is_err(),
        "the Datalog check, not the hop field, is the enforcement"
    );
}

/// The audit view reports the cap so a decision record can show what bound the call.
#[test]
fn the_chain_view_reports_the_effective_cap() {
    let (_a, agent, vc) = setup();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(500), 2)
        .with_max_action_cost(100);
    let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
    assert_eq!(token.chain().entries[0].max_action_cost, Some(100));
}

#[test]
fn out_of_range_ttl_errors_rather_than_panicking() {
    // REGRESSION, found by fuzzing the issuance API (Schemathesis, 2026-09-05).
    //
    // `ttl_secs as i64` wraps for a u64 above `i64::MAX`, and `chrono::Duration::seconds`
    // PANICS for a large-magnitude result instead of returning an error. `2^63` maps
    // exactly to `i64::MIN`, which is outside chrono's representable range.
    //
    // The values matter: `u64::MAX` casts to `-1`, which is perfectly representable and
    // does NOT panic - so a test that only tried the obvious extreme would have passed
    // while the bug remained. The trigger is the value that wraps to a LARGE magnitude.
    let org = crate::testkit::MockOrg::new("TTL Bounds").unwrap();
    let agent = org
        .issue_agent(vec!["tool:search".into()], Some(10), 2, 3600)
        .unwrap();
    let token = agent
        .mint(vec!["tool:search".into()], Some(10), 1, 300)
        .unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();

    for ttl in [9_223_372_036_854_775_808u64, u64::MAX, u64::MAX / 2] {
        let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(10), 0);
        // The contract is "never panic"; erroring and clamping are both acceptable
        // outcomes, and which one applies depends on how the value wraps.
        let _ = token.attenuate(scope, ttl, &sub);
    }
}

#[test]
fn credential_rejects_an_unrepresentable_lifetime() {
    // The same overflow reached through issuance, which is where the fuzzer found it.
    // `CapabilityClaims::validate` bounded `valid_for_secs` from below but not from above.
    let mut claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
    claims.valid_for_secs = 9_223_372_036_854_775_808;
    assert!(
        matches!(
            claims.validate(),
            Err(AgentCredsError::OutOfBounds {
                field: "valid_for_secs",
                ..
            })
        ),
        "an unrepresentable lifetime must be refused, not carried into Duration::seconds"
    );

    // The bound is a century; anything at or under it still validates.
    claims.valid_for_secs = crate::vc::MAX_VALID_FOR_SECS;
    assert!(claims.validate().is_ok(), "a century must remain issuable");
}

#[test]
fn verify_at_enforces_scope_and_the_exact_expiry_boundary() {
    // MUTATION-DRIVEN, twice over. CI's first complete shard pass found `verify_at`
    // could be stubbed to `Ok(())` with no core test noticing - the conformance vectors
    // exercise it only through the bindings, which cargo-mutants cannot see. And because
    // `verify_at` takes `now`, it is a clock seam into `verify_inner`: the expiry
    // boundary there (`now > min_expiry`) had been an ACCEPTED-EQUIVALENT mutant since
    // 2026-08-27 on the grounds that no seam existed. One did. This test kills both the
    // stub and the boundary flip, and the 1057:20 exclusion is retired.
    let org = crate::testkit::MockOrg::new("VerifyAt").unwrap();
    let agent = org
        .issue_agent(vec!["tool:search".into()], Some(10), 1, 3600)
        .unwrap();
    let token = agent
        .mint(vec!["tool:search".into()], Some(10), 0, 300)
        .unwrap();
    let t = token.expires_at();

    let ok = Action::new("tool:search", "");
    assert!(token
        .verify_at(&ok, t - chrono::Duration::nanoseconds(1))
        .is_ok());
    assert!(
        token.verify_at(&ok, t).is_ok(),
        "a token is valid AT its expiry instant - the check is `now > expiry`, exclusive"
    );
    assert!(
        matches!(
            token.verify_at(&ok, t + chrono::Duration::nanoseconds(1)),
            Err(AgentCredsError::TokenExpired { .. })
        ),
        "and invalid one nanosecond later"
    );

    // Scope is enforced through this entry point too, not just expiry - a stub that
    // returned Ok would pass the boundary assertions above only by luck of ordering.
    let denied = Action::new("tool:email", "");
    assert!(
        token
            .verify_at(&denied, t - chrono::Duration::seconds(1))
            .is_err(),
        "an out-of-scope action must be refused via verify_at"
    );
}

#[test]
fn subset_boundaries_are_inclusive_where_equality_is_legal() {
    // MUTATION-DRIVEN, from the shard-0 territory CI had never run. Both action-cost
    // comparisons in `Scope::is_subset_of` could flip `>` to `>=` unnoticed - meaning
    // no test ever exercised the EQUAL case, which is the legal one: restating the
    // parent's exact cap is REQUIRED by `attenuate` (inheriting silently was rejected
    // by design), and a per-action cap equal to the whole budget is within authority.
    // Under the mutants, both legal-equal cases become "widening" and every conforming
    // caller is refused - fail-closed, but wrong, on the flagship predicate.
    let parent = {
        let mut s = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
        s.max_action_cost = Some(40);
        s
    };

    // Equal cap: the required restatement must count as a subset.
    let mut equal_cap = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    equal_cap.max_action_cost = Some(40);
    assert!(
        equal_cap.is_subset_of(&parent),
        "restating the parent's exact per-action cap is narrowing, not widening"
    );

    // One cent over: widening, refused.
    let mut over_cap = equal_cap.clone();
    over_cap.max_action_cost = Some(41);
    assert!(
        !over_cap.is_subset_of(&parent),
        "a higher cap must be refused"
    );

    // Cap exactly equal to the parent's total budget: one call may spend the whole
    // delegation, which the delegation permits.
    let no_cap_parent = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 2);
    let mut cap_at_ceiling = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    cap_at_ceiling.max_action_cost = Some(100);
    assert!(
        cap_at_ceiling.is_subset_of(&no_cap_parent),
        "a per-action cap equal to the whole budget is within the granted authority"
    );
    let mut cap_over_ceiling = cap_at_ceiling.clone();
    cap_over_ceiling.max_action_cost = Some(101);
    assert!(
        !cap_over_ceiling.is_subset_of(&no_cap_parent),
        "one cent above the ceiling is not"
    );
}
