//! Non-human principals and the accountable party.
//!
//! Two separate properties, deliberately not conflated:
//!
//! * A **workload** can be the principal an agent acts for, so the dual-axis check
//!   (capability and principal entitlement) applies to service-initiated agents instead of
//!   being vacuous. Before this, `on_behalf_of` was human-only and a service-initiated
//!   credential carried no principal at all - only one axis bound.
//! * **Accountability is not the principal.** A service can exercise authority but
//!   cannot answer for it; a team can. So the accountable party is a separate claim,
//!   and unlike the advisory `authorized_by` it cannot be selectively withheld.
//!
//! The binding, invariance and subset checks are shared with the human case on purpose -
//! these tests assert the workload path gets them, rather than re-testing the mechanism.

use agentcreds_core::prelude::*;
use agentcreds_core::principal::HumanIdentity;
use agentcreds_core::vc::{AuthoritySource, PrincipalKind};
use chrono::{Duration, Utc};

const SPIFFE: &str = "spiffe://payments.example/service/settlement";

fn workload_principal() -> HumanIdentity {
    HumanIdentity::from_spiffe(SPIFFE).expect("a well-formed SPIFFE ID")
}

// -- Minting a workload principal ---------------------------------------------

#[test]
fn a_workload_gets_a_stable_did_distinct_from_a_human_namespace() {
    let w = workload_principal();
    assert_eq!(w.kind(), PrincipalKind::Workload);
    assert!(
        w.did().starts_with("did:web:payments.example:w:"),
        "{}",
        w.did()
    );

    // Deterministic: the same SPIFFE ID always mints the same DID, or a principal could
    // not be matched across issuances.
    assert_eq!(w.did(), HumanIdentity::from_spiffe(SPIFFE).unwrap().did());

    // And it cannot collide with a human's namespace, which uses `:u:`.
    let h = HumanIdentity::from_idp("https://idp.example", "alice").unwrap();
    assert!(h.did().contains(":u:"), "{}", h.did());
    assert_ne!(w.did(), h.did());
}

#[test]
fn a_different_workload_gets_a_different_principal() {
    let a = HumanIdentity::from_spiffe("spiffe://payments.example/service/settlement").unwrap();
    let b = HumanIdentity::from_spiffe("spiffe://payments.example/service/reporting").unwrap();
    assert_ne!(a.did(), b.did(), "two services collapsed to one principal");
}

#[test]
fn a_malformed_spiffe_id_is_refused() {
    // Fail closed: a principal minted from a malformed identifier would be a principal
    // nobody attested.
    for bad in [
        "payments.example/service",     // no scheme
        "spiffe://payments.example",    // no workload path
        "spiffe:///service/settlement", // no trust domain
        "spiffe://payments.example/",   // empty path
    ] {
        assert!(
            HumanIdentity::from_spiffe(bad).is_err(),
            "accepted malformed SPIFFE ID: {bad}"
        );
    }
}

// -- The dual axis now applies to service-initiated agents --------------------

fn credential_for(
    anchor: &TrustAnchor,
    agent_did: &str,
    principal: &HumanIdentity,
    resource_authority: Vec<String>,
) -> CapabilityCredential {
    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    claims.on_behalf_of = Some(principal.authorize_now(
        Utc::now() + Duration::hours(1),
        vec!["tool:pay".into()],
        resource_authority,
        AuthoritySource::Attested,
    ));
    CapabilityCredential::issue(anchor, agent_did, claims, None).unwrap()
}

#[test]
fn a_workload_principal_binds_like_a_human_one() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let w = workload_principal();
    let vc = credential_for(&anchor, agent.did(), &w, vec![]);

    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1),
        300,
        &agent,
    )
    .unwrap();

    let action = Action::new("tool:pay", "amount=1").on_behalf_of(w.did());
    token
        .verify_rooted(&action, &vc, &anchor)
        .expect("workload principal must verify");
}

// -- The resource bound, carried without a principal --------------------------

/// A resource ceiling on the **capability** axis bounds a token exactly as the
/// principal's `resource_authority` did, with no principal in sight.
///
/// This is what let the workload principal be removed rather than merely made
/// optional. The bound was the one thing that axis genuinely carried for a
/// service-initiated agent; everything else it held was a copy of a bound
/// issuance had already applied. Carried here, it costs nothing at the relying
/// party - no principal means no R5 symmetric-presence obligation, so no need
/// for the enforcement point to independently learn who the workload is.
#[test]
fn a_capability_resource_ceiling_bounds_a_token_without_any_principal() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    claims.resources = Some(vec!["ledger:payments/*".into()]);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    assert!(vc.on_behalf_of().is_none(), "no principal is involved here");

    // Within the ceiling: mints, and verifies with no `acting_for` at all - the
    // shape a PEP can actually produce for a service-initiated agent.
    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
            .with_resources(vec!["ledger:payments/eu".into()]),
        300,
        &agent,
    )
    .expect("a resource inside the ceiling must mint");
    let action = Action::new("tool:pay", "amount=1").on_resource("ledger:payments/eu");
    token
        .verify_rooted(&action, &vc, &anchor)
        .expect("no principal means no acting_for obligation");

    // Outside it: refused at mint, so the token can never exist to be presented.
    let escaped = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
            .with_resources(vec!["ledger:treasury/eu".into()]),
        300,
        &agent,
    );
    assert!(
        matches!(escaped, Err(AgentCredsError::ScopeWideningAttempt { .. })),
        "a resource outside the credential's ceiling was minted: {escaped:?}"
    );
}

/// `None` means unbounded, not "bounded by nothing". Guards the distinction
/// `entitlement.rs` is careful about everywhere else - a credential that says
/// nothing about resources must not silently become a credential that permits
/// none, which would break every existing token.
#[test]
fn no_resource_ceiling_leaves_resources_unbounded() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    assert!(vc.claims().resources.is_none());

    DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
            .with_resources(vec!["anything:at:all".into()]),
        300,
        &agent,
    )
    .expect("an unbounded credential must not refuse a resource");
}

/// Both bounds apply when both exist, and they are independent: a resource
/// inside the credential's ceiling but outside the principal's entitlement is
/// still refused. Without this the capability ceiling could be mistaken for a
/// replacement for the second axis rather than a separate one.
#[test]
fn the_capability_ceiling_does_not_replace_the_principal_axis() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let w = workload_principal();

    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    claims.resources = Some(vec!["ledger:*".into()]); // broad grant
    claims.on_behalf_of = Some(w.authorize_now(
        Utc::now() + Duration::hours(1),
        vec!["tool:pay".into()],
        vec!["ledger:payments/*".into()], // narrower entitlement
        AuthoritySource::Attested,
    ));
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let escaped = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
            .with_resources(vec!["ledger:treasury/eu".into()]), // inside grant, outside entitlement
        300,
        &agent,
    );
    assert!(
        matches!(escaped, Err(AgentCredsError::ConsentViolation { .. })),
        "the principal's entitlement stopped bounding once a ceiling existed: {escaped:?}"
    );
}

/// The shape that broke the 2026-08-06 AWS deploy: attested enrollment mints a
/// workload principal into every credential, and a relying party that never
/// learned that principal presents an `Action` with no `acting_for`.
///
/// Every test above hands `verify_rooted` an action that already names the
/// principal, which is why none of them saw this. The deployed PEP had no
/// independent source for it, so `acting_for` was `None` on every call.
///
/// Two things are asserted. The refusal is correct - R5 admits only symmetric
/// presence. And the error must name the **request** as the side that asserted
/// nothing, because a message blaming the token sends the next person hunting a
/// token-derivation bug that does not exist.
#[test]
fn a_workload_credential_refuses_a_request_that_names_no_principal() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let w = workload_principal();
    let vc = credential_for(&anchor, agent.did(), &w, vec![]);

    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1),
        300,
        &agent,
    )
    .unwrap();

    let action = Action::new("tool:pay", "amount=1"); // no `.on_behalf_of(...)`
    let err = token
        .verify_rooted(&action, &vc, &anchor)
        .expect_err("a principal-bound credential must not be spendable unbound");

    match &err {
        AgentCredsError::ActingForMismatch { required, asserted } => {
            assert_eq!(required, w.did());
            assert_eq!(*asserted, None);
        }
        other => panic!("expected ActingForMismatch, got {other:?}"),
    }

    // The token carried the principal the whole time - the getter agrees with the
    // check that just failed, so nothing implicates mint or the wire round-trip.
    assert_eq!(token.principal_did(), Some(w.did()));

    let msg = err.to_string();
    assert!(
        msg.contains("the request asserts principal '<none>'"),
        "message must blame the request, got: {msg}"
    );

    // The remedy is on the relying party, not the token: supply the principal it
    // verified for itself and the same token verifies.
    assert!(token
        .verify_rooted(&action.on_behalf_of(w.did()), &vc, &anchor)
        .is_ok());
}

#[test]
fn a_swapped_workload_principal_is_refused() {
    // R9's unconditional half: not exercisable with a mismatched principal. The control
    // is the test above - the same token verifies for the right principal.
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let w = workload_principal();
    let other = HumanIdentity::from_spiffe("spiffe://payments.example/service/reporting").unwrap();
    let vc = credential_for(&anchor, agent.did(), &w, vec![]);

    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1),
        300,
        &agent,
    )
    .unwrap();

    let action = Action::new("tool:pay", "amount=1").on_behalf_of(other.did());
    assert!(
        token.verify_rooted(&action, &vc, &anchor).is_err(),
        "an agent acted for a workload it was not bound to"
    );
}

#[test]
fn a_workload_cannot_exceed_its_own_resource_authority() {
    // THE POINT OF THE CHANGE. Previously a service-initiated credential carried no
    // principal, so this second axis did not exist and only the capability bound.
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let w = workload_principal();

    // The settlement service is entitled to settlement resources only.
    let vc = credential_for(
        &anchor,
        agent.did(),
        &w,
        vec!["res:ledger/settlement/*".into()],
    );

    let outside = Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
        .with_resources(vec!["res:ledger/payroll/*".into()]);
    assert!(
        DelegationToken::mint(&vc, outside, 300, &agent).is_err(),
        "minted authority over a resource outside the workload's entitlement"
    );

    // Control: inside its entitlement it mints, so the refusal above is the subset
    // check and not a blanket denial.
    let inside = Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1)
        .with_resources(vec!["res:ledger/settlement/eu".into()]);
    DelegationToken::mint(&vc, inside, 300, &agent)
        .expect("a scope within the workload's entitlement must mint");
}

// -- Accountability is a separate, non-suppressible claim ---------------------

#[test]
fn the_accountable_party_survives_a_json_round_trip() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 1, 3600);
    claims.accountable_party = Some("team:payments-platform".into());
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let parsed = CapabilityCredential::from_json(&vc.to_json().unwrap()).unwrap();
    assert_eq!(
        parsed.claims().accountable_party.as_deref(),
        Some("team:payments-platform")
    );
    parsed
        .verify(&anchor, true)
        .expect("accountability must not disturb the signature");
}

#[test]
fn a_credential_without_an_accountable_party_still_verifies() {
    // Migration safety: everything issued before this claim existed must keep working.
    // Absence means "issued before accountability was recorded", never "nobody is
    // responsible" - the issuing organization is accountable either way.
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:pay".into()], 1, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    assert!(vc.claims().accountable_party.is_none());
    vc.verify(&anchor, true).unwrap();
}

#[test]
fn a_human_principal_is_unchanged_on_the_wire() {
    // The kind discriminator must be omitted for humans, or the payload hash of every
    // credential carrying a principal would change and break tokens already bound to
    // them. `biscuit_wire_compat` guards the golden fixture; this states the rule.
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let h = HumanIdentity::from_idp("https://idp.example", "alice").unwrap();
    let vc = credential_for(&anchor, agent.did(), &h, vec![]);

    let json = vc.to_json().unwrap();
    assert!(
        !json.contains("\"kind\""),
        "the human default must not be serialized: {json}"
    );

    // A workload, by contrast, must say so - it is not the default.
    let w = workload_principal();
    let wvc = credential_for(&anchor, agent.did(), &w, vec![]);
    assert!(wvc.to_json().unwrap().contains("workload"));
}

// -- Autonomy level: wired, and only to what it can actually enforce ----------

/// The ladder is monotone-tightening and saturates, so an out-of-range level can
/// never widen anything. `validate` rejects >3, but a bound that depends on
/// validation having run is a bound that fails open when it has not.
#[test]
fn the_autonomy_ttl_ladder_only_ever_tightens() {
    use agentcreds_core::vc::max_token_ttl_secs;
    let ladder: Vec<u64> = (0..=3).map(max_token_ttl_secs).collect();
    assert_eq!(ladder, vec![3600, 1800, 900, 300]);
    assert!(
        ladder.windows(2).all(|w| w[0] > w[1]),
        "higher autonomy must mean a shorter leash: {ladder:?}"
    );
    assert_eq!(
        max_token_ttl_secs(255),
        300,
        "an out-of-range level must saturate at the tightest bound, never widen"
    );
}

/// `autonomy_level` used to document a policy it did not enforce. It now bounds
/// token lifetime, and `mint` **refuses** rather than silently shortening - a caller
/// that asked for an hour and received five minutes would proceed believing it had
/// an hour.
#[test]
fn a_high_autonomy_credential_refuses_a_long_token() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    claims.autonomy_level = 3; // fully autonomous: 300s ceiling
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let scope = || Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1);

    match DelegationToken::mint(&vc, scope(), 3600, &agent) {
        Err(AgentCredsError::OutOfBounds { field, detail }) => {
            assert_eq!(field, "ttl_secs");
            assert!(
                detail.contains("300"),
                "the ceiling must be named: {detail}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // At the ceiling exactly: permitted. Without this the case above also passes
    // for an implementation that refuses every mint.
    DelegationToken::mint(&vc, scope(), 300, &agent).expect("the ceiling itself must mint");
}

/// The ceiling holds down the chain without the token carrying the level:
/// `attenuate` caps each child at its parent's expiry, so a sub-agent cannot
/// out-live the bound its root was minted under.
#[test]
fn the_autonomy_ceiling_survives_attenuation() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let sub = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let mut claims = CapabilityClaims::new(vec!["tool:pay".into()], 3, 3600);
    claims.autonomy_level = 3;
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let root = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 2),
        300,
        &agent,
    )
    .unwrap();

    // The child asks for far longer than the root's remaining life.
    let child = root
        .attenuate(
            Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1),
            86_400,
            &sub,
        )
        .unwrap();
    assert!(
        child.expires_at() <= root.expires_at(),
        "a child outlived the autonomy ceiling its root was bound by"
    );
}

/// The claim that was removed, pinned as a negative so nobody reinstates it.
///
/// L0 is what `CapabilityClaims::new` produces, so *every* credential declares it.
/// Had L0 meant "human-in-the-loop" in any enforced sense, every ungated credential
/// in existence would be malformed. Requiring a human is `required_gates` (R10);
/// autonomy bounds lifetime and nothing else.
#[test]
fn autonomy_level_zero_is_not_a_human_in_the_loop_switch() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let claims = CapabilityClaims::new(vec!["tool:pay".into()], 2, 3600);
    assert_eq!(claims.autonomy_level, 0, "L0 is the default, not an opt-in");
    assert!(claims.required_gates.is_empty());

    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    let token = DelegationToken::mint(
        &vc,
        Scope::with_budget_and_depth(vec!["tool:pay".into()], None, 1),
        300,
        &agent,
    )
    .unwrap();

    let action = Action::new("tool:pay", "amount=1");
    assert!(
        token.required_gates(&action).is_empty(),
        "L0 must not conjure a gate - if this fails, the field has been given a \
         meaning that breaks every credential built with ::new()"
    );
    token
        .verify_rooted(&action, &vc, &anchor)
        .expect("an L0 credential with no gate authorizes normally");
}
