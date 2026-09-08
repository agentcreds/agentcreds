//! Emit a golden delegation-token fixture for `tests/biscuit_wire_compat.rs`.
//!
//! A 2-hop, on-behalf-of, gated, resource-scoped token plus the credential and anchor
//! DID needed to verify it. Long TTLs so the fixture does not expire out from under the
//! test. Run this only when a token-format change is DELIBERATE, and record why in the
//! test's header.
//!
//!     cargo run -p agentcreds-core --example gen_fixture

use agentcreds_core::delegation::{Action, DelegationToken, Scope};
use agentcreds_core::did::{AgentIdentity, DidMethod, TrustAnchor};
use agentcreds_core::vc::{
    AuthoritySource, CapabilityClaims, CapabilityCredential, HumanAuthorization,
};
use chrono::{Duration, Utc};

fn main() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let child = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let alice = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let obo = HumanAuthorization {
        principal_did: alice.did().to_string(),
        kind: Default::default(),
        entitlement_source: Default::default(),
        issuer: "https://idp.example".into(),
        subject: "alice@example.com".into(),
        authorized_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(3650),
        scope_consented: vec!["tool:echo".into()],
        resource_authority: vec!["mailbox:alice@example.com/*".into()],
    };

    let mut claims = CapabilityClaims::new(vec!["tool:echo".into()], 3, 315_360_000)
        .require_approval("tool:echo");
    claims.on_behalf_of = Some(obo);

    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();

    let root = Scope::with_budget_and_depth(vec!["tool:echo".into()], Some(500), 2)
        .with_resources(vec!["mailbox:alice@example.com/inbox".into()]);
    // The autonomy ladder caps a minted token at one hour (L0); a decade-long token is
    // no longer expressible, and asking for one made this generator panic. The fixture
    // therefore records `evaluated_at` and the test verifies AS OF it - see
    // `DelegationToken::verify_rooted_at`.
    let token_ttl = agentcreds_core::vc::max_token_ttl_secs(0);
    let token = DelegationToken::mint(&vc, root, token_ttl, &agent).unwrap();

    let narrow = Scope::with_budget_and_depth(vec!["tool:echo".into()], Some(100), 1)
        .with_resources(vec!["mailbox:alice@example.com/inbox".into()]);
    let token = token.attenuate(narrow, token_ttl, &child).unwrap();

    // Sanity: it verifies under the build that produced it.
    let action = Action::new("tool:echo", "text=hi")
        .on_resource("mailbox:alice@example.com/inbox")
        .on_behalf_of(alice.did());
    token.verify_rooted(&action, &vc, &anchor).unwrap();

    // Written as DATA, deliberately: the test source that reads this stays secret-scanned
    // while this one generator-produced path is exempted (see .gitleaks.toml). Do not
    // inline these constants back into the test.
    let doc = serde_json::json!({
        "note": concat!(
            "Generator-produced golden delegation-token fixture for ",
            "tests/biscuit_wire_compat.rs. PUBLIC artifacts only - did:key ",
            "identifiers (public keys), a CBOR delegation token, and a JSON ",
            "credential with its signature. No private key or seed appears here."
        ),
        "generator": "agentcreds-core examples/gen_fixture",
        "evaluated_at": chrono::Utc::now().timestamp(),
        "token_cbor_hex": hex::encode(token.to_cbor().unwrap()),
        "vc_json_hex": hex::encode(vc.to_json().unwrap()),
        "anchor_did": anchor.did(),
        "principal_did": alice.did(),
    });
    let out = "agentcreds-core/tests/fixtures/wire_compat.json";
    std::fs::write(
        out,
        serde_json::to_string_pretty(&doc).unwrap()
            + "
",
    )
    .unwrap();
    eprintln!("wrote {out}");
}
