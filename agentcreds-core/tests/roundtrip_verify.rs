//! Regression: a credential must still VERIFY after a JSON wire round-trip.
//!
//! The in-crate round-trip tests only assert field equality (`id`, `issuer`, claims) and
//! never call `verify()`, so the path every real deployment uses - issuer serializes to
//! JSON, the holder carries it, a relying party parses and verifies offline - was
//! untested. A live deployment failed here with `payload hash mismatch`.

use agentcreds_core::did::{AgentIdentity, DidMethod, TrustAnchor};
use agentcreds_core::vc::{CapabilityClaims, CapabilityCredential};

fn claims() -> CapabilityClaims {
    CapabilityClaims::new(vec!["tool:echo".into()], 2, 3600)
}

#[test]
fn verifies_after_json_round_trip() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap();
    vc.verify(&anchor, true)
        .expect("verifies before round-trip");

    let json = vc.to_json().unwrap();
    let restored = CapabilityCredential::from_json(&json).unwrap();

    // Surface WHICH field diverges before asserting, so a failure is diagnostic.
    assert_eq!(
        restored.issuance_date.to_rfc3339(),
        vc.issuance_date.to_rfc3339(),
        "issuanceDate string changed across the JSON round-trip"
    );
    assert_eq!(
        restored.expiration_date.to_rfc3339(),
        vc.expiration_date.to_rfc3339(),
        "expirationDate string changed across the JSON round-trip"
    );

    restored
        .verify(&anchor, true)
        .expect("verifies AFTER round-trip");
}

/// The live deployment signs with a **KMS P-256** anchor (ES256), not the Ed25519
/// software anchor every existing test uses. Same payload hashing either way, so this
/// isolates whether the algorithm is what differs.
#[test]
fn verifies_after_json_round_trip_p256_anchor() {
    use agentcreds_core::did::KeyAlgorithm;
    let anchor = TrustAnchor::create(DidMethod::Key, Some(KeyAlgorithm::P256), None).unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap();
    vc.verify(&anchor, true)
        .expect("P-256: verifies before round-trip");

    let json = vc.to_json().unwrap();
    let restored = CapabilityCredential::from_json(&json).unwrap();
    restored
        .verify(&anchor, true)
        .expect("P-256: verifies AFTER round-trip");
}

/// Regression for the failure that cost two AWS deploy cycles to diagnose.
///
/// `CredentialFormat` defaults to `W3cLinkedData`, so a credential in a format the
/// verifier does not know (e.g. `sd-jwt-vc` arriving at an older build) silently
/// deserialises to W3C and is routed to `verify_w3c`. Such credentials carry their proof
/// in the JWS and leave `payload_hash` empty, which used to surface as "payload hash
/// mismatch" - an integrity error implying tampering, for what is really a version skew.
///
/// The error must name the real cause. Simulated by blanking `payload_hash`, which is
/// exactly the state such a credential deserialises into; no `sd-jwt` feature required.
#[test]
fn empty_payload_hash_reports_format_skew_not_tampering() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap();

    let mut v: serde_json::Value = serde_json::from_str(&vc.to_json().unwrap()).unwrap();
    v["proof"]["payload_hash"] = serde_json::Value::String(String::new());
    let stripped = CapabilityCredential::from_json(&v.to_string()).unwrap();

    let err = stripped
        .verify(&anchor, true)
        .expect_err("a credential with no W3C payload hash must not verify");
    let msg = err.to_string();

    assert!(
        !msg.contains("payload hash mismatch"),
        "must not report tampering for a format-skew credential; got: {msg}"
    );
    assert!(
        msg.contains("newer credential format") || msg.contains("no W3C payload hash"),
        "error must name the real cause (format skew); got: {msg}"
    );
}

/// A genuinely tampered W3C credential must STILL report a hash mismatch - the guard
/// above must not swallow real integrity failures.
#[test]
fn tampered_payload_hash_still_reports_mismatch() {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims(), None).unwrap();

    let mut v: serde_json::Value = serde_json::from_str(&vc.to_json().unwrap()).unwrap();
    v["proof"]["payload_hash"] = serde_json::Value::String("deadbeef".repeat(8));
    let tampered = CapabilityCredential::from_json(&v.to_string()).unwrap();

    let msg = tampered.verify(&anchor, true).unwrap_err().to_string();
    assert!(
        msg.contains("payload hash mismatch"),
        "real tampering must still be reported as a mismatch; got: {msg}"
    );
}

/// R7 issuer half: `resign` must advance `updated` and keep the list verifiable, without
/// altering any revocation bit. A verifier can only enforce a staleness bound if a quiet
/// issuer still refreshes the signed state - otherwise "nothing changed" and "issuer
/// frozen" look identical and any bound eventually denies legitimate traffic.
#[test]
fn resign_advances_updated_without_changing_bits() {
    use agentcreds_core::revocation::RevocationList;

    let anchor = TrustAnchor::generate().unwrap();
    let mut list =
        RevocationList::new("https://issuer.example/revocation/1", &anchor, Some(1024)).unwrap();
    list.revoke(7, &anchor).unwrap();

    let before_updated = list.updated;
    let before_encoded = list.encoded_list.clone();
    assert!(list.is_revoked(7).unwrap(), "bit 7 revoked before re-sign");

    std::thread::sleep(std::time::Duration::from_millis(1100));
    list.resign(&anchor).expect("re-sign succeeds");

    assert!(list.updated > before_updated, "updated must advance");
    assert_eq!(
        list.encoded_list, before_encoded,
        "re-sign must NOT alter the bit vector"
    );
    assert!(
        list.is_revoked(7).unwrap(),
        "bit 7 still revoked after re-sign"
    );
    assert!(
        !list.is_revoked(8).unwrap(),
        "an unrelated bit must not be set"
    );
    list.verify(&anchor).expect("re-signed list still verifies");
}
