//! Fuzz-style tests for malformed and adversarial input handling.
//!
//! This suite runs on stable Rust via `proptest` (no `cargo-fuzz`/nightly
//! toolchain required). It targets the deserialisation and verification entry
//! points that accept attacker-controlled bytes - JSON, CBOR, TOML, base64
//! proofs, multibase-encoded keys, and OAuth status list bitstrings - and
//! asserts the crate returns `Err`, never panics.
//!
//! # Coverage, and what "fuzz" means here
//!
//! Currently covered: `CapabilityCredential`, `DelegationToken`,
//! `AgentCredsConfig`, `RevocationList` (bitstring and index arithmetic), DID
//! resolution, signature verification with arbitrary key/signature lengths,
//! and - added later - `KeyHistory`, `SignedTrustConfig`, `EvidenceBundle`,
//! `PopChallenge`, `ProofOfPossession`, `Presentation`, and JCS
//! canonicalization.
//!
//! **This is property-based testing, not coverage-guided fuzzing.** Inputs are
//! drawn from generators written here, so the suite can only reach states
//! somebody thought to describe. That is a real limit and it is why the
//! byte-flip strategies exist alongside the arbitrary-input ones: mutating a
//! *valid* artifact reaches the decoder's interior, where an arbitrary string
//! is usually rejected by the JSON or CBOR parser before any crate logic runs.
//! A libFuzzer/`cargo-fuzz` harness driven by coverage feedback would explore
//! what neither strategy can, and remains the open item.
//!
//! When adding a `from_json` / `from_cbor` entry point to the crate, add it
//! here too. The list above was accurate when written and silently stopped
//! being so; the fetched-artifact parsers went uncovered for exactly that
//! reason.
//!
//! Run with:
//! ```text
//! cargo test --features proptest --test fuzz_malformed_input
//! ```

#![cfg(feature = "proptest")]
#![allow(clippy::unwrap_used)]

use std::io::Write;

use base64ct::Encoding;
use chrono::Utc;
use proptest::prelude::*;

use agentcreds_core::compliance::EvidenceBundle;
use agentcreds_core::config::AgentCredsConfig;
use agentcreds_core::delegation::{Action, DelegationToken, Scope};
use agentcreds_core::did::{
    AgentIdentity, DidDocument, DidMethod, InMemoryResolver, KeyAlgorithm, PublicKey, TrustAnchor,
    VerificationMethod,
};
use agentcreds_core::error::AgentCredsError;
use agentcreds_core::pop::{PopChallenge, Presentation, ProofOfPossession};
use agentcreds_core::registry::{SignedTrustConfig, TrustEntry, TrustLevel, TrustRegistry};
use agentcreds_core::revocation::RevocationList;
use agentcreds_core::rotation::KeyHistory;
use agentcreds_core::testkit::MockOrg;
use agentcreds_core::vc::{CapabilityClaims, CapabilityCredential};

// -- Helpers -----------------------------------------------------------------

fn sample_credential() -> CapabilityCredential {
    let (vc, _agent) = sample_credential_with_subject();
    vc
}

/// Returns a credential together with the subject agent that holds it, so the
/// agent can also mint a token (the minting agent must be the VC subject).
fn sample_credential_with_subject() -> (CapabilityCredential, AgentIdentity) {
    let anchor = TrustAnchor::generate().unwrap();
    let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
    let claims = CapabilityClaims::new(vec!["tool:search".into(), "tool:email".into()], 2, 3600);
    let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
    (vc, agent)
}

fn sample_token() -> DelegationToken {
    let (vc, agent) = sample_credential_with_subject();
    let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], Some(100), 1);
    DelegationToken::mint(&vc, scope, 300, &agent).unwrap()
}

/// Flips a single byte of `data` (selected by `index % data.len()`) and
/// returns the mutated buffer. A no-op for empty input.
fn flip_byte(mut data: Vec<u8>, index: usize, mask: u8) -> Vec<u8> {
    if !data.is_empty() {
        let i = index % data.len();
        data[i] ^= mask;
    }
    data
}

/// Compresses+encodes an empty bitstring the same way `RevocationList`
/// does internally, for use in the truncated-list regression test.
fn empty_compressed_list() -> String {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&[]).unwrap();
    let compressed = encoder.finish().unwrap();
    // Must match RevocationList's wire encoding (OAuth Status List `lst`): base64url,
    // unpadded - the standard-base64 form would fail to decode.
    base64ct::Base64UrlUnpadded::encode_string(&compressed)
}

// -- JSON: CapabilityCredential ---------------------------------------------

proptest! {
    /// Arbitrary strings fed to `from_json` must never panic.
    #[test]
    fn prop_credential_from_json_never_panics(s in ".*") {
        let _ = CapabilityCredential::from_json(&s);
    }

    /// Single-byte mutations of a *valid* credential JSON must never panic.
    #[test]
    fn prop_credential_from_json_mutated_never_panics(index in any::<usize>(), mask in any::<u8>()) {
        let json = sample_credential().to_json().unwrap();
        let mutated = flip_byte(json.into_bytes(), index, mask);
        let mutated_str = String::from_utf8_lossy(&mutated).into_owned();
        let _ = CapabilityCredential::from_json(&mutated_str);
    }
}

// -- CBOR: DelegationToken ---------------------------------------------------

proptest! {
    /// Arbitrary byte sequences fed to `from_cbor` must never panic.
    #[test]
    fn prop_delegation_token_from_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let _ = DelegationToken::from_cbor(&bytes);
    }

    /// Single-byte mutations of a *valid* token's CBOR encoding must never
    /// panic, including when calling the accessor methods on whatever
    /// `DelegationToken` (possibly structurally degenerate) results.
    #[test]
    fn prop_delegation_token_from_cbor_mutated_never_panics(index in any::<usize>(), mask in any::<u8>()) {
        let bytes = sample_token().to_cbor().unwrap();
        let mutated = flip_byte(bytes, index, mask);
        if let Ok(token) = DelegationToken::from_cbor(&mutated) {
            let _ = token.depth();
            let _ = token.chain();
            let _ = token.leaf_agent_did();
            let _ = token.root_agent_did();
            let _ = token.leaf_binding();
        }
    }
}

// -- TOML: AgentCredsConfig -------------------------------------------------

proptest! {
    /// Arbitrary strings fed to the TOML config parser must never panic.
    #[test]
    fn prop_config_from_toml_str_never_panics(s in ".*") {
        let _ = AgentCredsConfig::from_toml_str(&s);
    }
}

// -- Revocation: OAuth status list bitstring ---------------------------------

proptest! {
    /// A `RevocationList` with an arbitrary `encoded_list` string (invalid
    /// base64, invalid DEFLATE, or a valid-but-empty bitstream) must not
    /// panic when checked or counted.
    #[test]
    fn prop_revocation_list_arbitrary_encoded_list_never_panics(encoded in ".*") {
        let list = RevocationList {
            id: "https://registry.example.com/status/fuzz".into(),
            issuer: "did:key:zFuzzIssuer".into(),
            alg: "EdDSA".into(),
            updated: Utc::now(),
            size: 64,
            bits: 1,
            encoded_list: encoded,
            signature: String::new(),
        };
        let _ = list.is_revoked(0);
        let _ = list.revocation_count();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// `is_revoked` on a correctly-constructed list must never panic for any
    /// `u64` index, in or out of bounds.
    #[test]
    fn prop_revocation_is_revoked_never_panics_for_any_index(index in any::<u64>()) {
        let anchor = TrustAnchor::generate().unwrap();
        let list = RevocationList::new("https://registry.example.com/status/fuzz", &anchor, Some(256)).unwrap();
        let _ = list.is_revoked(index);
    }

    /// `revoke`/`unrevoke` on a correctly-constructed list must never panic
    /// for any `u64` index - out-of-bounds indices must be rejected with
    /// `RevocationIndexOutOfBounds`, not a `bitvec` panic.
    #[test]
    fn prop_revocation_revoke_unrevoke_never_panics_for_any_index(index in any::<u64>()) {
        let anchor = TrustAnchor::generate().unwrap();
        let mut list = RevocationList::new("https://registry.example.com/status/fuzz", &anchor, Some(256)).unwrap();
        let _ = list.revoke(index, &anchor);
        let _ = list.unrevoke(index, &anchor);
    }
}

// -- DID resolution: malformed multibase keys --------------------------------

proptest! {
    /// A resolved DID document with an arbitrary `public_key_multibase`
    /// string must not panic during trust registry resolution.
    #[test]
    fn prop_did_resolution_malformed_multibase_never_panics(multibase in ".*") {
        let did = "did:key:zFuzzTarget";
        let now = Utc::now();
        let document = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                r#type: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                public_key_multibase: multibase,
            }],
            authentication: vec![],
            assertion_method: vec![],
            capability_delegation: vec![],
            created: now,
            updated: now,
        };

        let mut resolver = InMemoryResolver::new();
        resolver.register(did, document);
        let mut registry = TrustRegistry::with_resolver(Box::new(resolver));
        let _ = registry.resolve(did);
    }
}

// -- Registry: signature verification with arbitrary key/signature lengths --

proptest! {
    /// `TrustEntry::verify_signature` must never panic, regardless of the
    /// lengths of the stored public key, message, or signature bytes.
    #[test]
    fn prop_trust_entry_verify_signature_never_panics(
        key_bytes in proptest::collection::vec(any::<u8>(), 0..96),
        message in proptest::collection::vec(any::<u8>(), 0..64),
        sig_bytes in proptest::collection::vec(any::<u8>(), 0..96),
    ) {
        let public_key = PublicKey { algorithm: KeyAlgorithm::Ed25519, bytes: key_bytes };
        let entry = TrustEntry::new("did:key:zFuzzAnchor", "Fuzz Org", public_key, TrustLevel::Verified);
        let _ = entry.verify_signature(&message, &sig_bytes);
    }

    /// `AgentIdentity::verify` must never panic for arbitrary signature
    /// bytes, regardless of length.
    #[test]
    fn prop_agent_identity_verify_never_panics(
        message in proptest::collection::vec(any::<u8>(), 0..64),
        sig_bytes in proptest::collection::vec(any::<u8>(), 0..96),
    ) {
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let _ = agent.verify(&message, &sig_bytes);
    }
}

// -- Regression tests: malformed input rejected with `Err`, not a panic -----

/// `DelegationToken::from_cbor` rejects CBOR that deserialises into a token
/// with an empty hop chain, rather than allowing a structurally degenerate
/// token through to `leaf_agent_did()`/`attenuate()` (which assume a non-empty
/// chain). The token's wire form is `{ biscuit: <hex>, hops: [] }`; we craft it
/// directly since the struct fields are private.
#[test]
fn regression_empty_hops_token_rejected_by_from_cbor() {
    #[derive(serde::Serialize)]
    struct FakeWire {
        // Matches `DelegationTokenWire::biscuit` (serialized as a hex string).
        biscuit: String,
        // Matches `DelegationTokenWire::hops` - empty array.
        hops: Vec<u8>,
    }

    let fake = FakeWire {
        biscuit: String::new(),
        hops: Vec::new(),
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&fake, &mut bytes).unwrap();

    // Must be rejected (not a panic): empty chain is invalid.
    assert!(DelegationToken::from_cbor(&bytes).is_err());
}

/// `RevocationList::revoke`/`unrevoke` reject indices that are within
/// `size` but beyond the actual decoded bit length (e.g. a
/// truncated/corrupted list fetched from its publication URL) with
/// `RevocationIndexOutOfBounds`, rather than panicking inside
/// `BitVec::set`.
#[test]
fn regression_truncated_revocation_list_rejected_by_revoke() {
    let anchor = TrustAnchor::generate().unwrap();
    let mut list = RevocationList::new(
        "https://registry.example.com/status/fuzz",
        &anchor,
        Some(1024),
    )
    .unwrap();

    // `size` still claims 1024 entries, but the bitstring now decompresses
    // to zero bits.
    list.encoded_list = empty_compressed_list();

    assert!(matches!(
        list.revoke(0, &anchor),
        Err(AgentCredsError::RevocationIndexOutOfBounds { .. })
    ));
    assert!(matches!(
        list.unrevoke(0, &anchor),
        Err(AgentCredsError::RevocationIndexOutOfBounds { .. })
    ));
}

// ============================================================================
// Fetched signed artifacts
// ============================================================================
//
// The entry points below were added after the original suite and cover the
// artifacts a relying party FETCHES rather than receives inline: a peer's key
// history, a framework's trust config, a compliance evidence bundle, and the
// presentation triple. They are the sharpest targets in the crate - a fetched
// artifact is attacker-influenced by definition, and it is parsed BEFORE its
// signature can be checked, because the signature lives inside the thing being
// parsed. Every one of them must reach `Err`, never a panic.

fn valid_key_history_json() -> String {
    let anchor = TrustAnchor::generate().unwrap();
    KeyHistory::new(anchor.did()).to_json().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary strings fed to the key-history parser must never panic.
    #[test]
    fn prop_key_history_from_json_never_panics(s in ".*") {
        let _ = KeyHistory::from_json(&s);
    }

    /// Single-byte mutations of a *valid* key history must never panic. The
    /// mutation is what reaches the rotation logic - an arbitrary string is
    /// almost always rejected by the JSON parser before any of it runs.
    #[test]
    fn prop_key_history_from_json_mutated_never_panics(index in any::<usize>(), mask in any::<u8>()) {
        let bytes = flip_byte(valid_key_history_json().into_bytes(), index, mask);
        if let Ok(s) = String::from_utf8(bytes) {
            let _ = KeyHistory::from_json(&s);
        }
    }

    /// Arbitrary strings fed to the signed trust-config parser must never panic.
    #[test]
    fn prop_signed_trust_config_from_json_never_panics(s in ".*") {
        let _ = SignedTrustConfig::from_json(&s);
    }

    /// Arbitrary strings fed to the evidence-bundle parser must never panic.
    #[test]
    fn prop_evidence_bundle_from_json_never_panics(s in ".*") {
        let _ = EvidenceBundle::from_json(&s);
    }
}

// -- CBOR: the presentation triple -------------------------------------------

fn valid_presentation_cbor() -> Vec<u8> {
    let org = MockOrg::new("Fuzz Org").unwrap();
    let agent = org
        .issue_agent(vec!["tool:search".into()], Some(10), 1, 3600)
        .unwrap();
    let token = agent
        .mint(vec!["tool:search".into()], Some(10), 0, 300)
        .unwrap();
    let challenge = PopChallenge::new(Some("https://verifier.example.com".into()));
    agent.present(token, &challenge).unwrap().to_cbor().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary byte sequences fed to the challenge parser must never panic.
    #[test]
    fn prop_pop_challenge_from_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let _ = PopChallenge::from_cbor(&bytes);
    }

    /// Arbitrary byte sequences fed to the proof parser must never panic.
    #[test]
    fn prop_proof_of_possession_from_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let _ = ProofOfPossession::from_cbor(&bytes);
    }

    /// Arbitrary byte sequences fed to the presentation parser must never panic.
    #[test]
    fn prop_presentation_from_cbor_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let _ = Presentation::from_cbor(&bytes);
    }

    /// Single-byte mutations of a *valid* presentation must never panic, including
    /// when the degenerate result is then verified. This is the full relying-party
    /// input - token, credential and proof in one structure - so a panic here is
    /// reachable by anything that can hand a verifier bytes.
    #[test]
    fn prop_presentation_from_cbor_mutated_never_panics(index in any::<usize>(), mask in any::<u8>()) {
        let bytes = flip_byte(valid_presentation_cbor(), index, mask);
        if let Ok(presentation) = Presentation::from_cbor(&bytes) {
            let anchor = TrustAnchor::generate().unwrap();
            let challenge = PopChallenge::new(Some("https://verifier.example.com".into()));
            let action = Action::new("tool:search", "");
            let _ = presentation.verify(&action, &anchor, &challenge, 300);
        }
    }
}

// -- Canonicalization --------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// `jcs::canonicalize` must never panic on any JSON document it is handed.
    ///
    /// Actions are bound to canonicalized arguments, so this runs on
    /// attacker-supplied tool arguments on the enforcement path. Numbers are the
    /// live hazard - a value with no IEEE-754 representation must return `Err`,
    /// not unwrap a `None` - so floats are generated deliberately alongside the
    /// structural cases rather than left to chance.
    #[test]
    fn prop_jcs_canonicalize_never_panics(
        f in proptest::num::f64::ANY,
        i in any::<i64>(),
        s in ".*",
        depth in 0usize..6,
    ) {
        let mut value = serde_json::json!({ "f": f, "i": i, "s": s });
        for _ in 0..depth {
            value = serde_json::json!({ "nested": value, "arr": [value.clone(), null] });
        }
        let _ = agentcreds_core::jcs::canonicalize(&value);
    }
}
