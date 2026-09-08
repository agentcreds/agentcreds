//! Presentation decode and verification against fuzzed bytes.
//!
//! A presentation is the whole relying-party input in one structure - token, credential
//! and proof of possession - so it is the largest attack surface the verify path exposes,
//! and the one a PEP handles on every gated call.
//!
//! The first half of the input picks a split point so the fuzzer can vary the
//! presentation and the challenge independently; a fixed split would leave one of the two
//! effectively constant. Both are attacker-supplied in the threat model that matters
//! here: a captured presentation replayed against a verifier comes with its own bytes.
#![no_main]

use std::sync::OnceLock;

use agentcreds_core::delegation::Action;
use agentcreds_core::did::TrustAnchor;
use agentcreds_core::pop::{PopChallenge, Presentation};
use agentcreds_core::testkit::MockOrg;
use libfuzzer_sys::fuzz_target;

fn anchor() -> &'static TrustAnchor {
    static A: OnceLock<TrustAnchor> = OnceLock::new();
    A.get_or_init(|| {
        let org = MockOrg::new("Fuzz Org").expect("mock org");
        TrustAnchor::from_did_key(org.did()).expect("verify-only anchor")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Split proportionally rather than at a fixed offset, so both halves stay non-trivial
    // as the fuzzer grows the input.
    let split = (data[0] as usize * data.len()) / 256;
    let (challenge_bytes, presentation_bytes) = data[1..].split_at(split.min(data.len() - 1));

    let action = Action::new("tool:search", "");
    if let Ok(presentation) = Presentation::from_cbor(presentation_bytes) {
        if let Ok(challenge) = PopChallenge::from_cbor(challenge_bytes) {
            let _ = presentation.verify(&action, anchor(), &challenge, 300);
        }
    }
});
