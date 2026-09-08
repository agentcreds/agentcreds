//! Anchor-rooted verification against fuzzed token bytes.
//!
//! `token_decode` fuzzes the decoder. This fuzzes the *decision path*: a real anchor and
//! a real credential, held fixed, with only the token varying - which is the shape of the
//! actual attack. A relying party's anchor and the credential it pins are not
//! attacker-controlled; the token presented to it is.
//!
//! The fixtures are built once and reused. Generating a keypair per input would spend
//! almost all of the fuzzer's time in Ed25519 keygen rather than in the code under test,
//! and would make every run non-reproducible from its corpus.
//!
//! The property is that no input aborts. A token that verifies is not interesting here -
//! the fuzzer cannot forge a signature - so this is looking for panics reachable *after*
//! the decode, in scope evaluation, chain walking and the Datalog authorizer.
#![no_main]

use std::sync::OnceLock;

use agentcreds_core::delegation::{Action, DelegationToken};
use agentcreds_core::did::TrustAnchor;
use agentcreds_core::testkit::MockOrg;
use agentcreds_core::vc::CapabilityCredential;
use libfuzzer_sys::fuzz_target;

struct Fixture {
    anchor: TrustAnchor,
    credential: CapabilityCredential,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let org = MockOrg::new("Fuzz Org").expect("mock org");
        let agent = org
            .issue_agent(vec!["tool:search".into()], Some(10), 2, 3600)
            .expect("issue agent");
        Fixture {
            anchor: TrustAnchor::from_did_key(org.did()).expect("verify-only anchor"),
            credential: agent.credential,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    if let Ok(token) = DelegationToken::from_cbor(data) {
        let action = Action::new("tool:search", "");
        let _ = token.verify_rooted(&action, &f.credential, &f.anchor);
    }
});
