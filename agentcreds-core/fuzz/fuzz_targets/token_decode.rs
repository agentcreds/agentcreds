//! Decode arbitrary bytes as a `DelegationToken`, then exercise its accessors.
//!
//! The decoder is the first thing attacker-controlled bytes reach: a token arrives on
//! every tool call, from whoever is making the call. The accessors are included because
//! a structurally degenerate token that decodes is more interesting than one that does
//! not - `depth()` and `chain()` walk what the decoder produced, and a panic there is
//! reachable by anything that can hand a verifier bytes.
//!
//! Nothing here asserts a *decision*. The only property is that the crate returns
//! `Err`, or a value whose accessors do not panic - never an abort.
#![no_main]

use agentcreds_core::delegation::DelegationToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = DelegationToken::from_cbor(data) {
        let _ = token.depth();
        let _ = token.chain();
        let _ = token.leaf_agent_did();
        let _ = token.root_agent_did();
        let _ = token.leaf_binding();
        let _ = token.to_cbor();
    }
});
