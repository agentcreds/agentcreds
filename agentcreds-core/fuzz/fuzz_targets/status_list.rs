//! Revocation status list: parse arbitrary JSON, then look up arbitrary indices.
//!
//! A status list is *fetched* - a relying party pulls it from the issuer's endpoint - so
//! its bytes are attacker-influenced in the same way a DID document is, and it is parsed
//! before its signature can be checked because the signature is inside it.
//!
//! The index lookups are the second half of the target and matter as much as the parse:
//! the encoded bitstring is compressed and length-prefixed by fields the same untrusted
//! document supplies, so a list claiming a size its bitstring does not support is the
//! obvious way to reach an out-of-bounds path. `u64` indices are drawn from the input
//! rather than fixed, so the fuzzer can find the boundary itself.
#![no_main]

use agentcreds_core::revocation::RevocationList;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first 8 bytes, when present, become the index to probe; the rest is the
    // document. Taking the index from the input keeps the two coupled, so a corpus entry
    // that found an interesting size also carries the index that exposed it.
    let (index, json_bytes) = if data.len() >= 8 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(b), &data[8..])
    } else {
        (0u64, data)
    };

    let Ok(json) = std::str::from_utf8(json_bytes) else {
        return;
    };
    if let Ok(list) = RevocationList::from_json(json) {
        let _ = list.is_revoked(index);
        let _ = list.is_revoked(0);
        let _ = list.revocation_count();
    }
});
