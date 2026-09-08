//! Hostile-input tests for the decode entry points a relying party exposes.
//!
//! `Presentation::from_cbor` / `DelegationToken::from_cbor` are the PEP's front door:
//! they are handed bytes chosen by whoever is calling the tool, BEFORE any signature has
//! been checked. Everything a verifier does afterwards is irrelevant if the decoder can
//! be made to exhaust the stack or the heap first, so the decode step must fail as a
//! clean `Err` on every shape of garbage, never a panic or an abort.
//!
//! These are the classic parser-DoS shapes: unbounded nesting (recursive-descent stack
//! exhaustion) and a declared-length bomb (a few bytes that ask the decoder to reserve
//! gigabytes).

use agentcreds_core::delegation::DelegationToken;
use agentcreds_core::pop::Presentation;

/// `n` nested single-element CBOR arrays wrapping a zero. Each 0x81 costs one byte on
/// the wire and one frame in a recursive decoder - the cheapest possible amplification.
fn nested_arrays(n: usize) -> Vec<u8> {
    let mut v = vec![0x81u8; n];
    v.push(0x00);
    v
}

#[test]
fn deeply_nested_cbor_is_rejected_not_fatal() {
    // 1 MiB of nesting. If the decoder recurses per level without a bound this is a
    // stack overflow, which aborts the process - a remote kill switch on the PEP, not a
    // denied request.
    let bomb = nested_arrays(1_000_000);
    assert!(DelegationToken::from_cbor(&bomb).is_err());
    assert!(Presentation::from_cbor(&bomb).is_err());
}

#[test]
fn declared_length_bomb_does_not_reserve_memory() {
    // A definite-length byte string claiming ~4 GiB, with no payload behind it. A
    // decoder that trusts the length prefix and pre-allocates dies on 9 bytes of input.
    let bomb = vec![0x5a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
    assert!(DelegationToken::from_cbor(&bomb).is_err());
    assert!(Presentation::from_cbor(&bomb).is_err());

    // Same idea for an array header: 2^32-1 elements promised, none delivered.
    let bomb = vec![0x9a, 0xff, 0xff, 0xff, 0xff];
    assert!(DelegationToken::from_cbor(&bomb).is_err());
    assert!(Presentation::from_cbor(&bomb).is_err());
}

#[test]
fn truncated_and_empty_input_is_rejected() {
    for bytes in [
        b"".as_slice(),
        b"\x00",
        b"\xff",
        b"\x9f",
        b"not cbor at all",
    ] {
        assert!(DelegationToken::from_cbor(bytes).is_err());
        assert!(Presentation::from_cbor(bytes).is_err());
    }
}

#[test]
fn a2a_header_rejects_garbage_without_panicking() {
    // The A2A path base64-decodes an attacker-supplied header before any verification.
    for header in [
        "",
        "AgentCreds-A2A/1.",
        "AgentCreds-A2A/1.!!!!not-base64!!!!",
        "AgentCreds-A2A/1.AAAA",
        "wrong-prefix.AAAA",
    ] {
        assert!(Presentation::from_a2a_header(header).is_err());
    }
}
