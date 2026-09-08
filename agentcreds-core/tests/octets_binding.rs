//! The carry-the-octets binding profile (`agentcreds-octets-v1`), end to end in Rust.
//!
//! The claim is that no agreement about *serialization* is needed. The load-bearing test
//! is `a_serialization_no_canonicalizer_would_ever_emit`: a holder serializes perversely,
//! the verifier checks the proof over those exact bytes, and the call is admitted.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use agentcreds_core::binding;
use serde_json::{json, Value};

// -- semantic_eq: the rules the profile rests on ------------------------------

#[test]
fn semantic_eq_ignores_spelling_but_not_meaning() {
    // Key order is not meaning.
    assert!(binding::semantic_eq(
        &json!({"a": 1, "b": 2}),
        &json!({"b": 2, "a": 1})
    ));
    // Array order IS meaning.
    assert!(!binding::semantic_eq(&json!([1, 2]), &json!([2, 1])));
    // How a number was written is not part of what it means.
    assert!(binding::semantic_eq(&json!({"n": 1}), &json!({"n": 1.0})));
    assert!(!binding::semantic_eq(&json!({"n": 1}), &json!({"n": 2})));
    // ...but a number is not a string, and a missing key is not a null one.
    assert!(!binding::semantic_eq(&json!({"n": 1}), &json!({"n": "1"})));
    assert!(!binding::semantic_eq(
        &json!({"a": 1}),
        &json!({"a": 1, "b": 2})
    ));
    assert!(!binding::semantic_eq(&json!({"a": 1}), &json!({"a": null})));
}

#[test]
fn semantic_eq_does_not_confuse_booleans_with_numbers() {
    assert!(!binding::semantic_eq(
        &json!({"admin": true}),
        &json!({"admin": 1})
    ));
    assert!(binding::semantic_eq(
        &json!({"admin": true}),
        &json!({"admin": true})
    ));
}

#[test]
fn semantic_eq_compares_large_integers_exactly() {
    // The 2^53 cliff is a property of canonicalizing through doubles, not of binding.
    // Nothing here routes an integer through an f64, so neighbours stay distinguishable.
    assert!(!binding::semantic_eq(
        &json!({"id": 9_007_199_254_740_993_i64}),
        &json!({"id": 9_007_199_254_740_992_i64})
    ));
    assert!(binding::semantic_eq(
        &json!({"id": 9_007_199_254_740_993_i64}),
        &json!({"id": 9_007_199_254_740_993_i64})
    ));
}

#[test]
fn semantic_eq_handles_signed_and_unsigned_without_collapsing_them() {
    // u64::MAX does not fit in an i64, so the exact paths must not silently fall through
    // to an f64 compare that would call these equal.
    let big = json!({"n": u64::MAX});
    let other = json!({"n": u64::MAX - 1});
    assert!(binding::semantic_eq(&big, &json!({"n": u64::MAX})));
    assert!(!binding::semantic_eq(&big, &other));
    assert!(!binding::semantic_eq(&json!({"n": -1_i64}), &big));
}

// -- parse_bound_args: this all runs before anything is authenticated ---------

#[test]
fn carried_octets_are_bounded_and_must_be_json() {
    assert!(binding::parse_bound_args("").is_err());
    assert!(binding::parse_bound_args("{not json").is_err());

    let oversized = format!(
        r#"{{"blob":"{}"}}"#,
        "x".repeat(binding::MAX_BOUND_ARGS_BYTES)
    );
    let err = binding::parse_bound_args(&oversized).unwrap_err();
    assert!(
        format!("{err}").contains("over the"),
        "expected a size refusal, got {err}"
    );
}

#[test]
fn bind_args_round_trips_through_parse() {
    let value = json!({"q": "café", "amount": 1.0, "ids": [1, 2, 3]});
    let octets = binding::bind_args(&value).unwrap();
    let parsed = binding::parse_bound_args(&octets).unwrap();
    assert!(binding::semantic_eq(&value, &parsed));
}

// -- The claim ----------------------------------------------------------------

#[test]
fn a_serialization_no_canonicalizer_would_ever_emit() {
    let delivered: Value = json!({"q": "café", "amount": 1.0, "zeta": [1, 2], "alpha": null});

    // Indentation, unsorted keys - output no canonicalizer produces and no verifier
    // could guess.
    let perverse = serde_json::to_string_pretty(&delivered).unwrap();
    assert_ne!(
        perverse,
        agentcreds_core::jcs::canonicalize(&delivered).unwrap(),
        "fixture must not be accidentally canonical"
    );

    // The verifier's whole job: parse what was carried, compare it to what arrived.
    let parsed = binding::parse_bound_args(&perverse).unwrap();
    assert!(binding::semantic_eq(&parsed, &delivered));
}

#[test]
fn the_profile_identifier_is_stable() {
    // It travels on the wire; changing it silently would orphan every holder that
    // declares the old one.
    assert_eq!(binding::PROFILE, "agentcreds-octets-v1");
}
