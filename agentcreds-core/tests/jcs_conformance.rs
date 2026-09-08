//! RFC 8785 canonicalization, held to the SAME cross-language vectors as Python and Node.
//!
//! `../../conformance/jcs_vectors.json` is the contract. All three runtimes assert
//! against it, so a divergence fails on whichever side moved rather than surfacing later
//! as an unexplained binding mismatch on a request nobody tampered with.
//!
//! Why this file exists at all: the predecessor profile was three independent readings
//! of "sorted JSON", and measurement on 2026-08-12 had Python and Node disagreeing on
//! 9 of 18 ordinary cases. Rust had no implementation, so a Rust-native holder could not
//! participate in argument binding.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use agentcreds_core::jcs;
use serde_json::Value;

const VECTORS: &str = include_str!("../../conformance/jcs_vectors.json");

#[test]
fn every_shared_vector_canonicalizes_to_the_same_bytes_as_python_and_node() {
    let suite: Value = serde_json::from_str(VECTORS).expect("vectors must parse");
    assert_eq!(
        suite["profile"].as_str(),
        Some(jcs::PROFILE),
        "the profile identifier travels on the wire; it must match the vectors"
    );

    let cases = suite["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "vectors file is empty");

    for case in cases {
        let value = &case["value"];
        let expected = case["expected_jcs"].as_str().expect("expected_jcs");
        let got = jcs::canonicalize(value).expect("canonicalization must succeed");
        assert_eq!(got, expected, "diverged from the shared vector for {value}");
    }
}

/// ECMAScript `Number::toString`, which RFC 8785 defers to. These are the cases where a
/// port goes wrong: Rust's `Display` never uses exponential form and Python's `repr`
/// switches at different magnitudes, so the thresholds have to be pinned explicitly.
#[test]
fn numbers_follow_ecmascript_tostring() {
    let cases: &[(f64, &str)] = &[
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (1.234_56, "1.23456"),
        (1e20, "100000000000000000000"), // below the exponential threshold
        (1e21, "1e+21"),                 // at it
        (1e-6, "0.000001"),              // above the small threshold
        (1e-7, "1e-7"),                  // below it, and no zero-padded exponent
        (9007199254740992.0, "9007199254740992"),
        (5e-324, "5e-324"), // smallest subnormal
    ];
    for (value, expected) in cases {
        assert_eq!(
            &jcs::es_number_to_string(*value),
            expected,
            "{value} must format as {expected}"
        );
    }
}

#[test]
fn non_ascii_is_literal_and_controls_are_escaped() {
    // Python's json.dumps escapes every non-ASCII character by default; RFC 8785
    // requires literal UTF-8. This was the single biggest source of divergence.
    let v = serde_json::json!({"q": "café", "ctrl": "a\u{1}b", "nl": "x\ny"});
    let out = jcs::canonicalize(&v).unwrap();
    assert!(out.contains("café"), "{out}");
    assert!(!out.contains("\\u00e9"), "{out}");
    assert!(out.contains("\\u0001"), "{out}");
    assert!(out.contains("\\n"), "{out}");
}

/// RFC 8785 §3.2.3 orders keys by UTF-16 code unit. That differs from Rust's natural
/// `str` ordering only above the BMP - a surrogate pair begins 0xD800, so a non-BMP key
/// sorts BELOW U+E000..U+FFFF here and above it by scalar value.
#[test]
fn keys_sort_by_utf16_code_unit_not_scalar_value() {
    let v = serde_json::json!({"\u{1f511}": "non-BMP", "\u{e000}": "private use"});
    let out = jcs::canonicalize(&v).unwrap();
    let non_bmp = out.find('\u{1f511}').expect("non-BMP key present");
    let private = out.find('\u{e000}').expect("private-use key present");
    assert!(
        non_bmp < private,
        "UTF-16 code-unit order puts the surrogate pair first: {out}"
    );
    // Rust's own ordering would disagree, which is the point of sorting explicitly.
    assert!("\u{1f511}" > "\u{e000}", "scalar order is the opposite");
}

#[test]
fn structure_is_canonical_throughout() {
    let v = serde_json::json!({
        "nested": {"z": [1, 2, {"y": "ünïcode"}], "a": true},
        "empty_obj": {}, "empty_arr": [], "nulls": [null, true, false]
    });
    let out = jcs::canonicalize(&v).unwrap();
    assert_eq!(
        out,
        r#"{"empty_arr":[],"empty_obj":{},"nested":{"a":true,"z":[1,2,{"y":"ünïcode"}]},"nulls":[null,true,false]}"#
    );
    // No insignificant whitespace anywhere.
    assert!(!out.contains(", "), "{out}");
    assert!(!out.contains(": "), "{out}");
}

#[test]
fn canonicalization_is_stable_across_input_key_order() {
    // The whole point: two holders that built the same map differently must agree.
    let a: Value = serde_json::from_str(r#"{"b":2,"a":1,"c":3}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"c":3,"a":1,"b":2}"#).unwrap();
    assert_eq!(
        jcs::canonicalize(&a).unwrap(),
        jcs::canonicalize(&b).unwrap()
    );
    assert_eq!(jcs::canonicalize(&a).unwrap(), r#"{"a":1,"b":2,"c":3}"#);
}

// -- Precision hazards (2^53) ----------------------------------------------------
//
// Rust holds a 64-bit integer exactly, so `canonicalize` emits it correctly and no
// amount of testing HERE catches the problem. The hazard is that a JavaScript peer
// parsed the same literal into a double first, so it canonicalizes a different number:
// either the binding mismatches on an untampered request, or - with JS at both ends -
// it silently stops distinguishing the value from its neighbour.

#[test]
fn integers_past_2_53_are_reported_as_precision_hazards() {
    let snowflake = serde_json::json!({"id": 9_007_199_254_740_993_i64});
    let found = jcs::precision_hazards(&snowflake);
    assert_eq!(found.len(), 1, "expected one hazard, got {found:?}");
    assert_eq!(found[0].0, "/id");

    // Canonicalization itself still succeeds and is still exact - the check is a
    // separate call precisely because there is nothing to fail here.
    assert_eq!(
        jcs::canonicalize(&snowflake).unwrap(),
        r#"{"id":9007199254740993}"#
    );
}

#[test]
fn ordinary_values_report_no_hazard() {
    // 2^53-1 is the last exactly-representable integer, so the boundary is inclusive.
    let ok = serde_json::json!({
        "amount_minor": 9_007_199_254_740_991_i64,
        "ratio": 1.5,
        "big_float": 1e21,
        "id": "9007199254740993",
        "nested": [1, 2, {"n": -42}],
    });
    assert!(jcs::precision_hazards(&ok).is_empty());
}

#[test]
fn hazards_are_located_by_json_pointer_through_arrays_and_objects() {
    let value = serde_json::json!({
        "orders": [{"ref": 1}, {"ref": 9_007_199_254_740_994_i64}],
        "a/b": 18_446_744_073_709_551_615_u64,
    });
    let mut found = jcs::precision_hazards(&value);
    found.sort();
    let pointers: Vec<&str> = found.iter().map(|(p, _)| p.as_str()).collect();
    // RFC 6901 §3 escapes `/` inside a token as `~1`.
    assert_eq!(pointers, vec!["/a~1b", "/orders/1/ref"]);
}
