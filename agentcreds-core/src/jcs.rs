//! JSON Canonicalization Scheme (RFC 8785).
//!
//! Argument binding hashes a **string**, so a holder and a relying party must produce
//! byte-identical text from the same arguments or a legitimate call is refused as
//! tampering. Neither side sees the other's bytes - a tool call arrives as a parsed
//! structure, not as the sender's serialization - so both must reconstruct them.
//! Canonicalization is the workaround for not having the original octets; JWS and COSE
//! sidestep it by signing what they received, which a re-serializing transport cannot.
//!
//! The predecessor profile (`agentcreds-json-sorted-v1`) was independent readings of
//! "sorted JSON" in each language, and measurement on 2026-08-12 had Python and Node
//! disagreeing on **9 of 18** ordinary cases - every non-ASCII string, and floats in
//! four separate ways. RFC 8785 replaces convention with a specification, so a fourth
//! language reaches for a conformant library instead of reverse-engineering ours.
//!
//! ```rust
//! use agentcreds_core::jcs;
//!
//! let v: serde_json::Value = serde_json::json!({"b": 2, "a": 1.0, "q": "café"});
//! assert_eq!(jcs::canonicalize(&v)?, r#"{"a":1,"b":2,"q":"café"}"#);
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```
//!
//! # Limits, inherited from the JSON data model
//!
//! Numbers are IEEE-754 doubles, so an integer above 2^53 loses precision - and loses it
//! *identically on both sides* when both are double-backed, so no cross-language test
//! catches it. Amounts in minor units are safe (2^53 is ~9 quadrillion); a 64-bit
//! database key or a snowflake id is not. Carry those as **strings**.
//!
//! Rust and Python hold such integers exactly and JavaScript does not, so the two
//! outcomes are a *false refusal* (the JS end canonicalizes a different number) or, with
//! JS on both ends, a binding that silently stops distinguishing a value from its
//! neighbour. [`precision_hazards`] locates them; it is a separate call rather than a
//! side channel on [`canonicalize`] because this crate has no logging dependency and is
//! not the right place to acquire one - the holder-side runtimes warn on it.

use serde_json::Value;

use crate::{error::AgentCredsError, Result};

/// The profile identifier that travels on the wire alongside a binding.
///
/// Naming the profile is what separates "we disagree about the representation" from
/// "the arguments were altered" - both produce the same binding mismatch and call for
/// entirely different responses.
pub const PROFILE: &str = "agentcreds-jcs-v1";

/// The largest integer that survives the JSON data model intact.
///
/// Above this magnitude integers stop being uniquely representable as IEEE-754 doubles:
/// `2^53` and `2^53 + 1` both round to the same value. Matches JavaScript's
/// `Number.MAX_SAFE_INTEGER`, which is where the loss actually happens.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// JSON Pointers (RFC 6901) to every integer in `value` too large to survive the JSON
/// data model, paired with the offending integer as text.
///
/// Empty is the ordinary case. A non-empty result means argument binding over this value
/// is weaker than it looks: see the module docs. The fix is always to carry the
/// identifier as a string, never to round it.
///
/// Floats are not reported - a float is approximate by construction and both ends hold
/// the same double, so there is nothing to diverge.
#[must_use]
pub fn precision_hazards(value: &Value) -> Vec<(String, String)> {
    let mut found = Vec::new();
    walk_hazards(value, &mut String::new(), &mut found);
    found
}

fn walk_hazards(value: &Value, pointer: &mut String, found: &mut Vec<(String, String)>) {
    match value {
        Value::Number(n) => {
            let unsafe_int = n
                .as_i64()
                .map(i64::unsigned_abs)
                .or_else(|| n.as_u64())
                .is_some_and(|m| m > MAX_SAFE_INTEGER);
            if unsafe_int {
                found.push((pointer.clone(), n.to_string()));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                walk_hazards(item, pointer, found);
                pointer.truncate(len);
            }
        }
        Value::Object(map) => {
            for (key, v) in map {
                let len = pointer.len();
                pointer.push('/');
                // RFC 6901 §3: `~` and `/` are escaped inside a pointer token.
                pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                walk_hazards(v, pointer, found);
                pointer.truncate(len);
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
}

fn jcs_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::OutOfBounds {
        field: "arguments",
        detail: reason.into(),
    }
}

/// The RFC 8785 canonical form of `value`.
///
/// # Errors
/// `OutOfBounds` if the value cannot be represented - a non-finite number is the only
/// case `serde_json` can hold. Refusing beats guessing: a canonicalizer that substitutes
/// emits a string the other side cannot reproduce, which presents as tampering on a
/// request that was never tampered with.
pub fn canonicalize(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) => write_string(s, out),
        Value::Number(n) => out.push_str(&write_number(n)?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3 orders keys by UTF-16 code unit. That differs from code
            // point (and from Rust's default `str` ordering, which is by byte/scalar)
            // only above the BMP: a surrogate pair begins 0xD800, so a non-BMP key sorts
            // BELOW U+E000..U+FFFF here and above it under the other two orderings.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_units(a).cmp(&utf16_units(b)));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                // The key came from `map.keys()`, so the lookup cannot miss.
                let v = map.get(*key).unwrap_or(&Value::Null);
                write_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// RFC 8785 §3.2.2.2: escape only what JSON requires, using the short forms where
/// RFC 8259 defines them and lowercase `\u00xx` for the remaining C0 controls.
/// Everything else - including all non-ASCII - is emitted literally as UTF-8.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Lowercase hex - RFC 8785 is explicit about the case.
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number::toString` (ECMA-262 §6.1.6.1.20), which RFC 8785 §3.2.2.3 defers
/// to rather than defining its own number format.
///
/// The delegation is deliberate and lopsided: JSON came from JavaScript, so a JS engine
/// gets this for free and every other language ports it. Rust's `Display` for `f64`
/// yields the same shortest round-tripping digits but never switches to exponential
/// form, and Python's `repr` switches at different magnitudes and zero-pads the
/// exponent - which is exactly how three "sorted JSON" implementations ended up
/// disagreeing on `1e-6`, `1e20`, `1e21` and `1.0`.
///
/// `{:e}` gives the shortest digits plus a base-10 exponent; the placement rules below
/// are then applied verbatim from the spec.
fn write_number(n: &serde_json::Number) -> Result<String> {
    // Integers are exact and print without a decimal point.
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    let f = n
        .as_f64()
        .ok_or_else(|| jcs_err("number is not representable as an IEEE-754 double"))?;
    if !f.is_finite() {
        return Err(jcs_err(format!("{f} has no JSON representation")));
    }
    Ok(es_number_to_string(f))
}

/// ECMAScript number formatting for a finite `f64`. Public for the conformance suite
/// and for hosts implementing the profile against a different JSON library.
#[must_use]
pub fn es_number_to_string(f: f64) -> String {
    if f == 0.0 {
        return "0".into(); // also folds -0.0, which ES prints as "0"
    }
    let sign = if f < 0.0 { "-" } else { "" };

    // e.g. "1.2345e2" -> digits "12345", exp10 2. Rust's `{:e}` uses the shortest
    // round-tripping digit string, which is the same set ES uses.
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp10: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    // `n` is the decimal-point position: value == 0.<digits> * 10^n
    let n = exp10 + 1;

    if k <= n && n <= 21 {
        let mut s = String::from(sign);
        s.push_str(digits);
        for _ in 0..(n - k) {
            s.push('0');
        }
        return s;
    }
    if n > 0 && n <= 21 {
        let split = usize::try_from(n).unwrap_or(0);
        return format!("{sign}{}.{}", &digits[..split], &digits[split..]);
    }
    if n > -6 && n <= 0 {
        let zeros = "0".repeat(usize::try_from(-n).unwrap_or(0));
        return format!("{sign}0.{zeros}{digits}");
    }
    // Exponential form.
    let e = n - 1;
    let mant = if k == 1 {
        digits.to_string()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };
    format!("{sign}{mant}e{}{}", if e >= 0 { "+" } else { "-" }, e.abs())
}
