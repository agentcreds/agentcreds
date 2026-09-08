//! The carry-the-octets binding profile (`agentcreds-octets-v1`).
//!
//! Canonicalization is a workaround for not having the original octets. JWS and COSE
//! sidestep the problem by signing what they received; a re-serializing transport takes
//! that option away, so [`crate::jcs`] reconstructs the bytes on both sides and requires
//! two implementations to agree on how to write every value.
//!
//! This profile removes the requirement. The holder serializes its arguments however it
//! likes, signs *those exact bytes*, and carries them alongside the presentation. The
//! verifier never re-serializes anything:
//!
//! 1. It verifies the proof over the carried octets - the literal string the holder
//!    signed. In this crate that is just `Action::new(tool, carried)`, because the
//!    action binding hashes a string and does not care where it came from.
//! 2. It parses them and compares the result to what the transport delivered, using
//!    [`semantic_eq`].
//!
//! Both must hold. Altering the delivered arguments fails step 2; altering the carried
//! octets fails step 1. Neither can be traded for the other.
//!
//! # What it costs
//!
//! The arguments travel twice, so [`MAX_BOUND_ARGS_BYTES`] caps the carried copy - it is
//! attacker-controlled text that has to be parsed before anything is authenticated. The
//! second copy also lands wherever the transport keeps reserved arguments, which is
//! often logged more casually than a request body.
//!
//! # What it is not
//!
//! This is *comparison*, not authority: the tool still executes the arguments the
//! transport delivered, and what the profile guarantees is that those are semantically
//! the ones the holder signed. Making the carried copy authoritative - substituting it
//! into the call - is a strictly stronger property and a much larger change, because the
//! enforcement point would become rewriting rather than admitting.

use serde_json::{Number, Value};

use crate::{error::AgentCredsError, Result};

/// The profile identifier that travels on the wire alongside a binding.
pub const PROFILE: &str = "agentcreds-octets-v1";

/// Ceiling on the carried copy, in bytes.
///
/// Far above any plausible tool call. The point is that it is bounded at all: an
/// unbounded attacker-supplied string that the verifier must parse before authenticating
/// anything is a denial-of-service primitive.
pub const MAX_BOUND_ARGS_BYTES: usize = 64 * 1024;

fn binding_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::OutOfBounds {
        field: "bound_arguments",
        detail: reason.into(),
    }
}

/// Serialize arguments on the **holder** side, for both signing and carrying.
///
/// The exact serialization does not matter - that is the point of the profile - so this
/// is plain compact JSON. What matters is that the string returned here is the one bound
/// into the action AND the one carried to the verifier. Deriving them separately would
/// reintroduce exactly the divergence this profile exists to remove.
///
/// # Errors
/// `OutOfBounds` if the value cannot be serialized.
pub fn bind_args(value: &Value) -> Result<String> {
    serde_json::to_string(value).map_err(|e| binding_err(format!("could not serialize: {e}")))
}

/// Parse carried octets on the **verifier** side.
///
/// # Errors
/// `OutOfBounds` if the octets are oversized or not valid JSON. This runs before
/// anything has been authenticated, so every failure has to be a refusal.
pub fn parse_bound_args(text: &str) -> Result<Value> {
    if text.is_empty() {
        return Err(binding_err("no bound arguments were carried"));
    }
    if text.len() > MAX_BOUND_ARGS_BYTES {
        return Err(binding_err(format!(
            "bound arguments are {} bytes, over the {MAX_BOUND_ARGS_BYTES}-byte limit",
            text.len()
        )));
    }
    serde_json::from_str(text).map_err(|e| binding_err(format!("not valid JSON: {e}")))
}

/// Structural equality over two parsed JSON values.
///
/// This is why the profile is simpler than canonicalization: *comparing* two values is
/// forgiving where *emitting* one is not. Nothing here decides how many digits a float
/// gets, when to use exponential notation, or which characters to escape - only whether
/// two already-parsed values mean the same thing.
///
/// Objects compare as unordered key sets; arrays keep their order, because order is
/// meaning in JSON. Numbers compare numerically, so a holder that wrote `1` and a
/// transport that delivered `1.0` agree - and two integers compare *exactly*, which is
/// how this profile avoids the 2^53 cliff that [`crate::jcs`] inherits.
#[must_use]
pub fn semantic_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => numbers_eq(x, y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(p, q)| semantic_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| semantic_eq(v, w)))
        }
        _ => false,
    }
}

fn numbers_eq(a: &Number, b: &Number) -> bool {
    // Integers first and exactly - routing them through `f64` is precisely the mistake
    // that makes 2^53 a cliff, and this profile has no reason to make it.
    if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (a.as_u64(), b.as_u64()) {
        return x == y;
    }
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}
