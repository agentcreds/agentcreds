//! RFC 8785 (JSON Canonicalization Scheme) from the core, for Python.
//!
//! Exposed so a holder built on this wheel alone can produce a **correct** binding
//! string. Without it the only option is to reimplement JCS, and that is the exact
//! divergence the profile exists to remove - two independent readings of "sorted JSON"
//! disagreed on 9 of 18 ordinary cases when measured on 2026-08-12.
//!
//! It is also what lets `agentcreds_runtime.jcs` stop carrying its own port of
//! ECMAScript `Number::toString`: the same algorithm maintained twice in two languages
//! is the thing most likely to drift, and it is the hardest part of the profile to get
//! right.

use pyo3::prelude::*;

use crate::convert::py_to_json;
use crate::error::map_err;

/// The RFC 8785 canonical form of a JSON-representable Python value.
///
/// Raises rather than falling back for anything JSON cannot represent (a set, a
/// non-string key, NaN): a canonicalizer that guesses emits a string the other side
/// cannot reproduce, which presents as tampering on an untampered request.
#[pyfunction]
pub fn jcs_canonicalize(value: &Bound<'_, PyAny>) -> PyResult<String> {
    let json = py_to_json(value)?;
    agentcreds_core::jcs::canonicalize(&json).map_err(map_err)
}

/// ECMAScript `Number::toString` for a float, which RFC 8785 §3.2.2.3 defers to.
///
/// Integers are not routed through here - they print exactly and a `f64` would lose
/// anything past 2^53, which is the whole hazard this profile documents.
#[pyfunction]
pub fn jcs_serialize_float(value: f64) -> PyResult<String> {
    if !value.is_finite() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "{value} has no JSON representation"
        )));
    }
    Ok(agentcreds_core::jcs::es_number_to_string(value))
}

/// RFC 6901 pointers to every integer too large to survive the JSON data model, paired
/// with the offending integer as text. Empty is the ordinary case.
///
/// Reported rather than corrected: the value is exact here, and the hazard is that a
/// JavaScript peer parsed the same literal into a double before canonicalizing.
#[pyfunction]
pub fn jcs_precision_hazards(value: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    let json = py_to_json(value)?;
    Ok(agentcreds_core::jcs::precision_hazards(&json))
}
