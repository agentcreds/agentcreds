use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

/// Recursively convert a `serde_json::Value` into the equivalent Python object
/// (dict / list / str / int / float / bool / None).
pub fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py(py))
            } else {
                Ok(n.as_f64().unwrap_or_default().into_py(py))
            }
        }
        Value::String(s) => Ok(s.into_py(py)),
        Value::Array(items) => {
            let list = PyList::empty_bound(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

/// Convert a Python object into a `serde_json::Value`, refusing anything JSON cannot
/// represent rather than coercing it.
///
/// Refusing is the point. This feeds canonicalization, which produces the string both
/// sides of an argument binding must reproduce byte-for-byte - so a conversion that
/// guessed (stringifying a non-string key, or rounding an out-of-range integer) would
/// emit something the other side cannot reproduce, and that presents as tampering on a
/// request nobody tampered with.
///
/// Two orderings are load-bearing:
/// * `bool` is checked **before** `int`, because Python's `bool` is an `int` subclass
///   and `True` would otherwise serialize as `1`.
/// * `i64` then `u64` before `f64`, so a large integer keeps its exact value instead of
///   being routed through a double and losing its low bits.
pub fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    use pyo3::exceptions::PyValueError;
    use pyo3::types::{PyBool, PyFloat, PyInt, PyString};

    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = value.downcast::<PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(i) = value.extract::<i64>() {
            return Ok(Value::Number(i.into()));
        }
        if let Ok(u) = value.extract::<u64>() {
            return Ok(Value::Number(u.into()));
        }
        return Err(PyValueError::new_err(
            "integer is outside the range JSON can represent exactly",
        ));
    }
    if value.is_instance_of::<PyFloat>() {
        let f: f64 = value.extract()?;
        return serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err(format!("{f} has no JSON representation")));
    }
    if let Ok(s) = value.downcast::<PyString>() {
        return Ok(Value::String(s.extract::<String>()?));
    }
    if let Ok(list) = value.downcast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for item in list.iter() {
            out.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(tuple) = value.downcast::<pyo3::types::PyTuple>() {
        let mut out = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            out.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(out));
    }
    if let Ok(dict) = value.downcast::<PyDict>() {
        let mut map = serde_json::Map::with_capacity(dict.len());
        for (k, v) in dict.iter() {
            // JSON object keys are strings. Coercing here would silently turn `{1: "a"}`
            // into `{"1": "a"}` - a different document, canonicalized differently.
            let key = k.downcast::<PyString>().map_err(|_| {
                PyValueError::new_err(format!(
                    "object keys must be strings, got {}",
                    k.get_type()
                        .name()
                        .map(|n| n.to_string())
                        .unwrap_or_default()
                ))
            })?;
            map.insert(key.extract::<String>()?, py_to_json(&v)?);
        }
        return Ok(Value::Object(map));
    }
    Err(PyValueError::new_err(format!(
        "{} has no JSON representation",
        value
            .get_type()
            .name()
            .map(|n| n.to_string())
            .unwrap_or_default()
    )))
}
