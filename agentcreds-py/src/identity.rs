use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use agentcreds_core::did::{
    AgentIdentity, CheqdNetwork, DidDocument, DidMethod, InMemoryResolver, KeyAlgorithm, PublicKey,
    TrustAnchor, VerificationMethod,
};

use crate::convert::json_to_py;
use crate::error::map_err;

pub fn parse_algorithm(algorithm: Option<&str>) -> PyResult<Option<KeyAlgorithm>> {
    match algorithm {
        None => Ok(None),
        Some(a) => match a.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Some(KeyAlgorithm::Ed25519)),
            "p256" | "p-256" | "secp256r1" => Ok(Some(KeyAlgorithm::P256)),
            other => Err(PyValueError::new_err(format!(
                "unknown key algorithm '{other}' (expected 'ed25519' or 'p256')"
            ))),
        },
    }
}

pub fn algorithm_to_str(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ed25519 => "ed25519",
        KeyAlgorithm::P256 => "p256",
    }
}

pub fn parse_cheqd_network(network: &str) -> PyResult<CheqdNetwork> {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(CheqdNetwork::Mainnet),
        "testnet" => Ok(CheqdNetwork::Testnet),
        other => Err(PyValueError::new_err(format!(
            "unknown cheqd network '{other}' (expected 'mainnet' or 'testnet')"
        ))),
    }
}

// -- PublicKey ----------------------------------------------------------------

#[pyclass(name = "PublicKey", module = "agentcreds")]
#[derive(Clone)]
pub struct PyPublicKey {
    pub inner: PublicKey,
}

#[pymethods]
impl PyPublicKey {
    #[getter]
    fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm)
    }

    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.bytes)
    }

    fn to_multibase(&self) -> String {
        self.inner.to_multibase()
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKey(algorithm='{}', multibase='{}')",
            self.algorithm(),
            self.inner.to_multibase()
        )
    }
}

// -- VerificationMethod / DidDocument ------------------------------------------

#[pyclass(name = "VerificationMethod", module = "agentcreds")]
#[derive(Clone)]
pub struct PyVerificationMethod {
    pub inner: VerificationMethod,
}

#[pymethods]
impl PyVerificationMethod {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn r#type(&self) -> String {
        self.inner.r#type.clone()
    }

    #[getter]
    fn controller(&self) -> String {
        self.inner.controller.clone()
    }

    #[getter]
    fn public_key_multibase(&self) -> String {
        self.inner.public_key_multibase.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "VerificationMethod(id='{}', type='{}')",
            self.inner.id, self.inner.r#type
        )
    }
}

#[pyclass(name = "DidDocument", module = "agentcreds")]
#[derive(Clone)]
pub struct PyDidDocument {
    pub inner: DidDocument,
}

#[pymethods]
impl PyDidDocument {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn context(&self) -> Vec<String> {
        self.inner.context.clone()
    }

    #[getter]
    fn authentication(&self) -> Vec<String> {
        self.inner.authentication.clone()
    }

    #[getter]
    fn assertion_method(&self) -> Vec<String> {
        self.inner.assertion_method.clone()
    }

    #[getter]
    fn created(&self) -> DateTime<Utc> {
        self.inner.created
    }

    #[getter]
    fn updated(&self) -> DateTime<Utc> {
        self.inner.updated
    }

    #[getter]
    fn verification_method(&self) -> Vec<PyVerificationMethod> {
        self.inner
            .verification_method
            .iter()
            .cloned()
            .map(|inner| PyVerificationMethod { inner })
            .collect()
    }

    fn primary_key_multibase(&self) -> Option<String> {
        self.inner.primary_key_multibase().map(String::from)
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let value =
            serde_json::to_value(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))?;
        json_to_py(py, &value)
    }

    fn __repr__(&self) -> String {
        format!("DidDocument(id='{}')", self.inner.id)
    }
}

// -- AgentIdentity -------------------------------------------------------------

#[pyclass(name = "AgentIdentity", module = "agentcreds")]
pub struct PyAgentIdentity {
    pub inner: AgentIdentity,
}

#[pymethods]
impl PyAgentIdentity {
    /// Create an ephemeral `did:key` identity.
    #[staticmethod]
    #[pyo3(signature = (algorithm=None))]
    fn create_did_key(algorithm: Option<&str>) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: AgentIdentity::create(DidMethod::Key, algo).map_err(map_err)?,
        })
    }

    /// Create an org-anchored `did:web` identity.
    #[staticmethod]
    #[pyo3(signature = (host, path=None, algorithm=None))]
    fn create_did_web(
        host: String,
        path: Option<String>,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: AgentIdentity::create(DidMethod::Web { host, path }, algo).map_err(map_err)?,
        })
    }

    /// Create a `did:cheqd` identity for the given network.
    #[staticmethod]
    #[pyo3(signature = (network, unique_id, algorithm=None))]
    fn create_did_cheqd(
        network: &str,
        unique_id: String,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let network = parse_cheqd_network(network)?;
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: AgentIdentity::create(DidMethod::Cheqd { network, unique_id }, algo)
                .map_err(map_err)?,
        })
    }

    /// Create a `did:indy` identity within the given ledger namespace.
    #[staticmethod]
    #[pyo3(signature = (namespace, unique_id, algorithm=None))]
    fn create_did_indy(
        namespace: String,
        unique_id: String,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: AgentIdentity::create(
                DidMethod::Indy {
                    namespace,
                    unique_id,
                },
                algo,
            )
            .map_err(map_err)?,
        })
    }

    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[getter]
    fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm())
    }

    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key().clone(),
        }
    }

    fn document(&self) -> PyDidDocument {
        PyDidDocument {
            inner: self.inner.document().clone(),
        }
    }

    fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.inner.sign(message).map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &sig))
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        self.inner.verify(message, signature).map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "AgentIdentity(did='{}', algorithm='{}')",
            self.inner.did(),
            algorithm_to_str(self.inner.algorithm())
        )
    }
}

// -- TrustAnchor ---------------------------------------------------------------

#[pyclass(name = "TrustAnchor", module = "agentcreds")]
pub struct PyTrustAnchor {
    pub inner: TrustAnchor,
}

#[pymethods]
impl PyTrustAnchor {
    /// Convenience constructor for a `did:key` / Ed25519 trust anchor.
    #[staticmethod]
    fn generate() -> PyResult<Self> {
        Ok(Self {
            inner: TrustAnchor::generate().map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:key` identifier.
    #[staticmethod]
    #[pyo3(signature = (algorithm=None))]
    fn create_did_key(algorithm: Option<&str>) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: TrustAnchor::create(DidMethod::Key, algo, None).map_err(map_err)?,
        })
    }

    /// Construct a **verify-only** trust anchor from a ``did:key`` (no private
    /// key) - e.g. the current key reached by following a ``KeyHistory``. Use it
    /// to verify credentials/signatures against a known anchor DID; signing fails.
    #[staticmethod]
    fn from_did_key(did: &str) -> PyResult<Self> {
        Ok(Self {
            inner: TrustAnchor::from_did_key(did).map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:web` identifier.
    #[staticmethod]
    #[pyo3(signature = (host, path=None, algorithm=None))]
    fn create_did_web(
        host: String,
        path: Option<String>,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        Ok(Self {
            inner: TrustAnchor::create(DidMethod::Web { host, path }, algo, None)
                .map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:cheqd` identifier.
    #[staticmethod]
    #[pyo3(signature = (network, unique_id, algorithm=None))]
    fn create_did_cheqd(
        network: &str,
        unique_id: String,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let network = parse_cheqd_network(network)?;
        let algo = parse_algorithm(algorithm)?;
        let resolver = InMemoryResolver::new();
        Ok(Self {
            inner: TrustAnchor::create(
                DidMethod::Cheqd { network, unique_id },
                algo,
                Some(&resolver),
            )
            .map_err(map_err)?,
        })
    }

    /// Create a trust anchor anchored to a `did:indy` identifier.
    #[staticmethod]
    #[pyo3(signature = (namespace, unique_id, algorithm=None))]
    fn create_did_indy(
        namespace: String,
        unique_id: String,
        algorithm: Option<&str>,
    ) -> PyResult<Self> {
        let algo = parse_algorithm(algorithm)?;
        let resolver = InMemoryResolver::new();
        Ok(Self {
            inner: TrustAnchor::create(
                DidMethod::Indy {
                    namespace,
                    unique_id,
                },
                algo,
                Some(&resolver),
            )
            .map_err(map_err)?,
        })
    }

    #[getter]
    fn did(&self) -> String {
        self.inner.did().to_string()
    }

    #[getter]
    fn algorithm(&self) -> &'static str {
        algorithm_to_str(self.inner.algorithm())
    }

    #[getter]
    fn public_key(&self) -> PyPublicKey {
        PyPublicKey {
            inner: self.inner.public_key().clone(),
        }
    }

    fn document(&self) -> PyDidDocument {
        PyDidDocument {
            inner: self.inner.document().clone(),
        }
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        self.inner
            .verify_signature(message, signature)
            .map_err(map_err)
    }

    fn __repr__(&self) -> String {
        format!("TrustAnchor(did='{}')", self.inner.did())
    }
}

// -- InMemoryResolver ----------------------------------------------------------

/// In-memory DID resolver used for tests, local development, and wiring up
/// `TrustRegistry` cross-org resolution without a network round-trip.
///
/// Once passed to `TrustRegistry.with_in_memory_resolver()`, the resolver is
/// consumed and can no longer be modified.
#[pyclass(name = "InMemoryResolver", module = "agentcreds")]
pub struct PyInMemoryResolver {
    pub inner: Option<InMemoryResolver>,
}

#[pymethods]
impl PyInMemoryResolver {
    #[new]
    fn new() -> Self {
        Self {
            inner: Some(InMemoryResolver::new()),
        }
    }

    /// Register a DID document so it can be resolved later.
    fn register(&mut self, did: String, document: &PyDidDocument) -> PyResult<()> {
        let resolver = self.inner.as_mut().ok_or_else(|| {
            PyValueError::new_err(
                "resolver has already been bound to a TrustRegistry and can no longer be modified",
            )
        })?;
        resolver.register(did, document.inner.clone());
        Ok(())
    }

    /// Convenience: register an `AgentIdentity`'s DID document under its own DID.
    fn register_identity(&mut self, identity: &PyAgentIdentity) -> PyResult<()> {
        let resolver = self.inner.as_mut().ok_or_else(|| {
            PyValueError::new_err(
                "resolver has already been bound to a TrustRegistry and can no longer be modified",
            )
        })?;
        resolver.register(
            identity.inner.did().to_string(),
            identity.inner.document().clone(),
        );
        Ok(())
    }

    fn __repr__(&self) -> String {
        "InMemoryResolver()".to_string()
    }
}
