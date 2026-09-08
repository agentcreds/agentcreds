//! HTTP resolver backed by a [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver).
//!
//! A single endpoint resolves any DID method it supports - including the
//! ledger-anchored `did:cheqd` and `did:indy`, plus `did:web` - via
//! `GET {endpoint}/1.0/identifiers/{did}`. This is a **network** resolver: it
//! lives behind the `resolver-universal` feature, *outside* the offline verify
//! path. Supply it (or any [`DidResolver`]) to the resolver-aware verification
//! methods (`verify_with_resolver`, `verify_rooted_with_resolver`) so that
//! `did:web` / `did:cheqd` / `did:indy` hops can be checked.
//!
//! Only `publicKeyMultibase` verification methods are mapped (the form
//! AgentCreds verifies against); `publicKeyJwk` / `publicKeyBase58` are skipped.

use chrono::Utc;
use serde::Deserialize;

use agentcreds_core::did::DidResolver;
use agentcreds_core::did::{DidDocument, VerificationMethod};
use agentcreds_core::error::AgentCredsError;
use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on a resolution response body, matching `WebResolver`'s.
///
/// This resolver has the same threat model as `did:web` - an HTTP response from a host
/// the caller does not control - but was reading the body to completion with no bound,
/// so the endpoint chose how much the client allocated. A Universal Resolver is if
/// anything the *worse* case of the two: it is a single endpoint proxying every DID
/// method, so one compromised or hostile resolver reaches every resolution the client
/// makes, not just the ones for DIDs on its own host.
const MAX_DOC_BYTES: u64 = 1024 * 1024;

/// Characters a DID may legally contain in the position we interpolate it into.
/// Per the DID syntax a method-specific id is limited to unreserved characters plus
/// `:` `.` `%` `_` `-`; anything outside that set - notably `/`, `?`, `#`, `\` - would
/// let an untrusted DID steer the request off the intended path.
fn is_safe_did_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '%')
}

/// A DID resolver backed by a DIF Universal Resolver HTTP endpoint.
pub struct UniversalResolverClient {
    endpoint: String,
    http: reqwest::blocking::Client,
}

impl UniversalResolverClient {
    /// A client for `endpoint` (e.g. your own Universal Resolver instance).
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            // `reqwest` has no default timeout, and resolution can sit on a request
            // path: without these a resolver endpoint that stops responding parks the
            // calling thread forever rather than returning an error.
            http: reqwest::blocking::Client::builder()
                .timeout(FETCH_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }

    /// The DIF-hosted public Universal Resolver (`https://dev.uniresolver.io`).
    /// Convenient for development; run your own instance in production.
    #[must_use]
    pub fn dif() -> Self {
        Self::new("https://dev.uniresolver.io")
    }
}

impl DidResolver for UniversalResolverClient {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        if !did.starts_with("did:") {
            return Err(AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "not a DID (must start with 'did:')".into(),
            });
        }
        // The DID is untrusted and goes into the URL PATH, so it must not be able to
        // contain path or query syntax. `did:x/../../admin` would otherwise normalize
        // to a different endpoint on the resolver host, turning DID resolution into a
        // request-forgery primitive against whatever else that host serves. Reject
        // rather than escape: a DID containing these is malformed anyway, and rejecting
        // cannot silently change which document is returned.
        if let Some(bad) = did.chars().find(|c| !is_safe_did_char(*c)) {
            return Err(AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: format!("DID contains an illegal character {bad:?}"),
            });
        }
        let url = format!(
            "{}/1.0/identifiers/{}",
            self.endpoint.trim_end_matches('/'),
            did
        );
        let fail = |reason: String| AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason,
        };
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| fail(format!("HTTP request failed: {e}")))?
            .error_for_status()
            .map_err(|e| fail(format!("HTTP error: {e}")))?;
        // Reject on the declared length where the host provides one - cheap, and the
        // honest oversize case costs nothing to detect...
        if let Some(len) = resp.content_length() {
            if len > MAX_DOC_BYTES {
                return Err(fail(format!(
                    "resolution response too large: {len} bytes exceeds the {MAX_DOC_BYTES} byte limit"
                )));
            }
        }
        // ...but Content-Length is supplied by the same untrusted host, and is optional,
        // so the read is what actually bounds memory. `take` caps what comes off the
        // socket; a body that reaches the cap is over the limit whatever it contains.
        use std::io::Read as _;
        let mut raw = Vec::new();
        resp.take(MAX_DOC_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|e| fail(format!("failed to read response: {e}")))?;
        if raw.len() as u64 > MAX_DOC_BYTES {
            return Err(fail(format!(
                "resolution response too large: exceeds the {MAX_DOC_BYTES} byte limit"
            )));
        }
        let body = String::from_utf8(raw)
            .map_err(|e| fail(format!("response was not valid UTF-8: {e}")))?;
        parse_resolution_result(did, &body)
    }

    fn method(&self) -> &str {
        "universal"
    }

    fn handles(&self, did: &str) -> bool {
        did.starts_with("did:")
    }
}

// -- Resolution-result mapping (W3C / DIF camelCase -> our DidDocument) ------------

#[derive(Deserialize)]
struct ResolutionResult {
    #[serde(rename = "didDocument")]
    did_document: Option<UniDoc>,
}

#[derive(Deserialize)]
struct UniDoc {
    #[serde(rename = "@context", default)]
    context: serde_json::Value,
    id: String,
    #[serde(rename = "verificationMethod", default)]
    verification_method: Vec<UniVm>,
    #[serde(default)]
    authentication: Vec<serde_json::Value>,
    #[serde(rename = "assertionMethod", default)]
    assertion_method: Vec<serde_json::Value>,
    #[serde(rename = "capabilityDelegation", default)]
    capability_delegation: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct UniVm {
    id: String,
    #[serde(rename = "type")]
    vm_type: String,
    controller: String,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Option<String>,
}

/// Map a Universal Resolver resolution result (`{ "didDocument": {...} }`) or a
/// bare DID document JSON into our [`DidDocument`].
pub(crate) fn parse_resolution_result(
    did: &str,
    json: &str,
) -> Result<DidDocument, AgentCredsError> {
    let fail = |reason: String| AgentCredsError::DidResolutionFailed {
        did: did.to_string(),
        reason,
    };

    // The endpoint returns `{ didDocument: {...}, ... }`; some return the bare doc.
    let doc: UniDoc = match serde_json::from_str::<ResolutionResult>(json) {
        Ok(ResolutionResult {
            did_document: Some(d),
        }) => d,
        _ => serde_json::from_str(json)
            .map_err(|e| fail(format!("invalid DID document JSON: {e}")))?,
    };

    let verification_method: Vec<VerificationMethod> = doc
        .verification_method
        .into_iter()
        .filter_map(|vm| {
            vm.public_key_multibase.map(|mb| VerificationMethod {
                id: vm.id,
                r#type: vm.vm_type,
                controller: vm.controller,
                public_key_multibase: mb,
            })
        })
        .collect();

    if verification_method.is_empty() {
        return Err(fail(
            "resolved DID document has no publicKeyMultibase verification method".into(),
        ));
    }

    let now = Utc::now();
    // W3C DID Core: the resolved document's `id` MUST be the DID that was resolved.
    //
    // The reasoning differs from `did:web`'s. Here the endpoint is a third party that
    // answers for *every* method, so it is trusted to respond authoritatively about
    // DIDs it does not own - and this check does not change that: a hostile resolver
    // can always return its own key under the right `id`. What it catches is the
    // resolver returning the WRONG DOCUMENT - a cache keyed loosely, a batch response
    // mismatched to its request, an upstream method driver answering for a different
    // identifier - which would otherwise register a stranger's key under the DID the
    // caller asked about, silently.
    if doc.id != did {
        return Err(fail(format!(
            "resolver returned a document for '{}', not the requested DID",
            doc.id
        )));
    }

    Ok(DidDocument {
        context: context_to_vec(&doc.context),
        id: doc.id,
        verification_method,
        authentication: refs_to_vec(&doc.authentication),
        assertion_method: refs_to_vec(&doc.assertion_method),
        capability_delegation: refs_to_vec(&doc.capability_delegation),
        created: now,
        updated: now,
    })
}

fn context_to_vec(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn refs_to_vec(a: &[serde_json::Value]) -> Vec<String> {
    a.iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_in_a_did_is_rejected() {
        // The DID reaches the URL path, so path/query syntax in it must never survive.
        // These all resolve to a DIFFERENT endpoint on the resolver host if passed
        // through, which is request forgery, not DID resolution.
        let r = UniversalResolverClient::new("https://resolver.example");
        for hostile in [
            "did:web:x/../../admin",
            "did:web:x?a=b",
            "did:web:x#frag",
            "did:web:x\\..\\admin",
            "did:web:x/../",
            "did:web:host/path",
        ] {
            let err = r
                .resolve(hostile)
                .expect_err("must be refused before any request is made");
            // Assert the SPECIFIC reason. `is_err()` alone would also be satisfied by
            // the request failing to reach resolver.example, so the test would pass
            // with the gate deleted - green for the wrong reason.
            let msg = err.to_string();
            assert!(
                msg.contains("illegal character"),
                "{hostile} was rejected, but not by the character gate: {msg}"
            );
        }
    }

    #[test]
    fn legitimate_dids_still_pass_the_character_gate() {
        // Guards against the check above being vacuously strict: real DIDs use ':',
        // '.', '-', '_' and percent-encoding, and must not be rejected.
        for ok in [
            "did:web:example.com",
            "did:web:example.com%3A8443",
            "did:key:z6MkExample",
            "did:cheqd:mainnet:abc-123_x",
        ] {
            assert!(
                ok.chars().all(is_safe_did_char),
                "{ok} should pass the character gate"
            );
        }
    }

    #[test]
    fn maps_wrapped_resolution_result() {
        let json = r#"{
          "didResolutionMetadata": {},
          "didDocument": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:cheqd:mainnet:abc",
            "verificationMethod": [{
              "id": "did:cheqd:mainnet:abc#key-1",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:cheqd:mainnet:abc",
              "publicKeyMultibase": "z6MkExample"
            }],
            "authentication": ["did:cheqd:mainnet:abc#key-1"]
          }
        }"#;
        let doc = parse_resolution_result("did:cheqd:mainnet:abc", json).unwrap();
        assert_eq!(doc.id, "did:cheqd:mainnet:abc");
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            "z6MkExample"
        );
        assert_eq!(doc.authentication, vec!["did:cheqd:mainnet:abc#key-1"]);
    }

    #[test]
    fn maps_bare_document_with_string_context() {
        let json = r#"{
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "did:web:example.com",
          "verificationMethod": [{
            "id": "did:web:example.com#k",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:example.com",
            "publicKeyMultibase": "z6MkBare"
          }]
        }"#;
        let doc = parse_resolution_result("did:web:example.com", json).unwrap();
        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.context, vec!["https://www.w3.org/ns/did/v1"]);
        assert_eq!(doc.verification_method[0].public_key_multibase, "z6MkBare");
    }

    #[test]
    fn rejects_document_without_a_multibase_key() {
        let json = r##"{"didDocument":{"id":"did:x:y","verificationMethod":[
          {"id":"#k","type":"JsonWebKey2020","controller":"did:x:y","publicKeyJwk":{}}]}}"##;
        assert!(parse_resolution_result("did:x:y", json).is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_resolution_result("did:x:y", "not json").is_err());
    }

    // ========================================================================
    // The fetch path
    // ========================================================================
    //
    // Everything above tests `parse_resolution_result` - given a body, is it mapped
    // correctly - and the character gate. None of it drives `resolve`, so the HTTP
    // half was untested: status handling, the body read, and (until 2026-09-05) the
    // absence of any bound on how much a resolver endpoint could make the client
    // allocate. Same loopback-listener approach as `web.rs`, and no test-server
    // dependency for the same reason.

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn serve_once(response: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        (port, handle)
    }

    fn http_response(status_line: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status_line}\r\n{headers}\r\n\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn ok_json(body: &[u8]) -> Vec<u8> {
        http_response(
            "200 OK",
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}",
                body.len()
            ),
            body,
        )
    }

    fn resolve_against(response: Vec<u8>) -> Result<DidDocument, AgentCredsError> {
        let (port, handle) = serve_once(response);
        let client = UniversalResolverClient::new(format!("http://127.0.0.1:{port}"));
        let result = client.resolve("did:web:example.com");
        let _ = handle.join();
        result
    }

    const WRAPPED_DOC: &[u8] = br##"{"didDocument":{
        "@context":"https://www.w3.org/ns/did/v1",
        "id":"did:web:example.com",
        "verificationMethod":[{
            "id":"did:web:example.com#key-1",
            "type":"Ed25519VerificationKey2020",
            "controller":"did:web:example.com",
            "publicKeyMultibase":"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }]}}"##;

    #[test]
    fn resolves_over_http() {
        let doc = resolve_against(ok_json(WRAPPED_DOC)).expect("a valid result must resolve");
        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.verification_method.len(), 1);
    }

    #[test]
    fn rejects_non_success_status() {
        let err = resolve_against(http_response("500 Server Error", "Content-Length: 0", b""))
            .expect_err("5xx must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_invalid_json_over_http() {
        let err =
            resolve_against(ok_json(b"{ not json")).expect_err("malformed JSON must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_oversized_body_on_declared_length() {
        let response = http_response(
            "200 OK",
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}",
                MAX_DOC_BYTES + 1
            ),
            b"{}",
        );
        let err = resolve_against(response).expect_err("declared oversize must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_oversized_body_without_declared_length() {
        // REGRESSION. Before 2026-09-05 this resolver called `.text()`, which reads to
        // completion: the endpoint decided how much the client allocated, and omitting
        // Content-Length defeated any check that trusted it. This is the case the read
        // cap exists for, and the only test that reaches it.
        let body = vec![b'x'; (MAX_DOC_BYTES + 1024) as usize];
        let response = http_response("200 OK", "Content-Type: application/json", &body);
        let err = resolve_against(response).expect_err("undeclared oversize must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_non_utf8_body() {
        let response = ok_json(&[0xff, 0xfe, 0xfd]);
        let err = resolve_against(response).expect_err("non-UTF-8 must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_a_non_did_before_making_a_request() {
        // The character gate and the `did:` prefix check run before any I/O, so an
        // endpoint that does not exist is still an error about the DID, not a
        // connection failure.
        let client = UniversalResolverClient::new("http://127.0.0.1:1");
        let err = client.resolve("https://example.com").unwrap_err();
        match err {
            AgentCredsError::DidResolutionFailed { reason, .. } => {
                assert!(reason.contains("not a DID"), "unexpected reason: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn method_and_handles() {
        let client = UniversalResolverClient::new("https://resolver.example");
        assert_eq!(client.method(), "universal");
        assert!(client.handles("did:cheqd:mainnet:abc"));
        assert!(!client.handles("https://example.com"));
    }

    #[test]
    fn dif_endpoint_is_the_public_instance() {
        let _ = UniversalResolverClient::dif();
    }
}
