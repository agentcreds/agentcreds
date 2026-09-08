//! `did:web` resolution over HTTPS, with SSRF protection (the fetch target derives
//! from an untrusted DID).

#[cfg(feature = "resolver-web")]
use agentcreds_core::{
    did::{resolver::DidResolver, DidDocument},
    error::AgentCredsError,
};
#[cfg(feature = "resolver-web")]
use reqwest::blocking::Client;
#[cfg(feature = "resolver-web")]
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(feature = "resolver-web")]
use std::time::Duration;

/// Wall-clock ceiling on a single `did:web` fetch, and on establishing its connection.
/// Resolution can sit on a request path, and `reqwest` applies **no timeout by
/// default**, so without this a host that accepts the connection and then never
/// responds parks the calling thread indefinitely.
#[cfg(feature = "resolver-web")]
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "resolver-web")]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on a DID document body. A conforming `did:web` document is a few KiB; this
/// is generous by orders of magnitude while still bounding what an untrusted host can
/// make the resolver allocate. Without it, `.json()` reads the body to completion and
/// the host chooses how large that is.
#[cfg(feature = "resolver-web")]
const MAX_DOC_BYTES: u64 = 1024 * 1024;

#[cfg(feature = "resolver-web")]
/// HTTP-based resolver for `did:web`.
///
/// The fetch target is derived from the (untrusted) DID, so this is an SSRF
/// surface: a relying party resolves a DID *before* deciding whether to trust it.
/// By default the resolver requires `https`, resolves the host, **rejects any
/// non-public address** (loopback, RFC 1918, link-local/metadata, ULA), and pins
/// the connection to the validated address (defeating DNS rebinding).
#[derive(Default)]
pub struct WebResolver {
    allow_private: bool,
}

#[cfg(feature = "resolver-web")]
impl WebResolver {
    /// A production-safe web resolver (rejects private/loopback fetch targets).
    pub fn new() -> Self {
        WebResolver::default()
    }

    /// Allow resolving to private/loopback addresses (and `http`/explicit ports for
    /// loopback). **For local testing only** - this re-opens the SSRF surface and
    /// must never be enabled in production.
    #[must_use]
    pub fn allow_private_addresses(mut self) -> Self {
        self.allow_private = true;
        self
    }
}

#[cfg(feature = "resolver-web")]
impl DidResolver for WebResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        let url = did_web_to_url(did, self.allow_private)?;
        let fail = |reason: String| AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason,
        };
        let client = if self.allow_private {
            // Test-only path: no address validation (that is the point), but still
            // bounded in time - a hung local fixture should fail a test, not wedge it.
            Client::builder()
                .timeout(FETCH_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .map_err(|e| fail(format!("HTTP client build failed: {e}")))?
        } else {
            // Validate where the host resolves and pin the connection to it.
            pinned_client(&url, did)?
        };

        let response = client
            .get(&url)
            .send()
            .map_err(|e| fail(format!("HTTP request failed: {e}")))?
            .error_for_status()
            .map_err(|e| fail(format!("HTTP response error: {e}")))?;

        // Reject an oversized document on its declared length where the host provides
        // one, so the obvious case costs nothing to detect...
        if let Some(len) = response.content_length() {
            if len > MAX_DOC_BYTES {
                return Err(fail(format!(
                    "DID document too large: {len} bytes exceeds the {MAX_DOC_BYTES} byte limit"
                )));
            }
        }
        // ...but Content-Length is attacker-supplied and optional, so the read itself
        // is what actually bounds memory. `take` caps the bytes pulled off the socket;
        // a body that hits the cap is over the limit and fails to parse regardless.
        use std::io::Read as _;
        let mut body = Vec::new();
        response
            .take(MAX_DOC_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| fail(format!("failed to read response body: {e}")))?;
        if body.len() as u64 > MAX_DOC_BYTES {
            return Err(fail(format!(
                "DID document too large: exceeds the {MAX_DOC_BYTES} byte limit"
            )));
        }

        let document: DidDocument = serde_json::from_slice(&body)
            .map_err(|e| fail(format!("failed to parse DID document JSON: {e}")))?;

        // W3C DID Core: a resolved document's `id` MUST be the DID that was resolved.
        // For `did:web` the host IS the authority for its own DID, so a mismatch means
        // the host is misconfigured or answering for an identifier it was not asked
        // about - a wildcard vhost, a CDN serving another tenant's cached `did.json`, a
        // copy-pasted document.
        //
        // Scope of what this fixes, stated honestly: it is NOT a key-substitution
        // defence. Both callers (`TrustRegistry::resolve` and
        // `verify_delegation_attestation`) key the result by the DID they *asked for*
        // and take the key from `verification_method`, so a mismatched `id` never
        // decided which key was trusted. What it did do was flow into
        // `TrustEntry::org_name`, putting an attacker- or stranger-chosen string in
        // front of every operator who reads a registry entry, and mask the
        // misconfigurations above by resolving successfully.
        if document.id != did {
            return Err(fail(format!(
                "DID document is for '{}', not the requested DID",
                document.id
            )));
        }
        Ok(document)
    }

    fn method(&self) -> &str {
        "web"
    }
}

#[cfg(feature = "resolver-web")]
fn did_web_to_url(did: &str, allow_private: bool) -> Result<String, AgentCredsError> {
    let suffix =
        did.strip_prefix("did:web:")
            .ok_or_else(|| AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "invalid did:web format".into(),
            })?;

    let mut parts = suffix.split(':').collect::<Vec<_>>();
    let host = parts.remove(0);
    if host.is_empty() {
        return Err(AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "did:web has no host".into(),
        });
    }
    let loopback = host == "localhost" || host == "127.0.0.1";

    // Local-testing convenience (only when private targets are allowed):
    // `did:web:127.0.0.1:<port>` resolves to that port over http.
    if allow_private && loopback && parts.len() == 1 && parts[0].bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(format!("http://{host}:{}/.well-known/did.json", parts[0]));
    }

    let path = if parts.is_empty() {
        String::from(".well-known/did.json")
    } else {
        format!("{}/did.json", parts.join("/"))
    };
    // Always https in the secure (production) path - no http shortcut for loopback
    // (which is blocked anyway).
    let scheme = if allow_private && loopback {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{host}/{path}"))
}

#[cfg(feature = "resolver-web")]
/// Build an HTTP client pinned to a validated public address for `url`, rejecting
/// non-https URLs and any host that resolves to a private/loopback/metadata address.
fn pinned_client(url: &str, did: &str) -> Result<Client, AgentCredsError> {
    let fail = |reason: String| AgentCredsError::DidResolutionFailed {
        did: did.to_string(),
        reason,
    };
    let parsed = reqwest::Url::parse(url).map_err(|e| fail(format!("invalid url: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(fail("did:web must resolve over https".into()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| fail("url has no host".into()))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let addrs: Vec<SocketAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| fail(format!("DNS resolution failed: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(fail("host did not resolve".into()));
    }
    for addr in &addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(fail(format!(
                "host resolves to a blocked (non-public) address: {}",
                addr.ip()
            )));
        }
    }
    Client::builder()
        .resolve(&host, addrs[0])
        // NO REDIRECTS. This is load-bearing, not tidiness. Everything above validates
        // and pins ONE host: `.resolve()` overrides DNS for `host` alone, and
        // `is_blocked_ip` ran against that host's addresses only. `reqwest` follows up
        // to 10 redirects by default, and a redirect to a DIFFERENT host is resolved
        // normally - unpinned, unchecked, and not even re-checked for the https
        // requirement. That hands the whole SSRF control back: a did:web host the
        // attacker legitimately controls answers 302 to http://169.254.169.254/ (cloud
        // instance metadata) or to an internal address, and the resolver follows it.
        //
        // did:web has no need of redirects - the URL is derived deterministically from
        // the DID - so refusing them costs nothing. If they are ever required, the fix
        // is to re-run the full validate-and-pin on every hop, NOT to raise this limit.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| fail(format!("HTTP client build failed: {e}")))
}

#[cfg(feature = "resolver-web")]
/// Whether `ip` is non-public (loopback, private, link-local, ULA, multicast,
/// unspecified, CGNAT, reserved) and must not be the target of a `did:web` fetch.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        }
    }
}

#[cfg(all(test, feature = "resolver-web"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_loopback_and_metadata_ips() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "0.0.0.0",
            "100.64.0.1",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in ["::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                !is_blocked_ip(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn secure_mode_uses_https_and_pins_to_public_ips() {
        // No http shortcut for loopback in the secure (default) path.
        assert!(did_web_to_url("did:web:example.com", false)
            .unwrap()
            .starts_with("https://"));
        assert!(did_web_to_url("did:web:localhost", false)
            .unwrap()
            .starts_with("https://"));

        // Internal/metadata targets are rejected (IP-literal hosts -> no DNS).
        assert!(pinned_client("https://169.254.169.254/.well-known/did.json", "d").is_err());
        assert!(pinned_client("https://127.0.0.1/.well-known/did.json", "d").is_err());
        // Non-https is rejected outright.
        assert!(pinned_client("http://example.com/x", "d").is_err());
    }

    #[test]
    fn allow_private_enables_loopback_http_with_port() {
        let url = did_web_to_url("did:web:127.0.0.1:8443", true).unwrap();
        assert_eq!(url, "http://127.0.0.1:8443/.well-known/did.json");
    }

    // ========================================================================
    // The fetch-and-parse path
    // ========================================================================
    //
    // The tests above cover the SSRF guards - which addresses are blocked, which
    // URL a DID maps to. They do not cover `resolve` itself, so the guarded thing
    // was untested while its guards were not: what happens once an untrusted host
    // answers. These fixtures serve canned responses from a loopback listener and
    // drive the real resolver against them.
    //
    // A hand-rolled listener rather than a mock-HTTP crate, deliberately: this is
    // an SDK whose dependency surface is a selling point, and a test-only web
    // server would be a dependency a consumer still has to audit. Two dozen lines
    // of `std::net` cost less than that conversation.

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

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

    fn valid_document(did: &str) -> String {
        format!(
            r#"{{
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "{did}",
                "verificationMethod": [{{
                    "id": "{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "{did}",
                    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }}],
                "authentication": [],
                "assertionMethod": [],
                "capabilityDelegation": [],
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z"
            }}"#
        )
    }

    fn resolve_against(response: Vec<u8>) -> Result<DidDocument, AgentCredsError> {
        resolve_with(|_did| response)
    }

    /// Serve a response built from the DID the resolver will actually request.
    ///
    /// The listener binds an ephemeral port, so the DID is not known until then - and
    /// since `resolve` now requires the document's `id` to equal the requested DID, a
    /// fixture that wants to succeed has to be built after the port is chosen rather
    /// than hard-coded.
    fn resolve_with(
        make_response: impl FnOnce(&str) -> Vec<u8>,
    ) -> Result<DidDocument, AgentCredsError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        let did = format!("did:web:127.0.0.1:{port}");
        let response = make_response(&did);
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        let result = WebResolver::new().allow_private_addresses().resolve(&did);
        let _ = handle.join();
        result
    }

    #[test]
    fn resolves_a_well_formed_document() {
        let doc = resolve_with(|did| ok_json(valid_document(did).as_bytes()))
            .expect("a well-formed document should resolve");
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].r#type,
            "Ed25519VerificationKey2020"
        );
    }

    #[test]
    fn rejects_non_success_status() {
        let err = resolve_against(http_response("404 Not Found", "Content-Length: 0", b""))
            .expect_err("404 must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = resolve_against(ok_json(b"{ this is not json"))
            .expect_err("malformed JSON must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_empty_body() {
        let err = resolve_against(ok_json(b"")).expect_err("an empty body must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_json_that_is_not_a_did_document() {
        // Valid JSON, wrong shape - the parse must fail on the type, not merely on
        // syntax, or a host could return `[]` and be treated as a resolution.
        let err = resolve_against(ok_json(br#"{"unrelated": true}"#))
            .expect_err("a non-document must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_oversized_body_on_declared_length() {
        // An honest Content-Length above the cap is refused before the body is read.
        let body = vec![b'x'; 16];
        let response = http_response(
            "200 OK",
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}",
                MAX_DOC_BYTES + 1
            ),
            &body,
        );
        let err = resolve_against(response).expect_err("declared oversize must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn rejects_oversized_body_without_declared_length() {
        // The case that matters: Content-Length is attacker-supplied and optional, so
        // a host can simply omit it and stream. The read cap is what actually bounds
        // memory here, and this is the only test that exercises it - with a declared
        // length the request never reaches the read at all.
        let body = vec![b'x'; (MAX_DOC_BYTES + 1024) as usize];
        let response = http_response("200 OK", "Content-Type: application/json", &body);
        let err = resolve_against(response).expect_err("undeclared oversize must not resolve");
        assert!(matches!(err, AgentCredsError::DidResolutionFailed { .. }));
    }

    #[test]
    fn document_id_mismatch_is_rejected() {
        // A host serving `did:web:127.0.0.1:<port>` returns a document claiming to be an
        // entirely different DID. Previously this resolved successfully; the mismatch is
        // now refused, per W3C DID Core's requirement that a resolved document's `id` be
        // the DID that was resolved.
        //
        // What this does and does not fix is recorded on the check itself in `resolve`:
        // it never governed which key was trusted, but it did let a stranger's
        // identifier reach `TrustEntry::org_name`, and it masked host misconfiguration
        // by succeeding.
        let err = resolve_against(ok_json(
            valid_document("did:web:someone-else.example.com").as_bytes(),
        ))
        .expect_err("a document for a different DID must not resolve");
        match err {
            AgentCredsError::DidResolutionFailed { reason, .. } => assert!(
                reason.contains("someone-else.example.com"),
                "the error should name the DID actually served: {reason}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parses_the_w3c_field_spelling() {
        // REGRESSION. `DidDocument`'s fields are snake_case and had no camelCase
        // mapping, so this resolver - which deserialises straight into it - rejected
        // every W3C-conforming did:web document with "missing field
        // `verification_method`". `UniversalResolver` was unaffected because it maps
        // through its own camelCase DTO first, which is why the inconsistency survived.
        //
        // It survived for as long as it did because `resolve` had no test that fed it a
        // realistic document: the existing tests covered URL construction and the IP
        // blocklist, so nothing ever parsed a document that a real host would serve.
        let doc = resolve_with(|did| {
            ok_json(
                format!(
                    r#"{{
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "{did}",
                "verificationMethod": [{{
                    "id": "{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "{did}",
                    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }}],
                "authentication": ["{did}#key-1"],
                "assertionMethod": ["{did}#key-1"],
                "capabilityDelegation": ["{did}#key-1"],
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z"
            }}"#
                )
                .as_bytes(),
            )
        })
        .expect("a W3C-conforming document must resolve");

        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.capability_delegation.len(), 1);
    }

    #[test]
    fn still_parses_the_internal_field_spelling() {
        // The fix is a serde `alias`, not a `rename`, so the spelling this type emits
        // must keep deserialising. A document produced by this SDK and served back to
        // it has to round-trip, or the fix would trade one interop break for another.
        let doc = resolve_with(|did| {
            ok_json(
                format!(
                    r#"{{
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "{did}",
                "verification_method": [{{
                    "id": "{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "{did}",
                    "public_key_multibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }}],
                "authentication": [],
                "assertion_method": [],
                "capability_delegation": [],
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z"
            }}"#
                )
                .as_bytes(),
            )
        })
        .expect("the emitted spelling must still resolve");
        assert_eq!(doc.verification_method.len(), 1);
    }

    #[test]
    fn method_is_web() {
        assert_eq!(WebResolver::new().method(), "web");
    }
}
