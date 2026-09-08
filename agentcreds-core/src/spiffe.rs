//! SPIFFE adapter - bridge a SPIRE-issued JWT-SVID to capability-credential
//! issuance.
//!
//! Enterprises with SPIFFE/SPIRE deployed already attest workload identity. This
//! adapter validates a JWT-SVID against a [`SpiffeTrustBundle`] (the trust
//! domain's public keys), extracts the [`SpiffeId`], and lets the org's
//! [`TrustAnchor`] issue a [`CapabilityCredential`] gated on that attestation -
//! no rip-and-replace of the existing identity plane.
//!
//! Supports `EdDSA` (Ed25519) and `ES256` (P-256) JWT-SVIDs, the algorithms the
//! rest of the crate already uses.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::spiffe::{SpiffeTrustBundle, issue_from_svid};
//!
//! # fn demo(svid_jwt: &str, trust_domain_pubkey: &[u8], agent_did: &str) -> Result<(), agentcreds_core::error::AgentCredsError> {
//! let mut bundle = SpiffeTrustBundle::new();
//! bundle.add_ed25519_key(Some("spire-jwt-key".into()), trust_domain_pubkey)?;
//!
//! let svid = bundle.validate_jwt_svid(svid_jwt, Some("spiffe://example.org/agentcreds"))?;
//!
//! let anchor = TrustAnchor::generate()?;
//! let vc = issue_from_svid(&anchor, agent_did, &svid, vec!["tool:search".into()], 2, 3600)?;
//! assert_eq!(vc.subject_did(), agent_did);
//! # Ok(()) }
//! ```

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};

use crate::did::TrustAnchor;
use crate::vc::{CapabilityClaims, CapabilityCredential};
use crate::{error::AgentCredsError, Result};

fn svid_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::SvidValidationFailed {
        reason: reason.into(),
    }
}

// -- SpiffeId -------------------------------------------------------------------

/// A parsed SPIFFE ID: `spiffe://<trust_domain><path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// The trust domain (authority), e.g. `example.org`.
    pub trust_domain: String,
    /// The workload path, including the leading `/` (empty if none).
    pub path: String,
}

impl SpiffeId {
    /// Parse a SPIFFE ID from its URI form.
    ///
    /// # Errors
    /// `SvidValidationFailed` if the string is not a `spiffe://` URI or has an
    /// empty trust domain.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or_else(|| svid_err(format!("not a SPIFFE ID: {s}")))?;
        let (trust_domain, path) = match rest.split_once('/') {
            Some((d, p)) => (d.to_string(), format!("/{p}")),
            None => (rest.to_string(), String::new()),
        };
        if trust_domain.is_empty() {
            return Err(svid_err("SPIFFE ID has an empty trust domain"));
        }
        Ok(SpiffeId { trust_domain, path })
    }

    /// Render back to the `spiffe://...` URI form.
    pub fn uri(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

// -- Trust bundle ----------------------------------------------------------------

enum BundleKey {
    Ed25519([u8; 32]),
    P256(Box<p256::ecdsa::VerifyingKey>),
}

struct BundleEntry {
    kid: Option<String>,
    key: BundleKey,
}

/// The set of public keys for a SPIFFE trust domain, used to validate JWT-SVIDs.
pub struct SpiffeTrustBundle {
    entries: Vec<BundleEntry>,
}

impl Default for SpiffeTrustBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiffeTrustBundle {
    /// An empty trust bundle.
    pub fn new() -> Self {
        SpiffeTrustBundle {
            entries: Vec::new(),
        }
    }

    /// Add an Ed25519 (`EdDSA`) signing key, optionally keyed by `kid`.
    ///
    /// # Errors
    /// `SvidValidationFailed` if `public_key` is not a valid 32-byte Ed25519 key.
    pub fn add_ed25519_key(&mut self, kid: Option<String>, public_key: &[u8]) -> Result<()> {
        let arr: [u8; 32] = public_key
            .try_into()
            .map_err(|_| svid_err("Ed25519 public key must be 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| svid_err(format!("invalid Ed25519 key: {e}")))?;
        self.entries.push(BundleEntry {
            kid,
            key: BundleKey::Ed25519(arr),
        });
        Ok(())
    }

    /// Add a P-256 (`ES256`) signing key from SEC1 bytes, optionally keyed by `kid`.
    ///
    /// # Errors
    /// `SvidValidationFailed` if `sec1_public_key` is not a valid P-256 point.
    pub fn add_p256_key(&mut self, kid: Option<String>, sec1_public_key: &[u8]) -> Result<()> {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_public_key)
            .map_err(|e| svid_err(format!("invalid P-256 key: {e}")))?;
        self.entries.push(BundleEntry {
            kid,
            key: BundleKey::P256(Box::new(vk)),
        });
        Ok(())
    }

    /// Validate a JWT-SVID against this bundle.
    ///
    /// Verifies the signature with a trusted key, checks `exp`, parses the
    /// `sub` SPIFFE ID, and (if `expected_audience` is given) requires it to be
    /// present in `aud`.
    ///
    /// # Errors
    /// `SvidValidationFailed` for any malformation, signature failure, expiry,
    /// or audience mismatch.
    pub fn validate_jwt_svid(
        &self,
        jwt: &str,
        expected_audience: Option<&str>,
    ) -> Result<ValidatedSvid> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(svid_err("JWT-SVID must have three dot-separated parts"));
        }
        let header = decode_json(parts[0])?;
        let payload = decode_json(parts[1])?;
        let signature = Base64UrlUnpadded::decode_vec(parts[2])
            .map_err(|e| svid_err(format!("invalid base64url signature: {e}")))?;

        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| svid_err("JWT header missing 'alg'"))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        if !self.verify_signature(alg, kid, signing_input.as_bytes(), &signature) {
            return Err(svid_err("no trusted key validated the SVID signature"));
        }

        let sub = payload
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| svid_err("JWT-SVID missing 'sub'"))?;
        let spiffe_id = SpiffeId::parse(sub)?;

        let exp = payload
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| svid_err("JWT-SVID missing numeric 'exp'"))?;
        let expires_at = Utc
            .timestamp_opt(exp, 0)
            .single()
            .ok_or_else(|| svid_err("JWT-SVID 'exp' is not a valid timestamp"))?;
        if Utc::now() >= expires_at {
            return Err(svid_err("JWT-SVID has expired"));
        }

        let audiences = extract_audiences(&payload);
        if let Some(expected) = expected_audience {
            if !audiences.iter().any(|a| a == expected) {
                return Err(svid_err(format!(
                    "JWT-SVID audience does not include '{expected}'"
                )));
            }
        }

        Ok(ValidatedSvid {
            spiffe_id,
            expires_at,
            audiences,
        })
    }

    /// Export this bundle as a JWKS (RFC 7517 JSON Web Key Set) document - the
    /// portable, IETF-standard form a SPIFFE trust domain publishes so peers can
    /// import it (WIMSE trust-bundle exchange). Ed25519 keys are `OKP`/`Ed25519`,
    /// P-256 keys are `EC`/`P-256`.
    ///
    /// # Errors
    /// JSON serialization failure.
    pub fn to_jwks(&self) -> Result<String> {
        let keys: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                let mut jwk = match &e.key {
                    BundleKey::Ed25519(pk) => json!({
                        "kty": "OKP", "crv": "Ed25519",
                        "x": Base64UrlUnpadded::encode_string(pk),
                    }),
                    BundleKey::P256(vk) => {
                        let point = vk.to_encoded_point(false);
                        let b = point.as_bytes(); // 0x04 || x(32) || y(32)
                        json!({
                            "kty": "EC", "crv": "P-256",
                            "x": Base64UrlUnpadded::encode_string(&b[1..33]),
                            "y": Base64UrlUnpadded::encode_string(&b[33..65]),
                        })
                    }
                };
                if let Some(kid) = &e.kid {
                    jwk["kid"] = json!(kid);
                }
                jwk
            })
            .collect();
        serde_json::to_string(&json!({ "keys": keys })).map_err(AgentCredsError::from)
    }

    /// Import a trust bundle from a peer's JWKS document. Unknown key types are
    /// skipped. This is the receiving side of WIMSE trust-bundle exchange.
    ///
    /// # Errors
    /// `SvidValidationFailed` if the JWKS is malformed or a key is invalid.
    pub fn from_jwks(jwks: &str) -> Result<Self> {
        let doc: Value =
            serde_json::from_str(jwks).map_err(|e| svid_err(format!("JWKS JSON: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| svid_err("JWKS missing 'keys' array"))?;
        let mut bundle = Self::new();
        for jwk in keys {
            let kid = jwk.get("kid").and_then(Value::as_str).map(str::to_string);
            match jwk.get("kty").and_then(Value::as_str) {
                Some("OKP") => {
                    let x = jwk_coord(jwk, "x")?;
                    bundle.add_ed25519_key(kid, &x)?;
                }
                Some("EC") => {
                    let x = jwk_coord(jwk, "x")?;
                    let y = jwk_coord(jwk, "y")?;
                    let mut sec1 = Vec::with_capacity(65);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x);
                    sec1.extend_from_slice(&y);
                    bundle.add_p256_key(kid, &sec1)?;
                }
                _ => continue, // skip unsupported key types
            }
        }
        Ok(bundle)
    }

    /// Try every (kid-matching) key of the right algorithm; return true on the
    /// first that verifies.
    fn verify_signature(&self, alg: &str, kid: Option<&str>, msg: &[u8], sig: &[u8]) -> bool {
        for entry in &self.entries {
            if let Some(k) = kid {
                if entry.kid.as_deref() != Some(k) {
                    continue;
                }
            }
            let ok = match (alg, &entry.key) {
                ("EdDSA", BundleKey::Ed25519(pk)) => verify_ed25519(pk, msg, sig),
                ("ES256", BundleKey::P256(vk)) => verify_es256(vk, msg, sig),
                _ => false,
            };
            if ok {
                return true;
            }
        }
        false
    }
}

fn verify_ed25519(pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify(msg, &signature).is_ok()
}

fn verify_es256(vk: &p256::ecdsa::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    // JOSE ES256 signatures are raw r||s (64 bytes), not DER.
    let Ok(signature) = p256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

fn jwk_coord(jwk: &Value, field: &str) -> Result<Vec<u8>> {
    let s = jwk
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| svid_err(format!("JWK missing '{field}'")))?;
    Base64UrlUnpadded::decode_vec(s).map_err(|e| svid_err(format!("JWK '{field}' base64url: {e}")))
}

fn decode_json(part: &str) -> Result<Value> {
    let bytes = Base64UrlUnpadded::decode_vec(part)
        .map_err(|e| svid_err(format!("invalid base64url segment: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| svid_err(format!("invalid JSON segment: {e}")))
}

fn extract_audiences(payload: &Value) -> Vec<String> {
    match payload.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

// -- Validated SVID + issuance bridge --------------------------------------------

/// A successfully validated JWT-SVID.
#[derive(Debug, Clone)]
pub struct ValidatedSvid {
    /// The workload's SPIFFE ID.
    pub spiffe_id: SpiffeId,
    /// When the SVID expires.
    pub expires_at: DateTime<Utc>,
    /// The audiences the SVID was issued for.
    pub audiences: Vec<String>,
}

/// Issue a capability credential to `agent_did`, gated on a validated SVID. The
/// SVID's SPIFFE ID is recorded as the credential's `authorized_by` provenance,
/// so the workload identity that triggered issuance is auditable.
///
/// # Errors
/// Propagates credential issuance failure.
pub fn issue_from_svid(
    anchor: &TrustAnchor,
    agent_did: &str,
    svid: &ValidatedSvid,
    tools: Vec<String>,
    max_delegation_depth: u32,
    valid_for_secs: u64,
) -> Result<CapabilityCredential> {
    let mut claims = CapabilityClaims::new(tools, max_delegation_depth, valid_for_secs);
    claims.authorized_by = Some(svid.spiffe_id.uri());
    CapabilityCredential::issue(anchor, agent_did, claims, None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;

    const TD: &str = "example.org";
    const SUB: &str = "spiffe://example.org/workload/web";
    const AUD: &str = "spiffe://example.org/agentcreds";

    fn b64(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    /// Build an Ed25519 JWT-SVID and return (jwt, public_key_bytes).
    fn ed25519_svid(exp: i64, aud: Value) -> (String, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let header =
            b64(&serde_json::to_vec(&json!({"alg":"EdDSA","typ":"JWT","kid":"k1"})).unwrap());
        let payload =
            b64(&serde_json::to_vec(&json!({"sub": SUB, "exp": exp, "aud": aud})).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));
        (jwt, pk)
    }

    /// Build a P-256 JWT-SVID and return (jwt, sec1_public_key_bytes).
    fn es256_svid(exp: i64) -> (String, Vec<u8>) {
        let sk = P256SigningKey::random(&mut OsRng);
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let header = b64(&serde_json::to_vec(&json!({"alg":"ES256","typ":"JWT"})).unwrap());
        let payload =
            b64(&serde_json::to_vec(&json!({"sub": SUB, "exp": exp, "aud": AUD})).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));
        (jwt, pk)
    }

    fn future() -> i64 {
        (Utc::now() + Duration::hours(1)).timestamp()
    }

    #[test]
    fn spiffe_id_parses() {
        let id = SpiffeId::parse(SUB).unwrap();
        assert_eq!(id.trust_domain, TD);
        assert_eq!(id.path, "/workload/web");
        assert_eq!(id.uri(), SUB);
        assert!(SpiffeId::parse("https://example.org/x").is_err());
    }

    #[test]
    fn valid_ed25519_svid_validates() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let svid = bundle.validate_jwt_svid(&jwt, Some(AUD)).unwrap();
        assert_eq!(svid.spiffe_id.uri(), SUB);
        assert!(svid.audiences.contains(&AUD.to_string()));
    }

    #[test]
    fn valid_es256_svid_validates() {
        let (jwt, pk) = es256_svid(future());
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_p256_key(None, &pk).unwrap();
        let svid = bundle.validate_jwt_svid(&jwt, Some(AUD)).unwrap();
        assert_eq!(svid.spiffe_id.trust_domain, TD);
    }

    #[test]
    fn array_audience_supported() {
        let (jwt, pk) = ed25519_svid(future(), json!(["spiffe://other", AUD]));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        assert!(bundle.validate_jwt_svid(&jwt, Some(AUD)).is_ok());
    }

    #[test]
    fn expired_svid_rejected() {
        let (jwt, pk) = ed25519_svid((Utc::now() - Duration::hours(1)).timestamp(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        assert!(bundle.validate_jwt_svid(&jwt, Some(AUD)).is_err());
    }

    #[test]
    fn wrong_audience_rejected() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        assert!(bundle
            .validate_jwt_svid(&jwt, Some("spiffe://example.org/other"))
            .is_err());
    }

    #[test]
    fn untrusted_key_rejected() {
        let (jwt, _pk) = ed25519_svid(future(), json!(AUD));
        // Bundle holds a *different* key.
        let (_other_jwt, other_pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle
            .add_ed25519_key(Some("k1".into()), &other_pk)
            .unwrap();
        assert!(bundle.validate_jwt_svid(&jwt, Some(AUD)).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        // Flip the FIRST character of the signature segment, not the last: the final
        // base64url char of an Ed25519 signature carries 2 padding bits base64ct
        // requires to be zero, so a last-char flip lands on a non-canonical encoding
        // ~1/16 of the time and is rejected by the DECODER - never reaching signature
        // verification, which is what this test exists to pin. (The sd_jwt twin of
        // this pattern let a stubbed verifier survive a CI mutation run on exactly
        // that roll.)
        let sig_start = jwt.rfind('.').unwrap() + 1;
        let mut chars: Vec<char> = jwt.chars().collect();
        chars[sig_start] = if chars[sig_start] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        let err = bundle.validate_jwt_svid(&tampered, Some(AUD)).unwrap_err();
        assert!(
            !err.to_string().contains("base64"),
            "must be rejected by signature verification, not the decoder: {err}"
        );
    }

    #[test]
    fn issue_from_svid_records_provenance_and_verifies() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let svid = bundle.validate_jwt_svid(&jwt, Some(AUD)).unwrap();

        let anchor = TrustAnchor::generate().unwrap();
        let agent = crate::did::AgentIdentity::create(crate::did::DidMethod::Key, None).unwrap();
        let vc = issue_from_svid(
            &anchor,
            agent.did(),
            &svid,
            vec!["tool:search".into()],
            2,
            3600,
        )
        .unwrap();

        assert_eq!(vc.subject_did(), agent.did());
        assert_eq!(vc.claims().authorized_by.as_deref(), Some(SUB));
        // The issued credential verifies against the issuing anchor.
        assert!(vc.verify(&anchor, true).is_ok());
    }

    // -- Malformed input ----------------------------------------------------
    //
    // A JWT-SVID comes from the workload being admitted, and a JWKS comes from a peer
    // trust domain during bundle exchange. Both are untrusted bytes. The tests above
    // start from well-formed artifacts and vary the *semantics* (wrong key, wrong
    // audience, expired); these vary the *shape*.

    #[test]
    fn svid_with_wrong_segment_count_rejected() {
        let bundle = SpiffeTrustBundle::new();
        for bad in ["", "a", "a.b", "a.b.c.d", "..", "a.b."] {
            assert!(
                bundle.validate_jwt_svid(bad, None).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn svid_with_undecodable_segments_rejected() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();

        // Signature that is not base64url at all.
        let bad_sig = format!("{}.{}.{}", parts[0], parts[1], "!!!not-base64!!!");
        assert!(bundle.validate_jwt_svid(&bad_sig, None).is_err());

        // Header that is valid base64url but not JSON.
        let bad_header = format!("{}.{}.{}", b64(b"not json"), parts[1], parts[2]);
        assert!(bundle.validate_jwt_svid(&bad_header, None).is_err());

        // Payload that is valid base64url but not JSON.
        let bad_payload = format!("{}.{}.{}", parts[0], b64(b"not json"), parts[2]);
        assert!(bundle.validate_jwt_svid(&bad_payload, None).is_err());
    }

    #[test]
    fn svid_without_alg_rejected() {
        // `alg` selects the verification routine. A header without one must fail
        // closed rather than fall back to a default.
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let header = b64(&serde_json::to_vec(&json!({"typ": "JWT"})).unwrap());
        let no_alg = format!("{}.{}.{}", header, parts[1], parts[2]);
        assert!(bundle.validate_jwt_svid(&no_alg, None).is_err());
    }

    #[test]
    fn empty_bundle_validates_nothing() {
        // A bundle with no keys must reject a structurally perfect, correctly signed
        // SVID - there is no trusted key, so there is no basis to accept it.
        let (jwt, _pk) = ed25519_svid(future(), json!(AUD));
        assert!(SpiffeTrustBundle::new()
            .validate_jwt_svid(&jwt, Some(AUD))
            .is_err());
    }

    #[test]
    fn jwks_import_rejects_malformed_documents() {
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"keys": {}}"#,
            r#"{"keys": "not-an-array"}"#,
        ] {
            assert!(
                SpiffeTrustBundle::from_jwks(bad).is_err(),
                "{bad:?} should be rejected as a JWKS"
            );
        }
    }

    #[test]
    fn jwks_import_skips_unknown_key_types() {
        // Documented behaviour: unknown key types are skipped, not fatal - a peer may
        // legitimately publish RSA keys this implementation does not verify with. The
        // result is an empty bundle, which then validates nothing (see above), so
        // skipping cannot silently widen what is accepted.
        let jwks = r#"{"keys":[{"kty":"RSA","kid":"r1","n":"abc","e":"AQAB"}]}"#;
        let bundle = SpiffeTrustBundle::from_jwks(jwks).unwrap();
        let (jwt, _pk) = ed25519_svid(future(), json!(AUD));
        assert!(bundle.validate_jwt_svid(&jwt, Some(AUD)).is_err());
    }

    #[test]
    fn jwks_round_trips_through_export_and_import() {
        let (jwt, pk) = ed25519_svid(future(), json!(AUD));
        let mut bundle = SpiffeTrustBundle::new();
        bundle.add_ed25519_key(Some("k1".into()), &pk).unwrap();
        let jwks = bundle.to_jwks().unwrap();
        let reimported = SpiffeTrustBundle::from_jwks(&jwks).unwrap();
        assert!(reimported.validate_jwt_svid(&jwt, Some(AUD)).is_ok());
    }
}
