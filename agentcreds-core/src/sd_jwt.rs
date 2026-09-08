//! SD-JWT selective disclosure for capability credentials.
//!
//! Lets an agent present *"I hold a valid capability from Org A"* while
//! revealing only the claims it chooses - internal structure (budget, the human
//! who authorized it, model version, even other tools) stays hidden, and a
//! hidden claim is cryptographically unrecoverable from the presentation.
//!
//! Mechanism (IETF SD-JWT): the issuer signs a JWT whose selectively-disclosable
//! claims are replaced by salted SHA-256 digests in an `_sd` array. For each
//! such claim it emits a *disclosure* - `base64url(json([salt, name, value]))`.
//! The compact form is `<jwt>~<disclosure>~...~`. The holder presents only the
//! disclosures it wants; the verifier checks each presented disclosure's digest
//! is in `_sd`. Undisclosed claims leave only a salted digest behind.
//!
//! Registered claims (`iss`, `sub`, `iat`, `exp`, `vct`) are always disclosed.
//! Both Ed25519 (`EdDSA`) and P-256 (`ES256`) anchors are supported.
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::sd_jwt::{SdJwt, verify_presentation};
//!
//! let anchor = TrustAnchor::generate()?;
//! let agent  = AgentIdentity::create(DidMethod::Key, None)?;
//! let mut claims = CapabilityClaims::new(vec!["tool:search".into(), "tool:email".into()], 1, 3600);
//! claims.budget_usd = Some(500);
//! claims.authorized_by = Some("did:key:zSecretBoss".into());
//!
//! // Issuer issues a selectively-disclosable credential.
//! let sd = SdJwt::from_capability(&anchor, agent.did(), &claims, 3600)?;
//!
//! // Holder presents ONLY the tool list - budget and authorizer stay hidden.
//! let presentation = sd.present(&["tools"])?;
//!
//! // Verifier confirms issuer + the disclosed claim; hidden claims are absent.
//! let disclosed = verify_presentation(&presentation, &anchor)?;
//! assert_eq!(disclosed.issuer, anchor.did());
//! assert!(disclosed.disclosed.contains_key("tools"));
//! assert!(!disclosed.disclosed.contains_key("budget_usd"));
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, TimeZone, Utc};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::did::{KeyAlgorithm, TrustAnchor};
use crate::vc::CapabilityClaims;
use crate::{error::AgentCredsError, Result};

/// The `vct` (verifiable credential type) for AgentCreds capability SD-JWTs.
pub const VCT: &str = "AgentCredsCapability";

fn sd_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::InvalidVcProof {
        reason: reason.into(),
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// `base64url(sha256(disclosure))` - the digest that goes in `_sd`.
fn digest_of(disclosure: &str) -> String {
    let mut h = Sha256::new();
    h.update(disclosure.as_bytes());
    b64(&h.finalize())
}

/// Build a disclosure string for one claim: `base64url(json([salt, name, value]))`.
fn make_disclosure(name: &str, value: &Value) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let arr = json!([b64(&salt), name, value]);
    let bytes = serde_json::to_vec(&arr)?;
    Ok(b64(&bytes))
}

// -- JOSE signing / verification over the anchor's key --------------------------

/// Sign `signing_input` with `anchor`, returning `(alg, jose_signature_bytes)`.
fn jose_sign(anchor: &TrustAnchor, signing_input: &[u8]) -> Result<(&'static str, Vec<u8>)> {
    match anchor.algorithm() {
        // Ed25519 signatures are already raw 64 bytes = JOSE EdDSA.
        KeyAlgorithm::Ed25519 => Ok(("EdDSA", anchor.sign(signing_input)?)),
        // The anchor produces DER for P-256; JOSE ES256 wants raw r||s.
        KeyAlgorithm::P256 => {
            let der = anchor.sign(signing_input)?;
            let sig = p256::ecdsa::Signature::from_der(&der)
                .map_err(|e| sd_err(format!("P-256 signature encoding: {e}")))?;
            Ok(("ES256", sig.to_bytes().to_vec()))
        }
    }
}

/// Verify a JOSE `signature` (for `alg`) over `signing_input` against `anchor`.
fn jose_verify(
    anchor: &TrustAnchor,
    alg: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    let pk = anchor.public_key();
    match (alg, pk.algorithm) {
        ("EdDSA", KeyAlgorithm::Ed25519) => pk.verify(signing_input, signature),
        ("ES256", KeyAlgorithm::P256) => {
            use p256::ecdsa::signature::Verifier;
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|e| sd_err(format!("P-256 signature: {e}")))?;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.bytes)
                .map_err(|e| sd_err(format!("P-256 key: {e}")))?;
            vk.verify(signing_input, &sig)
                .map_err(|e| sd_err(format!("signature does not verify: {e}")))
        }
        _ => Err(sd_err(format!(
            "alg '{alg}' does not match the anchor key algorithm {:?}",
            pk.algorithm
        ))),
    }
}

// -- SdJwt ----------------------------------------------------------------------

/// An issued SD-JWT in compact form (`<jwt>~<disclosure>~...~`). The issuer hands
/// the whole thing to the holder; the holder calls [`SdJwt::present`] to reveal
/// a subset.
#[derive(Debug, Clone)]
pub struct SdJwt {
    jwt: String,
    disclosures: Vec<String>,
}

impl SdJwt {
    /// Issue an SD-JWT with arbitrary selectively-disclosable `claims`.
    ///
    /// `iss`/`sub`/`iat`/`exp`/`vct` are always disclosed; everything in
    /// `claims` is individually disclosable by the holder.
    ///
    /// # Errors
    /// `InvalidVcProof` on a signing/encoding failure.
    pub fn issue(
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: BTreeMap<String, Value>,
        valid_for_secs: u64,
    ) -> Result<Self> {
        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(valid_for_secs as i64);

        // One disclosure per disclosable claim; collect digests for `_sd`.
        let mut disclosures = Vec::with_capacity(claims.len());
        let mut sd_digests = Vec::with_capacity(claims.len());
        for (name, value) in &claims {
            let disclosure = make_disclosure(name, value)?;
            sd_digests.push(digest_of(&disclosure));
            disclosures.push(disclosure);
        }
        // Sort digests so `_sd` order does not leak claim order.
        sd_digests.sort_unstable();

        let payload = json!({
            "iss": anchor.did(),
            "sub": subject_did,
            "iat": now.timestamp(),
            "exp": exp.timestamp(),
            "vct": VCT,
            "_sd_alg": "sha-256",
            "_sd": sd_digests,
        });
        let payload_b64 = b64(&serde_json::to_vec(&payload)?);

        // Header carries the alg; sign `header.payload`.
        let alg_payload = b64(&serde_json::to_vec(&json!({
            "alg": "placeholder", "typ": "sd+jwt", "kid": format!("{}#key-1", anchor.did()),
        }))?);
        // We need the real alg before encoding the header - sign first to learn it.
        let probe_input = format!("{alg_payload}.{payload_b64}");
        let (alg, _) = jose_sign(anchor, probe_input.as_bytes())?;

        let header_b64 = b64(&serde_json::to_vec(&json!({
            "alg": alg, "typ": "sd+jwt", "kid": format!("{}#key-1", anchor.did()),
        }))?);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let (_, sig) = jose_sign(anchor, signing_input.as_bytes())?;
        let jwt = format!("{signing_input}.{}", b64(&sig));

        Ok(SdJwt { jwt, disclosures })
    }

    /// Issue an SD-JWT whose disclosable claims are the fields of a
    /// [`CapabilityClaims`] (tools, budget, depth, autonomy, and the optional
    /// model/artifact/authorizer fields when present).
    ///
    /// # Errors
    /// As [`SdJwt::issue`].
    pub fn from_capability(
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: &CapabilityClaims,
        valid_for_secs: u64,
    ) -> Result<Self> {
        let mut map: BTreeMap<String, Value> = BTreeMap::new();
        map.insert("tools".into(), json!(claims.tools));
        map.insert(
            "max_delegation_depth".into(),
            json!(claims.max_delegation_depth),
        );
        map.insert("autonomy_level".into(), json!(claims.autonomy_level));
        if let Some(b) = claims.budget_usd {
            map.insert("budget_usd".into(), json!(b));
        }
        if let Some(m) = &claims.model_version {
            map.insert("model_version".into(), json!(m));
        }
        if let Some(a) = &claims.artifact_hash {
            map.insert("artifact_hash".into(), json!(a));
        }
        if let Some(a) = &claims.authorized_by {
            map.insert("authorized_by".into(), json!(a));
        }
        Self::issue(anchor, subject_did, map, valid_for_secs)
    }

    /// The full compact serialization the issuer hands to the holder.
    pub fn as_str(&self) -> String {
        let mut s = self.jwt.clone();
        s.push('~');
        for d in &self.disclosures {
            s.push_str(d);
            s.push('~');
        }
        s
    }

    /// Parse a compact SD-JWT (e.g. one received from an issuer).
    ///
    /// # Errors
    /// `InvalidVcProof` if the form is malformed.
    pub fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split('~');
        let jwt = parts
            .next()
            .filter(|j| j.matches('.').count() == 2)
            .ok_or_else(|| sd_err("malformed SD-JWT: missing JWT"))?
            .to_string();
        let disclosures = parts
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        Ok(SdJwt { jwt, disclosures })
    }

    /// The names of the claims this SD-JWT can disclose.
    ///
    /// # Errors
    /// `InvalidVcProof` if a stored disclosure is malformed.
    pub fn disclosable_claims(&self) -> Result<Vec<String>> {
        self.disclosures
            .iter()
            .map(|d| disclosure_name(d))
            .collect()
    }

    /// Holder side: produce a presentation revealing only the named claims
    /// (plus the always-disclosed registered claims). Unknown names are ignored.
    ///
    /// # Errors
    /// `InvalidVcProof` if a stored disclosure is malformed.
    pub fn present(&self, disclose: &[&str]) -> Result<String> {
        let mut s = self.jwt.clone();
        s.push('~');
        for d in &self.disclosures {
            if disclose.contains(&disclosure_name(d)?.as_str()) {
                s.push_str(d);
                s.push('~');
            }
        }
        Ok(s)
    }
}

/// Extract the claim name (second element) from a disclosure.
fn disclosure_name(disclosure: &str) -> Result<String> {
    let arr = decode_disclosure(disclosure)?;
    arr.get(1)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| sd_err("disclosure missing claim name"))
}

fn decode_disclosure(disclosure: &str) -> Result<Vec<Value>> {
    let bytes = Base64UrlUnpadded::decode_vec(disclosure)
        .map_err(|e| sd_err(format!("disclosure base64url: {e}")))?;
    let arr: Vec<Value> =
        serde_json::from_slice(&bytes).map_err(|e| sd_err(format!("disclosure JSON: {e}")))?;
    if arr.len() != 3 {
        return Err(sd_err("disclosure must be [salt, name, value]"));
    }
    Ok(arr)
}

// -- Verification ----------------------------------------------------------------

/// The result of verifying an SD-JWT presentation: the always-present registered
/// claims plus exactly the claims the holder chose to disclose.
#[derive(Debug, Clone)]
pub struct DisclosedCredential {
    /// Issuer DID (`iss`).
    pub issuer: String,
    /// Subject DID (`sub`).
    pub subject: String,
    /// Issuance time (`iat`).
    pub issued_at: DateTime<Utc>,
    /// Expiry (`exp`).
    pub expires_at: DateTime<Utc>,
    /// Credential type (`vct`).
    pub vct: String,
    /// The claims the holder disclosed (name -> value).
    pub disclosed: BTreeMap<String, Value>,
}

/// Verifier side: verify a presentation against the issuer `anchor`.
///
/// Checks the issuer signature, expiry, and that every presented disclosure's
/// digest is in the signed `_sd` array. Returns the disclosed claims; any claim
/// the holder withheld is simply absent (and unrecoverable).
///
/// # Errors
/// `InvalidVcProof` for a bad signature, malformed input, or a disclosure whose
/// digest is not in `_sd`; `CredentialExpired` if past `exp`.
pub fn verify_presentation(
    presentation: &str,
    anchor: &TrustAnchor,
) -> Result<DisclosedCredential> {
    verify_presentation_at(presentation, anchor, Utc::now())
}

/// [`verify_presentation`] judged **as of** `now` rather than the wall clock.
///
/// The seam exists for audit re-verification and for tests that need the expiry
/// boundary pinned to an exact instant - the same pattern as
/// [`DelegationToken::verify_at`](crate::delegation::DelegationToken::verify_at) and
/// `verify_anchor_signed`. Its addition retired the last clock-boundary
/// accepted-equivalent mutant (368:19): "no seam exists" stopped being true here the
/// same way it stopped being true for the other two.
///
/// # Errors
/// As [`verify_presentation`].
pub fn verify_presentation_at(
    presentation: &str,
    anchor: &TrustAnchor,
    now: DateTime<Utc>,
) -> Result<DisclosedCredential> {
    let mut parts = presentation.split('~');
    let jwt = parts.next().ok_or_else(|| sd_err("empty presentation"))?;
    let presented: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();

    // 1. Verify the issuer-signed JWT.
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(sd_err("JWT must have three parts"));
    }
    let header: Value = decode_json(jwt_parts[0])?;
    let payload: Value = decode_json(jwt_parts[1])?;
    let signature = Base64UrlUnpadded::decode_vec(jwt_parts[2])
        .map_err(|e| sd_err(format!("signature base64url: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| sd_err("header missing alg"))?;
    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    jose_verify(anchor, alg, signing_input.as_bytes(), &signature)?;

    // 2. Bind to the issuer and check expiry.
    let issuer = string_claim(&payload, "iss")?;
    if issuer != anchor.did() {
        return Err(AgentCredsError::IssuerMismatch {
            expected: anchor.did().to_string(),
            got: issuer,
        });
    }
    let expires_at = time_claim(&payload, "exp")?;
    if now > expires_at {
        return Err(AgentCredsError::CredentialExpired {
            expired_at: expires_at.to_rfc3339(),
        });
    }

    // 3. Each presented disclosure's digest must be in the signed `_sd`.
    let sd: Vec<String> = payload
        .get("_sd")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut disclosed = BTreeMap::new();
    for d in presented {
        if !sd.contains(&digest_of(d)) {
            return Err(sd_err("presented disclosure is not in the signed _sd set"));
        }
        let arr = decode_disclosure(d)?;
        let name = arr[1]
            .as_str()
            .ok_or_else(|| sd_err("disclosure name not a string"))?
            .to_string();
        disclosed.insert(name, arr[2].clone());
    }

    Ok(DisclosedCredential {
        issuer: anchor.did().to_string(),
        subject: string_claim(&payload, "sub")?,
        issued_at: time_claim(&payload, "iat")?,
        expires_at,
        vct: string_claim(&payload, "vct").unwrap_or_else(|_| VCT.to_string()),
        disclosed,
    })
}

fn decode_json(part: &str) -> Result<Value> {
    let bytes =
        Base64UrlUnpadded::decode_vec(part).map_err(|e| sd_err(format!("base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| sd_err(format!("JSON: {e}")))
}

fn string_claim(payload: &Value, name: &str) -> Result<String> {
    payload
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| sd_err(format!("missing '{name}' claim")))
}

fn time_claim(payload: &Value, name: &str) -> Result<DateTime<Utc>> {
    let secs = payload
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| sd_err(format!("missing numeric '{name}' claim")))?;
    Utc.timestamp_opt(secs, 0)
        .single()
        .ok_or_else(|| sd_err(format!("'{name}' is not a valid timestamp")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod};

    fn issued() -> (TrustAnchor, SdJwt) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let mut claims =
            CapabilityClaims::new(vec!["tool:search".into(), "tool:email".into()], 1, 3600);
        claims.budget_usd = Some(500);
        claims.authorized_by = Some("did:key:zSecretBoss".into());
        let sd = SdJwt::from_capability(&anchor, agent.did(), &claims, 3600).unwrap();
        (anchor, sd)
    }

    #[test]
    fn disclose_all_reveals_everything() {
        let (anchor, sd) = issued();
        let names = sd.disclosable_claims().unwrap();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let presentation = sd.present(&refs).unwrap();
        let d = verify_presentation(&presentation, &anchor).unwrap();
        assert_eq!(d.issuer, anchor.did());
        assert!(d.disclosed.contains_key("tools"));
        assert!(d.disclosed.contains_key("budget_usd"));
        assert!(d.disclosed.contains_key("authorized_by"));
    }

    #[test]
    fn selective_disclosure_hides_the_rest() {
        let (anchor, sd) = issued();
        // Reveal only the tool list.
        let presentation = sd.present(&["tools"]).unwrap();
        let d = verify_presentation(&presentation, &anchor).unwrap();
        assert!(d.disclosed.contains_key("tools"));
        // Budget and the authorizer stay hidden.
        assert!(!d.disclosed.contains_key("budget_usd"));
        assert!(!d.disclosed.contains_key("authorized_by"));
        // The disclosed tool list is the real value.
        assert_eq!(
            d.disclosed.get("tools").unwrap(),
            &json!(["tool:search", "tool:email"])
        );
    }

    #[test]
    fn hidden_claim_is_not_in_the_presentation_bytes() {
        let (_anchor, sd) = issued();
        let presentation = sd.present(&["tools"]).unwrap();
        // The secret authorizer value must not appear anywhere in the wire form.
        assert!(!presentation.contains("zSecretBoss"));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (anchor, sd) = issued();
        let presentation = sd.present(&["tools"]).unwrap();
        // Flip the FIRST character of the signature segment, not the last. The last
        // base64url character of an Ed25519 signature carries 2 padding bits that
        // base64ct requires to be zero, so flipping it lands on a NON-CANONICAL char
        // ~1/16 of the time - the decoder then rejects before the signature is ever
        // checked, and a stubbed `jose_verify` survives on that roll of the salt. CI
        // caught exactly that: the mutant lived in one shard run after dozens of local
        // kills. A middle-of-segment flip is always canonical, so the tampered bytes
        // always REACH signature verification.
        let tilde = presentation.find('~').unwrap();
        let (jwt, rest) = presentation.split_at(tilde);
        let sig_start = jwt.rfind('.').unwrap() + 1;
        let mut chars: Vec<char> = jwt.chars().collect();
        chars[sig_start] = if chars[sig_start] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect::<String>() + rest;
        let err = verify_presentation(&tampered, &anchor)
            .expect_err("a tampered signature must fail verification")
            .to_string();
        assert!(
            !err.contains("base64"),
            "the tamper must be rejected by SIGNATURE verification, not the decoder: {err}"
        );
    }

    #[test]
    fn forged_disclosure_rejected() {
        let (anchor, sd) = issued();
        // Attacker appends a self-made disclosure not covered by `_sd`.
        let forged = make_disclosure("budget_usd", &json!(1_000_000)).unwrap();
        let presentation = format!("{}{forged}~", sd.present(&["tools"]).unwrap());
        assert!(verify_presentation(&presentation, &anchor).is_err());
    }

    #[test]
    fn wrong_anchor_rejected() {
        let (_anchor, sd) = issued();
        let other = TrustAnchor::generate().unwrap();
        let presentation = sd.present(&["tools"]).unwrap();
        assert!(verify_presentation(&presentation, &other).is_err());
    }

    #[test]
    fn expired_credential_rejected() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        // valid_for_secs = 0 -> exp == iat == now; a moment later it's expired.
        let sd = SdJwt::from_capability(&anchor, agent.did(), &claims, 0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let presentation = sd.present(&["tools"]).unwrap();
        assert!(matches!(
            verify_presentation(&presentation, &anchor),
            Err(AgentCredsError::CredentialExpired { .. })
        ));
    }

    // -- Malformed input ----------------------------------------------------
    //
    // An SD-JWT presentation arrives from the HOLDER, who is not the issuer and is
    // not necessarily honest. `parse` and `verify_presentation` are therefore
    // untrusted-input entry points, and the existing tests above all start from a
    // well-formed artifact this crate produced. These start from ones it did not.

    #[test]
    fn parse_rejects_a_non_jwt_first_segment() {
        // The JWT segment is identified by having exactly two dots; anything else is
        // not a JWT and must be refused rather than carried as an opaque string that
        // fails later somewhere less obvious.
        for bad in ["", "not-a-jwt", "one.dot", "a.b.c.d", "~", "~a~"] {
            assert!(
                SdJwt::parse(bad).is_err(),
                "{bad:?} should not parse as an SD-JWT"
            );
        }
    }

    #[test]
    fn parse_accepts_a_bare_jwt_with_no_disclosures() {
        // A holder disclosing nothing is legitimate: the registered claims are still
        // conveyed. It must parse, and report an empty disclosable set.
        let (_anchor, sd) = issued();
        let bare = format!("{}~", sd.jwt);
        let parsed = SdJwt::parse(&bare).unwrap();
        assert!(parsed.disclosable_claims().unwrap().is_empty());
    }

    #[test]
    fn malformed_disclosures_are_rejected_not_ignored() {
        // A disclosure that is not base64url, not JSON, or not a 3-element array must
        // produce an error from the accessor rather than being silently skipped -
        // skipping would let a holder hide a claim by corrupting it.
        let (_anchor, sd) = issued();
        for junk in ["!!!!", "YWJj", "W10"] {
            // not base64url / valid b64 but not JSON array / JSON array of wrong length
            let wire = format!("{}~{}~", sd.jwt, junk);
            let parsed = SdJwt::parse(&wire).unwrap();
            assert!(
                parsed.disclosable_claims().is_err(),
                "{junk:?} should be rejected as a disclosure"
            );
        }
    }

    #[test]
    fn present_ignores_unknown_claim_names() {
        // Documented behaviour: unknown names are ignored rather than erroring. Pin it,
        // because the alternative (erroring) would be a reasonable reading of the API
        // and the difference is observable to a holder.
        let (anchor, sd) = issued();
        let presentation = sd.present(&["tools", "no_such_claim"]).unwrap();
        let verified = verify_presentation(&presentation, &anchor).unwrap();
        assert!(verified.disclosed.contains_key("tools"));
        assert!(!verified.disclosed.contains_key("no_such_claim"));
    }

    #[test]
    fn verify_presentation_rejects_garbage() {
        let (anchor, _sd) = issued();
        for bad in ["", "~", "not.a.jwt~", "a.b.c~!!!~"] {
            assert!(
                verify_presentation(bad, &anchor).is_err(),
                "{bad:?} should not verify"
            );
        }
    }

    #[test]
    fn compact_round_trips_through_parse() {
        let (anchor, sd) = issued();
        let wire = sd.as_str();
        let reparsed = SdJwt::parse(&wire).unwrap();
        let presentation = reparsed.present(&["tools"]).unwrap();
        assert!(verify_presentation(&presentation, &anchor).is_ok());
    }

    #[test]
    fn p256_anchor_supported() {
        use crate::did::KeyAlgorithm;
        let anchor = TrustAnchor::create(DidMethod::Key, Some(KeyAlgorithm::P256), None).unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let sd = SdJwt::from_capability(&anchor, agent.did(), &claims, 3600).unwrap();
        let presentation = sd.present(&["tools"]).unwrap();
        let d = verify_presentation(&presentation, &anchor).unwrap();
        assert!(d.disclosed.contains_key("tools"));
    }

    #[test]
    fn expiry_boundary_is_exclusive_via_the_now_seam() {
        // The boundary that was accepted-equivalent (368:19, `now > expires_at`) for
        // want of a seam. `verify_presentation_at` IS the seam; the exclusion is
        // retired the same day, exactly as happened to delegation's 1057:20.
        let (anchor, sd) = issued();
        let presentation = sd.present(&["tools"]).unwrap();
        let ok = verify_presentation(&presentation, &anchor).unwrap();
        // The verified credential exposes the exact expiry instant.
        let exp = ok.expires_at;
        assert!(
            verify_presentation_at(&presentation, &anchor, exp).is_ok(),
            "valid AT the expiry instant - the check is exclusive"
        );
        assert!(
            matches!(
                verify_presentation_at(
                    &presentation,
                    &anchor,
                    exp + chrono::Duration::nanoseconds(1)
                ),
                Err(AgentCredsError::CredentialExpired { .. })
            ),
            "invalid one nanosecond later"
        );
    }
}
