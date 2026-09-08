//! OIDC adapter - bridge a human's identity-provider token to on-behalf-of
//! capability-credential issuance.
//!
//! This is the human analogue of [`crate::spiffe`]: instead of attesting a
//! *workload* from a SPIFFE JWT-SVID, it validates a *human* from an OpenID
//! Connect **ID token** (or an RFC 8693 token-exchange result carrying an `act`
//! claim) against the provider's published keys (JWKS), then lets the org's
//! [`TrustAnchor`] issue a [`CapabilityCredential`] bound to that human.
//!
//! The human authenticates at the IdP and holds no key here; issuance mints them
//! a real, stable DID (see [`crate::principal::HumanIdentity`]) and the anchor's
//! signature over the credential attests the DID <-> IdP-subject binding.
//!
//! Supports the three JOSE algorithms real IdPs use: `RS256` (the default for
//! most OIDC providers), `ES256` (P-256), and `EdDSA` (Ed25519).
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//! use agentcreds_core::oidc::{OidcProvider, issue_on_behalf_of};
//! use agentcreds_core::vc::AuthoritySource;
//!
//! # fn demo(id_token: &str, jwks: &str, agent_did: &str)
//! #   -> Result<(), agentcreds_core::error::AgentCredsError> {
//! // Build the provider from its discovered issuer, your client_id, and its JWKS.
//! let mut provider = OidcProvider::new("https://login.acme.com", "agentcreds-prod");
//! provider.add_keys_from_jwks(jwks)?;
//!
//! // Validate the human's ID token (and, for OBO tokens, that `act` is this agent).
//! let human = provider.validate_id_token(id_token, Some(agent_did), None)?;
//!
//! // Issue a credential for the agent, bound to the verified human principal.
//! //
//! // The consented scope comes from the token's own `scope` claim - not from `tools` -
//! // so the second axis is bounded by an authority outside this organisation. The
//! // resource authority has no standard OIDC claim, so it comes from deployment policy
//! // and is labelled as such.
//! let anchor = TrustAnchor::generate()?;
//! let vc = issue_on_behalf_of(
//!     &anchor, agent_did, &human,
//!     vec!["tool:read_email".into()],
//!     vec!["mailbox:alice@acme.com/*".into()],
//!     AuthoritySource::Policy,
//!     2, 3600,
//! )?;
//! assert_eq!(vc.subject_did(), agent_did);
//! # Ok(()) }
//! ```

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use crate::did::TrustAnchor;
use crate::principal::HumanIdentity;
use crate::vc::{AuthoritySource, CapabilityClaims, CapabilityCredential};
use crate::{error::AgentCredsError, Result};

fn oidc_err(reason: impl Into<String>) -> AgentCredsError {
    AgentCredsError::OidcValidationFailed {
        reason: reason.into(),
    }
}

// -- Provider keys -----------------------------------------------------------

enum ProviderKey {
    Ed25519([u8; 32]),
    P256(Box<p256::ecdsa::VerifyingKey>),
    Rsa(Box<rsa::RsaPublicKey>),
}

struct KeyEntry {
    kid: Option<String>,
    key: ProviderKey,
}

/// An OpenID Connect provider the org trusts: its `issuer`, the `audience`
/// (client id) tokens must be minted for, and its signing keys (from JWKS).
///
/// Verification is offline against the imported keys - the network fetch of the
/// JWKS lives in the host/server, matching the rest of the crate.
pub struct OidcProvider {
    issuer: String,
    audience: String,
    keys: Vec<KeyEntry>,
    leeway_secs: i64,
}

impl OidcProvider {
    /// A provider with no keys yet. `issuer` is the IdP's exact `iss`; `audience`
    /// is the client id every accepted token must list in `aud`.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        OidcProvider {
            issuer: issuer.into(),
            audience: audience.into(),
            keys: Vec::new(),
            leeway_secs: 60,
        }
    }

    /// Set the allowed clock skew (seconds) for `exp`/`nbf`. Default 60.
    #[must_use]
    pub fn with_leeway(mut self, leeway_secs: i64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }

    /// Add an Ed25519 (`EdDSA`) signing key, optionally keyed by `kid`.
    ///
    /// # Errors
    /// `OidcValidationFailed` if `public_key` is not a valid 32-byte Ed25519 key.
    pub fn add_ed25519_key(&mut self, kid: Option<String>, public_key: &[u8]) -> Result<()> {
        let arr: [u8; 32] = public_key
            .try_into()
            .map_err(|_| oidc_err("Ed25519 public key must be 32 bytes"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| oidc_err(format!("invalid Ed25519 key: {e}")))?;
        self.keys.push(KeyEntry {
            kid,
            key: ProviderKey::Ed25519(arr),
        });
        Ok(())
    }

    /// Add a P-256 (`ES256`) signing key from SEC1 bytes, optionally keyed by `kid`.
    ///
    /// # Errors
    /// `OidcValidationFailed` if `sec1_public_key` is not a valid P-256 point.
    pub fn add_p256_key(&mut self, kid: Option<String>, sec1_public_key: &[u8]) -> Result<()> {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1_public_key)
            .map_err(|e| oidc_err(format!("invalid P-256 key: {e}")))?;
        self.keys.push(KeyEntry {
            kid,
            key: ProviderKey::P256(Box::new(vk)),
        });
        Ok(())
    }

    /// Add an RSA (`RS256`) signing key from JWKS `n`/`e` (base64url, big-endian),
    /// optionally keyed by `kid`.
    ///
    /// # Errors
    /// `OidcValidationFailed` if `n`/`e` are not valid base64url or do not form a
    /// usable RSA public key.
    pub fn add_rsa_key(
        &mut self,
        kid: Option<String>,
        n_b64url: &str,
        e_b64url: &str,
    ) -> Result<()> {
        let n = Base64UrlUnpadded::decode_vec(n_b64url)
            .map_err(|e| oidc_err(format!("RSA 'n' base64url: {e}")))?;
        let e = Base64UrlUnpadded::decode_vec(e_b64url)
            .map_err(|e| oidc_err(format!("RSA 'e' base64url: {e}")))?;
        let n = rsa::BigUint::from_bytes_be(&n);
        let e = rsa::BigUint::from_bytes_be(&e);
        let key = rsa::RsaPublicKey::new(n, e)
            .map_err(|e| oidc_err(format!("invalid RSA public key: {e}")))?;
        self.keys.push(KeyEntry {
            kid,
            key: ProviderKey::Rsa(Box::new(key)),
        });
        Ok(())
    }

    /// Import the provider's signing keys from its JWKS document (the `keys`
    /// fetched from `jwks_uri`). Recognizes `RSA`, `EC`/`P-256`, and
    /// `OKP`/`Ed25519`; unknown key types are skipped.
    ///
    /// # Errors
    /// `OidcValidationFailed` if the JWKS is malformed or a recognized key is invalid.
    pub fn add_keys_from_jwks(&mut self, jwks: &str) -> Result<()> {
        let doc: Value =
            serde_json::from_str(jwks).map_err(|e| oidc_err(format!("JWKS JSON: {e}")))?;
        let keys = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| oidc_err("JWKS missing 'keys' array"))?;
        for jwk in keys {
            let kid = jwk.get("kid").and_then(Value::as_str).map(str::to_string);
            match jwk.get("kty").and_then(Value::as_str) {
                Some("RSA") => {
                    let n = jwk_field(jwk, "n")?;
                    let e = jwk_field(jwk, "e")?;
                    self.add_rsa_key(kid, n, e)?;
                }
                Some("EC") if jwk.get("crv").and_then(Value::as_str) == Some("P-256") => {
                    let x = jwk_coord(jwk, "x")?;
                    let y = jwk_coord(jwk, "y")?;
                    let mut sec1 = Vec::with_capacity(65);
                    sec1.push(0x04);
                    sec1.extend_from_slice(&x);
                    sec1.extend_from_slice(&y);
                    self.add_p256_key(kid, &sec1)?;
                }
                Some("OKP") if jwk.get("crv").and_then(Value::as_str) == Some("Ed25519") => {
                    let x = jwk_coord(jwk, "x")?;
                    self.add_ed25519_key(kid, &x)?;
                }
                _ => continue,
            }
        }
        Ok(())
    }

    /// Validate an OIDC ID token (or RFC 8693 OBO token) and return the verified
    /// human principal.
    ///
    /// Checks: signature against a trusted key (matched by `kid` when present),
    /// `iss` equals this provider's issuer, `aud` contains its audience, `exp`
    /// (and `nbf` if present) within the leeway, the `nonce` if `expected_nonce`
    /// is given, and - when the token carries an RFC 8693 `act` claim and
    /// `expected_agent_did` is given - that the actor is that agent.
    ///
    /// # Errors
    /// `OidcValidationFailed` for any malformation, signature failure, claim
    /// mismatch, or expiry.
    pub fn validate_id_token(
        &self,
        id_token: &str,
        expected_agent_did: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> Result<VerifiedHumanPrincipal> {
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(oidc_err("ID token must have three dot-separated parts"));
        }
        let header = decode_json(parts[0])?;
        let payload = decode_json(parts[1])?;
        let signature = Base64UrlUnpadded::decode_vec(parts[2])
            .map_err(|e| oidc_err(format!("invalid base64url signature: {e}")))?;

        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| oidc_err("JWT header missing 'alg'"))?;
        let kid = header.get("kid").and_then(Value::as_str);
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        if !self.verify_signature(alg, kid, signing_input.as_bytes(), &signature) {
            return Err(oidc_err("no trusted key validated the token signature"));
        }

        // Issuer must match exactly.
        let iss = payload
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| oidc_err("token missing 'iss'"))?;
        if iss != self.issuer {
            return Err(oidc_err(format!(
                "token issuer '{iss}' does not match provider '{}'",
                self.issuer
            )));
        }

        // Audience must include this provider's audience.
        let audiences = extract_audiences(&payload);
        if !audiences.iter().any(|a| a == &self.audience) {
            return Err(oidc_err(format!(
                "token audience does not include '{}'",
                self.audience
            )));
        }

        // Expiry / not-before, with leeway.
        let now = Utc::now().timestamp();
        let exp = payload
            .get("exp")
            .and_then(Value::as_i64)
            .ok_or_else(|| oidc_err("token missing numeric 'exp'"))?;
        if now > exp + self.leeway_secs {
            return Err(oidc_err("token has expired"));
        }
        if let Some(nbf) = payload.get("nbf").and_then(Value::as_i64) {
            if now + self.leeway_secs < nbf {
                return Err(oidc_err("token is not yet valid (nbf)"));
            }
        }

        // Replay binding: nonce must match if the caller is checking one.
        if let Some(expected) = expected_nonce {
            let nonce = payload.get("nonce").and_then(Value::as_str);
            if nonce != Some(expected) {
                return Err(oidc_err("token nonce does not match the expected value"));
            }
        }

        let subject = payload
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| oidc_err("token missing non-empty 'sub'"))?
            .to_string();

        // RFC 8693 actor: `act.sub` is the agent acting for the human. If the
        // caller named an expected agent and an actor is present, they must match.
        let acted_by = payload
            .get("act")
            .and_then(|a| a.get("sub"))
            .and_then(Value::as_str)
            .map(str::to_string);
        if let (Some(expected), Some(actor)) = (expected_agent_did, acted_by.as_deref()) {
            if expected != actor {
                return Err(oidc_err(format!(
                    "token actor '{actor}' does not match the presenting agent '{expected}'"
                )));
            }
        }

        let expires_at = Utc
            .timestamp_opt(exp, 0)
            .single()
            .ok_or_else(|| oidc_err("token 'exp' is not a valid timestamp"))?;

        Ok(VerifiedHumanPrincipal {
            issuer: self.issuer.clone(),
            subject,
            email: payload
                .get("email")
                .and_then(Value::as_str)
                .map(str::to_string),
            expires_at,
            scope: extract_scopes(&payload),
            acted_by,
        })
    }

    /// Try every (kid-matching) key of the right algorithm; true on the first
    /// that verifies.
    fn verify_signature(&self, alg: &str, kid: Option<&str>, msg: &[u8], sig: &[u8]) -> bool {
        for entry in &self.keys {
            if let Some(k) = kid {
                if entry.kid.as_deref() != Some(k) {
                    continue;
                }
            }
            let ok = match (alg, &entry.key) {
                ("EdDSA", ProviderKey::Ed25519(pk)) => verify_ed25519(pk, msg, sig),
                ("ES256", ProviderKey::P256(vk)) => verify_es256(vk, msg, sig),
                ("RS256", ProviderKey::Rsa(pk)) => verify_rs256(pk, msg, sig),
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
    vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .is_ok()
}

fn verify_es256(vk: &p256::ecdsa::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    // JOSE ES256 signatures are raw r||s (64 bytes), not DER.
    let Ok(signature) = p256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

fn verify_rs256(pk: &rsa::RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
    use rsa::signature::Verifier;
    let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk.clone());
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

fn jwk_field<'a>(jwk: &'a Value, field: &str) -> Result<&'a str> {
    jwk.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| oidc_err(format!("JWK missing '{field}'")))
}

fn jwk_coord(jwk: &Value, field: &str) -> Result<Vec<u8>> {
    let s = jwk_field(jwk, field)?;
    Base64UrlUnpadded::decode_vec(s).map_err(|e| oidc_err(format!("JWK '{field}' base64url: {e}")))
}

fn decode_json(part: &str) -> Result<Value> {
    let bytes = Base64UrlUnpadded::decode_vec(part)
        .map_err(|e| oidc_err(format!("invalid base64url segment: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| oidc_err(format!("invalid JSON segment: {e}")))
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

/// OAuth scopes from `scope` (space-delimited string) or `scp` (array).
fn extract_scopes(payload: &Value) -> Vec<String> {
    if let Some(s) = payload.get("scope").and_then(Value::as_str) {
        return s.split_whitespace().map(String::from).collect();
    }
    if let Some(a) = payload.get("scp").and_then(Value::as_array) {
        return a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    Vec::new()
}

// -- Verified principal + issuance bridge ------------------------------------

/// A human principal whose identity an IdP cryptographically attested.
#[derive(Debug, Clone)]
pub struct VerifiedHumanPrincipal {
    /// The IdP issuer (`iss`).
    pub issuer: String,
    /// The human's stable subject (`sub`).
    pub subject: String,
    /// The human's email, if the token disclosed it.
    pub email: Option<String>,
    /// When the token (and thus the authorization) expires.
    pub expires_at: DateTime<Utc>,
    /// OAuth scopes the token carried.
    pub scope: Vec<String>,
    /// The actor (`act.sub`) for an RFC 8693 on-behalf-of token - the agent the
    /// IdP itself recorded as acting for this human.
    pub acted_by: Option<String>,
}

impl VerifiedHumanPrincipal {
    /// Mint this principal's stable DID from its IdP identity.
    ///
    /// # Errors
    /// `OutOfBounds` if the issuer has no resolvable host or the subject is empty.
    pub fn human_identity(&self) -> Result<HumanIdentity> {
        HumanIdentity::from_idp(&self.issuer, &self.subject)
    }
}

/// Issue a capability credential to `agent_did`, bound to a verified human
/// principal - the human analogue of [`crate::spiffe::issue_from_svid`].
///
/// The credential's validity is capped at the human's authorization expiry, and the
/// human is minted a real DID and bound as the credential's on-behalf-of principal.
///
/// **The consented scope is the IdP's `scope` claim, not the caller's `tools`.** That
/// distinction is the entire value of the principal axis. Recording the granted tools as
/// the consented scope - which this helper previously did - makes
/// [`HumanAuthorization::permits_tools`](crate::vc::PrincipalAuthorization::permits_tools) a tautology: it returns true iff every granted
/// tool is in the consented set, and the two sets were the same vector. The check could
/// not fail, so the second axis bounded nothing while appearing to.
///
/// Taking the scope from the token instead means the bound comes from an authority
/// *outside* this organization, which is what makes it worth enforcing. It is recorded as
/// [`AuthoritySource::Attested`].
///
/// `resource_authority` is a separate argument because no standard OIDC claim carries
/// resource namespaces; a deployment resolves it from policy and passes it with the
/// matching `resource_source`. Pass [`AuthoritySource::Asserted`] only if it genuinely
/// came from the request - and know that it then bounds nothing.
///
/// # Errors
/// - `ConsentViolation` if a granted tool is outside the IdP-attested scope. This is now
///   reachable, which is the point.
/// - Propagates credential issuance failure.
pub fn issue_on_behalf_of(
    anchor: &TrustAnchor,
    agent_did: &str,
    principal: &VerifiedHumanPrincipal,
    tools: Vec<String>,
    resource_authority: Vec<String>,
    resource_source: AuthoritySource,
    max_delegation_depth: u32,
    valid_for_secs: u64,
) -> Result<CapabilityCredential> {
    let human = principal.human_identity()?;

    // The weaker of the two sources describes the pair, because a verifier reading one
    // `entitlement_source` must not be told "attested" when half of what it labels was
    // supplied by the requester.
    let source = if principal.scope.is_empty() {
        resource_source
    } else if resource_authority.is_empty() {
        AuthoritySource::Attested
    } else if resource_source.rank() < AuthoritySource::Attested.rank() {
        resource_source
    } else {
        AuthoritySource::Attested
    };

    let obo = human.authorize(
        Utc::now(),
        principal.expires_at,
        principal.scope.clone(),
        resource_authority,
        source,
    );
    let mut claims = CapabilityClaims::new(tools, max_delegation_depth, valid_for_secs);
    claims.on_behalf_of = Some(obo);
    CapabilityCredential::issue(anchor, agent_did, claims, None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod};
    use chrono::Duration;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use rand::rngs::OsRng;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::signature::SignatureEncoding;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::json;

    const ISS: &str = "https://login.acme.com";
    const AUD: &str = "agentcreds-prod";
    const SUB: &str = "auth0|alice";

    fn b64(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn future() -> i64 {
        (Utc::now() + Duration::hours(1)).timestamp()
    }

    /// Build a signed JWT from a header object and a claims object, signing with
    /// the given Ed25519 key. Returns the compact JWT.
    fn ed25519_jwt(sk: &SigningKey, claims: Value) -> String {
        let header =
            b64(&serde_json::to_vec(&json!({"alg":"EdDSA","typ":"JWT","kid":"k1"})).unwrap());
        let payload = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }

    fn standard_claims() -> Value {
        json!({"iss": ISS, "aud": AUD, "sub": SUB, "exp": future(),
               "scope": "openid email tool:read_email"})
    }

    // -- The principal axis actually bounds something -------------------------
    //
    // These exist because the axis previously did not. `issue_on_behalf_of` recorded the
    // *granted tools* as the consented scope, so `permits_tools` compared a set against
    // itself and could never fail. The credential looked dual-axis and was single-axis.

    #[test]
    fn the_consented_scope_comes_from_the_token_not_the_request() {
        // The whole value of the second axis: it is established by an authority outside
        // this organization. If it were taken from the same request that names the tools,
        // both axes would trace to one source and the second would bound nothing.
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        let human = p.validate_id_token(&jwt, None, None).unwrap();

        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into()],
            vec![],
            AuthoritySource::Policy,
            2,
            3600,
        )
        .unwrap();

        let obo = vc.on_behalf_of().unwrap();
        // The IdP said `openid email tool:read_email` - all three, not just the one tool
        // the caller asked to grant. The scope is the token's, verbatim.
        assert_eq!(
            obo.scope_consented,
            vec!["openid", "email", "tool:read_email"],
            "the consented scope was not taken from the token"
        );
        assert_ne!(
            obo.scope_consented,
            vc.claims().tools,
            "scope and tools are identical - the consent check is a tautology again"
        );
        assert_eq!(obo.entitlement_source, AuthoritySource::Attested);
    }

    #[test]
    fn a_tool_the_idp_did_not_authorize_is_refused() {
        // The check that could not fire before. `tool:transfer_funds` is not in the
        // token's scope, so granting it is a consent violation - regardless of the fact
        // that whoever called issuance asked for it.
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        let human = p.validate_id_token(&jwt, None, None).unwrap();

        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

        let err = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into(), "tool:transfer_funds".into()],
            vec![],
            AuthoritySource::Policy,
            2,
            3600,
        )
        .expect_err("a tool outside the IdP-attested scope was granted");
        assert!(
            format!("{err}").contains("transfer_funds"),
            "wrong refusal: {err}"
        );

        // Positive control: the same call without the unauthorized tool succeeds, so the
        // refusal is attributable to consent and not to the request being malformed.
        assert!(
            issue_on_behalf_of(
                &anchor,
                agent.did(),
                &human,
                vec!["tool:read_email".into()],
                vec![],
                AuthoritySource::Policy,
                2,
                3600,
            )
            .is_ok(),
            "control: an authorized tool must still issue"
        );
    }

    #[test]
    fn the_recorded_source_never_overstates_the_weaker_half() {
        // `entitlement_source` labels one field that covers two bounds. A verifier told
        // "attested" must not find that half of what the label covers came from the
        // request - so the pair takes the weaker of the two sources.
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        let human = p.validate_id_token(&jwt, None, None).unwrap();
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();

        // Attested scope + requester-supplied resources = the pair is only `asserted`.
        let mixed = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into()],
            vec!["mailbox:whatever/*".into()],
            AuthoritySource::Asserted,
            2,
            3600,
        )
        .unwrap();
        assert_eq!(
            mixed.on_behalf_of().unwrap().entitlement_source,
            AuthoritySource::Asserted,
            "a requester-supplied resource bound was labeled attested"
        );

        // With no resource bound at all, there is no weaker half to drag it down.
        let clean = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into()],
            vec![],
            AuthoritySource::Asserted,
            2,
            3600,
        )
        .unwrap();
        assert_eq!(
            clean.on_behalf_of().unwrap().entitlement_source,
            AuthoritySource::Attested
        );
    }

    #[test]
    fn valid_ed25519_id_token_validates() {
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();

        let human = p.validate_id_token(&jwt, None, None).unwrap();
        assert_eq!(human.subject, SUB);
        assert_eq!(human.issuer, ISS);
        assert!(human.scope.contains(&"tool:read_email".to_string()));
    }

    #[test]
    fn valid_es256_id_token_validates() {
        let sk = P256SigningKey::random(&mut OsRng);
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let header = b64(&serde_json::to_vec(&json!({"alg":"ES256","typ":"JWT"})).unwrap());
        let payload = b64(&serde_json::to_vec(&standard_claims()).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig: p256::ecdsa::Signature = {
            use p256::ecdsa::signature::Signer;
            sk.sign(signing_input.as_bytes())
        };
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));

        let mut p = OidcProvider::new(ISS, AUD);
        p.add_p256_key(None, &pk).unwrap();
        assert_eq!(p.validate_id_token(&jwt, None, None).unwrap().subject, SUB);
    }

    /// Build an RSA-signed (RS256) JWT and the matching JWKS, then validate via
    /// the JWKS import path.
    #[test]
    fn valid_rs256_id_token_validates_via_jwks() {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let signing_key = RsaSigningKey::<sha2::Sha256>::new(priv_key);

        let header =
            b64(&serde_json::to_vec(&json!({"alg":"RS256","typ":"JWT","kid":"rsa1"})).unwrap());
        let payload = b64(&serde_json::to_vec(&standard_claims()).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = signing_key.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));

        let jwks = json!({"keys": [{
            "kty": "RSA", "kid": "rsa1", "alg": "RS256", "use": "sig",
            "n": b64(&pub_key.n().to_bytes_be()),
            "e": b64(&pub_key.e().to_bytes_be()),
        }]})
        .to_string();

        let mut p = OidcProvider::new(ISS, AUD);
        p.add_keys_from_jwks(&jwks).unwrap();
        assert_eq!(p.validate_id_token(&jwt, None, None).unwrap().subject, SUB);
    }

    #[test]
    fn wrong_issuer_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["iss"] = json!("https://evil.example");
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn wrong_audience_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["aud"] = json!("some-other-client");
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["exp"] = json!((Utc::now() - Duration::hours(1)).timestamp());
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn nonce_mismatch_rejected_and_match_accepted() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["nonce"] = json!("n-123");
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, Some("n-999")).is_err());
        assert!(p.validate_id_token(&jwt, None, Some("n-123")).is_ok());
    }

    #[test]
    fn rfc8693_actor_must_match_presenting_agent() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["act"] = json!({"sub": "did:key:zAgent"});
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();

        // Wrong agent -> rejected; right agent -> accepted and recorded.
        assert!(p
            .validate_id_token(&jwt, Some("did:key:zOther"), None)
            .is_err());
        let human = p
            .validate_id_token(&jwt, Some("did:key:zAgent"), None)
            .unwrap();
        assert_eq!(human.acted_by.as_deref(), Some("did:key:zAgent"));
    }

    #[test]
    fn untrusted_key_rejected() {
        let signer = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&signer, standard_claims());
        // Provider holds a *different* key.
        let other = SigningKey::generate(&mut OsRng);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &other.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        // Swap the payload segment for a different claims set.
        let parts: Vec<&str> = jwt.split('.').collect();
        let forged_payload = b64(&serde_json::to_vec(&json!({
            "iss": ISS, "aud": AUD, "sub": "auth0|attacker", "exp": future()
        }))
        .unwrap());
        let tampered = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert!(p.validate_id_token(&tampered, None, None).is_err());
    }

    /// End-to-end: validate a human, issue an OBO credential bound to their real
    /// DID, and confirm it verifies and carries the principal.
    #[test]
    fn issue_on_behalf_of_binds_real_human_did() {
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        let human = p.validate_id_token(&jwt, None, None).unwrap();

        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into()],
            vec!["mailbox:alice@acme.com/*".into()],
            AuthoritySource::Policy,
            2,
            3600,
        )
        .unwrap();

        assert!(vc.verify(&anchor, true).is_ok());
        let obo = vc.on_behalf_of().unwrap();
        let expected_did = HumanIdentity::from_idp(ISS, SUB).unwrap();
        assert_eq!(obo.principal_did, expected_did.did());
        assert_eq!(obo.issuer, ISS);
    }

    /// The OBO credential cannot outlive the IdP token's expiry.
    #[test]
    fn issued_credential_capped_at_token_expiry() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        let soon = (Utc::now() + Duration::seconds(90)).timestamp();
        claims["exp"] = json!(soon);
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        let human = p.validate_id_token(&jwt, None, None).unwrap();

        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        // Ask for an hour, but the token expires in 90s.
        let vc = issue_on_behalf_of(
            &anchor,
            agent.did(),
            &human,
            vec!["tool:read_email".into()],
            vec![],
            AuthoritySource::Attested,
            2,
            3600,
        )
        .unwrap();
        assert!(vc.expiration_date() <= human.expires_at + Duration::seconds(1));
        assert!(vc.expiration_date() < Utc::now() + Duration::minutes(30));
    }

    // -- Key-import paths (EC / Ed25519 JWKS + error branches) -----------------

    #[test]
    fn jwks_imports_ec_p256_and_validates() {
        let sk = P256SigningKey::random(&mut OsRng);
        let ep = sk.verifying_key().to_encoded_point(false);
        let sec1 = ep.as_bytes(); // 0x04 || x(32) || y(32)
        let x = b64(&sec1[1..33]);
        let y = b64(&sec1[33..65]);

        let header =
            b64(&serde_json::to_vec(&json!({"alg":"ES256","typ":"JWT","kid":"ec1"})).unwrap());
        let payload = b64(&serde_json::to_vec(&standard_claims()).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig: p256::ecdsa::Signature = {
            use p256::ecdsa::signature::Signer;
            sk.sign(signing_input.as_bytes())
        };
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));

        let jwks = json!({"keys":[{"kty":"EC","crv":"P-256","kid":"ec1","x":x,"y":y}]}).to_string();
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_keys_from_jwks(&jwks).unwrap();
        assert_eq!(p.validate_id_token(&jwt, None, None).unwrap().subject, SUB);
    }

    #[test]
    fn jwks_imports_okp_ed25519_and_validates() {
        let sk = SigningKey::generate(&mut OsRng);
        let x = b64(&sk.verifying_key().to_bytes());
        let jwt = ed25519_jwt(&sk, standard_claims());
        let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":x}]}).to_string();
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_keys_from_jwks(&jwks).unwrap();
        assert_eq!(p.validate_id_token(&jwt, None, None).unwrap().subject, SUB);
    }

    #[test]
    fn jwks_unknown_kty_is_skipped_leaving_no_trusted_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let jwt = ed25519_jwt(&sk, standard_claims());
        // An unsupported `oct` key is skipped -> no key can validate the token.
        let jwks = json!({"keys":[{"kty":"oct","k":"AAAA","kid":"k1"}]}).to_string();
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_keys_from_jwks(&jwks).unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn malformed_jwks_rejected() {
        let mut p = OidcProvider::new(ISS, AUD);
        assert!(p.add_keys_from_jwks("not json").is_err());
        assert!(p
            .add_keys_from_jwks(&json!({"no_keys": []}).to_string())
            .is_err());
    }

    #[test]
    fn invalid_key_material_rejected() {
        let mut p = OidcProvider::new(ISS, AUD);
        assert!(p.add_ed25519_key(None, &[0u8; 16]).is_err()); // wrong length
        assert!(p.add_p256_key(None, &[0u8; 10]).is_err()); // not a curve point
        assert!(p.add_rsa_key(None, "!!!bad!!!", "AQAB").is_err()); // bad base64url 'n'
    }

    // -- Token-malformation branches -------------------------------------------

    #[test]
    fn structurally_malformed_tokens_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token("only.two", None, None).is_err()); // not 3 parts
        assert!(p.validate_id_token("a.b.c", None, None).is_err()); // bad base64/json segments
                                                                    // Well-formed header+payload but a non-base64url signature segment.
        let jwt = ed25519_jwt(&sk, standard_claims());
        let parts: Vec<&str> = jwt.split('.').collect();
        let bad_sig = format!("{}.{}.!!!", parts[0], parts[1]);
        assert!(p.validate_id_token(&bad_sig, None, None).is_err());
    }

    #[test]
    fn tokens_missing_required_claims_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        for missing in ["iss", "sub", "exp"] {
            let mut claims = standard_claims();
            claims.as_object_mut().unwrap().remove(missing);
            let jwt = ed25519_jwt(&sk, claims);
            assert!(
                p.validate_id_token(&jwt, None, None).is_err(),
                "a token missing '{missing}' must be rejected"
            );
        }
        // An empty `sub` is also rejected.
        let mut claims = standard_claims();
        claims["sub"] = json!("");
        let jwt = ed25519_jwt(&sk, claims);
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn header_missing_alg_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let header = b64(&serde_json::to_vec(&json!({"typ":"JWT","kid":"k1"})).unwrap());
        let payload = b64(&serde_json::to_vec(&standard_claims()).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", b64(&sig.to_bytes()));
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn not_yet_valid_nbf_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["nbf"] = json!((Utc::now() + Duration::hours(1)).timestamp());
        let jwt = ed25519_jwt(&sk, claims);
        let mut p = OidcProvider::new(ISS, AUD);
        p.add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(p.validate_id_token(&jwt, None, None).is_err());
    }

    #[test]
    fn leeway_admits_token_just_past_exp() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut claims = standard_claims();
        claims["exp"] = json!((Utc::now() - Duration::seconds(30)).timestamp()); // 30s ago
        let jwt = ed25519_jwt(&sk, claims);
        // A generous leeway admits it; zero leeway rejects the same token.
        let mut lenient = OidcProvider::new(ISS, AUD).with_leeway(120);
        lenient
            .add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(lenient.validate_id_token(&jwt, None, None).is_ok());
        let mut strict = OidcProvider::new(ISS, AUD).with_leeway(0);
        strict
            .add_ed25519_key(Some("k1".into()), &sk.verifying_key().to_bytes())
            .unwrap();
        assert!(strict.validate_id_token(&jwt, None, None).is_err());
    }
}
