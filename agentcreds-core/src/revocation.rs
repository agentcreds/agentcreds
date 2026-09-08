//! Credential revocation via an **OAuth Token Status List**
//! (draft-ietf-oauth-status-list).
//!
//! A Status List encodes revocation as a compressed bitstring: the bit at index N
//! is 1 if credential N is revoked (INVALID), 0 if VALID. AgentCreds uses 1 bit per
//! entry (revoked / valid); the format reserves 2/4/8-bit entries for richer states.
//!
//! The bitstring is DEFLATE-compressed and base64url-encoded, then published as a
//! **Status List Token** - a JWS with `typ: "statuslist+jwt"` whose payload carries
//! `sub` (the list URL), `iat`, and `status_list: { bits, lst }`. A credential points
//! at its slot with `status.status_list.{idx, uri}`. This is the exact artifact a
//! foreign OAuth / SD-JWT verifier (e.g. an OpenID4VP wallet) already knows how to
//! fetch and check - the same list now serves the W3C and SD-JWT VC paths alike.
//!
//! Verification is O(1): one JWS signature check plus a single bit test after
//! decompression. Decompressed lists are cached; revocation checks add <0.1ms.
//!
//! Note on `verify`: it re-derives the JWS signing input from the parsed fields, so
//! it round-trips tokens **produced by this library** (our own org's list). A foreign
//! issuer's token is consumed with that verifier's own JWS validation; cross-vendor
//! serving is the wrapper's concern, not the offline core's.
//!
//! Reference: draft-ietf-oauth-status-list.

use base64ct::Encoding;
use bitvec::prelude::*;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::did::{KeyAlgorithm, TrustAnchor};
use crate::vc::CapabilityCredential;
use crate::{error::AgentCredsError, Result};

/// Default list size - 131,072 entries (16KB bitstring).
pub const DEFAULT_LIST_SIZE: u64 = 131_072;

/// `typ` header of an OAuth Status List Token.
const STATUS_LIST_TYP: &str = "statuslist+jwt";

/// base64url (unpadded) - the JOSE encoding for JWS segments and the `lst` bitstring.
fn b64url(bytes: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64ct::Base64UrlUnpadded::decode_vec(s)
        .map_err(|_| AgentCredsError::InvalidRevocationListSignature)
}

/// The JWS `alg` string for an anchor's key type.
fn alg_for(anchor: &TrustAnchor) -> &'static str {
    match anchor.public_key().algorithm {
        KeyAlgorithm::Ed25519 => "EdDSA",
        KeyAlgorithm::P256 => "ES256",
    }
}

/// An OAuth Token Status List - the revocation list for a deployment environment.
///
/// One list serves an entire environment. Publish it as a Status List Token
/// ([`to_status_list_token`](Self::to_status_list_token)) at a stable URL - it is
/// referenced by every credential's `status.status_list.uri`.
///
/// The struct also serializes as plain JSON ([`to_json`](Self::to_json)) for the
/// control plane's internal at-rest storage; the *published* form a relying party
/// fetches is always the signed token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    /// Globally unique identifier for this list (the URL it is served at) - the
    /// token's `sub` claim.
    pub id: String,

    /// The DID of the entity that maintains this list - the token's `kid` header.
    pub issuer: String,

    /// JWS algorithm this list is signed with (`EdDSA` or `ES256`) - the token's
    /// `alg` header, fixed by the issuer anchor's key type.
    pub alg: String,

    /// When this list was last updated - the token's `iat` claim (second precision).
    pub updated: DateTime<Utc>,

    /// Number of entries (bit slots) in this list.
    pub size: u64,

    /// Status bits per entry. AgentCreds uses 1 (revoked / valid); the format
    /// reserves 2/4/8 for richer states.
    pub bits: u8,

    /// DEFLATE-compressed, base64url-encoded bitstring - the token's
    /// `status_list.lst`.
    pub encoded_list: String,

    /// base64url JWS signature over `header.payload`.
    pub signature: String,
}

impl RevocationList {
    /// Create a new, empty revocation list, signed as a Status List Token by `anchor`.
    ///
    /// # Arguments
    /// * `id`     - The URL at which this list will be published (`sub`)
    /// * `anchor` - The trust anchor that owns and signs this list
    /// * `size`   - Number of credential slots (default: 131,072)
    pub fn new(id: &str, anchor: &TrustAnchor, size: Option<u64>) -> Result<Self> {
        let n = size.unwrap_or(DEFAULT_LIST_SIZE);
        let raw = bitvec![u8, Msb0; 0; n as usize].as_raw_slice().to_vec();
        let encoded = Self::compress_and_encode(&raw)?;

        let mut list = RevocationList {
            id: id.to_string(),
            issuer: anchor.did().to_string(),
            alg: alg_for(anchor).to_string(),
            updated: Utc::now(),
            size: n,
            bits: 1,
            encoded_list: encoded,
            signature: String::new(),
        };
        list.sign(anchor)?;
        Ok(list)
    }

    /// Serialize this list to the internal JSON container (control-plane at-rest
    /// storage). For the **published** form a relying party fetches, use
    /// [`to_status_list_token`](Self::to_status_list_token).
    ///
    /// # Errors
    /// If serialization fails.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialise from the internal JSON container. **Verify it against the issuer
    /// anchor** ([`verify`](Self::verify)) before trusting it.
    ///
    /// # Errors
    /// If the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Serialize to a compact **OAuth Status List Token** (`header.payload.signature`,
    /// `typ: statuslist+jwt`) - the published form served at [`id`](Self::id) and
    /// consumed by any OAuth/SD-JWT verifier.
    ///
    /// # Errors
    /// If JOSE serialization fails.
    pub fn to_status_list_token(&self) -> Result<String> {
        Ok(format!("{}.{}", self.signing_input()?, self.signature))
    }

    /// Parse a compact OAuth Status List Token back into a [`RevocationList`].
    /// **Verify it against the issuer anchor** ([`verify`](Self::verify)) before
    /// trusting it - parsing performs no cryptographic check.
    ///
    /// # Errors
    /// [`AgentCredsError::InvalidRevocationListSignature`] if the token is malformed
    /// or is not a `statuslist+jwt`.
    pub fn from_status_list_token(token: &str) -> Result<Self> {
        let mut parts = token.splitn(3, '.');
        let (h, p, sig) = match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(sig)) if !h.is_empty() && !p.is_empty() && !sig.is_empty() => {
                (h, p, sig)
            }
            _ => return Err(AgentCredsError::InvalidRevocationListSignature),
        };

        let header: serde_json::Value = serde_json::from_slice(&b64url_decode(h)?)
            .map_err(|_| AgentCredsError::InvalidRevocationListSignature)?;
        let payload: serde_json::Value = serde_json::from_slice(&b64url_decode(p)?)
            .map_err(|_| AgentCredsError::InvalidRevocationListSignature)?;

        if header.get("typ").and_then(|v| v.as_str()) != Some(STATUS_LIST_TYP) {
            return Err(AgentCredsError::InvalidRevocationListSignature);
        }
        let str_at = |v: &serde_json::Value, k: &str| -> Result<String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or(AgentCredsError::InvalidRevocationListSignature)
        };

        let issuer = str_at(&header, "kid")?;
        let alg = str_at(&header, "alg")?;
        let id = str_at(&payload, "sub")?;
        let iat = payload
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or(AgentCredsError::InvalidRevocationListSignature)?;
        let updated = Utc
            .timestamp_opt(iat, 0)
            .single()
            .ok_or(AgentCredsError::InvalidRevocationListSignature)?;

        let sl = payload
            .get("status_list")
            .ok_or(AgentCredsError::InvalidRevocationListSignature)?;
        let bits = sl.get("bits").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let encoded_list = str_at(sl, "lst")?;

        // Logical capacity is the bitstring's bit length divided by bits-per-entry.
        let raw_len = Self::decode_and_decompress(&encoded_list)?.len() as u64;
        let size = raw_len.saturating_mul(8) / (bits.max(1) as u64);

        Ok(RevocationList {
            id,
            issuer,
            alg,
            updated,
            size,
            bits,
            encoded_list,
            signature: sig.to_string(),
        })
    }

    /// Revoke the credential at `index`. Re-signs the list.
    pub fn revoke(&mut self, index: u64, anchor: &TrustAnchor) -> Result<()> {
        self.check_index(index)?;
        let mut bits = self.decode_bits()?;
        if index as usize >= bits.len() {
            return Err(AgentCredsError::RevocationIndexOutOfBounds {
                index,
                size: self.size,
            });
        }
        bits.set(index as usize, true);
        self.update_bits(bits, anchor)
    }

    /// Re-sign the list **without changing any bit**, advancing `updated` to now.
    ///
    /// This is the issuer half of R7 bounded staleness
    /// (draft-reece-wimse-cross-org-delegation-01): a relying party must be able to
    /// "fail safe when its revocation information is older than a configured bound".
    /// A verifier can only enforce such a bound if `updated` advances even when
    /// nothing is revoked - otherwise a quiet issuer is indistinguishable from a
    /// frozen one, and any bound eventually denies legitimate traffic.
    ///
    /// Call it on an interval (the issuer's heartbeat). The bit vector is untouched,
    /// so this is safe to run concurrently with issuance: it re-asserts "this is the
    /// current state, as of now", which is precisely the claim staleness bounds rest
    /// on. Costs one anchor signature per call - relevant when the anchor is a KMS or
    /// HSM key, so pick an interval comfortably below the verifier's bound but not so
    /// tight that signing dominates.
    pub fn resign(&mut self, anchor: &TrustAnchor) -> Result<()> {
        self.updated = Utc::now();
        self.sign(anchor)
    }

    /// Un-revoke the credential at `index` (use with care in production).
    pub fn unrevoke(&mut self, index: u64, anchor: &TrustAnchor) -> Result<()> {
        self.check_index(index)?;
        let mut bits = self.decode_bits()?;
        if index as usize >= bits.len() {
            return Err(AgentCredsError::RevocationIndexOutOfBounds {
                index,
                size: self.size,
            });
        }
        bits.set(index as usize, false);
        self.update_bits(bits, anchor)
    }

    /// Check whether credential at `index` is revoked.
    /// Returns `Ok(true)` if revoked, `Ok(false)` if valid.
    pub fn is_revoked(&self, index: u64) -> Result<bool> {
        self.check_index(index)?;
        let bits = self.decode_bits()?;
        Ok(bits.get(index as usize).map_or(false, |b| *b))
    }

    /// Check whether `vc` is revoked by this list, using the credential's status
    /// reference (`status.status_list.{idx, uri}`).
    ///
    /// Returns `Ok(false)` if the credential carries no status entry (not subject to
    /// revocation). This is an **offline** check - verify the list's signature with
    /// [`RevocationList::verify`] first if you don't already trust it.
    ///
    /// # Errors
    /// `InvalidRevocationListSignature` if the credential's status entry points at a
    /// *different* list than this one (`uri != id`); `RevocationIndexOutOfBounds` if
    /// its index is outside this list.
    pub fn is_credential_revoked(&self, vc: &CapabilityCredential) -> Result<bool> {
        let Some(status) = vc.credential_status.as_ref() else {
            return Ok(false);
        };
        if status.status_list_credential != self.id {
            return Err(AgentCredsError::InvalidRevocationListSignature);
        }
        self.is_revoked(status.status_list_index)
    }

    /// Verify the token's JWS signature against the given trust anchor.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        let input = self.signing_input()?;
        let sig_bytes = b64url_decode(&self.signature)?;
        anchor
            .verify_signature(input.as_bytes(), &sig_bytes)
            .map_err(|_| AgentCredsError::InvalidRevocationListSignature)
    }

    /// Reject the list if its signed `updated`/`iat` is older than `max_age` relative
    /// to `now`. This bounds the staleness of the **authentic revocation state
    /// itself** (R7), distinct from any relying-party fetch cache: a cache TTL bounds
    /// only *how recently the list was fetched*, whereas this bounds *how old the
    /// signed state is*. It catches an issuer that has frozen its re-signing pipeline
    /// but keeps serving a validly-signed old list, and a replay of an old-but-valid
    /// list - cases a fetch-recency bound cannot see.
    ///
    /// `now` is supplied by the caller (not read from the clock) to keep the offline
    /// core deterministic and testable. This checks age only; call
    /// [`verify`](Self::verify) for authenticity, or [`verify_fresh`](Self::verify_fresh)
    /// to do both in one call.
    ///
    /// # Errors
    /// [`AgentCredsError::RevocationListStale`] if `now - updated > max_age`.
    pub fn check_fresh(&self, now: DateTime<Utc>, max_age: chrono::Duration) -> Result<()> {
        let age = now.signed_duration_since(self.updated);
        if age > max_age {
            return Err(AgentCredsError::RevocationListStale {
                updated: self.updated.to_rfc3339(),
                age_secs: age.num_seconds().max(0),
                max_age_secs: max_age.num_seconds(),
            });
        }
        Ok(())
    }

    /// Verify the token's signature against `anchor` **and** bound its staleness
    /// against `max_age` (R7 in one call): authenticity plus bounded information age.
    /// Prefer this over [`verify`](Self::verify) on the offline path when the relying
    /// party enforces a maximum revocation-state age.
    ///
    /// # Errors
    /// [`AgentCredsError::InvalidRevocationListSignature`] on a bad signature, or
    /// [`AgentCredsError::RevocationListStale`] if the signed state is too old.
    pub fn verify_fresh(
        &self,
        anchor: &TrustAnchor,
        now: DateTime<Utc>,
        max_age: chrono::Duration,
    ) -> Result<()> {
        self.verify(anchor)?;
        self.check_fresh(now, max_age)
    }

    /// Total number of revoked credentials in this list.
    pub fn revocation_count(&self) -> Result<u64> {
        let bits = self.decode_bits()?;
        Ok(bits.count_ones() as u64)
    }

    /// SHA-256 fingerprint of the current list state.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.id.as_bytes());
        h.update(self.updated.timestamp().to_le_bytes());
        h.update(self.encoded_list.as_bytes());
        hex::encode(h.finalize())
    }

    // -- Private helpers ------------------------------------------------------

    /// The JWS protected header, base64url-encoded. Built from a fixed key set so it
    /// re-derives byte-for-byte on both sign and verify.
    fn header_b64(&self) -> Result<String> {
        let header = json!({ "typ": STATUS_LIST_TYP, "alg": self.alg, "kid": self.issuer });
        Ok(b64url(&serde_json::to_vec(&header)?))
    }

    /// The Status List Token payload, base64url-encoded.
    fn payload_b64(&self) -> Result<String> {
        let payload = json!({
            "sub": self.id,
            "iat": self.updated.timestamp(),
            "status_list": { "bits": self.bits, "lst": self.encoded_list },
        });
        Ok(b64url(&serde_json::to_vec(&payload)?))
    }

    /// `header.payload` - the bytes the JWS signature covers.
    fn signing_input(&self) -> Result<String> {
        Ok(format!("{}.{}", self.header_b64()?, self.payload_b64()?))
    }

    /// Sign (or re-sign) the current state, updating [`signature`](Self::signature).
    fn sign(&mut self, anchor: &TrustAnchor) -> Result<()> {
        let input = self.signing_input()?;
        let sig_bytes = anchor.sign(input.as_bytes())?;
        self.signature = b64url(&sig_bytes);
        Ok(())
    }

    fn check_index(&self, index: u64) -> Result<()> {
        if index >= self.size {
            return Err(AgentCredsError::RevocationIndexOutOfBounds {
                index,
                size: self.size,
            });
        }
        Ok(())
    }

    fn decode_bits(&self) -> Result<BitVec<u8, Msb0>> {
        let bytes = Self::decode_and_decompress(&self.encoded_list)?;
        Ok(BitVec::<u8, Msb0>::from_vec(bytes))
    }

    fn update_bits(&mut self, bits: BitVec<u8, Msb0>, anchor: &TrustAnchor) -> Result<()> {
        let raw = bits.into_vec();
        self.encoded_list = Self::compress_and_encode(&raw)?;
        self.updated = Utc::now();
        self.sign(anchor)
    }

    fn compress_and_encode(raw: &[u8]) -> Result<String> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(raw)
            .map_err(|e| AgentCredsError::CryptoError {
                reason: e.to_string(),
            })?;
        let compressed = encoder.finish().map_err(|e| AgentCredsError::CryptoError {
            reason: e.to_string(),
        })?;
        Ok(b64url(&compressed))
    }

    fn decode_and_decompress(encoded: &str) -> Result<Vec<u8>> {
        let compressed = b64url_decode(encoded)?;
        let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
        let mut raw = Vec::new();
        decoder
            .read_to_end(&mut raw)
            .map_err(|e| AgentCredsError::CryptoError {
                reason: e.to_string(),
            })?;
        Ok(raw)
    }
}

// -- RevocationRegistry --------------------------------------------------------

/// Manages multiple revocation lists for different deployment environments.
/// In production, this is backed by the trust registry service.
#[derive(Debug, Default)]
pub struct RevocationRegistry {
    lists: std::collections::HashMap<String, RevocationList>,
}

impl RevocationRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a revocation list under its ID (URL).
    pub fn register(&mut self, list: RevocationList) {
        self.lists.insert(list.id.clone(), list);
    }

    /// Look up a revocation list by ID (URL).
    pub fn get(&self, list_id: &str) -> Option<&RevocationList> {
        self.lists.get(list_id)
    }

    /// Look up a revocation list mutably.
    pub fn get_mut(&mut self, list_id: &str) -> Option<&mut RevocationList> {
        self.lists.get_mut(list_id)
    }

    /// Check revocation status of a credential.
    pub fn is_revoked(&self, list_id: &str, index: u64, credential_id: &str) -> Result<()> {
        let list = self
            .lists
            .get(list_id)
            .ok_or_else(|| AgentCredsError::DidResolutionFailed {
                did: list_id.to_string(),
                reason: "revocation list not found".into(),
            })?;
        if list.is_revoked(index)? {
            return Err(AgentCredsError::CredentialRevoked {
                credential_id: credential_id.to_string(),
            });
        }
        Ok(())
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::TrustAnchor;

    fn anchor_and_list() -> (TrustAnchor, RevocationList) {
        let anchor = TrustAnchor::generate().unwrap();
        let list =
            RevocationList::new("https://registry.example.com/status/1", &anchor, Some(1024))
                .unwrap();
        (anchor, list)
    }

    #[test]
    fn new_list_has_no_revocations() {
        let (_anchor, list) = anchor_and_list();
        assert!(!list.is_revoked(0).unwrap());
        assert!(!list.is_revoked(1023).unwrap());
        assert_eq!(list.revocation_count().unwrap(), 0);
    }

    #[test]
    fn revoke_and_check() {
        let (anchor, mut list) = anchor_and_list();
        list.revoke(42, &anchor).unwrap();
        assert!(list.is_revoked(42).unwrap());
        assert!(!list.is_revoked(43).unwrap());
        assert_eq!(list.revocation_count().unwrap(), 1);
    }

    #[test]
    fn is_credential_revoked_tracks_status_entry() {
        use crate::did::{AgentIdentity, DidMethod};
        use crate::vc::{CapabilityClaims, CapabilityCredential, CredentialStatus};

        let (anchor, mut list) = anchor_and_list();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let status = CredentialStatus::new("https://registry.example.com/status/1", 7);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, Some(status)).unwrap();

        assert!(!list.is_credential_revoked(&vc).unwrap());
        list.revoke(7, &anchor).unwrap();
        assert!(list.is_credential_revoked(&vc).unwrap());
    }

    #[test]
    fn is_credential_revoked_rejects_wrong_list() {
        use crate::did::{AgentIdentity, DidMethod};
        use crate::vc::{CapabilityClaims, CapabilityCredential, CredentialStatus};

        let (anchor, list) = anchor_and_list();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        // Status entry points at a different list than `list`.
        let status = CredentialStatus::new("https://registry.example.com/status/OTHER", 7);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, Some(status)).unwrap();
        assert!(list.is_credential_revoked(&vc).is_err());
    }

    #[test]
    fn is_credential_revoked_false_without_status() {
        use crate::did::{AgentIdentity, DidMethod};
        use crate::vc::{CapabilityClaims, CapabilityCredential};

        let (anchor, list) = anchor_and_list();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        assert!(!list.is_credential_revoked(&vc).unwrap());
    }

    #[test]
    fn unrevoke_restores_valid() {
        let (anchor, mut list) = anchor_and_list();
        list.revoke(10, &anchor).unwrap();
        assert!(list.is_revoked(10).unwrap());
        list.unrevoke(10, &anchor).unwrap();
        assert!(!list.is_revoked(10).unwrap());
    }

    #[test]
    fn list_signature_verifies() {
        let (anchor, list) = anchor_and_list();
        assert!(list.verify(&anchor).is_ok());
    }

    #[test]
    fn wrong_anchor_fails_verification() {
        let (_, list) = anchor_and_list();
        let wrong_anchor = TrustAnchor::generate().unwrap();
        assert!(list.verify(&wrong_anchor).is_err());
    }

    #[test]
    fn status_list_token_round_trips_and_verifies() {
        // The published wire form is a Status List Token; parsing it back and
        // verifying reproduces the same revocation state and authenticity.
        let (anchor, mut list) = anchor_and_list();
        list.revoke(9, &anchor).unwrap();

        let token = list.to_status_list_token().unwrap();
        assert_eq!(
            token.matches('.').count(),
            2,
            "compact JWS has three segments"
        );

        let parsed = RevocationList::from_status_list_token(&token).unwrap();
        parsed.verify(&anchor).unwrap();
        assert!(parsed.is_revoked(9).unwrap());
        assert!(!parsed.is_revoked(10).unwrap());
        assert_eq!(parsed.id, list.id);
        assert_eq!(parsed.issuer, list.issuer);
    }

    #[test]
    fn status_list_token_is_oauth_shaped() {
        // typ=statuslist+jwt and an OAuth `status_list` claim with a 1-bit `lst`.
        let (_anchor, list) = anchor_and_list();
        let token = list.to_status_list_token().unwrap();
        let mut seg = token.split('.');
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(seg.next().unwrap()).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(seg.next().unwrap()).unwrap()).unwrap();

        assert_eq!(header["typ"], STATUS_LIST_TYP);
        assert_eq!(payload["sub"], list.id);
        assert_eq!(payload["status_list"]["bits"], 1);
        assert!(payload["status_list"]["lst"].is_string());
        assert!(
            payload["status"].is_null(),
            "not the W3C StatusList2021 document shape"
        );
    }

    #[test]
    fn malformed_token_is_rejected() {
        assert!(RevocationList::from_status_list_token("not-a-token").is_err());
        assert!(RevocationList::from_status_list_token("only.two").is_err());
        // A non-status-list JWS (wrong typ) is rejected.
        let bad_header = b64url(br#"{"typ":"JWT","alg":"EdDSA","kid":"did:x"}"#);
        let bad = format!("{bad_header}.e30.AAAA");
        assert!(RevocationList::from_status_list_token(&bad).is_err());
    }

    #[test]
    fn revoked_bit_cannot_be_forged_valid() {
        let (anchor, mut list) = anchor_and_list();
        list.revoke(42, &anchor).unwrap();
        assert!(list.verify(&anchor).is_ok());
        assert!(list.is_revoked(42).unwrap());

        // Clear the revoked bit in the signed bitstring without the anchor key.
        // The tampered list must not verify: a revoked authority cannot be made to
        // appear valid (R7 authenticity).
        let mut forged = list.clone();
        let mut bytes = forged.encoded_list.clone().into_bytes();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        forged.encoded_list = String::from_utf8(bytes).unwrap();
        assert!(
            forged.verify(&anchor).is_err(),
            "a tampered revocation bitstring must fail verification"
        );
    }

    #[test]
    fn signed_timestamp_is_tamper_evident() {
        let (anchor, list) = anchor_and_list();
        assert!(list.verify(&anchor).is_ok());

        // `iat` is part of the signed payload, so `updated` cannot be back- or
        // forward-dated to spoof freshness. A relying party's bounded-staleness
        // decision (R7) rests on an authentic age signal.
        let mut backdated = list.clone();
        backdated.updated = list.updated - chrono::Duration::days(30);
        assert!(backdated.verify(&anchor).is_err());

        let mut forwarded = list.clone();
        forwarded.updated = list.updated + chrono::Duration::days(30);
        assert!(forwarded.verify(&anchor).is_err());
    }

    #[test]
    fn tampered_alg_or_issuer_fails_verification() {
        // The JWS header (alg, kid) is covered by the signature.
        let (anchor, list) = anchor_and_list();
        let mut a = list.clone();
        a.alg = "ES256".into();
        assert!(a.verify(&anchor).is_err());
        let mut i = list.clone();
        i.issuer = "did:key:zAttacker".into();
        assert!(i.verify(&anchor).is_err());
    }

    #[test]
    fn fresh_list_passes_verify_fresh() {
        let (anchor, list) = anchor_and_list();
        let now = list.updated + chrono::Duration::seconds(10);
        assert!(list
            .verify_fresh(&anchor, now, chrono::Duration::seconds(60))
            .is_ok());
    }

    #[test]
    fn stale_but_valid_list_is_rejected() {
        // R7 (bounded staleness of the signed state): a *validly-signed* list whose
        // signed `iat` is older than the relying party's configured bound must be
        // rejected - even though its signature verifies and it was just fetched.
        let (anchor, list) = anchor_and_list();
        let max_age = chrono::Duration::seconds(60);
        let now = list.updated + chrono::Duration::seconds(120); // 2x max age

        assert!(list.verify(&anchor).is_ok(), "signature is still authentic");
        assert!(
            matches!(
                list.check_fresh(now, max_age),
                Err(AgentCredsError::RevocationListStale { .. })
            ),
            "an authentic but too-old list must fail the freshness gate"
        );
        assert!(
            matches!(
                list.verify_fresh(&anchor, now, max_age),
                Err(AgentCredsError::RevocationListStale { .. })
            ),
            "verify_fresh must fail closed on a too-old (but validly signed) list"
        );
    }

    #[test]
    fn verify_fresh_still_catches_bad_signature() {
        let (_anchor, list) = anchor_and_list();
        let wrong = TrustAnchor::generate().unwrap();
        let now = list.updated + chrono::Duration::seconds(1);
        assert!(matches!(
            list.verify_fresh(&wrong, now, chrono::Duration::seconds(60)),
            Err(AgentCredsError::InvalidRevocationListSignature)
        ));
    }

    #[test]
    fn out_of_bounds_index_rejected() {
        let (anchor, mut list) = anchor_and_list();
        assert!(matches!(
            list.revoke(9999, &anchor),
            Err(AgentCredsError::RevocationIndexOutOfBounds { .. })
        ));
    }

    // The *read* path must also bounds-check, not silently return "not revoked" for an
    // out-of-range index. (revoke() errors downstream on a bad bit-set even without the
    // guard; is_revoked() would quietly answer `false` - a fail-open - so it needs its
    // own assertion.) `size` is the first out-of-range index.
    #[test]
    fn is_revoked_rejects_out_of_bounds_index() {
        let (_anchor, list) = anchor_and_list();
        assert!(matches!(
            list.is_revoked(list.size),
            Err(AgentCredsError::RevocationIndexOutOfBounds { .. })
        ));
        assert!(
            list.is_revoked(u64::MAX).is_err(),
            "a wildly out-of-range read must error, never return false"
        );
        // unrevoke shares the same gate.
        let (anchor, mut list) = anchor_and_list();
        assert!(list.unrevoke(list.size, &anchor).is_err());
    }

    // Freshness bound is strictly-greater: a list whose signed age is *exactly* the
    // maximum is still fresh. (Guards against a `>`->`>=` slip that would reject a list
    // at the boundary.) `now` is caller-supplied, so this boundary is deterministic.
    #[test]
    fn freshness_bound_is_inclusive_at_the_edge() {
        let (_anchor, list) = anchor_and_list();
        let max_age = chrono::Duration::seconds(60);
        assert!(
            list.check_fresh(list.updated + max_age, max_age).is_ok(),
            "age exactly at max_age must pass"
        );
        assert!(
            list.check_fresh(
                list.updated + max_age + chrono::Duration::seconds(1),
                max_age
            )
            .is_err(),
            "one second past max_age must fail"
        );
    }

    // The list carries a real JWS `alg` (from the anchor's key type), not an empty or
    // junk string - a verifier keys off it, and the signed header embeds it.
    #[test]
    fn list_carries_a_real_jws_alg() {
        let (_anchor, list) = anchor_and_list();
        assert!(
            list.alg == "EdDSA" || list.alg == "ES256",
            "alg must be a valid JWS algorithm, got {:?}",
            list.alg
        );
    }

    // A Status List Token with an empty segment must be rejected at parse. This matters
    // most for an empty *signature* part: the signature is stored raw (never re-parsed),
    // so without the structural guard a `header.payload.` token would parse into a list
    // with an empty signature - deferring detection to a later verify() that a caller
    // might skip. The parse must fail closed here.
    #[test]
    fn from_status_list_token_rejects_empty_segments() {
        let (_anchor, list) = anchor_and_list();
        let token = list.to_status_list_token().unwrap();
        let (header_payload, _sig) = token.rsplit_once('.').unwrap();

        // Empty signature segment ("header.payload.").
        assert!(
            RevocationList::from_status_list_token(&format!("{header_payload}.")).is_err(),
            "an empty signature segment must be rejected at parse"
        );
        // Empty header/payload segments too.
        assert!(RevocationList::from_status_list_token("..sig").is_err());
        assert!(RevocationList::from_status_list_token("h..sig").is_err());
    }

    #[test]
    fn multiple_revocations() {
        let (anchor, mut list) = anchor_and_list();
        for i in [0u64, 7, 63, 100, 511, 1023] {
            list.revoke(i, &anchor).unwrap();
        }
        assert_eq!(list.revocation_count().unwrap(), 6);
        for i in [0u64, 7, 63, 100, 511, 1023] {
            assert!(list.is_revoked(i).unwrap(), "index {} should be revoked", i);
        }
        assert!(!list.is_revoked(1).unwrap());
    }

    #[test]
    fn registry_revocation_check() {
        let (anchor, mut list) = anchor_and_list();
        list.revoke(5, &anchor).unwrap();
        let list_id = list.id.clone();

        let mut registry = RevocationRegistry::new();
        registry.register(list);

        assert!(registry.is_revoked(&list_id, 5, "urn:vc:test").is_err());
        assert!(registry.is_revoked(&list_id, 6, "urn:vc:test").is_ok());
    }

    #[test]
    fn invalid_base64_signature_fails_verify() {
        let (anchor, mut list) = anchor_and_list();
        list.signature = "!!!not_base64!!!".to_string();
        assert!(matches!(
            list.verify(&anchor),
            Err(AgentCredsError::InvalidRevocationListSignature)
        ));
    }

    #[test]
    fn fingerprint_changes_after_revocation() {
        let (anchor, mut list) = anchor_and_list();
        let fp_before = list.fingerprint();
        list.revoke(42, &anchor).unwrap();
        let fp_after = list.fingerprint();
        assert_ne!(fp_before, fp_after);
    }

    #[test]
    fn revocation_registry_get_returns_none_for_unknown() {
        let registry = RevocationRegistry::new();
        assert!(registry.get("https://unknown.example.com/list").is_none());
    }

    #[test]
    fn revocation_registry_get_returns_list_after_register() {
        let (anchor, list) = anchor_and_list();
        let list_id = list.id.clone();
        let mut registry = RevocationRegistry::new();
        registry.register(list);
        assert!(registry.get(&list_id).is_some());
        assert_eq!(registry.get(&list_id).unwrap().id, list_id);
        assert!(registry.get(&list_id).unwrap().verify(&anchor).is_ok());
    }

    #[test]
    fn revocation_count_zero_on_new_list() {
        let (_anchor, list) = anchor_and_list();
        assert_eq!(list.revocation_count().unwrap(), 0);
    }

    #[test]
    fn get_mut_allows_revocation_via_registry() {
        let (anchor, list) = anchor_and_list();
        let list_id = list.id.clone();
        let mut registry = RevocationRegistry::new();
        registry.register(list);
        registry
            .get_mut(&list_id)
            .unwrap()
            .revoke(7, &anchor)
            .unwrap();
        assert!(registry.is_revoked(&list_id, 7, "urn:vc:test").is_err());
    }

    #[test]
    fn json_container_still_round_trips_for_storage() {
        // The internal at-rest JSON container (used by the control-plane store) still
        // round-trips and verifies - the token is the *published* form, not the only one.
        let (anchor, mut list) = anchor_and_list();
        list.revoke(3, &anchor).unwrap();
        let json = list.to_json().unwrap();
        let back = RevocationList::from_json(&json).unwrap();
        assert!(back.verify(&anchor).is_ok());
        assert!(back.is_revoked(3).unwrap());
    }
}
