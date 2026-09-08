//! Interop facade - the **stable contract a per-standard wrapper builds against**.
//!
//! The objective this module serves: put a thin wrapper around AgentCreds to match
//! whichever credential standard a vendor speaks in their own environment
//! (OpenID4VP, ISO mdoc, DIDComm, ...) *without* the wrapper reaching into core
//! internals and *without* the offline authority core (Biscuit attenuation, PoP,
//! one-time reliance, dual-axis) ever moving.
//!
//! # The division of labour
//!
//! A vendor standard is a **stack**, not just a credential format. This facade owns
//! only the parts that belong in the offline core; the wrapper owns the rest:
//!
//! | Concern                     | Owner                         |
//! |-----------------------------|-------------------------------|
//! | Credential *format*         | core - [`CredentialFormat`] (W3C + SD-JWT VC) |
//! | Selective disclosure + holder binding | core - this facade's [`CredentialPresenter`] |
//! | Issuer-signature verification | core - this facade's [`CredentialVerifier`] |
//! | Presentation *protocol* (OpenID4VP request/response, mdoc device engagement) | **wrapper** |
//! | Issuer *trust model* (did:key <-> x5c <-> OIDC federation <-> registry) | **wrapper**, via [`TrustMap`] |
//! | Claim *schema* mapping to the vendor's names/shapes | **wrapper**, via [`ClaimMap`] |
//!
//! So a vendor wrapper is: `{protocol envelope} + impl `[`TrustMap`]` + impl
//! `[`ClaimMap`]`, composed over `[`NativeInterop`]`. The three ports below -
//! [`CredentialIssuer`], [`CredentialPresenter`], [`CredentialVerifier`] - are the
//! only surface it needs, and they are format-agnostic: the same wrapper works
//! whether the credential is issued as W3C or SD-JWT VC.
//!
//! # What this facade deliberately does *not* do
//!
//! It does not speak any wire protocol and it opens no sockets - protocol and
//! transport live in a layer above the core, never inside it.
//! It also does not decide authority: after [`CredentialVerifier::verify_credential`]
//! authenticates the credential, the caller still roots and evaluates the delegation
//! token ([`crate::delegation`]) exactly as before. The credential is the anchor; the
//! Biscuit is the bearer.

use crate::did::{AgentIdentity, TrustAnchor};
use crate::error::AgentCredsError;
use crate::vc::{CapabilityClaims, CapabilityCredential, CredentialFormat, CredentialStatus};
use crate::Result;

// -- Request / result value types (the stable data on the wire of the port) ------

/// A verifier's challenge for holder-of-key: the presentation's KB-JWT is bound to
/// this `audience` and `nonce`. Present only when the verifier demands proof that
/// the presenter controls the credential's confirmation key.
#[derive(Debug, Clone, Copy)]
pub struct KeyBindingChallenge<'a> {
    /// The verifier's identifier the KB-JWT is bound to (`aud`).
    pub audience: &'a str,
    /// The verifier's freshness challenge, echoed in the KB-JWT (`nonce`).
    pub nonce: &'a str,
}

/// What a verifier asks a holder to present: which selectively-disclosable claims to
/// reveal, and an optional holder-of-key challenge.
///
/// `disclose` is honoured only by formats that *support* selective disclosure
/// (SD-JWT VC); a W3C credential carries all its claims unconditionally, so the field
/// is moot there. `key_binding` requires a holder-of-key-capable format - requesting
/// it against W3C is a hard error rather than a silent no-op.
#[derive(Debug, Clone)]
pub struct PresentationRequest<'a> {
    /// Names of selectively-disclosable claims the verifier is allowed to see.
    pub disclose: &'a [&'a str],
    /// Holder-of-key challenge, or `None` for a plain presentation.
    pub key_binding: Option<KeyBindingChallenge<'a>>,
}

impl<'a> PresentationRequest<'a> {
    /// A plain presentation: disclose the given claims, no holder binding.
    pub fn disclosing(disclose: &'a [&'a str]) -> Self {
        Self {
            disclose,
            key_binding: None,
        }
    }

    /// A holder-bound presentation: disclose the given claims and prove control of the
    /// confirmation key against `audience`/`nonce`.
    pub fn bound(disclose: &'a [&'a str], audience: &'a str, nonce: &'a str) -> Self {
        Self {
            disclose,
            key_binding: Some(KeyBindingChallenge { audience, nonce }),
        }
    }
}

/// The outcome of verifying a presented credential: the authenticated credential and
/// whether a holder-of-key binding was proved. The caller proceeds to root/evaluate
/// the delegation token; this type asserts only that the *credential* is genuine.
#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    /// The credential, with its issuer signature (and disclosures) authenticated.
    pub credential: CapabilityCredential,
    /// `true` iff the request carried a [`KeyBindingChallenge`] and the KB-JWT verified.
    pub key_binding_verified: bool,
}

// -- The three ports -------------------------------------------------------------

/// Issue a capability credential in a target wire format. The control-plane side of
/// the seam; a wrapper calls this to mint in whatever format the consuming ecosystem
/// expects, then serves it via that ecosystem's issuance protocol (e.g. OpenID4VCI).
pub trait CredentialIssuer {
    /// Mint a credential for `subject_did` in `format`, signed by `anchor`.
    fn issue_credential(
        &self,
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: CapabilityClaims,
        status: Option<CredentialStatus>,
        format: CredentialFormat,
    ) -> Result<CapabilityCredential>;
}

/// Produce a wire-form presentation (selective disclosure + optional holder binding)
/// from a held credential. The holder side of the seam; a wrapper embeds the returned
/// string in the vendor's presentation response (e.g. an OpenID4VP `vp_token`).
pub trait CredentialPresenter {
    /// Build a wire-form presentation of `credential` for `request`, signed for
    /// holder binding (where the format supports it) by `holder`.
    fn present_credential(
        &self,
        credential: &CapabilityCredential,
        holder: &AgentIdentity,
        request: &PresentationRequest,
    ) -> Result<String>;
}

/// Verify a presented credential in any supported format (auto-detected from the
/// wire). The verifier side of the seam; a wrapper calls this after unwrapping the
/// vendor's presentation envelope, having first resolved the issuer anchor via a
/// [`TrustMap`].
pub trait CredentialVerifier {
    /// Authenticate a presented credential against `anchor` (issuer signature,
    /// disclosures, and - when `key_binding` is set - holder-of-key).
    fn verify_credential(
        &self,
        wire: &str,
        anchor: &TrustAnchor,
        key_binding: Option<KeyBindingChallenge>,
    ) -> Result<VerifiedCredential>;
}

// -- The two data-driven seams a wrapper fills -----------------------------------

/// Maps AgentCreds claim names/shapes onto a vendor's expected schema, and back.
/// Keep wrappers data-driven: a vendor adapter supplies a concrete map instead of
/// bespoke per-vendor code. The default ([`IdentityClaimMap`]) does no remapping.
pub trait ClaimMap {
    /// AgentCreds claims -> the vendor's outward schema (issuance / presentation).
    fn map_out(&self, claims: &serde_json::Value) -> serde_json::Value {
        claims.clone()
    }
    /// The vendor's inward schema -> AgentCreds claims (verification).
    fn map_in(&self, claims: &serde_json::Value) -> serde_json::Value {
        claims.clone()
    }
}

/// The identity claim map - no remapping. AgentCreds claim names are already the
/// intended outward names; a wrapper overrides only where a vendor differs.
#[derive(Debug, Default, Clone, Copy)]
pub struct IdentityClaimMap;
impl ClaimMap for IdentityClaimMap {}

/// Resolves an issuer identifier - *as the vendor's protocol names it* - to the
/// verifying [`TrustAnchor`]. This is where a wrapper bridges AgentCreds' trust model
/// (offline `did:key`, or a signed trust registry) to the vendor's (x5c chains, OIDC
/// federation, a wallet trust list). A verifier resolves the issuer here *before*
/// calling [`CredentialVerifier::verify_credential`].
pub trait TrustMap {
    /// Resolve an issuer identifier (as the vendor's protocol names it) to the
    /// verifying anchor, or error if the issuer is not trusted.
    fn resolve_issuer(&self, issuer: &str) -> Result<TrustAnchor>;
}

/// The offline cross-org trust model: the issuer identifier *is* a `did:key`, so its
/// verifying key is self-certifying and needs no network round-trip. This is
/// AgentCreds' native posture; a wrapper substitutes an x5c/OIDC-federation resolver
/// when a vendor's verifier expects one of those instead.
#[derive(Debug, Default, Clone, Copy)]
pub struct DidKeyTrust;
impl TrustMap for DidKeyTrust {
    fn resolve_issuer(&self, issuer: &str) -> Result<TrustAnchor> {
        TrustAnchor::from_did_key(issuer)
    }
}

// -- NativeInterop: the wired default over both format impls ----------------------

/// The native AgentCreds implementation of all three ports, wiring the W3C and
/// SD-JWT VC format impls behind the stable contract. A wrapper composes this with
/// its own [`TrustMap`]/[`ClaimMap`] and protocol envelope - it should not need to
/// reimplement any of these methods, only wrap them.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeInterop;

impl CredentialIssuer for NativeInterop {
    fn issue_credential(
        &self,
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: CapabilityClaims,
        status: Option<CredentialStatus>,
        format: CredentialFormat,
    ) -> Result<CapabilityCredential> {
        CapabilityCredential::issue_as(anchor, subject_did, claims, status, format)
    }
}

impl CredentialPresenter for NativeInterop {
    fn present_credential(
        &self,
        credential: &CapabilityCredential,
        holder: &AgentIdentity,
        request: &PresentationRequest,
    ) -> Result<String> {
        match credential.format {
            // W3C carries every claim and has no holder-of-key mechanism: `disclose`
            // is moot, and a key-binding request is a capability mismatch, not a no-op.
            CredentialFormat::W3cLinkedData => {
                if request.key_binding.is_some() {
                    return Err(AgentCredsError::InvalidVcProof {
                        reason: "W3C credentials have no holder-of-key binding; issue \
                                 as SD-JWT VC to satisfy a key-binding challenge"
                            .into(),
                    });
                }
                credential.to_wire()
            }
            CredentialFormat::SdJwtVc => {
                #[cfg(feature = "sd-jwt")]
                {
                    match request.key_binding {
                        Some(kb) => credential.present_with_key_binding(
                            holder,
                            kb.audience,
                            kb.nonce,
                            request.disclose,
                        ),
                        None => credential.present_sd_jwt(request.disclose),
                    }
                }
                #[cfg(not(feature = "sd-jwt"))]
                {
                    let _ = holder;
                    Err(AgentCredsError::InvalidVcProof {
                        reason: "presenting an SD-JWT VC requires the `sd-jwt` feature".into(),
                    })
                }
            }
        }
    }
}

impl CredentialVerifier for NativeInterop {
    fn verify_credential(
        &self,
        wire: &str,
        anchor: &TrustAnchor,
        key_binding: Option<KeyBindingChallenge>,
    ) -> Result<VerifiedCredential> {
        // Auto-detect the format from the wire, then authenticate the issuer signature
        // (strict: the credential's issuer must be the anchor we resolved via TrustMap).
        let credential = CapabilityCredential::from_wire(wire)?;
        credential.verify(anchor, true)?;

        // The only assignment below sits behind `sd-jwt`; without that feature the
        // `Some` arm returns early instead, so the binding is never mutated and `mut`
        // is genuinely dead. It is still required when the feature is on, hence the
        // conditional allow rather than dropping `mut` or restructuring.
        #[cfg_attr(not(feature = "sd-jwt"), allow(unused_mut))]
        let mut key_binding_verified = false;
        if let Some(kb) = key_binding {
            #[cfg(feature = "sd-jwt")]
            {
                credential.verify_key_binding(kb.audience, kb.nonce)?;
                key_binding_verified = true;
            }
            #[cfg(not(feature = "sd-jwt"))]
            {
                let _ = kb;
                return Err(AgentCredsError::InvalidVcProof {
                    reason: "verifying a key-bound presentation requires the `sd-jwt` feature"
                        .into(),
                });
            }
        }

        Ok(VerifiedCredential {
            credential,
            key_binding_verified,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
    use crate::vc::CapabilityClaims;

    fn claims() -> CapabilityClaims {
        let mut c = CapabilityClaims::new(vec!["tool:search".into()], 3, 3600);
        c.model_version = Some("gpt-x-2026".into());
        c
    }

    // The facade round-trips a W3C credential: issue -> present -> verify, all through
    // the ports, with no format knowledge at the call site.
    #[test]
    fn facade_round_trips_w3c() {
        let anchor = TrustAnchor::generate().unwrap();
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let io = NativeInterop;

        let cred = io
            .issue_credential(
                &anchor,
                holder.did(),
                claims(),
                None,
                CredentialFormat::W3cLinkedData,
            )
            .unwrap();

        let wire = io
            .present_credential(&cred, &holder, &PresentationRequest::disclosing(&[]))
            .unwrap();

        let verified = io.verify_credential(&wire, &anchor, None).unwrap();
        assert_eq!(verified.credential.format, CredentialFormat::W3cLinkedData);
        assert!(!verified.key_binding_verified);
    }

    // Asking for a holder-of-key binding against a W3C credential is a hard error, not
    // a silent no-op - the wrapper learns it must issue SD-JWT VC to satisfy the verifier.
    #[test]
    fn w3c_rejects_a_key_binding_request() {
        let anchor = TrustAnchor::generate().unwrap();
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let io = NativeInterop;
        let cred = io
            .issue_credential(
                &anchor,
                holder.did(),
                claims(),
                None,
                CredentialFormat::W3cLinkedData,
            )
            .unwrap();

        let req = PresentationRequest::bound(&[], "https://verifier.example", "n-42");
        assert!(io.present_credential(&cred, &holder, &req).is_err());
    }

    // The DidKeyTrust seam resolves a did:key issuer to a verify-only anchor with no
    // network round-trip - AgentCreds' native offline cross-org trust posture. A
    // did:key holder identity carries its verifying key inline, so resolution is local.
    #[test]
    fn did_key_trust_resolves_did_key_issuer_offline() {
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert!(holder.did().starts_with("did:key"));
        let resolved = DidKeyTrust.resolve_issuer(holder.did()).unwrap();
        assert_eq!(resolved.did(), holder.did());
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn facade_round_trips_sd_jwt_vc_with_key_binding() {
        let anchor = TrustAnchor::generate().unwrap();
        // Subject == holder: the confirmation key is the holder's did:key.
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let io = NativeInterop;

        let cred = io
            .issue_credential(
                &anchor,
                holder.did(),
                claims(),
                None,
                CredentialFormat::SdJwtVc,
            )
            .unwrap();
        assert_eq!(cred.format, CredentialFormat::SdJwtVc);

        // Disclose model_version, prove holder-of-key against the verifier's challenge.
        let req =
            PresentationRequest::bound(&["model_version"], "https://verifier.example", "nonce-xyz");
        let wire = io.present_credential(&cred, &holder, &req).unwrap();

        let verified = io
            .verify_credential(
                &wire,
                &anchor,
                Some(KeyBindingChallenge {
                    audience: "https://verifier.example",
                    nonce: "nonce-xyz",
                }),
            )
            .unwrap();
        assert_eq!(verified.credential.format, CredentialFormat::SdJwtVc);
        assert!(verified.key_binding_verified);
    }

    #[test]
    fn identity_claim_map_is_actually_the_identity() {
        // MUTATION-DRIVEN. The trait's default `map_out`/`map_in` bodies could be
        // replaced with `-> Value::Null` and nothing failed: every existing test drives
        // the wrapper flow, where the mapped value feeds a verifier that has its own
        // assertions, but none pinned the MAP itself. For the documented "does no
        // remapping" default of the stable wrapper contract, identity must be an
        // assertion, not a comment - a vendor adapter relying on the default would
        // otherwise silently map every claim to null.
        let claims = serde_json::json!({
            "tools": ["tool:search"],
            "nested": { "budget_usd": 100, "arr": [1, 2, 3] },
            "empty": {},
        });
        let map = IdentityClaimMap;
        assert_eq!(map.map_out(&claims), claims, "map_out must be the identity");
        assert_eq!(map.map_in(&claims), claims, "map_in must be the identity");
        // Round-tripping through both directions is also the identity.
        assert_eq!(map.map_in(&map.map_out(&claims)), claims);
    }
}
