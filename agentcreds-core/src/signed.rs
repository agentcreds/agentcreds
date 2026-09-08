//! Shared handling for **anchor-signed, versioned, bounded-staleness artifacts**
//! - the trust registry config and the approver directory.
//!
//! One place to (a) encode/decode a signature in the crate-wide encoding
//! (base64), and (b) run the fail-closed "issuer matches + signature verifies +
//! not expired" check. Keeping this here removes the copy-paste that had already
//! let two configs drift to different signature encodings.

use base64ct::Encoding;
use chrono::{DateTime, Utc};

use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

/// Encode a signature over an anchor-signed artifact - base64, the crate-wide
/// convention (matches credential proofs, revocation lists, and audit commitments).
pub(crate) fn encode_signature(sig: &[u8]) -> String {
    base64ct::Base64::encode_string(sig)
}

/// Decode an artifact signature, labeling the artifact in any error.
pub(crate) fn decode_signature(signature: &str, label: &str) -> Result<Vec<u8>> {
    base64ct::Base64::decode_vec(signature).map_err(|e| AgentCredsError::InvalidVcProof {
        reason: format!("{label} signature base64: {e}"),
    })
}

/// Verify an anchor-signed artifact, fail-closed: `issuer_did` must equal the
/// anchor's DID, the base64 `signature` must verify over `digest`, and - when
/// `not_after` is set - the artifact must not be past it at `now`. `label` names
/// the artifact in error messages (e.g. `"trust config"`, `"approver directory"`).
///
/// # Errors
/// [`AgentCredsError::InvalidVcProof`] on an issuer mismatch, a bad signature, or
/// an expired artifact.
pub(crate) fn verify_anchor_signed(
    issuer_did: &str,
    digest: &[u8],
    signature: &str,
    not_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    anchor: &TrustAnchor,
    label: &str,
) -> Result<()> {
    if issuer_did != anchor.did() {
        return Err(AgentCredsError::InvalidVcProof {
            reason: format!("{label} issuer does not match the anchor"),
        });
    }
    let sig = decode_signature(signature, label)?;
    anchor
        .verify_signature(digest, &sig)
        .map_err(|_| AgentCredsError::InvalidVcProof {
            reason: format!("{label} signature does not verify"),
        })?;
    if let Some(t) = not_after {
        if now > t {
            return Err(AgentCredsError::InvalidVcProof {
                reason: format!("{label} expired at {}", t.to_rfc3339()),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // This module is the ONE shared fail-closed check for every anchor-signed fetched
    // artifact, and until 2026-09-06 it had no tests of its own - its coverage came
    // entirely from the trust-config and approver-directory suites exercising it
    // indirectly. For the function whose doc comment says "fail-closed", each closed
    // door deserves a direct assertion: an indirect caller pins its own behaviour, not
    // this contract.

    fn anchor() -> TrustAnchor {
        TrustAnchor::generate().unwrap()
    }

    fn signed(anchor: &TrustAnchor, digest: &[u8]) -> String {
        encode_signature(&anchor.sign(digest).unwrap())
    }

    #[test]
    fn a_correctly_signed_artifact_verifies() {
        let a = anchor();
        let digest = b"artifact-digest";
        let sig = signed(&a, digest);
        assert!(verify_anchor_signed(a.did(), digest, &sig, None, Utc::now(), &a, "test").is_ok());
    }

    #[test]
    fn issuer_mismatch_is_refused_before_the_signature_is_even_decoded() {
        // The issuer check runs first, so even a syntactically hopeless signature must
        // produce the ISSUER error - proving the check order, not just the outcome.
        let a = anchor();
        let err = verify_anchor_signed(
            "did:key:zSomeoneElse",
            b"digest",
            "not-even-base64!",
            None,
            Utc::now(),
            &a,
            "test artifact",
        )
        .unwrap_err();
        match err {
            AgentCredsError::InvalidVcProof { reason } => assert!(
                reason.contains("issuer does not match"),
                "expected the issuer error, got: {reason}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn undecodable_and_wrong_signatures_are_both_refused() {
        let a = anchor();
        let digest = b"digest";

        // Not base64 at all.
        assert!(verify_anchor_signed(a.did(), digest, "%%%", None, Utc::now(), &a, "t").is_err());
        // Valid base64, signed by a DIFFERENT anchor - decodes fine, must still fail.
        let stranger = anchor();
        let forged = signed(&stranger, digest);
        assert!(verify_anchor_signed(a.did(), digest, &forged, None, Utc::now(), &a, "t").is_err());
        // Signed by the right anchor over a DIFFERENT digest.
        let other = signed(&a, b"other-digest");
        assert!(verify_anchor_signed(a.did(), digest, &other, None, Utc::now(), &a, "t").is_err());
    }

    #[test]
    fn expiry_boundary_is_exclusive_and_deterministically_pinned() {
        // `now > t` - an artifact is valid AT its not_after instant and invalid one
        // nanosecond later. Elsewhere this exact boundary had to be accepted as an
        // equivalent mutant twice (delegation/mod.rs:915, sd_jwt.rs:368) because those
        // paths read the wall clock internally. THIS function takes `now` as a
        // parameter, so here the boundary is pinned exactly - which is the argument for
        // threading a clock seam through the others.
        let a = anchor();
        let digest = b"digest";
        let sig = signed(&a, digest);
        let t = Utc::now();

        let at = |now| verify_anchor_signed(a.did(), digest, &sig, Some(t), now, &a, "t");
        assert!(at(t).is_ok(), "valid AT the not_after instant");
        assert!(
            at(t - chrono::Duration::nanoseconds(1)).is_ok(),
            "valid just before"
        );
        assert!(
            at(t + chrono::Duration::nanoseconds(1)).is_err(),
            "invalid one nanosecond past"
        );
    }

    #[test]
    fn no_not_after_means_no_expiry_check() {
        let a = anchor();
        let digest = b"digest";
        let sig = signed(&a, digest);
        let far_future = Utc::now() + chrono::Duration::days(365 * 200);
        assert!(
            verify_anchor_signed(a.did(), digest, &sig, None, far_future, &a, "t").is_ok(),
            "with not_after unset, no instant is too late"
        );
    }

    #[test]
    fn the_error_names_the_artifact() {
        // `label` exists so an operator staring at a log knows WHICH fetched artifact
        // failed - the whole point of centralising this. Pin it into every branch.
        let a = anchor();
        for (issuer, sig, not_after, now) in [
            ("did:key:zWrong", "AAAA", None, Utc::now()),
            (a.did(), "%%%", None, Utc::now()),
            (
                a.did(),
                "AAAA",
                Some(Utc::now() - chrono::Duration::hours(1)),
                Utc::now(),
            ),
        ] {
            let err =
                verify_anchor_signed(issuer, b"d", sig, not_after, now, &a, "approver directory")
                    .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("approver directory"),
                "error must name the artifact: {msg}"
            );
        }
    }

    #[test]
    fn signature_encoding_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            decode_signature(&encode_signature(&bytes), "t").unwrap(),
            bytes
        );
    }
}
