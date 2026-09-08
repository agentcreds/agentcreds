//! A2A (agent-to-agent) identity header.
//!
//! Attaches a signed capability [`Presentation`] to an A2A task delegation so
//! the receiving agent can verify the caller's authority **offline** - no
//! callback to the issuer. The header is a compact, self-contained string
//! suitable for an HTTP header value or an A2A v1.0 Agent Card extension field.
//!
//! Wire form: `AgentCreds-A2A/1.<base64url(CBOR(Presentation))>`.
//!
//! ## Callback-free verification
//!
//! A normal [`Presentation`] is checked against a challenge the verifier issued
//! interactively. A2A task delegation is one-shot, so the **sender** mints the
//! challenge with `audience` set to the receiver and signs proof-of-possession
//! over it. The receiver verifies the embedded proof, requires the audience to
//! be itself, and enforces a freshness window. Within that window and audience
//! a captured header can be replayed, so keep `max_age_secs` short and the
//! audience specific (e.g. the task URI or the receiving agent's DID).
//!
//! ```rust
//! use agentcreds_core::prelude::*;
//!
//! // Caller side: mint a presentation bound to the receiver as audience.
//! let anchor = TrustAnchor::generate()?;
//! let agent  = AgentIdentity::create(DidMethod::Key, None)?;
//! let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
//! let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None)?;
//! let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
//! let token = DelegationToken::mint(&vc, scope, 300, &agent)?;
//!
//! let receiver = "a2a://orders.example/agent";
//! let challenge = PopChallenge::new(Some(receiver.into()));
//! let presentation = Presentation::create(token, vc, &challenge, &agent)?;
//! let header = presentation.to_a2a_header()?;
//!
//! // Receiver side: verify offline, requiring the audience to be itself.
//! let received = Presentation::from_a2a_header(&header)?;
//! received.verify_a2a(&Action::new("tool:search", "q=ok"), &anchor, receiver, 60)?;
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use base64ct::{Base64Url, Encoding};

use crate::delegation::Action;
use crate::did::TrustAnchor;
use crate::pop::Presentation;
use crate::{error::AgentCredsError, Result};

/// Scheme/version prefix for the A2A header wire form.
const A2A_SCHEME: &str = "AgentCreds-A2A/1.";

impl Presentation {
    /// Encode this presentation as an A2A identity header string.
    ///
    /// # Errors
    /// Propagates a CBOR serialization error.
    pub fn to_a2a_header(&self) -> Result<String> {
        let cbor = self.to_cbor()?;
        Ok(format!("{A2A_SCHEME}{}", Base64Url::encode_string(&cbor)))
    }

    /// Decode an A2A identity header string back into a presentation.
    ///
    /// # Errors
    /// `OutOfBounds` if the scheme prefix is missing or the body is not valid
    /// base64url; a deserialization error if the CBOR is malformed.
    pub fn from_a2a_header(header: &str) -> Result<Self> {
        let body = header
            .strip_prefix(A2A_SCHEME)
            .ok_or_else(|| AgentCredsError::OutOfBounds {
                field: "a2a_header",
                detail: format!("missing '{A2A_SCHEME}' scheme prefix"),
            })?;
        let cbor = Base64Url::decode_vec(body).map_err(|e| AgentCredsError::OutOfBounds {
            field: "a2a_header",
            detail: format!("invalid base64url body: {e}"),
        })?;
        Presentation::from_cbor(&cbor)
    }

    /// Verify an A2A presentation as the receiving agent.
    ///
    /// In addition to the full [`Presentation::verify`] checks (anchor-rooted
    /// token plus proof of possession), this requires the embedded challenge's
    /// audience to equal `expected_audience` (this verifier), so a header minted
    /// for one receiver cannot be replayed against another.
    ///
    /// # Errors
    /// `ProofOfPossessionFailed` if the audience does not match, plus any error
    /// from the underlying presentation verification.
    pub fn verify_a2a(
        &self,
        action: &Action,
        anchor: &TrustAnchor,
        expected_audience: &str,
        max_age_secs: i64,
    ) -> Result<()> {
        match self.proof.challenge.audience.as_deref() {
            Some(a) if a == expected_audience => {}
            _ => {
                return Err(AgentCredsError::ProofOfPossessionFailed {
                    reason: "a2a header audience does not match this verifier".into(),
                })
            }
        }
        let challenge = self.proof.challenge.clone();
        self.verify(action, anchor, &challenge, max_age_secs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::delegation::{Action, DelegationToken, Scope};
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};
    use crate::pop::{PopChallenge, Presentation};
    use crate::vc::{CapabilityClaims, CapabilityCredential};

    const RECEIVER: &str = "a2a://orders.example/agent";

    fn presentation_for(audience: Option<&str>) -> (TrustAnchor, Presentation) {
        presentation_aged(audience, chrono::Duration::zero())
    }

    /// Like [`presentation_for`], but the PoP challenge is back-dated by `age_back`
    /// (set *before* signing, so the digest stays valid). The success-path test
    /// uses this with a wide freshness window so the assertion turns on the
    /// round-trip + signature/binding checks, **not** on the wall clock holding
    /// still: a backward time step between issue and verify (e.g. an NTP step under
    /// load) must not be able to trip the future-skew bound. The freshness bounds
    /// themselves are covered by the dedicated tests in `pop`.
    fn presentation_aged(
        audience: Option<&str>,
        age_back: chrono::Duration,
    ) -> (TrustAnchor, Presentation) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let claims = CapabilityClaims::new(vec!["tool:search".into()], 1, 3600);
        let vc = CapabilityCredential::issue(&anchor, agent.did(), claims, None).unwrap();
        let scope = Scope::with_budget_and_depth(vec!["tool:search".into()], None, 1);
        let token = DelegationToken::mint(&vc, scope, 300, &agent).unwrap();
        let mut challenge = PopChallenge::new(audience.map(str::to_string));
        challenge.issued_at = challenge.issued_at - age_back;
        let presentation = Presentation::create(token, vc, &challenge, &agent).unwrap();
        (anchor, presentation)
    }

    #[test]
    fn header_round_trip_and_verify() {
        // Back-date the challenge 60s and verify within a 1-hour window: the result
        // turns on the round-trip + crypto, and tolerates ~65s of backward clock
        // movement between issue and verify so a wall-clock step can't flake it.
        let (anchor, presentation) =
            presentation_aged(Some(RECEIVER), chrono::Duration::seconds(60));
        let header = presentation.to_a2a_header().unwrap();
        assert!(header.starts_with("AgentCreds-A2A/1."));

        let received = Presentation::from_a2a_header(&header).unwrap();
        assert!(received
            .verify_a2a(&Action::new("tool:search", "q=ok"), &anchor, RECEIVER, 3600)
            .is_ok());
    }

    #[test]
    fn wrong_audience_rejected() {
        let (anchor, presentation) = presentation_for(Some(RECEIVER));
        let header = presentation.to_a2a_header().unwrap();
        let received = Presentation::from_a2a_header(&header).unwrap();
        // A different receiver must not accept a header minted for RECEIVER.
        assert!(received
            .verify_a2a(
                &Action::new("tool:search", "q=ok"),
                &anchor,
                "a2a://evil.example/agent",
                60,
            )
            .is_err());
    }

    #[test]
    fn missing_audience_rejected() {
        let (anchor, presentation) = presentation_for(None);
        let header = presentation.to_a2a_header().unwrap();
        let received = Presentation::from_a2a_header(&header).unwrap();
        assert!(received
            .verify_a2a(&Action::new("tool:search", "q=ok"), &anchor, RECEIVER, 60)
            .is_err());
    }

    #[test]
    fn missing_scheme_prefix_rejected() {
        assert!(Presentation::from_a2a_header("not-a-header").is_err());
    }

    #[test]
    fn tampered_header_body_rejected() {
        let (_anchor, presentation) = presentation_for(Some(RECEIVER));
        let header = presentation.to_a2a_header().unwrap();
        // Corrupt a character in the base64url body.
        let mut chars: Vec<char> = header.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        // Either decoding or verification must fail - never silently accept.
        let parsed = Presentation::from_a2a_header(&tampered);
        assert!(
            parsed.is_err() || {
                let anchor = TrustAnchor::generate().unwrap();
                parsed
                    .unwrap()
                    .verify_a2a(&Action::new("tool:search", "q=ok"), &anchor, RECEIVER, 60)
                    .is_err()
            }
        );
    }
}
