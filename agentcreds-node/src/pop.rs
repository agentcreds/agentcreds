use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::pop::{
    PopChallenge as CorePopChallenge, Presentation as CorePresentation,
    ProofOfPossession as CoreProofOfPossession,
};

use crate::credential::CapabilityCredential;
use crate::delegation::{Action, DelegationToken};
use crate::error::map_err;
use crate::identity::{AgentIdentity, TrustAnchor};

// -- PopChallenge --------------------------------------------------------------

#[napi]
pub struct PopChallenge {
    pub(crate) inner: CorePopChallenge,
}

#[napi]
impl PopChallenge {
    /// Create a fresh challenge with a random nonce. `audience` optionally binds
    /// the proof to a specific verifier (e.g. an MCP server URI).
    #[napi(constructor)]
    pub fn new(audience: Option<String>) -> Self {
        Self {
            inner: CorePopChallenge::new(audience),
        }
    }

    #[napi(getter)]
    pub fn nonce(&self) -> Buffer {
        Buffer::from(self.inner.nonce.clone())
    }

    #[napi(getter)]
    pub fn audience(&self) -> Option<String> {
        self.inner.audience.clone()
    }

    #[napi(getter)]
    pub fn issued_at(&self) -> DateTime<Utc> {
        self.inner.issued_at
    }

    /// Return a copy of this challenge bound to a specific request (pass
    /// `Action.requestBinding`). The holder signs the bound challenge, so the
    /// resulting presentation is valid only for that exact action.
    #[napi]
    pub fn with_request_binding(&self, binding: String) -> PopChallenge {
        Self {
            inner: self.inner.with_request_binding(binding),
        }
    }

    /// Serialize to CBOR for wire transport.
    #[napi]
    pub fn to_cbor(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.inner.to_cbor().map_err(map_err)?))
    }

    /// Deserialise a challenge from CBOR bytes.
    #[napi(factory)]
    pub fn from_cbor(data: Buffer) -> Result<Self> {
        Ok(Self {
            inner: CorePopChallenge::from_cbor(data.as_ref()).map_err(map_err)?,
        })
    }
}

// -- ProofOfPossession ---------------------------------------------------------

#[napi]
pub struct ProofOfPossession {
    pub(crate) inner: CoreProofOfPossession,
}

#[napi]
impl ProofOfPossession {
    #[napi(getter)]
    pub fn leaf_did(&self) -> String {
        self.inner.leaf_did.clone()
    }

    /// Verify this proof against `token` and the `challenge` the verifier
    /// issued, within `maxAgeSecs`. Throws on failure.
    #[napi]
    pub fn verify(
        &self,
        token: &DelegationToken,
        challenge: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.inner
            .verify(&token.inner, &challenge.inner, max_age_secs)
            .map_err(map_err)
    }

    /// Serialize to CBOR for wire transport.
    #[napi]
    pub fn to_cbor(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.inner.to_cbor().map_err(map_err)?))
    }

    /// Deserialise a proof from CBOR bytes.
    #[napi(factory)]
    pub fn from_cbor(data: Buffer) -> Result<Self> {
        Ok(Self {
            inner: CoreProofOfPossession::from_cbor(data.as_ref()).map_err(map_err)?,
        })
    }
}

// -- Presentation (MCP wire envelope) ------------------------------------------

#[napi]
pub struct Presentation {
    pub(crate) inner: CorePresentation,
}

#[napi]
impl Presentation {
    /// The delegation token being presented (e.g. for audit via `chain()`).
    #[napi(getter)]
    pub fn token(&self) -> DelegationToken {
        DelegationToken {
            inner: self.inner.token.clone(),
        }
    }

    /// The credential the token's root is derived from.
    #[napi(getter)]
    pub fn credential(&self) -> CapabilityCredential {
        CapabilityCredential {
            inner: self.inner.credential.clone(),
        }
    }

    /// Whether this presentation's proof is bound to a specific request. A
    /// verifier requiring per-request binding should reject presentations for
    /// which this is false.
    #[napi(getter)]
    pub fn is_action_bound(&self) -> bool {
        self.inner.is_action_bound()
    }

    /// Assemble a presentation (holder side): mints the proof of possession for
    /// `challenge` using `leafAgent` and bundles it with the token and its
    /// backing credential.
    #[napi(factory)]
    pub fn create(
        token: &DelegationToken,
        credential: &CapabilityCredential,
        challenge: &PopChallenge,
        leaf_agent: &AgentIdentity,
    ) -> Result<Self> {
        Ok(Self {
            inner: CorePresentation::create(
                token.inner.clone(),
                credential.inner.clone(),
                &challenge.inner,
                &leaf_agent.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Verify the full presentation (verifier side): anchor-rooted token
    /// verification plus proof of possession. Throws on failure.
    #[napi]
    pub fn verify(
        &self,
        action: &Action,
        anchor: &TrustAnchor,
        challenge: &PopChallenge,
        max_age_secs: i64,
    ) -> Result<()> {
        self.inner
            .verify(&action.inner, &anchor.inner, &challenge.inner, max_age_secs)
            .map_err(map_err)
    }

    /// `verify`, evaluated **as of** `epochSeconds` rather than the wall clock. One
    /// instant governs the credential, every hop, the Datalog time check and the
    /// proof's freshness window.
    ///
    /// **Not the enforcement path** - a relying party deciding in real time calls
    /// `verify`. This exists for audit re-verification and for golden vectors that must
    /// outlive the one-hour token lifetime the autonomy ladder permits.
    #[napi]
    pub fn verify_at(
        &self,
        action: &Action,
        anchor: &TrustAnchor,
        challenge: &PopChallenge,
        max_age_secs: i64,
        epoch_seconds: i64,
    ) -> Result<()> {
        let now = chrono::DateTime::from_timestamp(epoch_seconds, 0)
            .ok_or_else(|| napi::Error::from_reason("epochSeconds out of range"))?;
        self.inner
            .verify_at(
                &action.inner,
                &anchor.inner,
                &challenge.inner,
                max_age_secs,
                now,
            )
            .map_err(map_err)
    }

    /// Serialize to CBOR for wire transport.
    #[napi]
    pub fn to_cbor(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.inner.to_cbor().map_err(map_err)?))
    }

    /// Deserialise a presentation from CBOR bytes.
    #[napi(factory)]
    pub fn from_cbor(data: Buffer) -> Result<Self> {
        Ok(Self {
            inner: CorePresentation::from_cbor(data.as_ref()).map_err(map_err)?,
        })
    }

    /// Encode this presentation as an A2A identity header string
    /// (`AgentCreds-A2A/1.<base64url>`), suitable for an A2A task header.
    #[napi]
    pub fn to_a2a_header(&self) -> Result<String> {
        self.inner.to_a2a_header().map_err(map_err)
    }

    /// Decode an A2A identity header string back into a presentation.
    #[napi(factory)]
    pub fn from_a2a_header(header: String) -> Result<Self> {
        Ok(Self {
            inner: CorePresentation::from_a2a_header(&header).map_err(map_err)?,
        })
    }

    /// Verify an A2A presentation as the receiving agent: full presentation
    /// verification plus a requirement that the embedded challenge audience
    /// equals `expectedAudience` (this verifier).
    #[napi]
    pub fn verify_a2a(
        &self,
        action: &Action,
        anchor: &TrustAnchor,
        expected_audience: String,
        max_age_secs: i64,
    ) -> Result<()> {
        self.inner
            .verify_a2a(
                &action.inner,
                &anchor.inner,
                &expected_audience,
                max_age_secs,
            )
            .map_err(map_err)
    }
}
