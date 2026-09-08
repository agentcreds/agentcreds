use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::rotation::{KeyHistory as CoreHistory, RotationStatement as CoreStatement};

use crate::error::map_err;
use crate::identity::TrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("SerializationError: {e}"))
}

/// A signed endorsement by an outgoing anchor key of its successor.
#[napi]
pub struct RotationStatement {
    pub(crate) inner: CoreStatement,
}

#[napi]
impl RotationStatement {
    /// Issue a statement: `old` signs an endorsement of `next` (effective now).
    #[napi(factory)]
    pub fn issue(old: &TrustAnchor, next: &TrustAnchor) -> Result<Self> {
        Ok(Self {
            inner: CoreStatement::issue(&old.inner, &next.inner).map_err(map_err)?,
        })
    }

    /// Verify the statement is authentically signed by the outgoing key.
    #[napi]
    pub fn verify(&self) -> Result<()> {
        self.inner.verify().map_err(map_err)
    }

    #[napi(getter)]
    pub fn previous_did(&self) -> String {
        self.inner.previous_did.clone()
    }
    #[napi(getter)]
    pub fn next_did(&self) -> String {
        self.inner.next_did.clone()
    }
    #[napi(getter)]
    pub fn effective_at(&self) -> String {
        self.inner.effective_at.to_rfc3339()
    }
    #[napi(getter)]
    pub fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(ser_err)
    }

    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: serde_json::from_str(&s).map_err(ser_err)?,
        })
    }
}

/// The chain of rotation statements from an anchor's original key to its current.
#[napi]
pub struct KeyHistory {
    inner: CoreHistory,
}

#[napi]
impl KeyHistory {
    /// A new history rooted at `rootDid`.
    #[napi(constructor)]
    pub fn new(root_did: String) -> Self {
        Self {
            inner: CoreHistory::new(root_did),
        }
    }

    /// A new history rooted at `anchor`'s DID.
    #[napi(factory)]
    pub fn genesis(anchor: &TrustAnchor) -> Self {
        Self {
            inner: CoreHistory::genesis(&anchor.inner),
        }
    }

    /// Append a rotation (must chain from the current key and verify).
    #[napi]
    pub fn push(&mut self, statement: &RotationStatement) -> Result<()> {
        self.inner.push(statement.inner.clone()).map_err(map_err)
    }

    /// The current (latest) anchor DID in the chain.
    #[napi]
    pub fn current_did(&self) -> String {
        self.inner.current_did().to_string()
    }

    /// Verify the chain from `trustedRootDid` and return the current DID.
    #[napi]
    pub fn verify(&self, trusted_root_did: String) -> Result<String> {
        self.inner.verify(&trusted_root_did).map_err(map_err)
    }

    /// Verify the chain and return a verify-only `TrustAnchor` for the current key.
    #[napi]
    pub fn current_anchor(&self, trusted_root_did: String) -> Result<TrustAnchor> {
        Ok(TrustAnchor {
            inner: self
                .inner
                .current_anchor(&trusted_root_did)
                .map_err(map_err)?,
        })
    }

    /// Every anchor DID the organization legitimately held (root + successors).
    #[napi]
    pub fn dids(&self) -> Vec<String> {
        self.inner.dids()
    }

    /// Verify the chain and confirm `issuerDid` is in the history, returning a
    /// verify-only `TrustAnchor` for it (use to verify a credential's issuer).
    #[napi]
    /// Withdraw `did` from issuance. Re-seal afterwards or the change is unsigned.
    pub fn repudiate(&mut self, did: String) -> Result<()> {
        self.inner.repudiate(&did).map_err(map_err)
    }

    /// Seal the history: the **current** key signs the chain, repudiations and expiry.
    /// `notAfterUnix` is seconds since the epoch; omit for an unbounded seal.
    #[napi]
    pub fn seal(
        &mut self,
        current: &TrustAnchor,
        version: u32,
        not_after_unix: Option<i64>,
    ) -> Result<()> {
        let not_after = match not_after_unix {
            Some(ts) => Some(
                chrono::DateTime::from_timestamp(ts, 0)
                    .ok_or_else(|| Error::from_reason("invalid notAfterUnix"))?,
            ),
            None => None,
        };
        self.inner
            .seal(&current.inner, u64::from(version), not_after)
            .map_err(map_err)
    }

    /// Whether the sealed history is still inside its validity window.
    #[napi]
    pub fn is_current(&self) -> bool {
        self.inner.is_current()
    }

    /// Verify the chain and the seal under the current key (authenticity only).
    #[napi]
    pub fn verify_sealed(&self, trusted_root_did: String) -> Result<String> {
        self.inner.verify_sealed(&trusted_root_did).map_err(map_err)
    }

    /// Verify authenticity **and** freshness - what a relying party should use.
    #[napi]
    pub fn verify_current(&self, trusted_root_did: String) -> Result<String> {
        self.inner
            .verify_current(&trusted_root_did)
            .map_err(map_err)
    }

    /// The DIDs still trusted for issuance (the chain minus the repudiations).
    #[napi]
    pub fn active_dids(&self) -> Vec<String> {
        self.inner.active_dids()
    }

    /// The DIDs withdrawn from issuance.
    #[napi]
    pub fn repudiated(&self) -> Vec<String> {
        self.inner.repudiated.clone()
    }

    #[napi]
    pub fn authorize_issuer(
        &self,
        trusted_root_did: String,
        issuer_did: String,
    ) -> Result<TrustAnchor> {
        Ok(TrustAnchor {
            inner: self
                .inner
                .authorize_issuer(&trusted_root_did, &issuer_did)
                .map_err(map_err)?,
        })
    }

    /// Serialize the history to JSON (the portable artifact relying parties follow).
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a history from JSON.
    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: CoreHistory::from_json(&s).map_err(map_err)?,
        })
    }
}
