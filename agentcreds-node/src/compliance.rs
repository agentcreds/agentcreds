use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::adr::AuthzDecision as CoreDecision;
use agentcreds_core::compliance::{EvidenceBundle as CoreBundle, EvidenceReport as CoreReport};

use crate::adr::{AdrCheckpoint, AuthzDecision};
use crate::audit::AuditCompositor;
use crate::error::map_err;
use crate::identity::TrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("SerializationError: {e}"))
}

/// The summary returned by a successful `EvidenceBundle.verify`.
#[napi]
pub struct EvidenceReport {
    inner: CoreReport,
}

#[napi]
impl EvidenceReport {
    #[napi(getter)]
    pub fn correlation_id(&self) -> String {
        self.inner.correlation_id.clone()
    }
    #[napi(getter)]
    pub fn decisions(&self) -> i64 {
        self.inner.decisions as i64
    }
    #[napi(getter)]
    pub fn allowed(&self) -> i64 {
        self.inner.allowed as i64
    }
    #[napi(getter)]
    pub fn denied(&self) -> i64 {
        self.inner.denied as i64
    }
    #[napi(getter)]
    pub fn signals(&self) -> Vec<String> {
        self.inner
            .signals
            .iter()
            .map(|s| s.as_str().to_string())
            .collect()
    }
    #[napi(getter)]
    pub fn checkpoint_verified(&self) -> bool {
        self.inner.checkpoint_verified
    }
    #[napi(getter)]
    pub fn custody_entries(&self) -> i64 {
        self.inner.custody_entries as i64
    }
}

/// A signed, self-verifying compliance export of the authorization decisions
/// (and optional chain-of-custody) for a delegation flow.
#[napi]
pub struct EvidenceBundle {
    inner: CoreBundle,
}

#[napi]
impl EvidenceBundle {
    /// Seal and sign a bundle with `anchor` for the flow `correlationId` (the
    /// root `vcId`). `decisionsJson` is a JSON array of decision records (e.g.
    /// `JSON.stringify(records.map(r => JSON.parse(r.toJson())))`); optionally
    /// include the `subjectDid`, a stream `checkpoint`, and the chain-of-custody
    /// from an `AuditCompositor`.
    #[napi(factory)]
    pub fn seal(
        anchor: &TrustAnchor,
        correlation_id: String,
        decisions_json: String,
        subject_did: Option<String>,
        checkpoint: Option<&AdrCheckpoint>,
        compositor: Option<&AuditCompositor>,
    ) -> Result<Self> {
        let decisions: Vec<CoreDecision> =
            serde_json::from_str(&decisions_json).map_err(ser_err)?;
        let mut builder = CoreBundle::builder(correlation_id).decisions(decisions);
        if let Some(s) = subject_did {
            builder = builder.subject(s);
        }
        if let Some(cp) = checkpoint {
            builder = builder.stream_checkpoint(cp.inner.clone());
        }
        if let Some(comp) = compositor {
            builder = builder.custody_from(&comp.inner);
        }
        Ok(Self {
            inner: builder.seal(&anchor.inner).map_err(map_err)?,
        })
    }

    /// Verify the bundle against `anchor` and return an `EvidenceReport`.
    #[napi]
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<EvidenceReport> {
        Ok(EvidenceReport {
            inner: self.inner.verify(&anchor.inner).map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn bundle_id(&self) -> String {
        self.inner.bundle_id.clone()
    }
    #[napi(getter)]
    pub fn generated_at(&self) -> String {
        self.inner.generated_at.to_rfc3339()
    }
    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }
    #[napi(getter)]
    pub fn correlation_id(&self) -> String {
        self.inner.correlation_id.clone()
    }
    #[napi(getter)]
    pub fn subject_did(&self) -> Option<String> {
        self.inner.subject_did.clone()
    }
    #[napi(getter)]
    pub fn decisions_head(&self) -> String {
        self.inner.decisions_head.clone()
    }
    #[napi(getter)]
    pub fn custody_root(&self) -> Option<String> {
        self.inner.custody_root.clone()
    }
    #[napi(getter)]
    pub fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// The decision records included in the bundle.
    #[napi]
    pub fn decisions(&self) -> Vec<AuthzDecision> {
        self.inner
            .decisions
            .iter()
            .cloned()
            .map(|inner| AuthzDecision { inner })
            .collect()
    }

    /// The bundle as a JSON string (the export artifact).
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        self.inner.to_json().map_err(map_err)
    }

    /// Parse a bundle from its JSON string.
    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: CoreBundle::from_json(&s).map_err(map_err)?,
        })
    }
}
