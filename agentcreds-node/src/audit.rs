use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::audit::{
    AuditCommitment, AuditCompositor as CoreCompositor, AuditLog as CoreLog, AuditRecord,
};

use crate::error::map_err;
use crate::identity::TrustAnchor;

fn ser_err(e: impl std::fmt::Display) -> Error {
    Error::from_reason(format!("SerializationError: {e}"))
}

/// An org's private, append-only audit log for one correlation id. Only the
/// signed commitments (from `export`) are ever shared.
#[napi]
pub struct AuditLog {
    inner: CoreLog,
}

#[napi]
impl AuditLog {
    #[napi(constructor)]
    pub fn new(correlation_id: String, org_id: String) -> Self {
        Self {
            inner: CoreLog::new(correlation_id, org_id),
        }
    }

    /// Append an action; returns its per-org sequence number.
    #[napi]
    pub fn record(&mut self, agent_did: String, action: String, outcome: String) -> i64 {
        self.inner.record(agent_did, action, outcome) as i64
    }

    /// Export signed commitments to share, as a JSON array string. Raw records
    /// stay in this log.
    #[napi]
    pub fn export(&self, anchor: &TrustAnchor) -> Result<String> {
        let commitments = self.inner.export(&anchor.inner).map_err(map_err)?;
        serde_json::to_string(&commitments).map_err(ser_err)
    }

    /// Selectively reveal one raw record as a JSON string (or null).
    #[napi]
    pub fn reveal(&self, seq: i64) -> Result<Option<String>> {
        match self.inner.reveal(seq as u64) {
            Some(r) => Ok(Some(serde_json::to_string(r).map_err(ser_err)?)),
            None => Ok(None),
        }
    }

    #[napi(getter)]
    pub fn len(&self) -> i64 {
        self.inner.len() as i64
    }

    #[napi(getter)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Merges multiple orgs' commitments into one verifiable, ordered
/// chain-of-custody - without seeing raw logs.
#[napi]
pub struct AuditCompositor {
    pub(crate) inner: CoreCompositor,
}

#[napi]
impl AuditCompositor {
    #[napi(constructor)]
    pub fn new(correlation_id: String) -> Self {
        Self {
            inner: CoreCompositor::new(correlation_id),
        }
    }

    /// Ingest one org's exported commitments (the JSON from `AuditLog.export`),
    /// verifying every signature against `orgAnchor`.
    #[napi]
    pub fn ingest(&mut self, commitments_json: String, org_anchor: &TrustAnchor) -> Result<()> {
        let commitments: Vec<AuditCommitment> =
            serde_json::from_str(&commitments_json).map_err(ser_err)?;
        self.inner
            .ingest(&commitments, &org_anchor.inner)
            .map_err(map_err)
    }

    /// The merged chain-of-custody as a JSON array string.
    #[napi]
    pub fn chain_of_custody(&self) -> Result<String> {
        serde_json::to_string(self.inner.chain_of_custody()).map_err(ser_err)
    }

    /// A single tamper-evident digest over the whole ordered chain.
    #[napi]
    pub fn root_hash(&self) -> String {
        self.inner.root_hash()
    }

    /// Verify a selectively-revealed record (the JSON from `AuditLog.reveal`)
    /// against the composited commitment.
    #[napi]
    pub fn verify_revealed(&self, record_json: String) -> Result<bool> {
        let record: AuditRecord = serde_json::from_str(&record_json).map_err(ser_err)?;
        self.inner.verify_revealed(&record).map_err(map_err)
    }

    #[napi(getter)]
    pub fn len(&self) -> i64 {
        self.inner.len() as i64
    }

    #[napi(getter)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
