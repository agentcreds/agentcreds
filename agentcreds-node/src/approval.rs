//! Hybrid R10: per-approver keys under the org anchor.
//!
//! Anchor-signed approval proves the *organization* approved. The hybrid model proves
//! *who*: the human signs with their own key, and that key is authorized by an
//! org-anchor-signed [`ApproverDirectory`] - one trust root, per-human non-repudiation.
//!
//! Node could previously neither verify nor mint this evidence, so a Node relying party
//! could not enforce an `approval-key` gate at all.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::delegation::{
    ApprovalEvidence as CoreApprovalEvidence, ApproverDirectory as CoreApproverDirectory,
    ApproverEntry as CoreApproverEntry,
};

use crate::delegation::Action;
use crate::error::{invalid_arg, map_err};
use crate::identity::{AgentIdentity, TrustAnchor};

fn ts(unix: i64) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix, 0)
        .ok_or_else(|| invalid_arg("invalid unix timestamp"))
}

/// One enrolled human approver: a `did:key` signing identity, roles, and an optional
/// expiry (`notAfterUnix`, unix seconds).
#[napi]
#[derive(Clone)]
pub struct ApproverEntry {
    pub(crate) inner: CoreApproverEntry,
}

#[napi]
impl ApproverEntry {
    #[napi(constructor)]
    pub fn new(
        approver_id: String,
        approver_did: String,
        roles: Option<Vec<String>>,
        not_after_unix: Option<i64>,
    ) -> Result<Self> {
        let not_after = match not_after_unix {
            Some(t) => Some(ts(t)?),
            None => None,
        };
        Ok(Self {
            inner: CoreApproverEntry {
                approver_id,
                approver_did,
                roles: roles.unwrap_or_default(),
                not_after,
            },
        })
    }

    #[napi(getter)]
    pub fn approver_id(&self) -> String {
        self.inner.approver_id.clone()
    }

    #[napi(getter)]
    pub fn approver_did(&self) -> String {
        self.inner.approver_did.clone()
    }

    #[napi(getter)]
    pub fn roles(&self) -> Vec<String> {
        self.inner.roles.clone()
    }

    /// Per-approver expiry as unix seconds, or null if the entry does not expire.
    #[napi(getter)]
    pub fn not_after_unix(&self) -> Option<i64> {
        self.inner.not_after.map(|t| t.timestamp())
    }
}

/// A versioned, **anchor-signed** directory of human approver keys.
///
/// Verified under the same org anchor that roots delegation - there is no second trust
/// root - and carries a signed `notAfter` so a relying party can bound its staleness.
#[napi]
#[derive(Clone)]
pub struct ApproverDirectory {
    pub(crate) inner: CoreApproverDirectory,
}

#[napi]
impl ApproverDirectory {
    /// Seal (sign) a directory with the org `anchor`. `notAfterUnix` sets an optional
    /// staleness bound.
    #[napi(factory)]
    pub fn seal(
        entries: Vec<&ApproverEntry>,
        version: i64,
        anchor: &TrustAnchor,
        not_after_unix: Option<i64>,
    ) -> Result<Self> {
        let not_after = match not_after_unix {
            Some(t) => Some(ts(t)?),
            None => None,
        };
        Ok(Self {
            inner: CoreApproverDirectory::seal(
                entries.into_iter().map(|e| e.inner.clone()).collect(),
                version as u64,
                chrono::Utc::now(),
                not_after,
                &anchor.inner,
            )
            .map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn version(&self) -> i64 {
        self.inner.version as i64
    }

    /// DID of the anchor that sealed this directory.
    ///
    /// Under rotation this is the org's CURRENT key, which differs from the root a
    /// relying party pinned - so a verifier needs it to resolve the right key through
    /// the organization's key history.
    #[napi(getter)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    /// The enrolled approvers, in the sealed order (sorted by `approverId`).
    #[napi(getter)]
    pub fn entries(&self) -> Vec<ApproverEntry> {
        self.inner
            .entries
            .iter()
            .cloned()
            .map(|inner| ApproverEntry { inner })
            .collect()
    }

    /// The sealed expiry as unix seconds, or null if unbounded.
    #[napi(getter)]
    pub fn not_after_unix(&self) -> Option<i64> {
        self.inner.not_after.map(|t| t.timestamp())
    }

    /// Verify the signature against `anchor` **and** the expiry at `nowUnix`.
    ///
    /// Both together: an authentic-but-lapsed directory must be refused, not assumed
    /// current, or the staleness bound is decorative.
    #[napi]
    pub fn verify_current(&self, anchor: &TrustAnchor, now_unix: i64) -> Result<()> {
        self.inner
            .verify_current(&anchor.inner, ts(now_unix)?)
            .map_err(map_err)
    }

    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(|e| invalid_arg(e.to_string()))
    }

    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: serde_json::from_str(&s).map_err(|e| invalid_arg(e.to_string()))?,
        })
    }
}

/// Execution-time human authorization evidence (R10).
#[napi]
#[derive(Clone)]
pub struct ApprovalEvidence {
    pub(crate) inner: CoreApprovalEvidence,
}

#[napi]
impl ApprovalEvidence {
    /// Mint **anchor-signed** evidence: the organization approved.
    #[napi(factory)]
    pub fn approve(
        action: &Action,
        approver: String,
        approval_id: String,
        expires_at: i64,
        anchor: &TrustAnchor,
    ) -> Result<Self> {
        Ok(Self {
            inner: CoreApprovalEvidence::approve(
                &action.inner,
                approver,
                approval_id,
                expires_at,
                &anchor.inner,
            )
            .map_err(map_err)?,
        })
    }

    /// Mint **approver-key-signed** evidence: this individual approved. Verified against
    /// an [`ApproverDirectory`] rather than the org anchor.
    #[napi(factory)]
    pub fn approve_by_key(
        action: &Action,
        approver_id: String,
        approver: &AgentIdentity,
        approval_id: String,
        expires_at: i64,
    ) -> Result<Self> {
        Ok(Self {
            inner: CoreApprovalEvidence::approve_by_key(
                &action.inner,
                approver_id,
                &approver.inner,
                approval_id,
                expires_at,
            )
            .map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn approval_id(&self) -> String {
        self.inner.approval_id.clone()
    }

    #[napi(getter)]
    pub fn approver(&self) -> String {
        self.inner.approver.clone()
    }

    #[napi(getter)]
    pub fn expires_at(&self) -> i64 {
        self.inner.expires_at
    }

    /// Verify anchor-signed evidence for `action` at `nowUnix`.
    #[napi]
    pub fn verify(&self, action: &Action, anchor: &TrustAnchor, now_unix: i64) -> Result<()> {
        self.inner
            .verify(&action.inner, &anchor.inner, now_unix)
            .map_err(map_err)
    }

    /// Verify **approver-key-signed** evidence against an anchor-signed `directory`,
    /// optionally requiring a role.
    #[napi]
    pub fn verify_with_directory(
        &self,
        action: &Action,
        directory: &ApproverDirectory,
        anchor: &TrustAnchor,
        now_unix: i64,
        required_role: Option<String>,
    ) -> Result<()> {
        self.inner
            .verify_with_directory(
                &action.inner,
                &directory.inner,
                &anchor.inner,
                now_unix,
                required_role.as_deref(),
            )
            .map_err(map_err)
    }

    #[napi]
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(&self.inner).map_err(|e| invalid_arg(e.to_string()))
    }

    #[napi(factory)]
    pub fn from_json(s: String) -> Result<Self> {
        Ok(Self {
            inner: serde_json::from_str(&s).map_err(|e| invalid_arg(e.to_string()))?,
        })
    }
}
