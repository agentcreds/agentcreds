use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::revocation::{
    RevocationList as CoreRevocationList, RevocationRegistry as CoreRevocationRegistry,
    DEFAULT_LIST_SIZE,
};

use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;

/// Default OAuth Status List size (131,072 entries / 16KB bitstring).
#[napi]
pub fn default_list_size() -> i64 {
    DEFAULT_LIST_SIZE as i64
}

fn non_negative_index(index: i64) -> Result<u64> {
    if index < 0 {
        return Err(invalid_arg("index must be non-negative"));
    }
    Ok(index as u64)
}

// -- RevocationList ------------------------------------------------------------

#[napi]
pub struct RevocationList {
    pub(crate) inner: CoreRevocationList,
}

#[napi]
impl RevocationList {
    /// Create a new, empty revocation list published at `id`, signed by
    /// `anchor`. `size` defaults to [`defaultListSize`] (131,072 entries).
    #[napi(constructor)]
    pub fn new(id: String, anchor: &TrustAnchor, size: Option<i64>) -> Result<Self> {
        let size = match size {
            Some(s) => Some(non_negative_index(s)?),
            None => None,
        };
        Ok(Self {
            inner: CoreRevocationList::new(&id, &anchor.inner, size).map_err(map_err)?,
        })
    }

    /// Deserialise a published revocation list from its JSON form. Call `verify`
    /// against the issuer anchor before trusting it.
    #[napi(factory)]
    pub fn from_json(json: String) -> Result<Self> {
        Ok(Self {
            inner: CoreRevocationList::from_json(&json).map_err(map_err)?,
        })
    }

    /// Serialize this list to JSON (the published form a relying party fetches).
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        self.inner.to_json().map_err(map_err)
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[napi(getter)]
    pub fn updated(&self) -> DateTime<Utc> {
        self.inner.updated
    }

    #[napi(getter)]
    pub fn size(&self) -> i64 {
        self.inner.size as i64
    }

    #[napi(getter)]
    pub fn encoded_list(&self) -> String {
        self.inner.encoded_list.clone()
    }

    #[napi(getter)]
    pub fn signature(&self) -> String {
        self.inner.signature.clone()
    }

    /// Revoke the credential at `index`, re-signing the list with `anchor`.
    #[napi]
    pub fn revoke(&mut self, index: i64, anchor: &TrustAnchor) -> Result<()> {
        let index = non_negative_index(index)?;
        self.inner.revoke(index, &anchor.inner).map_err(map_err)
    }

    /// Un-revoke the credential at `index`, re-signing the list with `anchor`.
    #[napi]
    pub fn unrevoke(&mut self, index: i64, anchor: &TrustAnchor) -> Result<()> {
        let index = non_negative_index(index)?;
        self.inner.unrevoke(index, &anchor.inner).map_err(map_err)
    }

    /// True if the credential at `index` is revoked.
    #[napi]
    pub fn is_revoked(&self, index: i64) -> Result<bool> {
        let index = non_negative_index(index)?;
        self.inner.is_revoked(index).map_err(map_err)
    }

    /// Verify this list's signature against `anchor`.
    #[napi]
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<()> {
        self.inner.verify(&anchor.inner).map_err(map_err)
    }

    /// Total number of revoked credentials in this list.
    #[napi]
    pub fn revocation_count(&self) -> Result<i64> {
        self.inner
            .revocation_count()
            .map(|n| n as i64)
            .map_err(map_err)
    }

    /// SHA-256 fingerprint of the current list state.
    #[napi]
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "RevocationList(id='{}', size={})",
            self.inner.id, self.inner.size
        )
    }
}

// -- RevocationRegistry --------------------------------------------------------

#[napi]
pub struct RevocationRegistry {
    pub(crate) inner: CoreRevocationRegistry,
}

#[napi]
impl RevocationRegistry {
    /// Create an empty registry.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: CoreRevocationRegistry::new(),
        }
    }

    /// Register a revocation list under its ID (URL).
    #[napi]
    pub fn register(&mut self, list: &RevocationList) {
        self.inner.register(list.inner.clone());
    }

    /// Look up a revocation list by ID (URL), or `null` if not registered.
    #[napi]
    pub fn get(&self, list_id: String) -> Option<RevocationList> {
        self.inner
            .get(&list_id)
            .cloned()
            .map(|inner| RevocationList { inner })
    }

    /// Revoke `index` in the list identified by `listId`, re-signing with `anchor`.
    #[napi]
    pub fn revoke(&mut self, list_id: String, index: i64, anchor: &TrustAnchor) -> Result<()> {
        let index = non_negative_index(index)?;
        let list = self
            .inner
            .get_mut(&list_id)
            .ok_or_else(|| invalid_arg(format!("revocation list '{list_id}' not found")))?;
        list.revoke(index, &anchor.inner).map_err(map_err)
    }

    /// Un-revoke `index` in the list identified by `listId`, re-signing with `anchor`.
    #[napi]
    pub fn unrevoke(&mut self, list_id: String, index: i64, anchor: &TrustAnchor) -> Result<()> {
        let index = non_negative_index(index)?;
        let list = self
            .inner
            .get_mut(&list_id)
            .ok_or_else(|| invalid_arg(format!("revocation list '{list_id}' not found")))?;
        list.unrevoke(index, &anchor.inner).map_err(map_err)
    }

    /// Check the revocation status of `credentialId` (throws
    /// `CredentialRevokedError` if revoked, or if `listId` is unknown).
    #[napi]
    pub fn is_revoked(&self, list_id: String, index: i64, credential_id: String) -> Result<()> {
        let index = non_negative_index(index)?;
        self.inner
            .is_revoked(&list_id, index, &credential_id)
            .map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        "RevocationRegistry()".to_string()
    }
}

impl Default for RevocationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_size_matches_constant() {
        assert_eq!(default_list_size(), DEFAULT_LIST_SIZE as i64);
    }

    #[test]
    fn revocation_list_revoke_and_unrevoke() {
        let anchor = TrustAnchor::generate().unwrap();
        let mut list = RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(128),
        )
        .unwrap();
        assert_eq!(list.size(), 128);
        assert_eq!(list.issuer(), anchor.did());
        assert!(!list.is_revoked(5).unwrap());

        list.revoke(5, &anchor).unwrap();
        assert!(list.is_revoked(5).unwrap());
        assert_eq!(list.revocation_count().unwrap(), 1);
        assert!(list.verify(&anchor).is_ok());

        list.unrevoke(5, &anchor).unwrap();
        assert!(!list.is_revoked(5).unwrap());
        assert_eq!(list.revocation_count().unwrap(), 0);
    }

    #[test]
    fn revocation_list_rejects_negative_index() {
        let anchor = TrustAnchor::generate().unwrap();
        let mut list = RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(128),
        )
        .unwrap();
        assert!(list.revoke(-1, &anchor).is_err());
        assert!(list.is_revoked(-1).is_err());
    }

    #[test]
    fn revocation_list_rejects_negative_size() {
        let anchor = TrustAnchor::generate().unwrap();
        assert!(RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(-1)
        )
        .is_err());
    }

    #[test]
    fn revocation_list_out_of_bounds_index_fails() {
        let anchor = TrustAnchor::generate().unwrap();
        let mut list = RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(8),
        )
        .unwrap();
        assert!(list.revoke(100, &anchor).is_err());
    }

    #[test]
    fn fingerprint_changes_after_revoke() {
        let anchor = TrustAnchor::generate().unwrap();
        let mut list = RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(64),
        )
        .unwrap();
        let before = list.fingerprint();
        list.revoke(1, &anchor).unwrap();
        assert_ne!(before, list.fingerprint());
    }

    #[test]
    fn revocation_registry_register_and_revoke() {
        let anchor = TrustAnchor::generate().unwrap();
        let list = RevocationList::new(
            "https://registry.example.com/status/1".into(),
            &anchor,
            Some(64),
        )
        .unwrap();
        let list_id = list.id();

        let mut registry = RevocationRegistry::new();
        registry.register(&list);
        assert!(registry.get(list_id.clone()).is_some());
        assert!(registry
            .get("https://registry.example.com/status/missing".into())
            .is_none());

        registry.revoke(list_id.clone(), 3, &anchor).unwrap();
        assert!(registry
            .is_revoked(list_id.clone(), 3, "urn:vc:agentcreds:abc".into())
            .is_err());
        assert!(registry
            .is_revoked(list_id.clone(), 4, "urn:vc:agentcreds:abc".into())
            .is_ok());

        registry.unrevoke(list_id.clone(), 3, &anchor).unwrap();
        assert!(registry
            .is_revoked(list_id, 3, "urn:vc:agentcreds:abc".into())
            .is_ok());
    }

    #[test]
    fn revocation_registry_unknown_list_fails() {
        let anchor = TrustAnchor::generate().unwrap();
        let mut registry = RevocationRegistry::new();
        assert!(registry
            .revoke(
                "https://registry.example.com/status/missing".into(),
                0,
                &anchor
            )
            .is_err());
        assert!(registry
            .is_revoked(
                "https://registry.example.com/status/missing".into(),
                0,
                "urn:vc:agentcreds:abc".into()
            )
            .is_err());
    }

    #[test]
    fn revocation_registry_to_string() {
        let registry = RevocationRegistry::new();
        assert_eq!(registry.to_string(), "RevocationRegistry()");
    }
}
