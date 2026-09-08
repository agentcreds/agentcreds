//! `did:cheqd` resolver (feature `resolver-cheqd`) - a minimal stub. Direct Cosmos
//! ledger resolution lives outside the offline core; resolve via a DIF Universal
//! Resolver (`resolver-universal`) or supply a pre-fetched document.

#[cfg(feature = "resolver-cheqd")]
use agentcreds_core::{
    did::{resolver::DidResolver, DidDocument},
    error::AgentCredsError,
};

#[cfg(feature = "resolver-cheqd")]
/// Placeholder resolver for `did:cheqd`.
///
/// The implementation is intentionally minimal and can be extended with
/// Cosmos RPC / Cheqd REST integration later.
pub struct CheqdResolver {
    /// The cheqd node / RPC endpoint the resolver targets.
    pub node_url: String,
}

#[cfg(feature = "resolver-cheqd")]
impl CheqdResolver {
    /// Create a resolver targeting the cheqd node at `node_url`.
    pub fn new(node_url: impl Into<String>) -> Self {
        CheqdResolver {
            node_url: node_url.into(),
        }
    }
}

#[cfg(feature = "resolver-cheqd")]
impl DidResolver for CheqdResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        Err(AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "direct did:cheqd (Cosmos ledger) resolution is not built into the offline \
                     core; resolve via a DIF Universal Resolver (the `resolver-universal` \
                     feature's UniversalResolverClient) or supply a pre-fetched document through \
                     an InMemoryResolver"
                .into(),
        })
    }

    fn method(&self) -> &str {
        "cheqd"
    }
}
