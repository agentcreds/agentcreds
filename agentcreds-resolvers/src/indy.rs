//! `did:indy` resolver (feature `resolver-indy`) - a minimal stub. Direct
//! Hyperledger Indy ledger resolution lives outside the offline core; resolve via a
//! DIF Universal Resolver (`resolver-universal`) or supply a pre-fetched document.

#[cfg(feature = "resolver-indy")]
use agentcreds_core::{
    did::{resolver::DidResolver, DidDocument},
    error::AgentCredsError,
};

#[cfg(feature = "resolver-indy")]
/// Placeholder resolver for `did:indy`.
///
/// This is a stub implementation; a production resolver should use a
/// Hyperledger Indy pool client to resolve NYM transactions.
pub struct IndyResolver {
    /// The Hyperledger Indy pool configuration the resolver targets.
    pub pool_config: String,
}

#[cfg(feature = "resolver-indy")]
impl IndyResolver {
    /// Create a resolver using the given Indy `pool_config`.
    pub fn new(pool_config: impl Into<String>) -> Self {
        IndyResolver {
            pool_config: pool_config.into(),
        }
    }
}

#[cfg(feature = "resolver-indy")]
impl DidResolver for IndyResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        Err(AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "direct did:indy (Hyperledger Indy ledger) resolution is not built into the \
                     offline core; resolve via a DIF Universal Resolver (the `resolver-universal` \
                     feature's UniversalResolverClient) or supply a pre-fetched document through \
                     an InMemoryResolver"
                .into(),
        })
    }

    fn method(&self) -> &str {
        "indy"
    }
}
