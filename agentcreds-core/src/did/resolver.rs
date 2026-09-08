use std::collections::HashMap;

use crate::did::DidDocument;
use crate::error::AgentCredsError;

/// Abstraction for resolving DIDs to DID documents.
pub trait DidResolver: Send + Sync {
    /// Resolve a DID to its document.
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError>;

    /// Return the DID method handled by this resolver.
    fn method(&self) -> &str;

    /// Return true if this resolver can handle the given DID.
    fn handles(&self, did: &str) -> bool {
        did.starts_with(&format!("did:{}:", self.method()))
    }
}

/// Resolver that routes requests to the first registered implementation that handles the DID.
pub struct UniversalResolver {
    resolvers: Vec<Box<dyn DidResolver>>,
}

impl UniversalResolver {
    /// Create a new universal resolver from a list of delegates.
    pub fn new(resolvers: Vec<Box<dyn DidResolver>>) -> Self {
        UniversalResolver { resolvers }
    }

    /// Add a resolver instance.
    pub fn add_resolver(&mut self, resolver: Box<dyn DidResolver>) {
        self.resolvers.push(resolver);
    }
}

impl DidResolver for UniversalResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        for resolver in &self.resolvers {
            if resolver.handles(did) {
                return resolver.resolve(did);
            }
        }

        Err(AgentCredsError::DidResolutionFailed {
            did: did.to_string(),
            reason: "no resolver registered for this DID method".into(),
        })
    }

    fn method(&self) -> &str {
        "universal"
    }
}

/// In-memory resolver used for tests, development, and local caching.
pub struct InMemoryResolver {
    docs: HashMap<String, DidDocument>,
}

impl InMemoryResolver {
    /// Create a new, empty in-memory resolver.
    pub fn new() -> Self {
        InMemoryResolver {
            docs: HashMap::new(),
        }
    }

    /// Register a DID document to resolve later.
    pub fn register(&mut self, did: impl Into<String>, document: DidDocument) {
        self.docs.insert(did.into(), document);
    }
}

impl DidResolver for InMemoryResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, AgentCredsError> {
        self.docs
            .get(did)
            .cloned()
            .ok_or_else(|| AgentCredsError::DidResolutionFailed {
                did: did.to_string(),
                reason: "DID not found in memory resolver".into(),
            })
    }

    fn method(&self) -> &str {
        "memory"
    }

    fn handles(&self, did: &str) -> bool {
        self.docs.contains_key(did)
    }
}

// -- Tests ---------------------------------------------------------------------
//
// This file had NO test module. It is the dispatcher every non-`did:key` method plugs
// into - `did:web`, `cheqd`, `indy` all arrive through `UniversalResolver` - and a
// production-only coverage audit on 2026-08-08 measured it at 37.8%, the worst in the
// crate. It needs no network: the routing is pure, and `InMemoryResolver` is a real
// delegate, so the whole extension point is testable offline.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::TrustAnchor;

    /// A delegate that claims one method by prefix and counts its calls, so a test can
    /// tell "routed here" from "routed elsewhere and happened to succeed".
    struct Stub {
        method: &'static str,
        doc: DidDocument,
    }

    impl DidResolver for Stub {
        fn resolve(&self, _did: &str) -> Result<DidDocument, AgentCredsError> {
            Ok(self.doc.clone())
        }
        fn method(&self) -> &str {
            self.method
        }
    }

    fn a_document() -> DidDocument {
        TrustAnchor::generate().unwrap().document().clone()
    }

    fn stub(method: &'static str) -> Box<dyn DidResolver> {
        Box::new(Stub {
            method,
            doc: a_document(),
        })
    }

    /// The trait's default `handles` matches on the `did:<method>:` prefix - and must
    /// not match a method that merely shares a prefix, or `did:webfoo:` would be
    /// swallowed by the `did:web` resolver.
    #[test]
    fn the_default_handles_matches_the_method_prefix_exactly() {
        let web = Stub {
            method: "web",
            doc: a_document(),
        };
        assert!(web.handles("did:web:example.com"));
        assert!(!web.handles("did:key:z6Mk"));
        assert!(
            !web.handles("did:webfoo:example.com"),
            "a longer method name must not be captured by a shorter one"
        );
        assert!(!web.handles("did:web"), "the trailing colon is required");
        assert!(!web.handles("web:example.com"));
    }

    #[test]
    fn the_universal_resolver_routes_to_the_delegate_that_handles_the_method() {
        let r = UniversalResolver::new(vec![stub("web"), stub("cheqd")]);
        assert!(r.resolve("did:web:example.com").is_ok());
        assert!(r.resolve("did:cheqd:testnet:abc").is_ok());
        assert_eq!(r.method(), "universal");
    }

    /// An unroutable DID must be refused, and the error must NAME the DID. A resolution
    /// failure that does not say what it failed to resolve is the least useful error an
    /// operator can be handed.
    #[test]
    fn an_unregistered_method_is_refused_and_the_error_names_the_did() {
        let r = UniversalResolver::new(vec![stub("web")]);
        match r.resolve("did:indy:sovrin:xyz") {
            Err(AgentCredsError::DidResolutionFailed { did, reason }) => {
                assert_eq!(did, "did:indy:sovrin:xyz");
                assert!(
                    reason.contains("no resolver"),
                    "the reason must say why: {reason}"
                );
            }
            other => panic!("an unroutable DID must be refused: {other:?}"),
        }
        // Empty registry is the same case, not a panic.
        assert!(UniversalResolver::new(vec![]).resolve("did:web:x").is_err());
    }

    /// `add_resolver` extends a live dispatcher - the path a host uses to plug in a
    /// networked resolver after construction.
    #[test]
    fn add_resolver_extends_a_live_dispatcher() {
        let mut r = UniversalResolver::new(vec![]);
        assert!(r.resolve("did:web:example.com").is_err());
        r.add_resolver(stub("web"));
        assert!(
            r.resolve("did:web:example.com").is_ok(),
            "a resolver added after construction must take effect"
        );
    }

    /// First match wins, as documented. Registration order is therefore a routing
    /// decision, not a formality - two resolvers claiming one method resolve to the
    /// earlier one.
    #[test]
    fn the_first_registered_handler_wins() {
        let first = a_document();
        let second = a_document();
        assert_ne!(first.id, second.id, "the two stubs must be distinguishable");

        let r = UniversalResolver::new(vec![
            Box::new(Stub {
                method: "web",
                doc: first.clone(),
            }),
            Box::new(Stub {
                method: "web",
                doc: second,
            }),
        ]);
        assert_eq!(
            r.resolve("did:web:example.com").unwrap().id,
            first.id,
            "the earlier registration must win"
        );
    }

    /// `InMemoryResolver` OVERRIDES `handles` to mean "I hold this document", not "this
    /// is my method prefix". That is a real behavioural difference: inside a
    /// `UniversalResolver` it declines DIDs it does not have, so a later delegate still
    /// gets a chance instead of the request dying on a false claim.
    #[test]
    fn the_in_memory_resolver_only_claims_dids_it_actually_holds() {
        let doc = a_document();
        let did = doc.id.clone();
        let mut mem = InMemoryResolver::new();

        assert!(!mem.handles(&did), "an empty resolver claims nothing");
        mem.register(did.clone(), doc.clone());
        assert!(mem.handles(&did));
        assert!(!mem.handles("did:key:zNotRegistered"));
        assert_eq!(mem.method(), "memory");
        assert_eq!(mem.resolve(&did).unwrap().id, doc.id);

        match mem.resolve("did:key:zNotRegistered") {
            Err(AgentCredsError::DidResolutionFailed { did, .. }) => {
                assert_eq!(did, "did:key:zNotRegistered");
            }
            other => panic!("an unknown DID must be refused: {other:?}"),
        }
    }

    /// The consequence of that override, through the dispatcher: an in-memory resolver
    /// that lacks the document must not shadow a delegate that can serve it.
    #[test]
    fn an_in_memory_miss_does_not_shadow_a_later_resolver() {
        let served = a_document();
        let r = UniversalResolver::new(vec![
            Box::new(InMemoryResolver::new()), // holds nothing
            Box::new(Stub {
                method: "web",
                doc: served.clone(),
            }),
        ]);
        assert_eq!(
            r.resolve("did:web:example.com").unwrap().id,
            served.id,
            "an empty in-memory resolver must decline rather than swallow the request"
        );
    }
}
