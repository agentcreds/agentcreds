//! Networked DID method resolvers for AgentCreds.
//!
//! These live **outside** `agentcreds-core` so the core has no network dependency
//! in its manifest - it is unconditionally offline. Each resolver here implements
//! [`agentcreds_core::did::DidResolver`], so it drops into the core's
//! `UniversalResolver` dispatcher and everything downstream (registry resolution,
//! cross-org verification) is unchanged.
//!
//! - [`WebResolver`] - `did:web` over HTTPS (feature `resolver-web`)
//! - [`UniversalResolverClient`] - a DIF Universal Resolver endpoint (feature `resolver-universal`)
//! - [`CheqdResolver`] / [`IndyResolver`] - ledger-method stubs (features `resolver-cheqd` / `resolver-indy`)
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Same panic posture as agentcreds-core. This crate is the ONLY part of the SDK
// that touches the network, so it handles untrusted, attacker-influenced input
// (DID documents, resolver responses) - a panic here is a remote DoS on whatever
// embeds it. It previously carried only `forbid(unsafe_code)`, a weaker bar than
// the offline core it fronts.
#![deny(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "resolver-web")]
pub mod web;
#[cfg(feature = "resolver-web")]
pub use web::WebResolver;

#[cfg(feature = "resolver-universal")]
pub mod universal;
#[cfg(feature = "resolver-universal")]
pub use universal::UniversalResolverClient;

#[cfg(feature = "resolver-cheqd")]
pub mod cheqd;
#[cfg(feature = "resolver-cheqd")]
pub use cheqd::CheqdResolver;

#[cfg(feature = "resolver-indy")]
pub mod indy;
#[cfg(feature = "resolver-indy")]
pub use indy::IndyResolver;
