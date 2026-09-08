//! Node.js bindings for `agentcreds-core` - verifiable, attenuable
//! delegation for AI agents, verified offline.
//!
//! All bindings are synchronous: every operation in the underlying Rust
//! crate is sub-millisecond, so there is no `Promise`/`async` in this API.

#![deny(clippy::all)]
// `#[napi]` only binds inherent methods, so every class exposes JS's
// `toString()` via an inherent `to_string`, not `std::fmt::Display`.
#![allow(clippy::inherent_to_string)]

#[macro_use]
extern crate napi_derive;

mod adr;
mod approval;
mod audit;
mod compliance;
mod config;
mod convert;
mod credential;
mod delegation;
mod error;
mod identity;
mod oidc;
mod pop;
mod principal;
mod registry;
mod revocation;
mod rotation;
mod sd_jwt;
mod spiffe;
mod testkit;
mod wimse;

#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
