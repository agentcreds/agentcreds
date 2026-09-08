//! Delegation engine - the cryptographic heart of AgentCreds.
//!
//! ## Design
//!
//! A [`DelegationToken`] **is** a [Biscuit](https://www.biscuitsec.org/) token.
//! The runtime bearer the agent presents per call is a real Biscuit; the VC is
//! the anchor, the Biscuit is the bearer.
//!
//!   - **Authority block** (depth 0): built by [`DelegationToken::mint`] and
//!     signed by the credential subject's Ed25519 *delegation key*. It carries
//!     the scope as Datalog - `root_tool(..)` facts plus a `check if
//!     operation($op), [..].contains($op)` allow-list and a `check if time($t),
//!     $t <= <expiry>` TTL.
//!   - **Attenuation blocks** (depth 1..N): each is a Biscuit *third-party
//!     block* signed by the delegate agent's own delegation key, adding a
//!     *narrower* allow-list check. Because Biscuit only ever *adds* checks,
//!     scope can only narrow - widening is structurally impossible, enforced by
//!     the token's own Datalog evaluation rather than by policy.
//!
//! ## Identity binding
//!
//! Biscuit signs blocks with Ed25519 keys; agent identities may be Ed25519 or
//! P-256, so every agent carries a dedicated Ed25519 *delegation subkey*
//! attested by its primary identity key (see [`crate::did`]). Each hop records
//! that attestation, and verification checks three things per hop: the Biscuit
//! block was signed by the delegation key, the delegation key is attested by
//! the agent's primary key, and the attested DID is the agent named at that
//! hop. That preserves "every hop is bound to a real agent identity" on top of
//! Biscuit's capability attenuation.
//!
//! ## Authorization
//!
//! [`DelegationToken::verify`] runs a real Biscuit `Authorizer`: it adds the
//! requested `operation(..)` and the current `time(..)` and evaluates every
//! block's Datalog checks in one pass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use biscuit_auth::builder::{Algorithm as BiscuitAlgorithm, AuthorizerBuilder, BlockBuilder};
use biscuit_auth::{AuthorizerLimits, Biscuit, KeyPair, PrivateKey, PublicKey as BiscuitPublicKey};

use crate::did::{verify_delegation_attestation_resolved, AgentIdentity, DidResolver, TrustAnchor};
use crate::vc::CapabilityCredential;
use crate::{error::AgentCredsError, Result};

// R10 human-authorization primitives now live in `crate::approval`;
// re-exported here so existing `crate::delegation::*` paths are unchanged.
pub use crate::approval::{
    ApprovalEvidence, ApproverDirectory, ApproverEntry, ConsumedApprovals, Gate,
};
// Intent-alignment primitives (AARM R3/R7). Re-exported here alongside the approval
// types because they are the same pattern - a judgement made out of band, carried as
// signed evidence bound to the exact action, verified offline - and share the
// `ConsumedApprovals` ledger for one-time reliance.
pub use crate::intent::{
    AlignmentEvidence, AlignmentPolicy, AlignmentVerdict, IntentStatement, Judgement,
};

// -- Biscuit interop helpers ----------------------------------------------------

/// Map a Biscuit error into our error type (structural / signature failures).
fn bz<T>(r: std::result::Result<T, biscuit_auth::error::Token>) -> Result<T> {
    r.map_err(|e| AgentCredsError::InvalidBiscuitSignature {
        reason: e.to_string(),
    })
}

/// The signature algorithm AgentCreds delegation keys use. biscuit-auth 6 supports
/// more than one, so key parsing must name it explicitly; ours are Ed25519 throughout
/// (see `AgentIdentity::generate_delegation_key`). Stated once here so the choice is
/// visible rather than repeated at each call site.
const DELEGATION_ALG: BiscuitAlgorithm = BiscuitAlgorithm::Ed25519;

/// Build a Biscuit signing keypair from raw Ed25519 delegation secret bytes.
fn keypair_from_secret(secret: &[u8]) -> Result<KeyPair> {
    let pk = PrivateKey::from_bytes(secret, DELEGATION_ALG).map_err(|e| {
        AgentCredsError::InvalidKeyMaterial {
            reason: format!("delegation private key invalid: {e}"),
        }
    })?;
    Ok(KeyPair::from(&pk))
}

/// Parse a Biscuit Ed25519 public key from raw 32 bytes.
fn pubkey_from_bytes(b: &[u8]) -> Result<BiscuitPublicKey> {
    BiscuitPublicKey::from_bytes(b, DELEGATION_ALG).map_err(|e| {
        AgentCredsError::InvalidKeyMaterial {
            reason: format!("delegation public key invalid: {e}"),
        }
    })
}

/// Quote a value for inclusion in a Datalog string term, rejecting any
/// character that could break out of the quotes (defense against injection
/// through tool identifiers or DIDs).
fn datalog_str(s: &str) -> Result<String> {
    if s.contains(['"', '\\', '\n', '\r', '\0']) {
        return Err(AgentCredsError::OutOfBounds {
            field: "scope",
            detail: format!("illegal character in Datalog string term: {s:?}"),
        });
    }
    Ok(format!("\"{s}\""))
}

/// Render a sorted set of tool identifiers as a Datalog set literal,
/// e.g. `["tool:email", "tool:search"]`.
fn tool_set_literal(tools: &[String]) -> Result<String> {
    let mut parts = Vec::with_capacity(tools.len());
    for t in tools {
        parts.push(datalog_str(t)?);
    }
    Ok(format!("[{}]", parts.join(", ")))
}

/// Tools of a scope in stable (sorted) order - Datalog output must be
/// deterministic so two equal scopes produce byte-identical blocks.
fn sorted_tools(scope: &Scope) -> Vec<String> {
    let mut v: Vec<String> = scope.tools.iter().cloned().collect();
    v.sort_unstable();
    v
}

/// Resources of a scope in stable (sorted) order, for deterministic Datalog.
fn sorted_resources(scope: &Scope) -> Vec<String> {
    let mut v: Vec<String> = scope.resources.iter().cloned().collect();
    v.sort_unstable();
    v
}

/// True if `resource` falls under one of a principal's resource-authority
/// patterns. A pattern is a prefix; a trailing `*` is stripped before matching,
/// so `"mailbox:alice@acme.com/*"` covers any `"mailbox:alice@acme.com/..."`.
/// Used once at mint / `verify_rooted` to bound a token's exact resources to the
/// human's entitlement - not on the per-call hot path.
fn resource_within_authority(resource: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        let prefix = p.strip_suffix('*').unwrap_or(p);
        resource.starts_with(prefix)
    })
}

/// Biscuit date literal (RFC 3339, second precision, UTC).
fn date_literal(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Runtime bounds for the Biscuit authorizer. The **deterministic** bound is
/// facts/iterations (a function of chain depth); `max_time` is only a wall-clock
/// backstop, raised far above biscuit-auth's 1 ms default so a *valid* chain is never
/// spuriously denied under scheduler/GC pressure. The 1 ms default is timing-flaky on
/// deep on-behalf-of chains - biscuit-auth's own tests bump it for the same reason.
fn authorizer_limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_time: std::time::Duration::from_secs(1),
        ..Default::default()
    }
}

/// An authorizer over `biscuit`, carrying our runtime bounds. biscuit-auth 6 splits
/// this into a consuming `AuthorizerBuilder` that is `build`-ed against the token,
/// replacing v4's `biscuit.authorizer()` + `set_limits`.
fn bounded_authorizer(biscuit: &Biscuit) -> Result<biscuit_auth::Authorizer> {
    bz(AuthorizerBuilder::new()
        .set_limits(authorizer_limits())
        .build(biscuit))
}

/// Run a single-column string query against the authority block.
fn query_strings(biscuit: &Biscuit, rule: &str) -> Result<Vec<String>> {
    let mut az = bounded_authorizer(biscuit)?;
    let res: Vec<(String,)> = bz(az.query(rule))?;
    Ok(res.into_iter().map(|(s,)| s).collect())
}

/// Run a single-column integer query against the authority block.
fn query_ints(biscuit: &Biscuit, rule: &str) -> Result<Vec<i64>> {
    let mut az = bounded_authorizer(biscuit)?;
    let res: Vec<(i64,)> = bz(az.query(rule))?;
    Ok(res.into_iter().map(|(i,)| i).collect())
}

/// Run a two-column string query against the authority block (all blocks).
fn query_pairs(biscuit: &Biscuit, rule: &str) -> Result<Vec<(String, String)>> {
    let mut az = bounded_authorizer(biscuit)?;
    let res: Vec<(String, String)> = bz(az.query(rule))?;
    Ok(res)
}

// -- Scope --------------------------------------------------------------------

/// A set of permitted capabilities at one delegation hop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scope {
    /// Tool identifiers permitted at this level.
    pub tools: HashSet<String>,
    /// Optional spend limit in USD-cents.
    ///
    /// A **ceiling on delegated authority**, not a running balance: nothing decrements
    /// it. It bounds what any hop may assert, and it bounds
    /// [`max_action_cost`](Self::max_action_cost). For a limit the runtime actually
    /// enforces per call, set `max_action_cost`.
    pub budget_usd: Option<u32>,
    /// Maximum cost of any **single action**, in USD-cents. `None` = no per-action cap.
    ///
    /// This is the enforced transaction limit (ATF S-4). Unlike `budget_usd` it is
    /// checked on the authorization path: the mint and every attenuation emit a Datalog
    /// check, so the cap travels with the authority and can only tighten across hops.
    ///
    /// **It is a per-action cap, not a cumulative budget.** Ten actions of 50 cents each
    /// pass a 100-cent cap. Capping total spend needs a running balance, which is
    /// per-session state on a path whose value is being stateless and offline - the
    /// tension recorded in `Docs/pop-replay-posture.md`. Do not read this as a spend
    /// pool.
    ///
    /// **Setting it makes pricing mandatory.** A capped token denies any action whose
    /// [`Action::cost`] is absent, because a cap that silently passes unpriced calls
    /// would be a designation that looks enforced and is not.
    #[serde(default)]
    pub max_action_cost: Option<u32>,
    /// Maximum remaining delegation depth.
    pub max_depth: u32,
    /// Resource identifiers this level may touch (exact-match allow-list). Empty
    /// = no in-token resource constraint. This is the "whose data" axis of the
    /// on-behalf-of model; it can only narrow across hops.
    #[serde(default)]
    pub resources: HashSet<String>,
    /// Execution-time human-authorization designations (R10). Each names a tool
    /// that requires human-approval evidence before execution. Emitted into the
    /// Biscuit at mint/attenuate; because they are append-only facts, gates can
    /// only be added or preserved across hops, never removed (monotone).
    #[serde(default)]
    pub gates: Vec<Gate>,
}

impl Scope {
    /// Create a scope from a list of tool identifiers.
    pub fn new(tools: Vec<String>) -> Self {
        Scope {
            tools: tools.into_iter().collect(),
            budget_usd: None,
            max_action_cost: None,
            max_depth: 0,
            resources: HashSet::new(),
            gates: Vec::new(),
        }
    }

    /// Create a fully-specified scope (no resource constraint).
    pub fn with_budget_and_depth(
        tools: Vec<String>,
        budget_usd: Option<u32>,
        max_depth: u32,
    ) -> Self {
        Scope {
            tools: tools.into_iter().collect(),
            budget_usd,
            max_action_cost: None,
            max_depth,
            resources: HashSet::new(),
            gates: Vec::new(),
        }
    }

    /// Cap the cost of any single action at `usd_cents` (builder style).
    ///
    /// The cap is enforced by the verifier, monotone across hops, and bounded above by
    /// `budget_usd` when the credential sets one. Every action under the resulting token
    /// must carry an [`Action::cost`] or it is denied.
    #[must_use]
    pub fn with_max_action_cost(mut self, usd_cents: u32) -> Self {
        self.max_action_cost = Some(usd_cents);
        self
    }

    /// Add a resource allow-list to this scope (builder style).
    #[must_use]
    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources.into_iter().collect();
        self
    }

    /// Designate `tool` as requiring execution-time human approval (R10), builder
    /// style. The designation is carried in the token and can only be tightened
    /// (more gates), never removed, by later hops.
    #[must_use]
    pub fn require_approval(mut self, tool: impl Into<String>) -> Self {
        self.gates.push(Gate::approval(tool));
        self
    }

    /// Add arbitrary execution-time gates (R10), builder style.
    #[must_use]
    pub fn with_gates(mut self, gates: Vec<Gate>) -> Self {
        self.gates.extend(gates);
        self
    }

    /// Returns true if `self` is a subset of (or equal to) `parent`.
    /// Scope widening: `self.tools not a subset of parent.tools` -> false.
    pub fn is_subset_of(&self, parent: &Scope) -> bool {
        // Every tool in self must exist in parent
        if !self.tools.is_subset(&parent.tools) {
            return false;
        }
        // Budget can only decrease
        if let (Some(child_budget), Some(parent_budget)) = (self.budget_usd, parent.budget_usd) {
            if child_budget > parent_budget {
                return false;
            }
        }
        // Depth can only decrease
        if self.max_depth > parent.max_depth {
            return false;
        }
        // A per-action cap can only tighten, and REMOVING one is widening. The Datalog
        // check from the parent hop persists regardless, so this is a clear error
        // message rather than the only defence - but a subset test that called
        // cap-removal a subset would be wrong on its own terms.
        match (self.max_action_cost, parent.max_action_cost) {
            (_, None) => {}
            (None, Some(_)) => return false,
            (Some(child), Some(parent_cap)) if child > parent_cap => return false,
            (Some(_), Some(_)) => {}
        }
        // A per-action cap above the total ceiling is not within the granted authority:
        // one call could spend more than the whole delegation permits.
        if let (Some(cap), Some(ceiling)) = (self.max_action_cost, parent.budget_usd) {
            if cap > ceiling {
                return false;
            }
        }
        true
    }

    /// Find the first widening capability (for error messages).
    pub fn first_widening_capability(&self, parent: &Scope) -> Option<String> {
        self.tools.difference(&parent.tools).next().cloned()
    }
}

// -- Action -------------------------------------------------------------------

/// An action an agent wants to perform - checked against the token scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    /// The tool being invoked (e.g. `"tool:search"`).
    pub tool: String,
    /// Optional parameters (used in audit log, not evaluated in scope check).
    pub parameters: String,
    /// Timestamp of the action request.
    pub timestamp: DateTime<Utc>,
    /// The resource this call touches (e.g. `"mailbox:bob@acme.com/42"`). When a
    /// token carries a resource allow-list, this must be present and permitted.
    #[serde(default)]
    pub resource: Option<String>,
    /// The principal DID this call is being made on behalf of, supplied from the
    /// enforcer's verified session - **not** read from the token. A token bound
    /// to a principal can only be exercised with the matching `acting_for`.
    #[serde(default)]
    pub acting_for: Option<String>,
    /// What this call costs, in USD-cents, checked against
    /// [`Scope::max_action_cost`].
    ///
    /// **Supplied by the enforcement point from its own pricing, never by the agent** -
    /// the same rule as `acting_for`, and for a sharper reason. If the caller priced its
    /// own action, the cap would be a check that cannot fail: an agent moving 50,000
    /// dollars would declare one cent and pass. That is precisely the tautology removed
    /// from `oidc.rs`, where consented scope taken from the caller's own tools made
    /// `permits_tools` bound nothing while appearing to. Nothing that bounds authority
    /// may originate from the party being bounded.
    ///
    /// `None` is permitted and means "unpriced". An unpriced action is denied under a
    /// capped token; under an uncapped one it behaves exactly as before.
    #[serde(default)]
    pub cost: Option<u32>,
}

impl Action {
    /// Create an action with the current timestamp.
    pub fn new(tool: impl Into<String>, parameters: impl Into<String>) -> Self {
        Action {
            tool: tool.into(),
            parameters: parameters.into(),
            timestamp: Utc::now(),
            resource: None,
            acting_for: None,
            cost: None,
        }
    }

    /// Set the resource this action touches (builder style).
    #[must_use]
    pub fn on_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set the principal DID this action is performed on behalf of (builder style).
    #[must_use]
    pub fn on_behalf_of(mut self, principal_did: impl Into<String>) -> Self {
        self.acting_for = Some(principal_did.into());
        self
    }

    /// Price this action at `usd_cents` (builder style), for
    /// [`Scope::max_action_cost`].
    ///
    /// Call this from the enforcement point using the price the *resource owner* holds.
    /// Passing a figure the agent supplied defeats the cap entirely.
    #[must_use]
    pub fn with_cost(mut self, usd_cents: u32) -> Self {
        self.cost = Some(usd_cents);
        self
    }

    /// A stable content binding of the authorization-relevant inputs of this
    /// action - the tool, its parameters, and the resource it touches. Used to
    /// bind a proof of possession to *one specific request* (see
    /// [`crate::pop`]), so a captured presentation cannot be reused for a
    /// different call (e.g. the same proof for `amount=10` and `amount=1000000`).
    ///
    /// `acting_for` and `cost` are deliberately excluded: both are supplied by the
    /// verifier from its own session and pricing, not by the holder, so holder and
    /// verifier must compute the same binding from the inputs they share. Binding the
    /// cost here would make every proof of possession unverifiable, since the holder
    /// cannot know the verifier's price. The amount an agent *asked* for is already
    /// bound through `parameters`.
    pub fn request_binding(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"agentcreds-action-binding-v1");
        h.update((self.tool.len() as u64).to_le_bytes());
        h.update(self.tool.as_bytes());
        h.update((self.parameters.len() as u64).to_le_bytes());
        h.update(self.parameters.as_bytes());
        match &self.resource {
            Some(r) => {
                h.update([1u8]);
                h.update((r.len() as u64).to_le_bytes());
                h.update(r.as_bytes());
            }
            None => h.update([0u8]),
        }
        hex::encode(h.finalize())
    }

    /// The content binding for **execution-time human-authorization evidence**
    /// (R10). Unlike [`request_binding`](Self::request_binding), this binds the
    /// on-behalf-of **principal** as well as the operation, its parameters, and the
    /// target resource - because a human approver, unlike the PoP holder, knows
    /// exactly whom the action is for, and R10 requires the evidence to be bound to
    /// that principal. An approval grant is signed over this binding, so a grant
    /// approved for one principal cannot satisfy the same action for another.
    pub fn approval_binding(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"agentcreds-approval-binding-v1");
        h.update((self.tool.len() as u64).to_le_bytes());
        h.update(self.tool.as_bytes());
        h.update((self.parameters.len() as u64).to_le_bytes());
        h.update(self.parameters.as_bytes());
        match &self.resource {
            Some(r) => {
                h.update([1u8]);
                h.update((r.len() as u64).to_le_bytes());
                h.update(r.as_bytes());
            }
            None => h.update([0u8]),
        }
        match &self.acting_for {
            Some(p) => {
                h.update([1u8]);
                h.update((p.len() as u64).to_le_bytes());
                h.update(p.as_bytes());
            }
            None => h.update([0u8]),
        }
        hex::encode(h.finalize())
    }
}

// -- Hop (per-delegation-level identity proof + audit view) ----------------------

/// One delegation hop: the cryptographic identity proof binding the agent at
/// that level to the Biscuit block it signed, plus an advisory audit view of
/// the scope it asserted.
///
/// The identity fields (`agent_did`, `delegation_public`, `attestation`) are
/// verified on every [`DelegationToken::verify`]. The audit fields (`tools`,
/// `budget_usd`, timestamps) are advisory - enforcement lives in the Biscuit's
/// Datalog, so tampering with them cannot widen authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hop {
    /// `did:key` of the agent at this hop.
    agent_did: String,
    /// The agent's Ed25519 delegation public key that signed this hop's block.
    #[serde(with = "hex::serde")]
    delegation_public: Vec<u8>,
    /// Primary-key attestation binding `delegation_public` to `agent_did`.
    #[serde(with = "hex::serde")]
    attestation: Vec<u8>,
    /// Advisory: tools asserted at this hop (sorted).
    tools: Vec<String>,
    /// Advisory: resources asserted at this hop (sorted).
    #[serde(default)]
    resources: Vec<String>,
    /// Advisory: budget asserted at this hop.
    budget_usd: Option<u32>,
    /// Advisory: per-action cost cap asserted at this hop. Enforcement is the Biscuit
    /// check; this is the audit view of it.
    #[serde(default)]
    max_action_cost: Option<u32>,
    /// Advisory: when this hop was issued.
    issued_at: DateTime<Utc>,
    /// Advisory: when this hop expires.
    expires_at: DateTime<Utc>,
    /// Depth of this hop (0 = root).
    depth: u32,
}

// -- DelegationToken -----------------------------------------------------------

/// A multi-hop delegation token - a real Biscuit whose scope is Datalog.
///
/// Created from a [`CapabilityCredential`] via [`DelegationToken::mint`],
/// extended via [`DelegationToken::attenuate`], and checked at the tool-call
/// boundary via [`DelegationToken::verify`] / [`DelegationToken::verify_rooted`].
///
/// ## Security properties
/// - Scope can only narrow across hops (Biscuit only adds checks).
/// - Every block is signed; the whole signature chain is verified on parse.
/// - Each hop is bound to a real agent DID by a delegation-key attestation.
/// - Verification runs the token's own Datalog in one pass; target <1ms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "DelegationTokenWire", into = "DelegationTokenWire")]
pub struct DelegationToken {
    /// The serialized Biscuit token - the actual bearer credential.
    biscuit: Vec<u8>,
    /// Per-hop identity proofs and audit view (index 0 = root subject).
    hops: Vec<Hop>,

    // -- Derived cache: rebuilt from `biscuit` on parse, never trusted from the
    //    wire. Holds the *authoritative* values read out of the Biscuit's
    //    authority block. Not serialized - see `DelegationTokenWire`. ----------
    vc_id_cache: String,
    issuer_cache: String,
    subject_cache: String,
    root_tools_cache: Vec<String>,
    root_budget_cache: Option<u32>,
    root_max_action_cost_cache: Option<u32>,
    root_max_depth_cache: u32,
    /// The human principal this token is bound to (on-behalf-of), read from the
    /// Biscuit authority block. `None` for a non-OBO token.
    principal_cache: Option<String>,
    /// The root resource allow-list, read from the Biscuit authority block.
    root_resources_cache: Vec<String>,
    /// Execution-time gate designations (R10), read from every block's Biscuit
    /// facts. Authoritative - never trusted from the wire.
    gates_cache: Vec<Gate>,
}

/// Wire form of a [`DelegationToken`]: only the Biscuit and the per-hop
/// identity proofs. Every deserialization rebuilds the authoritative cache
/// from the Biscuit (via [`DelegationToken::hydrate`]), so wire-supplied scope
/// values can never be trusted directly.
#[derive(Serialize, Deserialize)]
struct DelegationTokenWire {
    #[serde(with = "hex::serde")]
    biscuit: Vec<u8>,
    hops: Vec<Hop>,
}

impl From<DelegationToken> for DelegationTokenWire {
    fn from(t: DelegationToken) -> Self {
        DelegationTokenWire {
            biscuit: t.biscuit,
            hops: t.hops,
        }
    }
}

impl TryFrom<DelegationTokenWire> for DelegationToken {
    type Error = AgentCredsError;

    fn try_from(w: DelegationTokenWire) -> Result<Self> {
        if w.hops.is_empty() {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "empty token chain".into(),
            });
        }
        let mut token = DelegationToken {
            biscuit: w.biscuit,
            hops: w.hops,
            vc_id_cache: String::new(),
            issuer_cache: String::new(),
            subject_cache: String::new(),
            root_tools_cache: Vec::new(),
            root_budget_cache: None,
            root_max_action_cost_cache: None,
            root_max_depth_cache: 0,
            principal_cache: None,
            root_resources_cache: Vec::new(),
            gates_cache: Vec::new(),
        };
        token.hydrate()?;
        Ok(token)
    }
}

impl DelegationToken {
    /// Mint a new delegation token from a capability credential.
    ///
    /// # Arguments
    /// * `vc`       - The capability credential (must be valid and not expired)
    /// * `scope`    - Initial scope (must be subset of vc.claims.tools)
    /// * `ttl_secs` - Time-to-live in seconds (capped at vc expiry)
    /// * `agent`    - The identity minting this token (its delegation key is the
    ///                Biscuit root; must be the credential subject)
    pub fn mint(
        vc: &CapabilityCredential,
        scope: Scope,
        ttl_secs: u64,
        agent: &AgentIdentity,
    ) -> Result<Self> {
        if !vc.is_valid() {
            return Err(AgentCredsError::CredentialExpired {
                expired_at: vc.expiration_date().to_rfc3339(),
            });
        }

        // The minting agent must be the credential's subject - the authority
        // block is signed with `agent`'s delegation key and `verify_rooted`
        // binds it back to `vc.subject_did()`.
        if agent.did() != vc.subject_did() {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "minting agent is not the credential subject".into(),
            });
        }

        // Autonomy ceiling: the less oversight this agent operates under, the shorter
        // its tokens may live. Refused rather than clamped - the house rule is that a
        // caller never silently receives less than it asked for and proceeds believing
        // otherwise. `attenuate` caps each child at its parent's expiry, so enforcing
        // here holds the bound down the whole chain without the token carrying the level.
        let ttl_ceiling = vc.claims().max_token_ttl_secs();
        if ttl_secs > ttl_ceiling {
            return Err(AgentCredsError::OutOfBounds {
                field: "ttl_secs",
                detail: format!(
                    "autonomy level {} permits at most {ttl_ceiling}s, requested {ttl_secs}s                      - raise the credential's oversight level or ask for a shorter token",
                    vc.claims().autonomy_level
                ),
            });
        }

        // Validate scope subset of VC claims.
        let vc_scope = Scope::with_budget_and_depth(
            vc.claims().tools.clone(),
            vc.claims().budget_usd,
            vc.claims().max_delegation_depth,
        );
        if !scope.is_subset_of(&vc_scope) {
            let cap = scope
                .first_widening_capability(&vc_scope)
                .unwrap_or_else(|| "budget or depth".into());
            return Err(AgentCredsError::ScopeWideningAttempt { capability: cap });
        }

        // Capability axis: the token's resource scope must lie within the ceiling
        // the credential grants. Independent of any principal - an org can bound
        // which namespaces an agent reaches without anyone acting on whose behalf.
        if let Some(allowed) = &vc.claims().resources {
            for r in &scope.resources {
                if !resource_within_authority(r, allowed) {
                    return Err(AgentCredsError::ScopeWideningAttempt {
                        capability: r.clone(),
                    });
                }
            }
        }

        // On-behalf-of: the token's resource scope must ALSO lie within what the
        // principal is entitled to. Both bounds apply - this is the second axis,
        // and it only earns its name when it comes from somewhere other than the
        // grant above (a human's IdP entitlement, not the same operator policy).
        if let Some(obo) = vc.on_behalf_of() {
            if !obo.resource_authority.is_empty() {
                for r in &scope.resources {
                    if !resource_within_authority(r, &obo.resource_authority) {
                        return Err(AgentCredsError::ConsentViolation {
                            capability: r.clone(),
                        });
                    }
                }
            }
        }

        let now = Utc::now();
        let expires_at = std::cmp::min(
            vc.expiration_date(),
            now + chrono::Duration::seconds(ttl_secs as i64),
        );

        let tools = sorted_tools(&scope);
        let resources = sorted_resources(&scope);
        let root_kp = keypair_from_secret(agent.delegation_secret_bytes())?;

        // Build the authority block as Datalog. biscuit-auth 6's builders are
        // CONSUMING - `fact`/`check` take and return `Self` rather than mutating in
        // place - so each step reassigns `b`. Same emitted Datalog, same token bytes.
        let mut b = Biscuit::builder();
        b = bz(b.fact(format!("vc_id({})", datalog_str(&vc.id)?).as_str()))?;
        b = bz(b.fact(format!("issuer({})", datalog_str(&vc.issuer)?).as_str()))?;
        b = bz(b.fact(format!("subject({})", datalog_str(vc.subject_did())?).as_str()))?;
        b = bz(b.fact(format!("max_depth({})", scope.max_depth).as_str()))?;
        if let Some(budget) = scope.budget_usd {
            b = bz(b.fact(format!("budget({budget})").as_str()))?;
        }
        // Per-action spend cap (ATF S-4). The limit is inlined as a LITERAL in the
        // check rather than referenced through the `max_action_cost` fact. That is not
        // stylistic: Datalog checks are existential, so `$c <= $cap` reading `$cap` from
        // facts would be satisfied if ANY hop's cap matched - and a later hop's tighter
        // cap would be bypassed by the parent's looser one still sitting in the
        // authorizer. With literals, each hop contributes an independent check and all
        // must pass, which makes the effective cap the minimum across the chain. This is
        // the same shape the tool and resource checks already use.
        //
        // A check with no matching fact FAILS in Biscuit, so a capped token denies any
        // action that arrives unpriced. That is the intended direction.
        if let Some(cap) = scope.max_action_cost {
            b = bz(b.fact(format!("max_action_cost({cap})").as_str()))?;
            b = bz(b.check(format!("check if action_cost($c), $c <= {cap}").as_str()))?;
        }
        for t in &tools {
            b = bz(b.fact(format!("root_tool({})", datalog_str(t)?).as_str()))?;
        }
        b = bz(b.check(
            format!(
                "check if operation($op), {}.contains($op)",
                tool_set_literal(&tools)?
            )
            .as_str(),
        ))?;
        b = bz(b.check(format!("check if time($t), $t <= {}", date_literal(expires_at)).as_str()))?;

        // Principal binding (on-behalf-of): an immutable authority-block fact and
        // a check that any asserted `acting_for` must equal it. Because this is at
        // depth 0 and Biscuit blocks only *add* checks, no attenuation can change
        // the bound principal - it can be preserved or the token rejected, never
        // swapped.
        if let Some(obo) = vc.on_behalf_of() {
            b = bz(b.fact(format!("principal({})", datalog_str(&obo.principal_did)?).as_str()))?;
            b = bz(b.check("check if acting_for($p), principal($p)"))?;
        }

        // Resource scope: an exact-match allow-list. Like tools, a parent block's
        // check always persists across hops, so resources can only narrow.
        for r in &resources {
            b = bz(b.fact(format!("root_resource({})", datalog_str(r)?).as_str()))?;
        }
        if !resources.is_empty() {
            b = bz(b.check(
                format!(
                    "check if resource($r), {}.contains($r)",
                    tool_set_literal(&resources)?
                )
                .as_str(),
            ))?;
        }

        // Execution-time human-authorization designations (R10). Each gate is an
        // append-only `gate(kind, tool)` fact, so later hops can add gates but can
        // never remove one - the designation is monotone and travels with the
        // authority. Enforcement (require verified, principal-bound, one-time
        // evidence; fail closed on an unrecognized kind) is in `verify_rooted_gated`.
        // The union of the agent-chosen scope gates and the gates the issuing
        // credential *mandates* - a gated credential cannot be spent ungated.
        for g in scope.gates.iter().chain(vc.required_gates().iter()) {
            b = bz(b.fact(
                format!("gate({}, {})", datalog_str(&g.kind)?, datalog_str(&g.tool)?).as_str(),
            ))?;
        }

        let biscuit = bz(b.build(&root_kp))?;
        let bytes = bz(biscuit.to_vec())?;

        let hop = Hop {
            agent_did: agent.did().to_string(),
            delegation_public: agent.delegation_public_key().to_vec(),
            attestation: agent.delegation_attestation().to_vec(),
            tools,
            resources,
            budget_usd: scope.budget_usd,
            max_action_cost: scope.max_action_cost,
            issued_at: now,
            expires_at,
            depth: 0,
        };

        let mut token = DelegationToken {
            biscuit: bytes,
            hops: vec![hop],
            vc_id_cache: String::new(),
            issuer_cache: String::new(),
            subject_cache: String::new(),
            root_tools_cache: Vec::new(),
            root_budget_cache: None,
            root_max_action_cost_cache: None,
            root_max_depth_cache: 0,
            principal_cache: None,
            root_resources_cache: Vec::new(),
            gates_cache: Vec::new(),
        };
        token.hydrate()?;
        Ok(token)
    }

    /// Attenuate this token for a sub-agent.
    ///
    /// `narrow` must be subset of the current leaf hop's scope. Appends a Biscuit
    /// third-party block signed by `agent`'s delegation key; widening is
    /// structurally impossible.
    ///
    /// # Arguments
    /// * `narrow`   - Narrower scope for the sub-agent
    /// * `ttl_secs` - TTL for this hop (capped at parent TTL)
    /// * `agent`    - The identity of the sub-agent being delegated to
    pub fn attenuate(&self, narrow: Scope, ttl_secs: u64, agent: &AgentIdentity) -> Result<Self> {
        let parent = self
            .hops
            .last()
            .ok_or_else(|| AgentCredsError::InvalidBiscuitSignature {
                reason: "empty token chain".into(),
            })?;
        let new_depth = parent.depth + 1;

        // Depth limit - bounded by the root's max delegation depth.
        if self.depth() >= self.root_max_depth_cache {
            return Err(AgentCredsError::DelegationDepthExceeded {
                depth: new_depth,
                max: self.root_max_depth_cache,
            });
        }

        // Scope widening check (clear errors; the Biscuit enforces it too).
        let mut parent_scope = Scope::with_budget_and_depth(
            parent.tools.clone(),
            parent.budget_usd,
            self.root_max_depth_cache.saturating_sub(parent.depth),
        );
        // Compare against the tightest cap in force, not just this hop's assertion:
        // the parent's Datalog check runs whatever a later hop claims, so using the
        // hop-local value would let attenuation report success against a bound the
        // verifier will then refuse.
        parent_scope.max_action_cost = self.root_max_action_cost_cache;
        let mut narrow_for_check = Scope::with_budget_and_depth(
            narrow.tools.iter().cloned().collect(),
            narrow.budget_usd,
            narrow.max_depth.min(parent_scope.max_depth),
        );
        // Deliberately NOT `.or(parent_scope.max_action_cost)`. Silently inheriting the
        // parent's cap would give `None` two meanings - "no cap" at mint, "keep the
        // parent's" here - and a caller who built the child scope with `Scope::new`
        // would believe the call was uncapped, then meet a confusing `action_cost`
        // denial at verification. Restating the cap is required, and omitting it is
        // refused here with a clear error. The parent's Datalog check binds either way,
        // so this is about where the developer finds out, not whether the cap holds.
        narrow_for_check.max_action_cost = narrow.max_action_cost;
        if !narrow_for_check.is_subset_of(&parent_scope)
            || !narrow
                .tools
                .is_subset(&parent.tools.iter().cloned().collect())
        {
            let parent_tools: HashSet<String> = parent.tools.iter().cloned().collect();
            let cap = narrow
                .tools
                .difference(&parent_tools)
                .next()
                .cloned()
                .unwrap_or_else(|| "budget or depth".into());
            return Err(AgentCredsError::ScopeWideningAttempt { capability: cap });
        }

        let now = Utc::now();
        // `as i64` on a u64 above `i64::MAX` wraps, and `Duration::seconds` PANICS for a
        // large-magnitude result rather than erroring - `2^63` maps to `i64::MIN`, which is
        // outside chrono's representable range. `min` with the parent's expiry would bound
        // the RESULT, but the panic happens while constructing the Duration, before the
        // comparison. Found by fuzzing the issuance API; reachable here by any SDK caller.
        let ttl = chrono::Duration::try_seconds(ttl_secs.min(crate::vc::MAX_VALID_FOR_SECS) as i64)
            .ok_or_else(|| AgentCredsError::OutOfBounds {
                field: "ttl_secs",
                detail: format!("must be <= {}", crate::vc::MAX_VALID_FOR_SECS),
            })?;
        let expires_at = std::cmp::min(parent.expires_at, now + ttl);

        let tools = sorted_tools(&narrow);
        let resources = sorted_resources(&narrow);

        // Parse the parent Biscuit and append a third-party block signed by the
        // sub-agent's delegation key.
        let root_pk = pubkey_from_bytes(&self.hops[0].delegation_public)?;
        let parent_biscuit = bz(Biscuit::from(&self.biscuit, root_pk))?;
        let request = bz(parent_biscuit.third_party_request())?;

        let mut block = BlockBuilder::new();
        block = bz(block.fact(format!("hop({})", datalog_str(agent.did())?).as_str()))?;
        block = bz(block.check(
            format!(
                "check if operation($op), {}.contains($op)",
                tool_set_literal(&tools)?
            )
            .as_str(),
        ))?;
        block =
            bz(block
                .check(format!("check if time($t), $t <= {}", date_literal(expires_at)).as_str()))?;
        // Narrow the resource scope. The parent's resource check still runs, so
        // this can only further constrain - adding resources outside the parent
        // set has no effect (the result is the intersection).
        if !resources.is_empty() {
            block = bz(block.check(
                format!(
                    "check if resource($r), {}.contains($r)",
                    tool_set_literal(&resources)?
                )
                .as_str(),
            ))?;
        }

        // Narrow the per-action cap. As at mint the bound is a literal, so this check
        // and the parent's both run and the tighter one wins. A sub-delegator that omits
        // a cap does not escape the parent's: the parent's check persists.
        if let Some(cap) = narrow.max_action_cost {
            block = bz(block.fact(format!("max_action_cost({cap})").as_str()))?;
            block = bz(block.check(format!("check if action_cost($c), $c <= {cap}").as_str()))?;
        }

        // A sub-delegator may *add* execution-time gates (R10) - tightening the
        // designation. It cannot remove a parent's gate: parent-block facts persist
        // in the authorizer, so gates only ever accumulate across the chain.
        for g in &narrow.gates {
            block = bz(block.fact(
                format!("gate({}, {})", datalog_str(&g.kind)?, datalog_str(&g.tool)?).as_str(),
            ))?;
        }

        let delegate_private =
            PrivateKey::from_bytes(agent.delegation_secret_bytes(), DELEGATION_ALG).map_err(
                |e| AgentCredsError::InvalidKeyMaterial {
                    reason: format!("delegation private key invalid: {e}"),
                },
            )?;
        let delegate_public = pubkey_from_bytes(agent.delegation_public_key())?;
        let response = bz(request.create_block(&delegate_private, block))?;
        let new_biscuit = bz(parent_biscuit.append_third_party(delegate_public, response))?;
        let bytes = bz(new_biscuit.to_vec())?;

        let hop = Hop {
            agent_did: agent.did().to_string(),
            delegation_public: agent.delegation_public_key().to_vec(),
            attestation: agent.delegation_attestation().to_vec(),
            tools,
            resources,
            budget_usd: narrow.budget_usd,
            max_action_cost: narrow.max_action_cost,
            issued_at: now,
            expires_at,
            depth: new_depth,
        };

        let mut new_hops = self.hops.clone();
        new_hops.push(hop);

        let mut token = DelegationToken {
            biscuit: bytes,
            hops: new_hops,
            vc_id_cache: String::new(),
            issuer_cache: String::new(),
            subject_cache: String::new(),
            root_tools_cache: Vec::new(),
            root_budget_cache: None,
            root_max_action_cost_cache: None,
            root_max_depth_cache: 0,
            principal_cache: None,
            root_resources_cache: Vec::new(),
            gates_cache: Vec::new(),
        };
        token.hydrate()?;
        Ok(token)
    }

    /// Verify the integrity and authenticity of the delegation chain, and that
    /// `action` is permitted, by running the token's own Datalog.
    ///
    /// Checks: the full Biscuit signature chain (on parse), per-hop identity
    /// binding (block signer <-> delegation key <-> attested DID), the delegation
    /// depth bound, token expiry, and the requested action against every
    /// block's Datalog allow-list.
    ///
    /// # Authority caveat
    /// This proves the chain is internally consistent and authentically signed,
    /// but not that the root authority traces to a trusted anchor - an attacker
    /// can mint a well-formed chain rooted at a `did:key` they control. Use
    /// [`DelegationToken::verify_rooted`] for the complete, anchor-rooted check.
    pub fn verify(&self, action: &Action) -> Result<()> {
        self.verify_inner(action, None, Utc::now())
    }

    /// [`verify`](Self::verify), evaluated **as of `now`**.
    ///
    /// The instant reaches both the friendly expiry check and the Datalog `time()` fact
    /// that cryptographically enforces it, so there is one clock per evaluation rather
    /// than two that could disagree. See
    /// [`CapabilityCredential::verify_at`](crate::vc::CapabilityCredential::verify_at)
    /// for when this is appropriate - and why it is not the enforcement path.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), with expiry judged against `now`.
    pub fn verify_at(&self, action: &Action, now: DateTime<Utc>) -> Result<()> {
        self.verify_inner(action, None, now)
    }

    /// Like [`verify`](Self::verify), but resolves non-`did:key` agent DIDs
    /// (e.g. `did:web`) through `resolver` to check each hop's delegation-key
    /// attestation. `did:key` hops need no resolver.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), plus `ResolverRequired` / `DidResolutionFailed`
    /// if a non-`did:key` hop cannot be resolved.
    pub fn verify_with_resolver(&self, action: &Action, resolver: &dyn DidResolver) -> Result<()> {
        self.verify_inner(action, Some(resolver), Utc::now())
    }

    fn verify_inner(
        &self,
        action: &Action,
        resolver: Option<&dyn DidResolver>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let biscuit = self.parse_and_check_identity(resolver)?;

        // Depth bound.
        if self.depth() > self.root_max_depth_cache {
            return Err(AgentCredsError::DelegationDepthExceeded {
                depth: self.depth(),
                max: self.root_max_depth_cache,
            });
        }

        // Expiry - friendly label from the advisory min expiry; the Datalog
        // time check below is the cryptographic enforcement. Both read the `now`
        // parameter, so an evaluation cannot straddle two different clocks.
        if let Some(min_expiry) = self.hops.iter().map(|h| h.expires_at).min() {
            if now > min_expiry {
                return Err(AgentCredsError::TokenExpired {
                    secs_ago: (now - min_expiry).num_seconds(),
                });
            }
        }

        // Principal binding (on-behalf-of): a token bound to a human principal
        // may only be exercised on that human's behalf. The Datalog check below
        // is the cryptographic enforcement; this yields a clear error and
        // rejects a token presented with no - or a mismatched - `acting_for`.
        //
        // This compares the token against the *request*, which is a different
        // failure from the token disagreeing with its credential (step 5 of
        // `verify_rooted_inner`). Keep them as distinct error variants: the
        // remedies are opposite - here the relying party must supply
        // `acting_for`, there the token is genuinely wrong for the credential.
        if let Some(principal) = &self.principal_cache {
            match &action.acting_for {
                Some(p) if p == principal => {}
                other => {
                    return Err(AgentCredsError::ActingForMismatch {
                        required: principal.clone(),
                        asserted: other.clone(),
                    });
                }
            }
        }

        // Action authorization via the Biscuit Authorizer (real Datalog). The request
        // facts are assembled on a consuming `AuthorizerBuilder` and only then bound to
        // the token; identical Datalog to the v4 `biscuit.authorizer()` form.
        let mut azb = AuthorizerBuilder::new().set_limits(authorizer_limits());
        azb = bz(azb.fact(format!("time({})", date_literal(now)).as_str()))?;
        azb = bz(azb.fact(format!("operation({})", datalog_str(&action.tool)?).as_str()))?;
        if let Some(resource) = &action.resource {
            azb = bz(azb.fact(format!("resource({})", datalog_str(resource)?).as_str()))?;
        }
        if let Some(cost) = action.cost {
            azb = bz(azb.fact(format!("action_cost({cost})").as_str()))?;
        }
        if let Some(principal) = &action.acting_for {
            azb = bz(azb.fact(format!("acting_for({})", datalog_str(principal)?).as_str()))?;
        }
        azb = bz(azb.policy("allow if true"))?;
        let mut az = bz(azb.build(&biscuit))?;
        az.authorize().map_err(|e| AgentCredsError::ActionDenied {
            action: action.tool.clone(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Verify `action` against this token **and** bind the chain's root to an
    /// anchor-issued credential. The complete check a relying party should run.
    ///
    /// In addition to every check in [`DelegationToken::verify`], this:
    ///  1. Verifies `vc` against `anchor` (issuer signature, not expired).
    ///  2. Confirms the token was derived from `vc` (`vc_id` / `issuer`).
    ///  3. Confirms the root block was minted by the VC's subject agent.
    ///  4. Confirms the root scope is within the VC's granted claims.
    ///
    /// # Bearer-token caveat
    /// A delegation token is a bearer credential. Closing presentation-time
    /// theft / prefix-stripping requires proof-of-possession - see
    /// [`crate::pop`]. Mint short TTLs and narrow scopes accordingly.
    pub fn verify_rooted(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
    ) -> Result<()> {
        self.verify_rooted_inner(action, vc, anchor, None, Utc::now())
    }

    /// [`verify_rooted`](Self::verify_rooted), evaluated **as of `now`**.
    ///
    /// One instant governs the whole evaluation - the credential's expiry, every hop's
    /// expiry, and the Datalog `time()` fact - so the answer is internally consistent
    /// rather than assembled from checks that each read the clock separately.
    ///
    /// Intended for **audit re-verification** ("was this authorized when it happened?")
    /// and for golden conformance vectors that must outlive the token lifetimes the
    /// autonomy ladder permits. Revocation is *not* covered here: a historical answer
    /// also needs the status list as it stood at `now`, not today's - see
    /// [`CapabilityCredential::verify_at`](crate::vc::CapabilityCredential::verify_at).
    ///
    /// **Not the enforcement path.** Real-time relying parties call
    /// [`verify_rooted`](Self::verify_rooted).
    ///
    /// # Errors
    /// As [`verify_rooted`](Self::verify_rooted), with every time check judged against `now`.
    pub fn verify_rooted_at(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.verify_rooted_inner(action, vc, anchor, None, now)
    }

    /// Like [`verify_rooted`](Self::verify_rooted), but resolves non-`did:key`
    /// agent DIDs through `resolver` for the per-hop attestation checks.
    ///
    /// # Errors
    /// As [`verify_rooted`](Self::verify_rooted), plus resolution errors.
    pub fn verify_rooted_with_resolver(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        resolver: &dyn DidResolver,
    ) -> Result<()> {
        self.verify_rooted_inner(action, vc, anchor, Some(resolver), Utc::now())
    }

    /// The execution-time gate designations carried by this token (R10), read
    /// authoritatively from the Biscuit's facts.
    pub fn gates(&self) -> &[Gate] {
        &self.gates_cache
    }

    /// The gates that designate `action.tool` - the human-authorization
    /// requirements a relying party must satisfy before executing it (R10).
    pub fn required_gates(&self, action: &Action) -> Vec<Gate> {
        self.gates_cache
            .iter()
            .filter(|g| g.tool == action.tool)
            .cloned()
            .collect()
    }

    /// The complete relying-party check **including R10 execution-time human
    /// authorization**: everything [`verify_rooted`](Self::verify_rooted) checks
    /// (R1-R6), plus, for every gate designating the requested tool, that carried,
    /// anchor-verified, principal-bound evidence satisfies it.
    ///
    /// - `evidence` - the human-authorization evidence carried with the request.
    /// - `recognized_kinds` - the gate kinds this relying party knows how to
    ///   satisfy. A designation whose kind is **not** recognized makes the action
    ///   unauthorized (fail closed), as R10 requires.
    /// - `now_unix` - current Unix time, for evidence-expiry checks.
    ///
    /// One-time reliance ("evidence not previously relied upon") is stateful, so
    /// it is enforced by the caller: this method returns the `approval_id`s it
    /// relied upon; record them and refuse a second reliance.
    ///
    /// # Errors
    /// As [`verify_rooted`](Self::verify_rooted); plus [`AgentCredsError::ActionDenied`]
    /// if a gate is unsatisfied, its kind unrecognized, or no valid evidence is present.
    pub fn verify_rooted_gated(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        evidence: &[ApprovalEvidence],
        recognized_kinds: &[&str],
        now_unix: i64,
    ) -> Result<Vec<String>> {
        // The no-directory entry point: identical checks, with only anchor-signed
        // `approval` gates satisfiable. Delegates to the single gated implementation
        // so an `approval-key` designation still fails closed (no directory => denied).
        self.verify_rooted_gated_with_directory(
            action,
            vc,
            anchor,
            evidence,
            None,
            recognized_kinds,
            now_unix,
        )
    }

    /// Like [`verify_rooted_gated`](Self::verify_rooted_gated), but also accepts the
    /// **hybrid** `approval-key` gate kind, whose evidence is signed by the
    /// individual approver's key and verified against an org-anchor-signed
    /// `ApproverDirectory` (per-human non-repudiation, single trust root). Anchor
    /// mode (`approval`) still works exactly as before; a directory is required only
    /// for `approval-key` gates.
    ///
    /// This is the single implementation behind both gated entry points; passing
    /// `directory = None` yields exactly [`verify_rooted_gated`](Self::verify_rooted_gated).
    ///
    /// # Errors
    /// As [`verify_rooted`](Self::verify_rooted); plus [`AgentCredsError::ActionDenied`]
    /// if a gate is unsatisfied, its kind unrecognized, or (for `approval-key`) no
    /// directory or valid approver-signed evidence is present.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_rooted_gated_with_directory(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        evidence: &[ApprovalEvidence],
        directory: Option<&ApproverDirectory>,
        recognized_kinds: &[&str],
        now_unix: i64,
    ) -> Result<Vec<String>> {
        self.verify_rooted(action, vc, anchor)?;

        let mut effective: Vec<Gate> = self.required_gates(action);
        for g in vc.required_gates() {
            if g.tool == action.tool && !effective.contains(g) {
                effective.push(g.clone());
            }
        }

        let deny = |reason: String| AgentCredsError::ActionDenied {
            action: action.tool.clone(),
            reason,
        };

        let mut relied_upon = Vec::new();
        for gate in effective {
            if !recognized_kinds.contains(&gate.kind.as_str()) {
                return Err(deny(format!(
                    "unrecognized execution-time gate kind '{}' - failing closed (R10)",
                    gate.kind
                )));
            }
            if gate.kind == Gate::APPROVAL {
                match evidence.iter().find(|e| {
                    e.kind == Gate::APPROVAL && e.verify(action, anchor, now_unix).is_ok()
                }) {
                    Some(e) => relied_upon.push(e.approval_id.clone()),
                    None => {
                        return Err(deny(
                            "action requires human approval; no valid execution-time evidence \
                             presented (R10)"
                                .into(),
                        ))
                    }
                }
            } else if gate.kind == Gate::APPROVAL_KEY {
                let dir = directory.ok_or_else(|| {
                    deny(
                        "action requires approver-key approval but no approver directory is \
                          configured (R10)"
                            .into(),
                    )
                })?;
                match evidence.iter().find(|e| {
                    e.kind == Gate::APPROVAL_KEY
                        && e.verify_with_directory(action, dir, anchor, now_unix, None)
                            .is_ok()
                }) {
                    Some(e) => relied_upon.push(e.approval_id.clone()),
                    None => {
                        return Err(deny(
                            "action requires approver-key approval; no valid approver-signed \
                             evidence presented (R10)"
                                .into(),
                        ))
                    }
                }
            } else {
                // Recognized, but this verifier has no handler for it. Refuse.
                //
                // `recognized_kinds` answers "do I know this designation exists", which is
                // NOT "and I have satisfied it". Falling through here treated a gate that
                // nobody enforced as met - a designation that appears enforced and is not.
                // That is the fail-OPEN direction of the R10 rule, and worse than having
                // no gate at all, because the token advertises a protection it never got.
                //
                // It matters because listing a kind in `recognized_kinds` is exactly what
                // an operator does to clear an "unrecognized gate kind" denial, so the
                // obvious remedy silently disabled the gate. Any kind added without a
                // handler - `Gate::INTENT` today - now denies until its handler exists.
                return Err(deny(format!(
                    "gate kind '{}' is recognized but this verifier has no handler for it - \
                     failing closed rather than treating an unenforced designation as met",
                    gate.kind
                )));
            }
        }
        Ok(relied_upon)
    }

    fn verify_rooted_inner(
        &self,
        action: &Action,
        vc: &CapabilityCredential,
        anchor: &TrustAnchor,
        resolver: Option<&dyn DidResolver>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // 1. The VC must itself be valid and anchor-signed - judged at the same instant
        //    as the token below, so a credential and a token cannot be assessed against
        //    two different clocks within one decision.
        vc.verify_at(anchor, true, now)?;

        // 2. The token must be derived from this VC (authoritative cache).
        if self.vc_id_cache != vc.id {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "token vc_id does not match the supplied credential".into(),
            });
        }
        if self.issuer_cache != vc.issuer {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "token issuer does not match the credential issuer".into(),
            });
        }

        // 3. The root block must have been minted by the VC's subject agent.
        if self.subject_cache != vc.subject_did() {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "token subject does not match the credential subject".into(),
            });
        }

        // 4. The root scope must be within the authority the VC grants.
        let vc_scope = Scope::with_budget_and_depth(
            vc.claims().tools.clone(),
            vc.claims().budget_usd,
            vc.claims().max_delegation_depth,
        );
        let mut root_scope = Scope::with_budget_and_depth(
            self.root_tools_cache.clone(),
            self.root_budget_cache,
            self.root_max_depth_cache,
        );
        root_scope.max_action_cost = self.root_max_action_cost_cache;
        if !root_scope.is_subset_of(&vc_scope) {
            let cap = root_scope
                .first_widening_capability(&vc_scope)
                .unwrap_or_else(|| "budget or depth".into());
            return Err(AgentCredsError::ScopeWideningAttempt { capability: cap });
        }

        // 5. On-behalf-of binding: the principal the token is bound to must be
        //    exactly the human the credential authorizes, and the token's
        //    resource scope must lie within that human's entitlement. This
        //    rejects a token that drops, adds, or swaps the principal relative to
        //    the credential it claims to derive from.
        match (self.principal_cache.as_deref(), vc.on_behalf_of()) {
            (Some(tok), Some(obo)) => {
                if tok != obo.principal_did {
                    return Err(AgentCredsError::PrincipalMismatch {
                        expected: obo.principal_did.clone(),
                        got: tok.to_string(),
                    });
                }
                if !obo.resource_authority.is_empty() {
                    for r in &self.root_resources_cache {
                        if !resource_within_authority(r, &obo.resource_authority) {
                            return Err(AgentCredsError::ConsentViolation {
                                capability: r.clone(),
                            });
                        }
                    }
                }
            }
            (Some(tok), None) => {
                return Err(AgentCredsError::PrincipalMismatch {
                    expected: "<none>".into(),
                    got: tok.to_string(),
                });
            }
            (None, Some(obo)) => {
                return Err(AgentCredsError::PrincipalMismatch {
                    expected: obo.principal_did.clone(),
                    got: "<none>".into(),
                });
            }
            (None, None) => {}
        }

        // 6. Full chain authenticity + the action check.
        self.verify_inner(action, resolver, now)
    }

    /// Parse the Biscuit (verifying the whole signature chain) and check that
    /// every hop's block signer matches its attested agent DID.
    fn parse_and_check_identity(&self, resolver: Option<&dyn DidResolver>) -> Result<Biscuit> {
        let first = self
            .hops
            .first()
            .ok_or_else(|| AgentCredsError::InvalidBiscuitSignature {
                reason: "empty token chain".into(),
            })?;
        let root_pk = pubkey_from_bytes(&first.delegation_public)?;
        let biscuit = bz(Biscuit::from(&self.biscuit, root_pk))?;

        if biscuit.block_count() != self.hops.len() {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: format!(
                    "block count {} does not match hop count {}",
                    biscuit.block_count(),
                    self.hops.len()
                ),
            });
        }

        // The authority block's `subject` fact must name the root signer.
        if self.subject_cache != first.agent_did {
            return Err(AgentCredsError::InvalidBiscuitSignature {
                reason: "authority subject does not match root signer DID".into(),
            });
        }

        let external = biscuit.external_public_keys();
        for (k, hop) in self.hops.iter().enumerate() {
            // The delegation key must be attested by the agent's primary key.
            // For non-did:key hops (e.g. did:web), the primary key is recovered
            // by resolving the DID document.
            verify_delegation_attestation_resolved(
                &hop.agent_did,
                &hop.delegation_public,
                &hop.attestation,
                resolver,
            )?;

            if k == 0 {
                // Authority block: signed by the root key we parsed with.
                continue;
            }
            // Attenuation block: the recorded delegation key must be the actual
            // third-party signer of block k.
            let signer = external.get(k).and_then(|o| o.as_ref()).ok_or_else(|| {
                AgentCredsError::InvalidBiscuitSignature {
                    reason: format!("block {k} is not a third-party block"),
                }
            })?;
            if signer.to_bytes().as_slice() != hop.delegation_public.as_slice() {
                return Err(AgentCredsError::InvalidBiscuitSignature {
                    reason: format!("block {k} signer does not match the hop delegation key"),
                });
            }
        }

        Ok(biscuit)
    }

    /// Re-derive the authoritative cache from the Biscuit. Called after
    /// construction and deserialization; never trusts wire-supplied values.
    fn hydrate(&mut self) -> Result<()> {
        let first = self
            .hops
            .first()
            .ok_or_else(|| AgentCredsError::InvalidBiscuitSignature {
                reason: "empty token chain".into(),
            })?;
        let root_pk = pubkey_from_bytes(&first.delegation_public)?;
        let biscuit = bz(Biscuit::from(&self.biscuit, root_pk))?;

        let one = |rule: &str| -> Result<String> {
            query_strings(&biscuit, rule)?
                .into_iter()
                .next()
                .ok_or_else(|| AgentCredsError::InvalidBiscuitSignature {
                    reason: format!("missing required fact: {rule}"),
                })
        };

        self.vc_id_cache = one("data($x) <- vc_id($x)")?;
        self.issuer_cache = one("data($x) <- issuer($x)")?;
        self.subject_cache = one("data($x) <- subject($x)")?;
        self.root_max_depth_cache = query_ints(&biscuit, "data($x) <- max_depth($x)")?
            .into_iter()
            .next()
            .unwrap_or(0) as u32;
        let mut tools = query_strings(&biscuit, "data($x) <- root_tool($x)")?;
        tools.sort_unstable();
        self.root_tools_cache = tools;
        self.root_budget_cache = query_ints(&biscuit, "data($x) <- budget($x)")?
            .into_iter()
            .next()
            .map(|v| v as u32);
        // The EFFECTIVE cap is the tightest asserted anywhere in the chain, matching
        // what the conjunction of per-hop checks actually enforces. Taking the first
        // would report the root's looser figure and understate the constraint.
        self.root_max_action_cost_cache = query_ints(&biscuit, "data($x) <- max_action_cost($x)")?
            .into_iter()
            .map(|v| v as u32)
            .min();
        // On-behalf-of principal (optional) and the root resource allow-list.
        self.principal_cache = query_strings(&biscuit, "data($x) <- principal($x)")?
            .into_iter()
            .next();
        let mut resources = query_strings(&biscuit, "data($x) <- root_resource($x)")?;
        resources.sort_unstable();
        self.root_resources_cache = resources;
        // Execution-time gates (R10) from every block's facts. De-duplicated and
        // sorted for a stable view; a repeated gate designates the same tool once.
        let mut gates: Vec<Gate> = query_pairs(&biscuit, "data($k, $t) <- gate($k, $t)")?
            .into_iter()
            .map(|(kind, tool)| Gate { kind, tool })
            .collect();
        gates.sort_unstable_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.tool.cmp(&b.tool)));
        gates.dedup();
        self.gates_cache = gates;
        Ok(())
    }

    /// Serialize to CBOR bytes for compact wire transport.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).map_err(AgentCredsError::from)?;
        Ok(buf)
    }

    /// Deserialise from CBOR bytes. Deserialization re-derives the
    /// authoritative cache from the embedded Biscuit (via the wire form), so
    /// the scope values are never trusted directly off the wire.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }

    /// The root VC identifier this token was derived from (from the Biscuit).
    pub fn vc_id(&self) -> &str {
        &self.vc_id_cache
    }

    /// The issuer DID (trust anchor) of the root VC (from the Biscuit).
    pub fn issuer_did(&self) -> &str {
        &self.issuer_cache
    }

    /// The DID of the leaf (most-delegated) agent.
    pub fn leaf_agent_did(&self) -> &str {
        // Safe: constructors guarantee at least one hop.
        self.hops.last().map(|h| h.agent_did.as_str()).unwrap_or("")
    }

    /// The DID of the root (subject) agent.
    pub fn root_agent_did(&self) -> &str {
        self.hops
            .first()
            .map(|h| h.agent_did.as_str())
            .unwrap_or("")
    }

    /// When this token stops being usable: the **earliest** expiry across its hops.
    ///
    /// Not the leaf's own expiry. `attenuate` caps each child at its parent, so the
    /// minimum is the effective bound - and taking the leaf's would report a longer
    /// life than the token actually has if any ancestor expires first. `verify` uses
    /// the same minimum, so this is what a caller can act on.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.hops
            .iter()
            .map(|h| h.expires_at)
            .min()
            .unwrap_or_else(Utc::now)
    }

    /// The human principal DID this token is bound to (on-behalf-of), or `None`
    /// for a non-OBO token. Read authoritatively from the Biscuit, not the wire.
    pub fn principal_did(&self) -> Option<&str> {
        self.principal_cache.as_deref()
    }

    /// The root resource allow-list this token was minted with (from the Biscuit).
    pub fn root_resources(&self) -> &[String] {
        &self.root_resources_cache
    }

    /// A stable content binding for the leaf - the SHA-256 of the serialized
    /// Biscuit. Changes if any block changes, so a stripped or substituted
    /// chain produces a different binding (used by proof-of-possession).
    pub fn leaf_binding(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.biscuit);
        hex::encode(h.finalize())
    }

    /// Current delegation depth (0 = not delegated).
    pub fn depth(&self) -> u32 {
        self.hops.len().saturating_sub(1) as u32
    }

    /// The root credential's maximum delegation depth - the ceiling that
    /// attenuation may not exceed (read from the Biscuit authority block).
    pub fn max_delegation_depth(&self) -> u32 {
        self.root_max_depth_cache
    }

    /// Extract the full delegation chain as audit entries.
    pub fn chain(&self) -> DelegationChain {
        DelegationChain {
            vc_id: self.vc_id_cache.clone(),
            issuer_did: self.issuer_cache.clone(),
            principal_did: self.principal_cache.clone(),
            entries: self
                .hops
                .iter()
                .map(|h| ChainEntry {
                    depth: h.depth,
                    agent_did: h.agent_did.clone(),
                    tools: h.tools.clone(),
                    resources: h.resources.clone(),
                    budget_usd: h.budget_usd,
                    max_action_cost: h.max_action_cost,
                    issued_at: h.issued_at,
                    expires_at: h.expires_at,
                })
                .collect(),
        }
    }
}

// -- DelegationChain (audit view) ----------------------------------------------

/// A human-readable, audit-friendly view of a delegation chain.
/// No signatures or key material - safe to include in audit logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    /// The root VC this chain was derived from.
    pub vc_id: String,
    /// The trust anchor that issued the root VC.
    pub issuer_did: String,
    /// The human principal the chain is bound to (on-behalf-of), if any.
    #[serde(default)]
    pub principal_did: Option<String>,
    /// One entry per delegation hop.
    pub entries: Vec<ChainEntry>,
}

/// One hop in a delegation chain audit view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Hop index (0 = root).
    pub depth: u32,
    /// DID of the agent at this hop.
    pub agent_did: String,
    /// Tools permitted at this hop.
    pub tools: Vec<String>,
    /// Resources permitted at this hop (empty = no resource constraint).
    #[serde(default)]
    pub resources: Vec<String>,
    /// Spend limit in USD-cents at this hop.
    pub budget_usd: Option<u32>,
    /// Enforced per-action cost cap in USD-cents at this hop (None = uncapped).
    #[serde(default)]
    pub max_action_cost: Option<u32>,
    /// When this hop was issued.
    pub issued_at: DateTime<Utc>,
    /// When this hop expires.
    pub expires_at: DateTime<Utc>,
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
