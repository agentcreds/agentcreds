//! Verifiable Credential (VC) layer.
//!
//! Implements W3C VC Data Model 1.1 capability credentials for AI agents.
//! Each credential:
//!   - Is issued by a `TrustAnchor` (org's root of trust)
//!   - Names a subject agent by DID
//!   - Declares capability scope, delegation depth, budget, and validity
//!   - Carries a linked-data proof (Ed25519Signature2020)
//!   - References a revocation entry in an OAuth Token Status List
//!
//! DATA MODEL VERSION: 1.1, not 2.0. Credentials emit the VCDM 1.1 context
//! `https://www.w3.org/2018/credentials/v1` with an `Ed25519Signature2020`
//! linked-data proof. VCDM 2.0 would mean the `https://www.w3.org/ns/credentials/v2`
//! context and a Data Integrity proof (`eddsa-2022`) - a wire-format break and a
//! conformance-test change, not a documentation edit. Do not re-label this 2.0
//! without changing what `issue` actually emits below.

use base64ct::Encoding;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::did::TrustAnchor;
use crate::{error::AgentCredsError, Result};

// -- Human authorization (on-behalf-of principal) ------------------------------

/// The human principal, attested by an identity provider, on whose behalf an
/// agent acts. This is the *bound principal* of the on-behalf-of (OBO) model:
/// distinct from the agent's tool scope, it answers "whose authority is the
/// agent exercising" and constrains "whose resources it may touch".
///
/// The human authenticates through the IdP and holds no signing key here; the
/// anchor's signature over the enclosing [`CapabilityCredential`] is what
/// attests the `principal_did` <-> IdP-subject binding. The principal is minted a
/// real, stable DID at issuance (see [`crate::principal::HumanIdentity`]), so it
/// is first-class in the same identifier space as agents and anchors.
/// **How a bound on an agent's authority was established.**
///
/// One vocabulary, used everywhere the question "where did this come from?" arises -
/// on the principal's entitlements and on the accountable party. It exists because the
/// weight an auditor should give a claim depends entirely on its origin, and that origin
/// is otherwise invisible: "Team X answers for this agent" means something different when
/// central policy assigned it than when the requester nominated itself.
///
/// The ordering is deliberate: `Attested` > `Policy` > `Asserted` in evidential strength.
/// A bound may always be *narrowed* by a weaker source; it may never be *widened* by one.
/// That is the single rule the whole issuance path enforces - nothing that bounds
/// authority may originate from the party being bounded.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthoritySource {
    /// Supplied by the requester. **Advisory: never permitted to widen a bound.**
    ///
    /// The default, so credentials written before provenance was recorded read back
    /// honestly - the weakest reading is the correct one for a record that never
    /// captured where its values came from. Absence must never be mistaken for strength.
    #[default]
    Asserted,
    /// Resolved from operator policy, server-side. The requester could not influence it.
    ///
    /// Not cryptographically attested, but the requester and the source are different
    /// parties - which is the property that makes the bound mean anything.
    Policy,
    /// Verified cryptographically at issuance - an OIDC ID token, a SPIFFE SVID.
    ///
    /// The strongest form: an authority outside this organization vouched for it.
    Attested,
}

impl AuthoritySource {
    /// Whether this is the default (asserted) source - used to omit it on the wire so
    /// existing credentials hash identically.
    #[must_use]
    pub fn is_asserted(&self) -> bool {
        matches!(self, AuthoritySource::Asserted)
    }

    /// The canonical lowercase name - the same token used on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthoritySource::Asserted => "asserted",
            AuthoritySource::Policy => "policy",
            AuthoritySource::Attested => "attested",
        }
    }

    /// Parse the canonical name.
    ///
    /// An unrecognised name returns `None` rather than falling back. Defaulting would
    /// report an unknown source as `Asserted`, which is the *weakest* reading - safe in
    /// the sense that it never overstates, but it would silently downgrade a stronger
    /// source this build does not understand, and an auditor would see evidence weaken
    /// for no reason.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "asserted" => Some(AuthoritySource::Asserted),
            "policy" => Some(AuthoritySource::Policy),
            "attested" => Some(AuthoritySource::Attested),
            _ => None,
        }
    }

    /// Evidential rank, for comparing two sources. Higher is stronger.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            AuthoritySource::Asserted => 0,
            AuthoritySource::Policy => 1,
            AuthoritySource::Attested => 2,
        }
    }

    /// Whether a bound from `self` may be *replaced* by one from `other`.
    ///
    /// Only by an equal or stronger source. A policy-resolved entitlement cannot be
    /// overwritten by a requester-asserted one - that is exactly the substitution the
    /// rule exists to prevent.
    #[must_use]
    pub fn admits(self, other: AuthoritySource) -> bool {
        other.rank() >= self.rank()
    }
}

/// What kind of principal an agent is acting for.
///
/// The distinction matters because the two are attested by different roots and mean
/// different things for accountability. A **human** principal is attested by an IdP and
/// is normally also the party answerable for the action. A **workload** principal is
/// attested by a SPIFFE trust domain and is *not* an answerable party in any sense an
/// auditor recognizes - a service cannot be held responsible, only the team that runs it.
/// That is why [`PrincipalAuthorization`] carries an accountable party separately rather
/// than assuming the principal is one.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    /// A human, attested by an identity provider (`issuer` = `iss`, `subject` = `sub`).
    ///
    /// The default so that credentials written before workloads could be principals
    /// deserialise unchanged - every one of them was a human.
    #[default]
    Human,
    /// A workload, attested by a SPIFFE trust domain (`issuer` = trust domain,
    /// `subject` = the SPIFFE ID).
    Workload,
}

impl PrincipalKind {
    /// Whether this is the default (human) kind - used to omit it on the wire so
    /// existing credentials hash identically.
    #[must_use]
    pub fn is_human(&self) -> bool {
        matches!(self, PrincipalKind::Human)
    }

    /// The canonical lowercase name - the same token used on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrincipalKind::Human => "human",
            PrincipalKind::Workload => "workload",
        }
    }

    /// Parse the canonical name.
    ///
    /// An unrecognised name returns `None` rather than falling back to `Human`. The
    /// default exists so *older* credentials, written before workloads could be
    /// principals, read back correctly - it must not be used to silently accept a kind
    /// this build does not understand, which would report a workload as a human.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(PrincipalKind::Human),
            "workload" => Some(PrincipalKind::Workload),
            _ => None,
        }
    }
}

/// Retained name for the human case. The type became kind-tagged when workloads were
/// admitted as principals; the binding, invariance and dual-axis checks are identical
/// for both, so there is one type rather than two.
pub type HumanAuthorization = PrincipalAuthorization;

/// The principal an agent acts for, and the bounds that principal's own authority puts
/// on it.
///
/// Distinct from the agent's tool scope: it answers "whose authority is the agent
/// exercising" and constrains "whose resources it may touch". Both a human (attested by
/// an IdP) and a workload (attested by a SPIFFE trust domain) are expressed here, because
/// binding, invariance and the dual-axis subset check are identical for both - only the
/// attesting root differs, which `kind` records.
///
/// The principal holds no signing key here; the anchor's signature over the enclosing
/// [`CapabilityCredential`] is what attests the `principal_did` <-> subject binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalAuthorization {
    /// The principal's stable DID, minted at issuance from the attested identity.
    pub principal_did: String,

    /// Which kind of principal this is, and therefore which root attested it.
    ///
    /// Omitted on the wire when `Human`, and defaulted back to `Human` on read. That is
    /// not cosmetic: the credential's payload hash covers these bytes, so emitting a
    /// `"kind":"human"` that was not in the original would change the hash and break
    /// every token already bound to a credential carrying a principal. The
    /// `biscuit_wire_compat` golden fixture catches exactly that.
    #[serde(default, skip_serializing_if = "PrincipalKind::is_human")]
    pub kind: PrincipalKind,

    /// **Where `scope_consented` and `resource_authority` came from.**
    ///
    /// The entitlements are the whole point of the principal axis: they bound the agent
    /// by something established *outside* the grant of capability. If they were supplied
    /// by whoever requested issuance, both axes trace to one source and the second one
    /// bounds nothing.
    ///
    /// `Attested` means an identity provider vouched for them (its `scope` claim).
    /// `Policy` means operator configuration resolved them for the attested identity -
    /// the only source available for a workload, because a SPIFFE SVID attests identity
    /// and deliberately carries no entitlement claims.
    ///
    /// Omitted on the wire when `Asserted`, so credentials that predate this hash
    /// identically - and so absence reads as the weakest source rather than an unknown
    /// one.
    #[serde(default, skip_serializing_if = "AuthoritySource::is_asserted")]
    pub entitlement_source: AuthoritySource,

    /// The attesting authority: an IdP `iss` for a human, a SPIFFE trust domain for a
    /// workload.
    pub issuer: String,

    /// The stable subject at that authority: an IdP `sub` for a human, the SPIFFE ID
    /// for a workload.
    pub subject: String,

    /// When the human granted this authorization.
    pub authorized_at: DateTime<Utc>,

    /// When the human's authorization expires (e.g. the IdP token's `exp`). The
    /// credential's own validity is capped at this instant.
    pub expires_at: DateTime<Utc>,

    /// The tools the human consented to, expressed in tool-identifier space
    /// (the IdP bridge maps OAuth scopes/claims to `"tool:*"` ids). The
    /// credential's `tools` must be a subset of this. Empty = no tool-level
    /// consent constraint recorded.
    #[serde(default)]
    pub scope_consented: Vec<String>,

    /// Resource namespaces the human is entitled to, as match patterns (e.g.
    /// `"mailbox:alice@acme.com/*"`). Bounds *whose data* the agent may touch.
    /// Empty = no in-credential resource constraint; ownership is enforced by
    /// the resource server using `principal_did`.
    #[serde(default)]
    pub resource_authority: Vec<String>,
}

// Declared on the underlying type rather than through the `HumanAuthorization`
// alias: both compile identically, but rustdoc does not index inherent methods
// written against an alias, so `PrincipalAuthorization::permits_tools` was
// unresolvable and any doc link to it failed the public repo's rustdoc gate.
impl PrincipalAuthorization {
    /// Returns true if every tool in `tools` was consented to. An empty
    /// `scope_consented` records no constraint and permits any tool.
    pub fn permits_tools(&self, tools: &[String]) -> bool {
        if self.scope_consented.is_empty() {
            return true;
        }
        let consented: std::collections::HashSet<&String> = self.scope_consented.iter().collect();
        tools.iter().all(|t| consented.contains(t))
    }

    /// The first tool in `tools` the human did not consent to, if any.
    pub fn first_unconsented_tool(&self, tools: &[String]) -> Option<String> {
        if self.scope_consented.is_empty() {
            return None;
        }
        let consented: std::collections::HashSet<&String> = self.scope_consented.iter().collect();
        tools.iter().find(|t| !consented.contains(*t)).cloned()
    }
}

// -- Capability Claims --------------------------------------------------------

/// The claims a capability credential asserts about the subject agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityClaims {
    /// Tool identifiers the agent is permitted to invoke.
    /// Convention: `"tool:<name>"` e.g. `"tool:search"`.
    pub tools: Vec<String>,

    /// Resource-namespace patterns the agent may reach - a **capability-axis**
    /// ceiling, alongside [`Self::tools`]. A pattern is a prefix; a trailing `*`
    /// is stripped before matching. `None` = unbounded by the credential.
    ///
    /// This is a bound on the *authority granted*, not on a principal's
    /// entitlement. The distinction matters because a bound needs no principal to
    /// carry it, and giving it one is expensive: a principal drags in R5's
    /// symmetric-presence rule, which requires every relying party to
    /// independently learn and assert that principal on each request. Where the
    /// bound and the principal genuinely come from different places - a human's
    /// IdP-attested entitlement vs. the org's grant - that cost buys a real second
    /// axis, and [`HumanAuthorization::resource_authority`](crate::vc::PrincipalAuthorization::resource_authority) is the right carrier.
    /// Where they come from the *same* place, as operator policy does for an
    /// attested workload, it buys nothing and this is the right carrier.
    ///
    /// Enforced at `mint`: a token's resource scope must lie within it. An
    /// authority claim, so deliberately **not** in `SD_DISCLOSABLE` - a verifier
    /// permitted not to see a bound is not bounded by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,

    /// Optional spending limit in USD-cents (None = no limit).
    pub budget_usd: Option<u32>,

    /// Maximum recursive delegation depth. 0 = agent may not delegate.
    pub max_delegation_depth: u32,

    /// Credential validity window in seconds from issuance.
    pub valid_for_secs: u64,

    /// Autonomy level (0-3): how little human oversight the agent operates under.
    /// L0 = closest supervision, L3 = fully autonomous.
    ///
    /// **Enforced**: it bounds how long a delegation token minted from this
    /// credential may live - see [`max_token_ttl_secs`]. `mint` refuses a longer
    /// TTL rather than silently shortening it, and `attenuate` caps every child at
    /// its parent's expiry, so the ceiling holds down the whole chain. The rationale
    /// is that the less anyone is watching, the less time a leaked token stays
    /// useful.
    ///
    /// **Not** a human-in-the-loop switch. This field once documented L0 as
    /// "human-in-the-loop", which nothing enforced and nothing could: L0 is the
    /// value [`CapabilityClaims::new`] produces, so *every* credential declared it
    /// while almost none carried a gate. Requiring a human is
    /// [`Self::required_gates`] (R10) - a designation carried in the authority,
    /// monotone across hops, and satisfied only by anchor-verified evidence bound to
    /// the exact action. Setting L0 and expecting a gate gets an ungated agent.
    pub autonomy_level: u8,

    /// Optional model version attestation (e.g. "gpt-4o-2024-08-06").
    pub model_version: Option<String>,

    /// SHA-256 hash of the agent artifact at deploy time.
    /// Links credential to a specific build - prevents identity drift.
    pub artifact_hash: Option<String>,

    /// Free-form provenance string for the principal that triggered issuance -
    /// e.g. a workload SPIFFE ID (see [`crate::spiffe`]). Advisory only. For an
    /// enforced human on-behalf-of principal, use [`Self::on_behalf_of`].
    pub authorized_by: Option<String>,

    /// **Who answers for what this agent does.**
    ///
    /// Distinct from the principal, and the distinction is the point. The principal is
    /// *whose authority is being exercised*; this is *who is responsible*. For a human
    /// principal the two coincide - Alice both grants and answers - so one field could
    /// carry both. For a **workload** principal they come apart: a payments service can
    /// exercise authority, but a service is not answerable to an auditor or a regulator.
    /// A team, an owner, an operator is.
    ///
    /// Unlike [`Self::authorized_by`], which is free-form provenance and *advisory*, this
    /// is an **enforced, non-suppressible** claim: it is deliberately absent from
    /// `SD_DISCLOSABLE`, so it cannot be withheld in an SD-JWT. A verifier that can be
    /// denied sight of the responsible party has no answer to give.
    ///
    /// Typed `Option` for one reason only - credentials issued before this existed must
    /// still deserialise. **Issuance requires it** (see the control plane); `None` means
    /// "issued before accountability was recorded", never "no one is responsible".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accountable_party: Option<String>,

    /// **Where `accountable_party` came from.**
    ///
    /// `Policy` when operator configuration resolved it for an attested identity;
    /// `Asserted` when an authenticated operator named it on the request. Both are
    /// legitimate, and the difference matters to an auditor: an operator holds the org's
    /// credentials and so speaks *for* the org, whereas a workload naming its own
    /// responsible party would be nominating someone else's team.
    ///
    /// Recorded rather than inferred from deployment config, which may since have
    /// changed. Excluded from `SD_DISCLOSABLE` for the same reason as the party itself -
    /// a verifier told who is responsible, but not how firmly, has been told very little.
    #[serde(default, skip_serializing_if = "AuthoritySource::is_asserted")]
    pub accountability_source: AuthoritySource,

    /// **Which revision of the ownership record named this party.**
    ///
    /// Without it, [`Self::accountable_party`] is a pointer with no time
    /// coordinate: an auditor asking "who was answerable" at some later date
    /// resolves it against an org chart that has since moved. This says *when* to
    /// resolve as of - the credential's own moment, not the reader's.
    ///
    /// `None` means no ownership record was configured for the party, not version
    /// zero. See [`crate::accountability`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_version: Option<u64>,

    /// **A salted commitment to the ownership record**, hex-encoded.
    ///
    /// Makes the resolution above *verifiable* rather than merely dated: produce
    /// the record, recompute, compare. A record that does not match was not the
    /// one committed to.
    ///
    /// Deliberately a commitment and not the record. The members are personal
    /// data, and a credential is signed, immutable, presented across
    /// organizational boundaries, and outlives the employment - so it can neither
    /// correct nor erase them. The commitment is salted, so it is not a membership
    /// oracle over a guessable list. Built by
    /// [`OwnershipRecord::commitment`](crate::accountability::OwnershipRecord::commitment).
    ///
    /// An authority-adjacent claim, so excluded from `SD_DISCLOSABLE` alongside
    /// the party itself - a commitment a verifier may be denied sight of commits
    /// to nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_commitment: Option<String>,

    /// The principal on whose behalf the subject
    /// agent acts. Unlike `authorized_by`, this is an *enforced* dimension:
    /// issuance gates `tools` to the consented scope, and the delegation token
    /// binds this principal so it cannot change across delegation hops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<HumanAuthorization>,

    /// Execution-time human-authorization gates the **issuer mandates** (R10):
    /// tools that require approval evidence before execution, regardless of what
    /// scope a minting agent chooses. `mint` emits them into the delegation token,
    /// and `verify_rooted_gated` enforces them from the credential even if a token
    /// omits them - so a gated credential cannot be spent ungated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_gates: Vec<crate::delegation::Gate>,
}

/// The longest a delegation token minted at `autonomy_level` may live, in seconds.
///
/// Higher autonomy means a shorter leash: the less human oversight an agent operates
/// under, the less time a leaked or misused token remains useful. Levels above 3 are
/// rejected by [`CapabilityClaims::validate`]; this saturates at the tightest bound
/// so an out-of-range value can never widen anything.
///
/// The ladder is defined here rather than left to each deployment because an autonomy
/// *level* is a shared vocabulary - "L3" has to mean the same thing to an issuer and a
/// relying party, or it means nothing. A deployment wanting a different bound sets a
/// shorter `valid_for_secs` on the credential, which `mint` already caps against.
#[must_use]
pub const fn max_token_ttl_secs(autonomy_level: u8) -> u64 {
    match autonomy_level {
        0 => 3600, // closest supervision - one hour
        1 => 1800,
        2 => 900,
        _ => 300, // fully autonomous (and anything out of range) - five minutes
    }
}

/// Upper bound on a credential's requested lifetime: 100 years in seconds.
///
/// Exists because the downstream `Duration::seconds(valid_for_secs as i64)` PANICS rather
/// than erroring on out-of-range input - a `u64` above `i64::MAX` wraps negative and falls
/// outside chrono's representable range. A fuzzer reached it through the issuance API with
/// nothing more exotic than a large number.
///
/// A century matches what the conformance-vector generator already treats as "far future",
/// so nothing legitimate is refused by this bound.
pub const MAX_VALID_FOR_SECS: u64 = 100 * 365 * 24 * 3600;

impl CapabilityClaims {
    /// The longest token this credential may mint - see [`max_token_ttl_secs`].
    #[must_use]
    pub fn max_token_ttl_secs(&self) -> u64 {
        max_token_ttl_secs(self.autonomy_level)
    }

    /// Create a basic claims set with minimal required fields.
    pub fn new(tools: Vec<String>, max_delegation_depth: u32, valid_for_secs: u64) -> Self {
        CapabilityClaims {
            // Asserted until an issuer says otherwise. The weakest reading is the
            // correct default for a value nobody has vouched for yet.
            accountability_source: AuthoritySource::default(),
            tools,
            resources: None,
            budget_usd: None,
            max_delegation_depth,
            valid_for_secs,
            autonomy_level: 0,
            model_version: None,
            artifact_hash: None,
            authorized_by: None,
            accountable_party: None,
            party_version: None,
            party_commitment: None,
            on_behalf_of: None,
            required_gates: Vec::new(),
        }
    }

    /// Mandate that `tool` requires execution-time human approval (R10), builder
    /// style. Every delegation token minted from this credential carries the gate,
    /// and it is enforced even if a token tries to omit it.
    #[must_use]
    pub fn require_approval(mut self, tool: impl Into<String>) -> Self {
        self.required_gates
            .push(crate::delegation::Gate::approval(tool));
        self
    }

    /// Validate that claims are internally consistent.
    pub fn validate(&self) -> Result<()> {
        if self.tools.is_empty() {
            return Err(AgentCredsError::MissingField { field: "tools" });
        }
        if self.valid_for_secs == 0 {
            return Err(AgentCredsError::OutOfBounds {
                field: "valid_for_secs",
                detail: "must be > 0".into(),
            });
        }
        // Upper bound, added 2026-09-05 after a fuzzer found the panic it prevents.
        //
        // The lower bound was checked here from the start; the upper one was not, and
        // `Duration::seconds(valid_for_secs as i64)` downstream PANICS rather than erroring
        // for large values - `9223372036854775808` (one past `i64::MAX`) wraps to
        // `i64::MIN` and is outside chrono's representable range. Reaching it needed only a
        // well-formed request with a big number in it.
        //
        // The cap is a century, matching what the conformance-vector generator already
        // treats as "far future". Anything beyond it is a mistake or an attack, not a
        // credential somebody meant to issue.
        if self.valid_for_secs > MAX_VALID_FOR_SECS {
            return Err(AgentCredsError::OutOfBounds {
                field: "valid_for_secs",
                detail: format!("maximum allowed value is {MAX_VALID_FOR_SECS} (100 years)"),
            });
        }
        if self.max_delegation_depth > 10 {
            return Err(AgentCredsError::OutOfBounds {
                field: "max_delegation_depth",
                detail: "maximum allowed value is 10".into(),
            });
        }
        if self.autonomy_level > 3 {
            return Err(AgentCredsError::OutOfBounds {
                field: "autonomy_level",
                detail: "must be 0-3".into(),
            });
        }
        // On-behalf-of: an agent cannot be granted authority the human never
        // consented to. The credential's tools must be within the principal's
        // consented scope, and the authorization window must be coherent.
        if let Some(obo) = &self.on_behalf_of {
            if obo.expires_at <= obo.authorized_at {
                return Err(AgentCredsError::OutOfBounds {
                    field: "on_behalf_of.expires_at",
                    detail: "human authorization expires at or before it was granted".into(),
                });
            }
            if let Some(tool) = obo.first_unconsented_tool(&self.tools) {
                return Err(AgentCredsError::ConsentViolation { capability: tool });
            }
        }
        Ok(())
    }
}

// -- Credential format ---------------------------------------------------------

/// Wire format and proof scheme of a capability credential. The delegation core is
/// **format-independent** - a delegation token roots in `vc.id`, not the
/// serialization - so this choice affects only issuance, the credential's own
/// signature, and how it serializes on the wire. SD-JWT VC is the intended default
/// for the OAuth/WIMSE ecosystem; W3C is the selectable interop fallback.
///
/// That split is a settled decision, not an accident: the primary outward format
/// targets the OAuth/WIMSE/SD-JWT VC ecosystem, the format stays pluggable and
/// contained to this module, and it is chosen at *issuance* - so one credential is
/// mint-once, present-either, with offline verification preserved on both paths.
/// `W3cLinkedData` remains the compiled-in default until the SD-JWT path is promoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialFormat {
    /// W3C VC 1.1 with a JSON-payload signature. Today's default and the fallback.
    /// Serializes as `"w3c-linked-data"`.
    #[default]
    W3cLinkedData,
    /// IETF SD-JWT VC - a compact JWS over the claims, issued and verified behind
    /// the `sd-jwt` feature. Full implementation: selective disclosure
    /// (`_sd`/salted disclosures), holder-of-key binding (`cnf` + KB-JWT), and an
    /// OAuth Token Status List revocation *reference* (`status.status_list`) pointing
    /// at a `statuslist+jwt` document (see [`crate::revocation`]) - reference and
    /// document are both OAuth end-to-end.
    SdJwtVc,
}

impl CredentialFormat {
    /// True for the W3C default - used to omit the `format` field from W3C JSON so
    /// existing credentials round-trip byte-for-byte.
    fn is_w3c(&self) -> bool {
        matches!(self, CredentialFormat::W3cLinkedData)
    }
}

// -- Linked-Data Proof --------------------------------------------------------

/// A linked-data proof attached to a Verifiable Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedDataProof {
    /// Proof type - "Ed25519Signature2020" or "EcdsaSecp256r1Signature2019".
    pub r#type: String,
    /// ISO 8601 creation time.
    pub created: DateTime<Utc>,
    /// The verification method (DID + key fragment) that produced this proof.
    pub verification_method: String,
    /// The purpose of this proof.
    pub proof_purpose: String,
    /// Base64url-encoded raw signature bytes.
    pub proof_value: String,
    /// SHA-256 of the credential payload that was signed.
    pub payload_hash: String,
}

// -- Credential Status (OAuth Token Status List reference) --------------------

/// Reference to the agent's slot in an **OAuth Token Status List**
/// (draft-ietf-oauth-status-list). The `status_list_index`/`status_list_credential`
/// pair maps directly to the spec's `status.status_list.{idx, uri}`: `idx` is the bit
/// index, `uri` is the Status List Token's URL. The SD-JWT VC path emits exactly that
/// object (see the private `oauth_status_claim` helper); the W3C VC path carries this
/// struct, which points
/// at the same token - one revocation list serves both formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// Unique identifier for this status entry (URL + fragment).
    pub id: String,
    /// Status entry type - `OAuthStatusListEntry` (references a `statuslist+jwt`).
    pub r#type: String,
    /// Purpose of the status check - always `revocation`.
    pub status_purpose: String,
    /// Bit index of this credential in the status list (`idx`).
    pub status_list_index: u64,
    /// URL of the Status List Token that contains the bitstring (`uri`).
    pub status_list_credential: String,
}

impl CredentialStatus {
    /// Construct an OAuth Token Status List entry reference.
    pub fn new(registry_url: &str, index: u64) -> Self {
        CredentialStatus {
            id: format!("{}#{}", registry_url, index),
            r#type: "OAuthStatusListEntry".into(),
            status_purpose: "revocation".into(),
            status_list_index: index,
            status_list_credential: registry_url.to_string(),
        }
    }
}

// -- Verifiable Credential ----------------------------------------------------

/// A W3C VC 1.1 capability credential for an AI agent.
///
/// Issued by a `TrustAnchor`, subject is the agent's DID.
/// The credential is serializable to JSON-LD for cross-org presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCredential {
    /// JSON-LD context URIs.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Globally unique credential identifier (URN).
    pub id: String,

    /// Credential type tags.
    pub r#type: Vec<String>,

    /// DID of the issuing trust anchor.
    pub issuer: String,

    /// Issuance timestamp.
    pub issuance_date: DateTime<Utc>,

    /// Expiry timestamp (derived from `valid_for_secs`).
    pub expiration_date: DateTime<Utc>,

    /// The capability claims about the subject agent.
    pub credential_subject: CredentialSubject,

    /// Revocation status reference.
    pub credential_status: Option<CredentialStatus>,

    /// Cryptographic proof over the credential payload. For W3C this is the
    /// JSON-payload signature; for SD-JWT VC it carries the compact JWS.
    pub proof: LinkedDataProof,

    /// Wire format / proof scheme. Defaults to W3C and is omitted from W3C JSON so
    /// existing credentials deserialize and round-trip unchanged.
    #[serde(default, skip_serializing_if = "CredentialFormat::is_w3c")]
    pub format: CredentialFormat,
}

/// The subject block of a capability credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// DID of the agent this credential is issued to.
    pub id: String,
    /// The capability claims.
    #[serde(flatten)]
    pub claims: CapabilityClaims,
}

impl CapabilityCredential {
    /// Issue a new capability credential.
    ///
    /// # Arguments
    /// * `anchor`        - The issuing trust anchor (signs the credential)
    /// * `subject_did`   - The agent's DID
    /// * `claims`        - Capability claims to assert
    /// * `revocation`    - Optional revocation status reference
    pub fn issue(
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: CapabilityClaims,
        revocation: Option<CredentialStatus>,
    ) -> Result<Self> {
        claims.validate()?;

        let now = Utc::now();
        let mut expiry = now + Duration::seconds(claims.valid_for_secs as i64);
        // The credential can never outlive the human's authorization window.
        if let Some(obo) = &claims.on_behalf_of {
            expiry = expiry.min(obo.expires_at);
        }
        let credential_id = Self::generate_id(anchor.did(), subject_did, now);

        let credential_subject = CredentialSubject {
            id: subject_did.to_string(),
            claims,
        };

        // Serialize the unsigned payload and hash it - this is what we sign.
        let unsigned_payload = serde_json::json!({
            "id": credential_id,
            "issuer": anchor.did(),
            "issuanceDate": now.to_rfc3339(),
            "expirationDate": expiry.to_rfc3339(),
            "credentialSubject": credential_subject,
        });
        let payload_bytes = serde_json::to_vec(&unsigned_payload)?;
        let payload_hash = Self::hash_payload(&payload_bytes);

        let signature_bytes = anchor.sign(&payload_bytes)?;
        let proof_value = base64ct::Base64::encode_string(&signature_bytes);

        let proof_type = "Ed25519Signature2020".to_string();

        let proof = LinkedDataProof {
            r#type: proof_type,
            created: now,
            verification_method: format!("{}#key-1", anchor.did()),
            proof_purpose: "assertionMethod".into(),
            proof_value,
            payload_hash,
        };

        Ok(CapabilityCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".into(),
                "https://w3id.org/agentcreds/v1".into(),
            ],
            id: credential_id,
            r#type: vec![
                "VerifiableCredential".into(),
                "AgentCapabilityCredential".into(),
            ],
            issuer: anchor.did().to_string(),
            issuance_date: now,
            expiration_date: expiry,
            credential_subject,
            credential_status: revocation,
            proof,
            format: CredentialFormat::W3cLinkedData,
        })
    }

    /// Issue a credential in a chosen wire format. SD-JWT VC is the intended default
    /// for OAuth/WIMSE interop; W3C is the selectable fallback. [`issue`](Self::issue)
    /// is the W3C shorthand kept for existing callers. SD-JWT VC requires the
    /// `sd-jwt` feature; without it this returns an error rather than silently
    /// falling back.
    pub fn issue_as(
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: CapabilityClaims,
        revocation: Option<CredentialStatus>,
        format: CredentialFormat,
    ) -> Result<Self> {
        match format {
            CredentialFormat::W3cLinkedData => Self::issue(anchor, subject_did, claims, revocation),
            CredentialFormat::SdJwtVc => {
                #[cfg(feature = "sd-jwt")]
                {
                    Self::issue_sd_jwt_vc(anchor, subject_did, claims, revocation)
                }
                #[cfg(not(feature = "sd-jwt"))]
                {
                    let _ = (anchor, subject_did, claims, revocation);
                    Err(AgentCredsError::InvalidVcProof {
                        reason: "SD-JWT VC issuance requires the `sd-jwt` feature".into(),
                    })
                }
            }
        }
    }

    /// Verify this credential's cryptographic proof against a trust anchor's public key.
    ///
    /// Checks:
    ///  1. Proof signature is valid over the credential payload
    ///  2. Credential has not expired
    ///  3. Issuer DID matches the anchor (optional strict mode)
    pub fn verify(&self, anchor: &TrustAnchor, strict_issuer: bool) -> Result<()> {
        self.verify_at(anchor, strict_issuer, Utc::now())
    }

    /// [`verify`](Self::verify), evaluated **as of `now`** instead of the wall clock.
    ///
    /// The evaluation instant is an input to verification, not ambient state - the same
    /// shape [`RevocationList::check_fresh`](crate::revocation::RevocationList::check_fresh)
    /// already has. Two callers need it:
    ///
    /// - **Audit re-verification.** "Was this authorized *when it happened*?" has to be
    ///   answered against the instant of the action. Ask it against the wall clock and
    ///   every historical decision fails for having expired, which would make the audit
    ///   record unusable for the one question it exists to answer.
    /// - **Golden conformance vectors**, which must stay verifiable indefinitely without
    ///   minting artifacts whose lifetime exceeds what the autonomy ladder permits.
    ///
    /// # Soundness - read before using
    ///
    /// An as-of answer is only meaningful if the **whole evidence set** is as-of
    /// consistent. Checking expiry against a past instant while checking revocation
    /// against today's status list yields a confident, wrong answer. Pass the same
    /// instant to every check in one evaluation, and for historical questions use the
    /// status list as it stood then - not the current one.
    ///
    /// **This is not the production path.** A relying party enforcing in real time must
    /// call [`verify`](Self::verify); accepting a caller-supplied instant on the hot path
    /// would let anything that can influence it revive an expired credential.
    ///
    /// # Errors
    /// As [`verify`](Self::verify), with expiry judged against `now`.
    pub fn verify_at(
        &self,
        anchor: &TrustAnchor,
        strict_issuer: bool,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // Common checks (format-independent).
        if strict_issuer && self.issuer != anchor.did() {
            return Err(AgentCredsError::IssuerMismatch {
                expected: anchor.did().to_string(),
                got: self.issuer.clone(),
            });
        }
        if now > self.expiration_date {
            return Err(AgentCredsError::CredentialExpired {
                expired_at: self.expiration_date.to_rfc3339(),
            });
        }

        // Format-specific proof verification.
        match self.format {
            CredentialFormat::W3cLinkedData => self.verify_w3c(anchor),
            CredentialFormat::SdJwtVc => {
                #[cfg(feature = "sd-jwt")]
                {
                    self.verify_sd_jwt(anchor)
                }
                #[cfg(not(feature = "sd-jwt"))]
                {
                    Err(AgentCredsError::InvalidVcProof {
                        reason: "SD-JWT VC verification requires the `sd-jwt` feature".into(),
                    })
                }
            }
        }
    }

    /// W3C proof verification: reconstruct the signed JSON payload and verify the
    /// anchor's signature over it (issuer/expiry already checked by [`verify`]).
    fn verify_w3c(&self, anchor: &TrustAnchor) -> Result<()> {
        let unsigned_payload = serde_json::json!({
            "id": self.id,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.to_rfc3339(),
            "expirationDate": self.expiration_date.to_rfc3339(),
            "credentialSubject": self.credential_subject,
        });
        let payload_bytes = serde_json::to_vec(&unsigned_payload)?;

        let expected_hash = Self::hash_payload(&payload_bytes);

        // An EMPTY payload_hash is not a corrupt W3C credential - it is almost always a
        // credential of a DIFFERENT format being verified by a build that does not know
        // that format. `CredentialFormat` has a `#[default]` of `W3cLinkedData`, so an
        // unrecognised `format` on the wire (e.g. `sd-jwt-vc` reaching an older build)
        // silently deserialises to W3C and lands here. SD-JWT credentials carry their
        // proof in the JWS, leaving `payload_hash` empty.
        //
        // Reporting "payload hash mismatch" for that case implies tampering and sends
        // people hunting for a crypto or serialization bug. It cost several days once.
        // Name the real cause instead.
        if self.proof.payload_hash.is_empty() {
            return Err(AgentCredsError::InvalidVcProof {
                reason: format!(
                    "credential carries no W3C payload hash (proof type {:?}); it is likely a \
                     newer credential format that this build does not support - upgrade the \
                     verifier, or reissue as w3c-linked-data",
                    self.proof.r#type
                ),
            });
        }

        if expected_hash != self.proof.payload_hash {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "payload hash mismatch".into(),
            });
        }

        let sig_bytes = base64ct::Base64::decode_vec(&self.proof.proof_value).map_err(|e| {
            AgentCredsError::InvalidVcProof {
                reason: format!("base64 decode failed: {}", e),
            }
        })?;

        anchor
            .verify_signature(&payload_bytes, &sig_bytes)
            .map_err(|e| AgentCredsError::InvalidVcProof {
                reason: e.to_string(),
            })
    }

    /// Returns the subject agent's DID.
    pub fn subject_did(&self) -> &str {
        &self.credential_subject.id
    }

    /// Returns the capability claims.
    pub fn claims(&self) -> &CapabilityClaims {
        &self.credential_subject.claims
    }

    /// The human principal this credential authorizes the agent to act for, if
    /// it is an on-behalf-of credential.
    pub fn on_behalf_of(&self) -> Option<&HumanAuthorization> {
        self.credential_subject.claims.on_behalf_of.as_ref()
    }

    /// The execution-time human-authorization gates this credential mandates
    /// (R10) - tools that require approval evidence before execution, enforced
    /// regardless of the delegation token's own gates.
    pub fn required_gates(&self) -> &[crate::delegation::Gate] {
        &self.credential_subject.claims.required_gates
    }

    /// Returns the expiration date/time.
    pub fn expiration_date(&self) -> DateTime<Utc> {
        self.expiration_date
    }

    /// Returns true if this credential is currently valid (not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_valid_at(Utc::now())
    }

    /// Whether the credential is unexpired **as of `now`** - see
    /// [`verify_at`](Self::verify_at) for when an explicit instant is appropriate and
    /// why it must not be used on the enforcement path.
    #[must_use]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now <= self.expiration_date
    }

    /// The URL of the OAuth Status List Token this credential's revocation status
    /// lives at, if the credential carries a status entry. A relying party
    /// fetches the list from here to check revocation.
    pub fn status_list_url(&self) -> Option<&str> {
        self.credential_status
            .as_ref()
            .map(|s| s.status_list_credential.as_str())
    }

    /// This credential's index within its OAuth Status List, if any.
    pub fn status_list_index(&self) -> Option<u64> {
        self.credential_status.as_ref().map(|s| s.status_list_index)
    }

    /// Serialize to canonical JSON-LD (for presentation to a verifier).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Deserialise from JSON-LD.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(Into::into)
    }

    /// Serialize to the credential's **wire form**: JSON-LD for W3C, or the compact
    /// SD-JWT VC (`<jws>~`) for SD-JWT. This is what a holder presents to a verifier.
    pub fn to_wire(&self) -> Result<String> {
        match self.format {
            CredentialFormat::W3cLinkedData => self.to_json(),
            CredentialFormat::SdJwtVc => {
                #[cfg(feature = "sd-jwt")]
                {
                    // Compact SD-JWT: issuer JWS then the disclosures section (empty
                    // until selective disclosure is wired).
                    Ok(format!("{}~", self.proof.proof_value))
                }
                #[cfg(not(feature = "sd-jwt"))]
                {
                    Err(AgentCredsError::InvalidVcProof {
                        reason: "SD-JWT VC serialization requires the `sd-jwt` feature".into(),
                    })
                }
            }
        }
    }

    /// Parse a credential from its wire form, auto-detecting the format: a leading
    /// `{` is W3C JSON-LD, otherwise a compact SD-JWT VC. Verify the result with
    /// [`verify`](Self::verify) before trusting it.
    pub fn from_wire(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.starts_with('{') {
            return Self::from_json(s);
        }
        #[cfg(feature = "sd-jwt")]
        {
            Self::from_sd_jwt_vc(s)
        }
        #[cfg(not(feature = "sd-jwt"))]
        {
            Err(AgentCredsError::InvalidVcProof {
                reason: "SD-JWT VC parsing requires the `sd-jwt` feature".into(),
            })
        }
    }

    fn generate_id(issuer_did: &str, subject_did: &str, ts: DateTime<Utc>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(issuer_did.as_bytes());
        hasher.update(subject_did.as_bytes());
        hasher.update(ts.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        format!(
            "urn:vc:agentcreds:{}",
            hex::encode(&hasher.finalize()[..16])
        )
    }

    fn hash_payload(payload_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload_bytes);
        hex::encode(hasher.finalize())
    }
}

// -- SD-JWT VC (IETF draft-ietf-oauth-sd-jwt-vc) ----------------------------------
//
// The credential's claims are signed as a JWS by the org anchor and carried in the
// compact `header.payload.signature~disclosure~...~` form. **Selective disclosure** is
// wired: advisory claims (`SD_DISCLOSABLE`) are salted, hashed into the payload's
// `_sd` array, and emitted as disclosures the holder may withhold per verifier;
// the **authority** claims (tools, budget, max-depth, on-behalf-of, gates) are always
// disclosed because `verify_rooted` needs them. The stored compact SD-JWT is the
// source of truth - verification checks the anchor's JWS signature, validates every
// carried disclosure against the signed `_sd` digests, and confirms the reconstructed
// claims equal the credential's fields. The anchor's existing raw sign/verify are
// reused: no new key or algorithm.
//
// Both once-deferred items now landed:
//   * key binding (`cnf` + KB-JWT) - optional, foreign-verifier interop only;
//     AgentCreds' action-bound PoP remains the primary holder proof;
//   * revocation - the `status` claim carries an OAuth Token Status List reference,
//     and the list document itself is a `statuslist+jwt` (see [`crate::revocation`]).

/// Advisory claims that are selectively disclosable in an SD-JWT VC. Authority claims
/// (tools, budget, max_delegation_depth, on_behalf_of, required_gates) are never here
/// - a verifier needs them - so only Option-typed metadata is disclosable, which also
/// means a withheld claim deserializes back to `None`.
#[cfg(feature = "sd-jwt")]
const SD_DISCLOSABLE: &[&str] = &["model_version", "artifact_hash", "authorized_by"];

#[cfg(feature = "sd-jwt")]
fn b64url(bytes: &[u8]) -> String {
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

#[cfg(feature = "sd-jwt")]
fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    base64ct::Base64UrlUnpadded::decode_vec(s).map_err(|e| AgentCredsError::InvalidVcProof {
        reason: format!("SD-JWT base64url: {e}"),
    })
}

/// SD-JWT disclosure digest: base64url(SHA-256(ascii(disclosure))).
#[cfg(feature = "sd-jwt")]
fn sd_digest(disclosure: &str) -> String {
    let mut h = Sha256::new();
    h.update(disclosure.as_bytes());
    b64url(&h.finalize())
}

/// Render revocation status as an IETF **OAuth Token Status List** `status` claim
/// (`draft-ietf-oauth-status-list`): `{ "status_list": { "idx", "uri" } }`. Both the
/// SD-JWT VC path (this inline claim) and the W3C VC path (a [`CredentialStatus`]
/// entry) reference the same OAuth Status List Token - this is the SD-JWT-native inline
/// shape. Null when the credential carries no status.
#[cfg(feature = "sd-jwt")]
fn oauth_status_claim(status: &Option<CredentialStatus>) -> serde_json::Value {
    match status {
        Some(s) => serde_json::json!({
            "status_list": { "idx": s.status_list_index, "uri": s.status_list_credential }
        }),
        None => serde_json::Value::Null,
    }
}

/// Parse an OAuth Token Status List `status` claim back into the internal
/// [`CredentialStatus`] (idx/uri are the significant fields; the W3C `id`/`type` are
/// re-derived).
#[cfg(feature = "sd-jwt")]
fn parse_oauth_status(v: &serde_json::Value) -> Result<Option<CredentialStatus>> {
    if v.is_null() {
        return Ok(None);
    }
    let sl = v
        .get("status_list")
        .ok_or_else(|| AgentCredsError::InvalidVcProof {
            reason: "SD-JWT VC status missing status_list".into(),
        })?;
    let idx = sl
        .get("idx")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AgentCredsError::InvalidVcProof {
            reason: "SD-JWT VC status_list missing idx".into(),
        })?;
    let uri = sl
        .get("uri")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AgentCredsError::InvalidVcProof {
            reason: "SD-JWT VC status_list missing uri".into(),
        })?;
    Ok(Some(CredentialStatus::new(uri, idx)))
}

#[cfg(feature = "sd-jwt")]
impl CapabilityCredential {
    /// Issue a capability credential as an SD-JWT VC - a compact JWS over the claims,
    /// with the advisory claims made selectively disclosable. Same logical credential
    /// as [`issue`](Self::issue); only the proof/serialization differs.
    pub fn issue_sd_jwt_vc(
        anchor: &TrustAnchor,
        subject_did: &str,
        claims: CapabilityClaims,
        revocation: Option<CredentialStatus>,
    ) -> Result<Self> {
        claims.validate()?;

        let now = Utc::now();
        let mut expiry = now + Duration::seconds(claims.valid_for_secs as i64);
        if let Some(obo) = &claims.on_behalf_of {
            expiry = expiry.min(obo.expires_at);
        }
        let credential_id = Self::generate_id(anchor.did(), subject_did, now);
        let credential_subject = CredentialSubject {
            id: subject_did.to_string(),
            claims,
        };

        let mut cred = CapabilityCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".into(),
                "https://w3id.org/agentcreds/v1".into(),
            ],
            id: credential_id,
            r#type: vec![
                "VerifiableCredential".into(),
                "AgentCapabilityCredential".into(),
            ],
            issuer: anchor.did().to_string(),
            issuance_date: now,
            expiration_date: expiry,
            credential_subject,
            credential_status: revocation,
            proof: LinkedDataProof {
                r#type: "vc+sd-jwt".into(),
                created: now,
                verification_method: format!("{}#0", anchor.did()),
                proof_purpose: "assertionMethod".into(),
                proof_value: String::new(),
                payload_hash: String::new(),
            },
            format: CredentialFormat::SdJwtVc,
        };
        cred.proof.proof_value = cred.encode_sd_jwt_vc(anchor)?;
        Ok(cred)
    }

    /// Build the full compact SD-JWT VC (issuer JWS + every disclosure) from the
    /// credential's fields.
    fn encode_sd_jwt_vc(&self, anchor: &TrustAnchor) -> Result<String> {
        use rand::{rngs::OsRng, RngCore};

        // Redact the disclosable claims out of `credentialSubject` into salted
        // disclosures, replacing them with digest entries in an `_sd` array.
        let mut cs = serde_json::to_value(&self.credential_subject)?;
        let obj = cs
            .as_object_mut()
            .ok_or_else(|| AgentCredsError::InvalidVcProof {
                reason: "credentialSubject is not an object".into(),
            })?;
        let mut disclosures = Vec::new();
        let mut sd = Vec::new();
        for &name in SD_DISCLOSABLE {
            if let Some(val) = obj.remove(name) {
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                let arr = serde_json::json!([b64url(&salt), name, val]);
                let disclosure = b64url(serde_json::to_string(&arr)?.as_bytes());
                sd.push(serde_json::Value::String(sd_digest(&disclosure)));
                disclosures.push(disclosure);
            }
        }
        if !sd.is_empty() {
            obj.insert("_sd".into(), serde_json::Value::Array(sd));
        }

        let alg = match anchor.algorithm() {
            crate::did::KeyAlgorithm::Ed25519 => "EdDSA",
            crate::did::KeyAlgorithm::P256 => "ES256",
        };
        let header = serde_json::json!({ "alg": alg, "typ": "vc+sd-jwt" });
        let payload = serde_json::json!({
            "iss": self.issuer,
            "sub": self.subject_did(),
            "vct": "AgentCapabilityCredential",
            "jti": self.id,
            "iat": self.issuance_date.timestamp(),
            "exp": self.expiration_date.timestamp(),
            "status": oauth_status_claim(&self.credential_status),
            // Key-binding confirmation: the holder is the credential subject, whose
            // did:key is its own public key - so a KB-JWT is verified against it.
            "cnf": { "kid": self.subject_did() },
            "credentialSubject": cs,
        });
        let signing_input = format!(
            "{}.{}",
            b64url(&serde_json::to_vec(&header)?),
            b64url(&serde_json::to_vec(&payload)?),
        );
        let sig = anchor.sign(signing_input.as_bytes())?;
        let mut compact = format!("{signing_input}.{}~", b64url(&sig));
        for d in &disclosures {
            compact.push_str(d);
            compact.push('~');
        }
        Ok(compact)
    }

    /// Verify an SD-JWT VC. Issuer/expiry are checked by [`verify`]; here we check the
    /// anchor's JWS signature, validate every carried disclosure against the signed
    /// `_sd` set, and confirm the reconstructed claims/iss/jti equal the credential.
    fn verify_sd_jwt(&self, anchor: &TrustAnchor) -> Result<()> {
        let (derived, iss, jti, status) = self.sd_jwt_reconstruct(Some(anchor))?;
        if iss != self.issuer || jti != self.id {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "SD-JWT VC iss/jti do not match the credential".into(),
            });
        }
        if serde_json::to_value(&self.credential_subject)? != serde_json::to_value(&derived)? {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "SD-JWT VC claims do not match the signed and disclosed credential".into(),
            });
        }
        // Revocation reference is signed into the payload: its significant fields
        // (idx, uri) must match the credential's - so it can't be silently repointed.
        let sig_status = status
            .as_ref()
            .map(|s| (s.status_list_index, s.status_list_credential.as_str()));
        let own_status = self
            .credential_status
            .as_ref()
            .map(|s| (s.status_list_index, s.status_list_credential.as_str()));
        if sig_status != own_status {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "SD-JWT VC status reference does not match the signed status".into(),
            });
        }
        Ok(())
    }

    /// Reconstruct `credentialSubject` from the stored compact SD-JWT, applying each
    /// carried disclosure (checked against the signed `_sd` digests). When `verify` is
    /// `Some`, the JWS signature is verified too. Returns `(subject, iss, jti, status)`.
    fn sd_jwt_reconstruct(
        &self,
        verify: Option<&TrustAnchor>,
    ) -> Result<(CredentialSubject, String, String, Option<CredentialStatus>)> {
        let mut segs = self.proof.proof_value.split('~');
        let jws = segs.next().ok_or_else(|| AgentCredsError::InvalidVcProof {
            reason: "empty SD-JWT VC".into(),
        })?;
        let (signing_input, sig_b64) =
            jws.rsplit_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed SD-JWT VC (no signature)".into(),
                })?;
        if let Some(anchor) = verify {
            let sig = b64url_decode(sig_b64)?;
            anchor
                .verify_signature(signing_input.as_bytes(), &sig)
                .map_err(|e| AgentCredsError::InvalidVcProof {
                    reason: e.to_string(),
                })?;
        }
        let (_h, payload_b64) =
            signing_input
                .split_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed SD-JWT VC (no payload)".into(),
                })?;
        let payload: serde_json::Value = serde_json::from_slice(&b64url_decode(payload_b64)?)?;
        let iss = payload["iss"].as_str().unwrap_or_default().to_string();
        let jti = payload["jti"].as_str().unwrap_or_default().to_string();
        let status = parse_oauth_status(&payload["status"])?;

        let mut cs_obj = payload
            .get("credentialSubject")
            .and_then(|v| v.as_object())
            .cloned()
            .ok_or_else(|| AgentCredsError::InvalidVcProof {
                reason: "SD-JWT VC missing credentialSubject".into(),
            })?;
        let sd: std::collections::HashSet<String> = cs_obj
            .remove("_sd")
            .and_then(|v| {
                v.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
            })
            .unwrap_or_default();
        for disc in segs {
            // Skip the empty trailing slot and a trailing KB-JWT (which has dots - a
            // disclosure is a single base64url token with none).
            if disc.is_empty() || disc.contains('.') {
                continue;
            }
            if !sd.contains(&sd_digest(disc)) {
                return Err(AgentCredsError::InvalidVcProof {
                    reason: "SD-JWT disclosure is not in the signed _sd set".into(),
                });
            }
            let arr: serde_json::Value = serde_json::from_slice(&b64url_decode(disc)?)?;
            let name = arr.get(1).and_then(|v| v.as_str()).ok_or_else(|| {
                AgentCredsError::InvalidVcProof {
                    reason: "malformed SD-JWT disclosure".into(),
                }
            })?;
            let value = arr.get(2).cloned().unwrap_or(serde_json::Value::Null);
            cs_obj.insert(name.to_string(), value);
        }
        let cs: CredentialSubject = serde_json::from_value(serde_json::Value::Object(cs_obj))?;
        Ok((cs, iss, jti, status))
    }

    /// Parse a compact SD-JWT VC into a credential (disclosures applied and
    /// digest-checked; the signature is verified later by [`verify`](Self::verify)).
    fn from_sd_jwt_vc(s: &str) -> Result<Self> {
        let compact = s.trim().to_string();
        let jws = compact.split('~').next().unwrap_or(&compact);
        let (signing_input, _sig) =
            jws.rsplit_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed SD-JWT VC".into(),
                })?;
        let (_h, payload_b64) =
            signing_input
                .split_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed SD-JWT VC".into(),
                })?;
        let payload: serde_json::Value = serde_json::from_slice(&b64url_decode(payload_b64)?)?;
        let iat = payload["iat"].as_i64().unwrap_or(0);
        let exp = payload["exp"].as_i64().unwrap_or(0);
        let issuance_date = DateTime::from_timestamp(iat, 0).unwrap_or_else(Utc::now);
        let expiration_date = DateTime::from_timestamp(exp, 0).unwrap_or_else(Utc::now);

        // Build a shell carrying the compact form, then fill claims/iss/jti/status from it.
        let mut cred = CapabilityCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".into(),
                "https://w3id.org/agentcreds/v1".into(),
            ],
            id: String::new(),
            r#type: vec![
                "VerifiableCredential".into(),
                "AgentCapabilityCredential".into(),
            ],
            issuer: String::new(),
            issuance_date,
            expiration_date,
            credential_subject: CredentialSubject {
                id: String::new(),
                claims: CapabilityClaims::new(vec!["tool:_".into()], 0, 1),
            },
            credential_status: None,
            proof: LinkedDataProof {
                r#type: "vc+sd-jwt".into(),
                created: issuance_date,
                verification_method: String::new(),
                proof_purpose: "assertionMethod".into(),
                proof_value: compact,
                payload_hash: String::new(),
            },
            format: CredentialFormat::SdJwtVc,
        };
        let (cs, iss, jti, status) = cred.sd_jwt_reconstruct(None)?;
        cred.credential_subject = cs;
        cred.issuer = iss;
        cred.id = jti;
        cred.credential_status = status;
        Ok(cred)
    }

    /// Produce a **selective-disclosure presentation**: the issuer JWS plus only the
    /// named advisory disclosures. Authority claims are always present; a withheld
    /// claim is cryptographically unrecoverable. Feed the result to [`from_wire`](Self::from_wire).
    pub fn present_sd_jwt(&self, disclose: &[&str]) -> Result<String> {
        let mut segs = self.proof.proof_value.split('~');
        let jws = segs.next().unwrap_or("");
        let mut out = format!("{jws}~");
        for disc in segs {
            if disc.is_empty() {
                continue;
            }
            let arr: serde_json::Value = serde_json::from_slice(&b64url_decode(disc)?)?;
            let name = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            if disclose.contains(&name) {
                out.push_str(disc);
                out.push('~');
            }
        }
        Ok(out)
    }

    /// Produce a **key-bound presentation**: a selective-disclosure presentation
    /// (via [`present_sd_jwt`](Self::present_sd_jwt)) with a holder-signed **KB-JWT**
    /// appended, proving the presenter controls the credential's confirmation key.
    /// `audience` and `nonce` come from the verifier. The holder must be the credential
    /// subject (whose `did:key` is the confirmation key).
    pub fn present_with_key_binding(
        &self,
        holder: &crate::did::AgentIdentity,
        audience: &str,
        nonce: &str,
        disclose: &[&str],
    ) -> Result<String> {
        if holder.did() != self.subject_did() {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "key-binding holder is not the credential subject".into(),
            });
        }
        let presentation = self.present_sd_jwt(disclose)?; // ends with '~'
        let mut h = Sha256::new();
        h.update(presentation.as_bytes());
        let sd_hash = b64url(&h.finalize());

        let alg = match holder.public_key().algorithm {
            crate::did::KeyAlgorithm::Ed25519 => "EdDSA",
            crate::did::KeyAlgorithm::P256 => "ES256",
        };
        let header = serde_json::json!({ "typ": "kb+jwt", "alg": alg });
        let payload = serde_json::json!({
            "iat": Utc::now().timestamp(),
            "aud": audience,
            "nonce": nonce,
            "sd_hash": sd_hash,
        });
        let kb_signing = format!(
            "{}.{}",
            b64url(&serde_json::to_vec(&header)?),
            b64url(&serde_json::to_vec(&payload)?),
        );
        let sig = holder.sign(kb_signing.as_bytes())?;
        Ok(format!("{presentation}{kb_signing}.{}", b64url(&sig)))
    }

    /// Verify the key binding of a presentation from
    /// [`present_with_key_binding`](Self::present_with_key_binding): the
    /// appended KB-JWT must be signed by the credential's confirmation key, bound to
    /// this exact presentation (`sd_hash`), and match the verifier's `audience`/`nonce`.
    /// Run **after** [`verify`](Self::verify) has authenticated the issuer JWS.
    pub fn verify_key_binding(&self, audience: &str, nonce: &str) -> Result<()> {
        let compact = &self.proof.proof_value;
        let pos = compact
            .rfind('~')
            .ok_or_else(|| AgentCredsError::InvalidVcProof {
                reason: "not a key-bound SD-JWT VC".into(),
            })?;
        let (presentation, kb) = (&compact[..=pos], &compact[pos + 1..]);
        if kb.is_empty() {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "no key binding present".into(),
            });
        }
        // sd_hash binds the KB-JWT to exactly this presentation (disclosures included).
        let mut h = Sha256::new();
        h.update(presentation.as_bytes());
        let sd_hash = b64url(&h.finalize());

        let (kb_signing, kb_sig_b64) =
            kb.rsplit_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed KB-JWT".into(),
                })?;
        let (_kb_h, kb_p) =
            kb_signing
                .split_once('.')
                .ok_or_else(|| AgentCredsError::InvalidVcProof {
                    reason: "malformed KB-JWT".into(),
                })?;
        let kb_payload: serde_json::Value = serde_json::from_slice(&b64url_decode(kb_p)?)?;
        if kb_payload["sd_hash"].as_str() != Some(sd_hash.as_str()) {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "KB-JWT sd_hash does not match the presentation".into(),
            });
        }
        if kb_payload["aud"].as_str() != Some(audience) {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "KB-JWT audience mismatch".into(),
            });
        }
        if kb_payload["nonce"].as_str() != Some(nonce) {
            return Err(AgentCredsError::InvalidVcProof {
                reason: "KB-JWT nonce mismatch".into(),
            });
        }
        // The KB-JWT must be signed by the confirmation key (the subject's did:key).
        let holder = crate::did::PublicKey::from_did_key(self.subject_did())?;
        let sig = b64url_decode(kb_sig_b64)?;
        holder
            .verify(kb_signing.as_bytes(), &sig)
            .map_err(|e| AgentCredsError::InvalidVcProof {
                reason: format!("KB-JWT signature: {e}"),
            })
    }
}

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::did::{AgentIdentity, DidMethod, TrustAnchor};

    fn make_anchor_and_agent() -> (TrustAnchor, AgentIdentity) {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create(DidMethod::Key, None).unwrap();
        (anchor, agent)
    }

    fn basic_claims() -> CapabilityClaims {
        CapabilityClaims::new(vec!["tool:search".into(), "tool:summarize".into()], 3, 3600)
    }

    #[test]
    fn issue_and_verify_credential() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        assert!(vc.verify(&anchor, true).is_ok());
    }

    #[test]
    fn round_trip_json() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        let json = vc.to_json().unwrap();
        let restored = CapabilityCredential::from_json(&json).unwrap();
        assert_eq!(vc.id, restored.id);
        assert_eq!(vc.subject_did(), restored.subject_did());
    }

    #[test]
    fn wrong_anchor_fails_verification() {
        let (anchor1, agent) = make_anchor_and_agent();
        let anchor2 = TrustAnchor::generate().unwrap();
        let vc = CapabilityCredential::issue(&anchor1, agent.did(), basic_claims(), None).unwrap();
        // strict_issuer=false but key still won't match
        assert!(vc.verify(&anchor2, false).is_err());
    }

    #[test]
    fn tampered_credential_fails_verification() {
        let (anchor, agent) = make_anchor_and_agent();
        let mut vc =
            CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        // Tamper with the subject DID
        vc.credential_subject.id = "did:key:zTAMPERED".to_string();
        assert!(vc.verify(&anchor, false).is_err());
    }

    #[test]
    fn claims_validation_rejects_empty_tools() {
        let bad = CapabilityClaims::new(vec![], 3, 3600);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn claims_validation_rejects_zero_validity() {
        let bad = CapabilityClaims::new(vec!["tool:x".into()], 3, 0);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn claims_validation_rejects_excessive_depth() {
        let bad = CapabilityClaims::new(vec!["tool:x".into()], 11, 3600);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn credential_status_reference() {
        let status = CredentialStatus::new("https://registry.example.com/revocation/1", 42);
        assert_eq!(status.status_list_index, 42);
        assert!(status.id.contains("42"));
    }

    #[test]
    fn expired_credential_fails_verification() {
        let (anchor, agent) = make_anchor_and_agent();
        let mut vc =
            CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        vc.expiration_date = Utc::now() - Duration::seconds(1);
        assert!(matches!(
            vc.verify(&anchor, false),
            Err(AgentCredsError::CredentialExpired { .. })
        ));
    }

    #[test]
    fn is_valid_returns_false_for_expired_credential() {
        let (anchor, agent) = make_anchor_and_agent();
        let mut vc =
            CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        vc.expiration_date = Utc::now() - Duration::seconds(1);
        assert!(!vc.is_valid());
    }

    #[test]
    fn strict_issuer_mismatch_fails() {
        let (anchor1, agent) = make_anchor_and_agent();
        let anchor2 = TrustAnchor::generate().unwrap();
        let vc = CapabilityCredential::issue(&anchor1, agent.did(), basic_claims(), None).unwrap();
        assert!(matches!(
            vc.verify(&anchor2, true),
            Err(AgentCredsError::IssuerMismatch { .. })
        ));
    }

    #[test]
    fn claims_validate_rejects_autonomy_level_above_3() {
        let mut claims = basic_claims();
        claims.autonomy_level = 4;
        assert!(matches!(
            claims.validate(),
            Err(AgentCredsError::OutOfBounds {
                field: "autonomy_level",
                ..
            })
        ));
    }

    #[test]
    fn claims_new_sets_sensible_defaults() {
        let claims = CapabilityClaims::new(vec!["tool:x".into()], 3, 7200);
        assert_eq!(claims.autonomy_level, 0);
        assert_eq!(claims.budget_usd, None);
        assert_eq!(claims.model_version, None);
        assert_eq!(claims.max_delegation_depth, 3);
        assert_eq!(claims.valid_for_secs, 7200);
    }

    #[test]
    fn credential_subject_did_matches_issued_to() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        assert_eq!(vc.subject_did(), agent.did());
        assert_eq!(vc.credential_subject.id, agent.did());
    }

    #[test]
    fn expiration_date_accessor_matches_field() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        assert_eq!(vc.expiration_date(), vc.expiration_date);
    }

    #[cfg(feature = "sd-jwt")]
    fn disclosable_claims() -> CapabilityClaims {
        let mut c = basic_claims();
        c.model_version = Some("gpt-x-2026".into());
        c.authorized_by = Some("spiffe://acme/agent/7".into());
        c
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_issue_verify_and_wire_round_trip() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue_as(
            &anchor,
            agent.did(),
            disclosable_claims(),
            None,
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        assert_eq!(vc.format, CredentialFormat::SdJwtVc);
        assert!(vc.verify(&anchor, true).is_ok());
        // A different anchor's key does not verify it.
        let other = TrustAnchor::generate().unwrap();
        assert!(vc.verify(&other, false).is_err());
        // Full wire round-trip: every disclosure present -> all claims recovered.
        let wire = vc.to_wire().unwrap();
        assert!(
            wire.ends_with('~'),
            "compact SD-JWT ends with the disclosures separator"
        );
        let parsed = CapabilityCredential::from_wire(&wire).unwrap();
        assert_eq!(parsed.format, CredentialFormat::SdJwtVc);
        assert_eq!(parsed.id, vc.id);
        assert_eq!(parsed.subject_did(), vc.subject_did());
        assert_eq!(parsed.claims().tools, vc.claims().tools);
        assert_eq!(parsed.claims().model_version.as_deref(), Some("gpt-x-2026"));
        assert_eq!(
            parsed.claims().authorized_by.as_deref(),
            Some("spiffe://acme/agent/7")
        );
        assert!(
            parsed.verify(&anchor, true).is_ok(),
            "round-tripped SD-JWT VC verifies"
        );
        // Field-integrity binding: tampering a claim breaks verification.
        let mut tampered = parsed.clone();
        tampered.credential_subject.id = "did:key:zEVIL".into();
        assert!(tampered.verify(&anchor, false).is_err());
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_selective_disclosure_hides_withheld_claims() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue_as(
            &anchor,
            agent.did(),
            disclosable_claims(),
            None,
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        // Disclose only model_version; withhold authorized_by.
        let presentation = vc.present_sd_jwt(&["model_version"]).unwrap();
        let seen = CapabilityCredential::from_wire(&presentation).unwrap();
        assert!(
            seen.verify(&anchor, true).is_ok(),
            "a redacted presentation still verifies"
        );
        // Authority claim survives; the disclosed claim is present; the withheld one is gone.
        assert_eq!(seen.claims().tools, vc.claims().tools);
        assert_eq!(seen.claims().model_version.as_deref(), Some("gpt-x-2026"));
        assert_eq!(
            seen.claims().authorized_by,
            None,
            "withheld claim is unrecoverable"
        );
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_forged_disclosure_is_rejected() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue_as(
            &anchor,
            agent.did(),
            disclosable_claims(),
            None,
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        // Append a well-formed disclosure whose digest is NOT in the signed _sd set.
        let forged = super::b64url(
            serde_json::to_string(&serde_json::json!([
                "ZZZZ",
                "authorized_by",
                "spiffe://evil"
            ]))
            .unwrap()
            .as_bytes(),
        );
        let tampered = format!("{}{}~", vc.to_wire().unwrap(), forged);
        assert!(
            CapabilityCredential::from_wire(&tampered).is_err(),
            "a disclosure not in the signed _sd set is rejected"
        );
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_uses_oauth_token_status_list() {
        let (anchor, agent) = make_anchor_and_agent();
        let status = CredentialStatus::new("https://acme.example/statuslists/1", 42);
        let vc = CapabilityCredential::issue_as(
            &anchor,
            agent.did(),
            disclosable_claims(),
            Some(status),
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        assert!(vc.verify(&anchor, true).is_ok());

        // The wire `status` claim is the OAuth Token Status List shape, not W3C.
        let wire = vc.to_wire().unwrap();
        let jws = wire.split('~').next().unwrap();
        let payload_b64 = jws.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&super::b64url_decode(payload_b64).unwrap()).unwrap();
        assert_eq!(payload["status"]["status_list"]["idx"], 42);
        assert_eq!(
            payload["status"]["status_list"]["uri"],
            "https://acme.example/statuslists/1"
        );
        assert!(
            payload["status"]["type"].is_null(),
            "not the W3C StatusList2021Entry shape"
        );

        // Round-trip preserves the status reference.
        let parsed = CapabilityCredential::from_wire(&wire).unwrap();
        assert_eq!(parsed.status_list_index(), Some(42));
        assert_eq!(
            parsed.status_list_url(),
            Some("https://acme.example/statuslists/1")
        );
        assert!(parsed.verify(&anchor, true).is_ok());

        // The signed status reference can't be silently repointed.
        let mut repointed = parsed.clone();
        repointed.credential_status = Some(CredentialStatus::new("https://evil.example/list", 0));
        assert!(repointed.verify(&anchor, false).is_err());
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_key_binding_holder_of_key() {
        use crate::did::{AgentIdentity, DidMethod};
        let anchor = TrustAnchor::generate().unwrap();
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = CapabilityCredential::issue_as(
            &anchor,
            holder.did(),
            disclosable_claims(),
            None,
            CredentialFormat::SdJwtVc,
        )
        .unwrap();

        // Holder presents with a key binding for a specific audience + nonce.
        let pres = vc
            .present_with_key_binding(
                &holder,
                "https://verifier.example",
                "n-123",
                &["model_version"],
            )
            .unwrap();
        let seen = CapabilityCredential::from_wire(&pres).unwrap();
        // Issuer JWS + disclosures verify, and the KB proves holder-of-key.
        assert!(seen.verify(&anchor, true).is_ok());
        assert!(seen
            .verify_key_binding("https://verifier.example", "n-123")
            .is_ok());
        assert_eq!(seen.claims().model_version.as_deref(), Some("gpt-x-2026"));
        assert_eq!(seen.claims().authorized_by, None);

        // Wrong audience or nonce -> rejected.
        assert!(seen
            .verify_key_binding("https://evil.example", "n-123")
            .is_err());
        assert!(seen
            .verify_key_binding("https://verifier.example", "wrong")
            .is_err());

        // A non-subject cannot mint a binding for this credential.
        let stranger = AgentIdentity::create(DidMethod::Key, None).unwrap();
        assert!(vc
            .present_with_key_binding(&stranger, "https://verifier.example", "n", &[])
            .is_err());
    }

    #[cfg(feature = "sd-jwt")]
    #[test]
    fn sd_jwt_vc_key_binding_is_bound_to_the_presentation() {
        use crate::did::{AgentIdentity, DidMethod};
        let anchor = TrustAnchor::generate().unwrap();
        let holder = AgentIdentity::create(DidMethod::Key, None).unwrap();
        let vc = CapabilityCredential::issue_as(
            &anchor,
            holder.did(),
            disclosable_claims(),
            None,
            CredentialFormat::SdJwtVc,
        )
        .unwrap();
        // Bind over a two-disclosure presentation.
        let pres = vc
            .present_with_key_binding(&holder, "aud", "n", &["model_version", "authorized_by"])
            .unwrap();
        assert!(CapabilityCredential::from_wire(&pres)
            .unwrap()
            .verify_key_binding("aud", "n")
            .is_ok());

        // Splicing that KB-JWT onto a *different* (reduced) presentation breaks sd_hash.
        let kb = pres.rsplit_once('~').unwrap().1;
        let reduced = vc.present_sd_jwt(&["model_version"]).unwrap();
        let spliced = format!("{reduced}{kb}");
        let tampered = CapabilityCredential::from_wire(&spliced).unwrap();
        assert!(
            tampered.verify_key_binding("aud", "n").is_err(),
            "sd_hash no longer matches"
        );
    }

    #[test]
    fn json_round_trip_preserves_claims() {
        let (anchor, agent) = make_anchor_and_agent();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), basic_claims(), None).unwrap();
        let json = vc.to_json().unwrap();
        let restored = CapabilityCredential::from_json(&json).unwrap();
        assert_eq!(restored.id, vc.id);
        assert_eq!(restored.issuer, vc.issuer);
        assert_eq!(restored.claims().tools, vc.claims().tools);
    }

    // -- Evidence vocabulary: AuthoritySource and PrincipalKind ----------------
    //
    // Found unexercised by a production-only coverage audit on 2026-08-08.
    //
    // `AuthoritySource` is how a credential says *on what basis* a binding was made -
    // asserted, policy, or attested - and `admits` is the comparison a verifier uses to
    // require a minimum strength of evidence. Both are wire vocabulary: the names cross
    // into credentials, decision records and the audit log, so a name that stops
    // round-tripping orphans everything written with it.
    //
    // The ordering matters more than the names. If `admits` were inverted, a verifier
    // demanding attested evidence would accept a self-asserted claim - a silent
    // downgrade of exactly the axis that exists to prevent one.

    #[test]
    fn authority_sources_round_trip_and_reject_unknown_names() {
        let all = [
            AuthoritySource::Asserted,
            AuthoritySource::Policy,
            AuthoritySource::Attested,
        ];
        for src in all {
            let name = src.as_str();
            assert!(!name.is_empty());
            assert_eq!(
                AuthoritySource::parse(name),
                Some(src),
                "{name} must parse back to the variant that emitted it"
            );
        }
        let mut names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "source names must be distinct");

        // An unknown name must NOT fall back to Asserted: that would silently downgrade
        // a stronger source this build does not understand, weakening evidence for no
        // reason an auditor could see.
        assert_eq!(AuthoritySource::parse("attested_by_notary"), None);
        assert_eq!(AuthoritySource::parse(""), None);
        assert_eq!(AuthoritySource::parse("Attested"), None, "parsing is exact");

        // `is_asserted` marks the default, which is omitted on the wire so existing
        // credentials keep hashing identically.
        assert!(AuthoritySource::Asserted.is_asserted());
        assert!(!AuthoritySource::Policy.is_asserted());
        assert!(!AuthoritySource::Attested.is_asserted());
        assert_eq!(AuthoritySource::default(), AuthoritySource::Asserted);
    }

    /// Rank is a total order, and `admits` accepts only evidence at least as strong.
    /// Asserted here as a full matrix: an inverted comparison would still pass a test
    /// that only checked "attested admits attested".
    #[test]
    fn stronger_evidence_is_admitted_and_weaker_is_not() {
        use AuthoritySource::{Asserted, Attested, Policy};

        assert!(Asserted.rank() < Policy.rank());
        assert!(Policy.rank() < Attested.rank());

        // Every pair, both directions. `required.admits(offered)`.
        let matrix = [
            (Asserted, Asserted, true),
            (Asserted, Policy, true),
            (Asserted, Attested, true),
            (Policy, Asserted, false),
            (Policy, Policy, true),
            (Policy, Attested, true),
            (Attested, Asserted, false),
            (Attested, Policy, false),
            (Attested, Attested, true),
        ];
        for (required, offered, want) in matrix {
            assert_eq!(
                required.admits(offered),
                want,
                "{required:?} requiring, {offered:?} offered"
            );
        }
    }

    #[test]
    fn principal_kinds_round_trip_and_distinguish_human_from_workload() {
        let all = [PrincipalKind::Human, PrincipalKind::Workload];
        for kind in all {
            let name = kind.as_str();
            assert!(!name.is_empty());
            assert_eq!(PrincipalKind::parse(name), Some(kind));
        }
        assert_ne!(
            PrincipalKind::Human.as_str(),
            PrincipalKind::Workload.as_str()
        );

        assert!(PrincipalKind::Human.is_human());
        assert!(
            !PrincipalKind::Workload.is_human(),
            "a workload is not a human - the whole NHI accountability model rests on \
             this distinction, so it gets its own assertion"
        );

        assert_eq!(PrincipalKind::parse("service"), None);
        assert_eq!(PrincipalKind::parse(""), None);
    }
}
