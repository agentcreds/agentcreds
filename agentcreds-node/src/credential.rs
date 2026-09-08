use chrono::{DateTime, Utc};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use agentcreds_core::accountability::OwnershipRecord as CoreOwnershipRecord;
use agentcreds_core::vc::{
    AuthoritySource, CapabilityClaims as CoreCapabilityClaims,
    CapabilityCredential as CoreCapabilityCredential, CredentialStatus as CoreCredentialStatus,
    HumanAuthorization as CoreHumanAuthorization, LinkedDataProof as CoreLinkedDataProof,
    PrincipalKind,
};

use crate::error::{invalid_arg, map_err};
use crate::identity::TrustAnchor;

// -- HumanAuthorization (on-behalf-of principal) -------------------------------

/// The human principal, attested by an IdP, on whose behalf an agent acts - the
/// enforced on-behalf-of dimension of a credential. A plain data object:
/// `scopeConsented`/`resourceAuthority` default to empty and `authorizedAt`
/// defaults to now when omitted.
#[napi(object)]
pub struct HumanAuthorization {
    pub principal_did: String,
    /// `"human"` or `"workload"` - which root attested this principal. Defaults to
    /// `"human"`.
    pub kind: Option<String>,
    /// Where `scopeConsented` and `resourceAuthority` came from - `"attested"`,
    /// `"policy"` or `"asserted"`. Defaults to `"asserted"`, the weakest reading,
    /// because a caller that does not say has not established anything.
    pub entitlement_source: Option<String>,
    pub issuer: String,
    pub subject: String,
    pub expires_at: DateTime<Utc>,
    pub scope_consented: Option<Vec<String>>,
    pub resource_authority: Option<Vec<String>>,
    pub authorized_at: Option<DateTime<Utc>>,
}

impl HumanAuthorization {
    pub(crate) fn to_core(self) -> Result<CoreHumanAuthorization> {
        // Rejected rather than defaulted: a typo that silently produced a human
        // principal would misreport which attesting root stands behind the binding.
        let kind = match self.kind.as_deref() {
            None => PrincipalKind::Human,
            Some(k) => PrincipalKind::parse(k).ok_or_else(|| {
                invalid_arg(&format!(
                    "unknown principal kind {k:?} (expected \"human\" or \"workload\")"
                ))
            })?,
        };
        // Rejected rather than defaulted, for the same reason as `kind`: reading an
        // unknown source as the default would misreport the evidence behind these
        // entitlements.
        let entitlement_source = match self.entitlement_source.as_deref() {
            None => AuthoritySource::default(),
            Some(v) => AuthoritySource::parse(v).ok_or_else(|| {
                invalid_arg(&format!(
                    "unknown authority source {v:?} (expected \"attested\", \"policy\" or \"asserted\")"
                ))
            })?,
        };
        Ok(CoreHumanAuthorization {
            principal_did: self.principal_did,
            kind,
            entitlement_source,
            issuer: self.issuer,
            subject: self.subject,
            authorized_at: self.authorized_at.unwrap_or_else(Utc::now),
            expires_at: self.expires_at,
            scope_consented: self.scope_consented.unwrap_or_default(),
            resource_authority: self.resource_authority.unwrap_or_default(),
        })
    }

    pub(crate) fn from_core(c: CoreHumanAuthorization) -> Self {
        Self {
            principal_did: c.principal_did,
            kind: Some(c.kind.as_str().to_string()),
            entitlement_source: Some(c.entitlement_source.as_str().to_string()),
            issuer: c.issuer,
            subject: c.subject,
            expires_at: c.expires_at,
            scope_consented: Some(c.scope_consented),
            resource_authority: Some(c.resource_authority),
            authorized_at: Some(c.authorized_at),
        }
    }
}

// -- CapabilityClaims ----------------------------------------------------------

/// Constructor options for [`CapabilityClaims`].
#[napi(object)]
pub struct CapabilityClaimsInit {
    pub tools: Vec<String>,
    /// Resource-namespace patterns the agent may reach - a capability-axis
    /// ceiling enforced at mint, needing no principal to carry it.
    pub resources: Option<Vec<String>>,
    pub max_delegation_depth: u32,
    pub valid_for_secs: i64,
    pub budget_usd: Option<u32>,
    pub autonomy_level: Option<u8>,
    pub model_version: Option<String>,
    pub artifact_hash: Option<String>,
    pub authorized_by: Option<String>,
    /// Who answers for what this agent does. Never selectively disclosable.
    pub accountable_party: Option<String>,
    /// Which revision of the ownership record named that party.
    pub party_version: Option<i64>,
    /// Salted commitment to that ownership record - the members never travel.
    pub party_commitment: Option<String>,
}

#[napi]
pub struct CapabilityClaims {
    pub(crate) inner: CoreCapabilityClaims,
}

#[napi]
impl CapabilityClaims {
    #[napi(constructor)]
    pub fn new(init: CapabilityClaimsInit) -> Result<Self> {
        if init.valid_for_secs < 0 {
            return Err(invalid_arg("valid_for_secs must be non-negative"));
        }
        let mut claims = CoreCapabilityClaims::new(
            init.tools,
            init.max_delegation_depth,
            init.valid_for_secs as u64,
        );
        claims.resources = init.resources;
        claims.budget_usd = init.budget_usd;
        claims.autonomy_level = init.autonomy_level.unwrap_or(0);
        claims.model_version = init.model_version;
        claims.artifact_hash = init.artifact_hash;
        claims.authorized_by = init.authorized_by;
        claims.accountable_party = init.accountable_party;
        claims.party_version = init.party_version.map(|v| v as u64);
        claims.party_commitment = init.party_commitment;
        Ok(Self { inner: claims })
    }

    #[napi(getter)]
    pub fn tools(&self) -> Vec<String> {
        self.inner.tools.clone()
    }

    #[napi(getter)]
    pub fn resources(&self) -> Option<Vec<String>> {
        self.inner.resources.clone()
    }

    #[napi(getter)]
    pub fn party_version(&self) -> Option<i64> {
        self.inner.party_version.map(|v| v as i64)
    }

    #[napi(getter)]
    pub fn party_commitment(&self) -> Option<String> {
        self.inner.party_commitment.clone()
    }

    #[napi(getter)]
    pub fn budget_usd(&self) -> Option<u32> {
        self.inner.budget_usd
    }

    #[napi(getter)]
    pub fn max_delegation_depth(&self) -> u32 {
        self.inner.max_delegation_depth
    }

    #[napi(getter)]
    pub fn valid_for_secs(&self) -> i64 {
        self.inner.valid_for_secs as i64
    }

    #[napi(getter)]
    pub fn autonomy_level(&self) -> u8 {
        self.inner.autonomy_level
    }

    #[napi(getter)]
    pub fn model_version(&self) -> Option<String> {
        self.inner.model_version.clone()
    }

    #[napi(getter)]
    pub fn artifact_hash(&self) -> Option<String> {
        self.inner.artifact_hash.clone()
    }

    #[napi(getter)]
    pub fn authorized_by(&self) -> Option<String> {
        self.inner.authorized_by.clone()
    }

    /// Who answers for what this agent does.
    ///
    /// Unlike `authorizedBy`, this is never selectively disclosable - a verifier is
    /// always shown it, because "who is responsible" is not a claim the holder gets to
    /// withhold.
    #[napi(getter)]
    pub fn accountable_party(&self) -> Option<String> {
        self.inner.accountable_party.clone()
    }

    /// How the accountable party was established. Travels with the party because in an
    /// audit they are one question.
    #[napi(getter)]
    pub fn accountability_source(&self) -> String {
        self.inner.accountability_source.as_str().to_string()
    }

    /// The human principal this credential authorizes the agent to act for, if
    /// it is an on-behalf-of credential.
    #[napi(getter)]
    pub fn on_behalf_of(&self) -> Option<HumanAuthorization> {
        self.inner
            .on_behalf_of
            .clone()
            .map(HumanAuthorization::from_core)
    }

    /// Bind a principal (on-behalf-of) to these claims.
    #[napi]
    pub fn set_on_behalf_of(&mut self, auth: HumanAuthorization) -> Result<()> {
        self.inner.on_behalf_of = Some(auth.to_core()?);
        Ok(())
    }

    /// Validate that claims are internally consistent (throws on failure).
    #[napi]
    pub fn validate(&self) -> Result<()> {
        self.inner.validate().map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "CapabilityClaims(tools={:?}, budget_usd={:?}, max_delegation_depth={}, valid_for_secs={})",
            self.inner.tools, self.inner.budget_usd, self.inner.max_delegation_depth, self.inner.valid_for_secs
        )
    }
}

// -- CredentialStatus ----------------------------------------------------------

#[napi]
pub struct CredentialStatus {
    pub(crate) inner: CoreCredentialStatus,
}

#[napi]
impl CredentialStatus {
    /// Construct an OAuth Status List entry reference for `index` within the list
    /// published at `registryUrl`.
    #[napi(constructor)]
    pub fn new(registry_url: String, index: i64) -> Result<Self> {
        if index < 0 {
            return Err(invalid_arg("index must be non-negative"));
        }
        Ok(Self {
            inner: CoreCredentialStatus::new(&registry_url, index as u64),
        })
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter, js_name = "type")]
    pub fn type_(&self) -> String {
        self.inner.r#type.clone()
    }

    #[napi(getter)]
    pub fn status_purpose(&self) -> String {
        self.inner.status_purpose.clone()
    }

    #[napi(getter)]
    pub fn status_list_index(&self) -> i64 {
        self.inner.status_list_index as i64
    }

    #[napi(getter)]
    pub fn status_list_credential(&self) -> String {
        self.inner.status_list_credential.clone()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "CredentialStatus(id='{}', status_list_index={})",
            self.inner.id, self.inner.status_list_index
        )
    }
}

// -- LinkedDataProof -----------------------------------------------------------

#[napi]
pub struct LinkedDataProof {
    pub(crate) inner: CoreLinkedDataProof,
}

#[napi]
impl LinkedDataProof {
    #[napi(getter, js_name = "type")]
    pub fn type_(&self) -> String {
        self.inner.r#type.clone()
    }

    #[napi(getter)]
    pub fn created(&self) -> DateTime<Utc> {
        self.inner.created
    }

    #[napi(getter)]
    pub fn verification_method(&self) -> String {
        self.inner.verification_method.clone()
    }

    #[napi(getter)]
    pub fn proof_purpose(&self) -> String {
        self.inner.proof_purpose.clone()
    }

    #[napi(getter)]
    pub fn proof_value(&self) -> String {
        self.inner.proof_value.clone()
    }

    #[napi(getter)]
    pub fn payload_hash(&self) -> String {
        self.inner.payload_hash.clone()
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "LinkedDataProof(type='{}', verification_method='{}')",
            self.inner.r#type, self.inner.verification_method
        )
    }
}

// -- CapabilityCredential ------------------------------------------------------

#[napi]
pub struct CapabilityCredential {
    pub(crate) inner: CoreCapabilityCredential,
}

#[napi]
impl CapabilityCredential {
    /// Issue a new capability credential signed by `anchor`.
    #[napi(factory)]
    pub fn issue(
        anchor: &TrustAnchor,
        subject_did: String,
        claims: &CapabilityClaims,
        revocation: Option<&CredentialStatus>,
    ) -> Result<Self> {
        let inner = CoreCapabilityCredential::issue(
            &anchor.inner,
            &subject_did,
            claims.inner.clone(),
            revocation.map(|r| r.inner.clone()),
        )
        .map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Deserialise a credential from its JSON-LD representation.
    #[napi(factory)]
    pub fn from_json(json: String) -> Result<Self> {
        Ok(Self {
            inner: CoreCapabilityCredential::from_json(&json).map_err(map_err)?,
        })
    }

    /// Serialize this credential to canonical JSON-LD.
    #[napi]
    pub fn to_json(&self) -> Result<String> {
        self.inner.to_json().map_err(map_err)
    }

    #[napi(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[napi(getter)]
    pub fn context(&self) -> Vec<String> {
        self.inner.context.clone()
    }

    #[napi(getter, js_name = "type")]
    pub fn type_(&self) -> Vec<String> {
        self.inner.r#type.clone()
    }

    #[napi(getter)]
    pub fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    #[napi(getter)]
    pub fn issuance_date(&self) -> DateTime<Utc> {
        self.inner.issuance_date
    }

    #[napi(getter)]
    pub fn proof(&self) -> LinkedDataProof {
        LinkedDataProof {
            inner: self.inner.proof.clone(),
        }
    }

    #[napi(getter)]
    pub fn credential_status(&self) -> Option<CredentialStatus> {
        self.inner
            .credential_status
            .clone()
            .map(|inner| CredentialStatus { inner })
    }

    #[napi]
    pub fn subject_did(&self) -> String {
        self.inner.subject_did().to_string()
    }

    #[napi]
    pub fn claims(&self) -> CapabilityClaims {
        CapabilityClaims {
            inner: self.inner.claims().clone(),
        }
    }

    #[napi]
    pub fn expiration_date(&self) -> DateTime<Utc> {
        self.inner.expiration_date()
    }

    #[napi]
    pub fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    /// Verify this credential's cryptographic proof against `anchor`.
    /// `strictIssuer` defaults to `true`.
    #[napi]
    pub fn verify(&self, anchor: &TrustAnchor, strict_issuer: Option<bool>) -> Result<()> {
        self.inner
            .verify(&anchor.inner, strict_issuer.unwrap_or(true))
            .map_err(map_err)
    }

    #[napi]
    pub fn to_string(&self) -> String {
        format!(
            "CapabilityCredential(id='{}', issuer='{}', subject='{}')",
            self.inner.id,
            self.inner.issuer,
            self.inner.subject_did()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    fn sample_claims() -> CapabilityClaims {
        CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools: vec!["tool:search".into(), "tool:email".into()],
            max_delegation_depth: 3,
            valid_for_secs: 3600,
            budget_usd: Some(100),
            autonomy_level: Some(2),
            model_version: Some("gpt-test".into()),
            artifact_hash: Some("sha256:abc".into()),
            authorized_by: Some("did:key:zissuer".into()),
            accountable_party: None,
        })
        .unwrap()
    }

    #[test]
    fn capability_claims_getters_and_validate() {
        let claims = sample_claims();
        assert_eq!(
            claims.tools(),
            vec!["tool:search".to_string(), "tool:email".to_string()]
        );
        assert_eq!(claims.budget_usd(), Some(100));
        assert_eq!(claims.max_delegation_depth(), 3);
        assert_eq!(claims.valid_for_secs(), 3600);
        assert_eq!(claims.autonomy_level(), 2);
        assert_eq!(claims.model_version(), Some("gpt-test".to_string()));
        assert_eq!(claims.artifact_hash(), Some("sha256:abc".to_string()));
        assert_eq!(claims.authorized_by(), Some("did:key:zissuer".to_string()));
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn capability_claims_default_autonomy_level() {
        let claims = CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools: vec!["tool:search".into()],
            max_delegation_depth: 1,
            valid_for_secs: 60,
            budget_usd: None,
            autonomy_level: None,
            model_version: None,
            artifact_hash: None,
            authorized_by: None,
            accountable_party: None,
        })
        .unwrap();
        assert_eq!(claims.autonomy_level(), 0);
        assert_eq!(claims.budget_usd(), None);
    }

    #[test]
    fn capability_claims_rejects_negative_valid_for_secs() {
        let result = CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools: vec![],
            max_delegation_depth: 0,
            valid_for_secs: -1,
            budget_usd: None,
            autonomy_level: None,
            model_version: None,
            artifact_hash: None,
            authorized_by: None,
            accountable_party: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn credential_status_getters_and_negative_index() {
        let status =
            CredentialStatus::new("https://registry.example.com/status/1".into(), 5).unwrap();
        assert_eq!(status.status_list_index(), 5);
        assert_eq!(status.type_(), "OAuthStatusListEntry");
        assert_eq!(status.status_purpose(), "revocation");
        assert_eq!(status.id(), "https://registry.example.com/status/1#5");
        assert_eq!(
            status.status_list_credential(),
            "https://registry.example.com/status/1"
        );

        assert!(CredentialStatus::new("https://registry.example.com/status/1".into(), -1).is_err());
    }

    #[test]
    fn issue_and_verify_capability_credential() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let claims = sample_claims();

        let vc = CapabilityCredential::issue(&anchor, agent.did(), &claims, None).unwrap();
        assert_eq!(vc.issuer(), anchor.did());
        assert_eq!(vc.subject_did(), agent.did());
        assert!(vc.is_valid());
        assert!(vc.verify(&anchor, None).is_ok());

        let proof = vc.proof();
        assert!(!proof.proof_value().is_empty());
        assert!(!proof.payload_hash().is_empty());

        let json = vc.to_json().unwrap();
        let round_tripped = CapabilityCredential::from_json(json).unwrap();
        assert_eq!(round_tripped.id(), vc.id());
        assert!(round_tripped.verify(&anchor, None).is_ok());
    }

    #[test]
    fn issue_with_revocation_status() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let claims = sample_claims();
        let status =
            CredentialStatus::new("https://registry.example.com/status/1".into(), 7).unwrap();

        let vc = CapabilityCredential::issue(&anchor, agent.did(), &claims, Some(&status)).unwrap();
        let cred_status = vc.credential_status().unwrap();
        assert_eq!(cred_status.status_list_index(), 7);
    }

    #[test]
    fn verify_fails_with_wrong_anchor() {
        let anchor = TrustAnchor::generate().unwrap();
        let other_anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let claims = sample_claims();

        let vc = CapabilityCredential::issue(&anchor, agent.did(), &claims, None).unwrap();
        assert!(vc.verify(&other_anchor, None).is_err());
    }

    #[test]
    fn capability_credential_to_string_contains_ids() {
        let anchor = TrustAnchor::generate().unwrap();
        let agent = AgentIdentity::create_did_key(None).unwrap();
        let claims = sample_claims();
        let vc = CapabilityCredential::issue(&anchor, agent.did(), &claims, None).unwrap();
        let s = vc.to_string();
        assert!(s.contains(&vc.id()));
        assert!(s.contains(&anchor.did()));
        assert!(s.contains(&agent.did()));
    }
}

#[cfg(test)]
mod accountability_tests {
    use super::*;
    use chrono::Duration;

    // A Node relying party sees the credential through this binding and nothing else.
    // A field that exists in core but stops at the FFI boundary is, to that party, a
    // field that does not exist - so it is checked here, not only in core.

    fn claims(accountable_party: Option<&str>) -> CapabilityClaims {
        CapabilityClaims::new(CapabilityClaimsInit {
            resources: None,
            party_version: None,
            party_commitment: None,
            tools: vec!["tool:pay".into()],
            max_delegation_depth: 1,
            valid_for_secs: 3600,
            budget_usd: None,
            autonomy_level: None,
            model_version: None,
            artifact_hash: None,
            authorized_by: None,
            accountable_party: accountable_party.map(str::to_string),
        })
        .unwrap()
    }

    #[test]
    fn accountable_party_crosses_the_binding() {
        let named = claims(Some("team:settlement"));
        assert_eq!(named.accountable_party(), Some("team:settlement".into()));
        assert_eq!(
            named.inner.accountable_party.as_deref(),
            Some("team:settlement"),
            "the getter and the core value disagree"
        );

        // Absence is representable and distinct from a named party: it means "issued
        // before accountability was recorded", never "no one is responsible".
        assert_eq!(claims(None).accountable_party(), None);
    }

    fn principal(kind: Option<&str>) -> HumanAuthorization {
        HumanAuthorization {
            principal_did: "did:web:acme.example:w:abc".into(),
            kind: kind.map(str::to_string),
            entitlement_source: None,
            issuer: "acme.example".into(),
            subject: "spiffe://acme.example/payments".into(),
            expires_at: Utc::now() + Duration::hours(1),
            scope_consented: None,
            resource_authority: None,
            authorized_at: None,
        }
    }

    #[test]
    fn a_workload_principal_round_trips_as_a_workload() {
        // The two populations must stay distinguishable across the boundary. Were the
        // kind dropped here, a Node verifier would read every service-initiated agent as
        // human-delegated - the exact confusion the kind exists to prevent.
        let core = principal(Some("workload")).to_core().unwrap();
        assert_eq!(core.kind, PrincipalKind::Workload);
        assert_eq!(
            HumanAuthorization::from_core(core).kind.as_deref(),
            Some("workload"),
            "the kind was lost on the way back out"
        );

        // Omitted means human, so credentials written before workloads could be
        // principals read back unchanged.
        assert_eq!(
            principal(None).to_core().unwrap().kind,
            PrincipalKind::Human
        );
    }

    #[test]
    fn the_entitlement_source_crosses_the_binding_in_both_directions() {
        // The label is the reason the second axis can be trusted at all. A Node verifier
        // that could read the entitlements but not their source would have to assume the
        // strongest reading - and `asserted`, the weakest, is the case worth noticing.
        let mut p = principal(Some("workload"));
        p.entitlement_source = Some("policy".into());
        let core = p.to_core().unwrap();
        assert_eq!(core.entitlement_source, AuthoritySource::Policy);
        assert_eq!(
            HumanAuthorization::from_core(core)
                .entitlement_source
                .as_deref(),
            Some("policy"),
            "the source was lost on the way back out"
        );

        // Omitted means asserted: a caller that does not say has established nothing,
        // and absence must not read as strength.
        assert_eq!(
            principal(None).to_core().unwrap().entitlement_source,
            AuthoritySource::Asserted
        );
    }

    #[test]
    fn an_unknown_authority_source_is_refused_not_defaulted() {
        // Defaulting would silently downgrade a source this build does not understand,
        // and an auditor would see evidence weaken for no reason.
        let mut p = principal(Some("workload"));
        p.entitlement_source = Some("Attested".into()); // wrong case
        let err = p.to_core().unwrap_err();
        assert!(
            err.to_string().contains("unknown authority source"),
            "wrong error: {err}"
        );

        let mut ok = principal(Some("workload"));
        ok.entitlement_source = Some("attested".into());
        assert!(ok.to_core().is_ok(), "control");
    }

    #[test]
    fn an_unknown_principal_kind_is_refused_not_defaulted() {
        // Defaulting would report an unrecognised kind as human - a silent
        // misattribution of which root attested the binding.
        let err = principal(Some("Workload")).to_core().unwrap_err();
        assert!(
            err.to_string().contains("unknown principal kind"),
            "wrong error: {err}"
        );
        assert!(principal(Some("workload")).to_core().is_ok(), "control");
    }
}

// -- OwnershipRecord (resolving a party to humans, later) ----------------------

/// One revision of "who is behind this accountable party".
///
/// Held by the organization and **never** placed in a credential - only `version`
/// and `commitment` travel. The members are personal data, and a credential is
/// signed, immutable, presented across organizational boundaries, and outlives the
/// employment, so it can neither correct nor erase them.
///
/// The commitment is salted, so it is not a membership oracle over a guessable
/// list. Erasure degrades in the right direction: delete someone from the store and
/// the commitment stops matching anything you can produce - you lose the ability to
/// prove *who was in the team*, and keep the ability to prove *which team*.
#[napi]
pub struct OwnershipRecord {
    inner: CoreOwnershipRecord,
}

#[napi]
impl OwnershipRecord {
    /// Build a record. `members` is sorted and de-duplicated, so the store's return
    /// order cannot change the commitment. `salt` must be at least 16 characters - a
    /// short salt makes the commitment brute-forceable from a candidate membership
    /// list, which is the exact data it exists to protect.
    #[napi(constructor)]
    pub fn new(party_id: String, version: i64, members: Vec<String>, salt: String) -> Result<Self> {
        if version < 0 {
            return Err(invalid_arg("version must be non-negative"));
        }
        Ok(Self {
            inner: CoreOwnershipRecord::new(party_id, version as u64, members, salt)
                .map_err(map_err)?,
        })
    }

    #[napi(getter)]
    pub fn party_id(&self) -> String {
        self.inner.party_id().to_string()
    }

    /// Which revision this is. Goes on the credential; an auditor uses it to ask the
    /// store for the record as it stood at issuance rather than as it stands now.
    #[napi(getter)]
    pub fn version(&self) -> i64 {
        self.inner.version() as i64
    }

    /// The members, sorted. Personal data - keep it here.
    #[napi(getter)]
    pub fn members(&self) -> Vec<String> {
        self.inner.members().to_vec()
    }

    /// The salted commitment, hex. The only part that travels.
    #[napi(getter)]
    pub fn commitment(&self) -> String {
        self.inner.commitment()
    }

    /// Whether this record is the one `commitment` was made over - the audit-time
    /// check. A record that does not match was not the one committed to.
    #[napi]
    pub fn matches(&self, commitment: String) -> bool {
        self.inner.matches(&commitment)
    }
}
