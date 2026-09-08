//! Generate cross-language conformance vectors.
//!
//! Emits a JSON file of canonical artifacts - a capability credential, a delegation
//! token, a full presentation (token + credential + proof-of-possession), and a
//! revocation list - produced by the Rust core, each paired with the anchor/action a
//! consumer must check and the expected accept/reject outcome. Every AgentCreds
//! language binding ships a conformance test that loads this file and must reach the
//! *same* decision, proving the wire formats and verification logic agree across
//! languages (Rust <-> Node <-> Python).
//!
//! Run: `cargo run -p agentcreds-core --example gen_conformance_vectors -- <out.json>`
//!
//! Validity windows are set a century out so the committed golden file never expires;
//! freshness/expiry semantics are exercised by unit tests, not by these vectors.

use agentcreds_core::delegation::{ApprovalEvidence, ApproverDirectory, ApproverEntry};
use agentcreds_core::prelude::*;
use agentcreds_core::registry::{TrustEntry, TrustLevel, TrustRegistry};
use agentcreds_core::revocation::RevocationList;
use agentcreds_core::rotation::{KeyHistory, RotationStatement};
use agentcreds_core::testkit::MockOrg;

/// Far-future validity for **credentials**, so golden vectors don't expire. A
/// credential's `valid_for_secs` is not bounded by the autonomy ladder.
const YEARS_100_SECS: u64 = 100 * 365 * 24 * 3600;

/// Token TTL for the vectors - the longest the autonomy ladder permits at level 0.
///
/// Tokens cannot borrow the credential's far-future trick: `max_token_ttl_secs` caps a
/// minted token at one hour (L0) down to five minutes (L3), deliberately, so a leaked
/// token stops being useful quickly. That is a security control and the vectors do not
/// get to opt out of it - which is why this file records `evaluated_at` and consumers
/// verify **as of** that instant rather than the wall clock.
///
/// Before this existed the generator asked for a 100-year token and simply failed, so the
/// vectors could not be regenerated at all once the ladder landed.
const TOKEN_TTL_SECS: u64 = agentcreds_core::vc::max_token_ttl_secs(0);
const REVOKED_INDEX: u64 = 7;
const CLEAR_INDEX: u64 = 8;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "conformance/vectors.json".to_string());

    // The instant every case is evaluated at. Recorded in the file so a consumer judges
    // the token-bearing cases against generation time rather than its own clock - the
    // tokens live one hour (the L0 autonomy ceiling), so wall-clock verification would
    // start failing an hour after this file was written.
    let generated_at = chrono::Utc::now().timestamp();

    // Two orgs: the issuer, and an unrelated org used for the wrong-anchor rejections.
    let org = MockOrg::new("conformance-issuer")?;
    let other = MockOrg::new("conformance-other")?;

    // An agent credentialed for search+email; a token attenuated to search only (so
    // an `tool:email` action is a genuine scope denial, not a missing credential).
    let agent = org.issue_agent(
        vec!["tool:search".into(), "tool:email".into()],
        Some(100),
        2,
        YEARS_100_SECS,
    )?;
    let token = agent.mint(vec!["tool:search".into()], Some(50), 1, TOKEN_TTL_SECS)?;

    // A TWO-HOP chain. Every case above this point is depth 0, which is how a wire-format
    // break that hit every attenuated token slipped past this suite entirely: the
    // biscuit-auth 4 -> 6 upgrade changed THIRD-PARTY block signing, and third-party
    // blocks only appear once a token has been attenuated. A binding could mishandle an
    // attenuated chain and nothing here would notice.
    //
    // The parent carries both tools so the child can narrow one AWAY - that makes the
    // rejection below a genuine attenuation check rather than a missing-capability check.
    let parent = agent.mint(
        vec!["tool:search".into(), "tool:email".into()],
        Some(100),
        1,
        TOKEN_TTL_SECS,
    )?;
    let sub_identity = AgentIdentity::create(DidMethod::Key, None)?;
    let child = parent.attenuate(
        Scope::with_budget_and_depth(vec!["tool:search".into()], Some(50), 0),
        TOKEN_TTL_SECS,
        &sub_identity,
    )?;

    let challenge = PopChallenge::new(Some("mcp://conformance".into()));
    let presentation = agent.present(token.clone(), &challenge)?;

    // Proof of possession on an attenuated chain must be signed by the LEAF key, not the
    // original agent's - a binding that reached for the wrong key would pass every
    // depth-0 case and fail here.
    let child_presentation = Presentation::create(
        child.clone(),
        agent.credential.clone(),
        &challenge,
        &sub_identity,
    )?;

    // A revocation list with one bit set, to check the offline revocation lookup.
    let mut list = RevocationList::new(
        "https://conformance.example/status/1",
        org.anchor(),
        Some(1024),
    )?;
    list.revoke(REVOKED_INDEX, org.anchor())?;

    let credential_json = agent.credential.to_json()?;
    let presentation_hex = to_hex(&presentation.to_cbor()?);
    let challenge_hex = to_hex(&challenge.to_cbor()?);
    let token_hex = to_hex(&token.to_cbor()?);
    let parent_token_hex = to_hex(&parent.to_cbor()?);
    let child_token_hex = to_hex(&child.to_cbor()?);
    let child_presentation_hex = to_hex(&child_presentation.to_cbor()?);
    let max_age = YEARS_100_SECS;
    // Ordered hop DIDs, root first - what a binding must surface from `chain()`.
    let chain_dids: Vec<String> = child
        .chain()
        .entries
        .iter()
        .map(|e| e.agent_did.clone())
        .collect();

    // -- Key rotation ------------------------------------------------------------
    //
    // An org rotates its anchor. The relying party pins the ROOT once and follows the
    // signed history forward, so a rotation is local to the rotating org rather than a
    // multilateral re-provisioning event.
    //
    // The distinction these cases exist to pin is between the two reasons to rotate.
    // PLANNED rotation (moving a key into a KMS, scheduled hygiene) leaves credentials
    // issued by the superseded key valid - it was legitimately held. COMPROMISE does
    // not, and the history says so by repudiating that key. A binding that treats
    // "superseded" and "repudiated" alike is wrong in one direction or the other:
    // it either breaks planned rotation or keeps honouring a stolen key.
    let rot = MockOrg::new("conformance-rotating")?;
    let rot_successor = MockOrg::new("conformance-rotating-successor")?;

    // Credentials from each key. Same org, same holder - only the issuing key differs.
    let rot_agent_root = rot.issue_agent(vec!["tool:search".into()], None, 1, YEARS_100_SECS)?;
    let rot_agent_new =
        rot_successor.issue_agent(vec!["tool:search".into()], None, 1, YEARS_100_SECS)?;
    let cred_by_root = rot_agent_root.credential.to_json()?;
    let cred_by_current = rot_agent_new.credential.to_json()?;

    // Sealed history: root -> successor. `None` expiry keeps the golden file evergreen,
    // matching the century-out validity used everywhere else here.
    let mut history = KeyHistory::genesis(rot.anchor());
    history.push(RotationStatement::issue(
        rot.anchor(),
        rot_successor.anchor(),
    )?)?;
    history.seal(rot_successor.anchor(), 1, None)?;
    let history_json = history.to_json()?;

    // The same history one incident later: the root key is repudiated.
    let mut repudiated = KeyHistory::from_json(&history_json)?;
    repudiated.repudiate(rot.did())?;
    repudiated.seal(rot_successor.anchor(), 2, None)?;
    let repudiated_json = repudiated.to_json()?;

    // An UNSEALED history, to prove a binding refuses one. Repudiations and the expiry
    // are strippable if the chain is unsigned, so honouring an unsealed history would
    // let an attacker downgrade to the permissive case by deleting a field.
    let mut unsealed = KeyHistory::genesis(rot.anchor());
    unsealed.push(RotationStatement::issue(
        rot.anchor(),
        rot_successor.anchor(),
    )?)?;
    let unsealed_json = unsealed.to_json()?;

    // -- Hybrid R10: approver-key evidence ---------------------------------------
    //
    // Anchor-signed approval proves the ORGANIZATION approved; this proves WHO. The
    // approver signs with their own key, authorized by an anchor-signed directory - one
    // trust root, per-human non-repudiation.
    //
    // The directory is also the joiner/mover/leaver control: removing an entry withdraws
    // that person authority, which is why the reject case below matters as much as the
    // accept.
    let approver = AgentIdentity::create(DidMethod::Key, None)?;
    let outsider = AgentIdentity::create(DidMethod::Key, None)?;
    let approval_action = Action::new("tool:wire", "amount=100");
    let far_future =
        (chrono::Utc::now() + chrono::Duration::seconds(YEARS_100_SECS as i64)).timestamp();

    let directory = ApproverDirectory::seal(
        vec![ApproverEntry {
            approver_id: "alice@example.com".into(),
            approver_did: approver.did().to_string(),
            roles: vec!["finance".into()],
            not_after: None,
        }],
        1,
        chrono::Utc::now(),
        None,
        org.anchor(),
    )?;
    let directory_json = serde_json::to_string(&directory)?;

    let evidence_enrolled = serde_json::to_string(&ApprovalEvidence::approve_by_key(
        &approval_action,
        "alice@example.com",
        &approver,
        "apr-1",
        far_future,
    )?)?;
    // Same shape, signed by a key the directory does not name.
    let evidence_outsider = serde_json::to_string(&ApprovalEvidence::approve_by_key(
        &approval_action,
        "mallory@evil.example",
        &outsider,
        "apr-2",
        far_future,
    )?)?;

    // -- Cross-org: the framework signed trust config ----------------------------
    //
    // R2 resolution through a trust framework, which no earlier vector carried. The
    // registry decides membership AND a minimum trust level, and both must survive the
    // language boundary - a binding that reads membership but drops the level would
    // silently admit under-verified organizations.
    let member_low = MockOrg::new("conformance-member-low")?;
    let mut framework_registry = TrustRegistry::new();
    framework_registry.register(TrustEntry::new(
        org.did(),
        "Conformance Issuer",
        org.anchor().public_key().clone(),
        TrustLevel::Verified,
    ));
    framework_registry.register(TrustEntry::new(
        member_low.did(),
        "Under-verified Member",
        member_low.anchor().public_key().clone(),
        TrustLevel::SelfAsserted,
    ));
    framework_registry.minimum_trust_level = TrustLevel::Verified;
    let framework = MockOrg::new("conformance-framework")?;
    let trust_config_json = framework_registry
        .export(framework.anchor(), 1)?
        .to_json()?;
    let low_agent = member_low.issue_agent(vec!["tool:search".into()], None, 1, YEARS_100_SECS)?;
    let low_credential_json = low_agent.credential.to_json()?;

    let vectors = serde_json::json!({
        "format": 3,
        "generator": "agentcreds-core examples/gen_conformance_vectors",
        "evaluated_at": generated_at,
        "note": "Golden cross-language conformance vectors. Every binding must reach the \
                 stated accept/reject for each case. Credentials are far-future, but TOKENS \
                 are bounded by the autonomy ladder (one hour at L0) and would otherwise \
                 expire within the hour - so verify AS OF `evaluated_at` (Unix seconds) via \
                 verify_rooted_at / verifyRootedAt, not against the wall clock. \
                 Regenerate when a wire format changes.",
        "cases": [
            {
                "name": "presentation_accept",
                "kind": "presentation",
                "anchor_did": org.did(),
                "presentation_cbor_hex": presentation_hex,
                "challenge_cbor_hex": challenge_hex,
                "action": { "tool": "tool:search", "parameters": "q=ok" },
                "max_age_secs": max_age,
                "expect": "accept"
            },
            {
                "name": "presentation_reject_denied_tool",
                "kind": "presentation",
                "anchor_did": org.did(),
                "presentation_cbor_hex": presentation_hex,
                "challenge_cbor_hex": challenge_hex,
                "action": { "tool": "tool:email", "parameters": "" },
                "max_age_secs": max_age,
                "expect": "reject"
            },
            {
                "name": "presentation_reject_wrong_anchor",
                "kind": "presentation",
                "anchor_did": other.did(),
                "presentation_cbor_hex": presentation_hex,
                "challenge_cbor_hex": challenge_hex,
                "action": { "tool": "tool:search", "parameters": "q=ok" },
                "max_age_secs": max_age,
                "expect": "reject"
            },
            {
                "name": "credential_accept",
                "kind": "credential",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "expect": "accept"
            },
            {
                "name": "credential_reject_wrong_anchor",
                "kind": "credential",
                "anchor_did": other.did(),
                "credential_json": credential_json,
                "expect": "reject"
            },
            {
                "name": "token_accept_permitted_action",
                "kind": "token",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "token_cbor_hex": token_hex,
                "action": { "tool": "tool:search", "parameters": "q=ok" },
                "expect": "accept"
            },
            {
                "name": "token_reject_denied_action",
                "kind": "token",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "token_cbor_hex": token_hex,
                "action": { "tool": "tool:email", "parameters": "" },
                "expect": "reject"
            },
            {
                "name": "token_multihop_accept",
                "kind": "token",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "token_cbor_hex": child_token_hex,
                "action": { "tool": "tool:search", "parameters": "q=ok" },
                "expect": "accept"
            },
            {
                // The control for the case below. Without it, "child rejects tool:email"
                // would also pass if the credential never granted tool:email at all -
                // green for the wrong reason. This proves the PARENT hop accepts it, so
                // the child's rejection can only be attenuation.
                "name": "token_multihop_parent_allows_before_attenuation",
                "kind": "token",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "token_cbor_hex": parent_token_hex,
                "action": { "tool": "tool:email", "parameters": "" },
                "expect": "accept"
            },
            {
                "name": "token_multihop_reject_attenuated_away",
                "kind": "token",
                "anchor_did": org.did(),
                "credential_json": credential_json,
                "token_cbor_hex": child_token_hex,
                // tool:email is granted by the credential AND by the parent hop, and
                // removed only by the child's narrowing. Accepting it would mean the
                // binding read the chain but not its attenuation.
                "action": { "tool": "tool:email", "parameters": "" },
                "expect": "reject"
            },
            {
                "name": "presentation_multihop_accept",
                "kind": "presentation",
                "anchor_did": org.did(),
                "presentation_cbor_hex": child_presentation_hex,
                "challenge_cbor_hex": challenge_hex,
                "action": { "tool": "tool:search", "parameters": "q=ok" },
                "max_age_secs": max_age,
                "expect": "accept"
            },
            {
                "name": "token_chain_multihop",
                "kind": "token_chain",
                "anchor_did": org.did(),
                "token_cbor_hex": child_token_hex,
                "expect_depth": 1,
                "expect_chain_agent_dids": chain_dids,
                "expect": "accept"
            },
            {
                // Planned rotation: the post-rotation key resolves against the pinned
                // ROOT, with nothing re-signed by anyone else.
                "name": "key_history_accept_rotated_issuer",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": history_json,
                "credential_json": cred_by_current,
                "expect": "accept"
            },
            {
                // THE CONTROL for the repudiation case below, and the reason this suite
                // is not just "old key rejected". Under planned rotation a superseded
                // key stays valid, so the rejection below is attributable to the
                // repudiation specifically - not to the key merely being old.
                "name": "key_history_accept_superseded_issuer",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": history_json,
                "credential_json": cred_by_root,
                "expect": "accept"
            },
            {
                // The compromise case. Identical credential and root to the case above;
                // only the history differs, by carrying a repudiation of that key.
                "name": "key_history_reject_repudiated_issuer",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": repudiated_json,
                "credential_json": cred_by_root,
                "expect": "reject"
            },
            {
                // Repudiating one key must not disable the organization. Without this,
                // a binding that refuses every issuer once any repudiation is present
                // would pass the case above for the wrong reason.
                "name": "key_history_accept_current_after_repudiation",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": repudiated_json,
                "credential_json": cred_by_current,
                "expect": "accept"
            },
            {
                // A valid chain is not membership: this history says nothing about an
                // issuer outside it.
                "name": "key_history_reject_foreign_issuer",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": history_json,
                "credential_json": credential_json,
                "expect": "reject"
            },
            {
                // An unsealed chain is refused even though its linkage is intact.
                "name": "key_history_reject_unsealed_history",
                "kind": "key_history",
                "anchor_did": rot.did(),
                "key_history_json": unsealed_json,
                "credential_json": cred_by_current,
                "expect": "reject"
            },
            {
                // Rooted elsewhere: the chain is internally valid but does not start at
                // the DID the relying party pinned.
                "name": "key_history_reject_wrong_root",
                "kind": "key_history",
                "anchor_did": other.did(),
                "key_history_json": history_json,
                "credential_json": cred_by_current,
                "expect": "reject"
            },
            {
                // The enrolled approver, signing for exactly this action.
                "name": "approval_key_accept_enrolled_approver",
                "kind": "approval_key",
                "anchor_did": org.did(),
                "directory_json": directory_json,
                "evidence_json": evidence_enrolled,
                "action": { "tool": "tool:wire", "parameters": "amount=100" },
                "expect": "accept"
            },
            {
                // THE CONTROL that makes the directory meaningful. Identical evidence
                // shape, valid signature, correct action - but signed by a key the
                // directory does not enrol. An implementation that verifies the
                // signature without consulting the directory passes the accept case and
                // fails here, which is exactly the mistake worth catching.
                "name": "approval_key_reject_unenrolled_approver",
                "kind": "approval_key",
                "anchor_did": org.did(),
                "directory_json": directory_json,
                "evidence_json": evidence_outsider,
                "action": { "tool": "tool:wire", "parameters": "amount=100" },
                "expect": "reject"
            },
            {
                // Approval is bound to the REQUEST, not just the tool. Replaying an
                // approval for a different amount is the canonical R10 attack.
                "name": "approval_key_reject_different_action",
                "kind": "approval_key",
                "anchor_did": org.did(),
                "directory_json": directory_json,
                "evidence_json": evidence_enrolled,
                "action": { "tool": "tool:wire", "parameters": "amount=999999" },
                "expect": "reject"
            },
            {
                // A directory verified against the wrong anchor authorizes nobody.
                "name": "approval_key_reject_wrong_anchor",
                "kind": "approval_key",
                "anchor_did": other.did(),
                "directory_json": directory_json,
                "evidence_json": evidence_enrolled,
                "action": { "tool": "tool:wire", "parameters": "amount=100" },
                "expect": "reject"
            },
            {
                "name": "trust_config_accept_member",
                "kind": "trust_config",
                "anchor_did": framework.did(),
                "config_json": trust_config_json,
                "credential_json": credential_json,
                "expect": "accept"
            },
            {
                // The security case: membership is not enough. A member below the
                // framework minimum must not resolve, or the trust level is decorative.
                "name": "trust_config_reject_below_minimum_level",
                "kind": "trust_config",
                "anchor_did": framework.did(),
                "config_json": trust_config_json,
                "credential_json": low_credential_json,
                "expect": "reject"
            },
            {
                // A non-member, with a perfectly valid credential of its own.
                "name": "trust_config_reject_non_member",
                "kind": "trust_config",
                "anchor_did": framework.did(),
                "config_json": trust_config_json,
                "credential_json": cred_by_current,
                "expect": "reject"
            },
            {
                // The config must verify under the FRAMEWORK anchor, not any anchor.
                "name": "trust_config_reject_wrong_framework",
                "kind": "trust_config",
                "anchor_did": other.did(),
                "config_json": trust_config_json,
                "credential_json": credential_json,
                "expect": "reject"
            },
            {
                "name": "revocation_lookup",
                "kind": "revocation",
                "anchor_did": org.did(),
                "list_json": list.to_json()?,
                "revoked_index": REVOKED_INDEX,
                "clear_index": CLEAR_INDEX
            }
        ]
    });

    std::fs::write(&out, serde_json::to_string_pretty(&vectors)?)?;
    eprintln!("wrote {} conformance cases to {out}", 28);
    Ok(())
}
