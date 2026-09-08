//! Resolving an accountable party to the humans behind it, without putting them
//! in the credential.
//!
//! # The problem
//!
//! `accountable_party` is a **pointer with no time coordinate**. Three moments
//! matter and the credential records one: issuance (the party is named), the
//! action, and the audit. Resolving the pointer at audit time means resolving it
//! against an org chart that has since moved - teams get renamed, merged and
//! dissolved, and people leave. The string is stable; its referent is not.
//!
//! # Why not just embed the members
//!
//! Because a credential is signed, immutable, presented to every relying party
//! including across organizational boundaries, and outlives the employment. A
//! membership list in it cannot be corrected, cannot be withheld, and cannot be
//! erased. An immutable signed artifact versus an erasure request is a fight the
//! artifact loses.
//!
//! # What this does instead
//!
//! The credential carries a **version** and a **salted commitment**; the humans
//! stay in the organization's own store under its own retention policy.
//!
//! - `party_version` says *which* revision of the ownership record named this
//!   party, so an auditor resolves against the org chart as it was, not as it is.
//! - `party_commitment` makes that resolution **verifiable**: produce the record,
//!   recompute, compare. A record that does not match was not the one committed to.
//!
//! The salt is load-bearing, not decoration. An unsalted digest over a small
//! membership list is a **membership oracle** - guess a candidate list, hash,
//! compare. Salted per record, the commitment reveals nothing without the reveal.
//! This is the same construction [`crate::audit`] uses for cross-org custody.
//!
//! # Erasure degrades in the right direction
//!
//! Delete a person from the store and the commitment no longer matches anything
//! that can be produced. What is lost is the ability to prove **who was in the
//! team**; what survives is the ability to prove **which team** - and a party id
//! is not personal data. The erasable thing is erasable and the accountability
//! pointer is not.
//!
//! # What none of this establishes
//!
//! That the record is *true*. A commitment binds the organization to a record it
//! produced; it does not make the team exist or those people members. That is an
//! organizational fact, and the only lever on it is where the record comes from -
//! see the governance-key design in
//! `Docs/spec-ownership-records.md` (stage 3), which is deliberately not built here.
//!
//! ```rust
//! use agentcreds_core::accountability::OwnershipRecord;
//!
//! let record = OwnershipRecord::new(
//!     "team:payments-platform",
//!     7,
//!     vec!["alice@acme.example".into(), "bob@acme.example".into()],
//!     "a1b2c3d4e5f60718293a4b5c6d7e8f90",
//! )?;
//! let commitment = record.commitment();
//!
//! // At audit time: produce the record, recompute, compare.
//! assert!(record.matches(&commitment));
//! # Ok::<(), agentcreds_core::error::AgentCredsError>(())
//! ```

use sha2::{Digest, Sha256};

use crate::{error::AgentCredsError, Result};

/// Domain separation for the ownership commitment, so it can never collide with
/// any other SHA-256 use in the crate.
const OWNERSHIP_DOMAIN: &[u8] = b"agentcreds-ownership-commitment-v1";

/// The minimum salt length. Short enough to be convenient, long enough that a
/// commitment over a small, guessable membership list is not brute-forceable.
pub const MIN_SALT_LEN: usize = 16;

/// One revision of "who is behind this accountable party".
///
/// Held by the organization, **never** placed in a credential. Only its
/// [`commitment`](Self::commitment) travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRecord {
    party_id: String,
    version: u64,
    /// Sorted and de-duplicated at construction, so the commitment does not
    /// depend on the order the store happened to return members in.
    members: Vec<String>,
    salt: String,
}

impl OwnershipRecord {
    /// Build a record. `members` is sorted and de-duplicated; `salt` must be at
    /// least [`MIN_SALT_LEN`] characters.
    ///
    /// # Errors
    /// `OutOfBounds` if `party_id` is empty or the salt is too short.
    pub fn new(
        party_id: impl Into<String>,
        version: u64,
        members: Vec<String>,
        salt: impl Into<String>,
    ) -> Result<Self> {
        let party_id = party_id.into();
        let salt = salt.into();
        if party_id.trim().is_empty() {
            return Err(AgentCredsError::OutOfBounds {
                field: "party_id",
                detail: "an ownership record must name a party".into(),
            });
        }
        if salt.len() < MIN_SALT_LEN {
            return Err(AgentCredsError::OutOfBounds {
                field: "salt",
                detail: format!(
                    "ownership salt must be at least {MIN_SALT_LEN} chars - a short salt \
                     makes the commitment a membership oracle over a guessable list"
                ),
            });
        }
        let mut members = members;
        members.sort_unstable();
        members.dedup();
        Ok(OwnershipRecord {
            party_id,
            version,
            members,
            salt,
        })
    }

    /// The party this record resolves.
    #[must_use]
    pub fn party_id(&self) -> &str {
        &self.party_id
    }

    /// Which revision this is. Goes on the credential; an auditor uses it to ask
    /// the store for the record as it stood at issuance.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The members, sorted. Personal data - keep it here, not in a credential.
    #[must_use]
    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// The salted commitment, hex-encoded. This is the only part that travels.
    #[must_use]
    pub fn commitment(&self) -> String {
        let mut h = Sha256::new();
        h.update(OWNERSHIP_DOMAIN);
        write_field(&mut h, self.party_id.as_bytes());
        h.update(self.version.to_le_bytes());
        write_field(&mut h, self.salt.as_bytes());
        h.update((self.members.len() as u64).to_le_bytes());
        for m in &self.members {
            write_field(&mut h, m.as_bytes());
        }
        hex::encode(h.finalize())
    }

    /// Whether this record is the one `commitment` was made over.
    ///
    /// The comparison is over hex digests of a public commitment, not secret
    /// material, so ordinary equality is appropriate - there is no secret to leak
    /// through timing.
    #[must_use]
    pub fn matches(&self, commitment: &str) -> bool {
        self.commitment().eq_ignore_ascii_case(commitment)
    }
}

fn write_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u64).to_le_bytes());
    h.update(field);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn rec(members: Vec<&str>) -> OwnershipRecord {
        OwnershipRecord::new(
            "team:payments",
            7,
            members.into_iter().map(String::from).collect(),
            "0123456789abcdef0123",
        )
        .unwrap()
    }

    #[test]
    fn commitment_is_order_independent() {
        // The store's return order must not change the commitment, or a record
        // that is genuinely the right one fails to verify for a cosmetic reason.
        assert_eq!(
            rec(vec!["alice", "bob"]).commitment(),
            rec(vec!["bob", "alice"]).commitment()
        );
    }

    #[test]
    fn commitment_changes_with_membership() {
        assert_ne!(
            rec(vec!["alice", "bob"]).commitment(),
            rec(vec!["alice", "carol"]).commitment()
        );
        assert_ne!(
            rec(vec!["alice"]).commitment(),
            rec(vec!["alice", "bob"]).commitment()
        );
    }

    #[test]
    fn commitment_changes_with_version_and_party() {
        let base = rec(vec!["alice"]);
        let later = OwnershipRecord::new(
            "team:payments",
            8,
            vec!["alice".into()],
            "0123456789abcdef0123",
        )
        .unwrap();
        assert_ne!(base.commitment(), later.commitment(), "version is unbound");

        let other = OwnershipRecord::new(
            "team:other",
            7,
            vec!["alice".into()],
            "0123456789abcdef0123",
        )
        .unwrap();
        assert_ne!(base.commitment(), other.commitment(), "party is unbound");
    }

    #[test]
    fn the_salt_binds_the_commitment() {
        // Without this, a commitment over a small membership list can be
        // brute-forced from a candidate list - the commitment would leak exactly
        // the personal data it exists to keep out of the credential.
        let a = rec(vec!["alice"]);
        let b = OwnershipRecord::new(
            "team:payments",
            7,
            vec!["alice".into()],
            "fedcba9876543210fedc",
        )
        .unwrap();
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn a_short_salt_is_refused() {
        assert!(OwnershipRecord::new("team:x", 1, vec![], "tooshort").is_err());
    }

    #[test]
    fn an_unnamed_party_is_refused() {
        assert!(OwnershipRecord::new("  ", 1, vec![], "0123456789abcdef0123").is_err());
    }

    #[test]
    fn matches_accepts_its_own_commitment_and_rejects_a_different_record() {
        let r = rec(vec!["alice", "bob"]);
        let c = r.commitment();
        assert!(r.matches(&c));
        assert!(r.matches(&c.to_uppercase()), "hex case must not matter");
        assert!(!rec(vec!["alice"]).matches(&c));
    }

    #[test]
    fn duplicate_members_do_not_change_the_commitment() {
        assert_eq!(
            rec(vec!["alice", "bob"]).commitment(),
            rec(vec!["alice", "bob", "alice"]).commitment()
        );
    }

    /// The read side of a record: an auditor resolving an accountable party asks for the
    /// version to fetch the right revision, and the members to answer "which humans".
    ///
    /// These accessors had no caller anywhere in the crate. They are not dead - they are
    /// how a host reads a record it has produced - so they are exercised rather than
    /// removed, and the sorting/de-duplication contract is pinned here because the
    /// commitment depends on it.
    #[test]
    fn the_accessors_expose_the_normalized_record() {
        let r = OwnershipRecord::new(
            "team:payments",
            7,
            vec![
                "carol@acme.example".into(),
                "alice@acme.example".into(),
                "alice@acme.example".into(),
            ],
            "0123456789abcdef0123",
        )
        .unwrap();

        assert_eq!(r.party_id(), "team:payments");
        assert_eq!(r.version(), 7);
        assert_eq!(
            r.members(),
            ["alice@acme.example", "carol@acme.example"],
            "members are sorted and de-duplicated, which is what makes the commitment              independent of the order the store returned them in"
        );
        // The accessor view and the committed view agree.
        assert!(r.matches(&r.commitment()));
    }
}
