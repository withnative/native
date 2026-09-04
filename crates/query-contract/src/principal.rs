//! `query::principal` — the narrow identity contract for caller-filtered
//! reads.
//!
//! Query needs exactly three facts about whoever is asking: the portable
//! credential to filter rows by, whether the trusted-local read bypass
//! applies, and whether trusted ingress supplied a request-local activity-read
//! candidate. Everything else the orchestration-layer `mcp::Caller` carries
//! (run context, hosting routing, exposure policy) is deliberately not
//! representable here, so query code can never grow a dependency on it.
//!
//! `mcp::Caller` converts INTO this type at call boundaries (the `From`
//! impls live next to `Caller`); query never imports `mcp`.

/// Narrow, query-owned identity facts for caller-filtered reads.
///
/// Public construction can never enable the trusted-local bypass — this
/// mirrors the `Caller` invariant that public credential construction must
/// never be able to enable `trusted_local` (src/mcp/registry.rs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRosterMember {
    account_id: String,
    member_ref: String,
}

impl ActivityRosterMember {
    /// Construct one member from a host-verified, current workspace roster.
    ///
    /// # Safety
    ///
    /// `account_id` must be the portable account resolved for a member in the
    /// same current catalog snapshot that authorized the hosted caller, and
    /// `member_ref` must be a workspace-local opaque reference derived by the
    /// trusted host. Neither value may originate in query arguments.
    #[doc(hidden)]
    pub unsafe fn verified_unchecked(
        account_id: impl Into<String>,
        member_ref: impl Into<String>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            member_ref: member_ref.into(),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn member_ref(&self) -> &str {
        &self.member_ref
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryPrincipal {
    credential: String,
    trusted_local_bypass: bool,
    activity_read: bool,
    activity_roster: Vec<ActivityRosterMember>,
}

impl QueryPrincipal {
    /// An authenticated caller. Never carries the trusted-local bypass.
    pub fn authenticated(credential: impl Into<String>) -> Self {
        QueryPrincipal {
            credential: credential.into(),
            trusted_local_bypass: false,
            activity_read: false,
            activity_roster: Vec::new(),
        }
    }

    /// Construct a principal carrying the trusted-local authorization bypass.
    ///
    /// # Safety
    ///
    /// The caller must have established both that the source caller is trusted
    /// local and that no hosting database route is present. The root crate's
    /// `From<&mcp::Caller>` conversion is the sole production call site.
    #[doc(hidden)]
    pub unsafe fn trusted_local_unchecked(credential: impl Into<String>) -> Self {
        QueryPrincipal {
            credential: credential.into(),
            trusted_local_bypass: true,
            activity_read: true,
            activity_roster: Vec::new(),
        }
    }

    /// Construct a transport-authorized activity-reader candidate.
    ///
    /// # Safety
    ///
    /// The caller must be derived from trusted ingress, and `activity_roster`
    /// must be the current catalog roster captured with that caller's active
    /// membership proof. The standalone operator uses the separate
    /// trusted-local constructor. Agent-authored query arguments can never
    /// supply either this bit or these rows.
    #[doc(hidden)]
    pub unsafe fn activity_reader_unchecked(
        credential: impl Into<String>,
        activity_roster: Vec<ActivityRosterMember>,
    ) -> Self {
        QueryPrincipal {
            credential: credential.into(),
            trusted_local_bypass: false,
            activity_read: true,
            activity_roster,
        }
    }

    /// The portable credential rows are filtered by.
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// Whether caller filtering is bypassed for a trusted local reader.
    pub fn trusted_local_bypass(&self) -> bool {
        self.trusted_local_bypass
    }

    pub fn activity_read(&self) -> bool {
        self.activity_read
    }

    pub fn activity_roster(&self) -> &[ActivityRosterMember] {
        &self.activity_roster
    }
}

impl From<&QueryPrincipal> for QueryPrincipal {
    fn from(principal: &QueryPrincipal) -> Self {
        principal.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_never_carries_the_bypass() {
        let principal = QueryPrincipal::authenticated("alice");
        assert_eq!(principal.credential(), "alice");
        assert!(!principal.trusted_local_bypass());
        assert!(!principal.activity_read());
    }

    #[test]
    fn trusted_local_carries_the_bypass() {
        // SAFETY: this member test exercises the explicitly privileged
        // constructor without presenting it as a safe downstream path.
        let principal = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        assert_eq!(principal.credential(), "local");
        assert!(principal.trusted_local_bypass());
        assert!(principal.activity_read());
    }
}
