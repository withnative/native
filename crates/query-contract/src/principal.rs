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

use std::sync::Arc;

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

/// One immutable `catalog_operations` row, projected by the serving
/// executor from its effective (callable) contracts. The executor owns the
/// projection; query only materializes the snapshot it is handed. `access`
/// is the stable lowercase operation access (`read`/`mutation`); the
/// booleans project to `0`/`1` INTEGER columns. `advertised_directly` is 0
/// only on a lean executor surface, for an operation reachable through
/// `call_executor` but not advertised as its own tool operation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogOperationRow {
    pub executor: String,
    pub operation: String,
    pub surface: String,
    pub access: String,
    pub plan_required: bool,
    pub direct_execution_enabled: bool,
    pub contract_version: String,
    pub contract_digest: String,
    pub source_tool: String,
    pub selector_field: Option<String>,
    pub selector_value: Option<String>,
    pub advertised_directly: bool,
}

/// Immutable per-execution serving catalogue for `catalog_operations`.
/// Shared by `Arc` so attaching it to a principal stays one pointer per
/// copy; rows are fixed at projection and never mutated afterwards.
pub type CatalogOperationsSnapshot = Arc<Vec<CatalogOperationRow>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryPrincipal {
    credential: String,
    trusted_local_bypass: bool,
    activity_read: bool,
    activity_roster: Vec<ActivityRosterMember>,
    /// Live catalog membership footing. Guests resolve without the
    /// `native:members` baseline in every visibility relation built from
    /// this principal. Required (rather than defaulted) so a construction
    /// that forgets the footing fails to compile.
    is_member: bool,
    /// Serving executor catalogue for `catalog_operations`. `None` on every
    /// public constructor: only the in-process executor may attach it, and
    /// only for the ad-hoc online SQLite `query_sql` path (serving standby
    /// included). Saved SQL, alpha-tab needs, member/offline copies and
    /// direct API executions carry `None` and refuse the relation instead
    /// of inventing rows.
    catalog_operations: Option<CatalogOperationsSnapshot>,
}

impl QueryPrincipal {
    /// An authenticated caller. Never carries the trusted-local bypass.
    /// `is_member` is the caller's folded catalog footing.
    pub fn authenticated(credential: impl Into<String>, is_member: bool) -> Self {
        QueryPrincipal {
            credential: credential.into(),
            trusted_local_bypass: false,
            activity_read: false,
            activity_roster: Vec::new(),
            is_member,
            catalog_operations: None,
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
            // Moot under the bypass, which admits everything below; member
            // footing keeps every other reader uniform.
            is_member: true,
            catalog_operations: None,
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
    ///
    /// `is_member` is the same snapshot's role fact: guests keep roster
    /// presence (attribution) without the members baseline. Required so a
    /// hosted construction that forgets the footing fails to compile.
    #[doc(hidden)]
    pub unsafe fn activity_reader_unchecked(
        credential: impl Into<String>,
        activity_roster: Vec<ActivityRosterMember>,
        is_member: bool,
    ) -> Self {
        QueryPrincipal {
            credential: credential.into(),
            trusted_local_bypass: false,
            activity_read: true,
            activity_roster,
            is_member,
            catalog_operations: None,
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

    /// Live catalog membership footing for the members-baseline relations.
    pub fn is_member(&self) -> bool {
        self.is_member
    }

    /// Serving executor catalogue for `catalog_operations`, if the
    /// in-process executor attached one for this execution.
    pub fn catalog_operations(&self) -> Option<&CatalogOperationsSnapshot> {
        self.catalog_operations.as_ref()
    }

    /// Attach the serving executor's projected catalogue snapshot.
    ///
    /// Trusted seam only: the in-process executor projects this from its
    /// effective (advertised) contracts immediately before delegation, for
    /// the ad-hoc online SQLite `query_sql` path alone. Tool arguments have
    /// no representation for it; every other construction carries `None`.
    #[doc(hidden)]
    pub fn with_catalog_operations_snapshot(mut self, snapshot: CatalogOperationsSnapshot) -> Self {
        self.catalog_operations = Some(snapshot);
        self
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
        let principal = QueryPrincipal::authenticated("alice", true);
        assert_eq!(principal.credential(), "alice");
        assert!(!principal.trusted_local_bypass());
        assert!(!principal.activity_read());
        assert!(principal.is_member());
    }

    #[test]
    fn guest_footing_is_explicit() {
        let guest = QueryPrincipal::authenticated("guest", false);
        assert!(!guest.is_member());
        assert!(!guest.trusted_local_bypass());
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
