//! Transport-neutral failures produced while selecting a hosted database or lens.
//!
//! The routing implementation remains hosted composition. These enums are the
//! small public contract its HTTP, realtime, and MCP consumers need in order
//! to preserve refusal semantics without depending on that implementation.

use crate::Error;

/// A database-selection failure that transports must preserve rather than
/// flatten into a generic engine error.
#[derive(Debug)]
pub enum DatabaseRouteError {
    /// The credential was invalid or a catalog/engine operation failed.
    Internal(Error),
    /// The requested id is unknown or is not visible to the authenticated user.
    /// These cases deliberately share one variant so transports cannot leak
    /// database existence.
    NotFound,
    /// A valid account has no membership at all, normally a failed provision.
    Unprovisioned,
    /// The caller's guest membership on this database has reached its access
    /// deadline. It is deliberately its own variant rather than an
    /// `Internal(Auth)` (a missing or expired *session*, which the guest can
    /// repair by signing in again) or `NotFound` (a workspace the caller never
    /// had): the credential is valid, the workspace exists, and the guest
    /// accesses are simply over. The workbench renders it as "your guest
    /// access has ended" rather than bouncing the visitor through sign-in.
    GuestAccessEnded,
    /// The account's recorded workspace selection is no longer usable (the
    /// membership is gone, the workspace is not ready, or offboarding is in
    /// flight). Legacy unscoped routing refuses rather than silently landing
    /// the caller in a different workspace; the id names the stale selection
    /// so the caller can re-select. It is the caller's own selection, so
    /// naming it leaks nothing about other workspaces.
    SelectedUnavailable { db_id: String },
    /// Routing cannot choose among multiple memberships.
    ///
    /// No longer produced by the legacy newest-membership resolver. The
    /// variant and its message remain the right answer for a route that must
    /// refuse rather than guess, and for an explicit per-account default.
    Ambiguous,
}

/// A lens-selection failure with deliberately content-free scope refusal.
#[derive(Debug)]
pub enum LensRouteError {
    /// The credential was invalid or a catalog/engine operation failed.
    Internal(Error),
    /// Unknown and not-owned lens ids deliberately collapse.
    NotFound,
    /// A constituent is missing, not ready, or no longer authorized. The
    /// variant deliberately carries no source detail.
    ScopeUnavailable,
}

impl From<Error> for LensRouteError {
    fn from(error: Error) -> Self {
        Self::Internal(error)
    }
}

impl From<Error> for DatabaseRouteError {
    fn from(error: Error) -> Self {
        Self::Internal(error)
    }
}
