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
