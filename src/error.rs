//! Crate-wide error type. Contract violations carry human-readable messages —
//! the TS oracle threw `Error(message)` and its tests assert on message
//! substrings, so the Rust port keeps messages as the stable surface. Auth
//! failures are a distinct variant (the TS `AuthError` subclass).

/// Server-controlled identity for an operation refused by deployment freeze.
/// Dynamic registered names are constructed only inside the engine; hosted
/// adapters can name their own fixed operations with [`Self::server`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentReadOnlyOperation(String);

impl DeploymentReadOnlyOperation {
    pub fn server(operation: &'static str) -> Self {
        Self(operation.to_string())
    }

    pub(crate) fn registered(operation: impl Into<String>) -> Self {
        Self(operation.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The stable code string for a member-copy write refusal (§6.2). Unchanged
/// from the pre-typed engine string so existing callers keep matching.
pub const STANDBY_READ_ONLY_CODE: &str = "STANDBY_READ_ONLY";

/// Engine error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A contract/engine rule was violated (projector guards, meta-tier guards,
    /// hosting lifecycle errors). The message is the contract surface.
    #[error("{0}")]
    Engine(String),
    /// An optimistic concurrency precondition did not match current state.
    /// Kept distinct from `Engine` so hosted callers can reliably classify a
    /// stale write (HTTP 409) without parsing the human-readable message.
    #[error("{0}")]
    Conflict(String),
    /// A read could not be served because this replica does not hold what was
    /// asked for — "not held here", which is a different fact from "absent"
    /// (`docs/honest-absence-contract.md`).
    ///
    /// Its own variant for the same reason `Conflict` is: a caller must be
    /// able to classify it without parsing a human-readable message. That is
    /// the whole contract. An agent that cannot tell this from "does not
    /// exist" writes the duplicate record, and a client that normalises the
    /// two before the agent sees them reintroduces the failure on the
    /// agent's behalf.
    ///
    /// Unlike every other error here, it is **not** retryable where it was
    /// raised: the answer exists at the authority, and this replica will
    /// return the same thing forever.
    #[error("{0}")]
    NotHeld(String),
    /// Authentication failure (OTP / session) — the TS `AuthError`.
    #[error("{0}")]
    Auth(String),
    /// A read cannot be answered from a current-state member copy: the
    /// surface, argument, relation or column is not held offline (contract
    /// c323277 rev 7 §2.2, §2.3). Typed so a caller can tell "not in the
    /// offline copy" from "not allowed"; `requirement` names the missing
    /// input. It never carries a record id or a workspace counter.
    #[error("unavailable_offline: {surface}")]
    UnavailableOffline {
        surface: String,
        requirement: String,
    },
    /// The member copy's credential expired but was not revoked; the device
    /// locked it on the §4.3 reconnect answer (§6.1). It carries no reason
    /// beyond itself and is cleared only by signing in.
    #[error("copy_locked")]
    CopyLocked { retry: &'static str },
    /// The member copy is not usable and no closer reason is member-facing
    /// (§2.2): a pending cleanup barrier, or a copy that is not ready. No
    /// reason travels; local diagnostics hold it.
    #[error("copy_unavailable")]
    CopyUnavailable,
    /// The member copy was removed for the caller's own membership/session
    /// reason (§2.2, §6); the cause is about the caller's footing, never a
    /// record.
    #[error("copy_removed")]
    CopyRemoved {
        cause: crate::member_copy_lifecycle::RemovedCause,
        deletion: crate::member_copy_lifecycle::DeletionState,
    },
    /// A write against a member copy is refused read-only (§6.2). The `code`
    /// string is unchanged (`STANDBY_READ_ONLY`), and it carries a fixed
    /// message, `retryable`, `retry` and `effect`; it never echoes arguments
    /// or a target id.
    #[error("{code}")]
    StandbyReadOnly {
        code: &'static str,
        message: &'static str,
        retryable: bool,
        retry: &'static str,
        effect: &'static str,
    },
    /// Outbound delivery failed (OTP email). Deliberately NOT `Auth`: the
    /// caller's credentials were fine and we could not send the code, so this
    /// must not read as "wrong code" to a user or to the HTTP status mapping.
    #[error("{0}")]
    Delivery(String),
    /// A server-derived mutation was refused before execution because this
    /// deployment is draining or frozen. The operation contains no caller
    /// arguments and is safe to return as structured retry guidance.
    #[error("DEPLOYMENT_READ_ONLY")]
    DeploymentReadOnly(DeploymentReadOnlyOperation),
    /// A durable write was refused because writers are paused for a deployment
    /// freeze drain, after earlier effects in the same operation may have
    /// committed. Unlike `DeploymentReadOnly` (refused before execution,
    /// `applied=false`), the outcome here is unknown: nothing may read as
    /// unapplied or safe to blindly resend.
    #[error("DEPLOYMENT_DRAINING")]
    DeploymentDraining(DeploymentReadOnlyOperation),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn engine(message: impl Into<String>) -> Self {
        Error::Engine(message.into())
    }

    pub fn not_held(message: impl Into<String>) -> Self {
        Error::NotHeld(message.into())
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Error::Auth(message.into())
    }

    /// §2.2 typed surface refusal.
    pub fn unavailable_offline(surface: impl Into<String>, requirement: impl Into<String>) -> Self {
        Error::UnavailableOffline {
            surface: surface.into(),
            requirement: requirement.into(),
        }
    }

    /// §6.1 locked copy; the only retry is signing in.
    pub fn copy_locked() -> Self {
        Error::CopyLocked {
            retry: "after_sign_in",
        }
    }

    /// §2.2 unavailable copy, no member-facing reason.
    pub fn copy_unavailable() -> Self {
        Error::CopyUnavailable
    }

    /// §2.2 removed copy carrying its own cause.
    pub fn copy_removed(
        cause: crate::member_copy_lifecycle::RemovedCause,
        deletion: crate::member_copy_lifecycle::DeletionState,
    ) -> Self {
        Error::CopyRemoved { cause, deletion }
    }

    /// §6.2 typed write refusal, code string unchanged.
    pub fn standby_read_only() -> Self {
        Error::StandbyReadOnly {
            code: STANDBY_READ_ONLY_CODE,
            message: "This workspace copy is offline and read-only. Nothing was changed.",
            retryable: true,
            retry: "when_online",
            effect: "not_applied",
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Error::Conflict(message.into())
    }

    pub fn delivery(message: impl Into<String>) -> Self {
        Error::Delivery(message.into())
    }

    pub(crate) fn deployment_read_only(operation: DeploymentReadOnlyOperation) -> Self {
        Error::DeploymentReadOnly(operation)
    }

    pub fn deployment_read_only_operation(&self) -> Option<&str> {
        match self {
            Error::DeploymentReadOnly(operation) => Some(operation.as_str()),
            _ => None,
        }
    }

    pub fn deployment_draining_operation(&self) -> Option<&str> {
        match self {
            Error::DeploymentDraining(operation) => Some(operation.as_str()),
            _ => None,
        }
    }

    /// True for SQLite lock contention (`SQLITE_BUSY` / `SQLITE_LOCKED`) — the
    /// condition `hosting::catalog::retry_while_busy` waits out.
    pub fn is_busy(&self) -> bool {
        match self {
            Error::Sqlx(sqlx::Error::Database(db)) => {
                let code = db.code();
                let code = code.as_deref().unwrap_or("");
                code == "5" || code == "6" || db.message().contains("database is locked")
            }
            _ => false,
        }
    }
}

/// The composition boundary for the extracted HTML artifact surface: its
/// message-carrying failures become engine errors verbatim, exactly what the
/// in-root modules produced via `Error::engine` before the move.
impl From<native_artifact_html::Error> for Error {
    fn from(error: native_artifact_html::Error) -> Self {
        Error::Engine(error.message().to_string())
    }
}

/// Composition boundary for the extracted query contracts. Message-carrying
/// contract/category failures remain engine errors; JSON failures retain the
/// root's transparent JSON variant.
impl From<native_query_contract::QueryError> for Error {
    fn from(error: native_query_contract::QueryError) -> Self {
        match error {
            native_query_contract::QueryError::Json(error) => Error::Json(error),
            error => Error::Engine(error.to_string()),
        }
    }
}

/// Composition boundary for the extracted federation runtime. Its typed
/// failures retain the same root classifications exposed before extraction.
impl From<native_federation::Error> for Error {
    fn from(error: native_federation::Error) -> Self {
        match error {
            native_federation::Error::Engine(message) => Error::Engine(message),
            native_federation::Error::Auth(message) => Error::Auth(message),
            native_federation::Error::Sqlx(error) => Error::Sqlx(error),
            native_federation::Error::Json(error) => Error::Json(error),
            native_federation::Error::Io(error) => Error::Io(error),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
