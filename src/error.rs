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
    /// Authentication failure (OTP / session) — the TS `AuthError`.
    #[error("{0}")]
    Auth(String),
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

    pub fn auth(message: impl Into<String>) -> Self {
        Error::Auth(message.into())
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
