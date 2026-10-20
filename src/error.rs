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

/// Machine code for a reused idempotency key that does not match the
/// original command (different normalized arguments or resolved intent).
/// It stays an [`Error::Engine`] refusal — a 4xx that must not be retried —
/// and is deliberately not [`Error::Conflict`], which hosted callers read as
/// a stale optimistic write.
pub const IDEMPOTENCY_CONFLICT_CODE: &str = "idempotency_conflict";

/// Which bound a keyed replay ran into while rebuilding a committed write's
/// receipt. All three are about resources, never about the caller's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayBound {
    /// The historical rebuild's row or byte budget.
    Budget,
    /// No rebuild slot became free before the deadline.
    Admission,
    /// The replay did not finish inside its execution deadline.
    Deadline,
}

impl ReplayBound {
    fn describe(self) -> &'static str {
        match self {
            Self::Budget => "historical replay budget exceeded",
            Self::Admission => "historical replay admission exhausted",
            Self::Deadline => "historical replay deadline exceeded",
        }
    }
}

/// How much of a keyed call a [`Error::ReplayBounded`] failure confirms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayApplied {
    /// The call is one write, and the key matched it: it committed.
    Committed,
    /// A multi-write call (`create_many`) stopped at an item whose replay hit a
    /// bound. `completed` of `total` items are confirmed committed: those that
    /// succeeded before it, plus the item that hit the bound (it committed;
    /// only its receipt was late). That is a count, not a prefix: an item that
    /// failed or depended on a failure earlier in the call is not in it, and
    /// the items after the bound were never reached and may not exist. A retry
    /// with the same key and arguments resumes, and creates each remaining
    /// item exactly once.
    Partial { completed: usize, total: usize },
}

/// Stable machine code for [`Error::ReplayBounded`] on the wire.
pub const REPLAY_BOUND_EXCEEDED_CODE: &str = "REPLAY_BOUND_EXCEEDED";

/// Guidance carried with [`REPLAY_BOUND_EXCEEDED_CODE`] for a single write.
pub const REPLAY_BOUND_EXCEEDED_RECOVERY: &str = "The write behind this idempotency key was committed; only its receipt could not be rebuilt within the replay bound. Retry with the same idempotency_key, or read the record for its current state. Do not issue a fresh write under a new key.";

/// Guidance for a [`ReplayApplied::Partial`] failure.
pub const REPLAY_BOUND_EXCEEDED_PARTIAL_RECOVERY: &str = "Part of this call is committed (completed_items of total_items items are confirmed committed, not necessarily the first ones) and its replay hit a bound before the rest were reached. Retry with the same idempotency_key and the same arguments: committed items replay and each remaining item is created exactly once. Do not issue the call again under a new key.";

/// Static admission stage selected at the refusal site, never from database prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StandbyAdmissionCheck {
    RouteOrigin,
    Consumer,
    ByteIdentity,
    EngineShape,
    ManifestState,
    ActOrderContinuity,
    /// The local current generation could not be read or trusted as a base
    /// (pointer, head, shape or manifest), whatever the candidate looks like.
    CurrentGeneration,
    ScalarRollbackContinuity,
    SuccessorPreservation,
    Integrity,
    Conformance,
    Awareness,
}
impl StandbyAdmissionCheck {
    pub fn token(self) -> &'static str {
        match self {
            Self::RouteOrigin => "install-fence:route-origin",
            Self::Consumer => "install-fence:consumer",
            Self::ByteIdentity => "install-fence:byte-identity",
            Self::EngineShape => "install-fence:engine-shape",
            Self::ManifestState => "install-fence:manifest-state",
            Self::ActOrderContinuity => "install-fence:act-order-continuity",
            Self::CurrentGeneration => "install-fence:current-generation",
            Self::ScalarRollbackContinuity => "install-fence:scalar-rollback-continuity",
            Self::SuccessorPreservation => "install-fence:successor",
            Self::Integrity => "install-fence:integrity",
            Self::Conformance => "install-fence:conformance",
            Self::Awareness => "install-fence:awareness",
        }
    }
}

/// Engine error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Preserve the internal source and its historical Display surface, with
    /// a separate static admission stage for payload-free refresh diagnostics.
    #[error("{source}")]
    StandbyAdmission {
        check: StandbyAdmissionCheck,
        #[source]
        source: Box<Error>,
    },

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
    /// A keyed replay found the original write and could not rebuild its
    /// receipt inside a resource bound (see [`ReplayBound`]). The write
    /// committed; only the answer is missing. It is a retryable
    /// outcome-known-to-be-applied failure, so hosted transports answer it
    /// 503 (never a 4xx refusal) and a retry with the same key is safe.
    #[error("{tool}: {bound}", bound = .bound.describe())]
    ReplayBounded {
        tool: String,
        bound: ReplayBound,
        applied: ReplayApplied,
    },
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn at_standby_check(self, check: StandbyAdmissionCheck) -> Self {
        // The deepest annotated refusal owns the diagnostic.
        if matches!(self, Self::StandbyAdmission { .. }) {
            self
        } else {
            Self::StandbyAdmission {
                check,
                source: Box::new(self),
            }
        }
    }

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

    /// A keyed replay hit `bound` rebuilding `tool`'s committed receipt.
    pub fn replay_bounded(tool: impl Into<String>, bound: ReplayBound) -> Self {
        Error::ReplayBounded {
            tool: tool.into(),
            bound,
            applied: ReplayApplied::Committed,
        }
    }

    /// Re-state a [`Error::ReplayBounded`] from a multi-write call as partial:
    /// `completed` of `total` items are confirmed. Any other error is returned
    /// unchanged.
    pub fn into_partial_replay(self, completed: usize, total: usize) -> Self {
        match self {
            Error::ReplayBounded { tool, bound, .. } => Error::ReplayBounded {
                tool,
                bound,
                applied: ReplayApplied::Partial { completed, total },
            },
            other => other,
        }
    }

    /// The wire fields of a [`Error::ReplayBounded`], shared by every
    /// transport: `error_code`, `applied` (`true`, or `"partial"` with
    /// `completed_items` / `total_items`), `retryable: true` and `recovery`.
    pub fn replay_bounded_fields(&self) -> Option<serde_json::Map<String, serde_json::Value>> {
        let Error::ReplayBounded { applied, .. } = self else {
            return None;
        };
        let mut fields = serde_json::Map::new();
        fields.insert("error_code".into(), REPLAY_BOUND_EXCEEDED_CODE.into());
        match applied {
            ReplayApplied::Committed => {
                fields.insert("applied".into(), true.into());
                fields.insert("recovery".into(), REPLAY_BOUND_EXCEEDED_RECOVERY.into());
            }
            ReplayApplied::Partial { completed, total } => {
                fields.insert("applied".into(), "partial".into());
                fields.insert("completed_items".into(), (*completed).into());
                fields.insert("total_items".into(), (*total).into());
                fields.insert(
                    "recovery".into(),
                    REPLAY_BOUND_EXCEEDED_PARTIAL_RECOVERY.into(),
                );
            }
        }
        fields.insert("retryable".into(), true.into());
        Some(fields)
    }

    /// True for [`Error::ReplayBounded`].
    pub fn is_replay_bounded(&self) -> bool {
        matches!(self, Error::ReplayBounded { .. })
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

    /// True for the shared provenance-key conflict refusals. The message
    /// texts are the long-standing contract, so the code is derived from them
    /// rather than carried in a new variant; a tool may prefix its own name.
    pub fn is_idempotency_conflict(&self) -> bool {
        match self {
            Error::Engine(message) => {
                message.ends_with(crate::provenance::IDEMPOTENCY_CONFLICTING_INPUT)
                    || message.ends_with(crate::provenance::IDEMPOTENCY_DIFFERENT_INTENT)
            }
            _ => false,
        }
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
