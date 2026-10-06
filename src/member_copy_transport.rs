//! Core member-copy transport interface (D2; contract c323277 rev 10 §1.3,
//! §7.1; consumer da0a471). This module is the *interface only*: the typed
//! request, the typed answer, bounded chunk windows, and the sealed
//! authenticated attempt context. It performs no HTTP and names no hosted
//! crate, so the dependency direction stays `held -> core`.
//!
//! Provenance: [`MemberCopyContext`], [`CredentialSelection`] and the answer
//! are sealed (private fields, `pub(crate)` constructors used only by the
//! adapter/driver). No config, caller string or on-disk manifest can construct
//! one, so a claimed identity always originates from a typed authenticated
//! attempt. This is **provenance plumbing, not cryptographic authentication**:
//! the real adapter binds the account/scope to the exact same answer and
//! credential selection; no in-process token is itself an authentication proof.

use std::fmt;

use futures::future::BoxFuture;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::member_copy_lifecycle::RevokedCause;
use crate::replica_generation::ReplicaGenerationManifest;
use crate::standby_snapshot::StandbyConsumerIdentity;

/// The hosted member-copy API the wire responses must name. The HTTP adapter
/// rejects a response that does not carry it.
pub const MEMBER_COPY_API: &str = "native.member-copy.v1";

/// The one request body the transport sends to `POST .../member-copy`.
/// `installed_*` are device *hints* only: the server decides the answer, and
/// neither field can set the device's expected scope. `db_id` is the hosted
/// route database id (the exact route), not the manifest's canonical origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberCopyRequest {
    pub db_id: String,
    pub consumer: StandbyConsumerIdentity,
    pub installed_generation_id: Option<String>,
    pub installed_scope_ref: Option<String>,
}

/// The typed answer to a member-copy request. `Replace::scope_changed` is a
/// hint; the authenticated scope travels in the attempt context, never the
/// flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberCopyAnswer {
    Current {
        generation_id: String,
        scope_ref: String,
        ordinal: i64,
        content_digest: String,
        download_handle: String,
        manifest: ReplicaGenerationManifest,
    },
    Replace {
        generation_id: String,
        scope_ref: String,
        scope_changed: bool,
        ordinal: i64,
        content_digest: String,
        download_handle: String,
        manifest: ReplicaGenerationManifest,
    },
    Revoked {
        cause: RevokedCause,
    },
    Locked,
    /// A catalog footing change between C1 and C2: the cut was discarded and
    /// the client must request again.
    Restart,
}

/// One bounded byte window from the pinned generation. `sha256` is the
/// **whole-file** SHA-256 (the wire `ETag`), not the window's; `start`/`end`
/// are the *actual* window the server served, so the driver advances from
/// them rather than from the size it requested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberCopyChunk {
    Bytes {
        bytes: Vec<u8>,
        start: u64,
        end: u64,
        total_size: u64,
        sha256: String,
    },
    Refused(MemberCopyDownloadRefusal),
}

/// A typed refusal on the bytes route. `Expired` is the uniform
/// foreign/unknown/cross-route not-found; `Revoked` preserves the caller's
/// own copy-level cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberCopyDownloadRefusal {
    Restart,
    Expired,
    Revoked { cause: RevokedCause },
    Locked,
}

/// Opaque credential selection: the retained bearer bytes for one attempt.
/// Private and zeroized; **no `Debug`, no `Serialize`**, and no public
/// constructor. Only the SHA-256 fingerprint is ever persisted. The adapter
/// reads it once (via the guarded reader) and the driver passes the same
/// selection to the POST and every chunk GET.
#[derive(Clone)]
pub struct CredentialSelection {
    secret: Zeroizing<Vec<u8>>,
}

impl CredentialSelection {
    /// Adapter/driver only: wrap Already-guarded credential bytes.
    pub(crate) fn from_bearer(secret: Zeroizing<Vec<u8>>) -> Self {
        Self { secret }
    }

    /// SHA-256 hex of the bearer. This is the only value that may be persisted
    /// or logged.
    pub fn fingerprint_sha256(&self) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&self.secret))
    }

    /// Adapter only: the raw bearer for the wire request.
    pub(crate) fn bearer(&self) -> &[u8] {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn for_test(secret: &[u8]) -> Self {
        Self {
            secret: Zeroizing::new(secret.to_vec()),
        }
    }
}

/// Sealed same-fence authenticated context for one successful `Current`/
/// `Replace`. Private fields and a `pub(crate)` constructor used only by the
/// adapter, so no caller/config/manifest string can forge an identity. Carries
/// the retained credential selection so every chunk uses the same credential.
/// `Clone` is allowed (needed to retain it across the boxed future) and leaks
/// nothing: no `Debug`/`Serialize`.
#[derive(Clone)]
pub struct MemberCopyContext {
    account_binding: String,
    server_origin: String,
    route_database_id: String,
    origin_database_id: String,
    consumer: StandbyConsumerIdentity,
    scope_ref: String,
    selection: CredentialSelection,
}

impl MemberCopyContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        account_binding: String,
        server_origin: String,
        route_database_id: String,
        origin_database_id: String,
        consumer: StandbyConsumerIdentity,
        scope_ref: String,
        selection: CredentialSelection,
    ) -> Self {
        Self {
            account_binding,
            server_origin,
            route_database_id,
            origin_database_id,
            consumer,
            scope_ref,
            selection,
        }
    }

    pub fn account_binding(&self) -> &str {
        &self.account_binding
    }
    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }
    pub fn route_database_id(&self) -> &str {
        &self.route_database_id
    }
    /// The portable `ndb_...` origin, from the authenticated manifest JSON —
    /// never the route UUID and never the downloaded candidate SQLite.
    pub fn origin_database_id(&self) -> &str {
        &self.origin_database_id
    }
    pub fn scope_ref(&self) -> &str {
        &self.scope_ref
    }
    pub fn consumer(&self) -> &StandbyConsumerIdentity {
        &self.consumer
    }
    pub fn selection_fingerprint_sha256(&self) -> String {
        self.selection.fingerprint_sha256()
    }
    pub(crate) fn selection(&self) -> &CredentialSelection {
        &self.selection
    }

    #[cfg(test)]
    pub(crate) fn for_test(account: &str, origin: &str, scope: &str) -> Self {
        Self::new(
            account.to_owned(),
            String::new(),
            String::new(),
            origin.to_owned(),
            test_consumer(),
            scope.to_owned(),
            CredentialSelection::for_test(b"test-bearer"),
        )
    }
}

#[cfg(test)]
pub(crate) fn test_consumer() -> StandbyConsumerIdentity {
    StandbyConsumerIdentity {
        contract: crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT.to_owned(),
        version: 1,
        platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
        source_sha: "a".repeat(40),
        artifact_sha256: "b".repeat(64),
        engine_schema_version: 1,
        ddl_sha256: "c".repeat(64),
    }
}

/// One successful authenticated call. `context` is `Some` only for
/// `Current`/`Replace`, derived from the SAME fence/C1/C2 evaluation that
/// produced `answer`.
pub struct MemberCopyAttempt {
    pub answer: MemberCopyAnswer,
    pub context: Option<MemberCopyContext>,
}

/// Manual, redacted `Debug`: the attempt must never render the retained
/// bearer through a derived context debug.
impl fmt::Debug for MemberCopyAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberCopyAttempt")
            .field("answer", &self.answer)
            .field("context", &self.context.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The transport boundary. Object-safe: both methods return a boxed future, so
/// `Arc<dyn MemberCopyTransport>` is `Send + Sync` for the multi-threaded
/// composition root and for tests that inject a mock. Implementations must
/// authenticate every request; a malformed or unexpected status is a typed
/// `Err`, never an empty success.
pub trait MemberCopyTransport: Send + Sync {
    /// `selection` is the driver-owned, once-per-attempt guarded credential.
    /// The client consumes it and returns the same-answer context.
    fn request(
        &self,
        request: MemberCopyRequest,
        selection: &CredentialSelection,
    ) -> BoxFuture<'_, Result<MemberCopyAttempt>>;

    /// Every chunk reuses the retained selection from the attempt context.
    fn read_range(
        &self,
        context: &MemberCopyContext,
        handle: &str,
        start: u64,
        end: u64,
    ) -> BoxFuture<'_, Result<MemberCopyChunk>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_fingerprint_is_stable_and_not_the_bearer() {
        let selection = CredentialSelection::for_test(b"secret-bearer");
        let fingerprint = selection.fingerprint_sha256();
        assert_eq!(fingerprint.len(), 64);
        assert_eq!(selection.fingerprint_sha256(), fingerprint);
        assert!(!fingerprint.contains("secret"));
    }

    #[test]
    fn attempt_debug_never_renders_the_bearer() {
        let context = MemberCopyContext::for_test("acct", "ndb_0", "scope-a");
        let attempt = MemberCopyAttempt {
            answer: MemberCopyAnswer::Restart,
            context: Some(context),
        };
        let debug = format!("{attempt:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("test-bearer"));
    }
}
