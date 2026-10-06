//! Dynamic member-copy stdio session (D2 session increment; contract c323277
//! REV10 §2.2, §2.3, §6.1, §6.2; design 7786219).
//!
//! A member copy is not the owner standby: its snapshot changes as generations
//! are admitted, replaced and purged, so [`super::stdio::StdioServer`]'s fixed
//! registry/engine/caller cannot serve it. This transport keeps one atomic
//! cell pairing a member-facing [`CopyStatus`] with the exact
//! `Arc<ToolRegistry>` + admitted `Db` + authenticated `Caller` currently
//! served.
//!
//! ## The one lock rule
//!
//! Each message is captured **briefly** (the cell's `std::sync::Mutex` is held
//! only long enough to clone the Arc/Db/Caller), then released **before** any
//! `await`. The owner's `quiesce()` (`deactivate` + `drain`) can therefore
//! always make progress, and no controller/snapshot lock is ever held across a
//! handler. The generation's installed member-copy gate — not this transport
//! — refuses a captured-but-retired snapshot at `begin_read`.
//!
//! ## No held snapshot
//!
//! With no captured snapshot the transport answers a **database-less** member
//! refusal. It never manufactures an empty SQLite `Db`, never reuses the
//! standby `STANDBY_STATUS_ONLY` contract, and never invents an account. Reads
//! answer the typed R6 copy-state error (`copy_unavailable` / `copy_locked` /
//! `copy_removed{cause,deletion}`); writes answer typed `STANDBY_READ_ONLY`.
//! `CopyStatus` carries no local `UnavailableReason` or counters, so none can
//! leak.

use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::error::{Error, Result};
use crate::mcp::member_scope::MemberScope;
use crate::member_copy_lifecycle::CopyStatus;

use super::protocol;
use super::registry::{Caller, EngineHandle, ToolRegistry};
use super::stdio::dispatch_engine_message;

/// The exact served triple plus the admitted generation it belongs to.
///
/// Every field is the admitted one; nothing is recomputed at dispatch time.
/// Fields are private so an ungated canonical `Db` cannot be paired by
/// accident: the only production constructor is [`Self::from_serving`], which
/// derives the gate from the actual owner.
#[derive(Clone)]
pub struct MemberServedSnapshot {
    registry: Arc<ToolRegistry>,
    database: crate::db::Db,
    caller: Caller,
    generation_id: String,
}

impl MemberServedSnapshot {
    /// Build the exact served snapshot from the serialized owner and a freshly
    /// built, gate-less member registry. Refuses an owner that is not serving.
    ///
    /// `owner.install_into` installs the generation-bound member-copy gate
    /// (handle + bound account), so the returned snapshot is gated and a
    /// substituted caller cannot reach storage. The caller is the
    /// authenticated account with the MCP channel, matching the ordinary stdio
    /// caller.
    pub fn from_serving(
        owner: &crate::member_copy_serving::MemberCopyServing,
        mut registry: ToolRegistry,
    ) -> Result<Self> {
        if !owner.is_serving() {
            return Err(Error::copy_unavailable());
        }
        let database = owner.database().ok_or_else(Error::copy_unavailable)?;
        let account_token = owner.account_token().ok_or_else(Error::copy_unavailable)?;
        let generation_id = owner
            .generation_id()
            .map(str::to_owned)
            .ok_or_else(Error::copy_unavailable)?;
        if !owner.install_into(&mut registry) {
            return Err(Error::copy_unavailable());
        }
        Ok(Self {
            registry: Arc::new(registry),
            database,
            caller: Caller::authenticated(account_token)
                .with_channel(crate::provenance::Channel::Mcp),
            generation_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        registry: Arc<ToolRegistry>,
        database: crate::db::Db,
        caller: Caller,
        generation_id: String,
    ) -> Self {
        Self {
            registry,
            database,
            caller,
            generation_id,
        }
    }

    /// The admitted generation this snapshot serves (observability only; the
    /// installed gate is the admission authority).
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Dispatch one message through the shared modern/legacy protocol, render
    /// and framing. `None` means no response goes out.
    pub async fn dispatch(&self, message: Value) -> Option<Value> {
        dispatch_engine_message(
            self.registry.clone(),
            EngineHandle::Sqlite(self.database.clone()),
            self.caller.clone(),
            message,
        )
        .await
    }
}

/// The coherent serving state: the member-facing status and the snapshot it
/// describes, never separately observable.
struct MemberSessionState {
    status: CopyStatus,
    snapshot: Option<MemberServedSnapshot>,
}

/// A member-copy MCP server whose served snapshot changes over time.
///
/// State is updated only by the trusted composition controller via
/// [`Self::publish`] / [`Self::clear`] / [`Self::set_status`], always with the
/// owner's `lifecycle_status()`, so the status and the snapshot cannot drift.
pub struct MemberStdioSession {
    surface: Arc<ToolRegistry>,
    state: Mutex<MemberSessionState>,
}

impl MemberStdioSession {
    /// A session with no held copy (`CopyStatus::Unavailable`). `surface` is
    /// the ungated member tool catalog, used only for discovery and
    /// database-less read/write classification.
    pub fn new(surface: Arc<ToolRegistry>) -> Self {
        Self {
            surface,
            state: Mutex::new(MemberSessionState {
                status: CopyStatus::Unavailable,
                snapshot: None,
            }),
        }
    }

    /// Atomically install a serving snapshot with the status that describes it.
    /// Returns the replaced snapshot, if any, so the controller can account
    /// for it; retirement/drain remains the owner's responsibility.
    pub fn publish(
        &self,
        status: CopyStatus,
        snapshot: MemberServedSnapshot,
    ) -> Option<MemberServedSnapshot> {
        let mut state = self
            .state
            .lock()
            .expect("member session lock is never poisoned");
        state.status = status;
        state.snapshot.replace(snapshot)
    }

    /// Atomically drop the serving snapshot (retiring the held copy) and set
    /// the status that describes the no-held state. Returns the dropped
    /// snapshot, if any.
    pub fn clear(&self, status: CopyStatus) -> Option<MemberServedSnapshot> {
        let mut state = self
            .state
            .lock()
            .expect("member session lock is never poisoned");
        state.status = status;
        state.snapshot.take()
    }

    /// Update the member-facing status from the owner's `lifecycle_status()`.
    /// The installed gate — not this status — is the authority that polices a
    /// held snapshot; the status only shapes the database-less refusal and
    /// discovery. A status that cannot read (`Locked`/`Removed`/`Unavailable`)
    /// clears the held snapshot so the session and the copy state cannot be
    /// observed disagreeing; `Ready`/`Refreshing` keep it. Returns the cleared
    /// snapshot, if any, for the controller to account for.
    pub fn set_status(&self, status: CopyStatus) -> Option<MemberServedSnapshot> {
        let mut state = self
            .state
            .lock()
            .expect("member session lock is never poisoned");
        state.status = status.clone();
        if status.can_read() {
            None
        } else {
            state.snapshot.take()
        }
    }

    /// The current member-facing copy status.
    pub fn status(&self) -> CopyStatus {
        self.state
            .lock()
            .expect("member session lock is never poisoned")
            .status
            .clone()
    }

    /// Whether a snapshot is currently served.
    pub fn has_snapshot(&self) -> bool {
        self.state
            .lock()
            .expect("member session lock is never poisoned")
            .snapshot
            .is_some()
    }

    /// Capture the coherent (status, snapshot) pair under a brief lock. The
    /// guard is dropped before the caller awaits.
    fn capture(&self) -> (CopyStatus, Option<MemberServedSnapshot>) {
        let state = self
            .state
            .lock()
            .expect("member session lock is never poisoned");
        (state.status.clone(), state.snapshot.clone())
    }

    /// Serve process stdin/stdout until EOF.
    pub async fn serve_stdio(&self) -> Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    /// Serve newline-delimited JSON-RPC over the supplied streams until EOF.
    pub async fn serve<R, W>(&self, mut reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => Some(protocol::error_response(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    &format!("parse error: {error}"),
                )),
            };
            if let Some(response) = response {
                let mut bytes = serde_json::to_vec(&response)?;
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }

    /// Capture the snapshot briefly, release the lock, then dispatch. With no
    /// snapshot, the shared modern/legacy handler runs unchanged except that
    /// `tools/call` answers the typed member refusal: validation, discovery,
    /// catalog and resource methods are byte-identical to the held path, so
    /// error precedence and the advertised surface never depend on held state.
    pub(crate) async fn handle_message(&self, message: Value) -> Option<Value> {
        let (status, snapshot) = self.capture();
        match snapshot {
            Some(snapshot) => snapshot.dispatch(message).await,
            None => {
                let refusal: Arc<dyn protocol::NoHeldToolCall> = Arc::new(MemberNoHeldRefusal {
                    surface: self.surface.clone(),
                    status,
                });
                let outcome = if protocol::is_modern_request(&message) {
                    protocol::handle_modern_member_message(self.surface.clone(), refusal, message)
                        .await
                } else {
                    protocol::handle_legacy_member_message(self.surface.clone(), refusal, message)
                        .await
                };
                match outcome {
                    protocol::RpcOutcome::Notification => None,
                    protocol::RpcOutcome::Response { body, .. } => Some(body),
                }
            }
        }
    }
}

/// The database-less `tools/call` classification. Known writes refuse
/// `STANDBY_READ_ONLY`; every other known tool — including a kind-less one —
/// takes the typed R6 copy-state precedence. Unknown names never reach here:
/// the shared dispatcher answers them `INVALID_PARAMS`, exactly as the held
/// path does. No canonical record or storage IO.
struct MemberNoHeldRefusal {
    surface: Arc<ToolRegistry>,
    status: CopyStatus,
}

impl protocol::NoHeldToolCall for MemberNoHeldRefusal {
    fn refuse(&self, name: &str, arguments: &Value) -> Error {
        let Some(tool) = self.surface.get(name) else {
            return Error::engine(format!("unknown tool: {name}"));
        };
        let Some(kind) = tool.kind else {
            // A kind-less known tool cannot be shown to be a write, so the R6
            // copy state takes precedence, as on the held path.
            return copy_state_error(&self.status);
        };
        let scope = kind.member_scope();
        if matches!(scope, MemberScope::WriteRefused) {
            return Error::standby_read_only();
        }
        if let Some(actions) = scope.refused_write_actions() {
            if arguments
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| actions.contains(&action))
            {
                return Error::standby_read_only();
            }
        }
        copy_state_error(&self.status)
    }
}

/// The typed R6 copy-state error for a database-less read (§6.1). `Ready` /
/// `Refreshing` with no captured snapshot is a limbo: no servable bytes, so
/// `copy_unavailable`. Local `UnavailableReason`/counters never travel.
fn copy_state_error(status: &CopyStatus) -> Error {
    match status {
        CopyStatus::Removed { cause, deletion } => Error::copy_removed(*cause, *deletion),
        CopyStatus::Locked { .. } => Error::copy_locked(),
        CopyStatus::Ready { .. } | CopyStatus::Refreshing { .. } | CopyStatus::Unavailable => {
            Error::copy_unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use serde_json::json;

    use crate::db::{open_member_database_read_only, Db};
    use crate::domain_transaction::request::{
        GovernedRequestOperation, GovernedRequestStageDisposition, GOVERNED_REQUEST_PIPELINE,
    };
    use crate::mcp::interactions::{
        AdmissionReason, CustomInteractionPolicy, ToolExposure, ToolFamily,
    };
    use crate::mcp::member_serving::{MemberCopyGate, MemberCopyLeaseGate};
    use crate::mcp::{register_builtin_tools, register_surface_tools};
    use crate::member_copy_admission::ExpectedFooting;
    use crate::member_copy_lifecycle::{MemberCopyLifecycle, ReconnectAnswer, RevokedCause};
    use crate::member_copy_producer::{build_member_copy, MemberCopyRequest};
    use crate::member_copy_serving::MemberCopyServing;
    use crate::member_copy_transport::MemberCopyContext;
    use crate::member_offline_fixtures::{two_caller, ACCT_A, ACCT_B};
    use crate::standby_snapshot::{
        StandbyConsumerIdentity, StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT,
    };

    const SCOPE_A: &str = "scope-a";
    const SCOPE_B: &str = "scope-b";
    const CUT: &str = "2026-09-30T00:00:00Z";

    const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
    const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";

    fn member_registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).expect("builtins");
        register_surface_tools(&mut registry).expect("surface");
        registry
    }

    fn member_surface() -> Arc<ToolRegistry> {
        Arc::new(member_registry())
    }

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "e".repeat(64),
        }
    }

    fn legacy_call(id: i64, name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        })
    }

    fn modern_call(id: i64, name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
                    CLIENT_CAPABILITIES_META: {},
                },
            },
        })
    }

    fn record_status(body: &Value, id: &str) -> Option<String> {
        body["result"]["structuredContent"]["records"]
            .as_array()?
            .iter()
            .find(|item| item["id"] == json!(id))
            .and_then(|item| item["status"].as_str())
            .map(str::to_owned)
    }

    fn error_code(body: &Value) -> Option<&str> {
        body["result"]["structuredContent"]["error_code"].as_str()
    }

    /// A real admitted snapshot: producer-built member file, `MemberReadOnly`
    /// `Db`, and the **actual** D1 gate bound to its handle + account through a
    /// real lease gate. The returned lease gate is what the owner retires.
    async fn snapshot_for(
        world: &Db,
        account: &str,
        scope: &str,
        dir: &Path,
    ) -> (MemberServedSnapshot, Arc<MemberCopyLeaseGate>) {
        let member_path = dir.join(format!("member-{account}.db"));
        let _copy = build_member_copy(
            world,
            MemberCopyRequest {
                member_account: account.to_owned(),
                scope_ref: scope.to_owned(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal: 1,
                consumer: consumer(),
                out_path: member_path.clone(),
            },
        )
        .await
        .expect("producer");
        let database = open_member_database_read_only(member_path.to_str().expect("path"))
            .await
            .expect("member open");

        let copy_root = dir.join(format!("life-{account}"));
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                account,
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle.mark_refreshed(CUT.to_owned()).expect("ready");

        let leases = MemberCopyLeaseGate::new(true);
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).expect("builtins");
        register_surface_tools(&mut registry).expect("surface");
        let gate = MemberCopyGate::with_leases(
            Arc::new(Mutex::new(lifecycle)),
            scope.to_owned(),
            1,
            Vec::new(),
            leases.clone(),
        )
        .with_generation_id(format!("gen-{account}"))
        .with_admission_binding(database.handle_id(), account.to_owned());
        registry.set_member_copy_gate_instance(gate);

        let snapshot = MemberServedSnapshot::for_test(
            Arc::new(registry),
            database,
            Caller::authenticated(account).with_channel(crate::provenance::Channel::Mcp),
            format!("gen-{account}"),
        );
        (snapshot, leases)
    }

    /// The production path: producer-built bytes admitted through the actual
    /// `MemberCopyServing`, paired by `MemberServedSnapshot::from_serving`. The
    /// owner is returned so it stays alive (its authority lock and lease gate).
    async fn admitted_owner(dir: &Path) -> (MemberCopyServing, MemberServedSnapshot) {
        let world = two_caller::build().await;
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(world.db.pool())
                .await
                .expect("origin");
        let staged = dir.join("staged.db");
        let copy = build_member_copy(
            &world.db,
            MemberCopyRequest {
                member_account: ACCT_A.to_owned(),
                scope_ref: SCOPE_A.to_owned(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal: 1,
                consumer: consumer(),
                out_path: staged.clone(),
            },
        )
        .await
        .expect("produce");
        let manifest_json = serde_json::to_vec(&copy.manifest).expect("manifest json");
        let root = dir.join("copy");
        let mut owner = MemberCopyServing::open(
            &root,
            ExpectedFooting {
                origin_database_id: origin.clone(),
                scope_ref: SCOPE_A.to_owned(),
                consumer: consumer(),
            },
        )
        .await
        .expect("owner");
        owner
            .sign_in(
                ACCT_A,
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .await
            .expect("sign in");
        let context = MemberCopyContext::for_test(ACCT_A, &origin, SCOPE_A);
        owner
            .admit_candidate(&staged, &manifest_json, &context)
            .await
            .expect("admit");
        let snapshot =
            MemberServedSnapshot::from_serving(&owner, member_registry()).expect("constructor");
        (owner, snapshot)
    }

    #[tokio::test]
    async fn no_held_refuses_reads_typed_and_writes_read_only_in_both_eras() {
        let session = MemberStdioSession::new(member_surface());

        let legacy_read = session
            .handle_message(legacy_call(1, "get_record", json!({ "ids": ["x"] })))
            .await
            .expect("response");
        assert_eq!(legacy_read["result"]["isError"], json!(true));
        assert_eq!(error_code(&legacy_read), Some("copy_unavailable"));

        let legacy_write = session
            .handle_message(legacy_call(
                2,
                "create_record",
                json!({ "type": "Document", "name": "n" }),
            ))
            .await
            .expect("response");
        assert_eq!(error_code(&legacy_write), Some("STANDBY_READ_ONLY"));

        let modern_read = session
            .handle_message(modern_call(3, "search", json!({ "query": "x" })))
            .await
            .expect("response");
        assert_eq!(modern_read["result"]["resultType"], json!("complete"));
        assert_eq!(error_code(&modern_read), Some("copy_unavailable"));

        let modern_write = session
            .handle_message(modern_call(
                4,
                "update_record",
                json!({ "id": "x", "body": "y" }),
            ))
            .await
            .expect("response");
        assert_eq!(error_code(&modern_write), Some("STANDBY_READ_ONLY"));

        for body in [&legacy_read, &legacy_write, &modern_read, &modern_write] {
            assert_ne!(
                error_code(body),
                Some("STANDBY_STATUS_ONLY"),
                "the member lifecycle is not standby diagnostics"
            );
        }

        // F1: modern metadata validation is the shared path, so a malformed
        // request is INVALID_PARAMS on the no-held path too — never a copy
        // refusal. `clientCapabilities` is required by the shared handler.
        let malformed = session
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "get_record",
                    "arguments": { "ids": ["x"] },
                    "_meta": { PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION },
                },
            }))
            .await
            .expect("response");
        assert_eq!(malformed["error"]["code"], json!(protocol::INVALID_PARAMS));

        // F3: modern `ping` is method-not-found, exactly as the held path.
        let modern_ping = session
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "ping",
                "params": {
                    "_meta": {
                        PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
                        CLIENT_CAPABILITIES_META: {},
                    },
                },
            }))
            .await
            .expect("response");
        assert_eq!(
            modern_ping["error"]["code"],
            json!(protocol::METHOD_NOT_FOUND)
        );

        // Unknown names keep the shared protocol's unknown-tool semantics: a
        // JSON-RPC INVALID_PARAMS error, identical to the held path, never a
        // copy refusal or a read classification.
        let unknown = session
            .handle_message(legacy_call(5, "not_a_tool", json!({})))
            .await
            .expect("response");
        assert_eq!(unknown["error"]["code"], json!(protocol::INVALID_PARAMS));
        assert!(unknown["error"]["message"]
            .as_str()
            .expect("message")
            .contains("unknown tool"));
    }

    #[tokio::test]
    async fn no_held_lists_the_member_surface_for_discovery() {
        let session = MemberStdioSession::new(member_surface());
        for message in [
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {
                    "_meta": {
                        PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
                        CLIENT_CAPABILITIES_META: {},
                    }
                }
            }),
        ] {
            let listed = session.handle_message(message).await.expect("response");
            let names: Vec<&str> = listed["result"]["tools"]
                .as_array()
                .expect("tools")
                .iter()
                .filter_map(|tool| tool["name"].as_str())
                .collect();
            assert!(names.contains(&"get_record"));
            assert!(names.contains(&"render_record"));
        }
    }

    #[tokio::test]
    async fn no_held_copy_state_keeps_its_own_cause() {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut locked = MemberCopyLifecycle::open(&dir.path().join("locked")).expect("lifecycle");
        locked
            .sign_in(
                ACCT_A,
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        locked.mark_refreshed(CUT.to_owned()).expect("ready");
        locked
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        let session = MemberStdioSession::new(member_surface());
        let _ = session.set_status(locked.status());
        let body = session
            .handle_message(legacy_call(1, "get_record", json!({ "ids": ["x"] })))
            .await
            .expect("response");
        assert_eq!(error_code(&body), Some("copy_locked"));

        let mut removed =
            MemberCopyLifecycle::open(&dir.path().join("removed")).expect("lifecycle");
        removed
            .sign_in(
                ACCT_A,
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        removed.mark_refreshed(CUT.to_owned()).expect("ready");
        removed
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::SessionRevoked,
            })
            .expect("revoked");
        let session = MemberStdioSession::new(member_surface());
        let _ = session.set_status(removed.status());
        let body = session
            .handle_message(legacy_call(2, "get_record", json!({ "ids": ["x"] })))
            .await
            .expect("response");
        assert_eq!(error_code(&body), Some("copy_removed"));
        assert_eq!(
            body["result"]["structuredContent"]["cause"],
            json!("session_revoked")
        );
    }

    #[tokio::test]
    async fn captured_old_snapshot_refuses_after_owner_retirement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let (snapshot, leases) = snapshot_for(&world.db, ACCT_A, SCOPE_A, dir.path()).await;

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot.clone(),
        );

        let served = session
            .handle_message(legacy_call(
                1,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );

        // The owner's quiesce: close the door, then drain in-flight readers.
        leases.deactivate();
        leases.drain().await;

        let refused = session
            .handle_message(legacy_call(
                2,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            error_code(&refused),
            Some("copy_unavailable"),
            "retirement refused body: {refused}"
        );
    }

    #[tokio::test]
    async fn generation_and_account_pair_swap_serve_the_admitted_slice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let (snapshot_a, leases_a) = snapshot_for(&world.db, ACCT_A, SCOPE_A, dir.path()).await;
        let (snapshot_b, _leases_b) = snapshot_for(&world.db, ACCT_B, SCOPE_B, dir.path()).await;

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot_a.clone(),
        );

        let a_own = session
            .handle_message(legacy_call(
                1,
                "get_record",
                json!({ "ids": [two_caller::A_OWNED], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&a_own, two_caller::A_OWNED).as_deref(),
            Some("found")
        );
        let a_sees_b = session
            .handle_message(legacy_call(
                2,
                "get_record",
                json!({ "ids": [two_caller::B_ONLY], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&a_sees_b, two_caller::B_ONLY).as_deref(),
            Some("not_found")
        );

        // Owner retires A (drain) then publishes B atomically.
        leases_a.deactivate();
        leases_a.drain().await;
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot_b,
        );

        // A captured before the swap is refused by its retired gate; B serves.
        let old = snapshot_a
            .dispatch(legacy_call(
                3,
                "get_record",
                json!({ "ids": [two_caller::A_OWNED], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            error_code(&old),
            Some("copy_unavailable"),
            "retired captured snapshot body: {old}"
        );

        let b_own = session
            .handle_message(legacy_call(
                4,
                "get_record",
                json!({ "ids": [two_caller::B_ONLY], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&b_own, two_caller::B_ONLY).as_deref(),
            Some("found")
        );
        let b_sees_a = session
            .handle_message(legacy_call(
                5,
                "get_record",
                json!({ "ids": [two_caller::A_OWNED], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&b_sees_a, two_caller::A_OWNED).as_deref(),
            Some("not_found")
        );
    }

    #[tokio::test]
    async fn served_snapshot_answers_modern_and_legacy_then_clear_returns_to_no_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let (snapshot, _leases) = snapshot_for(&world.db, ACCT_A, SCOPE_A, dir.path()).await;

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot,
        );

        let legacy = session
            .handle_message(legacy_call(
                1,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&legacy, two_caller::SHARED_CHILD).as_deref(),
            Some("found")
        );

        let modern = session
            .handle_message(modern_call(
                2,
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD }),
            ))
            .await
            .expect("response");
        assert_eq!(modern["result"]["resultType"], json!("complete"));
        let rendered = modern["result"]["structuredContent"]["markdown"]
            .as_str()
            .or_else(|| modern["result"]["content"][0]["text"].as_str())
            .unwrap_or_default();
        assert!(!rendered.is_empty(), "render_record must produce output");

        let dropped = session
            .clear(CopyStatus::Unavailable)
            .expect("returns the retired snapshot");
        assert_eq!(dropped.generation_id(), format!("gen-{ACCT_A}").as_str());

        let after = session
            .handle_message(legacy_call(
                3,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(error_code(&after), Some("copy_unavailable"));
    }

    /// The real admission proof: producer-built bytes are admitted through the
    /// **actual** `MemberCopyServing` owner, then
    /// `MemberServedSnapshot::from_serving` must pair the exact admitted `Db`
    /// handle + bound account (a wrong pairing is refused by the installed
    /// gate), and a captured snapshot must refuse after the owner's real
    /// `quiesce`. This discriminates the constructor and the pair binding,
    /// which the raw manual-gate fixtures cannot.
    #[tokio::test]
    async fn owner_admission_constructs_and_retires_the_served_snapshot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(world.db.pool())
                .await
                .expect("origin");

        let staged = dir.path().join("staged.db");
        let copy = build_member_copy(
            &world.db,
            MemberCopyRequest {
                member_account: ACCT_A.to_owned(),
                scope_ref: SCOPE_A.to_owned(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal: 1,
                consumer: consumer(),
                out_path: staged.clone(),
            },
        )
        .await
        .expect("produce");
        let manifest_json = serde_json::to_vec(&copy.manifest).expect("manifest json");

        let root = dir.path().join("copy");
        let mut owner = MemberCopyServing::open(
            &root,
            ExpectedFooting {
                origin_database_id: origin.clone(),
                scope_ref: SCOPE_A.to_owned(),
                consumer: consumer(),
            },
        )
        .await
        .expect("owner");
        assert!(
            MemberServedSnapshot::from_serving(&owner, member_registry()).is_err(),
            "an inactive owner must not construct a served snapshot"
        );

        owner
            .sign_in(
                ACCT_A,
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .await
            .expect("sign in");
        let context = MemberCopyContext::for_test(ACCT_A, &origin, SCOPE_A);
        owner
            .admit_candidate(&staged, &manifest_json, &context)
            .await
            .expect("admit");
        assert!(owner.is_serving());

        let snapshot =
            MemberServedSnapshot::from_serving(&owner, member_registry()).expect("constructor");
        assert_eq!(
            snapshot.generation_id(),
            owner.generation_id().expect("gen")
        );

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(owner.lifecycle_status(), snapshot.clone());

        let served = session
            .handle_message(legacy_call(
                1,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            record_status(&served, two_caller::SHARED_CHILD).as_deref(),
            Some("found"),
            "the constructor must bind the exact admitted Db handle and account"
        );

        // Real owner retirement: quiesce deactivates and drains the generation's
        // lease gate, then closes the pools. The captured snapshot must refuse.
        owner.quiesce().await;
        let refused = snapshot
            .dispatch(legacy_call(
                2,
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "format": "json" }),
            ))
            .await
            .expect("response");
        assert_eq!(
            error_code(&refused),
            Some("copy_unavailable"),
            "owner-quiesce refused body: {refused}"
        );
    }

    /// R2(a): a kind-less known tool is a read by default, so the R6 copy
    /// state takes precedence — never `unavailable_offline(unknown_surface)`.
    #[tokio::test]
    async fn no_held_kindless_known_tool_takes_the_copy_state_precedence() {
        let mut registry = member_registry();
        registry
            .register_custom(
                "kindless_probe",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::new(ToolFamily::System, false, AdmissionReason::Discoverability),
                "kind-less probe",
                json!({ "type": "object" }),
                |_db, _caller, _args| async { Ok(json!({ "ran": true })) },
            )
            .expect("kindless register");
        let session = MemberStdioSession::new(Arc::new(registry));

        let body = session
            .handle_message(legacy_call(1, "kindless_probe", json!({})))
            .await
            .expect("response");
        assert_eq!(error_code(&body), Some("copy_unavailable"));
        assert_ne!(error_code(&body), Some("unavailable_offline"));
    }

    /// R2(b): a non-readable status clears the held snapshot, so the session
    /// and the copy state cannot be observed disagreeing.
    #[tokio::test]
    async fn set_status_clears_a_held_snapshot_on_a_non_readable_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let (snapshot, _leases) = snapshot_for(&world.db, ACCT_A, SCOPE_A, dir.path()).await;

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot,
        );
        assert!(session.has_snapshot());

        let dropped = session.set_status(CopyStatus::Locked {
            cut_at: CUT.to_owned(),
        });
        assert!(
            dropped.is_some(),
            "a non-readable status must clear the held snapshot"
        );
        assert!(!session.has_snapshot());

        let body = session
            .handle_message(legacy_call(1, "get_record", json!({ "ids": ["x"] })))
            .await
            .expect("response");
        assert_eq!(error_code(&body), Some("copy_locked"));
    }

    /// R2(c): the no-held discovery/catalog/resource surface is the **shared**
    /// path, so it is byte-identical to the held path. Compared against the
    /// actual held handler, not a duplicated expectation.
    #[tokio::test]
    async fn no_held_discovery_is_parity_with_the_held_shared_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let world = two_caller::build().await;
        let (snapshot, _leases) = snapshot_for(&world.db, ACCT_A, SCOPE_A, dir.path()).await;

        let held = MemberStdioSession::new(member_surface());
        let _ = held.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot,
        );
        let no_held = MemberStdioSession::new(member_surface());

        let modern_meta = json!({
            PROTOCOL_VERSION_META: protocol::PROTOCOL_VERSION,
            CLIENT_CAPABILITIES_META: {},
        });
        let mut messages = vec![
            json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "_meta": modern_meta.clone() } }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/list",
                "params": { "_meta": modern_meta.clone() } }),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list",
                "params": { "_meta": modern_meta.clone() } }),
            json!({ "jsonrpc": "2.0", "id": 4, "method": "initialize",
                "params": { "protocolVersion": "2024-11-05" } }),
            json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": 6, "method": "ping", "params": {} }),
        ];

        // `resources/read` for the first advertised resource, both eras.
        let listed = held
            .handle_message(messages[1].clone())
            .await
            .expect("held resources/list");
        let uri = listed["result"]["resources"][0]["uri"]
            .as_str()
            .expect("a resource uri")
            .to_owned();
        messages.push(
            json!({ "jsonrpc": "2.0", "id": 7, "method": "resources/read",
            "params": { "uri": uri, "_meta": modern_meta.clone() } }),
        );

        for message in messages {
            let held_response = held
                .handle_message(message.clone())
                .await
                .expect("held response");
            let no_held_response = no_held
                .handle_message(message)
                .await
                .expect("no-held response");
            assert_eq!(
                held_response, no_held_response,
                "no-held discovery must equal the shared held path"
            );
        }
    }

    /// Reviewer-102 repair proof: on an **actual** member dispatch the governed
    /// request trace must show RunContext / StrictPortability / RealtimeWakeup /
    /// InteractionCapture **Suppressed** (and the rest Applied). This is the
    /// real discriminator — a swallowed missing-table error would otherwise
    /// look like success. `run_key: "new"` would mint through a canonical port;
    /// the suppressed member port must not.
    #[tokio::test]
    async fn member_dispatch_suppresses_request_lifecycle_capture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_owner, snapshot) = admitted_owner(dir.path()).await;

        // Product flow: bootstrap succeeds and mints a non-durable session key
        // locally (no storage read), then an ordinary read carries that key.
        let bootstrap = snapshot
            .registry
            .call_engine_detailed(
                EngineHandle::Sqlite(snapshot.database.clone()),
                snapshot.caller.clone(),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("bootstrap dispatch");
        let bootstrap_result = bootstrap
            .outcome
            .expect("bootstrap must succeed on a member copy");
        let run_key = bootstrap_result.structured["session"]["run_key"]
            .as_str()
            .expect("bootstrap mints a non-durable session run key")
            .to_owned();

        let cases = [
            ("bootstrap", json!({ "run_key": "new" })),
            ("bootstrap", json!({ "run_key": "scout-chair-a748b2" })),
            // Direct registry dispatch does not run `tools_call_kernel`'s
            // format stripping, so no `format` argument here: a handler's
            // `deny_unknown_fields` extractor would otherwise reject it.
            (
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD], "run_key": run_key.clone() }),
            ),
            (
                "search",
                json!({ "query": "alpha", "run_key": run_key.clone() }),
            ),
        ];
        for (name, arguments) in cases {
            let outcome = snapshot
                .registry
                .call_engine_detailed(
                    EngineHandle::Sqlite(snapshot.database.clone()),
                    snapshot.caller.clone(),
                    name,
                    arguments,
                )
                .await
                .expect("member dispatch");
            assert!(
                outcome.outcome.is_ok(),
                "{name} must succeed on a member copy"
            );
            assert_eq!(
                outcome.governed_request_trace.len(),
                GOVERNED_REQUEST_PIPELINE.len()
            );
            for event in &outcome.governed_request_trace {
                let expected = match event.operation {
                    GovernedRequestOperation::RunContext
                    | GovernedRequestOperation::StrictPortability
                    | GovernedRequestOperation::RealtimeWakeup
                    | GovernedRequestOperation::InteractionCapture => {
                        GovernedRequestStageDisposition::Suppressed
                    }
                    GovernedRequestOperation::Authorization
                    | GovernedRequestOperation::TransientEvidence
                    | GovernedRequestOperation::StableErrors => {
                        GovernedRequestStageDisposition::Applied
                    }
                };
                assert_eq!(
                    event.disposition, expected,
                    "operation {:?} on {name}",
                    event.operation
                );
            }
        }
    }

    /// Reviewer-102 repair proof (metadata-error echo): an invalid `format`
    /// routes through `run_context_for_engine`, which must suppress for a
    /// member engine. The refusal is a tool result whose run context carries no
    /// minted key even for the `"new"` sentinel.
    #[tokio::test]
    async fn member_invalid_format_run_context_is_suppressed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_owner, snapshot) = admitted_owner(dir.path()).await;

        let session = MemberStdioSession::new(member_surface());
        let _ = session.publish(
            CopyStatus::Ready {
                cut_at: CUT.to_owned(),
            },
            snapshot,
        );

        let body = session
            .handle_message(modern_call(
                1,
                "get_record",
                json!({
                    "ids": [two_caller::SHARED_CHILD],
                    "format": "bogus",
                    "run_key": "new",
                }),
            ))
            .await
            .expect("response");
        assert_eq!(body["result"]["isError"], json!(true));
        assert_eq!(
            body["result"]["structuredContent"]["run_context"]["run_key"],
            json!(null),
            "member invalid-format run context must be suppressed (no mint): {body}"
        );
    }
}
