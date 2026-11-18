use super::*;
use crate::authorization::Capability;
use crate::events::KERNEL_ROOT_ID;
use crate::mcp::executor_prototype::{
    HostedExecutorAuthority, HostedExecutorRuntime, HostedMembershipPreparation,
    HostedPlanCatalogue, HostedPlanKeyProvider,
};
use crate::mcp::{
    ExecutorTelemetryContext, ExecutorTelemetrySink, ExperimentalExecutors, McpSurfaceMode,
};
use futures::future::BoxFuture;

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    owner: String,
    manager: String,
    viewer: String,
    record: String,
    sibling: String,
    registry: std::sync::Arc<ToolRegistry>,
}
impl World {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, owner) = kernel::create_v2_database(
            dir.path().join("policy.db").to_str().unwrap(),
            "account",
            "Owner",
            "owner",
        )
        .await
        .unwrap();
        let manager = kernel::create_principal(&db, "account", "Manager", "manager", &owner)
            .await
            .unwrap();
        let viewer = kernel::create_principal(&db, "account", "Viewer", "viewer", &owner)
            .await
            .unwrap();
        let home = kernel::create_home(
            &db,
            KERNEL_ROOT_ID,
            Some(&[(&owner, "manage"), (&manager, "manage"), (&viewer, "view")]),
            &owner,
        )
        .await
        .unwrap();
        let record = kernel::create_record_as(&db, &owner, &home).await.unwrap();
        let sibling = kernel::create_record_as(&db, &owner, &home).await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        Self {
            _dir: dir,
            db,
            owner,
            manager,
            viewer,
            record,
            sibling,
            registry: std::sync::Arc::new(registry),
        }
    }
    async fn call(&self, account: &str, args: Value) -> Result<Value> {
        let caller = if account == "manager" {
            Caller::authenticated(account)
                .with_hosting_context("host:policy-manager", "db:policy-counter-proof")
                .with_hosting_owner(false)
                .with_hosting_member(true)
        } else {
            Caller::authenticated(account)
        };
        let value = self
            .registry
            .call_engine(
                EngineHandle::KernelV2(self.db.clone()),
                caller,
                "manage_record_policy",
                args,
            )
            .await?;
        if account == "manager" {
            assert!(
                crate::mcp::counter_fence::find_counters(&value).is_empty(),
                "{value}"
            );
        }
        Ok(value)
    }
    async fn listed(&self, id: &str) -> Value {
        self.call("owner", json!({"action":"list","record_id":id}))
            .await
            .unwrap()
    }
    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    async fn capability(&self, principal: &str, id: &str) -> Capability {
        kernel::kernel_effective_capability(&self.db, principal, id)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn v2_policy_nonowner_manager_changes_only_target_and_preserves_owner_and_inheritance() {
    let w = World::new().await;
    let inherited = w.listed(&w.record).await;
    assert_eq!(inherited["mode"], "inherit");
    let changed=w.call("manager",json!({"action":"grant","record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit","if_policy_revision":inherited["policy_revision"],"reason":"Share edit access"})).await.unwrap();
    assert_eq!(changed["changed"], true);
    assert_eq!(changed["boundary_created"], true);
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::Edit);
    assert_eq!(w.capability(&w.viewer, &w.sibling).await, Capability::View);
    let physical: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.record)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(&physical)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(owner.as_deref(), Some(w.owner.as_str()));
    let before = w.count().await;
    let unchanged=w.call("manager",json!({"action":"grant","record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"view","reason":"Already stronger"})).await.unwrap();
    assert_eq!(unchanged["changed"], false);
    assert_eq!(w.count().await, before);
    let explicit = w.listed(&w.record).await;
    w.call("owner",json!({"action":"restore_inheritance","record_id":w.record,"if_policy_revision":explicit["policy_revision"],"reason":"Use parent policy"})).await.unwrap();
    assert_eq!(w.listed(&w.record).await["mode"], "inherit");
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
    assert_eq!(w.capability(&w.owner, &w.record).await, Capability::Manage);
}

#[tokio::test]
async fn v2_policy_batch_is_atomic_and_retains_original_admission_after_self_revocation() {
    let w = World::new().await;
    let hidden_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.owner, "manage")]),
        &w.owner,
    )
    .await
    .unwrap();
    let hidden = kernel::create_record_as(&w.db, &w.owner, &hidden_home)
        .await
        .unwrap();
    let before = w.count().await;
    assert!(w.call("manager",json!({"action":"set_many","items":[
        {"record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit"},
        {"record_id":hidden,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit"}],"reason":"Atomic batch"})).await.is_err());
    assert_eq!(w.count().await, before);
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
    let result=w.call("manager",json!({"action":"set_many","items":[
        {"record_id":w.record,"subject":{"kind":"account","account_id":"manager"},"capability":null},
        {"record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit"}],"reason":"Transfer administration"})).await.unwrap();
    assert_eq!(result["changed_count"], 2);
    assert_eq!(result["outcomes"][0]["index"], 0);
    assert_eq!(result["outcomes"][1]["index"], 1);
    assert_eq!(w.capability(&w.manager, &w.record).await, Capability::None);
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::Edit);
    let before = w.count().await;
    assert!(w.call("manager",json!({"action":"revoke","record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"reason":"No longer authorized"})).await.is_err());
    assert_eq!(w.count().await, before);
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(w.capability(&w.manager, &w.record).await, Capability::None);
}

#[tokio::test]
async fn v2_policy_stale_guards_duplicates_and_members_manage_refuse_without_events() {
    let w = World::new().await;
    let before = w.count().await;
    for request in [
        json!({"action":"replace","record_id":w.record,"entries":[],"if_policy_revision":"stale","reason":"Conflict"}),
        json!({"action":"grant","record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit","if_content_seq":1,"reason":"Conflict"}),
        json!({"action":"set_members_baseline","record_id":w.record,"capability":"manage","reason":"Invalid baseline"}),
        json!({"action":"set_many","items":[{"record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"view"},{"record_id":w.record,"subject":{"kind":"account","account_id":"viewer"},"capability":"edit"}],"reason":"Duplicate"}),
        json!({"action":"restore_inheritance","record_id":"native:root","if_policy_revision":w.listed("native:root").await["policy_revision"],"reason":"Root cannot inherit"}),
    ] {
        assert!(w.call("owner", request).await.is_err());
        assert_eq!(w.count().await, before);
    }
    assert!(w
        .call("viewer", json!({"action":"inspect","record_id":w.record}))
        .await
        .unwrap()
        .get("entries")
        .is_none());
    assert!(w
        .call("viewer", json!({"action":"list","record_id":w.record}))
        .await
        .is_err());
}

async fn roster(db: &Db, actor: &str, members: &[&str]) -> Caller {
    kernel::hosted_identity::reconcile_hosted_caller(db, |_| async {
        // SAFETY: synthetic complete host catalogue; no public tool input.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                actor.into(),
                members.iter().map(|id| (*id).into()).collect(),
            )
        })
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn v2_policy_member_baseline_tracks_live_roster_and_replays_from_same_event() {
    let w = World::new().await;
    roster(&w.db, "owner", &["owner", "manager", "viewer"]).await;
    let revision = w.listed(&w.record).await["policy_revision"].clone();
    w.call("owner",json!({"action":"replace","record_id":w.record,"entries":[
        {"subject":{"kind":"account","account_id":"owner"},"capability":"manage"},
        {"subject":{"kind":"members"},"capability":"view"}],"if_policy_revision":revision,"reason":"Member reading"})).await.unwrap();
    roster(&w.db, "owner", &["owner", "manager", "viewer", "future"]).await;
    let future = kernel::resolve_principal_by_binding(&w.db, "future")
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(w.capability(&future, &w.record).await, Capability::View);
    roster(&w.db, "owner", &["owner", "manager", "viewer"]).await;
    assert_eq!(w.capability(&future, &w.record).await, Capability::None);
    roster(&w.db, "owner", &["owner", "manager", "viewer", "future"]).await;
    assert_eq!(w.capability(&future, &w.record).await, Capability::View);
    assert!(w.listed(&w.record).await["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["subject"]["kind"] == "members"));
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(w.capability(&future, &w.record).await, Capability::View);
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.record)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.owner, &home, &[(&w.owner, "manage")])
        .await
        .unwrap();
    assert_eq!(w.capability(&future, &w.record).await, Capability::None);
}

/// Hosted dispatch must let direct v2 operations through the plan gate: the
/// engine catalogue advertises `restore_inheritance` with
/// `plan_required == false`, so the legacy engine-blind plan table refusal
/// ("plan-required operations are unavailable until v2 write plans are
/// qualified") must not fire on a KernelV2 database.
const HOSTED_POLICY_DB_ID: &str = "db:policy-hosted";

#[derive(Debug)]
struct HostedPolicyNullSink;

impl ExecutorTelemetrySink for HostedPolicyNullSink {
    fn emit(&self, _event: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}

struct HostedPolicyAuthority {
    pool: sqlx::SqlitePool,
}

impl HostedPolicyAuthority {
    async fn new() -> Self {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(":memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE databases(id TEXT PRIMARY KEY, status TEXT NOT NULL, activity_epoch INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE executor_write_plans(plan_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, state TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, db_id TEXT NOT NULL, activity_epoch INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO databases(id, status, activity_epoch) VALUES(?1, 'ready', 1)")
            .bind(HOSTED_POLICY_DB_ID)
            .execute(&pool)
            .await
            .unwrap();
        Self { pool }
    }
}

impl HostedPlanCatalogue for HostedPolicyAuthority {
    fn executor_plan_pool(&self) -> &sqlx::SqlitePool {
        &self.pool
    }
}

impl HostedExecutorAuthority for HostedPolicyAuthority {
    fn validate_membership_write(&self, _arguments: Value) -> Result<()> {
        Ok(())
    }

    fn prepare_membership_write<'a>(
        &'a self,
        _db: &'a crate::Db,
        _caller: &'a Caller,
        _arguments: Value,
    ) -> BoxFuture<'a, Result<HostedMembershipPreparation>> {
        Box::pin(async { Err(Error::engine("policy fixture never prepares a write")) })
    }
}

struct HostedPolicyKeys;

impl HostedPlanKeyProvider for HostedPolicyKeys {
    fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
        Box::pin(async { Ok("policy-fixture-key".into()) })
    }

    fn seal(&self, key_id: String, _payload: Value) -> BoxFuture<'static, Result<String>> {
        Box::pin(async move { Ok(format!("{key_id}:fixture-signature")) })
    }

    fn verify(
        &self,
        key_id: String,
        _payload: Value,
        signature: String,
    ) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            if signature == format!("{key_id}:fixture-signature") {
                Ok(())
            } else {
                Err(Error::engine("policy fixture signature mismatch"))
            }
        })
    }
}

fn hosted_policy_caller() -> Caller {
    Caller::authenticated("owner")
        .with_hosting_context("host:policy-owner", HOSTED_POLICY_DB_ID)
        .with_hosting_owner(true)
        .with_hosting_member(true)
}

async fn hosted_policy_runtime(
    registry: std::sync::Arc<ToolRegistry>,
    surface: McpSurfaceMode,
) -> HostedExecutorRuntime {
    let authority: std::sync::Arc<dyn HostedExecutorAuthority> =
        std::sync::Arc::new(HostedPolicyAuthority::new().await);
    let keys: std::sync::Arc<dyn HostedPlanKeyProvider> = std::sync::Arc::new(HostedPolicyKeys);
    let telemetry =
        ExecutorTelemetryContext::new(std::sync::Arc::new(HostedPolicyNullSink), 1).unwrap();
    HostedExecutorRuntime::new_for_surface(
        registry,
        authority,
        keys,
        Some(telemetry),
        ExperimentalExecutors::empty(),
        surface,
    )
    .await
    .unwrap()
}

fn hosted_policy_message(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

fn hosted_restore_arguments(w: &World, revision: Value) -> Value {
    json!({
        "record_id": w.record,
        "if_policy_revision": revision,
        "reason": "Use parent policy",
    })
}

async fn hosted_grant_explicit(w: &World) -> Value {
    let inherited = w.listed(&w.record).await;
    assert_eq!(inherited["mode"], "inherit");
    w.call(
        "manager",
        json!({"action":"grant","record_id":w.record,
            "subject":{"kind":"account","account_id":"viewer"},"capability":"edit",
            "if_policy_revision":inherited["policy_revision"],"reason":"Share edit access"}),
    )
    .await
    .unwrap();
    let explicit = w.listed(&w.record).await;
    assert_eq!(explicit["mode"], "explicit");
    explicit["policy_revision"].clone()
}

#[tokio::test]
async fn hosted_restore_inheritance_reaches_direct_v2_handler_on_full_surface() {
    let w = World::new().await;
    let revision = hosted_grant_explicit(&w).await;
    let runtime = hosted_policy_runtime(w.registry.clone(), McpSurfaceMode::Executor).await;
    let response = runtime
        .handle_engine_with_persistence(
            EngineHandle::KernelV2(w.db.clone()),
            hosted_policy_caller(),
            HOSTED_POLICY_DB_ID.into(),
            hosted_policy_message(
                1,
                "access_admin",
                json!({
                    "operation": "manage_record_policy.restore_inheritance",
                    "format": "json",
                    "arguments": hosted_restore_arguments(&w, revision),
                }),
            ),
            None,
        )
        .await
        .unwrap()
        .expect("a direct v2 restore answers through the hosted entry point");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(w.listed(&w.record).await["mode"], "inherit");
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
}

#[tokio::test]
async fn hosted_restore_inheritance_reaches_direct_v2_handler_through_lean_call_executor() {
    let w = World::new().await;
    let revision = hosted_grant_explicit(&w).await;
    let runtime = hosted_policy_runtime(w.registry.clone(), McpSurfaceMode::Lean).await;
    let response = runtime
        .handle_engine_with_persistence(
            EngineHandle::KernelV2(w.db.clone()),
            hosted_policy_caller(),
            HOSTED_POLICY_DB_ID.into(),
            hosted_policy_message(
                2,
                "call_executor",
                json!({
                    "executor": "access_admin",
                    "operation": "manage_record_policy.restore_inheritance",
                    "format": "json",
                    "arguments": hosted_restore_arguments(&w, revision),
                }),
            ),
            None,
        )
        .await
        .unwrap()
        .expect("a lean call_executor restore answers through the hosted entry point");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(w.listed(&w.record).await["mode"], "inherit");
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
}

#[tokio::test]
async fn hosted_plan_gate_still_guards_v1_policy_and_unqualified_v2_operations() {
    let w = World::new().await;
    let revision = hosted_grant_explicit(&w).await;
    let runtime = hosted_policy_runtime(w.registry.clone(), McpSurfaceMode::Executor).await;
    // The same restore on a v1 database stays plan-gated: SQLite skips the
    // hosted v2 gate above and takes the plan-backed path, so the restore
    // must not execute directly and the policy stays explicit.
    let sqlite = crate::db::create_database(":memory:").await.unwrap();
    let v1_answer = runtime
        .handle_engine_with_persistence(
            EngineHandle::Sqlite(sqlite),
            hosted_policy_caller(),
            HOSTED_POLICY_DB_ID.into(),
            hosted_policy_message(
                3,
                "access_admin",
                json!({
                    "operation": "manage_record_policy.restore_inheritance",
                    "format": "json",
                    "arguments": hosted_restore_arguments(&w, revision),
                }),
            ),
            None,
        )
        .await
        .unwrap()
        .expect("a plan-gated v1 call answers through the hosted entry point");
    assert_eq!(v1_answer["result"]["isError"], true, "{v1_answer}");
    assert!(v1_answer.to_string().contains("prepare"), "{v1_answer}");
    assert_eq!(w.listed(&w.record).await["mode"], "explicit");
    // An operation with no v2 contract never reaches a handler: dispatch
    // refuses it without the plan-gate wording.
    let unqualified = runtime
        .handle_engine_with_persistence(
            EngineHandle::KernelV2(w.db.clone()),
            hosted_policy_caller(),
            HOSTED_POLICY_DB_ID.into(),
            hosted_policy_message(
                4,
                "sql_write",
                json!({
                    "operation": "sql_write",
                    "format": "json",
                    "arguments": {},
                }),
            ),
            None,
        )
        .await
        .unwrap()
        .expect("an unqualified v2 call answers with a dispatch refusal");
    assert_eq!(unqualified["result"]["isError"], true, "{unqualified}");
    assert!(
        !unqualified
            .to_string()
            .contains("plan-required operations are unavailable"),
        "{unqualified}"
    );
    w.db.close().await;
}

#[tokio::test]
async fn v2_policy_record_metadata_is_not_a_public_authority_bypass() {
    let w = World::new().await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.record)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let before = w.count().await;
    for (home, target) in [
        (home, w.record.clone()),
        (KERNEL_ROOT_ID.into(), KERNEL_ROOT_ID.into()),
    ] {
        let error=crate::store::append(&w.db,crate::store::AppendSpec {
            record_id:home,event_type:kernel::KERNEL_POLICY_REPLACED_EVENT.into(),
            payload:json!({"entries":[{"subject_id":w.viewer,"capability":"manage"}],
                "record_policy":{"target":target,"inherit":false,"members":null,"reason":"Forged authority"}}),
            actor:Some(w.viewer.clone()),
        }).await.unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(w.count().await, before);
    }
    assert_eq!(w.capability(&w.viewer, &w.record).await, Capability::View);
}
