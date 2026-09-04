#![cfg(feature = "postgres-tests")]

use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, EngineHandle, ToolRegistry,
};
use native_ce::postgres::{
    current_search_path, migration_version, register_postgres_tools, PostgresRuntimeConfig,
    PostgresSchemaCurrency,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;

fn postgres_url() -> Option<String> {
    std::env::var("NATIVE_CE_POSTGRES_TEST_URL").ok()
}

fn runtime_config(url: &str, logical_database_id: &str) -> PostgresRuntimeConfig {
    PostgresRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format": "native.postgres-runtime.v1",
            "logical_database_id": logical_database_id,
            "endpoint_url": url,
            "runtime_password": "contract-runtime-password",
            "tls_mode": "disable",
            "application_name": "native-ce-contract-runtime",
            "pool": {
                "min_connections": 0,
                "max_connections": 3,
                "acquisition_timeout_ms": 5000,
                "idle_lifetime_ms": 30000,
                "max_lifetime_ms": 60000
            },
            "timeouts": {
                "statement_timeout_ms": 10000,
                "lock_timeout_ms": 2000
            },
            "admin_url": url,
            "ownership_token": "contract-ownership-token"
        }))
        .unwrap(),
    )
    .unwrap()
}

async fn assert_runtime_role_sessions_closed(role: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&postgres_url().unwrap())
        .await
        .unwrap();
    for _ in 0..200 {
        let sessions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()",
        )
        .bind(role)
        .fetch_one(&admin)
        .await
        .unwrap();
        if sessions == 0 {
            admin.close().await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_stat_activity WHERE usename=$1 AND pid<>pg_backend_pid()",
    )
    .bind(role)
    .fetch_one(&admin)
    .await
    .unwrap();
    admin.close().await;
    assert_eq!(sessions, 0, "runtime pool sessions did not close");
}

#[tokio::test]
async fn legacy_v2_binding_audit_shape_is_refused_on_runtime_reopen() {
    let Some(url) = postgres_url() else {
        return;
    };
    let logical_database_id = format!("contract-legacy-v2-{}", uuid::Uuid::new_v4().simple());
    let config = runtime_config(&url, &logical_database_id);
    let (database, report) = config.provision_and_connect().await.unwrap();
    assert_eq!(report.schema_version, 6);
    let migrations = database.qualified_table("schema_migrations").unwrap();
    let binding_audit = database.qualified_table("binding_audit").unwrap();
    let mut transaction = database.pool().begin().await.unwrap();
    sqlx::query(&format!("DELETE FROM {migrations} WHERE version IN (5,6)"))
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(&format!("INSERT INTO {migrations}(version) VALUES(2)"))
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(&format!(
        "DROP TRIGGER binding_audit_append_only ON {binding_audit}"
    ))
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    database.close().await;

    let error = config.connect().await.unwrap_err().to_string();
    assert_eq!(
        error,
        "Postgres logical database uses legacy schema v2; authoritative substrate v6 requires operator-controlled reprovisioning"
    );
    config.drop_owned().await.unwrap();
}

#[tokio::test]
async fn main_era_v4_reopens_through_the_exact_v5_search_index_migration() {
    let Some(url) = postgres_url() else {
        return;
    };
    let logical_database_id = format!("contract-search-v4-{}", uuid::Uuid::new_v4().simple());
    let config = runtime_config(&url, &logical_database_id);
    let (database, report) = config.provision_and_connect().await.unwrap();
    assert_eq!(report.schema_version, 6);
    let records = database.qualified_table("records").unwrap();
    sqlx::query(&format!(
        "INSERT INTO {records}(id,record_type,kind,name,body,policy_anchor_id,created_at,updated_at) VALUES('contract:v4-search-survivor','Document','note','Migration survivor','migrationneedle','native:root',transaction_timestamp(),transaction_timestamp())"
    ))
    .execute(database.pool())
    .await
    .unwrap();
    database
        .contract_rewind_schema_v5_to_v4_for_test()
        .await
        .unwrap();
    database.close().await;

    let refusal = config.connect().await.unwrap_err().to_string();
    assert_eq!(
        refusal,
        "Postgres logical database uses legacy schema v4; authoritative substrate v6 requires provision_and_connect exact v4-to-v5 migration or operator-controlled reprovisioning"
    );

    let (migrated, migrated_report) = config.provision_and_connect().await.unwrap();
    assert_eq!(migrated_report.schema_version, 6);
    let survivor: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {records} WHERE id='contract:v4-search-survivor' AND body='migrationneedle')"
    ))
    .fetch_one(migrated.pool())
    .await
    .unwrap();
    assert!(survivor);
    let index_exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("{}.records_native_fts", migrated.schema()))
        .fetch_one(migrated.pool())
        .await
        .unwrap();
    assert!(index_exists);
    let binding_audit_guard_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_trigger trigger_state JOIN pg_class relation ON relation.oid=trigger_state.tgrelid JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname=$1 AND relation.relname='binding_audit' AND trigger_state.tgname='binding_audit_append_only' AND NOT trigger_state.tgisinternal)",
    )
    .bind(migrated.schema())
    .fetch_one(migrated.pool())
    .await
    .unwrap();
    assert!(binding_audit_guard_exists);
    migrated.close().await;
    config.drop_owned().await.unwrap();

    let malformed_id = format!(
        "contract-search-v4-malformed-{}",
        uuid::Uuid::new_v4().simple()
    );
    let malformed_config = runtime_config(&url, &malformed_id);
    let (malformed, _) = malformed_config.provision_and_connect().await.unwrap();
    malformed
        .contract_rewind_schema_v5_to_v4_for_test()
        .await
        .unwrap();
    let binding_audit = malformed.qualified_table("binding_audit").unwrap();
    sqlx::query(&format!(
        "DROP TRIGGER binding_audit_append_only ON {binding_audit}"
    ))
    .execute(malformed.pool())
    .await
    .unwrap();
    let refusal = malformed_config
        .provision_and_connect()
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal,
        "Postgres schema v4 search migration requires exact main-era v4 DDL"
    );
    assert_eq!(migration_version(&malformed).await.unwrap(), 4);
    let search_index_exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("{}.records_native_fts", malformed.schema()))
        .fetch_one(malformed.pool())
        .await
        .unwrap();
    assert!(!search_index_exists);
    malformed.close().await;
    malformed_config.drop_owned().await.unwrap();
}

#[tokio::test]
async fn provisioning_is_owned_idempotent_and_least_privilege() {
    let Some(url) = postgres_url() else {
        return;
    };
    let logical_database_id = format!("contract-runtime-{}", uuid::Uuid::new_v4().simple());
    let config = PostgresRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format": "native.postgres-runtime.v1",
            "logical_database_id": logical_database_id,
            "endpoint_url": url,
            "runtime_password": "contract-runtime-password",
            "tls_mode": "disable",
            "application_name": "native-ce-contract-runtime",
            "pool": {
                "min_connections": 0,
                "max_connections": 3,
                "acquisition_timeout_ms": 5000,
                "idle_lifetime_ms": 30000,
                "max_lifetime_ms": 60000
            },
            "timeouts": {
                "statement_timeout_ms": 10000,
                "lock_timeout_ms": 2000
            },
            "admin_url": postgres_url().unwrap(),
            "ownership_token": "contract-ownership-token"
        }))
        .unwrap(),
    )
    .unwrap();

    let (first_result, second_result) = tokio::join!(
        config.provision_and_connect(),
        config.provision_and_connect()
    );
    let (first, first_report) = first_result.unwrap();
    let (second, second_report) = second_result.unwrap();
    assert_eq!(
        usize::from(first_report.schema_created) + usize::from(second_report.schema_created),
        1,
        "exactly one concurrent provisioner creates the schema"
    );
    assert_eq!(
        usize::from(first_report.role_created) + usize::from(second_report.role_created),
        1,
        "exactly one concurrent provisioner creates the role"
    );
    assert_eq!(first_report.schema, config.schema_name());
    assert_eq!(first_report.runtime_role, config.runtime_role());
    assert_eq!(
        current_search_path(&first).await.unwrap(),
        "\"$user\", public"
    );
    let health = first.health().await.unwrap();
    assert_eq!(health.schema_currency, PostgresSchemaCurrency::Current);
    assert!(health.least_privilege);
    assert!(health.ready);
    assert!(health.write_ready);
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(first.pool())
        .await
        .unwrap();
    assert_eq!(current_user, config.runtime_role());
    let unauthorized_schema = format!("{}_escape", config.schema_name());
    let error = first
        .pool()
        .execute(format!("CREATE SCHEMA \"{unauthorized_schema}\"").as_str())
        .await
        .unwrap_err();
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref(),
        Some("42501")
    );

    assert_eq!(migration_version(&second).await.unwrap(), 6);
    assert_eq!(
        current_search_path(&second).await.unwrap(),
        "\"$user\", public"
    );

    let schema = config.schema_name();
    first
        .pool()
        .execute(
            format!(
                "ALTER TABLE \"{schema}\".\"facet_values\" RENAME TO \"facet_values_incomplete_test\""
            )
            .as_str(),
        )
        .await
        .unwrap();
    let incomplete = first.health().await.unwrap();
    assert_eq!(incomplete.schema_currency, PostgresSchemaCurrency::Current);
    assert!(
        !incomplete.ready,
        "a current ledger cannot hide a missing table"
    );
    assert!(!incomplete.write_ready);
    first
        .pool()
        .execute(
            format!(
                "ALTER TABLE \"{schema}\".\"facet_values_incomplete_test\" RENAME TO \"facet_values\""
            )
            .as_str(),
        )
        .await
        .unwrap();

    first
        .pool()
        .execute(
            format!("DROP TRIGGER control_events_append_only ON \"{schema}\".\"control_events\"")
                .as_str(),
        )
        .await
        .unwrap();
    let mutable_log = first.health().await.unwrap();
    assert!(
        !mutable_log.ready && !mutable_log.write_ready,
        "readiness must fail when an authoritative append-only trigger is absent"
    );
    first
        .pool()
        .execute(
            format!(
                "CREATE TRIGGER control_events_append_only BEFORE UPDATE OR DELETE ON \"{schema}\".\"control_events\" FOR EACH ROW EXECUTE FUNCTION \"{schema}\".reject_authoritative_event_mutation()"
            )
            .as_str(),
        )
        .await
        .unwrap();
    assert!(first.health().await.unwrap().write_ready);

    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_postgres_tools(&mut registry).unwrap();
    let runtime_engine = EngineHandle::Postgres(first.clone());
    for (id, account) in [
        ("9c150000-0000-4000-8000-004000000002", "acct:history-owner"),
        (
            "9c150000-0000-4000-8000-004000000001",
            "acct:history-outsider",
        ),
    ] {
        registry
            .call_engine(
                runtime_engine.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id,
                    "type": "Entity",
                    "kind": "person",
                    "name": id,
                    "reason": "Provision a member for the history authorization regression."
                }),
            )
            .await
            .unwrap();
        first
            .provision_member(id, account, &format!("native/{id}"))
            .await
            .unwrap();
    }
    registry
        .call_engine(
            runtime_engine.clone(),
            Caller::authenticated("acct:history-owner"),
            "create_record",
            json!({
                "id": "9c150000-0000-4000-8000-004000000003",
                "type": "Message",
                "kind": "text",
                "name": "Private history fixture",
                "body": "history-private-sentinel",
                "facets": { "expectation": "none" },
                "addressed_to": [],
                "reason": "Exercise fail-closed Postgres history authorization."
            }),
        )
        .await
        .unwrap();
    let owner_history = registry
        .call_engine(
            runtime_engine.clone(),
            Caller::authenticated("acct:history-owner"),
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-004000000003","detail":"full"}),
        )
        .await
        .unwrap();
    let owner_history_json = serde_json::to_string(&owner_history).unwrap();
    assert!(
        owner_history_json.contains("history-private-sentinel"),
        "{owner_history_json}"
    );
    assert!(
        owner_history_json.contains("acct:history-owner"),
        "the caller may see its own actor credential: {owner_history_json}"
    );
    assert!(
        !owner_history_json.contains("9c150000-0000-4000-8000-004000000002"),
        "event payload identity fields remain redacted: {owner_history_json}"
    );

    let outsider = registry
        .call_engine(
            runtime_engine.clone(),
            Caller::authenticated("acct:history-outsider"),
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-004000000003","detail":"full"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(outsider.contains("does not exist"), "{outsider}");
    assert!(!outsider.contains("history-private-sentinel"), "{outsider}");

    let whole_log = registry
        .call_engine(
            runtime_engine.clone(),
            Caller::authenticated("acct:history-outsider"),
            "get_history",
            json!({}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(whole_log.contains("requires record_id"), "{whole_log}");
    assert!(
        !whole_log.contains("history-private-sentinel"),
        "{whole_log}"
    );
    let local_history = registry
        .call_engine(
            runtime_engine.clone(),
            Caller::local(),
            "get_history",
            json!({"record_id":"9c150000-0000-4000-8000-004000000003","detail":"full"}),
        )
        .await
        .unwrap();
    assert_eq!(local_history["events"].as_array().map(Vec::len), Some(3));
    let local_history_json = serde_json::to_string(&local_history).unwrap();
    assert!(
        local_history_json.contains("history-private-sentinel"),
        "{local_history_json}"
    );
    assert!(
        local_history_json.contains("acct:history-owner"),
        "{local_history_json}"
    );

    drop(registry);
    drop(runtime_engine);
    first.close().await;
    second.close().await;
    drop(first);
    drop(second);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&postgres_url().unwrap())
        .await
        .unwrap();
    admin
        .execute(
            format!(
                "GRANT \"{}\" TO \"{}\" WITH ADMIN TRUE, INHERIT TRUE, SET FALSE",
                config.query_role(),
                config.runtime_role()
            )
            .as_str(),
        )
        .await
        .unwrap();
    admin.close().await;
    let reopened = config
        .connect()
        .await
        .expect("connect must repair unsafe options on the owned query-role membership");
    let reopened_health = reopened.health().await.unwrap();
    assert!(reopened_health.ready && reopened_health.least_privilege);
    let repaired_membership = sqlx::query_as::<_, (bool, bool, bool)>(
        "SELECT membership.admin_option,membership.inherit_option,membership.set_option FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname=current_user",
    )
    .bind(config.query_role())
    .fetch_one(reopened.pool())
    .await
    .unwrap();
    assert_eq!(repaired_membership, (false, false, true));
    reopened.close().await;
    drop(reopened);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&postgres_url().unwrap())
        .await
        .unwrap();
    admin
        .execute(
            format!(
                "REVOKE \"{}\" FROM \"{}\"",
                config.query_role(),
                config.runtime_role()
            )
            .as_str(),
        )
        .await
        .unwrap();
    admin
        .execute(format!("DROP ROLE \"{}\"", config.query_role()).as_str())
        .await
        .unwrap();
    admin.close().await;
    let recreated = config
        .connect()
        .await
        .expect("connect must recreate a missing owned query role for a current schema");
    assert!(recreated.health().await.unwrap().least_privilege);
    recreated.close().await;
    drop(recreated);
    assert_runtime_role_sessions_closed(&config.runtime_role()).await;
    config.drop_owned().await.unwrap();
    config.drop_owned().await.unwrap();
    assert_cancelled_provisioning_closes_the_session_lock_connection().await;
}

#[tokio::test]
async fn drop_owned_waits_for_the_database_catalog_lock_before_cleanup() {
    struct LockObservation {
        blocked_cleanup_pid: Option<i32>,
        schema_and_roles_while_blocked: (bool, bool, bool),
    }

    let Some(url) = postgres_url() else {
        return;
    };
    let logical_database_id = format!(
        "contract-drop-catalog-lock-{}",
        uuid::Uuid::new_v4().simple()
    );
    let config = runtime_config(&url, &logical_database_id);
    let (database, _) = config.provision_and_connect().await.unwrap();
    database.close().await;

    let probe_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let mut catalog_lock = probe_pool.acquire().await.unwrap();
    // A failed assertion must close the physical session rather than return a
    // session-level advisory lock to the pool.
    catalog_lock.close_on_drop();
    let catalog_lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *catalog_lock)
        .await
        .unwrap();
    sqlx::query(
        "SELECT pg_advisory_lock(hashtextextended('native-ce:postgres-database-provision:v1', 0))",
    )
    .execute(&mut *catalog_lock)
    .await
    .unwrap();

    let cleanup_application_name = format!("native-ce-drop-lock-{}", uuid::Uuid::new_v4().simple());
    let cleanup_config = config.clone();
    let cleanup_application_name_for_task = cleanup_application_name.clone();
    let mut cleanup = tokio::spawn(async move {
        cleanup_config
            .contract_drop_owned_with_application_name_for_test(&cleanup_application_name_for_task)
            .await
    });
    let observation: Result<LockObservation, sqlx::Error> = async {
        let mut blocked_cleanup_pid = None;
        for _ in 0..200 {
            blocked_cleanup_pid = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND $2 = ANY(pg_blocking_pids(pid)) AND wait_event='advisory'",
            )
            .bind(&cleanup_application_name)
            .bind(catalog_lock_pid)
            .fetch_optional(&mut *catalog_lock)
            .await?;
            if blocked_cleanup_pid.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let schema_and_roles_while_blocked: (bool, bool, bool) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1), EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2), EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$3)",
        )
        .bind(config.schema_name())
        .bind(config.runtime_role())
        .bind(config.query_role())
        .fetch_one(&mut *catalog_lock)
        .await?;
        Ok(LockObservation {
            blocked_cleanup_pid,
            schema_and_roles_while_blocked,
        })
    }
    .await;

    let unlock_result = sqlx::query_scalar::<_, bool>(
        "SELECT pg_advisory_unlock(hashtextextended('native-ce:postgres-database-provision:v1', 0))",
    )
    .fetch_one(&mut *catalog_lock)
    .await;
    drop(catalog_lock);
    probe_pool.close().await;

    let cleanup_result =
        match tokio::time::timeout(std::time::Duration::from_secs(10), &mut cleanup).await {
            Ok(result) => Some(result),
            Err(_) => {
                cleanup.abort();
                let _ = cleanup.await;
                None
            }
        };
    // Always make a final idempotent cleanup attempt before asserting any
    // observation, so a failed regression cannot strand test-owned resources.
    let fallback_cleanup_result = config.drop_owned().await;

    assert!(
        unlock_result.unwrap(),
        "catalog lock was not held at release"
    );
    let observation = observation.unwrap();
    assert!(
        observation.blocked_cleanup_pid.is_some(),
        "drop_owned never waited for the database catalog lock"
    );
    assert_eq!(
        observation.schema_and_roles_while_blocked,
        (true, true, true)
    );
    cleanup_result
        .expect("drop_owned remained blocked after the catalog lock was released")
        .unwrap()
        .unwrap();
    fallback_cleanup_result.unwrap();

    let verification_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema_and_roles_remain: (bool, bool, bool) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1), EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2), EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$3)",
    )
    .bind(config.schema_name())
    .bind(config.runtime_role())
    .bind(config.query_role())
    .fetch_one(&verification_pool)
    .await
    .unwrap();
    assert_eq!(schema_and_roles_remain, (false, false, false));
    verification_pool.close().await;
}

async fn assert_cancelled_provisioning_closes_the_session_lock_connection() {
    let Some(admin_url) = postgres_url() else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dummy_port = listener.local_addr().unwrap().port();
    let dummy_server = tokio::spawn(async move {
        let (_connection, _address) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let logical_database_id = format!("cancel-runtime-{}", uuid::Uuid::new_v4().simple());
    let config = PostgresRuntimeConfig::from_json(
        &serde_json::to_vec(&json!({
            "format": "native.postgres-runtime.v1",
            "logical_database_id": logical_database_id,
            "endpoint_url": format!("postgresql://127.0.0.1:{dummy_port}/native"),
            "runtime_password": "cancel-runtime-password",
            "tls_mode": "disable",
            "pool": {
                "min_connections": 0,
                "max_connections": 1,
                "acquisition_timeout_ms": 30000,
                "idle_lifetime_ms": 30000,
                "max_lifetime_ms": 60000
            },
            "timeouts": {
                "statement_timeout_ms": 30000,
                "lock_timeout_ms": 2000
            },
            "admin_url": admin_url.clone(),
            "ownership_token": "cancel-ownership-token"
        }))
        .unwrap(),
    )
    .unwrap();
    let probe_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let provision_config = config.clone();
    let provision = tokio::spawn(async move { provision_config.provision_and_connect().await });

    let mut observed_held = false;
    for _ in 0..200 {
        let available: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
                .bind(&logical_database_id)
                .fetch_one(&probe_pool)
                .await
                .unwrap();
        if available {
            let unlocked: bool =
                sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                    .bind(&logical_database_id)
                    .fetch_one(&probe_pool)
                    .await
                    .unwrap();
            assert!(unlocked);
        } else {
            observed_held = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        observed_held,
        "provisioning never reached the session advisory lock"
    );

    provision.abort();
    assert!(provision.await.unwrap_err().is_cancelled());
    let mut released_after_cancellation = false;
    for _ in 0..200 {
        let available: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1, 0))")
                .bind(&logical_database_id)
                .fetch_one(&probe_pool)
                .await
                .unwrap();
        if available {
            let unlocked: bool =
                sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                    .bind(&logical_database_id)
                    .fetch_one(&probe_pool)
                    .await
                    .unwrap();
            assert!(unlocked);
            released_after_cancellation = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        released_after_cancellation,
        "cancellation stranded the session advisory lock"
    );

    probe_pool.close().await;
    dummy_server.abort();
    config.drop_owned().await.unwrap();
}
