use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use native_ce::mcp::fetch::FetchConfig;
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::turso_local::{
    register_turso_local_tools_with, TursoLocalDb, TursoLocalRuntimeConfig,
    TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
};
use native_ce::{Error, Result};
use serde_json::Value;
use tempfile::TempDir;

use super::{ContractHarness, DeliveredMessageFixture, TestCaller};

/// Contract harness for the shipped Turso-local runtime.
///
/// Observable calls cross the same registry, engine handle, request wrapper,
/// authorization fold and domain handlers as a product runtime. Test-only
/// helpers are limited to portable fixture setup and physical replay probes.
pub struct TursoHarness {
    registry: ToolRegistry,
    next_database: AtomicUsize,
}

#[derive(Clone)]
pub struct TursoDatabase {
    inner: Arc<TursoDatabaseInner>,
}

struct TursoDatabaseInner {
    runtime: RwLock<Option<TursoLocalDb>>,
    config: TursoLocalRuntimeConfig,
    _directory: TempDir,
}

impl TursoDatabase {
    fn runtime(&self) -> Result<TursoLocalDb> {
        self.inner
            .runtime
            .read()
            .map_err(|_| Error::engine("Turso contract runtime lock is poisoned"))?
            .clone()
            .ok_or_else(|| Error::engine("Turso contract database is closed"))
    }

    pub fn runtime_for_test(&self) -> Result<TursoLocalDb> {
        self.runtime()
    }
}

impl TursoHarness {
    pub fn new() -> Self {
        Self::new_with_fetch_config(FetchConfig::default())
    }

    pub fn new_with_fetch_config(fetch_config: FetchConfig) -> Self {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).expect("register the shipped MCP surface");
        register_turso_local_tools_with(&mut registry, fetch_config)
            .expect("register the shipped Turso-local handlers");
        Self {
            registry,
            next_database: AtomicUsize::new(0),
        }
    }

    fn caller(caller: TestCaller) -> Caller {
        match caller {
            TestCaller::Local => Caller::local(),
            TestCaller::Member { account_id } => Caller::authenticated(account_id)
                .with_hosting_context("contract-member", "contract-database")
                .with_hosting_owner(false),
        }
    }

    pub async fn delete_event_for_test(&self, database: &TursoDatabase, seq: i64) -> Result<()> {
        database
            .runtime()?
            .contract_delete_content_event_for_test(seq)
            .await
    }

    pub async fn corrupt_event_for_test(&self, database: &TursoDatabase, seq: i64) -> Result<()> {
        database
            .runtime()?
            .contract_corrupt_content_event_for_test(seq)
            .await
    }

    pub async fn content_event_count_for_test(
        &self,
        database: &TursoDatabase,
        record_id: &str,
    ) -> Result<i64> {
        database
            .runtime()?
            .contract_content_event_count_for_test(record_id)
            .await
    }

    pub async fn blob_count_for_test(&self, database: &TursoDatabase) -> Result<i64> {
        database.runtime()?.contract_blob_count_for_test().await
    }

    pub async fn content_event_type_count_for_test(
        &self,
        database: &TursoDatabase,
        record_id: &str,
        event_type: &str,
    ) -> Result<i64> {
        database
            .runtime()?
            .contract_content_event_type_count_for_test(record_id, event_type)
            .await
    }

    pub async fn tombstone_record_for_test(
        &self,
        database: &TursoDatabase,
        record_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_tombstone_record_for_test(record_id)
            .await
    }

    pub async fn restrict_record_to_account_for_test(
        &self,
        database: &TursoDatabase,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_restrict_record_to_account_for_test(record_id, account_id)
            .await
    }

    pub async fn record_reference_query_plan_for_test(
        &self,
        database: &TursoDatabase,
    ) -> Result<Vec<String>> {
        database
            .runtime()?
            .contract_record_reference_query_plan_for_test()
            .await
    }

    pub async fn search_query_plan_for_test(
        &self,
        database: &TursoDatabase,
    ) -> Result<Vec<String>> {
        database
            .runtime()?
            .contract_search_query_plan_for_test()
            .await
    }

    pub async fn seed_delete_adjunct_state_for_test(
        &self,
        database: &TursoDatabase,
        message_id: &str,
        target_id: &str,
    ) -> Result<()> {
        self.call(
            database,
            TestCaller::Local,
            "manage_links",
            serde_json::json!({
                "action":"add",
                "source_id":message_id,
                "target_id":target_id,
                "relationship":"relates_to",
                "note":"Retained generic link."
            }),
        )
        .await?;
        database
            .runtime()?
            .contract_seed_delete_candidate_state(message_id)
            .await
    }

    pub async fn delete_adjunct_state_for_test(
        &self,
        database: &TursoDatabase,
        message_id: &str,
    ) -> Result<Value> {
        database
            .runtime()?
            .contract_delete_adjunct_state(message_id)
            .await
    }
}

impl ContractHarness for TursoHarness {
    type Database = TursoDatabase;

    async fn fresh_logical_database(&self) -> Result<Self::Database> {
        let ordinal = self.next_database.fetch_add(1, Ordering::AcqRel);
        let directory = tempfile::tempdir()
            .map_err(|error| Error::engine(format!("Turso contract tempdir failed: {error}")))?;
        let config =
            TursoLocalRuntimeConfig::from_json(&serde_json::to_vec(&serde_json::json!({
                "format":TURSO_LOCAL_RUNTIME_CONFIG_FORMAT,
                "logical_database_id":format!("contract-turso-{ordinal}"),
                "data_directory":directory.path(),
            }))?)?;
        let runtime = config.open().await?;
        Ok(TursoDatabase {
            inner: Arc::new(TursoDatabaseInner {
                runtime: RwLock::new(Some(runtime)),
                config,
                _directory: directory,
            }),
        })
    }

    async fn call(
        &self,
        database: &Self::Database,
        caller: TestCaller,
        tool: &str,
        arguments: Value,
    ) -> Result<Value> {
        self.registry
            .call_engine(
                EngineHandle::TursoLocal(database.runtime()?),
                Self::caller(caller),
                tool,
                arguments,
            )
            .await
    }

    async fn provision_member(
        &self,
        database: &Self::Database,
        person_id: &str,
        account_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_provision_member(person_id, account_id, principal_id)
            .await
    }

    async fn restrict_record_to_account_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        TursoHarness::restrict_record_to_account_for_test(self, database, record_id, account_id)
            .await
    }

    async fn create_historical_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        name: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_create_historical_record_for_test(record_id, name)
            .await
    }

    async fn create_attribution_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_create_attribution_record_for_test(record_id)
            .await
    }

    async fn tombstone_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        TursoHarness::tombstone_record_for_test(self, database, record_id).await
    }

    async fn create_suggestion_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        bearer_id: Option<&str>,
        home_id: Option<&str>,
        tombstoned: bool,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_create_suggestion_record_for_test(record_id, bearer_id, home_id, tombstoned)
            .await
    }

    async fn mark_record_archived_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_mark_record_archived_for_test(record_id)
            .await
    }

    async fn rehome_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        home_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_rehome_record_for_test(record_id, home_id)
            .await
    }

    async fn create_dashboard_link_overflow_for_test(
        &self,
        database: &Self::Database,
        source_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_create_dashboard_link_overflow_for_test(source_id)
            .await
    }

    async fn create_search_hidden_overflow_for_test(
        &self,
        database: &Self::Database,
        home_id: &str,
        policy_anchor_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_create_search_hidden_overflow_for_test(home_id, policy_anchor_id)
            .await
    }

    async fn activate_instruction_source_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        binding_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_activate_instruction_source_for_test(record_id, binding_id)
            .await
    }

    async fn install_facet_governance_fixture_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_install_facet_governance_fixture_for_test()
            .await
    }

    async fn install_facet_bounds_overflow_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_install_facet_bounds_overflow_for_test(record_id)
            .await
    }

    async fn install_ineligible_facet_records_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_install_ineligible_facet_records_for_test()
            .await
    }

    async fn install_hidden_scoped_facet_schema_for_test(
        &self,
        database: &Self::Database,
        scope_id: &str,
    ) -> Result<()> {
        database
            .runtime()?
            .contract_install_hidden_scoped_facet_schema_for_test(scope_id)
            .await
    }

    async fn facet_event_count_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<i64> {
        database
            .runtime()?
            .contract_facet_event_count_for_test(record_id)
            .await
    }

    async fn deliver_message_fixture(
        &self,
        database: &Self::Database,
        sender: TestCaller,
        fixture: DeliveredMessageFixture<'_>,
    ) -> Result<()> {
        let TestCaller::Member { account_id } = sender else {
            return Err(Error::engine(
                "Turso contract Message sender must be an authenticated member",
            ));
        };
        database
            .runtime()?
            .contract_deliver_message_fixture(
                &account_id,
                fixture.id,
                fixture.name,
                fixture.body,
                fixture.addressed_to,
            )
            .await
    }

    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()> {
        database
            .runtime()?
            .contract_assert_replay_equivalent()
            .await
    }

    async fn close(&self, database: &Self::Database) {
        let runtime = database
            .inner
            .runtime
            .write()
            .expect("lock Turso contract runtime for close")
            .take();
        drop(runtime);

        // No driver or lock handle remains. Remove every runtime-owned file
        // now rather than leaving cleanup to process exit.
        let entries = std::fs::read_dir(&database.inner.config.data_directory)
            .expect("read Turso contract data directory during close");
        for entry in entries {
            let path = entry.expect("read Turso contract-owned entry").path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).expect("remove Turso contract subdirectory");
            } else {
                std::fs::remove_file(&path).expect("remove Turso contract file");
            }
        }
        assert!(
            !database.inner.config.database_path().exists(),
            "Turso contract database survived close"
        );
        assert_eq!(
            std::fs::read_dir(&database.inner.config.data_directory)
                .expect("verify Turso contract data directory during close")
                .count(),
            0,
            "Turso contract-owned files survived close"
        );
    }
}
