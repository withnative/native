use native_ce::mcp::fetch::FetchConfig;
use native_ce::mcp::{register_surface_tools, Caller, EngineHandle, ToolRegistry};
use native_ce::postgres::{register_postgres_tools_with, PostgresCluster, PostgresDb};
use native_ce::{Error, Result};
use serde_json::{json, Value};

use super::{ContractHarness, DeliveredMessageFixture, TestCaller};

/// Postgres implementation of the same backend-neutral MCP contract used by
/// SQLite. Database identity is carried by the opaque engine handle; scenarios
/// cannot observe the schema-per-logical-database implementation below it.
pub struct PostgresHarness {
    cluster: PostgresCluster,
    registry: ToolRegistry,
}

impl PostgresHarness {
    pub async fn from_env() -> Result<Option<Self>> {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return Ok(None);
        };
        let url = url
            .into_string()
            .map_err(|_| Error::engine("NATIVE_CE_POSTGRES_TEST_URL is not valid UTF-8"))?;
        Self::connect(&url).await.map(Some)
    }

    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with_fetch_config(url, FetchConfig::default()).await
    }

    pub async fn connect_with_fetch_config(url: &str, fetch_config: FetchConfig) -> Result<Self> {
        let cluster = PostgresCluster::connect(url).await?;
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry)?;
        register_postgres_tools_with(&mut registry, fetch_config)?;
        Ok(Self { cluster, registry })
    }

    fn caller(caller: TestCaller) -> Caller {
        match caller {
            TestCaller::Local => Caller::local(),
            TestCaller::Member { account_id } => Caller::authenticated(account_id)
                .with_hosting_context("contract-member", "contract-database")
                .with_hosting_owner(false),
        }
    }

    pub async fn shutdown(&self) {
        self.cluster.close().await;
    }
}

impl ContractHarness for PostgresHarness {
    type Database = PostgresDb;

    async fn fresh_logical_database(&self) -> Result<Self::Database> {
        self.cluster.fresh_logical_database().await
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
                EngineHandle::Postgres(database.clone()),
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
            .provision_member(person_id, account_id, principal_id)
            .await
    }

    async fn restrict_record_to_account_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        database
            .append_policy_event(native_ce::postgres::PostgresPolicyEvent {
                id: uuid::Uuid::new_v4().to_string(),
                record_id: record_id.into(),
                event_type: "policy.replaced".into(),
                payload: Some(serde_json::json!({"entries":[{
                    "subject_kind":"account",
                    "subject_id":account_id,
                    "effect":"allow",
                    "capability":"edit"
                }]})),
                actor: "contract".into(),
                reason: "Restrict the shared contract fixture to an editor.".into(),
                created_at: chrono::Utc::now().to_rfc3339(),
            })
            .await?;
        Ok(())
    }

    async fn create_historical_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        name: &str,
    ) -> Result<()> {
        database
            .contract_create_historical_record_for_test(record_id, name)
            .await
    }

    async fn create_attribution_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        database
            .contract_create_attribution_record_for_test(record_id)
            .await
    }

    async fn activate_instruction_source_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        binding_id: &str,
    ) -> Result<()> {
        let bindings = database.qualified_table("instruction_bindings")?;
        sqlx::query(&format!("INSERT INTO {bindings}(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) VALUES($1,'database','native:root',$2,0,TRUE,'contract',transaction_timestamp(),transaction_timestamp())"))
            .bind(binding_id)
            .bind(record_id)
            .execute(database.pool())
            .await?;
        Ok(())
    }

    async fn tombstone_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        sqlx::query(&format!(
            "UPDATE {records} SET deleted_at=transaction_timestamp(), updated_at=transaction_timestamp() WHERE id=$1"
        ))
        .bind(record_id)
        .execute(database.pool())
        .await?;
        Ok(())
    }

    async fn create_suggestion_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        bearer_id: Option<&str>,
        home_id: Option<&str>,
        tombstoned: bool,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        let links = database.qualified_table("links")?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,home_id,policy_anchor_id,created_at,updated_at,deleted_at) VALUES($1,'Annotation','suggestion','Contract suggestion',$2,'native:root',transaction_timestamp(),transaction_timestamp(),CASE WHEN $3 THEN transaction_timestamp() ELSE NULL END)"
        ))
        .bind(record_id)
        .bind(home_id)
        .bind(tombstoned)
        .execute(&mut *transaction)
        .await?;
        if let Some(bearer_id) = bearer_id {
            sqlx::query(&format!(
                "INSERT INTO {links}(id,source_id,target_id,relationship,created_at) VALUES($1,$2,$3,'part_of',transaction_timestamp())"
            ))
            .bind(format!("fixture:part-of:{record_id}"))
            .bind(record_id)
            .bind(bearer_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn mark_record_archived_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        sqlx::query(&format!("UPDATE {records} SET archived=TRUE WHERE id=$1"))
            .bind(record_id)
            .execute(database.pool())
            .await?;
        Ok(())
    }

    async fn rehome_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        home_id: &str,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        sqlx::query(&format!("UPDATE {records} SET home_id=$1 WHERE id=$2"))
            .bind(home_id)
            .bind(record_id)
            .execute(database.pool())
            .await?;
        Ok(())
    }

    async fn create_dashboard_link_overflow_for_test(
        &self,
        database: &Self::Database,
        source_id: &str,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        let links = database.qualified_table("links")?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,policy_anchor_id,created_at,updated_at) \
             SELECT 'dashboard-overflow-target:' || lpad(n::text,5,'0'),'Document','note','Dashboard overflow target','native:root',transaction_timestamp(),transaction_timestamp() \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {links}(id,source_id,target_id,relationship,created_at) \
             SELECT 'dashboard-overflow-link:' || lpad(n::text,5,'0'),$1,'dashboard-overflow-target:' || lpad(n::text,5,'0'),'depends_on',transaction_timestamp() \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .bind(source_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn create_search_hidden_overflow_for_test(
        &self,
        database: &Self::Database,
        home_id: &str,
        policy_anchor_id: &str,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        let links = database.qualified_table("links")?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,body,home_id,policy_anchor_id,created_at,updated_at) \
             SELECT 'aaa:search-hidden:' || lpad(n::text,5,'0'),'Document','note','Meeting hidden overflow','meeting',$1,$2,transaction_timestamp(),transaction_timestamp() \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .bind(home_id)
        .bind(policy_anchor_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {links}(id,source_id,target_id,relationship,created_at) \
             SELECT 'aaa:search-hidden-link:' || lpad(n::text,5,'0'),'aaa:search-hidden:' || lpad(n::text,5,'0'),$1,'relates_to',transaction_timestamp() \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .bind(policy_anchor_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn install_facet_governance_fixture_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let vocabularies = database.qualified_table("vocabularies")?;
        let values = database.qualified_table("vocabulary_values")?;
        let schema = database.qualified_table("schema_config")?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query(&format!("INSERT INTO {vocabularies}(id,name,created_at) VALUES('voc:contract-confidence','contract-confidence','2026-08-17T00:00:00Z'::timestamptz)"))
            .execute(&mut *transaction).await?;
        for (id, value, ordinal, terminality, status) in [
            (
                "vv:contract-confidence:likely",
                "likely",
                100.0,
                "open",
                "active",
            ),
            (
                "vv:contract-confidence:probable",
                "probable",
                100.0,
                "open",
                "active",
            ),
            (
                "vv:contract-confidence:unicode-z",
                "Ångström",
                150.0,
                "open",
                "active",
            ),
            (
                "vv:contract-confidence:unicode-a",
                "äther",
                150.0,
                "open",
                "active",
            ),
            (
                "vv:contract-confidence:won",
                "won",
                200.0,
                "terminal_positive",
                "active",
            ),
            (
                "vv:contract-confidence:speculative",
                "speculative",
                300.0,
                "open",
                "proposed",
            ),
        ] {
            sqlx::query(&format!("INSERT INTO {values}(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES($1,'voc:contract-confidence',$2,$3,$4,$5,'{{}}'::jsonb)"))
                .bind(id).bind(value).bind(status).bind(ordinal).bind(terminality)
                .execute(&mut *transaction).await?;
        }
        sqlx::query(&format!("UPDATE {values} SET alias_of='vv:contract-confidence:likely' WHERE id='vv:contract-confidence:probable'"))
            .execute(&mut *transaction).await?;
        sqlx::query(&format!("INSERT INTO {schema}(id,layer,name,data,created_at) VALUES('contract:facet-schema','user','Contract facet schema',$1,'2026-08-17T00:00:00Z'::timestamptz)"))
            .bind(serde_json::json!({"shapes":{"WorkItem":{"facets":{"score":{"type":"number"},"effort":{"values":["s","m"]},"confidence":{"vocab":"contract-confidence"},"mandatory":{"required":true}}}}}).to_string())
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn install_facet_bounds_overflow_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let facets = database.qualified_table("facet_values")?;
        let vocabularies = database.qualified_table("vocabularies")?;
        let values = database.qualified_table("vocabulary_values")?;
        let schema = database.qualified_table("schema_config")?;
        let mut transaction = database.pool().begin().await?;
        sqlx::query(&format!(
            "INSERT INTO {facets}(record_id,key,value) \
             SELECT $1,'overflow_'||lpad(n::text,5,'0'),'\"value\"'::jsonb \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .bind(record_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {vocabularies}(id,name,created_at) VALUES \
             ('voc:contract-facet-overflow','contract-facet-overflow',transaction_timestamp())"
        ))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {values}(id,vocabulary_id,value,status,ordinal,terminality,metadata) \
             SELECT 'vv:contract-facet-overflow:'||lpad(n::text,5,'0'), \
                    'voc:contract-facet-overflow','choice_'||lpad(n::text,5,'0'), \
                    'active',n::double precision,'open','{{}}'::jsonb \
             FROM generate_series(0,10000) AS numbers(n)"
        ))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {schema}(id,layer,name,data,created_at) VALUES \
             ('contract:facet-overflow-schema','user','Contract facet overflow schema',$1,transaction_timestamp())"
        ))
        .bind(serde_json::json!({"shapes":{"Document:facet_limits":{"facets":{"choice":{"vocab":"contract-facet-overflow"}}}}}).to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn install_ineligible_facet_records_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let records = database.qualified_table("records")?;
        let links = database.qualified_table("links")?;
        let annotation_targets = database.qualified_table("annotation_targets")?;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {annotation_targets}(annotation_id TEXT PRIMARY KEY,target_record_id TEXT NOT NULL,source_slot TEXT NOT NULL)"
        ))
        .execute(database.pool())
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,body,policy_anchor_id,created_at,updated_at) VALUES
             ('facet:attribution','Annotation','attribution','Hidden attribution',NULL,'native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:malformed-comment','Annotation','comment','Malformed comment','body without bearer','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:comment-bearer-a','WorkItem','task','Comment bearer A','body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:comment-bearer-b','WorkItem','task','Comment bearer B','body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:target-mismatch','Annotation','comment','Target mismatch','root body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:root-comment','Annotation','comment','Valid root','root body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:targeted-reply','Annotation','comment','Targeted reply','reply body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:reply-one','Annotation','comment','Reply one','reply body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz),
             ('facet:reply-on-reply','Annotation','comment','Reply on reply','reply body','native:root','2026-08-17T00:00:00Z'::timestamptz,'2026-08-17T00:00:00Z'::timestamptz)"
        ))
        .execute(database.pool())
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {links}(id,source_id,target_id,relationship) VALUES
             ('facet:link-target-mismatch','facet:target-mismatch','facet:comment-bearer-a','part_of'),
             ('facet:link-root','facet:root-comment','facet:comment-bearer-a','part_of'),
             ('facet:link-targeted-reply','facet:targeted-reply','facet:root-comment','part_of'),
             ('facet:link-reply-one','facet:reply-one','facet:root-comment','part_of'),
             ('facet:link-reply-two','facet:reply-on-reply','facet:reply-one','part_of')"
        ))
        .execute(database.pool())
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {annotation_targets}(annotation_id,target_record_id,source_slot) VALUES
             ('facet:target-mismatch','facet:comment-bearer-b','body'),
             ('facet:root-comment','facet:comment-bearer-a','body'),
             ('facet:targeted-reply','facet:comment-bearer-a','body')"
        ))
        .execute(database.pool())
        .await?;
        Ok(())
    }

    async fn install_hidden_scoped_facet_schema_for_test(
        &self,
        database: &Self::Database,
        scope_id: &str,
    ) -> Result<()> {
        let schema = database.qualified_table("schema_config")?;
        sqlx::query(&format!("INSERT INTO {schema}(id,layer,name,data,applies_to_collection_id,created_at) VALUES('contract:hidden-facet-schema','user','Hidden facet schema',$1,$2,'2026-08-17T00:00:00Z'::timestamptz)"))
            .bind(serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"private-only":{"values":["secret"]}}}}}).to_string())
            .bind(scope_id)
            .execute(database.pool())
            .await?;
        Ok(())
    }

    async fn facet_event_count_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<i64> {
        let events = database.qualified_table("content_events")?;
        Ok(sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type IN ('facet.set','facet.unset')"))
            .bind(record_id)
            .fetch_one(database.pool())
            .await?)
    }

    async fn deliver_message_fixture(
        &self,
        database: &Self::Database,
        sender: TestCaller,
        fixture: DeliveredMessageFixture<'_>,
    ) -> Result<()> {
        // The current Postgres slice atomically appends record.created and
        // message.audience.declared through create_record. It intentionally
        // does not expose the SQLite policy-gated manage_messages tool yet.
        self.call(
            database,
            sender,
            "create_record",
            json!({
                "id": fixture.id,
                "type": "Message",
                "kind": "text",
                "name": fixture.name,
                "body": fixture.body,
                "facets": { "expectation": "reply" },
                "addressed_to": fixture.addressed_to,
                "reason": "Exercise delivered Message visibility in the backend contract."
            }),
        )
        .await?;
        Ok(())
    }

    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()> {
        database.assert_replay_equivalent().await
    }

    async fn close(&self, database: &Self::Database) {
        database
            .drop_schema()
            .await
            .expect("drop Postgres contract schema");
    }
}
