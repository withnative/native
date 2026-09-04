use native_ce::conformance::rebuild_and_diff;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db, Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Executor, Row};

use super::{ContractHarness, DeliveredMessageFixture, TestCaller};

/// SQLite implementation of the backend-neutral test contract.
pub struct SqliteHarness {
    registry: ToolRegistry,
}

impl SqliteHarness {
    pub fn new() -> Self {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).expect("register the shipped MCP surface");
        Self { registry }
    }

    fn caller(caller: TestCaller) -> Caller {
        match caller {
            TestCaller::Local => Caller::local(),
            TestCaller::Member { account_id } => Caller::authenticated(account_id)
                .with_hosting_context("contract-member", "contract-database")
                .with_hosting_owner(false),
        }
    }
}

impl ContractHarness for SqliteHarness {
    type Database = Db;

    async fn fresh_logical_database(&self) -> Result<Self::Database> {
        create_database(":memory:").await
    }

    async fn call(
        &self,
        database: &Self::Database,
        caller: TestCaller,
        tool: &str,
        arguments: Value,
    ) -> Result<Value> {
        self.registry
            .call(database.clone(), Self::caller(caller), tool, arguments)
            .await
    }

    async fn provision_member(
        &self,
        database: &Self::Database,
        person_id: &str,
        account_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let mut transaction = crate::common::fixture_write_pool(database)
            .await
            .begin()
            .await?;
        transaction
            .execute(
                sqlx::query(
                    "INSERT INTO bindings (record_id, system, identifier, is_canonical) \
                     VALUES (?, 'account', ?, 1)",
                )
                .bind(person_id)
                .bind(account_id),
            )
            .await?;
        transaction
            .execute(
                sqlx::query(
                    "INSERT INTO bindings (record_id, system, identifier, is_canonical) \
                     VALUES (?, 'native-principal', ?, 1)",
                )
                .bind(person_id)
                .bind(principal_id),
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn restrict_record_to_account_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        native_ce::authorization::replace_explicit_policy(
            database,
            "contract:record-reference-policy",
            record_id,
            vec![native_ce::authorization::AllowEntry::account(
                account_id,
                native_ce::authorization::Capability::Edit,
            )],
        )
        .await
    }

    async fn create_attribution_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        // The bearer must be a distinct record from `record_id` while staying
        // derivable from it, so the fixture is deterministic. Record ids are
        // now UUIDs, so reuse the attributed record's last 12 hex digits under
        // a bearer-specific prefix rather than the old readable slug.
        let bearer_id = format!("bea70000-0000-4000-8000-{}", &record_id[24..]);
        let body = "Contract attribution bearer body.";
        self.registry
            .call(
                database.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": bearer_id,
                    "type": "Document",
                    "kind": "note",
                    "name": "Contract attribution bearer",
                    "body": body,
                    "reason": "Create the authoritative attribution contract bearer."
                }),
            )
            .await?;
        let row = sqlx::query(
            "SELECT id FROM content_events WHERE record_id=? AND type='record.created' ORDER BY seq DESC LIMIT 1",
        )
        .bind(&bearer_id)
        .fetch_one(database.pool())
        .await?;
        let source_event_id: String = row.try_get("id")?;
        let issuer = native_ce::awareness::HumanInteractionTokenIssuer::random("contract-ui");
        let ids = vec![bearer_id.clone()];
        let token = issuer.issue(
            "local",
            "agent-executor:contract-agent:contract-delegation",
            &ids,
            60,
        )?;
        let caller = Caller::local().with_agent_executor_token(
            &issuer,
            &token,
            "contract-agent",
            "contract-delegation",
            &ids,
        )?;
        self.registry
            .call(
                database.clone(),
                caller,
                "create_attribution",
                json!({
                    "id": record_id,
                    "idempotency_key": format!("contract-attribution:{record_id}"),
                    "bearer_id": bearer_id,
                    "target": {
                        "source_event_id": source_event_id,
                        "source_body_sha256": hex::encode(Sha256::digest(body.as_bytes())),
                        "scope": "whole_revision",
                        "selectors": []
                    },
                    "subject": {"kind": "self_agent_execution"},
                    "relation": "expresses_view",
                    "polarity": "affirmed",
                    "confidence": "likely",
                    "transformation": "summary",
                    "rationale": "Exercise canonical attribution deletion exclusion."
                }),
            )
            .await?;
        Ok(())
    }

    async fn activate_instruction_source_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        binding_id: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) VALUES(?,'database','native:root',?,0,1,'contract','2026-08-16T00:00:00Z','2026-08-16T00:00:00Z')")
            .bind(binding_id)
            .bind(record_id)
            .execute(&crate::common::fixture_write_pool(database).await)
            .await?;
        Ok(())
    }

    async fn tombstone_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE records SET deleted_at=?, updated_at=? WHERE id=?")
            .bind("2026-08-16T00:00:01Z")
            .bind("2026-08-16T00:00:01Z")
            .bind(record_id)
            .execute(&crate::common::fixture_write_pool(database).await)
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
        let pool = crate::common::fixture_write_pool(database).await;
        sqlx::query("INSERT INTO records(id,type,kind,name,home_id,created_at,updated_at,deleted_at) VALUES(?,'Annotation','suggestion','Contract suggestion',?,'2026-08-16T00:00:00Z','2026-08-16T00:00:00Z',?)")
            .bind(record_id)
            .bind(home_id)
            .bind(tombstoned.then_some("2026-08-16T00:00:01Z"))
            .execute(&pool)
            .await?;
        if let Some(bearer_id) = bearer_id {
            sqlx::query("INSERT INTO links(id,source_id,target_id,relationship,created_at) VALUES(?,?,?,'part_of','2026-08-16T00:00:00Z')")
                .bind(format!("fixture:part-of:{record_id}"))
                .bind(record_id)
                .bind(bearer_id)
                .execute(&pool)
                .await?;
        }
        Ok(())
    }

    async fn mark_record_archived_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO facet_values(id,record_id,key,value) VALUES(?,?,'archived','true')",
        )
        .bind(format!("fixture:archived:{record_id}"))
        .bind(record_id)
        .execute(&crate::common::fixture_write_pool(database).await)
        .await?;
        Ok(())
    }

    async fn rehome_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        home_id: &str,
    ) -> Result<()> {
        sqlx::query("UPDATE records SET home_id=? WHERE id=?")
            .bind(home_id)
            .bind(record_id)
            .execute(&crate::common::fixture_write_pool(database).await)
            .await?;
        Ok(())
    }

    async fn install_facet_governance_fixture_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let pool = crate::common::fixture_write_pool(database).await;
        let mut transaction = pool.begin().await?;
        sqlx::query("INSERT INTO vocabularies(id,name,created_at) VALUES('voc:contract-confidence','contract-confidence','2026-08-17T00:00:00.000Z')")
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
            sqlx::query("INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES(?,'voc:contract-confidence',?,?,?,?, '{}')")
                .bind(id).bind(value).bind(status).bind(ordinal).bind(terminality)
                .execute(&mut *transaction).await?;
        }
        sqlx::query("UPDATE vocabulary_values SET alias_of='vv:contract-confidence:likely' WHERE id='vv:contract-confidence:probable'")
            .execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('contract:facet-schema','user','Contract facet schema',?,'2026-08-17T00:00:00.000Z')")
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
        const NUMBERS: &str = "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)), numbers(n) AS (SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d CROSS JOIN digits e WHERE a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d <= 10000) ";
        let pool = crate::common::fixture_write_pool(database).await;
        let mut transaction = pool.begin().await?;
        sqlx::query(&format!(
            "{NUMBERS}INSERT INTO facet_values(id,record_id,key,value) \
             SELECT printf('facet-overflow:%05d',n),?,printf('overflow_%05d',n),'value' FROM numbers"
        ))
        .bind(record_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO vocabularies(id,name,created_at) VALUES('voc:contract-facet-overflow','contract-facet-overflow','2026-08-17T00:00:00.000Z')")
            .execute(&mut *transaction).await?;
        sqlx::query(&format!(
            "{NUMBERS}INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) \
             SELECT printf('vv:contract-facet-overflow:%05d',n),'voc:contract-facet-overflow',printf('choice_%05d',n),'active',n,'open','{{}}' FROM numbers"
        ))
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('contract:facet-overflow-schema','user','Contract facet overflow schema',?,'2026-08-17T00:00:00.000Z')")
            .bind(serde_json::json!({"shapes":{"Document:facet_limits":{"facets":{"choice":{"vocab":"contract-facet-overflow"}}}}}).to_string())
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn install_ineligible_facet_records_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let pool = crate::common::fixture_write_pool(database).await;
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,body,policy_anchor_id,created_at,updated_at) VALUES
             ('facet:attribution','Annotation','attribution','Hidden attribution',NULL,'native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:malformed-comment','Annotation','comment','Malformed comment','body without bearer','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:comment-bearer-a','WorkItem','task','Comment bearer A','body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:comment-bearer-b','WorkItem','task','Comment bearer B','body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:target-mismatch','Annotation','comment','Target mismatch','root body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:root-comment','Annotation','comment','Valid root','root body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:targeted-reply','Annotation','comment','Targeted reply','reply body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:reply-one','Annotation','comment','Reply one','reply body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:reply-on-reply','Annotation','comment','Reply on reply','reply body','native:root','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES
             ('facet:link-target-mismatch','facet:target-mismatch','facet:comment-bearer-a','part_of'),
             ('facet:link-root','facet:root-comment','facet:comment-bearer-a','part_of'),
             ('facet:link-targeted-reply','facet:targeted-reply','facet:root-comment','part_of'),
             ('facet:link-reply-one','facet:reply-one','facet:root-comment','part_of'),
             ('facet:link-reply-two','facet:reply-on-reply','facet:reply-one','part_of')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO annotation_targets(annotation_id,target_record_id,source_slot,source_event_seq,source_sha256,selectors,created_at,updated_at) VALUES
             ('facet:target-mismatch','facet:comment-bearer-b','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:root-comment','facet:comment-bearer-a','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
             ('facet:targeted-reply','facet:comment-bearer-a','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z')",
        )
        .execute(&pool)
        .await?;
        Ok(())
    }

    async fn install_hidden_scoped_facet_schema_for_test(
        &self,
        database: &Self::Database,
        scope_id: &str,
    ) -> Result<()> {
        sqlx::query("INSERT INTO schema_config(id,layer,name,data,applies_to_collection_id,created_at) VALUES('contract:hidden-facet-schema','user','Hidden facet schema',?,?,'2026-08-17T00:00:00.000Z')")
            .bind(serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"private-only":{"values":["secret"]}}}}}).to_string())
            .bind(scope_id)
            .execute(&crate::common::fixture_write_pool(database).await)
            .await?;
        Ok(())
    }

    async fn facet_event_count_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id=? AND type IN ('facet.set','facet.unset')")
            .bind(record_id)
            .fetch_one(&crate::common::fixture_write_pool(database).await)
            .await?)
    }

    async fn deliver_message_fixture(
        &self,
        database: &Self::Database,
        sender: TestCaller,
        fixture: DeliveredMessageFixture<'_>,
    ) -> Result<()> {
        let sender_account = match &sender {
            TestCaller::Member { account_id } => account_id,
            TestCaller::Local => {
                return Err(native_ce::Error::engine(
                    "delivered Message contract fixtures require a member sender",
                ))
            }
        };
        let sender_person: String = sqlx::query_scalar(
            "SELECT record_id FROM bindings
              WHERE system='account' AND identifier=? AND is_canonical=1",
        )
        .bind(sender_account)
        .fetch_one(&crate::common::fixture_write_pool(database).await)
        .await?;
        let mut participant_ids = vec![sender_person];
        participant_ids.extend(fixture.addressed_to.iter().map(|id| (*id).to_owned()));
        let result = self
            .call(
                database,
                sender,
                "manage_messages",
                json!({
                    "action": "send",
                    "id": fixture.id,
                    "name": fixture.name,
                    "body": fixture.body,
                    "preview": "A backend-contract Message fixture.",
                    "origin":{"type":"direct","participant_ids":participant_ids},
                    "addressed_to": fixture.addressed_to,
                    "expectation": "reply",
                    "idempotency_key": fixture.idempotency_key,
                    "reason": "Exercise delivered Message visibility in the backend contract."
                }),
            )
            .await?;
        if result["delivery"]["status"] == "delivered" {
            Ok(())
        } else {
            Err(Error::engine(format!(
                "contract Message fixture was not delivered: {}",
                result["delivery"]
            )))
        }
    }

    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()> {
        let diff = rebuild_and_diff(database).await?;
        if diff.equal {
            Ok(())
        } else {
            Err(Error::engine(format!(
                "authoritative replay diverged from live projections: {:?}",
                diff.tables
            )))
        }
    }

    async fn close(&self, database: &Self::Database) {
        database.close().await;
    }
}
