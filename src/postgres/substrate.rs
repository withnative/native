//! Postgres implementation of Native's authoritative, direct-write, and
//! request-cross-cutting storage primitives.
//!
//! This module deliberately exposes named Native operations rather than a
//! universal CRUD trait. Ordinary domain handlers continue to own payload
//! validation and result shaping; this adapter owns Postgres transaction
//! cursors, deterministic locks, projection folds, and physical row codecs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::PostgresDb;
use crate::schema::ROOT_RECORD_ID;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresLogKind {
    Content,
    Meta,
    Policy,
    Control,
}

impl PostgresLogKind {
    pub const ALL: [Self; 4] = [Self::Content, Self::Meta, Self::Policy, Self::Control];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Meta => "meta",
            Self::Policy => "policy",
            Self::Control => "control",
        }
    }

    pub const fn relation(self) -> &'static str {
        match self {
            Self::Content => "content_events",
            Self::Meta => "meta_events",
            Self::Policy => "policy_events",
            Self::Control => "control_events",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PostgresAuthoritativeEvent {
    pub log: PostgresLogKind,
    pub seq: i64,
    pub id: String,
    pub subject_id: String,
    pub event_type: String,
    pub payload: Option<Value>,
    pub actor: Option<String>,
    pub run_key: Option<String>,
    pub parent_key: Option<String>,
    pub intent: Option<String>,
    pub reason: Option<String>,
    pub idempotency_key: Option<String>,
    pub schema_version: Option<i64>,
    pub aggregate_kind: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PostgresMetaEvent {
    pub id: String,
    pub subject_id: String,
    pub event_type: String,
    pub payload: Value,
    pub actor: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PostgresPolicyEvent {
    pub id: String,
    pub record_id: String,
    pub event_type: String,
    pub payload: Option<Value>,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PostgresControlEvent {
    pub id: String,
    pub idempotency_key: String,
    pub event_type: String,
    pub schema_version: i64,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
    pub payload: Value,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresBlob {
    pub id: String,
    pub bytes: Option<Vec<u8>>,
    pub mime: Option<String>,
    pub size_bytes: i64,
    pub sha256: String,
    pub original_filename: Option<String>,
    pub storage_tier: String,
    pub external_ref: Option<String>,
}

impl PostgresDb {
    pub(crate) async fn mint_run_key(&self, agent_key: Option<&str>) -> Result<String> {
        #[cfg(test)]
        if self.request_lifecycle_test_bypass {
            // The registry routing unit test deliberately constructs a lazy,
            // unreachable handle. Production handles are opened and health-
            // checked by PostgresCluster before dispatch.
            return Ok(format!("{}-000000", agent_key.unwrap_or("scout-chair")));
        }
        match agent_key {
            Some(agent_key) => {
                let agent_key = match crate::runkey::validate(Some(&format!("new:{agent_key}"))) {
                    crate::runkey::KeyOutcome::Requested {
                        agent_key: Some(valid),
                    } => valid,
                    _ => return Err(Error::engine("invalid agent key")),
                };
                let taken = self
                    .persisted_run_keys(Some(&format!("{agent_key}-%")))
                    .await?;
                crate::runkey::mint_run_for_agent(&agent_key, &taken)
            }
            None => {
                let taken = self.persisted_run_keys(None).await?;
                crate::runkey::mint_fresh_agent_run(&taken)
            }
        }
    }

    /// Durable run-key evidence, for minting only.
    ///
    /// The selection rule itself is the shared exhaustive one; this only
    /// gathers the tiers this backend owns. Reading them into one set up front
    /// is also what makes the shared walk possible: it decides against a
    /// snapshot instead of issuing a query per candidate.
    ///
    /// `request_interactions` is deliberately absent. It is the broad
    /// interaction tap, whose capability is classified Unsupported for this
    /// profile, and run context must not borrow evidence from a capability that
    /// is not claimed. A run that only ever read therefore leaves no evidence
    /// and its key stays mintable — the same degradation the reference profile
    /// accepts when its own disposable tier is absent.
    async fn persisted_run_keys(
        &self,
        agent_pattern: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        let events = self.qualified_table("content_events")?;
        let contexts = self.qualified_table("run_contexts")?;
        let (sql, pattern) = match agent_pattern {
            Some(pattern) => (
                format!(
                    "SELECT run_key FROM {events} WHERE run_key IS NOT NULL AND run_key LIKE $1 \
                     UNION SELECT run_key FROM {contexts} WHERE run_key IS NOT NULL AND run_key LIKE $1"
                ),
                Some(pattern.to_string()),
            ),
            None => (
                format!(
                    "SELECT run_key FROM {events} WHERE run_key IS NOT NULL \
                     UNION SELECT run_key FROM {contexts} WHERE run_key IS NOT NULL"
                ),
                None,
            ),
        };
        let mut query = sqlx::query_scalar::<_, String>(&sql);
        if let Some(pattern) = &pattern {
            query = query.bind(pattern);
        }
        Ok(query.fetch_all(&self.pool).await?.into_iter().collect())
    }

    /// The intent currently in force for an exact full run key, read from the
    /// run-context relation this stage owns rather than from the optional
    /// interaction tap.
    pub(crate) async fn intent_at(&self, run_key: Option<&str>) -> Option<String> {
        #[cfg(test)]
        if self.request_lifecycle_test_bypass {
            return None;
        }
        let run_key = run_key?;
        let contexts = self.qualified_table("run_contexts").ok()?;
        sqlx::query_scalar(&format!(
            "SELECT intent FROM {contexts} WHERE run_key=$1 AND intent IS NOT NULL"
        ))
        .bind(run_key)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
    }

    /// Persist one successfully handled declaration by exact full run key.
    ///
    /// The single upsert is the whole mutation boundary: a failed statement
    /// leaves the prior declaration intact, an identical redeclaration is
    /// idempotent, and changed prose replaces only this run's current value.
    pub(crate) async fn persist_intent(&self, run_key: &str, intent: &str) -> Result<()> {
        let crate::runkey::KeyOutcome::Valid(valid) = crate::runkey::validate_full(Some(run_key))
        else {
            return Err(Error::engine(
                "set_intent requires a valid full run key for persistence",
            ));
        };
        let contexts = self.qualified_table("run_contexts")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| Error::engine("cannot persist run intent"))?;
        sqlx::query(&format!(
            "INSERT INTO {contexts}(run_key,intent,agent_key) VALUES($1,$2,$3) \
             ON CONFLICT(run_key) DO UPDATE SET intent=EXCLUDED.intent,agent_key=EXCLUDED.agent_key,updated_at=transaction_timestamp()"
        ))
        .bind(&valid)
        .bind(intent)
        .bind(crate::runkey::agent_key_of(&valid))
        .execute(&mut *transaction)
        .await
        .map_err(|_| Error::engine("cannot persist run intent"))?;
        #[cfg(feature = "postgres-tests")]
        self.intent_persist_checkpoint.enter().await;
        transaction
            .commit()
            .await
            .map_err(|_| Error::engine("cannot persist run intent"))?;
        Ok(())
    }

    /// Admit one request against the persisted portability policy and keep that
    /// policy revision stable until the request's future completes.
    ///
    /// The decision is the shared capability-intersection one, not a Postgres
    /// dialect of it: a classified operation is admitted exactly when its
    /// capability survives the pinned target intersection, and a capability-less
    /// diagnostic stays callable in strict mode. Nothing is cached between
    /// requests, so a denial cannot outlive the call that earned it.
    pub(crate) async fn with_operation_admission<F, T>(
        &self,
        operation: &str,
        capability: Option<&str>,
        future: F,
    ) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        #[cfg(test)]
        if self.request_lifecycle_test_bypass {
            return future.await;
        }
        let _lease = self.portability_policy_gate.read().await;
        let policy = self.load_portability_policy().await?;
        crate::storage_profile::admit_request_operation(
            policy.as_ref(),
            &crate::storage_profile::active_profile_authority(),
            operation,
            capability,
        )?;
        future.await
    }

    async fn load_portability_policy(
        &self,
    ) -> Result<Option<crate::storage_profile::PersistedPolicy>> {
        let table = self.qualified_table("storage_portability_policy")?;
        let Some(row) = sqlx::query(&format!(
            "SELECT {} FROM {table} WHERE singleton=1",
            super::POLICY_COLUMN_PROJECTION
        ))
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        crate::storage_profile::decode_policy_columns(super::policy_columns_from_row(&row)?)
            .map(Some)
    }

    pub(crate) async fn capture_request_interaction(
        &self,
        capture: crate::domain_transaction::request::InteractionCapture<'_>,
    ) {
        #[cfg(test)]
        if self.request_lifecycle_test_bypass {
            return;
        }
        let table = match self.qualified_table("request_interactions") {
            Ok(table) => table,
            Err(_) => return,
        };
        let (outcome, error_kind) = match capture.outcome {
            Ok(_) => ("ok", None),
            Err(error) => (
                "error",
                Some(match error {
                    Error::Engine(_) => "engine",
                    Error::Conflict(_) => "conflict",
                    Error::Auth(_) => "auth",
                    Error::Delivery(_) => "delivery",
                    Error::DeploymentReadOnly(_) => "deployment_read_only",
                    Error::Sqlx(_) => "database",
                    Error::Json(_) => "json",
                    Error::Io(_) => "io",
                }),
            ),
        };
        let _ = sqlx::query(&format!(
            "INSERT INTO {table}(id,tool,actor,run_key,parent_key,arguments,outcome,error_kind,run_context,started_at,ended_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11::timestamptz)"
        ))
        .bind(Uuid::new_v4().to_string())
        .bind(capture.tool_name)
        .bind(capture.caller.actor())
        .bind(capture.caller.run_key())
        .bind(capture.caller.parent_key())
        .bind(capture.original_arguments)
        .bind(outcome)
        .bind(error_kind)
        .bind(capture.run_context)
        .bind(capture.started_at)
        .bind(capture.ended_at)
        .execute(&self.pool)
        .await;
    }

    async fn allocate_log_position(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        log: PostgresLogKind,
    ) -> Result<i64> {
        let cursors = self.qualified_table("log_cursors")?;
        let seq: i64 = sqlx::query_scalar(&format!(
            "UPDATE {cursors} SET last_seq=last_seq+1 WHERE log_name=$1 RETURNING last_seq"
        ))
        .bind(log.as_str())
        .fetch_one(&mut **tx)
        .await?;
        Ok(seq)
    }

    /// Append and synchronously fold one meta event. The cursor row is updated
    /// in the same transaction, so rollback cannot leave a visible gap.
    pub async fn append_meta_event(&self, event: PostgresMetaEvent) -> Result<i64> {
        validate_nonempty("meta event id", &event.id)?;
        validate_nonempty("meta event subject_id", &event.subject_id)?;
        validate_nonempty("meta event type", &event.event_type)?;
        let mut tx = self.pool.begin().await?;
        let seq = self
            .allocate_log_position(&mut tx, PostgresLogKind::Meta)
            .await?;
        let events = self.qualified_table("meta_events")?;
        sqlx::query(&format!(
            "INSERT INTO {events}(seq,id,subject_id,type,payload,actor,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz)"
        ))
        .bind(seq)
        .bind(&event.id)
        .bind(&event.subject_id)
        .bind(&event.event_type)
        .bind(&event.payload)
        .bind(&event.actor)
        .bind(&event.created_at)
        .execute(&mut *tx)
        .await?;
        self.project_meta_event(&mut tx, &event).await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(seq)
    }

    async fn project_meta_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: &PostgresMetaEvent,
    ) -> Result<()> {
        match event.event_type.as_str() {
            "vocabulary.created" => {
                let table = self.qualified_table("vocabularies")?;
                let payload: crate::meta::VocabularyCreatedPayload =
                    serde_json::from_value(event.payload.clone())?;
                sqlx::query(&format!(
                    "INSERT INTO {table}(id,name,created_at) VALUES($1,$2,$3::timestamptz)"
                ))
                .bind(&event.subject_id)
                .bind(payload.name)
                .bind(&event.created_at)
                .execute(&mut **tx)
                .await?;
            }
            "vocabulary.deleted" => {
                let table = self.qualified_table("vocabularies")?;
                let result = sqlx::query(&format!("DELETE FROM {table} WHERE id=$1"))
                    .bind(&event.subject_id)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.proposed" => {
                let table = self.qualified_table("vocabulary_values")?;
                let payload: crate::meta::VocabValueProposedPayload =
                    serde_json::from_value(event.payload.clone())?;
                sqlx::query(&format!(
                    "INSERT INTO {table}(id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)"
                ))
                .bind(&event.subject_id)
                .bind(payload.vocabulary_id)
                .bind(payload.value)
                .bind(payload.gloss)
                .bind(payload.status)
                .bind(payload.ordinal)
                .bind(payload.terminality)
                .bind(payload.metadata)
                .bind(Option::<String>::None)
                .execute(&mut **tx)
                .await?;
            }
            "vocab_value.promoted" | "vocab_value.deprecated" => {
                let table = self.qualified_table("vocabulary_values")?;
                let status = if event.event_type.ends_with("promoted") {
                    "active"
                } else {
                    "deprecated"
                };
                let assignment = if status == "active" {
                    "status=$2,alias_of=NULL"
                } else {
                    "status=$2"
                };
                let result = sqlx::query(&format!("UPDATE {table} SET {assignment} WHERE id=$1"))
                    .bind(&event.subject_id)
                    .bind(status)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.aliased" => {
                let table = self.qualified_table("vocabulary_values")?;
                let payload: crate::meta::VocabValueAliasedPayload =
                    serde_json::from_value(event.payload.clone())?;
                let result = sqlx::query(&format!(
                    "UPDATE {table} SET status='deprecated',alias_of=$2 WHERE id=$1"
                ))
                .bind(&event.subject_id)
                .bind(payload.alias_of)
                .execute(&mut **tx)
                .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.reordered" => {
                let table = self.qualified_table("vocabulary_values")?;
                let payload: crate::meta::VocabValueReorderedPayload =
                    serde_json::from_value(event.payload.clone())?;
                let result = sqlx::query(&format!("UPDATE {table} SET ordinal=$2 WHERE id=$1"))
                    .bind(&event.subject_id)
                    .bind(payload.ordinal)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.gloss_set" => {
                let table = self.qualified_table("vocabulary_values")?;
                let payload: crate::meta::VocabValueGlossSetPayload =
                    serde_json::from_value(event.payload.clone())?;
                let result = sqlx::query(&format!("UPDATE {table} SET gloss=$2 WHERE id=$1"))
                    .bind(&event.subject_id)
                    .bind(payload.gloss)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.metadata_set" => {
                let table = self.qualified_table("vocabulary_values")?;
                let payload: crate::meta::VocabValueMetadataSetPayload =
                    serde_json::from_value(event.payload.clone())?;
                let result = sqlx::query(&format!("UPDATE {table} SET metadata=$2 WHERE id=$1"))
                    .bind(&event.subject_id)
                    .bind(payload.metadata)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "vocab_value.deleted" => {
                let table = self.qualified_table("vocabulary_values")?;
                let result = sqlx::query(&format!("DELETE FROM {table} WHERE id=$1"))
                    .bind(&event.subject_id)
                    .execute(&mut **tx)
                    .await?;
                require_meta_hit(result, event)?;
            }
            "schema_config.set" => {
                let table = self.qualified_table("schema_config")?;
                let payload: crate::meta::SchemaConfigSetPayload =
                    serde_json::from_value(event.payload.clone())?;
                sqlx::query(&format!(
                    "INSERT INTO {table}(id,layer,name,data,applies_to_collection_id,version_lineage,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz) ON CONFLICT(id) DO UPDATE SET layer=EXCLUDED.layer,name=EXCLUDED.name,data=EXCLUDED.data,applies_to_collection_id=EXCLUDED.applies_to_collection_id,version_lineage=EXCLUDED.version_lineage"
                ))
                .bind(&event.subject_id)
                .bind(payload.layer)
                .bind(payload.name)
                .bind(payload.data)
                .bind(payload.applies_to_collection_id)
                .bind(payload.version_lineage)
                .bind(&event.created_at)
                .execute(&mut **tx).await?;
            }
            other => {
                return Err(Error::engine(format!(
                    "unknown Postgres meta event type: {other}"
                )))
            }
        }
        Ok(())
    }

    /// Replace or restore one explicit record policy atomically with its
    /// authoritative policy event.
    pub async fn append_policy_event(&self, event: PostgresPolicyEvent) -> Result<i64> {
        for (field, value) in [
            ("policy event id", event.id.as_str()),
            ("policy record_id", event.record_id.as_str()),
            ("policy actor", event.actor.as_str()),
            ("policy reason", event.reason.as_str()),
        ] {
            validate_nonempty(field, value)?;
        }
        let mut tx = self.pool.begin().await?;
        // The policy cursor is the global writer lock for this independent
        // log. Acquire it before any record lock so parent/child operations
        // cannot invert their target/descendant lock order.
        let seq = self
            .allocate_log_position(&mut tx, PostgresLogKind::Policy)
            .await?;
        let records = self.qualified_table("records")?;
        sqlx::query(&format!("SELECT id FROM {records} WHERE id=$1 FOR UPDATE"))
            .bind(&event.record_id)
            .fetch_one(&mut *tx)
            .await?;
        let events = self.qualified_table("policy_events")?;
        sqlx::query(&format!("INSERT INTO {events}(seq,id,record_id,type,payload,actor,reason,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8::timestamptz)"))
            .bind(seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type)
            .bind(&event.payload).bind(&event.actor).bind(&event.reason).bind(&event.created_at)
            .execute(&mut *tx).await?;
        self.project_policy_event(&mut tx, &event).await?;
        bump_authorization_revision(self, &mut tx).await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(seq)
    }

    async fn project_policy_event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event: &PostgresPolicyEvent,
    ) -> Result<()> {
        let policies = self.qualified_table("record_policies")?;
        let entries = self.qualified_table("policy_entries")?;
        let records = self.qualified_table("records")?;
        match event.event_type.as_str() {
            "policy.replaced" => {
                sqlx::query(&format!("INSERT INTO {policies}(record_id,created_at) VALUES($1,$2::timestamptz) ON CONFLICT(record_id) DO NOTHING"))
                    .bind(&event.record_id).bind(&event.created_at).execute(&mut **tx).await?;
                sqlx::query(&format!("DELETE FROM {entries} WHERE policy_anchor_id=$1"))
                    .bind(&event.record_id)
                    .execute(&mut **tx)
                    .await?;
                let payload = event
                    .payload
                    .as_ref()
                    .ok_or_else(|| Error::engine("policy.replaced requires payload"))?;
                // Reuse the canonical payload codecs so unknown/missing fields
                // cannot be silently normalized into a grant.
                let payload: crate::policy::PolicyReplacedPayload =
                    serde_json::from_value(payload.clone())?;
                let mut prior: Option<&crate::policy::NormalizedPolicyEntry> = None;
                for entry in &payload.entries {
                    let supported = match entry.subject_kind.as_str() {
                        "members" => {
                            entry.subject_id == "native:members"
                                && matches!(entry.capability.as_str(), "view" | "edit")
                        }
                        "account" => {
                            !entry.subject_id.is_empty()
                                && matches!(entry.capability.as_str(), "view" | "edit" | "manage")
                        }
                        _ => false,
                    };
                    if entry.effect != "allow" || !supported {
                        return Err(Error::engine(format!(
                            "unsupported normalized policy entry {}:{} {} {}",
                            entry.subject_kind, entry.subject_id, entry.effect, entry.capability
                        )));
                    }
                    if prior.is_some_and(|value| value >= entry) {
                        return Err(Error::engine(
                            "policy.replaced entries must be unique and canonically sorted",
                        ));
                    }
                    prior = Some(entry);
                    sqlx::query(&format!("INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES($1,$2,$3,$4,$5)"))
                        .bind(&event.record_id).bind(&entry.subject_kind).bind(&entry.subject_id)
                        .bind(&entry.effect).bind(&entry.capability)
                        .execute(&mut **tx).await?;
                }
                propagate_policy_anchor(self, tx, &event.record_id, Some(&event.record_id)).await?;
            }
            "policy.inheritance_restored" => {
                if event.payload.is_some() {
                    return Err(Error::engine(
                        "policy.inheritance_restored must not carry a payload",
                    ));
                }
                if event.record_id == ROOT_RECORD_ID {
                    return Err(Error::engine(
                        "the canonical root policy cannot restore inheritance",
                    ));
                }
                let inherited_anchor: Option<String> = sqlx::query_scalar(&format!(
                    "SELECT parent.policy_anchor_id FROM {records} record LEFT JOIN {records} parent ON parent.id=record.home_id WHERE record.id=$1"
                ))
                .bind(&event.record_id)
                .fetch_optional(&mut **tx)
                .await?
                .flatten();
                if inherited_anchor.is_none() {
                    return Err(Error::engine(
                        "policy inheritance restore requires an effective parent anchor",
                    ));
                }
                let result = sqlx::query(&format!("DELETE FROM {policies} WHERE record_id=$1"))
                    .bind(&event.record_id)
                    .execute(&mut **tx)
                    .await?;
                if result.rows_affected() != 1 {
                    return Err(Error::engine(
                        "policy inheritance restore requires an explicit policy",
                    ));
                }
                propagate_policy_anchor(self, tx, &event.record_id, inherited_anchor.as_deref())
                    .await?;
            }
            other => {
                return Err(Error::engine(format!(
                    "unknown Postgres policy event type: {other}"
                )))
            }
        }
        Ok(())
    }

    /// Append one idempotent control event and atomically store the exact
    /// canonical control projection. The fold is performed by the shared
    /// SQLite projector so Postgres cannot drift into a second state machine.
    pub async fn append_control_event(&self, event: PostgresControlEvent) -> Result<i64> {
        for (field, value) in [
            ("control event id", event.id.as_str()),
            ("control idempotency_key", event.idempotency_key.as_str()),
            ("control type", event.event_type.as_str()),
            ("control aggregate_kind", event.aggregate_kind.as_str()),
            ("control aggregate_id", event.aggregate_id.as_str()),
            ("control actor", event.actor.as_str()),
            ("control reason", event.reason.as_str()),
        ] {
            validate_nonempty(field, value)?;
        }
        if event.schema_version < 1 || !event.payload.is_object() {
            return Err(Error::engine(
                "control event requires a positive schema_version and object payload",
            ));
        }
        let mut canonical_event = crate::control::ControlEventRow {
            seq: 1,
            id: event.id.clone(),
            idempotency_key: event.idempotency_key.clone(),
            event_type: event.event_type.clone(),
            schema_version: event.schema_version,
            aggregate_kind: event.aggregate_kind.clone(),
            aggregate_id: event.aggregate_id.clone(),
            actor: event.actor.clone(),
            run_key: event.run_key.clone(),
            reason: event.reason.clone(),
            payload: serde_json::to_string(&event.payload)?,
            created_at: event.created_at.clone(),
        };
        crate::control::validate_control_event(&canonical_event)?;
        let mut tx = self.pool.begin().await?;
        // Allocate first: this locks the control cursor and serializes every
        // writer before the idempotency re-check. If the key already exists we
        // roll back the tentative cursor update, preserving gaplessness.
        let seq = self
            .allocate_log_position(&mut tx, PostgresLogKind::Control)
            .await?;
        let events = self.qualified_table("control_events")?;
        if let Some(row) = sqlx::query(&format!(
            "SELECT seq, type=$2 AND schema_version=$3 AND aggregate_kind=$4 AND aggregate_id=$5 AND actor=$6 AND reason=$7 AND payload=$8 AS immutable_match FROM {events} WHERE idempotency_key=$1"
        ))
        .bind(&event.idempotency_key)
        .bind(&event.event_type)
        .bind(event.schema_version)
        .bind(&event.aggregate_kind)
        .bind(&event.aggregate_id)
        .bind(&event.actor)
        .bind(&event.reason)
        .bind(&event.payload)
        .fetch_optional(&mut *tx)
        .await?
        {
            let existing_seq: i64 = row.try_get("seq")?;
            let immutable_match: bool = row.try_get("immutable_match")?;
            tx.rollback().await?;
            return if immutable_match {
                Ok(existing_seq)
            } else {
                Err(Error::engine(
                    "control idempotency key already names a different immutable event",
                ))
            };
        }
        canonical_event.seq = seq;
        let rows = sqlx::query(&format!(
            "SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload::text AS payload,created_at FROM {events} ORDER BY seq"
        ))
        .fetch_all(&mut *tx)
        .await?;
        let mut canonical_events = rows
            .into_iter()
            .map(|row| {
                Ok(crate::control::ControlEventRow {
                    seq: row.try_get("seq")?,
                    id: row.try_get("id")?,
                    idempotency_key: row.try_get("idempotency_key")?,
                    event_type: row.try_get("type")?,
                    schema_version: row.try_get("schema_version")?,
                    aggregate_kind: row.try_get("aggregate_kind")?,
                    aggregate_id: row.try_get("aggregate_id")?,
                    actor: row.try_get("actor")?,
                    run_key: row.try_get("run_key")?,
                    reason: row.try_get("reason")?,
                    payload: row.try_get("payload")?,
                    created_at: row
                        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")?
                        .to_rfc3339(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        canonical_events.push(canonical_event);
        let records = self.qualified_table("records")?;
        let record_ids = sqlx::query_scalar(&format!("SELECT id FROM {records} ORDER BY id"))
            .fetch_all(&mut *tx)
            .await?;
        let canonical_projection =
            crate::control::canonical_projection_snapshot(&canonical_events, &record_ids).await?;
        sqlx::query(&format!("INSERT INTO {events}(seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::timestamptz)"))
            .bind(seq).bind(&event.id).bind(&event.idempotency_key).bind(&event.event_type)
            .bind(event.schema_version).bind(&event.aggregate_kind).bind(&event.aggregate_id)
            .bind(&event.actor).bind(&event.run_key).bind(&event.reason).bind(&event.payload).bind(&event.created_at)
            .execute(&mut *tx).await?;
        let projections = self.qualified_table("control_projections")?;
        sqlx::query(&format!("DELETE FROM {projections}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!("INSERT INTO {projections}(aggregate_kind,aggregate_id,event_seq,event_type,schema_version,payload,updated_at) VALUES('canonical_control','state',$1,$2,$3,$4,$5::timestamptz)"))
            .bind(seq).bind(&event.event_type).bind(event.schema_version)
            .bind(&canonical_projection).bind(&event.created_at).execute(&mut *tx).await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(seq)
    }

    pub async fn authoritative_events(
        &self,
        log: PostgresLogKind,
    ) -> Result<Vec<PostgresAuthoritativeEvent>> {
        let mut tx = self.repeatable_read_snapshot().await?;
        let events = self.authoritative_events_on(&mut tx, log).await?;
        tx.commit().await?;
        Ok(events)
    }

    async fn authoritative_events_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        log: PostgresLogKind,
    ) -> Result<Vec<PostgresAuthoritativeEvent>> {
        let table = self.qualified_table(log.relation())?;
        let sql = match log {
            PostgresLogKind::Content => format!(
                "SELECT seq,id,record_id AS subject_id,type,payload,actor,run_key,parent_key,intent,NULL::text AS reason,NULL::text AS idempotency_key,NULL::bigint AS schema_version,NULL::text AS aggregate_kind,created_at FROM {table} ORDER BY seq"
            ),
            PostgresLogKind::Meta => format!(
                "SELECT seq,id,subject_id,type,payload,actor,NULL::text AS run_key,NULL::text AS parent_key,NULL::text AS intent,NULL::text AS reason,NULL::text AS idempotency_key,NULL::bigint AS schema_version,NULL::text AS aggregate_kind,created_at FROM {table} ORDER BY seq"
            ),
            PostgresLogKind::Policy => format!(
                "SELECT seq,id,record_id AS subject_id,type,payload,actor,NULL::text AS run_key,NULL::text AS parent_key,NULL::text AS intent,reason,NULL::text AS idempotency_key,NULL::bigint AS schema_version,NULL::text AS aggregate_kind,created_at FROM {table} ORDER BY seq"
            ),
            PostgresLogKind::Control => format!(
                "SELECT seq,id,aggregate_id AS subject_id,type,payload,actor,run_key,NULL::text AS parent_key,NULL::text AS intent,reason,idempotency_key,schema_version,aggregate_kind,created_at FROM {table} ORDER BY seq"
            ),
        };
        let rows = sqlx::query(&sql).fetch_all(&mut **tx).await?;
        rows.into_iter()
            .map(|row| {
                Ok(PostgresAuthoritativeEvent {
                    log,
                    seq: row.try_get("seq")?,
                    id: row.try_get("id")?,
                    subject_id: row.try_get("subject_id")?,
                    event_type: row.try_get("type")?,
                    payload: row.try_get("payload")?,
                    actor: row.try_get("actor")?,
                    run_key: row.try_get("run_key")?,
                    parent_key: row.try_get("parent_key")?,
                    intent: row.try_get("intent")?,
                    reason: row.try_get("reason")?,
                    idempotency_key: row.try_get("idempotency_key")?,
                    schema_version: row.try_get("schema_version")?,
                    aggregate_kind: row.try_get("aggregate_kind")?,
                    created_at: row
                        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")?
                        .to_rfc3339(),
                })
            })
            .collect()
    }

    pub(super) async fn repeatable_read_snapshot(&self) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Direct-write blob insertion is content-address checked and idempotent.
    /// Conflicting reuse of an id fails without overwriting the prior bytes.
    pub async fn put_blob(&self, blob: &PostgresBlob) -> Result<()> {
        validate_nonempty("blob id", &blob.id)?;
        validate_nonempty("blob sha256", &blob.sha256)?;
        if blob.sha256.len() != 64
            || !blob
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::engine(
                "blob sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        if blob.size_bytes < 0
            || blob
                .bytes
                .as_ref()
                .is_some_and(|bytes| bytes.len() as i64 != blob.size_bytes)
        {
            return Err(Error::engine("blob size_bytes does not match inline bytes"));
        }
        if blob.storage_tier == "inline" && blob.bytes.is_none()
            || blob.storage_tier == "external" && blob.external_ref.is_none()
        {
            return Err(Error::engine(
                "blob storage tier does not match its physical payload",
            ));
        }
        if let Some(bytes) = &blob.bytes {
            let digest = hex::encode(Sha256::digest(bytes));
            if digest != blob.sha256 {
                return Err(Error::engine("blob sha256 does not match inline bytes"));
            }
        }
        let table = self.qualified_table("blobs")?;
        sqlx::query(&format!("INSERT INTO {table}(id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING"))
            .bind(&blob.id).bind(&blob.bytes).bind(&blob.mime).bind(blob.size_bytes).bind(&blob.sha256)
            .bind(&blob.original_filename).bind(&blob.storage_tier).bind(&blob.external_ref)
            .execute(&self.pool).await?;
        let stored = self
            .get_blob(&blob.id)
            .await?
            .ok_or_else(|| Error::engine("blob insert did not persist"))?;
        if stored != *blob {
            return Err(Error::engine("blob id already names different content"));
        }
        Ok(())
    }

    pub async fn get_blob(&self, id: &str) -> Result<Option<PostgresBlob>> {
        let table = self.qualified_table("blobs")?;
        let row = sqlx::query(&format!("SELECT id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,external_ref FROM {table} WHERE id=$1"))
            .bind(id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            Ok(PostgresBlob {
                id: row.try_get("id")?,
                bytes: row.try_get("bytes")?,
                mime: row.try_get("mime")?,
                size_bytes: row.try_get("size_bytes")?,
                sha256: row.try_get("sha256")?,
                original_filename: row.try_get("original_filename")?,
                storage_tier: row.try_get("storage_tier")?,
                external_ref: row.try_get("external_ref")?,
            })
        })
        .transpose()
    }

    /// Return the durable origin identity, minting it exactly once under a
    /// transaction-scoped advisory lock. The audit row and singleton become
    /// visible atomically, so concurrent openers cannot observe two origins.
    pub async fn ensure_database_identity(&self, actor: &str, reason: &str) -> Result<String> {
        validate_nonempty("database identity actor", actor)?;
        validate_nonempty("database identity reason", reason)?;
        let identity = self.qualified_table("database_identity")?;
        let audit = self.qualified_table("database_identity_audit")?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('native.database_identity',0))")
            .execute(&mut *tx)
            .await?;
        if let Some(origin) = sqlx::query_scalar::<_, String>(&format!(
            "SELECT origin_db_id FROM {identity} WHERE singleton=1 FOR UPDATE"
        ))
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.commit().await?;
            return Ok(origin);
        }
        let origin = format!("ndb_{}", Uuid::new_v4().simple());
        sqlx::query(&format!(
            "INSERT INTO {identity}(singleton,origin_db_id,created_at) VALUES(1,$1,transaction_timestamp())"
        ))
        .bind(&origin)
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {audit}(id,action,new_origin_db_id,actor,reason,created_at) VALUES($1,'mint',$2,$3,$4,transaction_timestamp())"
        ))
        .bind(Uuid::new_v4().to_string())
        .bind(&origin)
        .bind(actor)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(origin)
    }

    pub async fn logical_snapshot(&self) -> Result<Value> {
        let mut tx = self.repeatable_read_snapshot().await?;
        let mut snapshot = self.authoritative_projection_snapshot_on(&mut tx).await?;
        let object = snapshot.as_object_mut().expect("snapshot object");
        object.insert(
            "direct".into(),
            json!({
                "bindings": self.json_rows_on(&mut tx, "bindings", "record_id,system,identifier").await?,
                "binding_audit": self.json_rows_on(&mut tx, "binding_audit", "seq").await?,
                "blobs": self.json_rows_on(&mut tx, "blobs", "id").await?,
                "database_identity": self.json_rows_on(&mut tx, "database_identity", "singleton").await?,
                "database_identity_audit": self.json_rows_on(&mut tx, "database_identity_audit", "seq").await?,
                "authorization_revision": self.json_rows_on(&mut tx, "authorization_revision", "id").await?,
            }),
        );
        tx.commit().await?;
        Ok(snapshot)
    }

    pub(crate) async fn authoritative_projection_snapshot(&self) -> Result<Value> {
        let mut tx = self.repeatable_read_snapshot().await?;
        let snapshot = self.authoritative_projection_snapshot_on(&mut tx).await?;
        tx.commit().await?;
        Ok(snapshot)
    }

    pub(super) async fn authoritative_projection_snapshot_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Value> {
        self.validate_log_integrity_on(tx).await?;
        let mut logs = serde_json::Map::new();
        for log in PostgresLogKind::ALL {
            logs.insert(
                log.as_str().into(),
                serde_json::to_value(self.authoritative_events_on(tx, log).await?)?,
            );
        }
        Ok(json!({
            "format": "native.postgres-logical-snapshot.v1",
            "cursors": {
                "content_compatibility": self.json_rows_on(tx, "event_cursor", "singleton").await?,
                "authoritative": self.json_rows_on(tx, "log_cursors", "log_name").await?,
            },
            "logs": logs,
            "adjunct_logs": {
                "notification_candidate_events": self.json_rows_on(tx, "notification_candidate_events", "seq").await?,
            },
            "identity": {
                "binding_audit": self.json_rows_on(tx, "binding_audit", "seq").await?,
                "bindings": self.json_rows_on(tx, "bindings", "record_id,system,identifier").await?,
            },
            "content": self.canonical_state_on(tx).await?,
            "projections": {
                "links": self.json_rows_on(tx, "links", "id").await?,
                "vocabularies": self.json_rows_on(tx, "vocabularies", "id").await?,
                "vocabulary_values": self.json_rows_on(tx, "vocabulary_values", "id").await?,
                "schema_config": self.json_rows_on(tx, "schema_config", "id").await?,
                "record_policies": self.json_selected_rows_on(tx, "record_policies", "record_id", "record_id").await?,
                "policy_entries": self.json_rows_on(tx, "policy_entries", "policy_anchor_id,subject_kind,subject_id,effect").await?,
                "control_projections": self.json_rows_on(tx, "control_projections", "aggregate_kind,aggregate_id").await?,
                "notification_candidates": self.json_rows_on(tx, "notification_candidates", "candidate_key").await?,
            }
        }))
    }

    async fn validate_log_integrity_on(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        let cursors = self.qualified_table("log_cursors")?;
        for log in PostgresLogKind::ALL {
            let events = self.qualified_table(log.relation())?;
            let row = sqlx::query(&format!(
                "SELECT COUNT(*) AS count,COALESCE(MIN(seq),0) AS minimum,COALESCE(MAX(seq),0) AS maximum FROM {events}"
            ))
            .fetch_one(&mut **tx)
            .await?;
            let count: i64 = row.try_get("count")?;
            let minimum: i64 = row.try_get("minimum")?;
            let maximum: i64 = row.try_get("maximum")?;
            let cursor: i64 =
                sqlx::query_scalar(&format!("SELECT last_seq FROM {cursors} WHERE log_name=$1"))
                    .bind(log.as_str())
                    .fetch_one(&mut **tx)
                    .await?;
            if cursor != maximum || count != maximum || (count > 0 && minimum != 1) {
                return Err(Error::engine(format!(
                    "Postgres {} log cursor/sequence integrity failed: cursor={cursor} count={count} min={minimum} max={maximum}",
                    log.as_str()
                )));
            }
            if log == PostgresLogKind::Content {
                let compatibility = self.qualified_table("event_cursor")?;
                let compatibility_cursor: i64 = sqlx::query_scalar(&format!(
                    "SELECT last_seq FROM {compatibility} WHERE singleton=TRUE"
                ))
                .fetch_one(&mut **tx)
                .await?;
                if compatibility_cursor != cursor {
                    return Err(Error::engine(format!(
                        "Postgres content compatibility cursor diverged: event_cursor={compatibility_cursor} log_cursor={cursor}"
                    )));
                }
            }
        }
        let binding_audit = self.qualified_table("binding_audit")?;
        let row = sqlx::query(&format!(
            "SELECT COUNT(*) AS count,COALESCE(MIN(seq),0) AS minimum,COALESCE(MAX(seq),0) AS maximum FROM {binding_audit}"
        ))
        .fetch_one(&mut **tx)
        .await?;
        let count: i64 = row.try_get("count")?;
        let minimum: i64 = row.try_get("minimum")?;
        let maximum: i64 = row.try_get("maximum")?;
        if count != maximum || (count > 0 && minimum != 1) {
            return Err(Error::engine(format!(
                "Postgres binding audit sequence integrity failed: count={count} min={minimum} max={maximum}"
            )));
        }
        Ok(())
    }

    async fn json_rows_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        table: &str,
        order: &str,
    ) -> Result<Value> {
        let table = self.qualified_table(table)?;
        // Both table and ordering expressions are source-static callers of
        // this private helper; runtime values never enter SQL identifiers.
        Ok(sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(ordered) ORDER BY {order}), '[]'::jsonb) FROM (SELECT * FROM {table}) ordered"
        ))
        .fetch_one(&mut **tx)
        .await?)
    }

    async fn json_selected_rows_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        table: &str,
        columns: &str,
        order: &str,
    ) -> Result<Value> {
        let table = self.qualified_table(table)?;
        Ok(sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(ordered) ORDER BY {order}), '[]'::jsonb) FROM (SELECT {columns} FROM {table}) ordered"
        ))
        .fetch_one(&mut **tx)
        .await?)
    }
}

async fn bump_authorization_revision(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    let table = db.qualified_table("authorization_revision")?;
    sqlx::query(&format!("UPDATE {table} SET epoch=epoch+1 WHERE id=1"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn require_meta_hit(
    result: sqlx::postgres::PgQueryResult,
    event: &PostgresMetaEvent,
) -> Result<()> {
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "meta event {} ({}) matched no row: subject {} does not exist",
            event.id, event.event_type, event.subject_id
        )))
    }
}

async fn propagate_policy_anchor(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
    root_id: &str,
    anchor_id: Option<&str>,
) -> Result<()> {
    let records = db.qualified_table("records")?;
    let policies = db.qualified_table("record_policies")?;
    let descendants: Vec<String> = sqlx::query_scalar(&format!(
        "WITH RECURSIVE inheriting(id) AS (\
         SELECT id FROM {records} WHERE id=$1 \
         UNION ALL \
         SELECT child.id FROM {records} child \
         JOIN inheriting parent ON child.home_id=parent.id \
         WHERE NOT EXISTS(SELECT 1 FROM {policies} explicit WHERE explicit.record_id=child.id)\
         ) SELECT record.id FROM {records} record JOIN inheriting ON inheriting.id=record.id \
         ORDER BY record.id COLLATE \"C\" FOR UPDATE OF record"
    ))
    .bind(root_id)
    .fetch_all(&mut **tx)
    .await?;
    sqlx::query(&format!(
        "UPDATE {records} SET policy_anchor_id=$2 WHERE id=ANY($1::text[])"
    ))
    .bind(descendants)
    .bind(anchor_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::engine(format!("{field} cannot be empty")))
    } else {
        Ok(())
    }
}
