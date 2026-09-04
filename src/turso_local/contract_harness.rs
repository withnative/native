//! Test-only physical seams for the shared backend contract.
//!
//! The contract harness dispatches every observable operation through the
//! shipped `TursoLocalDb` engine handlers. These helpers exist only for the
//! backend-neutral fixture capabilities that are not product tools and for
//! rebuilding production authoritative state with Turso's own projector.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;

#[derive(Clone, Debug)]
struct CandidateReplayEvent {
    seq: i64,
    id: String,
    candidate_key: String,
    action: String,
    recipient_account_id: String,
    message_id: String,
    reason: String,
    priority: String,
    not_before: Option<String>,
    redaction_class: String,
    evaluator_kind: String,
    policy_version: String,
    source_event_type: String,
    source_event_id: String,
    payload: String,
    created_at: String,
}

#[derive(Clone, Debug)]
struct BindingAuditEvent {
    seq: i64,
    id: String,
    action: String,
    system: String,
    identifier: String,
    old_record_id: Option<String>,
    new_record_id: Option<String>,
    old_canonical: Option<i64>,
    new_canonical: Option<i64>,
    actor: String,
    reason: String,
    run_key: Option<String>,
    parent_key: Option<String>,
    intent: Option<String>,
    created_at: String,
}

impl TursoLocalDb {
    pub async fn contract_install_ineligible_facet_records_for_test(&self) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute(
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
                (),
            )
            .await
            .map_err(|error| Error::engine(format!("insert ineligible facet records: {error}")))?;
        self.connect()?
            .execute(
                "INSERT INTO links(id,source_id,target_id,relationship) VALUES
                 ('facet:link-target-mismatch','facet:target-mismatch','facet:comment-bearer-a','part_of'),
                 ('facet:link-root','facet:root-comment','facet:comment-bearer-a','part_of'),
                 ('facet:link-targeted-reply','facet:targeted-reply','facet:root-comment','part_of'),
                 ('facet:link-reply-one','facet:reply-one','facet:root-comment','part_of'),
                 ('facet:link-reply-two','facet:reply-on-reply','facet:reply-one','part_of')",
                (),
            )
            .await
            .map_err(|error| Error::engine(format!("insert malformed facet links: {error}")))?;
        self.connect()?
            .execute(
                "INSERT INTO annotation_targets(annotation_id,target_record_id,source_slot,source_event_seq,source_sha256,selectors,created_at,updated_at) VALUES
                 ('facet:target-mismatch','facet:comment-bearer-b','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
                 ('facet:root-comment','facet:comment-bearer-a','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z'),
                 ('facet:targeted-reply','facet:comment-bearer-a','body',0,'0000000000000000000000000000000000000000000000000000000000000000','[]','2026-08-17T00:00:00.000Z','2026-08-17T00:00:00.000Z')",
                (),
            )
            .await
            .map_err(|error| Error::engine(format!("insert malformed facet targets: {error}")))?;
        Ok(())
    }

    pub async fn contract_install_hidden_scoped_facet_schema_for_test(
        &self,
        scope_id: &str,
    ) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        let data = serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"private-only":{"values":["secret"]}}}}}).to_string();
        self.connect()?
            .execute(
                "INSERT INTO schema_config(id,layer,name,data,applies_to_collection_id,created_at) VALUES('contract:hidden-facet-schema','user','Hidden facet schema',?1,?2,'2026-08-17T00:00:00.000Z')",
                turso::params![data, scope_id],
            )
            .await
            .map_err(|error| Error::engine(format!("insert hidden facet schema: {error}")))?;
        Ok(())
    }

    pub async fn contract_facet_event_count_for_test(&self, record_id: &str) -> Result<i64> {
        let connection = self.connect()?;
        let mut rows = connection
            .query(
                "SELECT COUNT(*) FROM content_events WHERE record_id=?1 AND type IN ('facet.set','facet.unset')",
                [record_id],
            )
            .await
            .map_err(|error| Error::engine(format!("count facet events: {error}")))?;
        rows.next()
            .await
            .map_err(|error| Error::engine(format!("read facet event count: {error}")))?
            .ok_or_else(|| Error::engine("facet event count row missing"))?
            .get::<i64>(0)
            .map_err(|error| Error::engine(format!("decode facet event count: {error}")))
    }

    pub async fn contract_install_facet_governance_fixture_for_test(&self) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|error| Error::engine(format!("begin facet fixture: {error}")))?;
        let result = async {
            connection.execute("INSERT INTO vocabularies(id,name,created_at) VALUES('voc:contract-confidence','contract-confidence','2026-08-17T00:00:00.000Z')", ()).await
                .map_err(|error| Error::engine(format!("insert facet vocabulary: {error}")))?;
            for (id, value, ordinal, terminality, status) in [
                ("vv:contract-confidence:likely", "likely", 100.0, "open", "active"),
                ("vv:contract-confidence:probable", "probable", 100.0, "open", "active"),
                ("vv:contract-confidence:unicode-z", "Ångström", 150.0, "open", "active"),
                ("vv:contract-confidence:unicode-a", "äther", 150.0, "open", "active"),
                ("vv:contract-confidence:won", "won", 200.0, "terminal_positive", "active"),
                ("vv:contract-confidence:speculative", "speculative", 300.0, "open", "proposed"),
            ] {
                connection.execute(
                    "INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) VALUES(?1,'voc:contract-confidence',?2,?3,?4,?5,'{}')",
                    turso::params![id, value, status, ordinal, terminality],
                ).await.map_err(|error| Error::engine(format!("insert facet vocabulary value: {error}")))?;
            }
            connection.execute("UPDATE vocabulary_values SET alias_of='vv:contract-confidence:likely' WHERE id='vv:contract-confidence:probable'", ()).await
                .map_err(|error| Error::engine(format!("alias facet vocabulary value: {error}")))?;
            let data = serde_json::json!({"shapes":{"WorkItem":{"facets":{"score":{"type":"number"},"effort":{"values":["s","m"]},"confidence":{"vocab":"contract-confidence"},"mandatory":{"required":true}}}}}).to_string();
            connection.execute(
                "INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('contract:facet-schema','user','Contract facet schema',?1,'2026-08-17T00:00:00.000Z')",
                [data],
            ).await.map_err(|error| Error::engine(format!("insert facet schema: {error}")))?;
            Ok::<_, Error>(())
        }.await;
        if let Err(error) = result {
            let _ = connection.execute("ROLLBACK", ()).await;
            return Err(error);
        }
        connection
            .execute("COMMIT", ())
            .await
            .map_err(|error| Error::engine(format!("commit facet fixture: {error}")))?;
        Ok(())
    }

    pub async fn contract_install_facet_bounds_overflow_for_test(
        &self,
        record_id: &str,
    ) -> Result<()> {
        const NUMBERS: &str = "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)), numbers(n) AS (SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d CROSS JOIN digits e WHERE a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d <= 10000) ";
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|error| Error::engine(format!("begin facet overflow fixture: {error}")))?;
        let result = async {
            connection
                .execute(
                    &format!(
                        "{NUMBERS}INSERT INTO facet_values(id,record_id,\"key\",value) SELECT printf('facet-overflow:%05d',n),?1,printf('overflow_%05d',n),'value' FROM numbers"
                    ),
                    [record_id.to_string()],
                )
                .await
                .map_err(|error| Error::engine(format!("insert facet overflow values: {error}")))?;
            connection.execute("INSERT INTO vocabularies(id,name,created_at) VALUES('voc:contract-facet-overflow','contract-facet-overflow','2026-08-17T00:00:00.000Z')", ()).await
                .map_err(|error| Error::engine(format!("insert facet overflow vocabulary: {error}")))?;
            connection
                .execute(
                    &format!(
                        "{NUMBERS}INSERT INTO vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) SELECT printf('vv:contract-facet-overflow:%05d',n),'voc:contract-facet-overflow',printf('choice_%05d',n),'active',n,'open','{{}}' FROM numbers"
                    ),
                    (),
                )
                .await
                .map_err(|error| Error::engine(format!("insert facet overflow vocabulary values: {error}")))?;
            let data = serde_json::json!({"shapes":{"Document:facet_limits":{"facets":{"choice":{"vocab":"contract-facet-overflow"}}}}}).to_string();
            connection.execute(
                "INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('contract:facet-overflow-schema','user','Contract facet overflow schema',?1,'2026-08-17T00:00:00.000Z')",
                [data],
            ).await.map_err(|error| Error::engine(format!("insert facet overflow schema: {error}")))?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            let _ = connection.execute("ROLLBACK", ()).await;
            return Err(error);
        }
        connection
            .execute("COMMIT", ())
            .await
            .map_err(|error| Error::engine(format!("commit facet overflow fixture: {error}")))?;
        Ok(())
    }

    /// Install the imported/legacy archived-container shape used by the
    /// shared descendant-pruning receipt.
    pub async fn contract_mark_record_archived_for_test(&self, record_id: &str) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute(
                "INSERT INTO facet_values(id,record_id,\"key\",value) VALUES(?1,?2,'archived','true')",
                [format!("fixture:archived:{record_id}"), record_id.to_string()],
            )
            .await
            .map_err(|error| Error::engine(format!("install archived fixture: {error}")))?;
        Ok(())
    }

    /// Rehome one projection fixture below a governed hidden record.
    pub async fn contract_rehome_record_for_test(
        &self,
        record_id: &str,
        home_id: &str,
    ) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute(
                "UPDATE records SET home_id=?1 WHERE id=?2",
                [home_id.to_string(), record_id.to_string()],
            )
            .await
            .map_err(|error| Error::engine(format!("install rehome fixture: {error}")))?;
        Ok(())
    }

    /// Install one bounded-overflow dependency fan-out directly in the
    /// physical projection. The shared receipt observes it only through the
    /// shipped scoped dashboard handler.
    pub async fn contract_create_dashboard_link_overflow_for_test(
        &self,
        source_id: &str,
    ) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|error| Error::engine(format!("begin dashboard overflow fixture: {error}")))?;
        let result = async {
            const DIGITS: &str = "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)), numbers(n) AS (SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d CROSS JOIN digits e WHERE a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d <= 10000) ";
            connection
                .execute(
                    &format!(
                        "{DIGITS}INSERT INTO records(id,type,kind,name,policy_anchor_id) SELECT printf('dashboard-overflow-target:%05d',n),'Document','note','Dashboard overflow target','native:root' FROM numbers"
                    ),
                    (),
                )
                .await
                .map_err(|error| Error::engine(format!("insert dashboard overflow records: {error}")))?;
            connection
                .execute(
                    &format!(
                        "{DIGITS}INSERT INTO links(id,source_id,target_id,relationship) SELECT printf('dashboard-overflow-link:%05d',n),?1,printf('dashboard-overflow-target:%05d',n),'depends_on' FROM numbers"
                    ),
                    [source_id.to_string()],
                )
                .await
                .map_err(|error| Error::engine(format!("insert dashboard overflow links: {error}")))?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            let _ = connection.execute("ROLLBACK", ()).await;
            return Err(error);
        }
        connection.execute("COMMIT", ()).await.map_err(|error| {
            Error::engine(format!("commit dashboard overflow fixture: {error}"))
        })?;
        Ok(())
    }

    pub async fn contract_create_search_hidden_overflow_for_test(
        &self,
        home_id: &str,
        policy_anchor_id: &str,
    ) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        const DIGITS: &str = "WITH digits(d) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)), numbers(n) AS (SELECT a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d CROSS JOIN digits e WHERE a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d <= 10000) ";
        // Turso's experimental FTS writer has a bounded segment reload seam;
        // keep the fixture realistic by committing small index batches rather
        // than relying on one synthetic 10k-row statement.
        for start in (0..=10_000).step_by(250) {
            let end = (start + 249).min(10_000);
            connection
                .execute("BEGIN IMMEDIATE", ())
                .await
                .map_err(|error| {
                    Error::engine(format!("begin search overflow fixture: {error}"))
                })?;
            let inserted = connection
                .execute(
                    &format!(
                        "{DIGITS}INSERT INTO records(id,type,kind,name,body,home_id,policy_anchor_id) SELECT printf('aaa:search-hidden:%05d',n),'Document','note','Meeting hidden overflow','meeting',?1,?2 FROM numbers WHERE n BETWEEN {start} AND {end}"
                    ),
                    [home_id.to_string(), policy_anchor_id.to_string()],
                )
                .await;
            if let Err(error) = inserted {
                let _ = connection.execute("ROLLBACK", ()).await;
                return Err(Error::engine(format!(
                    "insert search overflow records: {error}"
                )));
            }
            connection.execute("COMMIT", ()).await.map_err(|error| {
                Error::engine(format!("commit search overflow record batch: {error}"))
            })?;
        }
        connection
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(|error| {
                Error::engine(format!("begin search link overflow fixture: {error}"))
            })?;
        let links = connection
                .execute(
                    &format!(
                        "{DIGITS}INSERT INTO links(id,source_id,target_id,relationship) SELECT printf('aaa:search-hidden-link:%05d',n),printf('aaa:search-hidden:%05d',n),?1,'relates_to' FROM numbers"
                    ),
                    [policy_anchor_id.to_string()],
                )
                .await;
        if let Err(error) = links {
            let _ = connection.execute("ROLLBACK", ()).await;
            return Err(Error::engine(format!(
                "insert search overflow links: {error}"
            )));
        }
        connection
            .execute("COMMIT", ())
            .await
            .map_err(|error| Error::engine(format!("commit search overflow fixture: {error}")))?;
        Ok(())
    }

    pub async fn contract_seed_delete_candidate_state(&self, message_id: &str) -> Result<()> {
        let policy_record_id = message_id.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                append_replacement_policy(
                    transaction,
                    &policy_record_id,
                    &[json!({
                        "subject_kind":"account",
                        "subject_id":"acct:retained",
                        "effect":"allow",
                        "capability":"manage"
                    })],
                    "contract",
                    "Retain an authoritative explicit policy across Message deletion.",
                )
                .await
            })
        })
        .await?;
        let _write = self.inner.write_gate.lock().await;
        let connection = self.connect()?;
        let now = crate::store::now_iso();
        connection.execute("INSERT INTO notification_candidate_events(id,candidate_key,action,recipient_account_id,message_id,reason,priority,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES('candidate:proposed','candidate:key','proposed','acct:recipient',?1,'routine_arrival','routine','metadata_only','portable_default','v1','message.delivered','delivery:event','{\"schema\":\"native.notification-candidate.v1\"}',?2)", [message_id, now.as_str()]).await.map_err(|error| Error::engine(format!("seed candidate event failed: {error}")))?;
        let mut rows = connection
            .query(
                "SELECT seq FROM notification_candidate_events WHERE id='candidate:proposed'",
                (),
            )
            .await
            .map_err(|error| Error::engine(format!("read candidate event failed: {error}")))?;
        let seq = rows
            .next()
            .await
            .map_err(|error| Error::engine(format!("read candidate event failed: {error}")))?
            .ok_or_else(|| Error::engine("seeded candidate event missing"))?
            .get::<i64>(0)
            .map_err(|error| Error::engine(format!("invalid candidate seq: {error}")))?;
        connection.execute("INSERT INTO notification_candidates(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES('candidate:proposed','candidate:key','acct:recipient',?1,'routine_arrival','routine','metadata_only','portable_default','v1','message.delivered','delivery:event',?2,'effective',?3)", turso::params![message_id, seq, now]).await.map_err(|error| Error::engine(format!("seed candidate projection failed: {error}")))?;
        Ok(())
    }

    pub async fn contract_delete_adjunct_state(&self, message_id: &str) -> Result<Value> {
        let connection = self.connect()?;
        let mut rows = connection.query("SELECT (SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?1 AND subject_id='acct:retained'),(SELECT COUNT(*) FROM links WHERE source_id=?1),candidate.status,event.action,event.source_event_type,event.source_event_id,(SELECT id FROM content_events WHERE record_id=?1 AND type='record.deleted') FROM notification_candidates candidate JOIN notification_candidate_events event ON event.seq=candidate.candidate_event_seq WHERE candidate.candidate_id='candidate:proposed'", [message_id]).await.map_err(|error| Error::engine(format!("read retained delete adjunct state failed: {error}")))?;
        let row = rows
            .next()
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "read retained delete adjunct state failed: {error}"
                ))
            })?
            .ok_or_else(|| Error::engine("retained delete adjunct state missing"))?;
        Ok(json!({
            "policy_entries": row.get::<i64>(0).map_err(|error| Error::engine(format!("invalid policy count: {error}")))?,
            "links": row.get::<i64>(1).map_err(|error| Error::engine(format!("invalid link count: {error}")))?,
            "status": row.get::<String>(2).map_err(|error| Error::engine(format!("invalid candidate status: {error}")))?,
            "action": row.get::<String>(3).map_err(|error| Error::engine(format!("invalid candidate action: {error}")))?,
            "source_event_type": row.get::<String>(4).map_err(|error| Error::engine(format!("invalid candidate source type: {error}")))?,
            "source_event_id": row.get::<String>(5).map_err(|error| Error::engine(format!("invalid candidate source id: {error}")))?,
            "deletion_event_id": row.get::<String>(6).map_err(|error| Error::engine(format!("invalid deletion event id: {error}")))?,
        }))
    }

    pub async fn contract_activate_instruction_source_for_test(
        &self,
        record_id: &str,
        binding_id: &str,
    ) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        let now = crate::store::now_iso();
        self.connect()?
            .execute(
                "INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) VALUES(?1,'database','native:root',?2,0,1,'contract',?3,?3)",
                [binding_id.to_string(), record_id.to_string(), now],
            )
            .await
            .map_err(|error| Error::engine(format!("activate contract instruction source failed: {error}")))?;
        Ok(())
    }

    /// Append a governed attribution fixture through the authoritative content
    /// log so replay remains a valid assertion for the shared contract.
    pub async fn contract_create_attribution_record_for_test(&self, record_id: &str) -> Result<()> {
        let record_id = record_id.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                <TursoDomainTransaction<'_> as AttachmentPhysicalPort>::append_content(
                    transaction,
                    AppendSpec {
                        record_id: record_id.clone(),
                        event_type: "record.created".into(),
                        payload: json!({
                            "type":"Annotation",
                            "kind":"attribution",
                            "name":"Contract attribution",
                            "home_id":crate::schema::UNFILED_RECORD_ID,
                            "persistence":"enduring",
                            "reason":"Exercise portable attribution prefix exclusion."
                        }),
                        actor: None,
                    },
                )
                .await?;
                <TursoDomainTransaction<'_> as AttachmentPhysicalPort>::append_content(
                    transaction,
                    AppendSpec {
                        record_id: record_id.clone(),
                        event_type: "link.added".into(),
                        payload: json!({
                            "source_id":record_id,
                            "target_id":crate::schema::ROOT_RECORD_ID,
                            "relationship":"part_of",
                            "reason":"Bind attribution authorization to its bearer."
                        }),
                        actor: None,
                    },
                )
                .await
            })
        })
        .await
    }

    /// Append one record the way an older build left it behind: a projected
    /// `record.created` carrying a caller-chosen, non-UUID id. Today's
    /// admission rule refuses such an id, but databases written before it
    /// still hold them, so boundary behaviour (prefix resolution in
    /// particular) must keep answering for them. The event goes through the
    /// authoritative log and Turso's own projector, so replay equivalence
    /// still holds; only the id admission check is bypassed.
    pub async fn contract_create_historical_record_for_test(
        &self,
        record_id: &str,
        name: &str,
    ) -> Result<()> {
        let record_id = record_id.to_string();
        let name = name.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                let payload = json!({
                    "type":"Document",
                    "kind":"note",
                    "name":name,
                    "home_id":crate::schema::UNFILED_RECORD_ID,
                    "persistence":"enduring"
                });
                let payload = crate::domain_transaction::normalize_event_payload(
                    &record_id,
                    "record.created",
                    payload,
                );
                let mut event = EventRow {
                    local_seq: -1,
                    id: uuid::Uuid::new_v4().to_string(),
                    record_id,
                    event_type: "record.created".into(),
                    payload: Some(serde_json::to_string(&payload)?),
                    actor: Some("engine:migration".into()),
                    run_key: None,
                    parent_key: None,
                    intent: None,
                    created_at: crate::store::now_iso(),
                    causal_envelope: CausalEnvelopeV1::complete(CausalFrontierV1::empty()),
                };
                let control = transaction.control.clone();
                let intent = ProjectorIntent::from_event(&event)?;
                event.local_seq = transaction
                    .append_event(&mut event, &CausalAdmission::LocalComputed, &control)
                    .await?;
                transaction.apply_projector(&intent, &event, &control).await
            })
        })
        .await
    }

    /// Create governed suggestion projection fixtures through the same
    /// authoritative event fold used by production writes.
    pub async fn contract_create_suggestion_record_for_test(
        &self,
        record_id: &str,
        bearer_id: Option<&str>,
        home_id: Option<&str>,
        tombstoned: bool,
    ) -> Result<()> {
        let record_id = record_id.to_string();
        let bearer_id = bearer_id.map(str::to_string);
        let home_id = home_id.map(str::to_string);
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                transaction
                    .append_content(AppendSpec {
                        record_id: record_id.clone(),
                        event_type: "record.created".into(),
                        payload: json!({
                            "type":"Annotation",
                            "kind":"suggestion",
                            "name":"Contract suggestion",
                            "home_id":home_id,
                            "persistence":"enduring",
                            "reason":"Exercise portable render suggestion counting."
                        }),
                        actor: None,
                    })
                    .await?;
                if let Some(bearer_id) = bearer_id {
                    transaction
                        .append_content(AppendSpec {
                            record_id: record_id.clone(),
                            event_type: "link.added".into(),
                            payload: json!({
                                "source_id":record_id,
                                "target_id":bearer_id,
                                "relationship":"part_of"
                            }),
                            actor: None,
                        })
                        .await?;
                }
                if tombstoned {
                    transaction
                        .append_content(AppendSpec {
                            record_id,
                            event_type: "record.deleted".into(),
                            payload: json!({}),
                            actor: None,
                        })
                        .await?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Physical query-plan probe for the record-reference range contract.
    pub async fn contract_record_reference_query_plan_for_test(&self) -> Result<Vec<String>> {
        let connection = self.connect()?;
        let mut rows = connection
            .query(
                "EXPLAIN QUERY PLAN SELECT id FROM records \
                 WHERE id >= ?1 AND id < ?2 AND deleted_at IS NULL \
                 AND length(id) = ?3 ORDER BY id LIMIT ?4",
                turso::params!["abc123", "abc123g", 36_i64, 257_i64],
            )
            .await
            .map_err(|error| {
                Error::engine(format!("cannot plan Turso record-reference range: {error}"))
            })?;
        let mut plan = Vec::new();
        while let Some(row) = rows.next().await.map_err(|error| {
            Error::engine(format!("cannot read Turso record-reference plan: {error}"))
        })? {
            plan.push(row.get::<String>(3).map_err(|error| {
                Error::engine(format!(
                    "cannot decode Turso record-reference plan: {error}"
                ))
            })?);
        }
        Ok(plan)
    }

    /// Physical plan proof for the backend-native search boundary.
    pub async fn contract_search_query_plan_for_test(&self) -> Result<Vec<String>> {
        let connection = self.connect()?;
        let mut rows = connection
            .query(
                "EXPLAIN QUERY PLAN SELECT id FROM records WHERE name MATCH ?1 ORDER BY id",
                turso::params!["meeting"],
            )
            .await
            .map_err(|error| Error::engine(format!("cannot plan Turso native search: {error}")))?;
        let mut plan = Vec::new();
        while let Some(row) = rows.next().await.map_err(|error| {
            Error::engine(format!("cannot read Turso native search plan: {error}"))
        })? {
            plan.push(row.get::<String>(3).map_err(|error| {
                Error::engine(format!("cannot decode Turso native search plan: {error}"))
            })?);
        }
        Ok(plan)
    }

    /// Count physical blob rows without making substrate storage a product
    /// operation. Attachment receipts pair this with observable list/read
    /// assertions to prove rollback and detach retention.
    pub async fn contract_blob_count_for_test(&self) -> Result<i64> {
        let _write = self.inner.write_gate.lock().await;
        let mut rows = self
            .connect()?
            .query("SELECT COUNT(*) FROM blobs", ())
            .await
            .map_err(|error| Error::engine(format!("Turso blob count probe failed: {error}")))?;
        let row = rows
            .next()
            .await
            .map_err(|error| Error::engine(format!("Turso blob count probe failed: {error}")))?
            .ok_or_else(|| Error::engine("Turso blob count probe returned no count"))?;
        row.get(0)
            .map_err(|error| Error::engine(format!("invalid Turso blob count: {error}")))
    }

    /// Physical liveness probe used only by the attachment URL preflight
    /// contract. It creates an initial tombstone without routing through the
    /// request lifecycle so the test can isolate the guarded-fetch boundary.
    pub async fn contract_tombstone_record_for_test(&self, record_id: &str) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute(
                "UPDATE records SET deleted_at=?1 WHERE id=?2",
                [crate::store::now_iso(), record_id.to_string()],
            )
            .await
            .map_err(|error| Error::engine(format!("tombstone contract record failed: {error}")))?;
        Ok(())
    }

    /// Replace a fixture record's inherited policy through the authoritative
    /// policy event and Turso projector. This is setup for authorization-bound
    /// URL preflight tests; it never writes policy projections directly.
    pub async fn contract_restrict_record_to_account_for_test(
        &self,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        let record_id = record_id.to_string();
        let account_id = account_id.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                append_replacement_policy(
                    transaction,
                    &record_id,
                    &[json!({
                        "subject_kind": "account",
                        "subject_id": account_id,
                        "effect": "allow",
                        "capability": "edit"
                    })],
                    "contract:attachment-policy",
                    "Restrict the URL preflight fixture to its owner.",
                )
                .await
            })
        })
        .await
    }

    /// Install exact authoritative meta-log fixtures and their projections in
    /// one admitted write. `manage_vocabularies` and `manage_schema_config`
    /// are not yet qualified Turso routes, so the shared describe-schema test
    /// uses this narrow seam to prove live governed state rather than genesis.
    #[allow(clippy::too_many_arguments)]
    pub async fn contract_install_describe_schema_fixture_for_test(
        &self,
        hidden_collection_id: &str,
        kind_id: &str,
        kind_payload: Value,
        global_config_id: &str,
        global_config_data: String,
        hidden_config_id: &str,
        hidden_config_data: String,
    ) -> Result<()> {
        let hidden_collection_id = hidden_collection_id.to_string();
        let kind_id = kind_id.to_string();
        let global_config_id = global_config_id.to_string();
        let hidden_config_id = hidden_config_id.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                let now = crate::store::now_iso();
                let append_event = statement(
                    StatementKind::Insert,
                    "meta_events",
                    &[
                        "INSERT INTO {{relation}} (id,subject_id,type,payload,actor,created_at) VALUES (",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ")",
                    ],
                )
                .map_err(|error| stable("append describe-schema fixture", error))?;
                let insert_kind = statement(
                    StatementKind::Insert,
                    "vocabulary_values",
                    &[
                        "INSERT INTO {{relation}} (id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata) VALUES (",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ", ",
                        ")",
                    ],
                )
                .map_err(|error| stable("project describe-schema kind", error))?;
                let insert_config = statement(
                    StatementKind::Insert,
                    "schema_config",
                    &[
                        "INSERT INTO {{relation}} (id,layer,name,data,applies_to_collection_id,version_lineage,created_at) VALUES (",
                        ", 'user', ",
                        ", ",
                        ", ",
                        ", NULL, ",
                        ")",
                    ],
                )
                .map_err(|error| stable("project describe-schema config", error))?;

                let kind_projection: crate::meta::VocabValueProposedPayload =
                    serde_json::from_value(kind_payload.clone())?;
                transaction
                    .execute(
                        "append describe-schema fixture",
                        &append_event,
                        &[
                            BindValue::Text("event:describe-schema:kind".into()),
                            BindValue::Text(kind_id.clone()),
                            BindValue::Text("vocab_value.proposed".into()),
                            BindValue::Text(kind_payload.to_string()),
                            BindValue::Text("contract:describe-schema".into()),
                            BindValue::Text(now.clone()),
                        ],
                    )
                    .await?;
                transaction
                    .execute(
                        "project describe-schema kind",
                        &insert_kind,
                        &[
                            BindValue::Text(kind_id),
                            BindValue::Text(kind_projection.vocabulary_id),
                            BindValue::Text(kind_projection.value),
                            optional_binding(kind_projection.gloss.as_deref()),
                            BindValue::Text(kind_projection.status),
                            BindValue::Real(kind_projection.ordinal),
                            BindValue::Text(kind_projection.terminality),
                            BindValue::Text(kind_projection.metadata.to_string()),
                        ],
                    )
                    .await?;

                for (event_id, config_id, name, data, bearer) in [
                    (
                        "event:describe-schema:global-config",
                        global_config_id,
                        "Describe schema global contract",
                        global_config_data,
                        None,
                    ),
                    (
                        "event:describe-schema:hidden-config",
                        hidden_config_id,
                        "Describe schema hidden contract",
                        hidden_config_data,
                        Some(hidden_collection_id),
                    ),
                ] {
                    let payload = json!({
                        "layer":"user",
                        "name":name,
                        "data":data,
                        "applies_to_collection_id":bearer,
                        "version_lineage":null
                    });
                    transaction
                        .execute(
                            "append describe-schema fixture",
                            &append_event,
                            &[
                                BindValue::Text(event_id.into()),
                                BindValue::Text(config_id.clone()),
                                BindValue::Text("schema_config.set".into()),
                                BindValue::Text(payload.to_string()),
                                BindValue::Text("contract:describe-schema".into()),
                                BindValue::Text(now.clone()),
                            ],
                        )
                        .await?;
                    transaction
                        .execute(
                            "project describe-schema config",
                            &insert_config,
                            &[
                                BindValue::Text(config_id),
                                BindValue::Text(name.into()),
                                BindValue::Text(data),
                                bearer
                                    .map(BindValue::Text)
                                    .unwrap_or(BindValue::Null(LogicalType::Text)),
                                BindValue::Text(now.clone()),
                            ],
                        )
                        .await?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Corrupt one required non-overlay index after open. The describe-schema
    /// contract must re-read the installed catalog and fail closed rather than
    /// hashing its compiled constants.
    pub async fn contract_drop_describe_schema_index_for_test(&self) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute("DROP INDEX idx_records_type", ())
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "cannot drop Turso describe-schema contract index: {error}"
                ))
            })?;
        Ok(())
    }

    /// Corrupt one required non-overlay trigger after open. Kept separate from
    /// the index probe so both catalog object classes are independently proven.
    pub async fn contract_drop_describe_schema_trigger_for_test(&self) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute("DROP TRIGGER policy_events_no_update", ())
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "cannot drop Turso describe-schema contract trigger: {error}"
                ))
            })?;
        Ok(())
    }

    /// Arm a one-shot failure after a shipped write handler has completed its
    /// transaction work but before commit. Contract tests use this to prove
    /// operation-route rollback without adding production fault controls.
    pub fn contract_arm_post_handler_write_failure(&self, operation: &'static str) {
        self.inner
            .contract_faults
            .write
            .arm(operation, TursoContractFaultMode::Fail);
    }

    /// Block one shipped write route after handler work and before commit.
    pub fn contract_arm_post_handler_write_block(&self, operation: &'static str) {
        self.inner
            .contract_faults
            .write
            .arm(operation, TursoContractFaultMode::Block);
    }

    pub async fn contract_wait_for_write_block(&self) {
        self.inner.contract_faults.write.wait_until_entered().await;
    }

    /// Block a run-context declaration after its exact-key upsert but before
    /// commit, so cancellation proves the operation transaction rolls back.
    pub fn contract_arm_intent_persist_block(&self) {
        self.inner
            .contract_faults
            .intent
            .arm("persist_intent", TursoContractFaultMode::Block);
    }

    pub async fn contract_wait_for_intent_persist_block(&self) {
        self.inner.contract_faults.intent.wait_until_entered().await;
    }

    /// Block one shipped snapshot route at its operation-specific boundary.
    pub fn contract_arm_snapshot_block(&self, operation: &'static str) {
        self.inner
            .contract_faults
            .snapshot
            .arm(operation, TursoContractFaultMode::Block);
    }

    pub async fn contract_wait_for_snapshot_block(&self) {
        self.inner
            .contract_faults
            .snapshot
            .wait_until_entered()
            .await;
    }

    pub fn contract_release_snapshot_block(&self) {
        self.inner.contract_faults.snapshot.release();
    }

    /// Install the two canonical identity bindings used by portable caller
    /// fixtures. This is setup state, not a product operation.
    pub async fn contract_provision_member(
        &self,
        person_id: &str,
        account_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let person_id = person_id.to_string();
        let account_id = account_id.to_string();
        let principal_id = principal_id.to_string();
        run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                let insert = statement(
                    StatementKind::Insert,
                    "bindings",
                    &[
                        "INSERT INTO {{relation}} (record_id, system, identifier, is_canonical) VALUES (",
                        ", ",
                        ", ",
                        ", 1)",
                    ],
                )
                .map_err(|error| stable("provision contract member", error))?;
                for (system, identifier) in [
                    ("account", account_id),
                    ("native-principal", principal_id),
                ] {
                    let claim = crate::identity::BindingClaim {
                        system: system.into(),
                        identifier,
                    };
                    transaction
                        .execute(
                            "provision contract member",
                            &insert,
                            &[
                                BindValue::Text(person_id.clone()),
                                BindValue::Text(claim.system.clone()),
                                BindValue::Text(claim.identifier.clone()),
                            ],
                        )
                        .await?;
                    transaction
                        .append_binding_audit(BindingAudit {
                            action: "add",
                            claim: &claim,
                            old_record_id: None,
                            new_record_id: Some(&person_id),
                            old_canonical: None,
                            new_canonical: Some(true),
                            actor: "native:contract-provisioner",
                            reason: "Provision contract member identity bindings.",
                            run_key: None,
                            parent_key: None,
                            intent: None,
                        })
                        .await?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Establish the private Message fixture required by the portable corpus.
    /// The record is appended through the production content transaction and
    /// its replacement policy is authored in the same admitted write.
    pub async fn contract_deliver_message_fixture(
        &self,
        sender_account_id: &str,
        id: &str,
        name: &str,
        body: &str,
        addressed_to: &[&str],
    ) -> Result<()> {
        self.contract_deliver_message_fixture_with_run_context(
            sender_account_id,
            id,
            name,
            body,
            addressed_to,
            None,
            None,
            None,
        )
        .await
    }

    /// Establish the same fixture with populated event annotations so member
    /// history redaction can be exercised against real stored run context.
    #[allow(clippy::too_many_arguments)]
    pub async fn contract_deliver_message_fixture_with_run_context(
        &self,
        sender_account_id: &str,
        id: &str,
        name: &str,
        body: &str,
        addressed_to: &[&str],
        run_key: Option<&str>,
        parent_key: Option<&str>,
        intent: Option<&str>,
    ) -> Result<()> {
        let sender_account_id = sender_account_id.to_string();
        let id = id.to_string();
        let name = name.to_string();
        let body = body.to_string();
        let addressed_to = addressed_to
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let annotations = crate::store::EventAnnotations {
            run_key: run_key.map(str::to_owned),
            parent_key: parent_key.map(str::to_owned),
            intent: intent.map(str::to_owned),
        };
        crate::store::with_event_annotations(annotations, run_db_write(self, &ExecutionControl::default(), move |transaction| {
            Box::pin(async move {
                let binding = statement(
                    StatementKind::Select,
                    "bindings",
                    &[
                        "SELECT record_id, identifier FROM {{relation}} WHERE system='account' AND (identifier=",
                        " OR record_id IN (SELECT value FROM json_each(",
                        "))) ORDER BY record_id, identifier",
                    ],
                )
                .map_err(|error| stable("resolve contract Message audience", error))?;
                let addressed_json = serde_json::to_string(&addressed_to)?;
                let rows = transaction
                    .rows(
                        "resolve contract Message audience",
                        &binding,
                        &[
                            BindValue::Text(sender_account_id.clone()),
                            BindValue::Text(addressed_json),
                        ],
                        &[
                            ColumnSpec::required("record_id", LogicalType::Text),
                            ColumnSpec::required("identifier", LogicalType::Text),
                        ],
                    )
                    .await?;
                let mut sender_id = None;
                let mut addressed_accounts = BTreeMap::new();
                for row in rows {
                    let record_id = text(&row, "record_id", "contract Message binding")?;
                    let account = text(&row, "identifier", "contract Message binding")?;
                    if account == sender_account_id {
                        sender_id = Some(record_id.clone());
                    }
                    if addressed_to.contains(&record_id) {
                        addressed_accounts.insert(account, record_id);
                    }
                }
                let sender_id = sender_id.ok_or_else(|| {
                    Error::engine("contract Message sender has no canonical account binding")
                })?;
                if addressed_accounts.len() != addressed_to.len() {
                    return Err(Error::engine(
                        "contract Message audience has an unbound person fixture",
                    ));
                }

                transaction
                    .append_content(AppendSpec {
                        record_id: id.clone(),
                        event_type: "record.created".into(),
                        payload: json!({
                            "type":"Message",
                            "kind":"text",
                            "name":name,
                            "body":body,
                            "home_id":crate::schema::UNFILED_RECORD_ID,
                            "owner_id":sender_id,
                            "persistence":"enduring",
                            "mentions":[],
                            "reason":"Exercise delivered Message visibility in the backend contract."
                        }),
                        // Production writes the caller's account token here, and
                        // the SQLite harness reaches this through the real send
                        // tool. Fabricating a namespaced form made every actor
                        // unmatchable, which stayed invisible only while history
                        // redacted attribution unconditionally.
                        actor: Some(sender_account_id.to_string()),
                    })
                    .await?;

                transaction
                    .append_content(AppendSpec {
                        record_id: id.clone(),
                        event_type: "facet.set".into(),
                        payload: json!({ "key":"expectation", "value":"reply" }),
                        actor: Some(sender_account_id.to_string()),
                    })
                    .await?;

                let entries = addressed_accounts
                    .into_keys()
                    .map(|account| {
                        json!({
                            "subject_kind":"account",
                            "subject_id":account,
                            "effect":"allow",
                            "capability":"view"
                        })
                    })
                    .collect::<Vec<_>>();
                append_replacement_policy(
                    transaction,
                    &id,
                    &entries,
                    &format!("account:{sender_account_id}"),
                    "Establish the contract Message audience.",
                )
                .await
            })
        }))
        .await
    }

    /// Rebuild every production content projection and the policy projections
    /// used by the corpus from one captured authoritative source instant.
    pub async fn contract_assert_replay_equivalent(&self) -> Result<()> {
        let _source_write = self.inner.write_gate.lock().await;
        let source = self.connect()?;
        source
            .execute("PRAGMA foreign_keys = ON", ())
            .await
            .map_err(|_| Error::engine("cannot enable Turso-local replay source foreign keys"))?;
        let content = read_content_events(&source).await?;
        assert_gapless(
            content.iter().map(|event| event.local_seq),
            "content event positions",
        )?;
        let policies = read_policy_events(&source).await?;
        assert_gapless(
            policies.iter().map(|event| event.seq),
            "policy event positions",
        )?;
        let candidate_events = read_candidate_events(&source).await?;
        assert_gapless(
            candidate_events.iter().map(|event| event.seq),
            "notification candidate event positions",
        )?;
        let binding_audit = read_binding_audit(&source).await?;
        assert_gapless(
            binding_audit.iter().map(|event| event.seq),
            "binding audit positions",
        )?;
        let live = projection_snapshot(&source).await?;

        let directory = tempfile::tempdir()
            .map_err(|error| Error::engine(format!("Turso replay tempdir failed: {error}")))?;
        let config = TursoLocalRuntimeConfig {
            format: TURSO_LOCAL_RUNTIME_CONFIG_FORMAT.into(),
            // The enclosing tempdir is already unique. Keep the logical name
            // stable so replay ownership and cleanup are deterministic.
            logical_database_id: "contract-replay".into(),
            data_directory: directory.path().to_path_buf(),
        };
        let replay = config.open().await?;
        clear_replayable_state(&replay).await?;
        replay_content(&replay, content).await?;
        replay_policies(&replay, &policies).await?;
        replay_candidate_events(&replay, &candidate_events).await?;
        replay_bindings(&replay, binding_audit).await?;
        let replay_connection = replay.connect()?;
        let rebuilt = projection_snapshot(&replay_connection).await?;
        if rebuilt == live {
            Ok(())
        } else {
            Err(Error::engine(format!(
                "Turso-local authoritative replay diverged from production projections: live={live} replayed={rebuilt}"
            )))
        }
    }

    /// Prove that the binding replay authority cannot be rewritten in place.
    pub async fn contract_rewrite_binding_audit_for_test(&self) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute(
                "UPDATE binding_audit SET reason='forbidden rewrite' WHERE seq=1",
                (),
            )
            .await
            .map(|_| ())
            .map_err(|error| {
                Error::engine(format!("Turso binding audit rewrite probe failed: {error}"))
            })
    }

    /// Physical corruption probe only. Corpus calls never use this path.
    pub async fn contract_delete_content_event_for_test(&self, seq: i64) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute("DELETE FROM content_events WHERE seq=?1", [seq])
            .await
            .map_err(|error| {
                Error::engine(format!("Turso event deletion probe failed: {error}"))
            })?;
        Ok(())
    }

    /// Physical corruption probe only. Corpus calls never use this path.
    pub async fn contract_corrupt_content_event_for_test(&self, seq: i64) -> Result<()> {
        let _write = self.inner.write_gate.lock().await;
        self.connect()?
            .execute("UPDATE content_events SET payload='{}' WHERE seq=?1", [seq])
            .await
            .map_err(|error| {
                Error::engine(format!("Turso event corruption probe failed: {error}"))
            })?;
        Ok(())
    }

    /// Physical rollback probe only. Observable record absence is asserted
    /// separately through the registered production handler.
    pub async fn contract_content_event_count_for_test(&self, record_id: &str) -> Result<i64> {
        let _write = self.inner.write_gate.lock().await;
        let mut rows = self
            .connect()?
            .query(
                "SELECT COUNT(*) FROM content_events WHERE record_id=?1",
                [record_id],
            )
            .await
            .map_err(|error| {
                Error::engine(format!("Turso rollback event probe failed: {error}"))
            })?;
        let row = rows
            .next()
            .await
            .map_err(|error| Error::engine(format!("Turso rollback event probe failed: {error}")))?
            .ok_or_else(|| Error::engine("Turso rollback event probe returned no count"))?;
        row.get(0)
            .map_err(|error| Error::engine(format!("invalid Turso rollback event count: {error}")))
    }

    /// Physical event-type probe only. Product assertions still dispatch the
    /// registered handler; this verifies that a concurrent CAS race appended
    /// exactly one requested tombstone.
    pub async fn contract_content_event_type_count_for_test(
        &self,
        record_id: &str,
        event_type: &str,
    ) -> Result<i64> {
        let _write = self.inner.write_gate.lock().await;
        let mut rows = self
            .connect()?
            .query(
                "SELECT COUNT(*) FROM content_events WHERE record_id=?1 AND type=?2",
                [record_id.to_string(), event_type.to_string()],
            )
            .await
            .map_err(|error| Error::engine(format!("Turso event-type probe failed: {error}")))?;
        let row = rows
            .next()
            .await
            .map_err(|error| Error::engine(format!("Turso event-type probe failed: {error}")))?
            .ok_or_else(|| Error::engine("Turso event-type probe returned no count"))?;
        row.get(0)
            .map_err(|error| Error::engine(format!("invalid Turso event-type count: {error}")))
    }

    /// Every authoritative content event, flattened to text.
    ///
    /// Non-authoritative material must be provably absent from the durable log
    /// rather than merely undocumented, so this returns the whole log for the
    /// caller to search. It is a physical probe only; observable behaviour is
    /// asserted separately through the registered production handlers.
    pub async fn contract_all_content_event_text_for_test(&self) -> Result<String> {
        let _write = self.inner.write_gate.lock().await;
        let mut rows = self
            .connect()?
            .query(
                "SELECT id,record_id,type,COALESCE(payload,''),COALESCE(actor,''),\
                 COALESCE(run_key,''),COALESCE(parent_key,''),COALESCE(intent,'') \
                 FROM content_events ORDER BY seq",
                (),
            )
            .await
            .map_err(|error| Error::engine(format!("Turso content log probe failed: {error}")))?;
        let mut flattened = String::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|error| Error::engine(format!("Turso content log probe failed: {error}")))?
        {
            for column in 0..8 {
                let cell: String = row.get(column).map_err(|error| {
                    Error::engine(format!("invalid Turso content log cell: {error}"))
                })?;
                flattened.push_str(&cell);
                flattened.push('\u{1f}');
            }
            flattened.push('\n');
        }
        Ok(flattened)
    }

    /// Fail the next run-key mint, once.
    ///
    /// Minting only fails in production when the durable evidence read fails or
    /// the namespace is exhausted, neither of which a test can provoke without
    /// corrupting the database. This reaches the same branch of the lifecycle
    /// port deterministically and changes nothing while unarmed.
    pub fn contract_arm_run_key_mint_failure(&self) {
        self.inner
            .contract_faults
            .mint
            .arm("mint_run_key", TursoContractFaultMode::Fail);
    }
}

async fn append_replacement_policy(
    transaction: &mut TursoDomainTransaction<'_>,
    record_id: &str,
    entries: &[Value],
    actor: &str,
    reason: &str,
) -> Result<()> {
    let event = crate::policy::PolicyEventRow {
        // The projection fold only requires a positive sequence. The database
        // assigns the authoritative position during the append below.
        seq: 1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: record_id.into(),
        event_type: "policy.replaced".into(),
        payload: Some(json!({"entries":entries}).to_string()),
        actor: actor.into(),
        reason: reason.into(),
        created_at: crate::store::now_iso(),
    };
    let insert_event = statement(
        StatementKind::Insert,
        "policy_events",
        &[
            "INSERT INTO {{relation}} (id, record_id, type, payload, actor, reason, created_at) VALUES (",
            ", ",
            ", 'policy.replaced', ",
            ", ",
            ", ",
            ", ",
            ")",
        ],
    )
    .map_err(|error| stable("append contract Message policy", error))?;
    transaction
        .execute(
            "append contract Message policy",
            &insert_event,
            &[
                BindValue::Text(event.id.clone()),
                BindValue::Text(event.record_id.clone()),
                optional_binding(event.payload.as_deref()),
                BindValue::Text(event.actor.clone()),
                BindValue::Text(event.reason.clone()),
                BindValue::Text(event.created_at.clone()),
            ],
        )
        .await?;
    super::policy::project_policy(transaction, &event).await
}

async fn read_content_events(connection: &turso::Connection) -> Result<Vec<EventRow>> {
    let mut rows = connection
        .query(
            "SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status,(SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier frontier WHERE frontier.event_id=content_events.id) FROM content_events ORDER BY seq",
            (),
        )
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso content log: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso content event: {error}")))?
    {
        events.push(EventRow {
            local_seq: row.get(0).map_err(replay_column("content seq"))?,
            id: row.get(1).map_err(replay_column("content id"))?,
            record_id: row.get(2).map_err(replay_column("content record_id"))?,
            event_type: row.get(3).map_err(replay_column("content type"))?,
            payload: row.get(4).map_err(replay_column("content payload"))?,
            actor: row.get(5).map_err(replay_column("content actor"))?,
            run_key: row.get(6).map_err(replay_column("content run_key"))?,
            parent_key: row.get(7).map_err(replay_column("content parent_key"))?,
            intent: row.get(8).map_err(replay_column("content intent"))?,
            created_at: row.get(9).map_err(replay_column("content created_at"))?,
            causal_envelope: {
                let version: i64 = row
                    .get(10)
                    .map_err(replay_column("content causal version"))?;
                if version != 1 {
                    return Err(Error::engine("unsupported stored causal envelope version"));
                }
                let status: String = row
                    .get(11)
                    .map_err(replay_column("content causal status"))?;
                let frontier_json: String = row
                    .get(12)
                    .map_err(replay_column("content causal frontier"))?;
                let frontier =
                    CausalFrontierV1::new(serde_json::from_str::<Vec<String>>(&frontier_json)?)?;
                match status.as_str() {
                    "complete" => CausalEnvelopeV1::complete(frontier),
                    "import_incomplete" => CausalEnvelopeV1::import_incomplete(frontier),
                    "legacy_unknown" if frontier.is_empty() => CausalEnvelopeV1::legacy_unknown(),
                    _ => return Err(Error::engine("invalid stored causal envelope")),
                }
            },
        });
    }
    Ok(events)
}

async fn read_policy_events(
    connection: &turso::Connection,
) -> Result<Vec<crate::policy::PolicyEventRow>> {
    let mut rows = connection
        .query(
            "SELECT seq,id,record_id,type,payload,actor,reason,created_at FROM policy_events ORDER BY seq",
            (),
        )
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso policy log: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso policy event: {error}")))?
    {
        events.push(crate::policy::PolicyEventRow {
            seq: row.get(0).map_err(replay_column("policy seq"))?,
            id: row.get(1).map_err(replay_column("policy id"))?,
            record_id: row.get(2).map_err(replay_column("policy record_id"))?,
            event_type: row.get(3).map_err(replay_column("policy type"))?,
            payload: row.get(4).map_err(replay_column("policy payload"))?,
            actor: row.get(5).map_err(replay_column("policy actor"))?,
            reason: row.get(6).map_err(replay_column("policy reason"))?,
            created_at: row.get(7).map_err(replay_column("policy created_at"))?,
        });
    }
    Ok(events)
}

async fn read_candidate_events(
    connection: &turso::Connection,
) -> Result<Vec<CandidateReplayEvent>> {
    let mut rows = connection
        .query(
            "SELECT seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at FROM notification_candidate_events ORDER BY seq",
            (),
        )
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso candidate log: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso candidate event: {error}")))?
    {
        events.push(CandidateReplayEvent {
            seq: row.get(0).map_err(replay_column("candidate seq"))?,
            id: row.get(1).map_err(replay_column("candidate id"))?,
            candidate_key: row.get(2).map_err(replay_column("candidate key"))?,
            action: row.get(3).map_err(replay_column("candidate action"))?,
            recipient_account_id: row.get(4).map_err(replay_column("candidate recipient"))?,
            message_id: row.get(5).map_err(replay_column("candidate message"))?,
            reason: row.get(6).map_err(replay_column("candidate reason"))?,
            priority: row.get(7).map_err(replay_column("candidate priority"))?,
            not_before: row.get(8).map_err(replay_column("candidate not_before"))?,
            redaction_class: row.get(9).map_err(replay_column("candidate redaction"))?,
            evaluator_kind: row.get(10).map_err(replay_column("candidate evaluator"))?,
            policy_version: row.get(11).map_err(replay_column("candidate policy"))?,
            source_event_type: row
                .get(12)
                .map_err(replay_column("candidate source type"))?,
            source_event_id: row.get(13).map_err(replay_column("candidate source id"))?,
            payload: row.get(14).map_err(replay_column("candidate payload"))?,
            created_at: row.get(15).map_err(replay_column("candidate created_at"))?,
        });
    }
    Ok(events)
}

async fn read_binding_audit(connection: &turso::Connection) -> Result<Vec<BindingAuditEvent>> {
    let mut rows = connection
        .query(
            "SELECT seq,id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at FROM binding_audit ORDER BY seq",
            (),
        )
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso binding audit: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|error| Error::engine(format!("cannot read Turso binding audit row: {error}")))?
    {
        events.push(BindingAuditEvent {
            seq: row.get(0).map_err(replay_column("binding audit seq"))?,
            id: row.get(1).map_err(replay_column("binding audit id"))?,
            action: row.get(2).map_err(replay_column("binding audit action"))?,
            system: row.get(3).map_err(replay_column("binding audit system"))?,
            identifier: row
                .get(4)
                .map_err(replay_column("binding audit identifier"))?,
            old_record_id: row
                .get(5)
                .map_err(replay_column("binding audit old_record_id"))?,
            new_record_id: row
                .get(6)
                .map_err(replay_column("binding audit new_record_id"))?,
            old_canonical: row
                .get(7)
                .map_err(replay_column("binding audit old_canonical"))?,
            new_canonical: row
                .get(8)
                .map_err(replay_column("binding audit new_canonical"))?,
            actor: row.get(9).map_err(replay_column("binding audit actor"))?,
            reason: row.get(10).map_err(replay_column("binding audit reason"))?,
            run_key: row
                .get(11)
                .map_err(replay_column("binding audit run_key"))?,
            parent_key: row
                .get(12)
                .map_err(replay_column("binding audit parent_key"))?,
            intent: row.get(13).map_err(replay_column("binding audit intent"))?,
            created_at: row
                .get(14)
                .map_err(replay_column("binding audit created_at"))?,
        });
    }
    Ok(events)
}

fn replay_column(field: &'static str) -> impl FnOnce(turso::Error) -> Error {
    move |error| Error::engine(format!("invalid Turso replay {field}: {error}"))
}

fn assert_gapless(values: impl IntoIterator<Item = i64>, label: &str) -> Result<()> {
    for (offset, actual) in values.into_iter().enumerate() {
        let expected =
            i64::try_from(offset + 1).map_err(|_| Error::engine(format!("{label} overflow")))?;
        if actual != expected {
            return Err(Error::engine(format!(
                "{label} are not gapless: expected {expected}, got {actual}"
            )));
        }
    }
    Ok(())
}

async fn clear_replayable_state(db: &TursoLocalDb) -> Result<()> {
    let _write = db.inner.write_gate.lock().await;
    let connection = db.connect()?;
    connection
        .execute("PRAGMA foreign_keys=OFF", ())
        .await
        .map_err(|error| {
            Error::engine(format!("cannot suspend Turso replay foreign keys: {error}"))
        })?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|error| Error::engine(format!("cannot begin Turso replay reset: {error}")))?;
    let result = async {
        connection
            .execute("DELETE FROM binding_audit", ())
            .await
            .map_err(|error| {
                Error::engine(format!("cannot clear Turso replay binding audit: {error}"))
            })?;
        connection
            .execute("DELETE FROM bindings", ())
            .await
            .map_err(|error| {
                Error::engine(format!("cannot clear Turso replay bindings: {error}"))
            })?;
        connection
            .execute("DELETE FROM sqlite_sequence WHERE name='binding_audit'", ())
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "cannot reset Turso replay binding audit sequence: {error}"
                ))
            })?;
        for table in crate::schema::PROJECTION_TABLES.iter().rev() {
            connection
                .execute(&format!("DELETE FROM {table}"), ())
                .await
                .map_err(|error| {
                    Error::engine(format!("cannot clear Turso replay table {table}: {error}"))
                })?;
        }
        super::policy::clear_projections_for_replay(&connection).await?;
        connection
            .execute("DELETE FROM content_events", ())
            .await
            .map_err(|error| {
                Error::engine(format!("cannot clear Turso replay content log: {error}"))
            })?;
        connection
            .execute(
                "DELETE FROM sqlite_sequence WHERE name='content_events'",
                (),
            )
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "cannot reset Turso replay content sequence: {error}"
                ))
            })?;
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = result {
        let _ = connection.execute("ROLLBACK", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|error| Error::engine(format!("cannot commit Turso replay reset: {error}")))?;
    connection
        .execute("PRAGMA foreign_keys=ON", ())
        .await
        .map_err(|error| {
            Error::engine(format!("cannot restore Turso replay foreign keys: {error}"))
        })?;
    Ok(())
}

async fn replay_content(db: &TursoLocalDb, events: Vec<EventRow>) -> Result<()> {
    run_db_write(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            let insert = statement(
                StatementKind::Insert,
                "content_events",
                &[
                    "INSERT INTO {{relation}} (seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status) VALUES (",
                    ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ", ")",
                ],
            ).map_err(|error| stable("replay Turso content event", error))?;
            let insert_frontier = statement(
                StatementKind::Insert,
                "content_event_causal_frontier",
                &[
                    "INSERT INTO {{relation}} (event_id,parent_event_id) VALUES (",
                    ", ",
                    ")",
                ],
            )
            .map_err(|error| stable("replay Turso causal frontier", error))?;
            for event in events {
                transaction.execute(
                    "replay Turso content event",
                    &insert,
                    &[
                        BindValue::Integer(event.local_seq),
                        BindValue::Text(event.id.clone()),
                        BindValue::Text(event.record_id.clone()),
                        BindValue::Text(event.event_type.clone()),
                        optional_binding(event.payload.as_deref()),
                        optional_binding(event.actor.as_deref()),
                        optional_binding(event.run_key.as_deref()),
                        optional_binding(event.parent_key.as_deref()),
                        optional_binding(event.intent.as_deref()),
                        BindValue::Text(event.created_at.clone()),
                        BindValue::Integer(event.causal_envelope.version().as_i64()),
                        BindValue::Text(event.causal_envelope.status().as_str().into()),
                    ],
                ).await?;
                for parent_event_id in event.causal_envelope.frontier().as_slice() {
                    transaction
                        .execute(
                            "replay Turso causal frontier",
                            &insert_frontier,
                            &[
                                BindValue::Text(event.id.clone()),
                                BindValue::Text(parent_event_id.clone()),
                            ],
                        )
                        .await?;
                }
                let intent = ProjectorIntent::from_event(&event)?;
                let control = transaction.control.clone();
                transaction.apply_projector(&intent, &event, &control).await?;
            }
            Ok(())
        })
    }).await
}

async fn replay_bindings(db: &TursoLocalDb, events: Vec<BindingAuditEvent>) -> Result<()> {
    let _write = db.inner.write_gate.lock().await;
    let connection = db.connect()?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|error| Error::engine(format!("cannot begin Turso binding replay: {error}")))?;
    let result = async {
        for event in events {
            match event.action.as_str() {
                "add" => {
                    connection
                        .execute(
                            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?1,?2,?3,?4)",
                            vec![
                                turso::Value::Text(event.new_record_id.clone().ok_or_else(|| {
                                    Error::engine("binding add audit is missing its new record")
                                })?),
                                turso::Value::Text(event.system.clone()),
                                turso::Value::Text(event.identifier.clone()),
                                turso::Value::Integer(event.new_canonical.ok_or_else(|| {
                                    Error::engine(
                                        "binding add audit is missing canonical state",
                                    )
                                })?),
                            ],
                        )
                        .await
                        .map_err(|error| {
                            Error::engine(format!("cannot replay Turso binding add: {error}"))
                        })?;
                }
                "remove" => {
                    connection
                        .execute(
                            "DELETE FROM bindings WHERE record_id=?1 AND system=?2 AND identifier=?3",
                            vec![
                                turso::Value::Text(event.old_record_id.clone().ok_or_else(|| {
                                    Error::engine("binding remove audit is missing its old record")
                                })?),
                                turso::Value::Text(event.system.clone()),
                                turso::Value::Text(event.identifier.clone()),
                            ],
                        )
                        .await
                        .map_err(|error| {
                            Error::engine(format!("cannot replay Turso binding remove: {error}"))
                        })?;
                }
                "canonicalize" => {
                    connection
                        .execute(
                            "UPDATE bindings SET is_canonical=?1 WHERE record_id=?2 AND system=?3 AND identifier=?4",
                            vec![
                                turso::Value::Integer(event.new_canonical.ok_or_else(|| {
                                    Error::engine(
                                        "binding canonicalize audit is missing canonical state",
                                    )
                                })?),
                                turso::Value::Text(event.new_record_id.clone().ok_or_else(|| {
                                    Error::engine(
                                        "binding canonicalize audit is missing its record",
                                    )
                                })?),
                                turso::Value::Text(event.system.clone()),
                                turso::Value::Text(event.identifier.clone()),
                            ],
                        )
                        .await
                        .map_err(|error| {
                            Error::engine(format!(
                                "cannot replay Turso binding canonicalization: {error}"
                            ))
                        })?;
                }
                "transfer" => {
                    connection
                        .execute(
                            "UPDATE bindings SET record_id=?1 WHERE record_id=?2 AND system=?3 AND identifier=?4",
                            vec![
                                turso::Value::Text(event.new_record_id.clone().ok_or_else(|| {
                                    Error::engine("binding transfer audit is missing its new record")
                                })?),
                                turso::Value::Text(event.old_record_id.clone().ok_or_else(|| {
                                    Error::engine("binding transfer audit is missing its old record")
                                })?),
                                turso::Value::Text(event.system.clone()),
                                turso::Value::Text(event.identifier.clone()),
                            ],
                        )
                        .await
                        .map_err(|error| {
                            Error::engine(format!("cannot replay Turso binding transfer: {error}"))
                        })?;
                }
                action => {
                    return Err(Error::engine(format!(
                        "Turso binding replay encountered unknown action '{action}'"
                    )));
                }
            }
            let optional_text = |value: Option<String>| {
                value
                    .map(turso::Value::Text)
                    .unwrap_or(turso::Value::Null)
            };
            let optional_integer = |value: Option<i64>| {
                value
                    .map(turso::Value::Integer)
                    .unwrap_or(turso::Value::Null)
            };
            connection
                .execute(
                    "INSERT INTO binding_audit(seq,id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    vec![
                        turso::Value::Integer(event.seq),
                        turso::Value::Text(event.id),
                        turso::Value::Text(event.action),
                        turso::Value::Text(event.system),
                        turso::Value::Text(event.identifier),
                        optional_text(event.old_record_id),
                        optional_text(event.new_record_id),
                        optional_integer(event.old_canonical),
                        optional_integer(event.new_canonical),
                        turso::Value::Text(event.actor),
                        turso::Value::Text(event.reason),
                        optional_text(event.run_key),
                        optional_text(event.parent_key),
                        optional_text(event.intent),
                        turso::Value::Text(event.created_at),
                    ],
                )
                .await
                .map_err(|error| {
                    Error::engine(format!("cannot replay Turso binding audit: {error}"))
                })?;
        }
        Ok::<_, Error>(())
    }
    .await;
    match result {
        Ok(()) => connection
            .execute("COMMIT", ())
            .await
            .map(|_| ())
            .map_err(|error| Error::engine(format!("cannot commit Turso binding replay: {error}"))),
        Err(error) => {
            let _ = connection.execute("ROLLBACK", ()).await;
            Err(error)
        }
    }
}

async fn replay_policies(
    db: &TursoLocalDb,
    events: &[crate::policy::PolicyEventRow],
) -> Result<()> {
    let events = events.to_vec();
    run_db_write(db, &ExecutionControl::default(), move |transaction| {
        Box::pin(async move {
            for event in events {
                super::policy::project_policy(transaction, &event).await?;
            }
            Ok(())
        })
    })
    .await
}

async fn replay_candidate_events(db: &TursoLocalDb, events: &[CandidateReplayEvent]) -> Result<()> {
    let _write = db.inner.write_gate.lock().await;
    let connection = db.connect()?;
    connection
        .execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(|error| Error::engine(format!("cannot begin Turso candidate replay: {error}")))?;
    let result = async {
        for event in events {
            connection
                .execute(
                    "INSERT INTO notification_candidate_events(seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    turso::params![event.seq,event.id.clone(),event.candidate_key.clone(),event.action.clone(),event.recipient_account_id.clone(),event.message_id.clone(),event.reason.clone(),event.priority.clone(),event.not_before.clone(),event.redaction_class.clone(),event.evaluator_kind.clone(),event.policy_version.clone(),event.source_event_type.clone(),event.source_event_id.clone(),event.payload.clone(),event.created_at.clone()],
                )
                .await
                .map_err(|error| Error::engine(format!("cannot replay Turso candidate event: {error}")))?;
            if event.action == "proposed" {
                connection.execute("INSERT INTO notification_candidates(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'effective',?14)", turso::params![event.id.clone(),event.candidate_key.clone(),event.recipient_account_id.clone(),event.message_id.clone(),event.reason.clone(),event.priority.clone(),event.not_before.clone(),event.redaction_class.clone(),event.evaluator_kind.clone(),event.policy_version.clone(),event.source_event_type.clone(),event.source_event_id.clone(),event.seq,event.created_at.clone()]).await.map_err(|error| Error::engine(format!("cannot project Turso candidate proposal: {error}")))?;
            } else {
                let status = match event.action.as_str() {
                    "suppressed" => "suppressed",
                    "withdrawn" => "withdrawn",
                    action => return Err(Error::engine(format!("unknown notification candidate replay action: {action}"))),
                };
                connection.execute("UPDATE notification_candidates SET status=?1,candidate_event_seq=?2 WHERE candidate_key=?3", turso::params![status,event.seq,event.candidate_key.clone()]).await.map_err(|error| Error::engine(format!("cannot project Turso candidate transition: {error}")))?;
            }
        }
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = result {
        let _ = connection.execute("ROLLBACK", ()).await;
        return Err(error);
    }
    connection
        .execute("COMMIT", ())
        .await
        .map_err(|error| Error::engine(format!("cannot commit Turso candidate replay: {error}")))?;
    Ok(())
}

async fn projection_snapshot(connection: &turso::Connection) -> Result<Value> {
    let mut tables = serde_json::Map::new();
    for table in ["bindings", "binding_audit"]
        .into_iter()
        .chain(crate::schema::PROJECTION_TABLES.iter().copied())
        .chain(crate::schema::POLICY_PROJECTION_TABLES.iter().copied())
        .chain(["notification_candidate_events", "notification_candidates"])
    {
        let mut rows = connection
            .query(&format!("SELECT * FROM {table} ORDER BY rowid"), ())
            .await
            .map_err(|error| {
                Error::engine(format!("cannot snapshot Turso projection {table}: {error}"))
            })?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await.map_err(|error| {
            Error::engine(format!("cannot read Turso projection {table}: {error}"))
        })? {
            let mut value = Vec::with_capacity(row.column_count());
            for index in 0..row.column_count() {
                value.push(turso_value(row.get_value(index).map_err(|error| {
                    Error::engine(format!("cannot decode Turso projection {table}: {error}"))
                })?));
            }
            values.push(Value::Array(value));
        }
        tables.insert(table.into(), Value::Array(values));
    }
    Ok(Value::Object(tables))
}

fn turso_value(value: turso::Value) -> Value {
    match value {
        turso::Value::Null => Value::Null,
        turso::Value::Integer(value) => Value::from(value),
        turso::Value::Real(value) => serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        turso::Value::Text(value) => Value::String(value),
        turso::Value::Blob(value) => Value::String(hex::encode(value)),
    }
}
