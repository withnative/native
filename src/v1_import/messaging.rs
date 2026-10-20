//! Lossless current messaging snapshot. Source reads remain under the importer's
//! pinned read transaction; message bytes and private lanes commit atomically.
use super::*;
use serde_json::Value;

async fn rows(source: &mut SqliteConnection, table: &str, id: &str) -> Result<Vec<Value>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
    )
    .bind(table)
    .fetch_one(&mut *source)
    .await?;
    if !exists {
        return Ok(Vec::new());
    }
    let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(&mut *source)
        .await?;
    let expr = columns
        .iter()
        .map(|r| {
            let name: String = r.get("name");
            format!("'{name}',\"{name}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    let raw: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT json_object({expr}) FROM {table} WHERE message_id=? ORDER BY 1"
    ))
    .bind(id)
    .fetch_all(source)
    .await?;
    raw.into_iter()
        .map(|r| serde_json::from_str(&r).map_err(Into::into))
        .collect()
}

pub(super) async fn snapshot(
    source: &mut SqliteConnection,
    record: &Record,
    report: &mut Report,
) -> Result<k::MessageState> {
    if report.message_rules.is_none() {
        report.message_rules = Some(rules(source).await?);
    }
    let mut state = k::MessageState {
        home_id: record.home_id.clone(),
        created_at: Some(record.created_at.clone()),
        rules: report.message_rules.clone(),
        ..Default::default()
    };
    for table in [
        "message_audience_state",
        "message_audiences",
        "message_origin_state",
        "message_origin_principals",
        "message_conversations",
        "message_mentions",
        "human_message_awareness",
        "agent_message_dispositions",
        "message_preferences",
        "message_inbox_routing",
        "message_speakers",
        "awareness_events",
        "notification_candidates",
        "notification_candidate_events",
    ] {
        state
            .source
            .insert(table.into(), rows(source, table, &record.id).await?);
    }
    // Canonical v1 principal binding is independent of the account credential.
    let candidate_log:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='notification_candidate_events' AND type='table')").fetch_one(&mut *source).await?;
    if candidate_log {
        let head: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events")
                .fetch_one(&mut *source)
                .await?;
        state
            .source
            .insert("notification_frontier".into(), vec![json!({"seq":head})]);
    }
    let identities: Vec<(String,String)> = sqlx::query_as("SELECT p.identifier,a.identifier FROM bindings p JOIN bindings a ON a.record_id=p.record_id AND a.system='account' AND a.is_canonical=1 WHERE p.system='native-principal' AND p.is_canonical=1 ORDER BY p.identifier,a.identifier")
        .fetch_all(&mut *source).await?;
    let principals: BTreeMap<_, _> = identities
        .into_iter()
        .filter_map(|(p, a)| report.principals.get(&a).map(|v| (p, v.clone())))
        .collect();
    let declared = state.source["message_audience_state"]
        .iter()
        .any(|r| r["status"] == "declared");
    if !declared {
        return Err("message has no declared audience; manual review required".into());
    }
    let mut sender = None;
    for row in &state.source["message_audiences"] {
        let p = row["principal_id"]
            .as_str()
            .ok_or("invalid message principal")?;
        let target = principals
            .get(p)
            .ok_or("unresolved sealed message audience")?;
        // These are addressing facts for awareness/expectations, not an ACL.
        // The imported v1 policy and normalized owner alone govern access.
        if row["source"] == "sender" {
            sender = Some(target.clone());
        }
        state.audience.insert(target.clone(), "manage".into());
    }
    state.author = sender;
    for (table, lane) in [
        ("human_message_awareness", "human"),
        ("agent_message_dispositions", "agent"),
        ("message_preferences", "preference"),
        ("message_inbox_routing", "routing"),
    ] {
        for row in &state.source[table] {
            let account = row["subject_account_id"]
                .as_str()
                .ok_or("invalid private message subject")?;
            let target = report
                .principals
                .get(account)
                .ok_or("unresolved private message subject")?;
            state
                .private
                .entry(target.clone())
                .or_default()
                .insert(lane.into(), row.clone());
        }
    }
    state.conversations = state.source["message_conversations"]
        .iter()
        .filter_map(|r| r["conversation_id"].as_str().map(str::to_owned))
        .collect();
    state.origin = if let Some(row) = state.source["message_origin_state"].first() {
        if row["origin_type"] == "collection" {
            json!({"type":"collection","collection_id":row["collection_id"]})
        } else if row["origin_type"] == "direct" {
            let people:Vec<String>=sqlx::query_scalar("SELECT b.record_id FROM message_origin_principals p JOIN bindings b ON b.system='native-principal' AND b.is_canonical=1 AND b.identifier=p.principal_id WHERE p.message_id=? ORDER BY b.record_id").bind(&record.id).fetch_all(&mut *source).await?;
            json!({"type":"direct","participant_ids":people})
        } else {
            Value::Null
        }
    } else {
        Value::Null
    };
    state.addressed_to = sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship='addressed_to' ORDER BY target_id").bind(&record.id).fetch_all(&mut *source).await?;
    state.reply_to = sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship='reply_to' ORDER BY target_id LIMIT 1").bind(&record.id).fetch_optional(&mut *source).await?;
    state.expectation = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id=? AND key='expectation'",
    )
    .bind(&record.id)
    .fetch_optional(&mut *source)
    .await?
    .flatten();
    let reactions:Vec<(String,String)> = sqlx::query_as("WITH ranked AS (SELECT actor,json_extract(payload,'$.emoji') emoji,type,ROW_NUMBER() OVER(PARTITION BY actor,json_extract(payload,'$.emoji') ORDER BY seq DESC) n FROM content_events WHERE record_id=? AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')) SELECT actor,emoji FROM ranked WHERE n=1 AND type='message.reaction.added.v1' ORDER BY actor,emoji")
        .bind(&record.id).fetch_all(&mut *source).await?;
    for (actor, emoji) in reactions {
        // Preserve unresolved historical actors as namespaced provenance;
        // never confuse them with an authenticated v2 principal.
        let target = report
            .principals
            .get(&actor)
            .cloned()
            .or_else(|| principals.get(&actor).cloned())
            .unwrap_or_else(|| format!("v1:{actor}"));
        state.reactions.entry(target).or_default().push(emoji);
    }
    for (account, principal) in &report.principals {
        if state.audience.contains_key(principal) {
            let expectation = crate::message_expectation::derive_message_expectation_state_on(
                source, &record.id, account,
            )
            .await?;
            state
                .expectations
                .insert(principal.clone(), serde_json::to_value(expectation)?);
        }
    }
    state.mentions = state.source["message_mentions"].clone();
    state.speaker = if let Some(row) = state.source["message_speakers"].first() {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM records WHERE id=?")
            .bind(row["persona_id"].as_str().unwrap_or_default())
            .fetch_optional(&mut *source)
            .await?
            .flatten();
        Some(
            json!({"kind":row["speaker_kind"],"id":row["persona_id"],"display_name":name,"assurance":row["assurance"]}),
        )
    } else {
        None
    };
    Ok(state)
}

// This is a data image of the actual source rules, not today's compiled
// defaults. Unknown/retired kinds and negative/open terminalities stay out.
async fn rules(source: &mut SqliteConnection) -> Result<k::MessageRules> {
    let mut rules = k::MessageRules {
        source_origin: sqlx::query_scalar(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        )
        .fetch_optional(&mut *source)
        .await?,
        ..Default::default()
    };
    let has_schema: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='schema_config' AND type='table')",
    )
    .fetch_one(&mut *source)
    .await?;
    if has_schema {
        let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(source);
        for mut row in crate::query::cascade::schema_config_rows_with(&mut executor).await? {
            let mut shapes = serde_json::Map::new();
            for (key, shape) in row.data["shapes"].as_object().into_iter().flatten() {
                if (key == "WorkItem" || key.starts_with("WorkItem:"))
                    && shape["facets"].get("lifecycle").is_some()
                {
                    shapes.insert(
                        key.clone(),
                        json!({"facets":{"lifecycle":shape["facets"]["lifecycle"]}}),
                    );
                }
            }
            if !shapes.is_empty() {
                row.data = json!({"shapes":shapes});
                row.name = None;
                rules.schemas.push(serde_json::to_value(row)?);
            }
        }
    }
    let has_values:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='vocabulary_values' AND type='table')").fetch_one(&mut *source).await?;
    if has_values {
        let mut governing = std::collections::BTreeSet::new();
        for row in &rules.schemas {
            for shape in row["data"]["shapes"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, shape)| shape)
            {
                if let Some(vocab) = shape["facets"]["lifecycle"]
                    .get("vocab")
                    .or_else(|| shape["facets"]["lifecycle"].get("vocab_ref"))
                    .and_then(Value::as_str)
                {
                    governing.insert(crate::meta::resolve_vocab_ref(vocab).to_owned());
                }
            }
        }
        for designator in governing {
            let rows:Vec<(String,String)>=sqlx::query_as("SELECT v.value,COALESCE(c.terminality,v.terminality) FROM vocabularies vocabulary JOIN vocabulary_values v ON v.vocabulary_id=vocabulary.id LEFT JOIN vocabulary_values c ON c.id=v.alias_of WHERE (vocabulary.id=? OR vocabulary.name=?) AND ((v.alias_of IS NULL AND v.status='active') OR (v.alias_of IS NOT NULL AND c.status='active' AND c.alias_of IS NULL)) ORDER BY v.id")
                .bind(&designator).bind(&designator).fetch_all(&mut *source).await?;
            let mut seen = std::collections::BTreeSet::new();
            for (value, terminality) in rows {
                if seen.insert(value.clone()) && terminality == "terminal_positive" {
                    rules
                        .positive
                        .entry(designator.clone())
                        .or_default()
                        .insert(value);
                }
            }
        }
        let kinds: Vec<String> = sqlx::query_scalar(
            "SELECT value FROM vocabulary_values WHERE vocabulary_id=? ORDER BY value",
        )
        .bind(crate::meta::kind::kind_vocabulary_id("Resolution"))
        .fetch_all(&mut *source)
        .await?;
        for kind in kinds {
            let resolved = crate::meta::kind::resolve_on(source, "Resolution", &kind).await?;
            if crate::generated::kinds::CoreKind::ResolutionDecision.matches(&resolved) {
                rules.decision_kinds.insert(kind);
            }
        }
    }
    Ok(rules)
}

pub(super) async fn import_destinations(
    db: &Db,
    host: &str,
    source: &mut SqliteConnection,
    report: &mut Report,
) -> Result<()> {
    let columns = sqlx::query("PRAGMA table_info(member_destinations)")
        .fetch_all(&mut *source)
        .await?;
    if columns.is_empty() {
        return Ok(());
    }
    let expr = columns
        .iter()
        .map(|r| {
            let c: String = r.get("name");
            format!("'{c}',\"{c}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    let rows:Vec<String>=sqlx::query_scalar(&format!("SELECT json_object({expr}) FROM member_destinations ORDER BY subject_account_id,collection_id")).fetch_all(&mut *source).await?;
    let event_columns = sqlx::query("PRAGMA table_info(awareness_events)")
        .fetch_all(&mut *source)
        .await?;
    let event_expr = event_columns
        .iter()
        .map(|r| {
            let c: String = r.get("name");
            format!("'{c}',\"{c}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    for raw in rows {
        let mut state: Value = serde_json::from_str(&raw)?;
        let account = state["subject_account_id"]
            .as_str()
            .ok_or("destination subject missing")?
            .to_owned();
        let collection = state["collection_id"]
            .as_str()
            .ok_or("destination collection missing")?
            .to_owned();
        let Some(principal) = report.principals.get(&account) else {
            report
                .refusals
                .push(issue(&collection, "unresolved private destination subject"));
            continue;
        };
        if !event_expr.is_empty() {
            let events:Vec<String>=sqlx::query_scalar(&format!("SELECT json_object({event_expr}) FROM awareness_events WHERE subject_account_id=? AND destination_id=? ORDER BY seq")).bind(&account).bind(&collection).fetch_all(&mut *source).await?;
            state["source_awareness_events"] = Value::Array(
                events
                    .into_iter()
                    .map(|s| serde_json::from_str(&s))
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            );
        }
        let destination = k::messaging::Destination {
            principal_id: principal.clone(),
            collection_id: collection.clone(),
            state,
        };
        match k::messaging::import_destination(db, host, &destination).await {
            Ok(_) => {
                let mut snapshot = db.pool().begin().await?;
                if k::messaging::destination_on(
                    &mut snapshot,
                    &destination.principal_id,
                    &collection,
                )
                .await?
                .as_ref()
                    == Some(&destination.state)
                {
                    report.message_destinations_verified += 1;
                } else {
                    report.refusals.push(issue(
                        &collection,
                        "private destination verification mismatch",
                    ));
                }
                snapshot.rollback().await?;
            }
            Err(_) => report.refusals.push(issue(
                &collection,
                "private destination import requires review",
            )),
        }
    }
    Ok(())
}

pub(super) async fn persona_snapshot(
    source: &mut SqliteConnection,
    record: &Record,
    report: &Report,
) -> Result<Option<k::messaging::PersonaState>> {
    if record.v1_type != "Entity" || record.kind.as_deref() != Some("persona") {
        return Ok(None);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='personas')",
    )
    .fetch_one(&mut *source)
    .await?;
    if !exists {
        return Ok(None);
    }
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT owner_person_id,state FROM personas WHERE persona_id=?")
            .bind(&record.id)
            .fetch_optional(&mut *source)
            .await?;
    let Some((owner_person_id, state)) = row else {
        return Ok(None);
    };
    let account: String = sqlx::query_scalar(
        "SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1",
    )
    .bind(&owner_person_id)
    .fetch_one(source)
    .await?;
    let owner_principal = report
        .principals
        .get(&account)
        .ok_or("unresolved persona owner")?
        .clone();
    Ok(Some(k::messaging::PersonaState {
        owner_principal,
        owner_person_id,
        state,
        source: None,
    }))
}
