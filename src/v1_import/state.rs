//! Source catalogue and control folds. Raw row values are retained as legacy
//! evidence; none is dispatched as a native command or a live claim.
use super::*;
use serde_json::Value;

const TABLES: &[(&str, &str, &[&str])] = &[
    (
        "account_configs",
        "account_configs",
        &["account_id", "kind"],
    ),
    ("vocabularies", "vocabularies", &["id"]),
    ("vocabulary_values", "vocabulary_values", &["id"]),
    ("schema_config", "schema_config", &["id"]),
    ("onboarding_programmes", "onboarding_programmes", &["id"]),
    (
        "onboarding_programme_sources",
        "onboarding_programme_sources",
        &["programme_id", "source_record_id"],
    ),
    (
        "member_obligations",
        "member_obligations",
        &["account_id", "programme_id", "generation"],
    ),
    (
        "member_obligation_progress",
        "member_obligation_progress",
        &["account_id", "programme_id", "generation"],
    ),
    ("agent_runs", "runs", &["activity_id"]),
];
#[derive(Default, Serialize)]
pub struct StateCounts {
    pub source: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub refused: usize,
    pub removed: usize,
    pub retained_missing_source: usize,
    pub verified: usize,
}
#[derive(Default, Serialize)]
pub struct StateReport {
    pub member_contexts_prepared: bool,
    pub member_contexts_source_present: bool,
    pub member_contexts_invalid: usize,
    pub identity_directory_prepared: bool,
    pub surface_bindings_prepared: bool,
    pub sections: BTreeMap<String, StateCounts>,
    pub run_intents_source_present: bool,
    pub directory_self_only_accounts: usize,
    pub account_configs_prepared: bool,
    pub nonfinite_vocabulary_ordinals: usize,
    pub claims_held_at_snapshot: usize,
    pub claims_historical_nonoccupying: usize,
    pub onboarding_delivery: &'static str,
}
async fn present(source: &mut SqliteConnection, table: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
    )
    .bind(table)
    .fetch_one(source)
    .await?)
}
async fn table_rows(source: &mut SqliteConnection, table: &str) -> Result<Vec<Value>> {
    if !present(source, table).await? {
        return Ok(vec![]);
    }
    let columns: Vec<String> = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(&mut *source)
        .await?
        .iter()
        .map(|r| r.get("name"))
        .collect();
    let columns = columns
        .iter()
        .map(|c| {
            let name = c.replace('"', "\"\"");
            let expr = if table == "vocabulary_values" && c == "ordinal" {
                format!("CAST(\"{name}\" AS TEXT)")
            } else {
                format!("\"{name}\"")
            };
            format!("'{}',{expr}", c.replace('\'', "''"))
        })
        .collect::<Vec<_>>()
        .join(",");
    // Bypass SQLite JSON rendering and serde float reparse for REAL ordinals.
    // The sealed lane stores this canonical row text without reparsing it.
    let extra = if table == "vocabulary_values" {
        ",ordinal AS raw_ordinal"
    } else if table == "account_configs" {
        ",NOT EXISTS(SELECT 1 FROM records r WHERE r.id=account_configs.record_id) AS target_missing,EXISTS(SELECT 1 FROM records r WHERE r.id=account_configs.record_id AND r.deleted_at IS NOT NULL) AS target_deleted"
    } else {
        ""
    };
    let rows = sqlx::query(&format!(
        "SELECT json_object({columns}) AS row_json{extra} FROM {table}"
    ))
    .fetch_all(source)
    .await?;
    rows.into_iter()
        .map(|row| {
            let mut value: Value = serde_json::from_str(row.get::<&str, _>("row_json"))?;
            if table == "account_configs" {
                value["_target_missing"] = Value::Bool(row.get::<bool, _>("target_missing"));
                value["_target_deleted"] = Value::Bool(row.get::<bool, _>("target_deleted"));
            }
            if table == "vocabulary_values" {
                let number: Option<f64> = row.try_get("raw_ordinal")?;
                if let Some(number) = number.and_then(serde_json::Number::from_f64) {
                    value["ordinal"] = Value::Number(number);
                }
            }
            Ok(value)
        })
        .collect()
}
pub(super) async fn accounts(source: &mut SqliteConnection) -> Result<BTreeSet<String>> {
    let mut accounts = BTreeSet::new();
    for table in [
        "member_contexts",
        "agent_runs",
        "account_configs",
        "alpha_tab_orders",
        "member_obligations",
        "member_obligation_progress",
    ] {
        if present(source, table).await? {
            let ids: Vec<String> =
                sqlx::query_scalar(&format!("SELECT DISTINCT account_id FROM {table}"))
                    .fetch_all(&mut *source)
                    .await?;
            accounts.extend(ids);
        }
    }
    let claims:Vec<String>=sqlx::query_scalar("SELECT DISTINCT json_extract(payload,'$.claimed_by_account') FROM content_events WHERE type='record.updated' AND json_valid(payload) AND json_type(payload,'$.claimed_by_account')='text'").fetch_all(&mut *source).await?;
    accounts.extend(claims);
    let has_claims: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('records') WHERE name='claimed_by_account')",
    )
    .fetch_one(&mut *source)
    .await?;
    if has_claims {
        let current: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT claimed_by_account FROM records WHERE claimed_by_account IS NOT NULL",
        )
        .fetch_all(&mut *source)
        .await?;
        accounts.extend(current);
    }
    Ok(accounts)
}
pub(super) async fn import(
    db: &Db,
    host: &str,
    source: &mut SqliteConnection,
    origin: &str,
    report: &mut Report,
) -> Result<()> {
    let mut sections = BTreeMap::<String, Vec<(String, Value)>>::new();
    for (table, section, keys) in TABLES {
        if *table == "account_configs" && !present(source, table).await? {
            let previous: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_v1_state WHERE section='account_configs' AND origin=?)").bind(origin).fetch_one(db.pool()).await?;
            if previous {
                return Err("account_configs source table missing after previous capture".into());
            }
        }
        let rows = table_rows(source, table).await?;
        let rows = rows
            .into_iter()
            .map(|row| {
                let key = serde_json::to_string(
                    &keys
                        .iter()
                        .map(|key| row.get(*key).cloned().unwrap_or(Value::Null))
                        .collect::<Vec<_>>(),
                )?;
                Ok((key, row))
            })
            .collect::<Result<Vec<_>>>()?;
        sections.insert((*section).into(), rows);
    }
    super::member_context::capture(source, db, origin, report, &mut sections).await?;
    deletion_guards(source, &mut sections).await?;
    sections.insert(
        "surface_bindings".into(),
        super::surface_bindings::rows(source).await?,
    );
    // Preserve v1 directory privacy: another account's runs/intents require
    // its verified, visible Person record, never a blanket root-view bypass.
    let mut account_map = report.principals.clone();
    let prior:Vec<(String,String)>=sqlx::query_as("SELECT DISTINCT p.auth_binding,p.principal_id FROM kernel_v1_state s JOIN kernel_principals p ON p.principal_id=s.account_principal WHERE p.kind='account'").fetch_all(db.write_pool()).await?;
    account_map.extend(prior);
    let mut directory = vec![];
    let mut ambiguous_native_principals = 0;
    for account in account_map.keys() {
        let people:Vec<String>=sqlx::query_scalar("SELECT DISTINCT b.record_id FROM bindings b JOIN records p ON p.id=b.record_id WHERE b.system='account' AND b.is_canonical=1 AND b.identifier=? AND p.type='Entity' AND p.kind='person' AND p.deleted_at IS NULL").bind(account).fetch_all(&mut *source).await?;
        let person = if people.len() == 1 {
            people.first().cloned()
        } else {
            report.state.directory_self_only_accounts += 1;
            None
        };
        let native_principal = if let Some(person) = person.as_ref() {
            let values:Vec<String>=sqlx::query_scalar("SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1 ORDER BY identifier").bind(person).fetch_all(&mut *source).await?;
            if values.len() > 1 {
                ambiguous_native_principals += 1;
                report.refusals.push(issue(
                    person,
                    "ambiguous canonical native-principal in account directory",
                ));
            }
            if values.len() == 1 {
                values.into_iter().next()
            } else {
                None
            }
        } else {
            None
        };
        directory.push((
            account.clone(),
            json!({"account_id":account,"person_record_id":person,"native_principal_id":native_principal}),
        ));
    }
    sections.insert("account_directory".into(), directory);
    // Successful self-authored declarations are precisely v1's run_intents SQL
    // contract. The read log is optional, so its absence is explicitly reported.
    let mut intents = vec![];
    report.state.run_intents_source_present = present(source, "read_log_calls").await?;
    if present(source, "read_log_calls").await? && present(source, "agent_runs").await? {
        let rows:Vec<String>=sqlx::query_scalar("SELECT json_object('id',d.id,'source_seq',d.seq,'run_key',d.run_key,'account_id',r.account_id,'intent',d.intent,'declared_at',d.started_at,'ordinal',row_number() OVER(PARTITION BY d.run_key ORDER BY d.seq)) FROM read_log_calls d JOIN agent_runs r ON r.run_key=d.run_key AND r.account_id=d.actor WHERE d.tool='set_intent' AND d.outcome='ok' AND d.intent IS NOT NULL").fetch_all(&mut *source).await?;
        for row in rows {
            let row: Value = serde_json::from_str(&row)?;
            intents.push((row["id"].as_str().ok_or("intent id missing")?.into(), row));
        }
    }
    sections.insert("run_intents".into(), intents);
    // All durable claims (including releases), plus current state. A legacy
    // claim is evidence only; never populate the live provider occupancy lane.
    let mut claims = vec![];
    let claim_columns: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('records') WHERE name='claimed_by_account')",
    )
    .fetch_one(&mut *source)
    .await?;
    if claim_columns {
        let held: i64 =
            sqlx::query_scalar("SELECT count(*) FROM records WHERE claimed_by_account IS NOT NULL")
                .fetch_one(&mut *source)
                .await?;
        report.state.claims_held_at_snapshot = held as usize;
        let rows:Vec<String>=sqlx::query_scalar("SELECT json_object('id',e.id,'record_id',e.record_id,'account_id',json_extract(e.payload,'$.claimed_by_account'),'run_key',json_extract(e.payload,'$.claimed_run_key'),'actor',e.actor,'claimed_at',e.created_at,'released_at',(SELECT r.created_at FROM content_events r WHERE r.record_id=e.record_id AND r.seq>e.seq AND r.type='record.updated' AND json_type(r.payload,'$.claimed_by_account')='null' AND (r.actor=e.actor OR r.actor='local') ORDER BY r.seq LIMIT 1),'held_at_snapshot',EXISTS(SELECT 1 FROM records r WHERE r.id=e.record_id AND r.claimed_by_account=json_extract(e.payload,'$.claimed_by_account') AND r.claimed_at=e.created_at)) FROM content_events e WHERE e.type='record.updated' AND json_valid(e.payload) AND json_extract(e.payload,'$.claimed_by_account') IS NOT NULL").fetch_all(&mut *source).await?;
        for row in rows {
            let row: Value = serde_json::from_str(&row)?;
            claims.push((row["id"].as_str().ok_or("claim id missing")?.into(), row));
        }
        // Baseline claims can predate the available event log. Keep them, with an
        // explicit derived evidence identity rather than invent an original event.
        let current=sqlx::query("SELECT id,claimed_by_account,claimed_run_key,claimed_at FROM records WHERE claimed_by_account IS NOT NULL").fetch_all(&mut *source).await?;
        for row in current {
            let record: String = row.get("id");
            let at: String = row.get("claimed_at");
            let account: String = row.get("claimed_by_account");
            if claims.iter().any(|(_, v)| {
                v["record_id"] == record && v["claimed_at"] == at && v["account_id"] == account
            }) {
                continue;
            }
            let id = format!(
                "baseline-claim:{}",
                receipt(&format!("{origin}:{record}:{at}:{account}"))
            );
            claims.push((id.clone(),json!({"id":id,"record_id":record,"account_id":account,"run_key":row.get::<Option<String>,_>("claimed_run_key"),"claimed_at":at,"released_at":null,"held_at_snapshot":1,"baseline_without_event":true})));
        }
    }
    report.state.claims_historical_nonoccupying = claims.len();
    sections.insert("claims".into(), claims);
    report.state.onboarding_delivery = "read_only_no_delivery";
    let content: Option<(i64, String)> =
        sqlx::query_as("SELECT seq,id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *source)
            .await?;
    let control: Option<(i64, String)> = if present(source, "control_events").await? {
        sqlx::query_as("SELECT seq,id FROM control_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *source)
            .await?
    } else {
        None
    };
    let snapshot = json!({"content":content,"control":control});
    // Import observation time is explicit cutover evidence, not an invented v1
    // release/close timestamp. Unchanged rows retain their first observation.
    let observed_at = chrono::Utc::now().to_rfc3339();
    for (section, rows) in sections {
        let mut batch = vec![];
        let mut keys = BTreeSet::new();
        if section == "vocabulary_values" {
            report.state.nonfinite_vocabulary_ordinals = rows
                .iter()
                .filter(|(_, v)| v["ordinal"].is_string())
                .count();
        }
        let count = report.state.sections.entry(section.clone()).or_default();
        count.source = rows.len();
        for (key, value) in rows {
            if !keys.insert(key.clone()) {
                return Err("duplicate imported state identity".into());
            }
            let account_principal = value
                .get("account_id")
                .and_then(Value::as_str)
                .map(|account| {
                    account_map
                        .get(account)
                        .cloned()
                        .ok_or("imported control account has no principal")
                })
                .transpose()?;
            let record_id = value
                .get(if section == "member_contexts" {
                    "root_record_id"
                } else if section == "account_directory" {
                    "person_record_id"
                } else {
                    "record_id"
                })
                .and_then(Value::as_str)
                .map(str::to_owned);
            batch.push(k::v1_state::ImportedState {
                section: section.clone(),
                source_id: key,
                origin: origin.into(),
                value_json: Some(serde_json::to_string(&value)?),
                account_principal,
                record_id,
                observed_at: observed_at.clone(),
                snapshot: snapshot.clone(),
            });
        }
        let previous: Vec<String> = sqlx::query_scalar(
            "SELECT source_id FROM kernel_v1_state WHERE section=? AND origin=?",
        )
        .bind(&section)
        .bind(origin)
        .fetch_all(db.write_pool())
        .await?;
        for key in previous {
            if !keys.contains(&key) {
                // Historical coordination is not a current occupancy fold.
                // Source pruning must not erase evidence or unreserve run keys.
                if matches!(section.as_str(), "runs" | "run_intents" | "claims") {
                    let intact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_v1_state s JOIN content_events e ON e.seq=s.event_seq WHERE s.section=? AND s.source_id=? AND s.origin=? AND e.type='kernel.v1_state_imported.v1' AND json_extract(e.payload,'$.section')=s.section AND json_extract(e.payload,'$.source_id')=s.source_id AND json_extract(e.payload,'$.origin')=s.origin AND json_extract(e.payload,'$.record_id') IS s.record_id AND json_extract(e.payload,'$.value_json')=s.payload AND json_extract(e.payload,'$.account_principal') IS s.account_principal)").bind(&section).bind(&key).bind(origin).fetch_one(db.write_pool()).await?;
                    if !intact {
                        return Err(
                            "retained historical state differs from its sealed evidence".into()
                        );
                    }
                    count.retained_missing_source += 1;
                    count.unchanged += 1;
                    count.verified += 1;
                    continue;
                }
                count.removed += 1;
                batch.push(k::v1_state::ImportedState {
                    section: section.clone(),
                    source_id: key,
                    origin: origin.into(),
                    value_json: None,
                    account_principal: None,
                    record_id: None,
                    observed_at: observed_at.clone(),
                    snapshot: snapshot.clone(),
                });
            }
        }
        let mut failed = BTreeSet::new();
        for chunk in batch.chunks(256) {
            let results = match k::v1_state::import_state_batch_as(db, host, chunk).await {
                Ok(results) => results.into_iter().map(Ok).collect::<Vec<_>>(),
                Err(_) => {
                    // The bounded batch rolled back atomically. Isolate unsafe
                    // rows so a collision does not discard unrelated controls.
                    let mut results = vec![];
                    for row in chunk {
                        results.push(
                            k::v1_state::import_state_batch_as(db, host, std::slice::from_ref(row))
                                .await
                                .map(|v| v[0]),
                        );
                    }
                    results
                }
            };
            for (row, result) in chunk.iter().zip(results) {
                match result {
                    Ok(k::ImportResult::Created) => count.created += 1,
                    Ok(k::ImportResult::Updated) => count.updated += 1,
                    Ok(k::ImportResult::Unchanged) => count.unchanged += 1,
                    Err(error) => {
                        count.refused += 1;
                        failed.insert(row.source_id.clone());
                        report
                            .refusals
                            .push(issue(&row.source_id, &error.to_string()));
                    }
                }
            }
        }
        // Compare canonical text, not a second parse with a different float path.
        for row in &batch {
            if failed.contains(&row.source_id) {
                continue;
            }
            let value:Option<(String,Option<String>,Option<String>)>=sqlx::query_as("SELECT payload,account_principal,record_id FROM kernel_v1_state WHERE section=? AND source_id=?").bind(&section).bind(&row.source_id).fetch_optional(db.write_pool()).await?;
            let expected = row.value_json.as_ref().map(|v| {
                (
                    v.clone(),
                    row.account_principal.clone(),
                    row.record_id.clone(),
                )
            });
            if value != expected {
                return Err("imported control/catalogue verification mismatch".into());
            }
            if let Some(raw) = &row.value_json {
                let payload: Value = serde_json::from_str(raw)?;
                if let Some(account) = payload.get("account_id").and_then(Value::as_str) {
                    if account_map.get(account) != row.account_principal.as_ref() {
                        return Err("imported control account/principal mismatch".into());
                    }
                }
            }
            count.verified += 1;
        }
    }
    let directory = report
        .state
        .sections
        .get("account_directory")
        .ok_or("identity directory not inspected")?;
    // Publish a negative readiness receipt too: a prior successful resume must
    // not leave a usable marker behind when the source becomes ambiguous.
    let refused = directory.refused + ambiguous_native_principals;
    let complete = refused == 0 && directory.verified == directory.source + directory.removed;
    let accounts = directory.source;
    report
        .state
        .sections
        .get_mut("account_directory")
        .unwrap()
        .refused = refused;
    {
        k::v1_state::import_state_batch_as(
            db,
            host,
            &[k::v1_state::ImportedState {
                section: k::v1_state::IDENTITY_CAPTURE.into(),
                source_id: "identity-directory/v1".into(),
                origin: origin.into(),
                value_json: Some(
                    serde_json::json!({"version":k::v1_state::IDENTITY_CAPTURE_VERSION,"accounts":accounts,"refused":refused})
                        .to_string(),
                ),
                account_principal: None,
                record_id: None,
                observed_at: observed_at.clone(),
                snapshot: snapshot.clone(),
            }],
        )
        .await?;
        report.state.identity_directory_prepared = complete;
    }
    let configs = report
        .state
        .sections
        .get("account_configs")
        .ok_or("account config section not inspected")?;
    if configs.refused == 0 && configs.verified == configs.source + configs.removed {
        // A derived preparation receipt, never counted as a source row.
        k::v1_state::import_state_batch_as(
            db,
            host,
            &[k::v1_state::ImportedState {
                section: "account_config_capture".into(),
                source_id: "account_configs/v1".into(),
                origin: origin.into(),
                value_json: Some(serde_json::json!({"version":1}).to_string()),
                account_principal: None,
                record_id: None,
                observed_at: observed_at.clone(),
                snapshot: snapshot.clone(),
            }],
        )
        .await?;
        report.state.account_configs_prepared = true;
    }
    super::member_context::receipt(db, host, origin, &observed_at, &snapshot, report).await?;
    super::surface_bindings::receipt(db, host, origin, observed_at, snapshot, report).await
}

// Preserve exactly the two v1 store deletion guards. The derivation runtime
// remains unavailable; a missing source table is explicitly unknown, not false.
async fn deletion_guards(
    source: &mut SqliteConnection,
    sections: &mut BTreeMap<String, Vec<(String, Value)>>,
) -> Result<()> {
    let heads = present(source, "derivation_target_heads").await?;
    let roles = present(source, "derivation_artifact_role_assignments").await?
        && present(source, "derivation_artifact_role_heads").await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM records ORDER BY id")
        .fetch_all(&mut *source)
        .await?;
    let mut guards = Vec::with_capacity(ids.len());
    for id in ids {
        let body: Option<bool> = if heads {
            Some(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM derivation_target_heads WHERE target_kind='record' AND target_record_id=? AND target_slot='body' AND active_binding_id IS NOT NULL)").bind(&id).fetch_one(&mut *source).await?)
        } else {
            None
        };
        let role: Option<bool> = if roles {
            Some(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM derivation_artifact_role_assignments a JOIN derivation_artifact_role_heads h ON h.active_assignment_id=a.assignment_id WHERE a.target_kind='record' AND a.target_record_id=? AND a.target_slot='body')").bind(&id).fetch_one(&mut *source).await?)
        } else {
            None
        };
        guards.push((
            id.clone(),
            json!({"record_id":id,"active_body_binding":body,"active_artifact_role":role}),
        ));
    }
    sections.insert("record_deletion_guards".into(), guards);
    Ok(())
}
