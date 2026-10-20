//! Sealed, replayable v1 control/catalogue state. Imported runs never acquire
//! runtime authority; programme status is observational, never delivery.
use super::*;
use serde_json::Value;

pub(crate) const EVENT: &str = "kernel.v1_state_imported.v1";
pub(crate) const DDL: &str = "CREATE TABLE kernel_v1_state (
 section TEXT NOT NULL, source_id TEXT NOT NULL, origin TEXT NOT NULL,
 payload TEXT NOT NULL, account_principal TEXT, record_id TEXT,
 observed_at TEXT NOT NULL, event_seq INTEGER NOT NULL,
 PRIMARY KEY(section,source_id))";

pub(crate) const RUN_INDEX:&str="CREATE INDEX idx_kernel_v1_state_run ON kernel_v1_state(section,json_extract(payload,'$.run_key'))";
pub(crate) const ACCOUNT_INDEX:&str="CREATE INDEX idx_kernel_v1_state_account ON kernel_v1_state(section,account_principal,record_id)";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedState {
    pub section: String,
    pub source_id: String,
    pub origin: String,
    /// Canonical row JSON is sealed as text: reprojection/retry must not reparse floats.
    pub value_json: Option<String>,
    pub account_principal: Option<String>,
    pub record_id: Option<String>,
    pub observed_at: String,
    pub snapshot: Value,
}
fn validate(row: &ImportedState) -> Result<()> {
    let value = row
        .value_json
        .as_ref()
        .map(|v| serde_json::from_str::<Value>(v))
        .transpose()?;
    if row.value_json.is_none() && matches!(row.section.as_str(), "runs" | "run_intents" | "claims")
    {
        return Err(Error::engine(
            "historical coordination evidence cannot be erased",
        ));
    }
    if !matches!(
        row.section.as_str(),
        "record_deletion_guards"
            | "account_directory"
            | "vocabularies"
            | "vocabulary_values"
            | "schema_config"
            | "onboarding_programmes"
            | "onboarding_programme_sources"
            | "member_obligations"
            | "member_obligation_progress"
            | "runs"
            | "run_intents"
            | "claims"
    ) || row.source_id.is_empty()
        || row.origin.is_empty()
        || value.as_ref().is_some_and(|v| !v.is_object())
        || chrono::DateTime::parse_from_rfc3339(&row.observed_at).is_err()
        || !row.snapshot.is_object()
    {
        return Err(Error::engine("invalid imported catalogue/control state"));
    }
    Ok(())
}
pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(&DDL.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    for ddl in [RUN_INDEX, ACCOUNT_INDEX] {
        sqlx::query(&ddl.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
fn preserve_identity(section: &str, old: &str, new: &str) -> Result<()> {
    let keys: &[&str] = match section {
        "runs" => &[
            "activity_id",
            "run_key",
            "account_id",
            "started_at",
            "start_event_id",
            "start_event_seq",
        ],
        "run_intents" => &[
            "id",
            "source_seq",
            "run_key",
            "account_id",
            "intent",
            "declared_at",
        ],
        "claims" => &[
            "id",
            "record_id",
            "account_id",
            "run_key",
            "actor",
            "claimed_at",
            "baseline_without_event",
        ],
        _ => return Ok(()),
    };
    let old: Value = serde_json::from_str(old)?;
    let new: Value = serde_json::from_str(new)?;
    if keys.iter().any(|key| old[*key] != new[*key]) {
        return Err(Error::conflict("historical coordination identity differs"));
    }
    Ok(())
}
/// Each row and receipt are atomic. Bounded batches amortize SQLite commits;
/// unchanged retries append nothing, including after A→B→A transitions.
pub async fn import_state_batch_as(
    db: &Db,
    host: &str,
    rows: &[ImportedState],
) -> Result<Vec<ImportResult>> {
    if rows.len() > 256 {
        return Err(Error::engine("state import batch exceeds 256 rows"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    hq::require_source_import_open(&mut tx).await?;
    let mut acts = crate::act::ActAllocation::new();
    let mut result = Vec::new();
    for row in rows {
        validate(row)?;
        validate_account(&mut tx, row).await?;
        let original:Option<(String,String,Option<String>,Option<String>)>=sqlx::query_as(
            "SELECT origin,payload,account_principal,record_id FROM kernel_v1_state WHERE section=? AND source_id=?")
            .bind(&row.section).bind(&row.source_id).fetch_optional(&mut *tx).await?;
        if original.as_ref().is_some_and(|v| v.0 != row.origin) {
            return Err(Error::conflict("imported state source origin differs"));
        }
        if let (Some((_, old, _, _)), Some(new)) = (&original, &row.value_json) {
            preserve_identity(&row.section, old, new)?;
        }
        let unchanged = match (&original, &row.value_json) {
            (None, None) => true,
            (Some((_, payload, account, record)), Some(value)) => {
                payload == value && account == &row.account_principal && record == &row.record_id
            }
            _ => false,
        };
        if unchanged {
            result.push(ImportResult::Unchanged);
            continue;
        }
        crate::store::append_kernel_v1_state_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: KERNEL_ROOT_ID.into(),
                event_type: EVENT.into(),
                payload: serde_json::to_value(row)?,
                actor: Some(host.into()),
            },
            &mut acts,
        )
        .await?;
        result.push(if original.is_some() {
            ImportResult::Updated
        } else {
            ImportResult::Created
        });
    }
    tx.commit().await?;
    Ok(result)
}
async fn validate_account(conn: &mut SqliteConnection, row: &ImportedState) -> Result<()> {
    let value = row
        .value_json
        .as_ref()
        .map(|v| serde_json::from_str::<Value>(v))
        .transpose()?;
    {
        if let Some(key) = value
            .as_ref()
            .and_then(|v| v.get("run_key").or_else(|| v.get("updated_run_key")))
            .and_then(Value::as_str)
        {
            let collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal WHERE p.auth_binding=?)").bind(format!("mcp-run:{key}")).fetch_one(&mut *conn).await?;
            if collision {
                return Err(Error::conflict(
                    "historical run key collides with native runtime authority",
                ));
            }
        }
    }
    if let Some(value) = &value {
        if value.get("account_id").is_some_and(|v| !v.is_string()) {
            return Err(Error::engine("invalid imported account identity"));
        }
        let key = match row.section.as_str() {
            "account_directory" => Some("person_record_id"),
            "claims" | "record_deletion_guards" => Some("record_id"),
            _ => None,
        };
        if let Some(key) = key {
            if value.get(key).and_then(Value::as_str) != row.record_id.as_deref() {
                return Err(Error::engine("imported state record scope differs"));
            }
        }
    }
    let account = value
        .as_ref()
        .and_then(|v| v.get("account_id"))
        .and_then(Value::as_str);
    match (account, &row.account_principal) {
        (Some(account), Some(principal)) => {
            let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account' AND auth_binding=?)")
                .bind(principal).bind(account).fetch_one(conn).await?;
            if !valid {
                return Err(Error::engine("imported account/principal binding differs"));
            }
        }
        (Some(_), None) => return Err(Error::engine("imported account principal missing")),
        _ => {}
    }
    Ok(())
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine(
            "imported catalogue/control state requires the kernel root anchor",
        ));
    }
    let row: ImportedState = event_payload(event)?;
    validate(&row)?;
    validate_account(conn, &row).await?;
    let original: Option<String> =
        sqlx::query_scalar("SELECT origin FROM kernel_v1_state WHERE section=? AND source_id=?")
            .bind(&row.section)
            .bind(&row.source_id)
            .fetch_optional(&mut *conn)
            .await?;
    if original.is_some_and(|o| o != row.origin) {
        return Err(Error::conflict("imported state source origin differs"));
    }
    if let Some(new) = &row.value_json {
        if let Some(old) = sqlx::query_scalar::<_, String>(
            "SELECT payload FROM kernel_v1_state WHERE section=? AND source_id=?",
        )
        .bind(&row.section)
        .bind(&row.source_id)
        .fetch_optional(&mut *conn)
        .await?
        {
            preserve_identity(&row.section, &old, new)?;
        }
    }
    match &row.value_json {
        Some(value) => {
            sqlx::query("INSERT INTO kernel_v1_state VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(section,source_id) DO UPDATE SET payload=excluded.payload,account_principal=excluded.account_principal,record_id=excluded.record_id,observed_at=excluded.observed_at,event_seq=excluded.event_seq")
            .bind(&row.section).bind(&row.source_id).bind(&row.origin).bind(value)
            .bind(&row.account_principal).bind(&row.record_id).bind(&row.observed_at).bind(event.local_seq).execute(conn).await?;
        }
        None => {
            sqlx::query("DELETE FROM kernel_v1_state WHERE section=? AND source_id=?")
                .bind(&row.section)
                .bind(&row.source_id)
                .execute(conn)
                .await?;
        }
    }
    Ok(())
}
/// Internal rows only; each public surface must apply its own caller admission
/// before returning any payload (especially member/run/claim evidence).
pub(crate) async fn rows_on(conn: &mut SqliteConnection, section: &str) -> Result<Vec<Value>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM kernel_v1_state WHERE section=? ORDER BY source_id",
    )
    .bind(section)
    .fetch_all(conn)
    .await?;
    rows.into_iter()
        .map(|r| serde_json::from_str(&r).map_err(Into::into))
        .collect()
}

pub(crate) async fn schema_rows_on(
    conn: &mut SqliteConnection,
    actor: &str,
) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    let mut schema = vec![];
    for row in rows_on(conn, "schema_config").await? {
        let anchor = row["applies_to_collection_id"].as_str().map(str::to_owned);
        if let Some(anchor) = &anchor {
            let target = if anchor == "native:root" {
                crate::events::KERNEL_ROOT_ID
            } else {
                anchor
            };
            if !kernel_effective_capability_on(conn, actor, target)
                .await?
                .allows(Capability::View)
            {
                continue;
            }
        }
        let text = |key: &str| -> Result<String> {
            row[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::engine("invalid imported schema row"))
        };
        schema.push(crate::query::cascade::SchemaConfigRow {
            id: text("id")?,
            layer: text("layer")?,
            name: row["name"].as_str().map(str::to_owned),
            data: serde_json::from_str(&text("data")?)?,
            applies_to_collection_id: anchor,
            version_lineage: row["version_lineage"].as_str().map(str::to_owned),
            created_at: text("created_at")?,
        });
    }
    Ok(schema)
}

pub(crate) async fn interpreter_on(
    conn: &mut SqliteConnection,
    actor: &str,
) -> Result<crate::query::lifecycle::LifecycleInterpreter> {
    let schema = schema_rows_on(conn, actor).await?;
    crate::query::lifecycle::LifecycleInterpreter::from_imported_rows(
        schema,
        rows_on(conn, "vocabularies").await?,
        rows_on(conn, "vocabulary_values").await?,
    )
}
/// v1 schema overlays bind to the immediate home record, not the child id.
/// Internal semantic identity; public home disclosure still checks visibility.
pub(crate) async fn lifecycle_bearer_on(
    conn: &mut SqliteConnection,
    home: &str,
    record: Option<&str>,
) -> Result<String> {
    if home == crate::events::KERNEL_ROOT_ID {
        return Ok("native:root".into());
    }
    let mapped = sqlx::query_scalar::<_, String>("SELECT json_extract(payload,'$.source_record_id') FROM main.content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
        .bind(home).fetch_optional(&mut *conn).await?.unwrap_or_else(|| home.to_owned());
    if record == Some(mapped.as_str()) {
        let moved: Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.logical_home_id') FROM main.content_events WHERE record_id=? AND type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ORDER BY seq DESC LIMIT 1")
            .bind(record).fetch_optional(&mut *conn).await?.flatten();
        if let Some(moved) = moved {
            return Ok(moved);
        }

        let original: Option<String> = sqlx::query_scalar("SELECT CASE WHEN json_extract(payload,'$.legacy.payload.policy_anchor')=? THEN json_extract(payload,'$.legacy.payload.original_home') END FROM main.content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' ORDER BY seq DESC LIMIT 1")
            .bind(&mapped).bind(&mapped).fetch_optional(&mut *conn).await?.flatten();
        if let Some(original) = original {
            return Ok(original);
        }
    }
    Ok(mapped)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn lifecycle_as(
    db: &Db,
    actor: &str,
    typ: &str,
    kind: Option<&str>,
    id: &str,
    lifecycle: Option<&str>,
) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel_require(&mut tx, actor, id, Capability::View).await?;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let bearer = lifecycle_bearer_on(&mut tx, &home, Some(id)).await?;
    let interpreter = interpreter_on(&mut tx, actor).await?;
    Ok(serde_json::to_value(interpreter.interpret(
        typ,
        kind,
        Some(&bearer),
        lifecycle,
    ))?)
}

/// Member state is read-only. Completed/declined generations never enter the
/// pending list; no bootstrap action changes obligations or replays delivery.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn onboarding_as(db: &Db, actor: &str, is_member: bool) -> Result<Value> {
    if !is_member {
        return Ok(
            serde_json::json!({"status":"read_only","delivery_enabled":false,"pending":[],"programmes":[]}),
        );
    }
    let mut tx = db.write_pool().begin().await?;
    let rows:Vec<String>=sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='member_obligations' AND account_principal=? ORDER BY source_id").bind(actor).fetch_all(&mut *tx).await?;
    let obligations: Vec<Value> = rows
        .into_iter()
        .map(|v| serde_json::from_str(&v))
        .collect::<std::result::Result<_, _>>()?;
    let pending: Vec<_> = obligations
        .iter()
        .filter(|v| v["state"] == "pending")
        .cloned()
        .collect();
    // Programme/source status is visible only when all its retained sources
    // are visible. No hidden source ids, titles or evidence leak to members.
    let mut programmes = vec![];
    let sources = rows_on(&mut tx, "onboarding_programme_sources").await?;
    for programme in rows_on(&mut tx, "onboarding_programmes").await? {
        let mut visible = true;
        for source in sources
            .iter()
            .filter(|s| s["programme_id"] == programme["id"])
        {
            let id = source["source_record_id"].as_str().unwrap_or_default();
            if !kernel_effective_capability_on(&mut tx, actor, id)
                .await?
                .allows(Capability::View)
            {
                visible = false;
                break;
            }
        }
        if visible {
            programmes.push(serde_json::json!({"id":programme["id"],"generation":programme["generation"],"enabled":programme["enabled"]}));
        }
    }
    let progress:Vec<String>=sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='member_obligation_progress' AND account_principal=? ORDER BY source_id").bind(actor).fetch_all(&mut *tx).await?;
    let progress: Vec<Value> = progress
        .into_iter()
        .map(|v| serde_json::from_str(&v))
        .collect::<std::result::Result<_, _>>()?;
    Ok(
        serde_json::json!({"status":"read_only","delivery_enabled":false,"pending":pending,"states":obligations,"progress":progress,"programmes":programmes}),
    )
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn disclosed_accounts_on(
    conn: &mut SqliteConnection,
    actor: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let mut allowed = std::collections::BTreeSet::from([actor.to_owned()]);
    // SQL staging may own a TEMP content_events facade. The import witness
    // must always come from the canonical main log.
    let directory:Vec<(String,String)>=sqlx::query_as("SELECT DISTINCT d.account_principal,d.record_id FROM kernel_v1_state d JOIN kernel_records p ON p.id=d.record_id WHERE d.section='account_directory' AND d.account_principal IS NOT NULL AND p.pin_family='native.v1.record' AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=p.id AND f.name='v1_type' AND f.value_json='\"Entity\"') AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=p.id AND f.name='v1_kind' AND f.value_json='\"person\"') AND EXISTS(SELECT 1 FROM main.content_events e JOIN kernel_principals h ON h.principal_id=e.actor WHERE e.record_id=p.id AND e.type='kernel.import_state.v1' AND h.auth_binding=?)").bind(HOST_IMPORT_BINDING).fetch_all(&mut *conn).await?;
    for (account, person) in directory {
        if kernel_effective_capability_on(conn, actor, &person)
            .await?
            .allows(Capability::View)
        {
            allowed.insert(account);
        }
    }
    Ok(allowed)
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn claims_as(db: &Db, actor: &str, id: &str) -> Result<Vec<Value>> {
    let mut tx = db.write_pool().begin().await?;
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(&mut tx, actor).await?;
    kernel_require(&mut tx, actor, id, Capability::View).await?;
    let allowed = disclosed_accounts_on(&mut tx, actor).await?;
    let rows:Vec<(String,String,Option<String>)>=sqlx::query_as("SELECT payload,observed_at,account_principal FROM kernel_v1_state WHERE section='claims' AND record_id=? ORDER BY source_id").bind(id).fetch_all(&mut *tx).await?;
    rows.into_iter()
        .filter(|(_, _, account)| account.as_ref().is_some_and(|a| allowed.contains(a)))
        .map(|(p, cutover, _)| {
            let mut v: Value = serde_json::from_str(&p)?;
            v["historical"] = true.into();
            v["occupied"] = false.into();
            v["source_observed_at"] = cutover.clone().into();
            v["effective_released_at"] = v
                .get("released_at")
                .filter(|v| !v.is_null())
                .cloned()
                .unwrap_or(cutover.into());
            v["release_basis"] = if v.get("released_at").is_some_and(|v| !v.is_null()) {
                "source_release"
            } else {
                "cutover_nonoccupying"
            }
            .into();
            Ok(v)
        })
        .collect()
}

type RecordVocabularyContext = (Option<String>, Option<String>, Option<String>, String);

pub(crate) async fn validate_native_event(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let create = event.event_type == "kernel.record_created.v1";
    if !create
        && !matches!(
            event.event_type.as_str(),
            "kernel.record_revised.v1" | "kernel.record_revised.v2"
        )
    {
        return Ok(());
    }
    // UUID-preserving imports use the ordinary record event types too. Their
    // sealed host attribution distinguishes legacy evidence from runtime input.
    let imported: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND auth_binding=?)",
    )
    .bind(&event.actor)
    .bind(HOST_IMPORT_BINDING)
    .fetch_one(&mut *conn)
    .await?;
    if imported {
        return Ok(());
    }
    let payload: Value = event_payload(event)?;
    if !create
        && payload
            .get("fields")
            .and_then(|f| f.get("lifecycle"))
            .is_none()
    {
        return Ok(());
    }
    let row: Option<RecordVocabularyContext> = sqlx::query_as(
        "SELECT primary_type,kind,pin_family,home_id FROM kernel_records WHERE id=?",
    )
    .bind(&event.record_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((typ, kind, family, home)) = row else {
        return Ok(());
    };
    if family.as_deref() != Some(crate::v2_standard::v1_compat::FAMILY)
        && family.as_deref() != Some(crate::v2_standard::DOCUMENT_FAMILY)
    {
        return Ok(());
    }
    let fields:Vec<(String,String)>=sqlx::query_as("SELECT name,value_json FROM kernel_record_fields WHERE record_id=? AND name IN ('v1_type','v1_kind','lifecycle')").bind(&event.record_id).fetch_all(&mut *conn).await?;
    let fields: std::collections::BTreeMap<String, Value> = fields
        .into_iter()
        .map(|(k, v)| Ok((k, serde_json::from_str(&v)?)))
        .collect::<Result<_>>()?;
    let compat = family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY);
    let typ = if compat {
        fields.get("v1_type").and_then(Value::as_str)
    } else {
        typ.as_deref()
    };
    let kind = if compat {
        fields.get("v1_kind").and_then(Value::as_str)
    } else {
        kind.as_deref()
    };
    let interpreter = interpreter_on(conn, event.actor.as_deref().unwrap_or_default()).await?;
    if create
        && interpreter.canonical_imported_kind(typ.unwrap_or_default(), kind.unwrap_or_default())
            != kind.unwrap_or_default()
    {
        return Err(Error::engine(
            "canonicalize the kind alias before kernel record creation",
        ));
    }
    let bearer = lifecycle_bearer_on(conn, &home, Some(&event.record_id)).await?;
    interpreter.validate_imported_write(
        typ.unwrap_or_default(),
        kind.unwrap_or_default(),
        Some(&bearer),
        fields.get("lifecycle").and_then(Value::as_str),
    )
}
