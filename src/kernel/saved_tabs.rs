//! Event-backed host-owned working slots. These tables are projections, never
//! an independent source of sync truth. All writes pass canonical append.
use super::*;
use serde_json::{json, Value};

pub(crate) const PROTECTED_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM main.kernel_saved_tabs WHERE record_id=?1 OR home_id=?1)";

pub(crate) const EVENT: &str = "kernel.saved_tab_changed.v1";
pub(crate) const DDL: &str = "CREATE TABLE kernel_saved_tabs (
 principal_id TEXT NOT NULL REFERENCES kernel_principals(principal_id),
 record_id TEXT NOT NULL UNIQUE REFERENCES kernel_records(id),
 creation_key TEXT NOT NULL, create_digest TEXT NOT NULL,
 definition TEXT NOT NULL, event_seq INTEGER NOT NULL,
 home_id TEXT NOT NULL UNIQUE REFERENCES kernel_roots(root_id),
 PRIMARY KEY(principal_id,record_id), UNIQUE(principal_id,creation_key))";
pub(crate) const OPS_DDL: &str = "CREATE TABLE kernel_saved_tab_operations (
 principal_id TEXT NOT NULL, operation_id TEXT NOT NULL, record_id TEXT NOT NULL,
 request_digest TEXT NOT NULL, event_seq INTEGER NOT NULL,
 PRIMARY KEY(principal_id,operation_id))";

pub(crate) const ACTIVE_INDEX: &str = "CREATE INDEX idx_kernel_saved_tab_active ON kernel_saved_tabs(principal_id,json_extract(definition,'$.state'),record_id)";

pub(crate) const CREATE_INDEX: &str = "CREATE UNIQUE INDEX idx_kernel_saved_tab_creation ON content_events(actor,json_extract(payload,'$.creation_key')) WHERE type='kernel.saved_tab_changed.v1' AND json_extract(payload,'$.operation_id') IS NULL";
pub(crate) const OP_INDEX: &str = "CREATE UNIQUE INDEX idx_kernel_saved_tab_operation ON content_events(actor,json_extract(payload,'$.operation_id')) WHERE type='kernel.saved_tab_changed.v1' AND json_extract(payload,'$.operation_id') IS NOT NULL";

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [DDL, OPS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query(&ACTIVE_INDEX.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    for ddl in [CREATE_INDEX, OP_INDEX] {
        sqlx::query(&ddl.replacen(
            "CREATE UNIQUE INDEX",
            "CREATE UNIQUE INDEX IF NOT EXISTS",
            1,
        ))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Serving never installs definitions or repairs projections. A missing prerequisite
/// is an explicit capability result; corruption remains an error.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn available_on(conn: &mut SqliteConnection) -> Result<bool> {
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM main.sqlite_master WHERE type='table' AND name IN ('kernel_saved_tabs','kernel_saved_tab_operations')")
        .fetch_one(&mut *conn).await?;
    if tables != 2 {
        return Ok(false);
    }
    let manifest = crate::v2_standard::saved_tabs::package();
    let expected = manifest.identity()?;
    let Some(selection) =
        read_package_selection_in(conn, KERNEL_ROOT_ID, &manifest.namespace, &manifest.name)
            .await?
    else {
        return Ok(false);
    };
    if !selection
        .selected
        .is_some_and(|p| p.version == 1 && p.digest == expected.digest)
    {
        return Ok(false);
    }
    Ok(
        matches!(resolve_effective_adoption(conn, crate::v2_standard::saved_tabs::FAMILY, KERNEL_ROOT_ID).await?,
        Some(ScopedAdoption::Adopted(pin)) if pin.version == 1 && pin.digest == manifest.definitions[0].digest),
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Location {
    pub record_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Definition {
    pub version: u32,
    pub app: String,
    pub custom_title: Option<String>,
    pub initial_location: Location,
    pub state: String,
}
impl Definition {
    pub(crate) fn fields(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("serializable definition");
        value["title"] = json!(format!("Saved {} tab", self.app));
        if self.custom_title.is_none() {
            value.as_object_mut().unwrap().remove("customTitle");
        }
        if self.initial_location.record_id.is_none() {
            value["initialLocation"]
                .as_object_mut()
                .unwrap()
                .remove("recordId");
        }
        value
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 || !matches!(self.state.as_str(), "active" | "retired") {
            return Err(Error::engine("invalid saved tab version or state"));
        }
        token(&self.app, 256)?;
        if let Some(id) = &self.initial_location.record_id {
            token(id, 256)?;
        }
        if let Some(title) = &self.custom_title {
            if normalize_title(title)? != *title {
                return Err(Error::engine("saved tab title is not normalized"));
            }
        }
        Ok(())
    }
}
pub(crate) fn token(value: &str, bound: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > bound
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::engine("invalid saved tab identifier"));
    }
    Ok(())
}
pub(crate) fn normalize_title(value: &str) -> Result<String> {
    if value.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
        return Err(Error::engine("saved tab title contains control characters"));
    }
    let normalized = value
        .split(|c: char| c.is_whitespace() || c == '\u{feff}')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() || normalized.chars().count() > 256 {
        return Err(Error::engine(
            "saved tab title must contain 1 to 256 code points",
        ));
    }
    Ok(normalized)
}
#[derive(sqlx::FromRow)]
pub(crate) struct Row {
    #[cfg(feature = "v2-kernel-probe")]
    pub record_id: String,
    pub creation_key: String,
    #[cfg(feature = "v2-kernel-probe")]
    pub create_digest: String,
    pub definition: String,
    pub event_id: String,
}
impl Row {
    pub(crate) fn definition(&self) -> Result<Definition> {
        Ok(serde_json::from_str(&self.definition)?)
    }
    pub(crate) fn revision(&self) -> String {
        format!("saved-tab:{}", self.event_id)
    }
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn value(&self) -> Result<Value> {
        Ok(
            json!({"record_id":self.record_id,"revision":self.revision(),"definition":self.definition()?}),
        )
    }
}
pub(crate) async fn read_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<Row>> {
    Ok(sqlx::query_as("SELECT s.record_id,s.creation_key,s.create_digest,s.definition,e.id AS event_id FROM main.kernel_saved_tabs s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.principal_id=? AND s.record_id=?")
        .bind(actor).bind(id).fetch_optional(conn).await?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Change {
    pub created_act: Option<i64>,
    pub principal_id: String,
    pub creation_key: String,
    pub operation_id: Option<String>,
    pub expected_revision: Option<String>,
    pub definition: Definition,
    pub request_digest: String,
    pub reason: String,
}

// Protected records and their self-policy homes admit only this event. This
// catches generic fields/facets, archival, deletion, moves and policy editors
// at the append choke point, including batch/low-level supported commands.
pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    // Legacy databases have no kernel projections; their ordinary events do
    // not acquire authority over these v2-only records.
    if !event.event_type.starts_with("kernel.") {
        return Ok(());
    }
    if event.event_type == EVENT {
        return validate(conn, event).await.map(|_| ());
    }
    if event.event_type == "kernel.record_created.v1" {
        let p: KernelRecordPayload = event_payload(event)?;
        if p.pin
            .as_ref()
            .is_some_and(|p| p.family == crate::v2_standard::saved_tabs::FAMILY)
            && p.origin
                .as_ref()
                .and_then(|v| v.get("saved_tab_creation_key"))
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(Error::engine("saved tabs require scoped provisioning"));
        }
    }
    let protected: bool = sqlx::query_scalar(PROTECTED_SQL)
        .bind(&event.record_id)
        .fetch_one(conn)
        .await?;
    if protected {
        return Err(Error::engine(
            "saved tabs require scoped mutation; their private policy is immutable",
        ));
    }
    Ok(())
}

async fn validate(conn: &mut SqliteConnection, event: &EventRow) -> Result<Change> {
    let p: Change = event_payload(event)?;
    if event.actor.as_deref() != Some(p.principal_id.as_str()) || p.reason.trim().is_empty() {
        return Err(Error::engine("invalid saved tab actor or reason"));
    }
    p.definition.validate()?;
    token(&p.creation_key, 256)?;
    token(&p.request_digest, 128)?;
    let old = read_on(conn, &p.principal_id, &event.record_id).await?;
    if let Some(old) = old {
        if p.created_act.is_some() {
            return Err(Error::engine(
                "saved tab mutation cannot claim creation act",
            ));
        }
        let previous = old.definition()?;
        let Some(operation) = &p.operation_id else {
            return Err(Error::engine("saved tab mutation requires operation id"));
        };
        token(operation, 256)?;
        if previous.state == "retired"
            || p.expected_revision.as_deref() != Some(old.revision().as_str())
            || p.creation_key != old.creation_key
            || p.definition.app != previous.app
            || p.definition.initial_location != previous.initial_location
            || (p.definition.state == "retired"
                && p.definition.custom_title != previous.custom_title)
        {
            return Err(Error::conflict(
                "saved tab mutation conflicts with canonical state",
            ));
        }
        let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_saved_tab_operations WHERE principal_id=? AND operation_id=?)")
            .bind(&p.principal_id).bind(operation).fetch_one(&mut *conn).await?;
        if used {
            return Err(Error::conflict("saved tab operation id already used"));
        }
    } else {
        if p.operation_id.is_some()
            || p.expected_revision.is_some()
            || p.definition.state != "active"
            || p.definition.custom_title.is_some()
        {
            return Err(Error::engine("invalid saved tab creation"));
        }
        let created_act = p
            .created_act
            .filter(|act| *act > 0)
            .ok_or_else(|| Error::engine("saved tab creation act missing"))?;
        if event.act.is_some_and(|act| act != created_act) {
            return Err(Error::engine("saved tab binding act mismatch"));
        }
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records r JOIN main.kernel_principals a ON a.principal_id=r.owner_id WHERE r.id=?1 AND r.owner_id=?2 AND a.kind='account' AND r.pin_family=?3 AND r.pin_version=1 AND r.kind='saved_tab' AND EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.record_created.v1' AND e.actor=?2 AND e.act=?4 AND json_extract(e.payload,'$.origin.saved_tab_creation_key')=?5) AND EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=r.home_id AND e.type='kernel.home_created.v1' AND e.act=?4 AND json_extract(e.payload,'$.source_record_id')=r.id) AND (SELECT count(*) FROM main.kernel_policy_entries e WHERE e.root_id=r.home_id)=1 AND EXISTS(SELECT 1 FROM main.kernel_policy_entries e WHERE e.root_id=r.home_id AND e.subject_kind='account' AND e.subject_id=?2 AND e.effect='allow' AND e.capability='manage'))")
            .bind(&event.record_id).bind(&p.principal_id).bind(crate::v2_standard::saved_tabs::FAMILY)
            .bind(created_act).bind(&p.creation_key).fetch_one(&mut *conn).await?;
        if !valid {
            return Err(Error::engine(
                "saved tab creation requires a fresh registered private record in the same act",
            ));
        }
        let fields: Vec<(String, String)> = sqlx::query_as(
            "SELECT name,value_json FROM main.kernel_record_fields WHERE record_id=?",
        )
        .bind(&event.record_id)
        .fetch_all(&mut *conn)
        .await?;
        let fields = fields
            .into_iter()
            .map(|(k, v)| Ok((k, serde_json::from_str(&v)?)))
            .collect::<Result<serde_json::Map<String, Value>>>()?;
        if Value::Object(fields) != p.definition.fields() {
            return Err(Error::engine(
                "saved tab definition differs from its registered record",
            ));
        }
    }
    Ok(p)
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    // Validate against the replay prefix, never current schema/adoption/roster.
    let p = validate(conn, event).await?;
    let definition = serde_json::to_string(&p.definition)?;
    if let Some(operation) = p.operation_id {
        sqlx::query("INSERT INTO main.kernel_saved_tab_operations VALUES(?,?,?,?,?)")
            .bind(&p.principal_id)
            .bind(operation)
            .bind(&event.record_id)
            .bind(&p.request_digest)
            .bind(event.local_seq)
            .execute(&mut *conn)
            .await?;
        sqlx::query("UPDATE main.kernel_saved_tabs SET definition=?,event_seq=? WHERE principal_id=? AND record_id=?")
            .bind(definition).bind(event.local_seq).bind(&p.principal_id).bind(&event.record_id).execute(&mut *conn).await?;
        for field in ["customTitle", "state"] {
            let value = p.definition.fields().get(field).cloned();
            sqlx::query("DELETE FROM main.kernel_record_fields WHERE record_id=? AND name=?")
                .bind(&event.record_id)
                .bind(field)
                .execute(&mut *conn)
                .await?;
            if let Some(value) = value {
                sqlx::query("INSERT INTO main.kernel_record_fields(record_id,name,value_json,created_seq) VALUES(?,?,?,?)")
                    .bind(&event.record_id).bind(field).bind(serde_json::to_string(&value)?).bind(event.local_seq).execute(&mut *conn).await?;
            }
        }
    } else {
        sqlx::query("INSERT INTO main.kernel_saved_tabs VALUES(?,?,?,?,?,?,(SELECT home_id FROM main.kernel_records WHERE id=?))")
            .bind(p.principal_id)
            .bind(&event.record_id)
            .bind(p.creation_key)
            .bind(p.request_digest)
            .bind(definition)
            .bind(event.local_seq)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
