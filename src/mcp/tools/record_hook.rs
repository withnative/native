//! Opt-in `query_record` projection `record_hook.v1`.
//!
//! One validated filter becomes one SELECT on the caller's installed `records`
//! view. v1 and member copies use the existing owned `query_sql` session,
//! which installs the hosted or member view. Kernel v2 uses its `query_sql`
//! session so the same statement stages `updated_at_ms` and `is_current`.
//! The statement never names `main.records`.

use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::query::lifecycle::LifecycleInterpreter;
use crate::query::sql_contract::{QuerySqlParameter, QuerySqlRequest};

const PROJECTION: &str = "record_hook.v1";
const MAX_TYPES: usize = 16;
const MAX_TYPE_CHARS: usize = 64;
const MAX_IDS: usize = 200;
const MAX_ID_CHARS: usize = 128;
const MAX_LIMIT: i64 = 200;
const DEFAULT_LIMIT: i64 = 50;
const MAX_BODY_CHARS: i64 = 262_142;
const COLUMNS: &[&str] = &[
    "id",
    "type",
    "kind",
    "name",
    "summary",
    "home_id",
    "maturity",
    "created_at",
    "updated_at",
    "last_activity_at",
    "updated_at_ms",
    "is_current",
    "lifecycle",
];

pub(crate) fn requested(arguments: &Value) -> bool {
    arguments.get("projection").and_then(Value::as_str) == Some(PROJECTION)
}

struct Plan {
    sql: String,
    parameters: Vec<QuerySqlParameter>,
    limit: i64,
    offset: i64,
}

pub(crate) fn validate(tool: &str, arguments: &Value) -> Result<()> {
    prepare(tool, arguments).map(|_| ())
}

fn prepare(tool: &str, arguments: &Value) -> Result<Plan> {
    let object = arguments
        .as_object()
        .ok_or_else(|| bad(tool, "arguments must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "steps" | "projection" | "order" | "limit" | "offset" | "body_chars"
        ) {
            return Err(bad(
                tool,
                "record_hook.v1 accepts only steps, projection, order, limit, offset, and body_chars",
            ));
        }
    }
    if object.get("projection").and_then(Value::as_str) != Some(PROJECTION) {
        return Err(bad(tool, "projection must be record_hook.v1"));
    }
    let steps = object
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| bad(tool, "record_hook.v1 requires one filter step"))?;
    if steps.len() != 1 {
        return Err(bad(tool, "record_hook.v1 requires exactly one filter step"));
    }
    let step = steps[0]
        .as_object()
        .ok_or_else(|| bad(tool, "record_hook.v1 filter step must be an object"))?;
    if let Some(name) = step.get("step") {
        if name != "filter" {
            return Err(bad(tool, "record_hook.v1 step must be filter"));
        }
    }
    for key in step.keys() {
        if !matches!(key.as_str(), "step" | "types" | "kinds" | "ids" | "home_id") {
            return Err(bad(
                tool,
                "record_hook.v1 filter accepts types, optional kinds, and exactly one of ids or home_id",
            ));
        }
    }
    let has_ids = step.contains_key("ids");
    let has_home = step.contains_key("home_id");
    if has_ids == has_home {
        return Err(bad(
            tool,
            "record_hook.v1 requires exactly one of ids or home_id",
        ));
    }
    let types = string_list(
        tool,
        step.get("types")
            .ok_or_else(|| bad(tool, "record_hook.v1 requires types"))?,
        "types",
        1,
        MAX_TYPES,
        MAX_TYPE_CHARS,
    )?;
    let kinds = step
        .get("kinds")
        .map(|value| string_list(tool, value, "kinds", 1, MAX_TYPES, MAX_TYPE_CHARS))
        .transpose()?;
    let selector = if has_ids {
        Selector::Ids(string_list(
            tool,
            &step["ids"],
            "ids",
            1,
            MAX_IDS,
            MAX_ID_CHARS,
        )?)
    } else {
        let home = step["home_id"]
            .as_str()
            .filter(|value| within_kit_length(value, MAX_ID_CHARS))
            .ok_or_else(|| {
                bad(
                    tool,
                    "record_hook.v1 home_id must be a non-empty string of at most 128 characters",
                )
            })?;
        Selector::Home(home.to_owned())
    };
    let order = match object.get("order") {
        None => Order::UpdatedDesc,
        Some(Value::String(value)) if value == "updated_desc" => Order::UpdatedDesc,
        Some(Value::String(value)) if value == "name_nocase" => Order::NameNocase,
        _ => {
            return Err(bad(
                tool,
                "record_hook.v1 order must be updated_desc or name_nocase",
            ))
        }
    };
    let limit = match object.get("limit") {
        None => DEFAULT_LIMIT,
        Some(value) => integer(tool, value, "limit")?,
    };
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad(tool, "record_hook.v1 limit must be from 1 to 200"));
    }
    let offset = match object.get("offset") {
        None => 0,
        Some(value) => integer(tool, value, "offset")?,
    };
    if offset < 0 {
        return Err(bad(tool, "record_hook.v1 offset must be non-negative"));
    }
    let body_chars = match object.get("body_chars") {
        None => None,
        Some(value) => {
            let count = integer(tool, value, "body_chars")?;
            if !(1..=MAX_BODY_CHARS).contains(&count) {
                return Err(bad(
                    tool,
                    "record_hook.v1 body_chars must be an integer from 1 to 262142",
                ));
            }
            Some(count)
        }
    };
    if body_chars.is_some() && !matches!(&selector, Selector::Ids(ids) if ids.len() == 1) {
        return Err(bad(
            tool,
            "record_hook.v1 body_chars is valid only for exactly one id",
        ));
    }
    Ok(statement(
        types, kinds, selector, order, limit, offset, body_chars,
    ))
}

pub(crate) async fn execute_owned(db: &Db, caller: &Caller, arguments: Value) -> Result<Value> {
    let plan = prepare("query_record", &arguments)?;
    let result = crate::query::sql::query_sql_request_owned_with_vm_work(
        db.clone(),
        crate::query::QueryPrincipal::from(caller),
        QuerySqlRequest {
            sql: plan.sql,
            parameters: plan.parameters,
        },
        None,
        false,
    )
    .await?;
    let mut rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        let mut object = Map::new();
        for column in &result.columns {
            let value = row.get(column).cloned().ok_or_else(|| {
                Error::engine(format!(
                    "query_record: record_hook.v1 view row omitted {column}"
                ))
            })?;
            object.insert(column.clone(), value);
        }
        rows.push(Value::Object(object));
    }
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let interpreter = LifecycleInterpreter::load(db, principal).await?;
    project_page(&interpreter, rows, plan.limit, plan.offset)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn kernel_statement(arguments: &Value) -> Result<(String, Vec<Value>, i64, i64)> {
    let plan = prepare("query_record", arguments)?;
    let mut parameters = Vec::with_capacity(plan.parameters.len());
    for parameter in &plan.parameters {
        parameters.push(match parameter {
            QuerySqlParameter::Text { value } => json!({"type": "text", "value": value}),
            QuerySqlParameter::Integer { value } => json!({"type": "integer", "value": value}),
            _ => {
                return Err(Error::engine(
                    "query_record: record_hook.v1 binds only text and integer parameters",
                ))
            }
        });
    }
    Ok((plan.sql, parameters, plan.limit, plan.offset))
}

pub(crate) fn project_page(
    interpreter: &LifecycleInterpreter,
    rows: Vec<Value>,
    limit: i64,
    offset: i64,
) -> Result<Value> {
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        records.push(project_row(interpreter, row)?);
    }
    let has_more = records.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        records.truncate(usize::try_from(limit).unwrap_or(records.len()));
    }
    let returned = i64::try_from(records.len()).unwrap_or(i64::MAX);
    let mut payload = Map::new();
    payload.insert("shape".into(), json!("records"));
    payload.insert("records".into(), Value::Array(records));
    payload.insert("returned".into(), json!(returned));
    payload.insert("has_more".into(), json!(has_more));
    payload.insert("offset".into(), json!(offset));
    Ok(Value::Object(payload))
}

fn project_row(interpreter: &LifecycleInterpreter, row: Value) -> Result<Value> {
    let object = row
        .as_object()
        .ok_or_else(|| Error::engine("query_record: record_hook.v1 view row was not an object"))?;
    for column in COLUMNS {
        if !object.contains_key(*column) {
            return Err(Error::engine(format!(
                "query_record: record_hook.v1 view row omitted {column}"
            )));
        }
    }
    let record_type = object["type"]
        .as_str()
        .ok_or_else(|| Error::engine("query_record: record_hook.v1 view type was not text"))?;
    let kind = object["kind"].as_str().filter(|value| !value.is_empty());
    let home = object["home_id"].as_str().filter(|value| !value.is_empty());
    let lifecycle = object["lifecycle"].as_str();
    let interpretation = interpreter.interpret(record_type, kind, home, lifecycle);
    let mut out = Map::new();
    for key in [
        "id",
        "type",
        "kind",
        "name",
        "summary",
        "home_id",
        "maturity",
        "created_at",
        "updated_at",
        "last_activity_at",
        "updated_at_ms",
        "is_current",
        "lifecycle",
    ] {
        out.insert(key.into(), object[key].clone());
    }
    out.insert(
        "lifecycle_interpretation".into(),
        serde_json::to_value(interpretation)?,
    );
    for key in ["body", "body_length"] {
        if let Some(value) = object.get(key) {
            out.insert((*key).into(), value.clone());
        }
    }
    Ok(Value::Object(out))
}

enum Selector {
    Ids(Vec<String>),
    Home(String),
}

enum Order {
    UpdatedDesc,
    NameNocase,
}

fn statement(
    types: Vec<String>,
    kinds: Option<Vec<String>>,
    selector: Selector,
    order: Order,
    limit: i64,
    offset: i64,
    body_chars: Option<i64>,
) -> Plan {
    let mut parameters = Vec::new();
    let mut sql = String::from(
        "SELECT id, type, kind, name, summary, home_id, maturity, created_at, updated_at, last_activity_at, updated_at_ms, is_current, lifecycle",
    );
    if let Some(count) = body_chars {
        sql.push_str(", substr(body, 1, ");
        push_integer(&mut sql, &mut parameters, count);
        sql.push_str(") AS body, length(body) AS body_length");
    }
    sql.push_str(
        " FROM records WHERE deleted_at IS NULL AND archived = 0 AND COALESCE(kind, '') NOT IN ('artifact', 'attachment', 'query', 'selection') AND type IN (",
    );
    push_list(&mut sql, &mut parameters, &types);
    sql.push(')');
    if let Some(kinds) = kinds {
        sql.push_str(" AND kind IN (");
        push_list(&mut sql, &mut parameters, &kinds);
        sql.push(')');
    }
    match selector {
        Selector::Ids(ids) => {
            sql.push_str(" AND id IN (");
            push_list(&mut sql, &mut parameters, &ids);
            sql.push(')');
        }
        Selector::Home(home) => {
            sql.push_str(" AND home_id = ");
            push_text(&mut sql, &mut parameters, &home);
        }
    }
    sql.push_str(match order {
        Order::UpdatedDesc => " ORDER BY updated_at_ms DESC, id ASC",
        Order::NameNocase => " ORDER BY name COLLATE NOCASE ASC, id ASC",
    });
    sql.push_str(" LIMIT ");
    push_integer(&mut sql, &mut parameters, limit.saturating_add(1));
    sql.push_str(" OFFSET ");
    push_integer(&mut sql, &mut parameters, offset);
    Plan {
        sql,
        parameters,
        limit,
        offset,
    }
}

fn push_list(sql: &mut String, parameters: &mut Vec<QuerySqlParameter>, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        push_text(sql, parameters, value);
    }
}

fn push_text(sql: &mut String, parameters: &mut Vec<QuerySqlParameter>, value: &str) {
    parameters.push(QuerySqlParameter::Text {
        value: Some(value.to_owned()),
    });
    sql.push('?');
    sql.push_str(&parameters.len().to_string());
}

fn push_integer(sql: &mut String, parameters: &mut Vec<QuerySqlParameter>, value: i64) {
    parameters.push(QuerySqlParameter::Integer {
        value: Some(value.to_string()),
    });
    sql.push('?');
    sql.push_str(&parameters.len().to_string());
}

fn string_list(
    tool: &str,
    value: &Value,
    name: &str,
    min: usize,
    max: usize,
    max_chars: usize,
) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .ok_or_else(|| bad(tool, &format!("record_hook.v1 {name} must be an array")))?;
    if items.len() < min || items.len() > max {
        return Err(bad(
            tool,
            &format!("record_hook.v1 {name} must contain {min} to {max} values"),
        ));
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| within_kit_length(text, max_chars))
                .map(str::to_owned)
                .ok_or_else(|| {
                    bad(
                        tool,
                        &format!(
                            "record_hook.v1 {name} values must be non-empty strings of at most {max_chars} characters"
                        ),
                    )
                })
        })
        .collect()
}

/// Kit `validId` and the type filter use JavaScript `string.length`.
fn within_kit_length(text: &str, max_len: usize) -> bool {
    !text.is_empty() && text.encode_utf16().count() <= max_len
}

fn integer(tool: &str, value: &Value, name: &str) -> Result<i64> {
    value
        .as_i64()
        .ok_or_else(|| bad(tool, &format!("record_hook.v1 {name} must be an integer")))
}

fn bad(tool: &str, detail: &str) -> Error {
    Error::engine(format!("{tool}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hook(step: Value) -> Value {
        json!({
            "projection": "record_hook.v1",
            "steps": [step]
        })
    }

    #[test]
    fn record_hook_kind_is_bounded_and_bound_inside_the_visible_view() {
        let tool = "query_record";
        let request =
            hook(json!({"types": ["Document"], "kinds": ["note' OR 1=1 --"], "home_id": "folder"}));
        let plan = prepare(tool, &request).unwrap();
        assert!(plan.sql.contains(" FROM records WHERE "));
        assert!(plan.sql.contains(" AND kind IN (?2) AND home_id = ?3"));
        assert!(!plan.sql.contains("OR 1=1"));
        assert!(!plan.sql.contains("main."));
        for kinds in [
            json!([]),
            json!(null),
            json!([""]),
            json!(["x".repeat(65)]),
            json!(vec!["note"; 17]),
        ] {
            assert!(validate(
                tool,
                &hook(json!({"types": ["Document"], "kinds": kinds, "home_id": "folder"}))
            )
            .is_err());
        }
    }

    #[test]
    fn record_hook_validation_rejects_before_sql() {
        let tool = "query_record";
        let ok = hook(json!({"step": "filter", "types": ["Document"], "ids": ["rec-1"]}));
        assert!(validate(tool, &ok).is_ok());
        assert!(validate(tool, &json!({"projection": "record_hook_v1", "steps": [{"types": ["Document"], "ids": ["rec-1"]}]})).is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "ids": ["rec-1"], "home_id": "folder"}))
        )
        .is_err());
        assert!(validate(tool, &hook(json!({"types": ["Document"]}))).is_err());
        assert!(validate(tool, &hook(json!({"types": [], "ids": ["rec-1"]}))).is_err());
        let mut too_many_types = vec!["Document"; 17];
        too_many_types[0] = "Document";
        assert!(validate(
            tool,
            &hook(json!({"types": too_many_types, "ids": ["rec-1"]}))
        )
        .is_err());
        let ids: Vec<_> = (0..201)
            .map(|index| format!("id-{index}"))
            .collect::<Vec<_>>();
        assert!(validate(tool, &hook(json!({"types": ["Document"], "ids": ids}))).is_err());
        let mut both_orders = ok.clone();
        both_orders["order"] = json!("name_asc");
        assert!(validate(tool, &both_orders).is_err());
        both_orders["order"] = json!("name_nocase");
        assert!(validate(tool, &both_orders).is_ok());
        both_orders["limit"] = json!(0);
        assert!(validate(tool, &both_orders).is_err());
        both_orders["limit"] = json!(201);
        assert!(validate(tool, &both_orders).is_err());
        both_orders["limit"] = json!(1);
        both_orders["offset"] = json!(-1);
        assert!(validate(tool, &both_orders).is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "ids": ["x".repeat(129)]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["T".repeat(65)], "ids": ["rec-1"]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["T".repeat(64)], "ids": ["x".repeat(128)]}))
        )
        .is_ok());
        let bmp = "\u{00e9}";
        let non_bmp = "\u{1F600}";
        assert!(validate(
            tool,
            &hook(json!({
                "types": [bmp.repeat(64)],
                "ids": [bmp.repeat(128)]
            }))
        )
        .is_ok());
        assert!(validate(
            tool,
            &hook(json!({"types": [bmp.repeat(65)], "ids": ["rec-1"]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "ids": [bmp.repeat(129)]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({
                "types": [non_bmp.repeat(32)],
                "ids": [non_bmp.repeat(64)]
            }))
        )
        .is_ok());
        assert!(validate(
            tool,
            &hook(json!({"types": [non_bmp.repeat(33)], "ids": ["rec-1"]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "ids": [non_bmp.repeat(65)]}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "home_id": bmp.repeat(128)}))
        )
        .is_ok());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "home_id": non_bmp.repeat(64)}))
        )
        .is_ok());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "home_id": "x".repeat(129)}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "home_id": bmp.repeat(129)}))
        )
        .is_err());
        assert!(validate(
            tool,
            &hook(json!({"types": ["Document"], "home_id": non_bmp.repeat(65)}))
        )
        .is_err());
        assert!(validate(tool, &hook(json!({"types": ["Document"], "home_id": ""}))).is_err());
        let mut mixed = ok.clone();
        mixed["activity"] = json!({});
        assert!(validate(tool, &mixed).is_err());
        let mut traverse = ok;
        traverse["steps"] = json!([
            {"step": "filter", "types": ["Document"], "ids": ["rec-1"]},
            {"step": "traverse", "target": "children"}
        ]);
        assert!(validate(tool, &traverse).is_err());
        let one = hook(json!({"types": ["Document"], "ids": ["rec-1"]}));
        let mut prefixed = one.clone();
        prefixed["body_chars"] = json!(2);
        assert!(validate(tool, &prefixed).is_ok());
        prefixed["body_chars"] = json!(262142);
        assert!(validate(tool, &prefixed).is_ok());
        for rejected in [
            json!(0),
            json!(-1),
            json!(262143),
            json!(1.5),
            json!("2"),
            json!(true),
        ] {
            let mut bad_count = one.clone();
            bad_count["body_chars"] = rejected;
            assert!(validate(tool, &bad_count).is_err());
        }
        let mut several = one.clone();
        several["body_chars"] = json!(2);
        several["steps"] =
            json!([{"step": "filter", "types": ["Document"], "ids": ["rec-1", "rec-2"]}]);
        assert!(validate(tool, &several).is_err());
        let mut folder = one;
        folder["body_chars"] = json!(2);
        folder["steps"] = json!([{"step": "filter", "types": ["Document"], "home_id": "folder-a"}]);
        assert!(validate(tool, &folder).is_err());
    }

    #[tokio::test]
    async fn record_hook_v1_matches_records_view_and_preserves_metadata() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let caller = Caller::local();
        let mut tx = db.write_pool().begin().await.unwrap();
        for (id, name) in [("folder-a", "Folder A"), ("folder-b", "Folder B")] {
            sqlx::query(
                "INSERT INTO records(id,type,kind,name,summary,created_at,updated_at,last_activity_at,policy_anchor_id) VALUES(?,'Collection','folder',?,'Summary','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z',?)",
            )
            .bind(id)
            .bind(name)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        for (id, kind, name, home, updated, current) in [
            (
                "hook-art",
                "artifact",
                "Newer artifact",
                "folder-a",
                "2026-11-05T00:00:00.000Z",
                Some(1_i64),
            ),
            (
                "hook-mid",
                "note",
                "C",
                "folder-a",
                "2026-11-04T00:00:00.000Z",
                Some(1),
            ),
            (
                "hook-old",
                "note",
                "b",
                "folder-a",
                "2026-11-03T00:00:00.000Z",
                None,
            ),
            (
                "hook-other",
                "note",
                "A",
                "folder-b",
                "2026-11-02T00:00:00.000Z",
                Some(1),
            ),
        ] {
            sqlx::query(
                "INSERT INTO records(id,type,kind,name,body,summary,home_id,created_at,updated_at,last_activity_at,is_current,policy_anchor_id) VALUES(?,'Document',?,?,'BODY-SECRET','Summary',?,'2026-11-01T00:00:00.000Z',?,'2026-11-01T00:00:00.000Z',?,?)",
            )
            .bind(id)
            .bind(kind)
            .bind(name)
            .bind(home)
            .bind(updated)
            .bind(current)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();

        let page = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["hook-art", "hook-mid", "hook-old", "missing-id"]}],
                "limit": 1
            }),
        )
        .await
        .unwrap();
        assert_eq!(page["records"].as_array().unwrap().len(), 1);
        assert_eq!(page["records"][0]["id"], "hook-mid");
        assert_eq!(page["has_more"], true);
        assert!(page.get("total").is_none());
        assert!(page["records"][0].get("created_at").is_some());
        assert!(!page.to_string().contains("BODY-SECRET"));
        assert!(page["records"][0].get("body").is_none());
        assert!(page["records"][0].get("body_digest").is_none());
        assert!(page["records"][0].get("lifecycle_interpretation").is_some());

        let named = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "order": "name_nocase",
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["hook-mid", "hook-old"]}]
            }),
        )
        .await
        .unwrap();
        let names: Vec<_> = named["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["b", "C"]);
        let nocase = parity(
            &db,
            "SELECT name FROM records WHERE id IN (?1, ?2) ORDER BY name COLLATE NOCASE ASC, id ASC",
            &["hook-mid", "hook-old"],
        )
        .await;
        let binary = parity(
            &db,
            "SELECT name FROM records WHERE id IN (?1, ?2) ORDER BY name ASC, id ASC",
            &["hook-mid", "hook-old"],
        )
        .await;
        assert_eq!(nocase, vec!["b".to_owned(), "C".to_owned()]);
        assert_eq!(binary, vec!["C".to_owned(), "b".to_owned()]);

        sqlx::query("UPDATE records SET lifecycle = ? WHERE id = ?")
            .bind("not-a-state")
            .bind("hook-old")
            .execute(db.write_pool())
            .await
            .unwrap();
        let currency = parity_objects(
            &db,
            "SELECT id, created_at, updated_at_ms, is_current, lifecycle FROM records WHERE id IN (?1, ?2) ORDER BY id ASC",
            &["hook-mid", "hook-old"],
        )
        .await;
        let full = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["hook-mid", "hook-old"]}]
            }),
        )
        .await
        .unwrap();
        for row in full["records"].as_array().unwrap() {
            let id = row["id"].as_str().unwrap();
            let view = currency.iter().find(|item| item["id"] == id).unwrap();
            assert_eq!(row["created_at"], view["created_at"]);
            assert_eq!(row["updated_at_ms"], view["updated_at_ms"]);
            assert_eq!(row["is_current"], view["is_current"]);
            assert_eq!(row["lifecycle"], view["lifecycle"]);
        }
        let old = full["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "hook-old")
            .unwrap();
        let mid = full["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "hook-mid")
            .unwrap();
        assert_eq!(old["lifecycle"], "not-a-state");
        assert_eq!(old["lifecycle_interpretation"]["status"], "unclassified");
        assert_eq!(old["lifecycle_interpretation"]["raw"], "not-a-state");
        assert!(mid["lifecycle"].is_null());
        assert_eq!(mid["lifecycle_interpretation"]["status"], "absent");
        assert!(currency.iter().any(|row| row["is_current"].is_null()));
        assert!(currency.iter().any(|row| row["is_current"] == 1));

        let unknown = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            hook(json!({"types": ["Document"], "ids": ["missing-id"]})),
        )
        .await
        .unwrap();
        assert_eq!(unknown["records"].as_array().unwrap().len(), 0);
        assert!(unknown.get("total").is_none());
        assert_eq!(unknown["has_more"], false);
        assert_eq!(unknown["returned"], 0);
        let unknown_home = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            hook(json!({"types": ["Document"], "home_id": "missing-folder"})),
        )
        .await
        .unwrap();
        assert_eq!(unknown_home["records"].as_array().unwrap().len(), 0);
        assert!(unknown_home.get("total").is_none());
        let beyond = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "offset": 100,
                "limit": 1,
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["hook-mid", "hook-old"]}]
            }),
        )
        .await
        .unwrap();
        assert_eq!(beyond["returned"], 0);
        assert_eq!(beyond["has_more"], false);
        assert_eq!(beyond["offset"], 100);
        assert!(beyond.get("total").is_none());

        for projection in [None, Some("metadata")] {
            let mut args = json!({
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["hook-old"]}]
            });
            if let Some(value) = projection {
                args["projection"] = json!(value);
            }
            let page = super::super::querying::execute_query_record_args_as(
                &db,
                &caller,
                "query_record",
                args,
            )
            .await
            .unwrap();
            let row = &page["records"][0];
            assert!(row.get("updated_at_ms").is_none(), "{projection:?}");
            assert!(row.get("is_current").is_none(), "{projection:?}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn record_hook_v1_body_chars_returns_the_codepoint_prefix() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let caller = Caller::local();
        let emoji = "A😀B";
        let quoted = "say \"hi\"";
        let rows: [(&str, Option<&str>); 5] = [
            ("body-ascii", Some("ABCD")),
            ("body-emoji", Some(emoji)),
            ("body-quoted", Some(quoted)),
            ("body-empty", Some("")),
            ("body-null", None),
        ];
        let mut tx = db.write_pool().begin().await.unwrap();
        for (id, body) in rows {
            sqlx::query(
                "INSERT INTO records(id,type,kind,name,body,summary,created_at,updated_at,last_activity_at,policy_anchor_id) VALUES(?,'Document','note',?,?,'Summary','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z',?)",
            )
            .bind(id)
            .bind(id)
            .bind(body)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
                .bind(id)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        let oversized = "😀".repeat(70_000);
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,body,summary,created_at,updated_at,last_activity_at,policy_anchor_id) VALUES(?,'Document','note',?,?,'Summary','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z','2026-11-01T00:00:00.000Z',?)",
        )
        .bind("body-over")
        .bind("body-over")
        .bind(&oversized)
        .bind("body-over")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
            .bind("body-over")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let cases = [
            ("body-ascii", 2_i64, json!("AB"), json!(4)),
            ("body-emoji", 2, json!("A😀"), json!(3)),
            ("body-quoted", 8, json!(quoted), json!(8)),
            ("body-empty", 4, json!(""), json!(0)),
            ("body-null", 4, Value::Null, Value::Null),
        ];
        for (id, count, body, length) in cases {
            let page = super::super::querying::execute_query_record_args_as(
                &db,
                &caller,
                "query_record",
                json!({
                    "projection": "record_hook.v1",
                    "body_chars": count,
                    "steps": [{"step": "filter", "types": ["Document"], "ids": [id]}]
                }),
            )
            .await
            .unwrap();
            let row = &page["records"][0];
            let direct = body_parity(&db, count, id).await;
            assert_eq!(row["body"], direct["body"], "{id}");
            assert_eq!(row["body_length"], direct["body_length"], "{id}");
            assert_eq!(row["body"], body, "{id}");
            assert_eq!(row["body_length"], length, "{id}");
            assert!(row.get("body_digest").is_none(), "{id}");
        }

        let metadata = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["body-ascii"]}]
            }),
        )
        .await
        .unwrap();
        assert!(metadata["records"][0].get("body").is_none());
        assert!(metadata["records"][0].get("body_length").is_none());
        assert!(!metadata.to_string().contains("ABCD"));

        let hook_error = super::super::querying::execute_query_record_args_as(
            &db,
            &caller,
            "query_record",
            json!({
                "projection": "record_hook.v1",
                "body_chars": 70000,
                "steps": [{"step": "filter", "types": ["Document"], "ids": ["body-over"]}]
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        let direct_error = crate::query::sql::query_sql_request_owned_with_vm_work(
            db.clone(),
            crate::query::QueryPrincipal::from(&caller),
            QuerySqlRequest {
                sql: "SELECT substr(body, 1, ?1) AS body, length(body) AS body_length FROM records WHERE id = ?2".into(),
                parameters: vec![
                    QuerySqlParameter::Integer { value: Some("70000".into()) },
                    QuerySqlParameter::Text { value: Some("body-over".into()) },
                ],
            },
            None,
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            refuses_oversized_body(&hook_error),
            "hook={hook_error} direct={direct_error}"
        );
        assert!(
            refuses_oversized_body(&direct_error),
            "hook={hook_error} direct={direct_error}"
        );
        assert!(!hook_error.contains("\"shape\""), "{hook_error}");
        assert!(!hook_error.contains("body_length"), "{hook_error}");
        db.close().await;
    }

    fn refuses_oversized_body(error: &str) -> bool {
        let lower = error.to_ascii_lowercase();
        lower.contains("result_too_large")
            || lower.contains("sqlite_toobig")
            || lower.contains("too big")
            || lower.contains("string or blob too big")
    }

    async fn body_parity(db: &Db, count: i64, id: &str) -> Value {
        let result = crate::query::sql::query_sql_request_owned_with_vm_work(
            db.clone(),
            crate::query::QueryPrincipal::from(&Caller::local()),
            QuerySqlRequest {
                sql: "SELECT substr(body, 1, ?1) AS body, length(body) AS body_length FROM records WHERE id = ?2".into(),
                parameters: vec![
                    QuerySqlParameter::Integer { value: Some(count.to_string()) },
                    QuerySqlParameter::Text { value: Some(id.to_owned()) },
                ],
            },
            None,
            false,
        )
        .await
        .unwrap();
        let mut object = Map::new();
        for column in &result.columns {
            object.insert(column.clone(), result.rows[0][column].clone());
        }
        Value::Object(object)
    }

    async fn parity(db: &Db, sql: &str, ids: &[&str]) -> Vec<String> {
        parity_objects(db, sql, ids)
            .await
            .into_iter()
            .map(|row| row["name"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn parity_objects(db: &Db, sql: &str, ids: &[&str]) -> Vec<Value> {
        let parameters = ids
            .iter()
            .map(|id| QuerySqlParameter::Text {
                value: Some((*id).to_owned()),
            })
            .collect();
        let result = crate::query::sql::query_sql_request_owned_with_vm_work(
            db.clone(),
            crate::query::QueryPrincipal::from(&Caller::local()),
            QuerySqlRequest {
                sql: sql.into(),
                parameters,
            },
            None,
            false,
        )
        .await
        .unwrap();
        result
            .rows
            .into_iter()
            .map(|row| {
                let mut object = Map::new();
                for column in &result.columns {
                    object.insert(column.clone(), row[column].clone());
                }
                Value::Object(object)
            })
            .collect()
    }
}
