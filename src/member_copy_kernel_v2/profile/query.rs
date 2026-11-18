//! Existing member portable SQL contract over the admitted closed file.
use super::*;
use crate::{
    query::{sql as guard, sql_contract as contract},
    Error,
};
use contract::{
    QuerySqlErrorCategory as Category, QuerySqlParameter as Parameter, QuerySqlProfile,
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use serde_json::Value as Json;
use std::time::{Duration, Instant};

fn error(category: Category, message: &str) -> Error {
    contract::categorized_error(category, message)
}
fn sqlite(error_value: rusqlite::Error) -> Error {
    match error_value.sqlite_error_code() {
        Some(rusqlite::ErrorCode::OperationInterrupted) => {
            error(Category::Timeout, "query execution deadline exceeded")
        }
        Some(rusqlite::ErrorCode::TooBig) => error(
            Category::ResultTooLarge,
            "query value exceeds the cell limit",
        ),
        _ => error(
            Category::SyntaxOrType,
            "member SQL preparation or execution refused",
        ),
    }
}

fn parameter(value: &Parameter) -> crate::Result<Value> {
    Ok(match value {
        Parameter::Boolean { value } => value.map(|v| Value::Integer(i64::from(v))),
        Parameter::Integer { value } => value
            .as_ref()
            .map(|v| v.parse::<i64>().map(Value::Integer))
            .transpose()
            .map_err(|_| error(Category::InvalidArguments, "invalid integer parameter"))?,
        Parameter::Real { value } => value.map(Value::Real),
        Parameter::Text { value } | Parameter::Json { value } | Parameter::Timestamp { value } => {
            value.clone().map(Value::Text)
        }
        Parameter::Bytes { value } => {
            use base64::Engine as _;
            value
                .as_ref()
                .map(|s| {
                    base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .map(Value::Blob)
                })
                .transpose()
                .map_err(|_| error(Category::InvalidArguments, "invalid bytes parameter"))?
        }
    }
    .unwrap_or(Value::Null))
}

fn cell(value: Value) -> crate::Result<Json> {
    let value = match value {
        Value::Null => Json::Null,
        Value::Integer(n) => n.into(),
        Value::Real(n) => serde_json::Number::from_f64(n)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        Value::Text(text) => text.into(),
        Value::Blob(bytes) => {
            use base64::Engine as _;
            if bytes.len().saturating_add(2) / 3 * 4 + 2 > contract::MAX_CELL_ENCODED_BYTES {
                return Err(error(
                    Category::ResultTooLarge,
                    "encoded cell exceeds limit",
                ));
            }
            base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into()
        }
    };
    if serde_json::to_vec(&value)?.len() > contract::MAX_CELL_ENCODED_BYTES {
        return Err(error(
            Category::ResultTooLarge,
            "encoded cell exceeds limit",
        ));
    }
    Ok(value)
}

pub(super) fn ensure_blobs_view(file: &AdmittedMemberFile) -> crate::Result<()> {
    file.connection.execute_batch("CREATE TEMP VIEW IF NOT EXISTS blobs AS SELECT json_extract(metadata,'$.id') AS id, bytes, json_extract(metadata,'$.mime') AS mime, length(bytes) AS size_bytes,sha256,json_extract(metadata,'$.original_filename') AS original_filename,json_extract(metadata,'$.storage_tier') AS storage_tier,NULL AS external_ref,json_extract(metadata,'$.created_at') AS created_at,CAST((julianday(json_extract(metadata,'$.created_at'))-2440587.5)*86400000 AS INTEGER) AS created_at_ms FROM main.member_attachments").map_err(sqlite)
}

pub(super) fn execute(file: &AdmittedMemberFile, args: Json) -> crate::Result<Json> {
    file_fence::verify_on(&file.connection, &file.expected)
        .map_err(|_| Error::copy_unavailable())?;
    let request: contract::QuerySqlRequest = serde_json::from_value(args)
        .map_err(|_| error(Category::InvalidArguments, "invalid query_sql request"))?;
    request.validate()?;
    let profile = QuerySqlProfile::SqliteLocal;
    let statement = contract::classify_single_read_statement(profile, &request.sql)?;
    let (statement, assumed_order) =
        guard::apply_ad_hoc_default_order(&statement, contract::FunctionAllowance::Portable)?;
    // Match the shared member executor's typed-denial order. Some excluded
    // column-less reads fail the ordinary validator before it can observe
    // their relation; the existing probe distinguishes real reads from CTEs.
    if let Some(requirement) = guard::member_denied_requirement(&statement)? {
        return Err(Error::unavailable_offline("query_sql", requirement));
    }
    guard::validate(&statement)?;
    let dependencies = guard::validated_relation_dependencies(&statement)?;
    for relation in dependencies {
        if !crate::mcp::member_scope::QUERY_SQL_SERVED_RELATIONS.contains(&relation.as_str()) {
            return Err(Error::unavailable_offline(
                "query_sql",
                format!("{relation}_not_held"),
            ));
        }
        if ["schema_config", "facet_keys"].contains(&relation.as_str()) {
            let markers: String = file
                .connection
                .query_row(
                    "SELECT schema_incomplete_for FROM main.member_context",
                    [],
                    |r| r.get(0),
                )
                .map_err(sqlite)?;
            if markers != "[]" {
                return Err(Error::unavailable_offline("query_sql", "schema_incomplete"));
            }
        }
    }
    let columns = guard::validated_output_columns(&statement)?;
    if columns.len() > contract::MAX_COLUMNS {
        return Err(error(
            Category::ResultTooLarge,
            "result exceeds column limit",
        ));
    }
    let mut unique = BTreeSet::new();
    if columns
        .iter()
        .any(|c| !unique.insert(c.to_ascii_lowercase()))
    {
        return Err(error(
            Category::SyntaxOrType,
            "duplicate output column labels",
        ));
    }
    contract::validate_regexp_bound_patterns(profile, &statement, &request.parameters)?;
    contract::validate_utc_date_label_bound_args(profile, &statement, &request.parameters)?;
    contract::check_positional_arguments(profile, &statement, request.parameters.len())?;
    let (statement, clocks) = contract::rewrite_now_ms_calls(
        profile,
        &statement,
        &format!("?{}", request.parameters.len() + 1),
    )?;
    let now = (clocks > 0).then(|| chrono::Utc::now().timestamp_millis());
    let (statement, principals) = contract::rewrite_current_principal_calls(
        profile,
        &statement,
        &format!(
            "?{}",
            request.parameters.len() + 1 + usize::from(clocks > 0)
        ),
    )?;
    let (statement, date_labels) = contract::rewrite_utc_date_label_calls(
        profile,
        &statement,
        contract::UtcDateLabelEngine::Sqlite,
    )?;
    let mut parameters = request
        .parameters
        .iter()
        .map(parameter)
        .collect::<crate::Result<Vec<_>>>()?;
    if let Some(now) = now {
        parameters.push(Value::Integer(now));
    }
    if principals > 0 {
        parameters.push(Value::Text(file.principal.clone()));
    }
    contract::check_positional_arguments(profile, &statement, parameters.len())?;
    for ddl in contract::catalog_view_statements(true, false) {
        file.connection.execute_batch(&ddl).map_err(sqlite)?;
    }
    ensure_blobs_view(file)?;
    guard::register_regexp_function(&file.connection)?;
    // The portable classifier above owns caller functions. The actual-file
    // gate additionally confines reads to closed public tables and generated
    // catalog views. strftime belongs only to the shared utc_date_label rewrite.
    file.connection
        .authorizer(Some(move |context: AuthContext<'_>| match context.action {
            AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
            AuthAction::Read { table_name, .. }
                if context.database_name == Some("main")
                    && (crate::mcp::member_scope::QUERY_SQL_SERVED_RELATIONS
                        .contains(&table_name)
                        || (table_name == "member_attachments"
                            && context.accessor == Some("blobs"))) =>
            {
                Authorization::Allow
            }
            AuthAction::Read { table_name, .. }
                if context.database_name == Some("temp")
                    && ["catalog_relations", "catalog_columns", "blobs"].contains(&table_name) =>
            {
                Authorization::Allow
            }
            AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
            AuthAction::Function { function_name }
                if (context.accessor == Some("blobs")
                    && ["json_extract", "length", "julianday"].contains(&function_name))
                    || guard::portable_function_allowed(function_name)
                    || (date_labels > 0 && function_name.eq_ignore_ascii_case("strftime")) =>
            {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        }));
    let deadline = Instant::now() + Duration::from_millis(contract::QUERY_DEADLINE_MS);
    file.connection.progress_handler(
        guard::PROGRESS_OPS,
        Some(move || Instant::now() >= deadline),
    );
    let previous = unsafe {
        libsqlite3_sys::sqlite3_limit(
            file.connection.handle(),
            libsqlite3_sys::SQLITE_LIMIT_LENGTH,
            guard::MAX_SQLITE_VALUE_BYTES,
        )
    };
    let result = (|| {
        let capped = guard::cap_statement(&statement, contract::MAX_ROWS as i64);
        let mut statement = file.connection.prepare(&capped).map_err(sqlite)?;
        if !statement.readonly() {
            return Err(error(Category::SyntaxOrType, "read statement required"));
        }
        let mut cursor = statement
            .query(rusqlite::params_from_iter(parameters))
            .map_err(sqlite)?;
        let mut rows = Vec::new();
        let mut bytes = 2;
        let mut truncated = false;
        while let Some(row) = cursor.next().map_err(sqlite)? {
            if rows.len() == contract::MAX_ROWS {
                truncated = true;
                break;
            }
            let mut object = serde_json::Map::new();
            for (index, column) in columns.iter().enumerate() {
                object.insert(column.clone(), cell(row.get(index).map_err(sqlite)?)?);
            }
            let value = Json::Object(object);
            bytes += serde_json::to_vec(&value)?.len() + 1;
            if bytes > contract::MAX_RESULT_ENCODED_BYTES {
                return Err(error(
                    Category::ResultTooLarge,
                    "encoded result exceeds byte limit",
                ));
            }
            rows.push(value);
        }
        // Use the shared result model, then omit the excluded history token.
        let mut result = serde_json::to_value(contract::QuerySqlResult {
            columns,
            row_count: rows.len(),
            rows,
            truncated,
            truncation_hint: contract::truncation_hint_for(truncated),
            as_of_seq: 0,
            now_ms_ms: now,
            time_dependent: now.is_some(),
            assumed_order,
        })?;
        result.as_object_mut().unwrap().remove("as_of_seq");
        Ok(result)
    })();
    file.connection
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    file.connection.progress_handler(0, None::<fn() -> bool>);
    unsafe {
        libsqlite3_sys::sqlite3_limit(
            file.connection.handle(),
            libsqlite3_sys::SQLITE_LIMIT_LENGTH,
            previous,
        );
    }
    result
}
