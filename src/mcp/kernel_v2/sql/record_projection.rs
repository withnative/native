//! Caller SQL only reaches physically staged visible rows. Copy requested
//! cached cells once; keep large bodies and caller-relative cells lazy.
use super::*;
use kernel::sql_record_projection as cache;

#[cfg(test)]
tokio::task_local! { static ORACLE: (); }
#[cfg(test)]
pub(crate) async fn with_oracle<F: std::future::Future>(work: F) -> F::Output {
    ORACLE.scope((), work).await
}

fn stored_column(column: &str) -> Option<&str> {
    Some(match column {
        "body" | "home_id" | "is_current" | "successor_count" => return None,
        "created_at" | "created_at_ms" => "created_raw",
        "updated_at" | "updated_at_ms" => "updated_raw",
        "last_activity_at" | "last_activity_at_ms" => "activity_raw",
        "deleted_at" | "deleted_at_ms" => "deleted_raw",
        column => column,
    })
}

fn stored_cell(column: &str, lookup: impl Fn(&str) -> String) -> Option<String> {
    let raw = lookup(stored_column(column)?);
    Some(match column {
        "created_at" | "updated_at" => format!("strftime('%Y-%m-%dT%H:%M:%fZ',{raw})"),
        "created_at_ms" | "updated_at_ms" | "last_activity_at_ms" => millis(&raw),
        "deleted_at_ms" => format!("CAST(unixepoch({raw},'subsec')*1000 AS INTEGER)"),
        _ => raw,
    })
}

pub(super) async fn install(
    conn: &mut sqlx::SqliteConnection,
    reads: &BTreeSet<(String, String)>,
    expected: Option<&str>,
    finite: bool,
) -> Result<bool> {
    #[cfg(test)]
    if ORACLE.try_with(|_| ()).is_ok() {
        return Ok(false);
    }
    let Some(frontier) = cache::frontier_on(conn, expected).await? else {
        return Ok(false);
    };
    let columns = columns("records").expect("records contract");
    let copied: BTreeSet<_> = columns
        .iter()
        .filter_map(|column| {
            if *column == "id" || !reads.contains(&("records".into(), (*column).into())) {
                return None;
            }
            stored_column(column)
        })
        .collect();
    let names = copied
        .iter()
        .map(|name| format!(",{name}"))
        .collect::<String>();
    let values = copied
        .iter()
        .map(|name| format!(",p.{name}"))
        .collect::<String>();
    // A finite admitted set checks its own metadata rows by key instead: the
    // metadata frontier has no event_seq index, so the set form scans every
    // record. Both forms exclude exactly the same IDs.
    let freshness = if finite {
        format!(
            "v.id NOT IN ({}) AND NOT EXISTS({})",
            cache::changed_event_ids(),
            cache::changed_metadata_for("v.id")
        )
    } else {
        format!("v.id NOT IN ({})", cache::changed_ids())
    };
    // Copy raw clocks too: SQLite statement-time values must normalize when
    // caller SQL executes, not at an earlier staging statement.
    // The materialization runs trusted expressions only, before caller SQL.
    // CROSS JOIN fixes visible IDs as the driver; no user predicate can be
    // pushed through the resulting TEMP table into hidden shared rows.
    sqlx::query(&format!("CREATE TEMP TABLE _v2_record_cached(id TEXT PRIMARY KEY{names}); INSERT INTO temp._v2_record_cached SELECT v.id{values} FROM temp._v2_visible v CROSS JOIN main.kernel_sql_record_projection p ON p.id=v.id WHERE {freshness}; CREATE TEMP TABLE _v2_record_uncached(id TEXT PRIMARY KEY); INSERT INTO temp._v2_record_uncached SELECT v.id FROM temp._v2_visible v WHERE NOT EXISTS(SELECT 1 FROM temp._v2_record_cached c WHERE c.id=v.id)"))
        .bind(frontier).bind(i64::MAX).execute(&mut *conn).await?;
    let cached=columns.iter().map(|column| {
        let value=if *column=="id" {"c.id".into()}
        else {stored_cell(column,|cell| {
            if copied.contains(cell) {format!("c.{cell}")}
            else {format!("(SELECT p.{cell} FROM main.kernel_sql_record_projection p WHERE p.id=c.id)")}
        }).unwrap_or_else(||format!("o.{column}"))};
        format!("{value} AS {column}")
    }).collect::<Vec<_>>().join(",");
    let uncached = columns
        .iter()
        .map(|column| {
            let value = if *column == "id" {
                "u.id".into()
            } else {
                format!("o.{column}")
            };
            format!("{value} AS {column}")
        })
        .collect::<Vec<_>>()
        .join(",");
    // A separate physical id set prevents a fallback scan from re-evaluating
    // the oracle over the cached majority, regardless of caller predicates.
    // Expand the oracle once per branch. Per-cell oracle subqueries duplicate
    // its complete expression tree during SQLite statement preparation.
    sqlx::query(&format!("DROP VIEW temp._v2_record_values; CREATE TEMP VIEW _v2_record_values AS SELECT {cached} FROM temp._v2_record_cached c CROSS JOIN temp._v2_record_oracle o ON o.id=c.id UNION ALL SELECT {uncached} FROM temp._v2_record_uncached u CROSS JOIN temp._v2_record_oracle o ON o.id=u.id"))
        .persistent(false).execute(conn).await?;
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().record_projection_installations += 1);
    Ok(true)
}
