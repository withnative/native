//! Caller-visible staging from the replayable typed-time cache, never authority.
use crate::Result;
use sqlx::SqliteConnection;

pub(super) async fn stage(conn: &mut SqliteConnection) -> Result<()> {
    crate::kernel::facet_time_reads::require_ready_on(conn).await?;
    sqlx::query(
        "CREATE TEMP TABLE facet_times (
        record_id TEXT,key TEXT,kind TEXT,all_day INTEGER,
        start_date TEXT,end_date TEXT,start_ms INTEGER,end_ms INTEGER,
        tz TEXT,tzdb_version TEXT);
        INSERT INTO temp.facet_times
        SELECT f.* FROM temp._v2_visible v JOIN main.kernel_facet_time_rows f ON f.record_id=v.id",
    )
    .execute(&mut *conn)
    .await?;
    let dropped_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_visible v JOIN main.kernel_facet_time_invalid f ON f.record_id=v.id")
        .fetch_one(conn).await?;
    if dropped_rows != 0 {
        // Aggregate only over live caller-visible rows; no content or IDs.
        tracing::warn!(
            code = "facet_times_invalid_retained_row",
            dropped_rows,
            "Excluded invalid retained typed-time rows"
        );
    }
    #[cfg(test)]
    let _ =
        super::STATS.try_with(|s| s.borrow_mut().invalid_facet_time_rows += dropped_rows as usize);
    Ok(())
}
