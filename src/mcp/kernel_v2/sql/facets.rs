//! Preserve facet row presence while materializing only caller-read cells.
use std::collections::BTreeSet;

#[cfg(test)]
tokio::task_local! { static FULL_STAGING: (); }
#[cfg(test)]
pub(crate) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL_STAGING.scope((), work).await
}

pub(super) fn rows_sql(reads: &BTreeSet<(String, String)>) -> String {
    #[cfg(test)]
    if FULL_STAGING.try_with(|_| ()).is_ok() {
        return super::FACET_ROWS.to_owned();
    }
    let cells = [
        ("id", "printf('v2:facet:%s:%s',f.record_id,f.key)"),
        ("record_id", "f.record_id"),
        ("key", "f.key"),
        ("value", "f.value"),
        ("value_num", "f.value_num"),
        ("vocab_ref", "f.vocab_ref"),
        ("created_at", "strftime('%Y-%m-%dT%H:%M:%fZ',f.as_of)"),
        ("created_at_ms", "CAST(strftime('%s',f.as_of) AS INTEGER)*1000+CAST(substr(strftime('%f',f.as_of),4,3) AS INTEGER)"),
    ];
    let projection = cells
        .iter()
        .map(|(name, sql)| {
            if reads.contains(&("facet_values".to_owned(), (*name).to_owned())) {
                *sql
            } else {
                "NULL"
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    // Even COUNT(*) must keep the former value-presence filter. The unchanged
    // caller-relative gate applies before a facet can become a result row.
    format!("INSERT INTO temp._v2_facet_rows SELECT {projection} FROM main.kernel_facets f JOIN temp._v2_visible v ON v.id=f.record_id WHERE f.value IS NOT NULL")
}
