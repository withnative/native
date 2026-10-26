//! Read-only, content-redacted cutover receipts. Not an authorization token.
use super::*;
use sha2::{Digest, Sha256};

/// Provenance emitted by every library/CLI report, including failed captures.
#[derive(Serialize)]
pub struct ImportBuild {
    pub importer_build_sha: &'static str,
}
impl Default for ImportBuild {
    fn default() -> Self {
        Self {
            importer_build_sha: crate::FULL_GIT_SHA,
        }
    }
}

/// An override acknowledges a build mismatch only; all data/admission guards
/// remain mandatory. Unstamped development binaries cannot prove same-build.
pub fn admit_build_sha(
    importer: Option<&str>,
    operator: &str,
    allow_mismatch: bool,
) -> crate::Result<bool> {
    let valid = |s: &str| {
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let matches = valid(operator) && importer.is_some_and(|s| valid(s) && s == operator);
    if matches {
        return Ok(false);
    }
    if allow_mismatch {
        return Ok(true);
    }
    Err(crate::Error::engine("v2 cutover refused: build SHA differs or is unavailable; use matching stamped importer/operator/hosting builds, or explicitly --allow-build-mismatch"))
}

/// Hash the complete logical SQLite snapshot, including WAL-visible rows.
/// Length-prefix schema/table/row bytes; sort encoded rows, preserving duplicate
/// rows and SQLite value types. Never emit source values in diagnostics.
pub async fn snapshot_digest(path: &std::path::Path) -> Result<String> {
    let mut db = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true),
    )
    .await?;
    sqlx::query("BEGIN").execute(&mut db).await?;
    let mut digest = Sha256::new();
    let mut feed = |bytes: &[u8]| {
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    };
    for pragma in ["application_id", "user_version"] {
        let value: i64 = sqlx::query_scalar(&format!("PRAGMA {pragma}"))
            .fetch_one(&mut db)
            .await?;
        feed(pragma.as_bytes());
        feed(&value.to_le_bytes());
    }
    let schema:Vec<(String,String)>=sqlx::query_as("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_stat%' ORDER BY name").fetch_all(&mut db).await?;
    for (table, ddl) in schema {
        feed(table.as_bytes());
        feed(ddl.as_bytes());
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let columns = sqlx::query(&format!("PRAGMA table_info({quoted})"))
            .fetch_all(&mut db)
            .await?;
        let mut fields = Vec::new();
        for column in columns {
            let name: String = column.get("name");
            let name = format!("\"{}\"", name.replace('"', "\"\""));
            fields.push(format!("typeof({name}),hex(CAST({name} AS BLOB))"));
        }
        let query = format!(
            "SELECT json_array({}) AS encoded FROM {quoted} ORDER BY encoded COLLATE BINARY",
            fields.join(",")
        );
        use futures::TryStreamExt;
        let mut rows = sqlx::query_scalar::<_, String>(&query).fetch(&mut db);
        while let Some(row) = rows.try_next().await? {
            feed(row.as_bytes());
        }
    }
    db.close().await?;
    Ok(hex::encode(digest.finalize()))
}

/// Add a receipt only after an all/history import completed successfully.
/// A later operator checks both digests again against the frozen source and
/// still-unpublished target. The source must remain unchanged throughout import.
pub async fn attach_receipt(
    report: &Report,
    source: &std::path::Path,
    target: &std::path::Path,
    initial_source_digest: &str,
    all: bool,
    history: bool,
    resume: bool,
) -> Result<serde_json::Value> {
    let mut value = capture_report(report, source, all, history, resume).await?;
    let source_digest = snapshot_digest(source).await?;
    if source_digest != initial_source_digest {
        return Err("source changed during import; fresh immutable snapshot required".into());
    }
    let proof = &value["cutover_verification"];
    value["cutover_verification"] = json!({"schema":"native.v2-import-receipt.v1","importer_build_sha":crate::FULL_GIT_SHA,"all":all,"history":history,"resume":resume,"history_complete":proof["history_complete"],"source_records":proof["source_records"],"origin_db_id":proof["origin_db_id"],"source_digest":source_digest,"target_digest":snapshot_digest(target).await?,"target":target.canonicalize()?});
    Ok(value)
}

/// A non-binding progress gate for the first delta pass. Only the subsequent
/// verification resume emits a digest-bound receipt for identity preparation.
pub async fn capture_report(
    report: &Report,
    source: &std::path::Path,
    all: bool,
    history: bool,
    resume: bool,
) -> Result<serde_json::Value> {
    let mut db = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(source)
            .read_only(true),
    )
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM records WHERE id<>'native:root'")
        .fetch_one(&mut db)
        .await?;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut db)
            .await?;
    db.close().await?;
    let mismatches = report.refusals.len()
        + report.review.len()
        + report.message_non_audience_leaks
        + report.message_v1_visible_but_v2_denied
        + report.message_v2_visible_but_v1_hidden;
    let history_complete = history
        && !report.history.streams.is_empty()
        && report
            .history
            .streams
            .values()
            .all(|s| s.source == s.verified);
    // Only these three reviewed outcomes are counted without blocking. An
    // inherited tombstone is already part of tombstones_verified, not an
    // additional excluded source row. No refusal category is a waiver.
    let counted_complete = report.counted.iter().all(|i| {
        matches!(
            i.reason.as_str(),
            "excluded_deleted" | "excluded_invisible_in_v1" | "inherited_bearer_tombstone"
        )
    }) && report
        .counted
        .iter()
        .filter(|i| i.reason == "excluded_deleted")
        .count()
        == report.excluded_deleted
        && report
            .counted
            .iter()
            .filter(|i| i.reason == "inherited_bearer_tombstone")
            .count()
            == report.inherited_bearer_tombstones
        && report
            .counted
            .iter()
            .filter(|i| i.reason == "excluded_invisible_in_v1")
            .count()
            == report.excluded_invisible_in_v1
        && report.excluded_invisible_tombstones_verified <= report.excluded_invisible_in_v1
        && report.excluded_invisible_tombstones_verified <= report.tombstones_verified
        && report.inherited_bearer_tombstones <= report.tombstones_verified
        && report
            .counted_breakdown
            .iter()
            .map(|i| i.count)
            .sum::<usize>()
            == report.counted.len();
    let capture_complete = all
        && report.state.member_contexts_prepared
        && counted_complete
        && history_complete
        && mismatches == 0
        && usize::try_from(count)?
            == report.verified
                + report.tombstones_verified
                + report.excluded_deleted
                + report.excluded_invisible_in_v1
                - report.excluded_invisible_tombstones_verified;
    let mut value = serde_json::to_value(report)?;
    value["capture_complete"] = json!(capture_complete);
    value["mismatches"] = json!(mismatches);
    value["cutover_verification"] = json!({"schema":"native.v2-import-capture.v1","importer_build_sha":crate::FULL_GIT_SHA,"all":all,"history":history,"resume":resume,"history_complete":history_complete,"source_records":count,"origin_db_id":origin});
    Ok(value)
}
