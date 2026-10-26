//! Group interpretation inputs inside the caller's already visible snapshot.
//! No authority, interpreted result or caller row survives this transaction.
use crate::{kernel, Error, Result};
use serde_json::json;
use sqlx::SqliteConnection;

#[cfg(test)]
tokio::task_local! { static FULL_STAGING: (); }
#[cfg(test)]
pub(crate) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL_STAGING.scope((), work).await
}

pub(super) async fn install(tx: &mut SqliteConnection, actor: &str) -> Result<()> {
    #[cfg(test)]
    if FULL_STAGING.try_with(|_| ()).is_ok() {
        return install_full(tx, actor).await;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_visible")
        .fetch_one(&mut *tx)
        .await?;
    if count > 20_000 {
        return Err(Error::engine(
            "record_lifecycle_interpretations exceeds 20000 visible records; use get_record",
        ));
    }
    let interpretation_started = std::time::Instant::now();
    let interpreter = kernel::v1_state::interpreter_on(tx, actor).await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "lifecycle_interpreter", elapsed_us = interpretation_started.elapsed().as_micros() as u64);
    let homes_started = std::time::Instant::now();
    // The scalar bearer helper's exact precedence, evaluated once per home
    // by SQLite rather than through hundreds of asynchronous round trips.
    // CTAS retains expression types; validate them before interpreting, just
    // as the scalar String/Option<String> decoders did for malformed carriers.
    sqlx::query("CREATE TEMP TABLE _v2_lifecycle_homes AS SELECT home_id,CASE WHEN home_id=?1 THEN 'native:root' ELSE coalesce((SELECT json_extract(e.payload,'$.source_record_id') FROM main.content_events e WHERE e.record_id=h.home_id AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id') IS NOT NULL ORDER BY e.seq LIMIT 1),home_id) END AS bearer,NULL AS self_bearer FROM (SELECT DISTINCT r.home_id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id) h")
        .bind(crate::events::KERNEL_ROOT_ID).execute(&mut *tx).await?;
    let _: Vec<String> = sqlx::query_scalar("SELECT bearer FROM temp._v2_lifecycle_homes")
        .fetch_all(&mut *tx)
        .await?;
    // install_relations already required the provenance-complete SQL frontier.
    // Locate provenance through its replayed header before reading the one
    // canonical payload, rather than parsing every retained event in the home.
    sqlx::query("UPDATE temp._v2_lifecycle_homes AS h SET self_bearer=CASE WHEN home_id!=?1 AND EXISTS(SELECT 1 FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id WHERE v.id=h.bearer AND r.home_id=h.home_id) THEN coalesce((SELECT json_extract(e.payload,'$.logical_home_id') FROM main.content_events e WHERE e.record_id=h.bearer AND e.type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ORDER BY e.seq DESC LIMIT 1),(SELECT CASE WHEN json_extract(e.payload,'$.legacy.payload.policy_anchor')=h.bearer THEN json_extract(e.payload,'$.legacy.payload.original_home') END FROM main.content_events e JOIN main.kernel_legacy_sql_events header ON header.seq=e.seq AND header.event_type='v1.snapshot_provenance' WHERE e.record_id=h.bearer AND e.type='kernel.legacy_recorded.v1' ORDER BY e.seq DESC LIMIT 1),bearer) ELSE bearer END")
        .bind(crate::events::KERNEL_ROOT_ID).execute(&mut *tx).await?;
    let _: Vec<String> = sqlx::query_scalar("SELECT self_bearer FROM temp._v2_lifecycle_homes")
        .fetch_all(&mut *tx)
        .await?;
    sqlx::query("CREATE UNIQUE INDEX temp._v2_lifecycle_home ON _v2_lifecycle_homes(home_id)")
        .execute(&mut *tx)
        .await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "lifecycle_bearers", elapsed_us = homes_started.elapsed().as_micros() as u64);
    let inputs_started = std::time::Instant::now();
    // Keep expression affinities: do not silently cast malformed numeric
    // carrier fields into text. The group decoder has the same types as the
    // old per-record decoder. SQL IS below preserves Option/NULL equality.
    sqlx::query(INPUTS).execute(&mut *tx).await?;
    sqlx::query("CREATE TEMP TABLE _v2_lifecycle_keys AS SELECT DISTINCT typ,kind,raw,bearer FROM temp._v2_lifecycle_inputs; CREATE UNIQUE INDEX temp._v2_lifecycle_key ON _v2_lifecycle_keys(typ,kind,raw,bearer)")
        .execute(&mut *tx).await?;
    type Key = (i64, String, Option<String>, Option<String>, String);
    let keys: Vec<Key> =
        sqlx::query_as("SELECT rowid,typ,kind,raw,bearer FROM temp._v2_lifecycle_keys")
            .fetch_all(&mut *tx)
            .await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "lifecycle_inputs", elapsed_us = inputs_started.elapsed().as_micros() as u64);
    let output_started = std::time::Instant::now();
    let mut interpreted = Vec::with_capacity(keys.len());
    for (id, typ, kind, raw, bearer) in keys {
        let value = serde_json::to_value(interpreter.interpret(
            &typ,
            kind.as_deref(),
            Some(&bearer),
            raw.as_deref(),
        ))?;
        interpreted.push(json!([
            id,
            value["status"],
            value["axis"]["key"],
            value["axis"]["label"],
            value["vocabulary"]["id"],
            value["vocabulary"]["name"],
            value["value"]["id"],
            value["value"]["canonical"],
            value["terminality"],
            value["reason"]
        ]));
    }
    sqlx::query("CREATE TEMP TABLE _v2_lifecycle_results(id INTEGER PRIMARY KEY,status,axis_key,axis_label,vocabulary_id,vocabulary_name,value_id,canonical,terminality,reason); INSERT INTO temp._v2_lifecycle_results SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]'),json_extract(value,'$[4]'),json_extract(value,'$[5]'),json_extract(value,'$[6]'),json_extract(value,'$[7]'),json_extract(value,'$[8]'),json_extract(value,'$[9]') FROM json_each(?)")
        .bind(serde_json::to_string(&interpreted)?).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO temp.record_lifecycle_interpretations SELECT i.id,d.status,i.raw,d.axis_key,d.axis_label,d.vocabulary_id,d.vocabulary_name,d.value_id,d.canonical,d.terminality,d.reason FROM temp._v2_lifecycle_inputs i JOIN temp._v2_lifecycle_keys k ON k.typ=i.typ AND k.kind IS i.kind AND k.raw IS i.raw AND k.bearer=i.bearer JOIN temp._v2_lifecycle_results d ON d.id=k.rowid")
        .execute(&mut *tx).await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "lifecycle_output", elapsed_us = output_started.elapsed().as_micros() as u64);
    Ok(())
}

const INPUTS: &str = "CREATE TEMP TABLE _v2_lifecycle_inputs AS SELECT r.id,coalesce(CASE WHEN r.pin_family='native.v1.record' THEN json_extract(t.value_json,'$') ELSE r.primary_type END,'') AS typ,CASE WHEN r.pin_family='native.v1.record' THEN json_extract(k.value_json,'$') ELSE r.kind END AS kind,json_extract(l.value_json,'$') AS raw,CASE WHEN h.bearer=r.id THEN h.self_bearer ELSE h.bearer END AS bearer FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id LEFT JOIN main.kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN main.kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' LEFT JOIN main.kernel_record_fields l ON l.record_id=r.id AND l.name='lifecycle' JOIN temp._v2_lifecycle_homes h ON h.home_id=r.home_id";

#[cfg(test)]
type LifecycleSqlRow = (String, String, Option<String>, Option<String>, String);
#[cfg(test)]
async fn install_full(tx: &mut SqliteConnection, actor: &str) -> Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_visible")
        .fetch_one(&mut *tx)
        .await?;
    if count > 20_000 {
        return Err(crate::Error::engine(
            "record_lifecycle_interpretations exceeds 20000 visible records; use get_record",
        ));
    }
    let interpreter = kernel::v1_state::interpreter_on(tx, actor).await?;
    let rows:Vec<LifecycleSqlRow>=sqlx::query_as("SELECT r.id,coalesce(CASE WHEN r.pin_family='native.v1.record' THEN json_extract(t.value_json,'$') ELSE r.primary_type END,''),CASE WHEN r.pin_family='native.v1.record' THEN json_extract(k.value_json,'$') ELSE r.kind END,json_extract(l.value_json,'$'),r.home_id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id LEFT JOIN main.kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN main.kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' LEFT JOIN main.kernel_record_fields l ON l.record_id=r.id AND l.name='lifecycle'").fetch_all(&mut *tx).await?;
    let mut bearers = std::collections::BTreeMap::new();
    let mut cache = std::collections::BTreeMap::new();
    let mut interpreted = Vec::with_capacity(rows.len());
    for (id, typ, kind, raw, home) in rows {
        if !bearers.contains_key(&home) {
            let bearer = kernel::v1_state::lifecycle_bearer_on(tx, &home, None).await?;
            bearers.insert(home.clone(), bearer);
        }
        let bearer = if bearers[&home] == id {
            kernel::v1_state::lifecycle_bearer_on(tx, &home, Some(&id)).await?
        } else {
            bearers[&home].clone()
        };
        let key = (typ, kind, raw.clone(), bearer);
        let value = cache
            .entry(key)
            .or_insert_with_key(|(typ, kind, raw, bearer)| {
                serde_json::to_value(interpreter.interpret(
                    typ,
                    kind.as_deref(),
                    Some(bearer),
                    raw.as_deref(),
                ))
                .expect("lifecycle interpretation serializes")
            });
        interpreted.push(json!([
            id,
            value["status"],
            raw,
            value["axis"]["key"],
            value["axis"]["label"],
            value["vocabulary"]["id"],
            value["vocabulary"]["name"],
            value["value"]["id"],
            value["value"]["canonical"],
            value["terminality"],
            value["reason"]
        ]));
    }
    sqlx::query("INSERT INTO temp.record_lifecycle_interpretations SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]'),json_extract(value,'$[4]'),json_extract(value,'$[5]'),json_extract(value,'$[6]'),json_extract(value,'$[7]'),json_extract(value,'$[8]'),json_extract(value,'$[9]'),json_extract(value,'$[10]') FROM json_each(?)")
        .bind(serde_json::to_string(&interpreted)?).execute(&mut *tx).await?;
    Ok(())
}
