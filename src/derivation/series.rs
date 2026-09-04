//! Stable derivation-series identity and recipe-fenced creation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Principal;
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};

use super::{
    append_derivation_event_in, DerivationEventPayload, DerivationSeriesCreated,
    NewDerivationEvent, RecipeRevisionRef,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivationSeriesInspection {
    pub id: String,
    pub series_key: String,
    pub definition: Value,
    pub definition_sha256: String,
    pub created_event_id: String,
    pub created_event_seq: i64,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CreateOrGetDerivationSeries {
    pub id: String,
    pub series_key: String,
    pub definition: Value,
    pub recipe_revision: RecipeRevisionRef,
    pub expected_recipe_status_event_seq: i64,
    pub idempotency_key: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreatedOrExistingDerivationSeries {
    pub series: DerivationSeriesInspection,
    pub created: bool,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::engine(format!(
            "derivation series {label} cannot be empty"
        )))
    } else {
        Ok(())
    }
}

fn row(row: sqlx::sqlite::SqliteRow) -> Result<DerivationSeriesInspection> {
    Ok(DerivationSeriesInspection {
        id: row.try_get("id")?,
        series_key: row.try_get("series_key")?,
        definition: serde_json::from_str(row.try_get("definition")?)?,
        definition_sha256: row.try_get("definition_sha256")?,
        created_event_id: row.try_get("created_event_id")?,
        created_event_seq: row.try_get("created_event_seq")?,
        created_at: row.try_get("created_at")?,
    })
}

const SELECT_SERIES: &str = "SELECT id,series_key,definition,definition_sha256,
    created_event_id,created_event_seq,created_at FROM derivation_series";

pub(crate) async fn inspect_series_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<DerivationSeriesInspection>> {
    sqlx::query(&format!("{SELECT_SERIES} WHERE id=?"))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(row)
        .transpose()
}

pub async fn inspect_series(db: &Db, id: &str) -> Result<Option<DerivationSeriesInspection>> {
    nonblank("id", id)?;
    sqlx::query(&format!("{SELECT_SERIES} WHERE id=?"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?
        .map(row)
        .transpose()
}

pub async fn inspect_series_by_key(
    db: &Db,
    series_key: &str,
) -> Result<Option<DerivationSeriesInspection>> {
    nonblank("key", series_key)?;
    sqlx::query(&format!("{SELECT_SERIES} WHERE series_key=?"))
        .bind(series_key)
        .fetch_optional(db.pool())
        .await?
        .map(row)
        .transpose()
}

pub(crate) async fn create_or_get_series_for_recipe_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    input: &CreateOrGetDerivationSeries,
) -> Result<CreatedOrExistingDerivationSeries> {
    for (label, value) in [
        ("id", input.id.as_str()),
        ("key", input.series_key.as_str()),
        ("actor", input.actor.as_str()),
        ("idempotency key", input.idempotency_key.as_str()),
        ("reason", input.reason.as_str()),
    ] {
        nonblank(label, value)?;
    }
    if principal.account_id != Some(input.actor.as_str()) {
        return Err(Error::engine(
            "derivation series actor must match the authorized account principal",
        ));
    }
    if !input.definition.is_object() {
        return Err(Error::engine(
            "derivation series definition must be an object",
        ));
    }
    let expected_digest = super::digest_json(&input.definition);
    let existing = sqlx::query(&format!(
        "{SELECT_SERIES} WHERE id=? OR series_key=? ORDER BY id LIMIT 2"
    ))
    .bind(&input.id)
    .bind(&input.series_key)
    .fetch_all(&mut **tx)
    .await?;
    if !existing.is_empty() {
        if existing.len() != 1 {
            return Err(Error::engine(
                "derivation series id and key resolve to different stable series",
            ));
        }
        let series = row(existing.into_iter().next().expect("non-empty"))?;
        if series.id != input.id
            || series.series_key != input.series_key
            || super::digest_json(&series.definition) != expected_digest
            || series.definition_sha256 != expected_digest
        {
            return Err(Error::engine(
                "derivation series identity was reused for different canonical intent",
            ));
        }
        let release = crate::recipe::require_recipe_release_for_execution_on(
            tx,
            principal,
            &input.recipe_revision.definition_id,
            &input.recipe_revision.publication_id,
            input.expected_recipe_status_event_seq,
        )
        .await?;
        if release.descriptor_sha256 != input.recipe_revision.sha256 {
            return Err(Error::engine(
                "derivation series recipe digest does not match its governed release",
            ));
        }
        return Ok(CreatedOrExistingDerivationSeries {
            series,
            created: false,
        });
    }
    let release = crate::recipe::require_recipe_release_for_new_series_on(
        tx,
        principal,
        &input.recipe_revision.definition_id,
        &input.recipe_revision.publication_id,
        input.expected_recipe_status_event_seq,
    )
    .await?;
    if release.descriptor_sha256 != input.recipe_revision.sha256 {
        return Err(Error::engine(
            "derivation series recipe digest does not match its governed release",
        ));
    }
    append_derivation_event_in(
        tx,
        NewDerivationEvent::authored(
            input.idempotency_key.clone(),
            input.actor.clone(),
            input.run_key.clone(),
            input.reason.clone(),
            DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                id: input.id.clone(),
                series_key: input.series_key.clone(),
                definition: input.definition.clone(),
            }),
        )?,
    )
    .await?;
    let series = inspect_series_in(tx, &input.id)
        .await?
        .ok_or_else(|| Error::engine("derivation series projection is missing"))?;
    Ok(CreatedOrExistingDerivationSeries {
        series,
        created: true,
    })
}

pub async fn create_or_get_series_for_recipe(
    db: &Db,
    principal: Principal<'_>,
    input: CreateOrGetDerivationSeries,
) -> Result<CreatedOrExistingDerivationSeries> {
    let mut tx = begin_write(db.write_pool()).await?;
    let result = create_or_get_series_for_recipe_in(&mut tx, principal, &input).await?;
    tx.commit().await?;
    Ok(result)
}
