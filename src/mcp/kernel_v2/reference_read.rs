//! Cross-workspace reference reads using the v1 grammar and live kernel authority.
use super::*;
use crate::mcp::{hosted_transport::HostedReferenceResolution as Resolution, record_ref};

/// Read-only v2 counterpart of `hosted_transport::resolve_hosted_reference`.
/// The host must bind this caller to the routed database through H3 first.
pub async fn resolve_as(db: &Db, caller: &Caller, reference: &str) -> Result<Resolution> {
    let actor = principal(db, caller).await?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    let mut kinds = None;
    if record_ref::is_canonical_uuid(reference) {
        return Ok(
            if visible_reference_on(&mut tx, &actor, reference, &mut kinds).await? {
                Resolution::Resolved(reference.into())
            } else {
                Resolution::Unresolved
            },
        );
    }
    let Some(prefix) = record_ref::canonical_prefix(reference) else {
        return Ok(Resolution::Unresolved);
    };
    let upper = format!("{prefix}{}", record_ref::PREFIX_SENTINEL);
    let mut cursor: Option<String> = None;
    let mut live_rows = 0;
    let mut visible = Vec::new();
    // v1 bounds live candidates before authorization. Page past tombstones
    // using the existing kernel liveness helper, without new visibility SQL.
    while live_rows < record_ref::MAX_CANDIDATES {
        let rows:Vec<String>=sqlx::query_scalar("SELECT id FROM main.kernel_records WHERE id>=? AND id<? AND length(id)=36 AND (? IS NULL OR id>?) ORDER BY id LIMIT ?")
            .bind(&prefix).bind(&upper).bind(&cursor).bind(&cursor).bind(record_ref::MAX_CANDIDATES).fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            break;
        }
        for id in rows {
            cursor = Some(id.clone());
            if kernel::hq::tombstoned_on(&mut tx, &id).await? {
                continue;
            }
            live_rows += 1;
            if record_ref::is_canonical_uuid(&id)
                && visible_reference_on(&mut tx, &actor, &id, &mut kinds).await?
            {
                visible.push(id);
            }
            if live_rows == record_ref::MAX_CANDIDATES {
                break;
            }
        }
    }
    Ok(match visible.as_slice() {
        [] => Resolution::Unresolved,
        [id] => Resolution::Resolved(id.clone()),
        _ => Resolution::Ambiguous,
    })
}

async fn visible_reference_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
    kinds: &mut Option<KindCatalogue>,
) -> Result<bool> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Ok(false);
    }
    // Reference resolution needs authority and identity, never body bytes.
    let capability = match kernel::kernel_effective_capability_on(conn, actor, id).await {
        Ok(capability) => capability,
        Err(Error::Engine(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    if !capability.allows(crate::authorization::Capability::View) {
        return Ok(false);
    }
    let (typ,kind):(Option<String>,Option<String>)=sqlx::query_as("SELECT CASE WHEN r.pin_family=? THEN json_extract(t.value_json,'$') ELSE r.primary_type END,CASE WHEN r.pin_family=? THEN json_extract(k.value_json,'$') ELSE r.kind END FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE r.id=?")
        .bind(crate::v2_standard::v1_compat::FAMILY).bind(crate::v2_standard::v1_compat::FAMILY).bind(id).fetch_one(&mut *conn).await?;
    if typ.as_deref() != Some("Annotation") {
        return Ok(true);
    }
    let Some(kind) = kind else { return Ok(true) };
    if kinds.is_none() {
        *kinds = Some(KindCatalogue {
            annotation_vocabulary: kernel::v1_state::rows_on(conn, "vocabularies")
                .await?
                .into_iter()
                .find(|row| row["name"] == "kind:Annotation")
                .and_then(|row| row["id"].as_str().map(str::to_owned)),
            values: kernel::v1_state::rows_on(conn, "vocabulary_values").await?,
        });
    }
    let kinds = kinds
        .as_ref()
        .expect("kind catalogue loaded for Annotation");
    // Missing imported kind authority cannot establish a public Annotation
    // reference. Keep the v1 unavailable shape instead of guessing identity.
    let Some(vocabulary) = &kinds.annotation_vocabulary else {
        return Ok(false);
    };
    let value = kinds
        .values
        .iter()
        .find(|row| row["vocabulary_id"] == *vocabulary && row["value"] == kind);
    let mut joined = None;
    if let Some(value) = value {
        use crate::portable_sql::{NormalizedRow, NormalizedValue};
        let canonical = value["alias_of"]
            .as_str()
            .and_then(|id| kinds.values.iter().find(|row| row["id"] == id));
        let mut row = NormalizedRow::new();
        for name in ["id", "status", "metadata", "alias_of"] {
            row.insert(
                name.into(),
                value[name]
                    .as_str()
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null),
            );
        }
        for (name, column) in [
            ("canonical_id", "id"),
            ("canonical_value", "value"),
            ("canonical_status", "status"),
            ("canonical_metadata", "metadata"),
        ] {
            row.insert(
                name.into(),
                canonical
                    .and_then(|row| row[column].as_str())
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null),
            );
        }
        joined = Some(row);
    }
    let resolution = crate::meta::kind::resolve_identity_row("Annotation", &kind, joined.as_ref())?;
    Ok(!crate::meta::kind::matches_identity(
        &resolution,
        "Annotation",
        "vv:voc:kind:Annotation:attribution",
    ))
}

struct KindCatalogue {
    annotation_vocabulary: Option<String>,
    values: Vec<Value>,
}
