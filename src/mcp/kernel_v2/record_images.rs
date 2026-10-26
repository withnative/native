//! Atomic v2 image insertion. V1: record_images.rs:558,735; HTTP admission is
//! engine-aware and retains its deployment barrier and current membership fence.
use crate::authorization::Capability;
use crate::kernel::{
    self, create_input_admitted_in, kernel_effective_capability_on, read_record_on,
    FacetObservation, FieldInput,
};
use crate::mcp::Caller;
use crate::record_images::{
    self as v1, ImageContent, ImageInsertMetadata, ImageInsertResult, RecordImageError,
};
use crate::store::{append_in, AppendSpec};
use crate::{
    db::{begin_write, Db},
    Error,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
type ImageResult<T> = std::result::Result<T, RecordImageError>;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
async fn actor(db: &Db, caller: &Caller) -> ImageResult<String> {
    super::principal(db, caller)
        .await
        .map_err(RecordImageError::Internal)
}
async fn require(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    cap: Capability,
) -> ImageResult<()> {
    let capability = match kernel_effective_capability_on(conn, actor, id).await {
        Ok(capability) => capability,
        Err(Error::Engine(message)) if message == kernel::HIDDEN_OR_MISSING => {
            return Err(RecordImageError::NotFound)
        }
        Err(error) => return Err(error.into()),
    };
    if !capability.allows(cap) {
        return Err(RecordImageError::NotFound);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    db: &Db,
    caller: &Caller,
    bearer: &str,
    metadata: ImageInsertMetadata,
    body: String,
    bytes: Vec<u8>,
    mime: &'static str,
) -> ImageResult<ImageInsertResult> {
    if body.len() > v1::MAX_BODY_BYTES {
        return Err(RecordImageError::TooLarge(
            "body exceeds the 4 MiB route limit".into(),
        ));
    }
    let actual = v1::validate_image(&bytes)?;
    if actual != mime {
        return Err(RecordImageError::UnsupportedMedia(
            "declared image type does not match decoded bytes".into(),
        ));
    }
    let source = v1::validate_metadata(&metadata, &body)?;
    let request = v1::request_digest(&metadata, &body, &bytes)?;
    let committed = format!(
        "{}{}{}",
        &body[..metadata.splice.start],
        source,
        &body[metadata.splice.end..]
    );
    let actor = actor(db, caller).await?;
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    require(&mut tx, &actor, bearer, Capability::Edit).await?;
    let parent = read_record_on(&mut tx, &actor, bearer)
        .await?
        .ok_or(RecordImageError::NotFound)?;
    sqlx::query(super::writes::RECEIPTS)
        .execute(&mut *tx)
        .await?;
    let old:Option<(String,String)>=sqlx::query_as("SELECT w.request_json,w.receipt_json FROM kernel_records r JOIN kernel_mcp_write_receipts w ON w.principal_id=r.owner_id AND w.operation='insert_record_image' AND w.operation_key=r.id WHERE r.id=?")
        .bind(&metadata.idempotency_key).fetch_optional(&mut *tx).await?;
    let old = match old {
        Some(old) => Some(old),
        None => {
            let raw:Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.legacy.payload.image_insert') FROM content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='record.created' ORDER BY seq LIMIT 1")
                .bind(&metadata.idempotency_key).fetch_optional(&mut *tx).await?.flatten();
            match raw {
                Some(raw) => {
                    let receipt: Value = serde_json::from_str(&raw)?;
                    Some((
                        json!({"record_id":bearer,"request_digest":receipt["request_digest"]})
                            .to_string(),
                        raw,
                    ))
                }
                None => None,
            }
        }
    };
    if let Some((old, raw)) = old {
        let old: Value = serde_json::from_str(&old)?;
        let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1 ORDER BY target_id").bind(&metadata.idempotency_key).fetch_all(&mut *tx).await?;
        if old["record_id"] != bearer || old["request_digest"] != request || targets != [bearer] {
            return Err(RecordImageError::Conflict);
        }
        require(&mut tx, &actor, &metadata.idempotency_key, Capability::View).await?;
        return v1::replay_from_receipt(&serde_json::from_str::<Value>(&raw)?, &request)
            .ok_or(RecordImageError::Conflict);
    }
    let collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=? UNION ALL SELECT 1 FROM kernel_roots WHERE root_id=? UNION ALL SELECT 1 FROM kernel_principals WHERE principal_id=?)")
        .bind(&metadata.idempotency_key).bind(&metadata.idempotency_key).bind(&metadata.idempotency_key).fetch_one(&mut *tx).await?;
    if collision {
        return Err(RecordImageError::Conflict);
    }
    if parent.archived {
        return Err(RecordImageError::NotFound);
    }
    if digest(parent.body.as_deref().unwrap_or_default().as_bytes()) != metadata.if_body_digest {
        return Err(RecordImageError::Conflict);
    }
    let home = if parent.fields.get("v1_type").and_then(Value::as_str) == Some("Collection")
        && parent.fields.get("v1_kind").and_then(Value::as_str) == Some("folder")
    {
        crate::v1_import::resolve_home_on(&mut tx, &actor, bearer).await?
    } else {
        parent.home_id.clone()
    };
    let receipt = json!({"version":"native.record-image-insert.v1","attachment_id":metadata.idempotency_key,"request_digest":request,
        "metadata_sha256":digest(&serde_jcs::to_vec(&metadata)?),"body_sha256":digest(body.as_bytes()),"blob_sha256":digest(&bytes),
        "placement_source":source,"body_digest":digest(committed.as_bytes())});
    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        &actor,
        "insert_record_image",
        request.clone(),
        Some("image inserted".into()),
        &mut acts,
    )
    .await?;
    let mut meta = crate::blob::new_blob_meta(&bytes, Some(mime), metadata.filename.as_deref());
    meta.id = meta.sha256.clone();
    kernel::blobs::put(&mut tx, &bytes, &meta).await?;
    let fields = crate::v2_standard::v1_compat::compat_fields(
        "Document",
        "attachment",
        Some(metadata.filename.as_deref().unwrap_or("image")),
        None,
        None,
    );
    let raw_fields = serde_json::to_string(&fields)?;
    let id = create_input_admitted_in(
        db,
        &mut tx,
        &mut acts,
        &actor,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        FieldInput::Raw(&raw_fields),
        &home,
        Some(bearer),
        true,
        Some(&metadata.idempotency_key),
        None,
        None,
    )
    .await?;
    kernel::blobs::bind(db, &mut tx, &mut acts, &actor, &id, &meta).await?;
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.facet_observed.v1".into(),
            payload: json!(FacetObservation {
                key: "blob_ref".into(),
                value: Some(meta.id),
                value_num: None,
                vocab_ref: None,
                as_of: crate::store::now_iso()
            }),
            actor: Some(actor.clone()),
        },
        &mut acts,
    )
    .await?;
    kernel::generic_links::add_generic_link_in(
        db, &mut tx, &mut acts, &actor, &id, bearer, "part_of", None,
    )
    .await?;
    kernel::hq::record_edit(&mut tx, &actor, bearer, Some(parent.revision)).await?;
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: bearer.into(),
            event_type: "kernel.body_set.v1".into(),
            payload: json!({"body":committed}),
            actor: Some(actor.clone()),
        },
        &mut acts,
    )
    .await?;
    kernel::app_installs::finish_app_action_in(db, &mut tx, &actor, pending, &mut acts).await?;
    sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES(?,'insert_record_image',?,?,?)")
        .bind(&actor)
        .bind(&id)
        .bind(json!({"record_id":bearer,"request_digest":request}).to_string())
        .bind(receipt.to_string())
        .execute(&mut *tx)
        .await?;
    let mut result = v1::replay_from_receipt(&receipt, &request).ok_or_else(|| {
        RecordImageError::Internal(Error::engine("invalid committed image receipt"))
    })?;
    result.replayed = false;
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

pub async fn read(db: &Db, caller: &Caller, bearer: &str, id: &str) -> ImageResult<ImageContent> {
    let actor = actor(db, caller).await?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    require(&mut tx, &actor, bearer, Capability::View).await?;
    let record = read_record_on(&mut tx, &actor, id)
        .await?
        .ok_or(RecordImageError::NotFound)?;
    if record.archived
        || record.fields.get("v1_type").and_then(Value::as_str) != Some("Document")
        || record.fields.get("v1_kind").and_then(Value::as_str) != Some("attachment")
    {
        return Err(RecordImageError::NotFound);
    }
    let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1 ORDER BY target_id").bind(id).fetch_all(&mut *tx).await?;
    if targets != [bearer] {
        return Err(RecordImageError::NotFound);
    }
    let has_receipts:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_mcp_write_receipts')").fetch_one(&mut *tx).await?;
    let native = if has_receipts {
        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_mcp_write_receipts w ON w.principal_id=r.owner_id AND w.operation='insert_record_image' AND w.operation_key=r.id WHERE r.id=? AND json_extract(w.request_json,'$.record_id')=?)").bind(id).bind(bearer).fetch_one(&mut *tx).await?
    } else {
        false
    };
    // Receipt presence is internal proof, never a disclosure bypass. The two
    // record reads and the exact bearer link above have already passed View.
    let imported:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='record.created' AND json_extract(payload,'$.legacy.payload.image_insert.version')='native.record-image-insert.v1')")
        .bind(id).fetch_one(&mut *tx).await?;
    if !native && !imported {
        return Err(RecordImageError::NotFound);
    }
    let meta = kernel::blobs::metadata_optional(&mut tx, &actor, id)
        .await?
        .ok_or(RecordImageError::NotFound)?;
    if meta.storage_tier != "inline"
        || !(0..=v1::MAX_IMAGE_BYTES as i64).contains(&meta.size_bytes)
        || !matches!(
            meta.mime.as_deref(),
            Some("image/png" | "image/jpeg" | "image/webp" | "image/gif")
        )
    {
        return Err(RecordImageError::NotFound);
    }
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM kernel_blobs WHERE sha256=?")
        .bind(&meta.sha256)
        .fetch_one(&mut *tx)
        .await?;
    if digest(&bytes) != meta.sha256 || bytes.len() as i64 != meta.size_bytes {
        return Err(RecordImageError::Internal(Error::engine(
            "stored blob integrity mismatch",
        )));
    }
    Ok(ImageContent {
        bytes,
        mime: meta.mime.unwrap(),
        filename: meta.original_filename,
        sha256: meta.sha256,
    })
}
