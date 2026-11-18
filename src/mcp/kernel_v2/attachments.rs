//! Ordinary attachment reads. Authorization and bytes share a read snapshot.
use super::*;
use crate::kernel::blobs;
use base64::Engine as _;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    attachment_id: String,
    offset: Option<u64>,
    length: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageArgs {
    Inspect {
        attachment_id: String,
    },
    List {
        record_id: String,
    },
    Detach {
        attachment_id: String,
        if_content_seq: Option<i64>,
    },
}

/// A scoped app directly naming an attachment outside its grant gets the
/// typed scope refusal instead of the uniform hidden one.
async fn scope_refusal(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    attachment_id: &str,
) -> Result<()> {
    if let Some(error) = kernel::app_scope_direct_refusal_on(
        tx,
        actor,
        attachment_id,
        crate::authorization::Capability::View,
    )
    .await?
    {
        return Err(error);
    }
    Ok(())
}

pub(super) async fn read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: ReadArgs = parse("read_attachment", args)?;
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    scope_refusal(&mut tx, actor, &args.attachment_id).await?;
    let meta = blobs::metadata(&mut tx, actor, &args.attachment_id).await?;
    let length = args.length.unwrap_or(64 * 1024);
    let offset = args.offset.unwrap_or(0);
    if length == 0 || length > 512 * 1024 {
        return Err(Error::engine(
            "read_attachment: 'length' must be between 1 and 524288",
        ));
    }
    if offset >= i64::MAX as u64 {
        return Err(Error::engine("blob range out of bounds"));
    }
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT substr(bytes,?,?) FROM kernel_blobs WHERE sha256=?")
            .bind(offset as i64 + 1)
            .bind(length as i64)
            .bind(&meta.sha256)
            .fetch_one(&mut *tx)
            .await?;
    let returned = bytes.len();
    let (content, encoding) = match String::from_utf8(bytes) {
        Ok(text)
            if meta
                .mime
                .as_deref()
                .is_some_and(crate::domain_transaction::attachments::is_text_mime) =>
        {
            (text, "utf-8")
        }
        Ok(text) => (
            base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
            "base64",
        ),
        Err(e) => (
            base64::engine::general_purpose::STANDARD.encode(e.as_bytes()),
            "base64",
        ),
    };
    let record = kernel::read_record_on(&mut tx, actor, &args.attachment_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    Ok(
        json!({"attachment_id":args.attachment_id,"name":record.fields.get("title"),"deleted_at":null,"blob":meta,"offset":offset,"length":returned,"eof":offset.saturating_add(returned as u64)>=meta.size_bytes as u64,"content":content,"content_encoding":encoding}),
    )
}
pub(super) async fn manage(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: ManageArgs = parse("manage_attachments", args)?;
    if let ManageArgs::Detach {
        attachment_id,
        if_content_seq,
    } = args
    {
        return detach(db, actor, &attachment_id, if_content_seq).await;
    }
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    match args {
        ManageArgs::Inspect { attachment_id } => {
            scope_refusal(&mut tx, actor, &attachment_id).await?;
            let meta = blobs::metadata(&mut tx, actor, &attachment_id).await?;
            let record = kernel::read_record_on(&mut tx, actor, &attachment_id)
                .await?
                .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
            let created_at: String =
                sqlx::query_scalar("SELECT created_at FROM kernel_records WHERE id=?")
                    .bind(&attachment_id)
                    .fetch_one(&mut *tx)
                    .await?;
            Ok(
                json!({"attachment_id":attachment_id,"name":record.fields.get("title"),"created_at":created_at,"detached":false,"deleted_at":null,"blob":meta}),
            )
        }
        ManageArgs::List { record_id } => {
            kernel::kernel_require(
                &mut tx,
                actor,
                &record_id,
                crate::authorization::Capability::View,
            )
            .await?;
            let ids:Vec<String>=sqlx::query_scalar("SELECT a.record_id FROM kernel_attachment_blobs a JOIN kernel_records r ON r.id=a.record_id JOIN kernel_generic_links l ON l.source_id=a.record_id WHERE l.target_id=? AND l.relationship='part_of' AND l.active=1 ORDER BY r.created_at,r.id").bind(&record_id).fetch_all(&mut *tx).await?;
            let mut attachments = Vec::new();
            for id in ids {
                if let Some(record) = kernel::read_record_on(&mut tx, actor, &id).await? {
                    let meta = blobs::metadata(&mut tx, actor, &id).await?;
                    let created_at: String =
                        sqlx::query_scalar("SELECT created_at FROM kernel_records WHERE id=?")
                            .bind(&id)
                            .fetch_one(&mut *tx)
                            .await?;
                    attachments.push(json!({"attachment_id":id,"name":record.fields.get("title"),"created_at":created_at,"blob_id":meta.id,"mime":meta.mime,"size_bytes":meta.size_bytes,"sha256":meta.sha256,"original_filename":meta.original_filename,"storage_tier":meta.storage_tier}));
                }
            }
            Ok(json!({"record_id":record_id,"attachments":attachments}))
        }
        ManageArgs::Detach { .. } => unreachable!(),
    }
}

/// Detach has the same Manage and retained-blob semantics as v1. All target
/// checks and the tombstone share one write transaction; it never deletes bytes.
async fn detach(db: &Db, actor: &str, id: &str, expected: Option<i64>) -> Result<Value> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let previous = kernel::deletion::validate_on(&mut tx, actor, id, expected, i64::MAX).await?;
    let (typ, kind): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END, CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE r.id=?"
    ).bind(id).fetch_one(&mut *tx).await?;
    if typ.as_deref() != Some("Document") || kind.as_deref() != Some("attachment") {
        return Err(Error::engine(
            "manage_attachments: record is not a Document kind:attachment",
        ));
    }
    let blob = blobs::metadata(&mut tx, actor, id).await?;
    let mut acts = crate::act::ActAllocation::new();
    use sha2::{Digest, Sha256};
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "manage_attachments.detach",
        hex::encode(Sha256::digest(serde_jcs::to_vec(
            &json!({"action":"detach","attachment_id":id,"if_content_seq":expected}),
        )?)),
        None,
        &mut acts,
    )
    .await?;
    let event = crate::store::append_in(
        db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: id.into(),
            event_type: kernel::deletion::EVENT.into(),
            payload: serde_json::to_value(kernel::deletion::Deleted {
                reason: "Detach attachment".into(),
                previous_seq: previous,
            })?,
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    let attribution =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?;
    let mut result = json!({"attachment_id":id,"detached":true,"blob_id":blob.id,
        "blob_retained":true,"act":acts.get(),
        "event_id":event.id});
    if let Some(attribution) = attribution {
        result["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(result)
}
