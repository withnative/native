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
    Inspect { attachment_id: String },
    List { record_id: String },
}

pub(super) async fn read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: ReadArgs = parse("read_attachment", args)?;
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
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
    let mut tx = db.write_pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    match args {
        ManageArgs::Inspect { attachment_id } => {
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
    }
}
