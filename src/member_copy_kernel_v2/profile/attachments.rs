//! Native attachment identity comes from the source-authorized immutable
//! kernel binding, never from a synthesized legacy kind catalogue.
use super::{executor::NativeStatementExecutor, file_fence, AdmittedMemberFile};
use crate::blob::{BlobMeta, BlobSlice};
use crate::domain_transaction::attachments::{
    attachment_inspect_response, attachment_list_response, attachment_read_response,
};
use crate::mcp::tools::attachments::MemberAttachmentRequest;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

struct Identity {
    name: String,
    created_at: String,
    meta: BlobMeta,
}

fn fence(file: &AdmittedMemberFile) -> crate::Result<()> {
    file_fence::verify_on(&file.connection, &file.expected)
        .map_err(|_| crate::Error::copy_unavailable())
}
fn missing() -> crate::Error {
    crate::Error::engine("native member attachment is hidden or missing")
}

/// The producer selects these witnesses using kernel::blobs::metadata on
/// its authenticated source transaction. Kernel attachment admission verifies
/// the compat-carrier identity; metadata's record read follows the unique
/// derived bearer chain. Admission verifies file closure and all byte hashes.
/// Recheck the held identity/link/mapping, without inventing CoreKind facts.
fn resolve(file: &AdmittedMemberFile, id: &str) -> crate::Result<Identity> {
    fence(file)?;
    let row: Option<(String, String, String, String, i64, String)> = file.connection.query_row(
        "SELECT r.name,r.created_at,a.metadata,a.sha256,length(a.bytes),f.value
         FROM main.member_attachments a JOIN main.records r ON r.id=a.record_id
         JOIN main.facet_values f ON f.record_id=r.id AND f.key='blob_ref'
         WHERE a.record_id=? AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL
         AND (SELECT count(*) FROM main.links l WHERE l.source_id=r.id AND l.relationship='part_of')=1
         AND EXISTS(SELECT 1 FROM main.links l JOIN main.records bearer ON bearer.id=l.target_id
                    WHERE l.source_id=r.id AND l.relationship='part_of' AND bearer.deleted_at IS NULL)",
        [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    ).optional().map_err(|_| missing())?;
    let (name, created_at, raw, sha, size, blob_ref) = row.ok_or_else(missing)?;
    let meta: BlobMeta = serde_json::from_str(&raw).map_err(|_| missing())?;
    if meta.id != blob_ref
        || meta.sha256 != sha
        || meta.size_bytes != size
        || meta.storage_tier != "inline"
    {
        return Err(missing());
    }
    Ok(Identity {
        name,
        created_at,
        meta,
    })
}

pub(crate) fn dispatch(
    port: &NativeStatementExecutor<'_>,
    request: MemberAttachmentRequest,
) -> crate::Result<Value> {
    let file = port.0;
    fence(file)?;
    let response = match request {
        MemberAttachmentRequest::Read {
            id,
            offset,
            length,
            max_length,
        } => {
            let identity = resolve(file, &id)?;
            if length == 0 || length > max_length {
                return Err(crate::Error::engine(format!(
                    "read_attachment: 'length' must be between 1 and {max_length}"
                )));
            }
            let start =
                i64::try_from(offset.checked_add(1).ok_or_else(missing)?).map_err(|_| missing())?;
            let count = i64::try_from(length).map_err(|_| missing())?;
            // Bind the range to the referencing record's admitted witness,
            // rather than accepting a blob handle as read authority.
            let bytes: Vec<u8> = file
                .connection
                .query_row(
                    "SELECT substr(bytes,?2,?3) FROM main.member_attachments WHERE record_id=?1",
                    params![id, start, count],
                    |r| r.get(0),
                )
                .map_err(|_| missing())?;
            let total_size = identity.meta.size_bytes as u64;
            let slice = BlobSlice {
                eof: offset.saturating_add(bytes.len() as u64) >= total_size,
                bytes,
                offset,
                total_size,
            };
            attachment_read_response(&id, &identity.name, None, identity.meta, offset, slice)
        }
        MemberAttachmentRequest::Inspect { id } => {
            let identity = resolve(file, &id)?;
            attachment_inspect_response(
                &id,
                &identity.name,
                &identity.created_at,
                None,
                Some(identity.meta),
            )
        }
        MemberAttachmentRequest::List { record_id } => {
            let present: bool = file
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM main.records WHERE id=? AND deleted_at IS NULL)",
                    [&record_id],
                    |r| r.get(0),
                )
                .map_err(|_| missing())?;
            if !present {
                return Err(missing());
            }
            let mut statement=file.connection.prepare("SELECT a.record_id FROM main.member_attachments a JOIN main.records r ON r.id=a.record_id JOIN main.links l ON l.source_id=r.id AND l.relationship='part_of' WHERE l.target_id=? ORDER BY r.created_at,r.id").map_err(|_| missing())?;
            let ids = statement
                .query_map([&record_id], |r| r.get::<_, String>(0))
                .map_err(|_| missing())?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| missing())?;
            let mut attachments = vec![];
            for id in ids {
                let identity = resolve(file, &id)?;
                attachments.push(attachment_list_response(
                    &id,
                    &identity.name,
                    &identity.created_at,
                    (&identity.meta).into(),
                ));
            }
            json!({"record_id":record_id,"attachments":attachments})
        }
    };
    fence(file)?;
    Ok(response)
}
