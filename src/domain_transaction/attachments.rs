use futures::future::BoxFuture;
use serde_json::{json, Value};
#[cfg(feature = "mcp-executor-prototype")]
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authorization::{Capability, Principal};
use crate::blob::{BlobMeta, BlobSlice, BLOB_REF_FACET_KEY};
use crate::generated::kinds::CoreKind;
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, LogicalType, NormalizedRow, NormalizedValue,
    StatementKind, StatementTemplate,
};
use crate::store::AppendSpec;
use crate::{Error, Result};

use super::{
    assert_required_not_worsened, facet_set_spec, govern_facet_writes, required_violations,
    FacetWrite,
};

/// The only attachment operations which are inherently physical. Relational
/// reads use reviewed statements; event meaning remains in the canonical
/// append/project kernel reached by `append_content`.
pub(crate) trait AttachmentPhysicalPort {
    /// Serialize signed content-revision checks with the backend's canonical
    /// event append. SQLite/Turso write transactions already hold the writer
    /// fence; Postgres acquires the same cursor lock used by append_event.
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;

    fn insert_blob<'a>(
        &'a mut self,
        bytes: &'a [u8],
        mime: Option<&'a str>,
        original_filename: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlobMeta>>;

    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> BoxFuture<'a, Result<Option<BlobSlice>>>;

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<()>>;
}

pub(crate) struct AttachmentCreate<'a> {
    pub tool: &'a str,
    pub bearer_id: &'a str,
    pub bytes: &'a [u8],
    pub mime: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub name: &'a str,
    pub lifecycle: Option<&'a str>,
    pub owner_id: Option<&'a str>,
    pub persistence: Option<&'a str>,
    pub maturity: Option<&'a str>,
    pub extra_facets: Vec<FacetWrite>,
    pub actor: &'a str,
    pub credential: &'a str,
    pub principal: Principal<'a>,
    /// A route-owned portable identity. Ordinary attachment tools leave this
    /// absent and continue to receive a fresh UUID.
    pub attachment_id: Option<&'a str>,
    /// Provenance carried on record.created but ignored by projection.
    pub image_insert: Option<Value>,
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct AttachmentDetachPreparation {
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

struct AttachmentDetachState {
    #[cfg(feature = "mcp-executor-prototype")]
    bearer_id: String,
    #[cfg(feature = "mcp-executor-prototype")]
    name: String,
    #[cfg(feature = "mcp-executor-prototype")]
    created_at: String,
    blob_id: String,
}

fn statement(
    operation: &str,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments)
        .map_err(|error| super::stable_storage_error(operation, &error))
}

async fn fetch<E: DomainStatementExecutor>(
    executor: &mut E,
    operation: &str,
    statement: &StatementTemplate,
    bindings: &[BindValue],
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    executor
        .fetch_all(statement, bindings, columns)
        .await
        .map_err(|error| super::stable_storage_error(operation, &error))
}

fn text(row: &NormalizedRow, column: &str, context: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn optional_text(row: &NormalizedRow, column: &str, context: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn integer(row: &NormalizedRow, column: &str, context: &str) -> Result<i64> {
    match row.get(column) {
        Some(NormalizedValue::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn optional_integer(row: &NormalizedRow, column: &str, context: &str) -> Result<Option<i64>> {
    match row.get(column) {
        Some(NormalizedValue::Integer(value)) => Ok(Some(*value)),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

async fn require_record<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    if crate::authorization::allows_record_with(executor, principal, record_id, required).await? {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{tool}: record {record_id} does not exist"
        )))
    }
}

async fn bearer_state<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    bearer_id: &str,
) -> Result<(String, Option<String>, Option<String>)> {
    let statement = statement(
        "read attachment parent",
        "records",
        &[
            "SELECT type, kind, home_id, deleted_at FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read attachment parent",
        &statement,
        &[BindValue::Text(bearer_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("home_id", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Err(Error::engine(format!(
            "{tool}: record {bearer_id} does not exist"
        )));
    };
    if optional_text(row, "deleted_at", "attachment parent")?.is_some() {
        return Err(Error::engine(format!(
            "{tool}: record {bearer_id} is deleted (tombstoned)"
        )));
    }
    Ok((
        text(row, "type", "attachment parent")?,
        optional_text(row, "kind", "attachment parent")?,
        optional_text(row, "home_id", "attachment parent")?,
    ))
}

/// Check the parent liveness boundary before any backend-owned work such as
/// URL fetching. Authorization alone is insufficient for trusted-local
/// callers because the policy fold intentionally permits initial tombstones.
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) async fn require_live_attachment_bearer<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    bearer_id: &str,
) -> Result<()> {
    bearer_state(executor, tool, bearer_id).await.map(|_| ())
}

async fn portable_owner<E: DomainStatementExecutor>(
    executor: &mut E,
    credential: &str,
) -> Result<Option<String>> {
    let statement = statement(
        "resolve attachment owner",
        "bindings",
        &[
            "SELECT record_id FROM {{relation}} WHERE system = 'account' AND identifier = ",
            " AND is_canonical = 1 ORDER BY record_id LIMIT 1",
        ],
    )?;
    let rows = fetch(
        executor,
        "resolve attachment owner",
        &statement,
        &[BindValue::Text(credential.into())],
        &[ColumnSpec::required("record_id", LogicalType::Text)],
    )
    .await?;
    rows.first()
        .map(|row| text(row, "record_id", "attachment owner"))
        .transpose()
}

pub(crate) async fn create_attachment<P>(
    port: &mut P,
    create: AttachmentCreate<'_>,
) -> Result<Value>
where
    P: DomainStatementExecutor + AttachmentPhysicalPort,
{
    let AttachmentCreate {
        tool,
        bearer_id,
        bytes,
        mime,
        filename,
        name,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        mut extra_facets,
        actor,
        credential,
        principal,
        attachment_id,
        image_insert,
    } = create;
    require_record(port, principal, tool, bearer_id, Capability::Edit).await?;
    let (bearer_type, bearer_kind, bearer_home) = bearer_state(port, tool, bearer_id).await?;
    let attachment_home = if bearer_type == "Collection" && bearer_kind.as_deref() == Some("folder")
    {
        bearer_id.to_string()
    } else {
        bearer_home.ok_or_else(|| {
            Error::engine(format!("{tool}: record {bearer_id} has no canonical home"))
        })?
    };

    let meta = port.insert_blob(bytes, mime, filename).await?;
    let attachment_id = attachment_id
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut created = json!({
        "type": CoreKind::DocumentAttachment.record_type(),
        "kind": CoreKind::DocumentAttachment.token(),
        "name": name,
        "home_id": attachment_home,
    });
    let created_fields = created.as_object_mut().expect("record.created object");
    if let Some(receipt) = image_insert {
        created_fields.insert("image_insert".into(), receipt);
    }
    if !principal.is_trusted_local() {
        let portable_owner = portable_owner(port, credential).await?.ok_or_else(|| {
            Error::engine(format!("{tool}: caller has no portable account binding"))
        })?;
        if owner_id.is_some_and(|owner| owner != portable_owner) {
            return Err(Error::engine(format!(
                "{tool}: owner_id must be the caller's portable identity"
            )));
        }
        created_fields.insert("owner_id".into(), json!(portable_owner));
    }
    for (key, value) in [
        ("lifecycle", lifecycle),
        ("owner_id", owner_id),
        ("persistence", persistence),
        ("maturity", maturity),
    ] {
        if let Some(value) = value {
            created_fields.insert(key.into(), json!(value));
        }
    }

    let schema_rows = crate::query::cascade::schema_config_rows_with(port).await?;
    govern_facet_writes(
        port,
        &schema_rows,
        tool,
        CoreKind::DocumentAttachment.record_type(),
        Some(CoreKind::DocumentAttachment.token()),
        &mut extra_facets,
    )
    .await?;
    let before = required_violations(port, &schema_rows, &[&attachment_id]).await?;
    let mut specs = vec![
        AppendSpec {
            record_id: attachment_id.clone(),
            event_type: "record.created".into(),
            payload: created,
            actor: Some(actor.into()),
        },
        AppendSpec {
            record_id: attachment_id.clone(),
            event_type: "link.added".into(),
            payload: json!({
                "source_id": attachment_id,
                "target_id": bearer_id,
                "relationship": "part_of"
            }),
            actor: Some(actor.into()),
        },
        AppendSpec {
            record_id: attachment_id.clone(),
            event_type: "facet.set".into(),
            payload: json!({ "key": BLOB_REF_FACET_KEY, "value": meta.id }),
            actor: Some(actor.into()),
        },
    ];
    specs.extend(
        extra_facets
            .iter()
            .map(|facet| facet_set_spec(&attachment_id, facet, actor)),
    );
    for spec in specs {
        port.append_content(spec).await?;
    }
    let after = required_violations(port, &schema_rows, &[&attachment_id]).await?;
    assert_required_not_worsened(tool, &before, &after)?;
    Ok(json!({
        "attachment_id": attachment_id,
        "record_id": bearer_id,
        "name": name,
        "blob": meta,
    }))
}

fn attachment_not_found(tool: &str, attachment_id: &str) -> Error {
    Error::engine(format!("{tool}: attachment {attachment_id} does not exist"))
}

async fn attachment_bearer<E: DomainStatementExecutor>(
    executor: &mut E,
    attachment_id: &str,
) -> Result<Option<String>> {
    let statement = statement(
        "read attachment bearer",
        "records",
        &[
            "SELECT type, kind, deleted_at, (SELECT COUNT(*) FROM links WHERE source_id = {{relation}}.id AND relationship = 'part_of') AS bearer_count, (SELECT target_id FROM links WHERE source_id = {{relation}}.id AND relationship = 'part_of' ORDER BY id LIMIT 1) AS bearer_id FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read attachment bearer",
        &statement,
        &[BindValue::Text(attachment_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ColumnSpec::required("bearer_count", LogicalType::Integer),
            ColumnSpec::nullable("bearer_id", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let valid = text(row, "type", "attachment bearer")? == "Document"
        && optional_text(row, "kind", "attachment bearer")?.as_deref() == Some("attachment")
        && optional_text(row, "deleted_at", "attachment bearer")?.is_none()
        && integer(row, "bearer_count", "attachment bearer")? == 1;
    if !valid {
        return Ok(None);
    }
    optional_text(row, "bearer_id", "attachment bearer")
}

async fn require_attachment<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
    required: Capability,
) -> Result<String> {
    let bearer = attachment_bearer(executor, attachment_id)
        .await?
        .ok_or_else(|| attachment_not_found(tool, attachment_id))?;
    if !crate::authorization::allows_record_with(executor, principal, attachment_id, required)
        .await?
    {
        return Err(attachment_not_found(tool, attachment_id));
    }
    Ok(bearer)
}

async fn resolve_attachment<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    id: &str,
) -> Result<(String, Option<String>, String, String)> {
    let statement = statement(
        "resolve attachment",
        "records",
        &[
            "SELECT r.type, r.kind, r.name, r.deleted_at, r.created_at, fv.value AS blob_id FROM {{relation}} r LEFT JOIN facet_values fv ON fv.record_id = r.id AND fv.key = ",
            " WHERE r.id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "resolve attachment",
        &statement,
        &[
            BindValue::Text(BLOB_REF_FACET_KEY.into()),
            BindValue::Text(id.into()),
        ],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::required("name", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ColumnSpec::required("created_at", LogicalType::Text),
            ColumnSpec::nullable("blob_id", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Err(attachment_not_found(tool, id));
    };
    let record_type = text(row, "type", "attachment")?;
    let Some(kind) = optional_text(row, "kind", "attachment")? else {
        return Err(Error::engine(format!(
            "{tool}: record {id} is not an attachment (Document kind:attachment)"
        )));
    };
    let governed = crate::meta::kind::resolve_with(executor, &record_type, &kind).await?;
    if !CoreKind::DocumentAttachment.matches(&governed) {
        return Err(Error::engine(format!(
            "{tool}: record {id} is not an attachment (Document kind:attachment)"
        )));
    }
    let Some(blob_id) = optional_text(row, "blob_id", "attachment")? else {
        return Err(Error::engine(format!(
            "{tool}: attachment {id} has no '{BLOB_REF_FACET_KEY}' facet"
        )));
    };
    Ok((
        text(row, "name", "attachment")?,
        optional_text(row, "deleted_at", "attachment")?,
        text(row, "created_at", "attachment")?,
        blob_id,
    ))
}

async fn blob_meta<E: DomainStatementExecutor>(
    executor: &mut E,
    blob_id: &str,
) -> Result<Option<BlobMeta>> {
    let statement = statement(
        "read attachment blob metadata",
        "blobs",
        &[
            "SELECT id, mime, size_bytes, sha256, original_filename, storage_tier, created_at FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read attachment blob metadata",
        &statement,
        &[BindValue::Text(blob_id.into())],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::nullable("mime", LogicalType::Text),
            ColumnSpec::required("size_bytes", LogicalType::Integer),
            ColumnSpec::required("sha256", LogicalType::Text),
            ColumnSpec::nullable("original_filename", LogicalType::Text),
            ColumnSpec::required("storage_tier", LogicalType::Text),
            ColumnSpec::required("created_at", LogicalType::Text),
        ],
    )
    .await?;
    rows.first()
        .map(|row| {
            Ok(BlobMeta {
                id: text(row, "id", "attachment blob")?,
                mime: optional_text(row, "mime", "attachment blob")?,
                size_bytes: integer(row, "size_bytes", "attachment blob")?,
                sha256: text(row, "sha256", "attachment blob")?,
                original_filename: optional_text(row, "original_filename", "attachment blob")?,
                storage_tier: text(row, "storage_tier", "attachment blob")?,
                created_at: text(row, "created_at", "attachment blob")?,
            })
        })
        .transpose()
}

fn is_text_mime(mime: &str) -> bool {
    let essence = mime.split(';').next().unwrap_or("").trim().to_lowercase();
    essence.starts_with("text/")
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
        || matches!(
            essence.as_str(),
            "application/json" | "application/xml" | "application/javascript"
        )
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) async fn read_attachment<P>(
    port: &mut P,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
    offset: u64,
    length: u64,
    max_length: u64,
) -> Result<Value>
where
    P: DomainStatementExecutor + AttachmentPhysicalPort,
{
    require_attachment(port, principal, tool, attachment_id, Capability::View).await?;
    let (name, deleted_at, _, blob_id) = resolve_attachment(port, tool, attachment_id).await?;
    if length == 0 || length > max_length {
        return Err(Error::engine(format!(
            "{tool}: 'length' must be between 1 and {max_length}"
        )));
    }
    let meta = blob_meta(port, &blob_id).await?.ok_or_else(|| {
        Error::engine(format!(
            "{tool}: blob {blob_id} referenced by attachment {attachment_id} does not exist"
        ))
    })?;
    let slice = port
        .read_blob_range(&blob_id, offset, length)
        .await?
        .expect("blob row existed for metadata");
    let returned = slice.bytes.len();
    let texty = meta.mime.as_deref().is_some_and(is_text_mime);
    let (content, content_encoding) = match String::from_utf8(slice.bytes) {
        Ok(text) if texty => (text, "utf-8"),
        Ok(text) => (encode_base64(text.as_bytes()), "base64"),
        Err(error) => (encode_base64(error.as_bytes()), "base64"),
    };
    Ok(json!({
        "attachment_id": attachment_id,
        "name": name,
        "deleted_at": deleted_at,
        "blob": meta,
        "offset": offset,
        "length": returned,
        "eof": slice.eof,
        "content": content,
        "content_encoding": content_encoding,
    }))
}

pub(crate) async fn list_attachments<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    record_id: &str,
) -> Result<Value> {
    require_record(executor, principal, tool, record_id, Capability::View).await?;
    let statement = statement(
        "list attachments",
        "records",
        &[
            "SELECT r.id, r.kind, r.name, r.created_at, fv.value AS blob_id, b.mime, b.size_bytes, b.sha256, b.original_filename, b.storage_tier FROM {{relation}} r JOIN links bearer ON bearer.source_id = r.id AND bearer.relationship = 'part_of' LEFT JOIN facet_values fv ON fv.record_id = r.id AND fv.key = ",
            " LEFT JOIN blobs b ON b.id = fv.value WHERE bearer.target_id = ",
            " AND r.type = ",
            " AND r.deleted_at IS NULL ORDER BY r.created_at, r.id",
        ],
    )?;
    let rows = fetch(
        executor,
        "list attachments",
        &statement,
        &[
            BindValue::Text(BLOB_REF_FACET_KEY.into()),
            BindValue::Text(record_id.into()),
            BindValue::Text(CoreKind::DocumentAttachment.record_type().into()),
        ],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::required("name", LogicalType::Text),
            ColumnSpec::required("created_at", LogicalType::Text),
            ColumnSpec::nullable("blob_id", LogicalType::Text),
            ColumnSpec::nullable("mime", LogicalType::Text),
            ColumnSpec::nullable("size_bytes", LogicalType::Integer),
            ColumnSpec::nullable("sha256", LogicalType::Text),
            ColumnSpec::nullable("original_filename", LogicalType::Text),
            ColumnSpec::nullable("storage_tier", LogicalType::Text),
        ],
    )
    .await?;
    let mut attachments = Vec::new();
    for row in rows {
        let id = text(&row, "id", "attachment list")?;
        if require_attachment(executor, principal, tool, &id, Capability::View)
            .await
            .is_err()
        {
            continue;
        }
        let Some(kind) = optional_text(&row, "kind", "attachment list")? else {
            continue;
        };
        let resolution = crate::meta::kind::resolve_with(
            executor,
            CoreKind::DocumentAttachment.record_type(),
            &kind,
        )
        .await?;
        if !CoreKind::DocumentAttachment.matches(&resolution) {
            continue;
        }
        attachments.push(json!({
            "attachment_id": id,
            "name": text(&row, "name", "attachment list")?,
            "created_at": text(&row, "created_at", "attachment list")?,
            "blob_id": optional_text(&row, "blob_id", "attachment list")?,
            "mime": optional_text(&row, "mime", "attachment list")?,
            "size_bytes": optional_integer(&row, "size_bytes", "attachment list")?,
            "sha256": optional_text(&row, "sha256", "attachment list")?,
            "original_filename": optional_text(&row, "original_filename", "attachment list")?,
            "storage_tier": optional_text(&row, "storage_tier", "attachment list")?,
        }));
    }
    Ok(json!({ "record_id": record_id, "attachments": attachments }))
}

pub(crate) async fn inspect_attachment<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
) -> Result<Value> {
    require_attachment(executor, principal, tool, attachment_id, Capability::View).await?;
    let (name, deleted_at, created_at, blob_id) =
        resolve_attachment(executor, tool, attachment_id).await?;
    let meta = blob_meta(executor, &blob_id).await?;
    Ok(json!({
        "attachment_id": attachment_id,
        "name": name,
        "created_at": created_at,
        "detached": deleted_at.is_some(),
        "deleted_at": deleted_at,
        "blob": meta,
    }))
}

async fn attachment_detach_state<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
) -> Result<AttachmentDetachState> {
    let bearer_id =
        require_attachment(executor, principal, tool, attachment_id, Capability::Manage).await?;
    let (name, _, created_at, blob_id) = resolve_attachment(executor, tool, attachment_id).await?;
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let _ = (bearer_id, name, created_at);
    Ok(AttachmentDetachState {
        #[cfg(feature = "mcp-executor-prototype")]
        bearer_id,
        #[cfg(feature = "mcp-executor-prototype")]
        name,
        #[cfg(feature = "mcp-executor-prototype")]
        created_at,
        blob_id,
    })
}

async fn attachment_content_seq<E: DomainStatementExecutor>(
    executor: &mut E,
    attachment_id: &str,
) -> Result<Option<i64>> {
    let statement = statement(
        "read attachment detach revision",
        "content_events",
        &[
            "SELECT MAX(seq) AS previous_seq FROM {{relation}} WHERE record_id = ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read attachment detach revision",
        &statement,
        &[BindValue::Text(attachment_id.into())],
        &[ColumnSpec::nullable("previous_seq", LogicalType::Integer)],
    )
    .await?;
    rows.first()
        .map(|row| optional_integer(row, "previous_seq", "attachment detach revision"))
        .transpose()
        .map(Option::flatten)
}

async fn assert_attachment_content_seq<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    attachment_id: &str,
    expected: i64,
) -> Result<()> {
    let actual = attachment_content_seq(executor, attachment_id).await?;
    if actual != Some(expected) {
        return Err(Error::engine(format!(
            "{tool}: content revision conflict; inspect the attachment and prepare again"
        )));
    }
    Ok(())
}

/// Exercise the exact backend-neutral detach authorization and target
/// resolution without appending a tombstone. The projection is consumed by
/// the signed executor plan and deliberately lives beside the production
/// domain operation so backend adapters cannot invent a second meaning.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_attachment_detach<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
) -> Result<AttachmentDetachPreparation> {
    let state = attachment_detach_state(executor, principal, tool, attachment_id).await?;
    let previous_seq = attachment_content_seq(executor, attachment_id)
        .await?
        .ok_or_else(|| attachment_not_found(tool, attachment_id))?;
    let state_revision = format!("content-seq:{previous_seq}");
    let target_state = json!({
        "attachment_id": attachment_id,
        "name": state.name,
        "created_at": state.created_at,
        "bearer_id": state.bearer_id,
        "blob_id": state.blob_id,
        "previous_seq": previous_seq,
    });
    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&target_state)?));
    let effect = json!({
        "target": {
            "attachment_id": attachment_id,
            "name": state.name,
            "bearer_id": state.bearer_id,
        },
        "before": {
            "detached": false,
            "blob_id": state.blob_id,
        },
        "after": {
            "detached": true,
            "blob_id": state.blob_id,
            "blob_retained": true,
        },
        "changed": true,
    });
    Ok(AttachmentDetachPreparation {
        canonical_source_arguments: json!({
            "action": "detach",
            "attachment_id": attachment_id,
            "if_content_seq": previous_seq,
        }),
        target_id: attachment_id.into(),
        target: format!("{} ({attachment_id})", state.name),
        state_revision,
        target_state_digest,
        effect,
        effect_summary: format!(
            "detach attachment '{}' ({attachment_id}) from record {} while retaining blob {}",
            state.name, state.bearer_id, state.blob_id
        ),
        operation_evidence: target_state,
    })
}

pub(crate) async fn detach_attachment<P>(
    port: &mut P,
    principal: Principal<'_>,
    tool: &str,
    attachment_id: &str,
    actor: &str,
    if_content_seq: Option<i64>,
) -> Result<Value>
where
    P: DomainStatementExecutor + AttachmentPhysicalPort,
{
    let state = attachment_detach_state(port, principal, tool, attachment_id).await?;
    if let Some(expected) = if_content_seq {
        port.lock_content_log().await?;
        assert_attachment_content_seq(port, tool, attachment_id, expected).await?;
    }
    port.append_content(AppendSpec {
        record_id: attachment_id.into(),
        event_type: "record.deleted".into(),
        payload: json!({}),
        actor: Some(actor.into()),
    })
    .await?;
    Ok(json!({
        "attachment_id": attachment_id,
        "detached": true,
        "blob_id": state.blob_id,
        "blob_retained": true,
    }))
}
