//! Tools 22–25 — blobs & attachments (docs/tool-surface.md §Blobs &
//! attachments).
//!
//! An attachment is not a type: it is a `Document kind:attachment` record
//! referencing a `blobs` row via the `blob_ref` open facet (a978c23). The
//! byte tier is SUBSTRATE: blob bytes are written directly through
//! `crate::blob` (never through the event log), while the records that
//! reference them go append-event → project as normal (`store::append_batch`,
//! one atomic batch for record.created + its facets). Tool 25's "detach" is a
//! `record.deleted` soft-delete of the attachment record with the BLOB
//! RETAINED — there is no blob hard-delete in v1.
//!
//! Record-creating-tool invariant: every public tool that emits
//! `record.created` accepts open facets and commits them in the same atomic
//! batch. Today those paths are `create_record`, `attach_text`, and
//! `attach_from_url`.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::blob;
use crate::db::Db;
use crate::domain_transaction::{
    AttachmentCreate, AttachmentPhysicalPort, TransactionLifecyclePort,
};
use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;
use crate::mcp::fetch::{self, FetchConfig, MAX_FETCH_BYTES};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor,
    ExecutionControl, NormalizedRow, StatementTemplate,
};

use super::lifecycle::{assert_facet_value_predicates, parse_facet_entry, FacetWrite};
use super::{parse_args, require_record};

/// Cap on `attach_text` payloads — matches the guarded-fetch hard ceiling, so
/// neither ingestion path can out-size the other.
const MAX_ATTACH_TEXT_BYTES: usize = MAX_FETCH_BYTES as usize;
/// Default / maximum page sizes for `read_attachment`.
const DEFAULT_READ_LENGTH: u64 = 64 * 1024;
const MAX_READ_LENGTH: u64 = 512 * 1024;
/// Mime recorded when `attach_text` is given none.
const DEFAULT_TEXT_MIME: &str = "text/plain; charset=utf-8";
/// Open facet recording where `attach_from_url` fetched from (provenance).
/// Unlike `blob_ref`, this is caller-editable: correcting provenance does not
/// change which immutable blob the attachment resolves to.
const SOURCE_URL_FACET_KEY: &str = "source_url";

// ---------------------------------------------------------------------------
// Argument shapes (parsed via `super::parse_args`, deny_unknown_fields)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachTextArgs {
    record_id: String,
    text: String,
    filename: Option<String>,
    mime: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachFromUrlArgs {
    record_id: String,
    url: String,
    filename: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    max_bytes: Option<u64>,
    facets: Option<Map<String, Value>>,
}

/// Backend-neutral, fully parsed URL ingress request.  Keeping this typed
/// request separate from the fetch lets each backend perform its cheap
/// authorization/liveness preflight before network I/O.
pub(crate) struct AttachmentUrlRequest {
    pub record_id: String,
    pub filename: Option<String>,
    pub name: Option<String>,
    pub lifecycle: Option<String>,
    pub owner_id: Option<String>,
    pub persistence: Option<String>,
    pub maturity: Option<String>,
    pub facets: Vec<FacetWrite>,
    pub url: String,
}

/// Backend-neutral result of the guarded URL ingress.  Network work is
/// deliberately completed before any backend write transaction is opened;
/// the backend then feeds these bytes and the normalized metadata into the
/// same attachment creation fold as `attach_text`.
pub(crate) struct PreparedAttachmentFromUrl {
    pub record_id: String,
    pub bytes: Vec<u8>,
    pub mime: String,
    pub filename: Option<String>,
    pub name: String,
    pub lifecycle: Option<String>,
    pub owner_id: Option<String>,
    pub persistence: Option<String>,
    pub maturity: Option<String>,
    pub facets: Vec<FacetWrite>,
    pub url: String,
    pub final_url: String,
    pub redirects: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAttachmentArgs {
    attachment_id: String,
    offset: Option<u64>,
    length: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageAttachmentsArgs {
    List {
        record_id: String,
    },
    Inspect {
        attachment_id: String,
    },
    Detach {
        attachment_id: String,
        #[serde(default)]
        if_content_seq: Option<i64>,
    },
}

struct SqliteAttachmentTransaction<'a> {
    db: &'a Db,
    tx: &'a mut Transaction<'static, Sqlite>,
}

struct SqliteAttachmentLifecycle<'a> {
    db: &'a Db,
    write: bool,
}

impl TransactionLifecyclePort for SqliteAttachmentLifecycle<'_> {
    type Transaction = Transaction<'static, Sqlite>;

    fn begin<'a>(&'a mut self) -> futures::future::BoxFuture<'a, Result<Self::Transaction>> {
        Box::pin(async move {
            if self.write {
                crate::db::begin_write(self.db.write_pool()).await
            } else {
                Ok(self.db.write_pool().begin().await?)
            }
        })
    }

    fn commit<'a>(
        &'a mut self,
        transaction: Self::Transaction,
    ) -> futures::future::BoxFuture<'a, crate::portable_sql::SqlResult<()>> {
        Box::pin(async move {
            if self.write {
                self.db.commit_content_for_domain(transaction).await
            } else {
                transaction.commit().await.map_err(|error| {
                    crate::portable_sql::normalize_sqlx_error(
                        crate::portable_sql::Backend::Sqlite,
                        crate::portable_sql::ExecutionPhase::Commit,
                        &error,
                    )
                })
            }
        })
    }

    fn rollback<'a>(
        &'a mut self,
        transaction: Self::Transaction,
    ) -> futures::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(transaction.rollback().await?) })
    }
}

impl DomainStatementExecutor for SqliteAttachmentTransaction<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> futures::future::BoxFuture<'a, crate::portable_sql::SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            let mut executor = BorrowedSqliteStatementExecutor::new(self.tx);
            executor.fetch_all(statement, bindings, columns).await
        })
    }
}

impl AttachmentPhysicalPort for SqliteAttachmentTransaction<'_> {
    fn lock_content_log<'a>(&'a mut self) -> futures::future::BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn insert_blob<'a>(
        &'a mut self,
        bytes: &'a [u8],
        mime: Option<&'a str>,
        original_filename: Option<&'a str>,
    ) -> futures::future::BoxFuture<'a, Result<blob::BlobMeta>> {
        Box::pin(async move { blob::insert_blob_in(self.tx, bytes, mime, original_filename).await })
    }

    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> futures::future::BoxFuture<'a, Result<Option<blob::BlobSlice>>> {
        Box::pin(async move { blob::read_range_on(self.tx, blob_id, offset, length).await })
    }

    fn append_content<'a>(
        &'a mut self,
        spec: crate::store::AppendSpec,
    ) -> futures::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::store::append_in(self.db, self.tx, spec)
                .await
                .map(|_| ())
        })
    }
}

// ---------------------------------------------------------------------------
// Shared attachment plumbing
// ---------------------------------------------------------------------------

/// Fast-fail check that an attach target exists and is live, used BEFORE
/// expensive work (tool 23's fetch). Advisory only: the authoritative check
/// runs inside `create_attachment`'s write transaction — the projector does
/// not validate `home_id`, so the tool layer must, race-free.
async fn assert_attach_target_live(db: &Db, tool: &str, id: &str) -> Result<()> {
    let row = sqlx::query("SELECT deleted_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!("{tool}: record {id} does not exist")));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "{tool}: record {id} is deleted (tombstoned)"
        )));
    }
    Ok(())
}

/// Create the attachment: bytes DIRECT into the blob tier plus one atomic
/// event batch (`record.created` + `facet.set` per facet) for the record that
/// references them. Authorization, bytes, and referencing events share one
/// transaction, so denial or rollback leaves no orphan blob row.
///
/// The parent-liveness guard runs INSIDE the same write transaction as the
/// batch (`BEGIN IMMEDIATE` serializes writers), so a parent soft-deleted
/// after any earlier check — e.g. during `attach_from_url`'s fetch — is
/// caught here: nothing may attach under a tombstone (frozen-after-soft-
/// delete, decision ef32e44; the projector's parent check does not cover
/// tombstones).
async fn create_attachment(db: &Db, create: AttachmentCreate<'_>) -> Result<Value> {
    assert_facet_value_predicates(
        db,
        create.tool,
        CoreKind::DocumentAttachment.record_type(),
        Some(CoreKind::DocumentAttachment.token()),
        None,
        &create.extra_facets,
    )
    .await?;
    let control = ExecutionControl::default();
    let mut lifecycle = SqliteAttachmentLifecycle { db, write: true };
    let mut context = (db, Some(create));
    crate::domain_transaction::run_backend_transaction(
        &mut lifecycle,
        &control,
        &mut context,
        |transaction, context| {
            Box::pin(async move {
                let create = context
                    .1
                    .take()
                    .expect("attachment transaction handler runs once");
                let mut port = SqliteAttachmentTransaction {
                    db: context.0,
                    tx: transaction,
                };
                crate::domain_transaction::create_attachment(&mut port, create).await
            })
        },
    )
    .await
    .map_err(|error| error.stable("create attachment"))
}

/// Parse the caller facet map through the same open-facet contract used by
/// `create_record`. Attachment creation does not admit unsets: every supplied
/// entry is part of a new record's initial atomic batch.
fn parse_attachment_facets(
    tool: &str,
    facets: Option<&Map<String, Value>>,
) -> Result<Vec<FacetWrite>> {
    facets
        .into_iter()
        .flatten()
        .map(|(key, value)| {
            parse_facet_entry(tool, key, value, false)
                .map(|facet| facet.expect("allow_unset=false never yields None"))
        })
        .collect()
}

/// Parse and validate one URL attachment before database I/O.  The returned
/// typed request is intentionally separate from fetching so each backend can
/// authorize and check liveness before network I/O.
pub(crate) fn parse_attachment_from_url(
    tool: &str,
    arguments: Value,
    mut config: FetchConfig,
) -> Result<(AttachmentUrlRequest, FetchConfig)> {
    let args: AttachFromUrlArgs = parse_args(tool, arguments)?;
    let record_id = args.record_id;
    let url = args.url;
    let filename_arg = args.filename;
    let name_arg = args.name;
    let lifecycle = args.lifecycle;
    let owner_id = args.owner_id;
    let persistence = args.persistence;
    let maturity = args.maturity;
    let facets = parse_attachment_facets(tool, args.facets.as_ref())?;
    if let Some(max_bytes) = args.max_bytes {
        if max_bytes == 0 || max_bytes > MAX_FETCH_BYTES {
            return Err(Error::engine(format!(
                "{tool}: 'max_bytes' must be between 1 and {MAX_FETCH_BYTES}"
            )));
        }
        config.max_bytes = max_bytes;
    }
    let request = AttachmentUrlRequest {
        record_id,
        filename: filename_arg,
        name: name_arg,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        facets,
        url,
    };
    Ok((request, config))
}

pub(crate) async fn fetch_attachment_from_url(
    request: AttachmentUrlRequest,
    config: &FetchConfig,
) -> Result<PreparedAttachmentFromUrl> {
    let AttachmentUrlRequest {
        record_id,
        filename: filename_arg,
        name: name_arg,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        mut facets,
        url,
    } = request;
    let fetched = fetch::fetch_url(&url, config).await?;
    let filename = filename_arg.or_else(|| filename_from_url(&fetched.final_url));
    let name = name_arg
        .or_else(|| filename.clone())
        .unwrap_or_else(|| url.clone());
    let mime = fetched
        .mime
        .unwrap_or_else(|| "application/octet-stream".into());
    if !facets.iter().any(|facet| facet.key == SOURCE_URL_FACET_KEY) {
        facets.push(FacetWrite {
            key: SOURCE_URL_FACET_KEY.into(),
            value: Value::String(url.clone()),
            vocab_ref: None,
        });
    }
    Ok(PreparedAttachmentFromUrl {
        record_id,
        bytes: fetched.bytes,
        mime,
        filename,
        name,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        facets,
        url,
        final_url: fetched.final_url,
        redirects: fetched.redirects,
    })
}

// ---------------------------------------------------------------------------
// Tool 22 — attach_text
// ---------------------------------------------------------------------------

async fn attach_text(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "attach_text";
    let args: AttachTextArgs = parse_args(TOOL, arguments)?;
    let record_id = args.record_id;
    let text = args.text;
    if text.len() > MAX_ATTACH_TEXT_BYTES {
        return Err(Error::engine(format!(
            "{TOOL}: text exceeds the {MAX_ATTACH_TEXT_BYTES} byte cap"
        )));
    }
    let filename = args.filename;
    let lifecycle = args.lifecycle;
    let owner_id = args.owner_id;
    let persistence = args.persistence;
    let maturity = args.maturity;
    let mime = args.mime.unwrap_or_else(|| DEFAULT_TEXT_MIME.into());
    let facets = parse_attachment_facets(TOOL, args.facets.as_ref())?;
    let name = args
        .name
        .or_else(|| filename.clone())
        .unwrap_or_else(|| "attachment".into());

    require_record(&db, &caller, TOOL, &record_id, Capability::Edit).await?;
    // Parent authorization and liveness are enforced again inside
    // create_attachment's transaction.
    create_attachment(
        &db,
        AttachmentCreate {
            tool: TOOL,
            bearer_id: &record_id,
            bytes: text.as_bytes(),
            mime: Some(&mime),
            filename: filename.as_deref(),
            name: &name,
            lifecycle: lifecycle.as_deref(),
            owner_id: owner_id.as_deref(),
            persistence: persistence.as_deref(),
            maturity: maturity.as_deref(),
            extra_facets: facets,
            actor: caller.actor(),
            credential: caller.credential(),
            principal: super::principal(&caller),
            attachment_id: None,
            image_insert: None,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Tool 23 — attach_from_url
// ---------------------------------------------------------------------------

/// The last path segment of the final URL, as a filename hint.
fn filename_from_url(final_url: &str) -> Option<String> {
    let parsed = url::Url::parse(final_url).ok()?;
    let segment = parsed.path_segments()?.next_back()?.trim();
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

async fn attach_from_url(
    db: Db,
    caller: Caller,
    arguments: Value,
    config: FetchConfig,
) -> Result<Value> {
    const TOOL: &str = "attach_from_url";
    let (request, config) = parse_attachment_from_url(TOOL, arguments, config)?;
    require_record(&db, &caller, TOOL, &request.record_id, Capability::Edit).await?;
    assert_attach_target_live(&db, TOOL, &request.record_id).await?;
    let prepared = fetch_attachment_from_url(request, &config).await?;
    let PreparedAttachmentFromUrl {
        record_id,
        bytes,
        mime,
        filename,
        name,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        facets,
        url,
        final_url,
        redirects,
    } = prepared;

    let mut result = create_attachment(
        &db,
        AttachmentCreate {
            tool: TOOL,
            bearer_id: &record_id,
            bytes: &bytes,
            mime: Some(&mime),
            filename: filename.as_deref(),
            name: &name,
            lifecycle: lifecycle.as_deref(),
            owner_id: owner_id.as_deref(),
            persistence: persistence.as_deref(),
            maturity: maturity.as_deref(),
            extra_facets: facets,
            actor: caller.actor(),
            credential: caller.credential(),
            principal: super::principal(&caller),
            attachment_id: None,
            image_insert: None,
        },
    )
    .await?;
    let object = result.as_object_mut().expect("create_attachment payload");
    object.insert("url".into(), json!(url));
    object.insert("final_url".into(), json!(final_url));
    object.insert("redirects".into(), json!(redirects));
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tool 24 — read_attachment
// ---------------------------------------------------------------------------

async fn read_attachment(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "read_attachment";
    let args: ReadAttachmentArgs = parse_args(TOOL, arguments)?;
    let attachment_id = args.attachment_id;
    let offset = args.offset.unwrap_or(0);
    let length = args.length.unwrap_or(DEFAULT_READ_LENGTH);
    let control = ExecutionControl::default();
    let mut lifecycle = SqliteAttachmentLifecycle {
        db: &db,
        write: false,
    };
    let mut context = (&db, &caller, attachment_id, offset, length);
    crate::domain_transaction::run_backend_snapshot(
        &mut lifecycle,
        &control,
        &mut context,
        |transaction, context| {
            Box::pin(async {
                let mut port = SqliteAttachmentTransaction {
                    db: context.0,
                    tx: transaction,
                };
                crate::domain_transaction::read_attachment(
                    &mut port,
                    super::principal(context.1),
                    TOOL,
                    &context.2,
                    context.3,
                    context.4,
                    MAX_READ_LENGTH,
                )
                .await
            })
        },
    )
    .await
    .map_err(|error| error.stable("read attachment"))
}

// ---------------------------------------------------------------------------
// Tool 25 — manage_attachments
// ---------------------------------------------------------------------------

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_manage_attachments_detach(
    db: &Db,
    caller: &Caller,
    arguments: Value,
) -> Result<crate::domain_transaction::AttachmentDetachPreparation> {
    let ManageAttachmentsArgs::Detach {
        attachment_id,
        if_content_seq: None,
    } = parse_args("manage_attachments", arguments)?
    else {
        return Err(Error::engine(
            "manage_attachments: executor preparation only supports action detach without an internal revision",
        ));
    };
    let control = ExecutionControl::default();
    let mut lifecycle = SqliteAttachmentLifecycle { db, write: false };
    let mut context = (db, caller, attachment_id);
    crate::domain_transaction::run_backend_snapshot(
        &mut lifecycle,
        &control,
        &mut context,
        |transaction, context| {
            Box::pin(async {
                let mut port = SqliteAttachmentTransaction {
                    db: context.0,
                    tx: transaction,
                };
                crate::domain_transaction::prepare_attachment_detach(
                    &mut port,
                    super::principal(context.1),
                    "manage_attachments",
                    &context.2,
                )
                .await
            })
        },
    )
    .await
    .map_err(|error| error.stable("detach attachment"))
}

async fn manage_attachments(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_attachments";
    match parse_args(TOOL, arguments)? {
        ManageAttachmentsArgs::List { record_id } => {
            let control = ExecutionControl::default();
            let mut lifecycle = SqliteAttachmentLifecycle {
                db: &db,
                write: false,
            };
            let mut context = (&db, &caller, record_id);
            crate::domain_transaction::run_backend_snapshot(
                &mut lifecycle,
                &control,
                &mut context,
                |transaction, context| {
                    Box::pin(async {
                        let mut port = SqliteAttachmentTransaction {
                            db: context.0,
                            tx: transaction,
                        };
                        crate::domain_transaction::list_attachments(
                            &mut port,
                            super::principal(context.1),
                            TOOL,
                            &context.2,
                        )
                        .await
                    })
                },
            )
            .await
            .map_err(|error| error.stable("list attachments"))
        }
        ManageAttachmentsArgs::Inspect { attachment_id } => {
            let control = ExecutionControl::default();
            let mut lifecycle = SqliteAttachmentLifecycle {
                db: &db,
                write: false,
            };
            let mut context = (&db, &caller, attachment_id);
            crate::domain_transaction::run_backend_snapshot(
                &mut lifecycle,
                &control,
                &mut context,
                |transaction, context| {
                    Box::pin(async {
                        let mut port = SqliteAttachmentTransaction {
                            db: context.0,
                            tx: transaction,
                        };
                        crate::domain_transaction::inspect_attachment(
                            &mut port,
                            super::principal(context.1),
                            TOOL,
                            &context.2,
                        )
                        .await
                    })
                },
            )
            .await
            .map_err(|error| error.stable("inspect attachment"))
        }
        ManageAttachmentsArgs::Detach {
            attachment_id,
            if_content_seq,
        } => {
            let control = ExecutionControl::default();
            let mut lifecycle = SqliteAttachmentLifecycle {
                db: &db,
                write: true,
            };
            let mut context = (&db, &caller, attachment_id, if_content_seq);
            crate::domain_transaction::run_backend_transaction(
                &mut lifecycle,
                &control,
                &mut context,
                |transaction, context| {
                    Box::pin(async {
                        let mut port = SqliteAttachmentTransaction {
                            db: context.0,
                            tx: transaction,
                        };
                        crate::domain_transaction::detach_attachment(
                            &mut port,
                            super::principal(context.1),
                            TOOL,
                            &context.2,
                            context.1.actor(),
                            context.3,
                        )
                        .await
                    })
                },
            )
            .await
            .map_err(|error| error.stable("detach attachment"))
        }
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register tools 22–25 with the production fetch guard.
pub fn register_attachment_tools(registry: &mut ToolRegistry) -> Result<()> {
    register_attachment_tools_with(registry, FetchConfig::default())
}

/// Register tools 22–25 with an explicit [`FetchConfig`] — the seam the SSRF
/// tests use to point `attach_from_url` at a local server and to script the
/// resolver. Production callers use [`register_attachment_tools`].
pub fn register_attachment_tools_with(
    registry: &mut ToolRegistry,
    fetch_config: FetchConfig,
) -> Result<()> {
    registry.register(
        ToolKind::AttachText,
        "Capture text as an attachment under a record: bytes into the blob tier, \
         plus a Document kind:attachment record bound via the blob_ref facet.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string", "description": "Record to attach under." },
                "text": { "type": "string", "description": "The text to store." },
                "filename": { "type": "string" },
                "mime": { "type": "string", "description": "Defaults to text/plain; charset=utf-8." },
                "name": { "type": "string", "description": "Attachment record name; defaults to filename." },
                "lifecycle": { "type": "string", "description": "Attachment lifecycle spine facet." },
                "owner_id": { "type": "string", "description": "Attachment owner spine facet (record id)." },
                "persistence": { "type": "string", "enum": ["enduring", "occurrent"], "description": "Attachment persistence; defaults to enduring." },
                "maturity": { "type": "string", "description": "Attachment maturity spine facet." },
                "facets": {
                    "type": "object",
                    "description": "Open facets on the attachment record: key → string/number value or { value, vocab_ref }. Preserve JSON numbers for facets declared type:number. Engine-reserved and spine facets are refused.",
                    "additionalProperties": true
                }
            },
            "required": ["record_id", "text"],
            "additionalProperties": false
        }),
        attach_text,
    )?;
    registry.register(
        ToolKind::AttachFromUrl,
        "Fetch a URL (SSRF-guarded: http/https only, public addresses only, pinned \
         DNS, per-hop redirect revalidation, streamed size cap) and store the \
         capture as an attachment under a record.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string", "description": "Record to attach under." },
                "url": { "type": "string", "description": "http(s) URL to fetch." },
                "filename": { "type": "string" },
                "name": { "type": "string" },
                "lifecycle": { "type": "string", "description": "Attachment lifecycle spine facet." },
                "owner_id": { "type": "string", "description": "Attachment owner spine facet (record id)." },
                "persistence": { "type": "string", "enum": ["enduring", "occurrent"], "description": "Attachment persistence; defaults to enduring." },
                "maturity": { "type": "string", "description": "Attachment maturity spine facet." },
                "facets": {
                    "type": "object",
                    "description": "Open facets on the attachment record: key → string/number value or { value, vocab_ref }. Preserve JSON numbers for facets declared type:number. Engine-reserved and spine facets are refused; source_url may explicitly correct the default provenance.",
                    "additionalProperties": true
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Byte cap for the fetched body.",
                    "minimum": 1,
                    "maximum": MAX_FETCH_BYTES
                }
            },
            "required": ["record_id", "url"],
            "additionalProperties": false
        }),
        move |db, caller, arguments| {
            let config = fetch_config.clone();
            attach_from_url(db, caller, arguments, config)
        },
    )?;
    registry.register(
        ToolKind::ReadAttachment,
        "Read an attachment's content, ranged/paged for large blobs. Textual mimes \
         return UTF-8; everything else returns base64.",
        json!({
            "type": "object",
            "properties": {
                "attachment_id": { "type": "string" },
                "offset": { "type": "integer", "minimum": 0, "description": "Byte offset to read from (default 0)." },
                "length": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_READ_LENGTH,
                    "description": "Bytes per page (default 65536)."
                }
            },
            "required": ["attachment_id"],
            "additionalProperties": false
        }),
        read_attachment,
    )?;
    registry.register(
        ToolKind::ManageAttachments,
        "List, inspect or detach attachments on a record. Detach soft-deletes the \
         attachment record (record.deleted); the blob is retained.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["list", "inspect", "detach"] },
                "record_id": { "type": "string", "description": "list: the record whose attachments to list." },
                "attachment_id": { "type": "string", "description": "inspect/detach: the attachment record." }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        manage_attachments,
    )?;
    Ok(())
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, replace_explicit_policy_on, AllowEntry};
    use crate::store::{append_in, create_record, AppendSpec};

    // Pinned fixture record ids. `DEAD_PARENT_ID` and `REVOKED_PARENT_ID` are
    // quoted verbatim inside the expected error strings, and `ALICE_ID` inside
    // a binding INSERT, so those are built from these same constants.
    const PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000001";
    const ARCHIVED_PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000002";
    const DEAD_PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000003";
    const REVOKED_PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000004";
    const ATTACHMENT_PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000005";
    const ALICE_ID: &str = "a77ac000-0000-4000-8000-000000000006";

    async fn fixture() -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        crate::meta::seed_vocabularies(&db).await.unwrap();
        db
    }

    async fn parent(db: &Db, id: &str) {
        create_record(
            db,
            json!({ "id": id, "type": "Collection", "kind": "folder", "name": id }),
        )
        .await
        .unwrap();
    }

    async fn count(db: &Db, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn required_failure_after_blob_insert_leaves_no_orphan_tier() {
        let db = fixture().await;
        parent(&db, PARENT_ID).await;
        sqlx::query(
            "INSERT INTO schema_config (id, layer, data) VALUES ('attachment-required', 'user', ?)",
        )
        .bind(
            json!({ "shapes": { "Document:attachment": { "facets": {
                "classification": { "required": true }
            } } } })
            .to_string(),
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let error = attach_text(
            db.clone(),
            Caller::local(),
            json!({ "record_id": PARENT_ID, "text": "must roll back" }),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required facet 'classification'"));
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 0);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM content_events WHERE type = 'record.created' AND json_extract(payload, '$.kind') = 'attachment'",
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type = 'Document' AND kind = 'attachment'",
            )
            .await,
            0
        );
    }

    #[tokio::test]
    async fn projector_failure_after_blob_and_event_append_leaves_no_orphan_tier() {
        let db = fixture().await;
        parent(&db, ARCHIVED_PARENT_ID).await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: ARCHIVED_PARENT_ID.into(),
                event_type: "facet.set".into(),
                payload: json!({ "key": "archived", "value": "true" }),
                actor: Some("agent:test".into()),
            },
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();

        let error = attach_text(
            db.clone(),
            Caller::local(),
            json!({ "record_id": ARCHIVED_PARENT_ID, "text": "must roll back" }),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("must be a live, unarchived, enduring Collection kind:folder"));
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 0);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM content_events WHERE type = 'record.created' AND json_extract(payload, '$.kind') = 'attachment'",
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type = 'Document' AND kind = 'attachment'",
            )
            .await,
            0
        );
    }

    #[tokio::test]
    async fn queued_attach_rechecks_parent_liveness_and_authorization() {
        let db = fixture().await;
        parent(&db, DEAD_PARENT_ID).await;
        let mut blocker = crate::db::begin_write(db.write_pool()).await.unwrap();
        let worker_db = db.clone();
        let dead_worker = tokio::spawn(async move {
            attach_text(
                worker_db,
                Caller::local(),
                json!({ "record_id": DEAD_PARENT_ID, "text": "late" }),
            )
            .await
            .unwrap_err()
            .to_string()
        });
        tokio::task::yield_now().await;
        append_in(
            &db,
            &mut blocker,
            AppendSpec {
                record_id: DEAD_PARENT_ID.into(),
                event_type: "record.deleted".into(),
                payload: json!({}),
                actor: Some("agent:test".into()),
            },
        )
        .await
        .unwrap();
        db.commit_content(blocker).await.unwrap();
        assert_eq!(
            dead_worker.await.unwrap(),
            format!("attach_text: record {DEAD_PARENT_ID} is deleted (tombstoned)")
        );

        parent(&db, REVOKED_PARENT_ID).await;
        create_record(
            &db,
            json!({ "id": ALICE_ID, "type": "Entity", "kind": "person", "name": "Alice" }),
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical) \
                 VALUES ('{ALICE_ID}', 'account', 'acct:alice', 1)"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "agent:test",
            REVOKED_PARENT_ID,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        )
        .await
        .unwrap();

        let mut blocker = crate::db::begin_write(db.write_pool()).await.unwrap();
        let worker_db = db.clone();
        let revoked_worker = tokio::spawn(async move {
            attach_text(
                worker_db,
                Caller::authenticated("acct:alice"),
                json!({ "record_id": REVOKED_PARENT_ID, "text": "late" }),
            )
            .await
            .unwrap_err()
            .to_string()
        });
        tokio::task::yield_now().await;
        replace_explicit_policy_on(&mut blocker, "agent:test", REVOKED_PARENT_ID, vec![])
            .await
            .unwrap();
        blocker.commit().await.unwrap();
        assert_eq!(
            revoked_worker.await.unwrap(),
            format!("attach_text: record {REVOKED_PARENT_ID} does not exist")
        );
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 0);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type = 'Document' AND kind = 'attachment'",
            )
            .await,
            0
        );
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn detach_preparation_is_non_mutating_and_handler_cas_fences_stale_replay() {
        let db = fixture().await;
        parent(&db, ATTACHMENT_PARENT_ID).await;
        let attachment = attach_text(
            db.clone(),
            Caller::local(),
            json!({
                "record_id": ATTACHMENT_PARENT_ID,
                "text": "prepared attachment",
                "filename": "prepared.txt",
            }),
        )
        .await
        .unwrap()["attachment_id"]
            .as_str()
            .unwrap()
            .to_string();
        let arguments = json!({ "action": "detach", "attachment_id": attachment });
        let events_before = count(&db, "SELECT COUNT(*) FROM content_events").await;
        let prepared = prepare_manage_attachments_detach(&db, &Caller::local(), arguments.clone())
            .await
            .unwrap();
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM content_events").await,
            events_before
        );
        assert_eq!(prepared.effect["after"]["blob_retained"], true);

        crate::store::update_record(
            &db,
            &attachment,
            json!({ "summary": "changed after approval" }),
        )
        .await
        .unwrap();
        let stale = manage_attachments(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stale.contains("content revision conflict"), "{stale}");

        let fresh = prepare_manage_attachments_detach(&db, &Caller::local(), arguments)
            .await
            .unwrap();
        let first = manage_attachments(
            db.clone(),
            Caller::local(),
            fresh.canonical_source_arguments.clone(),
        );
        let second = manage_attachments(
            db.clone(),
            Caller::local(),
            fresh.canonical_source_arguments,
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let result = first.or(second).unwrap();
        assert_eq!(result["detached"], true);
        let deletes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.deleted'",
        )
        .bind(&attachment)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(deletes, 1);
    }
}
