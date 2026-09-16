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
use super::{parse_args, require_record, require_record_in};

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
    /// Optional caller-supplied idempotency key for the whole attach call.
    /// Absent (or blank) means exactly today's behavior. When present, the
    /// call joins the provenance command-attestation mechanism that
    /// `create_record` uses: same key plus same normalized request replays
    /// the original receipt without appending; same key plus a materially
    /// different request is a conflict error. One key covers the call's whole
    /// effect — blob row, attachment record, link and facets alike — so no
    /// per-record identity plumbing is needed and ids stay random.
    idempotency_key: Option<String>,
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
    // The provenance digests run over the raw tool arguments: no server-minted
    // id enters the conflict detector, or every retry would conflict with the
    // call it repeats. Run-context keys are already stripped by the request
    // layer before the handler sees them.
    let provenance_arguments = arguments.clone();
    let args: AttachTextArgs = parse_args(TOOL, arguments)?;
    let record_id = args.record_id;
    let text = args.text;
    if text.len() > MAX_ATTACH_TEXT_BYTES {
        return Err(Error::engine(format!(
            "{TOOL}: text exceeds the {MAX_ATTACH_TEXT_BYTES} byte cap"
        )));
    }
    // Only the digest is stored, so an unbounded key is a mild DoS surface:
    // the same 1..=200 bound `create_record` enforces. Blank stays keyless
    // rather than erroring — a call with no key behaves as today.
    if args
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key.len() > 200)
    {
        return Err(Error::engine(
            "attach_text: idempotency_key must be 1..200 characters",
        ));
    }
    let idempotent = args
        .idempotency_key
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty());
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

    if idempotent {
        return attach_text_keyed(
            &db,
            &caller,
            &provenance_arguments,
            &record_id,
            text.as_bytes(),
            Some(&mime),
            filename.as_deref(),
            &name,
            lifecycle.as_deref(),
            owner_id.as_deref(),
            persistence.as_deref(),
            maturity.as_deref(),
            facets,
        )
        .await;
    }

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

/// Keyed `attach_text`: the whole call — blob row, attachment record, link
/// and facets — under one idempotency key, using the same provenance
/// command-attestation mechanism `create_record` uses.
///
/// The tentative write below is the validation: it runs the exact domain
/// fold the first call ran (authorization, bearer liveness, facet
/// predicates, required checks), so a replay whose bearer has since been
/// deleted or revoked fails exactly as a first call would. On a hit the
/// whole tentative transaction — tentative blob row included — is rolled
/// back and the receipt is rebuilt from the attested command's own outputs,
/// so a retry appends nothing and leaves no second blob row. Ids stay
/// random throughout: the attested outputs name the original attachment,
/// bearer and blob, which still exist because blobs are never hard-deleted.
#[allow(clippy::too_many_arguments)]
async fn attach_text_keyed(
    db: &Db,
    caller: &Caller,
    provenance_arguments: &Value,
    bearer_id: &str,
    bytes: &[u8],
    mime: Option<&str>,
    filename: Option<&str>,
    name: &str,
    lifecycle: Option<&str>,
    owner_id: Option<&str>,
    persistence: Option<&str>,
    maturity: Option<&str>,
    extra_facets: Vec<FacetWrite>,
) -> Result<Value> {
    const TOOL: &str = "attach_text";
    // Advisory preflight, same as the keyless path. The authoritative
    // authorization and liveness checks rerun inside the write transaction.
    require_record(db, caller, TOOL, bearer_id, Capability::Edit).await?;
    // ONE transaction. Everything below either commits together or does not
    // exist. The reserved action identity is taken before the tentative
    // write so the miss path commits under one accepted action.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let draft = crate::provenance::reserve_action_attestation()?;
    let tentative = {
        let mut port = SqliteAttachmentTransaction { db, tx: &mut tx };
        crate::domain_transaction::create_attachment(
            &mut port,
            AttachmentCreate {
                tool: TOOL,
                bearer_id,
                bytes,
                mime,
                filename,
                name,
                lifecycle,
                owner_id,
                persistence,
                maturity,
                extra_facets,
                actor: caller.actor(),
                credential: caller.credential(),
                principal: super::principal(caller),
                attachment_id: None,
                image_insert: None,
            },
        )
        .await?
    };
    // Idempotent replay, after every authorization and validation check and
    // inside the same BEGIN IMMEDIATE transaction as the mutation — the same
    // ordering contract `create_record` keeps so the tool cannot become a
    // command-existence oracle. A reused key with different normalized input
    // errors out of the lookup below, after an explicit rollback so the
    // tentative writes read as a rollback on every path, not just the hit.
    let hit = match crate::provenance::lookup_authorized_command_attestation_in(
        &mut tx,
        caller.credential(),
        TOOL,
        provenance_arguments,
        caller.intent(),
    )
    .await
    {
        Ok(hit) => hit,
        Err(error) => {
            tx.rollback().await?;
            return Err(error);
        }
    };
    if let Some(attestation_id) = hit {
        let attested = attested_attachment_in(&mut tx, &attestation_id).await?;
        // Non-disclosure for the outputs: the receipt names the attachment,
        // its bearer and its blob, so the replaying caller must still view
        // both records. A caller that lost access gets the opaque denial,
        // not the receipt.
        require_record_in(
            &mut tx,
            caller,
            TOOL,
            &attested.attachment_id,
            Capability::View,
        )
        .await?;
        require_record_in(&mut tx, caller, TOOL, &attested.bearer_id, Capability::View).await?;
        tx.rollback().await?;
        crate::provenance::note_replayed_action_attestation(attestation_id);
        // Reads happen only after the rollback; holding a second connection
        // while the write transaction is live is the one deadlock trap here.
        return read_attested_attachment_receipt(db, caller, &attested).await;
    }

    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;
    Ok(tentative)
}

/// The attested command's own outputs: which attachment it created, under
/// which bearer, pointing at which blob. The blob row itself is not an
/// attested output — it sits outside the event log — but the `blob_ref`
/// facet that names it is, and blobs are never hard-deleted, so the row the
/// facet names is still there to read.
struct AttestedAttachment {
    attachment_id: String,
    bearer_id: String,
    blob_id: String,
}

async fn attested_attachment_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    attestation_id: &str,
) -> Result<AttestedAttachment> {
    let rows = sqlx::query(
        "SELECT e.type, e.record_id, e.payload FROM provenance_action_outputs o
           JOIN content_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='content'
          ORDER BY o.ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    let incomplete = || Error::engine("attach_text: idempotent receipt is incomplete");
    let mut created: Vec<String> = Vec::new();
    let mut bearers: Vec<(String, String)> = Vec::new();
    let mut blobs: Vec<(String, String)> = Vec::new();
    for row in &rows {
        let event_type: String = row.try_get("type")?;
        let record_id: String = row.try_get("record_id")?;
        // Extra caller facets land as further `facet.set` events beside the
        // `blob_ref` one, so every event is filtered by shape, not position.
        match event_type.as_str() {
            "record.created" => created.push(record_id),
            "link.added" => {
                let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
                if payload.get("relationship").and_then(Value::as_str) != Some("part_of") {
                    continue;
                }
                let source = payload
                    .get("source_id")
                    .and_then(Value::as_str)
                    .ok_or_else(incomplete)?;
                let target = payload
                    .get("target_id")
                    .and_then(Value::as_str)
                    .ok_or_else(incomplete)?;
                bearers.push((source.to_string(), target.to_string()));
            }
            "facet.set" => {
                let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
                if payload.get("key").and_then(Value::as_str)
                    != Some(crate::blob::BLOB_REF_FACET_KEY)
                {
                    continue;
                }
                let blob_id = payload
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(incomplete)?;
                blobs.push((record_id, blob_id.to_string()));
            }
            _ => {}
        }
    }
    // This operation appends exactly one of each: one attachment record, one
    // `part_of` link onto its bearer, one `blob_ref` facet. Anything else
    // means the attestation does not describe this command. This couples to
    // `create_attachment`'s current shape on purpose: if that fold ever gains
    // a second link or facet, this fails closed with "receipt is incomplete"
    // rather than guessing which output names the blob.
    if created.len() != 1 || bearers.len() != 1 || blobs.len() != 1 {
        return Err(incomplete());
    }
    let attachment_id = created.pop().expect("exactly one record.created");
    let (link_source, bearer_id) = bearers.pop().expect("exactly one part_of link");
    let (facet_record, blob_id) = blobs.pop().expect("exactly one blob_ref facet");
    if link_source != attachment_id || facet_record != attachment_id {
        return Err(incomplete());
    }
    Ok(AttestedAttachment {
        attachment_id,
        bearer_id,
        blob_id,
    })
}

/// Rebuild the first call's receipt from the attested outputs: the original
/// attachment id and bearer, the live record name, and the ORIGINAL blob
/// metadata — read from the still-present blob row, never from a tentative
/// insert, so a retry returns the same blob id rather than minting a twin.
async fn read_attested_attachment_receipt(
    db: &Db,
    caller: &Caller,
    attested: &AttestedAttachment,
) -> Result<Value> {
    const TOOL: &str = "attach_text";
    // Re-check after the rollback: the in-transaction View checks ran before
    // it, so a concurrent tombstone or revocation in between must not yield
    // a receipt. A miss maps to the same opaque denial the sibling
    // `create_exploration` replay uses — a caller who has lost access must
    // not learn the attachment still exists.
    //
    // Liveness is explicit rather than folded into `require_record`: that
    // gate passes tombstoned ordinary records for shape-valid callers, so a
    // detached attachment would otherwise present as live.
    let live: Option<Option<String>> =
        sqlx::query_scalar("SELECT deleted_at FROM records WHERE id=?")
            .bind(&attested.attachment_id)
            .fetch_optional(db.write_pool())
            .await?;
    if !matches!(live, Some(None)) {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            attested.attachment_id
        )));
    }
    let bearer_live: Option<Option<String>> =
        sqlx::query_scalar("SELECT deleted_at FROM records WHERE id=?")
            .bind(&attested.bearer_id)
            .fetch_optional(db.write_pool())
            .await?;
    if !matches!(bearer_live, Some(None)) {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            attested.bearer_id
        )));
    }
    require_record(db, caller, TOOL, &attested.attachment_id, Capability::View).await?;
    require_record(db, caller, TOOL, &attested.bearer_id, Capability::View).await?;
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM records WHERE id=?")
        .bind(&attested.attachment_id)
        .fetch_optional(db.write_pool())
        .await?;
    let Some(name) = name else {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            attested.attachment_id
        )));
    };
    let meta = crate::blob::get_meta(db, &attested.blob_id)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: blob {} referenced by attachment {} does not exist",
                attested.blob_id, attested.attachment_id
            ))
        })?;
    Ok(json!({
        "attachment_id": attested.attachment_id,
        "record_id": attested.bearer_id,
        "name": name,
        "blob": meta,
    }))
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
        crate::mcp::record_ref::with_record_selector_aliases("attach_text", json!({
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
                },
                // Bare, like the `create_record` key: the Rust field comment
                // carries the semantics, and the federated-lens Focused
                // descriptor budget is binding down to the byte.
                "idempotency_key": { "type": "string" }
            },
            "required": ["record_id", "text"],
            "additionalProperties": false
        })),
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
    let list_schema = crate::mcp::record_ref::with_record_selector_aliases(
        "manage_attachments.list",
        json!({
            "type":"object",
            "properties":{
                "action":{"const":"list"},
                "record_id":{"type":"string","description":"Attachment parent."}
            },
            "required":["action","record_id"],
            "additionalProperties":false
        }),
    );
    let action_schema = json!({
        "type":"object",
        "oneOf":[
            list_schema,
            {
                "type":"object",
                "properties":{
                    "action":{"const":"inspect"},
                    "attachment_id":{"type":"string"}
                },
                "required":["action","attachment_id"],
                "additionalProperties":false
            },
            {
                "type":"object",
                "properties":{
                    "action":{"const":"detach"},
                    "attachment_id":{"type":"string"}
                },
                "required":["action","attachment_id"],
                "additionalProperties":false
            }
        ]
    });
    registry.register(
        ToolKind::ManageAttachments,
        "List, inspect or detach attachments on a record. Detach soft-deletes the \
         attachment record (record.deleted); the blob is retained.",
        action_schema,
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

#[cfg(test)]
mod idempotency_tests {
    use super::*;

    const PARENT_ID: &str = "a77ac000-0000-4000-8000-000000000011";

    async fn db() -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        crate::meta::seed_vocabularies(&db).await.unwrap();
        db
    }

    fn registry() -> crate::mcp::ToolRegistry {
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
    }

    async fn parent(db: &Db) {
        crate::store::create_record(
            db,
            json!({ "id": PARENT_ID, "type": "Collection", "kind": "folder", "name": PARENT_ID }),
        )
        .await
        .unwrap();
    }

    async fn call(registry: &crate::mcp::ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
        registry
            .call(db.clone(), Caller::local(), tool, args)
            .await
            .unwrap()
    }

    async fn call_err(
        registry: &crate::mcp::ToolRegistry,
        db: &Db,
        tool: &str,
        args: Value,
    ) -> String {
        registry
            .call(db.clone(), Caller::local(), tool, args)
            .await
            .unwrap_err()
            .to_string()
    }

    async fn count(db: &Db, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    }

    fn attach_args(key: Option<&str>) -> Value {
        let mut args = json!({
            "record_id": PARENT_ID,
            "text": "keyed bytes",
            "filename": "keyed.txt",
            // An extra caller facet rides beside `blob_ref` as a further
            // `facet.set` output, so the replay path must pick the blob by
            // facet shape rather than by position.
            "facets": { "replay_tag": "keep" },
        });
        if let Some(key) = key {
            args.as_object_mut()
                .unwrap()
                .insert("idempotency_key".into(), json!(key));
        }
        args
    }

    /// Same key plus same normalized request replays the original receipt —
    /// same attachment id, same blob id — and appends nothing: one blob
    /// row, one attachment record, one command attestation.
    #[tokio::test]
    async fn keyed_retry_returns_original_attachment_and_single_blob() {
        let db = db().await;
        parent(&db).await;
        let registry = registry();
        let first = call(
            &registry,
            &db,
            "attach_text",
            attach_args(Some("attach-key")),
        )
        .await;
        let second = call(
            &registry,
            &db,
            "attach_text",
            attach_args(Some("attach-key")),
        )
        .await;
        assert_eq!(first, second, "retry converges on the original receipt");
        assert_eq!(
            first["attachment_id"].as_str().unwrap(),
            second["attachment_id"].as_str().unwrap()
        );
        assert_eq!(
            first["blob"]["id"].as_str().unwrap(),
            second["blob"]["id"].as_str().unwrap(),
            "replay reads the original blob row, never a tentative twin"
        );
        assert_eq!(first["record_id"].as_str().unwrap(), PARENT_ID);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 1);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='attachment'"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM content_events WHERE type='record.created' AND json_extract(payload, '$.kind')='attachment'"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM provenance_local_attestation_authority WHERE principal='local' AND operation='attach_text'",
            )
            .await,
            1,
            "exactly one command attestation was issued"
        );
        db.close().await;
    }

    /// Same key with different bytes is a conflict error, and the failed
    /// retry leaves no second blob row behind.
    #[tokio::test]
    async fn reused_key_with_different_text_conflicts() {
        let db = db().await;
        parent(&db).await;
        let registry = registry();
        call(
            &registry,
            &db,
            "attach_text",
            attach_args(Some("attach-conflict")),
        )
        .await;
        let mut different = attach_args(Some("attach-conflict"));
        different["text"] = json!("different bytes");
        let error = call_err(&registry, &db, "attach_text", different).await;
        assert!(
            error.contains("conflicting action input"),
            "reused key with different content must conflict, got: {error}"
        );
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 1);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='attachment'"
            )
            .await,
            1
        );
        db.close().await;
    }

    /// Keyless calls behave exactly as today: every call mints again, blob
    /// row included.
    #[tokio::test]
    async fn keyless_repeats_mint_again() {
        let db = db().await;
        parent(&db).await;
        let registry = registry();
        let first = call(&registry, &db, "attach_text", attach_args(None)).await;
        let second = call(&registry, &db, "attach_text", attach_args(None)).await;
        assert_ne!(
            first["attachment_id"], second["attachment_id"],
            "keyless repeats mint again"
        );
        assert_ne!(
            first["blob"]["id"], second["blob"]["id"],
            "keyless repeats write a fresh blob row each time"
        );
        assert_eq!(count(&db, "SELECT COUNT(*) FROM blobs").await, 2);
        db.close().await;
    }

    /// A replay whose bearer has since been deleted fails exactly as a
    /// first call would — the tentative fold reruns every guard — and the
    /// rolled-back tentative blob leaves no orphan row. The bearer is a
    /// Document (homed in the folder) rather than the folder itself, so
    /// deleting it is not blocked by the attachment homed beside it.
    #[tokio::test]
    async fn replay_after_bearer_deleted_fails_closed_and_leaves_no_blob() {
        let db = db().await;
        parent(&db).await;
        let registry = registry();
        let bearer = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "Document",
                "kind": "note",
                "name": "bearer",
                "home_id": PARENT_ID,
                "reason": "fail-closed fixture",
            }),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut args = attach_args(Some("attach-stale"));
        args["record_id"] = json!(bearer);
        call(&registry, &db, "attach_text", args.clone()).await;
        call(
            &registry,
            &db,
            "delete_record",
            json!({ "id": bearer, "reason": "fail-closed fixture" }),
        )
        .await;
        let error = call_err(&registry, &db, "attach_text", args).await;
        assert!(
            error.contains("tombstoned") || error.contains("does not exist"),
            "replay under a deleted bearer must fail closed, got: {error}"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM blobs").await,
            1,
            "the rolled-back tentative blob leaves no orphan row"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='attachment'"
            )
            .await,
            1
        );
        db.close().await;
    }

    /// The post-rollback receipt read re-checks View and liveness: a detached
    /// attachment is refused with the opaque denial rather than returned as
    /// live, and a full replay fails closed the same way.
    #[tokio::test]
    async fn attested_receipt_read_refuses_detached_attachment() {
        let db = db().await;
        parent(&db).await;
        let registry = registry();
        let args = attach_args(Some("attach-detach"));
        let first = call(&registry, &db, "attach_text", args.clone()).await;
        let attested = AttestedAttachment {
            attachment_id: first["attachment_id"].as_str().unwrap().to_string(),
            bearer_id: PARENT_ID.to_string(),
            blob_id: first["blob"]["id"].as_str().unwrap().to_string(),
        };
        call(
            &registry,
            &db,
            "manage_attachments",
            json!({ "action": "detach", "attachment_id": attested.attachment_id }),
        )
        .await;
        let error = read_attested_attachment_receipt(&db, &Caller::local(), &attested)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not exist"),
            "detached attachment must map to the opaque denial, got: {error}"
        );
        let replay = call_err(&registry, &db, "attach_text", args).await;
        assert!(
            replay.contains("does not exist"),
            "replay of a detached attachment must fail closed, got: {replay}"
        );
        db.close().await;
    }
}
