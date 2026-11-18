//! KernelV2 `attach_from_url` (`external_import.attach_from_url` on v2).
//!
//! V2 already stores blobs, serves attachment reads, inserts editor images
//! and captures text; URL import had no handler. This wires it with the v1
//! keyed shape (tools/attachments.rs `attach_from_url`, A2 record 10ca9e2):
//!
//! 1. **Authorized preflight before any network I/O** — a short write
//!    transaction admits the caller, checks Edit on the bearer, checks the
//!    bearer is live, then looks a keyed call up. A hit replays without
//!    fetching.
//! 2. **Fetch with no transaction open** — `mcp::fetch::fetch_url` under the
//!    production `FetchConfig` guard (scheme allowlist, address policy,
//!    pinned DNS, per-hop redirect revalidation, streamed size cap,
//!    timeout). There is no unguarded fetcher on this path; tests pass an
//!    explicit loopback config into [`execute`].
//! 3. **Atomic commit** — the commit transaction re-admits, re-checks Edit
//!    and liveness (current authority at commit, not preflight's), repeats
//!    the keyed lookup (a racer may have committed during the fetch), then
//!    commits blob bytes, attachment record, `part_of` link, `source_url`
//!    provenance, app action and keyed receipt together. Anything failing
//!    rolls everything back; dropping the future before commit (fetch
//!    cancellation included) writes nothing because no transaction is open
//!    across the fetch.
//!
//! The commit-time unique backstop reruns the whole call shape: on a
//! conflicting receipt record the tentative write rolls back and a fresh
//! lookup replays the stored receipt (same key, same args) or refuses
//! (same key, changed args). Keyed receipts omit `final_url`/`redirects`,
//! which are not attested — the v1 semantic.

use super::{
    dispatched_fingerprint, event, facets, invalid, text, validate_lifecycle, view, RECEIPTS,
};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::{begin_write, Db},
    kernel,
    mcp::fetch::{fetch_url, FetchConfig, MAX_FETCH_BYTES},
    v2_standard::v1_compat,
    Error, Result,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const TOOL: &str = "attach_from_url";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    record_id: String,
    attachment_id: Option<String>,
    #[serde(rename = "id_nonce")]
    _id_nonce: Option<String>,
    url: String,
    filename: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    facets: Option<Value>,
    max_bytes: Option<u64>,
    idempotency_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyArgs {
    record_id: String,
    url: String,
    filename: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    facets: Option<Value>,
    max_bytes: Option<u64>,
    idempotency_key: Option<String>,
}

fn parse_args(args: Value) -> Result<Args> {
    if super::minted_ids_enabled() {
        return super::super::parse(TOOL, args);
    }
    let old: LegacyArgs = super::super::parse(TOOL, args)?;
    Ok(Args {
        record_id: old.record_id,
        url: old.url,
        filename: old.filename,
        name: old.name,
        lifecycle: old.lifecycle,
        facets: old.facets,
        max_bytes: old.max_bytes,
        idempotency_key: old.idempotency_key,
        attachment_id: None,
        _id_nonce: None,
    })
}

/// The fetched bytes plus the normalized metadata the commit folds in.
/// `source_url` provenance always names the requested URL; the redirect
/// chain is receipt-only (keyed receipts omit it, as on v1).
pub(crate) struct FetchedUrl {
    pub bytes: Vec<u8>,
    pub mime: String,
    pub filename: Option<String>,
    pub name: String,
    pub final_url: String,
    pub redirects: u32,
}

/// Full flow: parse, authorized preflight (with keyed replay), guarded
/// fetch with no transaction open, atomic commit. `config` is the
/// production guard in service; tests pass an explicit loopback config.
pub(crate) async fn execute(
    db: &Db,
    actor: &str,
    args: Value,
    config: &FetchConfig,
) -> Result<Value> {
    super::mint_evidence(actor, &args, "attachment_id")?;
    let parsed = parse_args(args.clone())?;
    let mut config = config.clone();
    if let Some(max_bytes) = parsed.max_bytes {
        if max_bytes == 0 || max_bytes > MAX_FETCH_BYTES {
            return Err(invalid(format!(
                "{TOOL}: 'max_bytes' must be between 1 and {MAX_FETCH_BYTES}"
            )));
        }
        config.max_bytes = max_bytes;
    }
    let key = parsed
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty());
    if key.is_some_and(|key| key.chars().count() > 200) {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    let request_json = dispatched_fingerprint(TOOL, args.clone())?;
    // Step 1 runs before any network I/O; a keyed hit returns here and the
    // fetch below never runs.
    if let Some(receipt) = preflight(db, actor, &parsed, key, &request_json).await? {
        return Ok(receipt);
    }
    // Step 2 holds no transaction: cancellation or fetch failure writes
    // nothing and leaves nothing behind.
    let fetched = fetch_url(&parsed.url, &config).await?;
    let filename = parsed
        .filename
        .clone()
        .or_else(|| filename_from_url(&fetched.final_url));
    let name = parsed
        .name
        .clone()
        .or_else(|| filename.clone())
        .unwrap_or_else(|| parsed.url.clone());
    commit(
        db,
        actor,
        &args,
        &request_json,
        FetchedUrl {
            bytes: fetched.bytes,
            mime: fetched
                .mime
                .unwrap_or_else(|| "application/octet-stream".into()),
            filename,
            name,
            final_url: fetched.final_url,
            redirects: fetched.redirects,
        },
    )
    .await
}

/// Keyed lookup shared by preflight and commit: same key plus the same
/// normalized request replays the stored receipt (after re-proving current
/// policy); same key plus a materially different request is a conflict.
/// The fold is recorded so a replay appends no duplicate fact or act, only
/// replay accounting — mirroring the write driver's keyed path.
async fn replay_in(
    db: &Db,
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    key: &str,
    request_json: &str,
) -> Result<Option<Value>> {
    kernel::mcp_write_receipts::fences::refuse_key_on(tx, actor, TOOL, key).await?;
    let old: Option<(String, String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='attach_from_url' AND operation_key=?")
        .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
    let Some((old_request, receipt_raw)) = old else {
        return Ok(None);
    };
    let old_request: Value = serde_json::from_str(&old_request)?;
    if kernel::mcp_write_receipts::stored_fingerprint(TOOL, old_request)? != request_json {
        return Err(Error::conflict(
            "idempotency_key reused for different request",
        ));
    }
    let receipt: Value = serde_json::from_str(&receipt_raw)?;
    // Replay re-proves current policy on the same snapshot: Edit on the
    // bearer, the attachment's blob still readable, Edit on the attachment,
    // View on every link target. Revocation or a move refuses here.
    let bearer = text(&receipt, "record_id")?.to_owned();
    let id = text(&receipt, "attachment_id")?.to_owned();
    kernel::kernel_require(tx, actor, &bearer, Capability::Edit).await?;
    kernel::blobs::metadata(tx, actor, &id).await?;
    kernel::kernel_require(tx, actor, &id, Capability::Edit).await?;
    for target in receipt["link_targets"].as_array().into_iter().flatten() {
        let target = target
            .as_str()
            .ok_or_else(|| invalid(format!("{TOOL}: idempotent receipt is incomplete")))?;
        kernel::kernel_require(tx, actor, target, Capability::View).await?;
    }
    let mut replay_acts = ActAllocation::new();
    kernel::mcp_write_receipts::record_on(
        db,
        tx,
        &mut replay_acts,
        kernel::mcp_write_receipts::Outcome {
            principal: actor,
            operation: TOOL,
            key,
            request: request_json,
            receipt: &receipt_raw,
        },
    )
    .await?;
    Ok(Some(receipt))
}

/// The last path segment of the final URL, as a filename hint. Mirrors the
/// v1 derivation (tools/attachments.rs `filename_from_url`).
fn filename_from_url(final_url: &str) -> Option<String> {
    let parsed = url::Url::parse(final_url).ok()?;
    let segment = parsed.path_segments()?.next_back()?.trim();
    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

/// Step 1: admit, Edit on the bearer, bearer liveness, then the keyed
/// lookup. A short write transaction serializes the lookup with committers.
/// A hit commits its replay accounting and returns the stored receipt; a
/// miss rolls back and the caller proceeds to fetch.
async fn preflight(
    db: &Db,
    actor: &str,
    parsed: &Args,
    key: Option<&str>,
    request_json: &str,
) -> Result<Option<Value>> {
    let mut tx = begin_write(db.write_pool()).await?;
    if let Some(key) = key {
        kernel::mcp_write_receipts::fences::refuse_key_on(&mut tx, actor, TOOL, key).await?;
    }
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    kernel::kernel_require(&mut tx, actor, &parsed.record_id, Capability::Edit).await?;
    if let Some(key) = key {
        // A2/v1 parity: a same-key retry replays the committed outcome even
        // if the bearer has since archived; current Edit/View authority is
        // still re-proved inside the lookup. Liveness gates new work only.
        if let Some(receipt) = replay_in(db, &mut tx, actor, key, request_json).await? {
            db.commit_kernel_content(tx).await?;
            return Ok(Some(receipt));
        }
    }
    if let Some(id) = &parsed.attachment_id {
        super::refuse_minted_occupancy(&mut tx, id).await?;
    }
    let parent = view(&mut tx, actor, &parsed.record_id).await?;
    if parent.archived {
        return Err(invalid(format!("{TOOL}: attachment target is archived")));
    }
    tx.rollback().await?;
    Ok(None)
}

/// Step 3: re-admit and re-check Edit plus liveness inside the commit
/// transaction (preflight's answer may be stale after the fetch), repeat
/// the keyed lookup, then commit blob, attachment, link, provenance, app
/// action and receipt atomically. `args` is the original request: facets
/// and lifecycle validate from it so the fingerprint covers what commits.
pub(crate) async fn commit(
    db: &Db,
    actor: &str,
    args: &Value,
    request_json: &str,
    fetched: FetchedUrl,
) -> Result<Value> {
    let mint = super::mint_evidence(actor, args, "attachment_id")?;
    let parsed = parse_args(args.clone())?;
    let key = parsed
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty());
    let mut tx = begin_write(db.write_pool()).await?;
    if let Some(key) = key {
        kernel::mcp_write_receipts::fences::refuse_key_on(&mut tx, actor, TOOL, key).await?;
    }
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    kernel::kernel_require(&mut tx, actor, &parsed.record_id, Capability::Edit).await?;
    if let Some(key) = key {
        // A same-key commit may have landed while this call was fetching —
        // or the bearer archived since the first commit: replay instead of
        // attaching twice. Liveness below gates new work only.
        if let Some(receipt) = replay_in(db, &mut tx, actor, key, request_json).await? {
            db.commit_kernel_content(tx).await?;
            return Ok(receipt);
        }
    }
    if let Some(id) = &parsed.attachment_id {
        super::refuse_minted_occupancy(&mut tx, id).await?;
    }
    let parent = view(&mut tx, actor, &parsed.record_id).await?;
    if parent.archived {
        return Err(invalid(format!("{TOOL}: attachment target is archived")));
    }
    let home = if parent.fields.get("v1_type").and_then(Value::as_str) == Some("Collection")
        && parent.fields.get("v1_kind").and_then(Value::as_str) == Some("folder")
    {
        crate::v1_import::resolve_home_on(&mut tx, actor, &parsed.record_id).await?
    } else {
        parent.home_id
    };
    if fetched.bytes.len() > MAX_FETCH_BYTES as usize {
        return Err(invalid(format!(
            "{TOOL}: fetched bytes exceed the {MAX_FETCH_BYTES} byte limit"
        )));
    }
    validate_lifecycle(args)?;
    let mut acts = ActAllocation::new();
    let request_digest = hex::encode(Sha256::digest(request_json.as_bytes()));
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        TOOL,
        request_digest,
        None,
        &mut acts,
    )
    .await?;
    let mut meta = crate::blob::new_blob_meta(
        &fetched.bytes,
        Some(&fetched.mime),
        fetched.filename.as_deref(),
    );
    meta.id = meta.sha256.clone();
    kernel::blobs::put(&mut tx, &fetched.bytes, &meta).await?;
    let fields = v1_compat::compat_fields(
        "Document",
        "attachment",
        Some(&fetched.name),
        None,
        parsed.lifecycle.as_deref(),
    );
    let raw = serde_json::to_string(&fields)?;
    let id = kernel::create_attachment_input_in(
        db,
        &mut tx,
        &mut acts,
        actor,
        &parsed.record_id,
        kernel::FieldInput::Raw(&raw),
        &home,
        parsed.attachment_id.as_deref(),
        mint,
    )
    .await?;
    // Provenance: a caller-supplied `source_url` corrects the default, as
    // on v1; otherwise the requested URL is recorded.
    let mut facet_map = match &parsed.facets {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(invalid(format!("{TOOL}: facets must be an object"))),
    };
    facet_map
        .entry("source_url")
        .or_insert(Value::String(parsed.url.clone()));
    facets(
        db,
        &mut tx,
        &mut acts,
        actor,
        &id,
        Some(&Value::Object(facet_map)),
        TOOL,
    )
    .await?;
    kernel::blobs::bind(db, &mut tx, &mut acts, actor, &id, &meta).await?;
    event(
        db,
        &mut tx,
        &mut acts,
        actor,
        &id,
        "kernel.facet_observed.v1",
        json!(kernel::FacetObservation {
            key: "blob_ref".into(),
            value: Some(meta.id.clone()),
            value_num: None,
            vocab_ref: None,
            as_of: crate::store::now_iso()
        }),
    )
    .await?;
    kernel::generic_links::add_generic_link_in(
        db,
        &mut tx,
        &mut acts,
        actor,
        &id,
        &parsed.record_id,
        "part_of",
        None,
    )
    .await?;
    let mut receipt = json!({"attachment_id": id, "record_id": parsed.record_id, "name": fetched.name,
        "blob": meta, "url": parsed.url, "link_targets": [&parsed.record_id], "act": acts.get()});
    if key.is_none() {
        // The redirect chain is receipt-only, never a facet; keyed receipts
        // omit it because it is not attested (v1 parity).
        receipt["final_url"] = json!(fetched.final_url);
        receipt["redirects"] = json!(fetched.redirects);
    }
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    if let Some(key) = key {
        let receipt_raw = serde_json::to_string(&receipt)?;
        match kernel::mcp_write_receipts::record_on(
            db,
            &mut tx,
            &mut acts,
            kernel::mcp_write_receipts::Outcome {
                principal: actor,
                operation: TOOL,
                key,
                request: request_json,
                receipt: &receipt_raw,
            },
        )
        .await
        {
            Ok(()) => {}
            Err(error) if matches!(error, Error::Conflict(_)) => {
                // Backstop: a same-key commit landed between this call's
                // lookup and its receipt record. Roll the tentative write
                // back, then replay-or-refuse from the stored outcome.
                tx.rollback().await?;
                return replay_after_conflict(db, actor, key, request_json, error).await;
            }
            Err(error) => return Err(error),
        }
    }
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}

// The conflict branch must use a fresh serialized transaction after rollback;
// a settlement may have committed while this request released its first writer.
pub(super) async fn replay_after_conflict(
    db: &Db,
    actor: &str,
    key: &str,
    request_json: &str,
    error: Error,
) -> Result<Value> {
    let mut retry = begin_write(db.write_pool()).await?;
    kernel::mcp_write_receipts::fences::refuse_key_on(&mut retry, actor, TOOL, key).await?;
    kernel::app_installs::admit_dispatched_on(&mut retry, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *retry).await?;
    let replayed = replay_in(db, &mut retry, actor, key, request_json).await?;
    db.commit_kernel_content(retry).await?;
    replayed.ok_or(error)
}
