//! The workspace app shelf: which first-party apps a shared workspace offers.
//!
//! The shelf is the fold of two reserved events on the aggregate
//! `kernel:workspace-apps:<package>`; it has no table, so the v2 owned schema
//! and its generation coordinates are untouched (the membership bundles
//! precedent). Adding stages one workspace-readable Document from the release
//! catalogue under a deterministic id and records the pin. It never installs,
//! adopts or consents for anyone: member consent, folder grants and tab order
//! stay on each member's own `kernel_app_installs` row.
//!
//! Both event types are refused from generic appends
//! (`store::reject_public_runtime_event`); only the writers below emit them.
use super::*;
#[cfg(feature = "v2-kernel-probe")]
use crate::mcp::tools::catalog_assets::CatalogAssets;
use crate::mcp::tools::catalog_assets::{validate_catalog, verify_retained_payload};

pub(crate) const ADDED: &str = "kernel.workspace_app_added.v1";
pub(crate) const REMOVED_BY_WORKSPACE: &str = "kernel.workspace_app_removed.v1";
pub(crate) const SHELF_PREFIX: &str = "kernel:workspace-apps:";

pub(crate) fn shelf_aggregate(package: &str) -> String {
    format!("{SHELF_PREFIX}{package}")
}

/// Deterministic shared-source record id, so a retry creates nothing new.
fn source_id(package: &str, version: &str, digest: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        &serde_json::to_vec(&("workspace-app-source", package, version, digest))
            .expect("string tuple"),
    )
    .to_string()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Added {
    format: u32,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration_digest: String,
    added_by: String,
    key: String,
    // Retained release evidence, so replay never consults the running release.
    catalog: Value,
    entry: Value,
    payload_text: String,
    attestation: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Removed {
    format: u32,
    package: String,
    expected_shelf_event_id: String,
    removed_by: String,
}

/// One live shelf entry: the pin members will install from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShelfEntry {
    /// Id of the `workspace_app_added` event that is this entry's identity.
    pub(crate) shelf_event_id: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) digest: String,
    pub(crate) artifact_id: String,
    pub(crate) source_revision: String,
    pub(crate) declaration_digest: String,
    pub(crate) added_by: String,
    pub(crate) key: String,
    pub(crate) added_at: String,
}

impl ShelfEntry {
    /// The wire shape shared by `shelf_add` and `list`. It never names the
    /// adder: `added_by` stays inside the engine (design section 4).
    pub(crate) fn to_json(&self) -> Value {
        json!({"package":self.package,"version":self.version,"digest":self.digest,
            "artifact_id":self.artifact_id,"source_revision":self.source_revision,
            "declaration_digest":self.declaration_digest,
            "shelf_event_id":self.shelf_event_id,"added_at":self.added_at})
    }
}

/// The newest shelf event for a package and what it means.
pub(crate) enum Shelf {
    /// Latest event is an add: the app is on the shelf.
    Live(ShelfEntry),
    /// Latest event is a removal of `removed_entry`.
    Removed {
        removal_event_id: String,
        removed_entry: String,
    },
}

type Row = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

const LATEST_SQL: &str = "SELECT id,type,json_extract(payload,'$.package'),json_extract(payload,'$.version'),json_extract(payload,'$.digest'),json_extract(payload,'$.artifact_id'),json_extract(payload,'$.source_revision'),json_extract(payload,'$.declaration_digest'),json_extract(payload,'$.added_by'),json_extract(payload,'$.key'),json_extract(payload,'$.expected_shelf_event_id'),created_at FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? ORDER BY seq DESC LIMIT 1";

fn shelf_from(row: Row) -> Result<Shelf> {
    let (id, kind, package, version, digest, artifact, revision, decl, by, key, expected, at) = row;
    if kind == REMOVED_BY_WORKSPACE {
        return Ok(Shelf::Removed {
            removal_event_id: id,
            removed_entry: expected.ok_or_else(|| invalid("shelf removal without target"))?,
        });
    }
    let need = |v: Option<String>| v.ok_or_else(|| invalid("shelf entry incomplete"));
    Ok(Shelf::Live(ShelfEntry {
        shelf_event_id: id,
        package: need(package)?,
        version: need(version)?,
        digest: need(digest)?,
        artifact_id: need(artifact)?,
        source_revision: need(revision)?,
        declaration_digest: need(decl)?,
        added_by: need(by)?,
        key: need(key)?,
        added_at: at,
    }))
}

/// The shelf state of one package using events strictly before `before`.
pub(crate) async fn shelf_before(
    conn: &mut SqliteConnection,
    package: &str,
    before: i64,
) -> Result<Option<Shelf>> {
    let row: Option<Row> = sqlx::query_as(LATEST_SQL)
        .bind(shelf_aggregate(package))
        .bind(ADDED)
        .bind(REMOVED_BY_WORKSPACE)
        .bind(before)
        .fetch_optional(conn)
        .await?;
    row.map(shelf_from).transpose()
}

/// The live shelf entry for a package, if any. Slice 2 reads this to resolve
/// `install from_shelf` and to refuse a removed entry at admission.
pub(crate) async fn current_entry_on(
    conn: &mut SqliteConnection,
    package: &str,
) -> Result<Option<ShelfEntry>> {
    Ok(match shelf_before(conn, package, i64::MAX).await? {
        Some(Shelf::Live(entry)) => Some(entry),
        _ => None,
    })
}

/// Every live shelf entry, ordered by package.
pub(crate) async fn list_on(conn: &mut SqliteConnection) -> Result<Vec<ShelfEntry>> {
    let aggregates: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT record_id FROM main.content_events WHERE type=? ORDER BY record_id",
    )
    .bind(ADDED)
    .fetch_all(&mut *conn)
    .await?;
    let mut entries = Vec::new();
    for aggregate in aggregates {
        let Some(package) = aggregate.strip_prefix(SHELF_PREFIX) else {
            continue;
        };
        if let Some(entry) = current_entry_on(conn, package).await? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// The refusal for an app whose shelf entry was taken off the workspace.
pub(crate) const WORKSPACE_REMOVED: &str = "workspace_removed";

pub(crate) fn removed_error() -> Error {
    Error::engine(format!(
        "manage_alpha_tabs: this app was removed from the workspace [{WORKSPACE_REMOVED}]"
    ))
}

/// Retained evidence for a shared source: the first add that staged this
/// artifact revision. Re-adding the same pin reuses the revision, so the
/// first event is the one stable witness for replay.
pub(crate) struct VerifiedSource {
    pub(crate) seq: i64,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) declaration: Value,
    pub(crate) body: String,
}

async fn first_add_of(
    conn: &mut SqliteConnection,
    artifact: &str,
    revision: &str,
) -> Result<Option<(String, i64, String)>> {
    if revision.is_empty() {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT id,seq,payload FROM main.content_events WHERE type=? AND json_extract(payload,'$.artifact_id')=? AND json_extract(payload,'$.source_revision')=? ORDER BY seq LIMIT 1",
    )
    .bind(ADDED)
    .bind(artifact)
    .bind(revision)
    .fetch_optional(conn)
    .await?)
}

/// Whether this artifact revision is a workspace shelf source.
pub(crate) async fn is_source_on(
    conn: &mut SqliteConnection,
    artifact: &str,
    revision: &str,
) -> Result<bool> {
    Ok(first_add_of(conn, artifact, revision).await?.is_some())
}

/// Resolve a shelf source from its retained add event. The body comes from
/// the immutable body revision the add pinned, never from the shared
/// record's present state, so a later edit or archive of the shared artifact
/// changes nothing a member consented to.
pub(crate) async fn verified_source_on(
    conn: &mut SqliteConnection,
    artifact: &str,
    revision: &str,
) -> Result<Option<VerifiedSource>> {
    let Some((event_id, seq, raw)) = first_add_of(conn, artifact, revision).await? else {
        return Ok(None);
    };
    let raw: Value = serde_json::from_str(&raw)?;
    let added: Added = serde_json::from_value(raw.clone())?;
    let body: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.body') FROM main.content_events WHERE id=? AND record_id=? AND type='kernel.body_set.v1' AND seq<?")
        .bind(&added.source_revision).bind(&added.artifact_id).bind(seq).fetch_optional(&mut *conn).await?.flatten();
    let body = body.ok_or_else(|| invalid("workspace app source revision missing"))?;
    verify_retained_payload(&added.entry, added.payload_text.as_bytes(), &body)?;
    sources::verify_attestation(
        &raw,
        &added.artifact_id,
        &event_id,
        &added.source_revision,
        &body,
    )?;
    let payload: Value = serde_json::from_str(&added.payload_text)?;
    Ok(Some(VerifiedSource {
        seq,
        package: added.package,
        version: added.version,
        declaration: payload["declaration"].clone(),
        body,
    }))
}

/// A pin may be consented to only while the shelf entry for it is live. Replay
/// asks the same question of the log strictly before the event.
pub(crate) async fn require_live_pin_before_on(
    conn: &mut SqliteConnection,
    package: &str,
    artifact: &str,
    revision: &str,
    before: i64,
) -> Result<ShelfEntry> {
    match shelf_before(conn, package, before).await? {
        Some(Shelf::Live(entry))
            if entry.artifact_id == artifact && entry.source_revision == revision =>
        {
            Ok(entry)
        }
        Some(Shelf::Removed { .. }) => Err(removed_error()),
        _ => Err(invalid("pin is not on the workspace shelf")),
    }
}

/// Admission: a row that came from the shelf keeps running while the app is on
/// the shelf, whichever pin is current there (members keep the version they
/// consented to). It stops, with a typed refusal, once the app is removed.
/// Rows with no `shelf_event_id` are never affected.
pub(crate) async fn require_not_removed_on(
    conn: &mut SqliteConnection,
    row: &Value,
    package: &str,
) -> Result<()> {
    if !row["shelf_event_id"].is_string() {
        return Ok(());
    }
    match shelf_before(conn, package, i64::MAX).await? {
        Some(Shelf::Live(_)) => Ok(()),
        _ => Err(removed_error()),
    }
}

/// The install request for a live shelf entry. Everything comes from the
/// retained add event; nothing is taken from the caller.
pub(crate) async fn request_for_on(
    conn: &mut SqliteConnection,
    entry: &ShelfEntry,
) -> Result<InstallRequest> {
    let source = verified_source_on(conn, &entry.artifact_id, &entry.source_revision)
        .await?
        .ok_or_else(|| invalid("workspace app source missing"))?;
    Ok(InstallRequest {
        package: entry.package.clone(),
        version: entry.version.clone(),
        digest: entry.digest.clone(),
        artifact_id: entry.artifact_id.clone(),
        source_revision: entry.source_revision.clone(),
        declaration: source.declaration,
        reason: String::new(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: None,
    })
}

/// Writer authority. Membership is the roster's (guests are never admitted);
/// write access is exactly what ordinary record creation at the workspace
/// root requires, so view-only members refuse here too.
async fn require_shelf_writer_on(conn: &mut SqliteConnection, actor: &str) -> Result<()> {
    consent::require_member(conn, actor, i64::MAX).await?;
    require_shelf_edit_on(conn, actor).await
}

/// Root Edit against the policy as currently projected (see `project`).
async fn require_shelf_edit_on(conn: &mut SqliteConnection, actor: &str) -> Result<()> {
    kernel_require(conn, actor, crate::events::KERNEL_ROOT_ID, Capability::Edit)
        .await
        .map_err(|_| {
            Error::auth("manage_alpha_tabs: adding or removing workspace apps requires edit access")
        })
}

#[cfg(feature = "v2-kernel-probe")]
fn pin_for(assets: &CatalogAssets, package: &str) -> Result<(Value, Vec<u8>, String)> {
    let version = assets.catalog["entries"]
        .as_array()
        .and_then(|entries| entries.iter().find(|e| e["package"] == package))
        .and_then(|e| e["version"].as_str())
        .ok_or_else(|| {
            Error::engine("manage_alpha_tabs: package is not in the approved catalogue")
        })?
        .to_owned();
    assets.select(package, &version)
}

/// Add a first-party app to the workspace shelf. Idempotent by pin and by key.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn add_as(
    db: &Db,
    actor: &str,
    assets: &CatalogAssets,
    package: &str,
    key: &str,
) -> Result<Value> {
    if key.trim().is_empty() || key.len() > 200 {
        return Err(invalid(
            "shelf_add requires an idempotency_key of 1..200 bytes",
        ));
    }
    crate::mcp::tools::alpha_tabs::require_package(package)?;
    if !crate::mcp::tools::alpha_tabs::install_link::packages()
        .iter()
        .any(|allowed| allowed == package)
    {
        return Err(Error::engine(
            "manage_alpha_tabs: package is not in the approved catalogue",
        ));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_apps_open_on(&mut tx).await?;
    require_shelf_writer_on(&mut tx, actor).await?;
    let (entry, bytes, body) = pin_for(assets, package)?;
    let payload: Value = serde_json::from_slice(&bytes)?;
    if !declarations::source_supported(&payload["declaration"]) {
        return Err(invalid("catalog declaration unsupported on v2"));
    }
    let version = string(&entry, "version")?.to_owned();
    let digest = string(&entry, "digest")?.to_owned();
    let aggregate = shelf_aggregate(package);

    // A retried key never re-adds, even after a removal: a stale retry must
    // not resurrect an app somebody deliberately took off the shelf.
    let prior_key: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id,record_id,json_extract(payload,'$.version'),json_extract(payload,'$.digest') FROM main.content_events WHERE type=? AND json_extract(payload,'$.key')=? AND json_extract(payload,'$.added_by')=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(ADDED)
    .bind(key)
    .bind(actor)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((event_id, record, prior_version, prior_digest)) = prior_key {
        if record != aggregate
            || prior_version.as_deref() != Some(&version)
            || prior_digest.as_deref() != Some(&digest)
        {
            return Err(Error::conflict(
                "shelf_add idempotency key reused for a different app or version",
            ));
        }
        let entry = entry_by_event_on(&mut tx, &event_id).await?;
        tx.rollback().await?;
        return Ok(
            json!({"package":package,"changed":false,"idempotent_retry":true,"entry":entry.to_json()}),
        );
    }

    // Already on the shelf at this pin: nothing to write.
    if let Some(Shelf::Live(live)) = shelf_before(&mut tx, package, i64::MAX).await? {
        if live.version == version && live.digest == digest {
            tx.rollback().await?;
            return Ok(
                json!({"package":package,"changed":false,"idempotent_retry":true,"entry":live.to_json()}),
            );
        }
    }

    let artifact = source_id(package, &version, &digest);
    let reused: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(payload,'$.source_revision') FROM main.content_events WHERE record_id=? AND type=? AND json_extract(payload,'$.version')=? AND json_extract(payload,'$.digest')=? ORDER BY seq LIMIT 1",
    )
    .bind(&aggregate)
    .bind(ADDED)
    .bind(&version)
    .bind(&digest)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let mut acts = crate::act::ActAllocation::new();
    let event_id = Uuid::new_v4().to_string();
    let revision = match reused {
        // Re-adding the same pin revives the same source and revision, so a
        // member's earlier consent stays valid.
        Some(revision) => revision,
        None => {
            let revision = Uuid::new_v4().to_string();
            let carrier = crate::v2_standard::v1_compat::v1_carrier_for("Document", "artifact");
            let fields = crate::v2_standard::v1_compat::compat_fields(
                "Document",
                "artifact",
                entry["title"].as_str(),
                None,
                None,
            );
            let raw_fields = serde_json::to_string(&fields)?;
            // Homed at the workspace root, not account-only: every member
            // reads it. Edit on the root is re-checked by creation itself.
            create_input_admitted_in(
                db,
                &mut tx,
                &mut acts,
                actor,
                carrier.family(),
                carrier.kind(),
                FieldInput::Raw(&raw_fields),
                crate::events::KERNEL_ROOT_ID,
                None,
                true,
                Some(&artifact),
                None,
                None,
            )
            .await?;
            for (facet, value) in [("runtime", "native.html.v1"), ("app_package", "true")] {
                append_in(
                    db,
                    &mut tx,
                    AppendSpec {
                        record_id: artifact.clone(),
                        event_type: "kernel.facet_observed.v1".into(),
                        actor: Some(actor.into()),
                        payload: json!({"key":facet,"value":value,"as_of":chrono::Utc::now().to_rfc3339()}),
                    },
                    &mut acts,
                )
                .await?;
            }
            crate::store::append_with_event_id_on(
                db,
                &mut tx,
                revision.clone(),
                AppendSpec {
                    record_id: artifact.clone(),
                    event_type: "kernel.body_set.v1".into(),
                    actor: Some(actor.into()),
                    payload: json!({"body":body}),
                },
                &mut acts,
            )
            .await?;
            revision
        }
    };
    let attestation = sources::attestation(&artifact, &event_id, &revision, &body)?;
    let added = Added {
        format: 1,
        package: package.into(),
        version,
        digest,
        artifact_id: artifact,
        source_revision: revision,
        declaration_digest: string(&entry, "declaration_digest")?.to_owned(),
        added_by: actor.into(),
        key: key.into(),
        catalog: assets.catalog.clone(),
        entry,
        payload_text: String::from_utf8(bytes).map_err(|_| invalid("catalog payload encoding"))?,
        attestation,
    };
    crate::store::append_with_event_id_on(
        db,
        &mut tx,
        event_id.clone(),
        AppendSpec {
            record_id: aggregate,
            event_type: ADDED.into(),
            actor: Some(actor.into()),
            payload: serde_json::to_value(&added)?,
        },
        &mut acts,
    )
    .await?;
    let stored = entry_by_event_on(&mut tx, &event_id).await?;
    db.commit_kernel_content(tx).await?;
    Ok(json!({"package":package,"changed":true,"idempotent_retry":false,"entry":stored.to_json()}))
}

async fn entry_by_event_on(conn: &mut SqliteConnection, event_id: &str) -> Result<ShelfEntry> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT id,type,json_extract(payload,'$.package'),json_extract(payload,'$.version'),json_extract(payload,'$.digest'),json_extract(payload,'$.artifact_id'),json_extract(payload,'$.source_revision'),json_extract(payload,'$.declaration_digest'),json_extract(payload,'$.added_by'),json_extract(payload,'$.key'),json_extract(payload,'$.expected_shelf_event_id'),created_at FROM main.content_events WHERE id=? AND type=?",
    )
    .bind(event_id)
    .bind(ADDED)
    .fetch_optional(conn)
    .await?;
    match row.map(shelf_from).transpose()? {
        Some(Shelf::Live(entry)) => Ok(entry),
        _ => Err(invalid("shelf entry missing")),
    }
}

/// Take an app off the shelf for everyone. Nothing is deleted.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn remove_as(
    db: &Db,
    actor: &str,
    package: &str,
    expected_shelf_event_id: &str,
) -> Result<Value> {
    crate::mcp::tools::alpha_tabs::require_package(package)?;
    if expected_shelf_event_id.trim().is_empty() {
        return Err(invalid("shelf_remove requires expected_shelf_event_id"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_apps_open_on(&mut tx).await?;
    require_shelf_writer_on(&mut tx, actor).await?;
    match shelf_before(&mut tx, package, i64::MAX).await? {
        Some(Shelf::Live(live)) if live.shelf_event_id == expected_shelf_event_id => {}
        Some(Shelf::Removed {
            removal_event_id,
            removed_entry,
        }) if removed_entry == expected_shelf_event_id => {
            tx.rollback().await?;
            return Ok(
                json!({"package":package,"changed":false,"idempotent_retry":true,
                "removed_shelf_event_id":removed_entry,"removal_event_id":removal_event_id}),
            );
        }
        _ => {
            return Err(Error::conflict(
                "workspace shelf entry changed; list the shelf and retry",
            ))
        }
    }
    let removal = Removed {
        format: 1,
        package: package.into(),
        expected_shelf_event_id: expected_shelf_event_id.into(),
        removed_by: actor.into(),
    };
    let row = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: shelf_aggregate(package),
            event_type: REMOVED_BY_WORKSPACE.into(),
            actor: Some(actor.into()),
            payload: serde_json::to_value(&removal)?,
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    db.commit_kernel_content(tx).await?;
    Ok(
        json!({"package":package,"changed":true,"idempotent_retry":false,
        "removed_shelf_event_id":expected_shelf_event_id,"removal_event_id":row.id}),
    )
}

/// Projection and replay validation for both shelf events. Everything is
/// checked against the log strictly before the event, never today's release
/// or today's access policy.
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND payload IS ? AND actor IS ? AND act IS ?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type)
        .bind(&event.payload).bind(&event.actor).bind(event.act).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(invalid(
            "workspace shelf event is not a retained host outcome",
        ));
    }
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("shelf actor missing"))?;
    consent::require_member(conn, actor, event.local_seq).await?;
    // Writer authority at this point in history: roster and member-policy
    // template are read strictly before this event's seq (the log is fully
    // present during replay), and projected policy is in log order, so a
    // later loss of Edit or roster removal never invalidates an earlier
    // legitimate add or removal.
    if !crate::kernel::hosted_identity::capability_at_event_on(
        conn,
        actor,
        crate::events::KERNEL_ROOT_ID,
        event,
    )
    .await?
    .allows(Capability::Edit)
    {
        return Err(Error::auth(
            "manage_alpha_tabs: adding or removing workspace apps requires edit access",
        ));
    }
    if event.event_type == REMOVED_BY_WORKSPACE {
        let removal: Removed = event_payload(event)?;
        if removal.format != 1
            || removal.removed_by != actor
            || event.record_id != shelf_aggregate(&removal.package)
        {
            return Err(invalid("invalid workspace app removal"));
        }
        return match shelf_before(conn, &removal.package, event.local_seq).await? {
            Some(Shelf::Live(live)) if live.shelf_event_id == removal.expected_shelf_event_id => {
                Ok(())
            }
            _ => Err(invalid(
                "workspace app removal does not match the live shelf entry",
            )),
        };
    }
    if event.event_type != ADDED {
        return Err(invalid("unknown workspace shelf event"));
    }
    let raw: Value = event_payload(event)?;
    let added: Added = serde_json::from_value(raw.clone())?;
    crate::mcp::tools::alpha_tabs::require_package(&added.package)?;
    let entry = &added.entry;
    if added.format != 1
        || added.added_by != actor
        || added.key.trim().is_empty()
        || added.key.len() > 200
        || event.record_id != shelf_aggregate(&added.package)
        || entry["package"] != added.package
        || entry["version"] != added.version
        || entry["digest"] != added.digest
        || entry["declaration_digest"] != added.declaration_digest
        || added.artifact_id != source_id(&added.package, &added.version, &added.digest)
    {
        return Err(invalid(
            "workspace app pin does not match its catalogue entry",
        ));
    }
    validate_catalog(&added.catalog)?;
    if !added.catalog["entries"]
        .as_array()
        .is_some_and(|entries| entries.contains(entry))
    {
        return Err(invalid(
            "workspace app entry is absent from its retained catalogue",
        ));
    }
    let body: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.body') FROM content_events WHERE id=? AND record_id=? AND type='kernel.body_set.v1' AND seq<?")
        .bind(&added.source_revision).bind(&added.artifact_id).bind(event.local_seq).fetch_optional(&mut *conn).await?.flatten();
    let body = body.ok_or_else(|| invalid("workspace app source revision missing"))?;
    verify_retained_payload(entry, added.payload_text.as_bytes(), &body)?;
    sources::verify_attestation(
        &raw,
        &added.artifact_id,
        &event.id,
        &added.source_revision,
        &body,
    )?;
    // The same pin always reuses one source revision; an identical live pin is
    // never added twice.
    let earlier: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.source_revision') FROM content_events WHERE record_id=? AND type=? AND seq<? AND json_extract(payload,'$.version')=? AND json_extract(payload,'$.digest')=? ORDER BY seq LIMIT 1")
        .bind(&event.record_id).bind(ADDED).bind(event.local_seq).bind(&added.version).bind(&added.digest).fetch_optional(&mut *conn).await?.flatten();
    if earlier.is_some_and(|revision| revision != added.source_revision) {
        return Err(invalid(
            "workspace app pin was re-added with a different source",
        ));
    }
    if let Some(Shelf::Live(live)) = shelf_before(conn, &added.package, event.local_seq).await? {
        if live.version == added.version && live.digest == added.digest {
            return Err(invalid("workspace app is already on the shelf at this pin"));
        }
    }
    Ok(())
}

/// What this shelf entry means for `viewer` alone, read from the viewer's own
/// install row and nobody else's: `available` (nothing set up, or removed),
/// `installed`, `disabled`, or `needs_update` (the viewer enabled an earlier
/// pin of this app from the shelf and the shelf has moved on).
///
/// The second value is the viewer's `update` hint, present only when their own
/// live row is on another pin than the entry: `from` is `shelf` (an earlier
/// shelf pin) or `personal` (a personal install of the same package, which
/// stays `installed` and untouched until the viewer moves). `consent` is
/// `unchanged` when the declaration is the same and the row's adoption is
/// verified, so the move carries consent, folder grant and tab order without
/// a prompt; otherwise `required`, and the viewer sees the one-click consent.
/// It is advisory: projection alone decides whether consent carries.
async fn my_status_on(
    conn: &mut SqliteConnection,
    viewer: &str,
    entry: &ShelfEntry,
) -> Result<(&'static str, Option<Value>)> {
    let mine: Option<(String, String, bool, Option<String>)> = sqlx::query_as(
        "SELECT status,row_json,executable,refusal FROM main.kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(viewer)
    .bind(&entry.package)
    .fetch_optional(conn)
    .await?;
    Ok(match mine {
        None => ("available", None),
        Some((status, ..)) if status == "removed" => ("available", None),
        Some((status, ..)) if status == "disabled" => ("disabled", None),
        Some((_, raw, executable, refusal)) => {
            let row: Value = serde_json::from_str(&raw)?;
            let on_pin = row["artifact_id"] == entry.artifact_id
                && row["consented_source_revision"] == entry.source_revision;
            if on_pin {
                ("installed", None)
            } else {
                let from_shelf = row["shelf_event_id"].is_string();
                let silent = executable
                    && refusal.is_none()
                    && row["adoption"].as_str().is_some_and(verified_adoption)
                    && !row["adoption_provenance"].is_null()
                    && row["declaration_digest"] == entry.declaration_digest;
                let update = json!({
                    "from": if from_shelf { "shelf" } else { "personal" },
                    "consent": if silent { "unchanged" } else { "required" },
                    // The same candidate facts the host derives for a personal
                    // update, so it can open the ordinary review.
                    "candidate_version": entry.version,
                    "candidate_matches": false,
                    "shelf_event_id": entry.shelf_event_id,
                });
                (
                    if from_shelf {
                        "needs_update"
                    } else {
                        "installed"
                    },
                    Some(update),
                )
            }
        }
    })
}

/// A display name safe to show other members: the linked Person's title when
/// `viewer` may read that Person, else "A member". Hosted account labels are
/// generic ("Hosted member", "Imported v1 account"), so they are never shown;
/// ids and emails are refused by the shared resolver.
async fn display_name(
    conn: &mut SqliteConnection,
    viewer: &str,
    principal: &str,
    binding: &str,
) -> Result<String> {
    Ok(
        hosted_identity::visible_account_name_on(conn, viewer, principal, binding)
            .await?
            .unwrap_or_else(|| "A member".into()),
    )
}

/// The `shelf` block of `list`, for `viewer`. Names only: `who_can_add` lists
/// display names of admitted members who hold edit access to the workspace
/// root (the add/remove gate), and `added_by_name` the adder's display name.
/// No ids, bindings or emails leave the engine. Slice 2 adds per-member
/// status to the entries.
pub(crate) async fn shelf_view_on(conn: &mut SqliteConnection, viewer: &str) -> Result<Value> {
    let accounts: Vec<(String, String)> = sqlx::query_as(
        "SELECT principal_id,auth_binding FROM main.kernel_principals WHERE kind='account' ORDER BY principal_id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut who_can_add = Vec::new();
    // The viewer's own answer to "may I add or remove?": the same edit check the
    // write enforces, so a view-only member is never offered a button that refuses.
    let mut can_add = false;
    let mut names = std::collections::BTreeMap::new();
    for (principal, binding) in accounts {
        if !hosted_identity::account_admitted_before(conn, &principal, i64::MAX).await? {
            continue;
        }
        let name = display_name(conn, viewer, &principal, &binding).await?;
        if kernel_require(
            conn,
            &principal,
            crate::events::KERNEL_ROOT_ID,
            Capability::Edit,
        )
        .await
        .is_ok()
        {
            who_can_add.push(name.clone());
            if principal == viewer {
                can_add = true;
            }
        }
        names.insert(principal, name);
    }
    who_can_add.sort();
    let mut entries = Vec::new();
    for entry in list_on(conn).await? {
        let mut value = entry.to_json();
        if let Some(name) = names.get(&entry.added_by) {
            value["added_by_name"] = json!(name);
        }
        value["added_by_me"] = json!(entry.added_by == viewer);
        let (status, update) = my_status_on(conn, viewer, &entry).await?;
        value["my_status"] = json!(status);
        if let Some(update) = update {
            value["update"] = update;
        }
        entries.push(value);
    }
    Ok(json!({"supported":true,"can_add":can_add,"who_can_add":who_can_add,"entries":entries}))
}
