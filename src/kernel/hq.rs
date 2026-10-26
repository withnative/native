//! HQ cutover substrate. Legacy bytes are recorded, never interpreted under v2 pins.
use super::*;
use crate::events::CausalEnvelopeV1;
use std::collections::BTreeSet;

/// UTF-8 bytes, matching v1's persisted body-block projection admission
/// (`body_blocks::MAX_PROJECTED_BODY_BYTES`). Separate from field budgets.
pub const KERNEL_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const BODIES_DDL: &str = "CREATE TABLE kernel_record_bodies (
 record_id TEXT PRIMARY KEY REFERENCES kernel_records(id), body TEXT NOT NULL,
 event_seq INTEGER NOT NULL)";

pub const HOST_IMPORT_BINDING: &str = "host:v1-import";
pub(crate) const LEGACY_IMPORT_BATCH_LIMIT: usize = 256;
pub(crate) const FACETS_DDL: &str = "CREATE TABLE kernel_facets (
 record_id TEXT NOT NULL REFERENCES kernel_records(id), key TEXT NOT NULL,
 value TEXT, value_num REAL, vocab_ref TEXT, as_of TEXT NOT NULL, event_seq INTEGER NOT NULL,
 PRIMARY KEY(record_id,key))";
pub(crate) const LIFECYCLE_DDL: &str = "CREATE TABLE kernel_lifecycle (
 record_id TEXT PRIMARY KEY REFERENCES kernel_records(id), archived INTEGER NOT NULL CHECK(archived IN (0,1)))";

pub(crate) const TOMBSTONES_DDL:&str="CREATE TABLE kernel_import_tombstones (record_id TEXT PRIMARY KEY REFERENCES kernel_records(id), deleted_at TEXT,event_seq INTEGER NOT NULL)";
pub(crate) async fn ensure_tombstones(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(&TOMBSTONES_DDL.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
        .execute(conn)
        .await?;
    Ok(())
}
pub(crate) async fn tombstoned_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_import_tombstones WHERE record_id=?)",
    )
    .bind(id)
    .fetch_one(conn)
    .await?)
}

/// Original v1 envelope. `payload` is retained without v2 interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyEvent {
    /// Source metadata and row digest, present only for full-history import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<serde_json::Value>,
    pub id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: String,
    pub actor: Option<String>,
    pub run_key: Option<String>,
}

fn legacy_actor(actor: Option<&str>) -> Option<String> {
    actor.map(|token| format!("v1:{token}"))
}

pub(super) async fn require_import(conn: &mut SqliteConnection, principal: &str) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND auth_binding=?)",
    )
    .bind(principal)
    .bind(HOST_IMPORT_BINDING)
    .fetch_one(conn)
    .await?;
    if !valid {
        return Err(Error::engine("reserved host import principal required"));
    }
    Ok(())
}

/// Live source reconciliation closes before native consent is activated.
/// Keep this separate from require_import: replay and hosted preparation still
/// need the reserved principal after source reconciliation has closed.
pub(super) async fn require_source_import_open(conn: &mut SqliteConnection) -> Result<()> {
    let closed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type IN ('kernel.hosted_membership.v1','kernel.app_installs_activated.v1'))")
        .fetch_one(conn).await?;
    if closed {
        return Err(Error::engine(
            "source import is closed after hosted activation",
        ));
    }
    Ok(())
}

pub(super) async fn refuse_message_collision(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    refuse_collision(conn, id).await
}

async fn refuse_collision(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    if id.starts_with(super::app_state::AGGREGATE_PREFIX)
        || id.starts_with(super::app_installs::PREFIX)
        || id.starts_with(super::artifact_closures::PREFIX)
        || id.starts_with("kernel:canvas:")
    {
        return Err(Error::conflict("reserved app custody aggregate namespace"));
    }
    let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=? UNION ALL SELECT 1 FROM kernel_roots WHERE root_id=? UNION ALL SELECT 1 FROM kernel_principals WHERE principal_id=?)")
        .bind(id).bind(id).bind(id).fetch_one(conn).await?;
    if used {
        return Err(Error::conflict("kernel id space collision"));
    }
    Ok(())
}

/// Selected, adopted definition and its current fields. Any installed family
/// is eligible; the import host does not choose types or kinds on its behalf.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDefinition {
    pub pin: RevisionIdentity,
    pub primary_type: String,
    pub kind: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecordState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona: Option<messaging::PersonaState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RecordMetadata>,
    pub definition: Option<ImportDefinition>,
    /// First-class record text, never charged to the definition field budget.
    #[serde(default)]
    pub body: Option<String>,
    pub facets: Vec<FacetObservation>,
    pub archived: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportSnapshot {
    home_id: String,
    owner_id: Option<String>,
    state: ImportRecordState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ImportResult {
    Created,
    Unchanged,
    Updated,
}

/// Create a preserved identity and its complete current state atomically.
/// Two events share one host-attributed act, regardless of facet count.
/// Home/owner must exist; a definition must be installed and adopted in home.
pub async fn import_record_as(
    db: &Db,
    principal: &str,
    id: &str,
    home: &str,
    owner: Option<&str>,
    state: &ImportRecordState,
) -> Result<ImportResult> {
    import_record_with_blob_as(db, principal, id, home, owner, state, None).await
}

/// Sealed snapshot import: bytes and reference commit with the record.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn import_record_with_blob_as(
    db: &Db,
    principal: &str,
    id: &str,
    home: &str,
    owner: Option<&str>,
    state: &ImportRecordState,
    blob: Option<(&[u8], &crate::blob::BlobMeta)>,
) -> Result<ImportResult> {
    import_record_snapshot_as(db, principal, id, home, owner, state, blob, false, None).await
}

/// Sealed resume: only identities already owned by this import host may advance.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume_record_with_blob_as(
    db: &Db,
    principal: &str,
    id: &str,
    home: &str,
    owner: Option<&str>,
    state: &ImportRecordState,
    blob: Option<(&[u8], &crate::blob::BlobMeta)>,
) -> Result<ImportResult> {
    import_record_snapshot_as(db, principal, id, home, owner, state, blob, true, None).await
}

/// The final observed state and its v1 tombstone commit in one host act.
pub(crate) async fn resume_record_tombstone_as(
    db: &Db,
    principal: &str,
    id: &str,
    home: &str,
    owner: Option<&str>,
    state: &ImportRecordState,
    evidence: &ImportRemovalEvidence,
) -> Result<ImportResult> {
    import_record_snapshot_as(
        db,
        principal,
        id,
        home,
        owner,
        state,
        None,
        true,
        Some(evidence),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn import_record_snapshot_as(
    db: &Db,
    principal: &str,
    id: &str,
    home: &str,
    owner: Option<&str>,
    state: &ImportRecordState,
    blob: Option<(&[u8], &crate::blob::BlobMeta)>,
    delta: bool,
    tombstone: Option<&ImportRemovalEvidence>,
) -> Result<ImportResult> {
    if id == super::workspace_metadata::RECORD_ID {
        return Err(Error::engine(
            "workspace metadata is a reserved import stream",
        ));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    if let Some(metadata) = &state.metadata {
        metadata.validate()?;
    }
    if let Some(body) = &state.body {
        validate_body(body)?;
    }
    if let Some((bytes, meta)) = blob {
        super::blobs::put(&mut tx, bytes, meta).await?;
    }
    let previous_tombstone: Option<Option<String>> =
        sqlx::query_scalar("SELECT deleted_at FROM kernel_import_tombstones WHERE record_id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if previous_tombstone.is_some() && tombstone.is_none() {
        return Err(Error::conflict(
            "source live record was previously tombstoned; identity requires review",
        ));
    }
    let same_tombstone = match (tombstone, &previous_tombstone) {
        (None, None) => true,
        (Some(e), Some(previous)) => &e.deleted_at == previous,
        _ => false,
    };
    let mut request = ImportSnapshot {
        home_id: home.into(),
        owner_id: owner.map(str::to_owned),
        state: state.clone(),
    };
    request.state.facets.sort_by(|a, b| a.key.cmp(&b.key));
    for facet in &request.state.facets {
        validate_facet(facet)?;
    }
    if request
        .state
        .facets
        .windows(2)
        .any(|p| p[0].key == p[1].key)
    {
        return Err(Error::engine("duplicate current import facet key"));
    }
    let existing: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT CASE WHEN type='kernel.import_state_delta.v1' THEN json_extract(payload,'$.snapshot') ELSE payload END,actor FROM content_events WHERE record_id=? AND type IN ('kernel.import_state.v1','kernel.import_state_delta.v1') ORDER BY seq DESC LIMIT 1")
        .bind(id).fetch_optional(&mut *tx).await?;
    let updating = existing.is_some();
    if let Some((payload, actor)) = existing {
        if request.state.message.is_some() {
            refuse_native_changes(&mut tx, id, i64::MAX).await?;
        }
        // Compare the exact serialized event payload. Reparsing JSON numbers can
        // round f64 differently; enabling float_roundtrip globally would alter v1.
        if same_tombstone
            && actor.as_deref() == Some(principal)
            && payload.as_deref()
                == Some(serde_json::to_string(&serde_json::to_value(&request)?)?.as_str())
        {
            if let Some((_, meta)) = blob {
                let existing: Option<String> = sqlx::query_scalar(
                    "SELECT metadata FROM kernel_attachment_blobs WHERE record_id=?",
                )
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
                if existing.as_deref() != Some(serde_json::to_string(meta)?.as_str()) {
                    return Err(Error::conflict("attachment import metadata differs"));
                }
            }
            tx.commit().await?;
            return Ok(ImportResult::Unchanged);
        }
        if !delta || actor.as_deref() != Some(principal) {
            return Err(Error::conflict("record import content differs"));
        }
        refuse_native_changes(&mut tx, id, i64::MAX).await?;
    } else {
        refuse_collision(&mut tx, id).await?;
    }
    let mut record = KernelRecordPayload {
        home_id: home.into(),
        owner_id: owner.map(str::to_owned),
        primary_type: None,
        kind: None,
        accession: None,
        pin: None,
        interpreter: None,
        fields: None,
        origin: None,
        basis: None,
    };
    if let Some(selection) = &state.definition {
        let pin = select_adoption_pin(
            &mut tx,
            &selection.pin.family,
            &selection.primary_type,
            &selection.kind,
            home,
        )
        .await?;
        if pin != selection.pin {
            return Err(Error::conflict(
                "import definition pin is not the adopted revision",
            ));
        }
        let artifact = crate::definition_registry::read_definition_artifact_on(
            &mut tx,
            &pin.family,
            pin.version,
            &pin.digest,
        )
        .await?
        .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
        let interpreter = interpreter_for_bytes(&artifact.bytes)?;
        // Use raw ingress for structured interpreters, as ordinary creation does.
        let raw = serde_json::to_string(&selection.fields)?;
        let fields = FieldInput::Raw(&raw).parse(
            crate::meta::definition_artifact::language_capabilities(Some(interpreter))
                .supports_structured_values,
        )?;
        let (_, identity) = validated_field_rows(
            &mut tx,
            &artifact.bytes,
            &pin.family,
            &selection.kind,
            fields.as_ref(),
        )
        .await?;
        let accession = match identity {
            IdentityOutcome::Field(_, canonical) => {
                format!("{}:{}:{canonical}", pin.family, selection.kind)
            }
            IdentityOutcome::Record => format!("{}:{}:{id}", pin.family, selection.kind),
            IdentityOutcome::Legacy => format!("{}:{}:", pin.family, selection.kind),
        };
        let fields = if crate::meta::definition_artifact::language_capabilities(Some(interpreter))
            .supports_structured_values
        {
            crate::structured_values::normalize(&serde_json::Value::Object(
                fields
                    .iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ))
            .as_object()
            .unwrap()
            .clone()
        } else {
            fields.into_owned()
        };
        record.primary_type = Some(selection.primary_type.clone());
        record.kind = Some(selection.kind.clone());
        record.accession = Some(accession);
        record.pin = Some(pin);
        record.interpreter = Some(interpreter.into());
        record.fields = Some(fields);
    }
    let mut acts = crate::act::ActAllocation::new();
    if !updating {
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: id.into(),
                event_type: if Uuid::parse_str(id).is_ok() {
                    "kernel.record_created.v1"
                } else {
                    "kernel.import_record_created.v1"
                }
                .into(),
                payload: serde_json::to_value(&record)?,
                actor: Some(principal.into()),
            },
            &mut acts,
        )
        .await?;
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.into(),
            event_type: if updating {
                "kernel.import_state_delta.v1"
            } else {
                "kernel.import_state.v1"
            }
            .into(),
            payload: if updating {
                serde_json::to_value(RecordDelta {
                    snapshot: request,
                    record,
                    tombstone: tombstone.cloned(),
                })?
            } else {
                serde_json::to_value(request)?
            },
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    if !updating {
        if let Some(evidence) = tombstone {
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: id.into(),
                    event_type: "kernel.import_removed.v1".into(),
                    payload: serde_json::to_value(ImportedRemoval {
                        kind: ImportedRemovalKind::Record,
                        evidence: evidence.clone(),
                    })?,
                    actor: Some(principal.into()),
                },
                &mut acts,
            )
            .await?;
        }
    }
    if let Some((_, meta)) = blob {
        super::blobs::bind(db, &mut tx, &mut acts, principal, id, meta).await?;
    }
    tx.commit().await?;
    Ok(if updating {
        ImportResult::Updated
    } else {
        ImportResult::Created
    })
}

/// Source-authoritative resume refuses native current-state edits, including
/// edits made before an interrupted resume. Legacy and relationship history
/// alone do not overwrite record state.
async fn refuse_native_changes(conn: &mut SqliteConnection, id: &str, before: i64) -> Result<()> {
    let changed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e WHERE record_id=? AND seq<? AND (type IN ('kernel.record_revised.v1','kernel.record_revised.v2','kernel.body_set.v1','kernel.facet_observed.v1','kernel.named_view_admitted.v1','kernel.named_view_revision_recorded.v1','kernel.named_view_binding_changed.v1','kernel.metadata_set.v1','kernel.archive_changed.v1','kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.message_state.v1') OR (type='kernel.attachment_bound.v1' AND actor!=(SELECT principal_id FROM kernel_principals WHERE auth_binding='host:v1-import'))))")
        .bind(id).bind(before).fetch_one(conn).await?;
    if changed {
        return Err(Error::conflict(
            "native record edits require delta-import review",
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDelta {
    snapshot: ImportSnapshot,
    record: KernelRecordPayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tombstone: Option<ImportRemovalEvidence>,
}

/// Monotonic source frontier prevents an older snapshot undoing a partial delta.
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ImportSourceHead {
    origin: String,
    seq: i64,
    event_id: Option<String>,
    control_seq: i64,
    control_event_id: Option<String>,
}
pub async fn import_source_head_as(
    db: &Db,
    principal: &str,
    origin: &str,
    seq: i64,
    event_id: Option<String>,
    control_seq: i64,
    control_event_id: Option<String>,
) -> Result<ImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    let head = ImportSourceHead {
        origin: origin.into(),
        seq,
        event_id,
        control_seq,
        control_event_id,
    };
    let prior:Option<String>=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_optional(&mut *tx).await?;
    if let Some(raw) = prior {
        let previous: ImportSourceHead = serde_json::from_str(&raw)?;
        validate_source_head(&previous, &head)?;
        if previous == head {
            return Ok(ImportResult::Unchanged);
        }
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: "kernel.import_source_head.v1".into(),
            payload: serde_json::to_value(head)?,
            actor: Some(principal.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(ImportResult::Created)
}
fn validate_source_head(previous: &ImportSourceHead, next: &ImportSourceHead) -> Result<()> {
    if previous.origin != next.origin
        || next.seq < previous.seq
        || (previous.seq == next.seq && previous.event_id != next.event_id)
        || next.control_seq < previous.control_seq
        || (previous.control_seq == next.control_seq
            && previous.control_event_id != next.control_event_id)
    {
        return Err(Error::conflict(
            "source snapshot is older than, or diverges from, the last attempted import",
        ));
    }
    Ok(())
}

/// Negative snapshot evidence is a host observation, not an invented v1
/// deletion author/time. A real source event is retained when available.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRemovalEvidence {
    pub source_origin: String,
    pub snapshot: String,
    pub reason: String,
    pub deleted_at: Option<String>,
    pub source_event: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedRemovalKind {
    Record,
    Attachment,
    CommentAnchor,
    InstructionBinding,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedRemoval {
    kind: ImportedRemovalKind,
    evidence: ImportRemovalEvidence,
}

/// Remove only an import-owned projection; bytes, record identity, history
/// and the negative source evidence are retained. A repeat appends nothing.
pub async fn import_removal_as(
    db: &Db,
    principal: &str,
    id: &str,
    kind: ImportedRemovalKind,
    evidence: &ImportRemovalEvidence,
) -> Result<ImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    let owned = removal_owned(&mut tx, id, kind, i64::MAX).await?;
    if !owned {
        return Err(Error::conflict("removal requires an import-owned identity"));
    }
    if kind == ImportedRemovalKind::Record {
        refuse_native_changes(&mut tx, id, i64::MAX).await?;
    }
    if kind == ImportedRemovalKind::Record && tombstoned_on(&mut tx, id).await? {
        return Ok(ImportResult::Unchanged);
    }
    let payload = serde_json::to_value(ImportedRemoval {
        kind,
        evidence: evidence.clone(),
    })?;
    let previous: Option<String>=sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.import_removed.v1' AND json_extract(payload,'$.kind')=? ORDER BY seq DESC LIMIT 1")
        .bind(id).bind(serde_json::to_value(kind)?.as_str().unwrap()).fetch_optional(&mut *tx).await?;
    // The absence is durable; a new source head does not fabricate another removal.
    let inactive: bool = match kind {
        ImportedRemovalKind::Record => tombstoned_on(&mut tx, id).await?,
        ImportedRemovalKind::Attachment => {
            sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM kernel_attachment_blobs WHERE record_id=?)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?
        }
        ImportedRemovalKind::CommentAnchor => {
            sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM kernel_comment_anchors WHERE annotation_id=?)",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?
        }
        ImportedRemovalKind::InstructionBinding => sqlx::query_scalar(
            "SELECT NOT EXISTS(SELECT 1 FROM kernel_instruction_bindings WHERE id=? AND enabled=1)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?,
    };
    if previous.is_some() && inactive {
        return Ok(ImportResult::Unchanged);
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.into(),
            event_type: "kernel.import_removed.v1".into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(ImportResult::Updated)
}
async fn removal_owned(
    conn: &mut SqliteConnection,
    id: &str,
    kind: ImportedRemovalKind,
    before: i64,
) -> Result<bool> {
    let event = match kind {
        ImportedRemovalKind::InstructionBinding => "kernel.instruction_binding_imported.v1",
        _ => "kernel.import_state.v1",
    };
    if kind == ImportedRemovalKind::CommentAnchor {
        let native:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_comment_anchors a JOIN content_events e ON e.seq=a.event_seq WHERE annotation_id=? AND e.type!='kernel.comment_anchor_imported.v1')").bind(id).fetch_one(&mut *conn).await?;
        if native {
            return Ok(false);
        }
    }
    if kind == ImportedRemovalKind::Attachment {
        let native:bool=sqlx::query_scalar("SELECT coalesce((SELECT p.auth_binding!='host:v1-import' FROM content_events e LEFT JOIN kernel_principals p ON p.principal_id=e.actor WHERE record_id=? AND type='kernel.attachment_bound.v1' ORDER BY seq DESC LIMIT 1),0)").bind(id).fetch_one(&mut *conn).await?;
        if native {
            return Ok(false);
        }
    }
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e JOIN kernel_principals p ON p.principal_id=e.actor WHERE record_id=? AND type=? AND p.auth_binding=? AND e.seq<?)")
        .bind(id).bind(event).bind(HOST_IMPORT_BINDING).bind(before).fetch_one(conn).await?)
}

async fn fold_tombstone(
    conn: &mut SqliteConnection,
    id: &str,
    evidence: &ImportRemovalEvidence,
    seq: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO kernel_import_tombstones(record_id,deleted_at,event_seq) VALUES(?,?,?) ON CONFLICT(record_id) DO UPDATE SET deleted_at=excluded.deleted_at,event_seq=excluded.event_seq").bind(id).bind(&evidence.deleted_at).bind(seq).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM kernel_attachment_blobs WHERE record_id=?")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Forensic verification is reserved to the sealed import host. Ordinary
/// callers continue to see a tombstone exactly as a missing record.
pub struct ImportedRecordSnapshot {
    pub record: KernelRecordView,
    pub facets: Vec<FacetObservation>,
    pub tombstoned: bool,
}
pub async fn read_imported_snapshot_as(
    db: &Db,
    principal: &str,
    id: &str,
) -> Result<Option<ImportedRecordSnapshot>> {
    let mut tx = db.write_pool().begin().await?;
    require_import(&mut tx, principal).await?;
    if !removal_owned(&mut tx, id, ImportedRemovalKind::Record, i64::MAX).await? {
        return Ok(None);
    }
    let viewer: String =
        sqlx::query_scalar("SELECT coalesce(owner_id,?) FROM kernel_records WHERE id=?")
            .bind(principal)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let Some(record) = read_record_unchecked_on(&mut tx, &viewer, id).await? else {
        return Ok(None);
    };
    let rows:Vec<FacetObservation>=sqlx::query_as("SELECT key,value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? AND value IS NOT NULL ORDER BY key").bind(id).fetch_all(&mut *tx).await?;
    Ok(Some(ImportedRecordSnapshot {
        record,
        facets: rows,
        tombstoned: tombstoned_on(&mut tx, id).await?,
    }))
}

/// Reconcile stored link evidence without granting the transform service
/// ordinary visibility of either sealed endpoint.
pub async fn read_imported_generic_link_as(
    db: &Db,
    principal: &str,
    link: &GenericLink,
) -> Result<Option<GenericLink>> {
    let mut tx = db.write_pool().begin().await?;
    require_import(&mut tx, principal).await?;
    Ok(sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship=? AND active=1")
        .bind(&link.source_id).bind(&link.target_id).bind(&link.relationship)
        .fetch_optional(&mut *tx).await?)
}

/// A missing roster and an explicitly empty roster are different states.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedMembersRoster {
    members: Option<BTreeSet<String>>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ImportRosterResult {
    Recorded,
    Unchanged,
    Changed {
        added: BTreeSet<String>,
        removed: BTreeSet<String>,
    },
    UntrackedTarget,
}
async fn imported_roster_on(
    conn: &mut SqliteConnection,
    before: Option<i64>,
) -> Result<Option<ImportedMembersRoster>> {
    let payload: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='kernel.import_members_roster.v1' AND (? IS NULL OR seq<?) ORDER BY seq DESC LIMIT 1")
        .bind(KERNEL_ROOT_ID).bind(before).bind(before).fetch_optional(conn).await?;
    payload
        .map(|p| serde_json::from_str(&p).map_err(Into::into))
        .transpose()
}
async fn untracked_roster_effects_on(
    conn: &mut SqliteConnection,
    before: Option<i64>,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type IN ('kernel.import_state.v1','kernel.import_home.v1','kernel.import_home_policy.v1') AND (? IS NULL OR seq<?))")
        .bind(before).bind(before).fetch_one(conn).await?)
}
/// Freeze the first supplied roster before any import policy effects. None
/// records that no roster has been supplied; it can transition to Some once.
/// Set comparison occurs under the write lock, before any event is appended.
pub async fn import_members_roster_as(
    db: &Db,
    principal: &str,
    members: Option<&BTreeSet<String>>,
) -> Result<ImportRosterResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type='kernel.hosted_membership.v1')",
    )
    .fetch_one(&mut *tx)
    .await?;
    if live {
        return Err(Error::engine(
            "cannot resume import after hosted membership activation",
        ));
    }
    if members.is_some_and(|ms| ms.iter().any(|m| m.trim().is_empty())) {
        return Err(Error::engine("roster account ids must not be empty"));
    }
    if let Some(previous) = imported_roster_on(&mut tx, None).await? {
        if let Some(frozen) = previous.members {
            if let Some(supplied) = members {
                if &frozen != supplied {
                    return Ok(ImportRosterResult::Changed {
                        added: supplied.difference(&frozen).cloned().collect(),
                        removed: frozen.difference(supplied).cloned().collect(),
                    });
                }
            }
            return Ok(ImportRosterResult::Unchanged);
        }
        if members.is_none() {
            return Ok(ImportRosterResult::Unchanged);
        }
    } else if untracked_roster_effects_on(&mut tx, None).await? {
        // Older targets cannot prove the exact roster that produced their grants.
        return Ok(ImportRosterResult::UntrackedTarget);
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: "kernel.import_members_roster.v1".into(),
            payload: serde_json::to_value(ImportedMembersRoster {
                members: members.cloned(),
            })?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(ImportRosterResult::Recorded)
}

/// Stable home identity for a legacy record. This namespace is permanent.
pub fn v1_import_home_id(record: &str) -> String {
    Uuid::new_v5(
        &Uuid::from_u128(0x6a1ae2a0329d590d89835bed02ae6715),
        record.as_bytes(),
    )
    .to_string()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedHome {
    source_record_id: String,
    home: KernelHomeCreatedPayload,
}

/// Sealed, retryable home import. The source record identity remains separate
/// from its deterministic home identity. Policies contain principal IDs only.
pub async fn import_home_as(
    db: &Db,
    principal: &str,
    id: &str,
    source_record: &str,
    parent: &str,
    owner: &str,
    entries: Option<&[(&str, &str)]>,
) -> Result<ImportResult> {
    import_home_snapshot_as(
        db,
        principal,
        id,
        source_record,
        parent,
        owner,
        entries,
        false,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resume_home_as(
    db: &Db,
    principal: &str,
    id: &str,
    source_record: &str,
    parent: &str,
    owner: &str,
    entries: Option<&[(&str, &str)]>,
) -> Result<ImportResult> {
    import_home_snapshot_as(
        db,
        principal,
        id,
        source_record,
        parent,
        owner,
        entries,
        true,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn import_home_snapshot_as(
    db: &Db,
    principal: &str,
    id: &str,
    source_record: &str,
    parent: &str,
    owner: &str,
    entries: Option<&[(&str, &str)]>,
    delta: bool,
) -> Result<ImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    if source_record == "native:root"
        || source_record.trim().is_empty()
        || id != v1_import_home_id(source_record)
    {
        return Err(Error::engine("invalid imported home mapping"));
    }
    let payload = serde_json::to_value(ImportedHome {
        source_record_id: source_record.into(),
        home: KernelHomeCreatedPayload {
            source_record_id: None,
            parent_id: parent.into(),
            owner_id: owner.into(),
            entries: entries.map(|es| {
                es.iter()
                    .map(|(s, c)| KernelHomeEntryPayload {
                        subject_id: (*s).into(),
                        capability: (*c).into(),
                    })
                    .collect()
            }),
        },
    })?;
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT payload,actor FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.import_home_delta.v1') ORDER BY seq DESC LIMIT 1")
        .bind(id).fetch_optional(&mut *tx).await?;
    let updating = existing.is_some();
    if let Some((original, actor)) = existing {
        if serde_json::from_str::<serde_json::Value>(&original)? == payload && actor == principal {
            return Ok(ImportResult::Unchanged);
        }
        if !delta || actor != principal {
            return Err(Error::conflict("home import content differs"));
        }
    } else {
        refuse_collision(&mut tx, id).await?;
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.into(),
            event_type: if updating {
                "kernel.import_home_delta.v1"
            } else {
                "kernel.import_home.v1"
            }
            .into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(if updating {
        ImportResult::Updated
    } else {
        ImportResult::Created
    })
}

/// Import-host policy replacement. Source account IDs are subjects/owners,
/// never impersonated native actors for migration setup or cleanup.
pub async fn import_home_policy_as(
    db: &Db,
    principal: &str,
    home: &str,
    entries: &[(&str, &str)],
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    let payload = serde_json::to_value(KernelPolicyReplacedPayload {
        entries: entries
            .iter()
            .map(|(subject, capability)| KernelHomeEntryPayload {
                subject_id: (*subject).into(),
                capability: (*capability).into(),
            })
            .collect(),
    })?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: home.into(),
            event_type: "kernel.import_home_policy.v1".into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Append one historical envelope and its real-time import receipt atomically.
/// Original event ids occupy the canonical content-event id namespace; a
/// identical retry is unchanged; conflicting content refuses. No v1 event
/// dispatch is performed. Raw actors live only in the legacy envelope; the
/// actor column uses a `v1:` namespace which can never be a UUID principal.
pub async fn import_event_as(
    db: &Db,
    principal: &str,
    record: &str,
    legacy: &LegacyEvent,
) -> Result<ImportResult> {
    import_event_with_facet_as(db, principal, record, legacy, None).await
}

pub async fn import_event_with_facet_as(
    db: &Db,
    principal: &str,
    record: &str,
    legacy: &LegacyEvent,
    facet: Option<&FacetObservation>,
) -> Result<ImportResult> {
    Ok(import_events_with_facets_as(db, principal, &[(record, legacy, facet)]).await?[0])
}

/// Offline bounded batch. Receipts remain native host acts and precede every
/// legacy row; historical rows retain their individual identities and order.
pub(crate) async fn import_history_batch_as(
    db: &Db,
    principal: &str,
    entries: &[(String, LegacyEvent)],
) -> Result<Vec<ImportResult>> {
    let entries: Vec<_> = entries
        .iter()
        .map(|(id, event)| (id.as_str(), event, None))
        .collect();
    import_events_with_facets_as(db, principal, &entries).await
}

async fn import_events_with_facets_as(
    db: &Db,
    principal: &str,
    entries: &[(&str, &LegacyEvent, Option<&FacetObservation>)],
) -> Result<Vec<ImportResult>> {
    if entries.len() > LEGACY_IMPORT_BATCH_LIMIT {
        return Err(Error::engine("legacy import batch exceeds 256 events"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_import(&mut tx, principal).await?;
    require_source_import_open(&mut tx).await?;
    let mut results = Vec::new();
    let mut pending = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for &(record, legacy, facet) in entries {
        if let Some(key) = &legacy.run_key {
            let collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal WHERE p.auth_binding=?)").bind(format!("mcp-run:{key}")).fetch_one(&mut *tx).await?;
            if collision {
                return Err(Error::conflict(
                    "legacy run key collides with native runtime authority",
                ));
            }
        }
        if !ids.insert(&legacy.id) {
            return Err(Error::conflict("duplicate event id in legacy batch"));
        }
        if legacy.id.trim().is_empty()
            || legacy.created_at.trim().is_empty()
            || legacy.event_type.trim().is_empty()
        {
            return Err(Error::engine("legacy event requires id, time and type"));
        }
        if let Some(facet) = facet {
            validate_facet(facet)?;
        }
        let payload = serde_json::to_string(&serde_json::json!({"legacy":legacy,"facet":facet}))?;
        let actor = legacy_actor(legacy.actor.as_deref());
        #[allow(clippy::type_complexity)]
        let existing: Option<(String, String, Option<String>, Option<String>, Option<String>, String, String)> = sqlx::query_as(
            "SELECT record_id,type,payload,actor,run_key,created_at,causal_status FROM content_events WHERE id=?")
            .bind(&legacy.id).fetch_optional(&mut *tx).await?;
        if let Some((anchor, kind, original, original_actor, run_key, created_at, status)) =
            existing
        {
            if anchor != record
                || kind != "kernel.legacy_recorded.v1"
                || original.as_deref() != Some(payload.as_str())
                || original_actor != actor
                || run_key != legacy.run_key
                || created_at != legacy.created_at
                || status != "legacy_unknown"
            {
                return Err(Error::conflict(
                    "content event id collision or import content differs",
                ));
            }
            results.push(ImportResult::Unchanged);
            continue;
        }
        // Existing canonical envelopes remain retryable before enforcing the
        // current placement contract for new imports.
        if super::app_state::private_control(legacy) {
            let custody = super::app_state::history_aggregate(legacy)?.ok_or_else(|| {
                Error::engine("app control history requires control source metadata")
            })?;
            if custody != *record
                || legacy
                    .source
                    .as_ref()
                    .and_then(|s| s["app_custody"].as_u64())
                    != Some(super::app_state::HISTORY_CUSTODY_VERSION)
                || facet.is_some()
            {
                return Err(Error::engine("app control history requires sealed custody"));
            }
            super::app_state::refuse_entity_collision(&mut tx, record).await?;
        } else {
            if record.starts_with(super::app_state::AGGREGATE_PREFIX)
                || legacy
                    .source
                    .as_ref()
                    .is_some_and(|s| s.get("app_custody").is_some())
            {
                return Err(Error::engine("reserved app history custody stream"));
            }
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?1 UNION ALL SELECT 1 FROM kernel_roots WHERE root_id=?1)")
                .bind(record).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(Error::engine(HIDDEN_OR_MISSING));
            }
        }
        pending.push(EventRow {
            local_seq: -1,
            id: legacy.id.clone(),
            record_id: record.into(),
            event_type: "kernel.legacy_recorded.v1".into(),
            payload: Some(payload),
            actor,
            run_key: legacy.run_key.clone(),
            parent_key: None,
            intent: None,
            created_at: legacy.created_at.clone(),
            causal_envelope: CausalEnvelopeV1::legacy_unknown(),
            act: None,
        });
        results.push(ImportResult::Created);
    }
    let mut acts = crate::act::ActAllocation::new();
    let subjects: Vec<_> = pending
        .iter()
        .map(|e| (e.record_id.as_str(), e.id.as_str()))
        .collect();
    crate::store::append_kernel_import_receipts_in(db, &mut tx, principal, &subjects, &mut acts)
        .await?;
    for mut event in pending {
        crate::store::append_kernel_legacy_in(&mut tx, &mut event, &mut acts).await?;
    }
    tx.commit().await?;
    Ok(results)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct FacetObservation {
    pub key: String,
    /// None means unset; Some("") remains a real value.
    pub value: Option<String>,
    #[serde(default, deserialize_with = "deserialize_facet_number")]
    pub value_num: Option<f64>,
    pub vocab_ref: Option<String>,
    pub as_of: String,
}
// All facet consumers share the additive audit envelope, including admission
// and history. Keep unknown observation members fail-closed.
pub(super) fn decode_facet_observation(mut payload: serde_json::Value) -> Result<FacetObservation> {
    if let Some(origin) = payload.as_object_mut().and_then(|p| p.remove("origin")) {
        if !origin.is_object() {
            return Err(Error::engine("invalid facet origin"));
        }
    }
    Ok(serde_json::from_value(payload)?)
}

// Rust's number parser round-trips the immutable facet number token. Scoped to
// the probe facet envelope; production v1 JSON parsing/canonicalization is unchanged.
fn deserialize_facet_number<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<f64>, D::Error> {
    let raw = Option::<Box<serde_json::value::RawValue>>::deserialize(d)?;
    raw.map(|raw| raw.get().parse::<f64>().map_err(serde::de::Error::custom))
        .transpose()
}
fn validate_new_facet(p: &FacetObservation) -> Result<()> {
    if p.key == "named_view" {
        return Err(Error::engine("named_view is reserved for engine admission"));
    }
    validate_facet(p)
}

pub(crate) fn validate_facet(p: &FacetObservation) -> Result<()> {
    if chrono::DateTime::parse_from_rfc3339(&p.as_of).is_err()
        || p.key == crate::schema::ARCHIVED_FACET_KEY
        || p.key.trim().is_empty()
        || p.as_of.trim().is_empty()
        || p.value_num.is_some_and(|v| !v.is_finite())
        || (p.value.is_none() && (p.value_num.is_some() || p.vocab_ref.is_some()))
    {
        return Err(Error::engine("invalid facet observation"));
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == "kernel.import_members_roster.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        let p: ImportedMembersRoster = event_payload(event)?;
        if event.record_id != KERNEL_ROOT_ID
            || p.members
                .as_ref()
                .is_some_and(|ms| ms.iter().any(|m| m.trim().is_empty()))
        {
            return Err(Error::engine("invalid imported members roster"));
        }
        if let Some(previous) = imported_roster_on(conn, Some(event.local_seq)).await? {
            if previous.members.is_some() || p.members.is_none() {
                return Err(Error::engine(
                    "imported members roster is immutable after first use",
                ));
            }
        } else if untracked_roster_effects_on(conn, Some(event.local_seq)).await? {
            return Err(Error::engine(
                "imported policies predate roster metadata; recreate target",
            ));
        }
        return Ok(());
    }
    if event.event_type == "kernel.import_source_head.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
        let head: ImportSourceHead = event_payload(event)?;
        let prior:Option<String>=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' AND seq<? ORDER BY seq DESC LIMIT 1").bind(event.local_seq).fetch_optional(conn).await?;
        if let Some(raw) = prior {
            validate_source_head(&serde_json::from_str(&raw)?, &head)?;
        }
        return Ok(());
    }
    if event.event_type == "kernel.import_home_delta.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
        let p: ImportedHome = event_payload(event)?;
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_home.v1' AND actor=? AND seq<?)").bind(&event.record_id).bind(&event.actor).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if !owned || event.record_id != v1_import_home_id(&p.source_record_id) {
            return Err(Error::engine("home delta requires imported mapping"));
        }
        let cycle:bool=sqlx::query_scalar("WITH RECURSIVE ancestors(id) AS (SELECT ? UNION SELECT r.parent_id FROM kernel_roots r JOIN ancestors a ON r.root_id=a.id WHERE r.parent_id IS NOT NULL) SELECT EXISTS(SELECT 1 FROM ancestors WHERE id=?)")
            .bind(&p.home.parent_id).bind(&event.record_id).fetch_one(&mut *conn).await?;
        if cycle {
            return Err(Error::engine("home delta ancestry cycle"));
        }
        sqlx::query("UPDATE kernel_roots SET parent_id=?,owner_id=? WHERE root_id=?")
            .bind(&p.home.parent_id)
            .bind(&p.home.owner_id)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        if let Some(entries) = p.home.entries {
            let mut projected = event.clone();
            projected.payload = Some(serde_json::to_string(&KernelPolicyReplacedPayload {
                entries,
            })?);
            project_kernel_home_policy_replaced(conn, &projected).await?;
        } else {
            sqlx::query("DELETE FROM kernel_policies WHERE root_id=?")
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
        }
        return Ok(());
    }
    if event.event_type == "kernel.import_home.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        let p: ImportedHome = event_payload(event)?;
        if p.source_record_id == "native:root"
            || p.source_record_id.trim().is_empty()
            || event.record_id != v1_import_home_id(&p.source_record_id)
        {
            return Err(Error::engine("invalid imported home mapping"));
        }
        let mut projected = event.clone();
        projected.payload = Some(serde_json::to_string(&p.home)?);
        return project_kernel_home_created(conn, &projected).await;
    }
    if event.event_type == "kernel.import_home_policy.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        return project_kernel_home_policy_replaced(conn, event).await;
    }
    if event.event_type == "kernel.import_record_created.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        return project_kernel_record_created(conn, event).await;
    }
    if event.event_type == "kernel.import_removed.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
        let p: ImportedRemoval = event_payload(event)?;
        if !removal_owned(conn, &event.record_id, p.kind, event.local_seq).await? {
            return Err(Error::engine("removal requires an import-owned identity"));
        }
        match p.kind {
            ImportedRemovalKind::Record => {
                refuse_native_changes(conn, &event.record_id, event.local_seq).await?;
                fold_tombstone(conn, &event.record_id, &p.evidence, event.local_seq).await?;
                // A tombstone retains all content but detaches its byte reference.
                sqlx::query("DELETE FROM kernel_attachment_blobs WHERE record_id=?")
                    .bind(&event.record_id)
                    .execute(&mut *conn)
                    .await?;
            }
            ImportedRemovalKind::Attachment => {
                sqlx::query("DELETE FROM kernel_attachment_blobs WHERE record_id=?")
                    .bind(&event.record_id)
                    .execute(&mut *conn)
                    .await?;
            }
            ImportedRemovalKind::CommentAnchor => {
                sqlx::query("DELETE FROM kernel_comment_anchors WHERE annotation_id=?")
                    .bind(&event.record_id)
                    .execute(&mut *conn)
                    .await?;
            }
            ImportedRemovalKind::InstructionBinding => {
                sqlx::query(
                    "UPDATE kernel_instruction_bindings SET enabled=0,event_seq=? WHERE id=?",
                )
                .bind(event.local_seq)
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
            }
        }
        return Ok(());
    }
    if event.event_type == "kernel.import_state_delta.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        let p: RecordDelta = event_payload(event)?;
        let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1' AND actor=? AND seq<?)")
            .bind(&event.record_id).bind(&event.actor).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if !owned {
            return Err(Error::engine(
                "delta requires an imported record owned by this host",
            ));
        }
        refuse_native_changes(conn, &event.record_id, event.local_seq).await?;
        if p.record.home_id != p.snapshot.home_id || p.record.owner_id != p.snapshot.owner_id {
            return Err(Error::engine("delta snapshot placement mismatch"));
        }
        match &p.snapshot.state.definition {
            Some(d)
                if p.record.pin.as_ref() == Some(&d.pin)
                    && p.record.primary_type.as_deref() == Some(&d.primary_type)
                    && p.record.kind.as_deref() == Some(&d.kind)
                    && p.record.fields.as_ref() == Some(&d.fields) => {}
            None if p.record.pin.is_none() && p.record.fields.is_none() => {}
            _ => return Err(Error::engine("delta snapshot definition mismatch")),
        }
        let mut projected = event.clone();
        projected.payload = Some(serde_json::to_string(&p.record)?);
        project_kernel_record_created(conn, &projected).await?;
        // A complete snapshot replaces the key set, including explicit unsets.
        sqlx::query("DELETE FROM kernel_facets WHERE record_id=?")
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM kernel_record_bodies WHERE record_id=?")
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("DELETE FROM kernel_message_people WHERE person_id=?")
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        if let Some(principal) = &p.snapshot.state.message_principal {
            sqlx::query("INSERT INTO kernel_message_people VALUES(?,?)")
                .bind(&event.record_id)
                .bind(principal)
                .execute(&mut *conn)
                .await?;
        }
        if let Some(persona) = &p.snapshot.state.persona {
            messaging::fold_persona(conn, &event.record_id, persona, event.local_seq).await?;
        }
        if let Some(message) = &p.snapshot.state.message {
            messaging::fold(conn, &event.record_id, message, event.local_seq).await?;
            super::notifications::import_history(conn, &event.record_id, message, event.local_seq)
                .await?;
        }
        if let Some(metadata) = &p.snapshot.state.metadata {
            record_metadata::fold_on(conn, &event.record_id, metadata, event.local_seq).await?;
        }
        for facet in &p.snapshot.state.facets {
            fold_facet(conn, event, facet).await?;
        }
        if let Some(body) = &p.snapshot.state.body {
            fold_body(conn, event, body).await?;
        }
        sqlx::query("UPDATE kernel_lifecycle SET archived=? WHERE record_id=?")
            .bind(p.snapshot.state.archived)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        if !p
            .snapshot
            .state
            .facets
            .iter()
            .any(|f| f.key == "blob_ref" && f.value.is_some())
        {
            sqlx::query("DELETE FROM kernel_attachment_blobs WHERE record_id=?")
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
        }
        if let Some(evidence) = &p.tombstone {
            fold_tombstone(conn, &event.record_id, evidence, event.local_seq).await?;
        }
        // Moving a terminal bearer carries the whole existing thread atomically.
        sqlx::query("WITH RECURSIVE thread(id) AS (SELECT source_id FROM kernel_generic_links WHERE target_id=? AND relationship='part_of' AND active=1 UNION SELECT l.source_id FROM kernel_generic_links l JOIN thread t ON l.target_id=t.id WHERE l.relationship='part_of' AND l.active=1) UPDATE kernel_records SET home_id=? WHERE id IN (SELECT t.id FROM thread t JOIN kernel_record_fields f ON f.record_id=t.id AND f.name='v1_type' AND f.value_json='\"Annotation\"' JOIN kernel_record_fields k ON k.record_id=t.id AND k.name='v1_kind' AND k.value_json='\"comment\"')")
            .bind(&event.record_id).bind(&p.snapshot.home_id).execute(&mut *conn).await?;
        super::search_v2::refresh_search_row(conn, &event.record_id).await?;
        return Ok(());
    }
    match event.event_type.as_str() {
        "kernel.host_import_created.v1" => {
            let p: KernelPrincipalPayload = event_payload(event)?;
            if event.actor.as_deref() != Some(KERNEL_GENESIS_ACTOR)
                || p.kind != "agent"
                || p.auth_binding != HOST_IMPORT_BINDING
            {
                return Err(Error::engine("invalid host import principal envelope"));
            }
            project_kernel_principal_payload(conn, event, p).await
        }
        "kernel.import_state.v1" => {
            require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
            let p: ImportSnapshot = event_payload(event)?;
            let creation: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type IN ('kernel.record_created.v1','kernel.import_record_created.v1') AND actor=? AND act=? AND seq<?)")
                .bind(&event.record_id).bind(&event.actor).bind(event.act).bind(event.local_seq).fetch_one(&mut *conn).await?;
            if !creation {
                return Err(Error::engine(
                    "import snapshot requires same-act record creation",
                ));
            }
            sqlx::query("DELETE FROM kernel_message_people WHERE person_id=?")
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
            if let Some(principal) = &p.state.message_principal {
                sqlx::query("INSERT INTO kernel_message_people VALUES(?,?)")
                    .bind(&event.record_id)
                    .bind(principal)
                    .execute(&mut *conn)
                    .await?;
            }
            if let Some(persona) = &p.state.persona {
                messaging::fold_persona(conn, &event.record_id, persona, event.local_seq).await?;
            }
            if let Some(message) = &p.state.message {
                messaging::fold(conn, &event.record_id, message, event.local_seq).await?;
                super::notifications::import_history(
                    conn,
                    &event.record_id,
                    message,
                    event.local_seq,
                )
                .await?;
            }
            if let Some(metadata) = &p.state.metadata {
                record_metadata::fold_on(conn, &event.record_id, metadata, event.local_seq).await?;
            }
            for facet in &p.state.facets {
                fold_facet(conn, event, facet).await?;
            }
            if let Some(body) = &p.state.body {
                fold_body(conn, event, body).await?;
            }
            sqlx::query("INSERT INTO kernel_lifecycle(record_id,archived) VALUES(?,?)")
                .bind(&event.record_id)
                .bind(p.state.archived)
                .execute(conn)
                .await?;
            Ok(())
        }
        "kernel.import_receipt.v1" => {
            require_import(conn, event.actor.as_deref().unwrap_or("")).await
        }
        "kernel.legacy_recorded.v1" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Recorded {
                legacy: LegacyEvent,
                facet: Option<FacetObservation>,
            }
            let p: Recorded = event_payload(event)?;
            let witnessed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e JOIN kernel_principals p ON p.principal_id=e.actor WHERE e.type='kernel.import_receipt.v1' AND e.record_id=? AND json_extract(e.payload,'$.legacy_event_id')=? AND e.seq<? AND e.act=? AND p.auth_binding=?)")
                .bind(&event.record_id).bind(&event.id).bind(event.local_seq).bind(event.act).bind(HOST_IMPORT_BINDING).fetch_one(&mut *conn).await?;
            if !witnessed
                || p.legacy.id != event.id
                || legacy_actor(p.legacy.actor.as_deref()) != event.actor
                || p.legacy.run_key != event.run_key
                || p.legacy.created_at != event.created_at
                || event.causal_envelope != CausalEnvelopeV1::legacy_unknown()
            {
                return Err(Error::engine("invalid legacy import envelope"));
            }
            // Older canonical envelopes remain replayable. New custody is
            // explicitly versioned; it cannot be replayed onto a public bearer.
            let marker = p
                .legacy
                .source
                .as_ref()
                .and_then(|source| source.get("app_custody"));
            if marker.is_some()
                || event
                    .record_id
                    .starts_with(super::app_state::AGGREGATE_PREFIX)
            {
                if marker.and_then(|v| v.as_u64())
                    != Some(super::app_state::HISTORY_CUSTODY_VERSION)
                    || super::app_state::history_aggregate(&p.legacy)?.as_deref()
                        != Some(event.record_id.as_str())
                    || p.facet.is_some()
                {
                    return Err(Error::engine("invalid app history custody envelope"));
                }
                super::app_state::refuse_entity_collision(conn, &event.record_id).await?;
            }
            super::legacy_history::project(conn, event, &p.legacy).await?;
            if let Some(facet) = p.facet {
                fold_facet(conn, event, &facet).await?;
            }
            Ok(())
        }
        "kernel.body_set.v1" => {
            let p: KernelBodyPayload = event_payload(event)?;
            fold_body(conn, event, &p.body).await
        }
        "kernel.facet_observed.v1" => {
            let p = decode_facet_observation(event_payload(event)?)?;
            fold_facet(conn, event, &p).await
        }
        "kernel.archive_changed.v1" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Archive {
                archived: bool,
            }
            let p: Archive = event_payload(event)?;
            sqlx::query("INSERT INTO kernel_lifecycle(record_id,archived) VALUES(?,?) ON CONFLICT(record_id) DO UPDATE SET archived=excluded.archived")
                .bind(&event.record_id).bind(p.archived).execute(conn).await?;
            Ok(())
        }
        "kernel.link_removed.v1" => {
            let p: KernelLinkPayload = event_payload(event)?;
            if p.source_id != event.record_id
                || crate::v2_standard::relates_to::reserves(&p.relationship)
            {
                return Err(Error::engine("invalid generic unlink envelope"));
            }
            sqlx::query(
                "DELETE FROM kernel_links WHERE source_id=? AND target_id=? AND relationship=?",
            )
            .bind(&p.source_id)
            .bind(&p.target_id)
            .bind(&p.relationship)
            .execute(conn)
            .await?;
            Ok(())
        }
        _ => Err(Error::engine("unknown HQ kernel event")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelBodyPayload {
    body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<serde_json::Value>,
}

fn validate_body(body: &str) -> Result<()> {
    if body.len() > KERNEL_MAX_BODY_BYTES {
        return Err(Error::engine(format!(
            "kernel body exceeds {KERNEL_MAX_BODY_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

async fn fold_body(conn: &mut SqliteConnection, event: &EventRow, body: &str) -> Result<()> {
    validate_body(body)?;
    sqlx::query("INSERT INTO kernel_record_bodies(record_id,body,event_seq) VALUES(?,?,?) ON CONFLICT(record_id) DO UPDATE SET body=excluded.body,event_seq=excluded.event_seq")
        .bind(&event.record_id).bind(body).bind(event.local_seq).execute(&mut *conn).await?;
    // S7a probe index follows the projection in the same transaction.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    super::search_v2::refresh_search_row(&mut *conn, &event.record_id).await?;
    Ok(())
}

pub(crate) async fn body_on(conn: &mut SqliteConnection, record: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT body FROM kernel_record_bodies WHERE record_id=?")
            .bind(record)
            .fetch_optional(conn)
            .await?,
    )
}

/// Whole-body replace. Empty text clears the contents but remains distinct
/// from a record that has never had a body. The record revision fences all
/// concurrent edits, including field, facet and lifecycle changes.
pub async fn set_body_as(
    db: &Db,
    principal: &str,
    record: &str,
    body: &str,
    expected_revision: i64,
) -> Result<()> {
    validate_body(body)?;
    mutation_as(
        db,
        principal,
        record,
        "kernel.body_set.v1",
        serde_json::to_value(KernelBodyPayload {
            body: body.into(),
            origin: None,
        })?,
        Some(expected_revision),
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelBodyRevision {
    pub body: String,
    pub event: KernelHistoryEvent,
}

/// Imported initial text and later native body revisions, in event sequence
/// order, with the same View/attribution rules as record history. Legacy
/// envelopes remain uninterpreted provenance, not native body revisions.
pub async fn body_history_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<Vec<KernelBodyRevision>> {
    let history =
        history_page_as(db, principal, record, None, false, usize::MAX, false, false).await?;
    let mut result = Vec::new();
    for event in history {
        if !matches!(
            event.event_type.as_str(),
            "kernel.body_set.v1" | "kernel.import_state.v1" | "kernel.import_state_delta.v1"
        ) {
            continue;
        }
        let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE seq=?")
            .bind(event.seq)
            .fetch_one(db.pool())
            .await?;
        let body = if event.event_type == "kernel.body_set.v1" {
            Some(serde_json::from_str::<KernelBodyPayload>(&payload)?.body)
        } else if event.event_type == "kernel.import_state_delta.v1" {
            serde_json::from_str::<RecordDelta>(&payload)?
                .snapshot
                .state
                .body
        } else {
            serde_json::from_str::<ImportSnapshot>(&payload)?.state.body
        };
        if let Some(body) = body {
            result.push(KernelBodyRevision { body, event });
        }
    }
    Ok(result)
}

pub(crate) fn facet_observation_wins(current: Option<&str>, incoming: &str) -> Result<bool> {
    let incoming = chrono::DateTime::parse_from_rfc3339(incoming)
        .map_err(|_| Error::engine("invalid facet as_of"))?;
    Ok(match current {
        Some(current) => {
            incoming
                >= chrono::DateTime::parse_from_rfc3339(current)
                    .map_err(|_| Error::engine("invalid stored facet as_of"))?
        }
        None => true,
    })
}

async fn fold_facet(
    conn: &mut SqliteConnection,
    event: &EventRow,
    p: &FacetObservation,
) -> Result<()> {
    validate_facet(p)?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT as_of FROM kernel_facets WHERE record_id=? AND key=?")
            .bind(&event.record_id)
            .bind(&p.key)
            .fetch_optional(&mut *conn)
            .await?;
    if !facet_observation_wins(current.as_deref(), &p.as_of)? {
        return Ok(());
    }
    // Retain unset tombstones so an older imported observation cannot resurrect
    // a removed value. as_of wins; append sequence breaks equal-time ties.
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,value_num,vocab_ref,as_of,event_seq) VALUES(?,?,?,?,?,?,?) ON CONFLICT(record_id,key) DO UPDATE SET value=excluded.value,value_num=excluded.value_num,vocab_ref=excluded.vocab_ref,as_of=excluded.as_of,event_seq=excluded.event_seq")
        .bind(&event.record_id).bind(&p.key).bind(&p.value).bind(p.value_num).bind(&p.vocab_ref).bind(&p.as_of).bind(event.local_seq).execute(conn).await?;
    Ok(())
}

/// Creation-fence exemption for `record_edit`: true exactly when the record
/// is a derived artifact whose initial bearer chain is still incomplete (its link, body, or
/// anchor landing in the admitted creation act) and the writer owns it.
/// Recorded bearer history and imported state disqualify later writes from
/// this exemption; infrastructure failures propagate as errors, never as
/// denials.
async fn creation_fence_applies(
    conn: &mut SqliteConnection,
    principal: &str,
    record: &str,
) -> Result<bool> {
    if !super::comments_v2::is_derived_on(conn, record).await? {
        return Ok(false);
    }
    if super::comments_v2::derived_terminal_on(conn, record)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let established: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE source_id=? AND relationship='part_of') OR EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1')")
        .bind(record).bind(record).fetch_one(&mut *conn).await?;
    if established {
        return Ok(false);
    }
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id = ?")
            .bind(record)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    Ok(owner.as_deref() == Some(principal))
}

pub(crate) async fn record_edit(
    conn: &mut SqliteConnection,
    principal: &str,
    record: &str,
    expected: Option<i64>,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
        .bind(record)
        .fetch_one(&mut *conn)
        .await?;
    if !exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    // A comment under construction has no bearer link yet, so derived Edit
    // cannot hold; its writer proved bearer View to open the creation, and
    // the link, body, and anchor writes below all belong to that admitted
    // act. The owner may fence those writes — every later comment write
    // derives Edit from the terminal bearer with no exemption.
    if !creation_fence_applies(conn, principal, record).await? {
        require_on(conn, principal, record, Capability::Edit).await?;
    }
    if let Some(expected) = expected {
        let head: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
                .bind(record)
                .fetch_one(conn)
                .await?;
        if head != expected {
            return Err(Error::conflict(format!(
                "record revision mismatch: expected {expected}, found {head}"
            )));
        }
    }
    Ok(())
}

async fn mutation_as(
    db: &Db,
    principal: &str,
    record: &str,
    event_type: &str,
    payload: serde_json::Value,
    expected: Option<i64>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    record_edit(&mut tx, principal, record, expected).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: record.into(),
            event_type: event_type.into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Set or unset a facet. The event log is the observation history. Latest
/// effective as_of wins, with content sequence as a deterministic tie-break.
pub async fn observe_facet_as(
    db: &Db,
    principal: &str,
    record: &str,
    observation: &FacetObservation,
    expected_revision: Option<i64>,
) -> Result<()> {
    validate_new_facet(observation)?;
    mutation_as(
        db,
        principal,
        record,
        "kernel.facet_observed.v1",
        serde_json::to_value(observation)?,
        expected_revision,
    )
    .await
}

/// Archive is a reversible lifecycle flag; it does not alter access rights.
pub async fn set_archived_as(
    db: &Db,
    principal: &str,
    record: &str,
    archived: bool,
    expected_revision: i64,
) -> Result<()> {
    mutation_as(
        db,
        principal,
        record,
        "kernel.archive_changed.v1",
        serde_json::json!({"archived": archived}),
        Some(expected_revision),
    )
    .await
}

/// Remove an ordinary directed link. Governed relates_to predicates continue
/// to use their provider port. Definition witnesses remain historical facts.
pub async fn unlink_as(
    db: &Db,
    principal: &str,
    source: &str,
    predicate: &str,
    target: &str,
    expected_revision: i64,
) -> Result<()> {
    mutation_as(
        db,
        principal,
        source,
        "kernel.link_removed.v1",
        serde_json::to_value(KernelLinkPayload {
            source_id: source.into(),
            target_id: target.into(),
            relationship: predicate.into(),
        })?,
        Some(expected_revision),
    )
    .await
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == "kernel.facet_observed.v1" {
        validate_new_facet(&decode_facet_observation(event_payload(event)?)?)?;
    }

    if event.event_type == super::deletion::EVENT {
        super::deletion::admit(conn, event).await?;
    }
    if event.event_type == "kernel.import_home_policy.v1" {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        let p: KernelPolicyReplacedPayload = event_payload(event)?;
        for entry in p.entries {
            parse_kernel_capability(&entry.capability)?;
        }
    }
    if matches!(
        event.event_type.as_str(),
        "kernel.import_home.v1" | "kernel.import_record_created.v1"
    ) {
        require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        refuse_collision(conn, &event.record_id).await?;
    }
    if matches!(
        event.event_type.as_str(),
        "kernel.facet_observed.v1"
            | "kernel.archive_changed.v1"
            | "kernel.link_removed.v1"
            | "kernel.body_set.v1"
            | "kernel.metadata_set.v1"
    ) {
        record_edit(
            conn,
            event.actor.as_deref().unwrap_or(""),
            &event.record_id,
            None,
        )
        .await?;
    }
    if event.event_type == "kernel.link_removed.v1" {
        let p: KernelLinkPayload = event_payload(event)?;
        if p.source_id != event.record_id
            || p.relationship.trim().is_empty()
            || crate::v2_standard::relates_to::reserves(&p.relationship)
        {
            return Err(Error::engine(
                "generic unlink excludes governed relates_to predicates",
            ));
        }
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_links WHERE source_id=? AND target_id=? AND relationship=?)")
            .bind(&p.source_id).bind(&p.target_id).bind(&p.relationship).fetch_one(&mut *conn).await?;
        if !exists {
            return Err(Error::conflict("link is absent"));
        }
        // Match link creation's target visibility rule, including principal targets.
        let target_record: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
                .bind(&p.target_id)
                .fetch_one(&mut *conn)
                .await?;
        if target_record {
            require_on(
                conn,
                event.actor.as_deref().unwrap_or(""),
                &p.target_id,
                Capability::View,
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn facets_as(db: &Db, principal: &str, record: &str) -> Result<Vec<FacetObservation>> {
    let mut tx = db.write_pool().begin().await?;
    kernel_require(&mut tx, principal, record, Capability::View).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, Option<String>, Option<f64>, Option<String>, String)> = sqlx::query_as("SELECT key,value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? AND value IS NOT NULL ORDER BY key")
        .bind(record).fetch_all(&mut *tx).await?;
    Ok(rows
        .into_iter()
        .map(
            |(key, value, value_num, vocab_ref, as_of)| FacetObservation {
                key,
                value,
                value_num,
                vocab_ref,
                as_of,
            },
        )
        .collect())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FacetHistoryEntry {
    pub observation: FacetObservation,
    pub event: KernelHistoryEvent,
}

pub async fn facet_history_as(
    db: &Db,
    principal: &str,
    record: &str,
    key: &str,
) -> Result<Vec<FacetHistoryEntry>> {
    // Reuse history's visibility and attribution rules. Payloads are immutable.
    let history =
        history_page_as(db, principal, record, None, false, usize::MAX, false, false).await?;
    let mut result = Vec::new();
    for event in history {
        if !matches!(
            event.event_type.as_str(),
            "kernel.facet_observed.v1"
                | "kernel.legacy_recorded.v1"
                | "kernel.import_state.v1"
                | "kernel.import_state_delta.v1"
        ) {
            continue;
        }
        let raw: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE seq=?")
            .bind(event.seq)
            .fetch_one(db.pool())
            .await?;
        if matches!(
            event.event_type.as_str(),
            "kernel.import_state.v1" | "kernel.import_state_delta.v1"
        ) {
            let raw = if event.event_type == "kernel.import_state_delta.v1" {
                let p: serde_json::Value = serde_json::from_str(&raw)?;
                serde_json::to_string(&p["snapshot"])?
            } else {
                raw
            };
            let snapshot: ImportSnapshot = serde_json::from_str(&raw)?;
            for observation in snapshot.state.facets {
                if observation.key == key {
                    result.push(FacetHistoryEntry {
                        observation,
                        event: event.clone(),
                    });
                }
            }
            continue;
        }
        let observation: Option<FacetObservation> =
            if event.event_type == "kernel.legacy_recorded.v1" {
                #[derive(Deserialize)]
                struct FacetEnvelope {
                    facet: Option<FacetObservation>,
                }
                serde_json::from_str::<FacetEnvelope>(&raw)?.facet
            } else {
                Some(decode_facet_observation(serde_json::from_str(&raw)?)?)
            };
        if let Some(observation) = observation {
            if observation.key == key {
                result.push(FacetHistoryEntry { observation, event });
            }
        }
    }
    Ok(result)
}

pub(crate) async fn archived_on(conn: &mut SqliteConnection, record: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT archived FROM kernel_lifecycle WHERE record_id=?")
            .bind(record)
            .fetch_optional(conn)
            .await?
            .unwrap_or(false),
    )
}

async fn require_on(
    conn: &mut SqliteConnection,
    principal: &str,
    record: &str,
    capability: Capability,
) -> Result<()> {
    if !kernel_effective_capability_on(conn, principal, record)
        .await?
        .allows(capability)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn world() -> (Db, String, String) {
        let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
            .await
            .unwrap();
        let import = resolve_principal_by_binding(&db, HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        (db, admin, import)
    }
    fn legacy() -> LegacyEvent {
        LegacyEvent {
            source: None,
            id: Uuid::new_v4().to_string(),
            event_type: "record.updated".into(),
            payload: serde_json::json!({"body":"original"}),
            created_at: "2020-01-02T03:04:05Z".into(),
            actor: Some("legacy:actor".into()),
            run_key: Some("legacy:run".into()),
        }
    }
    #[tokio::test]
    async fn sealed_import_preserves_envelope_and_refuses_unauthorized_and_collisions() {
        let (db, admin, import) = world().await;
        let id = Uuid::new_v4().to_string();
        assert!(import_record_as(
            &db,
            &admin,
            &id,
            KERNEL_ROOT_ID,
            Some(&admin),
            &ImportRecordState::default()
        )
        .await
        .is_err());
        import_record_as(
            &db,
            &import,
            &id,
            KERNEL_ROOT_ID,
            Some(&admin),
            &ImportRecordState::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            import_record_as(
                &db,
                &import,
                &id,
                KERNEL_ROOT_ID,
                Some(&admin),
                &ImportRecordState::default()
            )
            .await
            .unwrap(),
            ImportResult::Unchanged
        );
        assert!(import_record_as(
            &db,
            &import,
            KERNEL_ROOT_ID,
            KERNEL_ROOT_ID,
            None,
            &ImportRecordState::default()
        )
        .await
        .is_err());
        assert!(import_record_as(
            &db,
            &import,
            &admin,
            KERNEL_ROOT_ID,
            None,
            &ImportRecordState::default()
        )
        .await
        .is_err());
        let mut event = legacy();
        // Even a token equal to a real v2 principal remains a separate actor.
        event.actor = Some(admin.clone());
        assert!(import_event_as(&db, &admin, &id, &event).await.is_err());
        import_event_as(&db, &import, &id, &event).await.unwrap();
        let history = history_as(&db, &admin, &id).await.unwrap();
        let row = history.iter().find(|e| e.id == event.id).unwrap();
        assert_eq!(row.actor, legacy_actor(event.actor.as_deref()));
        assert_eq!(row.created_at, event.created_at);
        assert_eq!(row.run_key, event.run_key);
        assert_eq!(row.causal_status, "legacy_unknown");
        assert!(!history
            .iter()
            .any(|e| e.event_type == "kernel.import_receipt.v1"));
        let detailed = history_page_as(&db, &admin, &id, None, false, 100, true, true)
            .await
            .unwrap();
        assert!(detailed
            .iter()
            .any(|e| e.event_type == "kernel.import_receipt.v1"
                && e.actor.as_deref() == Some(import.as_str())
                && e.created_at > event.created_at));
        assert_eq!(
            import_event_as(&db, &import, &id, &event).await.unwrap(),
            ImportResult::Unchanged
        );
        let mut changed = event.clone();
        changed.payload = serde_json::json!({"body":"different"});
        assert!(matches!(
            import_event_as(&db, &import, &id, &changed).await,
            Err(Error::Conflict(_))
        ));
        let principal: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=?)",
        )
        .bind(row.actor.as_deref())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(!principal);
        assert_ne!(row.actor.as_deref(), Some(admin.as_str()));
        assert_eq!(history_as(&db, &admin, &id).await.unwrap(), history);
        let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
            .bind(&event.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&payload).unwrap()["legacy"],
            serde_json::to_value(&event).unwrap()
        );
        replay_all_projections(&db).await.unwrap();
        assert_eq!(history_as(&db, &admin, &id).await.unwrap(), history);
    }
    #[tokio::test]
    async fn current_state_import_uses_adopted_package_and_one_host_act() {
        use crate::package_manifest::{DefinitionEntry, PackageManifest};
        let (db, admin, import) = world().await;
        let definition = serde_json::json!({"family":"fixture.v1.workitem","version":1,"interpreter":"native.defn/5","primary_type":"WorkItem",
            "kinds":[{"token":"task","fields":[{"name":"title","type":"text","required":true},{"name":"lifecycle","type":"text","required":false}],"identity":{"mode":"record"},"links":[],"maturity":"current","description":"Import fixture."}]}).to_string();
        let digest = crate::meta::definition_artifact::digest_artifact_bytes(definition.as_bytes());
        let package = PackageManifest {
            namespace: "fixture.v1".into(),
            name: "carrier".into(),
            version: 1,
            definitions: vec![DefinitionEntry {
                family: "fixture.v1.workitem".into(),
                version: 1,
                artifact_bytes: definition,
                digest: digest.clone(),
            }],
            behaviour: None,
            surface: None,
            declared_reads: vec![],
            operations: vec![],
        };
        let installed = install_package_as(&db, &admin, &package).await.unwrap();
        adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &package, Some(&installed), &[])
            .await
            .unwrap();
        let fields = serde_json::json!({"title":"Bring over task","lifecycle":"completed"})
            .as_object()
            .unwrap()
            .clone();
        let state = ImportRecordState {
            message: None,
            persona: None,
            message_principal: None,
            metadata: None,
            definition: Some(ImportDefinition {
                pin: RevisionIdentity {
                    family: "fixture.v1.workitem".into(),
                    version: 1,
                    digest,
                },
                primary_type: "WorkItem".into(),
                kind: "task".into(),
                fields: fields.clone(),
            }),
            body: Some("Original body\né\0".repeat(100_000)),
            facets: vec![observation(Some("kept"), "2021-02-03T04:05:06Z")],
            archived: true,
        };
        let id = Uuid::new_v4().to_string();
        assert_eq!(
            import_record_as(&db, &import, &id, KERNEL_ROOT_ID, Some(&admin), &state)
                .await
                .unwrap(),
            ImportResult::Created
        );
        let view = read_record_as(&db, &admin, &id).await.unwrap().unwrap();
        assert_eq!(view.fields, fields);
        assert_eq!(view.body, state.body);
        assert!(view.body.as_ref().unwrap().len() > 1_300_000);
        assert!(!view.fields.contains_key("body"));
        assert_eq!(view.interpreter.as_deref(), Some("native.defn/5"));
        let body_history = body_history_as(&db, &admin, &id).await.unwrap();
        assert_eq!(body_history.len(), 1);
        assert_eq!(
            body_history[0].body.as_str(),
            state.body.as_deref().unwrap()
        );
        assert_eq!(
            body_history[0].event.actor.as_deref(),
            Some(import.as_str())
        );
        assert_eq!(view.kind.as_deref(), Some("task"));
        assert_eq!(
            view.pin.as_ref(),
            Some(&state.definition.as_ref().unwrap().pin)
        );
        assert_eq!(view.owner_id.as_deref(), Some(admin.as_str()));
        assert!(view.archived);
        assert_eq!(facets_as(&db, &admin, &id).await.unwrap(), state.facets);
        let observations = facet_history_as(&db, &admin, &id, "free.form")
            .await
            .unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].event.actor.as_deref(),
            Some(import.as_str())
        );
        assert_eq!(observations[0].observation.as_of, "2021-02-03T04:05:06Z");
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*),COUNT(DISTINCT act) FROM content_events WHERE record_id=? AND actor=?",
        )
        .bind(&id)
        .bind(&import)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(counts, (2, 1));
        let before = dump_all_kernel_tables(&db).await.unwrap();
        let history = history_as(&db, &admin, &id).await.unwrap();
        assert_eq!(
            import_record_as(&db, &import, &id, KERNEL_ROOT_ID, Some(&admin), &state)
                .await
                .unwrap(),
            ImportResult::Unchanged
        );
        assert_eq!(history_as(&db, &admin, &id).await.unwrap(), history);
        let mut changed_body = state.clone();
        changed_body.body = Some("different body".into());
        assert!(matches!(
            import_record_as(
                &db,
                &import,
                &id,
                KERNEL_ROOT_ID,
                Some(&admin),
                &changed_body
            )
            .await,
            Err(Error::Conflict(_))
        ));
        let mut changed = state.clone();
        changed.archived = false;
        assert!(matches!(
            import_record_as(&db, &import, &id, KERNEL_ROOT_ID, Some(&admin), &changed).await,
            Err(Error::Conflict(_))
        ));
        for bad in ["primary_type", "kind", "fields", "pin"] {
            let mut invalid = state.clone();
            let selection = invalid.definition.as_mut().unwrap();
            match bad {
                "primary_type" => selection.primary_type = "Note".into(),
                "kind" => selection.kind = "missing".into(),
                "fields" => {
                    selection
                        .fields
                        .insert("title".into(), serde_json::json!(42));
                }
                _ => selection.pin.version = 2,
            }
            assert!(import_record_as(
                &db,
                &import,
                &Uuid::new_v4().to_string(),
                KERNEL_ROOT_ID,
                Some(&admin),
                &invalid
            )
            .await
            .is_err());
        }
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), before);
        replay_all_projections(&db).await.unwrap();
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), before);
        assert_eq!(
            read_record_as(&db, &admin, &id).await.unwrap().unwrap(),
            view
        );
        // The initial import receipt remains the retry witness even after edits
        // or a later package disable. Resuming must not overwrite live edits.
        let patch = serde_json::json!({"title":"Edited after import"})
            .as_object()
            .unwrap()
            .clone();
        let revision = read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        revise_json_as_expected(
            &db,
            &admin,
            &id,
            &serde_json::to_string(&patch).unwrap(),
            Some(revision),
        )
        .await
        .unwrap();
        adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &package, None, &[])
            .await
            .unwrap();
        assert_eq!(
            import_record_as(&db, &import, &id, KERNEL_ROOT_ID, Some(&admin), &state)
                .await
                .unwrap(),
            ImportResult::Unchanged
        );
        assert_eq!(
            read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap()
                .fields["title"],
            "Edited after import"
        );
    }

    #[tokio::test]
    async fn body_revisions_require_edit_and_current_record_revision_and_replay() {
        let (db, admin, importer) = world().await;
        let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let initial = read_record_as(&db, &admin, &record).await.unwrap().unwrap();
        assert_eq!(initial.body, None);
        assert!(body_history_as(&db, &admin, &record)
            .await
            .unwrap()
            .is_empty());
        let text = "A body outside the field budget\n😀\0".repeat(4000);
        assert!(text.len() > 64 * 1024);
        set_body_as(&db, &admin, &record, &text, initial.revision)
            .await
            .unwrap();
        let written = read_record_as(&db, &admin, &record).await.unwrap().unwrap();
        assert_eq!(written.body.as_deref(), Some(text.as_str()));
        let history = body_history_as(&db, &admin, &record).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].body, text);
        assert_eq!(history[0].event.actor.as_deref(), Some(admin.as_str()));
        assert_eq!(history[0].event.event_type, "kernel.body_set.v1");
        assert!(matches!(
            set_body_as(&db, &admin, &record, "stale", initial.revision).await,
            Err(Error::Conflict(_))
        ));
        assert!(
            set_body_as(&db, &importer, &record, "forbidden", written.revision)
                .await
                .is_err()
        );
        assert!(read_record_as(&db, &importer, &record)
            .await
            .unwrap()
            .is_none());
        assert!(body_history_as(&db, &importer, &record)
            .await
            .unwrap()
            .is_empty());
        assert!(crate::store::append(
            &db,
            AppendSpec {
                record_id: record.clone(),
                event_type: "kernel.body_set.v1".into(),
                payload: serde_json::json!({"body":"forbidden raw append"}),
                actor: Some(importer),
            }
        )
        .await
        .is_err());
        let too_large = "x".repeat(KERNEL_MAX_BODY_BYTES + 1);
        assert!(
            set_body_as(&db, &admin, &record, &too_large, written.revision)
                .await
                .is_err()
        );
        assert_eq!(
            body_history_as(&db, &admin, &record).await.unwrap(),
            history
        );
        // A facet edit must also stale a body writer's record revision.
        observe_facet_as(
            &db,
            &admin,
            &record,
            &observation(Some("changed"), "2024-01-01T00:00:00Z"),
            Some(written.revision),
        )
        .await
        .unwrap();
        assert!(matches!(
            set_body_as(&db, &admin, &record, "stale after facet", written.revision).await,
            Err(Error::Conflict(_))
        ));
        let head = read_record_as(&db, &admin, &record)
            .await
            .unwrap()
            .unwrap()
            .revision;
        set_body_as(&db, &admin, &record, "", head).await.unwrap();
        assert_eq!(
            read_record_as(&db, &admin, &record)
                .await
                .unwrap()
                .unwrap()
                .body
                .as_deref(),
            Some("")
        );
        let revisions = body_history_as(&db, &admin, &record).await.unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].body, text);
        assert_eq!(revisions[1].body, "");
        let before = dump_all_kernel_tables(&db).await.unwrap();
        replay_all_projections(&db).await.unwrap();
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), before);
        assert_eq!(
            body_history_as(&db, &admin, &record).await.unwrap(),
            revisions
        );
        assert_eq!(
            list_records_as(&db, &admin).await.unwrap()[0]
                .body
                .as_deref(),
            Some("")
        );
    }

    #[tokio::test]
    async fn imported_body_limit_refuses_atomically() {
        let (db, admin, importer) = world().await;
        let record = Uuid::new_v4().to_string();
        let before = dump_all_kernel_tables(&db).await.unwrap();
        let state = ImportRecordState {
            body: Some("x".repeat(KERNEL_MAX_BODY_BYTES + 1)),
            ..Default::default()
        };
        assert!(import_record_as(
            &db,
            &importer,
            &record,
            KERNEL_ROOT_ID,
            Some(&admin),
            &state
        )
        .await
        .is_err());
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), before);
        assert!(history_as(&db, &admin, &record).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn archived_facet_refuses_in_every_facet_import_lane() {
        let (db, admin, import) = world().await;
        let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let mut facet = observation(Some("true"), "2024-01-01T00:00:00Z");
        facet.key = crate::schema::ARCHIVED_FACET_KEY.into();
        assert!(observe_facet_as(&db, &admin, &record, &facet, None)
            .await
            .is_err());
        assert!(
            import_event_with_facet_as(&db, &import, &record, &legacy(), Some(&facet))
                .await
                .is_err()
        );
        let state = ImportRecordState {
            facets: vec![facet.clone()],
            ..Default::default()
        };
        assert!(import_record_as(
            &db,
            &import,
            &Uuid::new_v4().to_string(),
            KERNEL_ROOT_ID,
            Some(&admin),
            &state
        )
        .await
        .is_err());
        assert!(crate::store::append(
            &db,
            AppendSpec {
                record_id: record.clone(),
                event_type: "kernel.facet_observed.v1".into(),
                payload: serde_json::to_value(facet).unwrap(),
                actor: Some(admin.clone())
            }
        )
        .await
        .is_err());
        assert!(facets_as(&db, &admin, &record).await.unwrap().is_empty());
    }

    fn observation(value: Option<&str>, as_of: &str) -> FacetObservation {
        FacetObservation {
            key: "free.form".into(),
            value: value.map(str::to_owned),
            value_num: value.map(|_| 42.5),
            vocab_ref: value.map(|_| "legacy:vocab".into()),
            as_of: as_of.into(),
        }
    }

    #[tokio::test]
    async fn facets_preserve_observations_and_rebuild_effective_values() {
        let (db, admin, import) = world().await;
        let id = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let first = observation(Some("new"), "2024-02-01T00:00:00Z");
        observe_facet_as(&db, &admin, &id, &first, None)
            .await
            .unwrap();
        let event = legacy();
        // This timestamp's local text sorts later but its instant is older.
        let old = observation(Some("old"), "2024-02-01T01:00:00+02:00");
        import_event_with_facet_as(&db, &import, &id, &event, Some(&old))
            .await
            .unwrap();
        assert_eq!(
            facets_as(&db, &admin, &id).await.unwrap(),
            vec![first.clone()]
        );
        let unset = observation(None, "2024-03-01T00:00:00Z");
        observe_facet_as(&db, &admin, &id, &unset, None)
            .await
            .unwrap();
        assert!(facets_as(&db, &admin, &id).await.unwrap().is_empty());
        // An old import after the tombstone must not resurrect the key.
        import_event_with_facet_as(&db, &import, &id, &legacy(), Some(&old))
            .await
            .unwrap();
        let history = facet_history_as(&db, &admin, &id, "free.form")
            .await
            .unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[1].observation, old);
        assert_eq!(history[1].event.actor, legacy_actor(event.actor.as_deref()));
        assert_eq!(history[1].event.causal_status, "legacy_unknown");
        assert_eq!(history[2].observation, unset);
        let tables = dump_all_kernel_tables(&db).await.unwrap();
        replay_all_projections(&db).await.unwrap();
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), tables);
        assert!(facets_as(&db, &admin, &id).await.unwrap().is_empty());
        assert_eq!(
            facet_history_as(&db, &admin, &id, "free.form")
                .await
                .unwrap(),
            history
        );
        // Equal instants use the later append, preserving empty text as a value.
        let restored = observation(Some(""), "2024-03-01T01:00:00+01:00");
        observe_facet_as(&db, &admin, &id, &restored, None)
            .await
            .unwrap();
        replay_all_projections(&db).await.unwrap();
        assert_eq!(facets_as(&db, &admin, &id).await.unwrap(), vec![restored]);
    }

    #[tokio::test]
    async fn archive_and_unlink_check_revisions_and_replay() {
        let (db, admin, _) = world().await;
        let source = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let target = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let head = read_record_as(&db, &admin, &source)
            .await
            .unwrap()
            .unwrap()
            .revision;
        set_archived_as(&db, &admin, &source, true, head)
            .await
            .unwrap();
        assert!(
            read_record_as(&db, &admin, &source)
                .await
                .unwrap()
                .unwrap()
                .archived
        );
        let before = history_as(&db, &admin, &source).await.unwrap();
        assert!(matches!(
            set_archived_as(&db, &admin, &source, false, head).await,
            Err(Error::Conflict(_))
        ));
        assert_eq!(history_as(&db, &admin, &source).await.unwrap(), before);
        let head = before.last().unwrap().seq;
        set_archived_as(&db, &admin, &source, false, head)
            .await
            .unwrap();
        link_as(&db, &admin, &source, "depends_on", &target)
            .await
            .unwrap();
        let head = read_record_as(&db, &admin, &source)
            .await
            .unwrap()
            .unwrap()
            .revision;
        assert!(
            unlink_as(&db, &admin, &source, "depends_on", &target, head - 1)
                .await
                .is_err()
        );
        unlink_as(&db, &admin, &source, "depends_on", &target, head)
            .await
            .unwrap();
        assert!(links_from_as(&db, &admin, &source)
            .await
            .unwrap()
            .is_empty());
        let head = read_record_as(&db, &admin, &source)
            .await
            .unwrap()
            .unwrap()
            .revision;
        assert!(unlink_as(&db, &admin, &source, "relates_to", &target, head)
            .await
            .is_err());
        link_as(&db, &admin, &source, "depends_on", &target)
            .await
            .unwrap();
        let history = history_as(&db, &admin, &source).await.unwrap();
        assert_eq!(
            history
                .iter()
                .filter(|e| e.event_type == "kernel.archive_changed.v1")
                .count(),
            2
        );
        replay_all_projections(&db).await.unwrap();
        assert!(
            !read_record_as(&db, &admin, &source)
                .await
                .unwrap()
                .unwrap()
                .archived
        );
        assert_eq!(links_from_as(&db, &admin, &source).await.unwrap().len(), 1);
        assert_eq!(history_as(&db, &admin, &source).await.unwrap(), history);
    }

    #[tokio::test]
    async fn edit_right_governs_facets_archive_and_unlink_including_raw_append() {
        let (db, admin, import) = world().await;
        let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        let target = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        link_as(&db, &admin, &record, "depends_on", &target)
            .await
            .unwrap();
        let head = read_record_as(&db, &admin, &record)
            .await
            .unwrap()
            .unwrap()
            .revision;
        let before = history_as(&db, &admin, &record).await.unwrap();
        let facet = observation(Some("no"), "2024-01-01T00:00:00Z");
        assert!(observe_facet_as(&db, &import, &record, &facet, None)
            .await
            .is_err());
        assert!(set_archived_as(&db, &import, &record, true, head)
            .await
            .is_err());
        assert!(
            unlink_as(&db, &import, &record, "depends_on", &target, head)
                .await
                .is_err()
        );
        assert!(crate::store::append(
            &db,
            AppendSpec {
                record_id: record.clone(),
                event_type: "kernel.facet_observed.v1".into(),
                payload: serde_json::to_value(&facet).unwrap(),
                actor: Some(import.clone())
            }
        )
        .await
        .is_err());
        assert!(
            create_principal(&db, "agent", "fake", HOST_IMPORT_BINDING, &admin)
                .await
                .is_err()
        );
        assert_eq!(history_as(&db, &admin, &record).await.unwrap(), before);
    }
}
