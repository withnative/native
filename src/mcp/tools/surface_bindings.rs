//! `manage_surface_bindings` — the MCP family over the general K3 binding
//! resolver (`src/surface_binding.rs`, design `6e2acbd` §3.4, task `441844b`).
//!
//! A binding points a surface at one artifact. Storage is the reserved
//! `surface_binding` link relationship (see `crate::surface_binding`): one edge
//! from the binding's `who` record — a member's person record, or `native:root`
//! for the workspace default — to the bound artifact. The surface, subject, and
//! mode travel in the link note as `native.surface-binding.v1`.
//!
//! This deliberately does not overload `manage_renderer_binding`: binding a
//! surface to a subject is a different thing from binding governed data to a
//! port. The shape follows that precedent — validated on write, authority
//! checked on read, with an explicit path when the target is missing or the
//! viewer has lost access.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::act::ActAllocation;
use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{LinkAddedPayload, LinkRemovedPayload};
use crate::generated::kinds::CoreKind;
use crate::store::{append_in, AppendSpec};
use crate::surface_binding::{
    Mode, SubjectPattern, Surface, SurfaceBinding, SurfaceRequest, TargetStatus, Who,
    SURFACE_BINDING_NOTE_VERSION, SURFACE_BINDING_RELATIONSHIP,
};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    echo_act, parse_args, previous_record_seq_in, require_record_in, ACT_DESCRIPTION,
    PREVIOUS_SEQ_DESCRIPTION,
};

const TOOL: &str = "manage_surface_bindings";

/// The workspace root record. It is the `who` record for the workspace default.
const WORKSPACE_ROOT: &str = "native:root";

/// The one surface registered in this slice.
const SURFACE_HOME: &str = "home";

/// The one subject exercised in this slice.
const SUBJECT_ENVIRONMENT: &str = "environment";

/// Arguments accepted by `manage_surface_bindings`.
///
/// `subject` is carried and defaults to `environment`; only `environment` is
/// accepted in this slice. `scope` selects the `who`: `personal` (the caller's
/// own person record) or `workspace` (`native:root`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub enum ManageSurfaceBindingsArgs {
    List {
        surface: String,
    },
    Get {
        surface: String,
        #[serde(default)]
        subject: Option<String>,
    },
    Set {
        surface: String,
        scope: String,
        target_id: String,
        #[serde(default)]
        subject: Option<String>,
        #[serde(default)]
        mode: Option<String>,
        #[serde(default)]
        expected_target_id: Option<String>,
    },
    Reset {
        surface: String,
        scope: String,
        #[serde(default)]
        subject: Option<String>,
        #[serde(default)]
        expected_target_id: Option<String>,
    },
}

/// The link-note descriptor. Unknown fields are tolerated on read so the K1
/// consent fields can be added later without invalidating existing notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingDescriptor {
    pub v: String,
    pub surface: String,
    pub subject: DescriptorSubject,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorSubject {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

fn parse_surface(surface: &str) -> Result<Surface> {
    match surface {
        SURFACE_HOME => Ok(Surface::Home),
        other => Err(Error::engine(format!(
            "{TOOL}: unknown surface '{other}'; the registered surfaces are ['home']"
        ))),
    }
}

fn surface_name(surface: Surface) -> &'static str {
    match surface {
        Surface::Home => SURFACE_HOME,
    }
}

/// Parse the subject argument. Only `environment` is accepted in this slice.
fn parse_subject(subject: Option<&str>) -> Result<SubjectPattern> {
    match subject.unwrap_or(SUBJECT_ENVIRONMENT) {
        SUBJECT_ENVIRONMENT => Ok(SubjectPattern::Environment),
        other => Err(Error::engine(format!(
            "{TOOL}: subject '{other}' is not resolvable in this slice; only 'environment' is accepted"
        ))),
    }
}

fn parse_mode(mode: Option<&str>) -> Result<Mode> {
    match mode.unwrap_or("isolated") {
        "isolated" => Ok(Mode::Isolated),
        "trusted" => Err(Error::engine(format!(
            "{TOOL}: mode 'trusted' is not exercised in this slice; only 'isolated' is accepted"
        ))),
        other => Err(Error::engine(format!(
            "{TOOL}: unknown mode '{other}'; expected 'isolated'"
        ))),
    }
}

fn descriptor(surface: Surface, subject: &SubjectPattern, mode: Mode) -> BindingDescriptor {
    BindingDescriptor {
        v: SURFACE_BINDING_NOTE_VERSION.into(),
        surface: surface_name(surface).into(),
        subject: match subject {
            SubjectPattern::Environment => DescriptorSubject {
                kind: SUBJECT_ENVIRONMENT.into(),
                value: None,
            },
            SubjectPattern::Slot(value) => DescriptorSubject {
                kind: "slot".into(),
                value: Some(value.clone()),
            },
            SubjectPattern::Kind(value) => DescriptorSubject {
                kind: "kind".into(),
                value: Some(value.clone()),
            },
            SubjectPattern::Collection(value) => DescriptorSubject {
                kind: "collection".into(),
                value: Some(value.clone()),
            },
            SubjectPattern::Record(value) => DescriptorSubject {
                kind: "record".into(),
                value: Some(value.clone()),
            },
        },
        mode: match mode {
            Mode::Isolated => "isolated".into(),
            Mode::Trusted => "trusted".into(),
        },
    }
}

/// Decode a link note into a descriptor, or `None` when it is not a valid
/// surface-binding descriptor. A note that does not parse is ignored rather
/// than treated as a binding: `manage_links` remains open, so `read` reports
/// invalid graph states explicitly instead of trusting them.
fn decode_descriptor(note: Option<&str>) -> Option<BindingDescriptor> {
    let descriptor: BindingDescriptor = serde_json::from_str(note?).ok()?;
    if descriptor.v != SURFACE_BINDING_NOTE_VERSION {
        return None;
    }
    if descriptor.surface != SURFACE_HOME {
        return None;
    }
    let ok_subject = match descriptor.subject.kind.as_str() {
        SUBJECT_ENVIRONMENT => descriptor.subject.value.is_none(),
        "slot" | "kind" | "collection" | "record" => descriptor.subject.value.is_some(),
        _ => false,
    };
    if !ok_subject {
        return None;
    }
    // `trusted` is carried in the vocabulary but not exercised in this slice;
    // a note carrying it is still a well-formed binding and is read back.
    if !matches!(descriptor.mode.as_str(), "isolated" | "trusted") {
        return None;
    }
    Some(descriptor)
}

fn descriptor_subject(descriptor: &BindingDescriptor) -> Option<SubjectPattern> {
    let value = descriptor.subject.value.clone();
    match descriptor.subject.kind.as_str() {
        SUBJECT_ENVIRONMENT => Some(SubjectPattern::Environment),
        "slot" => value.map(SubjectPattern::Slot),
        "kind" => value.map(SubjectPattern::Kind),
        "collection" => value.map(SubjectPattern::Collection),
        "record" => value.map(SubjectPattern::Record),
        _ => None,
    }
}

/// The target's live record type and kind value identity, or `None` when the
/// record is absent or tombstoned.
async fn artifact_status_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    target: &str,
) -> Result<TargetStatus> {
    let predicate = CoreKind::DocumentArtifact.sql_matches("r");
    let row = sqlx::query(&format!(
        "SELECT r.deleted_at, \
                EXISTS (SELECT 1 FROM facet_values av WHERE av.record_id = r.id AND av.key = ?) AS archived, \
                {predicate} AS is_artifact \
         FROM records r WHERE r.id = ?"
    ))
    .bind(crate::schema::ARCHIVED_FACET_KEY)
    .bind(target)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(TargetStatus::Missing);
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(TargetStatus::Missing);
    }
    if row.try_get::<i64, _>("is_artifact")? == 0 {
        return Ok(TargetStatus::WrongRecordType);
    }
    if row.try_get::<i64, _>("archived")? != 0 {
        return Ok(TargetStatus::Archived);
    }
    Ok(TargetStatus::Resolvable)
}

/// One stored edge read from `links`.
struct StoredLink {
    link_id: String,
    target_id: String,
    note: Option<String>,
}

async fn links_for_source(db: &Db, source_id: &str) -> Result<Vec<StoredLink>> {
    let rows = sqlx::query(
        "SELECT id, target_id, note FROM links \
         WHERE source_id = ? AND relationship = ? ORDER BY target_id",
    )
    .bind(source_id)
    .bind(SURFACE_BINDING_RELATIONSHIP)
    .fetch_all(db.write_pool())
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| StoredLink {
            link_id: row.try_get("id").unwrap_or_default(),
            target_id: row.try_get("target_id").unwrap_or_default(),
            note: row.try_get("note").ok().flatten(),
        })
        .collect())
}

/// The person record bound to the caller's credential, if any. Pool form of
/// `crate::attribution::caller_person_in`, so reads do not take the write lock.
async fn caller_person_pool(db: &Db, credential: &str) -> Result<Option<String>> {
    let predicate = CoreKind::EntityPerson.sql_matches("r");
    Ok(sqlx::query_scalar(&format!(
        "SELECT r.id FROM bindings b JOIN records r ON r.id = b.record_id \
         WHERE b.system = 'account' AND b.identifier = ? AND b.is_canonical = 1 \
           AND r.deleted_at IS NULL AND {predicate} \
         ORDER BY r.id LIMIT 1"
    ))
    .bind(credential)
    .fetch_optional(db.write_pool())
    .await?)
}

async fn artifact_status_pool(db: &Db, target: &str) -> Result<TargetStatus> {
    let predicate = CoreKind::DocumentArtifact.sql_matches("r");
    let row = sqlx::query(&format!(
        "SELECT r.deleted_at, \
                EXISTS (SELECT 1 FROM facet_values av WHERE av.record_id = r.id AND av.key = ?) AS archived, \
                {predicate} AS is_artifact \
         FROM records r WHERE r.id = ?"
    ))
    .bind(crate::schema::ARCHIVED_FACET_KEY)
    .bind(target)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(row) = row else {
        return Ok(TargetStatus::Missing);
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(TargetStatus::Missing);
    }
    if row.try_get::<i64, _>("is_artifact")? == 0 {
        return Ok(TargetStatus::WrongRecordType);
    }
    if row.try_get::<i64, _>("archived")? != 0 {
        return Ok(TargetStatus::Archived);
    }
    Ok(TargetStatus::Resolvable)
}

/// Which `who` a `set`/`reset` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Personal,
    Workspace,
}

impl Scope {
    fn parse(scope: &str) -> Result<Self> {
        match scope {
            "personal" => Ok(Scope::Personal),
            "workspace" => Ok(Scope::Workspace),
            "group" => Err(Error::engine(format!(
                "{TOOL}: scope 'group' is carried but not resolved in this slice"
            ))),
            other => Err(Error::engine(format!(
                "{TOOL}: unknown scope '{other}'; expected 'personal' or 'workspace'"
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Scope::Personal => "personal",
            Scope::Workspace => "workspace",
        }
    }

    /// The capability required on the binding's source record. A personal
    /// override is the member's own; the workspace default changes what
    /// everyone sees, so it requires Manage on the workspace root.
    fn required_capability(self) -> Capability {
        match self {
            Scope::Personal => Capability::Edit,
            Scope::Workspace => Capability::Manage,
        }
    }
}

/// The source record a scope writes to.
async fn scope_source_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    scope: Scope,
) -> Result<String> {
    match scope {
        Scope::Workspace => Ok(WORKSPACE_ROOT.into()),
        Scope::Personal => crate::attribution::caller_person_in(tx, caller.credential())
            .await?
            .ok_or_else(|| {
                Error::engine(format!(
                    "{TOOL}: no person record is bound to this caller, so there is no personal scope"
                ))
            }),
    }
}

/// Every live environment binding on a source record, in target order.
///
/// More than one is an ambiguous generic-link state. `set` refuses it, but
/// `reset` clears all of them, so a duplicate edge forged before this slice —
/// or written by hand — stays repairable through the tool.
async fn environment_bindings_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT id, target_id, note FROM links \
         WHERE source_id = ? AND relationship = ? ORDER BY target_id",
    )
    .bind(source_id)
    .bind(SURFACE_BINDING_RELATIONSHIP)
    .fetch_all(&mut **tx)
    .await?;
    let mut found: Vec<(String, String)> = Vec::new();
    for row in rows {
        let note: Option<String> = row.try_get("note")?;
        let Some(descriptor) = decode_descriptor(note.as_deref()) else {
            continue;
        };
        if descriptor_subject(&descriptor) == Some(SubjectPattern::Environment) {
            found.push((row.try_get("id")?, row.try_get("target_id")?));
        }
    }
    Ok(found)
}

/// The one current environment binding, or an ambiguity error. Used by `set`,
/// which must not silently choose among duplicates.
async fn environment_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    source_id: &str,
) -> Result<Option<(String, String)>> {
    let mut found = environment_bindings_in(tx, source_id).await?;
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(Error::engine(format!(
            "{TOOL}: source {source_id} has ambiguous surface bindings; reset it to clear the duplicate edges"
        ))),
    }
}

fn target_status_name(status: TargetStatus) -> &'static str {
    status
        .skip_reason()
        .map(skip_reason_name)
        .unwrap_or("resolvable")
}

/// Every surface binding stored against one `who` record, with its target
/// status computed for this caller.
async fn bindings_for_who(
    db: &Db,
    caller: &Caller,
    source_id: &str,
    who: Who,
) -> Result<Vec<(String, BindingDescriptor, SurfaceBinding)>> {
    let mut out = Vec::new();
    for link in links_for_source(db, source_id).await? {
        let Some(descriptor) = decode_descriptor(link.note.as_deref()) else {
            // `manage_links` stays open, so a `surface_binding` edge can be
            // written by hand. An undecodable note is ignored rather than
            // trusted; it is not a binding.
            continue;
        };
        let Some(subject) = descriptor_subject(&descriptor) else {
            continue;
        };
        let mode = if descriptor.mode == "trusted" {
            Mode::Trusted
        } else {
            Mode::Isolated
        };
        let mut status = artifact_status_pool(db, &link.target_id).await?;
        if status.is_resolvable()
            && !super::can_record(db, caller, &link.target_id, Capability::View).await?
        {
            status = TargetStatus::Unauthorized;
        }
        out.push((
            link.link_id.clone(),
            descriptor,
            SurfaceBinding {
                binding_id: link.link_id,
                who,
                subject,
                surface: Surface::Home,
                mode,
                target: Some(link.target_id),
                status,
            },
        ));
    }
    Ok(out)
}

fn source_name(source: crate::surface_binding::BindingSource) -> &'static str {
    use crate::surface_binding::BindingSource;
    match source {
        BindingSource::Principal => "personal",
        BindingSource::Group => "group",
        BindingSource::Workspace => "workspace",
        BindingSource::AppFallback => "app_fallback",
    }
}

fn who_name(who: Who) -> &'static str {
    match who {
        Who::Principal => "principal",
        Who::Group => "group",
        Who::Workspace => "workspace",
    }
}

fn subject_json(subject: &SubjectPattern) -> Value {
    match subject {
        SubjectPattern::Environment => json!({ "kind": "environment" }),
        SubjectPattern::Slot(value) => json!({ "kind": "slot", "value": value }),
        SubjectPattern::Kind(value) => json!({ "kind": "kind", "value": value }),
        SubjectPattern::Collection(value) => json!({ "kind": "collection", "value": value }),
        SubjectPattern::Record(value) => json!({ "kind": "record", "value": value }),
    }
}

fn skip_reason_name(reason: crate::surface_binding::SkipReason) -> &'static str {
    use crate::surface_binding::SkipReason;
    match reason {
        SkipReason::Unbound => "unbound",
        SkipReason::Missing => "missing",
        SkipReason::Archived => "archived",
        SkipReason::Unauthorized => "unauthorized",
        SkipReason::WrongRecordType => "wrong_record_type",
        SkipReason::NotRenderable => "not_renderable",
        SkipReason::TrustedModeUnsupported => "trusted_mode_unsupported",
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Isolated => "isolated",
        Mode::Trusted => "trusted",
    }
}

fn binding_json(binding: &SurfaceBinding) -> Value {
    let status = if binding.status.is_resolvable() {
        "resolvable"
    } else {
        skip_reason_name(
            binding
                .status
                .skip_reason()
                .unwrap_or(crate::surface_binding::SkipReason::Unbound),
        )
    };
    json!({
        "binding_id": binding.binding_id,
        "who": who_name(binding.who),
        "subject": subject_json(&binding.subject),
        "surface": surface_name(binding.surface),
        "mode": mode_name(binding.mode),
        "target_id": binding.target,
        "status": status,
        "resolves": binding.status.is_resolvable() && binding.target.is_some(),
    })
}

fn resolution_json(
    surface: Surface,
    request: &SurfaceRequest,
    resolution: &crate::surface_binding::Resolution,
) -> Value {
    let _ = request;
    json!({
        "surface": surface_name(surface),
        "source": source_name(resolution.source),
        "target_id": resolution.target,
        "binding_id": resolution.binding_id,
        "mode": resolution.mode.map(mode_name),
        "fallback": resolution.is_fallback(),
        "skipped": resolution.skipped.iter().map(|skipped| json!({
            "binding_id": skipped.binding_id,
            "who": who_name(skipped.who),
            "subject": subject_json(&skipped.subject),
            "target_id": skipped.target,
            "reason": skip_reason_name(skipped.reason),
        })).collect::<Vec<_>>(),
    })
}

/// Resolve the effective binding for one surface for this caller, reading both
/// the personal override and the workspace default.
async fn effective_resolution(
    db: &Db,
    caller: &Caller,
    surface: Surface,
) -> Result<crate::surface_binding::Resolution> {
    let person = caller_person_pool(db, caller.credential()).await?;
    let mut bindings = Vec::new();
    if let Some(person) = person.as_deref() {
        bindings.extend(
            bindings_for_who(db, caller, person, Who::Principal)
                .await?
                .into_iter()
                .map(|(_, _, binding)| binding),
        );
    }
    bindings.extend(
        bindings_for_who(db, caller, WORKSPACE_ROOT, Who::Workspace)
            .await?
            .into_iter()
            .map(|(_, _, binding)| binding),
    );
    Ok(crate::surface_binding::resolve(
        surface,
        &SurfaceRequest::environment(),
        &bindings,
    ))
}

async fn manage_surface_bindings(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ManageSurfaceBindingsArgs = parse_args(TOOL, arguments)?;
    match args {
        ManageSurfaceBindingsArgs::List { surface } => {
            let surface = parse_surface(&surface)?;
            let person = caller_person_pool(&db, caller.credential()).await?;
            let mut bindings = Vec::new();
            if let Some(person) = person.as_deref() {
                bindings.extend(bindings_for_who(&db, &caller, person, Who::Principal).await?);
            }
            bindings.extend(bindings_for_who(&db, &caller, WORKSPACE_ROOT, Who::Workspace).await?);
            let out = bindings
                .iter()
                .filter(|(_, _, binding)| binding.surface == surface)
                .map(|(_, _, binding)| binding_json(binding))
                .collect::<Vec<_>>();
            Ok(json!({
                "surface": surface_name(surface),
                "bindings": out,
            }))
        }
        ManageSurfaceBindingsArgs::Get { surface, subject } => {
            let surface = parse_surface(&surface)?;
            let _ = parse_subject(subject.as_deref())?;
            let resolution = effective_resolution(&db, &caller, surface).await?;
            Ok(resolution_json(
                surface,
                &SurfaceRequest::environment(),
                &resolution,
            ))
        }
        ManageSurfaceBindingsArgs::Set {
            surface,
            scope,
            target_id,
            subject,
            mode,
            expected_target_id,
        } => {
            let surface = parse_surface(&surface)?;
            let _ = parse_subject(subject.as_deref())?;
            let mode = parse_mode(mode.as_deref())?;
            let scope = Scope::parse(&scope)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let source_id = scope_source_in(&mut tx, &caller, scope).await?;
            require_record_in(
                &mut tx,
                &caller,
                TOOL,
                &source_id,
                scope.required_capability(),
            )
            .await?;
            // The target must be a live artifact the caller may view. An
            // unauthorized or wrong-typed target is refused here at bind time,
            // where the person is present to be told; the read path is what
            // degrades honestly when authority is lost later.
            let status = artifact_status_in(&mut tx, &target_id).await?;
            if !status.is_resolvable() {
                return Err(Error::engine(format!(
                    "{TOOL}: target {target_id} is {}",
                    target_status_name(status)
                )));
            }
            require_record_in(&mut tx, &caller, TOOL, &target_id, Capability::View).await?;
            let existing = environment_binding_in(&mut tx, &source_id).await?;
            let current = existing.as_ref().map(|(_, target)| target.clone());
            if current != expected_target_id {
                return Err(Error::engine(format!(
                    "{TOOL}: binding revision does not match; expected current target {} but found {}",
                    expected_target_id.as_deref().unwrap_or("none"),
                    current.as_deref().unwrap_or("none")
                )));
            }
            if current.as_deref() == Some(target_id.as_str()) {
                tx.rollback().await?;
                let resolution = effective_resolution(&db, &caller, surface).await?;
                return Ok(json!({
                    "status": "unchanged",
                    "scope": scope.name(),
                    "source_id": source_id,
                    "resolution": resolution_json(
                        surface,
                        &SurfaceRequest::environment(),
                        &resolution,
                    ),
                }));
            }
            let previous_seq = previous_record_seq_in(&mut tx, &source_id).await?;
            let mut act = ActAllocation::new();
            if let Some((_, old_target)) = existing {
                append_in(
                    &db,
                    &mut tx,
                    AppendSpec {
                        record_id: source_id.clone(),
                        event_type: "link.removed".into(),
                        payload: serde_json::to_value(LinkRemovedPayload {
                            source_id: source_id.clone(),
                            target_id: old_target,
                            relationship: SURFACE_BINDING_RELATIONSHIP.into(),
                        })?,
                        actor: Some(caller.actor().into()),
                    },
                    &mut act,
                )
                .await?;
            }
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: source_id.clone(),
                    event_type: "link.added".into(),
                    payload: serde_json::to_value(LinkAddedPayload {
                        id: None,
                        source_id: source_id.clone(),
                        target_id: target_id.clone(),
                        relationship: SURFACE_BINDING_RELATIONSHIP.into(),
                        note: Some(serde_json::to_string(&descriptor(
                            surface,
                            &SubjectPattern::Environment,
                            mode,
                        ))?),
                    })?,
                    actor: Some(caller.actor().into()),
                },
                &mut act,
            )
            .await?;
            db.commit_content(tx).await?;
            let resolution = effective_resolution(&db, &caller, surface).await?;
            Ok(echo_act(
                json!({
                "status": "bound",
                "scope": scope.name(),
                "source_id": source_id,
                "previous_seq": previous_seq,
                "resolution": resolution_json(
                    surface,
                    &SurfaceRequest::environment(),
                    &resolution,
                ),
                }),
                act.get(),
            )?)
        }
        ManageSurfaceBindingsArgs::Reset {
            surface,
            scope,
            subject,
            expected_target_id,
        } => {
            let surface = parse_surface(&surface)?;
            let _ = parse_subject(subject.as_deref())?;
            let scope = Scope::parse(&scope)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let source_id = scope_source_in(&mut tx, &caller, scope).await?;
            require_record_in(
                &mut tx,
                &caller,
                TOOL,
                &source_id,
                scope.required_capability(),
            )
            .await?;
            let existing = environment_bindings_in(&mut tx, &source_id).await?;
            // Exactly one binding is compare-and-set against the expected
            // target. Several are a repair: the caller cannot name one current
            // target, so `reset` clears them all rather than refusing.
            if existing.len() <= 1 {
                let current = existing.first().map(|(_, target)| target.clone());
                if current != expected_target_id {
                    return Err(Error::engine(format!(
                        "{TOOL}: binding revision does not match; expected current target {} but found {}",
                        expected_target_id.as_deref().unwrap_or("none"),
                        current.as_deref().unwrap_or("none")
                    )));
                }
            }
            if existing.is_empty() {
                tx.rollback().await?;
                let resolution = effective_resolution(&db, &caller, surface).await?;
                return Ok(json!({
                    "status": "unchanged",
                    "scope": scope.name(),
                    "source_id": source_id,
                    "resolution": resolution_json(
                        surface,
                        &SurfaceRequest::environment(),
                        &resolution,
                    ),
                }));
            }
            let previous_seq = previous_record_seq_in(&mut tx, &source_id).await?;
            let removed: Vec<String> = existing.iter().map(|(_, target)| target.clone()).collect();
            let mut act = ActAllocation::new();
            for (_, old_target) in &existing {
                append_in(
                    &db,
                    &mut tx,
                    AppendSpec {
                        record_id: source_id.clone(),
                        event_type: "link.removed".into(),
                        payload: serde_json::to_value(LinkRemovedPayload {
                            source_id: source_id.clone(),
                            target_id: old_target.clone(),
                            relationship: SURFACE_BINDING_RELATIONSHIP.into(),
                        })?,
                        actor: Some(caller.actor().into()),
                    },
                    &mut act,
                )
                .await?;
            }
            db.commit_content(tx).await?;
            let resolution = effective_resolution(&db, &caller, surface).await?;
            Ok(echo_act(
                json!({
                "status": "reset",
                "scope": scope.name(),
                "source_id": source_id,
                "removed_target_id": removed.first().cloned(),
                "removed_target_ids": removed,
                "previous_seq": previous_seq,
                "resolution": resolution_json(
                    surface,
                    &SurfaceRequest::environment(),
                    &resolution,
                ),
                }),
                act.get(),
            )?)
        }
    }
}

/// Register `manage_surface_bindings`.
pub fn register_surface_binding_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageSurfaceBindings,
        &format!(
            "List, get, set, or reset a surface binding. A binding points a surface \
             (today only 'home') at one artifact for a who ('personal' for the caller's \
             own override, 'workspace' for the default). get returns the effective \
             binding, its source, target, mode, and any skipped bindings with reasons; \
             set validates and returns what it resolved; reset removes a scoped override. \
             With nothing bound, the app-owned fallback renders — the surface is never \
             blank. {PREVIOUS_SEQ_DESCRIPTION} {ACT_DESCRIPTION}"
        ),
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "surface": { "type": "string", "description": "Registered surface; only 'home' in this slice." }
                    },
                    "required": ["action", "surface"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "get" },
                        "surface": { "type": "string" },
                        "subject": { "type": "string", "description": "Optional subject; only 'environment' in this slice." }
                    },
                    "required": ["action", "surface"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "set" },
                        "surface": { "type": "string" },
                        "scope": { "type": "string", "enum": ["personal", "workspace"] },
                        "target_id": { "type": "string", "description": "Live Document kind:artifact to bind." },
                        "subject": { "type": "string", "description": "Optional subject; only 'environment' in this slice." },
                        "mode": { "type": "string", "enum": ["isolated"], "description": "Only 'isolated' is exercised in this slice." },
                        "expected_target_id": { "type": ["string", "null"], "description": "Current bound target (null when unbound); a compare-and-set guard." }
                    },
                    "required": ["action", "surface", "scope", "target_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "reset" },
                        "surface": { "type": "string" },
                        "scope": { "type": "string", "enum": ["personal", "workspace"] },
                        "subject": { "type": "string", "description": "Optional subject; only 'environment' in this slice." },
                        "expected_target_id": { "type": ["string", "null"], "description": "Current bound target; a compare-and-set guard." }
                    },
                    "required": ["action", "surface", "scope"],
                    "additionalProperties": false
                }
            ]
        }),
        manage_surface_bindings,
    )?;
    Ok(())
}
