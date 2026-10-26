//! Probe-only snapshot importer. Source content never appears in reports/errors.
use crate::{db::Db, events::KERNEL_ROOT_ID, kernel as k, v2_standard as standard};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Connection, Row, SqliteConnection};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Instant,
};
use uuid::Uuid;

mod app_state;
mod history;
mod member_context;
mod messaging;
mod state;
mod surface_bindings;
mod table_coverage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub mod cutover;
mod delta;
pub mod refusal_breakdown;
mod workspace_metadata;
const V1_ROOT: &str = "native:root";
// Fixed forever: later history replay must target these same identities.
const RECEIPT_NS: Uuid = Uuid::from_u128(0x54a479d20406561aafc2ca388ee11fc9);

pub struct Options {
    pub source: PathBuf,
    pub target: PathBuf,
    pub seeds: Vec<String>,
    pub all: bool,
    pub history: bool,
    pub resume: bool,
    pub members_file: Option<PathBuf>,
}
#[derive(Default, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub build: cutover::ImportBuild,
    pub refusal_breakdown: Vec<refusal_breakdown::RefusalCount>,
    /// Counted-only source outcomes, separate from blocking refusals/review.
    pub counted_breakdown: Vec<refusal_breakdown::RefusalCount>,
    pub counted: Vec<Issue>,
    pub excluded_deleted: usize,
    pub excluded_invisible_in_v1: usize,
    /// Subset of both excluded_invisible_in_v1 and tombstones_verified.
    /// Subtract this overlap once when reconciling source coverage.
    pub excluded_invisible_tombstones_verified: usize,
    pub inherited_bearer_tombstones: usize,
    pub live_messages_imported: usize,
    pub state: state::StateReport,
    #[serde(skip)]
    message_rules: Option<k::MessageRules>,
    pub history: history::HistoryReport,
    pub app_state: app_state::Report,
    pub table_coverage: table_coverage::TableCoverage,
    /// Wall-clock diagnostics only; dotted phases are included in their parent.
    pub phase_seconds: BTreeMap<String, f64>,
    pub imported: BTreeMap<String, usize>,
    pub created: usize,
    pub updated: usize,
    pub delta: BTreeMap<String, usize>,
    pub unchanged: usize,
    pub verified: usize,
    pub tombstones_verified: usize,
    pub links_imported: usize,
    pub links_by_relationship: BTreeMap<String, LinkCounts>,
    pub skipped_links: BTreeMap<String, usize>,
    pub message_destinations_verified: usize,
    pub message_non_audience_checks: usize,
    pub message_non_audience_leaks: usize,
    pub message_v2_visible_but_v1_hidden: usize,
    pub message_v1_visible_but_v2_denied: usize,
    pub message_visibility_checks: usize,
    /// IDs and pass/fail only: private-policy owner overrides must not widen audience.
    pub message_owner_override_visibility: BTreeMap<String, bool>,
    /// Counts only: source placement differs from the terminal bearer placement.
    pub derived_replaced: BTreeMap<String, usize>,
    pub derived_refused: BTreeMap<String, usize>,
    pub comment_anchors_imported: usize,
    pub comment_anchors_verified: usize,
    pub assumed_owners: Vec<String>,
    pub owner_overrides: Vec<OwnerOverride>,
    pub review: Vec<Issue>,
    pub refusals: Vec<Issue>,
    pub homes: BTreeMap<String, String>,
    pub principals: BTreeMap<String, String>,
    pub expanded_members: BTreeSet<String>,
    pub excluded_bound_accounts: BTreeSet<String>,
    pub roster_change: Option<RosterChange>,
    pub verified_ids: Vec<String>,
    pub instruction_bindings: InstructionBindingsReport,
    pub nonfinite_facets: Vec<NonfiniteFacet>,
    pub metadata_coverage: MetadataCoverage,
}
#[derive(Serialize)]
pub struct OwnerOverride {
    pub record_id: String,
    pub original_owner_id: Option<String>,
    pub verified_owner_account: Option<String>,
    pub verified_owner_accounts: Vec<String>,
    pub private_policy_account: String,
}
fn phase(report: &mut Report, name: &str, started: Instant) {
    *report.phase_seconds.entry(name.into()).or_default() += started.elapsed().as_secs_f64();
}
#[derive(Default, Serialize)]
pub struct MetadataCoverage {
    pub persistence: usize,
    pub maturity: usize,
    pub last_activity_at: usize,
    pub note_summary: usize,
    pub note_lifecycle: usize,
}
#[derive(Serialize)]
pub struct NonfiniteFacet {
    pub record_id: String,
    pub key: String,
    pub reason: &'static str,
}
#[derive(Default, Serialize)]
pub struct LinkCounts {
    pub imported: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub verified: usize,
    pub skipped: usize,
    pub refused: usize,
    pub review: usize,
}
#[derive(Serialize)]
pub struct RosterChange {
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
}
/// Source accounting and sealed current-state binding reconciliation.
#[derive(Default, Serialize)]
pub struct InstructionBindingsReport {
    pub source_table_present: bool,
    pub total: usize,
    pub targets_in_subset: usize,
    pub by_scope: BTreeMap<String, usize>,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub verified: usize,
    pub refused: usize,
    pub disabled_target_deleted: usize,
    pub standing_targets_added: usize,
    pub not_yet_imported: Vec<SourceInstructionBinding>,
}
#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct SourceInstructionBinding {
    pub id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub source_record_id: String,
    pub position: i64,
    pub enabled: bool,
    pub target_in_subset: bool,
    #[serde(skip_serializing)]
    pub created_at: String,
    #[serde(skip_serializing)]
    pub actor: Option<String>,
}
#[derive(Serialize)]
pub struct Issue {
    pub id: String,
    pub reason: String,
}
#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
struct Record {
    id: String,
    #[sqlx(rename = "type")]
    v1_type: String,
    kind: Option<String>,
    name: String,
    body: Option<String>,
    home_id: Option<String>,
    owner_id: Option<String>,
    lifecycle: Option<String>,
    summary: Option<String>,
    persistence: String,
    maturity: Option<String>,
    last_activity_at: String,
    created_at: String,
    updated_at: String,
    archived: bool,
    policy_anchor_id: Option<String>,
    deleted_at: Option<String>,
}
#[derive(Clone)]
struct Policy {
    entries: Vec<(String, String)>,
    private: Option<String>,
    visible_accounts: BTreeSet<String>,
}
// Source authorization only; never infer visibility from the selected v2
// owner. Richard's private-policy-wins decision explicitly supersedes the
// conflicting legacy owner floor at exclusive account-only boundaries.
fn v1_visible(
    record: &Record,
    account: &str,
    policies: &BTreeMap<String, Policy>,
    owner_accounts: &BTreeMap<String, Vec<String>>,
    records: &BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
) -> bool {
    let Some(current) = terminal_record(record, records, bearers) else {
        return false;
    };
    if let Some(policy) = current
        .policy_anchor_id
        .as_ref()
        .and_then(|a| policies.get(a))
    {
        if let Some(private_account) = &policy.private {
            return private_account == account;
        }
    }
    current
        .policy_anchor_id
        .as_ref()
        .and_then(|a| policies.get(a))
        .is_some_and(|p| p.visible_accounts.contains(account))
        || current
            .owner_id
            .as_ref()
            .and_then(|id| owner_accounts.get(id))
            .is_some_and(|accounts| accounts.iter().any(|a| a == account))
}
pub(crate) fn derived(id: &str) -> String {
    k::v1_import_home_id(id)
}
fn is_derived_record(record: &Record) -> bool {
    record.v1_type == "Annotation"
        || (record.v1_type == "Document" && record.kind.as_deref() == Some("attachment"))
}
fn invisible_v1_attachment(record: &Record, bearers: &BTreeMap<String, Vec<String>>) -> bool {
    record.deleted_at.is_none()
        && record.v1_type == "Document"
        && record.kind.as_deref() == Some("attachment")
        && bearers.get(&record.id).is_none_or(Vec::is_empty)
}
fn terminal_record<'a>(
    record: &'a Record,
    records: &'a BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
) -> Option<&'a Record> {
    let mut current = record;
    for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        if current.deleted_at.is_some() {
            return None;
        }
        if !is_derived_record(current) {
            return Some(current);
        }
        if depth == crate::authorization::MAX_DERIVED_BEARER_DEPTH {
            return None;
        }
        let [bearer] = bearers.get(&current.id).map(Vec::as_slice).unwrap_or(&[]) else {
            return None;
        };
        current = records.get(bearer)?;
    }
    None
}
// A valid, bounded comment chain may be unavailable solely because a bearer
// is tombstoned. Preserve that negative fact, never infer it from a broken chain.
fn tombstoned_comment_bearer<'a>(
    record: &'a Record,
    records: &'a BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
) -> Option<&'a Record> {
    if !is_comment_record(record) || record.deleted_at.is_some() {
        return None;
    }
    let mut current = record;
    let mut deleted = None;
    let mut seen = BTreeSet::new();
    for _ in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        if !seen.insert(&current.id) {
            return None;
        }
        if current.deleted_at.is_some() {
            deleted = Some(current);
        }
        if !is_derived_record(current) {
            return deleted;
        }
        let [bearer] = bearers.get(&current.id).map(Vec::as_slice).unwrap_or(&[]) else {
            return None;
        };
        current = records.get(bearer)?;
    }
    None
}
fn is_comment_record(record: &Record) -> bool {
    record.v1_type == "Annotation" && record.kind.as_deref() == Some("comment")
}
fn receipt(id: &str) -> String {
    Uuid::new_v5(&RECEIPT_NS, id.as_bytes()).to_string()
}
async fn principal(db: &Db, admin: &str, binding: &str) -> Result<String> {
    if let Some((id, kind, _)) = k::resolve_principal_by_binding(db, binding).await? {
        if kind != "account" {
            return Err("account binding collides with a non-account principal".into());
        }
        return Ok(id);
    }
    Ok(k::create_principal(db, "account", "Imported v1 account", binding, admin).await?)
}

// A retry verifies installed bytes, selection/log agreement and active family
// pins without issuing a new adoption. Re-adoption's dependency preflight must
// remain private-record-aware; imported member instructions may be hidden from
// the admin. Actual selection changes still use the governed adoption API.
async fn ensure_import_package(
    db: &Db,
    admin: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<()> {
    k::install_package_as(db, admin, manifest).await?;
    let identity = manifest.identity()?;
    let mut tx = db.write_pool().begin().await?;
    if let Some(stored) =
        k::read_package_selection_in(&mut tx, KERNEL_ROOT_ID, &manifest.namespace, &manifest.name)
            .await?
    {
        let expected = k::PackageSelection {
            namespace: manifest.namespace.clone(),
            name: manifest.name.clone(),
            version: manifest.version,
            digest: identity.digest.clone(),
        };
        let mut reads = manifest.declared_reads.clone();
        reads.sort();
        if stored.selected.as_ref() == Some(&expected)
            && stored.ack_actor == admin
            && stored.acknowledged_reads == reads
        {
            for definition in &manifest.definitions {
                if !matches!(k::resolve_effective_adoption_verified(&mut tx, &definition.family, KERNEL_ROOT_ID).await?,
                    Some(k::ScopedAdoption::Adopted(pin)) if pin.version == definition.version && pin.digest == definition.digest)
                {
                    return Err(
                        "import package definition pin differs from its verified selection".into(),
                    );
                }
            }
            tx.rollback().await?;
            return Ok(());
        }
    }
    tx.rollback().await?;
    k::adopt_package_at(
        db,
        admin,
        KERNEL_ROOT_ID,
        manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await?;
    Ok(())
}
fn issue(id: &str, reason: &str) -> Issue {
    Issue {
        id: id.into(),
        reason: reason.into(),
    }
}

#[derive(sqlx::FromRow)]
struct Link {
    id: String,
    source_id: String,
    target_id: String,
    relationship: String,
    note: Option<String>,
    created_at: String,
}

/// Attribute the current edge, not an earlier removed edge or a migration host.
// Cache only source facts, never authorization or target state. CTAS deliberately
// keeps JSON expression affinity: TEXT coercion would make numeric JSON IDs
// match text record IDs where the original json_extract comparison did not.
async fn cache_link_provenance(source: &mut SqliteConnection) -> Result<bool> {
    let malformed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type IN ('link.added','link.removed') AND payload IS NOT NULL AND NOT json_valid(payload))",
    ).fetch_one(&mut *source).await?;
    if malformed {
        // Preserve the direct reader's behavior, including when an earlier
        // matching row makes an unrelated malformed payload unreachable.
        return Ok(false);
    }
    sqlx::query("CREATE TEMP TABLE _v1_import_link_facts AS SELECT seq,type,actor,created_at,json_extract(payload,'$.source_id') AS source_id,json_extract(payload,'$.target_id') AS target_id,json_extract(payload,'$.relationship') AS relationship,json_extract(payload,'$.id') AS explicit_id FROM content_events WHERE type IN ('link.added','link.removed')")
        .execute(&mut *source).await?;
    sqlx::query("CREATE INDEX temp._v1_import_link_added ON _v1_import_link_facts(type,source_id,target_id,relationship,created_at,seq)")
        .execute(&mut *source).await?;
    sqlx::query("CREATE INDEX temp._v1_import_link_removed ON _v1_import_link_facts(type,source_id,target_id,relationship,seq)")
        .execute(&mut *source).await?;
    Ok(true)
}
const CACHED_LINK_PROVENANCE_SQL: &str = "SELECT a.actor FROM temp._v1_import_link_facts a WHERE a.type='link.added' AND a.source_id=?1 AND a.target_id=?2 AND a.relationship=?3 AND COALESCE(a.explicit_id,'lnk:'||?1||':'||?2||':'||?3)=?4 AND a.created_at=?5 AND NOT EXISTS(SELECT 1 FROM temp._v1_import_link_facts r WHERE r.type='link.removed' AND r.seq>a.seq AND r.source_id=?1 AND r.target_id=?2 AND r.relationship=?3) ORDER BY a.seq LIMIT 1";

const DIRECT_LINK_PROVENANCE_SQL: &str =
    "SELECT a.actor FROM content_events a WHERE a.type='link.added'
         AND json_extract(a.payload,'$.source_id')=?1 AND json_extract(a.payload,'$.target_id')=?2
         AND json_extract(a.payload,'$.relationship')=?3
         AND COALESCE(json_extract(a.payload,'$.id'),'lnk:'||?1||':'||?2||':'||?3)=?4
         AND a.created_at=?5 AND NOT EXISTS(SELECT 1 FROM content_events r
          WHERE r.type='link.removed' AND r.seq>a.seq
          AND json_extract(r.payload,'$.source_id')=?1 AND json_extract(r.payload,'$.target_id')=?2
          AND json_extract(r.payload,'$.relationship')=?3) ORDER BY a.seq LIMIT 1";

async fn link_provenance(
    source: &mut SqliteConnection,
    link: &Link,
    governed: bool,
    cached: bool,
) -> Result<(Option<String>, String)> {
    let content: Option<Option<String>> = sqlx::query_scalar(if cached {
        CACHED_LINK_PROVENANCE_SQL
    } else {
        DIRECT_LINK_PROVENANCE_SQL
    })
    .bind(&link.source_id)
    .bind(&link.target_id)
    .bind(&link.relationship)
    .bind(&link.id)
    .bind(&link.created_at)
    .fetch_optional(&mut *source)
    .await?;
    if let Some(actor) = content {
        return Ok((actor, link.created_at.clone()));
    }
    if governed {
        if let Some((origin, id)) = link.id.strip_prefix("rel:").and_then(|s| s.split_once(':')) {
            let legacy: Option<(String,String)> = sqlx::query_as(
                "SELECT source_facts,created_at FROM relationship_legacy_links WHERE relationship_origin_db_id=? AND relationship_id=?")
                .bind(origin).bind(id).fetch_optional(&mut *source).await?;
            if let Some((facts, created_at)) = &legacy {
                let facts: Vec<serde_json::Value> = serde_json::from_str(facts)?;
                if !facts.is_empty() {
                    let start = facts
                        .iter()
                        .rposition(|f| f["operation"] == "remove")
                        .map_or(0, |i| i + 1);
                    let actor = facts
                        .iter()
                        .skip(start)
                        .find(|f| f["operation"] == "add" && f["occurred_at"] == *created_at)
                        .and_then(|f| f["actor"].as_str())
                        .map(str::to_owned);
                    return Ok((actor, created_at.clone()));
                }
            }
            let event: Option<(String,String)> = sqlx::query_as(
                "SELECT actor,occurred_at FROM relationship_events WHERE relationship_origin_db_id=? AND relationship_id=? AND type='relationship.created.v1' ORDER BY seq LIMIT 1")
                .bind(origin).bind(id).fetch_optional(&mut *source).await?;
            if let Some((actor, time)) = event {
                let original_time = legacy.map_or_else(|| time.clone(), |(_, time)| time);
                // A migration receipt's actor must not become an older link's
                // author when the original author evidence is missing.
                let author = (original_time == time).then_some(actor);
                return Ok((author, original_time));
            }
        }
    }
    Ok((None, link.created_at.clone()))
}

/// Verify after every bearer link is present: comment visibility depends on
/// the complete thread, including for ordinary edges targeting a reply.
async fn verify_generic_link(
    db: &Db,
    host: &str,
    original: k::GenericLink,
    result: crate::Result<k::GenericLinkOutcome>,
    report: &mut Report,
) -> Result<()> {
    let active = k::read_imported_generic_link_as(db, host, &original).await?;
    let counts = report
        .links_by_relationship
        .entry(original.relationship.clone())
        .or_default();
    if let Some(other) = active
        .as_ref()
        .filter(|_| matches!(&result, Ok(_) | Err(crate::Error::Conflict(_))))
    {
        if other.link_id != original.link_id {
            counts.review += 1;
            report.review.push(issue(
                &original.link_id,
                &format!(
                    "generic link triple has different active id: {}",
                    other.link_id
                ),
            ));
            return Ok(());
        }
    }
    match result {
        Ok(outcome) => {
            counts.imported += 1;
            report.links_imported += 1;
            match outcome {
                k::GenericLinkOutcome::Created => counts.created += 1,
                k::GenericLinkOutcome::Updated => counts.updated += 1,
                k::GenericLinkOutcome::Unchanged => counts.unchanged += 1,
            }
            let mut expected = original;
            expected.actor = expected.actor.map(|a| format!("v1:{a}"));
            if active.as_ref() == Some(&expected) {
                counts.verified += 1;
            } else {
                counts.refused += 1;
                report.refusals.push(issue(
                    &expected.link_id,
                    "generic link kernel read reconciliation mismatch",
                ));
            }
        }
        Err(error) => {
            counts.refused += 1;
            let reason = match error {
                crate::Error::Conflict(_) => "generic link identity or provenance conflict",
                crate::Error::Engine(_) => "generic link admission refused",
                _ => "generic link import failed",
            };
            report.refusals.push(issue(&original.link_id, reason));
        }
    }
    Ok(())
}

/// One current-state record import: carrier fields, facets, kernel record,
/// snapshot provenance, and the expected-state entry the verification loop
/// reconciles. Shared by the ordinary phase and the comment phase; only the
/// caller-chosen home differs (own home for records, bearer home for
/// comments).
#[allow(clippy::too_many_arguments)]
async fn import_record_row(
    db: &Db,
    host: &str,
    origin: &str,
    source: &mut SqliteConnection,
    record: &Record,
    owner: String,
    home: String,
    packages: &[crate::package_manifest::PackageManifest],
    owner_accounts: &BTreeMap<String, Vec<String>>,
    report: &mut Report,
    expected: &mut BTreeMap<String, (String, String, k::ImportRecordState)>,
    tombstone: Option<&k::ImportRemovalEvidence>,
) -> Result<()> {
    let phase_prefix = if is_comment_record(record) {
        "comments"
    } else {
        "records"
    };
    let carrier =
        standard::v1_compat::v1_carrier_for(&record.v1_type, record.kind.as_deref().unwrap_or(""));
    let fields = if carrier == standard::v1_compat::V1Carrier::Compat {
        standard::v1_compat::compat_fields(
            &record.v1_type,
            record.kind.as_deref().unwrap_or(""),
            Some(&record.name),
            record.summary.as_deref(),
            record.lifecycle.as_deref(),
        )
    } else {
        let mut fields = serde_json::Map::new();
        if !record.name.is_empty() {
            fields.insert("title".into(), record.name.clone().into());
        }
        if let Some(summary) = &record.summary {
            fields.insert("summary".into(), summary.clone().into());
        }
        if let Some(lifecycle) = &record.lifecycle {
            fields.insert("lifecycle".into(), lifecycle.clone().into());
        }
        fields
    };
    let manifest = &packages[if carrier == standard::v1_compat::V1Carrier::Compat {
        0
    } else {
        1
    }];
    let def = &manifest.definitions[0];
    let mut facets = Vec::new();
    let mut missing_observation = false;
    let mut archived = record.archived;
    let mut archive_observed_at: Option<String> = None;
    let started = Instant::now();
    for row in sqlx::query("SELECT f.key,f.value,f.value_num,f.vocab_ref,(SELECT o.as_of FROM facet_observations o WHERE o.record_id=f.record_id AND o.key=f.key ORDER BY o.event_seq DESC,o.as_of DESC LIMIT 1) AS as_of FROM facet_values f WHERE f.record_id=? ORDER BY f.key")
        .bind(&record.id).fetch_all(&mut *source).await? {
        let key:String=row.get("key");
        let value:Option<String>=row.get("value");
        if key=="archived" {archived=true; archive_observed_at=row.get("as_of"); continue;}
        let Some(as_of)=row.get::<Option<String>,_>("as_of") else {report.review.push(issue(&record.id,"current facet has no observation timestamp"));missing_observation=true;continue;};
        let mut value_num: Option<f64> = row.get("value_num");
        if value_num.is_some_and(|n| !n.is_finite()) {
            if value.is_none() { report.review.push(issue(&record.id,"non-finite facet has no original text value")); missing_observation=true; continue; }
            report.nonfinite_facets.push(NonfiniteFacet { record_id:record.id.clone(),key:key.clone(),reason:"non-finite numeric projection omitted; original text retained" });
            value_num=None;
        }
        facets.push(k::FacetObservation {key,value,value_num,vocab_ref:row.get("vocab_ref"),as_of});
    }
    phase(report, &format!("{phase_prefix}.facets_source"), started);
    if missing_observation {
        return Ok(());
    }
    let persona = messaging::persona_snapshot(source, record, report).await?;
    let state = k::ImportRecordState {
        persona,
        message_principal: if record.v1_type == "Entity" && record.kind.as_deref() == Some("person")
        {
            owner_accounts
                .get(&record.id)
                .filter(|a| a.len() == 1)
                .and_then(|a| report.principals.get(&a[0]))
                .cloned()
        } else {
            None
        },
        message: if record.v1_type == "Message" {
            Some(messaging::snapshot(source, record, report).await?)
        } else {
            None
        },
        metadata: Some(k::RecordMetadata {
            persistence: record.persistence.clone(),
            maturity: record.maturity.clone(),
            last_activity_at: record.last_activity_at.clone(),
        }),
        definition: Some(k::ImportDefinition {
            pin: crate::meta::definition_artifact::RevisionIdentity {
                family: def.family.clone(),
                version: def.version,
                digest: def.digest.clone(),
            },
            primary_type: if carrier == standard::v1_compat::V1Carrier::Compat {
                "V1"
            } else {
                "Document"
            }
            .into(),
            kind: carrier.kind().into(),
            fields,
        }),
        body: record.body.clone(),
        facets,
        archived,
    };
    let started = Instant::now();
    if record.v1_type == "Document"
        && record.kind.as_deref() == Some("attachment")
        && tombstone.is_none()
    {
        let bearers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM links WHERE source_id=? AND relationship='part_of'",
        )
        .bind(&record.id)
        .fetch_one(&mut *source)
        .await?;
        if bearers != 1 {
            report.refusals.push(issue(
                &record.id,
                &format!("attachment requires exactly one part_of bearer; found {bearers}"),
            ));
            return Ok(());
        }
    }
    let already_imported:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1' AND actor=?)").bind(&record.id).bind(host).fetch_one(db.pool()).await?;
    let attachment = if record.v1_type == "Document"
        && record.kind.as_deref() == Some("attachment")
        && tombstone.is_none()
        && !(already_imported
            && !state
                .facets
                .iter()
                .any(|f| f.key == "blob_ref" && f.value.is_some()))
    {
        let handle = state
            .facets
            .iter()
            .find(|f| f.key == "blob_ref")
            .and_then(|f| f.value.as_deref());
        let Some(handle) = handle else {
            report
                .refusals
                .push(issue(&record.id, "attachment has no blob reference"));
            return Ok(());
        };
        let row = sqlx::query("SELECT bytes,id,mime,size_bytes,sha256,original_filename,storage_tier,created_at FROM blobs WHERE id=?").bind(handle).fetch_optional(&mut *source).await?;
        let Some(row) = row else {
            report
                .refusals
                .push(issue(&record.id, "attachment blob missing"));
            return Ok(());
        };
        let bytes: Option<Vec<u8>> = row.get("bytes");
        let Some(bytes) = bytes else {
            report
                .refusals
                .push(issue(&record.id, "attachment bytes not held in snapshot"));
            return Ok(());
        };
        let meta = crate::blob::BlobMeta {
            id: row.try_get("id")?,
            mime: row.try_get("mime")?,
            size_bytes: row.try_get("size_bytes")?,
            sha256: row.try_get("sha256")?,
            original_filename: row.try_get("original_filename")?,
            storage_tier: row.try_get("storage_tier")?,
            created_at: row.try_get("created_at")?,
        };
        Some((bytes, meta))
    } else {
        None
    };
    phase(report, &format!("{phase_prefix}.blobs_source"), started);
    let previous:Option<String>=sqlx::query_scalar("SELECT CASE WHEN type='kernel.import_state_delta.v1' THEN json_extract(payload,'$.snapshot') ELSE payload END FROM content_events WHERE record_id=? AND type IN ('kernel.import_state.v1','kernel.import_state_delta.v1') ORDER BY seq DESC LIMIT 1").bind(&record.id).fetch_optional(db.pool()).await?;
    let started = Instant::now();
    let was_tombstoned = if tombstone.is_some() {
        k::read_imported_snapshot_as(db, host, &record.id)
            .await?
            .is_some_and(|s| s.tombstoned)
    } else {
        false
    };
    let imported = if let Some(evidence) = tombstone {
        k::resume_record_tombstone_as(db, host, &record.id, &home, Some(&owner), &state, evidence)
            .await
    } else {
        k::resume_record_with_blob_as(
            db,
            host,
            &record.id,
            &home,
            Some(&owner),
            &state,
            attachment
                .as_ref()
                .map(|(bytes, meta)| (bytes.as_slice(), meta)),
        )
        .await
    };
    phase(
        report,
        &format!("{phase_prefix}.atomic_state_body_facets_blobs"),
        started,
    );
    match imported {
        Ok(k::ImportResult::Created) => report.created += 1,
        Ok(k::ImportResult::Updated) => {
            report.updated += 1;
            *report.delta.entry("records_updated".into()).or_default() += 1;
            if let Some(previous) = previous {
                let old: serde_json::Value = serde_json::from_str(&previous)?;
                let next = serde_json::to_value(&state)?;
                for key in [
                    "body",
                    "metadata",
                    "facets",
                    "archived",
                    "definition",
                    "message",
                    "message_principal",
                ] {
                    if old["state"][key] != next[key] {
                        *report
                            .delta
                            .entry(format!("records_{key}_changed"))
                            .or_default() += 1;
                    }
                }
                if old["home_id"] != home {
                    *report.delta.entry("records_rehomed".into()).or_default() += 1;
                }
                if old["owner_id"] != owner {
                    *report
                        .delta
                        .entry("records_owner_changed".into())
                        .or_default() += 1;
                }
            }
        }
        Ok(k::ImportResult::Unchanged) => report.unchanged += 1,
        Err(error) => {
            report.refusals.push(issue(
                &record.id,
                &format!(
                    "kernel current-state import refused: {}",
                    redact_record_error(&error.to_string(), record, &state)
                ),
            ));
            return Ok(());
        }
    }
    if let Some(evidence) = tombstone.filter(|_| !was_tombstoned) {
        *report.delta.entry("records_tombstoned".into()).or_default() += 1;
        if evidence.reason.starts_with("comment detached") {
            *report.delta.entry("comments_detached".into()).or_default() += 1;
        }
    }
    let started = Instant::now();
    // Snapshot provenance, not a fabricated v1 event or native creator/editor pin.
    let creator:Option<String>=sqlx::query_scalar("SELECT actor FROM content_events WHERE record_id=? AND type='record.created' ORDER BY seq LIMIT 1").bind(&record.id).fetch_optional(&mut *source).await?.flatten();
    let editor:Option<String>=sqlx::query_scalar("SELECT actor FROM content_events WHERE record_id=? AND (type IN ('record.created','record.updated') OR (type='receipt.committed.v1' AND json_type(payload,'$.body') IS NOT NULL) OR (type='unit.revision.recorded.v1' AND json_type(payload,'$.content.content') IS NOT NULL) OR (type='message.revision.recorded.v1' AND json_type(payload,'$.body') IS NOT NULL)) ORDER BY seq DESC LIMIT 1").bind(&record.id).fetch_optional(&mut *source).await?.flatten();
    let mut provenance = k::LegacyEvent {
        source: None,
        id: receipt(&format!("{origin}:snapshot:{}", record.id)),
        event_type: "v1.snapshot_provenance".into(),
        created_at: record.created_at.clone(),
        actor: creator.clone(),
        run_key: None,
        payload: json!({"source_origin":origin,"record_id":record.id,"creator":creator,"created_at":record.created_at,"last_editor":editor,"updated_at":record.updated_at,"persistence":record.persistence,"maturity":record.maturity,"last_activity_at":record.last_activity_at,"original_owner":record.owner_id,"verified_owner_accounts":record.owner_id.as_ref().and_then(|id|owner_accounts.get(id)),"owner_assumed":report.assumed_owners.contains(&record.id),"original_home":record.home_id,"policy_anchor":record.policy_anchor_id,"derived_home":derived(&record.id),"archive_observed_at":archive_observed_at,"v1_type":record.v1_type,"v1_kind":record.kind,"lifecycle":record.lifecycle,"summary":record.summary}),
    };
    // Preserve the current typed-time projection even without --history.
    // Empty is authoritative too: old typed history must not resurrect a
    // value that an untyped current write or unset already removed on v1.
    if report
        .table_coverage
        .imported
        .iter()
        .any(|name| name == "facet_times")
    {
        let times: Vec<String> = sqlx::query_scalar("SELECT json_object('key',t.key,'kind',t.kind,'all_day',t.all_day,'start_date',t.start_date,'end_date',t.end_date,'start_ms',t.start_ms,'end_ms',t.end_ms,'tz',t.tz,'tzdb_version',t.tzdb_version,'value',f.value) FROM facet_times t JOIN facet_values f ON f.record_id=t.record_id AND f.key=t.key WHERE t.record_id=? ORDER BY t.key")
            .bind(&record.id).fetch_all(&mut *source).await?;
        provenance.payload["facet_times"] = serde_json::Value::Array(
            times
                .into_iter()
                .map(|row| serde_json::from_str(&row))
                .collect::<std::result::Result<_, _>>()?,
        );
    }
    if let Some(owner_override) = report
        .owner_overrides
        .iter()
        .find(|o| o.record_id == record.id)
    {
        provenance.payload.as_object_mut().unwrap().insert(
            "owner_override".into(),
            serde_json::to_value(owner_override)?,
        );
    }
    if let Some(deleted_at) = &record.deleted_at {
        provenance
            .payload
            .as_object_mut()
            .unwrap()
            .insert("deleted_at".into(), deleted_at.clone().into());
    }
    phase(
        report,
        &format!("{phase_prefix}.provenance_source"),
        started,
    );
    let started = Instant::now();
    let first: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(&provenance.id)
        .fetch_optional(db.pool())
        .await?;
    if let Some(first) = first {
        let old: serde_json::Value = serde_json::from_str(&first)?;
        if serde_json::to_string(&old["legacy"]["payload"])?
            != serde_json::to_string(&provenance.payload)?
        {
            provenance.id = receipt(&format!(
                "{origin}:snapshot:{}:{}",
                record.id,
                crate::meta::definition_artifact::digest_artifact_bytes(
                    serde_json::to_string(&provenance.payload)?.as_bytes()
                )
            ));
        }
    }
    k::import_event_as(db, host, &record.id, &provenance).await?;
    phase(
        report,
        &format!("{phase_prefix}.provenance_commit"),
        started,
    );
    *report
        .imported
        .entry(format!(
            "{}/{}",
            record.v1_type,
            record.kind.as_deref().unwrap_or("")
        ))
        .or_default() += 1;
    expected.insert(record.id.clone(), (home, owner, state));
    Ok(())
}

async fn verify_anchor(db: &Db, id: &str, import: &k::comments_v2::AnchorImport) -> Result<bool> {
    let stored: Option<k::comments_v2::CommentAnchor> = sqlx::query_as(
        "SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors WHERE annotation_id=?",
    )
    .bind(id)
    .fetch_optional(db.write_pool())
    .await?;
    Ok(stored.is_some_and(|stored| {
        stored.target_record_id == import.anchor.target_record_id
            && stored.source_slot == import.anchor.source_slot
            && stored.selectors
                == serde_json::to_string(&import.anchor.selectors).unwrap_or_default()
            && stored.body_revision == import.anchor.body_revision
            && stored.body_revision_source == import.anchor.body_revision_source.as_str()
            && stored.body_sha256 == import.anchor.body_sha256
            && stored.purpose == import.anchor.purpose
            && stored.created_at == import.created_at
            && stored.actor == import.actor.clone().map(|actor| format!("v1:{actor}"))
    }))
}

/// Sealed comment-anchor phase, after records and bearer links. Roots pin
/// the v1 `annotation_targets` row they were anchored with — target,
/// selectors, and the body revision and hash — with the comment's legacy
/// creator as provenance. Replies are targetless: an anchor row on one is a
/// refusal. Identical retries report unchanged, so resume is idempotent.
#[allow(clippy::type_complexity)]
async fn import_comment_anchors(
    db: &Db,
    host: &str,
    source: &mut SqliteConnection,
    records: &BTreeMap<String, Record>,
    expected: &BTreeMap<String, (String, String, k::ImportRecordState)>,
    report: &mut Report,
) -> Result<()> {
    let has_anchors: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='annotation_targets')",
    )
    .fetch_one(&mut *source)
    .await?;
    for (id, (_, _, _)) in expected {
        let Some(record) = records.get(id) else {
            continue;
        };
        if record.v1_type != "Annotation" || record.kind.as_deref() != Some("comment") {
            continue;
        }
        let bearers: Vec<String> = sqlx::query_scalar(
            "SELECT target_id FROM links WHERE source_id=? AND relationship='part_of' ORDER BY target_id",
        )
        .bind(id)
        .fetch_all(&mut *source)
        .await?;
        if bearers.len() != 1 {
            report
                .refusals
                .push(issue(id, "comment bearer is not exactly one part_of link"));
            continue;
        }
        let bearer = &bearers[0];
        let bearer_is_comment = records.get(bearer).is_some_and(|bearer| {
            bearer.v1_type == "Annotation" && bearer.kind.as_deref() == Some("comment")
        });
        if bearer_is_comment {
            if has_anchors {
                let anchored: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id=?)",
                )
                .bind(id)
                .fetch_one(&mut *source)
                .await?;
                if anchored {
                    report
                        .refusals
                        .push(issue(id, "comment replies must be targetless"));
                }
            }
            continue;
        }
        if !expected.contains_key(bearer) {
            report
                .refusals
                .push(issue(id, "comment bearer was not imported"));
            continue;
        }
        if !has_anchors {
            continue;
        }
        let row: Option<(String, String, Option<i64>, String, String, Option<String>, String)> = sqlx::query_as(
            "SELECT target_record_id, source_slot, source_event_seq, source_sha256, selectors, purpose, created_at FROM annotation_targets WHERE annotation_id=?",
        )
        .bind(id)
        .fetch_optional(&mut *source)
        .await?;
        let Some((target, slot, revision, sha, selectors, purpose, created_at)) = row else {
            continue;
        };
        if target != *bearer || slot != "body" {
            report.refusals.push(issue(
                id,
                "anchored comment root must target its part_of bearer's body",
            ));
            continue;
        }
        let Some(revision) = revision else {
            report
                .refusals
                .push(issue(id, "comment anchor has no pinned body revision"));
            continue;
        };
        let selectors: serde_json::Value = match serde_json::from_str(&selectors) {
            Ok(selectors) => selectors,
            Err(_) => {
                report
                    .refusals
                    .push(issue(id, "comment anchor selectors are not JSON"));
                continue;
            }
        };
        let creator: Option<String> = sqlx::query_scalar("SELECT actor FROM content_events WHERE record_id=? AND type='record.created' ORDER BY seq LIMIT 1").bind(id).fetch_optional(&mut *source).await?.flatten();
        let import = k::comments_v2::AnchorImport {
            anchor: k::comments_v2::AnchorPayload {
                target_record_id: target,
                source_slot: slot,
                selectors,
                body_revision: revision,
                body_revision_source: k::comments_v2::RevisionSource::V1SourceSeq,
                body_sha256: sha,
                purpose,
            },
            created_at,
            actor: creator,
        };
        match k::comments_v2::resume_anchor_as(db, host, id, &import).await {
            Ok(k::comments_v2::AnchorImportOutcome::Updated) => {
                *report
                    .delta
                    .entry("comment_anchors_updated".into())
                    .or_default() += 1;
                if verify_anchor(db, id, &import).await? {
                    report.comment_anchors_verified += 1;
                } else {
                    report.refusals.push(issue(
                        id,
                        "comment anchor kernel read reconciliation mismatch",
                    ));
                }
            }
            Ok(k::comments_v2::AnchorImportOutcome::Created) => {
                report.comment_anchors_imported += 1;
                if verify_anchor(db, id, &import).await? {
                    report.comment_anchors_verified += 1;
                } else {
                    report.refusals.push(issue(
                        id,
                        "comment anchor kernel read reconciliation mismatch",
                    ));
                }
            }
            Ok(k::comments_v2::AnchorImportOutcome::Unchanged) => {
                if verify_anchor(db, id, &import).await? {
                    report.comment_anchors_verified += 1;
                } else {
                    report.refusals.push(issue(
                        id,
                        "comment anchor kernel read reconciliation mismatch",
                    ));
                }
            }
            Err(_) => {
                report
                    .refusals
                    .push(issue(id, "comment anchor import refused"));
            }
        }
    }
    Ok(())
}

async fn import_instruction_bindings(
    db: &Db,
    host: &str,
    imported_records: &BTreeSet<String>,
    source_db: &mut SqliteConnection,
    origin: &str,
    report: &mut Report,
) -> Result<()> {
    for source in std::mem::take(&mut report.instruction_bindings.not_yet_imported) {
        if !imported_records.contains(&source.source_record_id) {
            let old: Option<(String, bool)> = sqlx::query_as(
                "SELECT source_record_id,enabled FROM kernel_instruction_bindings WHERE id=?",
            )
            .bind(&source.id)
            .fetch_optional(db.pool())
            .await?;
            let target_live: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
            )
            .bind(&source.source_record_id)
            .fetch_one(&mut *source_db)
            .await?;
            if let Some((old_target, enabled)) = old {
                let disabled_for_deleted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_removed.v1' AND actor=? AND json_extract(payload,'$.kind')='instruction_binding' AND json_extract(payload,'$.evidence.reason') IN ('binding target deleted in source snapshot','binding target removed or retargeted in source snapshot'))")
                    .bind(&source.id).bind(host).fetch_one(db.pool()).await?;
                if !target_live && (enabled || disabled_for_deleted) {
                    let evidence = delta::evidence(
                        source_db,
                        origin,
                        &source.id,
                        delta::EvidenceKind::BindingRetarget,
                        "binding target deleted in source snapshot",
                        None,
                    )
                    .await?;
                    if k::import_removal_as(
                        db,
                        host,
                        &source.id,
                        k::ImportedRemovalKind::InstructionBinding,
                        &evidence,
                    )
                    .await?
                        != k::ImportResult::Unchanged
                    {
                        *report
                            .delta
                            .entry("instruction_bindings_disabled_target_deleted".into())
                            .or_default() += 1;
                    }
                    let disabled: bool = sqlx::query_scalar(
                        "SELECT NOT enabled FROM kernel_instruction_bindings WHERE id=?",
                    )
                    .bind(&source.id)
                    .fetch_one(db.pool())
                    .await?;
                    if disabled {
                        report.instruction_bindings.disabled_target_deleted += 1;
                        let before = report.refusals.len();
                        report.refusals.retain(|i| {
                            i.id != source.id
                                || i.reason
                                    != "instruction binding target missing from source snapshot"
                        });
                        report.instruction_bindings.refused -= before - report.refusals.len();
                        continue;
                    }
                } else if enabled && old_target != source.source_record_id {
                    report.review.push(issue(&source.id,
                        "binding target removed or retargeted but not safely imported; prior binding disabled"));
                    let evidence = delta::evidence(
                        source_db,
                        origin,
                        &source.id,
                        delta::EvidenceKind::BindingRetarget,
                        "binding target retargeted in source snapshot",
                        None,
                    )
                    .await?;
                    k::import_removal_as(
                        db,
                        host,
                        &source.id,
                        k::ImportedRemovalKind::InstructionBinding,
                        &evidence,
                    )
                    .await?;
                } else if enabled && source.target_in_subset {
                    report.review.push(issue(
                        &source.id,
                        "live binding target not safely imported; prior binding retained",
                    ));
                }
            }
            if source.target_in_subset {
                report.refusals.push(issue(
                    &source.id,
                    "instruction binding target was not imported",
                ));
                report.instruction_bindings.refused += 1;
            }
            report.instruction_bindings.not_yet_imported.push(source);
            continue;
        }
        let account_principal = if source.scope_kind == "account" {
            let Some(mapped) = report.principals.get(&source.scope_id) else {
                report.review.push(issue(
                    &source.id,
                    "instruction binding account scope has no mapped principal",
                ));
                report.instruction_bindings.not_yet_imported.push(source);
                continue;
            };
            Some(mapped.clone())
        } else {
            None
        };
        let binding = k::ImportInstructionBinding {
            id: source.id.clone(),
            scope_kind: source.scope_kind.clone(),
            scope_id: source.scope_id.clone(),
            account_principal,
            source_record_id: source.source_record_id.clone(),
            position: source.position,
            enabled: source.enabled,
            created_at: source.created_at.clone(),
            actor: source.actor.clone(),
        };
        match k::import_instruction_binding_as(db, host, &binding).await {
            Ok(k::InstructionBindingImportResult::Created) => {
                report.instruction_bindings.created += 1
            }
            Ok(k::InstructionBindingImportResult::Updated) => {
                report.instruction_bindings.updated += 1
            }
            Ok(k::InstructionBindingImportResult::Unchanged) => {
                report.instruction_bindings.unchanged += 1
            }
            Err(_) => {
                report.refusals.push(issue(
                    &source.id,
                    "sealed instruction binding import refused",
                ));
                report.instruction_bindings.refused += 1;
                report.instruction_bindings.not_yet_imported.push(source);
                continue;
            }
        }
        let stored = sqlx::query_as::<_, k::ImportInstructionBinding>(
            "SELECT id,scope_kind,scope_id,account_principal,source_record_id,position,enabled,created_at,legacy_actor AS actor FROM kernel_instruction_bindings WHERE id=?"
        ).bind(&binding.id).fetch_optional(db.write_pool()).await?;
        let mapping_matches = if binding.scope_kind == "account" {
            k::resolve_principal_by_binding(db, &binding.scope_id)
                .await?
                .is_some_and(|(id, kind, _)| {
                    kind == "account"
                        && Some(&id) == binding.account_principal.as_ref()
                        && report.principals.get(&binding.scope_id) == Some(&id)
                })
        } else {
            binding.account_principal.is_none()
        };
        let mut expected = binding;
        expected.actor = expected.actor.map(|a| format!("v1:{a}"));
        if stored.as_ref() == Some(&expected) && mapping_matches {
            report.instruction_bindings.verified += 1;
        } else {
            report.instruction_bindings.refused += 1;
            report.refusals.push(issue(
                &source.id,
                "instruction binding state or account principal correspondence mismatch",
            ));
            report.instruction_bindings.not_yet_imported.push(source);
        }
    }
    Ok(())
}

/// Resolve a logical folder ID or native kernel home in the caller's
/// transaction. A derived ID alone is not proof: an imported or native-folder
/// home binding must exist, and both alias and home must be visible.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn resolve_home_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: &str,
    requested: &str,
) -> crate::Result<String> {
    let native: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(requested)
            .fetch_one(&mut **tx)
            .await?;
    let home = if native {
        requested.to_owned()
    } else if requested == V1_ROOT {
        KERNEL_ROOT_ID.to_owned()
    } else {
        let derived = derived(requested);
        let mapped: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events e JOIN kernel_roots h ON h.root_id=e.record_id WHERE e.record_id=? AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id')=?)",
        ).bind(&derived).bind(requested).fetch_one(&mut **tx).await?;
        if !mapped {
            // Do not misdiagnose a visible, older native folder as hidden.
            // The View gate still makes missing and inaccessible IDs identical.
            k::kernel_require(
                tx,
                principal,
                requested,
                crate::authorization::Capability::View,
            )
            .await?;
            if let Some(folder) = k::read_record_on(tx, principal, requested).await? {
                if folder
                    .fields
                    .get("v1_type")
                    .and_then(serde_json::Value::as_str)
                    == Some("Collection")
                    && folder
                        .fields
                        .get("v1_kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("folder")
                {
                    return Err(crate::Error::engine("folder has no child-home binding; create a child record or move a record into this folder to bind it"));
                }
            }
            return Err(crate::Error::engine(
                "home_id must name a folder or kernel home",
            ));
        }
        k::kernel_require(
            tx,
            principal,
            requested,
            crate::authorization::Capability::View,
        )
        .await?;
        derived
    };
    let tombstoned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e JOIN kernel_import_tombstones t ON t.record_id=json_extract(e.payload,'$.source_record_id') WHERE e.record_id=? AND e.type='kernel.import_home.v1')").bind(&home).fetch_one(&mut **tx).await?;
    if tombstoned {
        return Err(crate::Error::engine(k::HIDDEN_OR_MISSING));
    }
    k::kernel_require(tx, principal, &home, crate::authorization::Capability::View).await?;
    Ok(home)
}

/// Placement for read layers: preserve the v1 folder record ID while retaining
/// the actual kernel policy/placement home. Missing and hidden return None.
#[derive(Debug, Serialize)]
pub struct ImportedPlacement {
    pub home_id: Option<String>,
    pub kernel_home_id: String,
}
// The prepared header is the canonical witness for this exact envelope kind.
// Looking through the raw retained stream decodes unrelated source revisions.
pub(crate) const SNAPSHOT_PROVENANCE_SQL: &str = "SELECT e.payload FROM main.kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq WHERE h.record_id=? AND h.source_stream='snapshot_provenance' ORDER BY h.seq DESC LIMIT 1";

pub async fn placement_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> crate::Result<Option<ImportedPlacement>> {
    let mut tx = db.write_pool().begin().await?;
    let result = placement_on(&mut tx, principal, record).await?;
    tx.rollback().await?;
    Ok(result)
}

/// Placement and its View checks in the caller's existing live snapshot.
pub(crate) async fn placement_on(
    tx: &mut sqlx::SqliteConnection,
    principal: &str,
    record: &str,
) -> crate::Result<Option<ImportedPlacement>> {
    k::legacy_history::require_sql_frontier_on(tx).await?;
    let Some(home): Option<String> =
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(record)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(None);
    };
    if !k::kernel_effective_capability_on(&mut *tx, principal, record)
        .await?
        .allows(crate::authorization::Capability::View)
    {
        return Ok(None);
    }
    let provenance: Option<String> = sqlx::query_scalar(SNAPSHOT_PROVENANCE_SQL)
        .bind(record)
        .fetch_optional(&mut *tx)
        .await?;
    let original: Option<serde_json::Value> =
        provenance.map(|v| serde_json::from_str(&v)).transpose()?;
    let mut mapped: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM main.content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
        .bind(&home).fetch_optional(&mut *tx).await?;
    let root_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root')")
            .fetch_one(&mut *tx)
            .await?;
    if home == KERNEL_ROOT_ID && mapped.is_none() {
        let root_imported: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.import_home_policy.v1')").bind(KERNEL_ROOT_ID).fetch_one(&mut *tx).await?;
        if root_imported || root_record {
            mapped = Some(V1_ROOT.into());
        }
    }
    let moved: Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.logical_home_id') FROM main.content_events WHERE record_id=? AND type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ORDER BY seq DESC LIMIT 1")
        .bind(record).fetch_optional(&mut *tx).await?.flatten();
    let direct_home = k::messaging::logical_direct_home_on(tx, record).await?;
    let candidate = if moved.is_some() {
        moved
    } else if direct_home.is_some() {
        direct_home.clone()
    } else if home == derived(record)
        && original
            .as_ref()
            .is_some_and(|p| p["legacy"]["payload"]["policy_anchor"].as_str() == Some(record))
    {
        original
            .as_ref()
            .and_then(|p| p["legacy"]["payload"]["original_home"].as_str())
            .map(str::to_owned)
    } else {
        Some(mapped.clone().unwrap_or_else(|| home.clone()))
    };
    let home_id = if let Some(candidate) = candidate {
        let is_record: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
                .bind(&candidate)
                .fetch_one(&mut *tx)
                .await?;
        let target = if !is_record && candidate == V1_ROOT && !root_record {
            KERNEL_ROOT_ID
        } else {
            candidate.as_str()
        };
        // This public filing sentinel does not disclose or grant View on the
        // separate private policy home. Other home IDs still need live View.
        let visible = (candidate == "native:unfiled"
            && direct_home.as_deref() == Some("native:unfiled"))
            || k::kernel_effective_capability_on(&mut *tx, principal, target)
                .await?
                .allows(crate::authorization::Capability::View);
        visible.then_some(candidate)
    } else {
        None
    };
    Ok(Some(ImportedPlacement {
        home_id,
        kernel_home_id: home,
    }))
}

/// Authorized snapshot provenance, separate from v2 definition pins. This also
/// retains lifecycle for first-class notes, whose definition has no such field.
pub async fn snapshot_provenance_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> Result<Option<serde_json::Value>> {
    let mut tx = db.write_pool().begin().await?;
    if k::read_record_on(&mut tx, principal, record)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    k::legacy_history::require_sql_frontier_on(&mut tx).await?;
    let payload: Option<String> = sqlx::query_scalar(SNAPSHOT_PROVENANCE_SQL)
        .bind(record)
        .fetch_optional(&mut *tx)
        .await?;
    payload
        .map(|p| {
            let value: serde_json::Value = serde_json::from_str(&p)?;
            Ok(value["legacy"]["payload"].clone())
        })
        .transpose()
}

/// A frozen v1 attribution stamp, never the actor or clock of a native v2 edit.
/// Only these metadata fields may cross the ordinary MCP read boundary.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LegacyRecordProvenance {
    pub kind: &'static str,
    pub creator: Option<String>,
    pub created_at: Option<String>,
    pub last_editor: Option<String>,
    pub updated_at: Option<String>,
    pub actors_withheld: bool,
}

pub async fn legacy_record_provenance_as(
    db: &Db,
    principal: &str,
    record: &str,
) -> crate::Result<Option<LegacyRecordProvenance>> {
    let mut tx = db.write_pool().begin().await?;
    legacy_record_provenance_on(&mut tx, principal, record).await
}
pub(crate) async fn legacy_record_provenance_on(
    tx: &mut sqlx::SqliteConnection,
    principal: &str,
    record: &str,
) -> crate::Result<Option<LegacyRecordProvenance>> {
    k::legacy_history::require_sql_frontier_on(tx).await?;
    // Provenance needs visibility, not a hydrated body/fields read.
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
        .bind(record)
        .fetch_one(&mut *tx)
        .await?;
    if !exists
        || !k::kernel_effective_capability_on(tx, principal, record)
            .await?
            .allows(crate::authorization::Capability::View)
    {
        return Ok(None);
    }
    let payload: Option<String> = sqlx::query_scalar(SNAPSHOT_PROVENANCE_SQL)
        .bind(record)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_str(&payload)?;
    let legacy = &value["legacy"]["payload"];
    // Match history_as's directory-attribution fence, in the same snapshot as
    // record visibility. A visible record must not recover withheld actors.
    let root_visible = k::kernel_effective_capability_on(tx, principal, KERNEL_ROOT_ID)
        .await?
        .allows(crate::authorization::Capability::View);
    let actor = |key: &str| {
        if root_visible {
            legacy[key].as_str().map(|id| format!("v1:{id}"))
        } else {
            None
        }
    };
    Ok(Some(LegacyRecordProvenance {
        kind: "v1.snapshot_provenance",
        creator: actor("creator"),
        created_at: legacy["created_at"].as_str().map(str::to_owned),
        last_editor: actor("last_editor"),
        updated_at: legacy["updated_at"].as_str().map(str::to_owned),
        actors_withheld: !root_visible,
    }))
}

// Keep the kernel diagnostic, while redacting source values before it enters
// the counts/IDs-only reconciliation report. Identifiers and type/kind tokens
// remain usable evidence; bodies, titles, summaries and facet text never do.
fn redact_record_error(error: &str, record: &Record, state: &k::ImportRecordState) -> String {
    let mut secrets: Vec<&str> = [
        record.name.as_str(),
        record.body.as_deref().unwrap_or(""),
        record.summary.as_deref().unwrap_or(""),
    ]
    .into_iter()
    .collect();
    if let Some(definition) = &state.definition {
        secrets.extend(
            definition
                .fields
                .values()
                .filter_map(serde_json::Value::as_str),
        );
    }
    secrets.extend(state.facets.iter().filter_map(|f| f.value.as_deref()));
    secrets.retain(|s| {
        !s.is_empty()
            && *s != record.id
            && *s != record.v1_type
            && Some(*s) != record.kind.as_deref()
    });
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut message = error.to_owned();
    for secret in secrets {
        let escaped = serde_json::to_string(secret).expect("string serializes");
        message = message
            .replace(&escaped[1..escaped.len() - 1], "[redacted]")
            .replace(secret, "[redacted]");
    }
    message
}

/// Reads one SQLite transaction; target writes exclusively through kernel APIs.
/// Errors deliberately omit engine messages which can contain source values.
pub async fn run(options: Options) -> Result<Report> {
    let total_started = Instant::now();
    let snapshot_started = Instant::now();
    #[cfg(unix)]
    if options.target.exists() {
        use std::os::unix::fs::MetadataExt;
        let source_meta = options.source.metadata()?;
        let target_meta = options.target.metadata()?;
        if source_meta.dev() == target_meta.dev() && source_meta.ino() == target_meta.ino() {
            return Err("source and target must differ".into());
        }
    }
    if options.target.exists() && options.source.canonicalize()? == options.target.canonicalize()? {
        return Err("source and target must differ".into());
    }
    let mut report = Report::default();
    if options.all && options.members_file.is_none() {
        report.refusals.push(issue(
            "native:members",
            "full import requires --members-file from the live hosted roster",
        ));
        return Ok(refusal_breakdown::without_source(report));
    }
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&options.source)
            .read_only(true),
    )
    .await?;
    sqlx::query("PRAGMA temp_store=MEMORY")
        .execute(&mut source)
        .await?;
    sqlx::query("BEGIN").execute(&mut source).await?;
    report.table_coverage = table_coverage::check(&mut source).await?;
    if !report.table_coverage.unclassified.is_empty() {
        report.refusals.push(issue(
            "source_schema",
            "unclassified source tables; explicit import/drop disposition required",
        ));
        return Ok(report);
    }
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut source)
            .await?;
    // Link identities must be unique before any write or deferred verification.
    // Check the whole snapshot: a smaller seed set cannot hide an ambiguity.
    let duplicates: Vec<(String, i64)> =
        sqlx::query_as("SELECT id,count(*) FROM links GROUP BY id HAVING count(*)>1 ORDER BY id")
            .fetch_all(&mut source)
            .await?;
    if !duplicates.is_empty() {
        for (id, count) in duplicates {
            report.refusals.push(issue(
                &id,
                &format!(
                    "duplicate source link_id: {count} rows; import refused before target writes"
                ),
            ));
        }
        return Ok(refusal_breakdown::without_source(report));
    }
    // Hold one importer across the full multi-act resume, not just individual
    // SQLite transactions: two source frontiers must never interleave.
    let mut lock_name = options.target.as_os_str().to_os_string();
    lock_name.push(".import.lock");
    let _import_lock = {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(lock_name))?;
        file.try_lock()
            .map_err(|_| "target import is already running; concurrent resumes are refused")?;
        file
    };
    if options.resume && options.target.exists() {
        let mut target_read = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&options.target)
                .read_only(true),
        )
        .await?;
        let activated: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE type='kernel.hosted_membership.v1')",
        )
        .fetch_one(&mut target_read)
        .await?;
        target_read.close().await?;
        if activated {
            return Err("target has hosted v2 activation; --resume is forbidden".into());
        }
    }
    let raw_policies: Vec<(String,String,String,String)> = sqlx::query_as("SELECT policy_anchor_id,subject_kind,subject_id,capability FROM policy_entries ORDER BY 1,2,3")
        .fetch_all(&mut source).await?;
    let admin_accounts: Vec<_> = raw_policies
        .iter()
        .filter(|(a, s, _, c)| a == V1_ROOT && s == "account" && c == "manage")
        .map(|(_, _, id, _)| id.clone())
        .collect();
    if admin_accounts.len() != 1 {
        return Err("source must have exactly one workspace admin account".into());
    }
    let admin_account = &admin_accounts[0];
    let members: BTreeSet<String> = options
        .members_file
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path).map(|text| {
                text.lines()
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
        })
        .transpose()?
        .unwrap_or_default();
    report.instruction_bindings.source_table_present = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='instruction_bindings')"
    ).fetch_one(&mut source).await?;
    if report.instruction_bindings.source_table_present {
        let rows = sqlx::query_as::<_, SourceInstructionBinding>(
            "SELECT id,scope_kind,scope_id,source_record_id,position,enabled,created_at,created_by AS actor,0 AS target_in_subset FROM instruction_bindings ORDER BY scope_kind,scope_id,position,id"
        ).fetch_all(&mut source).await?;
        for row in rows {
            *report
                .instruction_bindings
                .by_scope
                .entry(row.scope_kind.clone())
                .or_default() += 1;
            report.instruction_bindings.not_yet_imported.push(row);
        }
        report.instruction_bindings.total = report.instruction_bindings.not_yet_imported.len();
    }
    if options.members_file.is_none()
        && report
            .instruction_bindings
            .not_yet_imported
            .iter()
            .any(|b| b.scope_kind == "account" && &b.scope_id != admin_account)
    {
        report.refusals.push(issue(
            "native:members",
            "member instruction bindings require --members-file from the live hosted roster",
        ));
        return Ok(refusal_breakdown::without_source(report));
    }
    let mut records = BTreeMap::<String, Record>::new();
    let mut queue = options.seeds.clone();
    if options.all {
        queue.extend(
            sqlx::query_scalar::<_, String>("SELECT id FROM records ORDER BY id")
                .fetch_all(&mut source)
                .await?,
        );
    }
    queue.push(V1_ROOT.into());
    let standing_targets: BTreeSet<_> = report
        .instruction_bindings
        .not_yet_imported
        .iter()
        .filter(|b| {
            (b.scope_kind == "database" && b.scope_id == "native:database")
                || (b.scope_kind == "account"
                    && (members.contains(&b.scope_id) || &b.scope_id == admin_account))
        })
        .map(|b| b.source_record_id.clone())
        .collect();
    for id in standing_targets {
        // A removed target is accounted for by its binding, not turned into
        // an implicit seed that repeatedly refuses as a missing record.
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
            .bind(&id)
            .fetch_one(&mut source)
            .await?;
        if exists {
            if !options.all && !options.seeds.contains(&id) {
                report.instruction_bindings.standing_targets_added += 1;
            }
            queue.push(id);
        }
    }

    while let Some(id) = queue.pop() {
        if records.contains_key(&id) {
            continue;
        }
        let row = sqlx::query_as::<_,Record>("SELECT id,type,kind,name,body,home_id,owner_id,lifecycle,summary,persistence,maturity,last_activity_at,created_at,updated_at,archived,policy_anchor_id,deleted_at FROM records WHERE id=?")
            .bind(&id).fetch_optional(&mut source).await?;
        let Some(row) = row else {
            report.refusals.push(issue(&id, "source record missing"));
            continue;
        };
        if let Some(parent) = &row.home_id {
            queue.push(parent.clone());
        }
        // Explicit policy boundaries can occur above placement in old snapshots.
        if let Some(anchor) = &row.policy_anchor_id {
            if anchor != &id {
                queue.push(anchor.clone());
            }
        }
        if is_derived_record(&row) {
            queue.extend(
                sqlx::query_scalar::<_, String>(
                    "SELECT target_id FROM links WHERE source_id=? AND relationship='part_of'",
                )
                .bind(&id)
                .fetch_all(&mut source)
                .await?,
            );
        }
        records.insert(id, row);
    }
    for row in &mut report.instruction_bindings.not_yet_imported {
        row.target_in_subset = records.contains_key(&row.source_record_id);
        report.instruction_bindings.targets_in_subset += usize::from(row.target_in_subset);
        if options.all && !row.target_in_subset {
            report.refusals.push(issue(
                &row.id,
                "instruction binding target missing from source snapshot",
            ));
            report.instruction_bindings.refused += 1;
        }
    }
    // Only canonical account bindings are verified identity evidence in v1.
    let bindings: Vec<(String,String)> = sqlx::query_as("SELECT record_id,identifier FROM bindings WHERE system='account' AND is_canonical=1 ORDER BY record_id,identifier")
        .fetch_all(&mut source).await?;
    let mut owner_accounts = BTreeMap::<String, Vec<String>>::new();
    let mut accounts = BTreeSet::new();
    for (person, account) in bindings {
        accounts.insert(account.clone());
        owner_accounts.entry(person).or_default().push(account);
    }
    accounts.insert(admin_account.clone());
    accounts.extend(
        report
            .instruction_bindings
            .not_yet_imported
            .iter()
            .filter(|b| {
                b.target_in_subset && b.scope_kind == "account" && !b.scope_id.trim().is_empty()
            })
            .map(|b| b.scope_id.clone()),
    );
    for (_, kind, id, _) in &raw_policies {
        if kind == "account" {
            accounts.insert(id.clone());
        }
    }
    let anchors: Vec<String> =
        sqlx::query_scalar("SELECT record_id FROM record_policies ORDER BY record_id")
            .fetch_all(&mut source)
            .await?;
    let anchors: Vec<_> = anchors
        .into_iter()
        .filter(|a| records.contains_key(a))
        .collect();
    let members_anchors: BTreeSet<_> = raw_policies
        .iter()
        .filter(|(a, kind, _, _)| anchors.contains(a) && kind == "members")
        .map(|(a, _, _, _)| a.clone())
        .collect();
    if !members_anchors.is_empty() && options.members_file.is_none() {
        for anchor in members_anchors {
            report.refusals.push(issue(
                &anchor,
                "members policy requires --members-file from the live hosted roster",
            ));
        }
        return Ok(refusal_breakdown::without_source(report));
    }
    if !members_anchors.is_empty() {
        report.expanded_members = members.clone();
        report.excluded_bound_accounts = owner_accounts
            .values()
            .flatten()
            .filter(|a| !members.contains(*a))
            .cloned()
            .collect();
        accounts.extend(members.iter().cloned());
    }
    let mut policies = BTreeMap::new();
    for anchor in anchors {
        let entries: Vec<_> = raw_policies
            .iter()
            .filter(|(a, _, _, _)| a == &anchor)
            .collect();
        let private = if entries.len() == 1 && entries[0].1 == "account" {
            Some(entries[0].2.clone())
        } else {
            None
        };
        let mut mapped = BTreeMap::<String, String>::new();
        for (_, kind, id, cap) in entries {
            if !matches!(kind.as_str(), "members" | "account")
                || !matches!(cap.as_str(), "view" | "edit" | "manage")
            {
                return Err("unsupported source policy entry".into());
            }
            let ids = if kind == "members" {
                members.iter().cloned().collect::<Vec<_>>()
            } else {
                vec![id.clone()]
            };
            for account in ids {
                let entry = mapped.entry(account).or_insert_with(|| cap.clone());
                let rank = |c: &str| match c {
                    "manage" => 3,
                    "edit" => 2,
                    _ => 1,
                };
                if rank(cap) > rank(entry) {
                    *entry = cap.clone();
                }
            }
        }
        policies.insert(
            anchor,
            Policy {
                visible_accounts: mapped.keys().cloned().collect(),
                entries: mapped.into_iter().collect(),
                private,
            },
        );
    }
    // Match Caller::credential() exactly: stdio --account and authenticated
    // hosted callers present the bare account ID, without an importer prefix.
    let binding = admin_account;
    let source_binding = format!("v1:{origin}:import-source");
    phase(&mut report, "snapshot_read", snapshot_started);
    let setup_started = Instant::now();
    // Atomic exclusive creation also refuses concurrent first imports. Never truncate.
    let exists = options.target.exists();
    if exists && !options.resume {
        return Err("target exists; --resume required".into());
    }
    let (db, admin) = if exists {
        let db =
            crate::db::open_database(options.target.to_str().ok_or("invalid target path")?).await?;
        // Refuse pre-isolation targets even when this resume omits --history.
        // Canonical placement is immutable; a new target is required.
        let old_private: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type='kernel.legacy_recorded.v1' AND record_id NOT GLOB 'kernel:app-custody:*' AND (json_extract(payload,'$.legacy.event_type') GLOB 'alpha_tab.*' OR (json_extract(payload,'$.legacy.source.stream')='control_events' AND (json_type(payload,'$.legacy.payload.account_id') IS NOT NULL OR json_extract(payload,'$.legacy.payload.scope_kind')='account'))))")
            .fetch_one(db.pool()).await?;
        if old_private {
            return Err("private app history requires a fresh custody-isolated target".into());
        }
        k::resolve_principal_by_binding(&db, &source_binding)
            .await?
            .ok_or("target belongs to a different source")?;
        let admin: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
                .bind(KERNEL_ROOT_ID)
                .fetch_one(db.pool())
                .await?;
        let admin = admin.ok_or("target workspace owner is missing")?;
        (db, admin)
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&options.target)?;
        let (db, admin) = k::create_v2_database(
            options.target.to_str().ok_or("invalid target path")?,
            "account",
            "Workspace administrator",
            binding,
        )
        .await?;
        // Source identity is a separate durable marker, never a caller binding.
        k::create_principal(&db, "agent", "V1 import source", &source_binding, &admin).await?;
        (db, admin)
    };
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await?
        .ok_or("missing import host")?
        .0;
    // Freeze/compare before creating accounts, installing packages, or replacing
    // any root/home policies. A refusal leaves all target events unchanged.
    match k::import_members_roster_as(&db, &host, options.members_file.as_ref().map(|_| &members))
        .await?
    {
        k::ImportRosterResult::Changed { added, removed } => {
            report.roster_change = Some(RosterChange { added, removed });
            report.refusals.push(issue("native:members", "supplied members roster differs from frozen target roster; see added/removed account ids in roster_change"));
            return Ok(refusal_breakdown::without_source(report));
        }
        k::ImportRosterResult::UntrackedTarget => {
            report.refusals.push(issue(
                "native:members",
                "target imported policies without frozen roster metadata; recreate target",
            ));
            return Ok(refusal_breakdown::without_source(report));
        }
        k::ImportRosterResult::Recorded | k::ImportRosterResult::Unchanged => {}
    }
    let target_admin_binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM kernel_principals WHERE principal_id=?")
            .bind(&admin)
            .fetch_one(db.pool())
            .await?;
    if &target_admin_binding != binding {
        report.refusals.push(issue("native:workspace-owner",&format!("workspace owner/admin changed: {target_admin_binding} -> {binding}; explicit ownership review required")));
        return Ok(refusal_breakdown::without_source(report));
    }
    k::prepare_v2_database(&db).await?;
    let source_head: Option<(i64, String)> =
        sqlx::query_as("SELECT seq,id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut source)
            .await?;
    let (source_seq, source_id) = source_head.map_or((0, None), |(seq, id)| (seq, Some(id)));
    let control_head = delta::control_head(&mut source).await?;
    let (control_seq, control_id) = control_head.map_or((0, None), |(seq, id)| (seq, Some(id)));
    if let Err(e) = k::import_source_head_as(
        &db,
        &host,
        &origin,
        source_seq,
        source_id,
        control_seq,
        control_id,
    )
    .await
    {
        report
            .refusals
            .push(issue("native:source-head", &e.to_string()));
        return Ok(refusal_breakdown::without_source(report));
    }
    accounts.extend(state::accounts(&mut source).await?);
    for account in accounts {
        let id = principal(&db, &admin, &account).await?;
        report.principals.insert(account, id);
    }
    let hosted_emails: Vec<(String, String)> = sqlx::query_as("SELECT e.identifier,a.identifier FROM bindings e JOIN bindings a ON a.record_id=e.record_id AND a.system='account' AND a.is_canonical=1 JOIN records p ON p.id=e.record_id AND p.type='Entity' AND p.kind='person' AND p.deleted_at IS NULL WHERE e.system='email' ORDER BY e.identifier,a.identifier")
        .fetch_all(&mut source).await?;
    k::hosted_identity::import_accounts(&db, &host, hosted_emails).await?;
    let transform = k::resolve_principal_by_binding(&db, "host:relates-to:transform")
        .await?
        .ok_or("missing transform host")?
        .0;
    // Resolve policy subjects only after the source authorization snapshot is fixed.
    for policy in policies.values_mut() {
        for (account, _) in &mut policy.entries {
            *account = report
                .principals
                .get(account)
                .ok_or("unmapped policy account")?
                .clone();
        }
    }
    let mut owners = BTreeMap::new();
    // Comment bearer chains, resolved once from the source links: comment
    // visibility derives through these, and comment placement follows them.
    let mut bearers = BTreeMap::<String, Vec<String>>::new();
    for (source_id, target_id) in sqlx::query_as::<_, (String, String)>(
        "SELECT source_id, target_id FROM links WHERE relationship='part_of' ORDER BY source_id, target_id",
    )
    .fetch_all(&mut source)
    .await?
    {
        bearers.entry(source_id).or_default().push(target_id);
    }
    for record in records.values() {
        if invisible_v1_attachment(record, &bearers) {
            // A fresh excluded row needs no invented owner. For an identity
            // imported earlier, preserve its sealed owner while tombstoning;
            // v1 denies every member access to the current bearerless state.
            if let Some(prior) = k::read_imported_snapshot_as(&db, &host, &record.id).await? {
                if let Some(owner) = prior.record.owner_id {
                    owners.insert(record.id.clone(), owner);
                }
            }
            continue;
        }
        let verified = record
            .owner_id
            .as_ref()
            .and_then(|o| owner_accounts.get(o))
            .filter(|as_| as_.len() == 1)
            .map(|a| a[0].clone());
        let private = (!is_derived_record(record))
            .then_some(record)
            .and_then(|record| record.policy_anchor_id.as_ref())
            .and_then(|a| policies.get(a))
            .and_then(|p| p.private.clone());
        if let Some(account) = private {
            let verified_accounts = record
                .owner_id
                .as_ref()
                .and_then(|o| owner_accounts.get(o))
                .cloned()
                .unwrap_or_default();
            if verified_accounts.iter().any(|v| v != &account) {
                // Richard's private-policy-wins decision: the kernel owner
                // floor must preserve the source's exclusive visibility.
                report.owner_overrides.push(OwnerOverride {
                    record_id: record.id.clone(),
                    original_owner_id: record.owner_id.clone(),
                    verified_owner_account: verified.clone(),
                    verified_owner_accounts: verified_accounts,
                    private_policy_account: account.clone(),
                });
            }
            // A private policy identifies the safe principal, but an unknown
            // original owner is still an explicit ownership assumption.
            if verified.is_none() && record.id != V1_ROOT {
                report.assumed_owners.push(record.id.clone());
            }
            owners.insert(record.id.clone(), report.principals[&account].clone());
        } else if let Some(account) = verified {
            owners.insert(record.id.clone(), report.principals[&account].clone());
        } else if v1_visible(
            record,
            admin_account,
            &policies,
            &owner_accounts,
            &records,
            &bearers,
        ) {
            owners.insert(record.id.clone(), admin.clone());
            if record.id != V1_ROOT {
                report.assumed_owners.push(record.id.clone());
            }
        } else {
            report.review.push(issue(
                &record.id,
                "unknown or ambiguous owner: workspace administrator cannot view the source record",
            ));
        }
    }
    // The first two entries are the record carriers selected below. Ordinary
    // relates_to writes and start_work also require their runtime packages;
    // bootstrap/run setup, bodies, facets and generic links are kernel lanes.
    let packages = [
        standard::v1_compat::package(),
        standard::document4_package(),
        standard::relates_to::package(),
        standard::claims_v1::package(),
    ];
    for manifest in &packages {
        ensure_import_package(&db, &admin, manifest).await?;
    }
    // Include each placement home and each explicit policy anchor. Root is not a record.
    let mut home_records: BTreeSet<String> = records
        .values()
        .filter_map(|r| r.home_id.clone())
        // Empty legacy folders must also be usable as attachment bearers.
        .chain(
            records
                .values()
                .filter(|r| {
                    r.v1_type == "Collection"
                        && r.kind.as_deref() == Some("folder")
                        && r.deleted_at.is_none()
                })
                .map(|r| r.id.clone()),
        )
        .chain(
            records
                .keys()
                .filter(|id| policies.contains_key(*id))
                .cloned(),
        )
        .filter(|id| id != V1_ROOT)
        .collect();
    report.homes.insert(V1_ROOT.into(), KERNEL_ROOT_ID.into());
    // Quarantine reviewed homes and their placement/policy dependents. Never
    // reparent them or default their owners to make an unrelated import work.
    let mut blocked_by: BTreeMap<String, String> = home_records
        .iter()
        .filter(|id| !owners.contains_key(*id))
        .map(|id| (id.clone(), id.clone()))
        .collect();
    loop {
        let before = blocked_by.len();
        for id in &home_records {
            if let Some(record) = records.get(id) {
                let cause = record
                    .home_id
                    .as_ref()
                    .and_then(|home| blocked_by.get(home))
                    .or_else(|| {
                        record
                            .policy_anchor_id
                            .as_ref()
                            .and_then(|home| blocked_by.get(home))
                    })
                    .cloned();
                if let Some(cause) = cause {
                    blocked_by.entry(id.clone()).or_insert(cause);
                }
            }
        }
        if blocked_by.len() == before {
            break;
        }
    }
    home_records.retain(|id| !blocked_by.contains_key(id));
    for id in &home_records {
        report.homes.insert(id.clone(), derived(id));
    }
    let mut pending = home_records.clone();
    while !pending.is_empty() {
        let before = pending.len();
        for id in pending.clone() {
            let Some(record) = records.get(&id) else {
                return Err("missing home ancestor".into());
            };
            let parent = record.home_id.as_deref().unwrap_or(V1_ROOT);
            if pending.contains(parent) {
                continue;
            }
            let owner = owners.get(&id).ok_or("home owner requires review")?;
            let entries = policies.get(&id).map(|p| {
                p.entries
                    .iter()
                    .map(|(s, c)| (s.as_str(), c.as_str()))
                    .collect::<Vec<_>>()
            });
            k::resume_home_as(
                &db,
                &host,
                &report.homes[&id],
                &id,
                &report.homes[parent],
                owner,
                entries.as_deref(),
            )
            .await?;
            pending.remove(&id);
        }
        if pending.len() == before {
            return Err("home ancestry cycle".into());
        }
    }
    let root_entries = &policies.get(V1_ROOT).ok_or("root policy missing")?.entries;
    k::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &root_entries
            .iter()
            .map(|(s, c)| (s.as_str(), c.as_str()))
            .collect::<Vec<_>>(),
    )
    .await?;
    k::prepare_v2_database(&db).await?;
    phase(
        &mut report,
        "principals_homes_policies_packages",
        setup_started,
    );
    let state_started = Instant::now();
    state::import(&db, &host, &mut source, &origin, &mut report).await?;
    phase(&mut report, "catalogue_control_state", state_started);
    if options.resume {
        let started = Instant::now();
        delta::reconcile(&db, &host, &mut source, &origin, false, &mut report).await?;
        phase(&mut report, "delta_removals", started);
    }
    let records_started = Instant::now();
    let mut expected = BTreeMap::new();
    for record in records
        .values()
        .filter(|r| r.id != V1_ROOT && !is_derived_record(r))
    {
        // Deleted Messages import below as sealed tombstones, including on
        // the first run; their audience/private state must not disappear.
        if record.v1_type == "Message" && record.deleted_at.is_some() {
            continue;
        }
        // Deleted non-Messages are counted below after any existing target
        // identity has been tombstoned. V1 has no member undelete surface.
        if record.deleted_at.is_some() {
            continue;
        }
        let Some(owner) = owners.get(&record.id) else {
            continue;
        };
        if let Some(home) = [
            Some(record.id.as_str()),
            record.home_id.as_deref(),
            record.policy_anchor_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .find_map(|id| blocked_by.get(id))
        {
            report.review.push(issue(
                &record.id,
                &format!("home requires ownership review: {home}"),
            ));
            continue;
        }
        // A record-local policy needs a home boundary even for the folder record itself.
        let home = if policies.contains_key(&record.id) {
            report.homes[&record.id].clone()
        } else {
            report.homes[record.home_id.as_deref().unwrap_or(V1_ROOT)].clone()
        };
        import_record_row(
            &db,
            &host,
            &origin,
            &mut source,
            record,
            owner.clone(),
            home,
            &packages,
            &owner_accounts,
            &mut report,
            &mut expected,
            None,
        )
        .await?;
    }
    phase(&mut report, "records", records_started);
    let comments_started = Instant::now();
    // All derived artifacts file in the terminal bearer's physical home,
    // regardless of stale v1 placement or policy anchors. Refuse any broken,
    // ambiguous, dead or over-depth chain; never guess a placement.
    let pending: Vec<String> = records
        .values()
        .filter(|r| r.id != V1_ROOT && is_derived_record(r))
        .map(|r| r.id.clone())
        .collect();
    let mut invisible_attachments = BTreeSet::new();
    for id in pending {
        // Deleted rows and inherited tombstones are handled below, never live.
        if records[&id].deleted_at.is_some()
            || tombstoned_comment_bearer(&records[&id], &records, &bearers).is_some()
        {
            continue;
        }
        let record = &records[&id];
        if invisible_v1_attachment(record, &bearers) {
            // Richard's cutover decision: v1 denies this shape to every member.
            // Retain history and an explicit exclusion receipt, never publish it.
            invisible_attachments.insert(id);
            continue;
        }
        let category = if record.v1_type == "Annotation" {
            "annotations"
        } else {
            "attachments"
        };
        let Some(terminal) = terminal_record(record, &records, &bearers) else {
            let count = bearers.get(&id).map_or(0, Vec::len);
            let reason = if record.v1_type == "Document" && count != 1 {
                format!("attachment requires exactly one part_of bearer; found {count}")
            } else if is_comment_record(record) {
                "comment bearer is not exactly one part_of link".into()
            } else {
                "derived record requires exactly one live part_of chain to a terminal bearer".into()
            };
            report.refusals.push(issue(&id, &reason));
            continue;
        };
        let Some((bearer_home, _, _)) = expected.get(&terminal.id) else {
            report
                .refusals
                .push(issue(&id, "derived terminal bearer was not imported"));
            continue;
        };
        let old_home = if policies.contains_key(&record.id) {
            report.homes.get(&record.id)
        } else {
            report
                .homes
                .get(record.home_id.as_deref().unwrap_or(V1_ROOT))
        };
        let replaced = old_home != Some(bearer_home);
        let Some(owner) = owners.get(&id) else {
            continue;
        };
        let record = &records[&id];
        import_record_row(
            &db,
            &host,
            &origin,
            &mut source,
            record,
            owner.clone(),
            bearer_home.clone(),
            &packages,
            &owner_accounts,
            &mut report,
            &mut expected,
            None,
        )
        .await?;
        if replaced && expected.contains_key(&id) {
            *report.derived_replaced.entry(category.into()).or_default() += 1;
        }
    }
    phase(&mut report, "comments.records", comments_started);
    workspace_metadata::import(
        &db,
        &host,
        records.get(V1_ROOT).ok_or("workspace root missing")?,
    )
    .await?;
    let links_started = Instant::now();
    report.assumed_owners.retain(|id| expected.contains_key(id));
    // Grant only the sealed transform service transient access, then always restore.
    let mut grants = Vec::new();
    grants.push((KERNEL_ROOT_ID.to_string(), root_entries.clone()));
    for id in &home_records {
        if let Some(policy) = policies.get(id) {
            grants.push((report.homes[id].clone(), policy.entries.clone()));
        }
    }
    for (home, entries) in &grants {
        let mut temporary = entries.clone();
        temporary.push((transform.clone(), "edit".into()));
        k::import_home_policy_as(
            &db,
            &host,
            home,
            &temporary
                .iter()
                .map(|(s, c)| (s.as_str(), c.as_str()))
                .collect::<Vec<_>>(),
        )
        .await?;
    }
    let link_result: Result<()> = async {
        let mut links=sqlx::query_as::<_,Link>("SELECT id,source_id,target_id,relationship,note,created_at FROM links ORDER BY id").fetch_all(&mut source).await?;
        // Bearer-dependent links last: a reply's `part_of` verifies through
        // its root's chain, so the root's bearer link must already be
        // imported. Governed threads nest at most one reply deep.
        links.sort_by_key(|link| {
            if link.relationship != "part_of" { return 0; }
            let mut depth=1;
            let mut current=records.get(&link.source_id);
            while let Some(record)=current.filter(|r|is_derived_record(r)) {
                if depth>crate::authorization::MAX_DERIVED_BEARER_DEPTH { break; }
                current=bearers.get(&record.id).and_then(|ids| if let [id]=ids.as_slice() {records.get(id)} else {None});
                depth+=1;
            }
            depth
        });
        let cache_started=Instant::now();
        let cached=cache_link_provenance(&mut source).await?;
        phase(&mut report,"links.provenance_cache_prepare",cache_started);
        let governed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='relationship_legacy_links') AND EXISTS(SELECT 1 FROM sqlite_master WHERE name='relationship_events')").fetch_one(&mut source).await?;
        let mut relations=BTreeMap::<(String,String),Vec<standard::relates_to::Source>>::new();
        let mut generic_checks = Vec::new();
        for link in links {
            let id=link.id.clone(); let from=link.source_id.clone(); let to=link.target_id.clone(); let predicate=link.relationship.clone();
            // Reserved bindings are captured as sealed configuration, never as generic link authority.
            if predicate==crate::surface_binding::SURFACE_BINDING_RELATIONSHIP { *report.skipped_links.entry("sealed_surface_binding_metadata".into()).or_default()+=1; report.links_by_relationship.entry(predicate).or_default().skipped+=1; continue; }
            if options.all && (!records.contains_key(&from) || !records.contains_key(&to)) {*report.skipped_links.entry("endpoint_missing_from_source".into()).or_default()+=1;report.links_by_relationship.entry(predicate.clone()).or_default().skipped+=1;continue;}
            if !records.contains_key(&from) && !records.contains_key(&to) {continue;}
            if !expected.contains_key(&from)||!expected.contains_key(&to) {*report.skipped_links.entry("endpoint_outside_imported_subset".into()).or_default()+=1;report.links_by_relationship.entry(predicate.clone()).or_default().skipped+=1;continue;}
            if predicate=="relates_to" {
                let started=Instant::now(); let (author,time)=link_provenance(&mut source,&link,governed,cached).await?; phase(&mut report,"links.provenance_source",started);
                let pair=if from<to {(from.clone(),to.clone())}else{(to.clone(),from.clone())};
                relations.entry(pair).or_default().push(standard::relates_to::Source {source_id:id,from,to,claimed_author:author.map(|a|format!("v1:{a}")),claimed_timestamp:Some(time),note:link.note});
            } else {
                let started=Instant::now(); let (actor,_)=link_provenance(&mut source,&link,governed,cached).await?; phase(&mut report,"links.provenance_source",started); let started=Instant::now();
                let original=k::GenericLink {link_id:id,source_id:from,target_id:to,relationship:predicate,note:link.note,created_at:link.created_at,actor};
                let outcome=k::import_generic_link_as(&db,&host,&original).await;
                generic_checks.push((original,outcome)); phase(&mut report,"links.generic_import_verify",started);
            }
        }
        delta::relations(&db,&transform,&mut source,&origin,relations,&mut report).await?;
        for (original,outcome) in generic_checks {
            let started=Instant::now();
            verify_generic_link(&db,&host,original,outcome,&mut report).await?;
            phase(&mut report,"links.generic_import_verify",started);
        }
        Ok(())
    }.await;
    for (home, entries) in &grants {
        k::import_home_policy_as(
            &db,
            &host,
            home,
            &entries
                .iter()
                .map(|(s, c)| (s.as_str(), c.as_str()))
                .collect::<Vec<_>>(),
        )
        .await?;
    }
    link_result?;
    // Preserve member-policy provenance only after the transient transform
    // grants are restored. Native policy replacement supersedes this template.
    for source in policies.keys() {
        let Some(home) = report.homes.get(source) else {
            continue;
        };
        let mut explicit = BTreeMap::new();
        let mut member_cap: Option<String> = None;
        let rank = |cap: &str| match cap {
            "manage" => 3,
            "edit" => 2,
            _ => 1,
        };
        for (_, kind, account, cap) in raw_policies.iter().filter(|(a, _, _, _)| a == source) {
            if kind == "account" {
                explicit.insert(report.principals[account].clone(), cap.clone());
            } else if kind == "members" && member_cap.as_ref().is_none_or(|c| rank(cap) > rank(c)) {
                member_cap = Some(cap.clone());
            }
        }
        k::hosted_identity::import_policy(&db, &host, home, explicit, member_cap).await?;
    }
    phase(&mut report, "links", links_started);
    let started = Instant::now();
    import_comment_anchors(&db, &host, &mut source, &records, &expected, &mut report).await?;
    phase(&mut report, "comments.anchors", started);
    let bindings_started = Instant::now();
    import_instruction_bindings(
        &db,
        &host,
        &expected.keys().cloned().collect(),
        &mut source,
        &origin,
        &mut report,
    )
    .await?;
    phase(&mut report, "instruction_bindings", bindings_started);
    messaging::import_destinations(&db, &host, &mut source, &mut report).await?;
    let mut verified_tombstones = BTreeSet::new();
    {
        for record in records.values() {
            let inherited = tombstoned_comment_bearer(record, &records, &bearers);
            if !options.resume && record.v1_type != "Message" && inherited.is_none() {
                continue;
            }
            if record.id == V1_ROOT
                || (record.deleted_at.is_none()
                    && !delta::unavailable_comment(&mut source, record).await?)
            {
                continue;
            }
            let prior = k::read_imported_snapshot_as(&db, &host, &record.id).await?;
            if prior.is_none() && record.v1_type != "Message" && inherited.is_none() {
                continue;
            }
            let Some(owner) = owners.get(&record.id) else {
                report.review.push(issue(
                    &record.id,
                    "final tombstone state requires ownership review",
                ));
                continue;
            };
            let mut terminal = record;
            if is_derived_record(record) {
                for _ in 0..crate::authorization::MAX_DERIVED_BEARER_DEPTH {
                    let Some([bearer]) = bearers.get(&terminal.id).map(Vec::as_slice) else {
                        break;
                    };
                    let Some(next) = records.get(bearer) else {
                        break;
                    };
                    terminal = next;
                    if !is_derived_record(terminal) {
                        break;
                    }
                }
            }
            let home = if is_derived_record(terminal) && invisible_attachments.contains(&record.id)
            {
                // The reviewed zero-bearer exclusion is already invisible in
                // v1. Keep a previously imported identity in its prior home
                // while sealing its final state as a tombstone; do not widen
                // this exception to other malformed derived chains.
                prior
                    .as_ref()
                    .ok_or("excluded attachment has no prior import")?
                    .record
                    .home_id
                    .clone()
            } else if is_derived_record(terminal) {
                report.review.push(issue(
                    &record.id,
                    "unavailable comment has no terminal bearer; prior home retained",
                ));
                prior
                    .as_ref()
                    .ok_or("unavailable comment has no prior import")?
                    .record
                    .home_id
                    .clone()
            } else {
                let key = if policies.contains_key(&terminal.id) {
                    terminal.id.as_str()
                } else {
                    terminal.home_id.as_deref().unwrap_or(V1_ROOT)
                };
                let Some(home) = report.homes.get(key) else {
                    report.review.push(issue(
                        &record.id,
                        "final tombstone state requires home review",
                    ));
                    continue;
                };
                home.clone()
            };
            let evidence = delta::evidence(
                &mut source,
                &origin,
                &record.id,
                if record.deleted_at.is_some() {
                    delta::EvidenceKind::Record
                } else {
                    delta::EvidenceKind::CommentBearer
                },
                if record.deleted_at.is_some() {
                    "source record tombstone"
                } else if bearers.get(&record.id).is_none_or(Vec::is_empty) {
                    "comment detached from its bearer in source snapshot"
                } else {
                    "comment bearer missing or tombstoned in source snapshot"
                },
                record
                    .deleted_at
                    .clone()
                    .or_else(|| inherited.and_then(|r| r.deleted_at.clone())),
            )
            .await?;
            let mut final_state = BTreeMap::new();
            import_record_row(
                &db,
                &host,
                &origin,
                &mut source,
                record,
                owner.clone(),
                home,
                &packages,
                &owner_accounts,
                &mut report,
                &mut final_state,
                Some(&evidence),
            )
            .await?;
            if let Some((home, owner, state)) = final_state.remove(&record.id) {
                let observed = k::read_imported_snapshot_as(&db, &host, &record.id)
                    .await?
                    .ok_or("imported tombstone missing")?;
                let matched = observed.tombstoned
                    && observed.record.home_id == home
                    && observed.record.owner_id.as_deref() == Some(owner.as_str())
                    && observed.record.body == state.body
                    && Some(&observed.record.metadata) == state.metadata.as_ref()
                    && observed.record.archived == state.archived
                    && observed.record.fields == state.definition.as_ref().unwrap().fields
                    && observed.facets == state.facets;
                if matched {
                    report.tombstones_verified += 1;
                    verified_tombstones.insert(record.id.clone());
                    if inherited.is_some() {
                        report.inherited_bearer_tombstones += 1;
                        report
                            .counted
                            .push(issue(&record.id, "inherited_bearer_tombstone"));
                    }
                    report.refusals.retain(|i| {
                        i.id != record.id
                            || !matches!(
                                i.reason.as_str(),
                                "record outside current-state importer scope"
                                    | "comment bearer was not imported"
                                    | "comment bearer is not exactly one part_of link"
                            )
                    });
                } else {
                    report.refusals.push(issue(
                        &record.id,
                        "final tombstone snapshot reconciliation mismatch",
                    ));
                }
                for principal in report.principals.values() {
                    if k::read_record_as(&db, principal, &record.id)
                        .await?
                        .is_some()
                    {
                        report
                            .refusals
                            .push(issue(&record.id, "tombstone visibility mismatch"));
                    }
                }
            }
        }
    }
    for id in invisible_attachments {
        report.excluded_invisible_in_v1 += 1;
        report.counted.push(issue(&id, "excluded_invisible_in_v1"));
        if verified_tombstones.contains(&id) {
            report.excluded_invisible_tombstones_verified += 1;
        }
    }
    for record in records
        .values()
        .filter(|r| r.id != V1_ROOT && r.deleted_at.is_some())
    {
        if !verified_tombstones.contains(&record.id) {
            report.excluded_deleted += 1;
            report.counted.push(issue(&record.id, "excluded_deleted"));
        }
    }
    if options.resume {
        let started = Instant::now();
        delta::reconcile(&db, &host, &mut source, &origin, true, &mut report).await?;
        phase(&mut report, "delta_removals", started);
    }
    if options.history || options.all {
        let history_started = Instant::now();
        // Preserve existing anchor identities, including source rows now
        // tombstoned or missing. Mapping them to a home/root would conflict
        // with their already retained history IDs.
        let imported_history_anchors: BTreeSet<String> = sqlx::query_scalar(
            "SELECT DISTINCT record_id FROM content_events WHERE type='kernel.import_state.v1' AND actor=?"
        ).bind(&host).fetch_all(db.pool()).await?.into_iter().collect();
        let mut history_homes = report.homes.clone();
        let durable_homes: Vec<(String,String)> = sqlx::query_as("SELECT json_extract(payload,'$.source_record_id'),record_id FROM content_events WHERE type='kernel.import_home.v1' AND actor=?")
            .bind(&host).fetch_all(db.pool()).await?;
        for (source_id, home) in durable_homes {
            if history_homes
                .insert(source_id, home.clone())
                .is_some_and(|previous| previous != home)
            {
                return Err("import history home mapping conflict".into());
            }
        }
        history::import(
            &mut source,
            &db,
            &host,
            &origin,
            history::Scope {
                imported: imported_history_anchors,
                selected: records.keys().cloned().collect(),
                homes: &history_homes,
                all: options.all,
            },
            &mut report.history,
        )
        .await?;
        #[cfg(feature = "v2-kernel-probe")]
        if let Some((id, count)) = sqlx::query_as::<_, (String, i64)>(
            "SELECT e.record_id,COUNT(*) FROM content_events e JOIN kernel_records r ON r.id=e.record_id WHERE e.type='kernel.legacy_recorded.v1' GROUP BY e.record_id ORDER BY COUNT(*) DESC,e.record_id LIMIT 1"
        ).fetch_optional(db.write_pool()).await? {
            if let Some((_, owner, _)) = expected.get(&id) {
                // A private-policy owner can be outside a Message's audience.
                // Optional timing must not turn that correct denial into an
                // import failure or use the sealed host to impersonate a reader.
                if k::read_record_as(&db, owner, &id).await?.is_some() {
                    let started = std::time::Instant::now();
                    let page = crate::mcp::kernel_v2::get_history(&db, owner, json!({"record_id":id,"limit":100})).await?;
                    report.history.busy_record_read = Some(history::HistoryTiming {
                        retained_events: count,
                        returned_events: page["events"].as_array().map_or(0, Vec::len),
                        get_history_ms: started.elapsed().as_secs_f64() * 1000.0,
                    });
                }
            }
        }
        phase(&mut report, "history", history_started);
    }
    let app_state_started = Instant::now();
    app_state::import(
        &mut source,
        &db,
        &host,
        &origin,
        &expected,
        &mut report.app_state,
    )
    .await?;
    phase(&mut report, "app_state", app_state_started);
    if !report.app_state.capture_complete {
        report.refusals.push(issue(
            "app_state",
            "incomplete app custody capture; cutover refused",
        ));
    }
    let verify_started = Instant::now();
    for (id, (home, owner, state)) in &expected {
        let view_reader: &String =
            if let Some(author) = state.message.as_ref().and_then(|m| m.author.as_ref()) {
                author
            } else if is_derived_record(&records[id]) {
                terminal_record(&records[id], &records, &bearers)
                    .and_then(|terminal| expected.get(&terminal.id))
                    .map(|(_, owner, _)| owner)
                    .unwrap_or(owner)
            } else {
                owner
            };
        let started = Instant::now();
        // A private policy can exclude even the original sender. Verify the
        // stored Message through the sealed host seam, then independently test
        // every ordinary principal below (including positive visibility).
        let sealed = if state.message.is_some() {
            Some(
                k::read_imported_snapshot_as(&db, &host, id)
                    .await?
                    .ok_or("imported Message snapshot missing")?,
            )
        } else {
            None
        };
        let view = if let Some(snapshot) = &sealed {
            snapshot.record.clone()
        } else {
            k::read_record_as(&db, view_reader, id)
                .await?
                .ok_or("imported record unreadable by owner")?
        };
        phase(&mut report, "verify.record_read", started);
        let started = Instant::now();
        let facets = if let Some(snapshot) = sealed {
            snapshot.facets
        } else {
            k::facets_as(&db, view_reader, id).await?
        };
        phase(&mut report, "verify.facets_read", started);
        let started = Instant::now();
        let record = &records[id];
        let provenance = if state.message.is_some() {
            let raw: String = sqlx::query_scalar("SELECT json_extract(payload,'$.legacy.payload') FROM content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' ORDER BY seq DESC LIMIT 1")
                .bind(id).fetch_one(db.pool()).await?;
            serde_json::from_str(&raw)?
        } else {
            snapshot_provenance_as(&db, view_reader, id)
                .await?
                .ok_or("snapshot provenance missing")?
        };
        phase(&mut report, "verify.provenance_read", started);
        // Owner disclosure follows the reader: for comments the stored
        // owner is compared directly, since the terminal owner reading
        // the thread is generally not the comment's author.
        let stored_owner: Option<String> =
            if is_derived_record(record) || record.v1_type == "Message" {
                sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id = ?")
                    .bind(id)
                    .fetch_optional(db.write_pool())
                    .await?
                    .flatten()
            } else {
                None
            };
        let owner_ok = if is_derived_record(record) || record.v1_type == "Message" {
            stored_owner.as_deref() == Some(owner.as_str())
        } else {
            view.owner_id.as_deref() == Some(owner.as_str())
        };
        let observed_message = if state.message.is_some() {
            let mut snapshot = db.pool().begin().await?;
            let observed = k::messaging::on(&mut snapshot, id).await?;
            snapshot.rollback().await?;
            observed
        } else {
            None
        };
        let mut matched = observed_message == state.message
            && provenance["lifecycle"] == serde_json::to_value(&record.lifecycle)?
            && provenance["original_home"] == serde_json::to_value(&record.home_id)?
            && provenance["original_owner"] == serde_json::to_value(&record.owner_id)?
            && provenance["owner_override"]
                == serde_json::to_value(
                    report.owner_overrides.iter().find(|o| &o.record_id == id),
                )?
            && provenance["created_at"] == record.created_at
            && provenance["updated_at"] == record.updated_at
            && view.home_id == *home
            && owner_ok
            && Some(&view.metadata) == state.metadata.as_ref()
            && view.body == state.body
            && view.archived == state.archived
            && view.fields == state.definition.as_ref().unwrap().fields
            && facets == state.facets;
        let visibility_started = Instant::now();
        let mut visibility_matches = true;
        for (account, other) in &report.principals {
            let expected_visible = v1_visible(
                record,
                account,
                &policies,
                &owner_accounts,
                &records,
                &bearers,
            );
            let visible = k::read_record_as(&db, other, id).await?.is_some();
            if state.message.is_some() {
                report.message_visibility_checks += 1;
                report.message_v2_visible_but_v1_hidden +=
                    usize::from(visible && !expected_visible);
                report.message_v1_visible_but_v2_denied +=
                    usize::from(expected_visible && !visible);
                if !expected_visible {
                    report.message_non_audience_checks += 1;
                    report.message_non_audience_leaks += usize::from(visible);
                }
            }
            let hidden_history = if state.message.is_some() && !expected_visible {
                k::history_as(&db, other, id).await?.is_empty()
            } else {
                true
            };
            if visible != expected_visible || !hidden_history {
                visibility_matches = false;
                matched = false;
                report
                    .refusals
                    .push(issue(id, "policy visibility mismatch"));
            }
        }
        if state.message.is_some() && report.owner_overrides.iter().any(|o| &o.record_id == id) {
            report
                .message_owner_override_visibility
                .insert(id.clone(), visibility_matches);
        }
        phase(&mut report, "verify.visibility", visibility_started);
        if matched {
            report.metadata_coverage.persistence += 1;
            report.metadata_coverage.last_activity_at += 1;
            report.metadata_coverage.maturity += usize::from(record.maturity.is_some());
            if record.v1_type == "Document" && record.kind.as_deref() == Some("note") {
                report.metadata_coverage.note_summary +=
                    usize::from(record.summary.as_ref().is_some_and(|s| !s.is_empty()));
                report.metadata_coverage.note_lifecycle += usize::from(record.lifecycle.is_some());
            }
            report.verified += 1;
            report.verified_ids.push(id.clone());
        } else {
            report
                .refusals
                .push(issue(id, "kernel read reconciliation mismatch"));
        }
    }
    refusal_breakdown::populate(
        &mut report,
        &records,
        &bearers,
        &expected.keys().map(String::as_str).collect(),
    );
    for refusal in &report.refusals {
        if let Some(record) = records.get(&refusal.id).filter(|r| is_derived_record(r)) {
            let category = if record.v1_type == "Annotation" {
                "annotations"
            } else {
                "attachments"
            };
            *report
                .derived_refused
                .entry(format!("{category}: {}", refusal.reason))
                .or_default() += 1;
        }
    }
    phase(&mut report, "verify", verify_started);
    let comments_seconds = report
        .phase_seconds
        .get("comments.records")
        .copied()
        .unwrap_or_default()
        + report
            .phase_seconds
            .get("comments.anchors")
            .copied()
            .unwrap_or_default();
    report
        .phase_seconds
        .insert("comments".into(), comments_seconds);
    sqlx::query("ROLLBACK").execute(&mut source).await?;
    phase(&mut report, "total", total_started);
    Ok(report)
}

#[cfg(test)]
mod tests;
