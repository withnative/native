//! Canonical storage interchange v1, revision 2.
//!
//! The wire representation is intentionally logical rather than a SQLite file
//! copy: every durable table is an ordered section, every SQLite value carries
//! an explicit storage-class tag, and integrity covers the canonical compact
//! JSON bytes. Import builds and validates a fresh database before publishing
//! it at the requested path, so malformed input cannot partially mutate a
//! usable destination.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Row as _, Sqlite, TypeInfo as _, ValueRef as _};

use crate::db::{
    apply_schema, open_database_at, open_existing_database_at, Db, CURRENT_ENGINE_SCHEMA_VERSION,
};
use crate::{Error, Result};

pub const FORMAT: &str = "native.canonical-interchange.v1";
pub const REVISION: u64 = 2;
const LEGACY_REVISION: u64 = 1;
pub const SECTION_FORMAT: &str = "native.canonical-interchange.section.v1";
pub const LOGICAL_CONTRACT: &str = "native.logical.v1";

const SOURCE_PROFILE_ID: &str = "sqlite-local";
const SOURCE_PROFILE_REVISION: u64 = 2;
const ENCODING: &str = "utf-8-json";
const ORDERING: &str = "sections-by-contract;rows-by-primary-key;columns-by-schema";

// Explicit allow-list: internal, derived, and transient SQLite state never
// becomes part of the interchange contract. Keep event logs before their
// projections to make the authority boundary apparent to readers.
// `engine_migration_drills` is deliberately absent: it is engine-local
// promotion-drill bookkeeping about one physical file's migration history,
// so a canonically rebuilt destination honestly starts without it.
const SECTION_NAMES: &[&str] = &[
    "content_events",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "policy_events",
    "meta_events",
    "control_events",
    "awareness_events",
    "notification_candidate_events",
    "relationship_events",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "relationship_federation_events",
    "relationship_federation_quarantine",
    "content_event_sources",
    "replicated_message_provenance",
    "destination_message_ingest",
    "replicated_message_references",
    "provenance_interaction_receipts",
    "provenance_action_attestations",
    "provenance_action_events",
    "provenance_attestation_validity_events",
    "provenance_action_outputs",
    "webhook_endpoints",
    "webhook_credentials",
    "webhook_deliveries",
    "records",
    "record_policies",
    "policy_entries",
    "links",
    "relationships",
    "relationship_endpoints",
    "relationship_legacy_links",
    "relationship_assertion_heads",
    "relationship_endpoint_activity",
    "message_audience_state",
    "message_audiences",
    "message_origin_state",
    "message_origin_principals",
    "message_conversations",
    "awareness_command_intents",
    "human_message_awareness",
    "agent_message_dispositions",
    "awareness_event_evidence",
    "message_inbox_routing",
    "message_preferences",
    "member_destinations",
    "message_mentions",
    "notification_candidates",
    "module_releases",
    "module_release_imports",
    "artifact_source_attestations",
    "artifact_inputs",
    "artifact_module_grants",
    "annotation_targets",
    "attribution_targets",
    "attribution_assertions",
    "attribution_evidence",
    "attribution_retractions",
    "facet_values",
    "facet_observations",
    "semantic_units",
    "unit_revisions",
    "unit_heads",
    "occurrences",
    "freshness_command_results",
    "freshness_runtime_command_results",
    "receipts",
    "receipt_provenance",
    "dependencies",
    "dependency_assessments",
    "receipt_comparisons",
    "receipt_uncertainty_lineage",
    "reconciliations",
    "unit_supersessions",
    "dependency_audits",
    "canvas_objects",
    "canvas_batches",
    "bindings",
    "binding_audit",
    "external_observations",
    "database_identity",
    "database_identity_audit",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "read_log_calls",
    "read_log_touches",
    "member_contexts",
    "instruction_bindings",
    "onboarding_programmes",
    "onboarding_programme_sources",
    "member_obligations",
    "member_obligation_progress",
    "seeded_instruction_sources",
    "control_event_applications",
    "storage_portability_policy",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    manifest: Manifest,
    sections: Vec<Section>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    revision: u64,
    source_profile: ProfileRevision,
    source_engine_schema: i64,
    logical_contract: String,
    encoding: String,
    ordering: String,
    sections: Vec<SectionDescriptor>,
    content_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRevision {
    id: String,
    revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SectionDescriptor {
    name: String,
    revision: u64,
    row_count: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Section {
    pub(crate) format: String,
    pub(crate) revision: u64,
    pub(crate) name: String,
    pub(crate) columns: Vec<Column>,
    pub(crate) primary_key: Vec<String>,
    pub(crate) rows: Vec<Vec<Cell>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Column {
    pub(crate) name: String,
    pub(crate) declared_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub(crate) enum Cell {
    Null,
    Integer(i64),
    /// Exact finite IEEE-754 bits as 16 lowercase hexadecimal digits.
    Real(String),
    Text(String),
    /// Standard padded base64.
    Blob(String),
}

/// An integrity-checked interchange document. Sibling backends can inspect
/// immutable sections, but cannot construct or mutate a value that bypasses
/// the canonical validator.
pub(crate) struct ValidatedInterchange(Bundle);

#[cfg(feature = "postgres")]
impl ValidatedInterchange {
    pub(crate) fn sections(&self) -> &[Section] {
        &self.0.sections
    }

    pub(crate) fn section(&self, name: &str) -> Option<&Section> {
        self.0.sections.iter().find(|section| section.name == name)
    }

    pub(crate) fn source_profile(&self) -> (&str, u64) {
        (
            &self.0.manifest.source_profile.id,
            self.0.manifest.source_profile.revision,
        )
    }
}

/// Parse and fully validate canonical bytes for a sibling storage backend.
pub(crate) fn validate_canonical_interchange(bytes: &[u8]) -> Result<ValidatedInterchange> {
    let mut bundle: Bundle = serde_json::from_slice(bytes)
        .map_err(|error| Error::engine(format!("invalid canonical interchange JSON: {error}")))?;
    if bundle.manifest.revision == LEGACY_REVISION {
        let legacy_names = SECTION_NAMES
            .iter()
            .copied()
            .filter(|name| {
                !matches!(
                    *name,
                    "content_event_causal_frontier" | "content_event_causal_cutover"
                )
            })
            .collect::<Vec<_>>();
        validate_bundle_revision(&bundle, &legacy_names, LEGACY_REVISION, 45)?;
        upgrade_legacy_bundle(&mut bundle)?;
    }
    validate_bundle(&bundle)?;
    Ok(ValidatedInterchange(bundle))
}

fn upgrade_legacy_bundle(bundle: &mut Bundle) -> Result<()> {
    let events = bundle
        .sections
        .iter_mut()
        .find(|section| section.name == "content_events")
        .ok_or_else(|| Error::engine("legacy interchange is missing content_events"))?;
    let created_at = events
        .columns
        .iter()
        .position(|column| column.name == "created_at")
        .ok_or_else(|| Error::engine("legacy content_events is missing created_at"))?;
    let seq = events
        .columns
        .iter()
        .position(|column| column.name == "seq")
        .ok_or_else(|| Error::engine("legacy content_events is missing seq"))?;
    let last_legacy_local_seq = events
        .rows
        .iter()
        .filter_map(|row| match row.get(seq) {
            Some(Cell::Integer(value)) => Some(*value),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    events.columns.insert(
        created_at,
        Column {
            name: "causal_envelope_version".into(),
            declared_type: "INTEGER".into(),
        },
    );
    events.columns.insert(
        created_at + 1,
        Column {
            name: "causal_status".into(),
            declared_type: "TEXT".into(),
        },
    );
    for row in &mut events.rows {
        row.insert(created_at, Cell::Integer(1));
        row.insert(created_at + 1, Cell::Text("legacy_unknown".into()));
    }

    let frontier = Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: "content_event_causal_frontier".into(),
        columns: vec![
            Column {
                name: "event_id".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "parent_event_id".into(),
                declared_type: "TEXT".into(),
            },
        ],
        primary_key: vec!["event_id".into(), "parent_event_id".into()],
        rows: Vec::new(),
    };
    let cutover = Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: "content_event_causal_cutover".into(),
        columns: vec![
            Column {
                name: "singleton".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "last_legacy_local_seq".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "cutover_at".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "from_engine_schema".into(),
                declared_type: "INTEGER".into(),
            },
        ],
        primary_key: vec!["singleton".into()],
        rows: vec![vec![
            Cell::Integer(1),
            Cell::Integer(last_legacy_local_seq),
            Cell::Text("1970-01-01T00:00:00.000Z".into()),
            Cell::Integer(45),
        ]],
    };
    bundle.sections.insert(1, frontier);
    bundle.sections.insert(2, cutover);
    for section in &mut bundle.sections {
        section.revision = REVISION;
    }
    bundle.manifest.revision = REVISION;
    bundle.manifest.sections = bundle
        .sections
        .iter()
        .map(|section| {
            Ok(SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    bundle.manifest.content_sha256 = sha256_json(&bundle.sections)?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct TableColumn {
    name: String,
    #[sqlx(rename = "type")]
    declared_type: String,
    pk: i64,
}

/// Export a deterministic canonical interchange document through the public
/// database seam. The result is compact UTF-8 JSON.
pub async fn export_canonical_interchange(db: &Db) -> Result<Vec<u8>> {
    let mut tx = db.write_pool().begin().await?;
    reject_nonportable_state(&mut tx).await?;
    let mut sections = Vec::with_capacity(SECTION_NAMES.len());
    for &name in SECTION_NAMES {
        sections.push(export_section(&mut tx, name).await?);
    }
    tx.commit().await?;

    let descriptors = sections
        .iter()
        .map(|section| {
            Ok(SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let content_sha256 = sha256_json(&sections)?;
    let bundle = Bundle {
        manifest: Manifest {
            format: FORMAT.into(),
            revision: REVISION,
            source_profile: ProfileRevision {
                id: SOURCE_PROFILE_ID.into(),
                revision: SOURCE_PROFILE_REVISION,
            },
            source_engine_schema: CURRENT_ENGINE_SCHEMA_VERSION,
            logical_contract: LOGICAL_CONTRACT.into(),
            encoding: ENCODING.into(),
            ordering: ORDERING.into(),
            sections: descriptors,
            content_sha256,
        },
        sections,
    };
    Ok(serde_json::to_vec(&bundle)?)
}

/// Validate and import a canonical document into a new SQLite database.
///
/// The destination must not exist. All parsing and portable schema validation
/// happen before a staging database is created; database-level validation and
/// full conformance run before the staged file is atomically published.
pub async fn import_canonical_interchange(bytes: &[u8], destination: &Path) -> Result<Db> {
    if path_is_occupied(destination) {
        return Err(Error::engine(format!(
            "canonical interchange destination already exists: {}",
            destination.display()
        )));
    }
    let validated = validate_canonical_interchange(bytes)?;
    let bundle = &validated.0;

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let staging_dir = tempfile::Builder::new()
        .prefix(".native-interchange-")
        .tempdir_in(parent)?;
    let staging_path = staging_dir.path().join("import.db");
    let staging = open_database_at(&staging_path).await?;
    apply_schema(&staging).await?;

    let import_result = async {
        let mut tx = staging.write_pool().begin().await?;
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await?;
        for section in &bundle.sections {
            validate_destination_section(&mut tx, section).await?;
            // A strict policy becomes active as soon as its singleton row is
            // visible. Defer that row until after conformance's rollback-only
            // mutation probes, then validate the exact catalog pin before the
            // staged file can be published.
            if section.name == "storage_portability_policy" {
                continue;
            }
            if section.name == "content_event_causal_cutover" {
                sqlx::query("DELETE FROM content_event_causal_cutover")
                    .execute(&mut *tx)
                    .await?;
            }
            import_section(&mut tx, section).await?;
        }
        crate::relationship::initialize_receiver_local_state_after_import_in(&mut tx).await?;
        tx.commit().await?;

        let report = crate::conformance::run_conformance(&staging).await;
        if !report.ok {
            let failures = report
                .checks
                .iter()
                .filter(|check| !check.ok)
                .map(|check| format!("{}: {}", check.check, check.violations.join("; ")))
                .collect::<Vec<_>>()
                .join(" | ");
            return Err(Error::engine(format!(
                "canonical interchange failed conformance: {failures}"
            )));
        }
        let policy_section = bundle
            .sections
            .iter()
            .find(|section| section.name == "storage_portability_policy")
            .expect("validated canonical policy section");
        let mut policy_tx = staging.write_pool().begin().await?;
        import_section(&mut policy_tx, policy_section).await?;
        policy_tx.commit().await?;
        crate::storage_profile::portability_policy_report(&staging).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(staging.write_pool())
            .await?;
        Result::<()>::Ok(())
    }
    .await;

    if let Err(error) = import_result {
        staging.close().await;
        return Err(error);
    }
    staging.close().await;

    if path_is_occupied(destination) {
        return Err(Error::engine(format!(
            "canonical interchange destination appeared during import: {}",
            destination.display()
        )));
    }
    // The staging directory is deliberately beside the destination, so a hard
    // link is an atomic, same-filesystem, no-clobber publish. Dropping the temp
    // directory removes the staging name while the destination link remains.
    std::fs::hard_link(&staging_path, destination)?;
    open_existing_database_at(destination).await
}

async fn reject_nonportable_state(tx: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
    let embeddings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM embeddings")
        .fetch_one(&mut **tx)
        .await?;
    if embeddings != 0 {
        return Err(Error::engine(
            "canonical interchange cannot export profile-specific embeddings",
        ));
    }
    let external_blobs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE storage_tier <> 'inline'")
            .fetch_one(&mut **tx)
            .await?;
    if external_blobs != 0 {
        return Err(Error::engine(
            "canonical interchange cannot export external blob references",
        ));
    }
    Ok(())
}

fn path_is_occupied(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

async fn table_columns<'e, E>(executor: E, table: &str) -> Result<Vec<TableColumn>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let sql = format!("PRAGMA table_info({})", quote_identifier(table));
    Ok(sqlx::query_as::<_, TableColumn>(&sql)
        .fetch_all(executor)
        .await?)
}

async fn export_section(tx: &mut sqlx::Transaction<'_, Sqlite>, name: &str) -> Result<Section> {
    let table_info = table_columns(&mut **tx, name).await?;
    if table_info.is_empty() {
        return Err(Error::engine(format!(
            "canonical interchange table is missing: {name}"
        )));
    }
    let columns = table_info
        .iter()
        .map(|column| Column {
            name: column.name.clone(),
            declared_type: column.declared_type.clone(),
        })
        .collect::<Vec<_>>();
    let mut primary_key = table_info
        .iter()
        .filter(|column| column.pk > 0)
        .map(|column| (column.pk, column.name.clone()))
        .collect::<Vec<_>>();
    primary_key.sort_by_key(|(position, _)| *position);
    let primary_key = primary_key
        .into_iter()
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
    if primary_key.is_empty() {
        return Err(Error::engine(format!(
            "canonical interchange table has no primary key: {name}"
        )));
    }

    let select_columns = columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(", ");
    let order = primary_key
        .iter()
        .map(|column| quote_identifier(column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {select_columns} FROM {} ORDER BY {order}",
        quote_identifier(name)
    );
    let result_rows = sqlx::query(&sql).fetch_all(&mut **tx).await?;
    let mut rows = Vec::with_capacity(result_rows.len());
    for row in result_rows {
        let mut cells = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let raw = row.try_get_raw(index)?;
            if raw.is_null() {
                cells.push(Cell::Null);
                continue;
            }
            let cell = match raw.type_info().name() {
                "INTEGER" => Cell::Integer(row.try_get(index)?),
                "REAL" => {
                    let value: f64 = row.try_get(index)?;
                    if !value.is_finite() {
                        return Err(Error::engine(format!(
                            "canonical interchange rejects non-finite REAL in {name}"
                        )));
                    }
                    Cell::Real(format!("{:016x}", value.to_bits()))
                }
                "TEXT" => Cell::Text(row.try_get(index)?),
                "BLOB" => Cell::Blob(
                    base64::engine::general_purpose::STANDARD
                        .encode(row.try_get::<Vec<u8>, _>(index)?),
                ),
                storage_class => {
                    return Err(Error::engine(format!(
                        "unsupported SQLite storage class {storage_class} in {name}"
                    )))
                }
            };
            cells.push(cell);
        }
        rows.push(cells);
    }

    Ok(Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: name.into(),
        columns,
        primary_key,
        rows,
    })
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    ensure(
        matches!(
            bundle.manifest.source_engine_schema,
            45 | CURRENT_ENGINE_SCHEMA_VERSION
        ),
        "unsupported source engine schema revision",
    )?;
    validate_bundle_revision(
        bundle,
        SECTION_NAMES,
        REVISION,
        bundle.manifest.source_engine_schema,
    )
}

fn validate_bundle_revision(
    bundle: &Bundle,
    section_names: &[&str],
    revision: u64,
    source_engine_schema: i64,
) -> Result<()> {
    let manifest = &bundle.manifest;
    ensure(manifest.format == FORMAT, "unsupported interchange format")?;
    ensure(
        manifest.revision == revision,
        "unsupported interchange revision",
    )?;
    ensure(
        !manifest.source_profile.id.is_empty() && manifest.source_profile.revision > 0,
        "invalid source storage profile revision",
    )?;
    ensure(
        manifest.source_engine_schema == source_engine_schema,
        "unsupported source engine schema revision",
    )?;
    ensure(
        manifest.logical_contract == LOGICAL_CONTRACT,
        "unsupported logical contract",
    )?;
    ensure(manifest.encoding == ENCODING, "unsupported encoding")?;
    ensure(manifest.ordering == ORDERING, "unsupported ordering")?;
    ensure(
        manifest.sections.len() == section_names.len()
            && bundle.sections.len() == section_names.len(),
        "canonical interchange section inventory is incomplete",
    )?;

    for (index, expected_name) in section_names.iter().enumerate() {
        let descriptor = &manifest.sections[index];
        let section = &bundle.sections[index];
        ensure(
            descriptor.name == *expected_name && section.name == *expected_name,
            "canonical interchange section order or name is invalid",
        )?;
        ensure(
            descriptor.revision == revision
                && section.revision == revision
                && section.format == SECTION_FORMAT,
            "unsupported canonical section revision",
        )?;
        ensure(
            descriptor.row_count == section.rows.len() as u64,
            "canonical section row count does not match manifest",
        )?;
        ensure(
            descriptor.sha256 == sha256_json(section)?,
            "canonical section integrity check failed",
        )?;
        validate_section_shape(section)?;
    }
    ensure(
        manifest.content_sha256 == sha256_json(&bundle.sections)?,
        "canonical interchange content integrity check failed",
    )?;
    Ok(())
}

fn validate_section_shape(section: &Section) -> Result<()> {
    ensure(
        !section.columns.is_empty(),
        "canonical section has no columns",
    )?;
    ensure(
        !section.primary_key.is_empty(),
        "canonical section has no primary key",
    )?;
    let names = section
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure(
        section
            .columns
            .iter()
            .all(|column| !column.name.is_empty() && !column.declared_type.is_empty()),
        "canonical section contains an empty column name or type",
    )?;
    ensure(
        names.len() == section.columns.len(),
        "canonical section contains duplicate columns",
    )?;
    ensure(
        section
            .primary_key
            .iter()
            .all(|column| names.contains(column.as_str())),
        "canonical section primary key references an unknown column",
    )?;
    ensure(
        section.primary_key.iter().collect::<BTreeSet<_>>().len() == section.primary_key.len(),
        "canonical section contains duplicate primary-key columns",
    )?;
    ensure(
        section
            .rows
            .iter()
            .all(|row| row.len() == section.columns.len()),
        "canonical section row width does not match columns",
    )?;
    for row in &section.rows {
        for cell in row {
            validate_cell(cell)?;
        }
    }
    let primary_key_indexes = section
        .primary_key
        .iter()
        .map(|name| {
            section
                .columns
                .iter()
                .position(|column| &column.name == name)
                .expect("validated primary-key column")
        })
        .collect::<Vec<_>>();
    for adjacent in section.rows.windows(2) {
        match compare_primary_keys(&adjacent[0], &adjacent[1], &primary_key_indexes) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(Error::engine(
                    "canonical section contains duplicate primary keys",
                ));
            }
            Ordering::Greater => {
                return Err(Error::engine(
                    "canonical section rows are not in strictly increasing primary-key order",
                ));
            }
        }
    }
    Ok(())
}

fn compare_primary_keys(left: &[Cell], right: &[Cell], indexes: &[usize]) -> Ordering {
    indexes
        .iter()
        .map(|index| compare_sqlite_values(&left[*index], &right[*index]))
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

/// Compare canonical cells the way SQLite's default `ORDER BY` does: NULL,
/// numeric values, TEXT with BINARY collation, then BLOB. INTEGER and REAL
/// share one numeric domain, so this must not compare their wire tags or cast
/// an i64 to f64 (which would collapse distinct values beyond 2^53).
fn compare_sqlite_values(left: &Cell, right: &Cell) -> Ordering {
    match (left, right) {
        (Cell::Null, Cell::Null) => Ordering::Equal,
        (Cell::Null, _) => Ordering::Less,
        (_, Cell::Null) => Ordering::Greater,
        (Cell::Integer(left), Cell::Integer(right)) => left.cmp(right),
        (Cell::Real(left), Cell::Real(right)) => canonical_real(left)
            .partial_cmp(&canonical_real(right))
            .expect("canonical REAL values are finite"),
        (Cell::Integer(left), Cell::Real(right)) => {
            compare_integer_real(*left, canonical_real(right))
        }
        (Cell::Real(left), Cell::Integer(right)) => {
            compare_integer_real(*right, canonical_real(left)).reverse()
        }
        (Cell::Integer(_) | Cell::Real(_), Cell::Text(_) | Cell::Blob(_)) => Ordering::Less,
        (Cell::Text(_) | Cell::Blob(_), Cell::Integer(_) | Cell::Real(_)) => Ordering::Greater,
        (Cell::Text(left), Cell::Text(right)) => left.as_bytes().cmp(right.as_bytes()),
        (Cell::Text(_), Cell::Blob(_)) => Ordering::Less,
        (Cell::Blob(_), Cell::Text(_)) => Ordering::Greater,
        (Cell::Blob(left), Cell::Blob(right)) => canonical_blob(left).cmp(&canonical_blob(right)),
    }
}

fn canonical_real(bits: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(bits, 16).expect("validated canonical REAL bits"))
}

fn canonical_blob(encoded: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("validated canonical BLOB")
}

// This follows SQLite's exact integer/REAL comparison at the i64 boundaries.
// In particular, `i64 as f64` is not precise enough for primary-key ordering.
fn compare_integer_real(integer: i64, real: f64) -> Ordering {
    const I64_UPPER_BOUND: f64 = 9_223_372_036_854_775_808.0;

    if real < i64::MIN as f64 {
        return Ordering::Greater;
    }
    if real >= I64_UPPER_BOUND {
        return Ordering::Less;
    }

    let truncated = real as i64;
    match integer.cmp(&truncated) {
        Ordering::Equal => (integer as f64)
            .partial_cmp(&real)
            .expect("canonical REAL values are finite"),
        ordering => ordering,
    }
}

fn validate_cell(cell: &Cell) -> Result<()> {
    match cell {
        Cell::Real(bits) => {
            ensure(
                bits.len() == 16
                    && bits
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "canonical REAL must be 16 lowercase hexadecimal digits",
            )?;
            let bits = u64::from_str_radix(bits, 16)
                .map_err(|_| Error::engine("canonical REAL has invalid bits"))?;
            ensure(
                f64::from_bits(bits).is_finite(),
                "canonical REAL must be finite",
            )
        }
        Cell::Blob(encoded) => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| Error::engine("canonical BLOB is not valid padded base64"))?;
            ensure(
                base64::engine::general_purpose::STANDARD.encode(decoded) == *encoded,
                "canonical BLOB is not canonical padded base64",
            )
        }
        Cell::Null | Cell::Integer(_) | Cell::Text(_) => Ok(()),
    }
}

async fn validate_destination_section(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    section: &Section,
) -> Result<()> {
    let columns = table_columns(&mut **tx, &section.name).await?;
    let expected_columns = columns
        .iter()
        .map(|column| Column {
            name: column.name.clone(),
            declared_type: column.declared_type.clone(),
        })
        .collect::<Vec<_>>();
    ensure(
        section.columns == expected_columns,
        "canonical section columns do not match the destination schema",
    )?;
    let mut primary_key = columns
        .iter()
        .filter(|column| column.pk > 0)
        .map(|column| (column.pk, column.name.clone()))
        .collect::<Vec<_>>();
    primary_key.sort_by_key(|(position, _)| *position);
    let primary_key = primary_key
        .into_iter()
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
    ensure(
        section.primary_key == primary_key,
        "canonical section primary key does not match the destination schema",
    )
}

async fn import_section(tx: &mut sqlx::Transaction<'_, Sqlite>, section: &Section) -> Result<()> {
    let columns = section
        .columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(", ");
    for row in &section.rows {
        let mut query = QueryBuilder::<Sqlite>::new(format!(
            "INSERT INTO {} ({columns}) ",
            quote_identifier(&section.name)
        ));
        query.push_values(std::iter::once(row), |mut separated, cells| {
            for cell in cells {
                match cell {
                    Cell::Null => separated.push_bind(None::<i64>),
                    Cell::Integer(value) => separated.push_bind(*value),
                    Cell::Real(bits) => separated.push_bind(f64::from_bits(
                        u64::from_str_radix(bits, 16).expect("validated REAL bits"),
                    )),
                    Cell::Text(value) => separated.push_bind(value.clone()),
                    Cell::Blob(value) => separated.push_bind(
                        base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .expect("validated BLOB"),
                    ),
                };
            }
        });
        query.build().execute(&mut **tx).await?;
    }
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    condition
        .then_some(())
        .ok_or_else(|| Error::engine(message))
}

fn sha256_json(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refresh_bundle_integrity(bundle: &mut Bundle, section_index: usize) {
        bundle.manifest.sections[section_index].row_count =
            bundle.sections[section_index].rows.len() as u64;
        bundle.manifest.sections[section_index].sha256 =
            sha256_json(&bundle.sections[section_index]).unwrap();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
    }

    fn downgrade_to_revision_1(mut bundle: Bundle) -> Bundle {
        for name in [
            "content_event_causal_cutover",
            "content_event_causal_frontier",
        ] {
            let index = bundle
                .sections
                .iter()
                .position(|section| section.name == name)
                .unwrap();
            bundle.sections.remove(index);
        }
        let events = bundle
            .sections
            .iter_mut()
            .find(|section| section.name == "content_events")
            .unwrap();
        let mut causal_columns = events
            .columns
            .iter()
            .enumerate()
            .filter_map(|(index, column)| {
                matches!(
                    column.name.as_str(),
                    "causal_envelope_version" | "causal_status"
                )
                .then_some(index)
            })
            .collect::<Vec<_>>();
        causal_columns.sort_unstable_by(|left, right| right.cmp(left));
        for index in causal_columns {
            events.columns.remove(index);
            for row in &mut events.rows {
                row.remove(index);
            }
        }
        for section in &mut bundle.sections {
            section.revision = LEGACY_REVISION;
        }
        bundle.manifest.revision = LEGACY_REVISION;
        bundle.manifest.source_profile.revision = 1;
        bundle.manifest.source_engine_schema = 45;
        bundle.manifest.sections = bundle
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                revision: LEGACY_REVISION,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section).unwrap(),
            })
            .collect();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
        bundle
    }

    async fn populated_provenance_bundle(source: &Db) -> (Bundle, String, String) {
        let origin = crate::identity::database_id(source).await.unwrap();
        let arguments = serde_json::json!({
            "text":"must remain digest-only",
            "idempotency_key":"portable-command"
        });
        let scope = crate::provenance::verified_action_scope("interchange_fixture", &arguments);
        let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("host-ui");
        let token = issuer.issue("local", &scope, 60).unwrap();
        let caller = crate::mcp::Caller::local()
            .with_provenance_interaction_token(&issuer, &token, &scope)
            .unwrap();
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "interchange_fixture",
            &arguments,
            None,
        );
        dispatch
            .scope(crate::store::append(
                source,
                crate::store::AppendSpec {
                    record_id: "1a7e4000-0000-4000-8000-000000000001".into(),
                    event_type: "record.created".into(),
                    payload: serde_json::json!({
                        "type":"Document","kind":"note","name":"portable provenance"
                    }),
                    actor: Some("local".into()),
                },
            ))
            .await
            .unwrap();
        let attestation_id = dispatch.receipt_ids().pop().unwrap();
        let bundle =
            serde_json::from_slice(&export_canonical_interchange(source).await.unwrap()).unwrap();
        (bundle, attestation_id, origin)
    }

    fn key_section(rows: Vec<Vec<Cell>>, primary_key: &[&str]) -> Section {
        Section {
            format: SECTION_FORMAT.into(),
            revision: REVISION,
            name: "ordering_test".into(),
            columns: vec![
                Column {
                    name: "first".into(),
                    declared_type: "BLOB".into(),
                },
                Column {
                    name: "second".into(),
                    declared_type: "BLOB".into(),
                },
            ],
            primary_key: primary_key.iter().map(|name| (*name).into()).collect(),
            rows,
        }
    }

    fn real(value: f64) -> Cell {
        Cell::Real(format!("{:016x}", value.to_bits()))
    }

    fn cell_text(cell: &Cell) -> Option<&str> {
        match cell {
            Cell::Text(value) => Some(value),
            _ => None,
        }
    }

    fn cell_integer(cell: &Cell) -> Option<i64> {
        match cell {
            Cell::Integer(value) => Some(*value),
            _ => None,
        }
    }

    fn assert_protocol_inventory_tracks_section_names() {
        assert_eq!(SECTION_NAMES.len(), 97);
        for (label, source) in [
            (
                "manifest",
                include_str!("../protocol/storage-portability/v1/interchange/manifest.schema.json"),
            ),
            (
                "bundle",
                include_str!("../protocol/storage-portability/v1/interchange/bundle.schema.json"),
            ),
        ] {
            let schema: serde_json::Value = serde_json::from_str(source).unwrap();
            let sections = &schema["properties"]["sections"];
            assert_eq!(
                sections["minItems"],
                serde_json::json!(SECTION_NAMES.len()),
                "{label} schema minimum section count drifted"
            );
            assert_eq!(
                sections["maxItems"],
                serde_json::json!(SECTION_NAMES.len()),
                "{label} schema maximum section count drifted"
            );
        }

        let readme = include_str!("../protocol/storage-portability/v1/interchange/README.md");
        let inventory = readme
            .split_once("## Section inventory")
            .unwrap()
            .1
            .split_once("```text\n")
            .unwrap()
            .1
            .split_once("\n```")
            .unwrap()
            .0;
        let documented = inventory.lines().collect::<Vec<_>>();
        assert_eq!(documented.as_slice(), SECTION_NAMES);
    }

    #[test]
    fn strict_cells_reject_noncanonical_encodings() {
        assert_protocol_inventory_tracks_section_names();
        assert!(validate_cell(&Cell::Real("3ff0000000000000".into())).is_ok());
        assert!(validate_cell(&Cell::Real("3FF0000000000000".into())).is_err());
        assert!(validate_cell(&Cell::Blob("AA==".into())).is_ok());
        assert!(validate_cell(&Cell::Blob("AA".into())).is_err());
    }

    #[tokio::test]
    async fn revision_1_upgrade_is_legacy_unknown_with_an_exact_cutover_and_no_edges() {
        let source = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id":"1a7e4000-0000-4000-8000-000000000046",
                "type":"Document",
                "kind":"note",
                "name":"legacy interchange"
            }),
        )
        .await
        .unwrap();
        let current: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();
        let legacy = downgrade_to_revision_1(current);
        let legacy_event_count = legacy
            .sections
            .iter()
            .find(|section| section.name == "content_events")
            .unwrap()
            .rows
            .len() as i64;

        let upgraded = validate_canonical_interchange(&serde_json::to_vec(&legacy).unwrap())
            .unwrap()
            .0;
        assert_eq!(upgraded.manifest.revision, REVISION);
        let events = upgraded
            .sections
            .iter()
            .find(|section| section.name == "content_events")
            .unwrap();
        let status = events
            .columns
            .iter()
            .position(|column| column.name == "causal_status")
            .unwrap();
        assert!(events
            .rows
            .iter()
            .all(|row| cell_text(&row[status]) == Some("legacy_unknown")));
        let frontier = upgraded
            .sections
            .iter()
            .find(|section| section.name == "content_event_causal_frontier")
            .unwrap();
        assert!(frontier.rows.is_empty());
        let cutover = upgraded
            .sections
            .iter()
            .find(|section| section.name == "content_event_causal_cutover")
            .unwrap();
        assert_eq!(cell_integer(&cutover.rows[0][1]), Some(legacy_event_count));
        assert_eq!(cell_integer(&cutover.rows[0][3]), Some(45));
    }

    #[tokio::test]
    async fn revision_2_round_trip_preserves_causal_sections_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id":"1a7e4000-0000-4000-8000-000000000047",
                "type":"Document",
                "kind":"note",
                "name":"causal round trip"
            }),
        )
        .await
        .unwrap();
        let bytes = export_canonical_interchange(&source).await.unwrap();
        let bundle: Bundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bundle.manifest.revision, REVISION);
        assert_eq!(bundle.sections[1].name, "content_event_causal_frontier");
        assert_eq!(bundle.sections[2].name, "content_event_causal_cutover");
        assert!(!bundle.sections[1].rows.is_empty());

        let destination = temp.path().join("destination.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        let source_edges: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_id,parent_event_id FROM content_event_causal_frontier
              ORDER BY event_id,parent_event_id",
        )
        .fetch_all(source.write_pool())
        .await
        .unwrap();
        let imported_edges: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_id,parent_event_id FROM content_event_causal_frontier
              ORDER BY event_id,parent_event_id",
        )
        .fetch_all(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(imported_edges, source_edges);
        let source_cutover: (i64, String, Option<i64>) = sqlx::query_as(
            "SELECT last_legacy_local_seq,cutover_at,from_engine_schema
               FROM content_event_causal_cutover WHERE singleton=1",
        )
        .fetch_one(source.write_pool())
        .await
        .unwrap();
        let imported_cutover: (i64, String, Option<i64>) = sqlx::query_as(
            "SELECT last_legacy_local_seq,cutover_at,from_engine_schema
               FROM content_event_causal_cutover WHERE singleton=1",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(imported_cutover, source_cutover);
        imported.close().await;
        source.close().await;
    }

    #[test]
    fn primary_key_order_uses_exact_sqlite_storage_class_semantics() {
        let section = key_section(
            vec![
                vec![Cell::Null, Cell::Null],
                vec![Cell::Integer(-1), Cell::Null],
                vec![real(-0.5), Cell::Null],
                vec![Cell::Integer(0), Cell::Null],
                vec![Cell::Integer(9_007_199_254_740_991), Cell::Null],
                vec![real(9_007_199_254_740_992.0), Cell::Null],
                vec![Cell::Integer(9_007_199_254_740_993), Cell::Null],
                vec![Cell::Integer(i64::MAX), Cell::Null],
                vec![real(9_223_372_036_854_775_808.0), Cell::Null],
                vec![Cell::Text("A".into()), Cell::Null],
                vec![Cell::Text("é".into()), Cell::Null],
                vec![Cell::Blob("AA==".into()), Cell::Null],
                vec![Cell::Blob("AQ==".into()), Cell::Null],
            ],
            &["first"],
        );
        validate_section_shape(&section).unwrap();

        let numerically_equal = key_section(
            vec![
                vec![Cell::Integer(9_007_199_254_740_992), Cell::Null],
                vec![real(9_007_199_254_740_992.0), Cell::Null],
            ],
            &["first"],
        );
        assert!(validate_section_shape(&numerically_equal)
            .unwrap_err()
            .to_string()
            .contains("duplicate primary keys"));
    }

    #[test]
    fn multipart_primary_keys_are_compared_lexicographically() {
        let section = key_section(
            vec![
                vec![Cell::Text("a".into()), Cell::Null],
                vec![Cell::Text("a".into()), Cell::Integer(1)],
                vec![Cell::Text("a".into()), real(1.5)],
                vec![Cell::Text("a".into()), Cell::Text("".into())],
                vec![Cell::Text("a".into()), Cell::Blob("".into())],
                vec![Cell::Text("b".into()), Cell::Null],
            ],
            &["first", "second"],
        );
        validate_section_shape(&section).unwrap();

        let mut reordered = section;
        reordered.rows.swap(1, 2);
        assert!(validate_section_shape(&reordered)
            .unwrap_err()
            .to_string()
            .contains("strictly increasing primary-key order"));
    }

    #[tokio::test]
    async fn valid_hashes_do_not_hide_reordered_section_rows() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source.db");
        let source = crate::create_database(source_path.to_str().unwrap())
            .await
            .unwrap();
        let mut bundle: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();

        let records_index = bundle
            .sections
            .iter()
            .position(|section| section.name == "records")
            .unwrap();
        let records = &mut bundle.sections[records_index];
        assert!(records.rows.len() >= 2);
        records.rows.swap(0, 1);
        bundle.manifest.sections[records_index].sha256 = sha256_json(records).unwrap();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();

        let error = match validate_canonical_interchange(&serde_json::to_vec(&bundle).unwrap()) {
            Ok(_) => panic!("reordered rows must fail even when all digests are recomputed"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("strictly increasing primary-key order"));
        source.close().await;
    }

    #[tokio::test]
    async fn database_failure_rolls_back_staging_and_leaves_source_usable() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source.db");
        let source = crate::create_database(source_path.to_str().unwrap())
            .await
            .unwrap();
        let mut bundle: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();

        let records_index = bundle
            .sections
            .iter()
            .position(|section| section.name == "records")
            .unwrap();
        let records = &mut bundle.sections[records_index];
        let type_index = records
            .columns
            .iter()
            .position(|column| column.name == "type")
            .unwrap();
        records.rows[0][type_index] = Cell::Text("NotAClosedRecordType".into());
        bundle.manifest.sections[records_index].sha256 = sha256_json(records).unwrap();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();

        let destination = temp.path().join("must-not-exist.db");
        let error =
            import_canonical_interchange(&serde_json::to_vec(&bundle).unwrap(), &destination)
                .await
                .expect_err("database constraint failure must reject the import");
        assert!(
            error.to_string().contains("CHECK constraint failed")
                || error.to_string().contains("conformance")
        );
        assert!(!destination.exists());

        let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(source.write_pool())
            .await
            .unwrap();
        assert_eq!(records, 2);
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id":"1a7e4000-0000-4000-8000-000000000003",
                "type":"Document",
                "kind":"note",
                "name":"usable"
            }),
        )
        .await
        .unwrap();
        source.close().await;
    }

    #[tokio::test]
    async fn populated_provenance_round_trips_without_minting_receiver_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let (bundle, attestation_id, origin) = populated_provenance_bundle(&source).await;
        let source_inspection = crate::provenance::inspect_action_attestation(
            &source,
            &crate::mcp::Caller::local(),
            &attestation_id,
            crate::provenance::InspectionDetail::Why,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            source_inspection.attestation.trust,
            crate::provenance::AttestationTrust::NativeVerified
        );
        assert!(source_inspection.attestation.has_verified_interaction);
        assert!(source_inspection.interaction.is_some());
        let destination = temp.path().join("imported.db");
        let imported =
            import_canonical_interchange(&serde_json::to_vec(&bundle).unwrap(), &destination)
                .await
                .unwrap();
        let attestations: Vec<(String, String)> = sqlx::query_as(
            "SELECT id,issuer_origin_database_id FROM provenance_action_attestations ORDER BY id",
        )
        .fetch_all(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(attestations, vec![(attestation_id.clone(), origin)]);
        let local_anchors: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provenance_local_attestation_authority")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(local_anchors, 0, "import must not mint receiver authority");
        assert!(crate::provenance::state_violations(&imported)
            .await
            .unwrap()
            .is_empty());
        let inspected = crate::provenance::inspect_action_attestation(
            &imported,
            &crate::mcp::Caller::local(),
            &attestation_id,
            crate::provenance::InspectionDetail::Why,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            inspected.attestation.trust,
            crate::provenance::AttestationTrust::ForeignUnverified
        );
        assert!(!inspected.attestation.has_verified_interaction);
        assert!(inspected.interaction.is_none());
        assert!(inspected.why.is_none());
        let mut tx = crate::db::begin_write(imported.write_pool()).await.unwrap();
        let error = crate::provenance::validate_action_attestation_evidence_in(
            &mut tx,
            &crate::mcp::Caller::local(),
            &attestation_id,
            None,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("provenance action attestation does not exist"));
        tx.rollback().await.unwrap();

        // The foreign claim retains its source command digest but cannot squat
        // the receiving database's local idempotency namespace.
        let arguments = serde_json::json!({
            "text":"must remain digest-only",
            "idempotency_key":"portable-command"
        });
        let local_dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &crate::mcp::Caller::local(),
            "interchange_fixture",
            &arguments,
            None,
        );
        local_dispatch
            .scope(crate::store::append(
                &imported,
                crate::store::AppendSpec {
                    record_id: "1a7e4000-0000-4000-8000-000000000002".into(),
                    event_type: "record.created".into(),
                    payload: serde_json::json!({
                        "type":"Document","kind":"note","name":"receiver local provenance"
                    }),
                    actor: Some("local".into()),
                },
            ))
            .await
            .unwrap();
        assert_eq!(local_dispatch.receipt_ids().len(), 1);
        let local_inspection = crate::provenance::inspect_action_attestation(
            &imported,
            &crate::mcp::Caller::local(),
            &local_dispatch.receipt_ids()[0],
            crate::provenance::InspectionDetail::Summary,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            local_inspection.attestation.trust,
            crate::provenance::AttestationTrust::NativeVerified
        );
        imported.close().await;
        source.close().await;
    }

    #[tokio::test]
    async fn relationship_origin_state_round_trips_without_receiver_local_admission() {
        let temp = tempfile::tempdir().unwrap();
        let source =
            crate::create_database(temp.path().join("relationship-source.db").to_str().unwrap())
                .await
                .unwrap();
        let origin = crate::identity::database_id(&source).await.unwrap();
        let left_ref = crate::identity::encode_native_record(&origin, "portable-left").unwrap();
        let right_ref = crate::identity::encode_native_record(&origin, "portable-right").unwrap();
        let endpoints = vec![
            crate::relationship::RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: left_ref.clone(),
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: None,
            },
            crate::relationship::RelationshipEndpoint {
                role: "participant".into(),
                portable_ref: right_ref,
                record_type: Some("Document".into()),
                record_kind: Some("note".into()),
                record_id: None,
            },
        ];
        let definition = crate::relationship::core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == "relates_to.v1")
            .unwrap();
        let key = definition
            .canonical_proposition_key(
                &endpoints
                    .iter()
                    .map(crate::relationship::RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>(),
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
        let relationship_created = crate::relationship::RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: 1,
            relationship_type: "relates_to".into(),
            type_definition_id: "relates_to.v1".into(),
            endpoint_semantics: crate::relationship::EndpointSemantics::Symmetric,
            endpoints,
            identity_qualifiers: serde_json::Map::new(),
            canonical_proposition_key: key,
            reducer_id: "default".into(),
            reducer_version: 1,
            legacy_link: None,
        };
        let origin_admission: crate::relationship::OriginAdmissionV1 =
            serde_json::from_value(serde_json::json!({
                "schema_version":1,
                "relationship_type_definition":"relates_to.v1",
                "admission_class":"anchor_authorised_support",
                "authority_anchor":{"endpoint_role":"participant","endpoint_ref":left_ref},
                "admission_rule":"edit_either_anchor_view_both.v1",
                "authorization_decision_digest":"a".repeat(64),
                "authoring_action_attestation_id":"attestation-portable"
            }))
            .unwrap();
        let assertion_created = crate::relationship::AssertionCreatedV1 {
            schema_version: 1,
            // Genesis coordinates are placeholders here: the trusted prepare
            // seam preallocates and overwrites both with the exact relationship
            // aggregate and creation-event identities before validation.
            relationship: crate::relationship::RelationshipCoordinate {
                relationship_origin_db_id: origin.clone(),
                relationship_id: uuid::Uuid::new_v4().to_string(),
                relationship_revision: 1,
            },
            relationship_created_event: crate::relationship::RelationshipEventCoordinate {
                issuer_origin_db_id: origin.clone(),
                event_id: uuid::Uuid::new_v4().to_string(),
            },
            stance: "support".into(),
            semantic_claimant: "native-principal".into(),
            on_behalf_of: Some("semantic-context-only".into()),
            rationale: None,
            valid_from: None,
            valid_until: None,
            causal_parents: Vec::new(),
            origin_admission,
            authoring_action_attestation_id: "attestation-portable".into(),
        };
        let command = crate::relationship::prepare_relationship_with_assertion(
            &origin,
            "native-principal",
            "2026-08-12T00:00:00.000Z",
            "2026-08-12T00:00:00.000Z",
            relationship_created,
            assertion_created,
        )
        .unwrap();
        let assertion_id = command.assertion_event.stream_id.clone();
        crate::relationship::create_relationship_with_assertion(&source, &command)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE relationship_local_admissions
                SET local_admission_state='admitted',
                    local_admission_class='anchor_authorised_support',
                    local_reason='source-local-only fixture'
              WHERE issuer_origin_db_id=? AND assertion_id=?",
        )
        .bind(&origin)
        .bind(&assertion_id)
        .execute(source.write_pool())
        .await
        .unwrap();

        let bundle = export_canonical_interchange(&source).await.unwrap();
        assert_eq!(
            bundle,
            export_canonical_interchange(&source).await.unwrap(),
            "canonical relationship export must be byte-stable on repetition"
        );
        let destination = temp.path().join("relationship-imported.db");
        let imported = import_canonical_interchange(&bundle, &destination)
            .await
            .unwrap();
        let coordinate: (String, String, i64) = sqlx::query_as(
            "SELECT issuer_origin_db_id,assertion_id,relationship_revision
               FROM relationship_assertion_heads",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(coordinate, (origin, assertion_id, 1));
        let local: (String, Option<String>) = sqlx::query_as(
            "SELECT local_admission_state,local_admission_class
               FROM relationship_local_admissions",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(
            local,
            ("unresolved".into(), None),
            "import must re-derive local state without inheriting source authority"
        );
        let authority: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provenance_local_attestation_authority")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(
            authority, 0,
            "import must not mint local attestation authority"
        );
        let imported_once = export_canonical_interchange(&imported).await.unwrap();
        assert_eq!(
            imported_once,
            export_canonical_interchange(&imported).await.unwrap(),
            "receiver-local trust degradation must not destabilize portable export"
        );
        assert_eq!(
            bundle, imported_once,
            "local admission is non-portable; origin evidence must round-trip byte-exactly"
        );
        imported.close().await;
        source.close().await;
    }

    #[tokio::test]
    async fn recomputed_foreign_interaction_claim_never_upgrades_to_native_verified() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let (mut bundle, attestation_id, _) = populated_provenance_bundle(&source).await;
        let receipt_index = bundle
            .sections
            .iter()
            .position(|section| section.name == "provenance_interaction_receipts")
            .unwrap();
        let verifier_index = bundle.sections[receipt_index]
            .columns
            .iter()
            .position(|column| column.name == "verifier")
            .unwrap();
        bundle.sections[receipt_index].rows[0][verifier_index] =
            Cell::Text("attacker-recomputed-verifier".into());
        refresh_bundle_integrity(&mut bundle, receipt_index);

        let imported = import_canonical_interchange(
            &serde_json::to_vec(&bundle).unwrap(),
            &temp.path().join("fabricated.db"),
        )
        .await
        .unwrap();
        let inspected = crate::provenance::inspect_action_attestation(
            &imported,
            &crate::mcp::Caller::local(),
            &attestation_id,
            crate::provenance::InspectionDetail::Why,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            inspected.attestation.trust,
            crate::provenance::AttestationTrust::ForeignUnverified
        );
        assert!(!inspected.attestation.has_verified_interaction);
        assert!(inspected.interaction.is_none());
        assert!(inspected.why.is_none());
        imported.close().await;
        source.close().await;
    }

    #[tokio::test]
    async fn imported_interaction_principal_must_bind_to_attestation_principal() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let (mut bundle, _, _) = populated_provenance_bundle(&source).await;
        let receipt_index = bundle
            .sections
            .iter()
            .position(|section| section.name == "provenance_interaction_receipts")
            .unwrap();
        let principal_index = bundle.sections[receipt_index]
            .columns
            .iter()
            .position(|column| column.name == "principal")
            .unwrap();
        bundle.sections[receipt_index].rows[0][principal_index] =
            Cell::Text("acct:different-principal".into());
        refresh_bundle_integrity(&mut bundle, receipt_index);

        let error = import_canonical_interchange(
            &serde_json::to_vec(&bundle).unwrap(),
            &temp.path().join("principal-mismatch.db"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("provenance-state"), "{error}");
        assert!(
            error.to_string().contains("principal is inconsistent"),
            "{error}"
        );
        source.close().await;
    }

    #[tokio::test]
    async fn populated_provenance_import_rejects_extra_commitment_fields_and_missing_membership() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let (bundle, _, _) = populated_provenance_bundle(&source).await;

        let mut extra = bundle.clone();
        let action_index = extra
            .sections
            .iter()
            .position(|section| section.name == "provenance_action_attestations")
            .unwrap();
        let commitment_index = extra.sections[action_index]
            .columns
            .iter()
            .position(|column| column.name == "action_commitment")
            .unwrap();
        let digest_index = extra.sections[action_index]
            .columns
            .iter()
            .position(|column| column.name == "action_digest")
            .unwrap();
        let malformed = serde_json::json!({
            "arguments_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "operation":"interchange_fixture",
            "raw":"must not be accepted"
        });
        let malformed_text =
            String::from_utf8(crate::canonical_json::canonical_json(&malformed)).unwrap();
        extra.sections[action_index].rows[0][commitment_index] = Cell::Text(malformed_text);
        extra.sections[action_index].rows[0][digest_index] =
            Cell::Text(crate::provenance::digest_json(&malformed));
        refresh_bundle_integrity(&mut extra, action_index);
        let error = import_canonical_interchange(
            &serde_json::to_vec(&extra).unwrap(),
            &temp.path().join("extra.db"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("provenance-state"), "{error}");

        let mut missing = bundle;
        let membership_index = missing
            .sections
            .iter()
            .position(|section| section.name == "provenance_action_outputs")
            .unwrap();
        missing.sections[membership_index].rows.clear();
        refresh_bundle_integrity(&mut missing, membership_index);
        let error = import_canonical_interchange(
            &serde_json::to_vec(&missing).unwrap(),
            &temp.path().join("missing.db"),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("provenance-state"), "{error}");
        source.close().await;
    }
}
