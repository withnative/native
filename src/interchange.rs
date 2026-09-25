//! Canonical storage interchange v1, revision 5.
//!
//! The wire representation is intentionally logical rather than a SQLite file
//! copy: every durable table is an ordered section, every SQLite value carries
//! an explicit storage-class tag, and integrity covers the canonical compact
//! JSON bytes. Import builds and validates a fresh database before publishing
//! it at the requested path, so malformed input cannot partially mutate a
//! usable destination.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, TypeInfo as _, ValueRef as _};

use crate::db::{
    apply_schema, open_database_at, open_existing_database_at, Db, CURRENT_ENGINE_SCHEMA_VERSION,
};
use crate::{Error, Result};

pub const FORMAT: &str = "native.canonical-interchange.v1";
pub const REVISION: u64 = 5;

// SQLite's application id is database-local provenance, not portable content.
// The high bytes identify Native's canonical-history marker and the low byte
// records the interchange revision from which this database was materialised.
// Zero/foreign values are deliberately "unknown" and may not author deltas.
pub(crate) const SOURCE_HISTORY_APPLICATION_ID_BASE: i64 = 0x4e41_5400;

pub(crate) const fn source_history_application_id(revision: u64) -> i64 {
    SOURCE_HISTORY_APPLICATION_ID_BASE + revision as i64
}

fn source_history_revision_from_application_id(marker: i64) -> Option<u64> {
    let revision = marker.checked_sub(SOURCE_HISTORY_APPLICATION_ID_BASE)?;
    (1..=REVISION as i64)
        .contains(&revision)
        .then_some(revision as u64)
}
const REVISION_4: u64 = 4;
const ACT_REVISION: u64 = 3;
const REVISION_2: u64 = 2;
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
pub(crate) const SECTION_NAMES: &[&str] = &[
    "content_events",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "act_state",
    "act_cutover",
    "policy_events",
    "meta_events",
    "control_events",
    "derivation_events",
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
    "record_mentions",
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

// The expected inventories of earlier wire revisions are frozen here as
// explicit lists. They are deliberately NOT derived from `SECTION_NAMES`: an
// earlier bug did exactly that, so removing the read log from the current
// revision also shrank the expected revision-1/2/3 inventories, and every
// pre-existing bundle failed the section-inventory check before its upgrade
// path ran. A historical list must not track the current revision.
//
// Revision 4 is `SECTION_NAMES` above: the read log is not portable.
//
// Revision 3 is revision 4 plus `read_log_calls` and `read_log_touches`
// (inserted after `schema_config`).
const REVISION_3_SECTION_NAMES: &[&str] = &[
    "content_events",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "act_state",
    "act_cutover",
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

// Revision 2 is revision 3 without `act_state`/`act_cutover` (and with the
// read log).
const REVISION_2_SECTION_NAMES: &[&str] = &[
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

// Revision 1 is revision 2 without `content_event_causal_frontier`/
// `content_event_causal_cutover` (and with the read log).
const REVISION_1_SECTION_NAMES: &[&str] = &[
    "content_events",
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
    /// Original history fidelity after compatibility import. Older revision-5
    /// documents omit this and therefore remain unknown rather than being
    /// silently promoted to exhaustive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_history_revision: Option<u64>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub(crate) struct ValidatedInterchange {
    bundle: Bundle,
    source_revision: u64,
}

impl ValidatedInterchange {
    /// The revision carried by the input before compatibility upgrades.
    pub(crate) fn source_revision(&self) -> u64 {
        self.source_revision
    }

    /// Only a document authored at the current revision is exhaustive for
    /// every current canonical log. Compatibility upgrades preserve import
    /// support, but cannot recover derivation history omitted by revisions
    /// 1 through 3, nor observation/intent grouping omitted by revision 4.
    #[cfg(test)]
    pub(crate) fn require_native_current_revision(&self) -> Result<()> {
        ensure(
            self.source_revision == REVISION,
            "canonical interchange must be authored at revision 5 for exhaustive canonical history",
        )
    }

    fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn sections(&self) -> &[Section] {
        &self.bundle.sections
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn section(&self, name: &str) -> Option<&Section> {
        self.bundle
            .sections
            .iter()
            .find(|section| section.name == name)
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn source_profile(&self) -> (&str, u64) {
        (
            &self.bundle.manifest.source_profile.id,
            self.bundle.manifest.source_profile.revision,
        )
    }
}

/// Parse and fully validate canonical bytes for a sibling storage backend.
pub(crate) fn validate_canonical_interchange(bytes: &[u8]) -> Result<ValidatedInterchange> {
    let mut bundle: Bundle = serde_json::from_slice(bytes)
        .map_err(|error| Error::engine(format!("invalid canonical interchange JSON: {error}")))?;
    let wire_revision = bundle.manifest.revision;
    let source_revision = if wire_revision == REVISION {
        bundle.manifest.source_history_revision.unwrap_or_default()
    } else {
        wire_revision
    };
    if bundle.manifest.revision == LEGACY_REVISION {
        validate_bundle_revision(&bundle, REVISION_1_SECTION_NAMES, LEGACY_REVISION, 45)?;
        upgrade_legacy_bundle(&mut bundle)?;
    }
    if bundle.manifest.revision == REVISION_2 {
        validate_bundle_revision(
            &bundle,
            REVISION_2_SECTION_NAMES,
            REVISION_2,
            bundle.manifest.source_engine_schema,
        )?;
        upgrade_revision_2_bundle(&mut bundle)?;
    }
    if bundle.manifest.revision == ACT_REVISION {
        validate_bundle_revision(
            &bundle,
            REVISION_3_SECTION_NAMES,
            ACT_REVISION,
            bundle.manifest.source_engine_schema,
        )?;
        upgrade_revision_3_bundle(&mut bundle)?;
    }
    if bundle.manifest.revision == REVISION_4 {
        // Two revision-4 inventories shipped independently with the same
        // section count. Select by exact ordered names, never by count.
        let main_revision_4_names = REVISION_3_SECTION_NAMES
            .iter()
            .copied()
            .filter(|name| !matches!(*name, "read_log_calls" | "read_log_touches"))
            .flat_map(|name| {
                if name == "message_mentions" {
                    vec![name, "record_mentions"]
                } else {
                    vec![name]
                }
            })
            .collect::<Vec<_>>();
        let branch_revision_4_names = REVISION_3_SECTION_NAMES
            .iter()
            .copied()
            .filter(|name| !matches!(*name, "read_log_calls" | "read_log_touches"))
            .flat_map(|name| {
                if name == "awareness_events" {
                    vec!["derivation_events", name]
                } else {
                    vec![name]
                }
            })
            .collect::<Vec<_>>();
        let actual_names = bundle
            .sections
            .iter()
            .map(|section| section.name.as_str())
            .collect::<Vec<_>>();
        let names = if actual_names == main_revision_4_names {
            main_revision_4_names.as_slice()
        } else if actual_names == branch_revision_4_names {
            branch_revision_4_names.as_slice()
        } else {
            return Err(Error::engine("unsupported revision-4 section inventory"));
        };
        validate_bundle_revision(
            &bundle,
            names,
            REVISION_4,
            bundle.manifest.source_engine_schema,
        )?;
        upgrade_revision_4_bundle(&mut bundle)?;
    }
    validate_bundle(&bundle)?;
    Ok(ValidatedInterchange {
        bundle,
        source_revision,
    })
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
        revision: REVISION_2,
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
        revision: REVISION_2,
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
        section.revision = REVISION_2;
    }
    bundle.manifest.revision = REVISION_2;
    bundle.manifest.sections = bundle
        .sections
        .iter()
        .map(|section| {
            Ok(SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION_2,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    bundle.manifest.content_sha256 = sha256_json(&bundle.sections)?;
    Ok(())
}

/// Upgrade a revision-2 bundle to revision 3 in place: stamp a trailing
/// `act` column (all NULL — revision-2 rows predate act stamping, so their
/// grouping is unknown) on the sequenced event sections the bundle carries,
/// and add the `act_state` counter plus the recorded `act_cutover`.
///
/// The counter resumes above every act the bundle carries (zero when none
/// do), and the cutover marks each domain's whole section grouping-unknown
/// at its current maximum replay position.
///
/// `derivation_events` did not travel at revision 3. Its cutover row is still
/// emitted — honestly zero for the state this document can materialize — so
/// the cutover inventory covers all ten sequenced canonical domains.
fn upgrade_revision_2_bundle(bundle: &mut Bundle) -> Result<()> {
    const ACT_DOMAINS: [&str; 10] = [
        "content_events",
        "policy_events",
        "awareness_events",
        "notification_candidate_events",
        "binding_audit",
        "database_identity_audit",
        "meta_events",
        "control_events",
        "derivation_events",
        "relationship_events",
    ];
    let source_engine_schema = bundle.manifest.source_engine_schema;
    // Revision-2 sections carry no act column at all, so no bundle act can
    // exist and the counter honestly resumes at zero.
    let max_act = 0_i64;
    // Section rows are primary-key ordered, so the cutover rows are emitted
    // in domain sort order, not stamping order.
    const SORTED_DOMAINS: [&str; 10] = [
        "awareness_events",
        "binding_audit",
        "content_events",
        "control_events",
        "database_identity_audit",
        "derivation_events",
        "meta_events",
        "notification_candidate_events",
        "policy_events",
        "relationship_events",
    ];
    let mut cutover_rows = Vec::with_capacity(ACT_DOMAINS.len());
    let mut legacy_max: std::collections::BTreeMap<&str, i64> = std::collections::BTreeMap::new();
    for domain in ACT_DOMAINS {
        // Domains without an interchange section (today only
        // `derivation_events`) contribute an honestly empty cutover row.
        let Some(section) = bundle
            .sections
            .iter_mut()
            .find(|section| section.name == domain)
        else {
            legacy_max.insert(domain, 0);
            continue;
        };
        let seq = section
            .columns
            .iter()
            .position(|column| column.name == "seq")
            .ok_or_else(|| Error::engine(format!("revision-2 {domain} is missing seq")))?;
        section.columns.push(Column {
            name: "act".into(),
            declared_type: "INTEGER".into(),
        });
        let mut last_legacy_seq = 0_i64;
        for row in &mut section.rows {
            if let Some(Cell::Integer(value)) = row.get(seq) {
                last_legacy_seq = last_legacy_seq.max(*value);
            }
            row.push(Cell::Null);
        }
        legacy_max.insert(domain, last_legacy_seq);
    }
    for domain in SORTED_DOMAINS {
        cutover_rows.push(vec![
            Cell::Text(domain.into()),
            Cell::Integer(legacy_max[domain]),
            Cell::Text("1970-01-01T00:00:00.000Z".into()),
            Cell::Integer(source_engine_schema),
        ]);
    }
    let state = Section {
        format: SECTION_FORMAT.into(),
        revision: ACT_REVISION,
        name: "act_state".into(),
        columns: vec![
            Column {
                name: "singleton".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "next_act".into(),
                declared_type: "INTEGER".into(),
            },
        ],
        primary_key: vec!["singleton".into()],
        rows: vec![vec![Cell::Integer(1), Cell::Integer(max_act)]],
    };
    let cutover = Section {
        format: SECTION_FORMAT.into(),
        revision: ACT_REVISION,
        name: "act_cutover".into(),
        columns: vec![
            Column {
                name: "domain".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "last_legacy_seq".into(),
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
        primary_key: vec!["domain".into()],
        rows: cutover_rows,
    };
    let position = bundle
        .sections
        .iter()
        .position(|section| section.name == "content_event_causal_cutover")
        .ok_or_else(|| Error::engine("revision-2 interchange is missing its causal cutover"))?
        + 1;
    bundle.sections.insert(position, state);
    bundle.sections.insert(position + 1, cutover);
    for section in &mut bundle.sections {
        section.revision = ACT_REVISION;
    }
    bundle.manifest.revision = ACT_REVISION;
    bundle.manifest.sections = bundle
        .sections
        .iter()
        .map(|section| {
            Ok(SectionDescriptor {
                name: section.name.clone(),
                revision: ACT_REVISION,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    bundle.manifest.content_sha256 = sha256_json(&bundle.sections)?;
    Ok(())
}

/// Upgrade a revision-3 document to revision 4. Revision 3 omitted the
/// derivation log entirely and predates act stamping for provenance validity
/// changes. The compatibility image is therefore explicit about both unknowns:
/// it synthesizes an empty derivation log and stamps every historical validity
/// row with NULL. Callers that claim exhaustive source fidelity must reject
/// this upgraded representation at any exhaustive-history authority boundary.
fn upgrade_revision_3_bundle(bundle: &mut Bundle) -> Result<()> {
    bundle
        .sections
        .retain(|section| !matches!(section.name.as_str(), "read_log_calls" | "read_log_touches"));
    let validity = bundle
        .sections
        .iter_mut()
        .find(|section| section.name == "provenance_attestation_validity_events")
        .ok_or_else(|| Error::engine("revision-3 interchange is missing validity events"))?;
    ensure(
        !validity.columns.iter().any(|column| column.name == "act"),
        "revision-3 validity events unexpectedly carry an act column",
    )?;
    validity.columns.push(Column {
        name: "act".into(),
        declared_type: "INTEGER".into(),
    });
    for row in &mut validity.rows {
        row.push(Cell::Null);
    }

    let derivation = Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION_4,
        name: "derivation_events".into(),
        columns: vec![
            Column {
                name: "seq".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "id".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "idempotency_key".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "type".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "schema_version".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "aggregate_kind".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "aggregate_id".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "actor".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "run_key".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "reason".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "payload".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "created_at".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "act".into(),
                declared_type: "INTEGER".into(),
            },
        ],
        primary_key: vec!["seq".into()],
        rows: Vec::new(),
    };
    let position = SECTION_NAMES
        .iter()
        .position(|name| *name == "derivation_events")
        .expect("current inventory contains derivation_events");
    bundle.sections.insert(position, derivation);
    for section in &mut bundle.sections {
        section.revision = REVISION_4;
    }
    bundle.manifest.revision = REVISION_4;
    bundle.manifest.sections = bundle
        .sections
        .iter()
        .map(|section| {
            Ok(SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION_4,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    bundle.manifest.content_sha256 = sha256_json(&bundle.sections)?;
    Ok(())
}

/// Upgrade a revision-4 document to revision 5. Revision 4 predates act
/// stamping for external observations and awareness command intents: both
/// sections gain a trailing `act` column with every historical row stamped
/// NULL. Their transaction grouping is permanently unknown, so the upgrade
/// never fabricates grouping — it only preserves import support. Callers
/// that claim exhaustive source fidelity must reject this upgraded
/// representation at any exhaustive-history authority boundary,
/// which now requires revision 5.
fn empty_derivation_section() -> Section {
    let columns = [
        ("seq", "INTEGER"),
        ("id", "TEXT"),
        ("idempotency_key", "TEXT"),
        ("type", "TEXT"),
        ("schema_version", "INTEGER"),
        ("aggregate_kind", "TEXT"),
        ("aggregate_id", "TEXT"),
        ("actor", "TEXT"),
        ("run_key", "TEXT"),
        ("reason", "TEXT"),
        ("payload", "TEXT"),
        ("created_at", "TEXT"),
        ("act", "INTEGER"),
    ]
    .into_iter()
    .map(|(name, declared_type)| Column {
        name: name.into(),
        declared_type: declared_type.into(),
    })
    .collect();
    Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: "derivation_events".into(),
        columns,
        primary_key: vec!["seq".into()],
        rows: Vec::new(),
    }
}

fn upgrade_revision_4_bundle(bundle: &mut Bundle) -> Result<()> {
    bundle
        .sections
        .retain(|section| !matches!(section.name.as_str(), "read_log_calls" | "read_log_touches"));
    if !bundle
        .sections
        .iter()
        .any(|section| section.name == "derivation_events")
    {
        let position = SECTION_NAMES
            .iter()
            .position(|name| *name == "derivation_events")
            .expect("current inventory contains derivation_events");
        bundle.sections.insert(position, empty_derivation_section());
    }
    if !bundle
        .sections
        .iter()
        .any(|section| section.name == "record_mentions")
    {
        let rows = derive_record_mentions_rows(bundle)?;
        let position = SECTION_NAMES
            .iter()
            .position(|name| *name == "record_mentions")
            .expect("current inventory contains record_mentions");
        bundle
            .sections
            .insert(position, record_mentions_section(rows));
    }
    for table in [
        "provenance_attestation_validity_events",
        "external_observations",
        "awareness_command_intents",
    ] {
        let section = bundle
            .sections
            .iter_mut()
            .find(|section| section.name == table)
            .ok_or_else(|| Error::engine(format!("revision-4 interchange is missing {table}")))?;
        if !section.columns.iter().any(|column| column.name == "act") {
            section.columns.push(Column {
                name: "act".into(),
                declared_type: "INTEGER".into(),
            });
            for row in &mut section.rows {
                row.push(Cell::Null);
            }
        }
    }
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

/// The `record_mentions` section descriptor, in `SECTION_NAMES` column order.
fn record_mentions_section(rows: Vec<Vec<Cell>>) -> Section {
    Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: "record_mentions".into(),
        columns: vec![
            Column {
                name: "source_id".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "occurrence_ix".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "source_event_seq".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "span_start".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "span_end".into(),
                declared_type: "INTEGER".into(),
            },
            Column {
                name: "authored_reference".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "lookup_key".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "form".into(),
                declared_type: "TEXT".into(),
            },
            Column {
                name: "parser_version".into(),
                declared_type: "INTEGER".into(),
            },
        ],
        primary_key: vec!["source_id".into(), "occurrence_ix".into()],
        rows,
    }
}

/// Derive revision-4 `record_mentions` rows from a revision-3 bundle's own
/// `records` and `content_events` sections.
///
/// The source of truth is the record's current `body` column — never an event
/// payload — scanned with the current parser. Provenance is the latest
/// body-carrying content event for that record
/// (`record_body::payload_carries_body`, the Rust twin of the migration
/// backfill's `BODY_CARRYING_EVENT_SQL`), so a metadata-only update after the
/// body keeps the body event's sequence. A live non-empty body with no
/// body-carrying event yields no rows, exactly as the migration backfill
/// leaves it: stamping a sequence the log cannot justify would make the
/// imported projection disagree with replay, so the missing provenance is
/// refused by the post-import conformance run rather than invented here.
///
/// Rows are deterministic: `records` is ordered by its primary key and
/// occurrences follow `scan_body`'s left-to-right order, so the section
/// digest is stable across imports.
fn derive_record_mentions_rows(bundle: &Bundle) -> Result<Vec<Vec<Cell>>> {
    let records = bundle
        .sections
        .iter()
        .find(|section| section.name == "records")
        .ok_or_else(|| Error::engine("revision-3 interchange is missing records"))?;
    let events = bundle
        .sections
        .iter()
        .find(|section| section.name == "content_events")
        .ok_or_else(|| Error::engine("revision-3 interchange is missing content_events"))?;
    let record_column = |name: &str| {
        records
            .columns
            .iter()
            .position(|column| column.name == name)
            .ok_or_else(|| Error::engine(format!("revision-3 records is missing {name}")))
    };
    let event_column = |name: &str| {
        events
            .columns
            .iter()
            .position(|column| column.name == name)
            .ok_or_else(|| Error::engine(format!("revision-3 content_events is missing {name}")))
    };
    let record_id = record_column("id")?;
    let record_body = record_column("body")?;
    let record_deleted = record_column("deleted_at")?;
    let event_record = event_column("record_id")?;
    let event_seq = event_column("seq")?;
    let event_type = event_column("type")?;
    let event_payload = event_column("payload")?;

    let mut provenance: BTreeMap<&str, i64> = BTreeMap::new();
    for row in &events.rows {
        let Some(Cell::Text(event_type)) = row.get(event_type) else {
            continue;
        };
        if !matches!(
            event_type.as_str(),
            "record.created"
                | "record.updated"
                | "receipt.committed.v1"
                | "unit.revision.recorded.v1"
        ) {
            continue;
        }
        let Some(Cell::Text(payload)) = row.get(event_payload) else {
            continue;
        };
        let payload: serde_json::Value = serde_json::from_str(payload).map_err(|error| {
            Error::engine(format!(
                "revision-3 content event payload is not valid JSON: {error}"
            ))
        })?;
        if !crate::record_body::payload_carries_body(event_type, &payload) {
            continue;
        }
        let (Some(Cell::Text(record_id)), Some(Cell::Integer(seq))) =
            (row.get(event_record), row.get(event_seq))
        else {
            continue;
        };
        provenance
            .entry(record_id.as_str())
            .and_modify(|current| *current = (*current).max(*seq))
            .or_insert(*seq);
    }

    let mut rows = Vec::new();
    for row in &records.rows {
        if !matches!(row.get(record_deleted), Some(Cell::Null)) {
            continue;
        }
        let (Some(Cell::Text(record_id)), Some(Cell::Text(body))) =
            (row.get(record_id), row.get(record_body))
        else {
            continue;
        };
        if body.is_empty() {
            continue;
        }
        let Some(&source_event_seq) = provenance.get(record_id.as_str()) else {
            continue;
        };
        for (occurrence_ix, occurrence) in crate::mentions::scan_body(body).iter().enumerate() {
            rows.push(vec![
                Cell::Text(record_id.clone()),
                Cell::Integer(occurrence_ix as i64),
                Cell::Integer(source_event_seq),
                Cell::Integer(occurrence.span_start as i64),
                Cell::Integer(occurrence.span_end as i64),
                Cell::Text(occurrence.authored_reference.clone()),
                Cell::Text(occurrence.lookup_key.clone()),
                Cell::Text(occurrence.form.as_str().to_owned()),
                Cell::Integer(crate::mentions::MENTION_PARSER_VERSION),
            ]);
        }
    }
    Ok(rows)
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
    let source_history_marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *tx)
        .await?;
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
            source_history_revision: source_history_revision_from_application_id(
                source_history_marker,
            ),
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
    let source_revision = validated.source_revision();
    let bundle = validated.bundle();

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
            if section.name == "content_event_causal_cutover"
                || section.name == "act_state"
                || section.name == "act_cutover"
            {
                sqlx::query(&format!("DELETE FROM {}", quote_identifier(&section.name)))
                    .execute(&mut *tx)
                    .await?;
            }
            import_section(&mut tx, section).await?;
        }
        sqlx::query(&format!(
            "PRAGMA application_id = {}",
            source_history_application_id(source_revision)
        ))
        .execute(&mut *tx)
        .await?;
        let derivation_events = crate::derivation::read_all_derivation_events(&mut tx).await?;
        crate::derivation::replay_derivations_in(&mut tx, &derivation_events).await?;
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
    let columns = sqlx::query_as::<_, TableColumn>(&sql)
        .fetch_all(executor)
        .await?;
    Ok(columns)
}

/// Logical columns plus the declared primary key for one interchange
/// table. This is the single section-shape helper: the full export and the
/// standby authority act-range cut both build their `Column` inventory and
/// `ORDER BY` from it, so a schema change cannot move one path without the
/// other.
async fn section_shape<'e, E>(executor: E, table: &str) -> Result<(Vec<Column>, Vec<String>)>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let table_info = table_columns(executor, table).await?;
    if table_info.is_empty() {
        return Err(Error::engine(format!(
            "canonical interchange table is missing: {table}"
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
            "canonical interchange table has no primary key: {table}"
        )));
    }
    Ok((columns, primary_key))
}

/// Encode one fetched SQLite row with the exact canonical cell rules: NULL
/// stays NULL, INTEGER/REAL/TEXT/BLOB carry their storage-class tags, REAL
/// is finite-only exact-bits hex, and BLOB is canonical padded base64. This
/// is the single cell codec: the full export and the standby authority
/// act-range cut share it, so the cut preserves interchange encoding
/// byte-for-byte.
fn encode_row_cells(
    row: &sqlx::sqlite::SqliteRow,
    columns: &[Column],
    table: &str,
) -> Result<Vec<Cell>> {
    use sqlx::Row as _;
    let mut cells = Vec::with_capacity(columns.len());
    for index in 0..columns.len() {
        let raw = row.try_get_raw(index)?;
        if table == "read_log_touches"
            && index == 1
            && (raw.is_null() || raw.type_info().name() != "TEXT")
        {
            return Err(Error::engine(
                "canonical read-log touch has no TEXT dictionary identity",
            ));
        }
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
                        "canonical interchange rejects non-finite REAL in {table}"
                    )));
                }
                Cell::Real(format!("{:016x}", value.to_bits()))
            }
            "TEXT" => Cell::Text(row.try_get(index)?),
            "BLOB" => Cell::Blob(
                base64::engine::general_purpose::STANDARD.encode(row.try_get::<Vec<u8>, _>(index)?),
            ),
            storage_class => {
                return Err(Error::engine(format!(
                    "unsupported SQLite storage class {storage_class} in {table}"
                )))
            }
        };
        cells.push(cell);
    }
    Ok(cells)
}

async fn export_section(tx: &mut sqlx::Transaction<'_, Sqlite>, name: &str) -> Result<Section> {
    let (columns, primary_key) = section_shape(&mut **tx, name).await?;

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
    for row in &result_rows {
        rows.push(encode_row_cells(row, &columns, name)?);
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

/// Export the act-stamped rows of one canonical table in
/// `(from_exclusive_act, to_inclusive_act]`, ordered by the declared primary
/// key with the exact interchange [`Column`]/[`Cell`] encoding.
///
/// This is the authority-side row reader for the standby whole-act cut. It
/// shares [`section_shape`] and [`encode_row_cells`] with the full export, so
/// there is exactly one canonical cell codec; the `WHERE` clause is the only
/// difference. `NULL` acts never match the range predicate, which is what
/// keeps grouping-unknown legacy rows out of a live-authority cut.
pub(crate) async fn export_act_range_section(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Section> {
    ensure(
        from_exclusive_act >= 0 && to_inclusive_act >= 0,
        "canonical act-range export bounds must be non-negative",
    )?;
    ensure(
        from_exclusive_act <= to_inclusive_act,
        "canonical act-range export range is reversed",
    )?;
    let (columns, primary_key) = section_shape(&mut *conn, table).await?;
    if !columns.iter().any(|column| column.name == "act") {
        return Err(Error::engine(format!(
            "authority act cut table has no act column: {table}"
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
    // This generic reader intentionally does not reproduce the
    // `read_log_touches` dictionary join used by full interchange export.
    // Act-range callers are restricted to ACT_STAMPED_TABLES; tables without
    // an `act` column fail above rather than receiving subtly different
    // logical-row encoding.
    let sql = format!(
        "SELECT {select_columns} FROM {} WHERE act > ? AND act <= ? ORDER BY {order}",
        quote_identifier(table)
    );
    let result_rows = sqlx::query(&sql)
        .bind(from_exclusive_act)
        .bind(to_inclusive_act)
        .fetch_all(&mut *conn)
        .await?;
    let mut rows = Vec::with_capacity(result_rows.len());
    for row in &result_rows {
        rows.push(encode_row_cells(row, &columns, table)?);
    }

    Ok(Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: table.into(),
        columns,
        primary_key,
        rows,
    })
}

/// A bound value for [`export_where_section`]. The bounded companion closure
/// binds integer act bounds and explicit text identifiers only, never a
/// caller-controlled identifier list of arbitrary shape.
#[derive(Debug, Clone)]
pub(crate) enum SelectionBind {
    Text(String),
    Integer(i64),
}

/// Export the rows of one table selected by a trusted, internal `WHERE`
/// fragment, ordered by the declared primary key and encoded by the single
/// canonical cell codec shared with the full export and the act-range reader.
///
/// `where_clause` is never caller input: it is a fixed literal built by the
/// companion closure in `crate::standby::companion_closure`, whose nested
/// subqueries restrict every companion selection to identifiers reachable from
/// the act-stamped cut. The fragment carries `?` placeholders that are bound
/// positionally from `bindings`.
pub(crate) async fn export_where_section(
    conn: &mut sqlx::SqliteConnection,
    table: &str,
    where_clause: &str,
    bindings: &[SelectionBind],
) -> Result<Section> {
    let (columns, primary_key) = section_shape(&mut *conn, table).await?;
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
        "SELECT {select_columns} FROM {} WHERE {where_clause} ORDER BY {order}",
        quote_identifier(table)
    );
    let mut query = sqlx::query(&sql);
    for binding in bindings {
        query = match binding {
            SelectionBind::Text(value) => query.bind(value.clone()),
            SelectionBind::Integer(value) => query.bind(*value),
        };
    }
    let result_rows = query.fetch_all(&mut *conn).await?;
    let mut rows = Vec::with_capacity(result_rows.len());
    for row in &result_rows {
        rows.push(encode_row_cells(row, &columns, table)?);
    }

    Ok(Section {
        format: SECTION_FORMAT.into(),
        revision: REVISION,
        name: table.into(),
        columns,
        primary_key,
        rows,
    })
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    // Accepted engine stamps are explicit. Older wire revisions upgrade
    // their section inventory and keep their source-history revision so a
    // re-export cannot claim exhaustive authority for a legacy source.
    ensure(
        matches!(
            bundle.manifest.source_engine_schema,
            45 | 53 | 55 | 56 | 57 | 58 | 59 | 60 | 61 | 62 | 63 | CURRENT_ENGINE_SCHEMA_VERSION
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
        manifest
            .source_history_revision
            .is_none_or(|source| source > 0 && source <= REVISION),
        "invalid canonical source-history revision",
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

pub(crate) fn validate_section_shape(section: &Section) -> Result<()> {
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

/// Negative zero's bit pattern. SQLite cannot round-trip it bit-exactly, so
/// canonical REAL cells never carry it.
const NEGATIVE_ZERO_BITS: u64 = 0x8000_0000_0000_0000;

/// Parse one canonical REAL cell and enforce the canonical value policy:
/// exactly sixteen lowercase hexadecimal digits, finite, and never negative
/// zero. Returns a `Result`, so a malformed cell is an error rather than a
/// panic even on a path that skipped section-level validation.
fn real_from_canonical_bits(bits: &str) -> Result<f64> {
    ensure(
        bits.len() == 16
            && bits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "canonical REAL must be 16 lowercase hexadecimal digits",
    )?;
    let raw = u64::from_str_radix(bits, 16)
        .map_err(|_| Error::engine("canonical REAL has invalid bits"))?;
    let value = f64::from_bits(raw);
    ensure(value.is_finite(), "canonical REAL must be finite")?;
    ensure(
        raw != NEGATIVE_ZERO_BITS,
        "canonical REAL must not be negative zero",
    )?;
    Ok(value)
}

/// Decode one canonical BLOB cell and enforce canonical padded base64. Returns
/// a `Result`, so a malformed cell is an error rather than a panic.
fn bytes_from_canonical_blob(encoded: &str) -> Result<Vec<u8>> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Error::engine("canonical BLOB is not valid padded base64"))?;
    ensure(
        base64::engine::general_purpose::STANDARD.encode(&decoded) == encoded,
        "canonical BLOB is not canonical padded base64",
    )?;
    Ok(decoded)
}

fn validate_cell(cell: &Cell) -> Result<()> {
    match cell {
        Cell::Real(bits) => real_from_canonical_bits(bits).map(|_| ()),
        Cell::Blob(encoded) => bytes_from_canonical_blob(encoded).map(|_| ()),
        Cell::Null | Cell::Integer(_) | Cell::Text(_) => Ok(()),
    }
}

/// The only two admitted destination conflict semantics. A receiver never
/// overwrites a canonical row: there is deliberately no upsert and no
/// `INSERT OR IGNORE` that could hide a divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictMode {
    /// Append-only act-stamped logs: every incoming primary key must be
    /// absent. An identical existing row is an overlapping act and refuses
    /// exactly like a divergent collision.
    ActLogRefuseExisting,
    /// Immutable canonical companions: an absent row inserts, an exactly
    /// equal row is an idempotent no-op, and any difference at all — a
    /// changed value, NULL versus non-NULL, or a different SQLite storage
    /// class — refuses. The row is never updated.
    ImmutableAllowIdentical,
}

/// Per-section insert-or-verify counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SectionIngestOutcome {
    pub(crate) inserted: usize,
    pub(crate) identical: usize,
}

/// Destination columns and declared primary key, or a refusal naming the
/// drift from `section`. The returned [`TableColumn`] inventory is the
/// trusted source for quoting every identifier a later ingest uses, so no
/// section-supplied name reaches SQL before this check passes.
async fn destination_columns(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    section: &Section,
) -> Result<Vec<TableColumn>> {
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
    )?;
    Ok(columns)
}

/// Refuse a section whose column list or primary key does not match the live
/// destination schema. This runs before any mutation of that schema.
pub(crate) async fn validate_destination_section(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    section: &Section,
) -> Result<()> {
    destination_columns(tx, section).await.map(|_| ())
}

/// Bind one canonical cell with its exact storage class. This is the single
/// `Cell` -> SQLite bind rule, shared by the interchange importer and the
/// receiver insert-or-verify primitive, so no path may bind a value under a
/// different storage class or quietly stringify it. The conversions are
/// checked: a malformed REAL or BLOB cell is an error, never a panic.
fn bind_cell<'q>(
    query: sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    cell: &Cell,
) -> Result<sqlx::query::Query<'q, Sqlite, sqlx::sqlite::SqliteArguments<'q>>> {
    Ok(match cell {
        Cell::Null => query.bind(None::<i64>),
        Cell::Integer(value) => query.bind(*value),
        Cell::Real(bits) => query.bind(real_from_canonical_bits(bits)?),
        Cell::Text(value) => query.bind(value.clone()),
        Cell::Blob(encoded) => query.bind(bytes_from_canonical_blob(encoded)?),
    })
}

/// Insert one canonical row under an already-quoted column list of the same
/// width. Every cell is bound by [`bind_cell`]; the SQL text carries no value.
async fn insert_row_cells(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    quoted_table: &str,
    column_list: &str,
    row: &[Cell],
) -> Result<()> {
    let placeholders = vec!["?"; row.len()].join(", ");
    let sql = format!("INSERT INTO {quoted_table} ({column_list}) VALUES ({placeholders})");
    let mut query = sqlx::query(&sql);
    for cell in row {
        query = bind_cell(query, cell)?;
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

/// Fetch the destination row for one primary key and decode it with the
/// canonical [`encode_row_cells`] codec. `LIMIT 2` turns a schema that lost its
/// primary-key uniqueness into a refusal instead of a silently picked row.
async fn select_existing_row(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    quoted_table: &str,
    column_list: &str,
    primary_key_predicate: &str,
    primary_key_cells: &[&Cell],
    columns: &[Column],
    table: &str,
) -> Result<Option<Vec<Cell>>> {
    let sql =
        format!("SELECT {column_list} FROM {quoted_table} WHERE {primary_key_predicate} LIMIT 2");
    let mut query = sqlx::query(&sql);
    for cell in primary_key_cells {
        query = bind_cell(query, cell)?;
    }
    let rows = query.fetch_all(&mut **tx).await?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(encode_row_cells(row, columns, table)?)),
        _ => Err(Error::engine(
            "destination holds more than one row for a canonical primary key",
        )),
    }
}

/// SQLite treats a single-column `INTEGER PRIMARY KEY` as a rowid alias, and
/// recognizes the type case-insensitively, so an exact-case comparison would
/// miss `integer PRIMARY KEY`. Surrounding whitespace is deliberately *not*
/// trimmed: SQLite's parser already normalizes token whitespace, and a quoted
/// type like `" INTEGER "` is not a rowid alias at all, so trimming would
/// classify a non-alias column as one. This is the one classification helper
/// for that rule.
fn is_rowid_alias_declared_type(declared_type: &str) -> bool {
    declared_type.eq_ignore_ascii_case("INTEGER")
}

/// Refuse a NULL in any declared primary-key cell, and require an [`Cell::Integer`]
/// for a single-column `INTEGER PRIMARY KEY`: that is SQLite's rowid alias,
/// where a NULL would auto-assign a rowid and a non-integer would not pin the
/// row the caller named. This runs before any SQL for the row.
fn validate_primary_key_cells(
    row: &[Cell],
    primary_key_indexes: &[usize],
    rowid_alias: bool,
) -> Result<()> {
    for index in primary_key_indexes {
        ensure(
            !matches!(row.get(*index), None | Some(Cell::Null)),
            "canonical primary-key cell must not be NULL",
        )?;
    }
    if rowid_alias {
        ensure(
            matches!(row.get(primary_key_indexes[0]), Some(Cell::Integer(_))),
            "canonical INTEGER PRIMARY KEY cell must be an Integer",
        )?;
    }
    Ok(())
}

/// Insert-or-verify every row of one canonical [`Section`] against the live
/// destination schema, using the section's declared full primary key and every
/// declared column.
///
/// Identifiers are quoted from the destination inventory returned by
/// [`destination_columns`] only after it has proven `section` matches it, so no
/// untrusted section name reaches SQL before validation. Values are bound with
/// [`bind_cell`] and compared with the canonical [`encode_row_cells`] codec, so
/// `seq`, `act`, timestamps, BLOB bytes, REAL bits and NULL are preserved
/// exactly and a storage-class difference refuses.
///
/// `read_log_touches` is deliberately refused: its logical `record_id` is
/// reconstructed through the receiver-local dictionary in
/// [`import_read_log_touches`], which this primitive cannot reproduce.
pub(crate) async fn ingest_section_rows(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    section: &Section,
    mode: ConflictMode,
) -> Result<SectionIngestOutcome> {
    ensure(
        section.name != "read_log_touches",
        "canonical read-log touches need the dictionary importer, not the pinned ingest primitive",
    )?;
    // Local, fail-closed well-formedness: this primitive may be reached by a
    // crate-internal caller that skipped the outer bundle/section validation,
    // so malformed REAL/BLOB cells and bad shapes must error here, not panic.
    validate_section_shape(section)?;
    let columns = destination_columns(tx, section).await?;
    let quoted_table = quote_identifier(&section.name);
    let column_list = columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(", ");
    let primary_key_predicate = section
        .primary_key
        .iter()
        .map(|column| format!("{} = ?", quote_identifier(column)))
        .collect::<Vec<_>>()
        .join(" AND ");
    let primary_key_indexes = section
        .primary_key
        .iter()
        .map(|name| {
            section
                .columns
                .iter()
                .position(|column| &column.name == name)
                .ok_or_else(|| Error::engine("canonical primary-key column is missing"))
        })
        .collect::<Result<Vec<_>>>()?;
    // A single-column `INTEGER PRIMARY KEY` is SQLite's rowid alias.
    let rowid_alias = section.primary_key.len() == 1
        && is_rowid_alias_declared_type(&section.columns[primary_key_indexes[0]].declared_type);

    let mut outcome = SectionIngestOutcome::default();
    for row in &section.rows {
        validate_primary_key_cells(row, &primary_key_indexes, rowid_alias)?;
        let primary_key_cells = primary_key_indexes
            .iter()
            .map(|index| &row[*index])
            .collect::<Vec<_>>();
        match select_existing_row(
            tx,
            &quoted_table,
            &column_list,
            &primary_key_predicate,
            &primary_key_cells,
            &section.columns,
            &section.name,
        )
        .await?
        {
            Some(existing) => match mode {
                ConflictMode::ActLogRefuseExisting => {
                    return Err(Error::engine(format!(
                        "canonical act log '{}' refuses an existing primary key",
                        section.name
                    )));
                }
                ConflictMode::ImmutableAllowIdentical => {
                    ensure(
                        existing == *row,
                        "immutable canonical companion row diverged from the destination",
                    )?;
                    outcome.identical += 1;
                }
            },
            None => {
                insert_row_cells(tx, &quoted_table, &column_list, row).await?;
                // Fail closed on affinity or normalization: re-read the row
                // through the canonical codec and require the exact incoming
                // cells, so a coerced class, value or REAL bit pattern refuses
                // and the surrounding transaction rolls back.
                let stored = select_existing_row(
                    tx,
                    &quoted_table,
                    &column_list,
                    &primary_key_predicate,
                    &primary_key_cells,
                    &section.columns,
                    &section.name,
                )
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "canonical row vanished after insert into '{}'",
                        section.name
                    ))
                })?;
                ensure(
                    stored == *row,
                    "destination coerced or normalized a canonical row during insert",
                )?;
                outcome.inserted += 1;
            }
        }
    }
    Ok(outcome)
}

async fn import_section(tx: &mut sqlx::Transaction<'_, Sqlite>, section: &Section) -> Result<()> {
    if section.name == "read_log_touches" {
        return import_read_log_touches(tx, section).await;
    }
    ingest_section_rows(tx, section, ConflictMode::ActLogRefuseExisting)
        .await
        .map(|_| ())
}

/// The one path that reconstructs a logical read-log touch: the exported
/// `record_id` TEXT identity is interned into the receiver-local
/// `read_log_record_ids` dictionary and the row is inserted against its
/// INTEGER `record_ref`. It shares [`insert_row_cells`]/[`bind_cell`] with
/// every other canonical insert, so malformed cells still error rather than
/// panic.
///
/// This is the one intentional exception to the post-insert exact re-read in
/// [`ingest_section_rows`]: the logical row's identity is split across the
/// dictionary table and `read_log_touches` stores an INTEGER `record_ref`
/// where the section carries TEXT `record_id`, so the physical row cannot be
/// compared cell-for-cell to the incoming logical row. Read-log touches are
/// operational, disposable evidence rather than canonical state.
async fn import_read_log_touches(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    section: &Section,
) -> Result<()> {
    ensure(
        section.columns.len() >= 2 && section.columns[1].name == "record_id",
        "canonical read-log touch must carry record_id in its second column",
    )?;
    let columns = section
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            quote_identifier(if index == 1 {
                "record_ref"
            } else {
                &column.name
            })
        })
        .collect::<Vec<_>>()
        .join(", ");
    let quoted_table = quote_identifier(&section.name);
    let mut dictionary = std::collections::BTreeMap::<String, i64>::new();
    for row in &section.rows {
        let Some(Cell::Text(record_id)) = row.get(1) else {
            return Err(Error::engine("canonical read-log record ID must be TEXT"));
        };
        let record_ref = if let Some(record_ref) = dictionary.get(record_id) {
            *record_ref
        } else {
            sqlx::query("INSERT OR IGNORE INTO read_log_record_ids(record_id) VALUES (?)")
                .bind(record_id)
                .execute(&mut **tx)
                .await?;
            let record_ref: i64 =
                sqlx::query_scalar("SELECT record_ref FROM read_log_record_ids WHERE record_id=?")
                    .bind(record_id)
                    .fetch_one(&mut **tx)
                    .await?;
            dictionary.insert(record_id.clone(), record_ref);
            record_ref
        };
        let mut owned = row.clone();
        owned[1] = Cell::Integer(record_ref);
        insert_row_cells(tx, &quoted_table, &columns, &owned).await?;
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

    /// A populated read log in the logical shape revisions 1–3 carried.
    ///
    /// The pre-revision-4 wire format exported `read_log_touches` with a
    /// logical TEXT `record_id` column, not the physical `record_ref`
    /// dictionary integer. The 3→4 upgrade drops these sections wholesale, so
    /// only their generic section shape and presence matter here.
    fn read_log_sections(revision: u64) -> Vec<Section> {
        vec![
            Section {
                format: SECTION_FORMAT.into(),
                revision,
                name: "read_log_calls".into(),
                columns: vec![
                    Column {
                        name: "seq".into(),
                        declared_type: "INTEGER".into(),
                    },
                    Column {
                        name: "id".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "tool".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "outcome".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "started_at".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "ended_at".into(),
                        declared_type: "TEXT".into(),
                    },
                ],
                primary_key: vec!["seq".into()],
                rows: vec![vec![
                    Cell::Integer(1),
                    Cell::Text("portable-call".into()),
                    Cell::Text("get_record".into()),
                    Cell::Text("ok".into()),
                    Cell::Text("2026-09-12T00:00:00.000Z".into()),
                    Cell::Text("2026-09-12T00:00:00.000Z".into()),
                ]],
            },
            Section {
                format: SECTION_FORMAT.into(),
                revision,
                name: "read_log_touches".into(),
                columns: vec![
                    Column {
                        name: "call_seq".into(),
                        declared_type: "INTEGER".into(),
                    },
                    Column {
                        name: "record_id".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "interaction".into(),
                        declared_type: "TEXT".into(),
                    },
                    Column {
                        name: "result_rank".into(),
                        declared_type: "INTEGER".into(),
                    },
                ],
                primary_key: vec!["call_seq".into(), "record_id".into(), "interaction".into()],
                rows: vec![vec![
                    Cell::Integer(1),
                    Cell::Text("portable-record".into()),
                    Cell::Text("opened".into()),
                    Cell::Integer(1),
                ]],
            },
        ]
    }

    /// Insert the read-log sections in their historical position (after
    /// `schema_config`) so a downgraded bundle honestly resembles the wire
    /// format that revision actually shipped.
    fn insert_read_log_sections(bundle: &mut Bundle, revision: u64) {
        let position = bundle
            .sections
            .iter()
            .position(|section| section.name == "schema_config")
            .expect("fixture carries schema_config")
            + 1;
        for (offset, section) in read_log_sections(revision).into_iter().enumerate() {
            bundle.sections.insert(position + offset, section);
        }
    }

    fn downgrade_to_revision_1(mut bundle: Bundle) -> Bundle {
        // `record_mentions` postdates every wire revision below 4 (it first
        // ships as a revision-4 section at engine 59): a faithful revision-1
        // reconstruction carries no such section, so strip it before the
        // frozen-inventory gate counts sections.
        for name in [
            "content_event_causal_cutover",
            "content_event_causal_frontier",
            "act_state",
            "act_cutover",
            "derivation_events",
            "record_mentions",
        ] {
            let index = bundle
                .sections
                .iter()
                .position(|section| section.name == name)
                .unwrap();
            bundle.sections.remove(index);
        }
        for section in &mut bundle.sections {
            let mut upgraded_columns = section
                .columns
                .iter()
                .enumerate()
                .filter_map(|(index, column)| {
                    matches!(
                        column.name.as_str(),
                        "causal_envelope_version" | "causal_status" | "act"
                    )
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            upgraded_columns.sort_unstable_by(|left, right| right.cmp(left));
            for index in upgraded_columns {
                section.columns.remove(index);
                for row in &mut section.rows {
                    row.remove(index);
                }
            }
        }
        for section in &mut bundle.sections {
            section.revision = LEGACY_REVISION;
        }
        insert_read_log_sections(&mut bundle, LEGACY_REVISION);
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

    /// The validity section is act-stamped canonical state, and its `act`
    /// column travels through the generic section mechanism: export reads the
    /// column from `PRAGMA table_info` and import writes whatever columns the
    /// validated bundle carries, so a post-cutover validity change round-trips
    /// with its act and leaves no NULL.
    ///
    /// This is a *current-revision* round trip only. The changed validity
    /// section shape makes an old revision-3 descriptor non-interchangeable,
    /// and the revision-3→4 upgrade/downgrade fixtures that reconcile that are
    /// deliberately owned by ca5d258's single revision bump, not here.
    #[tokio::test]
    async fn validity_act_round_trips_through_current_interchange() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let (_, attestation_id, _) = populated_provenance_bundle(&source).await;
        let before_act = source.current_act().await.unwrap();

        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::provenance::append_validity_event_in(
            &mut tx,
            &mut act_alloc,
            &attestation_id,
            crate::provenance::ValidityChange::Invalidated,
            "interchange round trip",
            "test",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(source.current_act().await.unwrap(), before_act + 1);

        let bytes = export_canonical_interchange(&source).await.unwrap();
        let bundle: Bundle = serde_json::from_slice(&bytes).unwrap();
        let validity = bundle
            .sections
            .iter()
            .find(|section| section.name == "provenance_attestation_validity_events")
            .unwrap();
        let act_index = validity
            .columns
            .iter()
            .position(|column| column.name == "act")
            .expect("current export carries the validity act column");
        assert!(
            validity
                .rows
                .iter()
                .all(|row| cell_integer(&row[act_index]) == Some(before_act + 1)),
            "every exported validity row carries the transaction act"
        );

        let destination = temp.path().join("imported.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        let imported_acts: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT act FROM provenance_attestation_validity_events
              WHERE status='invalidated' ORDER BY ordinal",
        )
        .fetch_all(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(imported_acts, vec![Some(before_act + 1)]);
        let post_cutover_nulls: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_attestation_validity_events WHERE act IS NULL",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(post_cutover_nulls, 0);
        assert_eq!(imported.current_act().await.unwrap(), before_act + 1);
        imported.close().await;
        source.close().await;
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
        assert_eq!(SECTION_NAMES.len(), 99);
        for table in crate::act::CANONICAL_EVENT_TABLES {
            assert!(
                SECTION_NAMES.contains(&table),
                "canonical event table {table} is missing from interchange"
            );
        }
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
            .bundle;
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

    /// A read log is a person's attention, never shared state. It must not
    /// appear in the portable interchange surface at all: no `read_log_calls`,
    /// `read_log_touches`, or receiver-local `read_log_record_ids` section
    /// crosses, and a round trip carries no rows into the destination.
    ///
    /// This replaces the former round-trip tests that asserted the logical
    /// touch rows and their TEXT identity survived the crossing.
    #[tokio::test]
    async fn read_log_never_crosses_the_portable_interchange() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO read_log_calls (seq,id,tool,outcome,started_at,ended_at) VALUES (1,'portable-call','test','ok','2026-09-12','2026-09-12')")
            .execute(source.write_pool()).await.unwrap();
        for (index, id) in ["z", "Case", "case", "", "dangling-id", "雪"]
            .iter()
            .enumerate()
        {
            sqlx::query("INSERT INTO read_log_record_ids(record_ref,record_id) VALUES (?,?)")
                .bind(index as i64 + 1)
                .bind(id)
                .execute(source.write_pool())
                .await
                .unwrap();
            sqlx::query("INSERT INTO read_log_touches(call_seq,record_ref,interaction,result_rank) VALUES (1,?,'opened',?)")
                .bind(index as i64 + 1).bind(if index == 0 { None } else { Some(index as i64) })
                .execute(source.write_pool()).await.unwrap();
        }
        let calls: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(source.write_pool())
            .await
            .unwrap();
        let touches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches")
            .fetch_one(source.write_pool())
            .await
            .unwrap();
        assert!(calls > 0 && touches > 0, "fixture must have a read log");

        let bytes = export_canonical_interchange(&source).await.unwrap();
        let bundle: Bundle = serde_json::from_slice(&bytes).unwrap();
        for name in ["read_log_calls", "read_log_touches", "read_log_record_ids"] {
            assert!(
                !bundle.sections.iter().any(|section| section.name == name),
                "portable interchange must not carry a '{name}' section"
            );
            assert!(
                !bundle
                    .manifest
                    .sections
                    .iter()
                    .any(|descriptor| descriptor.name == name),
                "portable interchange manifest must not describe a '{name}' section"
            );
        }

        let destination = temp.path().join("imported.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        for table in ["read_log_calls", "read_log_touches", "read_log_record_ids"] {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
            assert_eq!(rows, 0, "import must not materialize '{table}' rows");
        }

        imported.close().await;
        source.close().await;
    }

    fn downgrade_to_revision_2(mut bundle: Bundle) -> Bundle {
        for name in [
            "act_state",
            "act_cutover",
            "derivation_events",
            "record_mentions",
        ] {
            let index = bundle
                .sections
                .iter()
                .position(|section| section.name == name)
                .unwrap();
            bundle.sections.remove(index);
        }
        for section in &mut bundle.sections {
            if let Some(act) = section
                .columns
                .iter()
                .position(|column| column.name == "act")
            {
                section.columns.remove(act);
                for row in &mut section.rows {
                    row.remove(act);
                }
            }
            section.revision = REVISION_2;
        }
        insert_read_log_sections(&mut bundle, REVISION_2);
        bundle.manifest.revision = REVISION_2;
        bundle.manifest.source_profile.revision = 2;
        bundle.manifest.source_engine_schema = 55;
        bundle.manifest.sections = bundle
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION_2,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section).unwrap(),
            })
            .collect();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
        bundle
    }

    fn downgrade_to_revision_3(mut bundle: Bundle) -> Bundle {
        let derivation = bundle
            .sections
            .iter()
            .position(|section| section.name == "derivation_events")
            .unwrap();
        bundle.sections.remove(derivation);
        let mentions = bundle
            .sections
            .iter()
            .position(|section| section.name == "record_mentions")
            .unwrap();
        bundle.sections.remove(mentions);
        for table in [
            "provenance_attestation_validity_events",
            "external_observations",
            "awareness_command_intents",
        ] {
            let section = bundle
                .sections
                .iter_mut()
                .find(|section| section.name == table)
                .unwrap();
            let act = section
                .columns
                .iter()
                .position(|column| column.name == "act")
                .unwrap();
            section.columns.remove(act);
            for row in &mut section.rows {
                row.remove(act);
            }
        }
        for section in &mut bundle.sections {
            section.revision = ACT_REVISION;
        }
        insert_read_log_sections(&mut bundle, ACT_REVISION);
        bundle.manifest.revision = ACT_REVISION;
        bundle.manifest.source_engine_schema = 56;
        bundle.manifest.sections = bundle
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                revision: ACT_REVISION,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section).unwrap(),
            })
            .collect();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
        bundle
    }

    fn downgrade_to_revision_4(mut bundle: Bundle) -> Bundle {
        let derivation = bundle
            .sections
            .iter()
            .position(|section| section.name == "derivation_events")
            .unwrap();
        bundle.sections.remove(derivation);
        for table in [
            "provenance_attestation_validity_events",
            "external_observations",
            "awareness_command_intents",
        ] {
            let section = bundle
                .sections
                .iter_mut()
                .find(|section| section.name == table)
                .unwrap();
            let act = section
                .columns
                .iter()
                .position(|column| column.name == "act")
                .unwrap();
            section.columns.remove(act);
            for row in &mut section.rows {
                row.remove(act);
            }
        }
        for section in &mut bundle.sections {
            section.revision = REVISION_4;
        }
        bundle.manifest.revision = REVISION_4;
        bundle.manifest.source_engine_schema = 59;
        bundle.manifest.sections = bundle
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION_4,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section).unwrap(),
            })
            .collect();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
        bundle
    }

    #[tokio::test]
    async fn revision_5_admits_data_only_62_and_63_sources_but_not_future_engine() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        let bytes = export_canonical_interchange(&source).await.unwrap();
        let mut bundle: Bundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bundle.manifest.revision, REVISION);
        for version in [62, 63, CURRENT_ENGINE_SCHEMA_VERSION] {
            bundle.manifest.source_engine_schema = version;
            validate_bundle(&bundle).unwrap();
        }
        bundle.manifest.source_engine_schema = CURRENT_ENGINE_SCHEMA_VERSION + 1;
        assert!(validate_bundle(&bundle).is_err());
        source.close().await;
    }

    /// Canonical interchange round-trips at revision 5 preserving act
    /// numbers.
    #[tokio::test]
    async fn revision_5_round_trip_preserves_act_numbers() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id":"1a7e4000-0000-4000-8000-000000000060",
                "type":"Document",
                "kind":"note",
                "name":"act round trip"
            }),
        )
        .await
        .unwrap();
        let bytes = export_canonical_interchange(&source).await.unwrap();
        let bundle: Bundle = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bundle.manifest.revision, REVISION);
        let validated = validate_canonical_interchange(&bytes).unwrap();
        assert_eq!(validated.source_revision(), REVISION);
        validated.require_native_current_revision().unwrap();
        let source_acts: Vec<Option<i64>> =
            sqlx::query_scalar("SELECT act FROM content_events ORDER BY seq")
                .fetch_all(source.write_pool())
                .await
                .unwrap();
        assert!(!source_acts.is_empty());
        assert!(source_acts.iter().all(|act| act.is_some()));

        let destination = temp.path().join("destination.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        let imported_acts: Vec<Option<i64>> =
            sqlx::query_scalar("SELECT act FROM content_events ORDER BY seq")
                .fetch_all(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(imported_acts, source_acts);
        let source_counter: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(source.write_pool())
                .await
                .unwrap();
        let imported_counter: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(imported_counter, source_counter);
        let reexported = export_canonical_interchange(&imported).await.unwrap();
        assert_eq!(reexported, bytes);
        imported.close().await;
        source.close().await;
    }

    /// Revision-5 import preserves observation and intent acts exactly and
    /// never advances the act counter: the destination re-exports
    /// byte-identical.
    #[tokio::test]
    async fn revision_5_round_trip_preserves_observation_and_intent_acts() {
        let temp = tempfile::tempdir().unwrap();
        let source =
            crate::create_database(temp.path().join("obs-intent-source.db").to_str().unwrap())
                .await
                .unwrap();
        let claim = crate::identity::BindingClaim {
            system: "native-principal".into(),
            identifier: "native/rev5-roundtrip".into(),
        };
        let actor = crate::identity::resolve_stdio_account_identity(&source, None)
            .await
            .unwrap();
        let observation = crate::identity::observe_external(
            &source,
            &crate::identity::MutationContext {
                actor: &actor,
                reason: "rev5 round trip",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: false,
                source_read_authorized: false,
            },
            std::slice::from_ref(&claim),
            &crate::identity::StubHints {
                name: Some("Rev5".into()),
                ..Default::default()
            },
            &claim,
            crate::identity::ObservationQuality::Reported,
            crate::identity::MaterializationPolicy::IdentityOnly,
            None,
            &crate::identity::ObservationProvenance::default(),
            Some("Rev5"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::awareness::register_human_batch_command(
            &mut tx,
            "acct:rev5",
            crate::awareness::HumanStage::Acknowledged,
            &[],
            &std::collections::BTreeMap::new(),
            "rev5-roundtrip-key",
            None,
            &crate::awareness::VerifiedHumanInteraction {
                nonce: "rev5".into(),
                executor_ref: "ui".into(),
            },
            "rev5",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let bytes = export_canonical_interchange(&source).await.unwrap();
        let source_observation_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM external_observations WHERE id = ?")
                .bind(&observation.observation_id)
                .fetch_one(source.write_pool())
                .await
                .unwrap();
        let source_intent_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents WHERE idempotency_key = 'rev5-roundtrip-key'",
        )
        .fetch_one(source.write_pool())
        .await
        .unwrap();
        assert!(source_observation_act.is_some());
        assert!(source_intent_act.is_some());
        let source_counter: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(source.write_pool())
                .await
                .unwrap();

        let destination = temp.path().join("obs-intent-imported.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        let imported_observation_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM external_observations WHERE id = ?")
                .bind(&observation.observation_id)
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        let imported_intent_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents WHERE idempotency_key = 'rev5-roundtrip-key'",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(imported_observation_act, source_observation_act);
        assert_eq!(imported_intent_act, source_intent_act);
        let imported_counter: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(imported_counter, source_counter);
        assert_eq!(
            export_canonical_interchange(&imported).await.unwrap(),
            bytes
        );
        imported.close().await;
        source.close().await;
    }

    #[tokio::test]
    async fn revision_5_round_trip_preserves_a_whole_act_across_content_and_derivation() {
        let temp = tempfile::tempdir().unwrap();
        let source =
            crate::create_database(temp.path().join("source-whole-act.db").to_str().unwrap())
                .await
                .unwrap();
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let content = crate::store::append_in(
            &source,
            &mut tx,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000064".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type":"Document",
                    "kind":"note",
                    "name":"whole act interchange"
                }),
                actor: Some("agent:test".into()),
            },
            &mut act_alloc,
        )
        .await
        .unwrap();
        let derivation = crate::derivation::append_derivation_event_in(
            &mut tx,
            crate::derivation::NewDerivationEvent::authored(
                "interchange-whole-act-series",
                "agent:test",
                Some("run:interchange-whole-act".into()),
                "prove whole-act carriage",
                crate::derivation::DerivationEventPayload::SeriesCreated(
                    crate::derivation::DerivationSeriesCreated {
                        id: "interchange-whole-act-series".into(),
                        series_key: "interchange:whole-act".into(),
                        definition: serde_json::json!({"kind":"test"}),
                    },
                ),
            )
            .unwrap(),
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let content_act: i64 = sqlx::query_scalar("SELECT act FROM content_events WHERE id=?")
            .bind(&content.id)
            .fetch_one(source.write_pool())
            .await
            .unwrap();
        let derivation_act: i64 =
            sqlx::query_scalar("SELECT act FROM derivation_events WHERE id=?")
                .bind(&derivation.id)
                .fetch_one(source.write_pool())
                .await
                .unwrap();
        assert_eq!(content_act, derivation_act);

        let bytes = export_canonical_interchange(&source).await.unwrap();
        let destination = temp.path().join("whole-act-imported.db");
        let imported = import_canonical_interchange(&bytes, &destination)
            .await
            .unwrap();
        let imported_content_act: i64 =
            sqlx::query_scalar("SELECT act FROM content_events WHERE id=?")
                .bind(&content.id)
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        let imported_derivation_act: i64 =
            sqlx::query_scalar("SELECT act FROM derivation_events WHERE id=?")
                .bind(&derivation.id)
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(imported_content_act, content_act);
        assert_eq!(imported_derivation_act, content_act);
        let projected: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM derivation_series WHERE id=?")
                .bind("interchange-whole-act-series")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(projected, 1, "import must rebuild derivation projections");
        assert_eq!(
            export_canonical_interchange(&imported).await.unwrap(),
            bytes
        );
        imported.close().await;
        source.close().await;
    }

    #[tokio::test]
    async fn revision_3_upgrade_is_importable_but_not_derivation_exhaustive() {
        let temp = tempfile::tempdir().unwrap();
        let source =
            crate::create_database(temp.path().join("revision-3-source.db").to_str().unwrap())
                .await
                .unwrap();
        let (_, attestation_id, _) = populated_provenance_bundle(&source).await;
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::provenance::append_validity_event_in(
            &mut tx,
            &mut act_alloc,
            &attestation_id,
            crate::provenance::ValidityChange::Invalidated,
            "revision-3 fixture",
            "test",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let current: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();
        let revision_3 = downgrade_to_revision_3(current);
        let validated =
            validate_canonical_interchange(&serde_json::to_vec(&revision_3).unwrap()).unwrap();
        assert_eq!(validated.source_revision(), ACT_REVISION);
        assert!(validated.require_native_current_revision().is_err());
        let derivation = validated
            .bundle()
            .sections
            .iter()
            .find(|section| section.name == "derivation_events")
            .unwrap();
        assert!(derivation.rows.is_empty());
        let validity = validated
            .bundle()
            .sections
            .iter()
            .find(|section| section.name == "provenance_attestation_validity_events")
            .unwrap();
        let act = validity
            .columns
            .iter()
            .position(|column| column.name == "act")
            .unwrap();
        assert!(validity
            .rows
            .iter()
            .all(|row| matches!(row[act], Cell::Null)));

        let imported = import_canonical_interchange(
            &serde_json::to_vec(&revision_3).unwrap(),
            &temp.path().join("revision-3-imported.db"),
        )
        .await
        .unwrap();
        let validity_acts: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT act FROM provenance_attestation_validity_events ORDER BY attestation_id,ordinal",
        )
        .fetch_all(imported.write_pool())
        .await
        .unwrap();
        assert!(!validity_acts.is_empty());
        assert!(validity_acts.iter().all(Option::is_none));
        assert!(crate::standby::read_authority_act_head(&imported)
            .await
            .is_err());
        let reexported = export_canonical_interchange(&imported).await.unwrap();
        let reimported = import_canonical_interchange(
            &reexported,
            &temp.path().join("revision-3-reimported.db"),
        )
        .await
        .unwrap();
        assert!(crate::standby::read_authority_act_head(&reimported)
            .await
            .is_err());
        reimported.close().await;
        imported.close().await;
        source.close().await;
    }

    /// A revision-4 document upgrades to revision 5 with trailing NULL acts
    /// on both new act-stamped sections, preserves source_revision=4, never
    /// fabricates grouping, and imports — but is not exhaustive, so the
    /// native-delta gate rejects it.
    fn downgrade_to_branch_revision_4(mut bundle: Bundle) -> Bundle {
        let mentions = bundle
            .sections
            .iter()
            .position(|section| section.name == "record_mentions")
            .unwrap();
        bundle.sections.remove(mentions);
        for table in ["external_observations", "awareness_command_intents"] {
            let section = bundle
                .sections
                .iter_mut()
                .find(|section| section.name == table)
                .unwrap();
            let act = section
                .columns
                .iter()
                .position(|column| column.name == "act")
                .unwrap();
            section.columns.remove(act);
            for row in &mut section.rows {
                row.remove(act);
            }
        }
        for section in &mut bundle.sections {
            section.revision = REVISION_4;
        }
        bundle.manifest.revision = REVISION_4;
        bundle.manifest.source_engine_schema = 60;
        bundle.manifest.sections = bundle
            .sections
            .iter()
            .map(|section| SectionDescriptor {
                name: section.name.clone(),
                revision: REVISION_4,
                row_count: section.rows.len() as u64,
                sha256: sha256_json(section).unwrap(),
            })
            .collect();
        bundle.manifest.content_sha256 = sha256_json(&bundle.sections).unwrap();
        bundle
    }

    #[tokio::test]
    async fn both_revision_4_inventories_upgrade_without_inventing_source_history() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(
            temp.path()
                .join("rev4-inventory-source.db")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let record_id = crate::store::create_record(
            &source,
            serde_json::json!({
                "type":"Document", "kind":"note", "name":"mentions", "body":"See [[My Note]]"
            }),
        )
        .await
        .unwrap();
        let current: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();
        let main = downgrade_to_revision_4(current.clone());
        let branch = downgrade_to_branch_revision_4(current);
        assert_eq!(main.sections.len(), branch.sections.len());
        for (label, historical) in [("main", main), ("branch", branch)] {
            let bytes = serde_json::to_vec(&historical).unwrap();
            let validated = validate_canonical_interchange(&bytes).unwrap();
            assert_eq!(validated.source_revision(), REVISION_4);
            assert!(validated.require_native_current_revision().is_err());
            let mentions = validated
                .bundle()
                .sections
                .iter()
                .find(|section| section.name == "record_mentions")
                .unwrap();
            assert!(
                !mentions.rows.is_empty(),
                "{label} rev4 upgrade lost mentions"
            );
            let imported =
                import_canonical_interchange(&bytes, &temp.path().join(format!("{label}.db")))
                    .await
                    .unwrap();
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM record_mentions WHERE source_id = ?")
                    .bind(&record_id)
                    .fetch_one(imported.write_pool())
                    .await
                    .unwrap();
            assert!(count > 0, "{label} rev4 import lost mention projection");
            imported.close().await;
        }
        source.close().await;
    }

    #[tokio::test]
    async fn revision_4_upgrade_adds_null_observation_and_intent_acts() {
        let temp = tempfile::tempdir().unwrap();
        let source =
            crate::create_database(temp.path().join("revision-4-source.db").to_str().unwrap())
                .await
                .unwrap();
        // An identity-only observation and a batch intent, both stamped at
        // revision 5. Downgrading strips their acts; upgrading must restore
        // NULLs without fabricating grouping.
        let claim = crate::identity::BindingClaim {
            system: "native-principal".into(),
            identifier: "native/rev4-upgrade".into(),
        };
        let actor = crate::identity::resolve_stdio_account_identity(&source, None)
            .await
            .unwrap();
        let observation = crate::identity::observe_external(
            &source,
            &crate::identity::MutationContext {
                actor: &actor,
                reason: "rev4 upgrade fixture",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: false,
                source_read_authorized: false,
            },
            std::slice::from_ref(&claim),
            &crate::identity::StubHints {
                name: Some("Rev4".into()),
                ..Default::default()
            },
            &claim,
            crate::identity::ObservationQuality::Reported,
            crate::identity::MaterializationPolicy::IdentityOnly,
            None,
            &crate::identity::ObservationProvenance::default(),
            Some("Rev4"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::awareness::register_human_batch_command(
            &mut tx,
            "acct:rev4",
            crate::awareness::HumanStage::Acknowledged,
            &[],
            &std::collections::BTreeMap::new(),
            "rev4-key",
            None,
            &crate::awareness::VerifiedHumanInteraction {
                nonce: "rev4".into(),
                executor_ref: "ui".into(),
            },
            "rev4",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let current: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();
        assert_eq!(current.manifest.revision, REVISION);
        let revision_4 = downgrade_to_revision_4(current);
        let validated =
            validate_canonical_interchange(&serde_json::to_vec(&revision_4).unwrap()).unwrap();
        assert_eq!(validated.source_revision(), REVISION_4);
        assert!(validated.require_native_current_revision().is_err());
        for table in ["external_observations", "awareness_command_intents"] {
            let section = validated
                .bundle()
                .sections
                .iter()
                .find(|section| section.name == table)
                .unwrap();
            let act = section
                .columns
                .iter()
                .position(|column| column.name == "act")
                .unwrap();
            assert_eq!(
                section.columns[act],
                Column {
                    name: "act".into(),
                    declared_type: "INTEGER".into()
                }
            );
            assert!(!section.rows.is_empty());
            assert!(section
                .rows
                .iter()
                .all(|row| matches!(row[act], Cell::Null)));
        }

        let imported = import_canonical_interchange(
            &serde_json::to_vec(&revision_4).unwrap(),
            &temp.path().join("revision-4-imported.db"),
        )
        .await
        .unwrap();
        let observation_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM external_observations WHERE id = ?")
                .bind(&observation.observation_id)
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(observation_act, None);
        let intent_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents WHERE idempotency_key = 'rev4-key'",
        )
        .fetch_one(imported.write_pool())
        .await
        .unwrap();
        assert_eq!(intent_act, None);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(imported.write_pool())
                .await
                .unwrap(),
            source_history_application_id(REVISION_4)
        );
        assert!(crate::standby::read_authority_act_head(&imported)
            .await
            .is_err());
        imported.close().await;
        source.close().await;
    }

    /// Revision-5 import still reads
    /// revision-2 documents, leaving their rows unstamped (grouping
    /// unknown) with a recorded cutover and a zeroed counter.
    #[tokio::test]
    async fn revision_2_import_leaves_rows_unstamped_with_a_recorded_cutover() {
        let temp = tempfile::tempdir().unwrap();
        let source = crate::create_database(temp.path().join("source.db").to_str().unwrap())
            .await
            .unwrap();
        crate::store::create_record(
            &source,
            serde_json::json!({
                "id":"1a7e4000-0000-4000-8000-000000000061",
                "type":"Document",
                "kind":"note",
                "name":"legacy interchange"
            }),
        )
        .await
        .unwrap();
        let current: Bundle =
            serde_json::from_slice(&export_canonical_interchange(&source).await.unwrap()).unwrap();
        let legacy_event_count = current
            .sections
            .iter()
            .find(|section| section.name == "content_events")
            .unwrap()
            .rows
            .len() as i64;
        let legacy = downgrade_to_revision_2(current);

        let upgraded = validate_canonical_interchange(&serde_json::to_vec(&legacy).unwrap())
            .unwrap()
            .bundle;
        assert_eq!(upgraded.manifest.revision, REVISION);
        let events = upgraded
            .sections
            .iter()
            .find(|section| section.name == "content_events")
            .unwrap();
        let act = events
            .columns
            .iter()
            .position(|column| column.name == "act")
            .unwrap();
        assert!(events.rows.iter().all(|row| matches!(row[act], Cell::Null)));
        let cutover = upgraded
            .sections
            .iter()
            .find(|section| section.name == "act_cutover")
            .unwrap();
        let content_row = cutover
            .rows
            .iter()
            .find(|row| cell_text(&row[0]) == Some("content_events"))
            .unwrap();
        assert_eq!(cell_integer(&content_row[1]), Some(legacy_event_count));
        assert_eq!(cell_integer(&content_row[3]), Some(55));

        let destination = temp.path().join("legacy-imported.db");
        let imported =
            import_canonical_interchange(&serde_json::to_vec(&legacy).unwrap(), &destination)
                .await
                .unwrap();
        let stamped: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE act IS NOT NULL")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(stamped, 0);
        let counter: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_one(imported.write_pool())
            .await
            .unwrap();
        assert_eq!(counter, 0);
        imported.close().await;
        source.close().await;
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

    /// A destination-schema-pinned insert preserves every SQLite storage class
    /// exactly. `seq` and `act` travel as ordinary integer columns and the
    /// comparison is over canonical exported [`Cell`]s — never `CAST` to text —
    /// so INTEGER zero, REAL bits, BLOB bytes and NULL are all pinned.
    #[tokio::test]
    async fn pinned_ingest_preserves_every_sqlite_cell_kind_exactly() {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE pinned_cells (
                 id TEXT NOT NULL,
                 part INTEGER NOT NULL,
                 seq INTEGER,
                 act INTEGER,
                 flag INTEGER,
                 ratio REAL,
                 label TEXT,
                 payload BLOB,
                 optional TEXT,
                 PRIMARY KEY (id, part)
             )",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let (columns, primary_key) = section_shape(db.pool(), "pinned_cells").await.unwrap();
        let row = vec![
            Cell::Text("alpha".into()),
            Cell::Integer(2),
            Cell::Integer(7),
            Cell::Integer(42),
            Cell::Integer(0),
            real(1.5),
            Cell::Text("héllo".into()),
            Cell::Blob(base64::engine::general_purpose::STANDARD.encode([0x00, 0xff, 0x10, 0x7f])),
            Cell::Null,
        ];
        let section = Section {
            format: SECTION_FORMAT.into(),
            revision: REVISION,
            name: "pinned_cells".into(),
            columns,
            primary_key,
            rows: vec![row.clone()],
        };

        let mut tx = db.write_pool().begin().await.unwrap();
        let outcome = ingest_section_rows(&mut tx, &section, ConflictMode::ActLogRefuseExisting)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            outcome,
            SectionIngestOutcome {
                inserted: 1,
                identical: 0
            }
        );

        let stored = sqlx::query(
            "SELECT id, part, seq, act, flag, ratio, label, payload, optional FROM pinned_cells",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let exported = encode_row_cells(&stored, &section.columns, "pinned_cells").unwrap();
        assert_eq!(exported, row, "canonical cells must round-trip exactly");

        // Storage classes are pinned, not merely value-equal: zero stays
        // INTEGER, the REAL stays REAL, the payload is BLOB and absent is NULL.
        let classes: String = sqlx::query_scalar(
            "SELECT typeof(id) || ',' || typeof(part) || ',' || typeof(seq) || ',' ||
                    typeof(act) || ',' || typeof(flag) || ',' || typeof(ratio) || ',' ||
                    typeof(label) || ',' || typeof(payload) || ',' || typeof(optional)
               FROM pinned_cells",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            classes,
            "text,integer,integer,integer,integer,real,text,blob,null"
        );
        db.close().await;
    }

    async fn table_count(db: &Db, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn empty_section_for(db: &Db, table: &str) -> Section {
        let (columns, primary_key) = section_shape(db.pool(), table).await.unwrap();
        Section {
            format: SECTION_FORMAT.into(),
            revision: REVISION,
            name: table.into(),
            columns,
            primary_key,
            rows: Vec::new(),
        }
    }

    async fn primitive_refusal(db: &Db, section: &Section, mode: ConflictMode) -> String {
        let mut tx = db.write_pool().begin().await.unwrap();
        let error = ingest_section_rows(&mut tx, section, mode)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        error.to_string()
    }

    /// Negative zero cannot round-trip bit-exactly, so canonical validation
    /// refuses it, and the pinned primitive refuses malformed REAL/BLOB cells
    /// as errors rather than panicking. No row is left behind.
    #[tokio::test]
    async fn pinned_ingest_rejects_negative_zero_real_and_malformed_cells() {
        assert!(validate_cell(&Cell::Real("8000000000000000".into())).is_err());
        assert!(validate_cell(&Cell::Real("3ff8000000000000".into())).is_ok());
        // Positive zero is a valid canonical REAL; only negative zero is
        // unrepresentable in SQLite and refuses.
        assert!(validate_cell(&real(0.0)).is_ok());
        assert_eq!(real(0.0), Cell::Real("0000000000000000".into()));
        assert!(validate_cell(&Cell::Real("zzzzzzzzzzzzzzzz".into())).is_err());
        assert!(validate_cell(&Cell::Blob("AA".into())).is_err());
        assert!(validate_cell(&Cell::Blob("!!!!".into())).is_err());

        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE pinned_reals (
                 id TEXT NOT NULL,
                 ratio REAL,
                 payload BLOB,
                 PRIMARY KEY (id)
             )",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut section = empty_section_for(&db, "pinned_reals").await;
        for (ratio, payload) in [
            (Cell::Real("8000000000000000".into()), Cell::Null),
            (Cell::Real("zzzzzzzzzzzzzzzz".into()), Cell::Null),
            (real(1.0), Cell::Blob("AA".into())),
            (real(1.0), Cell::Blob("!!!!".into())),
        ] {
            section.rows = vec![vec![Cell::Text("k".into()), ratio, payload]];
            // The failure must surface as an error, never as a panic.
            let error = primitive_refusal(&db, &section, ConflictMode::ActLogRefuseExisting).await;
            assert!(!error.is_empty(), "malformed cell must name an error");
        }
        assert_eq!(table_count(&db, "pinned_reals").await, 0);
        db.close().await;
    }

    /// `insert_row_cells` is reached directly by the read-log reconstruction,
    /// which skips section-shape validation. Its checked conversions must
    /// return an error for malformed cells instead of panicking.
    #[tokio::test]
    async fn insert_row_cells_errors_on_malformed_cells_instead_of_panicking() {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE raw_cells (id TEXT, ratio REAL, payload BLOB)")
            .execute(db.write_pool())
            .await
            .unwrap();
        for row in [
            vec![
                Cell::Text("a".into()),
                Cell::Real("zzzzzzzzzzzzzzzz".into()),
                Cell::Null,
            ],
            vec![
                Cell::Text("b".into()),
                Cell::Real("8000000000000000".into()),
                Cell::Null,
            ],
            vec![Cell::Text("c".into()), real(1.0), Cell::Blob("AA".into())],
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            let error = insert_row_cells(
                &mut tx,
                "\"raw_cells\"",
                "\"id\", \"ratio\", \"payload\"",
                &row,
            )
            .await
            .unwrap_err();
            assert!(!error.to_string().is_empty(), "{error}");
            tx.rollback().await.unwrap();
        }
        assert_eq!(table_count(&db, "raw_cells").await, 0);
        db.close().await;
    }

    /// A cell that SQLite's column affinity would coerce (INTEGER in a TEXT
    /// column, numeric TEXT in an INTEGER column, INTEGER in a REAL column)
    /// inserts but fails the post-insert exact re-read, so the transaction
    /// rolls back and no row remains. A canonical row then inserts and an
    /// identical retry stays an idempotent no-op.
    #[tokio::test]
    async fn pinned_ingest_refuses_affinity_coercion_and_leaves_no_row() {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE coercion (
                 id TEXT NOT NULL,
                 int_col INTEGER,
                 text_col TEXT,
                 real_col REAL,
                 PRIMARY KEY (id)
             )",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut section = empty_section_for(&db, "coercion").await;
        let coercions = [
            // INTEGER affinity would turn numeric TEXT into the integer 123.
            (Cell::Text("123".into()), Cell::Null, Cell::Null, "int_col"),
            // TEXT affinity would turn the integer into the text '123'.
            (Cell::Null, Cell::Integer(123), Cell::Null, "text_col"),
            // REAL affinity would turn the integer into the REAL 1.0.
            (Cell::Null, Cell::Null, Cell::Integer(1), "real_col"),
        ]
        .map(|(int_col, text_col, real_col, column)| {
            (
                vec![Cell::Text("k".into()), int_col, text_col, real_col],
                column,
            )
        });
        for (row, column) in coercions {
            section.rows = vec![row];
            let error = primitive_refusal(&db, &section, ConflictMode::ActLogRefuseExisting).await;
            assert!(
                error.contains("coerced or normalized"),
                "{column} coercion must be refused by the post-insert re-read: {error}"
            );
        }
        assert_eq!(
            table_count(&db, "coercion").await,
            0,
            "every coerced insert must roll back"
        );

        section.rows = vec![vec![
            Cell::Text("k".into()),
            Cell::Integer(5),
            Cell::Text("hello".into()),
            real(2.5),
        ]];
        let mut tx = db.write_pool().begin().await.unwrap();
        let inserted = ingest_section_rows(&mut tx, &section, ConflictMode::ActLogRefuseExisting)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(inserted.inserted, 1);

        let mut tx = db.write_pool().begin().await.unwrap();
        let retry = ingest_section_rows(&mut tx, &section, ConflictMode::ImmutableAllowIdentical)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!((retry.inserted, retry.identical), (0, 1));
        assert_eq!(table_count(&db, "coercion").await, 1);
        db.close().await;
    }

    /// A NULL in any declared primary-key cell is refused before SQL, and a
    /// single-column `INTEGER PRIMARY KEY` (SQLite's rowid alias) must be an
    /// Integer so SQLite cannot auto-assign or coerce a rowid. No insert or
    /// duplicate survives a refusal.
    #[tokio::test]
    async fn pinned_ingest_rejects_null_and_non_integer_primary_keys() {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE text_pk (id TEXT NOT NULL, value TEXT, PRIMARY KEY (id))")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE int_pk (rid INTEGER PRIMARY KEY, value TEXT)")
            .execute(db.write_pool())
            .await
            .unwrap();

        // TEXT primary key: NULL refuses.
        let mut text_section = empty_section_for(&db, "text_pk").await;
        text_section.rows = vec![vec![Cell::Null, Cell::Text("v".into())]];
        let error = primitive_refusal(&db, &text_section, ConflictMode::ActLogRefuseExisting).await;
        assert!(error.contains("must not be NULL"), "{error}");
        assert_eq!(table_count(&db, "text_pk").await, 0);

        // INTEGER rowid alias: NULL and non-Integer both refuse.
        let mut int_section = empty_section_for(&db, "int_pk").await;
        for (cell, needle) in [
            (Cell::Null, "must not be NULL"),
            (Cell::Text("7".into()), "must be an Integer"),
            (real(7.0), "must be an Integer"),
        ] {
            int_section.rows = vec![vec![cell, Cell::Text("v".into())]];
            let error =
                primitive_refusal(&db, &int_section, ConflictMode::ActLogRefuseExisting).await;
            assert!(error.contains(needle), "{error}");
        }
        assert_eq!(
            table_count(&db, "int_pk").await,
            0,
            "a refused rowid alias must not auto-assign a row"
        );

        // A canonical key inserts exactly once; an identical retry refuses
        // rather than duplicating.
        text_section.rows = vec![vec![Cell::Text("t1".into()), Cell::Text("v".into())]];
        let mut tx = db.write_pool().begin().await.unwrap();
        ingest_section_rows(&mut tx, &text_section, ConflictMode::ActLogRefuseExisting)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        int_section.rows = vec![vec![Cell::Integer(7), Cell::Text("v".into())]];
        let mut tx = db.write_pool().begin().await.unwrap();
        ingest_section_rows(&mut tx, &int_section, ConflictMode::ActLogRefuseExisting)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(table_count(&db, "text_pk").await, 1);
        assert_eq!(table_count(&db, "int_pk").await, 1);

        let error = primitive_refusal(&db, &text_section, ConflictMode::ActLogRefuseExisting).await;
        assert!(error.contains("refuses an existing primary key"), "{error}");
        let error = primitive_refusal(&db, &int_section, ConflictMode::ActLogRefuseExisting).await;
        assert!(error.contains("refuses an existing primary key"), "{error}");
        assert_eq!(table_count(&db, "text_pk").await, 1);
        assert_eq!(table_count(&db, "int_pk").await, 1);
        db.close().await;
    }

    /// The rowid-alias classification is case-insensitive, matching SQLite:
    /// `integer PRIMARY KEY` requires an Integer key before any SQL, while a
    /// quoted `" INTEGER "` type is not an alias and admits a non-numeric text
    /// key. Trimming would wrongly classify the quoted column as an alias.
    #[tokio::test]
    async fn pinned_ingest_classifies_rowid_alias_case_insensitively_without_trimming() {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE int_pk_lower (rid integer PRIMARY KEY, value TEXT)")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE int_pk_quoted_space (rid \" INTEGER \" PRIMARY KEY, value TEXT)")
            .execute(db.write_pool())
            .await
            .unwrap();

        let mut lower = empty_section_for(&db, "int_pk_lower").await;
        lower.rows = vec![vec![Cell::Text("7".into()), Cell::Text("v".into())]];
        let error = primitive_refusal(&db, &lower, ConflictMode::ActLogRefuseExisting).await;
        assert!(error.contains("must be an Integer"), "{error}");
        assert_eq!(table_count(&db, "int_pk_lower").await, 0);

        let mut quoted = empty_section_for(&db, "int_pk_quoted_space").await;
        quoted.rows = vec![vec![
            Cell::Text("not-an-int".into()),
            Cell::Text("v".into()),
        ]];
        let mut tx = db.write_pool().begin().await.unwrap();
        ingest_section_rows(&mut tx, &quoted, ConflictMode::ActLogRefuseExisting)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(table_count(&db, "int_pk_quoted_space").await, 1);
        let stored: String =
            sqlx::query_scalar("SELECT CAST(rid AS TEXT) FROM int_pk_quoted_space")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(stored, "not-an-int");
        db.close().await;
    }
}
