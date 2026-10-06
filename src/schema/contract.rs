//! The FROZEN v1 spine contract (task 33e5aab — critical-path step 2).
//!
//! This module pins the schema decided in Native doc 9561d43 (itself the
//! mechanical implementation of spine decision 2e5ed3e) as the frozen artifact
//! successor work derives from: tool-surface enumeration, the runtime, and
//! forkers all build against THIS contract, and `crate::conformance` enforces it
//! executably — a native-ce database either passes or it doesn't.
//!
//! Changing anything here (or in `ddl.rs`, which `FROZEN_DDL_SHA256`
//! fingerprints) is a deliberate contract revision, not a refactor: it requires
//! re-freezing the fingerprint and re-deriving the successor artifacts. Within
//! the contract, packs/users extend additively through kinds, nullable facets,
//! and substrate primitives. A core spine revision remains possible only
//! through this explicit re-freeze discipline (2e5ed3e Amendment 5).

use sha2::{Digest, Sha256};

use super::ddl::DDL_STATEMENTS;

/// The stable meaning of one member of the closed spine-type vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpineTypeMeaning {
    pub name: &'static str,
    pub short_gloss: &'static str,
    pub gloss: &'static str,
}

/// The current build's closed engine contract and its human-readable meanings.
/// Schema numbers used during development are not support baselines; only the
/// current DDL and constants below are authoritative until a baseline is
/// deliberately activated. `kind` remains the open-additive extension point.
pub const SPINE_TYPE_MEANINGS: [SpineTypeMeaning; 10] = [
    SpineTypeMeaning {
        name: "Document",
        short_gloss: "content",
        gloss: "Authored or captured content whose primary value is what it says. Common kinds distinguish notes, pages, attachments, and other content forms.",
    },
    SpineTypeMeaning {
        name: "Program",
        short_gloss: "operational definition",
        gloss: "A stable authored operational definition whose constitutive meaning is supplied by a declared interpreter. The Program owns the editable lineage; immutable publications own exact behaviour, executions are separate invocations, and outputs keep their own carrier identity.",
    },
    SpineTypeMeaning {
        name: "WorkItem",
        short_gloss: "Actionable work",
        gloss: "Actionable work that can carry lifecycle, ownership, dependencies, and coordination state. Kinds distinguish tasks and other work shapes.",
    },
    SpineTypeMeaning {
        name: "Outcome",
        short_gloss: "result",
        gloss: "A desired or measured result such as a goal or target. Link work to outcomes instead of treating the outcome as another task.",
    },
    SpineTypeMeaning {
        name: "Entity",
        short_gloss: "subject",
        gloss: "A durable subject such as a person, organization, place, product, or concept. Entity records are also the portable identities used by ownership and membership-related data.",
    },
    SpineTypeMeaning {
        name: "Collection",
        short_gloss: "grouping",
        gloss: "A containing or curated grouping. `kind:folder` is the canonical containment target; other kinds may describe governed collections without changing the one-home rule.",
    },
    SpineTypeMeaning {
        name: "Resolution",
        short_gloss: "resolved position",
        gloss: "A durable choice, policy, constraint, or other resolved position. Use links to show what it governs, implements, or supersedes.",
    },
    SpineTypeMeaning {
        name: "Conversation",
        short_gloss: "exchange",
        gloss: "A continuing exchange that contains or organizes messages. It is a record with history and policy, not an out-of-band chat container.",
    },
    SpineTypeMeaning {
        name: "Message",
        short_gloss: "communication",
        gloss: "One communication event within a conversation, with an explicit audience and expectation semantics. Use messaging tools for operations whose invariants span the conversation.",
    },
    SpineTypeMeaning {
        name: "Annotation",
        short_gloss: "Commentary",
        gloss: "Commentary or a proposed change attached to another record. Kinds distinguish comments, suggestions, and other annotation forms without widening the spine.",
    },
];

/// Concise agent-facing meanings for the closed spine types.
///
/// The write contract uses these compact forms while the record-types guide
/// uses the full glosses from the same ordered entries. Keeping both forms in
/// one catalog prevents either surface from growing a second vocabulary.
pub const SPINE_TYPE_GLOSSES: [(&str, &str); 10] = [
    (
        SPINE_TYPE_MEANINGS[0].name,
        SPINE_TYPE_MEANINGS[0].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[1].name,
        SPINE_TYPE_MEANINGS[1].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[2].name,
        SPINE_TYPE_MEANINGS[2].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[3].name,
        SPINE_TYPE_MEANINGS[3].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[4].name,
        SPINE_TYPE_MEANINGS[4].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[5].name,
        SPINE_TYPE_MEANINGS[5].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[6].name,
        SPINE_TYPE_MEANINGS[6].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[7].name,
        SPINE_TYPE_MEANINGS[7].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[8].name,
        SPINE_TYPE_MEANINGS[8].short_gloss,
    ),
    (
        SPINE_TYPE_MEANINGS[9].name,
        SPINE_TYPE_MEANINGS[9].short_gloss,
    ),
];

/// Inline-alternatives limit for governance failure messages. When the valid
/// set holds this many entries or fewer, refusals and warnings name the
/// alternatives inline; larger sets name the exact `schema_read`
/// `preview_record_shape` / `manage_vocabularies.list_values` call instead.
/// Sized at 10 so the closed spine-type set always lists inline.
pub const GOVERNANCE_INLINE_ALTERNATIVES_LIMIT: usize = 10;

/// Name-only compatibility projection for validation and schema enumeration.
pub const SPINE_TYPES: [&str; 10] = [
    SPINE_TYPE_MEANINGS[0].name,
    SPINE_TYPE_MEANINGS[1].name,
    SPINE_TYPE_MEANINGS[2].name,
    SPINE_TYPE_MEANINGS[3].name,
    SPINE_TYPE_MEANINGS[4].name,
    SPINE_TYPE_MEANINGS[5].name,
    SPINE_TYPE_MEANINGS[6].name,
    SPINE_TYPE_MEANINGS[7].name,
    SPINE_TYPE_MEANINGS[8].name,
    SPINE_TYPE_MEANINGS[9].name,
];

/// Direction contract for a guaranteed generic graph link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpineRelationshipDirection {
    /// The assertion is from source to target; reversing endpoints is a
    /// distinct assertion even when the relationship's everyday wording can
    /// sound symmetric.
    Directed,
}

/// The stable meaning of one guaranteed generic graph relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpineRelationshipMeaning {
    pub name: &'static str,
    pub direction: SpineRelationshipDirection,
    pub gloss: &'static str,
}

/// The guaranteed relationship vocabulary. The `links.relationship` string is
/// open-additive; these nine are the guaranteed interop floor every install must
/// be able to store — shared skills hard-dispatch on them.
pub const SPINE_RELATIONSHIP_MEANINGS: [SpineRelationshipMeaning; 9] = [
    SpineRelationshipMeaning {
        name: "relates_to",
        direction: SpineRelationshipDirection::Directed,
        gloss: "A deliberately weak association when no stronger guaranteed relationship is true.",
    },
    SpineRelationshipMeaning {
        name: "implements",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source realizes or carries out the target specification, resolution, or requirement.",
    },
    SpineRelationshipMeaning {
        name: "depends_on",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source cannot complete correctly without the target.",
    },
    SpineRelationshipMeaning {
        name: "blocks",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source currently prevents the target from progressing. This is directional and is not automatically inferred from `depends_on`.",
    },
    SpineRelationshipMeaning {
        name: "supersedes",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source replaces the target while preserving an explicit historical trail.",
    },
    SpineRelationshipMeaning {
        name: "owned_by",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source is accountable to the target entity or ownership record. This link can add context beyond the first-class owner facet.",
    },
    SpineRelationshipMeaning {
        name: "member_of",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source participates in the target group or collection without implying containment.",
    },
    SpineRelationshipMeaning {
        name: "part_of",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source is a constituent of the target whole. It is semantic composition, not the canonical browse home.",
    },
    SpineRelationshipMeaning {
        name: "derived_from",
        direction: SpineRelationshipDirection::Directed,
        gloss: "The source was produced from the target and should retain that provenance.",
    },
];

/// Name-only compatibility projection for validation and schema enumeration.
pub const SPINE_RELATIONSHIPS: [&str; 9] = [
    SPINE_RELATIONSHIP_MEANINGS[0].name,
    SPINE_RELATIONSHIP_MEANINGS[1].name,
    SPINE_RELATIONSHIP_MEANINGS[2].name,
    SPINE_RELATIONSHIP_MEANINGS[3].name,
    SPINE_RELATIONSHIP_MEANINGS[4].name,
    SPINE_RELATIONSHIP_MEANINGS[5].name,
    SPINE_RELATIONSHIP_MEANINGS[6].name,
    SPINE_RELATIONSHIP_MEANINGS[7].name,
    SPINE_RELATIONSHIP_MEANINGS[8].name,
];

/// Stable identities for the two engine-created filing records. They are
/// content records (and therefore event-sourced), not meta-tier objects.
pub const ROOT_RECORD_ID: &str = "native:root";
pub const UNFILED_RECORD_ID: &str = "native:unfiled";

/// The neutral display name every genesis path installs on `native:root` when
/// nothing better is known. The root record IS the workspace, and its name is
/// display-only: nothing downstream derives an identifier, handle, or URL from
/// it, so renaming it later is a pure presentation change. Deployment-specific
/// naming (the hosted per-account derivation) overrides this at genesis rather
/// than renaming after the fact.
pub const DEFAULT_WORKSPACE_NAME: &str = "Workspace";

/// Fixed content identities installed only by the sealed instruction
/// provisioning workflow. Keeping the catalog beside the other engine-owned
/// record ids gives live admission one explicit allowlist without teaching it
/// to trust forgeable event actors.
pub(crate) const INSTRUCTIONS_FOLDER_ID: &str = "native:agent-instructions";
pub(crate) const WORKSPACE_INSTRUCTIONS_ID: &str = "native:workspace-agent-instructions";
pub(crate) const OWNER_GUIDANCE_ID: &str = "native:onboarding-owner-guidance";
pub(crate) const OWNER_CRITERIA_ID: &str = "native:onboarding-owner-completion";
pub(crate) const MEMBER_GUIDANCE_ID: &str = "native:onboarding-member-guidance";
pub(crate) const MEMBER_CRITERIA_ID: &str = "native:onboarding-member-completion";
pub(crate) const GUEST_GUIDANCE_ID: &str = "native:onboarding-guest-guidance";
pub(crate) const ENGINE_PROVISIONED_RECORD_IDS: [&str; 7] = [
    INSTRUCTIONS_FOLDER_ID,
    WORKSPACE_INSTRUCTIONS_ID,
    OWNER_GUIDANCE_ID,
    OWNER_CRITERIA_ID,
    MEMBER_GUIDANCE_ID,
    MEMBER_CRITERIA_ID,
    GUEST_GUIDANCE_ID,
];

/// The 4 spine facet keys (2e5ed3e Am.2 §3 + Am.3), promoted to columns on
/// `records`. `persistence` is NON-NULL enumerated (Am.4) — dedup/merge
/// fails-wrong without it.
pub const SPINE_FACET_KEYS: [&str; 4] = ["lifecycle", "owner", "persistence", "maturity"];

/// The closed value set for the `persistence` spine facet.
pub const PERSISTENCE_VALUES: [&str; 2] = ["enduring", "occurrent"];

/// ENGINE-RESERVED facet keys (docs/tool-surface.md, tools 9 + 21). Reserved is a
/// stronger claim than spine: spine facets stay user-configurable (bounded by the
/// interop floor, 3057bba); reserved keys are NOT user-configurable at all, in
/// either direction, because the engine itself writes and hard-dispatches on them
/// (`archive_record` owns `archived`; the attachment tools own `blob_ref`;
/// `manage_canvas.promote` owns `canvas.promoted_from`; `archive_record` owns
/// `retraction` when a comment's author retracts it).
/// Enforced at the schema_config write path (`crate::meta::schema_config`) and
/// at every caller-supplied facet seam through
/// `crate::domain_transaction::assert_open_facet_key` and
/// `crate::domain_transaction::classify_facet_key`, which both read this one
/// constant. The DDL fingerprint does not include
/// this Rust contract constant, so extending the set is not a schema re-freeze.
pub const RETRACTION_FACET_KEY: &str = "retraction";

pub const ENGINE_RESERVED_FACET_KEYS: [&str; 4] = [
    "archived",
    "blob_ref",
    crate::canvas::PROMOTED_FROM_FACET_KEY,
    RETRACTION_FACET_KEY,
];

/// Owning-tool guidance per engine-reserved key, beside the constant so the
/// two cannot drift apart without a failing test. Each fragment completes the
/// refusal `"{tool}: facet '{key}' is engine-reserved — {guidance}"`; the
/// three pre-retraction fragments reproduce their historical messages
/// byte-identically.
pub const ENGINE_RESERVED_FACET_GUIDANCE: [(&str, &str); 4] = [
    (
        "archived",
        "archive and restore via the archive_record tool",
    ),
    (
        "blob_ref",
        "create attachment bindings via the attach_text or attach_from_url tool",
    ),
    (
        crate::canvas::PROMOTED_FROM_FACET_KEY,
        "it records that a record was promoted from a canvas, and only manage_canvas.promote writes it",
    ),
    (
        RETRACTION_FACET_KEY,
        "only archive_record writes it, when a comment's author retracts it",
    ),
];

/// The `archived` reserved facet.
/// Set/unset semantics: `archived='true'` archives; UNSETTING the facet restores
/// (absence IS the restored state — `archived=false` is unrepresentable, so
/// consumers can hard-dispatch on presence alone). Kept off `lifecycle` so
/// archive/restore round-trips preserve it.
pub const ARCHIVED_FACET_KEY: &str = "archived";

/// The substrate primitives as TABLES every native-ce database must carry
/// (2e5ed3e Am.2 §1–2): Record, Event, Link, FacetValue + Blob (a978c23), plus
/// the system/meta tier (982f4b2) and the v1 search surface. FacetObservation
/// (37b7871) is the valid-time history fold paired with FacetValue's current-state
/// fold. The substrate tier is OPEN — a database may carry ADDITIONAL tables
/// (new hard-shaped data lands as a new substrate primitive, not a new top-level
/// type) and still conform; conformance requires presence, never absence, of
/// tables.
pub const REQUIRED_TABLES: [&str; 133] = [
    // Substrate primitives
    "content_events",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "content_event_sources",
    "content_event_claim_meta",
    "content_event_reaction_meta",
    "replicated_message_provenance",
    "destination_message_ingest",
    "replicated_message_references",
    "provenance_interaction_receipts",
    "provenance_action_attestations",
    "provenance_local_attestation_authority",
    "provenance_action_events",
    "provenance_action_outputs",
    "webhook_endpoints",
    "webhook_credentials",
    "webhook_deliveries",
    "provenance_attestation_validity_events",
    "policy_events",
    "relationship_events",
    "relationships",
    "relationship_endpoints",
    "relationship_legacy_links",
    "relationship_assertion_heads",
    "relationship_local_admissions",
    "effective_relationships",
    "relationship_endpoint_activity",
    "relationship_federation_events",
    "relationship_federation_quarantine",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "control_events",
    "agent_runs",
    "derivation_events",
    "derivation_series",
    "derivation_revisions",
    "derivation_revision_inputs",
    "derivation_attempts",
    "derivation_target_bindings",
    "derivation_target_publications",
    "derivation_selected_publications",
    "derivation_target_heads",
    "derivation_event_applications",
    "derivation_requests",
    "derivation_artifact_role_assignments",
    "derivation_artifact_role_retirements",
    "derivation_artifact_role_heads",
    "derivation_revision_confirmations",
    "derivation_confirmation_retractions",
    "derivation_confirmation_heads",
    "records",
    "links",
    "facet_values",
    "facet_observations",
    "facet_times",
    "annotation_targets",
    "message_audience_state",
    "message_audiences",
    "message_origin_state",
    "message_origin_principals",
    "message_conversations",
    "awareness_events",
    "awareness_command_intents",
    "human_message_awareness",
    "agent_message_dispositions",
    "awareness_event_evidence",
    "message_inbox_routing",
    "message_preferences",
    "member_destinations",
    "message_mentions",
    "record_mentions",
    "body_task_items",
    "body_blocks",
    "notification_candidate_events",
    "notification_candidates",
    "module_releases",
    "module_release_imports",
    "recipe_releases",
    "recipe_release_input_classes",
    "artifact_source_attestations",
    "artifact_inputs",
    "artifact_module_grants",
    "semantic_units",
    "unit_revisions",
    "unit_heads",
    "occurrences",
    "freshness_command_results",
    "freshness_runtime_command_results",
    "dependencies",
    "dependency_assessments",
    "receipts",
    "receipt_provenance",
    "receipt_comparisons",
    "receipt_uncertainty_lineage",
    "reconciliations",
    "unit_supersessions",
    "dependency_audits",
    "canvas_objects",
    "canvas_batches",
    "blobs",
    "bindings",
    "binding_systems",
    "binding_audit",
    "external_observations",
    "database_identity",
    "database_identity_audit",
    "record_policies",
    "policy_entries",
    "authorization_revision",
    "member_contexts",
    "instruction_bindings",
    "onboarding_programmes",
    "onboarding_programme_sources",
    "member_obligations",
    "member_obligation_progress",
    "seeded_instruction_sources",
    "alpha_tab_installs",
    "alpha_tab_orders",
    "control_event_applications",
    "storage_portability_policy",
    // The meta tier's own authoritative log (ba9f97e). It sits with the logs
    // rather than with the meta tables below because it is a log, not a
    // projection — the meta tables are what it folds into.
    "meta_events",
    // Search (v1) + dormant embedding seam. `records_name_idx` is the unstemmed
    // `unicode61` sibling over `name` (3c40677): a REPAIR, not an optional extra
    // — without it `runni*` silently returns 0 against porter's stored stem, so a
    // fork that drops it has broken prefix recall and no failing test to show it.
    "records_fts",
    "records_name_idx",
    "embeddings",
    // System / meta tier (982f4b2) — projections of `meta_events` since ba9f97e.
    "vocabularies",
    "vocabulary_values",
    "vocabulary_value_json_nodes",
    "schema_config",
    "workspace_rule_installations",
    "jobs",
    // The read log (fbfaf25 §2.2). Required as PRESENCE, like everything else
    // here: a fresh/standard schema must create both tables, and structural
    // conformance reports them missing if a user later exercises the promise to
    // delete this disposable history. Tool operation remains independent of the
    // tables; behavioral responses stay identical apart from explicitly
    // enumerated exemptions, while `describe_schema` correctly mirrors the
    // physical drop. Recreating the tables restores structural conformance. The
    // `read-log-disposability` check holds the operational half of that split.
    "read_log_calls",
    "read_log_record_ids",
    "read_log_touches",
];

/// The column set of the authoritative CONTENT log — the content replay
/// contract's shape.
///
/// `run_key`, `parent_key` and `intent` (fbfaf25 §2.1) are in the SHAPE but not
/// in the FOLD: they are caller-stamped annotations the projector must never
/// read. Being listed here means a conforming database carries them; it does not
/// mean replay consumes them, and `tests/records/annotations.rs` pins that separation.
///
/// `seq` is a database-instance-local replay position. The required causal
/// envelope and normalized frontier carry event causality; neither local replay
/// position nor run hierarchy may be substituted for causal ancestry.
///
/// `reason` is deliberately absent. Per the payload-vs-column principle,
/// structural correlation keys are columns and prose is payload — `reason` lands
/// in the event JSON, which is why the write-path break needs no DDL change of
/// its own.
pub const EVENT_COLUMNS: [&str; 12] = [
    "seq",
    "id",
    "record_id",
    "type",
    "payload",
    "actor",
    "run_key",
    "parent_key",
    "intent",
    "causal_envelope_version",
    "causal_status",
    "created_at",
];

/// Opaque event-id edges comprising each content event's causal frontier.
/// `parent_event_id` intentionally has no foreign key because governed imports
/// may truthfully name a causal parent which has not arrived locally.
pub const CONTENT_EVENT_CAUSAL_FRONTIER_COLUMNS: [&str; 2] = ["event_id", "parent_event_id"];

/// Database-local migration boundary separating honest legacy unknowns from
/// the post-cutover causal admission contract. The stored sequence is not
/// itself a causal claim.
pub const CONTENT_EVENT_CAUSAL_CUTOVER_COLUMNS: [&str; 4] = [
    "singleton",
    "last_legacy_local_seq",
    "cutover_at",
    "from_engine_schema",
];

/// Source facts retained for identity-preserving Native Message creation.
/// Locally authored exportable Messages gain the same row when first sealed.
pub const CONTENT_EVENT_SOURCE_COLUMNS: [&str; 6] = [
    "event_id",
    "origin_database_id",
    "source_seq",
    "source_record_id",
    "source_principal",
    "source_fingerprint",
];

/// The column set of the authoritative META log (ba9f97e). Deliberately the same
/// shape as [`EVENT_COLUMNS`] except for the subject column: meta mutations are
/// not record-scoped, so `record_id` becomes `subject_id` — the id of the meta
/// row the event acts on (`voc:maturity`, `vv:voc:maturity:decided`, `pack:…`).
/// That one substitution is the whole structural difference between the tiers'
/// logs, and naming it honestly is why the meta log could never live in the
/// content log's `record_id TEXT NOT NULL`.
pub const META_EVENT_COLUMNS: [&str; 7] = [
    "seq",
    "id",
    "subject_id",
    "type",
    "payload",
    "actor",
    "created_at",
];

/// Canonical envelope of the independent portable instruction-control log.
/// Payload schema evolution uses the explicit per-event `schema_version`; the
/// engine rejects versions and event types it cannot deterministically fold.
pub const CONTROL_EVENT_COLUMNS: [&str; 12] = [
    "seq",
    "id",
    "idempotency_key",
    "type",
    "schema_version",
    "aggregate_kind",
    "aggregate_id",
    "actor",
    "run_key",
    "reason",
    "payload",
    "created_at",
];

/// Canonical envelope of the independent generic derivation log. It mirrors
/// the instruction-control envelope while remaining a separate authority and
/// replay boundary.
pub const DERIVATION_EVENT_COLUMNS: [&str; 12] = [
    "seq",
    "id",
    "idempotency_key",
    "type",
    "schema_version",
    "aggregate_kind",
    "aggregate_id",
    "actor",
    "run_key",
    "reason",
    "payload",
    "created_at",
];

/// Durable operational request rows are not replay projections, but their
/// lease and result fences are still part of the conforming engine shape.
pub const DERIVATION_REQUEST_COLUMNS: [&str; 26] = [
    "id",
    "request_key_sha256",
    "request_identity",
    "series_id",
    "definition_sha256",
    "canonical_request",
    "recipe_revision",
    "effective_source_boundary",
    "target_basis",
    "budget",
    "audience_sha256",
    "requested_by",
    "requested_run_key",
    "state",
    "lease_owner",
    "lease_run_key",
    "lease_generation",
    "lease_expires_at",
    "attempt_count",
    "retryable",
    "next_attempt_at",
    "failure_code",
    "failure_metadata",
    "result_revision_id",
    "created_at",
    "updated_at",
];

/// Canonical envelope of the co-located relationship/assertion authority log.
pub const RELATIONSHIP_EVENT_COLUMNS: [&str; 13] = [
    "seq",
    "id",
    "stream_kind",
    "stream_id",
    "stream_version",
    "relationship_origin_db_id",
    "relationship_id",
    "type",
    "payload",
    "actor",
    "issuer_origin_db_id",
    "occurred_at",
    "ingested_at",
];

/// Domain-qualified output membership shared by content and relationship
/// events. The output-event foreign key is checked by provenance conformance.
pub const PROVENANCE_ACTION_OUTPUT_COLUMNS: [&str; 4] = [
    "action_attestation_id",
    "ordinal",
    "output_domain",
    "output_event_id",
];

pub const RELATIONSHIP_COLUMNS: [&str; 19] = [
    "relationship_origin_db_id",
    "relationship_id",
    "relationship_revision",
    "relationship_type",
    "type_definition_id",
    "canonical_proposition_key",
    "endpoint_semantics",
    "identity_qualifiers",
    "reducer_id",
    "reducer_version",
    "stream_version",
    "status",
    "successor_origin_db_id",
    "successor_relationship_id",
    "created_event_issuer_origin_db_id",
    "created_event_id",
    "last_event_issuer_origin_db_id",
    "last_event_id",
    "occurred_at",
];

pub const RELATIONSHIP_ENDPOINT_COLUMNS: [&str; 8] = [
    "relationship_origin_db_id",
    "relationship_id",
    "ordinal",
    "role",
    "portable_ref",
    "record_type",
    "record_kind",
    "record_id",
];

pub const RELATIONSHIP_LEGACY_LINK_COLUMNS: [&str; 6] = [
    "relationship_origin_db_id",
    "relationship_id",
    "relationship_token",
    "note",
    "created_at",
    "source_facts",
];

/// Portable assertion head. Receiver-local admission is intentionally absent.
pub const RELATIONSHIP_ASSERTION_HEAD_COLUMNS: [&str; 23] = [
    "issuer_origin_db_id",
    "assertion_id",
    "relationship_origin_db_id",
    "relationship_id",
    "relationship_revision",
    "relationship_created_event_issuer_origin_db_id",
    "relationship_created_event_id",
    "stream_version",
    "stance",
    "semantic_claimant",
    "on_behalf_of",
    "rationale",
    "valid_from",
    "valid_until",
    "causal_parents",
    "origin_admission",
    "authoring_action_attestation_id",
    "state",
    "created_event_issuer_origin_db_id",
    "created_event_id",
    "last_event_issuer_origin_db_id",
    "last_event_id",
    "occurred_at",
];

/// Canonical serialization of the DDL, the input to the frozen fingerprint.
pub fn canonical_ddl() -> String {
    DDL_STATEMENTS.join("\n;\n")
}

/// Fingerprint the DDL as currently compiled into this build.
pub fn ddl_sha256() -> String {
    hex::encode(Sha256::digest(canonical_ddl().as_bytes()))
}

/// Rewrite the fresh `alpha_tab_installs` CREATE to its pre-72 shape for a
/// historical version: the two-value adoption CHECK and no request column
/// (task `f1d80b0`). Shared by `historical()` below and the 64→65 twin
/// test, so the transition text and the version gate cannot drift apart.
#[cfg(any(test, feature = "turso-local"))]
pub(crate) fn alpha_tab_installs_create_for_version(statement: &str, version: i64) -> String {
    let mut statement = statement.to_owned();
    if statement.starts_with("CREATE TABLE alpha_tab_installs (") {
        if version < 79 {
            statement = statement.replace(
                "     body_read_admission_event_id TEXT REFERENCES control_events(id),\n",
                "",
            );
        }
        if version < 78 {
            statement = statement.replace(
                "     adoption_provenance       TEXT CHECK (adoption_provenance IS NULL OR (json_valid(adoption_provenance) AND json_type(adoption_provenance) = 'object')),\n", "");
        }
        if version < 72 {
            statement = statement.replace(
                "     adoption                  TEXT NOT NULL CHECK (adoption IN ('caller_asserted','shell_adopt.v1','shell_auto.v1')),\n     request                   TEXT CHECK (request IS NULL OR (length(trim(request)) > 0 AND length(request) <= 500)),\n",
                "     adoption                  TEXT NOT NULL CHECK (adoption IN ('caller_asserted','shell_adopt.v1')),\n");
        }
    }
    statement
}

/// The current build's pinned DDL fingerprint.
///
/// This is an integrity gate for the schema compiled into this binary. It does
/// not record or imply support for any historical engine schema. A future
/// support baseline must deliberately add its own fixture and fingerprint as
/// part of the activation checklist in `docs/schema-migrations.md`.
// Measured from this tree's whole production modules with pinned Rust 1.98.0:
// 358 statements, with independent canonical-byte SHA agreement and the same
// DDL output from the schema-measurement harness.
pub const FROZEN_DDL_SHA256: &str =
    "0209d608f9d5b9bd88bde3b8da411057cfc7396149ba5f4918b0921207a10a9c";

/// Engine81 DDL before the facet-value node table. Measured from exact
/// ce3f5694's whole production modules with pinned Rust 1.98.0:
/// 357 statements / 150715 bytes, independently canonical-byte hashed.
pub const FROZEN_DDL_SHA256_PRE_82: &str =
    "be2bb309ab44f48c5196b31b0bb1f263da29d6340adf7cfcf44557dcecd10bfd";

/// Genuine workspace80 DDL on immutable main
/// `37524cedb45f5dccb63b4e33dd364092ad91ff68`, before config JSON nodes.
/// Its whole production canonical functions reproduce that tree's frozen pin:
/// 356 statements / 150015 bytes, independently byte-hashed with Rust 1.98.0.
pub const FROZEN_DDL_SHA256_PRE_81: &str =
    "ef05dfa0101e252ac9ac9881585a5237424916be174f5b151d4341d8c0c32aa2";

/// Released schema79 before workspace installations.
pub const FROZEN_DDL_SHA256_PRE_80: &str =
    "b4d9d0b25b4250c0b8899588e4300b6391c976f2e0571be31948825ad272b78c";

/// Released main269 v78 DDL before the inert reader pointer.
pub const FROZEN_DDL_SHA256_PRE_79: &str =
    "2b66cc4b90773c5cca5b2e903cad6c4c6831a0c36311e8fbd51707b444397383";

/// Released v77 DDL before alpha-tab adoption provenance.
pub const FROZEN_DDL_SHA256_PRE_78: &str =
    "cf9d8a6339085d67227151491e689891c7101424b48e15db71c70bc1da8d9df7";

/// Released v76 DDL before reaction metadata.
pub const FROZEN_DDL_SHA256_PRE_77: &str =
    "5997fc823b1dcb1d4cd6019d8acbcca1680519a25283153990c89482861f4da2";

/// Released v75 DDL before the vocabulary metadata node projection.
pub const FROZEN_DDL_SHA256_PRE_76: &str =
    "6da89d4400a191823c5270b1b6062de15b581a76ec64db064353e8a2794c01ee";

/// The released v74 DDL before the v75 block projection.
pub const FROZEN_DDL_SHA256_PRE_75: &str =
    "300a47089fa7b4651fd08d1915c151af36ba9449ca25ba527877dfc8f85b4840";

/// The released v73 DDL before the v74 body-task projection.
pub const FROZEN_DDL_SHA256_PRE_74: &str =
    "8c31ffbbaa7840f888811dabd583e709ffe715544d1a4880b6d88ee6a4cb5877";

/// The engine-72 fingerprint, superseded by the 72→73 currency-counts edge
/// (E3 M1). `historical(72)` must reproduce it exactly, proving the <73
/// currency strip rule; it is main `8eb9b2861`'s own frozen value.
pub const FROZEN_DDL_SHA256_PRE_73: &str =
    "195c6b0bcf6fea48f8f36839f969c9ab6f08a8549ed3f4c788b68ffd3e088434";

/// The engine-71 fingerprint, superseded by the 71→72 alpha-tab request +
/// shell-auto edge (task f1d80b0). `historical(71)` must reproduce it
/// exactly, proving the <72 adoption/request rewrite rule; it is main
/// `17f35ed1a`'s own frozen value.
pub const FROZEN_DDL_SHA256_PRE_72: &str =
    "718b9646db781f58a97c0753e14ea59d6d5f54603fcde628d0852322bd4afa5d";

/// The engine-70 fingerprint, superseded by the 70→71 field-change index
/// (task 68b48e5, `records.changes.v1`). `historical(70)` must reproduce it
/// exactly, proving the <71 strip rule; it is main `2e03ecc05`'s own frozen
/// value.
pub const FROZEN_DDL_SHA256_PRE_71: &str =
    "3ed621c8f78c08bc2b8d82c81fe94ee386f3f4810ec992c2810f300da3381a96";

/// The engine-69 fingerprint, superseded by the 69→70 `facet_times` edge
/// (task fef3469, D2 slice T2). `historical(69)` must reproduce it exactly,
/// proving the <70 strip rule; it is main `ad13d26b1`'s own frozen value.
pub const FROZEN_DDL_SHA256_PRE_70: &str =
    "93901e242e1204bbb8a55769529645b0326bc39ac5c42d96b7c7c1bb2135095e";

/// The engine-68 fingerprint, superseded by the 68→69 content-event
/// claim-metadata edge (task 73e5b92). `historical(68)` must reproduce it
/// exactly, proving the <69 strip rule.
pub const FROZEN_DDL_SHA256_PRE_69: &str =
    "d10a336345d4696f2fddaab5722335965a7423e747b94c61040929d1b41fb873";

/// The engine-67 fingerprint, superseded by the 67→68 alpha-tab order edge
/// (task c5d3820). `historical(67)` must reproduce it exactly, proving the
/// <68 strip rule.
pub const FROZEN_DDL_SHA256_PRE_68: &str =
    "68de57432c76536f4501307fff044acb68502f066577fd64e1ce75b421d0061d";

/// The engine-66 fingerprint, superseded by the 66→67 archived-projection
/// edge (E3 M1 slice 1). `historical(66)` must reproduce it exactly, proving
/// the <67 strip rule.
pub const FROZEN_DDL_SHA256_PRE_67: &str =
    "2cbc18dc616e65fbe70f1501101de5861a01942972037f577f0a7dc8aa0514d5";

/// The engine-65 fingerprint, superseded by the 65→66 grant-revision edge.
/// `historical(65)` must reproduce it exactly, proving the <66 strip rule.
pub const FROZEN_DDL_SHA256_PRE_66: &str =
    "3284d80259000f4c8ab4c88ad7ec06175561b6d526462aaf893235a8f3201111";

/// Existing historical reconstruction shared by reproducibility and allocated
/// measurement tests. This does not authorize or freeze an unmeasured history.
#[cfg(test)]
pub(crate) fn historical_ddl_for_test(version: i64) -> String {
    let mut statements = Vec::new();
    for statement in DDL_STATEMENTS {
        if version < 80 && statement.contains("workspace_rule_installations") {
            continue;
        }
        if version < 59
            && (statement.starts_with("CREATE TABLE record_mentions")
                || statement.starts_with("CREATE INDEX idx_record_mentions_"))
        {
            continue;
        }
        if version < 62
            && (statement.contains("idx_external_observations_act")
                || statement.contains("idx_awareness_command_intents_act"))
        {
            continue;
        }
        if version < 61
            && (statement.contains("idx_content_events_act")
                || statement.contains("idx_policy_events_act")
                || statement.contains("idx_awareness_events_act")
                || statement.contains("idx_notification_candidate_events_act")
                || statement.contains("idx_binding_audit_act")
                || statement.contains("idx_database_identity_audit_act")
                || statement.contains("idx_meta_events_act")
                || statement.contains("idx_control_events_act")
                || statement.contains("idx_derivation_events_act")
                || statement.contains("idx_relationship_events_act")
                || statement.contains("binding_systems_no_insert")
                || statement.contains("binding_systems_no_update")
                || statement.contains("binding_systems_no_delete"))
        {
            continue;
        }
        if version < 60 && statement.contains("idx_provenance_validity_act") {
            continue;
        }
        if version < 65
            && (statement.starts_with("CREATE TABLE alpha_tab_installs")
                || statement.starts_with("CREATE INDEX idx_alpha_tab_installs_"))
        {
            continue;
        }
        if version < 68 && statement.starts_with("CREATE TABLE alpha_tab_orders") {
            continue;
        }
        if version < 69
            && (statement.starts_with("CREATE TABLE content_event_claim_meta")
                || statement.starts_with("CREATE TRIGGER content_event_claim_meta_insert"))
        {
            continue;
        }
        if version < 74
            && (statement.starts_with("CREATE TABLE body_task_items")
                || statement.starts_with("CREATE INDEX idx_body_task_items_"))
        {
            continue;
        }
        if version < 77
            && (statement.starts_with("CREATE TABLE content_event_reaction_meta")
                || statement.starts_with("CREATE INDEX idx_content_event_reaction_meta_")
                || statement.starts_with("CREATE TRIGGER content_event_reaction_meta_insert"))
        {
            continue;
        }
        if version < 75 && statement.starts_with("CREATE TABLE body_blocks") {
            continue;
        }
        if version < 81 && statement.starts_with("CREATE TABLE schema_config_json_nodes") {
            continue;
        }
        if version < 82 && statement.starts_with("CREATE TABLE facet_value_json_nodes") {
            continue;
        }
        if version < 76 && statement.starts_with("CREATE TABLE vocabulary_value_json_nodes") {
            continue;
        }
        if version < 70
            && (statement.starts_with("CREATE TABLE facet_times")
                || statement.starts_with("CREATE INDEX idx_facet_times_"))
        {
            continue;
        }
        if version < 71 && statement.starts_with("CREATE INDEX idx_content_events_record_changes ")
        {
            continue;
        }
        if version < 66
            && (statement.starts_with("CREATE TABLE IF NOT EXISTS authorization_grant_revision")
                || statement.starts_with("INSERT OR IGNORE INTO authorization_grant_revision")
                || statement.starts_with("CREATE TRIGGER IF NOT EXISTS authorization_grant_"))
        {
            continue;
        }
        let mut statement = statement.to_owned();
        if version < 67 && statement.starts_with("CREATE TABLE records (") {
            statement = statement.replace(
                "     archived      INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1)),\n",
                "",
            );
        }
        if version < 73 && statement.starts_with("CREATE TABLE records (") {
            statement = statement.replace(
                "      -- E3 M1 currency counts (v73): caller-independent currency. is_current\n      -- is tri-state: 1 iff zero live incoming `supersedes`, NULL when >=1\n      -- live incoming leaves whole/partial scope unknown. 0 is reserved for\n      -- a future explicit whole-record assertion and is never written here\n      -- (the CHECK admits it so that assertion needs no migration).\n      -- DEFAULT 1 because a created record has no incoming links yet;\n      -- creation omits both columns so defaults apply. successor_count is\n      -- the live incoming `supersedes` count (deleted source excluded); it\n      -- may include an invisible successor but never stores/displays names.\n",
                "",
            );
            statement = statement.replace(
                "      is_current      INTEGER NULL DEFAULT 1 CHECK (is_current IS NULL OR is_current IN (0,1)),\n      successor_count INTEGER NOT NULL DEFAULT 0 CHECK (successor_count >= 0),\n",
                "",
            );
        }
        // Engine 72 (task f1d80b0) widens the alpha-tab adoption
        // CHECK to shell_auto.v1 and adds the nullable display-only
        // request column: pre-72 shapes carry the two-value CHECK
        // and no request column.
        if statement.starts_with("CREATE TABLE alpha_tab_installs (") {
            statement = alpha_tab_installs_create_for_version(&statement, version);
        }
        if version < 62
            && (statement.starts_with("CREATE TABLE external_observations")
                || statement.starts_with("CREATE TABLE awareness_command_intents"))
        {
            statement = statement.replace("     act            INTEGER,\n", "");
        }
        if version < 60
            && statement.starts_with("CREATE TABLE provenance_attestation_validity_events")
        {
            statement = statement.replace("     act            INTEGER,\n", "");
        }
        if statement.starts_with("PRAGMA user_version") {
            statement = format!("PRAGMA user_version = {version}");
        }
        statements.push(statement);
    }
    statements.join("\n;\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_ddl_fingerprint_matches_current_statements() {
        assert_eq!(ddl_sha256(), FROZEN_DDL_SHA256);
    }

    #[test]
    fn merged_historical_ddl_fingerprints_are_reproducible() {
        fn historical(version: i64) -> String {
            hex::encode(Sha256::digest(historical_ddl_for_test(version).as_bytes()))
        }

        assert_eq!(
            [
                historical(58),
                historical(59),
                historical(60),
                historical(61),
                historical(62),
                historical(63),
                historical(64),
                historical(65),
                historical(66),
                historical(67),
                historical(68),
                historical(69),
                historical(70),
                historical(71),
                historical(72),
                historical(73),
                historical(74),
                historical(75),
                historical(76),
                historical(77),
                historical(78),
                historical(79),
                historical(80),
                historical(81),
            ],
            [
                "b418f5ea746c5e791df9ec07041dbb4fdd3a5098b828de3dc3e983a456a9c755",
                "11ce556033de8ef9d11628cf27bf619632fe0448d357d8c6c2dc8b5e8542760b",
                "b0d60b656df93c2f5a722db72efa3e82b6951360e03c8000bd5a3f3e5cf7417c",
                "d6e6c4aaf797c7f4ddbf6b39b888de03774e923cc5b2f5cd2f14a25c25bd6e5a",
                "cda661e14f9631a96fce4d00d1ee057912a91056ed9f403e58359b8e8474110a",
                "0dfa34070e4d338834b837e792108daaf80d29ddb788eed4280c97953f47b2e8",
                // Engine 64 is main64's released DDL: historical(64) strips
                // the 64→65 alpha projection, reproducing main64's frozen
                // fingerprint exactly.
                "77f1fef8c81f424154e65afd978d39ebd69e5c7ab04ce97bd2aaf11f1ab896df",
                FROZEN_DDL_SHA256_PRE_66,
                FROZEN_DDL_SHA256_PRE_67,
                // Engine 67 is the pre-68 DDL: historical(67) strips the
                // 67→68 alpha-tab order table (task c5d3820), reproducing
                // the pre-68 fingerprint exactly.
                FROZEN_DDL_SHA256_PRE_68,
                // Engine 68 is the pre-69 DDL: historical(68) strips the
                // 68→69 claim-metadata table and trigger (task 73e5b92),
                // reproducing the pre-69 fingerprint exactly.
                FROZEN_DDL_SHA256_PRE_69,
                // Engine 69 is the pre-70 DDL: historical(69) strips the
                // 69→70 facet_times table and its indexes (task fef3469).
                FROZEN_DDL_SHA256_PRE_70,
                // Engine 70 is the pre-71 DDL: historical(70) strips the
                // 70→71 field-change index (task 68b48e5).
                FROZEN_DDL_SHA256_PRE_71,
                // Engine 71 is the pre-72 DDL: historical(71) restores the
                // two-value alpha-tab adoption CHECK and drops the request
                // column (task f1d80b0), reproducing the pre-72 fingerprint
                // exactly.
                FROZEN_DDL_SHA256_PRE_72,
                // Engine 72 is the pre-73 DDL: historical(72) strips the
                // 72→73 currency-counts columns (E3 M1), reproducing the
                // pre-73 fingerprint exactly.
                FROZEN_DDL_SHA256_PRE_73,
                FROZEN_DDL_SHA256_PRE_74,
                FROZEN_DDL_SHA256_PRE_75,
                FROZEN_DDL_SHA256_PRE_76,
                FROZEN_DDL_SHA256_PRE_77,
                FROZEN_DDL_SHA256_PRE_78,
                FROZEN_DDL_SHA256_PRE_79,
                FROZEN_DDL_SHA256_PRE_80,
                FROZEN_DDL_SHA256_PRE_81,
                FROZEN_DDL_SHA256_PRE_82,
            ]
        );
    }
}
