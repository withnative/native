//! Experimental bare-kernel mode (Native task 7907284). `#[cfg(test)]`
//! only (E2a; the feature-gated E2b split restores the probe feature):
//! no production seam, no frozen-contract change, no default-path change.
//!
//! A kernel database is the frozen v1 schema (`apply_schema`, untouched) PLUS
//! additive kernel tables and event folds. No `records` row exists — in
//! particular no Collection — and no v1 meta/content/identity seed runs.
//!
//! v2 slice 1 adds the owned-schema path: `create_v2_database` applies only a
//! store subset of the frozen DDL plus the kernel tables (no `records`,
//! `record_policies`, `links`, or `policy_entries` table at all), with
//! genesis and principals through the real content log. The meta log /
//! `definition_artifacts` carve-out is deferred to increment 6.
//!
//! The existing policy event log folds into a test-only kernel anchor table.
//! V1 `record_policies` remains tied to `records(id)` by frozen DDL. The
//! records-coupled nearest-anchor refresh is not used in this mode.

use crate::authorization::Capability;
use crate::db::{apply_schema, begin_write, open_database, Db};
use crate::error::Error;
use crate::error::Result;
use crate::events::EventRow;
use crate::events::{KERNEL_GENESIS_ACTOR, KERNEL_GENESIS_EVENT, KERNEL_ROOT_ID};
use crate::meta::definition_artifact::RevisionIdentity;
use crate::meta::events::MetaEventRow;
use crate::schema::DDL_STATEMENTS;
use crate::store::{append_in, AppendSpec};
use native_policy_kernel::{
    evaluate_policy_grants, resolve_effective_capability, PolicyEvaluationEntry,
    PolicyEvaluationPrincipal,
};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqliteConnection, Transaction};
use uuid::Uuid;

pub(crate) mod claims_port;
mod commit_port;
#[cfg(any(test, feature = "v2-kernel-probe"))]
#[cfg_attr(all(test, not(feature = "v2-kernel-probe")), allow(dead_code))]
pub(crate) mod historical;
pub mod hosted_identity;
pub(crate) mod legacy_history;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use legacy_history::visible as legacy_history_visible;
pub(crate) mod run_ledger;
pub(crate) mod slots;
pub mod v1_state;
// The batch and driver have no non-test caller until the Foci host lands (G6).
#[allow(dead_code)]
pub(crate) mod slots_batch;
#[cfg(test)]
mod slots_batch_tests;
// The evaluator and gate have no non-test caller until the operations land.
#[cfg(test)]
mod home_admission_tests;
#[allow(dead_code)]
pub(crate) mod slots_eval;
#[cfg(test)]
mod slots_eval_tests;
#[cfg(test)]
mod slots_gate_tests;
#[cfg(test)]
mod slots_home_for_tests;
// The gated host operations have no non-test caller until the Foci host lands.
#[allow(dead_code)]
pub(crate) mod slots_host;
// The operations have no non-test caller until the host wiring (G6) lands.
#[allow(dead_code)]
pub(crate) mod slots_ops;
#[cfg(test)]
mod slots_ops_tests;
#[cfg(test)]
mod slots_record_tests;
// The recovery helpers have no non-test caller until G6's rehome batch lands.
#[allow(dead_code)]
pub(crate) mod slots_recovery;
#[cfg(test)]
mod slots_recovery_tests;
#[cfg(test)]
mod slots_tests;
pub use claims_port::{
    claims_as, commit_claim_as, prepare_claim_as, ClaimRead, ClaimReceipt, ClaimRequest,
    ClaimResult,
};
pub use run_ledger::{
    finish_run_as, mint_run_as, open_run_as, run_intent_as, run_witness_as, set_run_intent_as,
    RunContext, Witness as RunWitness,
};
pub(crate) mod provider_catalogue;
#[cfg(test)]
mod rebind_v2;
pub(crate) mod relates_to_port;
#[cfg(test)]
pub(crate) use rebind_v2::project as project_kernel_record_rebound;
#[cfg(all(test, feature = "v2-kernel-probe"))]
use rebind_v2::rebind_record_as;
#[cfg_attr(all(test, not(feature = "v2-kernel-probe")), allow(dead_code))]
pub mod app_installs;
pub(crate) mod app_state;
#[cfg(all(test, feature = "v2-kernel-probe"))]
mod claims_port_tests;
// Default tests retain projector plumbing; the comment read/write helpers
// are exercised by the named v2 lane. Keep that lane's linting strict.
#[cfg_attr(all(test, not(feature = "v2-kernel-probe")), allow(dead_code))]
pub(crate) mod comments_v2;
pub(crate) mod messaging;
pub(crate) mod notifications;
pub use messaging::{is_message_record, MessageRules, MessageState};
#[cfg(all(test, feature = "v2-kernel-probe"))]
mod commit_port_tests;
pub(crate) mod generic_links;
pub(crate) mod hq;
pub(crate) mod record_metadata;
pub use record_metadata::{ensure_record_metadata, set_record_metadata_as, RecordMetadata};
#[cfg(any(test, feature = "v2-kernel-probe"))]
// Default tests need index/projector plumbing; query entry points are exercised
// by the probe lane. Keep dead-code linting strict when that lane is enabled.
#[cfg_attr(all(test, not(feature = "v2-kernel-probe")), allow(dead_code))]
pub(crate) mod search_v2;
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub use search_v2::ensure_search_index;
pub(crate) mod deletion;
pub(crate) mod instruction_bindings;
pub use generic_links::*;
pub use instruction_bindings::{
    import_instruction_binding_as, ImportInstructionBinding, InstructionBindingImportResult,
};
mod links_v2;
pub(crate) use commit_port::admit as admit_provider_event;
pub(crate) use commit_port::project as project_provider_outcome;
pub use commit_port::InterpretationPins;
pub use hq::*;
pub(crate) mod blobs;
pub mod workspace_metadata;
pub use relates_to_port::{
    commit_provider_as, prepare_provider_as, relations_as, ProviderReceipt, ProviderRequest,
};
#[cfg(all(test, feature = "v2-kernel-probe"))]
mod links_v2_tests;
pub(crate) use links_v2::{
    admit_link_event, check_link4_projection_authority, project_link4_added, refuse_legacy_defn4,
};
pub use links_v2::{
    describe_record_links_as, link4_as, prepare_link4_as, Link4Receipt, Link4Request,
};

/// Discover the closed W1 provider port independently of a package-specific client.
pub fn provider_port_contract() -> serde_json::Value {
    relates_to_port::contract()
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod file_tests;

const LOCAL_ACTOR: &str = "test:bare-kernel";

/// Row-shape aliases for the test-only kernel paths (clippy `type_complexity`).
type KindPinRow = (Option<String>, Option<String>, Option<i64>, Option<String>);
type RecordKeyRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);
type RecordViewRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);
type RevisePinRow = (
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);
type DescribedKinds = (
    serde_json::Value,
    bool,
    Vec<(String, Option<serde_json::Map<String, serde_json::Value>>)>,
);
type RootDumpRow = (String, Option<String>, Option<String>, i64, String);
type ScopeAdoptionDumpRow = (String, String, Option<i64>, Option<String>, i64);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelRecordPayload {
    home_id: String,
    owner_id: Option<String>,
    primary_type: Option<String>,
    kind: Option<String>,
    accession: Option<String>,
    pin: Option<RevisionIdentity>,
    interpreter: Option<String>,
    /// Generic `/2` field values. Absent on all pre-3a events; `deny_unknown`
    /// still holds because this is now a known key.
    #[serde(default)]
    fields: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelLinkPayload {
    source_id: String,
    target_id: String,
    relationship: String,
}

/// Additive kernel table. Applied AFTER the frozen DDL, so `DDL_STATEMENTS`
/// and `FROZEN_DDL_SHA256` are untouched. The columns are deliberately
/// ontology-free: no type, kind, home, or lifecycle — neutrality is
/// structural, not a renamed spine type.
pub const KERNEL_ROOTS_DDL: &str = r#"CREATE TABLE kernel_roots (
  root_id     TEXT PRIMARY KEY CHECK (length(trim(root_id)) > 0),
  parent_id   TEXT REFERENCES kernel_roots(root_id),
  owner_id    TEXT REFERENCES kernel_principals(principal_id),
  created_seq INTEGER NOT NULL CHECK (created_seq >= 1),
  created_at  TEXT NOT NULL CHECK (length(trim(created_at)) > 0)
)"#;

pub const KERNEL_POLICIES_DDL: &str = r#"CREATE TABLE kernel_policies (
  root_id TEXT PRIMARY KEY REFERENCES kernel_roots(root_id),
  created_at TEXT NOT NULL
)"#;
pub const KERNEL_POLICY_ENTRIES_DDL: &str = r#"CREATE TABLE kernel_policy_entries (
  root_id TEXT NOT NULL REFERENCES kernel_policies(root_id) ON DELETE CASCADE,
  subject_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  effect TEXT NOT NULL,
  capability TEXT NOT NULL,
  PRIMARY KEY (root_id, subject_kind, subject_id, capability)
)"#;
pub const KERNEL_RECORDS_DDL: &str = r#"CREATE TABLE kernel_records (
  id TEXT PRIMARY KEY,
  home_id TEXT NOT NULL REFERENCES kernel_roots(root_id),
  owner_id TEXT REFERENCES kernel_principals(principal_id),
  primary_type TEXT,
  kind TEXT,
  accession TEXT UNIQUE,
  pin_family TEXT,
  pin_version INTEGER,
  pin_digest TEXT,
  interpreter TEXT,
  created_seq INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  CHECK ((primary_type IS NULL AND kind IS NULL AND accession IS NULL AND pin_family IS NULL AND pin_version IS NULL AND pin_digest IS NULL)
    OR (primary_type IS NOT NULL AND kind IS NOT NULL AND accession IS NOT NULL AND pin_family IS NOT NULL AND pin_version >= 1 AND pin_digest IS NOT NULL))
)"#;
/// Generic field values (slice 2, increment 3a): one row per non-null field
/// of a `/2` record. `value_json` is the canonical JSON scalar, so equality
/// is textual. The identity uniqueness rule (family+kind+identity value) is
/// enforced by the write path and the fold, not by a DB constraint, so the
/// refusal message stays uniform.
pub const KERNEL_RECORD_FIELDS_DDL: &str = r#"CREATE TABLE kernel_record_fields (
  record_id TEXT NOT NULL REFERENCES kernel_records(id),
  name TEXT NOT NULL CHECK (length(trim(name)) > 0),
  value_json TEXT NOT NULL CHECK (length(trim(value_json)) > 0),
  created_seq INTEGER NOT NULL CHECK (created_seq >= 1),
  PRIMARY KEY (record_id, name)
)"#;
/// Scoped definition adoption (slice 2): which revision of a family applies
/// in a home subtree. Root scope means everywhere; a home scope overrides
/// for that subtree. `selected_*` NULL is the disable tombstone: the family
/// is explicitly off in this scope, not merely absent.
pub const KERNEL_ADOPTIONS_DDL: &str = r#"CREATE TABLE kernel_adoptions (
  scope_home TEXT NOT NULL REFERENCES kernel_roots(root_id),
  family TEXT NOT NULL CHECK (length(trim(family)) > 0),
  selected_version INTEGER,
  selected_digest TEXT,
  event_seq INTEGER NOT NULL CHECK (event_seq >= 1),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  PRIMARY KEY (scope_home, family),
  CHECK ((selected_version IS NULL AND selected_digest IS NULL)
    OR (selected_version >= 0 AND length(trim(selected_digest)) > 0))
)"#;
pub const KERNEL_LINKS_DDL: &str = r#"CREATE TABLE kernel_links (
  source_id TEXT NOT NULL REFERENCES kernel_records(id),
  target_id TEXT NOT NULL,
  relationship TEXT NOT NULL,
  created_seq INTEGER NOT NULL,
  PRIMARY KEY (source_id, target_id, relationship),
  CHECK (source_id <> target_id)
)"#;

/// Interpreter version for the definition language (ratified contract K4).
/// Every governed (package-defined) record event carries it alongside the
/// definition pin. Folds and replay refuse an unknown version loudly and
/// never fall back to current semantics.
pub const KERNEL_DEFINITION_INTERPRETER_V1: &str = "native.defn/1";
/// Second definition language (v2 kernel slice 2): the richer discovery
/// envelope with per-kind fields/identity/links/maturity/description. One
/// source of truth with the registry marker; the fold dispatches on the
/// pinned interpreter (contract K4) so `/1` and `/2` records coexist.
pub const KERNEL_DEFINITION_INTERPRETER_V2: &str =
    crate::meta::definition_artifact::DEFN2_INTERPRETER;
/// Third definition language (PR1 of the defaults-as-packages step): `/3` is
/// additive over `/2` — per-record identity, `choice`/`date` fields, optional
/// per-field descriptions, and non-blank required text. The fold dispatches on
/// the pinned interpreter (contract K4), so `/1`, `/2` and `/3` records
/// coexist in one database.
pub const KERNEL_DEFINITION_INTERPRETER_V3: &str =
    crate::meta::definition_artifact::DEFN3_INTERPRETER;

/// Fourth language: closed structural link selectors, inheriting `/3` fields.
pub const KERNEL_DEFINITION_INTERPRETER_V4: &str =
    crate::meta::definition_artifact::DEFN4_INTERPRETER;

/// Interpreter carried by new events, selected from immutable envelope bytes.
fn interpreter_for_bytes(artifact_bytes: &str) -> Result<&'static str> {
    if let Some(marker) = crate::structured_values::declared_language(artifact_bytes)? {
        return Ok(marker);
    }
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)?;
    if doc.get("interpreter").and_then(serde_json::Value::as_str)
        == Some(KERNEL_DEFINITION_INTERPRETER_V4)
    {
        return Ok(KERNEL_DEFINITION_INTERPRETER_V4);
    }
    if crate::meta::definition_artifact::envelope_is_defn3(artifact_bytes)? {
        Ok(KERNEL_DEFINITION_INTERPRETER_V3)
    } else if crate::meta::definition_artifact::envelope_is_defn2(artifact_bytes)? {
        Ok(KERNEL_DEFINITION_INTERPRETER_V2)
    } else {
        Ok(KERNEL_DEFINITION_INTERPRETER_V1)
    }
}

/// v2 principal directory. Rows carry no home and no policy: principals are
/// directory entries, never policy-bearing records. Ownership keys on
/// `principal_id`; `auth_binding` is how a caller credential resolves to a
/// principal, never itself an identity for ownership.
pub const KERNEL_PRINCIPALS_DDL: &str = r#"CREATE TABLE kernel_principals (
  principal_id  TEXT PRIMARY KEY CHECK (length(trim(principal_id)) > 0),
  kind          TEXT NOT NULL CHECK (kind IN ('account','agent','run')),
  display_label TEXT NOT NULL CHECK (length(trim(display_label)) > 0),
  auth_binding  TEXT NOT NULL UNIQUE CHECK (length(trim(auth_binding)) > 0)
)"#;

/// Content event type that carries v2 principal creation. Admitted by the
/// `#[cfg(test)]` intent/projector arms alongside the older kernel types;
/// production `EVENT_TYPES` is untouched.
pub const KERNEL_PRINCIPAL_CREATED_EVENT: &str = "kernel.principal_created.v1";

/// Apply the additive kernel table to a schema-only database.
pub async fn apply_kernel_schema(db: &Db) -> Result<()> {
    for ddl in V2_KERNEL_TABLES {
        sqlx::query(ddl).execute(db.write_pool()).await?;
    }
    // Probe-only (S7a) search index, scan covering index and version
    // marker, like `apply_v2_schema` above. Idempotent.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    {
        let mut tx = begin_write(db.write_pool()).await?;
        search_v2::apply_search_schema(&mut tx).await?;
        tx.commit().await?;
    }
    Ok(())
}

fn event_payload<T: serde::de::DeserializeOwned>(event: &EventRow) -> Result<T> {
    let raw = event
        .payload
        .as_deref()
        .ok_or_else(|| Error::engine("kernel event has no payload"))?;
    Ok(serde_json::from_str(raw)?)
}

/// Content-only fold: the immutable pin tuple is carried on the event.
/// Admission checks the selected artifact before append; replay does not
/// consult mutable adoption state.
fn is_record_replacement(event: &EventRow) -> bool {
    (cfg!(test) && event.event_type == "kernel.record_rebound.v1")
        || event.event_type == "kernel.import_state_delta.v1"
}

pub(crate) async fn project_kernel_record_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelRecordPayload = event_payload(event)?;
    // Legacy named identities (for example native:workspace-agent-instructions)
    // are admitted exclusively by the sealed host import event. Ordinary record
    // creation retains its UUID contract; replay retains the recorded identity.
    if event.record_id.trim().is_empty()
        || (Uuid::parse_str(&event.record_id).is_err()
            && event.event_type != "kernel.import_record_created.v1"
            && event.event_type != "kernel.import_state_delta.v1")
    {
        return Err(Error::engine("invalid kernel record identity or home"));
    }
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(&p.home_id)
            .fetch_one(&mut *conn)
            .await?;
    if !home_exists {
        return Err(Error::engine("invalid kernel record identity or home"));
    }
    if p.owner_id
        .as_deref()
        .is_some_and(|owner| owner.trim().is_empty())
    {
        return Err(Error::engine("invalid kernel record owner"));
    }
    let bare =
        p.primary_type.is_none() && p.kind.is_none() && p.accession.is_none() && p.pin.is_none();
    let package_defined = p
        .primary_type
        .as_deref()
        .is_some_and(|x| !x.trim().is_empty())
        && p.kind.as_deref().is_some_and(|x| !x.trim().is_empty())
        && p.accession.as_deref().is_some_and(|x| !x.trim().is_empty())
        && p.pin.as_ref().is_some_and(|x| {
            !x.family.trim().is_empty()
                && x.version > 0
                && x.digest.len() == 64
                && x.digest.bytes().all(|b| b.is_ascii_hexdigit())
        });
    if !bare && !package_defined {
        return Err(Error::engine(
            "invalid kernel record shape or definition pin",
        ));
    }
    // Governed records resolve their pin through retained artifact bytes —
    // never through current adoption state — and run under exactly the
    // carried interpreter version. The fold re-hashes the stored bytes
    // against the pinned digest and re-parses them to check the event's
    // declared primary_type and kind; the digest column alone is never
    // trusted. All three checks fail the fold (live and replay alike) with
    // the record and pin named.
    if let Some(pin) = &p.pin {
        // K4 pre-check: only known languages reach the byte fetch. The exact
        // match against the envelope's declared language happens below, once
        // the retained bytes are loaded (which also re-validates `/2`
        // semantics on every replay).
        if !matches!(
            p.interpreter.as_deref(),
            Some(KERNEL_DEFINITION_INTERPRETER_V1)
                | Some(KERNEL_DEFINITION_INTERPRETER_V2)
                | Some(KERNEL_DEFINITION_INTERPRETER_V3)
                | Some(KERNEL_DEFINITION_INTERPRETER_V4)
                | Some(crate::structured_values::INTERPRETER)
                | Some(crate::structured_values::INTERPRETER_V6)
        ) {
            return Err(Error::engine(format!(
                "unknown definition interpreter for kernel record {} pin {}@{}",
                event.record_id, pin.family, pin.version
            )));
        }
        let stored: Option<(String, String)> = sqlx::query_as(
            "SELECT digest, artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ?",
        )
        .bind(&pin.family)
        .bind(pin.version as i64)
        .fetch_optional(&mut *conn)
        .await?;
        let Some((stored_digest, stored_bytes)) = stored else {
            return Err(Error::engine(format!(
                "kernel record {} pins a missing definition artifact {}@{}#{}",
                event.record_id, pin.family, pin.version, pin.digest
            )));
        };
        if stored_digest != pin.digest
            || crate::meta::definition_artifact::digest_artifact_bytes(stored_bytes.as_bytes())
                != pin.digest
        {
            return Err(Error::engine(format!(
                "kernel record {} pins retained bytes that do not hash to {}@{}#{}",
                event.record_id, pin.family, pin.version, pin.digest
            )));
        }
        let parsed = crate::meta::definition_artifact::parse_artifact_envelope(&stored_bytes)?;
        // Kernel-side re-validation on every projection (live and replay):
        // `/2` semantics are checked here, never in the shared parser.
        crate::meta::definition_artifact::validate_kernel_definition_bytes(&stored_bytes)?;
        // K4 exact match: the event's interpreter must equal the language
        // the retained bytes declare (`/2`/`/3` semantics were re-validated
        // by the parse above). A `/3`-pinned event carrying `/2` — or any
        // cross — fails loudly and projects nothing.
        let expected = interpreter_for_bytes(&stored_bytes)?;
        if p.interpreter.as_deref() != Some(expected) {
            return Err(Error::engine(format!(
                "unknown definition interpreter for kernel record {} pin {}@{}",
                event.record_id, pin.family, pin.version
            )));
        }
        let stored_doc: serde_json::Value =
            serde_json::from_str(&stored_bytes).unwrap_or(serde_json::Value::Null);
        let declared_type: Option<&str> = stored_doc
            .get("primary_type")
            .and_then(serde_json::Value::as_str);
        let Some(primary_type) = &p.primary_type else {
            return Err(Error::engine(format!(
                "kernel record {} carries a pin but no primary type",
                event.record_id
            )));
        };
        if parsed.family != pin.family
            || parsed.version != pin.version
            || declared_type != Some(primary_type.as_str())
            || !crate::definition_registry::artifact_contains_kind(
                &parsed.kinds,
                p.kind.as_deref().unwrap_or_default(),
            )
        {
            return Err(Error::engine(format!(
                "kernel record {} declares primary type or kind outside its pinned artifact {}@{}#{}",
                event.record_id, pin.family, pin.version, pin.digest
            )));
        }
    }
    // Generic fields validate before the record row and project after it
    // (FK): re-validated here so replay of a tampered log fails loudly
    // instead of storing lies.
    let empty_fields = serde_json::Map::new();
    let fields = p.fields.as_ref().or_else(|| {
        crate::meta::definition_artifact::language_capabilities(p.interpreter.as_deref())
            .supports_structured_values
            .then_some(&empty_fields)
    });
    let field_rows: Vec<(String, String)> = match fields {
        None => Vec::new(),
        Some(fields) => {
            let pin = p.pin.as_ref().ok_or_else(|| {
                Error::engine("kernel record carries fields without a definition pin")
            })?;
            let stored_bytes: String = sqlx::query_scalar(
                "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
            )
            .bind(&pin.family)
            .bind(pin.version as i64)
            .bind(&pin.digest)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| {
                Error::engine(format!(
                    "kernel record {} pins a missing definition artifact {}@{}#{}",
                    event.record_id, pin.family, pin.version, pin.digest
                ))
            })?;
            let kind = p.kind.as_deref().unwrap_or_default();
            validated_field_rows(&mut *conn, &stored_bytes, &pin.family, kind, fields)
                .await?
                .0
        }
    };
    if is_record_replacement(event) {
        sqlx::query("DELETE FROM kernel_record_fields WHERE record_id=?")
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
    }
    let created_seq = if event.event_type == "kernel.import_state_delta.v1" {
        hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
        sqlx::query_scalar("SELECT created_seq FROM kernel_records WHERE id=?")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?
    } else {
        event.local_seq
    };
    let created_at = if is_record_replacement(event) {
        sqlx::query_scalar::<_, String>("SELECT created_at FROM kernel_records WHERE id=?")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?
    } else {
        event.created_at.clone()
    };
    let query = if is_record_replacement(event) {
        "UPDATE kernel_records SET id=?,home_id=?,owner_id=?,primary_type=?,kind=?,accession=?,pin_family=?,pin_version=?,pin_digest=?,interpreter=?,created_seq=?,created_at=? WHERE id=?"
    } else {
        "INSERT INTO kernel_records (id, home_id, owner_id, primary_type, kind, accession, pin_family, pin_version, pin_digest, interpreter, created_seq, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    };
    let mut query = sqlx::query(query)
        .bind(&event.record_id)
        .bind(&p.home_id)
        .bind(p.owner_id)
        .bind(p.primary_type)
        .bind(p.kind)
        .bind(p.accession)
        .bind(p.pin.as_ref().map(|x| x.family.as_str()))
        .bind(p.pin.as_ref().map(|x| x.version as i64))
        .bind(p.pin.as_ref().map(|x| x.digest.as_str()))
        .bind(p.interpreter)
        .bind(created_seq)
        .bind(&created_at);
    if is_record_replacement(event) {
        query = query.bind(&event.record_id);
    }
    query.execute(&mut *conn).await?;
    for (name, value_json) in field_rows {
        sqlx::query(
            "INSERT INTO kernel_record_fields (record_id, name, value_json, created_seq) VALUES (?, ?, ?, ?)",
        )
        .bind(&event.record_id)
        .bind(name)
        .bind(value_json)
        .bind(event.local_seq)
        .execute(&mut *conn)
        .await?;
    }
    // S7a probe index follows the projection in the same transaction.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    search_v2::refresh_search_row(&mut *conn, &event.record_id).await?;
    Ok(())
}

pub(crate) async fn project_kernel_link_added(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelLinkPayload = event_payload(event)?;
    if event.record_id != p.source_id
        || p.relationship.trim().is_empty()
        || p.source_id == p.target_id
    {
        return Err(Error::engine("invalid kernel link envelope"));
    }
    // Sources are records; targets are records or principals (never homes —
    // principals are not policy-bearing, so no capability attaches to them).
    let source_is_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(&p.source_id)
            .fetch_one(&mut *conn)
            .await?;
    let target_is_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(&p.target_id)
            .fetch_one(&mut *conn)
            .await?;
    let target_is_principal: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)")
            .bind(&p.target_id)
            .fetch_one(&mut *conn)
            .await?;
    if !source_is_record || !(target_is_record || target_is_principal) {
        return Err(Error::engine("invalid kernel link endpoints"));
    }
    // Allow-list re-validation on every projection (live and replay): a `/2`
    // source's predicate must be declared for the target definition.
    // Legacy (`relates_to`, bare, `/1`, principal-target) links pass through.
    if target_is_record {
        let src: Option<KindPinRow> = sqlx::query_as(
            "SELECT kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?",
        )
        .bind(&p.source_id)
        .fetch_optional(&mut *conn)
        .await?;
        let tgt: Option<(Option<String>, Option<String>)> =
            sqlx::query_as("SELECT primary_type, kind FROM kernel_records WHERE id = ?")
                .bind(&p.target_id)
                .fetch_optional(&mut *conn)
                .await?;
        if let (
            Some((Some(src_kind), Some(family), Some(version), Some(digest))),
            Some((tgt_type, tgt_kind)),
        ) = (src, tgt)
        {
            let stored_bytes: Option<String> = sqlx::query_scalar(
                "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
            )
            .bind(&family)
            .bind(version)
            .bind(&digest)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(bytes) = stored_bytes {
                if let Some(descriptor) = kind_descriptor(&bytes, &src_kind)? {
                    check_declared_link(
                        &descriptor,
                        &src_kind,
                        &p.relationship,
                        tgt_type.as_deref().unwrap_or_default(),
                        tgt_kind.as_deref().unwrap_or_default(),
                    )?;
                }
            }
        }
    }
    sqlx::query("INSERT INTO kernel_links (source_id, target_id, relationship, created_seq) VALUES (?, ?, ?, ?)")
        .bind(p.source_id).bind(p.target_id).bind(p.relationship).bind(event.local_seq)
        .execute(&mut *conn).await?;
    Ok(())
}

/// Content event type carrying scoped definition adoption (slice 2).
/// Admitted by the `#[cfg(test)]` intent/projector arms; production
/// `EVENT_TYPES` is untouched.
pub const KERNEL_DEFINITION_ADOPTED_EVENT: &str = "kernel.definition_adopted.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelDefinitionAdoptedPayload {
    family: String,
    selected: Option<RevisionIdentity>,
    scope_home: String,
}

/// Content event type carrying scoped package adoption (slice 3 S2b).
/// Admitted by the `#[cfg(test)]` intent/projector arms; production
/// `EVENT_TYPES` is untouched.
pub const KERNEL_PACKAGE_ADOPTED_EVENT: &str = "kernel.package_adopted.v1";

/// Selected package revision inside a scope, or an explicit disable
/// tombstone (`selected: None`). The tombstone keeps bytes and history and
/// refuses future execution; it clears nothing by itself — family pins are
/// carried by their own `kernel.definition_adopted.v1` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSelection {
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub digest: String,
}

/// Adopted package revision pin inside a scope: version plus the exact
/// package digest. `None` in the payload is the disable tombstone, which
/// still names its package through the payload's triple.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePin {
    pub version: u32,
    pub digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelPackageAdoptedPayload {
    scope_home: String,
    namespace: String,
    name: String,
    selected: Option<PackagePin>,
    /// Exact caller-asserted declaration acknowledgment: must equal the
    /// adopted manifest's declared reads as a set (empty for disable).
    /// Recorded attribution, never verified human consent.
    acknowledged_reads: Vec<String>,
}

/// Response-only multi-use freshness receipt returned to the adopting
/// caller. It is not an authority bearer and is never consulted as one: it
/// reports what was recorded (selection, ack, authorizing event seq) so
/// later readers can compare freshness against the current projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAdoptReceipt {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub selected: Option<PackageSelection>,
    pub acknowledged_reads: Vec<String>,
    pub ack_actor: String,
    pub event_seq: i64,
}

/// Scoped package selection (S2b): the current adopted revision per
/// `(scope, namespace, name)`. `selected_*` NULL is the disable tombstone.
/// `ack_*` records the caller-asserted acknowledgment, not consent.
pub const KERNEL_PACKAGE_SELECTIONS_DDL: &str = r#"CREATE TABLE kernel_package_selections (
  scope_home TEXT NOT NULL REFERENCES kernel_roots(root_id),
  namespace TEXT NOT NULL CHECK (length(trim(namespace)) > 0),
  name TEXT NOT NULL CHECK (length(trim(name)) > 0),
  selected_version INTEGER,
  selected_digest TEXT,
  ack_actor TEXT NOT NULL CHECK (length(trim(ack_actor)) > 0),
  ack_reads TEXT NOT NULL CHECK (json_valid(ack_reads) AND json_type(ack_reads) = 'array'),
  event_seq INTEGER NOT NULL CHECK (event_seq >= 1),
  created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
  PRIMARY KEY (scope_home, namespace, name),
  CHECK ((selected_version IS NULL AND selected_digest IS NULL)
    OR (selected_version >= 0 AND length(trim(selected_digest)) > 0))
)"#;

/// Fold one scoped adoption: the event is keyed by its scope home and
/// upserts that scope's row for the family. Selected pins must resolve to
/// installed bytes; anything else fails loudly and projects nothing.
pub(crate) async fn project_kernel_definition_adopted(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelDefinitionAdoptedPayload = event_payload(event)?;
    if event.record_id != p.scope_home {
        return Err(Error::engine("invalid adoption envelope"));
    }
    crate::meta::definition_artifact::validate_family_version(&p.family, 0)?;
    let scope_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(&p.scope_home)
            .fetch_one(&mut *conn)
            .await?;
    if !scope_exists {
        return Err(Error::engine("invalid adoption scope"));
    }
    if p.selected.as_ref().is_some_and(|s| s.family != p.family) {
        return Err(Error::engine(
            "definition adoption selected family mismatch",
        ));
    }
    let (version, digest) = match &p.selected {
        None => (None, None),
        Some(pin) => {
            let stored: Option<String> = sqlx::query_scalar(
                "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
            )
            .bind(&pin.family)
            .bind(pin.version as i64)
            .bind(&pin.digest)
            .fetch_optional(&mut *conn)
            .await?;
            let Some(bytes) = stored else {
                return Err(Error::engine(format!(
                    "adoption selects missing definition artifact {}@{}#{}",
                    pin.family, pin.version, pin.digest
                )));
            };
            crate::meta::definition_artifact::validate_kernel_definition_bytes(&bytes)?;
            (Some(pin.version as i64), Some(pin.digest.clone()))
        }
    };
    sqlx::query(
        "INSERT INTO kernel_adoptions (scope_home, family, selected_version, selected_digest, event_seq, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (scope_home, family) DO UPDATE SET
           selected_version = excluded.selected_version,
           selected_digest = excluded.selected_digest,
           event_seq = excluded.event_seq,
           created_at = excluded.created_at",
    )
    .bind(&p.scope_home)
    .bind(&p.family)
    .bind(version)
    .bind(digest)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Fold one scoped package adoption: the event is keyed by its scope home
/// and upserts that scope's row for the package name. An adopted revision
/// must resolve to an installed, verified package whose declared reads the
/// acknowledgment covers exactly; a tombstone carries no acknowledgment.
/// Family pins move exclusively through their own definition-adopted events,
/// never through this fold.
pub(crate) async fn project_kernel_package_adopted(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelPackageAdoptedPayload = event_payload(event)?;
    if event.record_id != p.scope_home {
        return Err(Error::engine("invalid package adoption envelope"));
    }
    let scope_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(&p.scope_home)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(false);
    if !scope_exists {
        return Err(Error::engine("invalid package adoption scope"));
    }
    let actor = event.actor.as_deref().unwrap_or("").trim();
    if actor.is_empty() {
        return Err(Error::engine("package adoption event is unattributed"));
    }
    let (version, digest) = match &p.selected {
        None => {
            if !p.acknowledged_reads.is_empty() {
                return Err(Error::engine(
                    "package disable tombstone carries no acknowledgment",
                ));
            }
            (None, None)
        }
        Some(pin) => {
            let stored = crate::meta::package::read_package_in(
                conn,
                &p.namespace,
                &p.name,
                pin.version,
                &pin.digest,
            )
            .await?
            .ok_or_else(|| Error::engine("package adoption selects a missing package revision"))?;
            // The honest writer stores sorted unique acks; the fold enforces
            // the canonical form so a forged unsorted or duplicated ack can
            // never replay, even when set-equal to the declared reads.
            let mut canon = p.acknowledged_reads.clone();
            canon.sort();
            canon.dedup();
            if canon != p.acknowledged_reads {
                return Err(Error::engine(
                    "package acknowledgment must be sorted and unique",
                ));
            }
            let mut declared = stored.manifest.declared_reads.clone();
            declared.sort();
            declared.dedup();
            if canon != declared {
                return Err(Error::engine(
                    "package acknowledgment must exactly cover the declared reads",
                ));
            }
            (Some(pin.version as i64), Some(pin.digest.clone()))
        }
    };
    let ack_reads = serde_json::to_string(&p.acknowledged_reads)?;
    sqlx::query(
        "INSERT INTO kernel_package_selections (scope_home, namespace, name, selected_version, selected_digest, ack_actor, ack_reads, event_seq, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (scope_home, namespace, name) DO UPDATE SET
           selected_version = excluded.selected_version,
           selected_digest = excluded.selected_digest,
           ack_actor = excluded.ack_actor,
           ack_reads = excluded.ack_reads,
           event_seq = excluded.event_seq,
           created_at = excluded.created_at",
    )
    .bind(&p.scope_home)
    .bind(&p.namespace)
    .bind(&p.name)
    .bind(version)
    .bind(digest)
    .bind(actor)
    .bind(&ack_reads)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelPrincipalPayload {
    kind: String,
    display_label: String,
    auth_binding: String,
}

pub(crate) async fn project_kernel_principal_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelPrincipalPayload = event_payload(event)?;
    refuse_caller_host_binding(&p.auth_binding)?;
    project_kernel_principal_payload(conn, event, p).await
}

async fn project_kernel_principal_payload(
    conn: &mut SqliteConnection,
    event: &EventRow,
    p: KernelPrincipalPayload,
) -> Result<()> {
    if Uuid::parse_str(&event.record_id).is_err()
        || !matches!(p.kind.as_str(), "account" | "agent" | "run")
        || p.display_label.trim().is_empty()
        || p.auth_binding.trim().is_empty()
    {
        return Err(Error::engine("invalid kernel principal envelope"));
    }
    sqlx::query("INSERT INTO kernel_principals (principal_id, kind, display_label, auth_binding) VALUES (?, ?, ?, ?)")
        .bind(&event.record_id).bind(&p.kind).bind(&p.display_label).bind(&p.auth_binding)
        .execute(&mut *conn).await?;
    // Principal creation grants nothing: root authority needs the explicit
    // bootstrap event below, never creation order.
    Ok(())
}

/// Content event type that names the initial workspace-root administrator.
/// Appendable exactly once per database; principal creation grants nothing.
pub const KERNEL_BOOTSTRAP_EVENT: &str = "kernel.root_admin_bootstrapped.v1";

async fn require_local_edit(conn: &mut SqliteConnection) -> Result<()> {
    let permitted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policy_entries WHERE root_id = ? AND subject_kind = 'members' AND subject_id = ? AND effect = 'allow' AND capability = 'edit')")
        .bind(KERNEL_ROOT_ID).bind(crate::authorization::MEMBERS_SUBJECT_ID)
        .fetch_one(&mut *conn).await?;
    if !permitted {
        return Err(Error::engine("kernel root lacks members/edit authority"));
    }
    Ok(())
}

/// Test-only authoring path over the real content log, with no compiled
/// primary-type arm and no v1 record row.
pub async fn create_bare_record(db: &Db) -> Result<String> {
    create_kernel_record(db, None, None, None, None).await
}

pub async fn create_package_record(
    db: &Db,
    primary_type: &str,
    kind: &str,
    accession: &str,
    family: &str,
) -> Result<String> {
    create_kernel_record(
        db,
        Some(primary_type),
        Some(kind),
        Some(accession),
        Some(family),
    )
    .await
}

async fn create_kernel_record(
    db: &Db,
    primary_type: Option<&str>,
    kind: Option<&str>,
    accession: Option<&str>,
    family: Option<&str>,
) -> Result<String> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_local_edit(&mut tx).await?;
    let pin = if let Some(family) = family {
        let (Some(primary_type), Some(kind)) = (primary_type, kind) else {
            return Err(Error::engine(
                "requested primary type disagrees with selected definition",
            ));
        };
        let selected =
            select_adoption_pin(&mut tx, family, primary_type, kind, KERNEL_ROOT_ID).await?;
        let artifact = crate::definition_registry::read_definition_artifact_on(
            &mut tx,
            family,
            selected.version,
            &selected.digest,
        )
        .await?
        .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
        (
            Some(selected),
            Some(interpreter_for_bytes(&artifact.bytes)?.to_string()),
        )
    } else {
        (None, None)
    };
    let (pin, interpreter) = pin;
    let id = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.record_created.v1".into(),
            payload: serde_json::to_value(KernelRecordPayload {
                home_id: KERNEL_ROOT_ID.into(),
                owner_id: None,
                primary_type: primary_type.map(str::to_owned),
                kind: kind.map(str::to_owned),
                accession: accession.map(str::to_owned),
                pin: pin.clone(),
                interpreter: interpreter.clone(),
                fields: None,
            })?,
            actor: Some(LOCAL_ACTOR.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Wipe every kernel and definition projection and rebuild both logs in the
/// required order: meta first (governed folds resolve pins through retained
/// bytes), then content. The single replay entry point every replay test
/// uses, so ordering can never silently differ between tests.
pub async fn replay_all_projections(db: &Db) -> Result<()> {
    messaging::migrate_command_receipts(db).await?;
    let mut tx = begin_write(db.write_pool()).await?;
    blobs::ensure_schema(&mut tx).await?;
    v1_state::ensure_schema(&mut tx).await?;
    hq::ensure_tombstones(&mut tx).await?;
    app_state::ensure_schema(&mut tx).await?;
    app_installs::ensure_schema(&mut tx).await?;
    legacy_history::ensure_schema(&mut tx).await?;
    let content = crate::conformance::rebuild::read_all_events(&mut tx).await?;
    #[allow(clippy::type_complexity)]
    let meta_rows: Vec<(i64, String, String, String, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT seq, id, subject_id, type, payload, actor, created_at FROM meta_events ORDER BY seq",
    )
    .fetch_all(&mut *tx)
    .await?;
    let meta: Vec<MetaEventRow> = meta_rows
        .into_iter()
        .map(
            |(seq, id, subject_id, event_type, payload, actor, created_at)| MetaEventRow {
                seq,
                id,
                subject_id,
                event_type,
                payload,
                actor,
                created_at,
            },
        )
        .collect();
    for table in [
        "kernel_app_actions",
        "kernel_app_package_sources",
        "kernel_app_install_outcomes",
        "kernel_app_installs",
        "kernel_app_consent_revocations",
        "kernel_app_state",
        "kernel_slot_lineage",
        "kernel_slots",
        "kernel_instruction_bindings",
        "kernel_v1_state",
        "kernel_runs",
        "kernel_provider_receipts",
        "kernel_provider_subjects",
        "kernel_provider_state",
        "kernel_link4_edges",
        "kernel_links",
        "kernel_package_selections",
        "kernel_record_fields",
        "kernel_attachment_blobs",
        "kernel_blob_handles",
        "kernel_legacy_subjects",
        "kernel_legacy_sql_events",
        "kernel_legacy_sql_progress",
        "kernel_legacy_history",
        "kernel_facets",
        "kernel_generic_links",
        "kernel_record_bodies",
        "kernel_record_metadata",
        "kernel_import_tombstones",
        "kernel_lifecycle",
        "kernel_message_receipts",
        "kernel_message_candidates",
        "kernel_message_candidate_events",
        "kernel_message_candidate_import_frontiers",
        "kernel_message_interactions",
        "kernel_personas",
        "kernel_message_destinations",
        "kernel_message_people",
        "kernel_messages",
        "kernel_comment_anchors",
        "kernel_records",
        "kernel_adoptions",
        "kernel_policy_entries",
        "kernel_policies",
        "kernel_root_bootstrap",
        // Roots before principals: homes reference their owner principal.
        "kernel_roots",
        "kernel_principals",
        "definition_adoptions",
        "definition_artifacts",
        "package_artifacts",
        "consumer_requirements",
        "rule_installations",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await?;
    }
    crate::projector::meta::replay_meta(&mut tx, &meta).await?;
    for event in &content {
        // Explicit retained-outcome route: no live write authority during replay.
        #[cfg(test)]
        if event.event_type == "kernel.record_rebound.v1" {
            rebind_v2::project(&mut tx, event, true).await?;
            record_metadata::touch_event(&mut tx, event).await?;
            continue;
        }
        if event.event_type == commit_port::PROVIDER_OUTCOME_EVENT {
            crate::projector::replay_kernel_provider(&mut tx, event).await?;
        } else if event.event_type == "kernel.link_added.v1" {
            refuse_legacy_defn4(&mut tx, event).await?;
            project_kernel_link_added(&mut tx, event).await?;
        } else if event.event_type == "kernel.link_added.v2" {
            crate::projector::replay_kernel_link4(&mut tx, event).await?;
        } else if matches!(
            event.event_type.as_str(),
            "kernel.message_created.v1"
                | "kernel.message_state.v1"
                | "kernel.message_destination_set.v1"
        ) {
            messaging::replay(&mut tx, event).await?;
        } else {
            crate::projector::project(&mut tx, event).await?;
        }
        if matches!(
            event.event_type.as_str(),
            "kernel.provider_outcome.v1" | "kernel.link_added.v1" | "kernel.link_added.v2"
        ) {
            record_metadata::touch_event(&mut tx, event).await?;
        }
    }
    // S7a: rebuild the probe search index from the replayed projections.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    search_v2::rebuild_search_index(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Every kernel and definition projection in one comparable value. Replay
/// tests snapshot this before and after `replay_all_projections`: all tables
/// are always dumped, so a reconstruction bug in any of them fails loudly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::type_complexity)]
pub struct KernelTableDump {
    pub message_candidates: Vec<(String, String, String, String, i64)>,
    pub message_candidate_events: Vec<(i64, String, String, String, String)>,
    pub message_candidate_import_frontiers: Vec<(String, i64)>,
    pub message_receipts: Vec<(String, String, String, String)>,
    pub message_interactions: Vec<(String, String, String)>,
    pub personas: Vec<(String, String, i64)>,
    pub message_destinations: Vec<(String, String, String, i64, bool)>,
    pub messages: Vec<(String, String, i64)>,
    pub message_people: Vec<(String, String)>,
    pub metadata: Vec<(String, String, Option<String>, String, i64)>,
    pub instruction_bindings: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        i64,
        bool,
        String,
        Option<String>,
        i64,
    )>,
    pub bodies: Vec<(String, String, i64)>,
    pub generic_links: Vec<(
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        bool,
        i64,
        bool,
    )>,
    pub facets: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        i64,
    )>,
    pub lifecycle: Vec<(String, bool)>,
    pub import_tombstones: Vec<(String, Option<String>, i64)>,
    pub comment_anchors: Vec<(
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        i64,
    )>,
    pub runs: Vec<(String, String, String, i64, i64, bool)>,
    pub app_state: Vec<(String, String, String, i64)>,
    pub app_installs: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        bool,
        Option<String>,
        Option<String>,
        i64,
    )>,
    pub app_package_sources: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
    )>,
    pub app_consent_revocations: Vec<(String, i64)>,
    pub app_install_outcomes: Vec<(String, String, String, String, String, i64)>,
    pub app_actions: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        i64,
    )>,
    pub legacy_sql_progress: Vec<(i64, i64)>,
    pub legacy_sql_events: Vec<(
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
    )>,

    pub v1_state: Vec<(
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        i64,
    )>,
    pub roots: Vec<RootDumpRow>,
    pub principals: Vec<(String, String, String, String)>,
    pub bootstrap: Vec<(String, i64)>,
    pub policies: Vec<(String, String)>,
    pub entries: Vec<(String, String, String, String, String)>,
    pub records: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    )>,
    pub links: Vec<(String, String, String, i64)>,
    pub link4_edges: Vec<(String, String, String, String, String, String, String, i64)>,
    pub provider_state: Vec<(String, String, String, String, i64)>,
    pub provider_receipts: Vec<(String, String, String, String, String, i64)>,
    pub provider_subjects: Vec<(String, String)>,
    pub slots: Vec<(String, String, String, i64, i64)>,
    pub slot_lineage: Vec<(String, String, i64, String, Option<String>, i64)>,
    pub record_fields: Vec<(String, String, String, i64)>,
    pub artifacts: Vec<(String, i64, String, String, String)>,
    pub adoptions: Vec<(String, Option<i64>, Option<String>, i64)>,
    pub scope_adoptions: Vec<ScopeAdoptionDumpRow>,
    pub packages: Vec<(
        String,
        String,
        String,
        Option<i64>,
        Option<String>,
        String,
        String,
        i64,
    )>,
    pub package_artifacts: Vec<(String, String, String, i64, String, String, i64, String)>,
    pub consumers: Vec<(
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        String,
    )>,
    pub installations: Vec<InstallationDumpRow>,
}

/// One comparable installation row: digests plus pins, status, and
/// attribution. Full bytes stay in the event log and the keyed read.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct InstallationDumpRow {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub revision_digest: String,
    pub settings_digest: String,
    pub settings_json: String,
    pub catalog_revision: i64,
    pub profile_id: String,
    pub profile_revision: i64,
    pub readset_digest: String,
    pub receipt_json: String,
    pub language: String,
    pub active: i64,
    pub event_seq: i64,
    pub actor: String,
}

pub async fn dump_all_kernel_tables(db: &Db) -> Result<KernelTableDump> {
    let pool = db.write_pool();
    Ok(KernelTableDump {
        legacy_sql_progress: sqlx::query_as("SELECT singleton,scanned_seq FROM kernel_legacy_sql_progress ORDER BY singleton").fetch_all(pool).await?,
        legacy_sql_events: sqlx::query_as("SELECT seq,source_id,record_id,event_type,actor,run_key,parent_key,created_at,source_stream FROM kernel_legacy_sql_events ORDER BY seq").fetch_all(pool).await?,
        app_installs: sqlx::query_as("SELECT principal,package,row_json,source_body,generation,status,executable,refusal,previous_generation,event_seq FROM kernel_app_installs ORDER BY principal,package").fetch_all(db.write_pool()).await?,
        app_package_sources: sqlx::query_as("SELECT package,version,digest,artifact_id,source_revision,declaration_digest,pin_json,source_body,event_seq FROM kernel_app_package_sources ORDER BY package,version,digest,artifact_id,source_revision,declaration_digest").fetch_all(pool).await?,
        app_consent_revocations: sqlx::query_as("SELECT principal,event_seq FROM kernel_app_consent_revocations ORDER BY principal").fetch_all(db.write_pool()).await?,
        app_install_outcomes: sqlx::query_as("SELECT principal,operation_key,operation,request_json,event_id,event_seq FROM kernel_app_install_outcomes ORDER BY principal,operation_key").fetch_all(pool).await?,
        app_actions: sqlx::query_as("SELECT event_id,admitted_event_id,principal,package,version,install_generation,revocation_epoch,operation,request_digest,outputs_json,event_seq FROM kernel_app_actions ORDER BY event_seq").fetch_all(pool).await?,
        app_state: sqlx::query_as("SELECT record_id,origin,payload,event_seq FROM kernel_app_state ORDER BY record_id").fetch_all(db.write_pool()).await?,

        message_candidates:sqlx::query_as("SELECT candidate_id,principal_id,message_id,state,event_seq FROM kernel_message_candidates ORDER BY candidate_id").fetch_all(pool).await?,
        message_candidate_events:sqlx::query_as("SELECT seq,event_key,principal_id,candidate_id,state FROM kernel_message_candidate_events ORDER BY seq").fetch_all(pool).await?,
        message_candidate_import_frontiers:sqlx::query_as("SELECT message_id,source_seq FROM kernel_message_candidate_import_frontiers ORDER BY message_id").fetch_all(pool).await?,
        message_receipts:sqlx::query_as("SELECT principal_id,operation_key,request,receipt FROM kernel_message_receipts ORDER BY principal_id,operation_key").fetch_all(pool).await?,
        message_interactions:sqlx::query_as("SELECT principal_id,nonce,operation_key FROM kernel_message_interactions ORDER BY principal_id,nonce").fetch_all(pool).await?,
        personas:sqlx::query_as("SELECT persona_id,state,event_seq FROM kernel_personas ORDER BY persona_id").fetch_all(pool).await?,
        message_destinations:sqlx::query_as("SELECT principal_id,collection_id,state,event_seq,imported FROM kernel_message_destinations ORDER BY principal_id,collection_id").fetch_all(pool).await?,
        messages: sqlx::query_as("SELECT message_id,state,event_seq FROM kernel_messages ORDER BY message_id").fetch_all(pool).await?,
        message_people: sqlx::query_as("SELECT person_id,principal_id FROM kernel_message_people ORDER BY person_id").fetch_all(pool).await?,
        metadata: sqlx::query_as("SELECT record_id,persistence,maturity,last_activity_at,event_seq FROM kernel_record_metadata ORDER BY record_id").fetch_all(pool).await?,
        instruction_bindings: sqlx::query_as("SELECT id,scope_kind,scope_id,account_principal,source_record_id,position,enabled,created_at,legacy_actor,event_seq FROM kernel_instruction_bindings ORDER BY id").fetch_all(pool).await?,
        generic_links: sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported FROM kernel_generic_links ORDER BY link_id").fetch_all(pool).await?,
        bodies: sqlx::query_as("SELECT record_id,body,event_seq FROM kernel_record_bodies ORDER BY record_id").fetch_all(pool).await?,
        facets: sqlx::query_as("SELECT record_id,key,value,CAST(value_num AS TEXT),vocab_ref,as_of,event_seq FROM kernel_facets ORDER BY record_id,key").fetch_all(pool).await?,
        import_tombstones:sqlx::query_as("SELECT record_id,deleted_at,event_seq FROM kernel_import_tombstones ORDER BY record_id").fetch_all(pool).await?,
        lifecycle: sqlx::query_as("SELECT record_id,archived FROM kernel_lifecycle ORDER BY record_id").fetch_all(pool).await?,
        comment_anchors: sqlx::query_as("SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors ORDER BY annotation_id").fetch_all(pool).await?,
        v1_state: sqlx::query_as("SELECT section,source_id,origin,payload,account_principal,record_id,observed_at,event_seq FROM kernel_v1_state ORDER BY section,source_id").fetch_all(pool).await?,
        runs: sqlx::query_as("SELECT id,owner_principal,run_principal,opened_seq,head,closed FROM kernel_runs ORDER BY id").fetch_all(db.pool()).await?,
        roots: sqlx::query_as(
            "SELECT root_id, parent_id, owner_id, created_seq, created_at FROM kernel_roots ORDER BY root_id",
        )
        .fetch_all(pool)
        .await?,
        principals: sqlx::query_as(
            "SELECT principal_id, kind, display_label, auth_binding FROM kernel_principals ORDER BY principal_id",
        )
        .fetch_all(pool)
        .await?,
        bootstrap: sqlx::query_as("SELECT principal_id, created_seq FROM kernel_root_bootstrap")
            .fetch_all(pool)
            .await?,
        policies: sqlx::query_as("SELECT root_id, created_at FROM kernel_policies ORDER BY root_id")
            .fetch_all(pool)
            .await?,
        entries: sqlx::query_as(
            "SELECT root_id, subject_kind, subject_id, effect, capability FROM kernel_policy_entries
             ORDER BY root_id, subject_kind, subject_id, capability",
        )
        .fetch_all(pool)
        .await?,
        records: sqlx::query_as(
            "SELECT id, home_id, owner_id, primary_type, kind, accession, pin_family, pin_version, pin_digest, interpreter
             FROM kernel_records ORDER BY id",
        )
        .fetch_all(pool)
        .await?,
        links: sqlx::query_as(
            "SELECT source_id, target_id, relationship, created_seq FROM kernel_links
             ORDER BY source_id, target_id, relationship",
        )
        .fetch_all(pool)
        .await?,
        link4_edges: sqlx::query_as("SELECT edge_id, principal_id, operation_key, source_id, target_id, predicate, witness_json, created_seq FROM kernel_link4_edges ORDER BY edge_id")
            .fetch_all(pool).await?,
        provider_state: sqlx::query_as("SELECT id,provider_key,subjects_json,state_json,head FROM kernel_provider_state ORDER BY id").fetch_all(db.pool()).await?,
        provider_subjects: sqlx::query_as("SELECT subject_id,aggregate_id FROM kernel_provider_subjects ORDER BY subject_id,aggregate_id").fetch_all(db.pool()).await?,
        provider_receipts: sqlx::query_as("SELECT principal_id,operation,operation_key,request_json,assertion_id,event_seq FROM kernel_provider_receipts ORDER BY principal_id,operation,operation_key").fetch_all(db.pool()).await?,
        slots: sqlx::query_as("SELECT principal_id,slot,target_id,generation,set_seq FROM kernel_slots ORDER BY principal_id,slot").fetch_all(pool).await?,
        slot_lineage: sqlx::query_as("SELECT principal_id,slot,generation,target_id,previous_target_id,event_seq FROM kernel_slot_lineage ORDER BY principal_id,slot,generation").fetch_all(pool).await?,
        record_fields: sqlx::query_as(
            "SELECT record_id, name, value_json, created_seq FROM kernel_record_fields
             ORDER BY record_id, name",
        )
        .fetch_all(pool)
        .await?,
        artifacts: sqlx::query_as(
            "SELECT family, version, digest, artifact_bytes, kinds FROM definition_artifacts ORDER BY family, version",
        )
        .fetch_all(pool)
        .await?,
        adoptions: sqlx::query_as(
            "SELECT family, selected_version, selected_digest, event_seq FROM definition_adoptions ORDER BY family",
        )
        .fetch_all(pool)
        .await?,
        scope_adoptions: sqlx::query_as(
            "SELECT scope_home, family, selected_version, selected_digest, event_seq FROM kernel_adoptions ORDER BY family, scope_home",
        )
        .fetch_all(pool)
        .await?,
        packages: sqlx::query_as(
            "SELECT scope_home, namespace, name, selected_version, selected_digest, ack_actor, ack_reads, event_seq
               FROM kernel_package_selections ORDER BY scope_home, namespace, name",
        )
        .fetch_all(pool)
        .await?,
        package_artifacts: sqlx::query_as(
            "SELECT id, namespace, name, version, digest, manifest_bytes, event_seq, created_at
               FROM package_artifacts ORDER BY id",
        )
        .fetch_all(pool)
        .await?,
        consumers: sqlx::query_as(
            "SELECT scope_home, consumer_kind, consumer_namespace, consumer_name, family,
                    version, digest, active, event_seq, actor
               FROM consumer_requirements
              ORDER BY scope_home, consumer_kind, consumer_namespace, consumer_name, family",
        )
        .fetch_all(pool)
        .await?,
        installations: sqlx::query_as(
            "SELECT scope_home, namespace, name, revision_digest, settings_digest,
                    settings_json, catalog_revision, profile_id, profile_revision,
                    readset_digest, receipt_json, language, active, event_seq, actor
               FROM rule_installations
              ORDER BY scope_home, namespace, name",
        )
        .fetch_all(pool)
        .await?,
    })
}

pub async fn link_records(db: &Db, source_id: &str, target_id: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    require_local_edit(&mut tx).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: source_id.into(),
            event_type: "kernel.link_added.v1".into(),
            payload: serde_json::to_value(KernelLinkPayload {
                source_id: source_id.into(),
                target_id: target_id.into(),
                relationship: "relates_to".into(),
            })?,
            actor: Some(LOCAL_ACTOR.into()),
        },
        &mut acts,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(())
}

/// The real policy event log folds into an additive anchor for the neutral
/// kernel root. The ordinary record-policy fold stays untouched.
pub(crate) async fn project_kernel_policy_rows(
    conn: &mut SqliteConnection,
    event: &crate::policy::PolicyEventRow,
) -> Result<()> {
    if event.event_type != "policy.replaced" {
        return Err(crate::error::Error::engine(
            "kernel root policy cannot restore inheritance",
        ));
    }
    let payload = crate::policy::replaced_payload(event)?;
    sqlx::query("INSERT OR IGNORE INTO kernel_policies (root_id, created_at) VALUES (?, ?)")
        .bind(&event.record_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM kernel_policy_entries WHERE root_id = ?")
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    for entry in payload.entries {
        sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, ?, ?, ?, ?)")
            .bind(&event.record_id).bind(entry.subject_kind).bind(entry.subject_id)
            .bind(entry.effect).bind(entry.capability).execute(&mut *conn).await?;
    }
    Ok(())
}

/// Disposable kernel database: real content and policy logs plus projectors,
/// one neutral root, zero domain rows. `:memory:` in tests.
pub async fn create_kernel_database(url: &str) -> Result<Db> {
    let db = open_database(url).await?;
    apply_schema(&db).await?;
    apply_kernel_schema(&db).await?;
    // E2a delta from S: E1 keeps the registry tables out of frozen DDL,
    // so the kernel database applies E1 REGISTRY_DDL explicitly.
    crate::definition_registry::ensure_registry_tables(&db).await?;
    crate::meta::package::ensure_package_tables(&db).await?;
    crate::meta::consumer::ensure_consumer_tables(&db).await?;
    crate::meta::rule_installation::ensure_rule_installation_tables(&db).await?;
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: KERNEL_GENESIS_EVENT.into(),
            payload: serde_json::json!({}),
            actor: Some(KERNEL_GENESIS_ACTOR.into()),
        },
        &mut acts,
    )
    .await?;
    crate::policy::append_replaced_in(
        &mut tx,
        KERNEL_ROOT_ID,
        vec![crate::policy::NormalizedPolicyEntry::new(
            "members".into(),
            crate::authorization::MEMBERS_SUBJECT_ID.into(),
            crate::authorization::Capability::Edit,
        )],
        KERNEL_GENESIS_ACTOR,
        "kernel root authority",
        &mut acts,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(db)
}

/// v2 store allowlist: exact frozen-statement prefixes a v2 database reuses
/// verbatim. Count-asserted at apply time so a frozen change surfaces here
/// instead of silently widening or narrowing v2.
const V2_STORE_PREFIXES: &[&str] = &[
    "CREATE TABLE content_events (",
    "CREATE INDEX idx_content_events_",
    "CREATE TRIGGER content_events_no_",
    "CREATE TABLE content_event_causal_frontier (",
    "CREATE INDEX idx_content_event_causal_frontier_parent",
    "CREATE TABLE content_event_causal_cutover (",
    "INSERT INTO content_event_causal_cutover",
    "CREATE TABLE act_state (",
    "INSERT INTO act_state",
    "CREATE TABLE act_cutover (",
    "INSERT INTO act_cutover",
];
const EXPECTED_V2_STORE_STATEMENTS: usize = 15;

/// Frozen meta-tier statements the v2 database needs, reused verbatim:
/// the `meta_events` log (no triggers, no FKs). The dedicated registry
/// projections come from E1 `crate::definition_registry::REGISTRY_DDL`,
/// never from frozen DDL: `vocabularies`, `record_definition_pins` and
/// the Resolution cutover tables stay out — the registry never reads them.
const V2_META_PREFIXES: &[&str] = &[
    "CREATE TABLE meta_events (",
    "CREATE INDEX idx_meta_events_subject",
    "CREATE INDEX idx_meta_events_act",
];
const EXPECTED_V2_META_STATEMENTS: usize = 3;
const EXPECTED_V2_REGISTRY_STATEMENTS: usize = 3;
const EXPECTED_V2_PACKAGE_STATEMENTS: usize = 2;
const EXPECTED_V2_CONSUMER_STATEMENTS: usize = 2;
const EXPECTED_V2_RULE_INSTALLATION_STATEMENTS: usize = 2;

/// Every kernel table a v2 database owns. Increment 1 exercises only roots
/// and principals; records/links/policies land now so the constructor stays
/// stable while later increments add their events and folds.
const V2_KERNEL_TABLES: &[&str] = &[
    app_state::DDL,
    app_installs::SOURCES_DDL,
    app_installs::INSTALLS_DDL,
    app_installs::REVOCATIONS_DDL,
    app_installs::IMPORT_CLOSED_INDEX,
    app_installs::OUTCOMES_DDL,
    app_installs::ACTIONS_DDL,
    instruction_bindings::DDL,
    v1_state::DDL,
    v1_state::RUN_INDEX,
    v1_state::ACCOUNT_INDEX,
    generic_links::DDL,
    "CREATE UNIQUE INDEX idx_kernel_generic_links_active_triple ON kernel_generic_links(source_id,target_id,relationship) WHERE active=1",
    "CREATE INDEX idx_kernel_generic_links_source_page ON kernel_generic_links(source_id,link_id)",
    "CREATE INDEX idx_kernel_generic_links_target_page ON kernel_generic_links(target_id,link_id)",
    "CREATE INDEX idx_kernel_generic_links_source ON kernel_generic_links(source_id,relationship,link_id)",
    "CREATE INDEX idx_kernel_generic_links_target ON kernel_generic_links(target_id,relationship,link_id)",
    record_metadata::DDL,
    blobs::BYTES_DDL,
    blobs::HANDLES_DDL,
    blobs::REFS_DDL,
    hq::BODIES_DDL,
    hq::FACETS_DDL,
    legacy_history::DDL,
    legacy_history::SUBJECTS_DDL,
    legacy_history::SQL_EVENTS_DDL,
    legacy_history::SQL_PROGRESS_DDL,
    legacy_history::SQL_EVENTS_INDEX_DDL,
    hq::LIFECYCLE_DDL,
    hq::TOMBSTONES_DDL,
    messaging::DDL,
    notifications::EVENTS_DDL,
    notifications::FRONTIER_DDL,
    notifications::DDL,
    notifications::INDEX,
    notifications::EVENT_INDEX,
    messaging::RECEIPTS_DDL,
    messaging::INTERACTIONS_DDL,
    messaging::PERSONAS_DDL,
    hosted_identity::EVENT_INDEX_DDL,
    messaging::DEST_DDL,
    messaging::PEOPLE_DDL,
    comments_v2::DDL,
    comments_v2::TARGET_INDEX_DDL,
    KERNEL_ROOTS_DDL,
    KERNEL_PRINCIPALS_DDL,
    KERNEL_ROOT_BOOTSTRAP_DDL,
    KERNEL_POLICIES_DDL,
    KERNEL_POLICY_ENTRIES_DDL,
    KERNEL_RECORDS_DDL,
    KERNEL_RECORD_FIELDS_DDL,
    KERNEL_LINKS_DDL,
    generic_links::LEGACY_TARGET_INDEX,
    links_v2::LINK4_DDL,
    run_ledger::DDL,
    run_ledger::OWNER_INDEX_DDL,
    commit_port::STATE_DDL,
    commit_port::RECEIPT_DDL,
    commit_port::SUBJECT_DDL,
    generic_links::PROVIDER_AGGREGATE_INDEX,
    "CREATE INDEX idx_kernel_link4_edges_created_seq ON kernel_link4_edges(created_seq)",
    KERNEL_ADOPTIONS_DDL,
    KERNEL_PACKAGE_SELECTIONS_DDL,
    slots::SLOTS_DDL,
    slots::LINEAGE_DDL,
    slots::HOME_OWNER_INDEX_DDL,
];

/// Apply the v2 owned schema: subset store tables plus kernel tables. The
/// frozen v1 `DDL_STATEMENTS` are only read, never modified.
pub async fn apply_v2_schema(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let objects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
            .fetch_one(&mut *tx)
            .await?;
    if objects != 0 {
        return Err(Error::engine("v2 creation requires an empty database; use explicit v2 preparation for existing files"));
    }
    let mut store_count = 0usize;
    for statement in DDL_STATEMENTS {
        if V2_STORE_PREFIXES
            .iter()
            .any(|prefix| statement.starts_with(prefix))
        {
            sqlx::query(statement).execute(&mut *tx).await?;
            store_count += 1;
        }
    }
    if store_count != EXPECTED_V2_STORE_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 store subset matched {store_count} frozen statements, expected {EXPECTED_V2_STORE_STATEMENTS}"
        )));
    }
    let mut meta_count = 0usize;
    for statement in DDL_STATEMENTS {
        if V2_META_PREFIXES
            .iter()
            .any(|prefix| statement.starts_with(prefix))
        {
            sqlx::query(statement).execute(&mut *tx).await?;
            meta_count += 1;
        }
    }
    if meta_count != EXPECTED_V2_META_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 meta subset matched {meta_count} frozen statements, expected {EXPECTED_V2_META_STATEMENTS}"
        )));
    }
    let mut registry_count = 0usize;
    for statement in crate::definition_registry::REGISTRY_DDL {
        sqlx::query(statement).execute(&mut *tx).await?;
        registry_count += 1;
    }
    if registry_count != EXPECTED_V2_REGISTRY_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 registry DDL applied {registry_count} statements, expected {EXPECTED_V2_REGISTRY_STATEMENTS}"
        )));
    }
    let mut package_count = 0usize;
    for statement in crate::meta::package::PACKAGE_DDL {
        sqlx::query(statement).execute(&mut *tx).await?;
        package_count += 1;
    }
    if package_count != EXPECTED_V2_PACKAGE_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 package DDL applied {package_count} statements, expected {EXPECTED_V2_PACKAGE_STATEMENTS}"
        )));
    }
    let mut consumer_count = 0usize;
    for statement in crate::meta::consumer::CONSUMER_DDL {
        sqlx::query(statement).execute(&mut *tx).await?;
        consumer_count += 1;
    }
    if consumer_count != EXPECTED_V2_CONSUMER_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 consumer DDL applied {consumer_count} statements, expected {EXPECTED_V2_CONSUMER_STATEMENTS}"
        )));
    }
    let mut installation_count = 0usize;
    for statement in crate::meta::rule_installation::RULE_INSTALLATION_DDL {
        sqlx::query(statement).execute(&mut *tx).await?;
        installation_count += 1;
    }
    if installation_count != EXPECTED_V2_RULE_INSTALLATION_STATEMENTS {
        return Err(Error::engine(format!(
            "v2 rule-installation DDL applied {installation_count} statements, expected {EXPECTED_V2_RULE_INSTALLATION_STATEMENTS}"
        )));
    }
    for ddl in V2_KERNEL_TABLES {
        sqlx::query(ddl).execute(&mut *tx).await?;
    }
    // Probe-only (S7a) search index and scan covering index. The frozen
    // `V2_KERNEL_TABLES` above stay untouched; this block is idempotent.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    search_v2::apply_search_schema(&mut tx).await?;
    sqlx::query(&format!(
        "PRAGMA application_id = {}",
        crate::db::V2_APPLICATION_ID
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Explicit preparation for legacy/imported v2 files. Serving never runs these
/// repairs; import and creation own the ready-to-serve schema.
pub async fn prepare_v2_database(db: &Db) -> Result<()> {
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(db.pool())
        .await?;
    if marker != 0 && marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "v2 preparation refuses a foreign application_id",
        ));
    }
    // A legacy v2 file must already have its owned root/principal schema.
    sqlx::query("SELECT root_id FROM kernel_roots LIMIT 0")
        .execute(db.pool())
        .await?;
    sqlx::query("SELECT principal_id, auth_binding FROM kernel_principals LIMIT 0")
        .execute(db.pool())
        .await?;
    let mut tx = begin_write(db.write_pool()).await?;
    blobs::ensure_schema(&mut tx).await?;
    v1_state::ensure_schema(&mut tx).await?;
    app_state::ensure_schema(&mut tx).await?;
    for ddl in [messaging::DDL, messaging::DEST_DDL, messaging::PEOPLE_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *tx)
            .await?;
    }
    app_installs::ensure_schema(&mut tx).await?;
    tx.commit().await?;
    ensure_record_metadata(db).await?;
    ensure_search_index(db).await?;
    ensure_link_read_indexes(db).await?;
    verify_v2_ready(db).await?;
    sqlx::query(&format!(
        "PRAGMA application_id = {}",
        crate::db::V2_APPLICATION_ID
    ))
    .execute(db.write_pool())
    .await?;
    Ok(())
}

/// Cheap, read-only readiness check. Missing/old projections require explicit
/// import/preparation, never a repair during serving.
pub async fn verify_v2_ready(db: &Db) -> Result<()> {
    let mut connection = db.pool().acquire().await?;
    verify_v2_ready_on(&mut connection).await
}

async fn verify_v2_ready_on(connection: &mut SqliteConnection) -> Result<()> {
    let required = [
        ("table", "kernel_roots"),
        ("table", "kernel_principals"),
        ("table", "kernel_blobs"),
        ("table", "kernel_blob_handles"),
        ("table", "kernel_attachment_blobs"),
        ("table", "kernel_record_metadata"),
        ("table", "kernel_import_tombstones"),
        ("table", "kernel_legacy_history"),
        ("table", "kernel_legacy_subjects"),
        ("table", "kernel_v1_state"),
        ("table", "kernel_app_state"),
        ("table", "kernel_app_installs"),
        ("table", "kernel_app_install_outcomes"),
        ("table", "kernel_app_actions"),
        ("table", "kernel_app_consent_revocations"),
        ("table", "kernel_app_package_sources"),
        ("index", "idx_kernel_import_closed"),
        ("table", "kernel_legacy_sql_events"),
        ("table", "kernel_legacy_sql_progress"),
        ("table", "kernel_messages"),
        ("table", "kernel_message_receipts"),
        ("table", "kernel_message_interactions"),
        ("table", "kernel_personas"),
        ("table", "kernel_message_destinations"),
        ("table", "kernel_message_people"),
        ("table", "kernel_search_fts"),
        ("table", "kernel_search_meta"),
        ("index", "idx_kernel_links_target"),
        ("index", "idx_kernel_provider_subjects_aggregate"),
        ("index", "idx_kernel_records_family_kind_accession"),
        ("index", "idx_kernel_v1_state_run"),
        ("index", "idx_kernel_v1_state_account"),
        ("index", "idx_kernel_hosted_event_lookup"),
    ];
    for (kind, name) in required {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type=? AND name=?)",
        )
        .bind(kind)
        .bind(name)
        .fetch_one(&mut *connection)
        .await?;
        if !exists {
            return Err(Error::engine(format!("v2 database is not ready: missing {name}; run explicit v2 import/preparation before serving")));
        }
    }
    let gap_free: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_sql_progress') WHERE name='gap_free')")
        .fetch_one(&mut *connection).await?;
    if !gap_free {
        return Err(Error::engine("v2 database is not ready: legacy SQL frontier format; run explicit v2 import/preparation before serving"));
    }
    let provenance_headers: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_sql_progress') WHERE name='provenance_headers')")
        .fetch_one(&mut *connection).await?;
    if !provenance_headers {
        return Err(Error::engine("v2 database is not ready: legacy provenance header format; run explicit v2 import/preparation before serving"));
    }
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_legacy_sql_progress WHERE provenance_headers!=1)",
    )
    .fetch_one(&mut *connection)
    .await?;
    if pending {
        return Err(Error::engine("v2 database is not ready: legacy provenance headers need backfill; run explicit v2 import/preparation before serving"));
    }
    let version: Option<i64> = sqlx::query_scalar("SELECT version FROM kernel_search_meta LIMIT 1")
        .fetch_optional(&mut *connection)
        .await?;
    if version != Some(search_v2::SEARCH_INDEX_VERSION) {
        return Err(Error::engine("v2 database is not ready: search index version; run explicit v2 import/preparation before serving"));
    }
    Ok(())
}

/// Verify a marked target without opening a writable pool or creating schema.
pub async fn verify_marked_v2_file_read_only(path: &std::path::Path) -> Result<()> {
    use sqlx::Connection;
    let mut connection = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true),
    )
    .await?;
    let result = async {
        let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&mut connection)
            .await?;
        if marker != crate::db::V2_APPLICATION_ID {
            return Err(Error::engine("cutover target requires NKV2 marker"));
        }
        verify_v2_ready_on(&mut connection).await
    }
    .await;
    connection.close().await?;
    result
}

/// Open an existing v2 file. Legacy unmarked files are stamped after readiness
/// verification; no open-time schema creation or projection rebuild is allowed.
pub async fn open_v2_database(path: &str) -> Result<Db> {
    open_v2_database_inner(path, true).await
}

/// Hosted routing requires an explicitly prepared and marked v2 file. Unlike
/// the local compatibility opener, this path never upgrades a legacy marker.
pub async fn open_marked_v2_database(path: &str) -> Result<Db> {
    open_v2_database_inner(path, false).await
}

async fn open_v2_database_inner(path: &str, allow_legacy: bool) -> Result<Db> {
    use sqlx::Connection;

    if !std::path::Path::new(path).is_file() {
        return Err(Error::engine(
            "v2 serving requires an existing database file",
        ));
    }
    // Serving admission checks the engine marker and small schema metadata,
    // not every database page. Deep integrity verification belongs to explicit
    // backup/restore qualification. Do not negotiate WAL or repair a legacy
    // file before its readiness has been established read-only.
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options).await?;
    let ready: Result<()> = async {
        let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&mut connection)
            .await?;
        if marker != 0 && marker != crate::db::V2_APPLICATION_ID {
            return Err(Error::engine(
                "refusing v2 open: foreign application_id; expected an existing v2 database",
            ));
        }
        if marker == 0 && !allow_legacy {
            return Err(Error::engine("hosted v2 open requires a marked v2 database; prepare legacy files explicitly before serving"));
        }
        if marker == 0 {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut connection)
                .await?;
            if version != 0 {
                return Err(Error::engine(
                    "refusing v2 open: expected an unmarked legacy v2 database, not a v1 schema",
                ));
            }
        }
        verify_v2_ready_on(&mut connection).await
    }
    .await;
    let closed = connection.close().await;
    ready?;
    closed?;
    let db = crate::db::open_existing_v2_file(path).await?;
    let result = async {
        verify_v2_ready(&db).await?;
        let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(db.pool())
            .await?;
        if marker == 0 && allow_legacy {
            sqlx::query(&format!(
                "PRAGMA application_id = {}",
                crate::db::V2_APPLICATION_ID
            ))
            .execute(db.write_pool())
            .await?;
        } else if marker != crate::db::V2_APPLICATION_ID {
            return Err(Error::engine("v2 open refuses a foreign application_id"));
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        db.close().await;
        return Err(error);
    }
    Ok(db)
}

/// v2 genesis: owned subset schema, one neutral root, one initial
/// root-admin principal, attributed single-shot bootstrap and reserved host
/// transform and import principals — all five events in one genesis transaction. There is no first-come window: any
/// later bootstrap refuses with no event. Plain commit, not `commit_content`:
/// the subset database has no provenance tables for attestation issuance.
pub async fn create_v2_database(
    url: &str,
    admin_kind: &str,
    admin_label: &str,
    admin_binding: &str,
) -> Result<(Db, String)> {
    refuse_caller_host_binding(admin_binding)?;
    let db = open_database(url).await?;
    apply_v2_schema(&db).await?;
    let admin_id = Uuid::new_v4().to_string();
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: KERNEL_GENESIS_EVENT.into(),
            payload: serde_json::json!({}),
            actor: Some(KERNEL_GENESIS_ACTOR.into()),
        },
        &mut acts,
    )
    .await?;
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: admin_id.clone(),
            event_type: KERNEL_PRINCIPAL_CREATED_EVENT.into(),
            payload: serde_json::json!({
                "kind": admin_kind,
                "display_label": admin_label,
                "auth_binding": admin_binding,
            }),
            actor: Some(KERNEL_GENESIS_ACTOR.into()),
        },
        &mut acts,
    )
    .await?;
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: KERNEL_BOOTSTRAP_EVENT.into(),
            payload: serde_json::to_value(KernelBootstrapPayload {
                principal_id: admin_id.clone(),
            })?,
            actor: Some(admin_id.clone()),
        },
        &mut acts,
    )
    .await?;
    // The reserved transform identity is minted inside genesis, before callers
    // can compete for its UNIQUE binding. It receives no grants automatically.
    append_in(&db, &mut tx, AppendSpec {
        record_id: Uuid::new_v4().to_string(),
        event_type: HOST_TRANSFORM_CREATED_EVENT.into(),
        payload: serde_json::json!({"kind":"agent","display_label":"Relationship host transform","auth_binding":relates_to_port::HOST_TRANSFORM_BINDING}),
        actor: Some(KERNEL_GENESIS_ACTOR.into()),
    }, &mut acts).await?;
    append_in(&db, &mut tx, AppendSpec {
        record_id: Uuid::new_v4().to_string(),
        event_type: "kernel.host_import_created.v1".into(),
        payload: serde_json::json!({"kind":"agent","display_label":"V1 host importer","auth_binding":HOST_IMPORT_BINDING}),
        actor: Some(KERNEL_GENESIS_ACTOR.into()),
    }, &mut acts).await?;
    tx.commit().await?;
    prepare_v2_database(&db).await?;
    Ok((db, admin_id))
}

/// Mint one principal through the real content log. No authorization gate:
/// none exists yet (increment 2); genesis setup only.
pub async fn create_principal(
    db: &Db,
    kind: &str,
    display_label: &str,
    auth_binding: &str,
    actor: &str,
) -> Result<String> {
    refuse_caller_host_binding(auth_binding)?;
    let id = Uuid::new_v4().to_string();
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: KERNEL_PRINCIPAL_CREATED_EVENT.into(),
            payload: serde_json::json!({
                "kind": kind,
                "display_label": display_label,
                "auth_binding": auth_binding,
            }),
            actor: Some(actor.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub(crate) const HOST_TRANSFORM_CREATED_EVENT: &str = "kernel.host_transform_created.v1";
fn refuse_caller_host_binding(binding: &str) -> Result<()> {
    if binding.starts_with("host:") {
        return Err(Error::engine(
            "host: auth bindings are reserved for kernel-owned principals",
        ));
    }
    Ok(())
}
pub(crate) async fn project_host_transform_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelPrincipalPayload = event_payload(event)?;
    if event.actor.as_deref() != Some(KERNEL_GENESIS_ACTOR)
        || p.kind != "agent"
        || p.auth_binding != relates_to_port::HOST_TRANSFORM_BINDING
    {
        return Err(Error::engine("invalid kernel host transform envelope"));
    }
    project_kernel_principal_payload(conn, event, p).await
}

/// Resolve `(principal_id, kind, display_label)` from an auth binding.
pub async fn resolve_principal_by_binding(
    db: &Db,
    auth_binding: &str,
) -> Result<Option<(String, String, String)>> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT principal_id, kind, display_label FROM kernel_principals WHERE auth_binding = ?",
    )
    .bind(auth_binding)
    .fetch_optional(db.write_pool())
    .await?;
    Ok(row)
}

/// Transport callers can never authenticate as a reserved host principal.
/// Internal sealed seams continue to use the low-level binding lookup.
#[cfg(feature = "v2-kernel-probe")]
pub async fn resolve_caller_principal_by_binding(
    db: &Db,
    auth_binding: &str,
) -> Result<Option<(String, String, String)>> {
    if auth_binding.starts_with("host:") {
        return Err(Error::engine(
            "kernel-v2: host bindings cannot authenticate callers",
        ));
    }
    resolve_principal_by_binding(db, auth_binding).await
}

/// Exactly-once marker for the explicit root-admin bootstrap. Authority never
/// depends on creation order: principal creation grants nothing.
pub const KERNEL_ROOT_BOOTSTRAP_DDL: &str = r#"CREATE TABLE kernel_root_bootstrap (
  singleton    INTEGER PRIMARY KEY CHECK (singleton = 1),
  principal_id TEXT NOT NULL REFERENCES kernel_principals(principal_id),
  created_seq  INTEGER NOT NULL CHECK (created_seq >= 1)
)"#;

/// Content event type that carries v2 home creation with its initial policy.
pub const KERNEL_HOME_CREATED_EVENT: &str = "kernel.home_created.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelHomeEntryPayload {
    subject_id: String,
    capability: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelHomeCreatedPayload {
    /// Logical folder identity; uses the same deterministic child-home binding as import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_record_id: Option<String>,
    parent_id: String,
    /// Owner principal: the creator for an ordinary home, or the existing
    /// folder owner for a child-home binding. Never an auth binding.
    owner_id: String,
    /// `Some` (possibly empty) installs an own policy anchor on the home;
    /// `None` leaves the home anchorless so it inherits its nearest ancestor.
    entries: Option<Vec<KernelHomeEntryPayload>>,
}

fn parse_kernel_capability(value: &str) -> Result<Capability> {
    Capability::from_policy_str(value)
        .ok_or_else(|| Error::engine(format!("unsupported kernel policy capability '{value}'")))
}

pub(crate) async fn project_kernel_home_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelHomeCreatedPayload = event_payload(event)?;
    if Uuid::parse_str(&event.record_id).is_err() || event.record_id == KERNEL_ROOT_ID {
        return Err(Error::engine("invalid kernel home envelope"));
    }
    let parent_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(&p.parent_id)
            .fetch_one(&mut *conn)
            .await?;
    if !parent_exists {
        return Err(Error::engine("invalid kernel home parent"));
    }
    if p.owner_id.trim().is_empty() {
        return Err(Error::engine("invalid kernel home owner"));
    }
    let owner_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)")
            .bind(&p.owner_id)
            .fetch_one(&mut *conn)
            .await?;
    if !owner_exists {
        return Err(Error::engine("invalid kernel home owner"));
    }
    if let Some(entries) = &p.entries {
        for entry in entries {
            if entry.subject_id.trim().is_empty() {
                return Err(Error::engine("invalid kernel home policy entry"));
            }
            parse_kernel_capability(&entry.capability)?;
        }
    }
    sqlx::query("INSERT INTO kernel_roots (root_id, parent_id, owner_id, created_seq, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&event.record_id)
        .bind(&p.parent_id)
        .bind(&p.owner_id)
        .bind(event.local_seq)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    if let Some(entries) = &p.entries {
        sqlx::query("INSERT INTO kernel_policies (root_id, created_at) VALUES (?, ?)")
            .bind(&event.record_id)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
        for entry in entries {
            sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', ?)")
                .bind(&event.record_id)
                .bind(&entry.subject_id)
                .bind(&entry.capability)
                .execute(&mut *conn).await?;
        }
    }
    Ok(())
}

/// Shared home admission (Foci v2 G6 increment 3b; design note 681a449 §3.3,
/// §4.2, §7). Runs at admission only, from `append_prepared_admitted` and
/// explicitly from `append_migration_on`, so no append route skips it; the
/// folds stay permissive and replay of an existing log is unaffected.
///
/// 1. Generic home creation refuses owner ≠ actor except a folder binding,
///    which preserves its live folder's existing owner and requires folder
///    Edit. Other delegated ownership uses sealed `home_created_for`.
/// 2. The record and home id spaces stay disjoint: a record id may not already
///    be a home, and a home id may not already be a record. The count and
///    probe queries of the rehome batch rely on this (§4.2).
///
/// Other event types pass through.
pub(crate) async fn admit_home_event(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::admit(conn, event).await?;
    blobs::admit(conn, event).await?;
    generic_links::admit(conn, event).await?;
    comments_v2::admit(conn, event).await?;
    match event.event_type.as_str() {
        KERNEL_HOME_CREATED_EVENT => {
            let p: KernelHomeCreatedPayload = event_payload(event)?;
            if let Some(folder) = &p.source_record_id {
                let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' AND t.value_json='\"Collection\"' JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' AND k.value_json='\"folder\"' WHERE r.id=? AND r.home_id=? AND r.owner_id=? AND NOT EXISTS(SELECT 1 FROM kernel_lifecycle life WHERE life.record_id=r.id AND life.archived=1) AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones dead WHERE dead.record_id=r.id))")
                    .bind(folder).bind(&p.parent_id).bind(&p.owner_id).fetch_one(&mut *conn).await?;
                if !valid || event.record_id != v1_import_home_id(folder) || p.entries.is_some() {
                    return Err(Error::engine("invalid folder home binding"));
                }
                if !kernel_effective_capability_on(
                    conn,
                    event.actor.as_deref().unwrap_or_default(),
                    folder,
                )
                .await?
                .allows(Capability::Edit)
                {
                    return Err(Error::engine(HIDDEN_OR_MISSING));
                }
                validate_move_parent(
                    conn,
                    &MoveHomeParent {
                        home_id: event.record_id.clone(),
                        parent_id: p.parent_id.clone(),
                    },
                )
                .await?;
            } else if event.actor.as_deref() != Some(p.owner_id.as_str()) {
                return Err(Error::engine(
                    "a home can be created for another owner only through the sealed home_created_for route",
                ));
            }
            refuse_taken_by_record(conn, &event.record_id).await
        }
        slots::HOME_CREATED_FOR => refuse_taken_by_record(conn, &event.record_id).await,
        "kernel.record_created.v1" => {
            let is_home: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
                    .bind(&event.record_id)
                    .fetch_one(&mut *conn)
                    .await?;
            if is_home {
                return Err(Error::engine("record id is already a home"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn refuse_taken_by_record(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    let is_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if is_record {
        return Err(Error::engine("home id is not fresh"));
    }
    Ok(())
}

/// Evaluate one kernel record or home for one principal.
///
/// The anchor is the target's nearest ancestor with an own policy: the
/// record's home, the home itself, then parents up to the workspace root
/// (which always carries one). Stored entries name principals by principal id
/// under the `account` subject kind: that is the whole of the evaluator
/// adapter (see `native_policy_kernel::evaluate_policy_grants`, which knows
/// no Person, bindings, or roster — matching is pure string comparison, and
/// this caller never writes `members` entries with `is_member=false`).
/// The owner floor composes last via the reused
/// `resolve_effective_capability`: the record's `owner_id` is a principal id
/// compared directly, never via `auth_binding`.
///
/// Parent links are immutable once written, so the walk cannot cycle; the
/// depth cap is fail-closed belt regardless.
const MAX_HOME_DEPTH: usize = 100;

/// The one refusal for every write/capability check against a record, home
/// or principal the caller cannot View: missing and hidden are
/// indistinguishable, and no id or title of the target leaks.
pub(crate) const HIDDEN_OR_MISSING: &str = "kernel target missing or hidden";

pub(crate) async fn kernel_effective_capability_on(
    conn: &mut SqliteConnection,
    principal_id: &str,
    target_id: &str,
) -> Result<Capability> {
    if !hosted_identity::admitted(conn, principal_id).await? {
        return Ok(Capability::None);
    }
    let is_home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(target_id)
            .fetch_one(&mut *conn)
            .await?;
    if !is_home && hq::tombstoned_on(conn, target_id).await? {
        return Ok(Capability::None);
    }
    if !is_home && !messaging::audience_allows(conn, principal_id, target_id).await? {
        return Ok(Capability::None);
    }
    if !is_home && comments_v2::is_derived_on(conn, target_id).await? {
        // All annotations and attachment documents inherit their terminal
        // bearer's authority, including its owner floor; never their own.
        let Some(terminal) = comments_v2::derived_terminal_on(conn, target_id).await? else {
            return Ok(Capability::None);
        };
        return kernel_effective_capability_on_terminal(conn, principal_id, &terminal, false).await;
    }
    kernel_effective_capability_on_terminal(conn, principal_id, target_id, is_home).await
}

/// Home-policy evaluation with the owner's floor, for a record already
/// proven not to derive (a home, an ordinary record, or a comment's
/// non-comment terminal). Split out so comment derivation terminates in
/// one hop without async recursion.
async fn kernel_effective_capability_on_terminal(
    conn: &mut SqliteConnection,
    principal_id: &str,
    target_id: &str,
    is_home: bool,
) -> Result<Capability> {
    if !is_home && hq::tombstoned_on(conn, target_id).await? {
        return Ok(Capability::None);
    }
    if !is_home {
        if let Some(capability) = messaging::capability(conn, principal_id, target_id).await? {
            // Missing message state and reserved maintenance identities fail closed.
            if capability == Capability::None {
                return Ok(Capability::None);
            }
            let base = kernel_base_capability_on(conn, principal_id, target_id, false).await?;
            return Ok(if base.allows(capability) {
                capability
            } else {
                base
            });
        }
    }
    kernel_base_capability_on(conn, principal_id, target_id, is_home).await
}
async fn kernel_base_capability_on(
    conn: &mut SqliteConnection,
    principal_id: &str,
    target_id: &str,
    is_home: bool,
) -> Result<Capability> {
    let anchor: String = if is_home {
        target_id.to_string()
    } else {
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id = ?")
            .bind(target_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?
    };
    let policy_capability = kernel_policy_capability_on(conn, principal_id, &anchor).await?;
    // Owner floor, composed last: records compare their `owner_id`, homes
    // compare the home's own `owner_id` — both principal ids, never auth
    // bindings. An emptied home stays recoverable by its owner.
    let owner: Option<String> = if is_home {
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id = ?")
            .bind(target_id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten()
    } else {
        sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id = ?")
            .bind(target_id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten()
    };
    Ok(resolve_effective_capability(
        policy_capability,
        owner.as_deref() == Some(principal_id),
    ))
}

/// Resolve the nearest explicit policy boundary, with the shared depth limit.
pub(crate) async fn kernel_policy_anchor_on(
    conn: &mut SqliteConnection,
    home: &str,
) -> Result<String> {
    let mut anchor = home.to_owned();
    let mut depth = 0usize;
    loop {
        let anchored: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policies WHERE root_id = ?)")
                .bind(&anchor)
                .fetch_one(&mut *conn)
                .await?;
        if anchored {
            break;
        }
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        anchor = sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
            .bind(&anchor)
            .fetch_optional(&mut *conn)
            .await?
            .flatten()
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    }
    Ok(anchor)
}

/// Policy only; record and home owner floors are composed separately.
async fn kernel_policy_capability_on(
    conn: &mut SqliteConnection,
    principal_id: &str,
    home: &str,
) -> Result<Capability> {
    if !hosted_identity::admitted(conn, principal_id).await? {
        return Ok(Capability::None);
    }
    let anchor = kernel_policy_anchor_on(conn, home).await?;
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT subject_kind, subject_id, effect, capability FROM kernel_policy_entries WHERE root_id = ?",
    )
    .bind(&anchor)
    .fetch_all(&mut *conn)
    .await?;
    let rows = hosted_identity::policy_rows(conn, principal_id, &anchor)
        .await?
        .unwrap_or(rows);
    let evaluation_entries: Vec<PolicyEvaluationEntry<'_>> = rows
        .iter()
        .map(|row| PolicyEvaluationEntry {
            subject_kind: &row.0,
            subject_id: &row.1,
            effect: &row.2,
            capability: &row.3,
        })
        .collect();
    let policy_capability = evaluate_policy_grants(
        PolicyEvaluationPrincipal::new(Some(principal_id), false),
        &evaluation_entries,
    )
    // Fail closed without naming the anchor: malformed stored policy must not
    // become an oracle for ancestor-home existence either.
    .map_err(|_| Error::engine(HIDDEN_OR_MISSING))?;
    Ok(policy_capability)
}

/// SQL-filterable visibility terms evaluated in the caller's snapshot.
/// A record is visible iff its home has `policy_valid` and either `policy_view`
/// or the caller owns that record. Home ownership alone does not admit records.
/// Broken anchors fail closed before the owner floor, as single-target checks do.
pub(crate) struct VisibleHomeAnchor {
    pub home_id: String,
    pub policy_valid: bool,
    pub policy_view: bool,
    /// Visibility of the home itself, including its own owner floor.
    #[cfg(feature = "v2-kernel-probe")]
    pub home_view: bool,
}
pub(crate) struct VisibleHomeAnchors {
    pub homes: Vec<VisibleHomeAnchor>,
    pub failed_homes: usize,
}
pub(crate) async fn visible_home_anchors_as(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<VisibleHomeAnchors> {
    if !hosted_identity::admitted(conn, principal).await? {
        return Ok(VisibleHomeAnchors {
            homes: Vec::new(),
            failed_homes: 0,
        });
    }
    let homes: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT h.root_id,h.owner_id FROM kernel_roots h UNION ALL SELECT DISTINCT r.home_id,NULL FROM kernel_records r WHERE NOT EXISTS(SELECT 1 FROM kernel_roots h WHERE h.root_id=r.home_id)",
    ).fetch_all(&mut *conn).await?;
    let mut result = VisibleHomeAnchors {
        homes: Vec::new(),
        failed_homes: 0,
    };
    for row in homes {
        #[cfg(feature = "v2-kernel-probe")]
        let (home, owner) = row;
        #[cfg(not(feature = "v2-kernel-probe"))]
        let (home, _) = row;
        match kernel_policy_capability_on(conn, principal, &home).await {
            Ok(capability) => {
                let view = capability.allows(Capability::View);
                result.homes.push(VisibleHomeAnchor {
                    home_id: home,
                    policy_valid: true,
                    policy_view: view,
                    #[cfg(feature = "v2-kernel-probe")]
                    home_view: view || owner.as_deref() == Some(principal),
                });
            }
            Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => {
                result.failed_homes += 1;
                result.homes.push(VisibleHomeAnchor {
                    home_id: home,
                    policy_valid: false,
                    policy_view: false,
                    #[cfg(feature = "v2-kernel-probe")]
                    home_view: false,
                });
            }
            // Storage failures (including interruption, BUSY, IO and NOMEM)
            // are not authority refusals and must reach the caller.
            Err(error) => return Err(error),
        }
    }
    if result.failed_homes > 0 {
        tracing::warn!(
            failed_homes = result.failed_homes,
            "bulk kernel visibility omitted broken policy scopes"
        );
    }
    Ok(result)
}

/// Snapshot-scoped evaluation for callers without their own transaction.
pub async fn kernel_effective_capability(
    db: &Db,
    principal_id: &str,
    target_id: &str,
) -> Result<Capability> {
    let mut snapshot = db.write_pool().begin().await?;
    let capability = kernel_effective_capability_on(&mut snapshot, principal_id, target_id).await?;
    snapshot.rollback().await?;
    Ok(capability)
}

#[allow(clippy::explicit_auto_deref)]
pub(crate) async fn kernel_require(
    tx: &mut Transaction<'_, Sqlite>,
    principal_id: &str,
    target_id: &str,
    required: Capability,
) -> Result<()> {
    // Evaluation then the caller's append share one write transaction. The
    // refusal is the uniform oracle answer: missing and hidden targets are
    // indistinguishable, with no id of either in the message.
    let capability = kernel_effective_capability_on(&mut **tx, principal_id, target_id).await?;
    if !capability.allows(required) {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

/// Bind a live logical folder to its deterministic, policy-inheriting child
/// home. Existing imported bindings are reused; older native folders are bound
/// on their first member write. Never called by read paths.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn folder_home_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    requested: &str,
) -> Result<()> {
    let logical: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
        .bind(requested).fetch_optional(&mut **tx).await?;
    let folder = logical.as_deref().unwrap_or(requested);
    let is_home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(folder)
            .fetch_one(&mut **tx)
            .await?;
    if is_home || folder == "native:root" {
        return Ok(());
    }
    let capability = kernel_effective_capability_on(tx, actor, folder).await?;
    if !capability.allows(Capability::View) {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let row = read_record_on(tx, actor, folder)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    if row.archived
        || row
            .fields
            .get("v1_type")
            .and_then(serde_json::Value::as_str)
            != Some("Collection")
        || row
            .fields
            .get("v1_kind")
            .and_then(serde_json::Value::as_str)
            != Some("folder")
    {
        return Err(Error::engine("home_id must name a live unarchived folder"));
    }
    if !capability.allows(Capability::Edit) {
        return Err(Error::engine("Edit on the destination folder is required"));
    }
    let home = v1_import_home_id(folder);
    let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=?)")
        .bind(&home).bind(folder).fetch_one(&mut **tx).await?;
    if !bound {
        // The member-facing view may redact another principal's identity.
        // This is authority state, read only after the folder Edit gate.
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id=?")
                .bind(folder)
                .fetch_one(&mut **tx)
                .await?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: home,
                event_type: KERNEL_HOME_CREATED_EVENT.into(),
                payload: serde_json::to_value(KernelHomeCreatedPayload {
                    source_record_id: Some(folder.into()),
                    parent_id: row.home_id,
                    owner_id: owner.ok_or_else(|| Error::engine("folder has no owner"))?,
                    entries: None,
                })?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
    }
    Ok(())
}

/// Create one home under `parent_id` through the real content log. Requires
/// Manage on the parent (the actor is a principal id, stamped on the event);
/// refusal appends nothing. `entries` `Some` (possibly empty) installs an own
/// policy anchor; `None` leaves the home anchorless so it inherits its
/// nearest ancestor's policy. Entries are `(principal_id, capability)`
/// allow-grants; the evaluator adapter stores them under `account`.
pub async fn create_home(
    db: &Db,
    parent_id: &str,
    entries: Option<&[(&str, &str)]>,
    actor_principal_id: &str,
) -> Result<String> {
    if let Some(entries) = entries {
        for (_, capability) in entries {
            parse_kernel_capability(capability)?;
        }
    }
    let id = Uuid::new_v4().to_string();
    let payload_entries: Option<Vec<KernelHomeEntryPayload>> = entries.map(|entries| {
        entries
            .iter()
            .map(|(subject_id, capability)| KernelHomeEntryPayload {
                subject_id: subject_id.to_string(),
                capability: capability.to_string(),
            })
            .collect()
    });
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(&mut tx, actor_principal_id, parent_id, Capability::Manage).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: KERNEL_HOME_CREATED_EVENT.into(),
            payload: serde_json::to_value(KernelHomeCreatedPayload {
                source_record_id: None,
                parent_id: parent_id.to_string(),
                owner_id: actor_principal_id.to_string(),
                entries: payload_entries,
            })?,
            actor: Some(actor_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Create one bare record as a principal. Requires Edit on the home; the
/// creator becomes the owner. The legacy members gate is not consulted.
pub async fn create_record_as(
    db: &Db,
    creator_principal_id: &str,
    home_id: &str,
) -> Result<String> {
    let mut tx = begin_write(db.write_pool()).await?;
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(home_id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);
    if !home_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut tx, creator_principal_id, home_id, Capability::Edit).await?;
    let id = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.record_created.v1".into(),
            payload: serde_json::to_value(KernelRecordPayload {
                home_id: home_id.to_string(),
                owner_id: Some(creator_principal_id.to_string()),
                primary_type: None,
                kind: None,
                accession: None,
                pin: None,
                interpreter: None,
                fields: None,
            })?,
            actor: Some(creator_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Link a record to a record or a principal as a principal. Requires Edit on
/// the source and View on a record target; a principal target needs no
/// capability beyond seeing the link (principals are not policy-bearing).
/// Either endpoint missing or hidden refuses. Homes are never endpoints.
/// The legacy members gate is not consulted.
/// Shared link endpoint gate (slice 1 rules, unchanged): the source must be
/// a record the caller can Edit; a record target needs View; a principal
/// target needs nothing beyond existence. Anything else is the uniform
/// hidden-or-missing refusal, checked before any validation message.
async fn check_link_endpoints(
    tx: &mut Transaction<'_, Sqlite>,
    creator_principal_id: &str,
    source_id: &str,
    target_id: &str,
) -> Result<()> {
    let source_is_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if !source_is_record {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut *tx, creator_principal_id, source_id, Capability::Edit).await?;
    let target_is_record: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(target_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if target_is_record {
        kernel_require(&mut *tx, creator_principal_id, target_id, Capability::View).await?;
    } else {
        let target_is_principal: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)",
        )
        .bind(target_id)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or(false);
        if !target_is_principal {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
    }
    Ok(())
}

/// Match a link against a source kind's declared `/2` links: the predicate
/// must be declared, and one declaration must match the target definition
/// with an outgoing direction. Undeclared predicates and target/direction
/// mismatches refuse with distinct messages naming only the caller's own
/// source side and the schema (capability is always checked first).
fn check_declared_link(
    descriptor: &KindDescriptor,
    kind: &str,
    predicate: &str,
    target_type: &str,
    target_kind: &str,
) -> Result<()> {
    if descriptor.links.iter().all(|(p, _, _, _)| p != predicate) {
        return Err(Error::engine(format!(
            "undeclared predicate '{predicate}' for kind '{kind}'"
        )));
    }
    let allowed = descriptor.links.iter().any(|(p, t, k, d)| {
        p == predicate && t == target_type && k == target_kind && (d == "out" || d == "either")
    });
    if !allowed {
        return Err(Error::engine(format!(
            "link target {target_type}/{target_kind} not allowed for predicate '{predicate}' from kind '{kind}'"
        )));
    }
    Ok(())
}

pub async fn link_records_as(
    db: &Db,
    creator_principal_id: &str,
    source_id: &str,
    target_id: &str,
) -> Result<()> {
    if links_v2::source_supports_closed_links(db, source_id).await? {
        let request = prepare_link4_as(
            db,
            creator_principal_id,
            source_id,
            "relates_to",
            target_id,
            &links_v2::wrapper_operation_key(
                db,
                creator_principal_id,
                source_id,
                "relates_to",
                target_id,
            )
            .await?,
        )
        .await?;
        link4_as(db, creator_principal_id, &request).await?;
        return Ok(());
    }
    let mut tx = begin_write(db.write_pool()).await?;
    check_link_endpoints(&mut tx, creator_principal_id, source_id, target_id).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: source_id.into(),
            event_type: "kernel.link_added.v1".into(),
            payload: serde_json::to_value(KernelLinkPayload {
                source_id: source_id.into(),
                target_id: target_id.into(),
                relationship: "relates_to".into(),
            })?,
            actor: Some(creator_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Generic link (slice 2, increment 3b): capability first (slice 1 rules,
/// unchanged), then the `/2` allow-list when the source is pinned to a `/2`
/// definition — predicate declared in the source kind's `links`, target
/// definition matching, outgoing direction. Bare, `/1`, and
/// principal-target links keep legacy behaviour. All refusals event-free.
pub async fn link_as(
    db: &Db,
    creator_principal_id: &str,
    source_id: &str,
    predicate: &str,
    target_id: &str,
) -> Result<()> {
    if predicate.trim().is_empty() {
        return Err(Error::engine("link predicate must not be empty"));
    }
    if links_v2::source_supports_closed_links(db, source_id).await? {
        let request = prepare_link4_as(
            db,
            creator_principal_id,
            source_id,
            predicate,
            target_id,
            &links_v2::wrapper_operation_key(
                db,
                creator_principal_id,
                source_id,
                predicate,
                target_id,
            )
            .await?,
        )
        .await?;
        link4_as(db, creator_principal_id, &request).await?;
        return Ok(());
    }
    let mut tx = begin_write(db.write_pool()).await?;
    check_link_endpoints(&mut tx, creator_principal_id, source_id, target_id).await?;
    let src: Option<RecordKeyRow> =
        sqlx::query_as(
            "SELECT primary_type, kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?",
        )
        .bind(source_id)
        .fetch_optional(&mut *tx)
        .await?;
    let tgt: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT primary_type, kind FROM kernel_records WHERE id = ?")
            .bind(target_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let (
        Some((_, Some(src_kind), Some(family), Some(version), Some(digest))),
        Some((tgt_type, tgt_kind)),
    ) = (src, tgt)
    {
        let stored_bytes: Option<String> = sqlx::query_scalar(
            "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
        )
        .bind(&family)
        .bind(version)
        .bind(&digest)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(bytes) = stored_bytes {
            if let Some(descriptor) = kind_descriptor(&bytes, &src_kind)? {
                check_declared_link(
                    &descriptor,
                    &src_kind,
                    predicate,
                    tgt_type.as_deref().unwrap_or_default(),
                    tgt_kind.as_deref().unwrap_or_default(),
                )?;
            }
        }
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: source_id.into(),
            event_type: "kernel.link_added.v1".into(),
            payload: serde_json::to_value(KernelLinkPayload {
                source_id: source_id.into(),
                target_id: target_id.into(),
                relationship: predicate.to_string(),
            })?,
            actor: Some(creator_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One query hit: the record id plus its stored field values (parsed).
/// Query returns record data by design (unlike describe); authority filtering
/// decides which rows appear at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryHit {
    pub id: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// One query page plus the opaque cursor for the next page (`None` = end).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryPage {
    pub hits: Vec<QueryHit>,
    pub cursor: Option<String>,
}

fn encode_cursor(accession: &str, id: &str) -> String {
    format!("{accession}\u{1f}{id}")
}

fn decode_cursor(cursor: &str) -> Result<(String, String)> {
    // Split at the LAST separator: ids are UUIDs, accessions may be anything.
    cursor
        .rsplit_once('\u{1f}')
        .map(|(a, i)| (a.to_string(), i.to_string()))
        .ok_or_else(|| Error::engine("invalid query cursor"))
}

/// Generic query (slice 2, increment 3c): conjunctive field equality over
/// the fields table plus an optional `linked_to (predicate, id, direction)`,
/// with `(direction out|in|either)`. Authority first: rows in unseen homes
/// are absent, and a `linked_to` id the caller cannot View behaves exactly
/// like a nonexistent id (empty page, no distinguishing error). Order is
/// `(accession, id)` — for `/2` records the accession namespaces the
/// identity value per family+kind, so this is identity-then-id order.
/// `/1` records are queryable by family and kind (field filters over their
/// empty field set simply match nothing).
// Eight positional parameters is the fixed contract surface (db, caller,
// what, filters, paging); bundling would only move the arity, not remove it.
#[allow(clippy::too_many_arguments)]
pub async fn query_as(
    db: &Db,
    principal_id: &str,
    family: &str,
    kind: &str,
    field_equals: &[(&str, serde_json::Value)],
    linked_to: Option<(&str, &str, &str)>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<QueryPage> {
    query_as_pinned(
        db,
        principal_id,
        family,
        kind,
        None,
        field_equals,
        linked_to,
        limit,
        cursor,
    )
    .await
}

/// Internal revision-pinned query: `pin` adds an exact SQL-level
/// `pin_version`/`pin_digest` filter BEFORE pagination, so records from
/// other revisions of the same family/kind never enter the candidate scan
/// (no post-filter, hence no cursor or empty-page leak). Public `query_as`
/// pins nothing and behaves exactly as before.
// This private shim mirrors query_as's stable positional contract and adds
// one revision pin without changing the public query API.
#[allow(clippy::too_many_arguments)]
async fn query_as_pinned(
    db: &Db,
    principal_id: &str,
    family: &str,
    kind: &str,
    pin: Option<(u32, &str)>,
    field_equals: &[(&str, serde_json::Value)],
    linked_to: Option<(&str, &str, &str)>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<QueryPage> {
    let limit = limit.clamp(1, 100);
    let after: Option<(String, String)> = cursor.map(decode_cursor).transpose()?;
    let mut tx = begin_write(db.write_pool()).await?;
    // Linked-to visibility gate: unseen and nonexistent ids are identical
    // (empty page). Principals follow the directory rule (root View).
    if let Some((_, linked_id, _)) = linked_to {
        let visible = if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)",
        )
        .bind(linked_id)
        .fetch_one(&mut *tx)
        .await?
        {
            kernel_effective_capability_on(&mut tx, principal_id, linked_id)
                .await?
                .allows(Capability::View)
        } else if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)",
        )
        .bind(linked_id)
        .fetch_one(&mut *tx)
        .await?
        {
            kernel_effective_capability_on(&mut tx, principal_id, KERNEL_ROOT_ID)
                .await?
                .allows(Capability::View)
        } else {
            false
        };
        if !visible {
            tx.rollback().await?;
            return Ok(QueryPage {
                hits: Vec::new(),
                cursor: None,
            });
        }
    }
    let mut sql = String::from(
        "SELECT r.id, r.accession FROM kernel_records r WHERE r.pin_family = ? AND r.kind = ?",
    );
    if pin.is_some() {
        sql.push_str(" AND r.pin_version = ? AND r.pin_digest = ?");
    }
    // Positional bind order below: family, kind, pin pair, field pairs,
    // linked_to, cursor pair. SQLite row-value comparison keeps pagination
    // stable.
    let mut text_params: Vec<String> = Vec::new();
    for (name, value) in field_equals {
        sql.push_str(
            " AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id = r.id AND f.name = ? AND ((r.interpreter IN (?, ?) AND f.value_json = ?) OR (r.interpreter NOT IN (?, ?) AND f.value_json = ?)))",
        );
        // Both structured markers match on the normalised form.
        text_params.push(name.to_string());
        text_params.push(crate::structured_values::INTERPRETER.to_string());
        text_params.push(crate::structured_values::INTERPRETER_V6.to_string());
        text_params.push(serde_json::to_string(
            &crate::structured_values::normalize(value),
        )?);
        text_params.push(crate::structured_values::INTERPRETER.to_string());
        text_params.push(crate::structured_values::INTERPRETER_V6.to_string());
        text_params.push(serde_json::to_string(value)?);
    }
    if let Some((predicate, linked_id, direction)) = linked_to {
        match direction {
            "out" => sql.push_str(
                " AND EXISTS(SELECT 1 FROM kernel_links l WHERE l.source_id = r.id AND l.target_id = ? AND l.relationship = ?)",
            ),
            "in" => sql.push_str(
                " AND EXISTS(SELECT 1 FROM kernel_links l WHERE l.target_id = r.id AND l.source_id = ? AND l.relationship = ?)",
            ),
            "either" => sql.push_str(
                " AND EXISTS(SELECT 1 FROM kernel_links l WHERE ((l.source_id = r.id AND l.target_id = ?) OR (l.target_id = r.id AND l.source_id = ?)) AND l.relationship = ?)",
            ),
            _ => return Err(Error::engine(format!("unknown link direction '{direction}'"))),
        }
        text_params.push(linked_id.to_string());
        if direction == "either" {
            text_params.push(linked_id.to_string());
        }
        text_params.push(predicate.to_string());
    }
    // Scan-to-fill: authority-skipped rows never surface, so the scan keeps
    // reading windows until the page holds `limit` visible hits plus one
    // probe, or candidates run out. A page carries a cursor only when
    // another *visible* hit exists, so an empty page always ends the walk
    // and reveals nothing about hidden rows. The bound keeps adversarial
    // scans finite (a few thousand candidates is fine for this slice).
    const QUERY_SCAN_BOUND: usize = 5000;
    let sql_base = sql;
    let mut after = after;
    let mut hits: Vec<QueryHit> = Vec::new();
    let mut hit_keys: Vec<(String, String)> = Vec::new();
    let mut scanned = 0usize;
    let cursor = loop {
        let fetch = limit - hits.len() + 1;
        let mut sql = sql_base.clone();
        if after.is_some() {
            sql.push_str(" AND (r.accession, r.id) > (?, ?)");
        }
        sql.push_str(" ORDER BY r.accession, r.id LIMIT ?");
        let mut query = sqlx::query_as::<_, (String, Option<String>)>(&sql)
            .bind(family)
            .bind(kind);
        if let Some((pin_version, pin_digest)) = pin {
            query = query.bind(pin_version as i64).bind(pin_digest);
        }
        for param in &text_params {
            query = query.bind(param);
        }
        if let Some((accession, id)) = &after {
            query = query.bind(accession).bind(id);
        }
        query = query.bind(fetch as i64);
        let rows: Vec<(String, Option<String>)> = query.fetch_all(&mut *tx).await?;
        scanned += rows.len();
        if scanned > QUERY_SCAN_BOUND {
            return Err(Error::engine("query scan bound exceeded"));
        }
        let window_full = rows.len() == fetch;
        for (id, accession) in rows {
            let accession = accession.unwrap_or_default();
            after = Some((accession.clone(), id.clone()));
            if !kernel_effective_capability_on(&mut tx, principal_id, &id)
                .await?
                .allows(Capability::View)
            {
                continue;
            }
            let field_rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? ORDER BY name",
            )
            .bind(&id)
            .fetch_all(&mut *tx)
            .await?;
            let mut fields = serde_json::Map::new();
            for (name, value_json) in field_rows {
                fields.insert(name, serde_json::from_str(&value_json)?);
            }
            hits.push(QueryHit {
                id: id.clone(),
                fields,
            });
            hit_keys.push((accession, id));
            if hits.len() > limit {
                break;
            }
        }
        if hits.len() > limit {
            hits.pop();
            hit_keys.pop();
            break hit_keys
                .last()
                .map(|(accession, id)| encode_cursor(accession, id));
        }
        if !window_full {
            break None;
        }
    };
    tx.rollback().await?;
    Ok(QueryPage { hits, cursor })
}
pub const KERNEL_POLICY_REPLACED_EVENT: &str = "kernel.home_policy_replaced.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelPolicyReplacedPayload {
    entries: Vec<KernelHomeEntryPayload>,
}

pub(crate) async fn project_kernel_home_policy_replaced(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelPolicyReplacedPayload = event_payload(event)?;
    let policy_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policies WHERE root_id = ?)")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if !policy_exists {
        return Err(Error::engine(
            "kernel policy replace targets no home anchor",
        ));
    }
    for entry in &p.entries {
        if entry.subject_id.trim().is_empty() {
            return Err(Error::engine("invalid kernel policy replacement entry"));
        }
        parse_kernel_capability(&entry.capability)?;
    }
    sqlx::query("DELETE FROM kernel_policy_entries WHERE root_id = ?")
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    for entry in &p.entries {
        sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', ?)")
            .bind(&event.record_id)
            .bind(&entry.subject_id)
            .bind(&entry.capability)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Replace a home's whole policy as an attributed event. Requires Manage on
/// the home. A home has an owner (`kernel_roots.owner_id`, stamped when it is
/// created), and the owner floor composes last for homes exactly as for
/// records, so the owner keeps Manage whatever the policy says. A later
/// Manage grantee can replace the policy too. The actor stamped is the
/// principal id.
pub async fn replace_home_policy(
    db: &Db,
    actor_principal_id: &str,
    home_id: &str,
    entries: &[(&str, &str)],
) -> Result<()> {
    for (_, capability) in entries {
        parse_kernel_capability(capability)?;
    }
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(&mut tx, actor_principal_id, home_id, Capability::Manage).await?;
    let payload_entries: Vec<KernelHomeEntryPayload> = entries
        .iter()
        .map(|(subject_id, capability)| KernelHomeEntryPayload {
            subject_id: subject_id.to_string(),
            capability: capability.to_string(),
        })
        .collect();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: home_id.into(),
            event_type: KERNEL_POLICY_REPLACED_EVENT.into(),
            payload: serde_json::to_value(KernelPolicyReplacedPayload {
                entries: payload_entries,
            })?,
            actor: Some(actor_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelBootstrapPayload {
    principal_id: String,
}

pub(crate) async fn project_kernel_root_admin_bootstrapped(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelBootstrapPayload = event_payload(event)?;
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine(
            "kernel bootstrap targets the workspace root only",
        ));
    }
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_root_bootstrap WHERE singleton = 1)",
    )
    .fetch_one(&mut *conn)
    .await?;
    if already {
        return Err(Error::engine(
            "workspace root admin is already bootstrapped",
        ));
    }
    let principal_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)")
            .bind(&p.principal_id)
            .fetch_one(&mut *conn)
            .await?;
    if !principal_exists {
        return Err(Error::engine("kernel bootstrap names an unknown principal"));
    }
    sqlx::query(
        "INSERT INTO kernel_root_bootstrap (singleton, principal_id, created_seq) VALUES (1, ?, ?)",
    )
    .bind(&p.principal_id)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', 'manage')")
        .bind(KERNEL_ROOT_ID)
        .bind(&p.principal_id)
        .execute(&mut *conn).await?;
    // The bootstrapped admin owns the workspace root, so the root stays
    // recoverable by its owner exactly like any other home.
    sqlx::query("UPDATE kernel_roots SET owner_id = ? WHERE root_id = ?")
        .bind(&p.principal_id)
        .bind(KERNEL_ROOT_ID)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Name the initial workspace-root administrator as an attributed, single-shot
/// event. Ungated by policy (there is no administrator yet); the fold refuses
/// any second attempt, so nothing appends twice. Who may create principals
/// stays ungated in this test-only path — hosted authentication integration
/// is the remaining gate.
pub async fn bootstrap_root_admin(db: &Db, principal_id: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_root_bootstrap WHERE singleton = 1)",
    )
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(false);
    if already {
        return Err(Error::engine(
            "workspace root admin is already bootstrapped",
        ));
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: KERNEL_BOOTSTRAP_EVENT.into(),
            payload: serde_json::to_value(KernelBootstrapPayload {
                principal_id: principal_id.to_string(),
            })?,
            actor: Some(principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelRehomePayload {
    new_home_id: String,
}

pub(crate) async fn project_kernel_record_rehomed(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelRehomePayload = event_payload(event)?;
    let record_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if !record_exists {
        return Err(Error::engine("kernel rehome targets no record"));
    }
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(&p.new_home_id)
            .fetch_one(&mut *conn)
            .await?;
    if !home_exists {
        return Err(Error::engine("kernel rehome targets no home"));
    }
    sqlx::query("UPDATE kernel_records SET home_id = ? WHERE id = ?")
        .bind(&p.new_home_id)
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Move a record to another home as a principal. Requires Edit on the record
/// and Manage on the destination home (the disclosure-level capability:
/// `None < View < Edit < Manage`, `crates/policy-kernel/src/lib.rs:26-47`).
/// Move and anchor effect land atomically in one transaction; inheritance is
/// read-time, so projections cannot go stale after commit.
pub async fn rehome_record_as(
    db: &Db,
    actor_principal_id: &str,
    record_id: &str,
    new_home_id: &str,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    rehome_record_in(
        db,
        &mut tx,
        &mut acts,
        actor_principal_id,
        record_id,
        new_home_id,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The `_in` form of `rehome_record_as`: every rehome check and the existing
/// rehome event, on the caller's transaction. It never begins or commits, so
/// a caller that fails must abort its own transaction. A home is not a
/// record, and the destination must be a home.
pub(crate) async fn rehome_record_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor_principal_id: &str,
    record_id: &str,
    new_home_id: &str,
) -> Result<()> {
    let is_home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if is_home {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(tx, actor_principal_id, record_id, Capability::Edit).await?;
    let dest_is_home: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(new_home_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if !dest_is_home {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(tx, actor_principal_id, new_home_id, Capability::Manage).await?;
    let old_home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?;
    if old_home != new_home_id {
        // This primitive does not carry dependents. Refuse derived artifacts
        // and their bearers; member moves use the atomic cohort path below.
        let derived: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM kernel_records c WHERE c.id=? AND {})",
            sql_is_derived_artifact("c")
        ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?;
        let children_sql = format!("SELECT EXISTS(SELECT 1 FROM kernel_generic_links l JOIN kernel_records c ON c.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND l.active=1 AND {})", sql_is_derived_artifact("c"));
        let has_dependents: bool = sqlx::query_scalar(&children_sql)
            .bind(record_id)
            .fetch_one(&mut **tx)
            .await?;
        if derived || has_dependents {
            return Err(Error::engine(
                "v2 rehoming records with comments or derived artifacts requires the atomic member move; nothing moved",
            ));
        }
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: record_id.into(),
            event_type: KERNEL_REHOMED_EVENT.into(),
            payload: serde_json::to_value(KernelRehomePayload {
                new_home_id: new_home_id.to_string(),
            })?,
            actor: Some(actor_principal_id.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelMovePayload {
    new_home_id: String,
    logical_home_id: String,
    parent_update: Option<MoveHomeParent>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoveHomeParent {
    home_id: String,
    parent_id: String,
}

async fn validate_move_parent(conn: &mut SqliteConnection, change: &MoveHomeParent) -> Result<()> {
    let mut current = Some(change.parent_id.clone());
    let mut depth = 0;
    while let Some(id) = current {
        if id == change.home_id || depth > MAX_HOME_DEPTH {
            return Err(Error::engine(
                "move would create a home cycle or exceed the home depth limit; nothing moved",
            ));
        }
        let row: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id=?")
                .bind(&id)
                .fetch_optional(&mut *conn)
                .await?;
        current = row.ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
        depth += 1;
    }
    let height: i64=sqlx::query_scalar("WITH RECURSIVE subtree(id,depth) AS (SELECT root_id,0 FROM kernel_roots WHERE root_id=? UNION ALL SELECT r.root_id,s.depth+1 FROM kernel_roots r JOIN subtree s ON r.parent_id=s.id WHERE s.depth<=?) SELECT coalesce(max(depth),0) FROM subtree")
        .bind(&change.home_id).bind(MAX_HOME_DEPTH as i64).fetch_one(conn).await?;
    if depth as i64 + height > MAX_HOME_DEPTH as i64 {
        return Err(Error::engine(
            "move would exceed the home depth limit; nothing moved",
        ));
    }
    Ok(())
}

pub(crate) async fn project_kernel_record_moved(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: KernelMovePayload = event_payload(event)?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?) AND EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
        .bind(&event.record_id).bind(&p.new_home_id).fetch_one(&mut *conn).await?;
    if !exists || p.logical_home_id.trim().is_empty() {
        return Err(Error::engine("invalid kernel move"));
    }
    if let Some(change) = &p.parent_update {
        let bound: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=?)")
            .bind(&change.home_id).bind(&event.record_id).fetch_one(&mut *conn).await?;
        if !bound {
            return Err(Error::engine("move home is not bound to its record"));
        }
        validate_move_parent(conn, change).await?;
        let updated = sqlx::query(
            "UPDATE kernel_roots SET parent_id=? WHERE root_id=? AND parent_id IS NOT NULL",
        )
        .bind(&change.parent_id)
        .bind(&change.home_id)
        .execute(&mut *conn)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(Error::engine("move cannot reparent the workspace root"));
        }
    }
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&p.new_home_id)
        .bind(&event.record_id)
        .execute(conn)
        .await?;
    Ok(())
}

// V1 authorization_target's derived-artifact rule. Keep raw rehome refusal
// and the atomic move cohort on the same predicate.
pub(crate) fn sql_is_derived_artifact(alias: &str) -> String {
    format!(
        "EXISTS(SELECT 1 FROM kernel_record_fields t \
         LEFT JOIN kernel_record_fields k ON k.record_id=t.record_id AND k.name='v1_kind' \
         WHERE t.record_id={alias}.id AND t.name='v1_type' \
           AND (t.value_json='\"Annotation\"' OR (t.value_json='\"Document\"' AND k.value_json='\"attachment\"')))"
    )
}

/// Member-facing relocation: v1 source Manage + destination Edit. Validate
/// every retained derived artifact before emitting any event, then move all records
/// in the caller's transaction/act. Raw rehome paths retain their own guard.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn move_record_with_comments_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    record: &str,
    home: &str,
) -> Result<()> {
    kernel_require(tx, actor, record, Capability::Manage).await?;
    kernel_require(tx, actor, home, Capability::Edit).await?;
    let derived: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM kernel_records c WHERE c.id=? AND {})",
        sql_is_derived_artifact("c")
    ))
    .bind(record)
    .fetch_one(&mut **tx)
    .await?;
    if derived {
        return Err(Error::engine(
            "a derived artifact moves only with its terminal bearer",
        ));
    }
    let old: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(record)
        .fetch_one(&mut **tx)
        .await?;
    // Keep a record-local ACL on its existing home. Its browse parent moves
    // independently; folder children inherit through their reparented home.
    let self_policy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=?)")
        .bind(&old).bind(record).fetch_one(&mut **tx).await?;
    // Imported and native folders share a deterministic child-home binding.
    // Older native folders without children can still move without a binding.
    let folder_home = v1_import_home_id(record);
    let bound_folder: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e JOIN kernel_roots h ON h.root_id=e.record_id WHERE e.record_id=? AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id')=?)")
        .bind(&folder_home).bind(record).fetch_one(&mut **tx).await?;
    let physical_home = if self_policy { old.as_str() } else { home };
    let moving_home = if self_policy {
        Some(old.clone())
    } else if bound_folder {
        Some(folder_home)
    } else {
        None
    };
    let parent_update = moving_home.map(|home_id| MoveHomeParent {
        home_id,
        parent_id: home.to_owned(),
    });
    if let Some(change) = &parent_update {
        validate_move_parent(tx, change).await?;
    }
    let logical_home: Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1")
        .bind(home).fetch_optional(&mut **tx).await?;
    let imported_root:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_home_policy.v1')")
        .bind(KERNEL_ROOT_ID).fetch_one(&mut **tx).await?;
    let logical_home = logical_home.unwrap_or_else(|| {
        if home == KERNEL_ROOT_ID && imported_root {
            "native:root".into()
        } else {
            home.to_owned()
        }
    });
    let mut cohort = vec![record.to_owned()];
    let mut depths = vec![0usize];
    let mut seen = std::collections::HashSet::from([record.to_owned()]);
    let mut index = 0;
    while index < cohort.len() {
        // Match v1 authorization_target: every Annotation (not only comments)
        // and every Document/attachment follows its unique part_of bearer.
        // Ordinary records with part_of links retain independent placement.
        let children: Vec<String> = sqlx::query_scalar(&format!("SELECT DISTINCT l.source_id FROM kernel_generic_links l JOIN kernel_records c ON c.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND l.active=1 AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones dead WHERE dead.record_id=c.id) AND {} ORDER BY c.id", sql_is_derived_artifact("c")))
            .bind(&cohort[index]).fetch_all(&mut **tx).await?;
        for child in children {
            let bearers = comments_v2::bearer_on(tx, &child).await?;
            if !seen.insert(child.clone())
                || bearers.as_slice() != [cohort[index].as_str()]
                || depths[index] >= crate::authorization::MAX_DERIVED_BEARER_DEPTH
            {
                return Err(Error::engine(
                    "invalid comment thread or derived artifact bearer; nothing moved",
                ));
            }
            // Authority is the terminal bearer's Manage, as in v1. A derived
            // artifact's own historical home does not grant independent access.
            depths.push(depths[index] + 1);
            cohort.push(child);
        }
        index += 1;
    }
    for id in cohort {
        let update = if id == record {
            parent_update.as_ref().map(|p| MoveHomeParent {
                home_id: p.home_id.clone(),
                parent_id: p.parent_id.clone(),
            })
        } else {
            None
        };
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: id,
                event_type: "kernel.record_rehomed.v2".into(),
                payload: serde_json::to_value(KernelMovePayload {
                    new_home_id: physical_home.into(),
                    logical_home_id: logical_home.clone(),
                    parent_update: update,
                })?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
    }
    Ok(())
}

/// Content event type that carries a record home change.
pub const KERNEL_REHOMED_EVENT: &str = "kernel.record_rehomed.v1";

/// One visible record, or `None` when missing or hidden (no leak either way).
/// Field values ride along in query-hit shape; pin/interpreter identify the
/// `/2` definition (all `None` on bare records).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelRecordView {
    pub metadata: RecordMetadata,
    /// First-class record text, separate from definition fields.
    pub body: Option<String>,
    pub archived: bool,
    pub id: String,
    pub home_id: String,
    pub owner_id: Option<String>,
    pub fields: serde_json::Map<String, serde_json::Value>,
    pub family: Option<String>,
    pub kind: Option<String>,
    pub pin: Option<RevisionIdentity>,
    pub interpreter: Option<String>,
    /// Compare-and-swap token for this record: the greatest content-event
    /// `seq` for the record in the same snapshot. `revise_as_expected` refuses
    /// with `Error::Conflict` when the caller's token no longer matches.
    pub revision: i64,
}

pub async fn read_record_as(
    db: &Db,
    principal_id: &str,
    record_id: &str,
) -> Result<Option<KernelRecordView>> {
    let mut snapshot = db.write_pool().begin().await?;
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(&mut snapshot, principal_id).await?;
    let view = read_record_on(&mut snapshot, principal_id, record_id).await?;
    snapshot.rollback().await?;
    Ok(view)
}

/// `read_record_as` on a connection the caller already holds: no snapshot of
/// its own, so a host operation can gate and read in one transaction. The
/// caller owns the transaction and ends it.
pub(crate) async fn read_record_on(
    snapshot: &mut SqliteConnection,
    principal_id: &str,
    record_id: &str,
) -> Result<Option<KernelRecordView>> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(record_id)
            .fetch_optional(&mut *snapshot)
            .await?
            .unwrap_or(false);
    if !exists {
        return Ok(None);
    };
    let capability =
        kernel_effective_capability_on(&mut *snapshot, principal_id, record_id).await?;
    if !capability.allows(Capability::View) {
        return Ok(None);
    }
    read_record_unchecked_on(snapshot, principal_id, record_id).await
}

/// Field hydration after the caller has established visibility through its
/// own gate — the home-policy check above, or a comment's derived bearer
/// chain. Hidden records still yield `None` (missing row); only the
/// authorization decision is the caller's.
pub(crate) async fn read_record_unchecked_on(
    snapshot: &mut SqliteConnection,
    principal_id: &str,
    record_id: &str,
) -> Result<Option<KernelRecordView>> {
    let row: Option<RecordViewRow> = sqlx::query_as(
        "SELECT id, home_id, owner_id, kind, pin_family, pin_version, pin_digest, interpreter
         FROM kernel_records WHERE id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut *snapshot)
    .await?;
    let Some((id, home_id, owner_id, kind, pin_family, pin_version, pin_digest, interpreter)) = row
    else {
        return Ok(None);
    };
    let root_visible = kernel_effective_capability_on(&mut *snapshot, principal_id, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View);
    // Fields and pin ride along only after the caller's View gate: hidden
    // records yield `None` before any of this runs.
    let field_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? ORDER BY name",
    )
    .bind(record_id)
    .fetch_all(&mut *snapshot)
    .await?;
    let mut fields = serde_json::Map::new();
    for (name, value_json) in field_rows {
        fields.insert(name, serde_json::from_str(&value_json)?);
    }
    let pin = match (pin_family, pin_version, pin_digest) {
        (Some(family), Some(version), Some(digest)) => Some(RevisionIdentity {
            family,
            version: u32::try_from(version).unwrap_or(0),
            digest,
        }),
        _ => None,
    };
    let family = pin.as_ref().map(|p| p.family.clone());
    // The CAS token is the latest content event for the record, read in the
    // same snapshot as the fields it describes.
    let revision: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) FROM main.content_events WHERE record_id = ?",
    )
    .bind(record_id)
    .fetch_one(&mut *snapshot)
    .await?;
    let owner_id = disclose_owner(principal_id, owner_id, root_visible);
    let archived = hq::archived_on(&mut *snapshot, &id).await?;
    let body = hq::body_on(&mut *snapshot, &id).await?;
    Ok(Some(KernelRecordView {
        metadata: record_metadata::read_on(snapshot, &id).await?,
        body,
        archived,
        id,
        home_id,
        owner_id,
        fields,
        family,
        kind,
        pin,
        interpreter,
        revision,
    }))
}

/// Apply the `history_as` attribution rule to an owner id: disclosed iff the
/// caller is the owner or holds at least View on the workspace root.
fn disclose_owner(viewer_id: &str, owner_id: Option<String>, root_visible: bool) -> Option<String> {
    match owner_id {
        None => None,
        Some(owner) if owner == viewer_id || root_visible => Some(owner),
        Some(_) => None,
    }
}

/// Edges out of a record, omitting ends the caller cannot View. A missing or
/// hidden source yields no edges and no signal (no count/title leak).
pub async fn links_from_as(
    db: &Db,
    principal_id: &str,
    source_id: &str,
) -> Result<Vec<(String, String)>> {
    let mut snapshot = db.write_pool().begin().await?;
    let source_visible =
        sqlx::query_scalar::<_, String>("SELECT id FROM kernel_records WHERE id = ?")
            .bind(source_id)
            .fetch_optional(&mut *snapshot)
            .await?
            .is_some()
            && kernel_effective_capability_on(&mut snapshot, principal_id, source_id)
                .await?
                .allows(Capability::View);
    if !source_visible {
        snapshot.rollback().await?;
        return Ok(Vec::new());
    }
    let edges: Vec<(String, String)> = sqlx::query_as(
        "SELECT target_id, relationship FROM kernel_links WHERE source_id = ? ORDER BY target_id, relationship",
    )
    .bind(source_id)
    .fetch_all(&mut *snapshot)
    .await?;
    let mut visible = Vec::new();
    for (target_id, relationship) in edges {
        // Principals are not policy-bearing: seeing the link is enough.
        let target_is_principal: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)",
        )
        .bind(&target_id)
        .fetch_one(&mut *snapshot)
        .await?;
        let target_visible = target_is_principal
            || (sqlx::query_scalar::<_, String>("SELECT id FROM kernel_records WHERE id = ?")
                .bind(&target_id)
                .fetch_optional(&mut *snapshot)
                .await?
                .is_some()
                && kernel_effective_capability_on(&mut snapshot, principal_id, &target_id)
                    .await?
                    .allows(Capability::View));
        if target_visible {
            visible.push((target_id, relationship));
        }
    }
    visible.extend(relates_to_port::active_links_in(&mut snapshot, principal_id, source_id).await?);
    snapshot.rollback().await?;
    Ok(visible)
}

/// Every record the caller can View. One snapshot, so policy cannot shift
/// mid-list.
pub async fn list_records_as(db: &Db, principal_id: &str) -> Result<Vec<KernelRecordView>> {
    let mut snapshot = db.write_pool().begin().await?;
    let rows: Vec<RecordViewRow> = sqlx::query_as(
        "SELECT id, home_id, owner_id, kind, pin_family, pin_version, pin_digest, interpreter
         FROM kernel_records ORDER BY id",
    )
    .fetch_all(&mut *snapshot)
    .await?;
    let root_visible = kernel_effective_capability_on(&mut snapshot, principal_id, KERNEL_ROOT_ID)
        .await
        .unwrap_or(Capability::None)
        .allows(Capability::View);
    let scope = visible_home_anchors_as(&mut snapshot, principal_id).await?;
    let homes: std::collections::BTreeMap<_, _> = scope
        .homes
        .into_iter()
        .map(|home| (home.home_id, (home.policy_valid, home.policy_view)))
        .collect();
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|(_, home, owner, ..)| {
            homes.get(home).is_some_and(|(valid, view)| {
                *valid && (*view || owner.as_deref() == Some(principal_id))
            })
        })
        .collect();
    let mut admitted = Vec::new();
    for row in rows {
        if kernel_effective_capability_on(&mut snapshot, principal_id, &row.0)
            .await?
            .allows(Capability::View)
        {
            admitted.push(row);
        }
    }
    let rows = admitted;
    let ids: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
    let mut all_fields: std::collections::BTreeMap<
        String,
        serde_json::Map<String, serde_json::Value>,
    > = std::collections::BTreeMap::new();
    let mut state = std::collections::BTreeMap::new();
    // Return-all API: batch the values it must return, instead of four round
    // trips per record. Every bind is from the snapshot's admitted ID set.
    for batch in ids.chunks(500) {
        let mut fields_sql = sqlx::QueryBuilder::<Sqlite>::new(
            "SELECT record_id,name,value_json FROM kernel_record_fields WHERE record_id IN (",
        );
        let mut args = fields_sql.separated(",");
        for id in batch {
            args.push_bind(id);
        }
        args.push_unseparated(")");
        let fields: Vec<(String, String, String)> = fields_sql
            .build_query_as()
            .fetch_all(&mut *snapshot)
            .await?;
        for (id, name, value) in fields {
            all_fields
                .entry(id)
                .or_default()
                .insert(name, serde_json::from_str(&value)?);
        }
        let mut state_sql = sqlx::QueryBuilder::<Sqlite>::new("SELECT r.id,b.body,coalesce(l.archived,0),(SELECT coalesce(max(seq),0) FROM main.content_events e WHERE e.record_id=r.id) FROM kernel_records r LEFT JOIN kernel_record_bodies b ON b.record_id=r.id LEFT JOIN kernel_lifecycle l ON l.record_id=r.id WHERE r.id IN (");
        let mut args = state_sql.separated(",");
        for id in batch {
            args.push_bind(id);
        }
        args.push_unseparated(")");
        let values: Vec<(String, Option<String>, bool, i64)> =
            state_sql.build_query_as().fetch_all(&mut *snapshot).await?;
        for (id, body, archived, revision) in values {
            state.insert(id, (body, archived, revision));
        }
    }
    let mut visible = Vec::new();
    for (id, home_id, owner_id, kind, pin_family, pin_version, pin_digest, interpreter) in rows {
        let fields = all_fields.remove(&id).unwrap_or_default();
        let pin = match (pin_family, pin_version, pin_digest) {
            (Some(family), Some(version), Some(digest)) => Some(RevisionIdentity {
                family,
                version: u32::try_from(version).unwrap_or(0),
                digest,
            }),
            _ => None,
        };
        let family = pin.as_ref().map(|p| p.family.clone());
        let (body, archived, revision) =
            state.remove(&id).expect("admitted record in same snapshot");
        visible.push(KernelRecordView {
            metadata: record_metadata::read_on(&mut snapshot, &id).await?,
            body,
            archived,
            id,
            home_id,
            owner_id: disclose_owner(principal_id, owner_id, root_visible),
            fields,
            family,
            kind,
            pin,
            interpreter,
            revision,
        });
    }
    snapshot.rollback().await?;
    Ok(visible)
}

/// One content event with attribution resolved for the caller: `actor` is
/// `Some` when disclosed, `None` when redacted. Slice rule: disclosed iff
/// the caller is the actor, or the caller has View on the event's record and
/// at least View on the workspace root. A missing or hidden record yields no
/// events and no signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelHistoryEvent {
    /// Retained v1 interpretation; payloads redacted at read time, source withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retained_legacy: Option<serde_json::Value>,
    pub id: String,
    pub run_key: Option<String>,
    pub causal_status: String,
    pub seq: i64,
    pub event_type: String,
    pub record_id: String,
    pub actor: Option<String>,
    pub actor_name: Option<String>,
    pub created_at: String,
}

pub async fn history_as(
    db: &Db,
    principal_id: &str,
    record_id: &str,
) -> Result<Vec<KernelHistoryEvent>> {
    history_page_as(
        db,
        principal_id,
        record_id,
        None,
        false,
        usize::MAX,
        true,
        false,
    )
    .await
}

/// History for a record, home, or principal id (slice-2 carry-over: homes
/// and principals were absent). Visibility per subject kind: records and
/// homes need View on the subject; a principal's own events are visible to
/// itself, otherwise to holders of root View (the directory rule). Missing
/// or hidden subjects yield the empty result — the same answer records
/// already gave — never a distinguishing refusal. Actors disclose under the
/// slice-1 rule in all three cases.
#[derive(sqlx::FromRow)]
struct HistoryReadRow {
    seq: i64,
    event_type: String,
    record_id: String,
    actor: Option<String>,
    created_at: String,
    id: String,
    run_key: Option<String>,
    causal_status: String,
    legacy_type: Option<String>,
    subjects: Option<String>,
    legacy_owner: Option<String>,
    hidden: Option<bool>,
    payload: Option<String>,
    acknowledgement: bool,
    actor_name: Option<String>,
    restricted: Option<bool>,
    claim_sensitive: Option<bool>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn history_page_as(
    db: &Db,
    principal_id: &str,
    subject_id: &str,
    after: Option<i64>,
    newest: bool,
    limit: usize,
    full: bool,
    include_import_receipts: bool,
) -> Result<Vec<KernelHistoryEvent>> {
    history_page_in_range_as(
        db,
        principal_id,
        subject_id,
        after,
        newest,
        limit,
        full,
        include_import_receipts,
        (0, i64::MAX),
    )
    .await
}

/// Canonical disclosure restricted to a caller-selected sequence window.
/// Freshness consumers bound their raw scan AND these nested history reads.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn history_page_in_range_as(
    db: &Db,
    principal_id: &str,
    subject_id: &str,
    after: Option<i64>,
    newest: bool,
    limit: usize,
    full: bool,
    include_import_receipts: bool,
    range: (i64, i64),
) -> Result<Vec<KernelHistoryEvent>> {
    history_page_selected_as(
        db,
        principal_id,
        subject_id,
        after,
        newest,
        limit,
        full,
        include_import_receipts,
        range,
        None,
    )
    .await
}

/// Hydrate an already bounded header window with the ordinary history disclosure
/// rules. One authority snapshot and subject cache, rather than one request and
/// provenance lookup per event. Each subject is independently authorized here.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn history_headers_as(
    db: &Db,
    principal_id: &str,
    sequences: &[i64],
    full: bool,
) -> Result<Vec<KernelHistoryEvent>> {
    if sequences.len() > 1000 {
        return Err(Error::engine("history header window exceeds 1000"));
    }
    if sequences.is_empty() {
        return Ok(Vec::new());
    }
    history_page_selected_as(
        db,
        principal_id,
        "",
        None,
        false,
        sequences.len(),
        full,
        false,
        (0, i64::MAX),
        Some(sequences),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn history_page_selected_as(
    db: &Db,
    principal_id: &str,
    subject_id: &str,
    after: Option<i64>,
    newest: bool,
    limit: usize,
    full: bool,
    include_import_receipts: bool,
    range: (i64, i64),
    selected: Option<&[i64]>,
) -> Result<Vec<KernelHistoryEvent>> {
    let mut snapshot = db.write_pool().begin().await?;
    let result = history_page_selected_on(
        &mut snapshot,
        principal_id,
        subject_id,
        after,
        newest,
        limit,
        full,
        include_import_receipts,
        range,
        selected,
    )
    .await;
    snapshot.rollback().await?;
    result
}

/// Existing history disclosure on the caller's read snapshot.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn history_page_in_range_on(
    snapshot: &mut SqliteConnection,
    principal_id: &str,
    subject_id: &str,
    after: Option<i64>,
    newest: bool,
    limit: usize,
    full: bool,
    include_import_receipts: bool,
    range: (i64, i64),
) -> Result<Vec<KernelHistoryEvent>> {
    history_page_selected_on(
        snapshot,
        principal_id,
        subject_id,
        after,
        newest,
        limit,
        full,
        include_import_receipts,
        range,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn history_page_selected_on(
    snapshot: &mut SqliteConnection,
    principal_id: &str,
    subject_id: &str,
    after: Option<i64>,
    newest: bool,
    limit: usize,
    full: bool,
    include_import_receipts: bool,
    range: (i64, i64),
    selected: Option<&[i64]>,
) -> Result<Vec<KernelHistoryEvent>> {
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(snapshot, principal_id).await?;
    if !hosted_identity::admitted(snapshot, principal_id).await? {
        return Ok(Vec::new());
    }
    let acknowledgement = legacy_history::sql_acknowledgement("r");
    if selected.is_none() {
        let record_ack: Option<bool> = sqlx::query_scalar(&format!(
            "SELECT COALESCE({acknowledgement},0) FROM kernel_records r WHERE r.id=?"
        ))
        .bind(subject_id)
        .fetch_optional(&mut *snapshot)
        .await?;
        let is_record = record_ack.is_some();
        if record_ack == Some(true) {
            return Ok(Vec::new());
        }
        let is_home: bool = if is_record {
            false
        } else {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
                .bind(subject_id)
                .fetch_optional(&mut *snapshot)
                .await?
                .unwrap_or(false)
        };
        let is_principal: bool = if is_record || is_home {
            false
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)",
            )
            .bind(subject_id)
            .fetch_optional(&mut *snapshot)
            .await?
            .unwrap_or(false)
        };
        if !is_record && !is_home && !is_principal {
            return Ok(Vec::new());
        }
        let visible = if is_principal {
            subject_id == principal_id
                || kernel_effective_capability_on(snapshot, principal_id, KERNEL_ROOT_ID)
                    .await?
                    .allows(Capability::View)
        } else {
            kernel_effective_capability_on(snapshot, principal_id, subject_id)
                .await?
                .allows(Capability::View)
        };
        if !visible {
            return Ok(Vec::new());
        }
        if is_record
            && !legacy_history::visible(
                snapshot,
                principal_id,
                subject_id,
                &mut std::collections::BTreeMap::new(),
            )
            .await?
        {
            return Ok(Vec::new());
        }
    }
    let root_visible = kernel_effective_capability_on(snapshot, principal_id, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View);
    let root_admin = kernel_effective_capability_on(snapshot, principal_id, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::Manage);
    let binding: Option<String> =
        sqlx::query_scalar("SELECT auth_binding FROM kernel_principals WHERE principal_id=?")
            .bind(principal_id)
            .fetch_optional(&mut *snapshot)
            .await?;
    let mut visible_rows = Vec::new();
    let mut subject_visibility = if selected.is_some() {
        std::collections::BTreeMap::new()
    } else {
        std::collections::BTreeMap::from([(subject_id.to_owned(), true)])
    };
    let selected_json = selected.map(serde_json::to_string).transpose()?;
    let mut cursor = after.unwrap_or(if newest { i64::MAX } else { 0 });
    let direction = if newest { "DESC" } else { "ASC" };
    let comparison = if newest { "<" } else { ">" };
    let batch = limit.min(256) as i64;
    loop {
        // Both arms seek indexed ranges. Payloads are never selected in metadata
        // mode; authorization uses small replayed facts instead of JSON envelopes.
        let selection = if selected.is_some() {
            format!("e.seq {comparison} ?2 AND e.seq IN (SELECT CAST(value AS INTEGER) FROM json_each(?10))")
        } else {
            format!("e.seq IN (SELECT seq FROM main.content_events WHERE record_id=?1 AND seq {comparison} ?2 AND seq BETWEEN ?8 AND ?9 UNION SELECT seq FROM kernel_legacy_subjects WHERE subject_id=?1 AND seq {comparison} ?2 AND seq BETWEEN ?8 AND ?9) AND ?10 IS NULL")
        };
        let sql = format!("SELECT e.seq,e.type AS event_type,e.record_id,e.actor,e.created_at,e.id,e.run_key,e.causal_status,
        h.event_type AS legacy_type,h.subjects,h.owner AS legacy_owner,h.hidden,
        CASE WHEN ?4 THEN e.payload ELSE NULL END AS payload,
        COALESCE({acknowledgement},0) AS acknowledgement,
        p.display_label AS actor_name,h.restricted,h.claim_sensitive
        FROM main.content_events e
        LEFT JOIN main.content_events receipt_legacy
          ON receipt_legacy.id=CASE WHEN ?5 AND e.type='kernel.import_receipt.v1'
             THEN json_extract(e.payload,'$.legacy_event_id') END
          AND receipt_legacy.type='kernel.legacy_recorded.v1'
          AND receipt_legacy.record_id=e.record_id AND receipt_legacy.act=e.act AND receipt_legacy.seq>e.seq
        LEFT JOIN kernel_legacy_history h
          ON h.seq=CASE WHEN e.type='kernel.import_receipt.v1' THEN receipt_legacy.seq ELSE e.seq END
        LEFT JOIN kernel_principals p ON p.principal_id=e.actor
        LEFT JOIN kernel_records r ON r.id=e.record_id
        WHERE {selection}
        AND e.type NOT IN ('kernel.v1_state_imported.v1','kernel.message_state.v1','kernel.message_command_committed.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1')
        AND (e.type!='kernel.import_receipt.v1' OR (?5 AND receipt_legacy.seq IS NOT NULL))
        AND (h.seq IS NULL OR (NOT h.hidden AND (?6 OR NOT h.restricted OR h.owner=?7)))
        ORDER BY e.seq {direction} LIMIT ?3");
        let rows: Vec<HistoryReadRow> = sqlx::query_as(&sql)
            .bind(subject_id)
            .bind(cursor)
            .bind(batch)
            .bind(full)
            .bind(include_import_receipts)
            .bind(root_admin)
            .bind(&binding)
            .bind(range.0)
            .bind(range.1)
            .bind(&selected_json)
            .fetch_all(&mut *snapshot)
            .await?;
        if rows.is_empty() {
            break;
        }
        let fetched = rows.len();
        for row in rows {
            cursor = row.seq;
            if selected.is_some()
                && (row.acknowledgement
                    || !legacy_history::visible(
                        snapshot,
                        principal_id,
                        &row.record_id,
                        &mut subject_visibility,
                    )
                    .await?)
            {
                continue;
            }
            let mut retained_legacy = None;
            if let Some(event_type) = &row.legacy_type {
                if row.hidden == Some(true) || row.acknowledgement {
                    continue;
                }
                let subjects: Vec<String> =
                    serde_json::from_str(row.subjects.as_deref().unwrap_or("[]"))?;
                if row.restricted == Some(true)
                    && !root_admin
                    && !row
                        .legacy_owner
                        .as_deref()
                        .is_some_and(|owner| Some(owner) == binding.as_deref())
                {
                    continue;
                }
                let mut allowed = true;
                for subject in subjects {
                    if !legacy_history::visible(
                        snapshot,
                        principal_id,
                        &subject,
                        &mut subject_visibility,
                    )
                    .await?
                    {
                        allowed = false;
                        break;
                    }
                }
                if !allowed {
                    continue;
                }
                // Receipts inherit disclosure facts from their witnessed row,
                // but stay native migration events, never duplicate legacy rows.
                if row.event_type == "kernel.legacy_recorded.v1" {
                    let specialized = event_type == crate::canvas::CANVAS_BATCH_EVENT_TYPE
                        || event_type.starts_with("agent_run.");
                    retained_legacy = Some(if full && root_visible && !specialized {
                        let mut envelope: serde_json::Value = serde_json::from_str(
                            row.payload
                                .as_deref()
                                .ok_or_else(|| Error::engine("missing retained envelope"))?,
                        )?;
                        let mut legacy = envelope["legacy"].take();
                        let holder = legacy["actor"]
                            .as_str()
                            .is_some_and(|a| Some(a) == binding.as_deref());
                        legacy_history::redact(
                            snapshot,
                            principal_id,
                            &mut legacy,
                            holder,
                            &mut subject_visibility,
                        )
                        .await?;
                        legacy
                    } else {
                        legacy_history::marker(event_type)
                    });
                }
            }
            // Retained app capsules can include other accounts' install consent
            // and references to independently protected records. They are custody,
            // not ordinary record history or an executable app grant.
            if row.event_type == app_state::IMPORTED_EVENT {
                continue;
            }
            if row.event_type == commit_port::PROVIDER_OUTCOME_EVENT {
                let payload: String =
                    sqlx::query_scalar("SELECT payload FROM main.content_events WHERE seq=?")
                        .bind(row.seq)
                        .fetch_one(&mut *snapshot)
                        .await?;
                let payload = serde_json::from_str(&payload)?;
                let entry = provider_catalogue::recorded(&payload)?;
                let decoded = (entry.decode)(&payload)?;
                let mut all_visible = true;
                for subject in &decoded.facts.subjects {
                    if !kernel_effective_capability_on(snapshot, principal_id, subject)
                        .await?
                        .allows(Capability::View)
                    {
                        all_visible = false;
                        break;
                    }
                }
                if !all_visible {
                    continue;
                }
            }
            if matches!(
                row.event_type.as_str(),
                "kernel.generic_link_note_updated.v1"
                    | "kernel.generic_link_note_imported.v1"
                    | "kernel.generic_link_added.v1"
                    | "kernel.generic_link_imported.v1"
                    | "kernel.generic_link_removed.v1"
                    | "kernel.generic_link_removal_imported.v1"
            ) && !generic_links::history_visible(snapshot, principal_id, row.seq).await?
            {
                continue;
            }
            if row.event_type == "kernel.link_added.v2" {
                let target: Option<String> = sqlx::query_scalar(
                    "SELECT target_id FROM kernel_link4_edges WHERE created_seq = ?",
                )
                .bind(row.seq)
                .fetch_optional(&mut *snapshot)
                .await?;
                let target =
                    target.ok_or_else(|| Error::engine("missing directed-link history witness"))?;
                if !kernel_effective_capability_on(snapshot, principal_id, &target)
                    .await?
                    .allows(Capability::View)
                {
                    continue;
                }
            }
            let claim_holder =
                row.actor.as_deref().and_then(|a| a.strip_prefix("v1:")) == binding.as_deref();
            let run_key = if row.claim_sensitive == Some(true) && !claim_holder {
                None
            } else {
                row.run_key.clone()
            };
            let provenance = (
                row.id.clone(),
                run_key,
                row.causal_status.clone(),
                row.actor_name.clone(),
            );
            let compact = (
                row.seq,
                row.event_type,
                row.record_id,
                row.actor,
                row.created_at,
            );
            visible_rows.push((compact, provenance, retained_legacy));
            if visible_rows.len() >= limit {
                break;
            }
        }
        if visible_rows.len() >= limit || fetched < batch as usize {
            break;
        }
    }
    Ok(visible_rows
        .into_iter()
        .map(
            |(
                (seq, event_type, record_id, actor, created_at),
                (id, run_key, causal_status, actor_name),
                retained_legacy,
            )| {
                let disclosed = match actor {
                    None => None,
                    Some(token) if token == principal_id => Some(token),
                    Some(token) if root_visible => Some(token),
                    Some(_) => None,
                };
                KernelHistoryEvent {
                    retained_legacy,
                    id,
                    run_key: if root_visible { run_key } else { None },
                    causal_status,
                    seq,
                    event_type,
                    record_id,
                    actor_name: disclosed.as_ref().and(actor_name),
                    actor: disclosed,
                    created_at,
                }
            },
        )
        .collect())
}

/// Describe the world for a principal: every definition that resolves in a
/// home the caller can View (via the shared effective-adoption function
/// create uses), with full kind semantics, adoption state, the visible
/// homes where it resolves (`resolved_in`), and the Edit subset
/// (`creatable_homes`). Unresolvable families stay absent, never marked;
/// no scope home the caller cannot View is ever named.
pub async fn describe_world_as(db: &Db, principal_id: &str) -> Result<serde_json::Value> {
    let mut snapshot = db.write_pool().begin().await?;
    // Family universe: every family with a scoped row or a workspace-wide
    // choice. Homes the caller can View, sorted. Then resolve each family in
    // each visible home with the SHARED effective-adoption function create
    // uses, grouping homes by outcome. A group with a non-empty visible set
    // becomes entries; anything else stays absent — so describe can neither
    // omit a usable definition nor name an unseen home.
    let mut families: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT family FROM kernel_adoptions ORDER BY family")
            .fetch_all(&mut *snapshot)
            .await?;
    let global_families: Vec<(String,)> =
        sqlx::query_as("SELECT family FROM definition_adoptions ORDER BY family")
            .fetch_all(&mut *snapshot)
            .await?;
    for (family,) in global_families {
        if !families.contains(&family) {
            families.push(family);
        }
    }
    families.sort();
    let all_homes: Vec<(String,)> =
        sqlx::query_as("SELECT root_id FROM kernel_roots ORDER BY root_id")
            .fetch_all(&mut *snapshot)
            .await?;
    let mut visible_homes = Vec::new();
    for (home,) in all_homes {
        if kernel_effective_capability_on(&mut snapshot, principal_id, &home)
            .await?
            .allows(Capability::View)
        {
            visible_homes.push(home);
        }
    }
    struct ResolvedGroup {
        family: String,
        pin: Option<RevisionIdentity>,
        homes: Vec<String>,
    }
    let mut groups: Vec<ResolvedGroup> = Vec::new();
    for family in &families {
        for home in &visible_homes {
            match resolve_effective_adoption(&mut snapshot, family, home).await? {
                None => {}
                Some(ScopedAdoption::Disabled) => {
                    match groups
                        .iter_mut()
                        .find(|g| g.family == *family && g.pin.is_none())
                    {
                        Some(group) => group.homes.push(home.clone()),
                        None => groups.push(ResolvedGroup {
                            family: family.clone(),
                            pin: None,
                            homes: vec![home.clone()],
                        }),
                    }
                }
                Some(ScopedAdoption::Adopted(pin)) => {
                    match groups
                        .iter_mut()
                        .find(|g| g.family == *family && g.pin.as_ref() == Some(&pin))
                    {
                        Some(group) => group.homes.push(home.clone()),
                        None => groups.push(ResolvedGroup {
                            family: family.clone(),
                            pin: Some(pin),
                            homes: vec![home.clone()],
                        }),
                    }
                }
            }
        }
    }
    let mut definitions: Vec<serde_json::Value> = Vec::new();
    // Package provenance (K6/K8): map every installed definition revision
    // embedded by an installed package to that package. A revision embedded
    // by no package is local. When more than one package embeds the same
    // revision the deterministic (namespace, name, version) order picks the
    // first. Unreadable package bytes are skipped rather than failing this
    // read: provenance is descriptive, not authority.
    let package_rows: Vec<(String, String, i64, String, String)> = sqlx::query_as(
        "SELECT namespace, name, version, digest, manifest_bytes FROM package_artifacts
          ORDER BY namespace, name, version",
    )
    .fetch_all(&mut *snapshot)
    .await?;
    let mut supplied: std::collections::HashMap<(String, u32, String), serde_json::Value> =
        std::collections::HashMap::new();
    for (ns, name, pkg_version, pkg_digest, manifest_bytes) in package_rows {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&manifest_bytes) else {
            continue;
        };
        let Ok(manifest) = crate::package_manifest::PackageManifest::from_canonical_value(&value)
        else {
            continue;
        };
        let provenance = serde_json::json!({
            "namespace": ns,
            "name": name,
            "version": pkg_version,
            "digest": pkg_digest,
        });
        for entry in manifest.definitions {
            supplied
                .entry((entry.family, entry.version, entry.digest))
                .or_insert_with(|| provenance.clone());
        }
    }
    for group in &groups {
        let (family, pin, resolved_in) = (&group.family, &group.pin, &group.homes);
        // Bytes for kind enumeration: the adopted pin, else the newest
        // installed revision (disable retains bytes), else nothing to list.
        let bytes: Option<String> = match &pin {
            Some(pin) => crate::definition_registry::read_definition_artifact_on(
                &mut snapshot,
                family,
                pin.version,
                &pin.digest,
            )
            .await?
            .map(|artifact| artifact.bytes),
            None => {
                let row: Option<(String, i64, String)> = sqlx::query_as(
                    "SELECT artifact_bytes, version, digest FROM definition_artifacts WHERE family = ? ORDER BY version DESC LIMIT 1",
                )
                .bind(family)
                .fetch_optional(&mut *snapshot)
                .await?;
                row.map(|(b, _, _)| b)
            }
        };
        // Package provenance (K6/K8) is the adopted revision's supplying
        // package. A disabled entry has no adopted pin, so it takes no
        // package: its bytes may come from a newer installed revision, but
        // that revision was never adopted here and must not be attributed to
        // the tombstone.
        let package = pin
            .as_ref()
            .and_then(|pin| supplied.get(&(family.clone(), pin.version, pin.digest.clone())))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let structured_language = bytes
            .as_deref()
            .map(crate::structured_values::declared_language)
            .transpose()?
            .flatten();
        // No bytes at all (disabled without any install): one null-kind
        // entry carrying the disabled state, so the tombstone is visible.
        let (primary_type, defn2, kinds): DescribedKinds = match bytes {
            None => (serde_json::Value::Null, false, vec![(String::new(), None)]),
            Some(bytes) => {
                crate::meta::definition_artifact::validate_kernel_definition_bytes(&bytes)?;
                let doc: serde_json::Value = serde_json::from_str(&bytes)?;
                let defn2 = doc
                    .get("interpreter")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|marker| {
                        crate::meta::definition_artifact::language_capabilities(Some(marker))
                            .supports_fields
                    });
                let primary_type = doc
                    .get("primary_type")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let mut kinds: Vec<(String, Option<serde_json::Map<String, serde_json::Value>>)> =
                    Vec::new();
                for entry in doc
                    .get("kinds")
                    .and_then(|k| k.as_array())
                    .into_iter()
                    .flatten()
                {
                    if let Some(token) = entry.as_str() {
                        kinds.push((token.to_string(), None));
                    } else if let Some(obj) = entry.as_object() {
                        if let Some(token) = obj.get("token").and_then(serde_json::Value::as_str) {
                            kinds.push((token.to_string(), Some(obj.clone())));
                        }
                    }
                }
                kinds.sort_by(|a, b| a.0.cmp(&b.0));
                if kinds.is_empty() {
                    kinds.push((String::new(), None));
                }
                (primary_type, defn2, kinds)
            }
        };
        // Creatable homes: the Edit subset of `resolved_in` — derivation
        // from the same visible set keeps F2 fixed by construction. Empty
        // when disabled (create would refuse: nothing is adopted here).
        let mut creatable: Vec<String> = Vec::new();
        if pin.is_some() {
            for home in resolved_in {
                if kernel_effective_capability_on(&mut snapshot, principal_id, home)
                    .await?
                    .allows(Capability::Edit)
                {
                    creatable.push(home.clone());
                }
            }
        }
        for (token, kind_obj) in &kinds {
            let kind_value = if token.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(token.clone())
            };
            let detail = describe_kind_detail(kind_obj.as_ref(), defn2);
            let (state, pin_value, operations) = match &pin {
                Some(pin) => (
                    "adopted",
                    serde_json::to_value(pin)?,
                    describe_operations_for(&primary_type, &kind_value),
                ),
                None => ("disabled", serde_json::Value::Null, serde_json::json!([])),
            };
            definitions.push(serde_json::json!({
                "family": family,
                "package": package,
                "version": pin.as_ref().map(|p| serde_json::json!(p.version)).unwrap_or(serde_json::Value::Null),
                "digest": pin.as_ref().map(|p| serde_json::json!(p.digest.clone())).unwrap_or(serde_json::Value::Null),
                "primary_type": primary_type,
                "kind": kind_value,
                "fields": detail.get("fields").cloned().unwrap_or(serde_json::Value::Null),
                "identity": detail.get("identity").cloned().unwrap_or(serde_json::Value::Null),
                "links": detail.get("links").cloned().unwrap_or(serde_json::Value::Null),
                "refines": detail.get("refines").cloned().unwrap_or(serde_json::Value::Null),
                "maturity": detail.get("maturity").cloned().unwrap_or(serde_json::Value::Null),
                "description": detail.get("description").cloned().unwrap_or(serde_json::Value::Null),
                "adoption": {"state": state, "resolved_in": resolved_in, "pin": pin_value, "creatable_homes": creatable},
                "operations": operations,
            }));
            if let Some(marker) = structured_language {
                let entry = definitions.last_mut().unwrap();
                entry["interpreter"] = marker.into();
                entry["value_contract"] = crate::structured_values::contract(marker);
            }
        }
    }
    // Visible callable operations: resolve each package selection adopted in a
    // home the caller can see through the same fail-closed activation gate a
    // call uses, and advertise its operations. A displaced, disabled, or
    // unreadable selection is skipped rather than advertised. The key is
    // omitted entirely when there is nothing callable, so an old
    // definitions-only world keeps its exact describe shape.
    let mut package_operations: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String, String, u32, String, String)> =
        std::collections::BTreeSet::new();
    let selection_rows: Vec<(String, String, String, i64, String, i64)> = sqlx::query_as(
        "SELECT scope_home, namespace, name, selected_version, selected_digest, event_seq
           FROM kernel_package_selections
          WHERE selected_version IS NOT NULL
          ORDER BY namespace, name, scope_home",
    )
    .fetch_all(&mut *snapshot)
    .await?;
    for (scope_home, namespace, name, _version, _digest, _event_seq) in selection_rows {
        if !visible_homes.iter().any(|home| home == &scope_home) {
            continue;
        }
        let Ok((selection, manifest)) =
            require_package_active_in(&mut snapshot, &scope_home, &namespace, &name).await
        else {
            continue;
        };
        let Some(selected) = selection.selected.as_ref() else {
            continue;
        };
        for operation in &manifest.operations {
            let key = (
                scope_home.clone(),
                namespace.clone(),
                name.clone(),
                selected.version,
                selected.digest.clone(),
                operation.name.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            let mut descriptor = serde_json::json!({
                "name":operation.name,"description":operation.description,"provider":operation.provider,
                "family":operation.family,"kind":operation.kind,"source_field":operation.source_field,
                "reads":operation.reads,"effects":operation.effects,
            });
            if operation.targets_any_record() {
                let object = descriptor.as_object_mut().expect("descriptor object");
                for selector in ["family", "kind", "source_field"] {
                    object.remove(selector);
                }
                object.insert("target".into(), serde_json::json!("any-record"));
            }
            package_operations.push(serde_json::json!({
                "scope_home": scope_home,
                "namespace": namespace,
                "name": name,
                "version": selected.version,
                "package_digest": selected.digest,
                "ack_event_seq": selection.event_seq,
                "operation": descriptor,
            }));
        }
    }
    snapshot.rollback().await?;
    let mut output = serde_json::json!({
        "definitions": definitions,
        "namespace_policy": crate::v2_standard::namespace_policy(),
        "directed_links": links_v2::contract(),
    });
    if package_operations
        .iter()
        .any(|op| op["operation"]["provider"] == crate::v2_standard::relates_to::PROVIDER)
    {
        output["governed_relationships"] = relates_to_port::contract();
    }
    if !package_operations.is_empty() {
        output.as_object_mut().expect("describe object").insert(
            "package_operations".to_string(),
            serde_json::Value::Array(package_operations),
        );
    }
    Ok(output)
}

/// One describe entry's kind detail: full `/2` semantics when the envelope
/// declares them, empty otherwise (`/1` definitions appear with the fields
/// they have: none). Reads validated bytes; missing keys fall back to null
/// rather than failing the whole describe.
fn describe_kind_detail(
    kind_obj: Option<&serde_json::Map<String, serde_json::Value>>,
    defn2: bool,
) -> serde_json::Value {
    if !defn2 {
        return serde_json::json!({
            "fields": [], "identity": null, "links": [],
            "refines": null, "maturity": null, "description": null,
        });
    }
    let get = |key: &str| {
        kind_obj
            .and_then(|o| o.get(key))
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    serde_json::json!({
        "fields": get("fields"), "identity": get("identity"), "links": get("links"),
        "refines": get("refines"), "maturity": get("maturity"),
        "description": get("description"),
    })
}

/// The generic operations for one adopted kind: fixed names with the
/// capability each requires. Disabled definitions get none.
fn describe_operations_for(
    primary_type: &serde_json::Value,
    kind: &serde_json::Value,
) -> serde_json::Value {
    let applies_to = serde_json::json!({"primary_type": primary_type, "kind": kind});
    serde_json::json!([
        {"name": "create", "requires": "Edit", "applies_to": applies_to},
        {"name": "link", "requires": "Edit", "applies_to": applies_to},
        {"name": "query", "requires": "View", "applies_to": applies_to},
        {"name": "revise", "requires": "Edit", "applies_to": applies_to},
        {"name": "history", "requires": "View", "applies_to": applies_to},
    ])
}

/// Install one definition revision as a principal. Requires Manage on the
/// workspace root; the install event is attributed to the principal id.
pub async fn install_definition_as(
    db: &Db,
    actor_principal_id: &str,
    family: &str,
    version: u32,
    artifact: &[u8],
) -> Result<RevisionIdentity> {
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(
        &mut tx,
        actor_principal_id,
        KERNEL_ROOT_ID,
        Capability::Manage,
    )
    .await?;
    if crate::v2_standard::is_reserved_namespace(family) {
        return Err(Error::engine(
            "reserved namespace: native and native.* definition names (ignoring ASCII case) must be installed through an exact first-party package compiled into this binary. Use your own definition family.",
        ));
    }
    // Kernel-side language gate (test-only): `/2` semantics and unknown
    // markers refuse here, before anything is appended. The shared registry
    // parse stays language-blind.
    let text = std::str::from_utf8(artifact)
        .map_err(|_| Error::engine("definition artifact bytes must be valid UTF-8"))?;
    crate::meta::definition_artifact::validate_kernel_definition_bytes(text)?;
    let mut acts = crate::act::ActAllocation::new();
    let outcome = crate::definition_registry::install_definition_artifact_as_in(
        &mut tx,
        family,
        version,
        artifact,
        Some(actor_principal_id),
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(outcome.identity)
}

/// Install one package revision as a principal. Requires Manage on the
/// workspace root; the install event is attributed to the principal id.
/// Every embedded definition installs in the same transaction, then one
/// package-installed meta event appends. Exact retry appends nothing;
/// same-triple/different-digest refuses with history unchanged.
pub async fn install_package_as(
    db: &Db,
    actor_principal_id: &str,
    manifest: &crate::package_manifest::PackageManifest,
) -> Result<crate::package_manifest::ManifestIdentity> {
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(
        &mut tx,
        actor_principal_id,
        KERNEL_ROOT_ID,
        Capability::Manage,
    )
    .await?;
    let mut acts = crate::act::ActAllocation::new();
    let outcome = crate::meta::package::install_package_in(
        &mut tx,
        manifest,
        Some(actor_principal_id),
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(outcome.identity)
}

/// Adopt (or, with `selected=None`, disable) one installed package revision
/// in a scope as a principal. Requires Manage on the scope home; refusal
/// appends nothing and names nothing beyond the uniform oracle answer.
///
/// All state changes share ONE transaction: the package selection event plus
/// the embedded family pin events (adopt) or conditional family tombstones
/// (disable). No nested transactions: family changes reuse the definition
/// event shape inline rather than calling `adopt_definition_at`.
pub async fn adopt_package_at(
    db: &Db,
    actor_principal_id: &str,
    scope_home: &str,
    manifest: &crate::package_manifest::PackageManifest,
    selected: Option<&crate::package_manifest::ManifestIdentity>,
    acknowledged_reads: &[String],
) -> Result<PackageAdoptReceipt> {
    manifest.validate()?;
    let identity = manifest.identity()?;
    if selected.is_some_and(|s| s != &identity) {
        return Err(Error::engine(
            "package adoption selects a different revision than the manifest",
        ));
    }
    let mut ack_sorted = acknowledged_reads.to_vec();
    ack_sorted.sort();
    let mut declared_sorted = manifest.declared_reads.clone();
    declared_sorted.sort();
    if selected.is_some() {
        if ack_sorted != declared_sorted {
            return Err(Error::engine(
                "package acknowledgment must exactly cover the declared reads; widened reads require a fresh acknowledgment",
            ));
        }
    } else if !acknowledged_reads.is_empty() {
        return Err(Error::engine(
            "package disable tombstone carries no acknowledgment",
        ));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let scope_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(scope_home)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);
    if !scope_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut tx, actor_principal_id, scope_home, Capability::Manage).await?;
    let stored = crate::meta::package::read_package_in(
        &mut tx,
        &manifest.namespace,
        &manifest.name,
        manifest.version,
        &identity.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("package adoption selects a missing package revision"))?;
    let _ = stored;
    // The retry/staleness decision runs on the verified read, never the raw
    // projection alone: a tampered row fails here instead of being blessed
    // as a no-op. Any verification error aborts before anything appends.
    let verified =
        read_package_selection_in(&mut tx, scope_home, &manifest.namespace, &manifest.name).await?;
    // Dependency-safety preflight (task e2bfaf5): prospective before/after
    // impact over the same writer tx, before any append — including on the
    // exact-retry paths below, so a retry verifies and enforces rather than
    // blessing state. Refusal appends nothing.
    {
        let (changes, old) = if selected.is_some() {
            (
                crate::dependency::prospective_for_package_adopt(
                    scope_home,
                    manifest,
                    &identity.digest,
                ),
                match resolve_effective_package_selection(
                    &mut tx,
                    scope_home,
                    &manifest.namespace,
                    &manifest.name,
                )
                .await?
                {
                    Some(stored) => match stored.selected {
                        Some(sel) => Some(
                            crate::meta::package::read_package_in(
                                &mut tx,
                                &sel.namespace,
                                &sel.name,
                                sel.version,
                                &sel.digest,
                            )
                            .await?
                            .ok_or_else(|| Error::engine(crate::dependency::DEPENDENCY_REFUSAL))?
                            .manifest,
                        ),
                        None => None,
                    },
                    None => None,
                },
            )
        } else {
            (
                crate::dependency::prospective_for_package_disable(&mut tx, scope_home, manifest)
                    .await?,
                None,
            )
        };
        let retained = old.as_ref().map(|old| crate::dependency::RetainedCheck {
            old,
            candidate: manifest,
        });
        let impact = crate::dependency::preflight(
            &mut tx,
            actor_principal_id,
            scope_home,
            &changes,
            retained,
        )
        .await?;
        if impact.refuses() {
            return Err(Error::engine(crate::dependency::DEPENDENCY_REFUSAL));
        }
    }
    let want_selected = selected.map(|_| PackageSelection {
        namespace: manifest.namespace.clone(),
        name: manifest.name.clone(),
        version: manifest.version,
        digest: identity.digest.clone(),
    });
    match (verified, selected) {
        // Exact-state retry includes the actor: a different Manage principal
        // acknowledging the same declaration gets their own attributed event,
        // never the previous actor's receipt. Same rule covers the disabled
        // no-op below.
        (Some(stored), _)
            if stored.selected == want_selected
                && stored.acknowledged_reads == ack_sorted
                && stored.ack_actor == actor_principal_id =>
        {
            let receipt = PackageAdoptReceipt {
                scope_home: scope_home.to_string(),
                namespace: manifest.namespace.clone(),
                name: manifest.name.clone(),
                selected: stored.selected,
                acknowledged_reads: stored.acknowledged_reads,
                ack_actor: stored.ack_actor,
                event_seq: stored.event_seq,
            };
            tx.rollback().await?;
            return Ok(receipt);
        }
        (Some(stored), None) => {
            // A live selection exists; only the matching revision may
            // tombstone it, so a stale disable cannot clobber another
            // selection.
            match &stored.selected {
                // Already tombstoned by the same attributor: no-op. A
                // different Manage principal falls through and records
                // their own tombstone below, per the attribution rule.
                None if stored.ack_actor == actor_principal_id
                    && stored.acknowledged_reads == ack_sorted =>
                {
                    let receipt = PackageAdoptReceipt {
                        scope_home: scope_home.to_string(),
                        namespace: manifest.namespace.clone(),
                        name: manifest.name.clone(),
                        selected: None,
                        acknowledged_reads: stored.acknowledged_reads.clone(),
                        ack_actor: stored.ack_actor.clone(),
                        event_seq: stored.event_seq,
                    };
                    tx.rollback().await?;
                    return Ok(receipt);
                }
                None => {}
                Some(current)
                    if current.version != manifest.version || current.digest != identity.digest =>
                {
                    return Err(Error::engine(
                        "stale package disable: the scope selection moved to another revision",
                    ));
                }
                Some(_) => {}
            }
        }
        (None, None) => {
            // No exact row: a child may still tombstone an inherited live
            // selection. Compare against the effective ancestor selection for
            // stale-pin safety; an already-suppressed subtree is a no-op.
            match resolve_effective_package_selection(
                &mut tx,
                scope_home,
                &manifest.namespace,
                &manifest.name,
            )
            .await?
            {
                None => {
                    return Err(Error::engine("no active package selection to disable"));
                }
                Some(ancestor) => match ancestor.selected {
                    None => {
                        let receipt = PackageAdoptReceipt {
                            scope_home: scope_home.to_string(),
                            namespace: manifest.namespace.clone(),
                            name: manifest.name.clone(),
                            selected: None,
                            acknowledged_reads: ancestor.acknowledged_reads,
                            ack_actor: ancestor.ack_actor,
                            event_seq: ancestor.event_seq,
                        };
                        tx.rollback().await?;
                        return Ok(receipt);
                    }
                    Some(current) => {
                        if current.version != manifest.version || current.digest != identity.digest
                        {
                            return Err(Error::engine(
                                "stale package disable: the scope selection moved to another revision",
                            ));
                        }
                    }
                },
            }
        }
        _ => {}
    }
    let mut acts = crate::act::ActAllocation::new();
    let event = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: scope_home.into(),
            event_type: KERNEL_PACKAGE_ADOPTED_EVENT.into(),
            payload: serde_json::to_value(KernelPackageAdoptedPayload {
                scope_home: scope_home.to_string(),
                namespace: manifest.namespace.clone(),
                name: manifest.name.clone(),
                selected: selected.map(|_| PackagePin {
                    version: manifest.version,
                    digest: identity.digest.clone(),
                }),
                acknowledged_reads: ack_sorted.clone(),
            })?,
            actor: Some(actor_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    if selected.is_some() {
        for entry in &manifest.definitions {
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: scope_home.into(),
                    event_type: KERNEL_DEFINITION_ADOPTED_EVENT.into(),
                    payload: serde_json::to_value(KernelDefinitionAdoptedPayload {
                        family: entry.family.clone(),
                        selected: Some(RevisionIdentity {
                            family: entry.family.clone(),
                            version: entry.version,
                            digest: entry.digest.clone(),
                        }),
                        scope_home: scope_home.to_string(),
                    })?,
                    actor: Some(actor_principal_id.into()),
                },
                &mut acts,
            )
            .await?;
        }
    } else {
        for entry in &manifest.definitions {
            let pinned_here = matches!(
                resolve_effective_adoption_verified(&mut tx, &entry.family, scope_home).await?,
                Some(ScopedAdoption::Adopted(pin))
                    if pin.version == entry.version && pin.digest == entry.digest
            );
            if !pinned_here {
                continue;
            }
            // Effective sharing (task e2bfaf5 falsifier): same-scope rows
            // alone would tombstone a pin an inherited selection still
            // provides. Consult every effective selection at this scope.
            if crate::dependency::scope_effectively_shares_family_pin(
                &mut tx,
                scope_home,
                &manifest.namespace,
                &manifest.name,
                &entry.family,
                entry.version,
                &entry.digest,
            )
            .await?
            {
                continue;
            }
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: scope_home.into(),
                    event_type: KERNEL_DEFINITION_ADOPTED_EVENT.into(),
                    payload: serde_json::to_value(KernelDefinitionAdoptedPayload {
                        family: entry.family.clone(),
                        selected: None,
                        scope_home: scope_home.to_string(),
                    })?,
                    actor: Some(actor_principal_id.into()),
                },
                &mut acts,
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(PackageAdoptReceipt {
        scope_home: scope_home.to_string(),
        namespace: manifest.namespace.clone(),
        name: manifest.name.clone(),
        selected: selected.map(|_| PackageSelection {
            namespace: manifest.namespace.clone(),
            name: manifest.name.clone(),
            version: manifest.version,
            digest: identity.digest.clone(),
        }),
        acknowledged_reads: ack_sorted,
        ack_actor: actor_principal_id.to_string(),
        event_seq: event.local_seq,
    })
}

/// One scoped package selection row with its caller-asserted acknowledgment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPackageSelection {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub selected: Option<PackageSelection>,
    pub ack_actor: String,
    pub acknowledged_reads: Vec<String>,
    pub event_seq: i64,
}

/// Read one package selection with projection/log agreement: the latest
/// content event for this package in the scope must reproduce the projection
/// row exactly, or the read fails rather than trusting either side alone.
type PackageSelectionProjectionRow = (Option<i64>, Option<String>, String, String, i64);

pub(crate) async fn read_package_selection_in(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<Option<StoredPackageSelection>> {
    read_package_selection_before(conn, scope_home, namespace, name, i64::MAX).await
}

async fn read_package_selection_before(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
    before: i64,
) -> Result<Option<StoredPackageSelection>> {
    let row: Option<PackageSelectionProjectionRow> = sqlx::query_as(
        "SELECT selected_version, selected_digest, ack_actor, ack_reads, event_seq
           FROM kernel_package_selections
          WHERE scope_home = ? AND namespace = ? AND name = ?",
    )
    .bind(scope_home)
    .bind(namespace)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((version, digest, ack_actor, ack_reads, event_seq)) = row else {
        return Ok(None);
    };
    // Latest authorizing event, SQL-filtered to this package: the scan is
    // bounded to the scope's package events via the (record_id) index half,
    // and the triple match runs inside SQLite (json_extract) rather than by
    // loading every package event in the scope.
    let event: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT payload, seq, actor FROM main.content_events
          WHERE record_id = ? AND type = 'kernel.package_adopted.v1' AND seq < ?
            AND json_extract(payload, '$.namespace') = ?
            AND json_extract(payload, '$.name') = ?
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(scope_home)
    .bind(before)
    .bind(namespace)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((payload_text, seq, event_actor)) = event else {
        return Err(Error::engine(
            "package selection projection has no authorizing log event",
        ));
    };
    let payload: KernelPackageAdoptedPayload = serde_json::from_str(&payload_text)?;
    if payload.scope_home != scope_home {
        return Err(Error::engine(
            "package authorizing event names a different scope",
        ));
    }
    if event_actor.as_deref().unwrap_or("") != ack_actor {
        return Err(Error::engine(
            "package selection actor disagrees with its authorizing log event",
        ));
    }
    let payload_selected = payload
        .selected
        .as_ref()
        .map(|pin| (pin.version as i64, pin.digest.clone()));
    let row_selected = version.zip(digest.clone());
    if payload_selected != row_selected
        || payload.acknowledged_reads != serde_json::from_str::<Vec<String>>(&ack_reads)?
        || seq != event_seq
    {
        return Err(Error::engine(
            "package selection projection disagrees with its authorizing log event",
        ));
    }
    Ok(Some(StoredPackageSelection {
        scope_home: scope_home.to_string(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        selected: payload.selected.map(|pin| PackageSelection {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version: pin.version,
            digest: pin.digest,
        }),
        ack_actor,
        acknowledged_reads: payload.acknowledged_reads,
        event_seq,
    }))
}

/// Nearest-ancestor package selection: walk the scope's ancestor chain for
/// the first selection row, tombstone included. A child tombstone suppresses
/// only its own subtree; a missing row inherits. Writes stay exact-scope —
/// this is the read/activation path only, mirroring definition
/// `resolve_scoped_adoption` (which likewise stops at the first row).
pub(crate) async fn resolve_effective_package_selection(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<Option<StoredPackageSelection>> {
    resolve_effective_package_selection_before(conn, scope_home, namespace, name, i64::MAX).await
}

async fn resolve_effective_package_selection_before(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
    before: i64,
) -> Result<Option<StoredPackageSelection>> {
    let mut scope = scope_home.to_string();
    let mut depth = 0usize;
    loop {
        if let Some(stored) =
            read_package_selection_before(conn, &scope, namespace, name, before).await?
        {
            return Ok(Some(stored));
        }
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        let parent: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
                .bind(&scope)
                .fetch_optional(&mut *conn)
                .await?;
        match parent.flatten() {
            Some(parent) => scope = parent,
            None => return Ok(None),
        }
    }
}

/// Fail-closed activation gate for future execution (and present reads): a
/// selection that is missing, tombstoned, or whose embedded definition pins
/// were displaced by another package refuses instead of running against a
/// projection that claims active. The selection resolves through ancestors
/// (root adoption activates children); displacement is checked through the
/// shared effective-adoption function at the requested scope.
pub(crate) async fn require_package_active_in(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<(
    StoredPackageSelection,
    crate::package_manifest::PackageManifest,
)> {
    let stored = resolve_effective_package_selection(conn, scope_home, namespace, name)
        .await?
        .ok_or_else(|| Error::engine("package is not adopted in this scope"))?;
    let Some(selection) = &stored.selected else {
        return Err(Error::engine("package is disabled in this scope"));
    };
    let manifest = crate::meta::package::read_package_in(
        conn,
        namespace,
        name,
        selection.version,
        &selection.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("adopted package revision is no longer installed"))?
    .manifest;
    for entry in &manifest.definitions {
        let current = resolve_effective_adoption(conn, &entry.family, scope_home).await?;
        let matches = matches!(current,
            Some(ScopedAdoption::Adopted(pin))
                if pin.version == entry.version && pin.digest == entry.digest);
        if !matches {
            return Err(Error::engine(format!(
                "package definition '{}@{}' was displaced; refusing closed",
                entry.family, entry.version
            )));
        }
    }
    Ok((stored, manifest))
}

/// Fallback view when no package manifest is known. Named and static: it
/// carries no reason, so missing, disabled, displaced, and undeclared
/// collapse into one indistinguishable answer.
pub const SURFACE_FALLBACK_VIEW: &str = "package.unavailable";

/// Clean report for a package that supplies no behaviour or surface (K5
/// definitions-only). A surface read against such a package answers this
/// notice instead of pretending a named fallback exists or erroring.
pub const SURFACE_NONE_VIEW: &str = "package.no-surface";

/// The single read token the fixed S3 operation serves. Other declared
/// scopes remain stored acknowledgment metadata for future operations; only
/// this token executes, and only with an explicit linked target.
pub const SURFACE_FIXED_READ: &str = "linked_record:view";

/// One visible row served through a package surface: id plus fields only.
/// No totals, hidden counts, or hidden ids ever accompany a page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceHit {
    pub id: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Freshness fence returned with every served page. It reports the package
/// pin, the authorizing selection event, and the content seq served — enough
/// for a later reader to detect invalidation by comparing against the live
/// selection. It is not a snapshot (rows may move), not authority, and not
/// consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceReadReceipt {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub package_version: u32,
    pub package_digest: String,
    pub ack_event_seq: i64,
    pub served_content_seq: i64,
}

/// Outcome of one fixed host-owned read-only surface read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceReadOutcome {
    Hits {
        hits: Vec<SurfaceHit>,
        cursor: Option<String>,
        receipt: SurfaceReadReceipt,
    },
    Fallback {
        fallback_view: String,
    },
}

/// One rendered row in a package surface list: visible id plus fields only.
/// The host owns the layout; packages contribute no markup, scripts, or
/// renderer names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceViewRow {
    pub id: String,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Minimal caller-authorized introspection (K8 feed): the verified package
/// pin, its embedded definition pins, and the declared read token. Present
/// only when the viewer may View the scope and the package is active; never
/// a broad catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIntrospection {
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub digest: String,
    pub definition_pins: Vec<crate::meta::definition_artifact::RevisionIdentity>,
    pub declared_reads: Vec<String>,
    pub ack_event_seq: i64,
}

/// Host-rendered declarative surface model: exactly one fixed bounded list
/// layout or one fixed fallback notice layout. `view`/`fallback` are safe
/// names from verified pinned bytes, used as title/notice markers — never
/// executed, never branched per package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceViewModel {
    List {
        title: String,
        rows: Vec<SurfaceViewRow>,
        cursor: Option<String>,
        receipt: SurfaceReadReceipt,
        introspection: Box<PackageIntrospection>,
    },
    Notice {
        notice: String,
    },
}

/// One fixed host-owned read-only behaviour (slice 3 S3, V2T only): serve a
/// bounded query page through an adopted package's declared reads, under the
/// viewing principal's authority. No package code runs; the host executes
/// one `query_as` with the fixed read token and returns only visible hits.
///
/// Gates, in order: the package selection is active with undisplaced pins
/// (fail closed, disabled check first); the read token sits in BOTH the
/// manifest behaviour reads and the acknowledged reads; the queried family
/// is one of the package's embedded definitions; the linked target, if any,
/// resolves under viewer authority inside `query_as` (private and missing
/// are indistinguishable there). Because `query_as` opens its own
/// transaction, the selection and pins are rechecked afterwards: any change
/// discards the page for the manifest's named fallback.
///
/// Named fallback from the latest verified SELECTED pin, scope-aware: the
/// requested scope names its newest selected revision (a same-scope
/// tombstone still keeps its snapshot's name even after a newer unadopted
/// version installs). With no selected event locally, an explicit local
/// tombstone stops the walk (suppressed subtrees borrow no ancestor
/// name); otherwise naming inherits from the nearest ancestor with a
/// selected event. Unverified or absent pins fall to the static generic
/// view — never an older substituted revision beyond this rule.
async fn latest_selected_payload(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Option<KernelPackageAdoptedPayload> {
    sqlx::query_as::<_, (String,)>(
        "SELECT payload FROM main.content_events
          WHERE record_id = ? AND type = 'kernel.package_adopted.v1'
            AND json_extract(payload, '$.namespace') = ?
            AND json_extract(payload, '$.name') = ?
            AND json_extract(payload, '$.selected') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(scope_home)
    .bind(namespace)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    .unwrap_or(None)
    .and_then(|(text,)| serde_json::from_str(&text).ok())
}

async fn has_tombstone(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM main.content_events
          WHERE record_id = ? AND type = 'kernel.package_adopted.v1'
            AND json_extract(payload, '$.namespace') = ?
            AND json_extract(payload, '$.name') = ?
            AND json_extract(payload, '$.selected') IS NULL",
    )
    .bind(scope_home)
    .bind(namespace)
    .bind(name)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(0)
        > 0
}

async fn fallback_view_for(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> String {
    let mut scope = scope_home.to_string();
    let mut depth = 0usize;
    loop {
        // Depth cap mirrors the activation resolver: a poisoned parent
        // cycle (or absurd chain) answers generic instead of looping.
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return SURFACE_FALLBACK_VIEW.to_string();
        }
        if let Some(payload) = latest_selected_payload(conn, &scope, namespace, name).await {
            if let Some(pin) = payload.selected {
                if let Ok(Some(stored)) = crate::meta::package::read_package_in(
                    conn,
                    namespace,
                    name,
                    pin.version,
                    &pin.digest,
                )
                .await
                {
                    return stored
                        .manifest
                        .surface
                        .map(|surface| surface.fallback)
                        .unwrap_or_else(|| SURFACE_NONE_VIEW.to_string());
                }
            }
            return SURFACE_FALLBACK_VIEW.to_string();
        }
        if scope == scope_home {
            // Requested scope selected nothing: an explicit local
            // tombstone stops here instead of borrowing an ancestor name.
            if has_tombstone(conn, &scope, namespace, name).await {
                return SURFACE_FALLBACK_VIEW.to_string();
            }
        }
        let parent: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
                .bind(&scope)
                .fetch_optional(&mut *conn)
                .await
                .unwrap_or(None);
        match parent.flatten() {
            Some(parent) => scope = parent,
            None => return SURFACE_FALLBACK_VIEW.to_string(),
        }
    }
}

// The fixed host call keeps its explicit read and paging operands visible at
// this V2T boundary; changing the signature would only hide them in a wrapper.
#[allow(clippy::too_many_arguments)]
pub async fn surface_read_as(
    db: &Db,
    viewer_principal_id: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
    read_token: &str,
    family: &str,
    kind: &str,
    field_equals: &[(&str, serde_json::Value)],
    linked_to: Option<(&str, &str, &str)>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<SurfaceReadOutcome> {
    let mut conn = db.write_pool().acquire().await?;
    // Scope visibility first: no package metadata (not even a named
    // fallback) crosses a scope the viewer cannot View. A missing scope
    // answers the generic fallback, never an error.
    let scope_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(scope_home)
            .fetch_one(&mut *conn)
            .await?;
    let scope_visible = scope_exists
        && kernel_effective_capability_on(&mut conn, viewer_principal_id, scope_home)
            .await?
            .allows(Capability::View);
    if !scope_visible {
        drop(conn);
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: SURFACE_FALLBACK_VIEW.to_string(),
        });
    }
    let active = require_package_active_in(&mut conn, scope_home, namespace, name).await;
    let (stored, manifest) = match active {
        Ok(ok) => ok,
        Err(_) => {
            let view = fallback_view_for(&mut conn, scope_home, namespace, name).await;
            drop(conn);
            return Ok(SurfaceReadOutcome::Fallback {
                fallback_view: view,
            });
        }
    };
    drop(conn);
    // Definitions-only packages carry no behaviour or surface: report that
    // cleanly instead of naming a fallback that does not exist.
    let (Some(behaviour), Some(surface)) = (&manifest.behaviour, &manifest.surface) else {
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: SURFACE_NONE_VIEW.to_string(),
        });
    };
    // Fixed-operation gate: only the supported token with an explicit
    // linked target executes. Any other token — even a declared one — or a
    // targetless call falls back rather than running a degraded query.
    if read_token != SURFACE_FIXED_READ || linked_to.is_none() {
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: surface.fallback.clone(),
        });
    }
    if !behaviour.reads.iter().any(|r| r == read_token)
        || !stored.acknowledged_reads.iter().any(|r| r == read_token)
    {
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: surface.fallback.clone(),
        });
    }
    // Family AND kind pinned to the single embedded definition revision:
    // manifests hold at most one revision per family, so the find is unique
    // and the package cannot read other revisions through a shared family.
    let pinned_entry = manifest
        .definitions
        .iter()
        .find(|e| e.family == family && e.declares_kind(kind));
    let Some(pinned_entry) = pinned_entry else {
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: surface.fallback.clone(),
        });
    };
    // Every query-leg error maps to the already-known manifest fallback:
    // the scan bound counts pre-authority candidates, so surfacing Err (or
    // distinct error kinds) would leak a threshold. The underlying scan
    // termination is unchanged.
    let page = match query_as_pinned(
        db,
        viewer_principal_id,
        family,
        kind,
        Some((pinned_entry.version, pinned_entry.digest.as_str())),
        field_equals,
        linked_to,
        limit,
        cursor,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => {
            return Ok(SurfaceReadOutcome::Fallback {
                fallback_view: surface.fallback.clone(),
            });
        }
    };
    // Recheck after the query's own transaction: a moved selection,
    // displaced pin, or revoked scope View discards the page. Revocation
    // answers the generic fallback (never package metadata or a receipt),
    // since the viewer may no longer learn either.
    let mut conn = db.write_pool().acquire().await?;
    let scope_visible = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)",
    )
    .bind(scope_home)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(false)
        && kernel_effective_capability_on(&mut conn, viewer_principal_id, scope_home)
            .await
            .map(|c| c.allows(Capability::View))
            .unwrap_or(false);
    if !scope_visible {
        drop(conn);
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: SURFACE_FALLBACK_VIEW.to_string(),
        });
    }
    let rechecked = require_package_active_in(&mut conn, scope_home, namespace, name).await;
    let served_content_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
            .fetch_one(&mut *conn)
            .await?;
    drop(conn);
    let (restored, _) = match rechecked {
        Ok(ok) => ok,
        Err(_) => {
            return Ok(SurfaceReadOutcome::Fallback {
                fallback_view: surface.fallback.clone(),
            });
        }
    };
    if restored.event_seq != stored.event_seq {
        return Ok(SurfaceReadOutcome::Fallback {
            fallback_view: surface.fallback.clone(),
        });
    }
    Ok(SurfaceReadOutcome::Hits {
        hits: page
            .hits
            .into_iter()
            .map(|h| SurfaceHit {
                id: h.id,
                fields: h.fields,
            })
            .collect(),
        cursor: page.cursor,
        receipt: SurfaceReadReceipt {
            scope_home: scope_home.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
            package_version: stored.selected.as_ref().map(|s| s.version).unwrap_or(0),
            package_digest: stored
                .selected
                .as_ref()
                .map(|s| s.digest.clone())
                .unwrap_or_default(),
            ack_event_seq: stored.event_seq,
            served_content_seq,
        },
    })
}

/// Render one adopted package surface as a host-owned declarative model
/// (slice 3 S4, V2T only): a single fixed bounded list layout, or a single
/// fixed fallback notice layout. The host calls the S3 read path unchanged
/// and maps its outcome; nothing per-package executes or branches.
///
/// On Hits the receipt pin and the live selection/ack seq are re-verified
/// before mapping, so a selection that moved mid-render still falls back.
/// The title and notice are the manifest's own `view`/`fallback` markers
/// from verified pinned bytes. Introspection rides only the active path.
// Mirrors surface_read_as's fixed operands so the host maps its outcome
// without introducing a second package-specific request contract.
#[allow(clippy::too_many_arguments)]
pub async fn render_package_surface_as(
    db: &Db,
    viewer_principal_id: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
    read_token: &str,
    family: &str,
    kind: &str,
    field_equals: &[(&str, serde_json::Value)],
    linked_to: Option<(&str, &str, &str)>,
    limit: usize,
    cursor: Option<&str>,
) -> Result<SurfaceViewModel> {
    match surface_read_as(
        db,
        viewer_principal_id,
        scope_home,
        namespace,
        name,
        read_token,
        family,
        kind,
        field_equals,
        linked_to,
        limit,
        cursor,
    )
    .await?
    {
        SurfaceReadOutcome::Fallback { fallback_view } => Ok(SurfaceViewModel::Notice {
            notice: fallback_view,
        }),
        SurfaceReadOutcome::Hits {
            hits,
            cursor,
            receipt,
        } => {
            // Post-read mapping rechecks, on one connection. Semantics,
            // reconciled with the S3 named fallback: a revoked scope maps
            // to the GENERIC notice (the viewer may no longer learn package
            // metadata or receipts), while moved selections, displaced
            // pins, and unverifiable installs map to the NAMED fallback —
            // the same name S3 would serve. Nothing maps to a detailed
            // error. The final gate is the full activation check, so a pin
            // displaced between the S3 read and this paint still refuses.
            let mut conn = db.write_pool().acquire().await?;
            let scope_visible = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)",
            )
            .bind(scope_home)
            .fetch_one(&mut *conn)
            .await
            .unwrap_or(false)
                && kernel_effective_capability_on(&mut conn, viewer_principal_id, scope_home)
                    .await
                    .map(|c| c.allows(Capability::View))
                    .unwrap_or(false);
            if !scope_visible {
                drop(conn);
                return Ok(SurfaceViewModel::Notice {
                    notice: SURFACE_FALLBACK_VIEW.into(),
                });
            }
            let active = require_package_active_in(&mut conn, scope_home, namespace, name).await;
            let Ok((live, manifest)) = active else {
                let view = fallback_view_for(&mut conn, scope_home, namespace, name).await;
                drop(conn);
                return Ok(SurfaceViewModel::Notice { notice: view });
            };
            let live_pin = live
                .selected
                .as_ref()
                .map(|s| (s.version, s.digest.clone()));
            if live_pin != Some((receipt.package_version, receipt.package_digest.clone()))
                || live.event_seq != receipt.ack_event_seq
            {
                let view = fallback_view_for(&mut conn, scope_home, namespace, name).await;
                drop(conn);
                return Ok(SurfaceViewModel::Notice { notice: view });
            }
            // A definitions-only package can never reach here (its S3 read
            // falls back), but the re-read manifest is authoritative: if the
            // surface vanished between the read and this paint, report the
            // named/generic fallback rather than dereferencing the absent
            // descriptor.
            let Some(surface) = &manifest.surface else {
                let view = fallback_view_for(&mut conn, scope_home, namespace, name).await;
                drop(conn);
                return Ok(SurfaceViewModel::Notice { notice: view });
            };
            let introspection = PackageIntrospection {
                namespace: namespace.to_string(),
                name: name.to_string(),
                version: receipt.package_version,
                digest: receipt.package_digest.clone(),
                definition_pins: manifest
                    .definitions
                    .iter()
                    .map(|e| crate::meta::definition_artifact::RevisionIdentity {
                        family: e.family.clone(),
                        version: e.version,
                        digest: e.digest.clone(),
                    })
                    .collect(),
                declared_reads: manifest.declared_reads.clone(),
                ack_event_seq: receipt.ack_event_seq,
            };
            Ok(SurfaceViewModel::List {
                title: surface.view.clone(),
                rows: hits
                    .into_iter()
                    .map(|h| SurfaceViewRow {
                        id: h.id,
                        fields: h.fields,
                    })
                    .collect(),
                cursor,
                receipt,
                introspection: Box::new(introspection),
            })
        }
    }
}

/// Adopt (or, with `selected=None`, disable) one definition family in a home
/// subtree as a principal. Root scope delegates to the workspace-wide
/// mechanism (slice 1's attributed meta event, unchanged); a home scope
/// appends an overriding kernel adoption event for that subtree. Requires
/// Manage on the scope home; refusal appends nothing and names nothing.
pub async fn adopt_definition_at(
    db: &Db,
    actor_principal_id: &str,
    family: &str,
    selected: Option<&RevisionIdentity>,
    scope_home: &str,
) -> Result<()> {
    if scope_home == KERNEL_ROOT_ID {
        return adopt_definition_as(db, actor_principal_id, family, selected).await;
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let scope_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(scope_home)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);
    if !scope_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut tx, actor_principal_id, scope_home, Capability::Manage).await?;
    if selected.is_some_and(|s| s.family != family) {
        return Err(Error::engine(
            "definition adoption selected family mismatch",
        ));
    }
    if let Some(pin) = selected {
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
        )
        .bind(&pin.family)
        .bind(pin.version as i64)
        .bind(&pin.digest)
        .fetch_optional(&mut *tx)
        .await?;
        if stored.is_none() {
            return Err(Error::engine(
                "adoption selects missing definition artifact",
            ));
        }
    }
    // Dependency-safety preflight (task e2bfaf5): the direct-definition seam
    // shares enforcement with package adoption so it cannot bypass it.
    {
        let change = crate::dependency::ProspectiveChange::ScopedFamily {
            scope_home: scope_home.to_string(),
            family: family.to_string(),
            pin: selected.cloned(),
        };
        let impact =
            crate::dependency::preflight(&mut tx, actor_principal_id, scope_home, &[change], None)
                .await?;
        if impact.refuses() {
            return Err(Error::engine(crate::dependency::DEPENDENCY_REFUSAL));
        }
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: scope_home.into(),
            event_type: KERNEL_DEFINITION_ADOPTED_EVENT.into(),
            payload: serde_json::to_value(KernelDefinitionAdoptedPayload {
                family: family.to_string(),
                selected: selected.cloned(),
                scope_home: scope_home.to_string(),
            })?,
            actor: Some(actor_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Adopt (or, with `selected=None`, disable) one definition family as a
/// principal. Unchanged slice-1 mechanism: the workspace-wide attributed
/// meta event. Requires Manage on the workspace root.
pub async fn adopt_definition_as(
    db: &Db,
    actor_principal_id: &str,
    family: &str,
    selected: Option<&RevisionIdentity>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(
        &mut tx,
        actor_principal_id,
        KERNEL_ROOT_ID,
        Capability::Manage,
    )
    .await?;
    // Dependency-safety preflight (task e2bfaf5) over the whole workspace:
    // the workspace-wide choice is the fallback for every home, so the
    // traversal domain is the root subtree. Same seam as the scoped API.
    {
        let change = crate::dependency::ProspectiveChange::GlobalFamily {
            family: family.to_string(),
            pin: selected.cloned(),
        };
        let impact = crate::dependency::preflight(
            &mut tx,
            actor_principal_id,
            KERNEL_ROOT_ID,
            &[change],
            None,
        )
        .await?;
        if impact.refuses() {
            return Err(Error::engine(crate::dependency::DEPENDENCY_REFUSAL));
        }
    }
    let mut acts = crate::act::ActAllocation::new();
    crate::meta::adoption::append_definition_adoption_keyed_in(
        &mut tx,
        family,
        selected,
        None,
        Some(actor_principal_id),
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Nearest scoped adoption for a family walking a home's ancestor chain to
/// the root. The nearest row wins: a pin means adopted, a NULL selection is
/// the disable tombstone, and no row on the path means absent.
pub(crate) enum ScopedAdoption {
    Adopted(RevisionIdentity),
    Disabled,
}

/// How a kind identifies its records. `/1` kinds declare no identity at all;
/// structured kinds name an identity field, and `/3` may instead declare
/// `{"mode": "record"}` (each record is its own identity, no uniqueness).
enum IdentityKind {
    Field(String),
    Record,
}

/// One validated field: name, closed type, required flag, and (for `choice`)
/// the inline allowed values. Install-time validation guarantees the shape.
struct FieldDescriptor {
    name: String,
    field_type: String,
    required: bool,
    values: Vec<String>,
}

/// One validated structured kind descriptor read back from installed bytes:
/// closed-type fields plus the identity rule. Install-time validation
/// guarantees the shape; read-side parsing stays loud on drift.
struct KindDescriptor {
    fields: Vec<FieldDescriptor>,
    identity: IdentityKind,
    /// `/3` rule: a required `text` value must be non-blank. `/2` keeps
    /// accepting a blank required string.
    non_blank_required_text: bool,
    structured_fields: Option<serde_json::Value>,
    /// The retained language marker, stamped on revise events, and its
    /// capabilities, which select the value rules (`/5` trim, `/6` W).
    interpreter: Option<String>,
    capabilities: crate::meta::definition_artifact::LanguageCapabilities,
    /// Declared outgoing links: (predicate, target primary_type, target
    /// kind, direction). Install-time validation guarantees the shape.
    links: Vec<(String, String, String, String)>,
}

/// The descriptor's immutable identity field, if it has one. Record-identity
/// kinds have no immutable field (the record id is the identity).
fn descriptor_identity_field(descriptor: Option<&KindDescriptor>) -> Option<&str> {
    match descriptor.map(|d| &d.identity) {
        Some(IdentityKind::Field(name)) => Some(name.as_str()),
        _ => None,
    }
}

/// Look up a kind's descriptor in retained artifact bytes. Returns `None`
/// for legacy (`/1`) envelopes — whose kinds declare no fields — and for
/// kinds the envelope does not declare (membership itself is checked
/// separately against the pin).
fn kind_descriptor(artifact_bytes: &str, kind: &str) -> Result<Option<KindDescriptor>> {
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)
        .map_err(|_| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    let marker = doc.get("interpreter").and_then(serde_json::Value::as_str);
    let capabilities = crate::meta::definition_artifact::language_capabilities(marker);
    let is_new = capabilities.supports_structured_values;
    let is_v3 = capabilities.supports_record_identity;
    let is_structured = capabilities.supports_fields;
    if !is_structured {
        return Ok(None);
    }
    let kinds = doc
        .get("kinds")
        .and_then(|k| k.as_array())
        .ok_or_else(|| Error::engine("defn/2 envelope must carry an array 'kinds'"))?;
    for entry in kinds {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("token").and_then(serde_json::Value::as_str) != Some(kind) {
            continue;
        }
        let mut fields = Vec::new();
        for field in obj
            .get("fields")
            .and_then(|f| f.as_array())
            .into_iter()
            .flatten()
        {
            let field = field.as_object().ok_or_else(|| {
                Error::engine(format!(
                    "defn/2 kind '{kind}' field entries must be objects"
                ))
            })?;
            let values = field
                .get("values")
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            fields.push(FieldDescriptor {
                name: field
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                field_type: field
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                required: field
                    .get("required")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                values,
            });
        }
        let identity = match obj.get("identity").and_then(|v| v.as_object()) {
            Some(identity_obj) if is_v3 && identity_obj.get("mode").is_some() => {
                let mode = identity_obj
                    .get("mode")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if mode == "record" {
                    IdentityKind::Record
                } else {
                    return Err(Error::engine(format!(
                        "defn/3 kind '{kind}' has unknown identity mode '{mode}'"
                    )));
                }
            }
            identity_obj => IdentityKind::Field(
                identity_obj
                    .and_then(|o| o.get("field"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ),
        };
        let mut links = Vec::new();
        for link in obj
            .get("links")
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
        {
            let link = link.as_object().ok_or_else(|| {
                Error::engine(format!(
                    "{} kind '{kind}' link entries must be objects",
                    if is_v3 { "defn/3" } else { "defn/2" }
                ))
            })?;
            let target = link.get("target").and_then(|t| t.as_object());
            links.push((
                link.get("predicate")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                target
                    .and_then(|t| t.get("primary_type"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                target
                    .and_then(|t| t.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                link.get("direction")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            ));
        }
        return Ok(Some(KindDescriptor {
            fields,
            identity,
            non_blank_required_text: is_v3,
            structured_fields: is_new.then(|| obj["fields"].clone()),
            interpreter: marker.map(str::to_string),
            capabilities,
            links,
        }));
    }
    Ok(None)
}

/// Closed field-type check. `time` is an RFC 3339 date-time; `date` (`/3`)
/// is a calendar date or an RFC 3339 date-time; `choice` (`/3`) is one of the
/// kind's inline values. Relationships are links, never fields, so no
/// reference type exists.
fn field_value_matches(value: &serde_json::Value, field: &FieldDescriptor) -> bool {
    match field.field_type.as_str() {
        "text" => value.is_string(),
        "integer" => integer_spelling_matches(value),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "time" => value
            .as_str()
            .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        "date" => value.as_str().is_some_and(is_calendar_date_or_rfc3339),
        "choice" => value
            .as_str()
            .is_some_and(|s| field.values.iter().any(|allowed| allowed == s)),
        _ => false,
    }
}

/// Integer writes accept only integer JSON representations, never decimal or
/// exponent spellings such as `1.0` or `1e0`. `-0` parses as floating
/// negative zero and is refused too (pre-existing serde_json behaviour). Keep this shared by admission
/// and projection so equality cannot disagree with a coerced integer write.
pub(crate) fn integer_spelling_matches(value: &serde_json::Value) -> bool {
    value.is_i64() || value.is_u64()
}

/// `YYYY-MM-DD` (strictly zero-padded, so parsing round-trips) or an RFC 3339
/// date-time, matching v1's "date or date-time".
pub(crate) fn is_calendar_date_or_rfc3339(s: &str) -> bool {
    let calendar_date = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map(|date| date.format("%Y-%m-%d").to_string() == s)
        .unwrap_or(false);
    calendar_date || chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

/// What a validated field payload says about identity. `Field` is the `/1`
/// no-op and the `/2`/`/3` named-identity case; `Record` is `/3` per-record
/// identity, which carries no uniqueness rule.
#[derive(Debug, Clone, PartialEq)]
enum IdentityOutcome {
    /// Legacy (`/1`) kinds accept no fields and have no identity rule.
    Legacy,
    /// `/3` `{"mode": "record"}`: each record is its own identity.
    Record,
    /// Named identity field plus its canonical JSON for the uniqueness check.
    Field(String, String),
}

/// Validate a field payload against a kind: unknown names, mistyped values,
/// and missing required fields refuse, naming the offending field (the
/// caller's own payload, so no oracle). Explicit nulls count as absent.
/// Record-identity kinds still validate their fields but run no uniqueness
/// check; legacy kinds accept no fields at all.
fn validate_record_fields(
    descriptor: Option<&KindDescriptor>,
    kind: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<IdentityOutcome> {
    let Some(descriptor) = descriptor else {
        if let Some(name) = fields.keys().find(|v| !fields[*v].is_null()) {
            return Err(Error::engine(format!(
                "unknown field '{name}' for kind '{kind}'"
            )));
        }
        return Ok(IdentityOutcome::Legacy);
    };
    if let Some(shape) = &descriptor.structured_fields {
        crate::structured_values::validate_values(shape, fields, &descriptor.capabilities)?;
        return match &descriptor.identity {
            IdentityKind::Record => Ok(IdentityOutcome::Record),
            IdentityKind::Field(name) => Ok(IdentityOutcome::Field(
                name.clone(),
                serde_json::to_string(&fields[name])?,
            )),
        };
    }
    for (name, value) in fields {
        if value.is_null() {
            continue;
        }
        let Some(field) = descriptor.fields.iter().find(|f| &f.name == name) else {
            return Err(Error::engine(format!(
                "unknown field '{name}' for kind '{kind}'"
            )));
        };
        if field.field_type == "choice" {
            let allowed = value
                .as_str()
                .is_some_and(|s| field.values.iter().any(|v| v == s));
            if !allowed {
                return Err(Error::engine(format!(
                    "field '{name}' value is not an allowed choice for kind '{kind}'"
                )));
            }
        } else if !field_value_matches(value, field) {
            return Err(Error::engine(format!(
                "field '{name}' has wrong type, expected {} for kind '{kind}'",
                field.field_type
            )));
        }
    }
    for field in &descriptor.fields {
        let present = fields.get(&field.name).filter(|v| !v.is_null());
        if field.required && present.is_none() {
            return Err(Error::engine(format!(
                "missing required field '{}' for kind '{kind}'",
                field.name
            )));
        }
        // `/3` review amendment: a required `text` must be non-blank.
        if descriptor.non_blank_required_text
            && field.required
            && field.field_type == "text"
            && present
                .and_then(serde_json::Value::as_str)
                .is_some_and(|s| s.trim().is_empty())
        {
            return Err(Error::engine(format!(
                "required field '{}' must not be blank for kind '{kind}'",
                field.name
            )));
        }
    }
    let IdentityKind::Field(identity_field) = &descriptor.identity else {
        return Ok(IdentityOutcome::Record);
    };
    let identity_value = fields
        .get(identity_field)
        .filter(|v| !v.is_null())
        .ok_or_else(|| {
            Error::engine(format!(
                "missing identity field '{identity_field}' for kind '{kind}'"
            ))
        })?;
    let canonical = serde_json::to_string(identity_value)?;
    Ok(IdentityOutcome::Field(identity_field.clone(), canonical))
}

/// Uniform identity refusal: workspace-wide per family+kind, never naming
/// where, what, or whose value collides. Accepted residual oracle (same
/// class as a unique constraint); see the design note's remaining gates.
pub const IDENTITY_UNAVAILABLE: &str = "identity value unavailable";

// Called under the same serialized write transaction as creation. Keep the
// SQL UNIQUE constraint as a backstop without exposing its raw SQL error or
// the identity/placement of the conflicting record to ordinary callers.
async fn require_available_accession(conn: &mut SqliteConnection, accession: &str) -> Result<()> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE accession=?)")
            .bind(accession)
            .fetch_one(conn)
            .await?;
    if exists {
        return Err(Error::engine(IDENTITY_UNAVAILABLE));
    }
    Ok(())
}

/// Validate a field payload and build its projection rows, enforcing
/// workspace-wide identity uniqueness per family+kind. Shared by the write
/// path (event-free refusal) and the fold (loud replay), so both agree.
/// Record-identity and legacy kinds run no uniqueness check.
async fn validated_field_rows(
    conn: &mut SqliteConnection,
    artifact_bytes: &str,
    pin_family: &str,
    kind: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(Vec<(String, String)>, IdentityOutcome)> {
    let descriptor = kind_descriptor(artifact_bytes, kind)?;
    let identity = validate_record_fields(descriptor.as_ref(), kind, fields)?;
    let mut rows = Vec::with_capacity(fields.len());
    for (name, value) in fields {
        if value.is_null() {
            continue;
        }
        let value = if descriptor
            .as_ref()
            .is_some_and(|d| d.structured_fields.is_some())
        {
            crate::structured_values::normalize(value)
        } else {
            value.clone()
        };
        rows.push((name.clone(), serde_json::to_string(&value)?));
    }
    if let IdentityOutcome::Field(identity_name, canonical) = &identity {
        let clash: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_record_fields f
              JOIN kernel_records r ON r.id = f.record_id
              WHERE r.pin_family = ? AND r.kind = ? AND f.name = ? AND f.value_json = ?)",
        )
        .bind(pin_family)
        .bind(kind)
        .bind(identity_name)
        .bind(canonical)
        .fetch_one(&mut *conn)
        .await?;
        if clash {
            return Err(Error::engine(IDENTITY_UNAVAILABLE));
        }
    }
    Ok((rows, identity))
}

pub(crate) async fn resolve_scoped_adoption(
    conn: &mut SqliteConnection,
    family: &str,
    home_id: &str,
) -> Result<Option<ScopedAdoption>> {
    let mut scope = home_id.to_string();
    let mut depth = 0usize;
    loop {
        let row: Option<(Option<i64>, Option<String>)> = sqlx::query_as(
            "SELECT selected_version, selected_digest FROM kernel_adoptions WHERE scope_home = ? AND family = ?",
        )
        .bind(&scope)
        .bind(family)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some((version, digest)) = row {
            match (version, digest) {
                (Some(version), Some(digest)) => {
                    return Ok(Some(ScopedAdoption::Adopted(RevisionIdentity {
                        family: family.to_string(),
                        version: u32::try_from(version)
                            .map_err(|_| Error::engine("invalid adoption projection version"))?,
                        digest,
                    })));
                }
                _ => return Ok(Some(ScopedAdoption::Disabled)),
            }
        }
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        let parent: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
                .bind(&scope)
                .fetch_optional(&mut *conn)
                .await?;
        match parent.flatten() {
            Some(parent) => scope = parent,
            None => return Ok(None),
        }
    }
}

/// The single effective-adoption function shared by create and describe:
/// walk the home's ancestor chain for the nearest scoped row, then fall back
/// to the workspace-wide choice. `Disabled` tombstones and absence are
/// distinct outcomes, never errors.
pub(crate) async fn resolve_effective_adoption(
    conn: &mut SqliteConnection,
    family: &str,
    home_id: &str,
) -> Result<Option<ScopedAdoption>> {
    match resolve_scoped_adoption(conn, family, home_id).await? {
        Some(outcome) => Ok(Some(outcome)),
        None => {
            // An existing workspace-wide row with no selection is a disable
            // tombstone (describe shows `disabled`); no row at all is
            // absence (describe omits the family).
            match crate::meta::adoption::read_definition_adoption_on(conn, family).await? {
                None => Ok(None),
                Some(choice) => Ok(Some(match choice.selected {
                    Some(pin) => ScopedAdoption::Adopted(pin),
                    None => ScopedAdoption::Disabled,
                })),
            }
        }
    }
}

/// Verified scoped adoption row (task e2bfaf5): the latest
/// `kernel.definition_adopted.v1` payload plus seq must agree with the
/// `kernel_adoptions` row — null-pair consistency on (version, digest), and
/// a selected pin must still be installed with exact bytes. A row without a
/// log event fails closed, and log events without a row fail closed; only
/// neither-row-nor-log reads as inheritance (absent).
pub(crate) async fn read_scoped_adoption_verified(
    conn: &mut SqliteConnection,
    scope_home: &str,
    family: &str,
) -> Result<Option<(Option<RevisionIdentity>, i64)>> {
    let row: Option<(Option<i64>, Option<String>, i64)> = sqlx::query_as(
        "SELECT selected_version, selected_digest, event_seq FROM kernel_adoptions
          WHERE scope_home = ? AND family = ?",
    )
    .bind(scope_home)
    .bind(family)
    .fetch_optional(&mut *conn)
    .await?;
    let event: Option<(String, i64)> = sqlx::query_as(
        "SELECT payload, seq FROM main.content_events
          WHERE record_id = ? AND type = ?
            AND json_extract(payload, '$.family') = ?
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(scope_home)
    .bind(KERNEL_DEFINITION_ADOPTED_EVENT)
    .bind(family)
    .fetch_optional(&mut *conn)
    .await?;
    match (row, event) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(Error::engine(
            "scoped adoption has log events but no projection row",
        )),
        (Some(_), None) => Err(Error::engine(
            "scoped adoption has a projection row but no authorizing event",
        )),
        (Some((version, digest, event_seq)), Some((payload_text, seq))) => {
            if seq != event_seq {
                return Err(Error::engine(
                    "scoped adoption projection disagrees with its authorizing log event",
                ));
            }
            let payload: KernelDefinitionAdoptedPayload = serde_json::from_str(&payload_text)?;
            if payload.family != family || payload.scope_home != scope_home {
                return Err(Error::engine(
                    "scoped adoption authorizing event names a different scope",
                ));
            }
            // Explicit null-pair shape BEFORE event comparison: the DDL
            // CHECK does not reliably prevent half-null rows in SQLite
            // (CHECK on NULL passes), and `Option::zip` would collapse a
            // mixed pair into `None` and bless it against a tombstone event.
            let row_pin: Option<(i64, String)> = match (version, digest) {
                (None, None) => None,
                (Some(v), Some(d)) => Some((v, d)),
                (Some(_), None) | (None, Some(_)) => {
                    return Err(Error::engine(
                        "scoped adoption projection has a half-null identity",
                    ));
                }
            };
            match (payload.selected, row_pin) {
                (None, None) => Ok(Some((None, seq))),
                (Some(sel), Some((rv, rd)))
                    if sel.version as i64 == rv && sel.digest == rd && sel.family == family =>
                {
                    Ok(Some((Some(sel), seq)))
                }
                _ => Err(Error::engine(
                    "scoped adoption projection disagrees with its authorizing log event",
                )),
            }
        }
    }
}

/// Verified workspace-wide adoption choice (task e2bfaf5): the underlying
/// read proves the row is at the latest family event, and this wrapper adds
/// the missing-row-with-prior-log detection it cannot see — a deleted
/// projection with surviving events refuses instead of reading as absence.
pub(crate) async fn read_global_adoption_verified(
    conn: &mut SqliteConnection,
    family: &str,
) -> Result<Option<crate::meta::adoption::AdoptionChoice>> {
    let choice = crate::meta::adoption::read_definition_adoption_on(conn, family).await?;
    if choice.is_none() {
        let logged: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM meta_events
              WHERE subject_id = ? AND type = 'definition_adoption.set.v1'",
        )
        .bind(format!("definition-adoption:{family}"))
        .fetch_one(&mut *conn)
        .await?;
        if logged != 0 {
            return Err(Error::engine(
                "global adoption has log events but no projection row",
            ));
        }
    }
    Ok(choice)
}

/// Effective adoption resolved entirely through verified reads: the scoped
/// walk uses [`read_scoped_adoption_verified`] (a dangling parent link fails
/// closed rather than terminating at a phantom root), then the verified
/// workspace-wide fallback. A selected pin must additionally be installed
/// with exact bytes — a pin whose artifact is gone fails closed here, not
/// as absence. Dependency-safety paths (actual, prospective, register,
/// disable) resolve through this, never the raw rows.
pub(crate) async fn resolve_effective_adoption_verified(
    conn: &mut SqliteConnection,
    family: &str,
    home_id: &str,
) -> Result<Option<ScopedAdoption>> {
    let mut scope = home_id.to_string();
    let mut depth = 0usize;
    loop {
        match read_scoped_adoption_verified(conn, &scope, family).await? {
            Some((Some(pin), _)) => {
                verify_installed_pin_for_dependency(conn, family, &pin).await?;
                return Ok(Some(ScopedAdoption::Adopted(pin)));
            }
            Some((None, _)) => return Ok(Some(ScopedAdoption::Disabled)),
            None => {}
        }
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        let parent: Option<Option<String>> =
            sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id = ?")
                .bind(&scope)
                .fetch_optional(&mut *conn)
                .await?;
        match parent {
            None => return Err(Error::engine(HIDDEN_OR_MISSING)),
            Some(None) => break,
            Some(Some(parent)) => scope = parent,
        }
    }
    match read_global_adoption_verified(conn, family).await? {
        None => Ok(None),
        Some(choice) => Ok(Some(match choice.selected {
            Some(pin) => {
                verify_installed_pin_for_dependency(conn, family, &pin).await?;
                ScopedAdoption::Adopted(pin)
            }
            None => ScopedAdoption::Disabled,
        })),
    }
}

/// A selected pin names retained bytes: prove them before trusting the pin.
/// Shared with the dependency-safety preflight, which validates every
/// changed family before applying an override — even with zero consumers.
pub(crate) async fn verify_installed_pin_for_dependency(
    conn: &mut SqliteConnection,
    family: &str,
    pin: &RevisionIdentity,
) -> Result<()> {
    if pin.family != family {
        return Err(Error::engine(
            "scoped adoption pin names a different family",
        ));
    }
    let installed = crate::definition_registry::read_definition_artifact_on(
        conn,
        &pin.family,
        pin.version,
        &pin.digest,
    )
    .await?;
    if installed.is_none() {
        return Err(Error::engine(
            "scoped adoption selects a definition revision that is not installed",
        ));
    }
    Ok(())
}

/// Resolve the in-scope adoption pin for a family at a home via the shared
/// effective-adoption function. Refuses when the family is not adopted
/// there, including after disable.
async fn resolve_adoption_pin_only(
    conn: &mut SqliteConnection,
    family: &str,
    home_id: &str,
) -> Result<RevisionIdentity> {
    match resolve_effective_adoption(conn, family, home_id).await? {
        Some(ScopedAdoption::Adopted(pin)) => Ok(pin),
        _ => Err(Error::engine("primary definition is not adopted")),
    }
}

async fn select_adoption_pin(
    conn: &mut SqliteConnection,
    family: &str,
    primary_type: &str,
    kind: &str,
    home_id: &str,
) -> Result<RevisionIdentity> {
    // Scoped rows override; the workspace-wide choice is the fallback, so
    // slice-1 root adoptions keep resolving unchanged.
    let selected = resolve_adoption_pin_only(conn, family, home_id).await?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        conn,
        family,
        selected.version,
        &selected.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
    let declared: serde_json::Value = serde_json::from_str(&artifact.bytes)?;
    if declared
        .get("primary_type")
        .and_then(serde_json::Value::as_str)
        != Some(primary_type)
    {
        return Err(Error::engine(
            "requested primary type disagrees with selected definition",
        ));
    }
    if !crate::definition_registry::artifact_contains_kind(&artifact.kinds, kind) {
        return Err(Error::engine("kind is absent from selected definition"));
    }
    Ok(selected)
}

/// Create one definition-pinned record as a principal. Requires Edit on the
/// home; refuses when the family is not adopted (including after disable).
/// The creator becomes the owner and the event carries the immutable pin.
pub async fn create_package_record_as(
    db: &Db,
    creator_principal_id: &str,
    home_id: &str,
    primary_type: &str,
    kind: &str,
    accession: &str,
    family: &str,
) -> Result<String> {
    let mut tx = begin_write(db.write_pool()).await?;
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(home_id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);
    if !home_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    kernel_require(&mut tx, creator_principal_id, home_id, Capability::Edit).await?;
    let pin = select_adoption_pin(&mut tx, family, primary_type, kind, home_id).await?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        &mut tx,
        family,
        pin.version,
        &pin.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
    let interpreter = interpreter_for_bytes(&artifact.bytes)?;
    if crate::meta::definition_artifact::language_capabilities(Some(interpreter))
        .supports_structured_values
    {
        validated_field_rows(
            &mut tx,
            &artifact.bytes,
            family,
            kind,
            &serde_json::Map::new(),
        )
        .await?;
    }
    require_available_accession(&mut tx, accession).await?;
    let id = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.record_created.v1".into(),
            payload: serde_json::to_value(KernelRecordPayload {
                home_id: home_id.to_string(),
                owner_id: Some(creator_principal_id.to_string()),
                primary_type: Some(primary_type.to_string()),
                kind: Some(kind.to_string()),
                accession: Some(accession.to_string()),
                pin: Some(pin),
                interpreter: Some(interpreter.into()),
                fields: None,
            })?,
            actor: Some(creator_principal_id.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub(crate) enum FieldInput<'a> {
    Parsed(&'a serde_json::Map<String, serde_json::Value>),
    Raw(&'a str),
}
impl<'a> FieldInput<'a> {
    fn parse(
        self,
        structured: bool,
    ) -> Result<std::borrow::Cow<'a, serde_json::Map<String, serde_json::Value>>> {
        match self {
            Self::Parsed(_) if structured => Err(Error::engine(
                "raw_json_required: use create_json_as or revise_json_as_expected for structured values",
            )),
            Self::Parsed(fields) => Ok(std::borrow::Cow::Borrowed(fields)),
            Self::Raw(raw) => {
                let value = if structured {
                    crate::structured_values::parse_json(raw)?
                } else {
                    serde_json::from_str(raw)?
                };
                match value {
                    serde_json::Value::Object(map) => Ok(std::borrow::Cow::Owned(map)),
                    _ => Err(Error::engine("fields must be a JSON object")),
                }
            }
        }
    }
}

/// Raw-field create ingress. The selected interpreter owns its parser:
/// structured requests are bounded and reject duplicate keys before Value.
pub async fn create_json_as(
    db: &Db,
    actor: &str,
    family: &str,
    kind: &str,
    raw: &str,
    home: &str,
) -> Result<String> {
    create_input_as(db, actor, family, kind, FieldInput::Raw(raw), home).await
}

/// Generic create (slice 2, increment 3a): validate a field payload against
/// the in-scope `/2` kind and store it. Resolves the adoption in scope for
/// the home (scoped, else root) and refuses when none; needs Edit on the
/// home. Field failures name the offending field; identity collisions use
/// the uniform message. All refusals are event-free (before append).
pub async fn create_as(
    db: &Db,
    creator_principal_id: &str,
    family: &str,
    kind: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
    home_id: &str,
) -> Result<String> {
    create_input_as(
        db,
        creator_principal_id,
        family,
        kind,
        FieldInput::Parsed(fields),
        home_id,
    )
    .await
}
/// `create_input_as` on a transaction the caller already holds: no begin or
/// commit of its own, so a host operation can create and register in one
/// transaction with one shared act allocation. The caller owns the
/// transaction and ends it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_input_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    creator_principal_id: &str,
    family: &str,
    kind: &str,
    input: FieldInput<'_>,
    home_id: &str,
) -> Result<String> {
    create_input_admitted_in(
        db,
        tx,
        acts,
        creator_principal_id,
        family,
        kind,
        input,
        home_id,
        None,
        true,
        None,
    )
    .await
}

/// Attachment creation has v1's bearer Edit admission, rather than home Edit.
/// This narrow route admits only the fixed compat attachment shape and the
/// bearer's canonical placement; it cannot create arbitrary records elsewhere.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn create_attachment_input_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    bearer: &str,
    input: FieldInput<'_>,
    home: &str,
) -> Result<String> {
    create_input_admitted_in(
        db,
        tx,
        acts,
        actor,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        input,
        home,
        Some(bearer),
        true,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_input_admitted_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    creator_principal_id: &str,
    family: &str,
    kind: &str,
    input: FieldInput<'_>,
    home_id: &str,
    attachment_bearer: Option<&str>,
    require_home_edit: bool,
    requested_id: Option<&str>,
) -> Result<String> {
    let home_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id = ?)")
            .bind(home_id)
            .fetch_optional(&mut **tx)
            .await?
            .unwrap_or(false);
    if !home_exists {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if let Some(bearer) = attachment_bearer {
        kernel_require(tx, creator_principal_id, bearer, Capability::Edit).await?;
        let parent = read_record_on(tx, creator_principal_id, bearer)
            .await?
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
        let folder = parent.family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY)
            && parent
                .fields
                .get("v1_type")
                .and_then(serde_json::Value::as_str)
                == Some("Collection")
            && parent
                .fields
                .get("v1_kind")
                .and_then(serde_json::Value::as_str)
                == Some("folder");
        let expected = if folder {
            if parent.archived {
                return Err(Error::engine("attachment folder is archived"));
            }
            crate::v1_import::derived(bearer)
        } else {
            parent.home_id
        };
        if home_id != expected {
            return Err(Error::engine(
                "attachment home differs from bearer placement",
            ));
        }
    } else if require_home_edit {
        kernel_require(&mut *tx, creator_principal_id, home_id, Capability::Edit).await?;
    }
    let pin = resolve_adoption_pin_only(tx, family, home_id).await?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        tx,
        family,
        pin.version,
        &pin.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
    let envelope: serde_json::Value = serde_json::from_str(&artifact.bytes)?;
    let primary_type = envelope
        .get("primary_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::engine("selected definition declares no primary type"))?;
    if !crate::definition_registry::artifact_contains_kind(&artifact.kinds, kind) {
        return Err(Error::engine("kind is absent from selected definition"));
    }
    let interpreter = interpreter_for_bytes(&artifact.bytes)?;
    let parsed = input.parse(
        crate::meta::definition_artifact::language_capabilities(Some(interpreter))
            .supports_structured_values,
    )?;
    let fields = parsed.as_ref();
    if attachment_bearer.is_some()
        && (fields.get("v1_type").and_then(serde_json::Value::as_str) != Some("Document")
            || fields.get("v1_kind").and_then(serde_json::Value::as_str) != Some("attachment"))
    {
        return Err(Error::engine(
            "attachment admission requires Document/attachment",
        ));
    }

    let id = if let Some(id) = requested_id {
        let parsed = Uuid::parse_str(id).map_err(|_| Error::engine("message id must be a UUID"))?;
        if parsed.to_string() != id {
            return Err(Error::engine("message id must be canonical"));
        }
        hq::refuse_message_collision(tx, id).await?;
        id.to_owned()
    } else {
        Uuid::new_v4().to_string()
    };
    let (_field_rows, identity) =
        validated_field_rows(tx, &artifact.bytes, family, kind, fields).await?;
    // Accession namespaces the identity per family+kind so the (global)
    // column constraint backstops exactly the specified rule. Record-identity
    // kinds have no identity value, so the record id supplies one and the
    // column stays unique without constraining the kind. Legacy (`/1`) kinds
    // keep the historical empty suffix. (Field rows project in the fold from
    // the event payload.)
    let accession = match &identity {
        IdentityOutcome::Field(_, canonical) => format!("{family}:{kind}:{canonical}"),
        IdentityOutcome::Record => format!("{family}:{kind}:{id}"),
        IdentityOutcome::Legacy => format!("{family}:{kind}:"),
    };
    require_available_accession(tx, &accession).await?;
    let event_fields = if crate::meta::definition_artifact::language_capabilities(Some(interpreter))
        .supports_structured_values
    {
        crate::structured_values::normalize(&serde_json::Value::Object(
            fields
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ))
        .as_object()
        .unwrap()
        .clone()
    } else {
        fields.clone()
    };
    append_in(
        db,
        &mut *tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "kernel.record_created.v1".into(),
            payload: serde_json::to_value(KernelRecordPayload {
                home_id: home_id.to_string(),
                owner_id: Some(creator_principal_id.to_string()),
                primary_type: Some(primary_type.to_string()),
                kind: Some(kind.to_string()),
                accession: Some(accession),
                pin: Some(pin),
                interpreter: Some(interpreter.into()),
                fields: Some(event_fields),
            })?,
            actor: Some(creator_principal_id.into()),
        },
        acts,
    )
    .await?;
    Ok(id)
}

async fn create_input_as(
    db: &Db,
    creator_principal_id: &str,
    family: &str,
    kind: &str,
    input: FieldInput<'_>,
    home_id: &str,
) -> Result<String> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let id = create_input_in(
        db,
        &mut tx,
        &mut acts,
        creator_principal_id,
        family,
        kind,
        input,
        home_id,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Content event type carrying a fields-only revision (slice 2, piece 4).
/// Admitted by the `#[cfg(test)]` intent/projector arms; production
/// `EVENT_TYPES` is untouched.
pub const KERNEL_REVISED_EVENT: &str = "kernel.record_revised.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelRevisePayload {
    fields: serde_json::Map<String, serde_json::Value>,
}

/// Guarded structured edit: retained pin plus base token and normalization.
pub const KERNEL_STRUCTURED_REVISED_EVENT: &str = "kernel.record_revised.v2";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredRevisePayload {
    fields: serde_json::Map<String, serde_json::Value>,
    base_revision: i64,
    pin: RevisionIdentity,
    interpreter: String,
    normalization: String,
}

fn validate_structured_patch(
    descriptor: Option<&KindDescriptor>,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    if let Some(shape) = descriptor.and_then(|d| d.structured_fields.as_ref()) {
        crate::structured_values::validate_value_budget(patch)?;
        let mut names: Vec<_> = patch.keys().collect();
        names.sort();
        for name in names {
            if !shape
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"].as_str() == Some(name))
            {
                return Err(Error::engine(format!(
                    "unknown_member at {}",
                    crate::structured_values::pointer("", name)
                )));
            }
        }
    }
    Ok(())
}

/// Merge a patch over stored fields: explicit nulls delete, other values
/// overwrite. The identity key may not appear in the patch at all — neither
/// changed nor cleared — because that makes a new bearer, not a revise.
fn apply_revise_patch(
    kind: &str,
    identity_field: Option<&str>,
    stored: &serde_json::Map<String, serde_json::Value>,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    if let Some(identity) = identity_field {
        if patch.contains_key(identity) {
            return Err(Error::engine(format!(
                "identity field '{identity}' is immutable for kind '{kind}'; create a new bearer"
            )));
        }
    }
    let mut merged = stored.clone();
    for (name, value) in patch {
        if value.is_null() {
            merged.remove(name);
        } else {
            merged.insert(name.clone(), value.clone());
        }
    }
    Ok(merged)
}

/// Fold one fields-only revision: re-validate the merged fields against the
/// pinned bytes (loud on tamper, live and replay alike) and upsert the field
/// rows. The `kernel_records` row — identity, pin, interpreter, home — is
/// never touched here.
pub(crate) async fn project_kernel_record_revised(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let guarded = if event.event_type == KERNEL_STRUCTURED_REVISED_EVENT {
        Some(event_payload::<StructuredRevisePayload>(event)?)
    } else {
        None
    };
    let p = if let Some(p) = &guarded {
        KernelRevisePayload {
            fields: p.fields.clone(),
        }
    } else {
        event_payload::<KernelRevisePayload>(event)?
    };
    let row: Option<RevisePinRow> =
        sqlx::query_as(
            "SELECT kind, pin_family, pin_version, pin_digest, interpreter FROM kernel_records WHERE id = ?",
        )
        .bind(&event.record_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some((kind, pin_family, pin_version, pin_digest, interpreter)) = row else {
        return Err(Error::engine(format!(
            "kernel revise targets no record {}",
            event.record_id
        )));
    };
    let (kind, pin_family, pin_version, pin_digest) =
        match (kind, pin_family, pin_version, pin_digest) {
            (Some(k), Some(f), Some(v), Some(d)) => (k, f, v, d),
            _ => {
                return Err(Error::engine(format!(
                    "kernel revise targets unpinned record {}",
                    event.record_id
                )))
            }
        };
    let stored_bytes: String = sqlx::query_scalar(
        "SELECT artifact_bytes FROM definition_artifacts WHERE family = ? AND version = ? AND digest = ?",
    )
    .bind(&pin_family)
    .bind(pin_version)
    .bind(&pin_digest)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "kernel revise {} pins a missing definition artifact",
            event.record_id
        ))
    })?;
    crate::meta::definition_artifact::validate_kernel_definition_bytes(&stored_bytes)?;
    let expected = interpreter_for_bytes(&stored_bytes)?;
    if interpreter.as_deref() != Some(expected) {
        return Err(Error::engine(format!(
            "kernel revise {} carries unexpected interpreter",
            event.record_id
        )));
    }
    if crate::meta::definition_artifact::language_capabilities(Some(expected))
        .supports_structured_values
    {
        let guard = guarded
            .as_ref()
            .ok_or_else(|| Error::engine("structured edits require guarded event"))?;
        let prior: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM main.content_events WHERE record_id = ? AND seq < ?",
        )
        .bind(&event.record_id)
        .bind(event.local_seq)
        .fetch_one(&mut *conn)
        .await?;
        if guard.base_revision != prior
            || guard.pin.family != pin_family
            || i64::from(guard.pin.version) != pin_version
            || guard.pin.digest != pin_digest
            || guard.interpreter != expected
            || guard.normalization != crate::structured_values::NORMALIZATION
        {
            return Err(Error::engine("guarded revision basis mismatch"));
        }
    } else if guarded.is_some() {
        return Err(Error::engine("guarded event requires structured language"));
    }
    let descriptor = kind_descriptor(&stored_bytes, &kind)?;
    validate_structured_patch(descriptor.as_ref(), &p.fields)?;
    let stored_rows: Vec<(String, String)> =
        sqlx::query_as("SELECT name, value_json FROM kernel_record_fields WHERE record_id = ?")
            .bind(&event.record_id)
            .fetch_all(&mut *conn)
            .await?;
    let mut stored = serde_json::Map::new();
    for (name, value_json) in stored_rows {
        stored.insert(name, serde_json::from_str(&value_json)?);
    }
    let merged = apply_revise_patch(
        &kind,
        descriptor_identity_field(descriptor.as_ref()),
        &stored,
        &p.fields,
    )?;
    // Same shared validator as create: names, types, required fields.
    validate_record_fields(descriptor.as_ref(), &kind, &merged)?;
    for (name, value) in &p.fields {
        if value.is_null() {
            sqlx::query("DELETE FROM kernel_record_fields WHERE record_id = ? AND name = ?")
                .bind(&event.record_id)
                .bind(name)
                .execute(&mut *conn)
                .await?;
        } else {
            sqlx::query(
                "INSERT INTO kernel_record_fields (record_id, name, value_json, created_seq) VALUES (?, ?, ?, ?)
                 ON CONFLICT (record_id, name) DO UPDATE SET value_json = excluded.value_json, created_seq = excluded.created_seq",
            )
            .bind(&event.record_id)
            .bind(name)
            .bind(serde_json::to_string(&if guarded.is_some() { crate::structured_values::normalize(value) } else { value.clone() })?)
            .bind(event.local_seq)
            .execute(&mut *conn)
            .await?;
        }
    }
    // S7a probe index follows the projection in the same transaction.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    search_v2::refresh_search_row(&mut *conn, &event.record_id).await?;
    Ok(())
}

/// Generic revise (slice 2, piece 4): patch a record's `/2` fields only.
/// Requires Edit on the record — missing or hidden records get the uniform
/// refusal — and the actor stamped on the event is the principal id.
/// Identity, kind, pin, interpreter and home can never change through this
/// path: the patch is a fields map, and naming the identity field is refused
/// outright (that makes a new bearer). All refusals are event-free.
pub async fn revise_as(
    db: &Db,
    actor_principal_id: &str,
    record_id: &str,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    revise_as_expected(db, actor_principal_id, record_id, patch, None).await
}

/// Generic revise with an optional compare-and-swap precondition.
///
/// The authority check runs first, then the latest-revision check, then the
/// append: a caller that supplies `expected_revision` (the `revision` from a
/// prior [`read_record_as`]) has its write refused with [`Error::Conflict`]
/// before any event is appended when another editor has moved the record on.
/// `revise_as` is the unconditional compatibility wrapper (`None`).
pub async fn revise_as_expected(
    db: &Db,
    actor_principal_id: &str,
    record_id: &str,
    patch: &serde_json::Map<String, serde_json::Value>,
    expected_revision: Option<i64>,
) -> Result<()> {
    revise_input_as(
        db,
        actor_principal_id,
        record_id,
        FieldInput::Parsed(patch),
        expected_revision,
    )
    .await
}
/// Raw-field guarded revise ingress, parsed under the record's retained pin.
pub async fn revise_json_as_expected(
    db: &Db,
    actor: &str,
    record_id: &str,
    raw: &str,
    expected_revision: Option<i64>,
) -> Result<()> {
    revise_input_as(
        db,
        actor,
        record_id,
        FieldInput::Raw(raw),
        expected_revision,
    )
    .await
}
/// `revise_input_as` on a transaction the caller already holds: no begin or
/// commit of its own, so a host operation can revise and register in one
/// transaction with one shared act allocation. The caller owns the
/// transaction and ends it.
pub(crate) async fn revise_input_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor_principal_id: &str,
    record_id: &str,
    input: FieldInput<'_>,
    expected_revision: Option<i64>,
) -> Result<()> {
    let row: Option<KindPinRow> = sqlx::query_as(
        "SELECT kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((kind, pin_family, pin_version, pin_digest)) = row else {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    };
    kernel_require(&mut *tx, actor_principal_id, record_id, Capability::Edit).await?;
    if let Some(expected) = expected_revision {
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq), 0) FROM main.content_events WHERE record_id = ?",
        )
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?;
        if current != expected {
            return Err(Error::conflict(format!(
                "record revision mismatch: expected {expected}, found {current}"
            )));
        }
    }
    let (kind, pin_family, pin_version, pin_digest) =
        match (kind, pin_family, pin_version, pin_digest) {
            (Some(k), Some(f), Some(v), Some(d)) => (k, f, v, d),
            _ => return Err(Error::engine("record carries no definition revision")),
        };
    let version_u32 =
        u32::try_from(pin_version).map_err(|_| Error::engine("invalid record pin version"))?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        tx,
        &pin_family,
        version_u32,
        &pin_digest,
    )
    .await?
    .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
    let descriptor = kind_descriptor(&artifact.bytes, &kind)?;
    let structured = descriptor
        .as_ref()
        .is_some_and(|d| d.structured_fields.is_some());
    let parsed = input.parse(structured)?;
    if structured && expected_revision.is_none() {
        return Err(Error::engine("expected_revision_required"));
    }
    let patch = parsed.as_ref();
    validate_structured_patch(descriptor.as_ref(), patch)?;

    let stored_rows: Vec<(String, String)> =
        sqlx::query_as("SELECT name, value_json FROM kernel_record_fields WHERE record_id = ?")
            .bind(record_id)
            .fetch_all(&mut **tx)
            .await?;
    let mut stored = serde_json::Map::new();
    for (name, value_json) in stored_rows {
        stored.insert(name, serde_json::from_str(&value_json)?);
    }
    let merged = apply_revise_patch(
        &kind,
        descriptor_identity_field(descriptor.as_ref()),
        &stored,
        patch,
    )?;
    validate_record_fields(descriptor.as_ref(), &kind, &merged)?;
    let payload = if structured {
        serde_json::to_value(StructuredRevisePayload {
            fields: crate::structured_values::normalize(&serde_json::Value::Object(patch.clone()))
                .as_object()
                .unwrap()
                .clone(),
            base_revision: expected_revision.unwrap(),
            pin: RevisionIdentity {
                family: pin_family,
                version: version_u32,
                digest: pin_digest,
            },
            interpreter: descriptor
                .as_ref()
                .and_then(|d| d.interpreter.clone())
                .ok_or_else(|| Error::engine("structured revise requires a retained language"))?,
            normalization: crate::structured_values::NORMALIZATION.to_string(),
        })?
    } else {
        serde_json::to_value(KernelRevisePayload {
            fields: patch.clone(),
        })?
    };
    append_in(
        db,
        &mut *tx,
        AppendSpec {
            record_id: record_id.into(),
            event_type: if structured {
                KERNEL_STRUCTURED_REVISED_EVENT
            } else {
                KERNEL_REVISED_EVENT
            }
            .into(),
            payload,
            actor: Some(actor_principal_id.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

async fn revise_input_as(
    db: &Db,
    actor_principal_id: &str,
    record_id: &str,
    input: FieldInput<'_>,
    expected_revision: Option<i64>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    revise_input_in(
        db,
        &mut tx,
        &mut acts,
        actor_principal_id,
        record_id,
        input,
        expected_revision,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Test-only observation of the existing validator, without writes or uniqueness checks.
#[cfg(test)]
pub(crate) fn definition_shape_accepts(
    bytes: &str,
    kind: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    let descriptor = kind_descriptor(bytes, kind).expect("validated definition fixture");
    validate_record_fields(descriptor.as_ref(), kind, fields).is_ok()
}
