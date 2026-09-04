//! Capability-scoped record-policy inspection and transactional mutation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{AllowEntry, Capability, PolicyMode, PolicySubject, MEMBERS_SUBJECT_ID};
use crate::db::Db;
use crate::error::{Error, Result};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    parse_args, previous_record_seq_in, require_nonblank_reason, require_record_in,
    REASON_DESCRIPTION,
};

const TOOL: &str = "manage_record_policy";
const MAX_SET_MANY_ITEMS: usize = 100;

#[path = "policy/transition.rs"]
mod transition;
use native_policy_kernel::PolicySnapshot;
use transition::{
    plan_policy_transition, validate_inheritance_restoration, PolicyMutation, PolicyTransition,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputCapability {
    View,
    Edit,
    Manage,
}

impl From<InputCapability> for Capability {
    fn from(value: InputCapability) -> Self {
        match value {
            InputCapability::View => Capability::View,
            InputCapability::Edit => Capability::Edit,
            InputCapability::Manage => Capability::Manage,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum SubjectInput {
    Members,
    Person {
        person_record_id: String,
        /// Executor-owned binding fence. Deliberately omitted from ToolSpec.
        if_account_id: Option<String>,
    },
    Account {
        account_id: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementEntryInput {
    subject: SubjectInput,
    capability: InputCapability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPolicyItemInput {
    record_id: String,
    subject: SubjectInput,
    capability: Option<InputCapability>,
    /// Executor-owned policy fence. Deliberately omitted from ToolSpec.
    if_policy_revision: Option<String>,
    /// Executor-owned content fence. Deliberately omitted from ToolSpec.
    if_content_seq: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageRecordPolicyArgs {
    Inspect {
        record_id: String,
    },
    List {
        record_id: String,
    },
    SetMany {
        items: Vec<SetPolicyItemInput>,
        reason: String,
    },
    Grant {
        record_id: String,
        subject: SubjectInput,
        capability: InputCapability,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    Revoke {
        record_id: String,
        subject: SubjectInput,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    SetMembersBaseline {
        record_id: String,
        capability: Option<InputCapability>,
        if_policy_revision: Option<String>,
        if_content_seq: Option<i64>,
        reason: String,
    },
    Replace {
        record_id: String,
        entries: Vec<ReplacementEntryInput>,
        if_policy_revision: String,
        if_content_seq: Option<i64>,
        reason: String,
    },
    RestoreInheritance {
        record_id: String,
        if_policy_revision: String,
        if_content_seq: Option<i64>,
        /// Executor-owned inherited-policy fence. Deliberately omitted from ToolSpec.
        if_inherited_policy_revision: Option<String>,
        reason: String,
    },
}

#[derive(Debug)]
struct PolicyAccess {
    authorization_target_id: String,
    caller_capability: Capability,
    policy_administration_authorized: bool,
}

/// Read-only result used by the production executor preparation seam.
///
/// Keeping this projection beside the production parser and policy checks is
/// deliberate: the prototype must not grow a second interpretation of the
/// consequential write it is evaluating.
#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct RecordPolicyPreparation {
    pub target_id: String,
    pub target_name: String,
    pub policy_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub canonical_source_arguments: Value,
}

#[cfg(feature = "mcp-executor-prototype")]
fn mutation_action(arguments: &ManageRecordPolicyArgs) -> Option<&'static str> {
    match arguments {
        ManageRecordPolicyArgs::SetMany { .. } => Some("set_many"),
        ManageRecordPolicyArgs::Grant { .. } => Some("grant"),
        ManageRecordPolicyArgs::Revoke { .. } => Some("revoke"),
        ManageRecordPolicyArgs::SetMembersBaseline { .. } => Some("set_members_baseline"),
        ManageRecordPolicyArgs::Replace { .. } => Some("replace"),
        ManageRecordPolicyArgs::RestoreInheritance { .. } => Some("restore_inheritance"),
        ManageRecordPolicyArgs::Inspect { .. } | ManageRecordPolicyArgs::List { .. } => None,
    }
}

/// Parse one exact production mutation variant without touching storage.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_record_policy_mutation(
    expected_action: &str,
    arguments: Value,
) -> Result<()> {
    let arguments: ManageRecordPolicyArgs = parse_args(TOOL, arguments)?;
    if mutation_action(&arguments) != Some(expected_action) {
        return Err(Error::engine(format!(
            "{TOOL}: executor preparation expected action {expected_action}"
        )));
    }
    if let ManageRecordPolicyArgs::SetMany { items, .. } = &arguments {
        validate_set_many_count(items)?;
    }
    let reason = match arguments {
        ManageRecordPolicyArgs::SetMany { reason, .. }
        | ManageRecordPolicyArgs::Grant { reason, .. }
        | ManageRecordPolicyArgs::Revoke { reason, .. }
        | ManageRecordPolicyArgs::SetMembersBaseline { reason, .. }
        | ManageRecordPolicyArgs::Replace { reason, .. }
        | ManageRecordPolicyArgs::RestoreInheritance { reason, .. } => reason,
        ManageRecordPolicyArgs::Inspect { .. } | ManageRecordPolicyArgs::List { .. } => {
            unreachable!("mutation action checked above")
        }
    };
    require_nonblank_reason(TOOL, &reason)
}

fn mode_name(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Inherit => "inherit",
        PolicyMode::Explicit => "explicit",
    }
}

fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::None => "none",
        Capability::View => "view",
        Capability::Edit => "edit",
        Capability::Manage => "manage",
    }
}

async fn policy_snapshot(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<PolicySnapshot> {
    let row = sqlx::query(
        "SELECT policy_anchor_id,
                EXISTS(SELECT 1 FROM record_policies p WHERE p.record_id=r.id) explicit
           FROM records r WHERE r.id=? AND r.deleted_at IS NULL",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    let anchor_id: Option<String> = row.try_get("policy_anchor_id")?;
    let anchor_id = anchor_id
        .ok_or_else(|| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    let mode = if row.try_get::<bool, _>("explicit")? {
        PolicyMode::Explicit
    } else {
        PolicyMode::Inherit
    };
    let rows = sqlx::query(
        "SELECT subject_kind,subject_id,capability
           FROM policy_entries WHERE policy_anchor_id=?
          ORDER BY subject_kind,subject_id,capability",
    )
    .bind(&anchor_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let subject_kind: String = row.try_get("subject_kind")?;
        let subject_id: String = row.try_get("subject_id")?;
        let capability = match row.try_get::<String, _>("capability")?.as_str() {
            "view" => Capability::View,
            "edit" => Capability::Edit,
            "manage" => Capability::Manage,
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: policy contains unsupported capability '{other}'"
                )))
            }
        };
        let subject = match subject_kind.as_str() {
            "members" if subject_id == MEMBERS_SUBJECT_ID => PolicySubject::Members,
            "account" => PolicySubject::Account(subject_id),
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: policy contains unsupported subject kind '{other}'"
                )))
            }
        };
        entries.push(AllowEntry {
            subject,
            capability,
        });
    }
    let latest_event: Option<i64> =
        sqlx::query_scalar("SELECT MAX(seq) FROM policy_events WHERE record_id=? OR record_id=?")
            .bind(record_id)
            .bind(&anchor_id)
            .fetch_one(&mut **tx)
            .await?;
    let mut digest = Sha256::new();
    digest.update(b"native.policy-revision.v1\0");
    digest.update(record_id.as_bytes());
    digest.update([0]);
    digest.update(mode_name(mode).as_bytes());
    digest.update([0]);
    digest.update(anchor_id.as_bytes());
    digest.update([0]);
    digest.update(latest_event.unwrap_or_default().to_be_bytes());
    let revision = format!("prv1:{}", hex::encode(digest.finalize()));
    Ok(PolicySnapshot {
        mode,
        anchor_id,
        entries,
        revision,
    })
}

async fn inherited_policy_snapshot(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<PolicySnapshot> {
    let home_id: Option<String> =
        sqlx::query_scalar("SELECT home_id FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let home_id = home_id.ok_or_else(|| {
        Error::engine(format!(
            "policy inheritance from '{record_id}' does not terminate at an explicit boundary"
        ))
    })?;
    policy_snapshot(tx, &home_id).await
}

async fn resolve_subject(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    subject: SubjectInput,
) -> Result<PolicySubject> {
    match subject {
        SubjectInput::Members => Ok(PolicySubject::Members),
        SubjectInput::Account { account_id } => {
            if account_id.trim().is_empty() {
                return Err(Error::engine(format!(
                    "{TOOL}: raw account_id must contain non-whitespace text"
                )));
            }
            Ok(PolicySubject::Account(account_id))
        }
        SubjectInput::Person {
            person_record_id,
            if_account_id,
        } => {
            require_record_in(tx, caller, TOOL, &person_record_id, Capability::View).await?;
            let row = sqlx::query(
                "SELECT r.type,r.kind,
                        (SELECT identifier FROM bindings
                          WHERE record_id=r.id AND system='account' AND is_canonical=1) account_id
                   FROM records r WHERE r.id=? AND r.deleted_at IS NULL",
            )
            .bind(&person_record_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| {
                Error::engine(format!("{TOOL}: record {person_record_id} does not exist"))
            })?;
            if row.try_get::<String, _>("type")? != "Entity"
                || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("person")
            {
                return Err(Error::engine(format!(
                    "{TOOL}: subject record {person_record_id} is not an Entity:person"
                )));
            }
            let account_id: Option<String> = row.try_get("account_id")?;
            let account_id = account_id.ok_or_else(|| {
                Error::engine(format!(
                    "{TOOL}: person {person_record_id} has no canonical local account binding"
                ))
            })?;
            if if_account_id
                .as_deref()
                .is_some_and(|expected| expected != account_id)
            {
                return Err(Error::engine(format!(
                    "{TOOL}: person {person_record_id} account binding changed since preparation"
                )));
            }
            Ok(PolicySubject::Account(account_id))
        }
    }
}

fn assert_content_seq(record_id: &str, actual: Option<i64>, expected: Option<i64>) -> Result<()> {
    if expected.is_some() && expected != actual {
        return Err(Error::engine(format!(
            "{TOOL}: record {record_id} content changed since preparation"
        )));
    }
    Ok(())
}

fn bind_resolved_subject(
    canonical_subject: &mut Value,
    input: &SubjectInput,
    resolved: &PolicySubject,
) {
    if matches!(input, SubjectInput::Person { .. }) {
        let PolicySubject::Account(account_id) = resolved else {
            unreachable!("a person subject resolves to an account")
        };
        canonical_subject
            .as_object_mut()
            .expect("production person subject parsed as an object")
            .insert("if_account_id".into(), json!(account_id));
    }
}

fn validate_set_many_count(items: &[SetPolicyItemInput]) -> Result<()> {
    if items.is_empty() || items.len() > MAX_SET_MANY_ITEMS {
        return Err(Error::engine(format!(
            "{TOOL}: set_many items must contain between 1 and {MAX_SET_MANY_ITEMS} entries"
        )));
    }
    Ok(())
}

async fn reject_set_many_target_ancestry(
    tx: &mut Transaction<'static, Sqlite>,
    targets: &[(usize, String)],
) -> Result<()> {
    let first_indexes = targets.iter().fold(
        BTreeMap::<String, usize>::new(),
        |mut indexes, (index, id)| {
            indexes.entry(id.clone()).or_insert(*index);
            indexes
        },
    );
    if first_indexes.len() < 2 {
        return Ok(());
    }
    let target_ids = first_indexes.keys().cloned().collect::<Vec<_>>();
    let row = sqlx::query(
        "WITH RECURSIVE
           targets(id) AS (SELECT value FROM json_each(?)),
           ancestry(descendant_id,ancestor_id) AS (
             SELECT t.id,r.home_id FROM targets t JOIN records r ON r.id=t.id
             UNION ALL
             SELECT a.descendant_id,r.home_id
               FROM ancestry a JOIN records r ON r.id=a.ancestor_id
              WHERE a.ancestor_id IS NOT NULL
           )
         SELECT a.descendant_id,a.ancestor_id
           FROM ancestry a JOIN targets t ON t.id=a.ancestor_id
          WHERE a.ancestor_id IS NOT NULL
          ORDER BY a.descendant_id,a.ancestor_id
          LIMIT 1",
    )
    .bind(serde_json::to_string(&target_ids)?)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let descendant_id: String = row.try_get("descendant_id")?;
    let ancestor_id: String = row.try_get("ancestor_id")?;
    let descendant_index = first_indexes[&descendant_id];
    let ancestor_index = first_indexes[&ancestor_id];
    Err(Error::engine(format!(
        "{TOOL}: set_many items {ancestor_index} and {descendant_index}: policy targets cannot have an ancestor/descendant containment relationship"
    )))
}

fn subject_key(subject: &PolicySubject) -> (&'static str, &str) {
    match subject {
        PolicySubject::Members => ("members", MEMBERS_SUBJECT_ID),
        PolicySubject::Account(account_id) => ("account", account_id),
    }
}

async fn resolve_set_many_item(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    index: usize,
    item: SetPolicyItemInput,
    canonical_item: Option<&mut Value>,
) -> Result<(
    String,
    Option<String>,
    Option<i64>,
    PolicySubject,
    Option<Capability>,
)> {
    let input_subject = item.subject.clone();
    let subject = resolve_subject(tx, caller, item.subject)
        .await
        .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
    if let Some(canonical_item) = canonical_item {
        bind_resolved_subject(
            canonical_item
                .get_mut("subject")
                .expect("set_many source item contains subject"),
            &input_subject,
            &subject,
        );
    }
    Ok((
        item.record_id,
        item.if_policy_revision,
        item.if_content_seq,
        subject,
        item.capability.map(Capability::from),
    ))
}

async fn resolve_policy_mutation(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
    arguments: ManageRecordPolicyArgs,
    mut canonical_source_arguments: Option<&mut Value>,
) -> Result<PolicyMutation> {
    match arguments {
        ManageRecordPolicyArgs::SetMany { .. } => {
            unreachable!("set_many is resolved by its batch preparation/execution path")
        }
        ManageRecordPolicyArgs::Grant {
            subject,
            capability,
            ..
        } => {
            let input_subject = subject.clone();
            let subject = resolve_subject(tx, caller, subject).await?;
            if let Some(canonical) = canonical_source_arguments.as_deref_mut() {
                bind_resolved_subject(
                    canonical
                        .get_mut("subject")
                        .expect("grant source arguments contain subject"),
                    &input_subject,
                    &subject,
                );
            }
            Ok(PolicyMutation::Grant {
                subject,
                capability: Capability::from(capability),
            })
        }
        ManageRecordPolicyArgs::Revoke { subject, .. } => {
            let input_subject = subject.clone();
            let subject = resolve_subject(tx, caller, subject).await?;
            if let Some(canonical) = canonical_source_arguments.as_deref_mut() {
                bind_resolved_subject(
                    canonical
                        .get_mut("subject")
                        .expect("revoke source arguments contain subject"),
                    &input_subject,
                    &subject,
                );
            }
            Ok(PolicyMutation::Revoke { subject })
        }
        ManageRecordPolicyArgs::SetMembersBaseline { capability, .. } => {
            Ok(PolicyMutation::SetMembersBaseline {
                capability: capability.map(Capability::from),
            })
        }
        ManageRecordPolicyArgs::Replace { entries, .. } => {
            let mut resolved = Vec::with_capacity(entries.len());
            for (index, entry) in entries.into_iter().enumerate() {
                let input_subject = entry.subject.clone();
                let subject = resolve_subject(tx, caller, entry.subject).await?;
                if let Some(canonical) = canonical_source_arguments.as_deref_mut() {
                    bind_resolved_subject(
                        canonical["entries"][index]
                            .get_mut("subject")
                            .expect("replacement entry contains subject"),
                        &input_subject,
                        &subject,
                    );
                }
                resolved.push(AllowEntry {
                    subject,
                    capability: Capability::from(entry.capability),
                });
            }
            Ok(PolicyMutation::Replace { entries: resolved })
        }
        ManageRecordPolicyArgs::RestoreInheritance { .. } => {
            let inherited = inherited_policy_snapshot(tx, record_id).await?;
            if let Some(canonical) = canonical_source_arguments {
                canonical
                    .as_object_mut()
                    .expect("production policy arguments parsed as an object")
                    .insert(
                        "if_inherited_policy_revision".into(),
                        Value::String(inherited.revision.clone()),
                    );
            }
            Ok(PolicyMutation::RestoreInheritance { inherited })
        }
        ManageRecordPolicyArgs::Inspect { .. } | ManageRecordPolicyArgs::List { .. } => {
            unreachable!("mutation action checked before resolving the mutation")
        }
    }
}

fn assert_revision(snapshot: &PolicySnapshot, expected: Option<&str>) -> Result<()> {
    if expected.is_some_and(|expected| expected != snapshot.revision) {
        return Err(Error::engine(format!(
            "{TOOL}: policy revision conflict; list the policy and retry"
        )));
    }
    Ok(())
}

async fn policy_access(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
    require_administration: bool,
) -> Result<PolicyAccess> {
    // The canonical root is the one policy boundary whose evaluator can be
    // empty while the host owner / standalone operator still needs to repair
    // it. Decide that external authority before any ordinary View gate. The
    // bypass is deliberately exact-id root only; descendants and derived
    // artifacts continue through the evaluator.
    let root_operator = record_id == crate::schema::ROOT_RECORD_ID && caller.is_host_owner();
    if !root_operator {
        require_record_in(tx, caller, TOOL, record_id, Capability::View).await?;
    }
    let authorization_target_id = crate::authorization::authorization_target_on(tx, record_id)
        .await
        .map_err(|_| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    let caller_capability =
        crate::authorization::effective_capability_on(tx, super::principal(caller), record_id)
            .await
            .map_err(|_| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    debug_assert!(!root_operator || authorization_target_id == crate::schema::ROOT_RECORD_ID);
    let legacy_local = caller.is_trusted_local() && caller.hosting_database().is_none();
    let policy_administration_authorized =
        caller_capability.allows(Capability::Manage) || root_operator || legacy_local;
    if require_administration && !policy_administration_authorized {
        return Err(Error::engine(format!(
            "{TOOL}: record {record_id} does not exist"
        )));
    }
    Ok(PolicyAccess {
        authorization_target_id,
        caller_capability,
        policy_administration_authorized,
    })
}

async fn mutation_policy_access(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<PolicyAccess> {
    let access = policy_access(tx, caller, record_id, true).await?;
    if access.authorization_target_id != record_id {
        return Err(Error::engine(format!(
            "{TOOL}: derived records cannot be policy mutation targets; target the authorization bearer explicitly"
        )));
    }
    Ok(access)
}

async fn listed_entries(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    entries: &[AllowEntry],
) -> Result<Vec<Value>> {
    let mut output = Vec::with_capacity(entries.len());
    for entry in entries {
        match &entry.subject {
            PolicySubject::Members => output.push(json!({
                "subject": {"kind":"members"},
                "capability": capability_name(entry.capability),
            })),
            PolicySubject::Account(account_id) => {
                let person = sqlx::query(
                    "SELECT r.id,r.name FROM bindings b JOIN records r ON r.id=b.record_id
                      WHERE b.system='account' AND b.identifier=? AND b.is_canonical=1
                        AND r.type='Entity' AND r.kind='person' AND r.deleted_at IS NULL
                      ORDER BY r.id LIMIT 1",
                )
                .bind(account_id)
                .fetch_optional(&mut **tx)
                .await?;
                let person = if let Some(row) = person {
                    let person_id = row.get::<String, _>("id");
                    let visible = crate::authorization::effective_capability_on(
                        tx,
                        super::principal(caller),
                        &person_id,
                    )
                    .await
                    .is_ok_and(|capability| capability.allows(Capability::View));
                    visible.then(|| {
                        json!({
                            "record_id":person_id,
                            "name":row.get::<String, _>("name"),
                        })
                    })
                } else {
                    None
                };
                output.push(json!({
                    "subject": {"kind":"account", "account_id":account_id, "person":person},
                    "capability": capability_name(entry.capability),
                }));
            }
        }
    }
    Ok(output)
}

fn state_json(snapshot: &PolicySnapshot) -> Value {
    json!({"mode":mode_name(snapshot.mode),"anchor_id":snapshot.anchor_id})
}

fn virtual_snapshot_after(
    before: &PolicySnapshot,
    transition: &PolicyTransition,
) -> PolicySnapshot {
    let entries = transition
        .after_normalized()
        .iter()
        .map(|entry| {
            let subject = match entry.subject_kind.as_str() {
                "members" => PolicySubject::Members,
                "account" => PolicySubject::Account(entry.subject_id.clone()),
                other => unreachable!("normalized policy subject kind {other}"),
            };
            let capability = match entry.capability.as_str() {
                "view" => Capability::View,
                "edit" => Capability::Edit,
                "manage" => Capability::Manage,
                other => unreachable!("normalized policy capability {other}"),
            };
            AllowEntry {
                subject,
                capability,
            }
        })
        .collect();
    PolicySnapshot {
        mode: transition.after_mode(),
        anchor_id: transition.after_anchor_id().to_owned(),
        entries,
        revision: before.revision.clone(),
    }
}

#[cfg(feature = "mcp-executor-prototype")]
fn entries_json(entries: &[crate::policy::NormalizedPolicyEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                let subject = match entry.subject_kind.as_str() {
                    "members" => json!({"kind":"members"}),
                    "account" => json!({"kind":"account","account_id":entry.subject_id}),
                    other => json!({"kind":other,"subject_id":entry.subject_id}),
                };
                json!({
                    "subject": subject,
                    "capability": entry.capability,
                })
            })
            .collect(),
    )
}

#[cfg(feature = "mcp-executor-prototype")]
async fn prepare_set_many(
    db: &Db,
    caller: &Caller,
    items: Vec<SetPolicyItemInput>,
    reason: String,
    mut canonical_source_arguments: Value,
) -> Result<RecordPolicyPreparation> {
    validate_set_many_count(&items)?;
    require_nonblank_reason(TOOL, &reason)?;
    let mut tx = db.write_pool().begin().await?;
    let mut seen = BTreeSet::new();
    let mut effects = Vec::with_capacity(items.len());
    let mut target_states = Vec::with_capacity(items.len());
    let mut target_keys = Vec::with_capacity(items.len());
    let mut virtual_snapshots = BTreeMap::<String, PolicySnapshot>::new();
    let mut indexed_targets = Vec::with_capacity(items.len());
    let mut changed_count = 0usize;

    for (index, item) in items.into_iter().enumerate() {
        let record_id = item.record_id.clone();
        indexed_targets.push((index, record_id.clone()));
        mutation_policy_access(&mut tx, caller, &record_id)
            .await
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        let content_seq = previous_record_seq_in(&mut tx, &record_id)
            .await?
            .ok_or_else(|| {
                Error::engine(format!(
                    "{TOOL}: set_many item {index}: record {record_id} has no content revision"
                ))
            })?;
        assert_content_seq(&record_id, Some(content_seq), item.if_content_seq)
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        let before = policy_snapshot(&mut tx, &record_id).await?;
        assert_revision(&before, item.if_policy_revision.as_deref())
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;

        let canonical_item = canonical_source_arguments["items"]
            .get_mut(index)
            .expect("set_many source arguments retain input positions");
        let (_, _, _, subject, capability) =
            resolve_set_many_item(&mut tx, caller, index, item, Some(canonical_item)).await?;
        let (subject_kind, subject_id) = subject_key(&subject);
        let subject_kind = subject_kind.to_owned();
        let subject_id = subject_id.to_owned();
        if !seen.insert((record_id.clone(), subject_kind.clone(), subject_id.clone())) {
            return Err(Error::engine(format!(
                "{TOOL}: set_many item {index}: duplicate resolved record and subject"
            )));
        }
        canonical_item
            .as_object_mut()
            .expect("set_many source item parsed as an object")
            .insert(
                "if_policy_revision".into(),
                Value::String(before.revision.clone()),
            );
        canonical_item
            .as_object_mut()
            .expect("set_many source item parsed as an object")
            .insert("if_content_seq".into(), json!(content_seq));

        let planning_before = virtual_snapshots
            .get(&record_id)
            .cloned()
            .unwrap_or_else(|| before.clone());
        let before_normalized =
            crate::authorization::normalize_entries(planning_before.entries.clone())?;
        let transition = plan_policy_transition(
            &record_id,
            &planning_before,
            PolicyMutation::Set {
                subject,
                capability,
            },
        )
        .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        if transition.changed() {
            changed_count += 1;
        }
        virtual_snapshots.insert(
            record_id.clone(),
            virtual_snapshot_after(&planning_before, &transition),
        );
        let target = sqlx::query(
            "SELECT id,name,type,kind,home_id,policy_anchor_id
               FROM records WHERE id=? AND deleted_at IS NULL",
        )
        .bind(&record_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
        let target_name: String = target.try_get("name")?;
        target_states.push(json!({
            "index": index,
            "id": target.try_get::<String, _>("id")?,
            "name": target_name.clone(),
            "type": target.try_get::<String, _>("type")?,
            "kind": target.try_get::<Option<String>, _>("kind")?,
            "home_id": target.try_get::<Option<String>, _>("home_id")?,
            "policy_anchor_id": target.try_get::<Option<String>, _>("policy_anchor_id")?,
            "content_seq": content_seq,
            "policy_revision": before.revision.clone(),
        }));
        target_keys.push(json!({
            "index":index,
            "record_id":record_id.clone(),
            "subject_kind":subject_kind,
            "subject_id":subject_id,
        }));
        effects.push(json!({
            "index":index,
            "target":{"record_id":record_id,"name":target_name},
            "before":{
                "mode":mode_name(planning_before.mode),
                "anchor_id":planning_before.anchor_id,
                "entries":entries_json(&before_normalized),
            },
            "after":{
                "mode":mode_name(transition.after_mode()),
                "anchor_id":transition.after_anchor_id(),
                "entries":entries_json(transition.after_normalized()),
            },
            "changed":transition.changed(),
        }));
    }
    reject_set_many_target_ancestry(&mut tx, &indexed_targets).await?;

    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&target_states)?));
    let target_key_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&target_keys)?));
    let policy_revision = format!("prvb1:{target_state_digest}");
    let item_count = effects.len();
    let effect = json!({
        "action":"set_many",
        "items":effects,
        "item_count":item_count,
        "changed_count":changed_count,
        "changed":changed_count > 0,
        "reason":reason,
    });
    tx.rollback().await?;
    Ok(RecordPolicyPreparation {
        target_id: format!("policy-set:{target_key_digest}"),
        target_name: format!("{item_count} record policy targets"),
        policy_revision,
        target_state_digest,
        effect,
        canonical_source_arguments,
    })
}

/// Exercise the exact production parser, authorization boundary, subject
/// resolution, policy normalization and compare-and-set checks without
/// mutating. The returned before/after projection is derived beside the
/// production mutation implementation so executor approval never grows a
/// second policy interpretation.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_record_policy_mutation(
    db: &Db,
    caller: &Caller,
    expected_action: &str,
    arguments: Value,
) -> Result<RecordPolicyPreparation> {
    let mut canonical_source_arguments = arguments.clone();
    let arguments: ManageRecordPolicyArgs = parse_args(TOOL, arguments)?;
    if mutation_action(&arguments) != Some(expected_action) {
        return Err(Error::engine(format!(
            "{TOOL}: executor preparation expected action {expected_action}"
        )));
    }
    if let ManageRecordPolicyArgs::SetMany { items, reason } = arguments {
        return prepare_set_many(db, caller, items, reason, canonical_source_arguments).await;
    }

    let mut tx = db.write_pool().begin().await?;
    let (record_id, reason, expected_revision, expected_content_seq) = match &arguments {
        ManageRecordPolicyArgs::SetMany { .. } => {
            unreachable!("set_many returned through its batch preparation path")
        }
        ManageRecordPolicyArgs::Grant {
            record_id,
            reason,
            if_policy_revision,
            if_content_seq,
            ..
        }
        | ManageRecordPolicyArgs::Revoke {
            record_id,
            reason,
            if_policy_revision,
            if_content_seq,
            ..
        }
        | ManageRecordPolicyArgs::SetMembersBaseline {
            record_id,
            reason,
            if_policy_revision,
            if_content_seq,
            ..
        } => (
            record_id.clone(),
            reason.clone(),
            if_policy_revision.clone(),
            *if_content_seq,
        ),
        ManageRecordPolicyArgs::Replace {
            record_id,
            reason,
            if_policy_revision,
            if_content_seq,
            ..
        }
        | ManageRecordPolicyArgs::RestoreInheritance {
            record_id,
            reason,
            if_policy_revision,
            if_content_seq,
            ..
        } => (
            record_id.clone(),
            reason.clone(),
            Some(if_policy_revision.clone()),
            *if_content_seq,
        ),
        ManageRecordPolicyArgs::Inspect { .. } | ManageRecordPolicyArgs::List { .. } => {
            unreachable!("mutation action checked above")
        }
    };
    require_nonblank_reason(TOOL, &reason)?;
    mutation_policy_access(&mut tx, caller, &record_id).await?;
    let content_seq = previous_record_seq_in(&mut tx, &record_id)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: record {record_id} has no content revision"
            ))
        })?;
    assert_content_seq(&record_id, Some(content_seq), expected_content_seq)?;
    let before = policy_snapshot(&mut tx, &record_id).await?;
    assert_revision(&before, expected_revision.as_deref())?;
    if matches!(
        &arguments,
        ManageRecordPolicyArgs::RestoreInheritance { .. }
    ) {
        // Keep semantic rejection ahead of inherited-state reads, matching
        // the authoring API's established error precedence.
        validate_inheritance_restoration(&record_id, &before)?;
    }
    canonical_source_arguments
        .as_object_mut()
        .expect("production policy arguments parsed as an object")
        .insert(
            "if_policy_revision".into(),
            Value::String(before.revision.clone()),
        );
    canonical_source_arguments
        .as_object_mut()
        .expect("production policy arguments parsed as an object")
        .insert("if_content_seq".into(), json!(content_seq));
    let before_normalized = crate::authorization::normalize_entries(before.entries.clone())?;
    let mutation = resolve_policy_mutation(
        &mut tx,
        caller,
        &record_id,
        arguments,
        Some(&mut canonical_source_arguments),
    )
    .await?;
    let transition = plan_policy_transition(&record_id, &before, mutation)?;

    let target = sqlx::query(
        "SELECT id,name,type,kind,home_id,policy_anchor_id
           FROM records WHERE id=? AND deleted_at IS NULL",
    )
    .bind(&record_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    let target_name: String = target.try_get("name")?;
    let target_state = json!({
        "id": target.try_get::<String, _>("id")?,
        "name": target_name,
        "type": target.try_get::<String, _>("type")?,
        "kind": target.try_get::<Option<String>, _>("kind")?,
        "home_id": target.try_get::<Option<String>, _>("home_id")?,
        "policy_anchor_id": target.try_get::<Option<String>, _>("policy_anchor_id")?,
        "content_seq": content_seq,
        "policy_revision": before.revision,
    });
    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&target_state)?));
    let effect = json!({
        "action": expected_action,
        "target": {"record_id":record_id,"name":target_name},
        "before": {
            "mode": mode_name(before.mode),
            "anchor_id": before.anchor_id,
            "entries": entries_json(&before_normalized),
        },
        "after": {
            "mode":mode_name(transition.after_mode()),
            "anchor_id":transition.after_anchor_id(),
            "entries": entries_json(transition.after_normalized()),
        },
        "changed": transition.changed(),
        "reason": reason,
    });
    tx.rollback().await?;
    Ok(RecordPolicyPreparation {
        target_id: record_id,
        target_name,
        policy_revision: before.revision,
        target_state_digest,
        effect,
        canonical_source_arguments,
    })
}

async fn mutation_result(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    before: PolicySnapshot,
    boundary_created: bool,
    event: crate::policy::PolicyEventRow,
) -> Result<Value> {
    let after = policy_snapshot(tx, record_id).await?;
    Ok(json!({
        "record_id":record_id,
        "changed":true,
        "event":{"id":event.id,"seq":event.seq},
        "before":state_json(&before),
        "after":state_json(&after),
        "boundary_created":boundary_created,
        "policy_revision":after.revision,
    }))
}

struct PlannedSetManyItem {
    index: usize,
    record_id: String,
    before: PolicySnapshot,
    transition: PolicyTransition,
}

async fn execute_set_many(
    db: Db,
    caller: &Caller,
    items: Vec<SetPolicyItemInput>,
    reason: String,
) -> Result<Value> {
    validate_set_many_count(&items)?;
    require_nonblank_reason(TOOL, &reason)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut seen = BTreeSet::new();
    let mut planned = Vec::with_capacity(items.len());
    let mut virtual_snapshots = BTreeMap::<String, PolicySnapshot>::new();
    let mut indexed_targets = Vec::with_capacity(items.len());

    // Finish authorization, resolution, duplicate detection, compare-and-set
    // checks and transition planning for every item before the first event is
    // appended. One invalid item therefore leaves the entire requested set
    // unchanged.
    for (index, item) in items.into_iter().enumerate() {
        let record_id = item.record_id.clone();
        indexed_targets.push((index, record_id.clone()));
        mutation_policy_access(&mut tx, caller, &record_id)
            .await
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        let content_seq = previous_record_seq_in(&mut tx, &record_id).await?;
        assert_content_seq(&record_id, content_seq, item.if_content_seq)
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        let before = policy_snapshot(&mut tx, &record_id).await?;
        assert_revision(&before, item.if_policy_revision.as_deref())
            .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        let (_, _, _, subject, capability) =
            resolve_set_many_item(&mut tx, caller, index, item, None).await?;
        let (subject_kind, subject_id) = subject_key(&subject);
        if !seen.insert((
            record_id.clone(),
            subject_kind.to_owned(),
            subject_id.to_owned(),
        )) {
            return Err(Error::engine(format!(
                "{TOOL}: set_many item {index}: duplicate resolved record and subject"
            )));
        }
        let planning_before = virtual_snapshots.get(&record_id).cloned().unwrap_or(before);
        let transition = plan_policy_transition(
            &record_id,
            &planning_before,
            PolicyMutation::Set {
                subject,
                capability,
            },
        )
        .map_err(|error| Error::engine(format!("{TOOL}: set_many item {index}: {error}")))?;
        virtual_snapshots.insert(
            record_id.clone(),
            virtual_snapshot_after(&planning_before, &transition),
        );
        planned.push(PlannedSetManyItem {
            index,
            record_id,
            before: planning_before,
            transition,
        });
    }
    reject_set_many_target_ancestry(&mut tx, &indexed_targets).await?;

    let mut outcomes = Vec::with_capacity(planned.len());
    let mut changed_count = 0usize;
    for item in planned {
        let mut outcome = match item.transition {
            PolicyTransition::NoChange { .. } => {
                let current = policy_snapshot(&mut tx, &item.record_id).await?;
                json!({
                    "record_id":item.record_id,
                    "changed":false,
                    "policy_revision":current.revision,
                })
            }
            PolicyTransition::ReplaceExplicit {
                entries,
                boundary_created,
                ..
            } => {
                let event = crate::authorization::replace_explicit_policy_on_with_reason(
                    &mut tx,
                    caller.actor(),
                    &item.record_id,
                    entries,
                    &reason,
                )
                .await?;
                changed_count += 1;
                mutation_result(
                    &mut tx,
                    &item.record_id,
                    item.before,
                    boundary_created,
                    event,
                )
                .await?
            }
            PolicyTransition::RestoreInheritance { .. } => {
                unreachable!("set_many only plans exact per-subject explicit policy changes")
            }
        };
        outcome
            .as_object_mut()
            .expect("policy mutation outcomes are objects")
            .insert("index".into(), json!(item.index));
        outcomes.push(outcome);
    }
    db.commit_authorization(tx).await?;
    Ok(json!({
        "ok":true,
        "item_count":outcomes.len(),
        "changed_count":changed_count,
        "outcomes":outcomes,
    }))
}

async fn execute_policy_mutation(
    db: Db,
    caller: &Caller,
    arguments: ManageRecordPolicyArgs,
) -> Result<Value> {
    if let ManageRecordPolicyArgs::SetMany { items, reason } = arguments {
        return execute_set_many(db, caller, items, reason).await;
    }
    let (record_id, reason, expected_revision, expected_content_seq, expected_inherited_revision) =
        match &arguments {
            ManageRecordPolicyArgs::SetMany { .. } => {
                unreachable!("set_many returned through its batch execution path")
            }
            ManageRecordPolicyArgs::Grant {
                record_id,
                reason,
                if_policy_revision,
                if_content_seq,
                ..
            }
            | ManageRecordPolicyArgs::Revoke {
                record_id,
                reason,
                if_policy_revision,
                if_content_seq,
                ..
            }
            | ManageRecordPolicyArgs::SetMembersBaseline {
                record_id,
                reason,
                if_policy_revision,
                if_content_seq,
                ..
            } => (
                record_id.clone(),
                reason.clone(),
                if_policy_revision.clone(),
                *if_content_seq,
                None,
            ),
            ManageRecordPolicyArgs::Replace {
                record_id,
                reason,
                if_policy_revision,
                if_content_seq,
                ..
            } => (
                record_id.clone(),
                reason.clone(),
                Some(if_policy_revision.clone()),
                *if_content_seq,
                None,
            ),
            ManageRecordPolicyArgs::RestoreInheritance {
                record_id,
                reason,
                if_policy_revision,
                if_content_seq,
                if_inherited_policy_revision,
            } => (
                record_id.clone(),
                reason.clone(),
                Some(if_policy_revision.clone()),
                *if_content_seq,
                if_inherited_policy_revision.clone(),
            ),
            ManageRecordPolicyArgs::Inspect { .. } | ManageRecordPolicyArgs::List { .. } => {
                unreachable!("read actions do not enter mutation execution")
            }
        };

    require_nonblank_reason(TOOL, &reason)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    mutation_policy_access(&mut tx, caller, &record_id).await?;
    let content_seq = previous_record_seq_in(&mut tx, &record_id).await?;
    assert_content_seq(&record_id, content_seq, expected_content_seq)?;
    let before = policy_snapshot(&mut tx, &record_id).await?;
    assert_revision(&before, expected_revision.as_deref())?;
    if matches!(
        &arguments,
        ManageRecordPolicyArgs::RestoreInheritance { .. }
    ) {
        validate_inheritance_restoration(&record_id, &before)?;
    }
    let mutation = resolve_policy_mutation(&mut tx, caller, &record_id, arguments, None).await?;
    let inherited_revision = if let PolicyMutation::RestoreInheritance { inherited } = &mutation {
        Some(inherited.revision.clone())
    } else {
        None
    };
    let transition = plan_policy_transition(&record_id, &before, mutation)?;
    if let Some(inherited_revision) = inherited_revision {
        if let Some(expected) = expected_inherited_revision.as_deref() {
            if inherited_revision != expected {
                return Err(Error::engine(format!(
                    "{TOOL}: inherited policy revision conflict: expected {expected}, current {}",
                    inherited_revision
                )));
            }
        }
    }
    let (event, boundary_created) = match transition {
        PolicyTransition::NoChange { .. } => {
            return Ok(
                json!({"record_id":record_id,"changed":false,"policy_revision":before.revision}),
            );
        }
        PolicyTransition::ReplaceExplicit {
            entries,
            boundary_created,
            ..
        } => (
            crate::authorization::replace_explicit_policy_on_with_reason(
                &mut tx,
                caller.actor(),
                &record_id,
                entries,
                &reason,
            )
            .await?,
            boundary_created,
        ),
        PolicyTransition::RestoreInheritance {
            after_anchor_id,
            after_normalized,
        } => {
            let event = crate::authorization::restore_inheritance_on_with_reason(
                &mut tx,
                caller.actor(),
                &record_id,
                &reason,
            )
            .await?;
            let restored = policy_snapshot(&mut tx, &record_id).await?;
            let restored_entries = crate::authorization::normalize_entries(restored.entries)?;
            if restored.mode != PolicyMode::Inherit
                || restored.anchor_id != after_anchor_id
                || restored_entries != after_normalized
            {
                return Err(Error::engine(format!(
                    "{TOOL}: restored policy does not match its inherited policy snapshot"
                )));
            }
            (event, false)
        }
    };
    let result = mutation_result(&mut tx, &record_id, before, boundary_created, event).await?;
    db.commit_authorization(tx).await?;
    Ok(result)
}

async fn manage_record_policy(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args(TOOL, arguments)? {
        ManageRecordPolicyArgs::Inspect { record_id } => {
            let mut tx = db.write_pool().begin().await?;
            let access = policy_access(&mut tx, &caller, &record_id, false).await?;
            let snapshot = policy_snapshot(&mut tx, &access.authorization_target_id).await?;
            tx.rollback().await?;
            Ok(json!({
                "record_id":record_id,
                "authorization_target_id":access.authorization_target_id,
                "mode":mode_name(snapshot.mode),
                "anchor_id":snapshot.anchor_id,
                "caller_capability":capability_name(access.caller_capability),
                "policy_administration_authorized":access.policy_administration_authorized,
            }))
        }
        ManageRecordPolicyArgs::List { record_id } => {
            let mut tx = db.write_pool().begin().await?;
            let access = policy_access(&mut tx, &caller, &record_id, true).await?;
            let snapshot = policy_snapshot(&mut tx, &access.authorization_target_id).await?;
            let entries = listed_entries(&mut tx, &caller, &snapshot.entries).await?;
            tx.rollback().await?;
            Ok(json!({
                "record_id":record_id,
                "authorization_target_id":access.authorization_target_id,
                "mode":mode_name(snapshot.mode),
                "anchor_id":snapshot.anchor_id,
                "caller_capability":capability_name(access.caller_capability),
                "policy_administration_authorized":access.policy_administration_authorized,
                "entries":entries,
                "policy_revision":snapshot.revision,
            }))
        }
        mutation => execute_policy_mutation(db, &caller, mutation).await,
    }
}

pub fn register_policy_tools(registry: &mut ToolRegistry) -> Result<()> {
    let subject = json!({
        "oneOf":[
            {"type":"object","properties":{"kind":{"const":"members"}},"required":["kind"],"additionalProperties":false},
            {"type":"object","properties":{"kind":{"const":"person"},"person_record_id":{"type":"string","minLength":1}},"required":["kind","person_record_id"],"additionalProperties":false},
            {"type":"object","properties":{"kind":{"const":"account"},"account_id":{"type":"string","minLength":1}},"required":["kind","account_id"],"additionalProperties":false}
        ]
    });
    let replacement_entry = json!({
        "type":"object",
        "properties":{"subject":subject.clone(),"capability":{"type":"string","enum":["view","edit","manage"]}},
        "required":["subject","capability"],
        "additionalProperties":false
    });
    let set_many_item = json!({
        "type":"object",
        "properties":{
            "record_id":{"type":"string","minLength":1},
            "subject":subject.clone(),
            "capability":{
                "type":["string","null"],
                "enum":["view","edit","manage",null],
                "description":"Exact desired capability for this subject; null means the grant must be absent."
            }
        },
        "required":["record_id","subject","capability"],
        "additionalProperties":false
    });
    registry.register(
        ToolKind::ManageRecordPolicy,
        "Inspect effective record access without disclosing its roster; policy administrators can list entries, apply transactional grant/revoke/baseline deltas, or atomically converge a bounded input-ordered set of exact per-subject capabilities. Inspection follows derived artifacts to the same authorization bearer used by enforcement, while mutations require that bearer to be targeted explicitly. Host owners and standalone operators administer native:root without inflating their evaluator-reported capability. native:root is the workspace itself: they alone may rename it, through update_record, and any other member is refused. That name is display-only — no identifier, handle, or URL derives from it — while the root's kind, home_id, and persistence stay immutable for life. Whole-policy replacement and inheritance restoration require the opaque revision returned by list. A delta against inherited access creates an explicit boundary only when it changes state.",
        json!({
            "type":"object",
            "oneOf":[
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"inspect"},
                        "record_id":{"type":"string","minLength":1}
                    },
                    "required":["action","record_id"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"list"},
                        "record_id":{"type":"string","minLength":1}
                    },
                    "required":["action","record_id"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"set_many"},
                        "items":{
                            "type":"array",
                            "minItems":1,
                            "maxItems":MAX_SET_MANY_ITEMS,
                            "items":set_many_item,
                            "description":"Input-ordered exact subject grants. Duplicate resolved record/subject pairs are rejected."
                        },
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","items","reason"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"grant"},
                        "record_id":{"type":"string","minLength":1},
                        "subject":subject.clone(),
                        "capability":{"type":"string","enum":["view","edit","manage"]},
                        "if_policy_revision":{"type":"string","minLength":1,"description":"Optional compare-and-set revision from list."},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","record_id","subject","capability","reason"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"revoke"},
                        "record_id":{"type":"string","minLength":1},
                        "subject":subject.clone(),
                        "if_policy_revision":{"type":"string","minLength":1,"description":"Optional compare-and-set revision from list."},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","record_id","subject","reason"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"set_members_baseline"},
                        "record_id":{"type":"string","minLength":1},
                        "capability":{"type":["string","null"],"enum":["view","edit",null]},
                        "if_policy_revision":{"type":"string","minLength":1,"description":"Optional compare-and-set revision from list."},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","record_id","reason"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"replace"},
                        "record_id":{"type":"string","minLength":1},
                        "entries":{"type":"array","items":replacement_entry},
                        "if_policy_revision":{"type":"string","minLength":1,"description":"Required opaque revision from list."},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","record_id","entries","if_policy_revision","reason"],
                    "additionalProperties":false
                },
                {
                    "type":"object",
                    "properties":{
                        "action":{"const":"restore_inheritance"},
                        "record_id":{"type":"string","minLength":1},
                        "if_policy_revision":{"type":"string","minLength":1,"description":"Required opaque revision from list."},
                        "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
                    },
                    "required":["action","record_id","if_policy_revision","reason"],
                    "additionalProperties":false
                }
            ]
        }),
        manage_record_policy,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "mcp-executor-prototype"))]
mod executor_preparation_tests {
    use super::*;

    #[tokio::test]
    async fn delta_preparation_is_non_mutating_and_handler_cas_fences_stale_replay() {
        let db = crate::create_database(":memory:")
            .await
            .expect("test database");
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).expect("surface tools register");
        let record_id = "98765432-1234-4234-8234-123456789abc";
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": record_id,
                    "type": "Entity",
                    "kind": "person",
                    "name": "Prepared policy target",
                    "reason": "Create the exact policy preparation fixture.",
                }),
            )
            .await
            .expect("create policy target");
        let source_arguments = json!({
            "action": "grant",
            "record_id": record_id,
            "subject": {"kind": "account", "account_id": "acct:prepared-policy-source"},
            "capability": "view",
            "reason": "Approve the exact account visibility grant.",
        });
        let content_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared =
            prepare_record_policy_mutation(&db, &Caller::local(), "grant", source_arguments)
                .await
                .expect("prepare grant");
        assert_eq!(
            prepared.canonical_source_arguments["if_policy_revision"],
            prepared.policy_revision
        );
        assert!(prepared.canonical_source_arguments["if_content_seq"].is_i64());
        assert_eq!(prepared.effect["action"], "grant");
        assert_eq!(prepared.effect["changed"], true);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            content_before,
            "preparation appended an event"
        );

        let result = manage_record_policy(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments.clone(),
        )
        .await
        .expect("execute prepared grant");
        assert_eq!(result["changed"], true);
        let stale = manage_record_policy(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments,
        )
        .await
        .expect_err("stale prepared arguments must fail closed")
        .to_string();
        assert!(stale.contains("policy revision conflict"), "{stale}");
        db.close().await;
    }

    #[tokio::test]
    async fn set_many_preparation_is_indexed_non_mutating_and_injects_each_fence() {
        let db = crate::create_database(":memory:")
            .await
            .expect("test database");
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).expect("surface tools register");
        let ids = [
            "98765432-1234-4234-8234-123456789ac1",
            "98765432-1234-4234-8234-123456789ac2",
        ];
        for (id, name) in ids.into_iter().zip(["Set first", "Set second"]) {
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "create_record",
                    json!({
                        "id":id,
                        "type":"Document",
                        "kind":"note",
                        "name":name,
                        "reason":"Create a set-many preparation fixture.",
                    }),
                )
                .await
                .expect("create policy target");
        }
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_record_policy_mutation(
            &db,
            &Caller::local(),
            "set_many",
            json!({
                "action":"set_many",
                "items":[
                    {
                        "record_id":ids[0],
                        "subject":{"kind":"account","account_id":"acct:first"},
                        "capability":"edit",
                    },
                    {
                        "record_id":ids[1],
                        "subject":{"kind":"account","account_id":"acct:second"},
                        "capability":null,
                    }
                ],
                "reason":"Approve the exact indexed policy set.",
            }),
        )
        .await
        .expect("prepare exact policy set");
        assert_eq!(prepared.effect["action"], "set_many");
        assert_eq!(prepared.effect["items"][0]["index"], 0);
        assert_eq!(prepared.effect["items"][1]["index"], 1);
        assert_eq!(prepared.effect["changed_count"], 1);
        for item in prepared.canonical_source_arguments["items"]
            .as_array()
            .unwrap()
        {
            assert!(item["if_policy_revision"].as_str().is_some());
            assert!(item["if_content_seq"].as_i64().is_some());
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            events_before,
            "set_many preparation appended an event"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn person_binding_preparation_is_non_mutating_and_handler_cas_fences_stale_replay() {
        let db = crate::create_database(":memory:")
            .await
            .expect("test database");
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).expect("surface tools register");
        let target_id = "98765432-1234-4234-8234-123456789abd";
        let person_id = "98765432-1234-4234-8234-123456789abe";
        for (id, name) in [(target_id, "Policy target"), (person_id, "Policy subject")] {
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "create_record",
                    json!({
                        "id": id,
                        "type": "Entity",
                        "kind": "person",
                        "name": name,
                        "reason": "Create a policy race fixture.",
                    }),
                )
                .await
                .expect("create policy race fixture");
        }
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
        )
        .bind(person_id)
        .bind("account")
        .bind("acct:before")
        .execute(db.write_pool())
        .await
        .expect("seed canonical account binding");

        let prepared = prepare_record_policy_mutation(
            &db,
            &Caller::local(),
            "grant",
            json!({
                "action":"grant",
                "record_id":target_id,
                "subject":{"kind":"person","person_record_id":person_id},
                "capability":"view",
                "reason":"Approve the exact resolved person grant.",
            }),
        )
        .await
        .expect("prepare person grant");
        assert_eq!(
            prepared.canonical_source_arguments["subject"]["if_account_id"],
            "acct:before"
        );
        sqlx::query("UPDATE bindings SET identifier=? WHERE record_id=? AND system='account'")
            .bind("acct:after")
            .bind(person_id)
            .execute(db.write_pool())
            .await
            .expect("race canonical account binding");
        let binding_race = manage_record_policy(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments,
        )
        .await
        .expect_err("changed person binding must fail closed")
        .to_string();
        assert!(
            binding_race.contains("account binding changed since preparation"),
            "{binding_race}"
        );

        let prepared = prepare_record_policy_mutation(
            &db,
            &Caller::local(),
            "grant",
            json!({
                "action":"grant",
                "record_id":target_id,
                "subject":{"kind":"account","account_id":"acct:content-race"},
                "capability":"view",
                "reason":"Approve a grant against this exact target content state.",
            }),
        )
        .await
        .expect("prepare content-fenced grant");
        registry
            .call(
                db.clone(),
                Caller::local(),
                "update_record",
                json!({
                    "id":target_id,
                    "name":"Renamed policy target",
                    "reason":"Race the prepared policy target content.",
                }),
            )
            .await
            .expect("rename policy target");
        let content_race = manage_record_policy(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments,
        )
        .await
        .expect_err("changed target content must fail closed")
        .to_string();
        assert!(
            content_race.contains("content changed since preparation"),
            "{content_race}"
        );
        db.close().await;
    }
}
