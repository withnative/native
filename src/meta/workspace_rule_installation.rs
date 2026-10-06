//! Supported-v1 durable snapshots. No MCP/admission/evaluator entry point.
//!
//! The only mutation token has no Deserialize implementation and no production
//! constructor. A future qualified intake must derive SQL/order evidence and
//! validate off Tokio, then seal after current authority/catalog rechecks in the
//! writer transaction. Decoding historical receipts NEVER creates that token.
//! See docs/prototypes/workspace_rule_storage_v1.md for the frozen preimages.
#![allow(dead_code)] // Internal substrate; qualified operational intake remains closed.

use super::events::MetaEventRow;
use super::log::{append_meta_in, MetaAppendSpec};
use crate::authorization::{effective_capability_on, Capability, Principal};
use crate::query::{rule_install as ri, rule_shape as shape};
use crate::{Error, Result};
use native_query_contract::rule_contract::{PinnedRelation, RuleInputReadset};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, SqliteConnection, Transaction};
use std::collections::{BTreeMap, BTreeSet};

mod canonical;

pub(crate) const EVENT: &str = "workspace_rule_installation.set.v1";
const ROOT: &str = crate::schema::ROOT_RECORD_ID;
fn corrupt() -> Error {
    Error::engine("workspace rule installation integrity failure")
}
fn unavailable() -> Error {
    Error::engine("workspace rule target unavailable")
}
fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(canonical::digest(&serde_json::to_value(value)?))
}
fn token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(corrupt());
    }
    Ok(())
}
fn subject(namespace: &str, name: &str) -> String {
    format!("{}{}:{name}", prefix(), namespace)
}
fn prefix() -> String {
    format!("workspace-rule:{}:", hex::encode(ROOT.as_bytes()))
}
fn parse_subject(value: &str) -> Result<(String, String)> {
    let (ns, name) = value
        .strip_prefix(&prefix())
        .and_then(|s| s.split_once(':'))
        .ok_or_else(corrupt)?;
    token(ns)?;
    token(name)?;
    if subject(ns, name) != value {
        return Err(corrupt());
    }
    Ok((ns.into(), name.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SnapshotVersion {
    WorkspaceRuleSnapshotV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RevisionVersion {
    WorkspaceRuleRevisionV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptVersion {
    WorkspaceRuleReceiptV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetadataVersion {
    WorkspaceRuleMetadataV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OrderVersion {
    WorkspaceRuleOrderV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SettingsVersion {
    WorkspaceRuleSettingsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    version: RevisionVersion,
    content: ri::RuleRevision,
}
impl Revision {
    fn identity(&self) -> serde_json::Value {
        serde_json::json!({"version":self.version,"content":ri::canonical_revision_value(&self.content)})
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptySettings {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    version: SettingsVersion,
    content: EmptySettings,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Level {
    Advise,
    Warn,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Watch {
    WorkItemCompletionV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Hook {
    CreateRecord,
    UpdateRecord,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Advisor {
    watch: Watch,
    hooks: Vec<Hook>,
    level: Level,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: MetadataVersion,
    advisor: Option<Advisor>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    revision: u32,
    profile_id: String,
    profile_revision: u32,
}
// This is a historical copy of the CURRENT proof2 wire fields, not a live
// proof constructor. Deserialize only in the historical structural decoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderProof {
    version: u32,
    profile_id: String,
    profile_revision: u32,
    relations: Vec<PinnedRelation>,
    singleton: bool,
    ordered_keys: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Orders {
    version: OrderVersion,
    input_order: Vec<String>,
    proofs: BTreeMap<String, OrderProof>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    revision_digest: String,
    settings_digest: String,
    language_identity: String,
    policy_version: String,
    engine_id: String,
    engine_version: String,
    bundle_sha256: Option<String>,
}
impl Evidence {
    fn legacy(&self) -> ri::EngineValidationEvidence {
        ri::EngineValidationEvidence {
            revision_digest: self.revision_digest.clone(),
            settings_digest: self.settings_digest.clone(),
            language_identity: self.language_identity.clone(),
            policy_version: self.policy_version.clone(),
            engine_id: self.engine_id.clone(),
            engine_version: self.engine_version.clone(),
            bundle_sha256: self.bundle_sha256.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: ReceiptVersion,
    root: String,
    namespace: String,
    name: String,
    revision_digest: String,
    settings_digest: String,
    metadata_digest: String,
    catalog_digest: String,
    readset_digest: String,
    order_digest: String,
    evidence: Evidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: SnapshotVersion,
    root: String,
    revision: Revision,
    revision_digest: String,
    settings: Settings,
    settings_digest: String,
    metadata: Metadata,
    metadata_digest: String,
    catalog: Catalog,
    catalog_digest: String,
    readsets: BTreeMap<String, RuleInputReadset>,
    readset_digest: String,
    orders: Orders,
    order_digest: String,
    receipt: Receipt,
    receipt_digest: String,
    active: bool,
    actor: String,
    previous_seq: Option<i64>,
}

fn verify(p: &Snapshot, event_subject: &str, event_actor: Option<&str>) -> Result<()> {
    let r = &p.revision.content;
    if p.root != ROOT
        || event_subject != subject(&r.namespace, &r.name)
        || event_actor != Some(p.actor.as_str())
        || p.actor.is_empty()
        || p.previous_seq.is_some_and(|s| s < 1)
    {
        return Err(corrupt());
    }
    ri::validate_revision_shape(r)?;
    if r.binding_contract != Some(shape::BindingContractVersion::ScalarRowsV1)
        || !r.definition_pins.is_empty()
    {
        return Err(corrupt());
    }
    let mut hooks = BTreeSet::new();
    if let Some(advisor) = &p.metadata.advisor {
        if advisor.hooks.is_empty()
            || advisor
                .hooks
                .iter()
                .any(|h| !hooks.insert(serde_json::to_string(h).expect("hook")))
        {
            return Err(corrupt());
        }
    } else if r
        .scalar_arguments
        .iter()
        .any(|s| matches!(s.source, shape::ScalarSource::CompletionV1 { .. }))
    {
        return Err(corrupt());
    }
    if p.revision_digest != canonical::digest(&p.revision.identity())
        || p.settings_digest != digest(&p.settings)?
        || p.metadata_digest != digest(&p.metadata)?
        || p.catalog_digest != digest(&p.catalog)?
        || p.order_digest != digest(&p.orders)?
        || p.receipt_digest != digest(&p.receipt)?
    {
        return Err(corrupt());
    }
    if p.catalog.profile_id.is_empty() {
        return Err(corrupt());
    }
    let names: BTreeSet<_> = r.inputs.iter().map(|i| i.name.clone()).collect();
    if names != p.readsets.keys().cloned().collect()
        || names != p.orders.proofs.keys().cloned().collect()
        || p.orders.input_order != ri::derive_input_order(r)?
    {
        return Err(corrupt());
    }
    for input in &r.inputs {
        let readset = &p.readsets[&input.name];
        let proof = &p.orders.proofs[&input.name];
        let slots: Vec<_> = input.parameters.iter().map(|p| p.slot).collect();
        let mut slots_sorted = slots;
        slots_sorted.sort();
        if slots_sorted != readset.parameter_slots
            || readset.parameter_slots != (1..=readset.parameter_slots.len()).collect::<Vec<_>>()
            || readset.uses_now_ms
        {
            return Err(corrupt());
        }
        let mut identities = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for relation in &readset.relations {
            if relation.name.is_empty()
                || relation.identity.is_empty()
                || relation.population_only != relation.columns.is_empty()
                || !identities.insert(&relation.identity)
                || previous.is_some_and(|s| s >= relation.name.as_str())
            {
                return Err(corrupt());
            }
            previous = Some(relation.name.as_str());
        }
        if proof.version != 2
            || proof.profile_id != p.catalog.profile_id
            || proof.profile_revision != p.catalog.profile_revision
            || proof.relations != readset.relations
            || (!proof.singleton && proof.ordered_keys.is_empty())
        {
            return Err(corrupt());
        }
        if proof.ordered_keys.iter().any(|k| k.is_empty())
            || proof.ordered_keys.iter().collect::<BTreeSet<_>>().len() != proof.ordered_keys.len()
        {
            return Err(corrupt());
        }
    }
    let pairs: Vec<_> = p.readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    if p.readset_digest
        != ri::readset_digest(
            p.catalog.revision,
            &p.catalog.profile_id,
            p.catalog.profile_revision,
            &pairs,
        )
    {
        return Err(corrupt());
    }
    let receipt = &p.receipt;
    if receipt.root != p.root
        || receipt.namespace != r.namespace
        || receipt.name != r.name
        || receipt.revision_digest != p.revision_digest
        || receipt.settings_digest != p.settings_digest
        || receipt.metadata_digest != p.metadata_digest
        || receipt.catalog_digest != p.catalog_digest
        || receipt.readset_digest != p.readset_digest
        || receipt.order_digest != p.order_digest
    {
        return Err(corrupt());
    }
    let evidence = receipt.evidence.legacy();
    ri::validate_evidence_shape(&evidence)?;
    ri::evidence_binds_request(
        &evidence,
        r,
        &ri::revision_digest(r)?,
        &ri::settings_digest(&serde_json::json!({}))?,
    )?;
    // Fixture refusal is part of historical validation, not merely intake.
    #[cfg(not(test))]
    ri::ensure_non_fixture_evidence(&evidence)?;
    #[cfg(test)]
    if !ri::is_fixture_engine_id(&evidence.engine_id) {
        ri::ensure_non_fixture_evidence(&evidence)?;
    }
    Ok(())
}

// Raw nested readsets/legacy examples are decoded then roundtripped exactly.
// This refuses ignored unknown fields/defaults and duplicate JSON object keys.
fn decode(bytes: &str) -> Result<Snapshot> {
    let raw: serde_json::Value = serde_json::from_str(bytes)?;
    if serde_json::to_string(&raw)? != bytes {
        return Err(corrupt());
    }
    let p: Snapshot = serde_json::from_str(bytes)?;
    if serde_json::to_value(&p)? != raw {
        return Err(corrupt());
    }
    Ok(p)
}
#[derive(Debug, Clone)]
struct Stored {
    snapshot: Snapshot,
    seq: i64,
}

pub(crate) async fn fold(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    if event.event_type != EVENT || event.seq < 1 {
        return Err(corrupt());
    }
    let p = decode(event.payload.as_deref().ok_or_else(corrupt)?)?;
    verify(&p, &event.subject_id, event.actor.as_deref())?;
    let current:Option<i64>=sqlx::query_scalar("SELECT event_seq FROM workspace_rule_installations WHERE root=? AND namespace=? AND name=?")
        .bind(&p.root).bind(&p.revision.content.namespace).bind(&p.revision.content.name).fetch_optional(&mut *conn).await?;
    if current != p.previous_seq || current.is_some_and(|s| s >= event.seq) {
        return Err(corrupt());
    }
    let json = serde_json::to_string(&serde_json::to_value(&p)?)?;
    sqlx::query("INSERT INTO workspace_rule_installations(root,namespace,name,snapshot_json,snapshot_digest,event_seq,actor,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(root,namespace,name) DO UPDATE SET snapshot_json=excluded.snapshot_json,snapshot_digest=excluded.snapshot_digest,event_seq=excluded.event_seq,actor=excluded.actor,created_at=excluded.created_at")
        .bind(&p.root).bind(&p.revision.content.namespace).bind(&p.revision.content.name).bind(json).bind(digest(&p)?).bind(event.seq).bind(&p.actor).bind(&event.created_at).execute(conn).await?;
    Ok(())
}

type LoggedSnapshot = (i64, String, String, Option<String>, Option<String>, String);
type ProjectedSnapshot = (String, String, i64, String, String);

// Verify the entire authorizing chain, structurally, in indexed subject order.
// No current authority/catalog/SQL calls here: historical replay precedes roots.
async fn read_on(conn: &mut SqliteConnection, ns: &str, name: &str) -> Result<Option<Stored>> {
    token(ns)?;
    token(name)?;
    let subject = subject(ns, name);
    let events: Vec<LoggedSnapshot>=sqlx::query_as("SELECT seq,subject_id,type,payload,actor,created_at FROM meta_events WHERE subject_id=? ORDER BY seq")
        .bind(&subject).fetch_all(&mut *conn).await?;
    let row: Option<ProjectedSnapshot>=sqlx::query_as("SELECT snapshot_json,snapshot_digest,event_seq,actor,created_at FROM workspace_rule_installations WHERE root=? AND namespace=? AND name=?")
        .bind(ROOT).bind(ns).bind(name).fetch_optional(&mut *conn).await?;
    let mut last: Option<(Snapshot, i64, String)> = None;
    for (seq, subject, kind, bytes, actor, time) in events {
        if kind != EVENT || seq < 1 {
            return Err(corrupt());
        }
        let p = decode(bytes.as_deref().ok_or_else(corrupt)?)?;
        verify(&p, &subject, actor.as_deref())?;
        if p.previous_seq != last.as_ref().map(|(_, s, _)| *s)
            || last.as_ref().is_some_and(|(_, s, _)| *s >= seq)
        {
            return Err(corrupt());
        }
        last = Some((p, seq, time));
    }
    match (row, last) {
        (None, None) => Ok(None),
        (Some((bytes, sha, seq, actor, time)), Some((p, log_seq, log_time))) => {
            let projected = decode(&bytes)?;
            verify(&projected, &subject, Some(&actor))?;
            if projected != p || sha != digest(&p)? || seq != log_seq || time != log_time {
                return Err(corrupt());
            }
            Ok(Some(Stored { snapshot: p, seq }))
        }
        _ => Err(corrupt()),
    }
}
async fn census_on(conn: &mut SqliteConnection) -> Result<Vec<Stored>> {
    let start = prefix();
    let end = format!("{};", start.trim_end_matches(':'));
    // Literal ASCII range on existing idx_meta_events_subject, never LIKE.
    let subjects:Vec<String>=sqlx::query_scalar("SELECT DISTINCT subject_id FROM meta_events WHERE subject_id>=? AND subject_id<? ORDER BY subject_id")
        .bind(&start).bind(&end).fetch_all(&mut *conn).await?;
    let mut keys = BTreeSet::new();
    for s in subjects {
        keys.insert(parse_subject(&s)?);
    }
    let rows:Vec<(String,String)>=sqlx::query_as("SELECT namespace,name FROM workspace_rule_installations WHERE root=? ORDER BY namespace,name")
        .bind(ROOT).fetch_all(&mut *conn).await?;
    keys.extend(rows);
    let mut out = Vec::new();
    for (ns, name) in keys {
        out.push(read_on(conn, &ns, &name).await?.ok_or_else(corrupt)?);
    }
    Ok(out)
}

async fn authorize(
    tx: &mut Transaction<'_, Sqlite>,
    caller: Principal<'_>,
    manage: bool,
) -> Result<String> {
    // No trusted-local or membership-only authority. Hide all state first.
    let actor = caller
        .account_id
        .filter(|a| !a.is_empty())
        .ok_or_else(unavailable)?;
    if caller.is_trusted_local() {
        return Err(unavailable());
    }
    let cap = effective_capability_on(tx, caller, ROOT)
        .await
        .map_err(|_| unavailable())?;
    if cap < Capability::View {
        return Err(unavailable());
    }
    if manage && cap < Capability::Manage {
        return Err(Error::engine("workspace rule Manage capability required"));
    }
    Ok(actor.into())
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceRuleRequirements {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) event_seq: i64,
    pub(crate) revision_digest: String,
    pub(crate) catalog_revision: u32,
    pub(crate) profile_id: String,
    pub(crate) profile_revision: u32,
    pub(crate) readsets: BTreeMap<String, RuleInputReadset>,
}

/// Verified structural readset hook for future catalog/profile evolution.
/// Actual caller View is established before census/diagnostics. No v2 family
/// pins and no second collector/enforcer are introduced by this hook.
pub(crate) async fn active_readsets(
    tx: &mut Transaction<'_, Sqlite>,
    caller: Principal<'_>,
) -> Result<Vec<WorkspaceRuleRequirements>> {
    authorize(tx, caller, false).await?;
    Ok(census_on(tx)
        .await?
        .into_iter()
        .filter(|s| s.snapshot.active)
        .map(|s| WorkspaceRuleRequirements {
            namespace: s.snapshot.revision.content.namespace,
            name: s.snapshot.revision.content.name,
            event_seq: s.seq,
            revision_digest: s.snapshot.revision_digest,
            catalog_revision: s.snapshot.catalog.revision,
            profile_id: s.snapshot.catalog.profile_id,
            profile_revision: s.snapshot.catalog.profile_revision,
            readsets: s.snapshot.readsets,
        })
        .collect())
}
async fn inspect(
    tx: &mut Transaction<'_, Sqlite>,
    caller: Principal<'_>,
    ns: &str,
    name: &str,
) -> Result<Stored> {
    authorize(tx, caller, false).await?;
    read_on(tx, ns, name).await?.ok_or_else(unavailable)
}

fn retry_identity(p: &Snapshot) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(p)?;
    value["revision"]["content"] = ri::canonical_revision_value(&p.revision.content);
    Ok(value)
}

/// Not Serialize/Deserialize, not publicly exported, NO production issuer.
/// Future issuer must carry a current transaction-bound qualified admission;
/// simply supplying/deserializing Receipt/Snapshot/Evidence is not authority.
struct VerifiedAdmission {
    snapshot: Snapshot,
}
async fn set_verified(
    tx: &mut Transaction<'static, Sqlite>,
    caller: Principal<'_>,
    sealed: VerifiedAdmission,
    expected: Option<i64>,
    act: &mut crate::act::ActAllocation,
) -> Result<(Stored, bool)> {
    let actor = authorize(tx, caller, true).await?;
    let mut p = sealed.snapshot;
    p.actor = actor;
    // Integrity before ExpectedSeq/equality. Compatibility belongs to the
    // future sealed issuer; disable intentionally preserves incompatible proof.
    let current = read_on(tx, &p.revision.content.namespace, &p.revision.content.name).await?;
    if current.as_ref().map(|s| s.seq) != expected {
        return Err(Error::conflict(
            "workspace rule installation sequence changed",
        ));
    }
    p.previous_seq = expected;
    verify(
        &p,
        &subject(&p.revision.content.namespace, &p.revision.content.name),
        Some(&p.actor),
    )?;
    if let Some(s) = &current {
        let mut retry = s.snapshot.clone();
        retry.previous_seq = p.previous_seq;
        if retry_identity(&retry)? == retry_identity(&p)? {
            return Ok((s.clone(), false));
        }
    }
    let event = append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            subject(&p.revision.content.namespace, &p.revision.content.name),
            EVENT,
            serde_json::to_value(&p)?,
        )
        .with_actor(Some(&p.actor)),
        act,
    )
    .await?;
    let stored = read_on(tx, &p.revision.content.namespace, &p.revision.content.name)
        .await?
        .ok_or_else(corrupt)?;
    if stored.seq != event.seq {
        return Err(corrupt());
    }
    Ok((stored, true))
}
async fn disable(
    tx: &mut Transaction<'static, Sqlite>,
    caller: Principal<'_>,
    ns: &str,
    name: &str,
    expected: Option<i64>,
    act: &mut crate::act::ActAllocation,
) -> Result<(Stored, bool)> {
    authorize(tx, caller, true).await?;
    let mut p = read_on(tx, ns, name)
        .await?
        .ok_or_else(unavailable)?
        .snapshot;
    p.active = false;
    set_verified(tx, caller, VerifiedAdmission { snapshot: p }, expected, act).await
}

#[cfg(test)]
mod tests;
