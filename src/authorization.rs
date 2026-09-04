//! Portable, caller-relative record authorization.
//!
//! Policies are complete replacement boundaries. `records.policy_anchor_id`
//! materializes only the nearest boundary; grants are never copied or unioned
//! down the tree. Host membership is supplied at evaluation time, so adding or
//! removing a catalog membership takes effect without rewriting the file.
//!
//! `record_policies` and `policy_entries` are materialized from the independent
//! authoritative `policy_events` log. Replaying content must never invent or
//! reactivate grants. `records.policy_anchor_id` is the only containment-derived
//! part and is deliberately excluded from the policy fold.

use std::collections::{HashMap, HashSet};

use sqlx::{Row, Sqlite, SqliteConnection, SqlitePool, Transaction};

use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, SqlError, SqlResult, StatementKind, StatementTemplate,
};

/// Monotonic revision over every authoritative authorization input, maintained
/// transactionally by schema triggers. Unlike a state digest, this is ABA-safe.
pub(crate) async fn authorization_revision(db: &Db) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(db.write_pool())
            .await?,
    )
}

pub(crate) async fn authorization_revision_on(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(&mut **transaction)
            .await?,
    )
}
use crate::schema::ROOT_RECORD_ID;

use native_policy_kernel::{
    evaluate_policy_grants, resolve_effective_capability, PolicyEvaluationEntry,
    PolicyEvaluationError, PolicyEvaluationPrincipal,
};
pub use native_policy_kernel::{
    AllowEntry, Capability, PolicyMode, PolicySubject, MEMBERS_SUBJECT_ID,
};
/// Defensive maximum number of derived-artifact `part_of` edges followed by
/// every authorization surface. Exactly this many edges are valid; a derived
/// record that would require one more hop fails closed.
pub const MAX_DERIVED_BEARER_DEPTH: usize = 100;
/// Defensive maximum number of semantic-Unit authority bearers intersected by
/// one authorization check. Promotion creates one edge, but raw event replay
/// must also fail closed on malformed chains and cycles.
pub const MAX_UNIT_BEARER_DEPTH: usize = 100;

fn parse_capability(value: &str) -> Result<Capability> {
    Capability::from_policy_str(value)
        .ok_or_else(|| Error::engine(format!("unsupported policy capability '{value}'")))
}

/// A host-verified portable account binding plus its live membership state.
/// `account_id = None` is an unbound identity: account grants remain stored but
/// dormant and cannot match by display name or email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Principal<'a> {
    pub account_id: Option<&'a str>,
    pub is_member: bool,
    trusted_local_bypass: bool,
}

impl<'a> Principal<'a> {
    pub fn bound(account_id: &'a str, is_member: bool) -> Self {
        Self {
            account_id: Some(account_id),
            is_member,
            trusted_local_bypass: false,
        }
    }

    pub fn unbound(is_member: bool) -> Self {
        Self {
            account_id: None,
            is_member,
            trusted_local_bypass: false,
        }
    }

    pub(crate) fn trusted_local() -> Self {
        Self {
            account_id: None,
            is_member: false,
            trusted_local_bypass: true,
        }
    }

    pub(crate) fn is_trusted_local(self) -> bool {
        self.trusted_local_bypass
    }
}

#[derive(Debug, Clone)]
struct AuthorizationRecordState {
    record_type: String,
    kind: Option<String>,
    deleted: bool,
    owner_id: Option<String>,
    policy_anchor_id: Option<String>,
}

#[derive(Debug, Clone)]
struct AuthorizationPolicyEntry {
    subject_kind: String,
    subject_id: String,
    effect: String,
    capability: String,
}

fn auth_statement(
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments)
        .map_err(|error| crate::domain_transaction::stable_storage_error("authorize", &error))
}

async fn auth_fetch<E: DomainStatementExecutor>(
    executor: &mut E,
    statement: &StatementTemplate,
    bindings: &[BindValue],
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    executor
        .fetch_all(statement, bindings, columns)
        .await
        .map_err(|error| crate::domain_transaction::stable_storage_error("authorize", &error))
}

fn row_text(row: &NormalizedRow, column: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "authorization state column '{column}' is invalid"
        ))),
    }
}

fn row_optional_text(row: &NormalizedRow, column: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "authorization state column '{column}' is invalid"
        ))),
    }
}

fn row_bool(row: &NormalizedRow, column: &str) -> Result<bool> {
    match row.get(column) {
        Some(NormalizedValue::Bool(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "authorization state column '{column}' is invalid"
        ))),
    }
}

async fn authorization_record<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<Option<AuthorizationRecordState>> {
    let statement = auth_statement(
        "records",
        &[
            "SELECT type, kind, deleted_at, owner_id, policy_anchor_id FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let rows = auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(record_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ColumnSpec::nullable("owner_id", LogicalType::Text),
            ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
        ],
    )
    .await?;
    rows.first()
        .map(|row| {
            Ok(AuthorizationRecordState {
                record_type: row_text(row, "type")?,
                kind: row_optional_text(row, "kind")?,
                deleted: row_optional_text(row, "deleted_at")?.is_some(),
                owner_id: row_optional_text(row, "owner_id")?,
                policy_anchor_id: row_optional_text(row, "policy_anchor_id")?,
            })
        })
        .transpose()
}

async fn derived_bearers<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<Vec<String>> {
    let statement = auth_statement(
        "links",
        &[
            "SELECT target_id FROM {{relation}} WHERE source_id = ",
            " AND relationship = 'part_of' ORDER BY target_id",
        ],
    )?;
    auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required("target_id", LogicalType::Text)],
    )
    .await?
    .iter()
    .map(|row| row_text(row, "target_id"))
    .collect()
}

async fn unit_bearer<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<Option<String>> {
    let statement = auth_statement(
        "semantic_units",
        &[
            "SELECT authority_bearer_record_id FROM {{relation}} WHERE unit_id = ",
            "",
        ],
    )?;
    let rows = auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required(
            "authority_bearer_record_id",
            LogicalType::Text,
        )],
    )
    .await?;
    rows.first()
        .map(|row| row_text(row, "authority_bearer_record_id"))
        .transpose()
}

async fn has_explicit_policy<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<bool> {
    let statement = auth_statement(
        "record_policies",
        &[
            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id = ",
            ") AS explicit",
        ],
    )?;
    let rows = auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required("explicit", LogicalType::Bool)],
    )
    .await?;
    row_bool(&rows[0], "explicit")
}

async fn authorization_policy_entries<E: DomainStatementExecutor>(
    executor: &mut E,
    policy_anchor_id: &str,
    ordered: bool,
) -> Result<Vec<AuthorizationPolicyEntry>> {
    let statement = if ordered {
        auth_statement(
            "policy_entries",
            &[
                "SELECT subject_kind, subject_id, effect, capability FROM {{relation}} WHERE policy_anchor_id = ",
                " ORDER BY subject_kind, subject_id, capability",
            ],
        )?
    } else {
        auth_statement(
            "policy_entries",
            &[
                "SELECT subject_kind, subject_id, effect, capability FROM {{relation}} WHERE policy_anchor_id = ",
                "",
            ],
        )?
    };
    auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(policy_anchor_id.into())],
        &[
            ColumnSpec::required("subject_kind", LogicalType::Text),
            ColumnSpec::required("subject_id", LogicalType::Text),
            ColumnSpec::required("effect", LogicalType::Text),
            ColumnSpec::required("capability", LogicalType::Text),
        ],
    )
    .await?
    .iter()
    .map(|row| {
        Ok(AuthorizationPolicyEntry {
            subject_kind: row_text(row, "subject_kind")?,
            subject_id: row_text(row, "subject_id")?,
            effect: row_text(row, "effect")?,
            capability: row_text(row, "capability")?,
        })
    })
    .collect()
}

async fn owner_bound_to_account<E: DomainStatementExecutor>(
    executor: &mut E,
    owner_record_id: &str,
    account_id: &str,
) -> Result<bool> {
    let statement = auth_statement(
        "bindings",
        &[
            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id = ",
            " AND system = 'account' AND identifier = ",
            " AND is_canonical = 1) AS owns",
        ],
    )?;
    let rows = auth_fetch(
        executor,
        &statement,
        &[
            BindValue::Text(owner_record_id.into()),
            BindValue::Text(account_id.into()),
        ],
        &[ColumnSpec::required("owns", LogicalType::Bool)],
    )
    .await?;
    row_bool(&rows[0], "owns")
}

/// Whether an event's `actor` may be disclosed to `principal`.
///
/// A name is identity, and identity is disclosed on the same terms as any other
/// record: by `View` on the person the account is bound to. Being the actor is
/// the trivial case rather than the rule. An actor bound to no readable person
/// stays hidden, so an unresolvable token never leaks as attribution.
///
/// This lives here, generic over the executor, because every engine serves
/// history through its own reader. Three copies of the rule had already drifted
/// once — SQLite and Turso withheld the run and intent alongside the actor while
/// Postgres withheld only the actor — and one shared decision point is what
/// stops that happening again.
pub(crate) async fn actor_disclosable_with<E: DomainStatementExecutor>(
    executor: &mut E,
    principal: Principal<'_>,
    actor: &str,
) -> Result<bool> {
    if principal.account_id == Some(actor) {
        return Ok(true);
    }
    let statement = auth_statement(
        "bindings",
        &[
            "SELECT record_id FROM {{relation}} WHERE system = 'account' AND identifier = ",
            " LIMIT 1",
        ],
    )?;
    let rows = auth_fetch(
        executor,
        &statement,
        &[BindValue::Text(actor.into())],
        &[ColumnSpec::required("record_id", LogicalType::Text)],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let person_id = row_text(row, "record_id")?;
    // A malformed or absent policy is a denial here, exactly as it is for an
    // ordinary record read: absence, tombstones and refusal stay one answer.
    Ok(
        effective_capability_with(executor, principal, &person_id, false)
            .await
            .is_ok_and(|capability| capability.allows(Capability::View)),
    )
}

/// Evaluate one record against exactly its materialized nearest explicit policy.
/// The owner floor is applied last and is not represented by a removable entry.
pub async fn effective_capability(
    db: &Db,
    principal: Principal<'_>,
    record_id: &str,
) -> Result<Capability> {
    effective_capability_in_pool(db.write_pool(), principal, record_id).await
}

pub(crate) async fn effective_capability_in_pool(
    pool: &SqlitePool,
    principal: Principal<'_>,
    record_id: &str,
) -> Result<Capability> {
    let mut snapshot = pool.begin().await?;
    let capability = effective_capability_on(&mut snapshot, principal, record_id).await?;
    snapshot.rollback().await?;
    Ok(capability)
}

/// Realtime delete envelopes need the record's frozen owner/policy boundary
/// after the tombstone lands so previously authorized clients can evict it.
/// This seam is deliberately not used by ordinary reads.
pub(crate) async fn effective_capability_for_tombstone_in_pool(
    pool: &SqlitePool,
    principal: Principal<'_>,
    record_id: &str,
) -> Result<Capability> {
    let mut snapshot = pool.begin().await?;
    let capability =
        effective_capability_on_inner(&mut snapshot, principal, record_id, true).await?;
    snapshot.rollback().await?;
    Ok(capability)
}

/// Evaluate inside one caller-owned transaction. Accepting only
/// [`Transaction`] makes a sequence of unrelated plain-connection reads
/// unrepresentable: protected mutations call this inside the same write
/// transaction as the mutation.
pub async fn effective_capability_on(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_id: &str,
) -> Result<Capability> {
    effective_capability_on_inner(transaction, principal, record_id, false).await
}

/// Validate the complete derived-artifact and semantic-Unit bearer shape
/// without evaluating grants. The trusted local compatibility boundary may
/// bypass policy, but it must never bypass structural validity.
pub(crate) async fn validate_authorization_shape(
    db: &Db,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<()> {
    let mut snapshot = db.write_pool().begin().await?;
    validate_authorization_shape_on(&mut snapshot, record_id, include_initial_tombstone).await?;
    snapshot.rollback().await?;
    Ok(())
}

pub(crate) async fn validate_authorization_shape_on(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<()> {
    let mut state = BorrowedSqliteStatementExecutor::new(transaction);
    validate_authorization_shape_with(&mut state, record_id, include_initial_tombstone).await
}

async fn validate_authorization_shape_with<E: DomainStatementExecutor>(
    state: &mut E,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<()> {
    validate_authorization_shape_memoized(
        state,
        &mut BearerTargetMemo::default(),
        record_id,
        include_initial_tombstone,
    )
    .await
}

async fn validate_authorization_shape_memoized<E: DomainStatementExecutor>(
    state: &mut E,
    memo: &mut BearerTargetMemo,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<()> {
    let mut target =
        authorization_target_memoized(state, memo, record_id, include_initial_tombstone).await?;
    let mut seen = HashSet::new();
    let mut unit_depth = 0usize;
    loop {
        if !seen.insert(target.clone()) {
            return Err(Error::engine(format!(
                "record '{record_id}' has a cyclic semantic Unit authority bearer"
            )));
        }
        let bearer = unit_bearer(state, &target).await?;
        let Some(bearer) = bearer else { return Ok(()) };
        if unit_depth >= MAX_UNIT_BEARER_DEPTH {
            return Err(Error::engine(format!(
                "record '{record_id}' semantic Unit authority bearer exceeds the {MAX_UNIT_BEARER_DEPTH}-edge limit"
            )));
        }
        target = authorization_target_memoized(state, memo, &bearer, false).await?;
        unit_depth += 1;
    }
}

/// Resolve the ordinary authorization bearer for a live record inside the
/// caller's transaction. Public policy-management surfaces use this to report
/// the same effective target the evaluator enforces, without reimplementing
/// the derived-artifact walk.
pub(crate) async fn authorization_target_on(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
) -> Result<String> {
    authorization_target_on_inner(transaction, record_id, false).await
}

async fn effective_capability_on_inner(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_id: &str,
    include_tombstone: bool,
) -> Result<Capability> {
    let mut state = BorrowedSqliteStatementExecutor::new(transaction);
    effective_capability_with(&mut state, principal, record_id, include_tombstone).await
}

async fn effective_capability_with<E: DomainStatementExecutor>(
    state: &mut E,
    principal: Principal<'_>,
    record_id: &str,
    include_tombstone: bool,
) -> Result<Capability> {
    effective_capability_memoized(
        state,
        &mut BearerTargetMemo::default(),
        principal,
        record_id,
        include_tombstone,
    )
    .await
}

async fn effective_capability_memoized<E: DomainStatementExecutor>(
    state: &mut E,
    memo: &mut BearerTargetMemo,
    principal: Principal<'_>,
    record_id: &str,
    include_tombstone: bool,
) -> Result<Capability> {
    if principal.trusted_local_bypass {
        validate_authorization_shape_memoized(state, memo, record_id, include_tombstone).await?;
        return Ok(Capability::Manage);
    }
    let mut authorization_target =
        authorization_target_memoized(state, memo, record_id, include_tombstone).await?;
    let mut seen = HashSet::new();
    let mut unit_depth = 0usize;
    let mut effective = Capability::Manage;
    loop {
        if !seen.insert(authorization_target.clone()) {
            return Err(Error::engine(format!(
                "record '{record_id}' has a cyclic semantic Unit authority bearer"
            )));
        }
        effective = effective
            .min(policy_capability_with(state, principal, record_id, &authorization_target).await?);
        let bearer = unit_bearer(state, &authorization_target).await?;
        let Some(bearer) = bearer else {
            return Ok(effective);
        };
        if unit_depth >= MAX_UNIT_BEARER_DEPTH {
            return Err(Error::engine(format!(
                "record '{record_id}' semantic Unit authority bearer exceeds the {MAX_UNIT_BEARER_DEPTH}-edge limit"
            )));
        }
        authorization_target = authorization_target_memoized(state, memo, &bearer, false).await?;
        unit_depth += 1;
    }
}

#[derive(Default)]
struct PreloadedAuthorizationState {
    records: HashMap<String, AuthorizationRecordState>,
    derived_bearers: HashMap<String, Vec<String>>,
    unit_bearers: HashMap<String, String>,
    explicit_policies: HashSet<String>,
    policy_entries: HashMap<String, Vec<AuthorizationPolicyEntry>>,
    owner_bindings: HashSet<(String, String)>,
}

fn preload_binding_text(bindings: &[BindValue], index: usize) -> SqlResult<&str> {
    match bindings.get(index) {
        Some(BindValue::Text(value)) => Ok(value),
        _ => Err(SqlError::contract(
            "preloaded authorization statement has invalid bindings",
        )),
    }
}

fn preload_row(values: impl IntoIterator<Item = (&'static str, NormalizedValue)>) -> NormalizedRow {
    values
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect()
}

impl DomainStatementExecutor for PreloadedAuthorizationState {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        _columns: &'a [ColumnSpec],
    ) -> futures::future::BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            let rows = match statement.relation() {
                "records" => {
                    let id = preload_binding_text(bindings, 0)?;
                    self.records
                        .get(id)
                        .map(|record| {
                            preload_row([
                                ("type", NormalizedValue::Text(record.record_type.clone())),
                                (
                                    "kind",
                                    record
                                        .kind
                                        .clone()
                                        .map(NormalizedValue::Text)
                                        .unwrap_or(NormalizedValue::Null),
                                ),
                                (
                                    "deleted_at",
                                    if record.deleted {
                                        NormalizedValue::Text("deleted".into())
                                    } else {
                                        NormalizedValue::Null
                                    },
                                ),
                                (
                                    "owner_id",
                                    record
                                        .owner_id
                                        .clone()
                                        .map(NormalizedValue::Text)
                                        .unwrap_or(NormalizedValue::Null),
                                ),
                                (
                                    "policy_anchor_id",
                                    record
                                        .policy_anchor_id
                                        .clone()
                                        .map(NormalizedValue::Text)
                                        .unwrap_or(NormalizedValue::Null),
                                ),
                            ])
                        })
                        .into_iter()
                        .collect()
                }
                "links" => {
                    let id = preload_binding_text(bindings, 0)?;
                    self.derived_bearers
                        .get(id)
                        .into_iter()
                        .flatten()
                        .map(|target| {
                            preload_row([("target_id", NormalizedValue::Text(target.clone()))])
                        })
                        .collect()
                }
                "semantic_units" => {
                    let id = preload_binding_text(bindings, 0)?;
                    self.unit_bearers
                        .get(id)
                        .map(|bearer| {
                            preload_row([(
                                "authority_bearer_record_id",
                                NormalizedValue::Text(bearer.clone()),
                            )])
                        })
                        .into_iter()
                        .collect()
                }
                "record_policies" => {
                    let id = preload_binding_text(bindings, 0)?;
                    vec![preload_row([(
                        "explicit",
                        NormalizedValue::Bool(self.explicit_policies.contains(id)),
                    )])]
                }
                "policy_entries" => {
                    let id = preload_binding_text(bindings, 0)?;
                    self.policy_entries
                        .get(id)
                        .into_iter()
                        .flatten()
                        .map(|entry| {
                            preload_row([
                                (
                                    "subject_kind",
                                    NormalizedValue::Text(entry.subject_kind.clone()),
                                ),
                                (
                                    "subject_id",
                                    NormalizedValue::Text(entry.subject_id.clone()),
                                ),
                                ("effect", NormalizedValue::Text(entry.effect.clone())),
                                (
                                    "capability",
                                    NormalizedValue::Text(entry.capability.clone()),
                                ),
                            ])
                        })
                        .collect()
                }
                "bindings" => {
                    let owner = preload_binding_text(bindings, 0)?;
                    let account = preload_binding_text(bindings, 1)?;
                    vec![preload_row([(
                        "owns",
                        NormalizedValue::Bool(
                            self.owner_bindings
                                .contains(&(owner.into(), account.into())),
                        ),
                    )])]
                }
                _ => {
                    return Err(SqlError::contract(
                        "preloaded authorization received an unknown statement",
                    ))
                }
            };
            Ok(rows)
        })
    }
}

/// Evaluate a bounded record set through the canonical authorization fold
/// without issuing request-scaled SQL. One recursive closure query and four
/// set loads populate the same [`DomainStatementExecutor`] contract used by
/// the scalar path; the grant/owner/derived/Unit rules are not reimplemented.
pub(crate) async fn effective_capabilities_preloaded_on(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_ids: &[String],
    include_initial_tombstone: bool,
) -> Result<HashMap<String, Option<Capability>>> {
    let record_ids = record_ids.iter().cloned().collect::<HashSet<_>>();
    if record_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let seeds = serde_json::to_string(&record_ids)?;
    let max_derived = i64::try_from(MAX_DERIVED_BEARER_DEPTH).unwrap_or(i64::MAX);
    let max_units = i64::try_from(MAX_UNIT_BEARER_DEPTH).unwrap_or(i64::MAX);
    let closure_rows = sqlx::query(
        "WITH RECURSIVE walk(id,derived_depth,unit_depth,path) AS (\
         SELECT value,0,0,'|'||hex(value)||'|' FROM json_each(?) \
         UNION ALL \
         SELECT CASE WHEN r.type='Annotation' OR (r.type='Document' AND r.kind='attachment') \
                     THEN (SELECT target_id FROM links \
                            WHERE source_id=r.id AND relationship='part_of' \
                            ORDER BY target_id LIMIT 1) \
                     ELSE unit.authority_bearer_record_id END, \
                CASE WHEN r.type='Annotation' OR (r.type='Document' AND r.kind='attachment') \
                     THEN walk.derived_depth+1 ELSE 0 END, \
                CASE WHEN r.type='Annotation' OR (r.type='Document' AND r.kind='attachment') \
                     THEN walk.unit_depth ELSE walk.unit_depth+1 END, \
                walk.path||hex(CASE \
                    WHEN r.type='Annotation' OR (r.type='Document' AND r.kind='attachment') \
                    THEN (SELECT target_id FROM links \
                           WHERE source_id=r.id AND relationship='part_of' \
                           ORDER BY target_id LIMIT 1) \
                    ELSE unit.authority_bearer_record_id END)||'|' \
           FROM walk JOIN records r ON r.id=walk.id \
           LEFT JOIN semantic_units unit ON unit.unit_id=r.id \
          WHERE ((r.type='Annotation' OR (r.type='Document' AND r.kind='attachment')) \
                  AND walk.derived_depth < ? \
                  AND (SELECT COUNT(*) FROM links \
                        WHERE source_id=r.id AND relationship='part_of') >= 1 \
                  AND instr(walk.path,'|'||hex((SELECT target_id FROM links \
                              WHERE source_id=r.id AND relationship='part_of' \
                              ORDER BY target_id LIMIT 1))||'|')=0) \
             OR (NOT (r.type='Annotation' OR (r.type='Document' AND r.kind='attachment')) \
                  AND unit.authority_bearer_record_id IS NOT NULL \
                  AND walk.unit_depth < ? \
                  AND instr(walk.path,'|'||hex(unit.authority_bearer_record_id)||'|')=0) \
         ) \
         SELECT DISTINCT r.id,r.type,r.kind,r.deleted_at,r.owner_id,r.policy_anchor_id,\
                unit.authority_bearer_record_id \
           FROM walk JOIN records r ON r.id=walk.id \
           LEFT JOIN semantic_units unit ON unit.unit_id=r.id",
    )
    .bind(seeds)
    .bind(max_derived)
    .bind(max_units)
    .fetch_all(&mut **transaction)
    .await?;

    let mut state = PreloadedAuthorizationState::default();
    for row in closure_rows {
        let id: String = row.try_get("id")?;
        if let Some(bearer) = row.try_get::<Option<String>, _>("authority_bearer_record_id")? {
            state.unit_bearers.insert(id.clone(), bearer);
        }
        state.records.insert(
            id,
            AuthorizationRecordState {
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                deleted: row.try_get::<Option<String>, _>("deleted_at")?.is_some(),
                owner_id: row.try_get("owner_id")?,
                policy_anchor_id: row.try_get("policy_anchor_id")?,
            },
        );
    }
    let loaded_ids = serde_json::to_string(&state.records.keys().collect::<Vec<_>>())?;
    for row in sqlx::query(
        "SELECT source_id,target_id FROM links \
          WHERE relationship='part_of' AND source_id IN (SELECT value FROM json_each(?)) \
          ORDER BY source_id,target_id",
    )
    .bind(&loaded_ids)
    .fetch_all(&mut **transaction)
    .await?
    {
        state
            .derived_bearers
            .entry(row.try_get("source_id")?)
            .or_default()
            .push(row.try_get("target_id")?);
    }
    let anchors = state
        .records
        .values()
        .filter_map(|record| record.policy_anchor_id.clone())
        .collect::<HashSet<_>>();
    let anchors_json = serde_json::to_string(&anchors)?;
    state.explicit_policies = sqlx::query_scalar(
        "SELECT record_id FROM record_policies \
          WHERE record_id IN (SELECT value FROM json_each(?))",
    )
    .bind(&anchors_json)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .collect();
    for row in sqlx::query(
        "SELECT policy_anchor_id,subject_kind,subject_id,effect,capability \
           FROM policy_entries \
          WHERE policy_anchor_id IN (SELECT value FROM json_each(?)) \
          ORDER BY policy_anchor_id,subject_kind,subject_id,capability",
    )
    .bind(&anchors_json)
    .fetch_all(&mut **transaction)
    .await?
    {
        state
            .policy_entries
            .entry(row.try_get("policy_anchor_id")?)
            .or_default()
            .push(AuthorizationPolicyEntry {
                subject_kind: row.try_get("subject_kind")?,
                subject_id: row.try_get("subject_id")?,
                effect: row.try_get("effect")?,
                capability: row.try_get("capability")?,
            });
    }
    if let Some(account_id) = principal.account_id {
        let owners = state
            .records
            .values()
            .filter_map(|record| record.owner_id.clone())
            .collect::<HashSet<_>>();
        let owners_json = serde_json::to_string(&owners)?;
        state.owner_bindings = sqlx::query_scalar::<_, String>(
            "SELECT record_id FROM bindings \
              WHERE system='account' AND identifier=? AND is_canonical=1 \
                AND record_id IN (SELECT value FROM json_each(?))",
        )
        .bind(account_id)
        .bind(owners_json)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|owner| (owner, account_id.into()))
        .collect();
    }

    let mut capabilities = HashMap::with_capacity(record_ids.len());
    for record_id in record_ids {
        let capability =
            effective_capability_with(&mut state, principal, &record_id, include_initial_tombstone)
                .await
                .ok();
        capabilities.insert(record_id, capability);
    }
    Ok(capabilities)
}

/// Filter a bounded record set through the canonical preloaded authorization
/// fold while preserving the caller's input order (and any duplicate ids).
/// Product surfaces own their separate record-family admission rules; this
/// helper answers only the capability question shared by those surfaces.
pub(crate) async fn ids_with_capability_preloaded_on(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_ids: Vec<String>,
    required: Capability,
    include_initial_tombstone: bool,
) -> Result<Vec<String>> {
    let capabilities = effective_capabilities_preloaded_on(
        transaction,
        principal,
        &record_ids,
        include_initial_tombstone,
    )
    .await?;
    Ok(record_ids
        .into_iter()
        .filter(|record_id| {
            capabilities
                .get(record_id)
                .copied()
                .flatten()
                .is_some_and(|actual| actual.allows(required))
        })
        .collect())
}

/// Canonical caller-relative authorization over an already admitted shared
/// domain executor. Attachment transactions use this seam so parent liveness,
/// policy evaluation, blob insertion and publication cannot cross snapshots.
pub(crate) async fn allows_record_with<E: DomainStatementExecutor>(
    state: &mut E,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
) -> Result<bool> {
    allows_record_memoized(
        state,
        &mut BearerTargetMemo::default(),
        principal,
        record_id,
        required,
    )
    .await
}

/// [`allows_record_with`] with a caller-owned bearer-walk memo, for surfaces
/// that authorize a whole record set against one snapshot. The decision is
/// unchanged; only the repeated suffix walks are elided.
pub(crate) async fn allows_record_memoized<E: DomainStatementExecutor>(
    state: &mut E,
    memo: &mut BearerTargetMemo,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
) -> Result<bool> {
    if principal.trusted_local_bypass {
        // `include_initial_tombstone` is true here, so the memo deliberately
        // does not retain this walk's origin.
        return Ok(
            validate_authorization_shape_memoized(state, memo, record_id, true)
                .await
                .is_ok(),
        );
    }
    Ok(matches!(
        effective_capability_memoized(state, memo, principal, record_id, false).await,
        Ok(actual) if actual.allows(required)
    ))
}

/// Whether one record resolves to the governed attribution identity through
/// the same portable snapshot used for authorization.
///
/// Attribution records are bearer-authorized aggregates rather than ordinary
/// records. Argument-prefix resolution must therefore exclude them before it
/// asks whether the caller can view a candidate; otherwise an attribution id
/// could be discovered through a general-purpose record affordance. Resolving
/// the stored kind through the governed vocabulary preserves historical
/// aliases and active-status semantics on every substrate.
pub(crate) async fn is_attribution_record_with<E: DomainStatementExecutor>(
    state: &mut E,
    record_id: &str,
) -> Result<bool> {
    let Some(record) = authorization_record(state, record_id).await? else {
        return Ok(false);
    };
    if record.record_type != "Annotation" {
        return Ok(false);
    }
    let Some(kind) = record.kind.as_deref() else {
        return Ok(false);
    };
    let resolution = crate::meta::kind::resolve_with(state, "Annotation", kind).await?;
    Ok(crate::meta::kind::matches_identity(
        &resolution,
        "Annotation",
        "vv:voc:kind:Annotation:attribution",
    ))
}

async fn policy_capability_with<E: DomainStatementExecutor>(
    state: &mut E,
    principal: Principal<'_>,
    requested_record_id: &str,
    authorization_target: &str,
) -> Result<Capability> {
    let record = authorization_record(state, authorization_target)
        .await?
        .ok_or_else(|| Error::engine(format!("record '{requested_record_id}' not found")))?;
    let anchor = record.policy_anchor_id.ok_or_else(|| {
        Error::engine(format!(
            "record '{authorization_target}' has no effective policy anchor"
        ))
    })?;
    if !has_explicit_policy(state, &anchor).await? {
        return Err(Error::engine(format!(
            "record '{requested_record_id}' points to non-explicit policy anchor '{anchor}'"
        )));
    }

    let entries = authorization_policy_entries(state, &anchor, false).await?;
    let evaluation_entries = entries
        .iter()
        .map(|entry| PolicyEvaluationEntry {
            subject_kind: &entry.subject_kind,
            subject_id: &entry.subject_id,
            effect: &entry.effect,
            capability: &entry.capability,
        })
        .collect::<Vec<_>>();
    let policy_capability = evaluate_policy_grants(
        PolicyEvaluationPrincipal::new(principal.account_id, principal.is_member),
        &evaluation_entries,
    )
    .map_err(|error| match error {
        PolicyEvaluationError::UnsupportedEffect(effect) => Error::engine(format!(
            "policy '{anchor}' contains unsupported effect '{effect}'"
        )),
        PolicyEvaluationError::UnsupportedSubjectKind(subject_kind) => Error::engine(format!(
            "policy '{anchor}' contains unsupported subject kind '{subject_kind}'"
        )),
        PolicyEvaluationError::UnsupportedCapability(capability) => {
            Error::engine(format!("unsupported policy capability '{capability}'"))
        }
    })?;
    let owner_matches = if let (Some(account_id), Some(owner_id)) =
        (principal.account_id, record.owner_id.as_deref())
    {
        owner_bound_to_account(state, owner_id, account_id).await?
    } else {
        false
    };
    Ok(resolve_effective_capability(
        policy_capability,
        owner_matches,
    ))
}

/// Snapshot the explicit entries at a record's current effective policy
/// boundary. This is used only when a new semantic Unit envelope is created so
/// its independent policy starts no more permissive or restrictive than the
/// source artefact. Current access still intersects the source bearer forever.
pub(crate) async fn effective_policy_entries_on(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
) -> Result<Vec<AllowEntry>> {
    let mut state = BorrowedSqliteStatementExecutor::new(transaction);
    let target = authorization_target_with(&mut state, record_id, false).await?;
    let target_state = authorization_record(&mut state, &target)
        .await?
        .filter(|record| !record.deleted)
        .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
    let anchor = target_state
        .policy_anchor_id
        .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
    let rows = authorization_policy_entries(&mut state, &anchor, true).await?;
    let mut entries = Vec::with_capacity(rows.len());
    for entry in rows {
        if entry.effect != "allow" {
            return Err(Error::engine(format!(
                "policy '{anchor}' contains unsupported effect '{}'",
                entry.effect
            )));
        }
        let capability = parse_capability(&entry.capability)?;
        let subject = match entry.subject_kind.as_str() {
            "members" if entry.subject_id == MEMBERS_SUBJECT_ID => PolicySubject::Members,
            "account" => PolicySubject::Account(entry.subject_id),
            other => {
                return Err(Error::engine(format!(
                    "policy '{anchor}' contains unsupported subject kind '{other}'"
                )))
            }
        };
        entries.push(AllowEntry {
            subject,
            capability,
        });
    }
    Ok(entries)
}

/// Resolve the record whose policy governs an ordinary authorization check.
/// All annotations and attachment documents are derived artifacts: they inherit
/// through exactly one outgoing `part_of` bearer. Each bearer may itself be a
/// derived artifact, so resolve recursively while rejecting malformed,
/// bearerless, multi-bearer, dead-bearer, and cyclic shapes.
async fn authorization_target_on_inner(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<String> {
    let mut state = BorrowedSqliteStatementExecutor::new(transaction);
    authorization_target_with(&mut state, record_id, include_initial_tombstone).await
}

/// Resolved suffixes of the derived-artifact bearer walk, valid for exactly
/// one immutable snapshot.
///
/// Every derived artifact has *exactly one* outgoing `part_of` edge (any other
/// count fails closed), so a bearer chain is a single deterministic path and
/// every record on it shares one terminal. Resolving each record from scratch
/// therefore re-walks the same suffix over and over: for a chain of D edges
/// that is O(D^2) statements, and the surfaces that resolve a whole record set
/// in one request pay it per record. Caching `(terminal, edges remaining)`
/// makes a resolved record O(1) on every later lookup while leaving the
/// canonical rule — including the [`MAX_DERIVED_BEARER_DEPTH`] ceiling, which
/// is re-checked against the cached distance — exactly where it was.
///
/// Only failure-free resolutions are memoized, and a record resolved under the
/// origin-specific tombstone allowance is evicted rather than cached, so a
/// tombstoned origin can never be served to an ordinary lookup. A memo must
/// never outlive the snapshot it was populated from.
#[derive(Default)]
pub(crate) struct BearerTargetMemo {
    resolved: HashMap<String, (String, usize)>,
}

async fn authorization_target_with<E: DomainStatementExecutor>(
    state: &mut E,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<String> {
    authorization_target_memoized(
        state,
        &mut BearerTargetMemo::default(),
        record_id,
        include_initial_tombstone,
    )
    .await
}

async fn authorization_target_memoized<E: DomainStatementExecutor>(
    state: &mut E,
    memo: &mut BearerTargetMemo,
    record_id: &str,
    include_initial_tombstone: bool,
) -> Result<String> {
    let mut current = record_id.to_string();
    let mut first = true;
    let mut depth = 0usize;
    let mut seen = HashSet::new();
    // Records walked before the terminal was known, nearest-origin first.
    let mut pending: Vec<String> = Vec::new();
    let (target, mut distance) = loop {
        // Reading is always sound: a memo entry only ever describes a live
        // record, and the tombstone allowance can only relax that.
        if let Some((target, distance)) = memo.resolved.get(&current) {
            break (target.clone(), *distance);
        }
        if !seen.insert(current.clone()) {
            return Err(Error::engine(format!(
                "record '{record_id}' has a cyclic authorization bearer"
            )));
        }
        let record = authorization_record(state, &current)
            .await?
            .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
        if record.deleted && !(first && include_initial_tombstone) {
            return Err(Error::engine(format!("record '{record_id}' not found")));
        }
        let derived = record.record_type == "Annotation"
            || (record.record_type == "Document" && record.kind.as_deref() == Some("attachment"));
        if !derived {
            break (current.clone(), 0);
        }
        if depth >= MAX_DERIVED_BEARER_DEPTH {
            return Err(Error::engine(format!(
                "record '{record_id}' authorization bearer exceeds the {MAX_DERIVED_BEARER_DEPTH}-edge limit"
            )));
        }
        let bearers = derived_bearers(state, &current).await?;
        if bearers.len() != 1 {
            return Err(Error::engine(format!(
                "record '{record_id}' has an invalid authorization bearer"
            )));
        }
        pending.push(std::mem::replace(&mut current, bearers[0].clone()));
        depth += 1;
        first = false;
    };
    // A memo hit can carry the chain past the ceiling that the loop above
    // would otherwise have caught one edge at a time. Re-check it here so a
    // cached suffix can never widen visibility.
    if distance + pending.len() > MAX_DERIVED_BEARER_DEPTH {
        return Err(Error::engine(format!(
            "record '{record_id}' authorization bearer exceeds the {MAX_DERIVED_BEARER_DEPTH}-edge limit"
        )));
    }
    memo.resolved
        .entry(target.clone())
        .or_insert_with(|| (target.clone(), 0));
    for id in pending.into_iter().rev() {
        distance += 1;
        memo.resolved.insert(id, (target.clone(), distance));
    }
    // Every record on the chain except the origin was required to be live, so
    // only the origin can have been admitted by the tombstone allowance. Drop
    // it rather than reason about which case applied.
    if include_initial_tombstone {
        memo.resolved.remove(record_id);
    }
    Ok(target)
}

/// Resolve the ordinary bearer used by the caller-visible SQL projection.
///
/// The projection separately excludes semantic Units (and artifacts resolving
/// to them), so this intentionally returns the first ordinary authorization
/// target rather than walking Unit authority edges.
#[cfg(feature = "turso-local")]
pub(crate) async fn query_sql_authorization_subject_memoized<E: DomainStatementExecutor>(
    state: &mut E,
    memo: &mut BearerTargetMemo,
    record_id: &str,
) -> Result<String> {
    authorization_target_memoized(state, memo, record_id, false).await
}

pub async fn require_capability(
    db: &Db,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    let actual = effective_capability(db, principal, record_id).await?;
    if actual.allows(required) {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "record '{record_id}' requires {required:?}; caller has {actual:?}"
        )))
    }
}

/// Transaction-scoped counterpart to [`require_capability`].
pub async fn require_capability_on(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
) -> Result<()> {
    let actual = effective_capability_on(transaction, principal, record_id).await?;
    if actual.allows(required) {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "record '{record_id}' requires {required:?}; caller has {actual:?}"
        )))
    }
}

pub async fn policy_mode(db: &Db, record_id: &str) -> Result<PolicyMode> {
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM record_policies WHERE record_id = r.id)
           FROM records r WHERE r.id = ?",
    )
    .bind(record_id)
    .fetch_optional(db.write_pool())
    .await?;
    match row {
        Some(0) => Ok(PolicyMode::Inherit),
        Some(_) => Ok(PolicyMode::Explicit),
        None => Err(Error::engine(format!("record '{record_id}' not found"))),
    }
}

pub(crate) fn normalize_entries(
    entries: Vec<AllowEntry>,
) -> Result<Vec<crate::policy::NormalizedPolicyEntry>> {
    native_policy_kernel::normalize_entries(entries)
        .map_err(|error| Error::engine(error.to_string()))
}

/// Install or replace a complete explicit policy, then repoint the inheriting
/// subtree. Existing entries at this boundary are replaced atomically.
pub async fn replace_explicit_policy(
    db: &Db,
    actor: &str,
    record_id: &str,
    entries: Vec<AllowEntry>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    replace_explicit_policy_on(&mut tx, actor, record_id, entries).await?;
    db.commit_authorization(tx).await?;
    Ok(())
}

/// Transaction-scoped policy replacement for callers composing policy changes
/// with another protected write. The event and both projections land in this
/// transaction; the caller owns rollback or an authorization-aware commit
/// (`Db::commit_content` when content also changed, otherwise
/// `Db::commit_authorization`) so realtime readers are woken after durability.
pub async fn replace_explicit_policy_on(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    record_id: &str,
    entries: Vec<AllowEntry>,
) -> Result<()> {
    replace_explicit_policy_on_with_reason(
        tx,
        actor,
        record_id,
        entries,
        "policy replacement through the engine API",
    )
    .await?;
    Ok(())
}

/// Reason-bearing policy replacement used by public authoring surfaces.
pub(crate) async fn replace_explicit_policy_on_with_reason(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    record_id: &str,
    entries: Vec<AllowEntry>,
    reason: &str,
) -> Result<crate::policy::PolicyEventRow> {
    crate::policy::validate_authored_actor(actor)?;
    let entries = normalize_entries(entries)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id = ? AND deleted_at IS NULL)",
    )
    .bind(record_id)
    .fetch_one(&mut **tx)
    .await?;
    if !exists {
        return Err(Error::engine(format!(
            "record '{record_id}' not found or is deleted"
        )));
    }
    let event = crate::policy::append_replaced_in(tx, record_id, entries, actor, reason).await?;
    refresh_policy_anchor_subtree(tx, record_id).await?;
    Ok(event)
}

/// Remove a replacement boundary. The canonical root cannot inherit because
/// every independently rooted tree must terminate at an explicit policy.
pub async fn restore_inheritance(db: &Db, actor: &str, record_id: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    restore_inheritance_on(&mut tx, actor, record_id).await?;
    db.commit_authorization(tx).await?;
    Ok(())
}

/// Transaction-scoped inheritance restoration. As with
/// [`replace_explicit_policy_on`], the owner must finish a successful mutation
/// with an authorization-aware `Db` commit helper.
pub async fn restore_inheritance_on(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    record_id: &str,
) -> Result<()> {
    restore_inheritance_on_with_reason(
        tx,
        actor,
        record_id,
        "inheritance restoration through the engine API",
    )
    .await?;
    Ok(())
}

/// Reason-bearing inheritance restoration used by public authoring surfaces.
pub(crate) async fn restore_inheritance_on_with_reason(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    record_id: &str,
    reason: &str,
) -> Result<crate::policy::PolicyEventRow> {
    crate::policy::validate_authored_actor(actor)?;
    if record_id == ROOT_RECORD_ID {
        return Err(Error::engine("the canonical root policy cannot inherit"));
    }
    let state: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM record_policies WHERE record_id = r.id)
           FROM records r WHERE r.id = ? AND r.deleted_at IS NULL",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(explicit) = state else {
        return Err(Error::engine(format!(
            "record '{record_id}' not found or is deleted"
        )));
    };
    if !explicit {
        return Err(Error::engine(format!(
            "record '{record_id}' does not have an explicit policy"
        )));
    }
    let event = crate::policy::append_inheritance_restored_in(tx, record_id, actor, reason).await?;
    refresh_policy_anchor_subtree(tx, record_id).await?;
    Ok(event)
}

/// Recompute only derived anchor pointers. Explicit descendants remain
/// boundaries and grants are never copied.
///
/// The existence probe and the rewrite below are two statements and are only
/// coherent inside the caller's write transaction. Every current caller passes
/// a connection already inside one; a future caller that handed this a pooled
/// connection outside a transaction would race a concurrent delete between the
/// probe and the update and silently refresh nothing.
pub(crate) async fn refresh_policy_anchor_subtree(
    connection: &mut SqliteConnection,
    record_id: &str,
) -> Result<()> {
    // Existence is asked separately because the rewrite below deliberately
    // skips rows whose anchor is already correct, so "no rows were written" is
    // the ordinary case and can no longer stand in for "no such record".
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id = ?)")
        .bind(record_id)
        .fetch_one(&mut *connection)
        .await?;
    if !exists {
        return Err(Error::engine(format!("record '{record_id}' not found")));
    }
    // Only rows whose derived anchor actually moves are written. Rewriting an
    // unchanged `policy_anchor_id` was invisible to readers but not to SQLite:
    // it advanced the database-wide authorization epoch once per subtree row,
    // so re-anchoring a large folder told every subscriber to re-read for a
    // change that had not happened.
    sqlx::query(
        "WITH RECURSIVE descendants(id, anchor_id) AS (
           SELECT r.id,
                  CASE WHEN own.record_id IS NOT NULL THEN r.id
                       ELSE parent.policy_anchor_id END
             FROM records r
             LEFT JOIN record_policies own ON own.record_id = r.id
             LEFT JOIN records parent ON parent.id = r.home_id
            WHERE r.id = ?
           UNION ALL
           SELECT child.id,
                  CASE WHEN own.record_id IS NOT NULL THEN child.id
                       ELSE descendants.anchor_id END
             FROM records child
             JOIN descendants ON child.home_id = descendants.id
             LEFT JOIN record_policies own ON own.record_id = child.id
         )
         UPDATE records
            SET policy_anchor_id = (
                SELECT anchor_id FROM descendants WHERE descendants.id = records.id
            )
          WHERE id IN (
                SELECT descendants.id FROM descendants
                  JOIN records current ON current.id = descendants.id
                 WHERE current.policy_anchor_id IS NOT descendants.anchor_id
          )",
    )
    .bind(record_id)
    .execute(&mut *connection)
    .await?;
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records
          WHERE id IN (
            WITH RECURSIVE subtree(id) AS (
              SELECT ? UNION ALL SELECT r.id FROM records r JOIN subtree s ON r.home_id = s.id
            ) SELECT id FROM subtree
          ) AND policy_anchor_id IS NULL",
    )
    .bind(record_id)
    .fetch_one(&mut *connection)
    .await?;
    if missing != 0 {
        return Err(Error::engine(format!(
            "policy inheritance from '{record_id}' does not terminate at an explicit boundary"
        )));
    }
    Ok(())
}

/// Validate authored policy rows and the derived nearest-anchor index. This is
/// used both by conformance and by ordinary database open so malformed imported
/// state fails closed before any content surface is served.
pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut snapshot = db.write_pool().begin().await?;
    let violations = state_violations_on(&mut snapshot).await?;
    snapshot.rollback().await?;
    Ok(violations)
}

/// Validate authorization state against one coherent caller-owned snapshot.
/// This transaction-only core prevents records, authored policies, entries,
/// and derived anchors from being observed at different commits.
pub async fn state_violations_on(transaction: &mut Transaction<'_, Sqlite>) -> Result<Vec<String>> {
    let records = sqlx::query("SELECT id, home_id, policy_anchor_id FROM records")
        .fetch_all(&mut **transaction)
        .await?;
    let policies: HashSet<String> = sqlx::query_scalar("SELECT record_id FROM record_policies")
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .collect();
    let mut parents = HashMap::new();
    let mut stored = HashMap::new();
    for row in records {
        let id: String = row.try_get("id")?;
        parents.insert(id.clone(), row.try_get::<Option<String>, _>("home_id")?);
        stored.insert(id, row.try_get::<Option<String>, _>("policy_anchor_id")?);
    }
    let mut violations = Vec::new();
    for id in parents.keys() {
        let mut cursor = Some(id.as_str());
        let mut seen = HashSet::new();
        let mut expected = None;
        while let Some(candidate) = cursor {
            if !seen.insert(candidate.to_string()) {
                violations.push(format!("record '{id}' has a containment cycle"));
                break;
            }
            if policies.contains(candidate) {
                expected = Some(candidate.to_string());
                break;
            }
            cursor = parents.get(candidate).and_then(|parent| parent.as_deref());
        }
        match (stored.get(id).and_then(Clone::clone), expected) {
            (None, _) => violations.push(format!("record '{id}' has a NULL policy anchor")),
            (Some(actual), Some(expected)) if actual != expected => violations.push(format!(
                "record '{id}' anchors at '{actual}', expected nearest explicit '{expected}'"
            )),
            (Some(actual), None) => violations.push(format!(
                "record '{id}' anchors at '{actual}' but inheritance has no explicit boundary"
            )),
            _ => {}
        }
    }
    if !parents.contains_key(ROOT_RECORD_ID) {
        violations.push("canonical root record is missing".into());
    } else if !policies.contains(ROOT_RECORD_ID) {
        violations.push("canonical root has no explicit policy".into());
    }
    for policy in &policies {
        if !parents.contains_key(policy) {
            violations.push(format!(
                "explicit policy '{policy}' does not belong to a record"
            ));
        }
    }

    for row in sqlx::query(
        "SELECT policy_anchor_id, subject_kind, subject_id, effect, capability FROM policy_entries",
    )
    .fetch_all(&mut **transaction)
    .await?
    {
        let anchor: String = row.try_get("policy_anchor_id")?;
        let kind: String = row.try_get("subject_kind")?;
        let id: String = row.try_get("subject_id")?;
        let effect: String = row.try_get("effect")?;
        let capability: String = row.try_get("capability")?;
        if !policies.contains(&anchor) {
            violations.push(format!(
                "policy entry references non-policy anchor '{anchor}'"
            ));
        }
        if effect != "allow" {
            violations.push(format!(
                "policy '{anchor}' uses unsupported effect '{effect}'"
            ));
        }
        let valid = match kind.as_str() {
            "members" => id == MEMBERS_SUBJECT_ID && matches!(capability.as_str(), "view" | "edit"),
            "account" => {
                !id.is_empty() && matches!(capability.as_str(), "view" | "edit" | "manage")
            }
            _ => false,
        };
        if !valid {
            violations.push(format!(
                "policy '{anchor}' has unsupported {kind}:{id} allow {capability}"
            ));
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use serde_json::json;
    use sqlx::Row;

    use super::*;
    use crate::db::{create_database, open_existing_database_at};
    use crate::store::{append_in, create_record, delete_record, update_record, AppendSpec};

    // Pinned fixture record ids. The record-id authority admits only canonical
    // v4/v7 UUIDs, so the readable slugs these replace are no longer creatable.
    // Two properties here are load-bearing and preserved by the numbering:
    //
    //   * `NESTED_BOUNDARY_ID` must sort before `NESTED_BOUNDARY_CHILD_ID`,
    //     because the anchor-refresh assertion reads them back `ORDER BY id`.
    //   * `GONE_ID` and the two nested ids are also interpolated verbatim into
    //     SQL literals, so those queries are built from these same constants.
    const ALICE_ID: &str = "a07b0000-0000-4000-8000-000000000001";
    const BEA_ID: &str = "a07b0000-0000-4000-8000-000000000002";
    const TEAM_ID: &str = "a07b0000-0000-4000-8000-000000000003";
    const PRIVATE_ID: &str = "a07b0000-0000-4000-8000-000000000004";
    const PRIVATE_CHILD_ID: &str = "a07b0000-0000-4000-8000-000000000005";
    const BROAD_CHILD_ID: &str = "a07b0000-0000-4000-8000-000000000006";
    const NESTED_BOUNDARY_ID: &str = "a07b0000-0000-4000-8000-000000000007";
    const NESTED_BOUNDARY_CHILD_ID: &str = "a07b0000-0000-4000-8000-000000000008";
    const PROTECTED_ID: &str = "a07b0000-0000-4000-8000-000000000009";
    const GONE_ID: &str = "a07b0000-0000-4000-8000-000000000010";
    const PORTABLE_ID: &str = "a07b0000-0000-4000-8000-000000000011";
    const OWNER_ID: &str = "a07b0000-0000-4000-8000-000000000012";
    const ALLOWED_ID: &str = "a07b0000-0000-4000-8000-000000000013";
    const HIDDEN_ID: &str = "a07b0000-0000-4000-8000-000000000014";
    const OWNED_ID: &str = "a07b0000-0000-4000-8000-000000000015";
    const DERIVED_ID: &str = "a07b0000-0000-4000-8000-000000000016";
    const UNIT_ID: &str = "a07b0000-0000-4000-8000-000000000017";
    const TERMINAL_ID: &str = "a07b0000-0000-4000-8000-000000000018";
    const OTHER_TERMINAL_ID: &str = "a07b0000-0000-4000-8000-000000000019";
    const BEARERLESS_ID: &str = "a07b0000-0000-4000-8000-000000000020";
    const MULTI_BEARER_ID: &str = "a07b0000-0000-4000-8000-000000000021";
    const DEAD_TERMINAL_ID: &str = "a07b0000-0000-4000-8000-000000000022";
    const DEAD_BEARER_ID: &str = "a07b0000-0000-4000-8000-000000000023";
    const DERIVED_CYCLE_A_ID: &str = "a07b0000-0000-4000-8000-000000000024";
    const DERIVED_CYCLE_B_ID: &str = "a07b0000-0000-4000-8000-000000000025";
    const UNIT_CYCLE_A_ID: &str = "a07b0000-0000-4000-8000-000000000026";
    const UNIT_CYCLE_B_ID: &str = "a07b0000-0000-4000-8000-000000000027";
    const INHERITED_ID: &str = "a07b0000-0000-4000-8000-000000000028";

    /// One pinned id per (series, depth) in the derived/unit bearer chains,
    /// which used to be `format!("derived-depth-{depth}")`. Deterministic, and
    /// disjoint from the constants above.
    fn depth_id(series: usize, depth: usize) -> String {
        format!("a07b0000-0000-4000-8000-{series:06}{depth:06}")
    }

    async fn create_account(db: &Db, record_id: &str, token: &str) {
        create_record(
            db,
            json!({
                "id": record_id,
                "type": "Entity",
                "kind": "person",
                "name": record_id,
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(record_id)
        .bind(token)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn create(db: &Db, id: &str, home: &str, owner: Option<&str>) {
        create_record(
            db,
            json!({
                "id": id,
                "type": "Collection",
                "kind": "folder",
                "name": id,
                "home_id": home,
                "owner_id": owner,
            }),
        )
        .await
        .unwrap();
    }

    async fn create_authorization_annotation(db: &Db, id: &str) {
        create_record(
            db,
            json!({
                "id":id,"type":"Annotation","kind":"suggestion","name":id,
                "home_id":ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
    }

    async fn link_authorization_bearer(db: &Db, source: &str, target: &str) {
        crate::store::append(
            db,
            AppendSpec {
                record_id: source.into(),
                event_type: "link.added".into(),
                payload: json!({
                    "source_id":source,"target_id":target,"relationship":"part_of"
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    async fn create_authorization_unit(db: &Db, id: &str) {
        crate::store::append(
            db,
            AppendSpec {
                record_id: id.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Entity","kind":"semantic-unit","name":id,
                    "home_id":ROOT_RECORD_ID
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    async fn bind_authorization_unit(db: &Db, id: &str, bearer: &str) {
        crate::store::append(
            db,
            AppendSpec {
                record_id: id.into(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version":"native.freshness-kernel.v1",
                    "authority_bearer_record_id":bearer,"label":id
                }),
                actor: Some("test:unit".into()),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn replacement_inheritance_owner_floor_and_live_subjects_compose() {
        let db = create_database(":memory:").await.unwrap();
        create_account(&db, ALICE_ID, "acct_alice").await;
        create_account(&db, BEA_ID, "acct_bea").await;
        create(&db, TEAM_ID, ROOT_RECORD_ID, Some(ALICE_ID)).await;
        create(&db, PRIVATE_ID, TEAM_ID, Some(ALICE_ID)).await;
        create(&db, PRIVATE_CHILD_ID, PRIVATE_ID, Some(ALICE_ID)).await;
        create(&db, BROAD_CHILD_ID, PRIVATE_ID, Some(ALICE_ID)).await;
        create(&db, NESTED_BOUNDARY_ID, PRIVATE_ID, Some(ALICE_ID)).await;
        create(
            &db,
            NESTED_BOUNDARY_CHILD_ID,
            NESTED_BOUNDARY_ID,
            Some(ALICE_ID),
        )
        .await;

        // The seeded root baseline is dynamic: the same account gains/loses it
        // solely from the host-supplied current-membership bit.
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", true), TEAM_ID)
                .await
                .unwrap(),
            Capability::Edit
        );
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", false), TEAM_ID)
                .await
                .unwrap(),
            Capability::None
        );
        assert_eq!(
            effective_capability(&db, Principal::unbound(true), ROOT_RECORD_ID)
                .await
                .unwrap(),
            Capability::None,
            "membership cannot authorize an identity without a verified account binding"
        );

        replace_explicit_policy(
            &db,
            "test:policy",
            PRIVATE_ID,
            vec![
                AllowEntry::account("acct_bea", Capability::View),
                AllowEntry::account("acct_bea", Capability::Edit),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            policy_mode(&db, PRIVATE_ID).await.unwrap(),
            PolicyMode::Explicit
        );
        assert_eq!(
            policy_mode(&db, PRIVATE_CHILD_ID).await.unwrap(),
            PolicyMode::Inherit
        );
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", true), PRIVATE_CHILD_ID)
                .await
                .unwrap(),
            Capability::Edit,
            "strongest direct allow wins and parent/root grants are not unioned"
        );
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", false), PRIVATE_CHILD_ID)
                .await
                .unwrap(),
            Capability::Edit,
            "a direct verified account grant does not depend on current membership"
        );
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_alice", false), PRIVATE_CHILD_ID)
                .await
                .unwrap(),
            Capability::Manage,
            "the record-local owner floor is independent of policy"
        );
        assert_eq!(
            effective_capability(&db, Principal::unbound(true), PRIVATE_CHILD_ID)
                .await
                .unwrap(),
            Capability::None,
            "a dormant direct account grant cannot match an unbound identity"
        );

        // A complete child boundary can be broader than its parent.
        replace_explicit_policy(
            &db,
            "test:policy",
            BROAD_CHILD_ID,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", true), BROAD_CHILD_ID)
                .await
                .unwrap(),
            Capability::View
        );

        replace_explicit_policy(
            &db,
            "test:policy",
            NESTED_BOUNDARY_ID,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();

        // Replacing and moving ancestors cannot pierce a descendant's complete
        // replacement boundary or rewrite its authored policy.
        replace_explicit_policy(&db, "test:policy", PRIVATE_ID, vec![])
            .await
            .unwrap();
        update_record(&db, PRIVATE_ID, json!({ "home_id": ROOT_RECORD_ID }))
            .await
            .unwrap();
        let nested_anchors: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT id, policy_anchor_id FROM records
              WHERE id IN ('{NESTED_BOUNDARY_ID}', '{NESTED_BOUNDARY_CHILD_ID}') ORDER BY id"
        ))
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            nested_anchors,
            vec![
                (NESTED_BOUNDARY_ID.into(), NESTED_BOUNDARY_ID.into()),
                (NESTED_BOUNDARY_CHILD_ID.into(), NESTED_BOUNDARY_ID.into()),
            ],
            "moving an ancestor subtree must stop anchor refresh at its nearer explicit descendant"
        );
        assert_eq!(
            effective_capability(
                &db,
                Principal::bound("acct_bea", true),
                NESTED_BOUNDARY_CHILD_ID,
            )
            .await
            .unwrap(),
            Capability::View,
            "the explicit descendant's authored policy survives its ancestor move"
        );

        update_record(&db, BROAD_CHILD_ID, json!({ "home_id": ROOT_RECORD_ID }))
            .await
            .unwrap();
        let explicit_anchor: String =
            sqlx::query("SELECT policy_anchor_id FROM records WHERE id = ?")
                .bind(BROAD_CHILD_ID)
                .fetch_one(db.write_pool())
                .await
                .unwrap()
                .try_get("policy_anchor_id")
                .unwrap();
        assert_eq!(explicit_anchor, BROAD_CHILD_ID);
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", true), BROAD_CHILD_ID)
                .await
                .unwrap(),
            Capability::View
        );

        restore_inheritance(&db, "test:policy", BROAD_CHILD_ID)
            .await
            .unwrap();
        let anchor: String = sqlx::query("SELECT policy_anchor_id FROM records WHERE id = ?")
            .bind(BROAD_CHILD_ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap()
            .try_get("policy_anchor_id")
            .unwrap();
        assert_eq!(anchor, ROOT_RECORD_ID);

        // Reparenting an inherited subtree changes only its anchor pointer.
        update_record(&db, PRIVATE_CHILD_ID, json!({ "home_id": ROOT_RECORD_ID }))
            .await
            .unwrap();
        assert_eq!(
            effective_capability(&db, Principal::bound("acct_bea", true), PRIVATE_CHILD_ID)
                .await
                .unwrap(),
            Capability::Edit
        );
        assert!(state_violations(&db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn capability_check_and_protected_mutation_share_one_transaction() {
        let db = create_database(":memory:").await.unwrap();
        create(&db, PROTECTED_ID, ROOT_RECORD_ID, None).await;
        replace_explicit_policy(
            &db,
            "test:policy",
            PROTECTED_ID,
            vec![AllowEntry::account("acct_writer", Capability::Edit)],
        )
        .await
        .unwrap();

        let mut tx = begin_write(db.write_pool()).await.unwrap();
        require_capability_on(
            &mut tx,
            Principal::bound("acct_writer", false),
            PROTECTED_ID,
            Capability::Edit,
        )
        .await
        .unwrap();
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: PROTECTED_ID.into(),
                event_type: "record.updated".into(),
                payload: json!({ "summary": "authorized atomically" }),
                actor: Some("acct_writer".into()),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let summary: String = sqlx::query_scalar("SELECT summary FROM records WHERE id = ?")
            .bind(PROTECTED_ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(summary, "authorized atomically");
    }

    #[tokio::test]
    async fn deleted_records_reject_policy_mutation_without_losing_authored_state() {
        let db = create_database(":memory:").await.unwrap();
        create(&db, GONE_ID, ROOT_RECORD_ID, None).await;
        replace_explicit_policy(
            &db,
            "test:policy",
            GONE_ID,
            vec![AllowEntry::account("acct_reader", Capability::View)],
        )
        .await
        .unwrap();
        delete_record(&db, GONE_ID).await.unwrap();

        let replace_err = replace_explicit_policy(&db, "test:policy", GONE_ID, vec![])
            .await
            .unwrap_err();
        assert!(replace_err.to_string().contains("deleted"));
        let restore_err = restore_inheritance(&db, "test:policy", GONE_ID)
            .await
            .unwrap_err();
        assert!(restore_err.to_string().contains("deleted"));

        let entry_count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id = '{GONE_ID}'"
        ))
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(entry_count, 1, "failed mutations must roll back completely");
    }

    #[tokio::test]
    async fn authored_policy_survives_reopen_export_and_content_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("portable-policy.db");
        let db = create_database(&path.to_string_lossy()).await.unwrap();
        create(&db, PORTABLE_ID, ROOT_RECORD_ID, None).await;
        replace_explicit_policy(
            &db,
            "test:policy",
            PORTABLE_ID,
            vec![AllowEntry::account("acct_portable", Capability::Manage)],
        )
        .await
        .unwrap();

        let rebuilt = crate::conformance::rebuild_and_diff(&db).await.unwrap();
        assert!(rebuilt.equal, "content rebuild remains policy-independent");
        let export = crate::export::export_connected_db(&db, Some(dir.path()))
            .await
            .unwrap();
        let exported = open_existing_database_at(&export.path()).await.unwrap();
        assert_eq!(
            effective_capability(
                &exported,
                Principal::bound("acct_portable", false),
                PORTABLE_ID,
            )
            .await
            .unwrap(),
            Capability::Manage
        );
        assert!(crate::conformance::run_conformance(&exported).await.ok);
        exported.close().await;
        export.cleanup().await;

        db.close().await;
        let reopened = open_existing_database_at(&path).await.unwrap();
        assert_eq!(
            effective_capability(
                &reopened,
                Principal::bound("acct_portable", false),
                PORTABLE_ID,
            )
            .await
            .unwrap(),
            Capability::Manage
        );
        assert!(state_violations(&reopened).await.unwrap().is_empty());
        reopened.close().await;
    }

    #[tokio::test]
    async fn policy_shape_rejects_v1_groups_limits_and_members_manage() {
        let db = create_database(":memory:").await.unwrap();
        let err = replace_explicit_policy(
            &db,
            "test:policy",
            ROOT_RECORD_ID,
            vec![AllowEntry::members(Capability::Manage)],
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("members baseline cannot grant manage"));

        for (kind, effect) in [("group", "allow"), ("account", "limit")] {
            let result = sqlx::query(
                "INSERT INTO policy_entries
                    (policy_anchor_id, subject_kind, subject_id, effect, capability)
                 VALUES (?, ?, 'future-subject', ?, 'view')",
            )
            .bind(ROOT_RECORD_ID)
            .bind(kind)
            .bind(effect)
            .execute(db.write_pool())
            .await;
            assert!(
                result.is_err(),
                "{kind}/{effect} must remain disabled in v1"
            );
        }
    }

    /// The epoch is a cache fence over authorization inputs, and every hosted
    /// subscriber is told to re-read whenever it moves. It must therefore
    /// follow changes to those inputs, not writes that merely mention them:
    /// before engine 46 an ordinary body edit advanced it, because the
    /// projector named all twelve updatable columns in SET and SQLite's
    /// `AFTER UPDATE OF` fires on named columns.
    #[tokio::test]
    async fn the_epoch_follows_authorization_changes_not_ordinary_edits() {
        let db = create_database(":memory:").await.unwrap();
        create_account(&db, ALICE_ID, "acct_alice").await;
        create_account(&db, BEA_ID, "acct_bea").await;
        create(&db, TEAM_ID, ROOT_RECORD_ID, Some(ALICE_ID)).await;
        create(&db, PRIVATE_ID, TEAM_ID, Some(ALICE_ID)).await;
        create(&db, PRIVATE_CHILD_ID, PRIVATE_ID, Some(ALICE_ID)).await;

        let quiet = authorization_revision(&db).await.unwrap();
        for fields in [
            json!({ "name": "renamed" }),
            json!({ "body": "a longer body than before" }),
            json!({ "summary": "a summary" }),
            json!({ "name": "renamed again", "body": "and edited again" }),
            // Re-asserting the values a record already holds is still an
            // ordinary edit: nothing about its authorization moved.
            json!({ "owner_id": ALICE_ID, "kind": "folder" }),
        ] {
            update_record(&db, PRIVATE_ID, fields.clone())
                .await
                .unwrap();
            assert_eq!(
                authorization_revision(&db).await.unwrap(),
                quiet,
                "{fields} advanced the authorization epoch"
            );
        }

        // Re-anchoring a subtree whose anchors are all already correct writes
        // nothing, so it is silent as well.
        let mut connection = db.write_pool().acquire().await.unwrap();
        refresh_policy_anchor_subtree(&mut connection, ROOT_RECORD_ID)
            .await
            .unwrap();
        drop(connection);
        assert_eq!(authorization_revision(&db).await.unwrap(), quiet);

        // A real change to any authorization input still moves the fence.
        let mut expected = quiet;
        for (label, fields) in [
            ("owner", json!({ "owner_id": BEA_ID })),
            ("kind", json!({ "kind": "workspace" })),
        ] {
            update_record(&db, PRIVATE_CHILD_ID, fields).await.unwrap();
            let observed = authorization_revision(&db).await.unwrap();
            assert!(
                observed > expected,
                "{label} must advance the authorization epoch"
            );
            expected = observed;
        }

        // A derived anchor that genuinely moves must still be published. Give
        // the parent an explicit policy so the child anchors to it, then move
        // the child out from under that boundary.
        replace_explicit_policy(
            &db,
            "test:epoch",
            PRIVATE_ID,
            vec![AllowEntry::account("acct_alice", Capability::Edit)],
        )
        .await
        .unwrap();
        let anchored = authorization_revision(&db).await.unwrap();
        assert!(anchored > expected);
        update_record(&db, PRIVATE_CHILD_ID, json!({ "home_id": ROOT_RECORD_ID }))
            .await
            .unwrap();
        let replaced = authorization_revision(&db).await.unwrap();
        assert!(
            replaced > anchored,
            "a derived anchor move must advance the authorization epoch"
        );

        delete_record(&db, PRIVATE_CHILD_ID).await.unwrap();
        assert!(
            authorization_revision(&db).await.unwrap() > replaced,
            "deletion must advance the authorization epoch"
        );
        db.close().await;
    }

    /// Hosted clients treat the authorization frame as their acknowledgement
    /// that a policy write landed, so a policy operation that happens to write
    /// no projection row must still advance the fence or the caller waits for
    /// a frame that never comes. Re-asserting an identical empty explicit
    /// policy is exactly that: `INSERT OR IGNORE` suppresses the
    /// `record_policies` trigger, the entry DELETE and re-INSERT touch no rows,
    /// and the narrowed anchor refresh writes nothing.
    #[tokio::test]
    async fn a_repeated_policy_operation_is_acknowledged_even_when_it_writes_nothing() {
        let db = create_database(":memory:").await.unwrap();
        create_account(&db, ALICE_ID, "acct_alice").await;
        create(&db, TEAM_ID, ROOT_RECORD_ID, Some(ALICE_ID)).await;

        replace_explicit_policy(&db, "test:ack", TEAM_ID, vec![])
            .await
            .unwrap();
        let mut expected = authorization_revision(&db).await.unwrap();
        for repeat in 0..3 {
            replace_explicit_policy(&db, "test:ack", TEAM_ID, vec![])
                .await
                .unwrap();
            let observed = authorization_revision(&db).await.unwrap();
            assert!(
                observed > expected,
                "repeat {repeat} of an identical empty policy must still be acknowledged"
            );
            expected = observed;
        }

        // Restoring inheritance does write, but is acknowledged by the same
        // rule rather than by whichever trigger happens to catch it.
        restore_inheritance(&db, "test:ack", TEAM_ID).await.unwrap();
        assert!(authorization_revision(&db).await.unwrap() > expected);
        db.close().await;
    }

    #[tokio::test]
    async fn malformed_anchor_state_fails_closed() {
        let db = create_database(":memory:").await.unwrap();
        sqlx::query("UPDATE records SET policy_anchor_id = NULL WHERE id = ?")
            .bind(crate::schema::UNFILED_RECORD_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let violations = state_violations(&db).await.unwrap();
        assert!(violations.iter().any(|v| v.contains("NULL policy anchor")));
        let err = effective_capability(
            &db,
            Principal::bound("someone", true),
            crate::schema::UNFILED_RECORD_ID,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no effective policy anchor"));
    }

    #[tokio::test]
    async fn state_validation_core_observes_one_transaction_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        sqlx::query("UPDATE records SET policy_anchor_id = NULL WHERE id = ?")
            .bind(crate::schema::UNFILED_RECORD_ID)
            .execute(&mut *tx)
            .await
            .unwrap();

        let violations = state_violations_on(&mut tx).await.unwrap();
        assert!(violations.iter().any(|v| v.contains("NULL policy anchor")));
        tx.rollback().await.unwrap();

        assert!(
            state_violations(&db).await.unwrap().is_empty(),
            "the public validator opens its own coherent snapshot and the rolled-back corruption is absent"
        );
    }

    #[tokio::test]
    async fn preloaded_authorization_is_exactly_scalar_for_inherited_derived_unit_owner_and_policy()
    {
        let db = create_database(":memory:").await.unwrap();
        create_account(&db, OWNER_ID, "acct_owner").await;
        create(&db, ALLOWED_ID, ROOT_RECORD_ID, None).await;
        create(&db, HIDDEN_ID, ROOT_RECORD_ID, None).await;
        create(&db, OWNED_ID, ROOT_RECORD_ID, Some(OWNER_ID)).await;
        replace_explicit_policy(
            &db,
            "test:policy",
            ALLOWED_ID,
            vec![AllowEntry::account("acct_reader", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:policy", HIDDEN_ID, vec![])
            .await
            .unwrap();
        create(&db, INHERITED_ID, ALLOWED_ID, None).await;
        crate::store::create_record(
            &db,
            json!({
                "id":DERIVED_ID,"type":"Annotation","kind":"suggestion",
                "name":DERIVED_ID,"home_id":ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        crate::store::append(
            &db,
            AppendSpec {
                record_id: DERIVED_ID.into(),
                event_type: "link.added".into(),
                payload: json!({
                    "source_id":DERIVED_ID,"target_id":ALLOWED_ID,"relationship":"part_of"
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        crate::store::append(
            &db,
            AppendSpec {
                record_id: UNIT_ID.into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Entity","kind":"semantic-unit",
                    "name":UNIT_ID,"home_id":ROOT_RECORD_ID
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        crate::store::append(
            &db,
            AppendSpec {
                record_id: UNIT_ID.into(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version":"native.freshness-kernel.v1",
                    "authority_bearer_record_id":ALLOWED_ID,"label":"Unit"
                }),
                actor: Some("test:unit".into()),
            },
        )
        .await
        .unwrap();

        let ids = [
            ALLOWED_ID,
            INHERITED_ID,
            HIDDEN_ID,
            OWNED_ID,
            DERIVED_ID,
            UNIT_ID,
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
        for principal in [
            Principal::bound("acct_reader", true),
            Principal::bound("acct_owner", false),
            Principal::trusted_local(),
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            let bulk = effective_capabilities_preloaded_on(&mut tx, principal, &ids, false)
                .await
                .unwrap();
            let mut scalar_visible = Vec::new();
            for id in &ids {
                let scalar = effective_capability_on(&mut tx, principal, id).await.ok();
                assert_eq!(bulk.get(id).copied().flatten(), scalar, "{id}");
                if scalar.is_some_and(|capability| capability.allows(Capability::View)) {
                    scalar_visible.push(id.clone());
                }
            }
            let bulk_visible = ids_with_capability_preloaded_on(
                &mut tx,
                principal,
                ids.clone(),
                Capability::View,
                false,
            )
            .await
            .unwrap();
            assert_eq!(bulk_visible, scalar_visible);
            tx.rollback().await.unwrap();
        }
    }

    unsafe extern "C" fn count_traced_statements(
        _event: u32,
        context: *mut c_void,
        _statement: *mut c_void,
        _sql: *mut c_void,
    ) -> i32 {
        // SAFETY: the trace is cleared before the boxed counter is dropped,
        // and `lock_handle` prevents concurrent use of this SQLite handle
        // while the callback is installed or removed.
        let counter = unsafe { &*context.cast::<AtomicUsize>() };
        counter.fetch_add(1, Ordering::Relaxed);
        0
    }

    async fn traced_preloaded_view_ids(
        db: &Db,
        ids: Vec<String>,
    ) -> (Vec<String>, usize, Duration) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let statements = Box::new(AtomicUsize::new(0));
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: the boxed context has a stable address and remains alive
            // until the callback is explicitly cleared below.
            let status = unsafe {
                libsqlite3_sys::sqlite3_trace_v2(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_TRACE_STMT as u32,
                    Some(count_traced_statements),
                    (&*statements as *const AtomicUsize).cast_mut().cast(),
                )
            };
            assert_eq!(status, libsqlite3_sys::SQLITE_OK);
        }
        let started = Instant::now();
        let result = ids_with_capability_preloaded_on(
            &mut tx,
            Principal::bound("acct:benchmark", true),
            ids,
            Capability::View,
            false,
        )
        .await;
        let elapsed = started.elapsed();
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: clearing the callback while holding the connection lock
            // ends SQLite's access to the context before it is dropped.
            unsafe {
                libsqlite3_sys::sqlite3_trace_v2(
                    handle.as_raw_handle().as_ptr(),
                    0,
                    None,
                    std::ptr::null_mut(),
                )
            };
        }
        let statement_count = statements.load(Ordering::Relaxed);
        let result = result.unwrap();
        tx.rollback().await.unwrap();
        (result, statement_count, elapsed)
    }

    async fn traced_scalar_view_ids(db: &Db, ids: &[String]) -> (Vec<String>, usize, Duration) {
        let mut tx = db.write_pool().begin().await.unwrap();
        let statements = Box::new(AtomicUsize::new(0));
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: see `traced_preloaded_view_ids`.
            let status = unsafe {
                libsqlite3_sys::sqlite3_trace_v2(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_TRACE_STMT as u32,
                    Some(count_traced_statements),
                    (&*statements as *const AtomicUsize).cast_mut().cast(),
                )
            };
            assert_eq!(status, libsqlite3_sys::SQLITE_OK);
        }
        let started = Instant::now();
        let mut visible = Vec::new();
        for id in ids {
            if effective_capability_on(&mut tx, Principal::bound("acct:benchmark", true), id)
                .await
                .is_ok_and(|capability| capability.allows(Capability::View))
            {
                visible.push(id.clone());
            }
        }
        let elapsed = started.elapsed();
        {
            let mut handle = tx.lock_handle().await.unwrap();
            // SAFETY: see `traced_preloaded_view_ids`.
            unsafe {
                libsqlite3_sys::sqlite3_trace_v2(
                    handle.as_raw_handle().as_ptr(),
                    0,
                    None,
                    std::ptr::null_mut(),
                )
            };
        }
        let statement_count = statements.load(Ordering::Relaxed);
        tx.rollback().await.unwrap();
        (visible, statement_count, elapsed)
    }

    async fn create_authorization_benchmark_corpus(db: &Db, count: usize) -> Vec<String> {
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let id = format!("ba7c0000-0000-4000-8000-{index:012}");
            sqlx::query(
                "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) \
                 VALUES(?,'Document','note',?,?,?)",
            )
            .bind(&id)
            .bind(&id)
            .bind(ROOT_RECORD_ID)
            .bind(ROOT_RECORD_ID)
            .execute(&mut *tx)
            .await
            .unwrap();
            ids.push(id);
        }
        tx.commit().await.unwrap();
        ids
    }

    #[tokio::test]
    async fn preloaded_authorization_statement_count_is_constant_for_401_records() {
        let db = create_database(":memory:").await.unwrap();
        let ids = create_authorization_benchmark_corpus(&db, 401).await;
        let (one_visible, one_statements, _) =
            traced_preloaded_view_ids(&db, ids[..1].to_vec()).await;
        let (all_visible, all_statements, _) = traced_preloaded_view_ids(&db, ids.clone()).await;

        assert_eq!(one_visible, ids[..1]);
        assert_eq!(all_visible, ids);
        assert_eq!(all_statements, one_statements);
        assert_eq!(all_statements, 5, "the set-wise fold has five set loads");
        db.close().await;
    }

    /// Run with:
    /// `NATIVE_AUTHORIZATION_MEASUREMENT=1 cargo test --release --lib authorization::tests::preloaded_authorization_release_benchmark_401_records -- --nocapture`
    #[tokio::test]
    async fn preloaded_authorization_release_benchmark_401_records() {
        if std::env::var("NATIVE_AUTHORIZATION_MEASUREMENT").as_deref() != Ok("1") {
            return;
        }
        let db = create_database(":memory:").await.unwrap();
        let ids = create_authorization_benchmark_corpus(&db, 401).await;
        let (scalar_visible, scalar_statements, scalar_elapsed) =
            traced_scalar_view_ids(&db, &ids).await;
        let (batch_visible, batch_statements, batch_elapsed) =
            traced_preloaded_view_ids(&db, ids.clone()).await;

        assert_eq!(batch_visible, scalar_visible);
        assert_eq!(batch_visible, ids);
        assert_eq!(batch_statements, 5);
        assert!(
            scalar_statements > batch_statements * 100,
            "the scalar path should retain request-scaled authorization chains"
        );
        eprintln!(
            "401-record authorization: scalar={scalar_elapsed:?} ({scalar_statements} statements), batched={batch_elapsed:?} ({batch_statements} statements)"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn preloaded_authorization_matches_scalar_fail_closed_bearer_shapes() {
        let db = create_database(":memory:").await.unwrap();
        create(&db, TERMINAL_ID, ROOT_RECORD_ID, None).await;
        create(&db, OTHER_TERMINAL_ID, ROOT_RECORD_ID, None).await;

        create_authorization_annotation(&db, BEARERLESS_ID).await;
        create_authorization_annotation(&db, MULTI_BEARER_ID).await;
        link_authorization_bearer(&db, MULTI_BEARER_ID, TERMINAL_ID).await;
        link_authorization_bearer(&db, MULTI_BEARER_ID, OTHER_TERMINAL_ID).await;

        create(&db, DEAD_TERMINAL_ID, ROOT_RECORD_ID, None).await;
        create_authorization_annotation(&db, DEAD_BEARER_ID).await;
        link_authorization_bearer(&db, DEAD_BEARER_ID, DEAD_TERMINAL_ID).await;
        delete_record(&db, DEAD_TERMINAL_ID).await.unwrap();

        create_authorization_annotation(&db, DERIVED_CYCLE_A_ID).await;
        create_authorization_annotation(&db, DERIVED_CYCLE_B_ID).await;
        link_authorization_bearer(&db, DERIVED_CYCLE_A_ID, DERIVED_CYCLE_B_ID).await;
        link_authorization_bearer(&db, DERIVED_CYCLE_B_ID, DERIVED_CYCLE_A_ID).await;

        for depth in 0..=MAX_DERIVED_BEARER_DEPTH {
            create_authorization_annotation(&db, &depth_id(1, depth)).await;
        }
        for depth in 0..MAX_DERIVED_BEARER_DEPTH {
            link_authorization_bearer(&db, &depth_id(1, depth), &depth_id(1, depth + 1)).await;
        }
        link_authorization_bearer(&db, &depth_id(1, MAX_DERIVED_BEARER_DEPTH), TERMINAL_ID).await;

        create_authorization_unit(&db, UNIT_CYCLE_A_ID).await;
        create_authorization_unit(&db, UNIT_CYCLE_B_ID).await;
        bind_authorization_unit(&db, UNIT_CYCLE_A_ID, UNIT_CYCLE_B_ID).await;
        bind_authorization_unit(&db, UNIT_CYCLE_B_ID, UNIT_CYCLE_A_ID).await;

        for depth in 0..=MAX_UNIT_BEARER_DEPTH {
            create_authorization_unit(&db, &depth_id(2, depth)).await;
        }
        for depth in 0..MAX_UNIT_BEARER_DEPTH {
            bind_authorization_unit(&db, &depth_id(2, depth), &depth_id(2, depth + 1)).await;
        }
        bind_authorization_unit(&db, &depth_id(2, MAX_UNIT_BEARER_DEPTH), TERMINAL_ID).await;

        let ids = vec![
            BEARERLESS_ID.to_string(),
            MULTI_BEARER_ID.to_string(),
            DEAD_BEARER_ID.to_string(),
            DERIVED_CYCLE_A_ID.to_string(),
            depth_id(1, 0),
            UNIT_CYCLE_A_ID.to_string(),
            depth_id(2, 0),
        ];
        for principal in [
            Principal::bound("acct:foreign", false),
            Principal::trusted_local(),
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            let bulk = effective_capabilities_preloaded_on(&mut tx, principal, &ids, false)
                .await
                .unwrap();
            for id in &ids {
                let scalar = effective_capability_on(&mut tx, principal, id).await.ok();
                assert_eq!(bulk.get(id).copied().flatten(), scalar, "{id}");
                assert_eq!(scalar, None, "{id} must fail closed");
            }
            tx.rollback().await.unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn policy_evaluator_adapter_preserves_malformed_state_precedence_and_wording() {
        let mut state = PreloadedAuthorizationState::default();
        state.records.insert(
            ALLOWED_ID.into(),
            AuthorizationRecordState {
                record_type: "Collection".into(),
                kind: Some("folder".into()),
                deleted: false,
                owner_id: Some(OWNER_ID.into()),
                policy_anchor_id: Some(ALLOWED_ID.into()),
            },
        );
        state.explicit_policies.insert(ALLOWED_ID.into());
        state
            .owner_bindings
            .insert((OWNER_ID.into(), "acct:owner".into()));
        state.policy_entries.insert(
            ALLOWED_ID.into(),
            vec![AuthorizationPolicyEntry {
                subject_kind: "account".into(),
                subject_id: "acct:owner".into(),
                effect: "limit".into(),
                capability: "manage".into(),
            }],
        );

        let err = effective_capability_with(
            &mut state,
            Principal::bound("acct:owner", true),
            ALLOWED_ID,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("policy '{ALLOWED_ID}' contains unsupported effect 'limit'")
        );

        state.policy_entries.insert(
            ALLOWED_ID.into(),
            vec![AuthorizationPolicyEntry {
                subject_kind: "account".into(),
                subject_id: "acct:owner".into(),
                effect: "allow".into(),
                capability: "future".into(),
            }],
        );
        let err = effective_capability_with(
            &mut state,
            Principal::bound("acct:owner", true),
            ALLOWED_ID,
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "unsupported policy capability 'future'");

        state.policy_entries.insert(
            ALLOWED_ID.into(),
            vec![AuthorizationPolicyEntry {
                subject_kind: "account".into(),
                subject_id: "acct:other".into(),
                effect: "allow".into(),
                capability: "future".into(),
            }],
        );
        assert_eq!(
            effective_capability_with(
                &mut state,
                Principal::bound("acct:owner", true),
                ALLOWED_ID,
                false,
            )
            .await
            .unwrap(),
            Capability::Manage,
            "a malformed capability on a dormant grant stays ignored before the owner floor"
        );
    }
}
