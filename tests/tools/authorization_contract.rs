//! Reviewable, action-complete authorization contract for the SQLite profile.
//!
//! The manifest owns the census and evidence map. This crate owns a compact
//! principal × topology × operation matrix through production MCP dispatch.
//! Specialized suites stay focused and are cited rather than copied here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::export::LocalSnapshotSource;
use native_ce::mcp::register_membership_tool_schema;
use native_ce::mcp::{
    register_builtin_tools, register_snapshot_tool, register_surface_tools,
    AuthorizationDisposition, Caller, ToolKind, ToolRegistry,
};
use native_ce::{create_database, Db};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic. Vocabulary
// names such as `matrix-vocab` are not record ids and stay readable.
// `matrix-inherited` used to be a textual prefix of `matrix-inherited-parent`;
// nothing asserts on that overlap (the search assertion below wants the child
// itself, which is a genuine hit), so the UUIDs are simply distinct.
/// `matrix-owner`
const MATRIX_OWNER: &str = "a0c00000-0000-4000-8000-000000000001";
/// `matrix-inherited-parent`
const MATRIX_INHERITED_PARENT: &str = "a0c00000-0000-4000-8000-000000000002";
/// `matrix-inherited`
const MATRIX_INHERITED: &str = "a0c00000-0000-4000-8000-000000000003";
/// `matrix-private-parent`
const MATRIX_PRIVATE_PARENT: &str = "a0c00000-0000-4000-8000-000000000004";
/// `matrix-broad-child`
const MATRIX_BROAD_CHILD: &str = "a0c00000-0000-4000-8000-000000000005";
/// `matrix-view-only`
const MATRIX_VIEW_ONLY: &str = "a0c00000-0000-4000-8000-000000000006";
/// `matrix-edit-only`
const MATRIX_EDIT_ONLY: &str = "a0c00000-0000-4000-8000-000000000007";
/// `matrix-managed-allow`
const MATRIX_MANAGED_ALLOW: &str = "a0c00000-0000-4000-8000-000000000008";
/// `matrix-managed-deny`
const MATRIX_MANAGED_DENY: &str = "a0c00000-0000-4000-8000-000000000009";
/// The `matrix-{account}` person fixtures, by account name.
const MATRIX_PEOPLE: [(&str, &str); 5] = [
    ("viewer", "a0c00000-0000-4000-8000-000000000011"),
    ("editor", "a0c00000-0000-4000-8000-000000000012"),
    ("manager", "a0c00000-0000-4000-8000-000000000013"),
    ("member", "a0c00000-0000-4000-8000-000000000014"),
    ("unrelated", "a0c00000-0000-4000-8000-000000000015"),
];

const MANIFEST: &str = include_str!("../fixtures/authorization-contract.json");
const REPORT: &str = include_str!("../../docs/authorization-contract.md");

#[derive(Clone, Debug, Deserialize)]
struct ContractManifest {
    schema_version: u32,
    claim: Claim,
    operations: Vec<OperationContract>,
}

#[derive(Clone, Debug, Deserialize)]
struct Claim {
    backend: String,
    evidence_suite: String,
    scope: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OperationContract {
    tool: String,
    action: String,
    disposition: String,
    risk_tier: String,
    fixture: String,
    expected_threshold: String,
    access: Access,
    non_disclosure: bool,
    no_write_on_deny: bool,
    positive_evidence: Evidence,
    negative_evidence: Evidence,
    #[serde(default)]
    rationale: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Access {
    Read,
    Mutation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Evidence {
    Test {
        file: String,
        test: String,
        claim: String,
    },
    NotApplicable {
        reason: String,
    },
}

#[derive(Clone, Debug)]
struct ExpectedOperation {
    disposition: &'static str,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct ContractStats {
    tools: usize,
    operations: usize,
    ordinary: usize,
    high: usize,
    specialized: usize,
    reads: usize,
    mutations: usize,
    non_disclosure: usize,
    no_write_on_deny: usize,
    negative_not_applicable: usize,
}

fn production_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_snapshot_tool(&mut registry, Arc::new(LocalSnapshotSource::new())).unwrap();
    register_membership_tool_schema(&mut registry).unwrap();
    registry
}

fn disposition_name(disposition: AuthorizationDisposition) -> &'static str {
    match disposition {
        AuthorizationDisposition::NoRecord => "no_record",
        AuthorizationDisposition::CallerFilteredRead => "caller_filtered_read",
        AuthorizationDisposition::RecordView => "record_view",
        AuthorizationDisposition::RecordEdit => "record_edit",
        AuthorizationDisposition::RecordManage => "record_manage",
        AuthorizationDisposition::HostOwner => "host_owner",
        AuthorizationDisposition::Specialized => "specialized",
    }
}

fn schema_actions(schema: &Value) -> BTreeSet<String> {
    fn collect(property: Option<&Value>, actions: &mut BTreeSet<String>) {
        let Some(property) = property else { return };
        if let Some(value) = property.get("const").and_then(Value::as_str) {
            actions.insert(value.to_string());
        }
        if let Some(values) = property.get("enum").and_then(Value::as_array) {
            actions.extend(values.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }

    let mut actions = BTreeSet::new();
    collect(schema.pointer("/properties/action"), &mut actions);
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        for branch in branches {
            collect(branch.pointer("/properties/action"), &mut actions);
        }
    }
    if actions.is_empty() {
        actions.insert("$tool".to_string());
    }
    actions
}

fn production_operations(registry: &ToolRegistry) -> BTreeMap<(String, String), ExpectedOperation> {
    let registered = registry
        .specs()
        .map(|spec| (spec.name.as_str(), spec))
        .collect::<BTreeMap<_, _>>();
    let kinds = ToolKind::ALL
        .into_iter()
        // The ordinary SQLite registry owns the authorization manifest below.
        // Standby status is registered only when mcp-stdio has an activated
        // local standby and therefore has a real status provider.
        .filter(|kind| *kind != ToolKind::StandbyStatus)
        .map(|kind| (kind.name(), kind))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(registered.len(), kinds.len());

    registered
        .into_iter()
        .flat_map(|(tool, spec)| {
            let disposition = disposition_name(kinds[tool].authorization());
            schema_actions(&spec.input_schema)
                .into_iter()
                .map(move |action| {
                    (
                        (tool.to_string(), action),
                        ExpectedOperation { disposition },
                    )
                })
        })
        .collect()
}

fn exact_test_exists(source: &str, file: &str, test: &str) -> bool {
    if file.ends_with(".rs") {
        let synchronous = format!("fn {test}(");
        let asynchronous = format!("async fn {test}(");
        let lines = source.lines().collect::<Vec<_>>();
        lines.iter().enumerate().any(|(index, line)| {
            let line = line.trim_start();
            if !line.starts_with(&synchronous) && !line.starts_with(&asynchronous) {
                return false;
            }
            lines[..index]
                .iter()
                .rev()
                .take_while(|line| line.trim_start().starts_with("#["))
                .any(|line| matches!(line.trim(), "#[test]" | "#[tokio::test]"))
        })
    } else if file.ends_with(".ts") {
        let double_quoted = format!("test(\"{test}\"");
        let single_quoted = format!("test('{test}'");
        source.lines().any(|line| {
            let line = line.trim_start();
            line.starts_with(&double_quoted) || line.starts_with(&single_quoted)
        })
    } else {
        false
    }
}

fn validate_evidence(
    evidence: &Evidence,
    side: &str,
    key: &(String, String),
    root: &Path,
) -> Result<(), String> {
    match evidence {
        Evidence::Test { file, test, claim } => {
            if claim.trim().is_empty() {
                return Err(format!("{}.{} {side} evidence has no claim", key.0, key.1));
            }
            let path = root.join(file);
            let source = std::fs::read_to_string(&path).map_err(|error| {
                format!(
                    "{}.{} {side} evidence file {} is unreadable: {error}",
                    key.0,
                    key.1,
                    path.display()
                )
            })?;
            if !exact_test_exists(&source, file, test) {
                return Err(format!(
                    "{}.{} {side} evidence does not resolve to an exact test {file}::{test}",
                    key.0, key.1
                ));
            }
        }
        Evidence::NotApplicable { reason } if reason.trim().is_empty() => {
            return Err(format!(
                "{}.{} {side} not_applicable evidence has no justification",
                key.0, key.1
            ));
        }
        Evidence::NotApplicable { .. } => {}
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ContractManifest,
    expected: &BTreeMap<(String, String), ExpectedOperation>,
    root: &Path,
) -> Result<ContractStats, String> {
    if manifest.schema_version != 2 {
        return Err("authorization contract schema_version must be 2".into());
    }
    let mut seen = BTreeSet::new();
    let mut stats = ContractStats::default();
    for contract in &manifest.operations {
        let key = (contract.tool.clone(), contract.action.clone());
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate operation {}.{}", key.0, key.1));
        }
        let Some(production) = expected.get(&key) else {
            return Err(format!(
                "manifest names unshipped operation {}.{}",
                key.0, key.1
            ));
        };
        if contract.disposition != production.disposition {
            return Err(format!(
                "{}.{} disposition drifted: manifest={} production={}",
                key.0, key.1, contract.disposition, production.disposition
            ));
        }
        if !matches!(
            contract.risk_tier.as_str(),
            "ordinary" | "high" | "specialized"
        ) {
            return Err(format!("{}.{} has an unknown risk tier", key.0, key.1));
        }
        if contract.fixture.trim().is_empty() || contract.expected_threshold.trim().is_empty() {
            return Err(format!(
                "{}.{} has incomplete review metadata",
                key.0, key.1
            ));
        }
        if contract.disposition == "specialized" && contract.rationale.trim().is_empty() {
            return Err(format!(
                "{}.{} has an unjustified specialized disposition",
                key.0, key.1
            ));
        }
        if contract.risk_tier != "ordinary" && !contract.non_disclosure {
            return Err(format!(
                "{}.{} is sensitive but has no non-disclosure obligation",
                key.0, key.1
            ));
        }
        match contract.access {
            Access::Mutation if !contract.no_write_on_deny => {
                return Err(format!(
                    "{}.{} mutates but no_write_on_deny is false",
                    key.0, key.1
                ));
            }
            Access::Read if contract.no_write_on_deny => {
                return Err(format!(
                    "{}.{} is read-only but no_write_on_deny is true",
                    key.0, key.1
                ));
            }
            _ => {}
        }
        if !matches!(contract.positive_evidence, Evidence::Test { .. }) {
            return Err(format!("{}.{} has no positive test evidence", key.0, key.1));
        }
        match (&contract.access, &contract.negative_evidence) {
            (Access::Mutation, Evidence::NotApplicable { .. }) => {
                return Err(format!(
                    "{}.{} mutation has no negative test evidence",
                    key.0, key.1
                ));
            }
            (Access::Read, Evidence::NotApplicable { .. })
                if contract.expected_threshold != "none" =>
            {
                return Err(format!(
                    "{}.{} protected read has no negative test evidence",
                    key.0, key.1
                ));
            }
            _ => {}
        }
        validate_evidence(&contract.positive_evidence, "positive", &key, root)?;
        validate_evidence(&contract.negative_evidence, "negative", &key, root)?;

        match contract.risk_tier.as_str() {
            "ordinary" => stats.ordinary += 1,
            "high" => stats.high += 1,
            "specialized" => stats.specialized += 1,
            _ => unreachable!(),
        }
        match contract.access {
            Access::Read => stats.reads += 1,
            Access::Mutation => stats.mutations += 1,
        }
        stats.non_disclosure += usize::from(contract.non_disclosure);
        stats.no_write_on_deny += usize::from(contract.no_write_on_deny);
        stats.negative_not_applicable += usize::from(matches!(
            contract.negative_evidence,
            Evidence::NotApplicable { .. }
        ));
    }
    let expected_keys = expected.keys().cloned().collect::<BTreeSet<_>>();
    if seen != expected_keys {
        let missing = expected_keys.difference(&seen).collect::<Vec<_>>();
        let extra = seen.difference(&expected_keys).collect::<Vec<_>>();
        return Err(format!(
            "operation census drifted; missing={missing:?} extra={extra:?}"
        ));
    }
    stats.tools = expected
        .keys()
        .map(|(tool, _)| tool.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    stats.operations = expected.len();
    Ok(stats)
}

fn render_operation_census(stats: &ContractStats) -> String {
    format!(
        "- **{} registered tools / {} operations**.\n\
- **{} ordinary, {} high-risk, and {} specialized operations**.\n\
- **{} read-only and {} mutating operations**.\n\
- **{} operations carry a non-disclosure obligation**.\n\
- All **{} mutating operations** carry an explicit no-write-on-deny obligation\n  and named negative evidence.\n\
- **{} read operations** have justified `negative_evidence: not_applicable`:\n  `ping.$tool`, `engine_info.$tool`, `quickstart.$tool`, `read_guide.$tool`, and\n  `manage_vocabularies.list_values`. They have no authorization threshold;\n  each still has positive executable evidence.\n\
- Complete-coverage claim: **SQLite local**, exercised by\n  `sqlite-reference-ci`. Postgres and Turso contract profiles do not inherit\n  this claim.",
        stats.tools,
        stats.operations,
        stats.ordinary,
        stats.high,
        stats.specialized,
        stats.reads,
        stats.mutations,
        stats.non_disclosure,
        stats.no_write_on_deny,
        stats.negative_not_applicable,
    )
}

fn validate_report_census(report: &str, stats: &ContractStats) -> Result<(), String> {
    let (_, after_heading) = report
        .split_once("## Current operation census\n\n")
        .ok_or_else(|| "report has no Current operation census section".to_string())?;
    let (actual, _) = after_heading
        .split_once("\n\n")
        .ok_or_else(|| "report's Current operation census has no end".to_string())?;
    let expected = render_operation_census(stats);
    if actual != expected {
        return Err(format!(
            "report operation census disagrees with the live registry or manifest\n\
             expected:\n{expected}\n\
             actual:\n{actual}"
        ));
    }
    Ok(())
}

fn parsed_manifest() -> ContractManifest {
    serde_json::from_str(MANIFEST).unwrap()
}

#[test]
fn manifest_is_an_exact_operation_census_with_live_evidence_owners() {
    let manifest = parsed_manifest();
    assert_eq!(manifest.claim.backend, "sqlite-local");
    assert_eq!(manifest.claim.evidence_suite, "sqlite-reference-ci");
    assert!(manifest.claim.scope.contains("do not inherit"));
    let expected = production_operations(&production_registry());
    let stats =
        validate_manifest(&manifest, &expected, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    validate_report_census(REPORT, &stats).unwrap();
    eprintln!("authorization operation contract: {stats:?}");
}

#[test]
fn report_validator_rejects_an_internally_consistent_stale_census() {
    let manifest = parsed_manifest();
    let expected = production_operations(&production_registry());
    let stats =
        validate_manifest(&manifest, &expected, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let stale_non_disclosure = stats.non_disclosure.checked_sub(1).unwrap();
    let stale_report = REPORT.replacen(
        &format!(
            "**{} operations carry a non-disclosure obligation**",
            stats.non_disclosure
        ),
        &format!("**{stale_non_disclosure} operations carry a non-disclosure obligation**"),
        1,
    );

    let error = validate_report_census(&stale_report, &stats).unwrap_err();
    assert!(error.contains("disagrees with the live registry or manifest"));
}

#[test]
fn contract_validator_fails_closed_on_action_evidence_and_mutation_drift() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = parsed_manifest();
    let expected = production_operations(&production_registry());
    validate_manifest(&manifest, &expected, root).unwrap();

    let mut added_schema_action = expected.clone();
    added_schema_action.insert(
        ("ping".into(), "newly_shipped_action".into()),
        ExpectedOperation {
            disposition: "no_record",
        },
    );
    let error = validate_manifest(&manifest, &added_schema_action, root).unwrap_err();
    assert!(error.contains("newly_shipped_action"), "{error}");

    let mut missing_negative = manifest.clone();
    let update = missing_negative
        .operations
        .iter_mut()
        .find(|operation| operation.tool == "update_record")
        .unwrap();
    update.negative_evidence = Evidence::NotApplicable {
        reason: "incorrectly omitted".into(),
    };
    let error = validate_manifest(&missing_negative, &expected, root).unwrap_err();
    assert!(
        error.contains("mutation has no negative test evidence"),
        "{error}"
    );

    let mut false_no_write = manifest.clone();
    false_no_write
        .operations
        .iter_mut()
        .find(|operation| operation.tool == "update_record")
        .unwrap()
        .no_write_on_deny = false;
    let error = validate_manifest(&false_no_write, &expected, root).unwrap_err();
    assert!(error.contains("no_write_on_deny is false"), "{error}");

    let mut substring_only = manifest;
    if let Evidence::Test { test, .. } = &mut substring_only
        .operations
        .iter_mut()
        .find(|operation| operation.tool == "update_record")
        .unwrap()
        .positive_evidence
    {
        *test = "ordinary_dispatch_matrix".into();
    }
    let error = validate_manifest(&substring_only, &expected, root).unwrap_err();
    assert!(error.contains("exact test"), "{error}");
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    mut arguments: Value,
) -> native_ce::Result<Value> {
    if matches!(
        tool,
        "create_record" | "update_record" | "archive_record" | "delete_record"
    ) {
        arguments
            .as_object_mut()
            .unwrap()
            .entry("reason")
            .or_insert_with(|| json!("Authorization contract fixture."));
    }
    registry.call(db.clone(), caller, tool, arguments).await
}

async fn create_local(registry: &ToolRegistry, db: &Db, arguments: Value) -> String {
    call_as(registry, db, Caller::local(), "create_record", arguments)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn bind_account(db: &Db, person: &str, account: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, 'account', ?, 1)",
    )
    .bind(person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

fn hosted(account: &str) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context(format!("host:{account}"), "db:authorization-contract")
        .with_hosting_owner(false)
}

fn hosted_owner(account: &str) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context(format!("host:{account}"), "db:authorization-contract")
        .with_hosting_owner(true)
}

async fn event_counts(db: &Db) -> (i64, i64, i64) {
    let content = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let policy = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let meta = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    (content, policy, meta)
}

#[tokio::test]
async fn ordinary_dispatch_matrix_keeps_allow_and_deny_adjacent() {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();

    let owner = create_local(
        &registry,
        &db,
        json!({"id":MATRIX_OWNER,"type":"Entity","kind":"person","name":"Owner"}),
    )
    .await;
    bind_account(&db, &owner, "acct:owner").await;
    for (account, id) in MATRIX_PEOPLE {
        let person = create_local(
            &registry,
            &db,
            json!({"id":id,"type":"Entity","kind":"person","name":account}),
        )
        .await;
        bind_account(&db, &person, &format!("acct:{account}")).await;
    }

    let inherited_parent = create_local(&registry, &db, json!({"id":MATRIX_INHERITED_PARENT,"type":"Collection","kind":"folder","name":"Members edit","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &inherited_parent,
        vec![AllowEntry::members(Capability::Edit)],
    )
    .await
    .unwrap();
    let inherited = create_local(&registry, &db, json!({"id":MATRIX_INHERITED,"type":"Document","kind":"note","name":"Inherited visible needle","body":"before","home_id":inherited_parent,"owner_id":owner})).await;

    let private_parent = create_local(&registry, &db, json!({"id":MATRIX_PRIVATE_PARENT,"type":"Collection","kind":"folder","name":"Hidden parent","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &private_parent,
        vec![AllowEntry::account("acct:owner", Capability::Manage)],
    )
    .await
    .unwrap();
    let broad_child = create_local(&registry, &db, json!({"id":MATRIX_BROAD_CHILD,"type":"Document","kind":"note","name":"Broad child needle","body":"broad","home_id":private_parent,"owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &broad_child,
        vec![AllowEntry::account("acct:viewer", Capability::View)],
    )
    .await
    .unwrap();

    let view_only = create_local(&registry, &db, json!({"id":MATRIX_VIEW_ONLY,"type":"Document","kind":"note","name":"View only","body":"unchanged","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &view_only,
        vec![AllowEntry::account("acct:viewer", Capability::View)],
    )
    .await
    .unwrap();
    let edit_only = create_local(&registry, &db, json!({"id":MATRIX_EDIT_ONLY,"type":"Document","kind":"note","name":"Edit only","body":"unchanged","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &edit_only,
        vec![AllowEntry::account("acct:editor", Capability::Edit)],
    )
    .await
    .unwrap();
    let managed_allow = create_local(&registry, &db, json!({"id":MATRIX_MANAGED_ALLOW,"type":"Document","kind":"note","name":"Manage allow","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &managed_allow,
        vec![AllowEntry::account("acct:manager", Capability::Manage)],
    )
    .await
    .unwrap();
    let managed_deny = create_local(&registry, &db, json!({"id":MATRIX_MANAGED_DENY,"type":"Document","kind":"note","name":"Manage deny","owner_id":owner})).await;
    replace_explicit_policy(
        &db,
        "matrix:policy",
        &managed_deny,
        vec![AllowEntry::account("acct:editor", Capability::Edit)],
    )
    .await
    .unwrap();

    // View: live member × inherited boundary is allowed; the same principal ×
    // explicit private boundary is denied with the batch not-found shape.
    let member_read = call_as(
        &registry,
        &db,
        hosted("acct:member"),
        "get_record",
        json!({"ids":[inherited, private_parent]}),
    )
    .await
    .unwrap();
    assert_eq!(member_read["records"][0]["status"], "found");
    assert_eq!(member_read["records"][1]["status"], "not_found");

    // View: direct grant × broader child is allowed while its hidden parent is
    // redacted; unrelated identity × that explicit boundary is denied.
    let direct_read = call_as(
        &registry,
        &db,
        hosted("acct:viewer"),
        "get_record",
        json!({"ids":[broad_child]}),
    )
    .await
    .unwrap();
    assert_eq!(direct_read["records"][0]["status"], "found");
    assert_eq!(direct_read["records"][0]["home_id"], Value::Null);
    assert!(!direct_read.to_string().contains(MATRIX_PRIVATE_PARENT));
    let unrelated_read = call_as(
        &registry,
        &db,
        hosted("acct:unrelated"),
        "get_record",
        json!({"ids":[broad_child]}),
    )
    .await
    .unwrap();
    assert_eq!(unrelated_read["records"][0]["status"], "not_found");

    // Edit: members baseline × inherited boundary and direct edit × explicit
    // boundary are allowed. Direct view × explicit boundary is denied.
    call_as(
        &registry,
        &db,
        hosted("acct:member"),
        "update_record",
        json!({"id":inherited,"body":"member edit","if_body_digest":hex::encode(sha2::Sha256::digest(b"before"))}),
    )
    .await
    .unwrap();
    call_as(
        &registry,
        &db,
        hosted("acct:editor"),
        "update_record",
        json!({"id":edit_only,"body":"editor edit","if_body_digest":hex::encode(sha2::Sha256::digest(b"unchanged"))}),
    )
    .await
    .unwrap();
    let before_denied_edit = event_counts(&db).await;
    let denied_edit = call_as(
        &registry,
        &db,
        hosted("acct:viewer"),
        "update_record",
        json!({"id":view_only,"body":"must not land"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        denied_edit,
        format!(
            "update_record: record {view_only} requires edit capability; caller has view capability"
        )
    );
    assert_eq!(event_counts(&db).await, before_denied_edit);
    let unchanged = call_as(
        &registry,
        &db,
        hosted("acct:viewer"),
        "get_record",
        json!({"ids":[view_only]}),
    )
    .await
    .unwrap();
    assert_eq!(unchanged["records"][0]["body"], "unchanged");

    // Manage: direct manage is allowed; direct edit is denied and leaves both
    // content and policy logs untouched.
    call_as(
        &registry,
        &db,
        hosted("acct:manager"),
        "archive_record",
        json!({"id":managed_allow}),
    )
    .await
    .unwrap();
    let before_denied_manage = event_counts(&db).await;
    let denied_manage = call_as(
        &registry,
        &db,
        hosted("acct:editor"),
        "delete_record",
        json!({"id":managed_deny}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        denied_manage,
        format!(
            "delete_record: record {managed_deny} requires manage capability; caller has edit capability"
        )
    );
    assert_eq!(event_counts(&db).await, before_denied_manage);

    // Caller-filtered discovery keeps the positive and negative records in one
    // response and computes totals only after authorization.
    let query = call_as(
        &registry,
        &db,
        hosted("acct:viewer"),
        "query_record",
        json!({"steps":[{"step":"filter","ids":[broad_child,private_parent]}]}),
    )
    .await
    .unwrap();
    assert_eq!(query["total"], 1);
    assert_eq!(query["records"][0]["id"], broad_child);
    assert!(!query.to_string().contains(MATRIX_PRIVATE_PARENT));
    let search = call_as(
        &registry,
        &db,
        hosted("acct:viewer"),
        "search",
        json!({"query":"needle"}),
    )
    .await
    .unwrap();
    let search_text = search.to_string();
    assert!(search_text.contains(MATRIX_BROAD_CHILD));
    assert!(search_text.contains(MATRIX_INHERITED));
    assert!(!search_text.contains(MATRIX_PRIVATE_PARENT));

    db.close().await;
}

#[tokio::test]
async fn vocabulary_operation_matrix_proves_each_host_owner_boundary() {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let owner = hosted_owner("acct:owner");
    let nonowner = hosted("acct:not-owner");

    async fn vocabulary_call(
        registry: &ToolRegistry,
        db: &Db,
        caller: Caller,
        arguments: Value,
    ) -> native_ce::Result<Value> {
        call_as(registry, db, caller, "manage_vocabularies", arguments).await
    }

    async fn denied_without_writes(
        registry: &ToolRegistry,
        db: &Db,
        caller: &Caller,
        arguments: Value,
    ) {
        let action = arguments["action"].as_str().unwrap().to_string();
        let before = event_counts(db).await;
        let denied = vocabulary_call(registry, db, caller.clone(), arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            denied.contains("owner") && denied.contains("host role"),
            "{action}: {denied}"
        );
        assert_eq!(event_counts(db).await, before, "{action} wrote on deny");
    }

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"create_vocabulary","name":"matrix-vocab"}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"create_vocabulary","name":"matrix-vocab"}),
    )
    .await
    .unwrap();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"propose_value","vocabulary":"matrix-vocab","value":"canonical"}),
    )
    .await;
    let canonical = vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"propose_value","vocabulary":"matrix-vocab","value":"canonical"}),
    )
    .await
    .unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_string();
    let alias = vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"propose_value","vocabulary":"matrix-vocab","value":"alias"}),
    )
    .await
    .unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_string();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"reorder_value","value_id":canonical,"ordinal":10}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"reorder_value","value_id":canonical,"ordinal":10}),
    )
    .await
    .unwrap();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"set_gloss","value_id":canonical,"gloss":"Definition under the host-owner boundary."}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"set_gloss","value_id":canonical,"gloss":"Definition under the host-owner boundary."}),
    )
    .await
    .unwrap();

    let kind_metadata = json!({
        "schema_version": 1,
        "provenance_ref": "rec:authorization-contract",
        "definition": "A governed kind used by the authorization contract.",
        "identity": {"criterion":"record identity","dedup":{"mode":"record_id","keys":[]}},
        "declared_capabilities": []
    });
    let kind_value = vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"propose_value","vocabulary":"kind:WorkItem","value":"authorization_contract_fixture","metadata":kind_metadata}),
    )
    .await
    .unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_string();
    let revised_metadata = json!({
        "schema_version": 1,
        "provenance_ref": "rec:authorization-contract",
        "definition": "A revised governed kind used by the authorization contract.",
        "identity": {"criterion":"record identity","dedup":{"mode":"record_id","keys":[]}},
        "declared_capabilities": []
    });
    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"set_metadata","value_id":kind_value,"metadata":revised_metadata}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"set_metadata","value_id":kind_value,"metadata":revised_metadata}),
    )
    .await
    .unwrap();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"promote_value","value_id":canonical}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"promote_value","value_id":canonical}),
    )
    .await
    .unwrap();
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"promote_value","value_id":alias}),
    )
    .await
    .unwrap();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"alias_value","value_id":alias,"canonical_id":canonical}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"alias_value","value_id":alias,"canonical_id":canonical}),
    )
    .await
    .unwrap();

    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"deprecate_value","value_id":canonical}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"deprecate_value","value_id":canonical}),
    )
    .await
    .unwrap();

    let disposable = vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"propose_value","vocabulary":"matrix-vocab","value":"disposable"}),
    )
    .await
    .unwrap()["value_id"]
        .as_str()
        .unwrap()
        .to_string();
    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"delete_value","value_id":disposable}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"delete_value","value_id":disposable}),
    )
    .await
    .unwrap();

    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"create_vocabulary","name":"disposable-vocab"}),
    )
    .await
    .unwrap();
    denied_without_writes(
        &registry,
        &db,
        &nonowner,
        json!({"action":"delete_vocabulary","vocabulary":"disposable-vocab"}),
    )
    .await;
    vocabulary_call(
        &registry,
        &db,
        owner.clone(),
        json!({"action":"delete_vocabulary","vocabulary":"disposable-vocab"}),
    )
    .await
    .unwrap();

    // list_values is deliberately the one operation on this mixed tool with
    // no host-owner threshold. Keep that exception explicit and executable.
    let listed = vocabulary_call(
        &registry,
        &db,
        nonowner,
        json!({"action":"list_values","vocabulary":"matrix-vocab"}),
    )
    .await
    .unwrap();
    assert_eq!(listed["vocabulary"]["name"], "matrix-vocab");
    db.close().await;
}
